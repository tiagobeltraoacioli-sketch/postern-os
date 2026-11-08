// SPDX-License-Identifier: MIT OR Apache-2.0

//! # postern-mobile-signer — the MOBILE (phone) side of phone-as-signer v1
//!
//! The phone is the credential; the desktop is the terminal. This crate does not
//! re-implement the protocol — it **integrates** the frozen PMO interfaces and
//! plugs in the phone's real wallet:
//!
//! - [`postern_signer_protocol`] (Dev2) owns the request/approve PROTOCOL:
//!   `SignRequest`/`Approval`, the replay guard (fresh nonce + monotonic counter +
//!   session binding), WYSIWYS + the three consequence tiers, revocable grants,
//!   and the [`WalletSigner`](postern_signer_protocol::WalletSigner) /
//!   [`Channel`](postern_signer_protocol::channel::Channel) seams.
//! - [`postern_pairing`] (Dev1) owns the mutually-authenticated, PQ-hybrid
//!   (ML-KEM-1024‖X25519) session channel + transport.
//! - [`bloch_mobile::WalletCore`] is the signing oracle (hybrid Falcon‖ML-DSA;
//!   seed + secret zeroized on drop). [`bloch_crypto`] decodes a real node
//!   transaction for the transfer WYSIWYS.
//!
//! ## What this crate adds
//!
//! | Piece | Role |
//! |---|---|
//! | [`WalletCoreSigner`] | the REAL [`WalletSigner`](postern_signer_protocol::WalletSigner), replacing the protocol crate's `ScaffoldSigner` |
//! | [`PairedSignerChannel`] | bridges a [`postern_pairing`] session into the protocol's `Channel` (seal→transport→open) |
//! | [`txwysiwys`] | decodes a `bloch_crypto` transaction into a protocol `TransferIntent` for WYSIWYS (fee honestly unverifiable) |
//! | [`MobileSigner`] | the app-drivable orchestrator: frame-in → WYSIWYS prompt → per-sign presence → approval-frame-out |
//! | [`ffi`] (feature) | the UniFFI surface, WITHOUT a second `setup_scaffolding!()` |
//!
//! ## RAILS (carried in code, never rounded off)
//!
//! - **The key/seed NEVER leaves the device — structurally.** The
//!   [`WalletSigner`](postern_signer_protocol::WalletSigner) seam yields only
//!   public outputs (pubkey, address, signature); the protocol's secret types have
//!   no `Serialize`; no wire type can carry key material (the protocol crate proves
//!   this with a compile-time census + a build-failing golden test). This crate's
//!   own denylist test re-checks that an approval frame never contains the secret.
//! - **Software keystore, NOT hardware.** Even on the phone the PQ secret is
//!   decrypted into RAM to sign (zeroized on drop). On the community edition it is
//!   a pure software keystore. A rooted/malware phone reads it and can forge the
//!   approval UI — unmitigable here. **This is not a hardware wallet.**
//! - **Replay-proof** (both the pairing channel's AEAD/counter binding AND the
//!   protocol's nonce/counter/session guard).
//! - **Per-sign user presence; no blanket auto-approve** ([`PresenceProof`] is
//!   bound to one request nonce). Optional revocable grants cover the reversible
//!   single-tap tier only — never a payment.
//! - **UNAUDITED scaffold.** The mobile image is **UNBOOTED** — this is a
//!   core/binding, **not a shipped app**. The coin is not a security. Community
//!   edition is "Postern for postmarketOS — community edition", never "Postern OS".

#![forbid(unsafe_code)]

pub mod bridge;
pub mod facade;
pub mod signer;
pub mod txwysiwys;

#[cfg(feature = "ffi")]
pub mod ffi;

// The frozen protocol/pairing crates, re-exported so an app can build requests /
// challenges without a second dependency line.
pub use postern_pairing as pairing;
pub use postern_signer_protocol as protocol;

pub use bridge::{BridgeError, PairedSignerChannel};
pub use facade::{
    MobileError, MobileSigner, PresenceMethod, PresenceProof, Prompt, Tier, NOT_A_HARDWARE_WALLET,
};
pub use signer::WalletCoreSigner;
pub use txwysiwys::{
    chain_id, describe_outputs, to_transfer_intent, OutputLine, TxDecodeError, TxDescription,
};

#[cfg(test)]
mod tests {
    use super::*;
    use postern_signer_protocol::{
        loopback, Channel as _, DesktopRequester, LoginChallenge, SessionId,
    };

    fn session() -> SessionId {
        [7u8; 16]
    }

    fn login() -> LoginChallenge {
        LoginChallenge {
            org: "acme".into(),
            user: "alice".into(),
            nonce: [3u8; 32],
            issued_at: 1_752_000_000,
        }
    }

    fn phone(session: SessionId) -> MobileSigner {
        let signer = WalletCoreSigner::from_seed_bytes(&[9u8; 32], true).unwrap();
        MobileSigner::new(signer, session, "Tiago's ThinkPad")
    }

    fn nonce_from(prompt: &Prompt) -> [u8; 32] {
        let mut n = [0u8; 32];
        n.copy_from_slice(&hex::decode(&prompt.req_nonce_hex).unwrap());
        n
    }

    /// End-to-end: desktop requests a login over the protocol loopback; the phone
    /// (real WalletCore) renders WYSIWYS, the user is present, it signs; the
    /// desktop matches the approval and the node verifier accepts the hybrid
    /// signature over the SAME login digest a consiglio server would check.
    #[test]
    fn end_to_end_login_sign_verifies_with_the_node_verifier() {
        let (mut desk, mut phone_end) = loopback();
        let mut requester = DesktopRequester::new(session());
        let challenge = login();
        let sent = requester.request_login(&mut desk, &challenge).unwrap();

        // The raw request frame as it arrives on the phone's transport.
        let request_frame = phone_end.recv().unwrap();

        let mut ms = phone(session());
        let prompt = ms.receive_frame(&request_frame).unwrap();
        assert_eq!(prompt.tier, Tier::SingleTap);
        assert!(!prompt.can_move_funds);
        assert!(prompt.sentence.contains("login challenge"));
        assert_eq!(prompt.peer_device, "Tiago's ThinkPad");

        // Per-sign presence bound to THIS request nonce.
        let presence = PresenceProof::granted(nonce_from(&prompt), PresenceMethod::Biometric);
        let approval_frame = ms.approve(presence).unwrap();

        // Deliver the approval back to the desktop and match it.
        phone_end.send(&approval_frame).unwrap();
        let approval = requester.recv_approval(&mut desk, &sent).unwrap();

        // The signature verifies over the login digest with the REAL hybrid
        // Falcon‖ML-DSA verifier (byte-identical to the node / consiglio server).
        assert!(bloch_crypto::crypto::verify(
            &approval.public_key,
            &challenge.signing_digest(),
            &approval.signature
        ));
    }

    #[test]
    fn presence_for_the_wrong_request_is_refused() {
        let (mut desk, mut phone_end) = loopback();
        let mut requester = DesktopRequester::new(session());
        requester.request_login(&mut desk, &login()).unwrap();
        let frame = phone_end.recv().unwrap();

        let mut ms = phone(session());
        ms.receive_frame(&frame).unwrap();
        // A proof minted for a different nonce cannot authorize this sign.
        let wrong = PresenceProof::granted([0xAAu8; 32], PresenceMethod::Biometric);
        assert!(matches!(ms.approve(wrong), Err(MobileError::PresenceMismatch)));
    }

    #[test]
    fn a_replayed_request_frame_is_refused_after_the_first_sign() {
        let (mut desk, mut phone_end) = loopback();
        let mut requester = DesktopRequester::new(session());
        requester.request_login(&mut desk, &login()).unwrap();
        let frame = phone_end.recv().unwrap();

        let mut ms = phone(session());
        let prompt = ms.receive_frame(&frame).unwrap();
        let presence = PresenceProof::granted(nonce_from(&prompt), PresenceMethod::Biometric);
        ms.approve(presence).unwrap();

        // Re-feeding the identical frame: the protocol replay guard (now committed)
        // rejects the non-advancing counter. Fail closed.
        assert!(ms.receive_frame(&frame).is_err());
    }

    #[test]
    fn approval_frame_never_contains_the_secret_key() {
        // Structural denylist re-check at this integration layer.
        let seed = [9u8; 32];
        let (_pk, sk) = bloch_crypto::crypto::generate_keypair_from_seed(&seed).unwrap();

        let (mut desk, mut phone_end) = loopback();
        let mut requester = DesktopRequester::new(session());
        requester.request_login(&mut desk, &login()).unwrap();
        let frame = phone_end.recv().unwrap();

        let mut ms = phone(session());
        let prompt = ms.receive_frame(&frame).unwrap();
        let presence = PresenceProof::granted(nonce_from(&prompt), PresenceMethod::Biometric);
        let approval_frame = ms.approve(presence).unwrap();

        assert!(
            !contains_subslice(&approval_frame, &sk),
            "an approval frame must NEVER contain the secret key"
        );
        assert!(
            !contains_subslice(&approval_frame, &seed),
            "an approval frame must NEVER contain the seed"
        );
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() || needle.len() > haystack.len() {
            return false;
        }
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
