// SPDX-License-Identifier: MIT OR Apache-2.0
//! # postern-signer-protocol — phone-as-signer, desktop-as-terminal (v1)
//!
//! The **desktop requests** a signature; the **phone** (which holds the hybrid
//! **Falcon‖ML-DSA** wallet key) **parses the actual bytes to be signed**, shows a
//! human "what you see is what you sign" sentence, and **approves + signs**. The
//! private key never crosses the channel — only signatures and approvals do — and
//! that is enforced **structurally** (the type system + a build-failing golden
//! test), not by convention.
//!
//! Implements Design §3 (phone-as-signer) and Security §4 (companion-signing) /
//! §5.1 (the private-key denylist). Scoped to the **v1 flow**: signing a desktop
//! **wallet-login challenge** in the `postern-consiglio-auth` shape. General
//! transaction signing is the same shape ([`TransferIntent`] proves it).
//!
//! ## Shape
//! ```text
//! Desktop (holds NOTHING)                 Phone (holds the key)
//! ─────────────────────                   ─────────────────────
//! SignRequest{ session_id, req_nonce,  ─▶ replay guard: fresh nonce + monotonic
//!   counter, payload=encode(intent) }      counter + session binding (fail closed)
//!                                          decode payload from the ACTUAL bytes
//!                                          WYSIWYS: "this signs a login … can't
//!                                            move funds" (3 consequence tiers)
//!                                          human approves (or grant-covered tap)
//!                                          sign canonical digest; commit guard
//!   match & relay Approval          ◀──── Approval{ signature, public_key, digest }
//! ```
//!
//! ## Honesty rails (binding — do not let a UI round these off)
//! - **Keys never cross the wire — structurally.** The seed and the Falcon‖ML-DSA
//!   secret live in [`secret`] types that have no `Serialize` and can never be a
//!   field of a wire message; every message is the sealed [`secret::WireSafe`];
//!   `tests/golden_denylist.rs` fails the build if any key byte reaches a message.
//! - **Software signing in RAM is NOT a hardware wallet.** Even on the phone the
//!   PQ secret is decrypted into normal RAM to sign (zeroized on drop). On the
//!   **Postern for postmarketOS — community edition** it is pure software. A
//!   rooted/malware endpoint (A5) reads the key from RAM and can forge the
//!   approval UI; nothing here fixes that. This is *not* a Ledger/Trezor.
//! - **Scaffold, unaudited.** This is a compiling reference of the protocol shape,
//!   not a hardened, audited signer. The real signer is `mobile/core`'s
//!   `WalletCore`; [`signer::ScaffoldSigner`] is a deterministic test stand-in and
//!   is **not real cryptography**.
//! - **Local-only.** No cloud, no relay, no telemetry — this protocol rides a
//!   local, paired, hybrid-PQ channel ([`channel::Channel`]).
//! - **The coin (BLCH) is not a security**, buys no software, and is not involved
//!   in licensing. A "sign" is nonetheless an irreversible spend — treat it so.
//!
//! Naming: the community mobile edition is **"Postern for postmarketOS — community
//! edition"**, never "Postern OS". The assurance name is never "BABA YAGA".

#![forbid(unsafe_code)]

pub mod channel;
pub mod error;
pub mod golden;
pub mod grant;
pub mod message;
pub mod protocol;
pub mod replay;
pub mod resume;
pub mod secret;
pub mod session;
pub mod signer;
pub mod wysiwys;

// ── The common path ───────────────────────────────────────────────────────────
pub use channel::{loopback, Channel, LoopEnd};
pub use error::{ProtocolError, SignerError};
pub use grant::{ApprovalGrant, GrantScope};
pub use message::{
    Approval, Chain, LoginChallenge, SessionId, SignPayload, SignRequest, TransferIntent,
    LOGIN_DOMAIN, SIGNER_DOMAIN,
};
pub use protocol::{DesktopRequester, Pending, PhoneApprover, SentRequest};
pub use replay::ReplayGuard;
pub use resume::{open_watermark, seal_watermark, ResumeError, WATERMARK_CONTEXT};
pub use secret::{SecretKey, SeedPhrase, WireSafe};
pub use session::{fresh_nonce, new_session_id, RequestCounter};
pub use signer::{ScaffoldSigner, WalletSigner};
pub use wysiwys::{render, ConsequenceTier, Wysiwys};

/// Build-time census: force `message::_WIRE_CENSUS` to evaluate so the compile-time
/// half of the structural denylist runs on every build.
#[allow(dead_code)]
const _: () = message::_WIRE_CENSUS;

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn login_digest_matches_consiglio_transcript_layout() {
        // The login digest is SHA3-256 over the SAME domain-separated field layout
        // as postern-consiglio-auth's Challenge::transcript(). Recompute it here to
        // pin the byte layout (tag ‖ len(org) ‖ org ‖ len(user) ‖ user ‖ nonce ‖ issued_at).
        use sha3::{Digest, Sha3_256};
        let c = login();
        let mut h = Sha3_256::new();
        h.update(LOGIN_DOMAIN);
        h.update((c.org.len() as u64).to_le_bytes());
        h.update(c.org.as_bytes());
        h.update((c.user.len() as u64).to_le_bytes());
        h.update(c.user.as_bytes());
        h.update(c.nonce);
        h.update(c.issued_at.to_le_bytes());
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(c.signing_digest(), expected);
    }

    #[test]
    fn login_is_single_tap_and_cannot_move_funds() {
        let w = render(&SignPayload::Login(login()), "Tiago's ThinkPad", session(), &[1u8; 32]);
        assert_eq!(w.tier, ConsequenceTier::SingleTap);
        assert!(!w.can_move_funds);
        assert!(w.sentence.contains("login challenge"));
        assert!(w.sentence.contains("can't move funds"));
        assert_eq!(w.peer_device, "Tiago's ThinkPad");
    }

    #[test]
    fn transfer_is_explicit_review_and_moves_funds() {
        let t = TransferIntent {
            to_address: "bloch1qdead".into(),
            amount: 1000,
            fee: 1,
            chain: Chain::Mainnet,
            nonce: [9u8; 32],
        };
        let w = render(&SignPayload::Transfer(t), "peer", session(), &[2u8; 32]);
        assert_eq!(w.tier, ConsequenceTier::ExplicitReview);
        assert!(w.can_move_funds);
        assert!(w.sentence.contains("1000 coins"));
    }

    #[test]
    fn replay_guard_rejects_stale_counter_replayed_nonce_and_wrong_session() {
        let mut guard = ReplayGuard::new(session());
        let req = SignRequest {
            session_id: session(),
            req_nonce: [5u8; 32],
            counter: 1,
            payload: SignPayload::Login(login()).encode(),
        };
        assert!(guard.check(&req).is_ok());
        guard.commit(&req);

        // Identical replay (same counter, same nonce) → the non-advancing counter
        // is the first tripwire.
        assert!(matches!(guard.check(&req), Err(ProtocolError::StaleCounter { .. })));

        // Advancing counter but REUSED nonce → caught by the nonce set.
        let nonce_reuse = SignRequest { req_nonce: [5u8; 32], counter: 2, ..req.clone() };
        assert_eq!(guard.check(&nonce_reuse), Err(ProtocolError::ReplayedNonce));

        // Fresh nonce but non-advancing counter → stale.
        let stale = SignRequest { req_nonce: [6u8; 32], counter: 1, ..req.clone() };
        assert!(matches!(guard.check(&stale), Err(ProtocolError::StaleCounter { .. })));

        // Right shape but wrong session → out of session.
        let other = SignRequest { session_id: [8u8; 16], req_nonce: [7u8; 32], counter: 2, ..req.clone() };
        assert_eq!(guard.check(&other), Err(ProtocolError::WrongSession));
    }

    #[test]
    fn undecodable_payload_fails_closed() {
        assert!(matches!(
            SignPayload::decode(b"not json"),
            Err(ProtocolError::UndecodablePayload(_))
        ));
    }

    #[test]
    fn frame_roundtrip_and_cap() {
        let f = channel::frame(b"hello").unwrap();
        assert_eq!(channel::deframe(&f).unwrap(), b"hello");
        assert!(channel::frame(&vec![0u8; channel::MAX_FRAME_LEN + 1]).is_err());
        assert!(channel::deframe(b"XXXXbad").is_err());
    }

    #[test]
    fn grant_is_fail_closed_and_never_covers_transfers() {
        let mut g = ApprovalGrant::new(
            "Tiago's ThinkPad",
            GrantScope::LoginTo { org: "acme".into() },
            2_000,
        );
        assert!(g.allows_login("Tiago's ThinkPad", "acme", 1_000));
        assert!(!g.allows_login("Tiago's ThinkPad", "other-org", 1_000)); // wrong org
        assert!(!g.allows_login("other-laptop", "acme", 1_000)); // wrong peer
        assert!(!g.allows_login("Tiago's ThinkPad", "acme", 3_000)); // expired
        g.revoke();
        assert!(!g.allows_login("Tiago's ThinkPad", "acme", 1_000)); // revoked
    }
}
