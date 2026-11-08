// SPDX-License-Identifier: MIT OR Apache-2.0
//! # postern-interop-test — the desktop⟷phone "one wire" proof (scaffold)
//!
//! This crate does not ship any product surface. It is the executable proof that
//! the **desktop terminal** and the **phone signer**, now that both CONSUME the
//! same two shipped crates, actually interoperate:
//!
//! - [`postern_pairing`] — the QR-pinned ephemeral anchor, the **KEM-bound** SAS
//!   (the real MITM tripwire), and the forward-secret, replay-guarded `Channel`.
//! - [`postern_signer_protocol`] — the `SignRequest`/`Approval` wire types and the
//!   `DesktopRequester` / `PhoneApprover` roles.
//! - [`postern_mobile_signer`] — the phone's REAL `WalletCoreSigner` (hybrid
//!   Falcon‖ML-DSA) and the `PairedSignerChannel` bridge (seal→transport→open).
//!
//! The [`harness`] pairs a desktop and a phone over `postern-pairing`'s in-memory
//! loopback transport (running the actual ML-KEM-1024‖X25519 handshake), then the
//! tests drive a wallet-login request → approve+sign → **verify** round-trip.
//!
//! RAILS: the desktop holds NO key; the wallet key never crosses the wire (only
//! the signature/approval does); QR + KEM-SAS are mandatory + fail-closed; software
//! signing in RAM is NOT a hardware wallet; UNAUDITED scaffold; BLCH is not a
//! security. Community mobile edition is "Postern for postmarketOS — community
//! edition", never "Postern OS"; the assurance name is never "BABA YAGA".

/// A deterministic wallet seed for the phone in these tests (>= 32 bytes). The
/// `WalletCore` derives the same address/key from it every run (golden invariant).
pub const PHONE_SEED: [u8; 32] = [9u8; 32];

/// The desktop is keyless — it TOFU-advertises this constant as its "terminal
/// identity" (the real per-session auth is the QR-pinned anchor + KEM-SAS). Kept
/// byte-identical to `desktop/src-tauri/src/pairing.rs`.
pub const DESKTOP_KEYLESS_IDENTITY: &[u8] = b"postern-desktop:keyless:v1";

/// The peer-device label the phone shows on its WYSIWYS card.
pub const DESKTOP_LABEL: &str = "Tiago's ThinkPad";

/// Pair a desktop and a phone over the loopback transport and hand back the two
/// live, mutually-authenticated `PairedSignerChannel`s (desktop end, phone end)
/// plus the shared 16-byte protocol session id and the phone's public key.
pub mod harness {
    use postern_mobile_signer::{PairedSignerChannel, WalletCoreSigner};
    use postern_pairing::transport::{LoopbackPair, LoopbackTransport};
    use postern_pairing::Pairing;
    use postern_signer_protocol::{SessionId, WalletSigner};

    /// The paired, ready-to-talk endpoints from one ceremony.
    pub struct Paired {
        pub desktop: PairedSignerChannel<LoopbackTransport>,
        pub phone: PairedSignerChannel<LoopbackTransport>,
        pub session_id: SessionId,
        pub phone_public_key: Vec<u8>,
    }

    /// Run the WHOLE pairing ceremony (real hybrid KEM + agreed SAS + fail-closed
    /// human confirm) and bridge both agreed channels onto a loopback transport.
    ///
    /// The phone's identity pinned by the desktop (TOFU) is the wallet's real
    /// public key, so the pin binds to the signing identity.
    pub fn pair_over_loopback(seed: &[u8]) -> Paired {
        // The phone's wallet signer (real WalletCore) — its public key is the
        // identity the desktop pins TOFU. Callers rebuild the signer from the same
        // seed (deterministic) when they need to actually sign.
        let signer = WalletCoreSigner::from_seed_bytes(seed, true).expect("wallet from seed");
        let phone_identity = signer.public_key_bytes();

        // 1) Desktop emits the QR (fresh ephemeral anchor + nonce).
        let (desk_pending, qr) = Pairing::begin_desktop(
            "phone",
            "lan:loopback",
            super::DESKTOP_KEYLESS_IDENTITY.to_vec(),
        );

        // 2) Phone scans it, runs the hybrid KEM, derives the SAS, and replies.
        let (phone_confirm, init) =
            Pairing::scan_desktop_qr(&qr, super::DESKTOP_LABEL, phone_identity.clone())
                .expect("phone scans desktop QR");

        // 3) Desktop accepts the reply and derives the SAME session key → SAME SAS.
        let desk_confirm = desk_pending.accept(&init).expect("desktop accepts init");
        assert_eq!(
            phone_confirm.sas().digits(),
            desk_confirm.sas().digits(),
            "KEM-bound SAS MUST agree on both screens (no MITM)"
        );

        // 4) The human confirms on both screens (fail-closed gate) → records + channels.
        let (_phone_rec, phone_ch) =
            phone_confirm.confirm_sas(true).expect("phone confirms SAS");
        let (_desk_rec, desk_ch) = desk_confirm.confirm_sas(true).expect("desktop confirms SAS");

        // 5) Bridge each agreed channel onto a loopback transport (seal↔open).
        let (desk_tx, phone_tx) = LoopbackPair::new();
        let desktop = PairedSignerChannel::new(desk_ch, desk_tx);
        let phone = PairedSignerChannel::new(phone_ch, phone_tx);

        // Both ends derive the same 16-byte protocol session id from the pairing.
        let session_id = desktop.protocol_session_id();
        assert_eq!(
            session_id,
            phone.protocol_session_id(),
            "both ends must agree on the protocol session id"
        );

        Paired { desktop, phone, session_id, phone_public_key: phone_identity }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use postern_consiglio_auth::Challenge;
    use postern_mobile_signer::{
        MobileSigner, PresenceMethod, PresenceProof, Tier, WalletCoreSigner,
    };
    use postern_signer_protocol::channel::{deframe, Channel as ProtocolChannel};
    use postern_signer_protocol::{
        loopback, DesktopRequester, LoginChallenge, PhoneApprover, SignPayload, SignRequest,
    };

    fn login_challenge() -> LoginChallenge {
        LoginChallenge {
            org: "acme".into(),
            user: "alice".into(),
            nonce: [3u8; 32],
            issued_at: 1_752_000_000,
        }
    }

    // ── (a) BYTE-IDENTITY ──────────────────────────────────────────────────────

    /// RE-PINNED byte-identity golden: the ONE wire, committed. The desktop
    /// terminal composes the pinned `SignRequest` to the exact golden bytes, and
    /// the phone signer (real `MobileSigner`) consumes the exact golden FRAME to the
    /// expected WYSIWYS with the golden nonce. Both ends reference the single
    /// `postern_signer_protocol::golden` fixture, so this crate's "one wire" claim
    /// is backed by a committed vector, not just a round-trip.
    #[test]
    fn one_wire_is_byte_identical_to_the_pinned_golden() {
        use postern_signer_protocol::golden;

        // Desktop-composed side: the pinned SignRequest serializes + frames to the
        // exact golden bytes.
        let body = serde_json::to_vec(&golden::sign_request()).unwrap();
        assert_eq!(body, hex_decode(golden::GOLDEN_SIGNREQUEST_BODY_HEX));
        let framed = postern_signer_protocol::channel::frame(&body).unwrap();
        assert_eq!(framed, hex_decode(golden::GOLDEN_SIGNREQUEST_FRAME_HEX));

        // Phone side: the REAL MobileSigner consumes that exact golden frame and
        // renders the expected single-tap login prompt, nonce bound to the golden.
        let mut ms = MobileSigner::new(
            WalletCoreSigner::from_seed_bytes(&PHONE_SEED, true).unwrap(),
            golden::GOLDEN_SESSION_ID,
            DESKTOP_LABEL,
        );
        let prompt = ms.receive_frame(&framed).unwrap();
        assert_eq!(prompt.tier, Tier::SingleTap);
        assert!(!prompt.can_move_funds);
        assert!(prompt.sentence.contains("login challenge"));
        assert_eq!(hex_decode(&prompt.req_nonce_hex), golden::GOLDEN_REQ_NONCE.to_vec());
    }

    /// The exact `SignRequest` bytes the desktop composes decode, byte-for-byte,
    /// into the same request on the phone, and carry the same login digest — which
    /// is itself byte-identical to a consiglio-auth wallet-login transcript.
    #[test]
    fn desktop_signrequest_bytes_are_byte_identical_on_the_phone() {
        let challenge = login_challenge();
        let session: postern_signer_protocol::SessionId = [7u8; 16];

        // Desktop composes + sends over the (unsealed) protocol loopback so we can
        // capture the raw request frame exactly as it goes on the wire.
        let (mut desk, mut phone) = loopback();
        let mut requester = DesktopRequester::new(session);
        let sent = requester.request_login(&mut desk, &challenge).unwrap();
        let request_frame = phone.recv().unwrap();

        // The raw signer-protocol frame → the SignRequest. Re-serializing the
        // decoded struct reproduces the IDENTICAL body bytes (stable serde wire).
        let body = deframe(&request_frame).unwrap();
        let decoded: SignRequest = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            serde_json::to_vec(&decoded).unwrap(),
            body,
            "the desktop-composed SignRequest bytes must round-trip byte-identically"
        );

        // The payload decodes to the SAME login and the SAME signed digest.
        let payload = SignPayload::decode(&decoded.payload).unwrap();
        assert_eq!(payload, SignPayload::Login(challenge.clone()));
        assert_eq!(payload.signing_digest(), challenge.signing_digest());
        assert_eq!(sent.expected_digest, challenge.signing_digest());

        // And postern-mobile-signer decodes THOSE EXACT bytes into a WYSIWYS login
        // prompt (single-tap, cannot move funds) — the phone parses the actual bytes.
        let mut ms = MobileSigner::new(
            WalletCoreSigner::from_seed_bytes(&PHONE_SEED, true).unwrap(),
            session,
            DESKTOP_LABEL,
        );
        let prompt = ms.receive_frame(&request_frame).unwrap();
        assert_eq!(prompt.tier, Tier::SingleTap);
        assert!(!prompt.can_move_funds);
        assert!(prompt.sentence.contains("login challenge"));
        assert_eq!(prompt.peer_device, DESKTOP_LABEL);
    }

    /// The login digest the desktop signs is byte-identical to what a wallet-as-login
    /// (consiglio-auth) server verifies — `expires_at` is deliberately NOT in the
    /// transcript, so the two shapes agree.
    #[test]
    fn login_digest_is_byte_identical_to_consiglio_transcript() {
        let challenge = login_challenge();
        let consiglio = Challenge {
            org_id: challenge.org.clone(),
            user_id: challenge.user.clone(),
            nonce: challenge.nonce,
            issued_at: challenge.issued_at,
            expires_at: challenge.issued_at + 120,
        };
        assert_eq!(
            challenge.signing_digest(),
            consiglio.transcript(),
            "the signer-protocol login digest must equal the consiglio-auth transcript"
        );
    }

    // ── (b) END-TO-END LOOPBACK INTEROP ────────────────────────────────────────

    /// Full round-trip over `postern-pairing`'s loopback transport: desktop pairs
    /// (real KEM + SAS) → requests a login signature → postern-mobile-signer's
    /// PhoneApprover (real WalletCore) approves + signs → the desktop matches the
    /// approval and VERIFIES the hybrid Falcon‖ML-DSA signature over the SAME login
    /// transcript. This is the proof the two ends now speak one wire.
    #[test]
    fn full_loopback_pairs_requests_signs_and_desktop_verifies() {
        let mut paired = harness::pair_over_loopback(&PHONE_SEED);
        let challenge = login_challenge();

        // Desktop side: compose + send the login request (seals over the paired
        // channel, ships over the loopback transport).
        let mut requester = DesktopRequester::new(paired.session_id);
        let sent = requester.request_login(&mut paired.desktop, &challenge).unwrap();

        // Phone side: the REAL WalletCore signer behind the protocol's PhoneApprover.
        let signer = WalletCoreSigner::from_seed_bytes(&PHONE_SEED, true).unwrap();
        let mut approver = PhoneApprover::new(signer, paired.session_id, DESKTOP_LABEL);

        // Receive (opens the sealed frame, runs the replay guard, decodes WYSIWYS).
        let pending = approver.receive(&mut paired.phone).unwrap();
        assert!(pending.is_single_tap(), "a login is the single-tap tier");
        assert!(pending.wysiwys.sentence.contains("login"));
        assert!(!pending.wysiwys.can_move_funds);

        // Approve + sign (seals the Approval back over the paired channel).
        let _approval_on_phone = approver.approve(&mut paired.phone, pending).unwrap();

        // Desktop matches the returned Approval to the request it sent.
        let approval = requester.recv_approval(&mut paired.desktop, &sent).unwrap();
        assert_eq!(approval.session_id, sent.session_id);
        assert_eq!(approval.req_nonce, sent.req_nonce);
        assert_eq!(approval.counter, sent.counter);
        assert_eq!(approval.payload_digest, sent.expected_digest);

        // ── F-3: the desktop VERIFIES the phone's hybrid signature over the login
        // transcript with the SAME verifier the node / consiglio server runs.
        assert_eq!(approval.public_key, paired.phone_public_key, "identity is the wallet key");
        assert!(
            bloch_crypto::crypto::verify(
                &approval.public_key,
                &sent.expected_digest,
                &approval.signature,
            ),
            "the phone's Falcon‖ML-DSA signature MUST verify over the login transcript"
        );
        // And it verifies over the challenge's own digest (byte-identity again).
        assert!(bloch_crypto::crypto::verify(
            &approval.public_key,
            &challenge.signing_digest(),
            &approval.signature,
        ));
    }

    /// The wallet key never appears on the wire: neither the sealed request frame
    /// nor the sealed approval frame contains the seed or the secret key bytes.
    #[test]
    fn the_wallet_key_never_crosses_the_wire() {
        // The full-flow above rides sealed frames; here we re-run the UNSEALED
        // protocol frames (a strictly larger attack surface than the sealed ones)
        // and confirm no key material is present even in plaintext.
        let (_pk, sk) = bloch_crypto::crypto::generate_keypair_from_seed(&PHONE_SEED).unwrap();

        let (mut desk, mut phone) = loopback();
        let mut requester = DesktopRequester::new([7u8; 16]);
        requester.request_login(&mut desk, &login_challenge()).unwrap();
        let request_frame = phone.recv().unwrap();

        let mut ms = MobileSigner::new(
            WalletCoreSigner::from_seed_bytes(&PHONE_SEED, true).unwrap(),
            [7u8; 16],
            DESKTOP_LABEL,
        );
        let prompt = ms.receive_frame(&request_frame).unwrap();
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&hex_decode(&prompt.req_nonce_hex));
        let presence = PresenceProof::granted(nonce, PresenceMethod::Biometric);
        let approval_frame = ms.approve(presence).unwrap();

        assert!(!contains(&request_frame, &sk), "request frame leaks the secret key");
        assert!(!contains(&approval_frame, &sk), "approval frame leaks the secret key");
        assert!(!contains(&request_frame, &PHONE_SEED), "request frame leaks the seed");
        assert!(!contains(&approval_frame, &PHONE_SEED), "approval frame leaks the seed");
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty()
            && needle.len() <= haystack.len()
            && haystack.windows(needle.len()).any(|w| w == needle)
    }
}
