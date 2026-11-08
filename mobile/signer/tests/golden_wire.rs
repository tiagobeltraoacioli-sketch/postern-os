// SPDX-License-Identifier: MIT OR Apache-2.0
//! BYTE-IDENTITY GOLDEN — the PHONE half.
//!
//! The desktop terminal and this phone signer are two implementations of one wire.
//! The single pinned reference lives in `postern-signer-protocol`'s `golden`
//! module; the desktop half checks it in that crate's `tests/golden_wire.rs`. Here
//! the PHONE implementation ([`MobileSigner`], driven by the same
//! `postern-signer-protocol` decode path) is asserted to be byte-identical to the
//! SAME constants — so the two ends are provably wire-equal, not just each
//! self-consistent.
//!
//! Feeding the exact golden request frame:
//! - the phone decodes and re-encodes it byte-identically to the golden body, and
//! - it renders the expected WYSIWYS (single-tap login, cannot move funds), with
//!   the request nonce bound to the golden nonce for per-sign presence.

use postern_mobile_signer::protocol::channel::deframe;
use postern_mobile_signer::protocol::golden;
use postern_mobile_signer::protocol::{SignPayload, SignRequest};
use postern_mobile_signer::{MobileSigner, Tier, WalletCoreSigner};

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("golden hex decodes")
}

const DESKTOP_LABEL: &str = "Tiago's ThinkPad";

/// The phone's decode/re-encode of the pinned frame is byte-identical to the
/// golden body the desktop composes — the two implementations share one wire.
#[test]
fn phone_decode_reencode_matches_desktop_golden() {
    let framed = unhex(golden::GOLDEN_SIGNREQUEST_FRAME_HEX);
    let body = deframe(&framed).unwrap();
    assert_eq!(
        body,
        unhex(golden::GOLDEN_SIGNREQUEST_BODY_HEX),
        "phone deframed a different body than the pinned desktop golden"
    );

    let decoded: SignRequest = serde_json::from_slice(&body).unwrap();
    assert_eq!(serde_json::to_vec(&decoded).unwrap(), body, "phone re-encoding drifted");
    assert_eq!(decoded.session_id, golden::GOLDEN_SESSION_ID);
    assert_eq!(decoded.req_nonce, golden::GOLDEN_REQ_NONCE);

    let payload = SignPayload::decode(&decoded.payload).unwrap();
    assert_eq!(payload, golden::sign_payload());
    assert_eq!(payload.signing_digest().to_vec(), unhex(golden::GOLDEN_LOGIN_DIGEST_HEX));
}

/// Driving the REAL `MobileSigner` with the exact golden frame yields the expected
/// WYSIWYS, and the prompt's bound request nonce is the golden nonce.
#[test]
fn mobile_signer_consumes_golden_frame_to_expected_wysiwys() {
    let framed = unhex(golden::GOLDEN_SIGNREQUEST_FRAME_HEX);
    let signer = WalletCoreSigner::from_seed_bytes(&[9u8; 32], true).unwrap();
    let mut ms = MobileSigner::new(signer, golden::GOLDEN_SESSION_ID, DESKTOP_LABEL);

    let prompt = ms.receive_frame(&framed).unwrap();
    assert_eq!(prompt.tier, Tier::SingleTap);
    assert!(!prompt.can_move_funds);
    assert!(prompt.sentence.contains("login challenge"));
    assert_eq!(prompt.peer_device, DESKTOP_LABEL);
    assert_eq!(prompt.req_nonce_hex, hex::encode(golden::GOLDEN_REQ_NONCE));
}
