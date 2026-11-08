// SPDX-License-Identifier: MIT OR Apache-2.0
//! BYTE-IDENTITY GOLDEN — the desktop/protocol half.
//!
//! `src/golden.rs` pins the ONE canonical wire: a fixed [`SignRequest`] and the
//! exact serde-JSON / framed bytes the encoder must produce. This test asserts the
//! encoder (the desktop-composed side) still yields those bytes, and that decoding
//! them and re-encoding is byte-identical (so the phone half, which imports the
//! same constants in `mobile/signer/tests/golden_wire.rs`, is provably wire-equal).
//!
//! A drift here is a wire break: fix the code, or — if the change is deliberate —
//! bump the domain suffix and regenerate the golden (see `src/golden.rs`).

use postern_signer_protocol::channel::{deframe, frame};
use postern_signer_protocol::golden;
use postern_signer_protocol::{SignPayload, SignRequest};

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("golden hex decodes")
}

/// The login digest is byte-stable (the exact 32 bytes the phone signs and a
/// consiglio server verifies).
#[test]
fn login_digest_matches_golden() {
    assert_eq!(
        golden::login_challenge().signing_digest().to_vec(),
        unhex(golden::GOLDEN_LOGIN_DIGEST_HEX),
    );
}

/// The inner `SignPayload` encoding is byte-stable.
#[test]
fn sign_payload_encoding_matches_golden() {
    assert_eq!(golden::sign_payload().encode(), unhex(golden::GOLDEN_PAYLOAD_BODY_HEX));
}

/// The full `SignRequest` wire body (what the desktop composes) is byte-identical
/// to the pinned golden.
#[test]
fn signrequest_body_matches_golden() {
    let body = serde_json::to_vec(&golden::sign_request()).unwrap();
    assert_eq!(
        body,
        unhex(golden::GOLDEN_SIGNREQUEST_BODY_HEX),
        "desktop-composed SignRequest bytes drifted from the pinned wire golden"
    );
}

/// The framed request (`PSG1 ‖ len ‖ body`) is byte-identical to the golden.
#[test]
fn signrequest_frame_matches_golden() {
    let body = serde_json::to_vec(&golden::sign_request()).unwrap();
    let framed = frame(&body).unwrap();
    assert_eq!(framed, unhex(golden::GOLDEN_SIGNREQUEST_FRAME_HEX));
}

/// The DECODE side (what the phone runs): deframe → parse → re-encode reproduces
/// the exact golden body, and the decoded payload/digest match. This is the join
/// that makes the two ends provably wire-identical, not merely self-consistent.
#[test]
fn decode_then_reencode_is_byte_identical_to_golden() {
    let framed = unhex(golden::GOLDEN_SIGNREQUEST_FRAME_HEX);
    let body = deframe(&framed).unwrap();
    assert_eq!(body, unhex(golden::GOLDEN_SIGNREQUEST_BODY_HEX));

    let decoded: SignRequest = serde_json::from_slice(&body).unwrap();
    assert_eq!(decoded.session_id, golden::GOLDEN_SESSION_ID);
    assert_eq!(decoded.req_nonce, golden::GOLDEN_REQ_NONCE);
    assert_eq!(decoded.counter, golden::GOLDEN_COUNTER);

    // Re-encoding the decoded struct reproduces the identical body bytes.
    assert_eq!(serde_json::to_vec(&decoded).unwrap(), body);

    // The payload decodes to the golden login and the golden signed digest.
    let payload = SignPayload::decode(&decoded.payload).unwrap();
    assert_eq!(payload, golden::sign_payload());
    assert_eq!(payload.signing_digest().to_vec(), unhex(golden::GOLDEN_LOGIN_DIGEST_HEX));
}
