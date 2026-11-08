// SPDX-License-Identifier: MIT OR Apache-2.0
//! Integration tests for the desktop Courier backend (src/courier.rs), driven
//! through the `bloch_desktop` library facade (src/lib.rs) — the same
//! disclosed dual-compile pattern as tests/vault_core.rs. No Tauri app is
//! spun up, and — deliberately — NO network and NO Tor process: the sealed
//! bytes travel through `postern_courier::drop_transport::MockDrop`, the
//! crate's in-memory drop behind the DropSender/DropFetcher trait seam
//! (enabled here via the test-only `mock-transport` feature). The live onion
//! path stays behind that same seam in postern-courier with its own
//! `#[ignore]`d live test; passing here is a LOGIC claim, never a
//! live-anonymity claim. Everything under test is UNAUDITED, pre-mainnet.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use bloch_desktop::courier::{
    courier_generate_recipient, courier_open, courier_seal, decode_inner, encode_inner,
    open_envelope, seal_envelope, ENVELOPE_V, HONESTY,
};
use postern_courier::drop_transport::{receive_verified, MockDrop, MOCK_DROP_ADDRESS};
use postern_courier::replay::ReplayGuard;
use postern_courier::sender_auth::{generate_sender_identity, sign_sealed};
use postern_courier::{seal, CourierError, SealedPayload};
use serde_json::{json, Value};
use std::time::Duration;

fn as_str<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or_else(|| panic!("missing '{k}' in {v}"))
}

// ── the command surface: recipient → seal → MockDrop → open ────────────────

// The full path the panes drive, with the wire routed through the mock drop:
// courier_generate_recipient → courier_seal → MockDrop deliver_wire/fetch_wire
// (the trait seam's in-memory stand-in) → courier_open returns the plaintext
// and the in-seal file name.
#[test]
fn recipient_seal_mockdrop_open_round_trip() {
    let ident = courier_generate_recipient();
    let plaintext = b"the payload the pane would seal";

    let envelope = courier_seal(
        as_str(&ident, "public").to_string(),
        B64.encode(plaintext),
        Some("report.pdf".to_string()),
    )
    .expect("seal");
    assert_eq!(as_str(&envelope, "v"), ENVELOPE_V);
    assert_eq!(as_str(&envelope, "fingerprint"), as_str(&ident, "fingerprint"));

    // Route the sealed wire bytes through the MockDrop seam — single-shot
    // deliver, then fetch from the mock's out-of-band address.
    let wire = B64.decode(as_str(&envelope, "sealedB64")).unwrap();
    let drop_slot = MockDrop::new();
    drop_slot.deliver_wire(wire).expect("deliver");
    let fetched = drop_slot.fetch_wire(MOCK_DROP_ADDRESS).expect("fetch");

    // Rebuild the envelope around the fetched bytes and open it.
    let fetched_envelope = json!({ "v": ENVELOPE_V, "sealedB64": B64.encode(&fetched) });
    let out = courier_open(as_str(&ident, "secret").to_string(), fetched_envelope).expect("open");
    assert_eq!(as_str(&out, "name"), "report.pdf");
    assert_eq!(B64.decode(as_str(&out, "bytesB64")).unwrap(), plaintext);
}

// A wire blob tampered in the (mock) drop parses as a frame but fails closed
// at open — the seal, not the wire, protects the payload.
#[test]
fn tampered_wire_from_the_drop_fails_closed() {
    let ident = courier_generate_recipient();
    let envelope = courier_seal(
        as_str(&ident, "public").to_string(),
        B64.encode(b"integrity matters"),
        None,
    )
    .unwrap();

    let mut wire = B64.decode(as_str(&envelope, "sealedB64")).unwrap();
    let last = wire.len() - 1;
    wire[last] ^= 0x01; // flip one AEAD-body bit

    let drop_slot = MockDrop::new();
    drop_slot.deliver_wire(wire).unwrap();
    let fetched = drop_slot.fetch_wire(MOCK_DROP_ADDRESS).unwrap();

    let err = courier_open(
        as_str(&ident, "secret").to_string(),
        json!({ "v": ENVELOPE_V, "sealedB64": B64.encode(&fetched) }),
    )
    .unwrap_err();
    assert!(err.contains("open failed"), "unexpected error: {err}");
}

// The signed pipeline over the mock: the drop re-serves the SAME recorded
// bytes (exactly the documented "a recorded frame can be re-served verbatim"
// transport limit) and receive_verified rejects the second presentation —
// fail closed per the replay guard, not per the wire.
#[test]
fn replayed_wire_fails_closed_per_receive_verified() {
    let sender_id = generate_sender_identity();
    let rcpt = postern_courier::generate_recipient();
    let plaintext = b"one-shot verified drop";
    let sealed = seal(&rcpt.public, plaintext).unwrap();
    let signed = sign_sealed(&sender_id, &rcpt.public, &sealed);

    let drop_slot = MockDrop::new();
    drop_slot.deliver_wire(signed.to_bytes()).unwrap();
    let mut guard = ReplayGuard::new(Duration::from_secs(600));

    // First presentation passes the whole pipeline (verify → guard → open).
    let wire1 = drop_slot.fetch_wire(MOCK_DROP_ADDRESS).unwrap();
    let first = postern_courier::sender_auth::SignedSealedPayload::from_bytes(&wire1).unwrap();
    let opened = receive_verified(
        &sender_id.public,
        &rcpt.public,
        &rcpt.secret,
        &first,
        &mut guard,
        first.timestamp,
    )
    .unwrap();
    assert_eq!(opened, plaintext);

    // Second presentation: the mock replays the same recorded bytes verbatim.
    let wire2 = drop_slot.fetch_wire(MOCK_DROP_ADDRESS).unwrap();
    assert_eq!(wire1, wire2, "the mock re-serves the recorded frame verbatim");
    let second = postern_courier::sender_auth::SignedSealedPayload::from_bytes(&wire2).unwrap();
    let err = receive_verified(
        &sender_id.public,
        &rcpt.public,
        &rcpt.secret,
        &second,
        &mut guard,
        second.timestamp,
    )
    .unwrap_err();
    assert!(matches!(err, CourierError::ReplayNonceReused));
}

// ── fail-closed edges of the command surface ────────────────────────────────

#[test]
fn wrong_secret_bad_inputs_and_wrong_version_fail_closed() {
    let a = courier_generate_recipient();
    let b = courier_generate_recipient();
    let envelope =
        courier_seal(as_str(&a, "public").to_string(), B64.encode(b"secret"), None).unwrap();

    // The wrong recipient's secret cannot open it.
    assert!(courier_open(as_str(&b, "secret").to_string(), envelope.clone()).is_err());

    // Garbage base64 inputs are rejected up front.
    assert!(courier_seal("not base64!!".into(), B64.encode(b"x"), None).is_err());
    assert!(courier_seal(as_str(&a, "public").to_string(), "not base64!!".into(), None).is_err());
    assert!(courier_open("not base64!!".into(), envelope.clone()).is_err());

    // A wrong/missing envelope version tag is rejected, never mis-parsed.
    let mut wrong_v = envelope.clone();
    wrong_v["v"] = json!("postern-courier/99");
    assert!(courier_open(as_str(&a, "secret").to_string(), wrong_v).is_err());
    assert!(courier_open(as_str(&a, "secret").to_string(), json!({})).is_err());

    // A truncated wire blob is rejected.
    let short = json!({ "v": ENVELOPE_V, "sealedB64": B64.encode([1u8, 2, 3]) });
    assert!(courier_open(as_str(&a, "secret").to_string(), short).is_err());
}

// ── inner framing (the in-seal file name) ───────────────────────────────────

#[test]
fn inner_framing_round_trips_and_rejects_corruption() {
    let inner = encode_inner("наклад.pdf", b"bytes").unwrap();
    let (name, bytes) = decode_inner(&inner).unwrap();
    assert_eq!(name, "наклад.pdf");
    assert_eq!(bytes, b"bytes");

    // Empty name and empty bytes are both well-formed.
    let (name, bytes) = decode_inner(&encode_inner("", b"").unwrap()).unwrap();
    assert_eq!(name, "");
    assert!(bytes.is_empty());

    // Short header, oversize name length, and a length past the end all fail.
    assert!(decode_inner(&[1, 2]).is_err());
    let mut oversize = encode_inner("x", b"y").unwrap().to_vec();
    oversize[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(decode_inner(&oversize).is_err());
    let mut past_end = encode_inner("x", b"y").unwrap().to_vec();
    past_end[0..4].copy_from_slice(&100u32.to_le_bytes());
    assert!(decode_inner(&past_end).is_err());
    // A multi-KiB name over the cap is refused at encode time too.
    assert!(encode_inner(&"n".repeat(5000), b"y").is_err());
}

// ── mandatory honesty text on every response ────────────────────────────────

#[test]
fn every_response_carries_the_honesty_text() {
    for needle in ["UNAUDITED reference prototype", "Mock-transport tested only", "no live-anonymity claim"] {
        assert!(HONESTY.contains(needle), "HONESTY lost '{needle}'");
    }

    let ident = courier_generate_recipient();
    assert_eq!(as_str(&ident, "honesty"), HONESTY);

    let envelope = seal_envelope(as_str(&ident, "public"), "f.bin", b"x").unwrap();
    assert_eq!(as_str(&envelope, "honesty"), HONESTY);

    let out = open_envelope(as_str(&ident, "secret"), &envelope).unwrap();
    assert_eq!(as_str(&out, "honesty"), HONESTY);
}

// The pure envelope cores round-trip a SealedPayload wire blob that the
// crate itself can also parse — no private format drift.
#[test]
fn envelope_wire_is_a_plain_postern_courier_payload() {
    let ident = courier_generate_recipient();
    let envelope = seal_envelope(as_str(&ident, "public"), "n", b"payload").unwrap();
    let wire = B64.decode(as_str(&envelope, "sealedB64")).unwrap();
    // Parses as the crate's own versioned wire format.
    let parsed = SealedPayload::from_bytes(&wire).expect("crate-parseable wire");
    assert_eq!(parsed.to_bytes(), wire);
}
