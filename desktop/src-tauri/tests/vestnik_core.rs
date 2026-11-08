// SPDX-License-Identifier: MIT OR Apache-2.0
//! Integration tests for the desktop Vestnik backend (src/vestnik.rs), driven
//! through the `bloch_desktop` library facade (src/lib.rs) — the same
//! disclosed dual-compile pattern as tests/courier_core.rs / tests/keys_core.rs.
//! No Tauri app is spun up, and — deliberately — NO homeserver, NO account,
//! and NO network: this exercises ONLY postern-messenger's default native
//! Megolm channel run in-process (the federated matrix-rust-sdk path is OFF).
//! Passing here is a LOGIC claim about the real vodozemac Megolm round trip,
//! never a live-messaging or PQ claim. Everything under test is UNAUDITED,
//! pre-mainnet.

use bloch_desktop::vestnik::{create_channel_impl, tier_badge, DEMO_PICKLE_KEY, HONESTY};

#[test]
fn create_channel_encrypt_decrypt_roundtrips_real_megolm() {
    let (mut ch, session_id, session_key) = create_channel_impl().expect("create channel");
    assert!(!session_id.is_empty(), "outbound session id must be set");
    assert!(!session_key.is_empty(), "outbound session key must be exported");

    // Real Megolm: the ciphertext is not the plaintext, and the loopback-to-
    // self inbound session (registered on create) decrypts it back verbatim.
    let frame = ch.encrypt(b"meet at the drop, 0200").expect("encrypt");
    assert_eq!(frame.session_id, session_id);
    assert_ne!(frame.ciphertext.as_bytes(), b"meet at the drop, 0200");

    let dec = ch.decrypt(&frame).expect("decrypt");
    assert_eq!(dec.plaintext, b"meet at the drop, 0200");
    assert_eq!(dec.message_index, 0);
    assert_eq!(dec.session_id, session_id);
}

#[test]
fn ratchet_advances_and_replays_fail_closed() {
    let (mut ch, _id, _key) = create_channel_impl().expect("create channel");
    let f0 = ch.encrypt(b"first").expect("encrypt 0");
    let f1 = ch.encrypt(b"second").expect("encrypt 1");
    assert_eq!(ch.decrypt(&f0).expect("decrypt 0").message_index, 0);
    assert_eq!(ch.decrypt(&f1).expect("decrypt 1").message_index, 1);
    // Replaying an already-seen frame is rejected (the crate's persisted
    // seen-set), never a silent re-accept.
    assert!(ch.decrypt(&f0).is_err(), "replayed frame must be rejected");
}

#[test]
fn honesty_text_and_tier_badge_hold_the_line() {
    for needle in ["UNAUDITED", "no homeserver", "classical", "NOT post-quantum", "out-of-band"] {
        assert!(HONESTY.contains(needle), "honesty text lost '{needle}'");
    }
    assert_eq!(tier_badge(), "E2EE (Postern)");
    // The placeholder at-rest key is a fixed, non-secret demo constant — the
    // honest gate is that PQ-vault custody is not yet wired into the desktop.
    assert_eq!(DEMO_PICKLE_KEY, [0x5a; 32]);
}
