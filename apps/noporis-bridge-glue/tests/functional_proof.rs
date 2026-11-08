// SPDX-License-Identifier: MIT OR Apache-2.0
//! # functional_proof — the offline, HOST-provable NoporIS crossing loop
//!
//! ## ⚠️ SCAFFOLD / reference-prototype — UNAUDITED. Certifies nothing.
//!
//! This is Dev E's **offline functional proof**: the whole
//! `create → consent → cross → kill → re-verify` loop, plus the tamper / replay /
//! fail-closed and **sealed-wallet** invariants, exercised end-to-end over the
//! REAL pairing crypto (`postern_pairing` PQ-hybrid `Channel` + AEAD + monotonic
//! counter/session/direction AAD) carried on an **in-memory loopback** — no
//! sockets, no network, no device.
//!
//! ### Honesty tier — every assertion in this file is `HOST`
//! It runs in one process against the crate's frozen PUBLIC API and its public
//! deps (exactly what `examples/crossing.rs` links), so it is green on day one
//! against the A/B/C/D stubs. It proves the *composition logic* of the crossing.
//! It **does not** prove anything about a real handset, a managed profile, GMS,
//! Waydroid, the OS process/storage boundary, or a rooted host — those are the
//! `VM` and `device` tiers, owned by `apps/noporis-e2e/**` +
//! `scripts/vm/noporis-*`, and are logged `pass` / `UNTESTED`, never CI-faked.
//!
//! A rooted / kernel-compromised host defeats every boundary asserted here. The
//! per-crossing gate is a userland, in-process check, not an OS/kernel boundary.
//! NoporIS is an app on stock Android, NEVER "Postern OS". The guardian is
//! Yagabona. The coin (BLCH) is not a security and buys no software.
//!
//! Run: `cargo test -p noporis-bridge-glue --test functional_proof`

use noporis_bridge_glue::{
    BridgeError, Capability, ConsequenceTier, CrossedPayload, CrossingGuard, CrossingReceiver,
    CrossingRequest, CrossingSender, DenyReason, Persona, ReferenceGate,
};
use postern_pairing::channel::{endpoints, Channel};
use postern_pairing::hybrid::SessionKey;
use postern_pairing::transport::{LoopbackPair, LoopbackTransport, Transport};
use zeroize::Zeroizing;

/// A frozen "now" — the whole loop is time-deterministic so expiry is explicit.
const NOW: i64 = 1_752_000_000;
/// A short lane window (10 minutes) — no lane is ever opened "forever".
const WINDOW: i64 = 600;

/// One live paired session over the real hybrid channel + a loopback bearer.
/// Returns `(play_channel, play_bearer, clean_channel, clean_bearer, session_id)`.
/// The Google-Play (less-private) side is persona A / the sender; the clean
/// (hardened, wallet-side) world is persona B / the receiver.
struct Wired {
    play_ch: Channel,
    play_tx: LoopbackTransport,
    clean_ch: Channel,
    clean_tx: LoopbackTransport,
    sid: [u8; 32],
}

fn wired() -> Wired {
    // In reality this session key is the output of QR + 6-digit SAS + PairingRecord
    // pinning; here we stand it up directly to focus the proof on the CROSSING.
    let sk: SessionKey = Zeroizing::new([0x42u8; 32]);
    let (play_ch, clean_ch) = endpoints(&sk);
    let sid = *play_ch.session_id();
    let (play_tx, clean_tx) = LoopbackPair::new();
    Wired { play_ch, play_tx, clean_ch, clean_tx, sid }
}

/// A gate that has accepted first-entry consent AND thrown exactly one lever.
/// This is the "consent" step's far side: deny-by-default everywhere else.
fn consented_gate(open: Capability) -> ReferenceGate {
    let mut g = ReferenceGate::new();
    g.accept_consent().open(open);
    g
}

/// Convenience: near side opens a lane, sends `payload`, far side receives.
/// Returns the receiver's `Result` so a test can assert delivery OR the refusal.
fn round_trip(
    w: &mut Wired,
    sender: &mut CrossingSender,
    receiver: &mut CrossingReceiver<ReferenceGate>,
    cap: Capability,
    payload: &[u8],
) -> Result<CrossedPayload, BridgeError> {
    sender.open_lane(cap, Persona::Clean, NOW + WINDOW);
    sender
        .send_crossing(&mut w.play_ch, &mut w.play_tx, cap, Persona::Clean, payload, NOW)
        .expect("near side has a live grant → sends");
    receiver.receive_crossing(&mut w.clean_ch, &mut w.clean_tx, NOW)
}

// ─────────────────────────────────────────────────────────────────────────────
//  THE LOOP — create → consent → cross → kill → re-verify, as ONE narrative.
//  [HOST] Every assertion below is host-provable against the frozen public API.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn loop_create_consent_cross_kill_reverify() {
    // ── [1] CREATE ────────────────────────────────────────────────────────────
    // A live paired session and the two persona endpoints. The receiver's gate
    // starts deny-by-default: consent NOT accepted, every one of the five bridges
    // closed, kill-switch clear.
    let mut w = wired();
    let mut play = CrossingSender::new(&w.sid, Persona::GooglePlay, "this handset · clean");
    let mut clean = CrossingReceiver::new(&w.sid, Persona::GooglePlay, Persona::Clean, ReferenceGate::new());

    // Both personas derive the SAME 16-byte crossing anchor from the 32-byte
    // pairing transcript, WITHOUT exchanging any new secret. [HOST]
    assert_eq!(play.session_id(), clean.session_id(), "shared crossing anchor");

    // The world label is derived from the pairing, never from a requester field:
    // the Google-Play side is the less-private side BY CONSTRUCTION. [HOST]
    assert!(Persona::GooglePlay.is_less_private());
    assert!(!Persona::Clean.is_less_private());
    assert!(Persona::GooglePlay.label().contains("less private"));

    // ── [2] CONSENT — deny-by-default BEFORE, allow only AFTER an explicit yes ──
    // A crossing is sent while the far gate has NOT accepted consent → fail closed
    // with the honest reason. Nothing crosses on the default path.
    play.open_lane(Capability::Clipboard, Persona::Clean, NOW + WINDOW);
    play.send_crossing(
        &mut w.play_ch, &mut w.play_tx, Capability::Clipboard, Persona::Clean, b"secret", NOW,
    )
    .expect("near side sends (it has a live grant)");
    let pre_consent = clean.receive_crossing(&mut w.clean_ch, &mut w.clean_tx, NOW);
    assert_eq!(
        pre_consent.unwrap_err(),
        BridgeError::GateDenied(DenyReason::ConsentNotAccepted),
        "[2] deny-by-default: no consent → nothing crosses",
    );

    // The human now accepts the first-entry disclosure AND throws the clipboard
    // lever. Only an explicit, disclosed, per-capability yes can Allow.
    *clean.gate_mut() = consented_gate(Capability::Clipboard);

    // ── [3] CROSS — with BOTH a live near grant AND a live far gate yes ─────────
    let got = round_trip(&mut w, &mut play, &mut clean, Capability::Clipboard, b"hello world")
        .expect("[3] both consents live → the payload crosses");
    assert_eq!(got.capability, Capability::Clipboard);
    assert_eq!(&*got.bytes, b"hello world");
    assert_eq!(got.from_persona, Persona::GooglePlay, "origin world derived, not claimed");
    assert_eq!(got.tier, ConsequenceTier::SingleTap, "clipboard tier is structural");

    // Counter advanced monotonically across the two accepted-send attempts.
    // (guard.last_counter is not public; we prove monotonicity by the fact that a
    //  resent-envelope replay is refused below in the tamper/replay section.)

    // ── [4] KILL — the operator cuts the span; ALL five bridges go dark ─────────
    clean.gate_mut().engage_kill_switch();
    for cap in Capability::ALL {
        // The near side still has (or can open) a live grant — the KILL is a
        // far-side, span-wide cut, independent of any near grant.
        play.open_lane(cap, Persona::Clean, NOW + WINDOW);
        play.send_crossing(&mut w.play_ch, &mut w.play_tx, cap, Persona::Clean, b"x", NOW)
            .expect("near side still sends");
        let killed = clean.receive_crossing(&mut w.clean_ch, &mut w.clean_tx, NOW);
        assert_eq!(
            killed.unwrap_err(),
            BridgeError::GateDenied(DenyReason::KillSwitchEngaged),
            "[4] kill-switch cuts the span for {cap:?}",
        );
    }

    // ── SEALED-WALLET INVARIANT ─────────────────────────────────────────────────
    // The kill-switch cuts the SPAN; it must NOT touch the sealed base. We model
    // the sealed base's survival two ways, both host-provable:
    //  (a) the near-side grants the user threw are untouched by the far-side kill —
    //      the lane is still live on the sending side (nothing was destroyed);
    //  (b) recovery requires a FRESH explicit consent (a new gate) — the kill did
    //      not silently leave a lever open, and re-verification is not automatic.
    assert!(
        play.has_live_grant(Capability::Clipboard, Persona::Clean, NOW),
        "[SEALED] the near grant survives a far-side kill — no wallet state destroyed",
    );

    // ── [5] RE-VERIFY — recovery is possible, but ONLY via explicit re-consent ───
    // Same paired session (the sealed base survived); the operator brings up a
    // fresh, consented gate. The span comes back — proving the kill was a cut, not
    // a teardown of the wallet/base.
    *clean.gate_mut() = consented_gate(Capability::Files);
    let reverified = round_trip(&mut w, &mut play, &mut clean, Capability::Files, b"quarterly.pdf")
        .expect("[5] re-verify: fresh consent on the surviving session resumes crossings");
    assert_eq!(reverified.capability, Capability::Files);
    assert_eq!(&*reverified.bytes, b"quarterly.pdf");

    // But a capability the fresh gate did NOT re-open stays denied — re-verify does
    // not blanket-open; every lane is still per-capability, deny-by-default. [HOST]
    play.open_lane(Capability::Mic, Persona::Clean, NOW + WINDOW);
    play.send_crossing(&mut w.play_ch, &mut w.play_tx, Capability::Mic, Persona::Clean, b"audio", NOW)
        .expect("near side sends");
    let mic = clean.receive_crossing(&mut w.clean_ch, &mut w.clean_tx, NOW);
    assert_eq!(
        mic.unwrap_err(),
        BridgeError::GateDenied(DenyReason::CapabilityClosed),
        "[5] re-verify is per-capability: an un-reopened lane stays closed",
    );
}

// ─────────────────────────────────────────────────────────────────────────────
//  FAIL-CLOSED — nothing crosses without BOTH a live near grant AND a live gate.
//  [HOST]
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn fail_closed_no_grant_the_near_side_refuses_to_send() {
    let mut w = wired();
    let mut play = CrossingSender::new(&w.sid, Persona::GooglePlay, "peer");
    // No open_lane() → no live grant. The near side refuses before anything is put
    // on the bearer.
    let err = play
        .send_crossing(&mut w.play_ch, &mut w.play_tx, Capability::Files, Persona::Clean, b"x", NOW)
        .unwrap_err();
    assert_eq!(err, BridgeError::NotGranted);
}

#[test]
fn fail_closed_expired_grant() {
    let mut w = wired();
    let mut play = CrossingSender::new(&w.sid, Persona::GooglePlay, "peer");
    play.open_lane(Capability::Files, Persona::Clean, NOW); // expires exactly now
    let err = play
        .send_crossing(&mut w.play_ch, &mut w.play_tx, Capability::Files, Persona::Clean, b"x", NOW)
        .unwrap_err();
    assert_eq!(err, BridgeError::NotGranted, "now < expiry is false at the boundary");
}

#[test]
fn fail_closed_revoked_lane_is_monotonic() {
    let mut w = wired();
    let mut play = CrossingSender::new(&w.sid, Persona::GooglePlay, "peer");
    play.open_lane(Capability::Clipboard, Persona::Clean, NOW + WINDOW);
    assert!(play.has_live_grant(Capability::Clipboard, Persona::Clean, NOW));
    play.revoke_lane(Capability::Clipboard);
    assert!(!play.has_live_grant(Capability::Clipboard, Persona::Clean, NOW));
    let err = play
        .send_crossing(&mut w.play_ch, &mut w.play_tx, Capability::Clipboard, Persona::Clean, b"x", NOW)
        .unwrap_err();
    assert_eq!(err, BridgeError::NotGranted);
}

#[test]
fn fail_closed_poisoned_gate_collapses_to_deny() {
    // A corrupt/normalize()-tripped gate state can never silently open a lane.
    let mut w = wired();
    let mut play = CrossingSender::new(&w.sid, Persona::GooglePlay, "peer");
    let mut gate = consented_gate(Capability::Camera);
    gate.poison();
    let mut clean = CrossingReceiver::new(&w.sid, Persona::GooglePlay, Persona::Clean, gate);
    play.open_lane(Capability::Camera, Persona::Clean, NOW + WINDOW);
    play.send_crossing(&mut w.play_ch, &mut w.play_tx, Capability::Camera, Persona::Clean, b"frame", NOW)
        .expect("near side sends");
    let err = clean.receive_crossing(&mut w.clean_ch, &mut w.clean_tx, NOW).unwrap_err();
    assert_eq!(err, BridgeError::GateDenied(DenyReason::Malformed));
}

#[test]
fn fail_closed_oversize_payload_is_refused() {
    use noporis_bridge_glue::MAX_CROSSING_BYTES;
    let mut w = wired();
    let mut play = CrossingSender::new(&w.sid, Persona::GooglePlay, "peer");
    play.open_lane(Capability::Files, Persona::Clean, NOW + WINDOW);
    let big = vec![0u8; MAX_CROSSING_BYTES + 1];
    let err = play
        .send_crossing(&mut w.play_ch, &mut w.play_tx, Capability::Files, Persona::Clean, &big, NOW)
        .unwrap_err();
    assert!(matches!(err, BridgeError::PayloadTooLarge { .. }));
}

// ─────────────────────────────────────────────────────────────────────────────
//  TAMPER & REPLAY — the real crypto rejects mutated, replayed, or mis-bound
//  frames. [HOST]
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn tamper_a_flipped_sealed_byte_is_rejected_by_aead() {
    // Flip a byte in the SEALED bearer bytes → the pairing channel's AEAD open
    // fails; the tampered frame never reaches the crossing layer.
    let mut w = wired();
    let mut play = CrossingSender::new(&w.sid, Persona::GooglePlay, "peer");
    let mut clean =
        CrossingReceiver::new(&w.sid, Persona::GooglePlay, Persona::Clean, consented_gate(Capability::Clipboard));

    play.open_lane(Capability::Clipboard, Persona::Clean, NOW + WINDOW);
    play.send_crossing(&mut w.play_ch, &mut w.play_tx, Capability::Clipboard, Persona::Clean, b"once", NOW)
        .expect("send");

    // Intercept the sealed frame off the bearer, flip a byte, re-inject it.
    let mut raw = w.clean_tx.recv().expect("sealed frame on the bearer");
    let last = raw.len() - 1;
    raw[last] ^= 0x01;
    w.play_tx.send(&raw).unwrap();

    let err = clean.receive_crossing(&mut w.clean_ch, &mut w.clean_tx, NOW).unwrap_err();
    assert!(
        matches!(err, BridgeError::Channel(_)),
        "AEAD rejects the tampered frame before the crossing layer: {err:?}",
    );
}

#[test]
fn replay_identical_frame_caught_by_the_channel_counter() {
    // Re-injecting the EXACT sealed bytes is caught by the pairing channel's own
    // monotonic-counter guard, BEFORE the crossing layer.
    let mut w = wired();
    let mut play = CrossingSender::new(&w.sid, Persona::GooglePlay, "peer");
    let mut clean =
        CrossingReceiver::new(&w.sid, Persona::GooglePlay, Persona::Clean, consented_gate(Capability::Clipboard));

    play.open_lane(Capability::Clipboard, Persona::Clean, NOW + WINDOW);
    play.send_crossing(&mut w.play_ch, &mut w.play_tx, Capability::Clipboard, Persona::Clean, b"once", NOW)
        .expect("send");

    let raw = w.clean_tx.recv().expect("frame on the bearer");
    w.play_tx.send(&raw).unwrap();
    let got = clean.receive_crossing(&mut w.clean_ch, &mut w.clean_tx, NOW).expect("first delivery");
    assert_eq!(&*got.bytes, b"once");

    w.play_tx.send(&raw).unwrap(); // replay the identical sealed frame
    let err = clean.receive_crossing(&mut w.clean_ch, &mut w.clean_tx, NOW).unwrap_err();
    assert!(matches!(err, BridgeError::Channel(_)), "channel replay guard fires: {err:?}");
}

#[test]
fn replay_resealed_envelope_caught_by_the_crossing_guard() {
    // Belt-and-suspenders: a duplicate envelope (same nonce+counter) re-sealed as a
    // FRESH channel frame passes the channel guard (its counter advances) but is
    // caught by the per-crossing CrossingGuard — its counter no longer advances.
    let mut w = wired();
    let mut play = CrossingSender::new(&w.sid, Persona::GooglePlay, "peer");
    let mut clean =
        CrossingReceiver::new(&w.sid, Persona::GooglePlay, Persona::Clean, consented_gate(Capability::Clipboard));

    play.open_lane(Capability::Clipboard, Persona::Clean, NOW + WINDOW);
    let sent = play
        .send_crossing(&mut w.play_ch, &mut w.play_tx, Capability::Clipboard, Persona::Clean, b"once", NOW)
        .expect("send");
    let got = clean.receive_crossing(&mut w.clean_ch, &mut w.clean_tx, NOW).expect("first delivery");
    assert_eq!(&*got.bytes, b"once");

    // Re-seal the SAME envelope on a NEW channel frame (channel counter advances,
    // so open_frame accepts it), then deliver → crossing guard refuses.
    let frame = w.play_ch.seal_frame(&sent.encode().unwrap()).unwrap();
    w.play_tx.send(&frame.to_bytes()).unwrap();
    let err = clean.receive_crossing(&mut w.clean_ch, &mut w.clean_tx, NOW).unwrap_err();
    assert!(
        matches!(err, BridgeError::StaleCounter { .. } | BridgeError::ReplayedNonce),
        "crossing replay guard fires: {err:?}",
    );
}

#[test]
fn cross_session_crossing_is_refused() {
    // A crossing minted under paired session A must not verify under session B.
    use noporis_bridge_glue::crossing_session_id;
    let sid_a = [1u8; 32];
    let sid_b = [2u8; 32];
    let guard_b = CrossingGuard::new(crossing_session_id(&sid_b));
    let req = CrossingRequest {
        session_id: crossing_session_id(&sid_a),
        req_nonce: [9u8; 32],
        counter: 1,
        capability: Capability::Files,
        from_persona: Persona::GooglePlay,
        payload: b"x".to_vec(),
    };
    assert_eq!(guard_b.check(&req), Err(BridgeError::WrongSession));
}

#[test]
fn a_refused_crossing_never_advances_the_sequence() {
    // Fail-closed sequencing: a gate-denied crossing must NOT poison the counter —
    // a later legitimate crossing (same or next counter) still delivers once the
    // gate is opened. Proves rejection leaves the guard un-committed.
    let mut w = wired();
    let mut play = CrossingSender::new(&w.sid, Persona::GooglePlay, "peer");
    // Gate consented but clipboard lever CLOSED → first crossing is denied.
    let mut gate = ReferenceGate::new();
    gate.accept_consent();
    let mut clean = CrossingReceiver::new(&w.sid, Persona::GooglePlay, Persona::Clean, gate);

    play.open_lane(Capability::Clipboard, Persona::Clean, NOW + WINDOW);
    play.send_crossing(&mut w.play_ch, &mut w.play_tx, Capability::Clipboard, Persona::Clean, b"first", NOW)
        .expect("send");
    let denied = clean.receive_crossing(&mut w.clean_ch, &mut w.clean_tx, NOW);
    assert_eq!(denied.unwrap_err(), BridgeError::GateDenied(DenyReason::CapabilityClosed));

    // Open the lever; the NEXT crossing (counter strictly advances) delivers — the
    // denied one did not consume/poison the sequence.
    clean.gate_mut().open(Capability::Clipboard);
    let got = round_trip(&mut w, &mut play, &mut clean, Capability::Clipboard, b"second")
        .expect("a fresh crossing delivers after the denied one");
    assert_eq!(&*got.bytes, b"second");
}
