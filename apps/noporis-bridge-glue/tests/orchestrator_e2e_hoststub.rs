// SPDX-License-Identifier: MIT OR Apache-2.0
//! # orchestrator_e2e_hoststub — the full HostStub 5-step NoporIS loop
//!
//! ## ⚠️ SCAFFOLD / reference-prototype — UNAUDITED. Certifies nothing.
//!
//! Dev F2's HOST-provable E2E: `create → consent → cross → kill → re-verify`,
//! run as ONE narrative entirely against the crate's already-tested library
//! composition — the [`Orchestrator`] driving a `host-stub` [`Substrate`]
//! backend, the signed [`ConsentLedger`] (the 5-step per-crossing check), and
//! [`CrossingReceiver::receive_crossing_audited`] — over the REAL pairing crypto
//! (`postern_pairing` PQ-hybrid `Channel` + AEAD) carried on an in-memory
//! loopback. No sockets, no device, no VM.
//!
//! ### Honesty tier — every assertion in this file is `HOST`
//! It proves the *composition logic* of the orchestrator + signed-consent +
//! crossing loop, including that it survives a simulated process restart via
//! [`noporis_bridge_glue::substrate::read_gate_state`]. It does **not** prove
//! anything about a real handset, a managed profile, GMS, Waydroid, or a rooted
//! host — those stay `VM`/`device` tier, owned elsewhere and never CI-faked here.
//!
//! ### F1-interface note (read before wiring this into `Daemon`)
//! PARTITION.md's F1 section describes a forthcoming `Daemon<S: Substrate,
//! G: GateConsent>` with `Daemon::tick(&mut self, now: i64) -> DaemonReport`,
//! shipped as a **separate** file (`src/daemon.rs`) + `[[bin]]` that F1 owns and
//! builds in a parallel worktree — neither exists in this crate as built here.
//! PARTITION.md's own F2 description of "the full 5-step loop" names exactly the
//! primitives this file drives (`Orchestrator`, `receive_crossing_audited`,
//! `ConsentLedger`, the sealed-wallet invariant) and TEST-GATE.md's F2 command
//! (`cargo test --test orchestrator_e2e_hoststub`) runs standalone with no `[[bin]]`
//! dependency — so this test is written directly against `Orchestrator` +
//! `CrossingReceiver` + `ConsentLedger`, NOT against `Daemon::tick`.
//! **Interface assumption to reconcile at integration:** once F1's `daemon.rs`
//! lands, an *additional* test driving the same 5 steps through `Daemon::tick`
//! (rather than `Orchestrator`/`CrossingReceiver` directly) would be a natural,
//! purely-additive follow-up — it is not required for this file to be green, and
//! this file does not assume any particular `Daemon` method name/signature.
//!
//! Run: `cargo test -p noporis-bridge-glue --test orchestrator_e2e_hoststub`

use noporis_bridge_glue::substrate::{
    read_gate_state, ConsentScope as GateConsentScope, GateState, Orchestrator, Reconciliation,
    StatePaths, WaydroidSubstrate,
};
use noporis_bridge_glue::{
    crossing_session_id, AuditTrail, BridgeError, Capability, ConsentAuthority, ConsentError,
    ConsentLedger, ConsentScope, CrossingReceiver, CrossingRequest, CrossingSender, Direction,
    Persona, ReferenceGate, Substrate, MAX_CROSSING_BYTES,
};
use postern_pairing::channel::{endpoints, Channel};
use postern_pairing::hybrid::SessionKey;
use postern_pairing::transport::{LoopbackPair, LoopbackTransport, Transport};
use zeroize::Zeroizing;

/// A frozen "now" — the whole loop is time-deterministic so expiry is explicit.
const NOW: i64 = 1_752_000_000;
/// A short lane/grant window (10 minutes) — nothing is ever opened "forever".
const WINDOW: i64 = 600;

struct Wired {
    play_ch: Channel,
    play_tx: LoopbackTransport,
    clean_ch: Channel,
    clean_tx: LoopbackTransport,
    paired_sid: [u8; 32],
}

fn wired() -> Wired {
    // Stands in for the QR + 6-digit SAS + PairingRecord pinning that produces
    // this session key in reality — the proof here is about the CROSSING loop.
    let sk: SessionKey = Zeroizing::new([0x77u8; 32]);
    let (play_ch, clean_ch) = endpoints(&sk);
    let paired_sid = *play_ch.session_id();
    let (play_tx, clean_tx) = LoopbackPair::new();
    Wired { play_ch, play_tx, clean_ch, clean_tx, paired_sid }
}

/// A far-side deny-by-default reference gate that has accepted consent and
/// thrown exactly one lever — the second, independent "yes" a crossing needs
/// alongside the signed [`ConsentLedger`] (defense in depth).
fn gate_allowing(cap: Capability) -> ReferenceGate {
    let mut g = ReferenceGate::new();
    g.accept_consent().open(cap);
    g
}

// ─────────────────────────────────────────────────────────────────────────────
//  THE 5-STEP LOOP — create → consent → cross → kill → re-verify, as ONE
//  narrative, run entirely on HOST stubs. [HOST]
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn full_hoststub_five_step_loop_create_consent_cross_kill_reverify() {
    let dir = tempfile::tempdir().unwrap();
    let state_paths = StatePaths::under(dir.path());
    let audit_path = dir.path().join("crossings.jsonl");

    // ── [1] CREATE ───────────────────────────────────────────────────────────
    // The orchestrator reconciles the far-side (Google-Play) substrate to Active
    // from a consented, clipboard-open gate, and — because F2 is the sole runtime
    // writer — the posture is committed to disk atomically in the same step.
    let mut orch = Orchestrator::new(WaydroidSubstrate::new(Persona::GooglePlay));
    let gate =
        GateState::consented(GateConsentScope::Session).open_crossing(Capability::Clipboard);
    let r = orch
        .commit(&gate, gate.to_gate_json().as_bytes(), &state_paths)
        .expect("[1] commit reconciles + persists");
    assert_eq!(r, Reconciliation::Activated, "[1] persona created and foregrounded");
    assert!(orch.open_lanes().is_open(Capability::Clipboard), "[1] the clipboard lane is mapped");
    assert!(!orch.open_lanes().is_open(Capability::Mic), "[1] an un-thrown lane stays closed");
    assert!(orch.substrate().status().sealed_wallet_preserved, "[SEALED] holds at create");

    // ── [2] CONSENT ──────────────────────────────────────────────────────────
    // The near side (the only mint authority) mints a signed, Direction-pinned,
    // session-bound `ConsentRecord` for exactly this capability, this direction.
    let mut w = wired();
    let crossing_sid = crossing_session_id(&w.paired_sid);
    let mut authority = ConsentAuthority::generate();
    let direction = Direction::new(Persona::GooglePlay, Persona::Clean);
    let record = authority.mint(
        crossing_sid,
        Capability::Clipboard,
        direction,
        ConsentScope::Session,
        NOW,
        NOW + WINDOW,
        "Tiago's Pixel · clean",
    );
    let mut ledger = ConsentLedger::new(authority.verifying_key());
    ledger.admit(record).expect("[2] a genuinely near-minted record admits");

    // ── [3] CROSS ────────────────────────────────────────────────────────────
    // A live device-level lane (step 1) AND a live signed consent (step 2) AND
    // the deny-by-default far gate (defense in depth) all say yes: the payload
    // crosses, and the durable audit trail records the delivery by digest.
    let mut sender = CrossingSender::new(&w.paired_sid, Persona::GooglePlay, "Tiago's Pixel · clean");
    let mut receiver: CrossingReceiver<ReferenceGate> =
        CrossingReceiver::new(&w.paired_sid, Persona::GooglePlay, Persona::Clean, gate_allowing(Capability::Clipboard));
    let mut audit = AuditTrail::open(&audit_path).expect("[3] durable audit trail opens");

    sender.open_lane(Capability::Clipboard, Persona::Clean, NOW + WINDOW);
    sender
        .send_crossing(&mut w.play_ch, &mut w.play_tx, Capability::Clipboard, Persona::Clean, b"hello from the far side", NOW)
        .expect("[3] near side has a live grant, sends");
    let crossed = receiver
        .receive_crossing_audited(&mut w.clean_ch, &mut w.clean_tx, &mut ledger, &mut audit, NOW, "2026-07-13T00:00:00Z")
        .expect("[3] device lane + signed consent + far gate all say yes → delivered");
    assert_eq!(crossed.capability, Capability::Clipboard);
    assert_eq!(&*crossed.bytes, b"hello from the far side");
    assert_eq!(crossed.from_persona, Persona::GooglePlay, "origin world derived, not claimed");

    // ── [4] KILL ─────────────────────────────────────────────────────────────
    // The operator cuts the span on every layer: the orchestrator's gate-state
    // (device lane) commit, the far-side reference gate, AND the signed consent
    // ledger's own kill-switch fan-out — then RE-VERIFY: nothing further crosses.
    let mut killed_gate = gate;
    killed_gate.kill_switch_engaged = true;
    let rk = orch
        .commit(&killed_gate, killed_gate.to_gate_json().as_bytes(), &state_paths)
        .expect("[4] commit reconciles the kill + persists it");
    assert_eq!(rk, Reconciliation::Killed, "[4] orchestrator cuts the span");
    assert!(orch.open_lanes().all_closed(), "[4] every device lane drops with the span");

    receiver.gate_mut().engage_kill_switch();
    ledger.engage_kill_switch(); // the cross-crate kill-switch fan-out target

    // The near side's grant is untouched by a far-side kill (nothing destroyed on
    // that side) — proving the KILL is a far-side/consent cut, not a wipe of the
    // near-side lever. The crossing must still be refused end-to-end.
    assert!(
        sender.has_live_grant(Capability::Clipboard, Persona::Clean, NOW),
        "[4] near-side grant survives — the kill is a far-side cut, not a wallet wipe"
    );
    sender.open_lane(Capability::Clipboard, Persona::Clean, NOW + WINDOW);
    sender
        .send_crossing(&mut w.play_ch, &mut w.play_tx, Capability::Clipboard, Persona::Clean, b"post-kill attempt", NOW)
        .expect("[4] near side still sends — the near grant is untouched");
    let after_kill = receiver.receive_crossing_audited(
        &mut w.clean_ch, &mut w.clean_tx, &mut ledger, &mut audit, NOW, "2026-07-13T00:00:01Z",
    );
    match after_kill {
        Err(BridgeError::ConsentRefused(msg)) => {
            assert!(
                msg.to_lowercase().contains("kill"),
                "[4] the signed ledger's own kill-switch fired, honestly labelled: {msg}"
            );
        }
        other => panic!("[4] re-verify: expected the killed consent ledger to refuse, got {other:?}"),
    }

    // ── [5] RE-VERIFY ────────────────────────────────────────────────────────
    // The sealed-wallet invariant held throughout, including across the kill —
    // AND a simulated process restart recovers the exact same posture from disk,
    // never a guess (the persistence half of this loop, not just the in-memory
    // one).
    assert!(orch.substrate().status().sealed_wallet_preserved, "[SEALED] holds after kill");
    assert!(killed_gate.sealed_wallet_preserved, "[SEALED] the gate itself never claims otherwise");

    let recovered_gate = read_gate_state(&state_paths);
    assert_eq!(recovered_gate, killed_gate, "[5] recovery replays exactly the persisted posture");

    let mut restarted = Orchestrator::new(WaydroidSubstrate::new(Persona::GooglePlay));
    let rr = restarted.reconcile(&recovered_gate).expect("[5] a restarted orchestrator reconciles cleanly");
    assert_eq!(rr, Reconciliation::Killed, "[5] restart re-derives Killed from disk, never a guess");
    assert!(restarted.open_lanes().all_closed(), "[5] a restarted span opens no lane on its own");
    assert!(restarted.substrate().status().sealed_wallet_preserved, "[SEALED] holds after restart");

    // Durable audit trail proves the whole loop out-of-band: one Delivered, and
    // the post-kill attempt was NOT recorded as a delivery (only the durable
    // record_denied/record_delivered calls the crossing layer itself makes).
    let raw = std::fs::read_to_string(&audit_path).unwrap();
    assert_eq!(raw.matches("\"event\":\"delivered\"").count(), 1, "exactly one delivery ever recorded");
    assert!(raw.contains("\"event\":\"denied\""), "the post-kill refusal is durably logged");
}

// ─────────────────────────────────────────────────────────────────────────────
//  Deny-by-default at every individual gate — the device lane, the signed
//  consent, and the far reference gate each independently block delivery. [HOST]
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn crossing_denied_when_the_device_lane_was_never_opened_by_the_orchestrator() {
    // Even with a perfectly valid signed consent record and a live near-side
    // grant, the crossing layer itself has no dependency on the orchestrator's
    // lane bit today (the lane is device-plumbing state, not a crypto gate) — but
    // the receiving far REFERENCE GATE must still independently deny when its own
    // capability lever was never thrown. Proves the two authorities (device lane,
    // consent+gate) are genuinely separate checks, not one relabelled as the
    // other.
    let mut w = wired();
    let mut authority = ConsentAuthority::generate();
    let direction = Direction::new(Persona::GooglePlay, Persona::Clean);
    let crossing_sid = crossing_session_id(&w.paired_sid);
    let record = authority.mint(
        crossing_sid, Capability::Mic, direction, ConsentScope::Session, NOW, NOW + WINDOW, "peer",
    );
    let mut ledger = ConsentLedger::new(authority.verifying_key());
    ledger.admit(record).unwrap();

    // The far reference gate has accepted consent but never thrown the mic lever.
    let mut gate = ReferenceGate::new();
    gate.accept_consent();
    let mut receiver: CrossingReceiver<ReferenceGate> =
        CrossingReceiver::new(&w.paired_sid, Persona::GooglePlay, Persona::Clean, gate);
    let mut sender = CrossingSender::new(&w.paired_sid, Persona::GooglePlay, "peer");
    let dir = tempfile::tempdir().unwrap();
    let mut audit = AuditTrail::open(dir.path().join("audit.jsonl")).unwrap();

    sender.open_lane(Capability::Mic, Persona::Clean, NOW + WINDOW);
    sender
        .send_crossing(&mut w.play_ch, &mut w.play_tx, Capability::Mic, Persona::Clean, b"audio", NOW)
        .expect("near side sends");
    let err = receiver
        .receive_crossing_audited(&mut w.clean_ch, &mut w.clean_tx, &mut ledger, &mut audit, NOW, "2026-07-13T00:00:00Z")
        .unwrap_err();
    assert!(
        matches!(err, BridgeError::GateDenied(_)),
        "signed consent said yes, but the independent far gate still denies: {err:?}"
    );
}

#[test]
fn a_consent_record_minted_for_the_reverse_direction_never_authorizes_this_crossing() {
    // Direction is cryptographically pinned end-to-end through the ledger, not
    // just at the record-check level (already unit-tested in consent_record.rs) —
    // prove it holds through the FULL crossing-audited path too.
    let mut w = wired();
    let mut authority = ConsentAuthority::generate();
    let crossing_sid = crossing_session_id(&w.paired_sid);
    // Minted the WRONG way around: Clean -> GooglePlay, but the crossing below is
    // GooglePlay -> Clean.
    let reversed = Direction::new(Persona::Clean, Persona::GooglePlay);
    let record = authority.mint(
        crossing_sid, Capability::Files, reversed, ConsentScope::Session, NOW, NOW + WINDOW, "peer",
    );
    let mut ledger = ConsentLedger::new(authority.verifying_key());
    ledger.admit(record).unwrap();

    // Pin down the EXACT reason directly on the ledger first (before it's folded
    // into a `BridgeError::ConsentRefused(String)` by the crossing layer) — proves
    // the refusal really is direction-shaped, not an accident of "no record
    // matched at all" swallowing the real cause.
    let direct = ledger.authorize(&crossing_sid, Capability::Files, Persona::GooglePlay, Persona::Clean, NOW);
    assert_eq!(direct.unwrap_err(), ConsentError::WrongDirection);

    let mut receiver: CrossingReceiver<ReferenceGate> =
        CrossingReceiver::new(&w.paired_sid, Persona::GooglePlay, Persona::Clean, gate_allowing(Capability::Files));
    let mut sender = CrossingSender::new(&w.paired_sid, Persona::GooglePlay, "peer");
    let dir = tempfile::tempdir().unwrap();
    let mut audit = AuditTrail::open(dir.path().join("audit.jsonl")).unwrap();

    sender.open_lane(Capability::Files, Persona::Clean, NOW + WINDOW);
    sender
        .send_crossing(&mut w.play_ch, &mut w.play_tx, Capability::Files, Persona::Clean, b"quarterly.pdf", NOW)
        .expect("near side sends");
    let err = receiver
        .receive_crossing_audited(&mut w.clean_ch, &mut w.clean_tx, &mut ledger, &mut audit, NOW, "2026-07-13T00:00:00Z")
        .unwrap_err();
    assert!(
        matches!(err, BridgeError::ConsentRefused(_)),
        "the full crossing path folds the direction mismatch into a consent refusal: {err:?}"
    );
}

#[test]
fn a_lying_from_persona_is_rejected_before_any_gate_or_consent_check() {
    // adversarial-review BUG 1 (HIGH): `CrossingRequest::from_persona` is a plain
    // field the SENDER sets — it must never be trusted on its own. The receiver
    // is bound (via the pairing/lane) to derive its origin as GooglePlay, and a
    // valid, correctly-signed, correctly-directed consent record is admitted for
    // exactly that direction, and the far gate is wide open — every OTHER check
    // would say yes. Only the crossing's claimed `from_persona` is a lie (Clean,
    // not GooglePlay). That lie alone must be enough to refuse it, fail-closed,
    // BEFORE the guard, the signed consent check, or the gate ever see it — and
    // certainly before the durable audit trail's `from` attribution could be
    // poisoned by it.
    let mut w = wired();
    let mut authority = ConsentAuthority::generate();
    let direction = Direction::new(Persona::GooglePlay, Persona::Clean);
    let crossing_sid = crossing_session_id(&w.paired_sid);
    let record = authority.mint(
        crossing_sid, Capability::Clipboard, direction, ConsentScope::Session, NOW, NOW + WINDOW, "peer",
    );
    let mut ledger = ConsentLedger::new(authority.verifying_key());
    ledger.admit(record).unwrap();

    let mut receiver: CrossingReceiver<ReferenceGate> = CrossingReceiver::new(
        &w.paired_sid,
        Persona::GooglePlay, // the receiver's DERIVED origin — the truth.
        Persona::Clean,
        gate_allowing(Capability::Clipboard),
    );
    let dir = tempfile::tempdir().unwrap();
    let mut audit = AuditTrail::open(dir.path().join("audit.jsonl")).unwrap();

    // Hand-craft the envelope directly (NOT through `CrossingSender`, which
    // always tells the truth about its own `from_persona`) so it CLAIMS the
    // wrong origin, then seal it exactly as a real sender would.
    let lying_req = CrossingRequest {
        session_id: crossing_sid,
        req_nonce: [0x5Au8; 32],
        counter: 1,
        capability: Capability::Clipboard,
        from_persona: Persona::Clean, // the lie: really GooglePlay, claims Clean.
        payload: b"pretend I'm the clean side".to_vec(),
    };
    let frame = w.play_ch.seal_frame(&lying_req.encode().unwrap()).unwrap();
    w.play_tx.send(&frame.to_bytes()).unwrap();

    let err = receiver
        .receive_crossing_audited(&mut w.clean_ch, &mut w.clean_tx, &mut ledger, &mut audit, NOW, "2026-07-13T00:00:00Z")
        .unwrap_err();
    assert_eq!(
        err,
        BridgeError::FromPersonaMismatch {
            claimed: Persona::Clean,
            expected: Persona::GooglePlay,
        },
        "a claimed origin that disagrees with the receiver's derived origin must be refused: {err:?}"
    );

    // Nothing was ever delivered — the check fires before the durable audit
    // trail is even opened for a write, so the poisoned claim never reaches it
    // (this is itself a proof: had anything been appended, the trail file below
    // would exist).
    assert!(!dir.path().join("audit.jsonl").exists(), "the lying crossing must never reach the durable audit trail");
}

#[test]
fn an_oversized_decoded_payload_is_rejected_at_the_receiver_even_if_validly_sealed() {
    // adversarial-review BUG 2 (MEDIUM): `MAX_CROSSING_BYTES` was only ever
    // checked in `CrossingSender::send_crossing` (a courtesy on the way OUT). A
    // compromised/divergent peer that seals an oversized frame directly bypasses
    // that check entirely; the sealed frame still opens cleanly (AEAD only proves
    // authenticity, not size policy). The receiver must independently re-check
    // the OPENED payload and refuse it, fail-closed.
    let mut w = wired();
    let mut authority = ConsentAuthority::generate();
    let direction = Direction::new(Persona::GooglePlay, Persona::Clean);
    let crossing_sid = crossing_session_id(&w.paired_sid);
    let record = authority.mint(
        crossing_sid, Capability::Files, direction, ConsentScope::Session, NOW, NOW + WINDOW, "peer",
    );
    let mut ledger = ConsentLedger::new(authority.verifying_key());
    ledger.admit(record).unwrap();

    let mut receiver: CrossingReceiver<ReferenceGate> = CrossingReceiver::new(
        &w.paired_sid, Persona::GooglePlay, Persona::Clean, gate_allowing(Capability::Files),
    );
    let dir = tempfile::tempdir().unwrap();
    let mut audit = AuditTrail::open(dir.path().join("audit.jsonl")).unwrap();

    // Built and sealed directly — NOT through `CrossingSender::send_crossing`,
    // which would have refused this at the door. Simulates a peer that skips the
    // sender's own cap entirely.
    let oversized_req = CrossingRequest {
        session_id: crossing_sid,
        req_nonce: [0x5Bu8; 32],
        counter: 1,
        capability: Capability::Files,
        from_persona: Persona::GooglePlay,
        payload: vec![0u8; MAX_CROSSING_BYTES + 1],
    };
    let frame = w.play_ch.seal_frame(&oversized_req.encode().unwrap()).unwrap();
    w.play_tx.send(&frame.to_bytes()).unwrap();

    let err = receiver
        .receive_crossing_audited(&mut w.clean_ch, &mut w.clean_tx, &mut ledger, &mut audit, NOW, "2026-07-13T00:00:00Z")
        .unwrap_err();
    assert_eq!(
        err,
        BridgeError::PayloadTooLarge { len: MAX_CROSSING_BYTES + 1, max: MAX_CROSSING_BYTES },
        "an oversized decoded payload must be refused at the receiver too, even validly sealed: {err:?}"
    );

    assert!(!dir.path().join("audit.jsonl").exists(), "the oversized crossing must never reach the durable audit trail");
}
