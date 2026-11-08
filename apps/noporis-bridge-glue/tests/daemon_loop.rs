// SPDX-License-Identifier: MIT OR Apache-2.0
//! # daemon_loop — the daemon core's own multi-tick, black-box HOST proof
//!
//! ## ⚠️ SCAFFOLD / reference-prototype — UNAUDITED. Certifies nothing.
//!
//! This exercises [`noporis_bridge_glue::Daemon`] ONLY through its public
//! surface (exactly what F2's E2E loop, and a real `[[bin]]`/init unit, would
//! call) — no internal module access. Where `tests/functional_proof.rs` (Dev
//! E) proves the crossing primitives compose correctly in isolation, this
//! file proves the **daemon's own tick/shutdown state machine** composes them
//! correctly across MULTIPLE ticks, with the persona-lifecycle substrate and
//! the persisted state files in the loop too — the piece that did not exist
//! before this crate had a `[[bin]]` target.
//!
//! Honesty tier: `HOST`. Everything here runs in one process against the
//! crate's frozen public API over the default `host-stub` seams — it proves
//! composition/control-flow, nothing about a real handset. A rooted/
//! kernel-compromised host defeats every boundary asserted here. NoporIS is
//! an app on stock Android, NEVER "Postern OS". The coin (BLCH) is not a
//! security and buys no software.
//!
//! Run: `cargo test -p noporis-bridge-glue --test daemon_loop`

use std::fs;

use noporis_bridge_glue::daemon::unix_to_iso8601;
use noporis_bridge_glue::{
    AuditTrail, Capability, ConsentAuthority, ConsentLedger, ConsentScope, CrossingLane,
    CrossingReceiver, CrossingRequest, Daemon, DaemonConfig, Direction, GateState, HostStubDpc,
    ManagedProfileSubstrate, Orchestrator, Persona, Reconciliation, ReferenceGate, StatePaths,
    crossing_session_id,
};
use postern_pairing::channel::endpoints;
use postern_pairing::hybrid::SessionKey;
use postern_pairing::transport::{LoopbackPair, LoopbackTransport, Transport};
use zeroize::Zeroizing;

const NOW: i64 = 1_752_000_000;

/// Build one `CrossingLane` (Google-Play → Clean) with a live, signed,
/// session-scope `ConsentRecord` already admitted for `capability`, and the
/// far-side gate posture `gate_open` explicitly. Returns the lane, the
/// SENDING side's transport + channel (so the test can push crossings in
/// exactly as a real paired session would), and the 32-byte paired session id.
///
/// **Why `gate_open` is a separate parameter from anything written to
/// `state.json`:** the per-lane [`crate::consent::GateConsent`] (here, a
/// [`ReferenceGate`] test double) and the [`GateState`]/[`Orchestrator`] the
/// daemon reads off `state.json` are two independent consumers of what is,
/// on a real device, the SAME N-gate decision (the real `apps/noporis-gate/`
/// both persists `state.json` AND implements `GateConsent` — one authority,
/// read twice). This crate's host tests have always kept them independent
/// stand-ins (`tests/functional_proof.rs` flips `receiver.gate_mut()`
/// directly, never derives it from a `GateState`) and the daemon does not
/// paper over that: `Daemon::tick` only synchronizes the **kill-switch**
/// from `GateState` into each lane's `ConsentLedger` (defense in depth), it
/// does not attempt to derive a `GateConsent` verdict from `GateState.crossings`
/// — a real `GateConsent` impl reads its own authoritative source.
fn wired_lane(
    capability: Capability,
    gate_open: bool,
    audit_path: &std::path::Path,
) -> (
    CrossingLane<ReferenceGate, LoopbackTransport>,
    LoopbackTransport,
    postern_pairing::channel::Channel,
    [u8; 32],
) {
    wired_lane_dir(
        Direction::new(Persona::GooglePlay, Persona::Clean),
        capability,
        gate_open,
        audit_path,
    )
}

/// Like [`wired_lane`] but for an arbitrary [`Direction`] — the receiver is bound
/// to `direction.to` and the signed `ConsentRecord` is minted for exactly
/// `direction`, so a crossing whose actual `from → to` does not match is refused
/// by the consent 5-step check's step 3 (direction pinning), fail-closed.
fn wired_lane_dir(
    direction: Direction,
    capability: Capability,
    gate_open: bool,
    audit_path: &std::path::Path,
) -> (
    CrossingLane<ReferenceGate, LoopbackTransport>,
    LoopbackTransport,
    postern_pairing::channel::Channel,
    [u8; 32],
) {
    let sk: SessionKey = Zeroizing::new([0x21u8; 32]);
    let (ch_send, ch_recv) = endpoints(&sk);
    let sid = *ch_send.session_id();
    let (tx_send, tx_recv) = LoopbackPair::new();

    let mut authority = ConsentAuthority::from_seed([0x33u8; 32]);
    let near_pub = authority.verifying_key();
    let mut consent = ConsentLedger::new(near_pub);
    let record = authority.mint(
        crossing_session_id(&sid),
        capability,
        direction,
        ConsentScope::Session,
        NOW - 100,
        NOW + 1_000_000,
        "the paired peer",
    );
    consent.admit(record).expect("near-signed record admits");

    let mut gate = ReferenceGate::new();
    gate.accept_consent();
    if gate_open {
        gate.open(capability);
    }
    let receiver = CrossingReceiver::new(&sid, direction.from, direction.to, gate);

    let audit = AuditTrail::open(audit_path).expect("open durable audit trail");
    let lane = CrossingLane::new(direction, ch_recv, tx_recv, receiver, consent, audit);
    (lane, tx_send, ch_send, sid)
}

fn send_one(
    tx: &mut LoopbackTransport,
    ch: &mut postern_pairing::channel::Channel,
    sid: &[u8; 32],
    capability: Capability,
    counter: u64,
    payload: &[u8],
) {
    send_from(tx, ch, sid, Persona::GooglePlay, capability, counter, payload);
}

/// Like [`send_one`] but with an explicit `from_persona` — so a test can drive a
/// reverse-direction lane (`Clean → GooglePlay`) or deliberately send a crossing
/// whose direction does NOT match the lane's pinned one (to prove the deny).
#[allow(clippy::too_many_arguments)]
fn send_from(
    tx: &mut LoopbackTransport,
    ch: &mut postern_pairing::channel::Channel,
    sid: &[u8; 32],
    from_persona: Persona,
    capability: Capability,
    counter: u64,
    payload: &[u8],
) {
    let req = CrossingRequest {
        session_id: crossing_session_id(sid),
        req_nonce: [counter as u8; 32],
        counter,
        capability,
        from_persona,
        payload: payload.to_vec(),
    };
    let frame = ch.seal_frame(&req.encode().unwrap()).unwrap();
    tx.send(&frame.to_bytes()).unwrap();
}

/// Seal a valid crossing, then flip a byte of the on-wire frame before sending —
/// a single-byte tamper that AEAD `open_frame` catches, surfacing as
/// [`noporis_bridge_glue::BridgeError::Channel`] → a `tamper` error in the
/// daemon's per-lane accounting (never a delivery, never a silent drop).
fn send_tampered(
    tx: &mut LoopbackTransport,
    ch: &mut postern_pairing::channel::Channel,
    sid: &[u8; 32],
    capability: Capability,
    counter: u64,
) {
    let req = CrossingRequest {
        session_id: crossing_session_id(sid),
        req_nonce: [counter as u8; 32],
        counter,
        capability,
        from_persona: Persona::GooglePlay,
        payload: b"tamper-me".to_vec(),
    };
    let frame = ch.seal_frame(&req.encode().unwrap()).unwrap();
    let mut bytes = frame.to_bytes();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff; // corrupt the tail (ciphertext/tag) → AEAD open fails.
    tx.send(&bytes).unwrap();
}

// ─────────────────────────────────────────────────────────────────────────
//  THE DAEMON LOOP — fail-closed boot → consent → activate → cross → kill →
//  clean shutdown, driven ENTIRELY through Daemon::tick / Daemon::shutdown.
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn daemon_loop_boot_consent_activate_cross_kill_shutdown() {
    let dir = tempfile::tempdir().unwrap();
    let paths = StatePaths::under(dir.path());

    let orchestrator = Orchestrator::new(ManagedProfileSubstrate::<HostStubDpc>::new(Persona::GooglePlay));
    let config = DaemonConfig {
        paths: paths.clone(),
        max_crossings_per_tick: 16,
    };
    let mut daemon = Daemon::new(orchestrator, config);

    let (lane, mut tx, mut ch, sid) = wired_lane(Capability::Clipboard, true, &dir.path().join("audit.jsonl"));
    daemon.add_lane(lane);

    // ── [1] BOOT — no state.json exists yet: fail-closed by construction. ──
    let boot = daemon.tick(NOW, &unix_to_iso8601(NOW));
    assert!(!boot.consent_accepted);
    assert!(!boot.kill_switch_engaged);
    assert!(boot.sealed_wallet_preserved);
    assert!(!boot.halted, "no consent is a held-closed posture, not a halt");
    assert_eq!(boot.reconciliation, Ok(Reconciliation::HeldClosedNoConsent));
    assert_eq!(boot.lanes[0].delivered, 0, "nothing was queued and nothing crosses pre-consent");
    // The daemon is the SOLE runtime writer — both files exist now.
    assert!(paths.state_json.exists());
    assert!(paths.sloboda_bridge_state.exists());

    // ── [2] CONSENT — the operator accepts + opens the clipboard lane. ──────
    let gate = GateState::consented(noporis_bridge_glue::substrate::ConsentScope::Session)
        .open_crossing(Capability::Clipboard);
    fs::write(&paths.state_json, gate.to_gate_json()).unwrap();

    // ── [3] CROSS — a crossing is queued on the lane's transport BEFORE the
    //     tick, exactly as a live paired session would have delivered it. ────
    send_one(&mut tx, &mut ch, &sid, Capability::Clipboard, 1, b"hello world");
    let active = daemon.tick(NOW + 1, &unix_to_iso8601(NOW + 1));
    assert_eq!(active.reconciliation, Ok(Reconciliation::Activated));
    assert!(!active.halted);
    assert_eq!(active.lanes[0].delivered, 1, "both consents live -> the payload crosses");
    assert_eq!(active.lanes[0].denied, 0);
    assert_eq!(active.lanes[0].errors, 0);
    assert!(active.sealed_wallet_preserved);

    // Persisted projection reflects the live, activated posture.
    let projection = fs::read_to_string(&paths.sloboda_bridge_state).unwrap();
    assert!(projection.starts_with("enabled\n"), "one lane open -> enabled: {projection}");
    assert!(projection.contains("container=allowed"));

    // ── [4] KILL — the operator engages the kill-switch; a second crossing is
    //     ALREADY queued when the tick observes it. It must be refused, not
    //     silently dropped, and the substrate must be driven through kill. ───
    send_one(&mut tx, &mut ch, &sid, Capability::Clipboard, 2, b"too late");
    let mut killed_gate = gate;
    killed_gate.kill_switch_engaged = true;
    fs::write(&paths.state_json, killed_gate.to_gate_json()).unwrap();

    let killed = daemon.tick(NOW + 2, &unix_to_iso8601(NOW + 2));
    assert!(killed.kill_switch_engaged);
    assert!(killed.halted);
    assert_eq!(killed.reconciliation, Ok(Reconciliation::Killed));
    assert_eq!(killed.lanes[0].delivered, 0, "kill-switch halts crossings THIS tick, not a tick late");
    assert_eq!(killed.lanes[0].denied, 1, "the already-queued crossing is refused, not dropped silently");
    assert!(killed.sealed_wallet_preserved, "cutting the span never destroys the sealed wallet");

    let killed_projection = fs::read_to_string(&paths.sloboda_bridge_state).unwrap();
    assert!(killed_projection.starts_with("disabled\n"));
    assert!(killed_projection.contains("kill=engaged"));

    // ── [5] CLEAN SHUTDOWN — idempotent, fail-closed, persists a kill posture
    //     even though the gate file on disk was never told to shut down. ─────
    let shutdown_report = daemon.shutdown(NOW + 3, &unix_to_iso8601(NOW + 3));
    assert!(shutdown_report.kill_switch_engaged);
    assert!(shutdown_report.halted);
    assert_eq!(shutdown_report.reconciliation, Ok(Reconciliation::Killed));
    assert!(shutdown_report.sealed_wallet_preserved);

    let second_shutdown = daemon.shutdown(NOW + 4, &unix_to_iso8601(NOW + 4));
    assert_eq!(second_shutdown.reconciliation, Ok(Reconciliation::Killed), "shutdown is idempotent");

    // The durable audit trail on the lane recorded BOTH the delivery and the
    // post-kill denial — nothing here is silent.
    assert!(paths.state_json.exists());
}

// ─────────────────────────────────────────────────────────────────────────
//  MULTIPLE DIRECTIONS — two independently-consented lanes on one daemon;
//  closing one leaves the other live (deny-by-default is per-capability AND
//  the daemon's lane drain is per-lane, never all-or-nothing on delivery).
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn two_lanes_are_independent_deny_by_default_channels() {
    let dir = tempfile::tempdir().unwrap();
    let paths = StatePaths::under(dir.path());
    let orchestrator = Orchestrator::new(ManagedProfileSubstrate::<HostStubDpc>::new(Persona::GooglePlay));
    let config = DaemonConfig {
        paths: paths.clone(),
        max_crossings_per_tick: 16,
    };
    let mut daemon = Daemon::new(orchestrator, config);

    let (clip_lane, mut clip_tx, mut clip_ch, clip_sid) =
        wired_lane(Capability::Clipboard, true, &dir.path().join("clip-audit.jsonl"));
    let (files_lane, mut files_tx, mut files_ch, files_sid) =
        wired_lane(Capability::Files, false, &dir.path().join("files-audit.jsonl"));
    daemon.add_lane(clip_lane);
    daemon.add_lane(files_lane);
    assert_eq!(daemon.lane_count(), 2);

    // Gate: consented, and ONLY the clipboard lane is thrown open at the
    // substrate level (state.json's `crossings`). The files lane's
    // ConsentRecord is live, but its own GateConsent lever was never opened
    // (`gate_open = false` above) — deny-by-default holds independently at
    // BOTH authorities; neither alone is sufficient to deliver.
    let gate = GateState::consented(noporis_bridge_glue::substrate::ConsentScope::Session)
        .open_crossing(Capability::Clipboard);
    fs::write(&paths.state_json, gate.to_gate_json()).unwrap();

    send_one(&mut clip_tx, &mut clip_ch, &clip_sid, Capability::Clipboard, 1, b"clip");
    send_one(&mut files_tx, &mut files_ch, &files_sid, Capability::Files, 1, b"file-bytes");

    let report = daemon.tick(NOW, &unix_to_iso8601(NOW));
    assert_eq!(report.reconciliation, Ok(Reconciliation::Activated));
    assert_eq!(report.lanes.len(), 2);

    // Both lanes share the same `Direction` (GooglePlay -> Clean); they are
    // distinguished by registration order, which `Daemon::tick` preserves
    // (clipboard was added first, files second).
    assert_eq!(report.lanes[0].delivered, 1, "clipboard lane: gate open -> delivered");
    assert_eq!(report.lanes[0].denied, 0);
    assert_eq!(report.lanes[1].delivered, 0, "files lane: gate closed -> denied, not delivered");
    assert_eq!(report.lanes[1].denied, 1, "denied via the gate, not silently dropped");
}

// ─────────────────────────────────────────────────────────────────────────
//  FAIL-CLOSED — a corrupt state.json, or a sealed-wallet-invariant
//  violation reported by the gate, must never panic and must never activate.
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn corrupt_state_file_never_panics_and_stays_closed() {
    let dir = tempfile::tempdir().unwrap();
    let paths = StatePaths::under(dir.path());
    fs::write(&paths.state_json, b"\x00\x01 not even close to json").unwrap();

    let orchestrator = Orchestrator::new(ManagedProfileSubstrate::<HostStubDpc>::new(Persona::GooglePlay));
    let config = DaemonConfig { paths, max_crossings_per_tick: 4 };
    let mut daemon: Daemon<ManagedProfileSubstrate<HostStubDpc>, ReferenceGate, LoopbackTransport> =
        Daemon::new(orchestrator, config);

    let report = daemon.tick(NOW, &unix_to_iso8601(NOW));
    assert!(!report.consent_accepted);
    assert!(!report.kill_switch_engaged);
    assert_eq!(report.reconciliation, Ok(Reconciliation::HeldClosedNoConsent));
    assert!(report.lanes.is_empty(), "zero lanes registered on this daemon instance");
}

#[test]
fn sealed_wallet_invariant_violation_is_a_hard_stop_not_a_panic() {
    // A foreign/malicious state.json can never assert `sealedWallet.preserved
    // == false` through the honest parser (from_gate_json refuses any value
    // other than `true` and collapses to deny_all()) — so we exercise the
    // Substrate/Orchestrator's hard-stop path directly through the SAME public
    // Orchestrator::commit the daemon calls, proving the daemon would fold a
    // hard-stop into `reconciliation` as an `Err`, never a panic, if it were
    // ever reachable.
    let dir = tempfile::tempdir().unwrap();
    let paths = StatePaths::under(dir.path());
    let mut orchestrator = Orchestrator::new(ManagedProfileSubstrate::<HostStubDpc>::new(Persona::GooglePlay));

    let mut poisoned = GateState::deny_all();
    poisoned.sealed_wallet_preserved = false; // constructible directly (not via the honest parser)
    let result = orchestrator.commit(&poisoned, poisoned.to_gate_json().as_bytes(), &paths);
    assert!(result.is_err(), "the invariant violation is a hard stop, surfaced as Err — never a silent proceed");
}

#[test]
fn read_gate_state_free_function_is_reusable_and_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let paths = StatePaths::under(dir.path());
    let (gate, bytes) = noporis_bridge_glue::daemon::read_gate_state(&paths);
    assert_eq!(gate, GateState::deny_all());
    assert!(!bytes.is_empty(), "a fresh deny_all() document is rendered even with no file on disk");
}

// ─────────────────────────────────────────────────────────────────────────
//  BOTH CROSSING DIRECTIONS — the lane doc promises both directions are
//  drivable, and a direction-mismatched lane denies fail-closed by pinning.
//  (Previously only GooglePlay -> Clean was exercised.)
// ─────────────────────────────────────────────────────────────────────────

/// Boot a single-lane daemon over `direction`, consent+open `capability`, push
/// one crossing sent `from` the given persona, tick once, and return the report.
fn one_crossing_over(
    dir: &std::path::Path,
    direction: Direction,
    from: Persona,
    capability: Capability,
) -> noporis_bridge_glue::DaemonReport {
    let paths = StatePaths::under(dir);
    let orchestrator = Orchestrator::new(ManagedProfileSubstrate::<HostStubDpc>::new(Persona::GooglePlay));
    let config = DaemonConfig { paths: paths.clone(), max_crossings_per_tick: 16 };
    let mut daemon = Daemon::new(orchestrator, config);

    let (lane, mut tx, mut ch, sid) =
        wired_lane_dir(direction, capability, true, &dir.join("audit.jsonl"));
    daemon.add_lane(lane);

    let gate = GateState::consented(noporis_bridge_glue::substrate::ConsentScope::Session)
        .open_crossing(capability);
    fs::write(&paths.state_json, gate.to_gate_json()).unwrap();

    send_from(&mut tx, &mut ch, &sid, from, capability, 1, b"payload");
    daemon.tick(NOW, &unix_to_iso8601(NOW))
}

#[test]
fn reverse_direction_clean_to_googleplay_delivers_when_consented_and_open() {
    let dir = tempfile::tempdir().unwrap();
    let direction = Direction::new(Persona::Clean, Persona::GooglePlay);
    let report = one_crossing_over(dir.path(), direction, Persona::Clean, Capability::Files);
    assert_eq!(report.reconciliation, Ok(Reconciliation::Activated));
    assert_eq!(report.lanes.len(), 1);
    assert_eq!(
        report.lanes[0].delivered, 1,
        "a Clean -> GooglePlay crossing delivers just like the forward direction"
    );
    assert_eq!(report.lanes[0].direction.from, Persona::Clean);
    assert_eq!(report.lanes[0].direction.to, Persona::GooglePlay);
    assert_eq!(report.lanes[0].denied, 0);
    assert_eq!(report.lanes[0].errors, 0);
}

#[test]
fn a_direction_mismatched_crossing_denies_by_pinning_never_delivers() {
    // The lane is pinned GooglePlay -> Clean (consent minted for that direction),
    // but the crossing arrives claiming from = Clean. The receiver's own
    // from_persona cross-check (derived from the lane's direction.from) refuses
    // it before the crossing ever reaches the signed consent's direction pinning
    // — a deny, not a delivery, not an error, and certainly not a silent drop.
    let dir = tempfile::tempdir().unwrap();
    let direction = Direction::new(Persona::GooglePlay, Persona::Clean);
    let report = one_crossing_over(dir.path(), direction, Persona::Clean, Capability::Clipboard);
    assert_eq!(report.reconciliation, Ok(Reconciliation::Activated));
    assert_eq!(report.lanes[0].delivered, 0, "a mismatched direction never delivers");
    assert_eq!(
        report.lanes[0].denied, 1,
        "it is denied by direction-pinning, fail-closed — not bucketed as an error"
    );
    assert_eq!(report.lanes[0].errors, 0);
}

#[test]
fn a_bidirectional_daemon_drives_both_lanes_independently() {
    // One daemon, two lanes — one each way — both consented+open, each handed a
    // crossing. Both deliver; neither direction starves or shadows the other.
    let dir = tempfile::tempdir().unwrap();
    let paths = StatePaths::under(dir.path());
    let orchestrator = Orchestrator::new(ManagedProfileSubstrate::<HostStubDpc>::new(Persona::GooglePlay));
    let config = DaemonConfig { paths: paths.clone(), max_crossings_per_tick: 16 };
    let mut daemon = Daemon::new(orchestrator, config);

    let fwd = Direction::new(Persona::GooglePlay, Persona::Clean);
    let rev = Direction::new(Persona::Clean, Persona::GooglePlay);
    let (fwd_lane, mut fwd_tx, mut fwd_ch, fwd_sid) =
        wired_lane_dir(fwd, Capability::Clipboard, true, &dir.path().join("fwd-audit.jsonl"));
    let (rev_lane, mut rev_tx, mut rev_ch, rev_sid) =
        wired_lane_dir(rev, Capability::Files, true, &dir.path().join("rev-audit.jsonl"));
    daemon.add_lane(fwd_lane);
    daemon.add_lane(rev_lane);
    assert_eq!(daemon.lane_count(), 2);

    let gate = GateState::consented(noporis_bridge_glue::substrate::ConsentScope::Session)
        .open_crossing(Capability::Clipboard)
        .open_crossing(Capability::Files);
    fs::write(&paths.state_json, gate.to_gate_json()).unwrap();

    send_from(&mut fwd_tx, &mut fwd_ch, &fwd_sid, Persona::GooglePlay, Capability::Clipboard, 1, b"fwd");
    send_from(&mut rev_tx, &mut rev_ch, &rev_sid, Persona::Clean, Capability::Files, 1, b"rev");

    let report = daemon.tick(NOW, &unix_to_iso8601(NOW));
    assert_eq!(report.reconciliation, Ok(Reconciliation::Activated));
    assert_eq!(report.lanes.len(), 2);
    assert_eq!(report.lanes[0].direction.from, Persona::GooglePlay);
    assert_eq!(report.lanes[0].delivered, 1, "forward lane delivers");
    assert_eq!(report.lanes[1].direction.from, Persona::Clean);
    assert_eq!(report.lanes[1].delivered, 1, "reverse lane delivers independently");
}

// ─────────────────────────────────────────────────────────────────────────
//  ERROR / RECOVERY ACCOUNTING — the collapsed `errors` bucket is now split
//  into named per-reason counters; a tamper is attributed as `tamper`, and
//  the grand total still matches the legacy `errors` field.
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn a_tampered_frame_is_accounted_as_tamper_not_a_generic_error_or_a_delivery() {
    let dir = tempfile::tempdir().unwrap();
    let paths = StatePaths::under(dir.path());
    let orchestrator = Orchestrator::new(ManagedProfileSubstrate::<HostStubDpc>::new(Persona::GooglePlay));
    let config = DaemonConfig { paths: paths.clone(), max_crossings_per_tick: 16 };
    let mut daemon = Daemon::new(orchestrator, config);

    let (lane, mut tx, mut ch, sid) =
        wired_lane(Capability::Clipboard, true, &dir.path().join("audit.jsonl"));
    daemon.add_lane(lane);

    let gate = GateState::consented(noporis_bridge_glue::substrate::ConsentScope::Session)
        .open_crossing(Capability::Clipboard);
    fs::write(&paths.state_json, gate.to_gate_json()).unwrap();

    // One clean crossing (delivers) + one tampered crossing (a `tamper` error).
    send_one(&mut tx, &mut ch, &sid, Capability::Clipboard, 1, b"clean");
    send_tampered(&mut tx, &mut ch, &sid, Capability::Clipboard, 2);

    let report = daemon.tick(NOW, &unix_to_iso8601(NOW));
    let lane = report.lanes[0];
    assert_eq!(lane.delivered, 1, "the clean crossing still delivers");
    assert_eq!(lane.denied, 0);
    // The split accounting attributes the failure to `tamper`, specifically.
    assert_eq!(lane.error_breakdown.tamper, 1, "the corrupted frame is counted as a tamper");
    assert_eq!(lane.error_breakdown.replay, 0);
    assert_eq!(lane.error_breakdown.wrong_session, 0);
    assert_eq!(lane.error_breakdown.audit_io, 0);
    assert_eq!(lane.error_breakdown.other, 0, "no failure lands in the catch-all bucket");
    // The grand total still equals the legacy collapsed `errors` field.
    assert_eq!(lane.errors, 1);
    assert_eq!(lane.errors, lane.error_breakdown.total());
}

// ─────────────────────────────────────────────────────────────────────────
//  SCHEMA-PREFLIGHT WIRED — a foreign sloboda-bridge.state projection makes
//  the daemon refuse the tick fail-closed (never clobbering it), and a clean
//  boot passes the preflight and reports Ok.
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn a_foreign_projection_makes_the_daemon_refuse_the_tick_and_never_clobbers_it() {
    let dir = tempfile::tempdir().unwrap();
    let paths = StatePaths::under(dir.path());
    fs::create_dir_all(dir.path()).unwrap();

    // A projection left by a writer whose schema_version this orchestrator does
    // not understand. The daemon must NOT overwrite it — it must refuse.
    let foreign = "enabled\ncontainer=allowed\nschema_version=999\n";
    fs::write(&paths.sloboda_bridge_state, foreign).unwrap();

    let orchestrator = Orchestrator::new(ManagedProfileSubstrate::<HostStubDpc>::new(Persona::GooglePlay));
    let config = DaemonConfig { paths: paths.clone(), max_crossings_per_tick: 4 };
    let mut daemon: Daemon<ManagedProfileSubstrate<HostStubDpc>, ReferenceGate, LoopbackTransport> =
        Daemon::new(orchestrator, config);

    // The standalone startup preflight refuses (this is what the [[bin]] surfaces
    // in its exit code).
    assert!(daemon.preflight().is_err(), "the startup preflight refuses a foreign projection");

    let report = daemon.tick(NOW, &unix_to_iso8601(NOW));
    assert!(report.halted, "a foreign projection halts the tick fail-closed");
    assert!(report.schema_preflight.is_err(), "the tick's schema-preflight is the refusal reason");
    assert!(report.reconciliation.is_err(), "no reconcile/commit happened");

    // Crucially: the foreign file is UNTOUCHED — the daemon never clobbered a
    // projection a version it does not understand may still own.
    assert_eq!(
        fs::read_to_string(&paths.sloboda_bridge_state).unwrap(),
        foreign,
        "the foreign projection is left exactly as found"
    );
    // And state.json was never written either (fail-closed short-circuit).
    assert!(!paths.state_json.exists(), "no state was written on a refused tick");
}

#[test]
fn a_clean_boot_passes_the_schema_preflight_and_reports_ok() {
    let dir = tempfile::tempdir().unwrap();
    let paths = StatePaths::under(dir.path());
    let orchestrator = Orchestrator::new(ManagedProfileSubstrate::<HostStubDpc>::new(Persona::GooglePlay));
    let config = DaemonConfig { paths: paths.clone(), max_crossings_per_tick: 4 };
    let mut daemon: Daemon<ManagedProfileSubstrate<HostStubDpc>, ReferenceGate, LoopbackTransport> =
        Daemon::new(orchestrator, config);

    assert!(daemon.preflight().is_ok(), "absent projection = first boot = preflight passes");
    let report = daemon.tick(NOW, &unix_to_iso8601(NOW));
    assert_eq!(report.schema_preflight, Ok(()), "a clean first tick's preflight is Ok");
    assert!(!report.halted);
    // Now the daemon's OWN write is on disk; a second tick reads it back and it
    // still verifies (the write-side and read-side agree round-trip).
    let second = daemon.tick(NOW + 1, &unix_to_iso8601(NOW + 1));
    assert_eq!(second.schema_preflight, Ok(()), "what the daemon wrote, it re-verifies next tick");
}
