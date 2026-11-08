// SPDX-License-Identifier: MIT OR Apache-2.0
//! # persistence_recovery — F2 persistence hardening, HOST-provable
//!
//! ## ⚠️ SCAFFOLD / reference-prototype — UNAUDITED. Certifies nothing.
//!
//! Three things this crate's persistence layer must hold, each host-provable
//! without a real device:
//!
//! 1. **Schema versioning fails closed.** Both the `state.json` schema (Dev C's,
//!    consumed verbatim via [`GateState::from_gate_json`]) and the
//!    `sloboda-bridge.state` projection (this crate's own, versioned via
//!    [`verify_sloboda_bridge_schema`]) refuse — never silently misparse — an
//!    unrecognized or missing version.
//! 2. **`write_atomic`'s rename-based durability holds under a simulated
//!    `SIGKILL`.** A crash that leaves a dangling, partially-written temp file
//!    behind must never be observed as a torn write on the canonical path — the
//!    target is always either the last fully-committed content or (before the
//!    first successful write) absent.
//! 3. **Crash-recovery + per-capability `LaneSet` round-trip.** A fresh
//!    orchestrator, "restarted" against the same [`StatePaths`] after a
//!    simulated crash, reconciles to the EXACT SAME per-capability lane posture
//!    that was live before the crash — proving the on-disk `state.json` is a
//!    complete, faithful source of truth for that posture, not merely a log.
//!
//! Run: `cargo test -p noporis-bridge-glue --test persistence_recovery`

use std::fs;

use noporis_bridge_glue::substrate::{
    parse_sloboda_bridge_schema_version, project_sloboda_bridge_state, read_gate_state,
    read_sloboda_bridge_state, verify_sloboda_bridge_schema, write_atomic,
    ConsentScope as GateConsentScope, GateState, ManagedProfileSubstrate, Orchestrator,
    Reconciliation, StatePaths, SubstrateError, WaydroidSubstrate, WriterLock,
    SLOBODA_BRIDGE_SCHEMA_VERSION,
};
use noporis_bridge_glue::{
    AuditTrail, Capability, ConsentAuthority, ConsentLedger, CrossingLane, CrossingReceiver, Daemon,
    DaemonConfig, Direction, Persona, ReferenceGate, Substrate,
};
use postern_pairing::channel::endpoints;
use postern_pairing::hybrid::SessionKey;
use postern_pairing::transport::{LoopbackPair, LoopbackTransport};
use postern_trail::verify_chain;
use zeroize::Zeroizing;

// ─────────────────────────────────────────────────────────────────────────────
//  1. SCHEMA VERSIONING — unknown/missing version fails closed, never a guess.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn state_json_unknown_version_denies_instead_of_misparsing() {
    // A file that is otherwise well-formed but claims a version this crate has
    // never spoken (2, the successor of the only version it knows) must deny —
    // not attempt a best-effort partial read of fields it happens to recognize.
    let future = "{\"schema\":\"postern.noporis-gate.state\",\"version\":2,\"tier\":\"non-attestable\",\
        \"consent\":{\"accepted\":true,\"scope\":\"persistent\"},\
        \"crossings\":{\"clipboard\":{\"open\":true}},\
        \"killSwitch\":{\"engaged\":false},\"sealedWallet\":{\"preserved\":true}}";
    let parsed = GateState::from_gate_json(future);
    assert_eq!(parsed, GateState::deny_all(), "an unrecognized version must deny wholesale");
    // In particular: it must NOT accidentally honor `consent.accepted: true` from
    // the "future" file just because the field name happens to still match.
    assert!(!parsed.consent_accepted);
    assert!(!parsed.any_crossing_open());
}

#[test]
fn state_json_read_from_disk_with_an_unknown_version_recovers_deny_all() {
    let dir = tempfile::tempdir().unwrap();
    let paths = StatePaths::under(dir.path());
    fs::create_dir_all(dir.path()).unwrap();
    let future = "{\"schema\":\"postern.noporis-gate.state\",\"version\":99,\"tier\":\"non-attestable\",\
        \"consent\":{\"accepted\":true,\"scope\":\"session\"},\
        \"crossings\":{},\"killSwitch\":{\"engaged\":false},\"sealedWallet\":{\"preserved\":true}}";
    fs::write(&paths.state_json, future).unwrap();

    // The crash-recovery reload path must refuse this exactly like the pure
    // parser does — the two must never drift apart.
    assert_eq!(read_gate_state(&paths), GateState::deny_all());
}

#[test]
fn sloboda_bridge_projection_schema_version_is_written_and_verifies() {
    let gate = GateState::consented_with_crossing(GateConsentScope::Session);
    let body = project_sloboda_bridge_state(&gate);
    assert_eq!(parse_sloboda_bridge_schema_version(&body), Some(SLOBODA_BRIDGE_SCHEMA_VERSION));
    assert!(verify_sloboda_bridge_schema(&body).is_ok());
    // Additive: the line-1 authority contract paw-lib.sh reads is unperturbed.
    assert!(body.starts_with("enabled\n"));
}

#[test]
fn sloboda_bridge_projection_unknown_version_fails_closed() {
    // Simulates a FUTURE writer bumping the format in a way this reader does not
    // understand — verification must refuse, never guess at line 1's meaning.
    let forged_future = "enabled\ncontainer=allowed\nschema_version=7\n";
    assert!(verify_sloboda_bridge_schema(forged_future).is_err());
}

#[test]
fn sloboda_bridge_projection_missing_version_fails_closed() {
    // Simulates a PRE-versioning writer (or a corrupted/truncated write that
    // dropped the trailing marker line) — must also refuse, not default-trust.
    let legacy_or_torn = "enabled\ncontainer=allowed\n";
    assert!(verify_sloboda_bridge_schema(legacy_or_torn).is_err());
}

#[test]
fn sloboda_bridge_projection_committed_by_the_orchestrator_verifies_on_disk() {
    let dir = tempfile::tempdir().unwrap();
    let paths = StatePaths::under(dir.path());
    let mut orch = Orchestrator::new(WaydroidSubstrate::new(Persona::GooglePlay));
    let gate = GateState::consented_with_crossing(GateConsentScope::Session);
    orch.commit(&gate, gate.to_gate_json().as_bytes(), &paths).unwrap();

    let body = fs::read_to_string(&paths.sloboda_bridge_state).unwrap();
    assert!(verify_sloboda_bridge_schema(&body).is_ok(), "what the orchestrator writes, it also honors on read-back");
}

// ─────────────────────────────────────────────────────────────────────────────
//  1b. SCHEMA-READER WIRED — read_sloboda_bridge_state is the runtime read-side
//      that finally invokes verify_sloboda_bridge_schema against a real file, so
//      a foreign projection is a hard refusal, not a silent overwrite.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn schema_reader_absent_present_and_foreign_projection_are_all_distinguished() {
    let dir = tempfile::tempdir().unwrap();
    let paths = StatePaths::under(dir.path());

    // Absent → first boot: Ok(None), nothing to distrust.
    assert_eq!(read_sloboda_bridge_state(&paths), Ok(None));

    // Present + our own schema-versioned write → Ok(Some(body)), and it verifies.
    let mut orch = Orchestrator::new(WaydroidSubstrate::new(Persona::GooglePlay));
    let gate = GateState::consented_with_crossing(GateConsentScope::Session);
    orch.commit(&gate, gate.to_gate_json().as_bytes(), &paths).unwrap();
    let body = read_sloboda_bridge_state(&paths).unwrap().expect("present after commit");
    assert!(verify_sloboda_bridge_schema(&body).is_ok());

    // Present + a foreign schema_version → hard refusal (Err), never Ok(None),
    // never a silent trust. This is the gap the wiring closes.
    fs::write(&paths.sloboda_bridge_state, b"disabled\nschema_version=4242\n").unwrap();
    let err = read_sloboda_bridge_state(&paths).unwrap_err();
    assert!(matches!(err, SubstrateError::Backend(_)));
}

#[test]
fn schema_reader_round_trips_the_orchestrators_own_write_across_a_simulated_restart() {
    // A crash/restart narrative: process #1 commits, "crashes", process #2 reads
    // the projection back through the SAME fail-closed reader a startup preflight
    // uses — and trusts it, because the schema is one it understands.
    let dir = tempfile::tempdir().unwrap();
    let paths = StatePaths::under(dir.path());
    let mut orch = Orchestrator::new(WaydroidSubstrate::new(Persona::GooglePlay));
    let gate = GateState::consented(GateConsentScope::Session).open_crossing(Capability::Mic);
    orch.commit(&gate, gate.to_gate_json().as_bytes(), &paths).unwrap();
    drop(orch); // simulate a crash — only the files on disk survive.

    let recovered = read_sloboda_bridge_state(&paths)
        .expect("a projection we wrote passes the preflight on restart")
        .expect("present");
    assert_eq!(
        parse_sloboda_bridge_schema_version(&recovered),
        Some(SLOBODA_BRIDGE_SCHEMA_VERSION)
    );
    assert!(recovered.starts_with("enabled\n"), "one crossing open → enabled");
}

// ─────────────────────────────────────────────────────────────────────────────
//  2. FAULT INJECTION — write_atomic's rename-based durability under a
//     simulated SIGKILL: never a torn write observed on reload.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn write_atomic_never_exposes_a_partial_write_the_target_is_all_or_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("state.json");

    write_atomic(&target, b"{\"posture\":\"first-committed\"}").unwrap();
    assert_eq!(fs::read_to_string(&target).unwrap(), "{\"posture\":\"first-committed\"}");

    // Simulate a process that was SIGKILLed AFTER it created+fsync'd its temp
    // file (write_atomic's own naming convention) but BEFORE the rename landed —
    // the exact window write_atomic's design closes. We hand-craft that dangling
    // temp file directly, bypassing write_atomic, since we cannot literally
    // signal-interrupt a running test process.
    let dangling_tmp = dir.path().join(format!(".state.json.{}.999999.tmp", std::process::id()));
    fs::write(&dangling_tmp, b"{\"posture\":\"TORN-mid-write-garb").unwrap(); // deliberately truncated

    // The canonical target must be COMPLETELY unaffected — no reader of
    // `state.json` (only that filename is ever trusted) can observe the dangling
    // temp file's existence or contents.
    assert_eq!(
        fs::read_to_string(&target).unwrap(),
        "{\"posture\":\"first-committed\"}",
        "a dangling temp file from a simulated crash must never be observed as the live state"
    );

    // A subsequent, real write_atomic call succeeds normally and is unaffected by
    // the stray leftover (distinct temp name — pid+monotonic seq never collide).
    write_atomic(&target, b"{\"posture\":\"second-committed\"}").unwrap();
    assert_eq!(fs::read_to_string(&target).unwrap(), "{\"posture\":\"second-committed\"}");

    // The stray leftover from the simulated crash is still just an inert file —
    // proving nothing in the read path ever picks it up by accident.
    assert!(dangling_tmp.exists(), "the simulated crash artifact is untouched (out of scope to clean up)");
    assert_ne!(
        fs::read_to_string(&dangling_tmp).unwrap(),
        fs::read_to_string(&target).unwrap()
    );
}

#[test]
fn write_atomic_leaves_no_temp_file_on_a_successful_write_only_the_target() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("sloboda-bridge.state");
    for i in 0..5 {
        write_atomic(&target, format!("iteration-{i}\n").as_bytes()).unwrap();
    }
    assert_eq!(fs::read_to_string(&target).unwrap(), "iteration-4\n");
    let tmp_leftovers: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
        .collect();
    assert!(tmp_leftovers.is_empty(), "every successful write_atomic call cleans up after itself");
}

#[test]
fn a_corrupted_state_json_on_disk_recovers_deny_all_never_a_torn_partial_trust() {
    // Models a torn write from something OUTSIDE this crate's control (e.g. disk
    // corruption, an operator's manual edit gone wrong) — read_gate_state must
    // still fail closed, not partially trust whatever JSON prefix happens to
    // parse.
    let dir = tempfile::tempdir().unwrap();
    let paths = StatePaths::under(dir.path());
    fs::create_dir_all(dir.path()).unwrap();

    // First, a real committed posture.
    let mut orch = Orchestrator::new(ManagedProfileSubstrate::new(Persona::GooglePlay));
    let gate = GateState::consented(GateConsentScope::Persistent).open_crossing(Capability::Camera);
    orch.commit(&gate, gate.to_gate_json().as_bytes(), &paths).unwrap();
    assert_eq!(read_gate_state(&paths), gate);

    // Now simulate corruption: truncate the file mid-object (as if a write was
    // interrupted by something that bypassed write_atomic entirely).
    let full = fs::read_to_string(&paths.state_json).unwrap();
    let truncated = &full[..full.len() / 2];
    fs::write(&paths.state_json, truncated).unwrap();

    assert_eq!(
        read_gate_state(&paths),
        GateState::deny_all(),
        "a truncated/corrupted file must deny wholesale, never partially trust a JSON prefix"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
//  3. CRASH-RECOVERY + PER-CAPABILITY LaneSet ROUND-TRIP
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn per_capability_laneset_round_trips_exactly_across_a_simulated_restart_waydroid() {
    let dir = tempfile::tempdir().unwrap();
    let paths = StatePaths::under(dir.path());

    let mut orch = Orchestrator::new(WaydroidSubstrate::new(Persona::GooglePlay));
    let gate = GateState::consented(GateConsentScope::Session)
        .open_crossing(Capability::Clipboard)
        .open_crossing(Capability::Mic)
        .open_crossing(Capability::Location);
    orch.commit(&gate, gate.to_gate_json().as_bytes(), &paths).unwrap();
    let before = orch.open_lanes();
    assert_eq!(before.count(), 3);

    // Simulate a crash: drop the orchestrator (and its substrate) without any
    // graceful shutdown — nothing but what's on disk survives.
    drop(orch);

    // "Restart": a brand-new process would construct a fresh Substrate (Lifecycle
    // Absent, LaneSet::none) and reload the gate posture from disk.
    let recovered_gate = read_gate_state(&paths);
    assert_eq!(recovered_gate, gate, "the persisted posture is recovered byte-for-byte");

    let mut restarted = Orchestrator::new(WaydroidSubstrate::new(Persona::GooglePlay));
    let r = restarted.reconcile(&recovered_gate).unwrap();
    assert_eq!(r, Reconciliation::Activated);

    let after = restarted.open_lanes();
    for cap in Capability::ALL {
        assert_eq!(
            before.is_open(cap),
            after.is_open(cap),
            "capability {cap:?} must round-trip exactly across the simulated restart"
        );
    }
    assert_eq!(after.count(), 3);
    assert!(restarted.substrate().status().sealed_wallet_preserved);
}

#[test]
fn per_capability_laneset_round_trips_exactly_across_a_simulated_restart_managed_profile() {
    // Same proof, other backend — the round-trip is a property of the
    // orchestrator + persisted GateState, not of one specific substrate.
    let dir = tempfile::tempdir().unwrap();
    let paths = StatePaths::under(dir.path());

    let mut orch = Orchestrator::new(ManagedProfileSubstrate::new(Persona::GooglePlay));
    let gate = GateState::consented(GateConsentScope::Session)
        .open_crossing(Capability::Files)
        .open_crossing(Capability::Camera);
    orch.commit(&gate, gate.to_gate_json().as_bytes(), &paths).unwrap();
    let before = orch.open_lanes();
    drop(orch);

    let recovered_gate = read_gate_state(&paths);
    let mut restarted = Orchestrator::new(ManagedProfileSubstrate::new(Persona::GooglePlay));
    restarted.reconcile(&recovered_gate).unwrap();
    let after = restarted.open_lanes();

    for cap in Capability::ALL {
        assert_eq!(before.is_open(cap), after.is_open(cap), "capability {cap:?} round-trips");
    }
}

#[test]
fn a_killed_posture_round_trips_as_all_lanes_closed_never_a_stale_open_lane() {
    // The dangerous direction to get wrong: a crash that happens to occur WHILE
    // killed must never "recover" back into an open lane.
    let dir = tempfile::tempdir().unwrap();
    let paths = StatePaths::under(dir.path());

    let mut orch = Orchestrator::new(WaydroidSubstrate::new(Persona::GooglePlay));
    let live = GateState::consented(GateConsentScope::Session).open_crossing(Capability::Files);
    orch.commit(&live, live.to_gate_json().as_bytes(), &paths).unwrap();
    assert!(orch.open_lanes().is_open(Capability::Files));

    let mut killed = live;
    killed.kill_switch_engaged = true;
    orch.commit(&killed, killed.to_gate_json().as_bytes(), &paths).unwrap();
    assert!(orch.open_lanes().all_closed());
    drop(orch);

    let recovered = read_gate_state(&paths);
    let mut restarted = Orchestrator::new(WaydroidSubstrate::new(Persona::GooglePlay));
    let r = restarted.reconcile(&recovered).unwrap();
    assert_eq!(r, Reconciliation::Killed, "recovery must never revive a killed span on its own");
    assert!(restarted.open_lanes().all_closed(), "no lane silently reopens across a restart");
}

#[test]
fn empty_laneset_round_trips_as_empty_not_as_a_parse_default_that_happens_to_match() {
    // Guards against a subtle bug class: an empty/default LaneSet round-tripping
    // "successfully" purely because zero-value defaults happen to coincide with
    // the fail-closed default, masking a real reader bug. Assert it explicitly
    // against a DIFFERENT posture in the same test run so the two are
    // distinguishable.
    let dir = tempfile::tempdir().unwrap();
    let paths = StatePaths::under(dir.path());
    let mut orch = Orchestrator::new(WaydroidSubstrate::new(Persona::GooglePlay));

    let no_crossings = GateState::consented(GateConsentScope::Session); // consented, zero lanes thrown
    orch.commit(&no_crossings, no_crossings.to_gate_json().as_bytes(), &paths).unwrap();
    assert!(orch.open_lanes().all_closed(), "consent alone opens nothing (deny-by-default)");

    let recovered = read_gate_state(&paths);
    assert_eq!(recovered.crossings, no_crossings.crossings);
    assert!(recovered.consent_accepted, "consent itself DID round-trip true");
    // The distinguishing proof: consent_accepted is true but crossings are empty —
    // these are two independent fields, not one masking the other.
    assert!(recovered.crossings.all_closed() && recovered.consent_accepted);
}

// ─────────────────────────────────────────────────────────────────────────────
//  SOLE-WRITER DISCIPLINE tied into the crash/restart narrative
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn writer_lock_prevents_two_orchestrators_racing_the_same_state_paths() {
    let dir = tempfile::tempdir().unwrap();
    let paths = StatePaths::under(dir.path());

    let _held = WriterLock::acquire(&paths).expect("the sole writer acquires cleanly");
    let racer = WriterLock::acquire(&paths);
    assert!(racer.is_err(), "a second orchestrator process must be refused, not silently interleaved");
}

#[test]
fn writer_lock_crash_then_restart_uses_the_explicit_steal_recovery_path() {
    let dir = tempfile::tempdir().unwrap();
    let paths = StatePaths::under(dir.path());

    // "Orchestrator process #1" acquires the lock, commits a posture, then is
    // SIGKILLed (Drop never runs — the lock file is left dangling on disk).
    let lock1 = WriterLock::acquire(&paths).unwrap();
    let mut orch = Orchestrator::new(WaydroidSubstrate::new(Persona::GooglePlay));
    let gate = GateState::consented(GateConsentScope::Session).open_crossing(Capability::Location);
    orch.commit(&gate, gate.to_gate_json().as_bytes(), &paths).unwrap();
    std::mem::forget(lock1); // simulate the crash: no cleanup runs.

    // A naive restart attempt is correctly refused — the crash is not silently
    // ignored.
    assert!(WriterLock::acquire(&paths).is_err());

    // The operator/daemon explicitly steals the lock (asserting out-of-band that
    // process #1 is really gone), then recovers the posture and resumes.
    let _lock2 = WriterLock::steal(&paths).expect("explicit steal recovers the lock");
    let recovered = read_gate_state(&paths);
    assert_eq!(recovered, gate);
    let mut restarted = Orchestrator::new(WaydroidSubstrate::new(Persona::GooglePlay));
    restarted.reconcile(&recovered).unwrap();
    assert!(restarted.open_lanes().is_open(Capability::Location));
}

#[test]
fn writer_lock_release_and_reacquire_is_a_normal_graceful_restart() {
    let dir = tempfile::tempdir().unwrap();
    let paths = StatePaths::under(dir.path());
    {
        let _lock = WriterLock::acquire(&paths).unwrap();
        // ... orchestrator does its work, then shuts down gracefully ...
    } // Drop releases the lock file here.
    // A graceful restart never needs `steal` — a plain `acquire` just works.
    assert!(WriterLock::acquire(&paths).is_ok());
}

// ─────────────────────────────────────────────────────────────────────────────
//  Sanity: the honest error surface used throughout is fail-closed by type, not
//  by convention — SubstrateError has no variant that means "trust anyway".
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn verify_sloboda_bridge_schema_error_is_the_backend_refusal_variant() {
    let err = verify_sloboda_bridge_schema("enabled\n").unwrap_err();
    assert!(matches!(err, SubstrateError::Backend(_)));
}

// ─────────────────────────────────────────────────────────────────────────────
//  DURABLE SHUTDOWN AUDIT MARKER — Daemon::shutdown threads its now_iso into a
//  positive, verify_chain-able fail-closed teardown entry on EVERY lane's trail,
//  so a clean shutdown is PROVABLE from the durable record, not merely inferred
//  from the absence of further crossings (which a truncated tail could fake).
//  [HOST]
// ─────────────────────────────────────────────────────────────────────────────

fn shutdown_far_gate() -> ReferenceGate {
    let mut g = ReferenceGate::new();
    g.accept_consent().open(Capability::Clipboard);
    g
}

#[test]
fn daemon_shutdown_writes_a_durable_timestamped_shutdown_marker_verifiable_via_verify_chain() {
    let dir = tempfile::tempdir().unwrap();
    let paths = StatePaths::under(dir.path());
    let audit_path = dir.path().join("crossings.jsonl");

    // Wire ONE lane over the REAL pairing channel + an in-memory loopback bearer,
    // exactly as the E2E loop does — the durable trail is the lane's own file.
    let sk: SessionKey = Zeroizing::new([0x77u8; 32]);
    let (send_ch, recv_ch) = endpoints(&sk);
    let sid = *send_ch.session_id();
    let (_tx_send, tx_recv): (LoopbackTransport, LoopbackTransport) = LoopbackPair::new();

    let direction = Direction::new(Persona::GooglePlay, Persona::Clean);
    let authority = ConsentAuthority::generate();
    let consent = ConsentLedger::new(authority.verifying_key());
    let receiver =
        CrossingReceiver::new(&sid, Persona::GooglePlay, Persona::Clean, shutdown_far_gate());
    let audit = AuditTrail::open(&audit_path).expect("durable audit trail opens");
    let lane = CrossingLane::new(direction, recv_ch, tx_recv, receiver, consent, audit);

    let orch = Orchestrator::new(WaydroidSubstrate::new(Persona::GooglePlay));
    let config = DaemonConfig {
        paths: paths.clone(),
        max_crossings_per_tick: 8,
    };
    let mut daemon = Daemon::new(orch, config);
    daemon.add_lane(lane);

    // Clean, fail-closed shutdown with an explicit, unmistakable wall-clock string.
    const SHUTDOWN_ISO: &str = "2027-11-12T13:14:15Z";
    let report = daemon.shutdown(1_752_000_500, SHUTDOWN_ISO);
    assert!(report.halted, "a clean shutdown is fail-closed, not merely 'stop'");
    assert_eq!(report.reconciliation, Ok(Reconciliation::Killed));
    assert_eq!(report.lanes.len(), 1);
    assert_eq!(
        report.lanes[0].error_breakdown.audit_io, 0,
        "the durable shutdown-marker append succeeded"
    );

    // The durable trail proves the teardown OUT-OF-BAND: exactly one chained,
    // verify_chain-able entry, stamped with the now_iso that was threaded in.
    assert_eq!(
        verify_chain(&audit_path).expect("the durable shutdown marker chain verifies"),
        1,
        "exactly one durable shutdown marker was appended, and the chain verifies"
    );
    let raw = fs::read_to_string(&audit_path).unwrap();
    assert!(raw.contains("\"event\":\"denied\""), "the marker is a fail-closed deny entry");
    assert!(
        raw.contains(SHUTDOWN_ISO),
        "the marker's ts is the now_iso Daemon::shutdown threaded through, verbatim"
    );
    assert!(
        raw.contains("fail-closed terminal marker"),
        "the marker states its fail-closed shutdown intent, greppable by an auditor"
    );
    assert!(raw.contains("\"payload_len\":0"), "a shutdown marker carries no crossing bytes");

    // Belt-and-suspenders: the fail-closed STATE posture landed durably too, so
    // BOTH the projection AND the audit trail independently attest the kill.
    let projection = fs::read_to_string(&paths.sloboda_bridge_state).unwrap();
    assert!(projection.starts_with("disabled\n"));
    assert!(projection.contains("kill=engaged"));
}
