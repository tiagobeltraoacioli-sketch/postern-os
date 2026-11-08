// SPDX-License-Identifier: MIT OR Apache-2.0
//! # `Daemon` — the NoporIS orchestrator DAEMON CORE
//!
//! ## ⚠️ SCAFFOLD / reference-prototype — UNAUDITED. Certifies nothing.
//!
//! This module composes the already-tested library pieces into ONE tick-driven
//! state machine — it invents **no** new crypto, pairing, signing, consent, or
//! substrate logic. It is pure composition:
//!
//! - [`crate::substrate::Orchestrator`] — reads a [`crate::substrate::GateState`]
//!   snapshot and drives a persona-isolation [`crate::substrate::Substrate`]
//!   (create / switch / lane-map / kill), and is the sole runtime writer of
//!   `state.json` + the `sloboda-bridge.state` projection.
//! - [`crate::bridge::CrossingReceiver`] + [`crate::consent_record::ConsentLedger`]
//!   — the signed, `Direction`-pinned, per-capability crossing decision (the
//!   5-step check), with every outcome recorded to a durable
//!   [`crate::audit::AuditTrail`].
//!
//! ## The public surface F2's E2E loop drives
//!
//! ```text
//! Daemon::new(orchestrator, DaemonConfig { paths, .. })   // one substrate, N lanes
//!   .add_lane(CrossingLane::new(direction, channel, transport, receiver, consent, audit))
//!   .tick(now_unix, now_iso) -> DaemonReport               // one state-machine step
//!   .shutdown(now_unix, now_iso) -> DaemonReport            // clean, fail-closed halt
//! ```
//!
//! [`Daemon::tick`] runs, in order, every call:
//! 1. **read** [`crate::substrate::GateState`] off [`DaemonConfig::paths`]
//!    (`state.json`) — fail-closed to [`crate::substrate::GateState::deny_all`] on
//!    a missing/corrupt/foreign file (this is
//!    [`crate::substrate::GateState::from_gate_json`]'s own contract; the daemon
//!    does not re-implement it, only calls it);
//! 2. **drain** each registered [`CrossingLane`] — up to
//!    [`DaemonConfig::max_crossings_per_tick`] crossings per lane per tick (a
//!    bounded, non-blocking drain: [`postern_pairing::transport::Transport::recv`]
//!    is itself non-blocking and a "nothing queued" result simply stops the drain
//!    for that lane, this tick — never a spin, never a block);
//! 3. **kill-switch fail-closed**: before draining, every lane's
//!    [`ConsentLedger`](crate::consent_record::ConsentLedger) kill-switch is
//!    synchronized to `gate.kill_switch_engaged` — engaged this tick means every
//!    lane denies every crossing this tick, even a live signed
//!    [`crate::consent_record::ConsentRecord`] notwithstanding (defense in depth:
//!    the far-side [`crate::consent::GateConsent`] on each
//!    [`crate::bridge::CrossingReceiver`] independently denies too). The
//!    [`Orchestrator::commit`](crate::substrate::Orchestrator::commit) call in
//!    step 4 separately drives the *substrate* through its own kill path;
//! 4. **persist + reconcile**: [`Orchestrator::commit`](crate::substrate::Orchestrator::commit)
//!    writes `state.json` (verbatim) + the derived `sloboda-bridge.state`
//!    projection, THEN drives the substrate to match — returning a
//!    [`DaemonReport`] the caller/test asserts on. Never panics, never
//!    `unwrap()`s on `None`; every failure is a typed `Err` folded into the
//!    report.
//!
//! [`Daemon::shutdown`] is the clean-shutdown path: it revokes every live consent
//! on every lane, appends a durable, timestamped **fail-closed shutdown marker**
//! to each lane's [`crate::audit::AuditTrail`] (a positive,
//! [`verify_chain`](postern_trail::verify_chain)-able teardown record, not merely
//! the absence of further crossings), forces the gate posture to
//! kill-switch-engaged, and runs one final commit — so a shutdown always leaves
//! `state.json` + `sloboda-bridge.state` in the same fail-closed posture a real
//! kill-switch engagement would, and the sealed-wallet invariant holds throughout
//! (a [`Daemon`] and its lanes hold no wallet; nothing here can clear it).
//!
//! ## Honesty rails (carried verbatim from the crate root)
//!
//! Reference-prototype, UNAUDITED. The per-crossing gate is a userland,
//! in-process check, NOT an OS/kernel boundary. This is an app on stock
//! Android, NEVER "Postern OS". The guardian is Yagabona, never "Baba Yaga".
//! The coin (BLCH) is not a security and buys no software.

use std::fs;

use postern_pairing::channel::Channel as PairedChannel;
use postern_pairing::transport::Transport;

use crate::audit::AuditTrail;
use crate::bridge::CrossingReceiver;
use crate::capability::Capability;
use crate::consent::GateConsent;
use crate::consent_record::{ConsentLedger, Direction};
use crate::crossing::CrossingRequest;
use crate::error::BridgeError;
use crate::substrate::{
    read_sloboda_bridge_state, GateState, Orchestrator, Reconciliation, StatePaths, Substrate,
    SubstrateError,
};

/// The stable, machine-greppable reason string stamped into every lane's durable
/// **fail-closed shutdown marker** (see [`Daemon::shutdown`]). An operator (or a
/// test) auditing a lane's [`AuditTrail`] after a clean teardown keys off this
/// exact substring to find the terminal entry that proves the lane was torn down
/// fail-closed — as opposed to merely observing an *absence* of further crossings,
/// which a truncated trail could also produce.
pub const SHUTDOWN_MARKER_REASON: &str =
    "noporis-daemon-shutdown: fail-closed terminal marker (lane consents revoked, kill-switch engaged)";

/// The nominal capability field a shutdown marker's synthetic [`CrossingRequest`]
/// carries. A shutdown is a lane-terminal *administrative* event, not a
/// per-capability crossing — the durable [`AuditTrail`] entry's meaning lives
/// entirely in [`SHUTDOWN_MARKER_REASON`] + its empty payload + zero counter, not
/// in this field. It is a placeholder only, present because [`CrossingRequest`]
/// requires one; it never denotes that a `Clipboard` crossing was attempted.
const SHUTDOWN_MARKER_CAPABILITY: Capability = Capability::Clipboard;

/// Daemon-wide configuration: where the two state files live, and how many
/// crossings a lane may drain in a single [`Daemon::tick`] (bounds the work a
/// single tick can do — a real device's `init`/systemd unit ticks repeatedly
/// rather than draining unboundedly).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonConfig {
    /// The canonical (or, in tests, temp-dir-rooted via
    /// [`StatePaths::under`]) paths of `state.json` and `sloboda-bridge.state`.
    pub paths: StatePaths,
    /// Upper bound on crossings drained per lane, per tick. Never `0` in
    /// practice (a `0` simply drains nothing, which is a valid — if useless —
    /// fail-closed posture, not a panic).
    pub max_crossings_per_tick: usize,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        DaemonConfig {
            paths: StatePaths::default(),
            max_crossings_per_tick: 64,
        }
    }
}

/// A **named** breakdown of the non-delivery, non-deny crossing failures a lane
/// saw in one drain — the finer-grained accounting the orchestrator brief asks
/// for, split out of what used to be a single collapsed `errors` count. Every
/// counter here is still a *rejection*, never a delivery; splitting them only
/// makes the error-path observability the brief wants first-class instead of
/// something a reader had to reconstruct from each lane's [`AuditTrail`].
///
/// Each field is derived directly from the [`BridgeError`] variant the lane's
/// [`CrossingReceiver::receive_crossing_audited`] returned — a mechanical,
/// exhaustive classification (no heuristics, no dropped variants: an
/// unclassified variant lands in [`LaneErrors::other`], never silently
/// vanishes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LaneErrors {
    /// [`BridgeError::WrongSession`] — a crossing bound to a different paired
    /// session (a capture from session A replayed onto session B).
    pub wrong_session: usize,
    /// [`BridgeError::StaleCounter`] + [`BridgeError::ReplayedNonce`] — the
    /// per-session monotonic counter did not advance, or a nonce was reused: a
    /// replay/reorder attempt.
    pub replay: usize,
    /// [`BridgeError::NotGranted`] — no live near-side grant for this capability
    /// (never opened, or revoked/expired) at the sending layer.
    pub not_granted: usize,
    /// [`BridgeError::Channel`] — the paired channel refused the frame (AEAD open
    /// failure): a single flipped ciphertext byte / tamper caught before any
    /// state is trusted.
    pub tamper: usize,
    /// [`BridgeError::Malformed`] — an undecodable crossing envelope.
    pub malformed: usize,
    /// [`BridgeError::PayloadTooLarge`] — the opaque payload exceeded the cap.
    pub oversize: usize,
    /// [`BridgeError::Audit`] — the durable audit trail could not record the
    /// event, so (fail-closed) the crossing did not proceed.
    pub audit_io: usize,
    /// Any [`BridgeError`] not otherwise classified above. Should stay `0` in
    /// practice; exists so a future variant is *counted*, never dropped.
    pub other: usize,
}

impl LaneErrors {
    /// The grand total across every named counter — the single number the old
    /// collapsed `errors` field carried, now derived rather than primary.
    pub fn total(&self) -> usize {
        self.wrong_session
            + self.replay
            + self.not_granted
            + self.tamper
            + self.malformed
            + self.oversize
            + self.audit_io
            + self.other
    }

    /// Classify one [`BridgeError`] into its named bucket, incrementing it.
    /// `Transport`, `GateDenied`, `ConsentRefused` and `FromPersonaMismatch` are
    /// handled by the caller (they are a drain-stop and a *deny*, respectively —
    /// not errors), so they are not expected here; if one ever reaches this method
    /// it is counted in [`LaneErrors::other`] rather than silently ignored.
    fn classify(&mut self, e: &BridgeError) {
        match e {
            BridgeError::WrongSession => self.wrong_session += 1,
            BridgeError::StaleCounter { .. } | BridgeError::ReplayedNonce => self.replay += 1,
            BridgeError::NotGranted => self.not_granted += 1,
            BridgeError::Channel(_) => self.tamper += 1,
            BridgeError::Malformed(_) => self.malformed += 1,
            BridgeError::PayloadTooLarge { .. } => self.oversize += 1,
            BridgeError::Audit(_) => self.audit_io += 1,
            _ => self.other += 1,
        }
    }
}

/// What one [`CrossingLane`] did during a [`Daemon::tick`]'s drain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaneReport {
    /// The cryptographically-pinned direction this lane serves.
    pub direction: Direction,
    /// Crossings delivered (both the signed consent 5-step check AND the
    /// deny-by-default gate said yes).
    pub delivered: usize,
    /// Crossings refused by the consent ledger or the gate (an honest,
    /// attributable deny — never silent).
    pub denied: usize,
    /// Total non-delivery, non-deny failures this tick — the sum of
    /// [`LaneReport::error_breakdown`]. Kept as the at-a-glance grand total (and
    /// for back-compatible asserts); the *reasons* now live in the breakdown
    /// beside it instead of being collapsed away.
    pub errors: usize,
    /// The named, per-reason split of [`LaneReport::errors`] (tamper, replay,
    /// wrong-session, oversize, malformed, audit-I/O, …). Every one is still a
    /// rejection; nothing here is ever a delivery.
    pub error_breakdown: LaneErrors,
}

/// The full outcome of one [`Daemon::tick`] (or [`Daemon::shutdown`]) — what a
/// caller/test asserts on. Deliberately flat and `Eq`-comparable so a test can
/// write `assert_eq!(report.reconciliation, Ok(Reconciliation::Activated))`
/// without reaching into the daemon's internals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonReport {
    /// The clock value this tick ran at (echoes the caller's input; never
    /// derived from a wall clock inside the daemon, so tests stay
    /// deterministic).
    pub now_unix: i64,
    /// What [`Orchestrator::commit`] did — persona create/switch/kill, or a
    /// hard-stop [`SubstrateError`] (e.g. the sealed-wallet invariant tripped).
    pub reconciliation: Result<Reconciliation, SubstrateError>,
    /// The gate's `killSwitch.engaged` this tick, as read from `state.json`.
    pub kill_switch_engaged: bool,
    /// The gate's `consent.accepted` this tick.
    pub consent_accepted: bool,
    /// The sealed-wallet invariant, as read from the gate snapshot. A
    /// [`Daemon`] holds no wallet itself; this is carried through so a test can
    /// assert it never silently flips to `false`.
    pub sealed_wallet_preserved: bool,
    /// `true` if this tick fail-closed everything (kill-switch engaged, the
    /// reconciliation hard-stopped on an invariant violation, or the
    /// `sloboda-bridge.state` schema-preflight refused a foreign projection) —
    /// the daemon's own summary judgement, so a caller need not re-derive it
    /// from the fields above.
    pub halted: bool,
    /// The outcome of this tick's **fail-closed schema-preflight**: before the
    /// daemon overwrites `sloboda-bridge.state`, it reads any existing
    /// projection back and verifies its `schema_version`
    /// ([`crate::substrate::read_sloboda_bridge_state`]). `Ok(())` = absent
    /// (first boot) or a version this orchestrator understands; `Err` = present
    /// but foreign/unknown/unreadable — a hard refusal to clobber a projection a
    /// version we do not understand may still own. On `Err` the tick does **not**
    /// commit and `halted` is `true`. This wires [`crate::substrate::verify_sloboda_bridge_schema`]
    /// to a real runtime read for the first time.
    pub schema_preflight: Result<(), SubstrateError>,
    /// Per-lane drain outcomes, in registration order.
    pub lanes: Vec<LaneReport>,
}

impl std::fmt::Display for DaemonReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "DaemonReport @ t={}", self.now_unix)?;
        writeln!(
            f,
            "  consent_accepted={} kill_switch_engaged={} sealed_wallet_preserved={} halted={}",
            self.consent_accepted, self.kill_switch_engaged, self.sealed_wallet_preserved, self.halted
        )?;
        if let Err(e) = &self.schema_preflight {
            writeln!(f, "  schema_preflight: REFUSED: {e}")?;
        }
        match &self.reconciliation {
            Ok(r) => writeln!(f, "  reconciliation: {r:?}")?,
            Err(e) => writeln!(f, "  reconciliation: ERROR: {e}")?,
        }
        if self.lanes.is_empty() {
            writeln!(f, "  lanes: (none registered)")?;
        }
        for lane in &self.lanes {
            writeln!(
                f,
                "  lane {:?}->{:?}: delivered={} denied={} errors={}",
                lane.direction.from, lane.direction.to, lane.delivered, lane.denied, lane.errors
            )?;
        }
        Ok(())
    }
}

/// One registered crossing direction's live plumbing: the paired
/// [`PairedChannel`] + [`Transport`] bearer, the
/// [`CrossingReceiver`](crate::bridge::CrossingReceiver) bound to it, the
/// signed [`ConsentLedger`] it checks, and the durable [`AuditTrail`] every
/// outcome is recorded to.
///
/// Construct one per `Direction` a paired session serves and hand it to
/// [`Daemon::add_lane`]. `direction.to` MUST match the `to_persona` the
/// `receiver` was constructed with — a mismatch is not a silent bug: the
/// signed consent check's step 3 (direction pinning) will simply refuse every
/// crossing on that lane, fail-closed, and it will show up as `denied`, never
/// as a delivered crossing.
pub struct CrossingLane<G: GateConsent, T: Transport> {
    direction: Direction,
    channel: PairedChannel,
    transport: T,
    receiver: CrossingReceiver<G>,
    consent: ConsentLedger,
    audit: AuditTrail,
}

impl<G: GateConsent, T: Transport> CrossingLane<G, T> {
    /// Assemble one lane from its already-tested parts. Nothing here mints a
    /// key, seals a frame, or decides a consent — it only wires the pieces the
    /// other crate modules already own.
    pub fn new(
        direction: Direction,
        channel: PairedChannel,
        transport: T,
        receiver: CrossingReceiver<G>,
        consent: ConsentLedger,
        audit: AuditTrail,
    ) -> Self {
        CrossingLane {
            direction,
            channel,
            transport,
            receiver,
            consent,
            audit,
        }
    }

    /// The direction this lane serves.
    pub fn direction(&self) -> Direction {
        self.direction
    }

    /// The lane's [`CrossingReceiver`] (e.g. to inspect its in-memory audit
    /// ledger after a test tick).
    pub fn receiver(&self) -> &CrossingReceiver<G> {
        &self.receiver
    }

    /// Mutable access to the lane's signed [`ConsentLedger`] (e.g. to
    /// [`admit`](ConsentLedger::admit) a freshly-minted [`crate::consent_record::ConsentRecord`]
    /// between ticks).
    pub fn consent_mut(&mut self) -> &mut ConsentLedger {
        &mut self.consent
    }

    /// The lane's durable [`AuditTrail`] (e.g. to independently verify its
    /// hash chain after a test run).
    pub fn audit(&self) -> &AuditTrail {
        &self.audit
    }

    /// Drain up to `max` crossings off this lane's transport. Fail-closed and
    /// bounded: a "nothing queued" [`BridgeError::Transport`] result (the
    /// transport's own non-blocking "would block" signal, or any other
    /// transport-level failure — either way, nothing more is available right
    /// now) stops the drain for this lane, this tick, WITHOUT looping or
    /// blocking. Every other refusal is bucketed into the returned
    /// [`LaneReport`]; nothing is ever silently dropped.
    fn drain(&mut self, max: usize, now_unix: i64, now_iso: &str) -> LaneReport {
        let mut delivered = 0usize;
        let mut denied = 0usize;
        let mut error_breakdown = LaneErrors::default();
        for _ in 0..max {
            match self.receiver.receive_crossing_audited(
                &mut self.channel,
                &mut self.transport,
                &mut self.consent,
                &mut self.audit,
                now_unix,
                now_iso,
            ) {
                Ok(_payload) => delivered += 1,
                Err(BridgeError::Transport(_)) => break, // nothing queued — stop, don't spin.
                Err(BridgeError::GateDenied(_))
                | Err(BridgeError::ConsentRefused(_))
                | Err(BridgeError::FromPersonaMismatch { .. }) => denied += 1,
                // Every other refusal is bucketed by its concrete reason, not
                // collapsed — the finer error-path accounting the brief asks for.
                Err(e) => error_breakdown.classify(&e),
            }
        }
        LaneReport {
            direction: self.direction,
            delivered,
            denied,
            errors: error_breakdown.total(),
            error_breakdown,
        }
    }

    /// Append one durable, timestamped **fail-closed shutdown marker** to this
    /// lane's [`AuditTrail`], stamped with the caller's wall-clock `now_iso`.
    ///
    /// A clean [`Daemon::shutdown`] is fail-closed, not merely "stop ticking": it
    /// revokes every consent and slams the gate to kill-switch-engaged. This
    /// records that terminal event **durably**, into the same `fsync`ed,
    /// SHAKE-256 hash-chained trail (via [`postern_trail`]) every crossing
    /// decision already lands in — so an operator auditing the trail afterwards
    /// sees an explicit, [`verify_chain`](postern_trail::verify_chain)-able
    /// "this lane was torn down fail-closed at `now_iso`" entry, not merely the
    /// *absence* of further crossings (which a truncated tail could equally
    /// produce). It is recorded as a [`crate::audit::CrossingEvent::Denied`]
    /// entry — the terminal, deny-everything posture a shutdown lands in —
    /// carrying [`SHUTDOWN_MARKER_REASON`]. It references **no real crossing**:
    /// `counter` is 0, the payload is empty (so `payload_len` is 0 and no bytes
    /// are ever written), and it is bound to this lane's own paired session id;
    /// the `capability` field is a documented nominal placeholder
    /// ([`SHUTDOWN_MARKER_CAPABILITY`]). `now_iso` lands verbatim in the entry's
    /// `ts`. Returns the durable-append result so the caller can fold an I/O
    /// failure into the report's [`LaneErrors::audit_io`] rather than panic on
    /// it — fail-closed to the end.
    fn record_shutdown_marker(&mut self, now_iso: &str) -> Result<(), postern_trail::ChainError> {
        let marker = CrossingRequest {
            session_id: self.receiver.session_id(),
            req_nonce: [0u8; 32],
            counter: 0,
            capability: SHUTDOWN_MARKER_CAPABILITY,
            from_persona: self.direction.from,
            payload: Vec::new(),
        };
        self.audit
            .record_denied(&marker, self.direction.to, now_iso, SHUTDOWN_MARKER_REASON)
    }
}

/// Read the gate's posture off `paths.state_json`, fail-closed. Returns the
/// parsed [`GateState`] AND the exact bytes that should be (re-)persisted:
/// the file's own bytes verbatim if it existed (even if it failed to parse —
/// [`GateState::from_gate_json`] already collapsed that to
/// [`GateState::deny_all`] internally, but the on-disk bytes are left
/// untouched so a corrupt file is never silently "fixed" without a trace), or
/// a freshly-rendered `deny_all()` document if no file exists yet (e.g. first
/// boot / a fresh `--state-dir`).
///
/// A free function (not a method) so it is independently unit-testable and
/// reusable by a future status/introspection surface without needing a live
/// [`Daemon`].
pub fn read_gate_state(paths: &StatePaths) -> (GateState, Vec<u8>) {
    match fs::read(&paths.state_json) {
        Ok(bytes) => {
            let text = String::from_utf8_lossy(&bytes);
            let gate = GateState::from_gate_json(&text);
            (gate, bytes)
        }
        Err(_) => {
            let gate = GateState::deny_all();
            (gate, gate.to_gate_json().into_bytes())
        }
    }
}

/// The daemon: one [`Orchestrator`] (persona-lifecycle reconcile) + N
/// [`CrossingLane`]s (per-direction, signed, deny-by-default crossing
/// decisions), ticked forward by an explicit clock the caller supplies. Holds
/// no wall-clock, no background thread, no signal handler — those are the
/// `[[bin]]`'s job (see `src/bin/noporis-orchestrator.rs`); this type is the
/// pure, host-testable state machine.
pub struct Daemon<S: Substrate, G: GateConsent, T: Transport> {
    orchestrator: Orchestrator<S>,
    config: DaemonConfig,
    lanes: Vec<CrossingLane<G, T>>,
}

impl<S: Substrate, G: GateConsent, T: Transport> Daemon<S, G, T> {
    /// Build a daemon around an already-constructed [`Orchestrator`] (which
    /// itself wraps the caller's [`Substrate`] choice — [`crate::substrate::ManagedProfileSubstrate`],
    /// [`crate::substrate::WaydroidSubstrate`], or a test double) and a
    /// [`DaemonConfig`]. Starts with zero lanes registered — a daemon with no
    /// lanes is a valid, fail-closed posture (it still reconciles the
    /// substrate every tick; it just never delivers anything, because nothing
    /// is registered to drain).
    pub fn new(orchestrator: Orchestrator<S>, config: DaemonConfig) -> Self {
        Daemon {
            orchestrator,
            config,
            lanes: Vec::new(),
        }
    }

    /// Register one crossing direction's live plumbing.
    pub fn add_lane(&mut self, lane: CrossingLane<G, T>) {
        self.lanes.push(lane);
    }

    /// How many lanes are currently registered.
    pub fn lane_count(&self) -> usize {
        self.lanes.len()
    }

    /// Immutable access to the underlying [`Orchestrator`] (e.g. to inspect
    /// [`Orchestrator::open_lanes`] after a tick).
    pub fn orchestrator(&self) -> &Orchestrator<S> {
        &self.orchestrator
    }

    /// Mutable access to the underlying [`Orchestrator`] (e.g. a test that
    /// wants to inspect or drive the substrate directly, alongside the
    /// daemon's own [`Daemon::tick`]).
    pub fn orchestrator_mut(&mut self) -> &mut Orchestrator<S> {
        &mut self.orchestrator
    }

    /// The daemon's configuration (paths + per-tick drain bound).
    pub fn config(&self) -> &DaemonConfig {
        &self.config
    }

    /// One state-machine step. See the module-level doc for the exact 4-step
    /// order this runs. `now_unix` is the caller's clock (injectable — tests
    /// pass a fixed instant; the `[[bin]]` passes the real wall clock or an
    /// injected `--now`). `now_iso` is the wall-clock string recorded into
    /// each lane's durable [`AuditTrail`] entries (see
    /// [`crate::daemon::unix_to_iso8601`] for a dependency-free formatter).
    pub fn tick(&mut self, now_unix: i64, now_iso: &str) -> DaemonReport {
        // 0. SCHEMA-PREFLIGHT (fail-closed): before we become the sole writer and
        //    overwrite `sloboda-bridge.state` in step 4's commit, read any
        //    existing projection back and verify its schema_version. Absent =
        //    fine (first boot). Present + understood = fine. Present + foreign/
        //    unknown/unreadable = a HARD refusal: we do NOT drain, do NOT commit
        //    (never clobber a projection a version we don't understand may own),
        //    and return a halted report carrying the reason. This is the runtime
        //    read that finally wires verify_sloboda_bridge_schema in.
        let schema_preflight = read_sloboda_bridge_state(&self.config.paths).map(|_| ());
        if let Err(e) = &schema_preflight {
            let lanes = self
                .lanes
                .iter()
                .map(|lane| LaneReport {
                    direction: lane.direction,
                    delivered: 0,
                    denied: 0,
                    errors: 0,
                    error_breakdown: LaneErrors::default(),
                })
                .collect();
            return DaemonReport {
                now_unix,
                kill_switch_engaged: false,
                consent_accepted: false,
                sealed_wallet_preserved: true,
                halted: true,
                schema_preflight: Err(e.clone()),
                lanes,
                reconciliation: Err(e.clone()),
            };
        }

        // 1. Read the gate's posture off disk — fail-closed on anything not a
        //    clean, current-schema parse (GateState::from_gate_json's own
        //    contract).
        let (gate, state_json_bytes) = read_gate_state(&self.config.paths);

        // 2 + 3. Drain every registered lane. The kill-switch is synchronized
        //    into each lane's ConsentLedger BEFORE draining, so an engagement
        //    observed THIS tick halts crossings THIS tick — never a tick late.
        let mut lanes = Vec::with_capacity(self.lanes.len());
        for lane in &mut self.lanes {
            if gate.kill_switch_engaged {
                lane.consent.engage_kill_switch();
                // Engage SIGNALS revocation — it does not only flip a flag
                // (the signer-glue kill fan-out contract): every live signed
                // consent is monotonically revoked, so disengaging later
                // reopens the LANE but never resurrects a revoked record —
                // each consent must be freshly re-minted. Idempotent while
                // engaged (0 newly revoked once all are cut), and it also
                // catches any record admitted mid-engagement. Sealed wallet
                // state and pairings are untouched — the ledger holds neither.
                let _ = lane
                    .consent
                    .revoke_all("NoporIS bridge kill-switch engaged: all live bridge consents revoked");
            } else {
                lane.consent.disengage_kill_switch();
            }
            lanes.push(lane.drain(self.config.max_crossings_per_tick, now_unix, now_iso));
        }

        // 4. Persist (state.json verbatim + the derived sloboda-bridge.state
        //    projection) THEN drive the substrate to match. Orchestrator::commit
        //    already orders the writes correctly (projection before the
        //    substrate acts) and already implements the sealed-wallet-invariant
        //    hard-stop and the kill-switch-wins-over-everything precedence — the
        //    daemon does not re-implement any of that, only calls it.
        let reconciliation = self
            .orchestrator
            .commit(&gate, &state_json_bytes, &self.config.paths);

        let halted = gate.kill_switch_engaged || reconciliation.is_err();

        DaemonReport {
            now_unix,
            kill_switch_engaged: gate.kill_switch_engaged,
            consent_accepted: gate.consent_accepted,
            sealed_wallet_preserved: gate.sealed_wallet_preserved,
            halted,
            schema_preflight,
            lanes,
            reconciliation,
        }
    }

    /// The standalone **startup schema-preflight** the `[[bin]]` runs once,
    /// before the first [`Daemon::tick`], to surface a foreign
    /// `sloboda-bridge.state` projection in its exit code (exactly like the
    /// [`crate::WriterLock`] refusal). `Ok(())` when the projection is absent or
    /// carries a schema version this orchestrator understands; `Err` when it is
    /// present but foreign/unknown/unreadable — the caller must then refuse to
    /// start rather than overwrite it. Every [`Daemon::tick`] independently
    /// re-runs this same check (see its step 0), so this is a loud, early copy of
    /// a guard the loop enforces on every pass regardless.
    pub fn preflight(&self) -> Result<(), SubstrateError> {
        read_sloboda_bridge_state(&self.config.paths).map(|_| ())
    }

    /// Clean shutdown: fail-closed, not merely "stop ticking". Revokes every
    /// live consent on every registered lane (defense in depth alongside the
    /// substrate kill below — a lane that somehow still had a live signed
    /// record is explicitly cut, not just left to time out), forces the gate
    /// posture to kill-switch-engaged, and runs one final
    /// [`Orchestrator::commit`] so `state.json` + `sloboda-bridge.state` land
    /// in the same fail-closed posture an operator-engaged kill-switch would
    /// leave them in. The sealed-wallet invariant holds throughout — a
    /// [`Daemon`]/[`CrossingLane`] holds no wallet, so nothing here can clear
    /// it.
    ///
    /// Every lane also gets one durable, `now_iso`-timestamped **fail-closed
    /// shutdown marker** appended to its [`AuditTrail`]
    /// (see [`CrossingLane::record_shutdown_marker`]) — so the teardown is a
    /// positive, [`verify_chain`](postern_trail::verify_chain)-able trail entry,
    /// not merely the absence of further crossings. A durable-append failure is
    /// folded into that lane's [`LaneErrors::audit_io`] (and hence its
    /// [`LaneReport::errors`]), never panicked on — the shutdown still forces the
    /// fail-closed posture regardless.
    ///
    /// Idempotent in posture: calling `shutdown` twice is safe (the second call
    /// revokes zero additional records and re-persists the same posture). Each
    /// call does append its own fresh marker — the trail is append-only, so a
    /// second shutdown honestly records a second teardown event rather than
    /// silently rewriting the first.
    pub fn shutdown(&mut self, now_unix: i64, now_iso: &str) -> DaemonReport {
        let mut lanes = Vec::with_capacity(self.lanes.len());
        for lane in &mut self.lanes {
            let _ = lane.consent.revoke_all("daemon shutdown");
            lane.consent.engage_kill_switch();

            // Durably record the terminal fail-closed marker, stamped now_iso. A
            // trail-I/O failure is bucketed (audit_io), never a panic — a shutdown
            // must always reach the fail-closed commit below.
            let mut error_breakdown = LaneErrors::default();
            if lane.record_shutdown_marker(now_iso).is_err() {
                error_breakdown.audit_io += 1;
            }
            lanes.push(LaneReport {
                direction: lane.direction,
                delivered: 0,
                denied: 0,
                errors: error_breakdown.total(),
                error_breakdown,
            });
        }

        let mut gate = GateState::deny_all();
        gate.kill_switch_engaged = true; // explicit — deny_all() alone is merely "no consent".
        let state_json_bytes = gate.to_gate_json().into_bytes();

        let reconciliation = self
            .orchestrator
            .commit(&gate, &state_json_bytes, &self.config.paths);

        DaemonReport {
            now_unix,
            kill_switch_engaged: true,
            consent_accepted: false,
            sealed_wallet_preserved: gate.sealed_wallet_preserved,
            halted: true,
            // Shutdown deliberately slams the projection to the fail-closed
            // terminal posture (disabled / kill=engaged); overwriting whatever
            // was there is the *point* of a shutdown, so the read-side preflight
            // does not gate it — Ok(()) here means "not applicable on teardown".
            schema_preflight: Ok(()),
            lanes,
            reconciliation,
        }
    }
}

/// Render a unix-seconds instant as a UTC ISO-8601 string
/// (`YYYY-MM-DDTHH:MM:SSZ`), with **no external dependency** (no `chrono`) —
/// the crate takes on no new dependency for this. Used only to fill each
/// audit entry's `ts: String` field ([`crate::audit::CrossingRecord::ts`]),
/// which this crate never parses back — any stable string is honest here, but
/// a real timestamp is more useful than a raw integer for a human reading the
/// trail. Uses the standard proleptic-Gregorian "days from civil" algorithm
/// (Howard Hinnant's `civil_from_days`), correct for the full `i64` range of
/// unix seconds this crate's dates ever take.
pub fn unix_to_iso8601(now_unix: i64) -> String {
    let days = now_unix.div_euclid(86_400);
    let secs_of_day = now_unix.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let hh = secs_of_day / 3600;
    let mm = (secs_of_day % 3600) / 60;
    let ss = secs_of_day % 60;
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Howard Hinnant's `civil_from_days`: days-since-epoch (1970-01-01) → a
/// proleptic-Gregorian `(year, month, day)`. Public-domain algorithm, ported
/// verbatim; see <http://howardhinnant.github.io/date_algorithms.html>.
fn civil_from_days(z_days: i64) -> (i64, u32, u32) {
    let z = z_days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 }.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::Capability;
    use crate::consent::{ConsentDecision, GateConsent};
    use crate::consent_record::{ConsentAuthority, ConsentScope as RecordScope};
    use crate::persona::Persona;
    use crate::substrate::{ConsentScope as GateScope, HostStubDpc, ManagedProfileSubstrate};
    use postern_pairing::channel::endpoints;
    use postern_pairing::hybrid::SessionKey;
    use postern_pairing::transport::{LoopbackPair, LoopbackTransport};
    use zeroize::Zeroizing;

    const NOW: i64 = 1_752_000_000;
    const ISO: &str = "2026-07-13T00:00:00Z";

    /// A permissive test gate: always Allow. Stands in for the real N-gate;
    /// this file tests the DAEMON's composition, not the gate's own semantics
    /// (those are `consent.rs`'s job).
    #[derive(Clone)]
    struct AllowAllGate;
    impl GateConsent for AllowAllGate {
        fn decide(&self, _capability: Capability, _from: Persona, _to: Persona) -> ConsentDecision {
            ConsentDecision::Allow
        }
    }

    /// Wire one lane AND admit a live, signed, `Session`-scope
    /// [`crate::consent_record::ConsentRecord`] for `capability` into its
    /// `ConsentLedger` — [`crate::bridge::CrossingReceiver::receive_crossing_audited`]
    /// requires BOTH the signed consent 5-step check AND the gate to say yes
    /// (defense in depth), so a daemon test that wants a crossing to actually
    /// deliver must mint one, exactly as the near side would.
    fn wired_lane(
        direction: Direction,
        capability: Capability,
        audit_path: &std::path::Path,
    ) -> (CrossingLane<AllowAllGate, LoopbackTransport>, LoopbackTransport, [u8; 32]) {
        let sk: SessionKey = Zeroizing::new([0x77u8; 32]);
        let (ch_send, ch_recv) = endpoints(&sk);
        let sid = *ch_send.session_id();
        let (tx_send, tx_recv) = LoopbackPair::new();

        let mut authority = ConsentAuthority::from_seed([0x55u8; 32]);
        let near_pub = authority.verifying_key();
        let mut consent = ConsentLedger::new(near_pub);
        let record = authority.mint(
            crate::crossing::crossing_session_id(&sid),
            capability,
            direction,
            RecordScope::Session,
            NOW - 100,
            NOW + 100_000,
            "test-peer",
        );
        consent.admit(record).expect("near-key-signed record admits");

        let receiver = CrossingReceiver::new(&sid, direction.from, direction.to, AllowAllGate);
        let audit = AuditTrail::open(audit_path).expect("open audit trail");
        let lane = CrossingLane::new(direction, ch_recv, tx_recv, receiver, consent, audit);
        // Return the SENDING side's channel/transport so the test can push a
        // crossing in; the lane owns the RECEIVING side.
        let _ = ch_send; // only its session id is needed by the caller
        (lane, tx_send, sid)
    }

    fn daemon_over(dir: &std::path::Path) -> Daemon<ManagedProfileSubstrate<HostStubDpc>, AllowAllGate, LoopbackTransport> {
        let orchestrator = Orchestrator::new(ManagedProfileSubstrate::<HostStubDpc>::new(Persona::GooglePlay));
        let config = DaemonConfig {
            paths: StatePaths::under(dir),
            max_crossings_per_tick: 8,
        };
        Daemon::new(orchestrator, config)
    }

    #[test]
    fn iso8601_formats_known_instants() {
        assert_eq!(unix_to_iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(unix_to_iso8601(86_400), "1970-01-02T00:00:00Z");
        assert_eq!(unix_to_iso8601(NOW), "2025-07-08T18:40:00Z");
    }

    #[test]
    fn fail_closed_default_with_no_state_file_holds_closed_and_never_panics() {
        let dir = tempfile::tempdir().unwrap();
        let mut daemon = daemon_over(dir.path());
        let report = daemon.tick(NOW, ISO);

        assert!(!report.kill_switch_engaged);
        assert!(!report.consent_accepted);
        assert!(report.sealed_wallet_preserved);
        assert!(!report.halted, "no consent is a held-closed posture, not a halt");
        assert_eq!(report.reconciliation, Ok(Reconciliation::HeldClosedNoConsent));
        assert!(report.lanes.is_empty());

        // The daemon is the sole writer: both files now exist with the
        // fail-closed default posture, even though no state.json existed yet.
        assert!(dir.path().join("state.json").exists());
        let projection = fs::read_to_string(dir.path().join("sloboda-bridge.state")).unwrap();
        assert!(projection.starts_with("disabled\n"));
    }

    #[test]
    fn a_corrupt_state_file_collapses_to_deny_never_panics() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("state.json"), b"{not json at all").unwrap();
        let mut daemon = daemon_over(dir.path());
        let report = daemon.tick(NOW, ISO);
        assert!(!report.consent_accepted);
        assert_eq!(report.reconciliation, Ok(Reconciliation::HeldClosedNoConsent));
    }

    #[test]
    fn consented_gate_activates_the_substrate_and_delivers_a_crossing() {
        let dir = tempfile::tempdir().unwrap();
        let mut daemon = daemon_over(dir.path());

        let direction = Direction::new(Persona::GooglePlay, Persona::Clean);
        let (lane, mut tx_send, sid) =
            wired_lane(direction, Capability::Clipboard, &dir.path().join("audit.jsonl"));
        daemon.add_lane(lane);

        // Consented + one crossing lane open (clipboard) — sent straight onto
        // the lane's transport before the tick, exactly as a real paired
        // session would have queued it.
        let gate = GateState::consented(GateScope::Session).open_crossing(Capability::Clipboard);
        fs::write(dir.path().join("state.json"), gate.to_gate_json()).unwrap();

        let req = crate::crossing::CrossingRequest {
            session_id: crate::crossing::crossing_session_id(&sid),
            req_nonce: [9u8; 32],
            counter: 1,
            capability: Capability::Clipboard,
            from_persona: Persona::GooglePlay,
            payload: b"hello".to_vec(),
        };
        // Seal it exactly as CrossingSender::send_crossing would, over a
        // freshly-endpointed matching channel (same session key/session id).
        let sk: SessionKey = Zeroizing::new([0x77u8; 32]);
        let (mut ch_send2, _ch_recv2) = endpoints(&sk);
        let frame = ch_send2.seal_frame(&req.encode().unwrap()).unwrap();
        tx_send.send(&frame.to_bytes()).unwrap();

        let report = daemon.tick(NOW, ISO);
        assert_eq!(report.reconciliation, Ok(Reconciliation::Activated));
        assert!(!report.halted);
        assert_eq!(report.lanes.len(), 1);
        assert_eq!(report.lanes[0].delivered, 1, "the queued crossing was delivered");
        assert_eq!(report.lanes[0].denied, 0);
        assert_eq!(report.lanes[0].errors, 0);
    }

    #[test]
    fn kill_switch_halts_every_lane_and_drives_the_substrate_kill_path() {
        let dir = tempfile::tempdir().unwrap();
        let mut daemon = daemon_over(dir.path());

        let direction = Direction::new(Persona::GooglePlay, Persona::Clean);
        let (lane, mut tx_send, sid) =
            wired_lane(direction, Capability::Clipboard, &dir.path().join("audit.jsonl"));
        daemon.add_lane(lane);

        // First tick: consented + open, so the substrate is Active.
        let gate = GateState::consented(GateScope::Session).open_crossing(Capability::Clipboard);
        fs::write(dir.path().join("state.json"), gate.to_gate_json()).unwrap();
        let first = daemon.tick(NOW, ISO);
        assert_eq!(first.reconciliation, Ok(Reconciliation::Activated));

        // Now engage the kill-switch AND still have a crossing queued.
        let mut killed_gate = gate;
        killed_gate.kill_switch_engaged = true;
        fs::write(dir.path().join("state.json"), killed_gate.to_gate_json()).unwrap();

        let req = crate::crossing::CrossingRequest {
            session_id: crate::crossing::crossing_session_id(&sid),
            req_nonce: [11u8; 32],
            counter: 1,
            capability: Capability::Clipboard,
            from_persona: Persona::GooglePlay,
            payload: b"still-queued".to_vec(),
        };
        let sk: SessionKey = Zeroizing::new([0x77u8; 32]);
        let (mut ch_send2, _ch_recv2) = endpoints(&sk);
        let frame = ch_send2.seal_frame(&req.encode().unwrap()).unwrap();
        tx_send.send(&frame.to_bytes()).unwrap();

        let second = daemon.tick(NOW + 1, ISO);
        assert!(second.kill_switch_engaged);
        assert!(second.halted, "kill-switch engaged this tick halts the daemon");
        assert_eq!(second.reconciliation, Ok(Reconciliation::Killed));
        assert_eq!(second.lanes[0].delivered, 0, "nothing crosses once the kill-switch is engaged");
        assert_eq!(second.lanes[0].denied, 1, "the queued crossing is refused, not silently dropped");

        // Sealed-wallet invariant: still true throughout — the substrate holds
        // no wallet and the kill path is structurally incapable of clearing it.
        assert!(second.sealed_wallet_preserved);
    }

    #[test]
    fn disengaging_the_kill_switch_never_resurrects_revoked_consents() {
        let dir = tempfile::tempdir().unwrap();
        let mut daemon = daemon_over(dir.path());

        let direction = Direction::new(Persona::GooglePlay, Persona::Clean);
        let (lane, mut tx_send, sid) =
            wired_lane(direction, Capability::Clipboard, &dir.path().join("audit.jsonl"));
        daemon.add_lane(lane);

        // Tick 1: consented + open — the lane's minted consent is live.
        let gate = GateState::consented(GateScope::Session).open_crossing(Capability::Clipboard);
        fs::write(dir.path().join("state.json"), gate.to_gate_json()).unwrap();
        assert_eq!(daemon.tick(NOW, ISO).reconciliation, Ok(Reconciliation::Activated));

        // Tick 2: the operator engages the kill-switch. Engage SIGNALS
        // revocation (the signer-glue kill fan-out contract): every live
        // signed consent is monotonically revoked, not merely gated behind
        // the reversible kill flag.
        let mut killed_gate = gate;
        killed_gate.kill_switch_engaged = true;
        fs::write(dir.path().join("state.json"), killed_gate.to_gate_json()).unwrap();
        assert!(daemon.tick(NOW + 1, ISO).halted);

        // Tick 3: the operator disengages. The LANE may reopen, but the
        // revoked consent must NOT come back: a queued crossing is refused
        // (Revoked), never delivered, until a consent is freshly re-minted
        // and re-admitted.
        fs::write(dir.path().join("state.json"), gate.to_gate_json()).unwrap();
        let req = crate::crossing::CrossingRequest {
            session_id: crate::crossing::crossing_session_id(&sid),
            req_nonce: [13u8; 32],
            counter: 1,
            capability: Capability::Clipboard,
            from_persona: Persona::GooglePlay,
            payload: b"after-disengage".to_vec(),
        };
        let sk: SessionKey = Zeroizing::new([0x77u8; 32]);
        let (mut ch_send, _unused) = endpoints(&sk);
        let frame = ch_send.seal_frame(&req.encode().unwrap()).unwrap();
        tx_send.send(&frame.to_bytes()).unwrap();

        let third = daemon.tick(NOW + 2, ISO);
        assert!(!third.kill_switch_engaged);
        assert!(!third.halted, "disengage reopens the lane itself");
        assert_eq!(
            third.lanes[0].delivered, 0,
            "a revoked consent never resurrects on disengage"
        );
        assert_eq!(
            third.lanes[0].denied, 1,
            "the crossing is refused (Revoked), not silently dropped"
        );
    }

    #[test]
    fn shutdown_is_fail_closed_and_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let mut daemon = daemon_over(dir.path());
        let direction = Direction::new(Persona::GooglePlay, Persona::Clean);
        let (lane, _tx_send, _sid) =
            wired_lane(direction, Capability::Files, &dir.path().join("audit.jsonl"));
        daemon.add_lane(lane);

        // Bring it up first.
        let gate = GateState::consented(GateScope::Session).open_crossing(Capability::Files);
        fs::write(dir.path().join("state.json"), gate.to_gate_json()).unwrap();
        let up = daemon.tick(NOW, ISO);
        assert_eq!(up.reconciliation, Ok(Reconciliation::Activated));

        let first_shutdown = daemon.shutdown(NOW + 1, ISO);
        assert!(first_shutdown.kill_switch_engaged);
        assert!(first_shutdown.halted);
        assert_eq!(first_shutdown.reconciliation, Ok(Reconciliation::Killed));
        assert!(first_shutdown.sealed_wallet_preserved);

        // Idempotent: a second shutdown is safe and lands the same posture.
        let second_shutdown = daemon.shutdown(NOW + 2, ISO);
        assert_eq!(second_shutdown.reconciliation, Ok(Reconciliation::Killed));

        // The persisted projection reflects the kill, durably.
        let projection = fs::read_to_string(dir.path().join("sloboda-bridge.state")).unwrap();
        assert!(projection.starts_with("disabled\n"));
        assert!(projection.contains("kill=engaged"));
    }

    #[test]
    fn shutdown_records_a_durable_timestamped_fail_closed_marker_in_each_lane() {
        use postern_trail::verify_chain;

        let dir = tempfile::tempdir().unwrap();
        let mut daemon = daemon_over(dir.path());

        // Two lanes, each with its OWN durable trail — the marker must land in
        // EVERY lane's trail, not just the first.
        let direction = Direction::new(Persona::GooglePlay, Persona::Clean);
        let audit_a = dir.path().join("audit-a.jsonl");
        let audit_b = dir.path().join("audit-b.jsonl");
        let (lane_a, _txa, _sa) = wired_lane(direction, Capability::Clipboard, &audit_a);
        let (lane_b, _txb, _sb) = wired_lane(direction, Capability::Files, &audit_b);
        daemon.add_lane(lane_a);
        daemon.add_lane(lane_b);

        // A distinct, unmistakable wall-clock string so the assert on `ts` can't
        // pass by coincidence with any other timestamp in the trail.
        const SHUTDOWN_ISO: &str = "2027-03-04T05:06:07Z";
        let report = daemon.shutdown(NOW + 5, SHUTDOWN_ISO);

        assert!(report.halted);
        assert_eq!(report.reconciliation, Ok(Reconciliation::Killed));
        assert_eq!(report.lanes.len(), 2);
        for lane_report in &report.lanes {
            assert_eq!(
                lane_report.error_breakdown.audit_io, 0,
                "the durable marker append succeeded on every lane"
            );
            assert_eq!(lane_report.errors, 0);
        }

        // Each lane's durable trail now carries EXACTLY the one terminal marker,
        // it verifies end-to-end, it is timestamped with now_iso, and it never
        // leaked any payload bytes (empty payload → payload_len 0).
        for path in [&audit_a, &audit_b] {
            let n = verify_chain(path).expect("the durable shutdown marker chain verifies");
            assert_eq!(n, 1, "exactly the one terminal shutdown marker was appended");
            let raw = fs::read_to_string(path).unwrap();
            assert!(raw.contains("\"event\":\"denied\""), "the marker is a fail-closed deny entry");
            assert!(
                raw.contains(SHUTDOWN_MARKER_REASON),
                "the marker carries the stable fail-closed reason"
            );
            assert!(
                raw.contains(SHUTDOWN_ISO),
                "the marker's ts is the caller's now_iso, threaded through verbatim"
            );
            assert!(raw.contains("\"payload_len\":0"), "a marker references no real crossing");
        }
    }

    #[test]
    fn shutdown_marker_chains_after_a_real_delivered_crossing_and_still_verifies() {
        use postern_trail::verify_chain;

        let dir = tempfile::tempdir().unwrap();
        let mut daemon = daemon_over(dir.path());

        let direction = Direction::new(Persona::GooglePlay, Persona::Clean);
        let audit_path = dir.path().join("audit.jsonl");
        let (lane, mut tx_send, sid) = wired_lane(direction, Capability::Clipboard, &audit_path);
        daemon.add_lane(lane);

        // Deliver one real crossing first, so the trail is non-empty when the
        // shutdown marker is appended — the marker must extend the SAME chain,
        // not start a fresh (or corrupt) one.
        let gate = GateState::consented(GateScope::Session).open_crossing(Capability::Clipboard);
        fs::write(dir.path().join("state.json"), gate.to_gate_json()).unwrap();
        let req = crate::crossing::CrossingRequest {
            session_id: crate::crossing::crossing_session_id(&sid),
            req_nonce: [21u8; 32],
            counter: 1,
            capability: Capability::Clipboard,
            from_persona: Persona::GooglePlay,
            payload: b"hello".to_vec(),
        };
        let sk: SessionKey = Zeroizing::new([0x77u8; 32]);
        let (mut ch_send2, _ch_recv2) = endpoints(&sk);
        let frame = ch_send2.seal_frame(&req.encode().unwrap()).unwrap();
        tx_send.send(&frame.to_bytes()).unwrap();
        assert_eq!(daemon.tick(NOW, ISO).lanes[0].delivered, 1);
        assert_eq!(verify_chain(&audit_path).unwrap(), 1, "one delivered crossing recorded");

        // Now shut down: the marker is appended AFTER the delivery, and the whole
        // chain (delivered + marker) still verifies.
        let report = daemon.shutdown(NOW + 1, "2027-03-04T05:06:07Z");
        assert_eq!(report.lanes[0].error_breakdown.audit_io, 0);
        assert_eq!(
            verify_chain(&audit_path).unwrap(),
            2,
            "delivery then terminal marker: two chained entries, still verifiable"
        );
        let raw = fs::read_to_string(&audit_path).unwrap();
        assert!(raw.contains("\"event\":\"delivered\""));
        assert!(raw.contains(SHUTDOWN_MARKER_REASON));
    }

    #[test]
    fn two_shutdowns_append_two_markers_and_the_chain_still_verifies() {
        use postern_trail::verify_chain;

        let dir = tempfile::tempdir().unwrap();
        let mut daemon = daemon_over(dir.path());
        let direction = Direction::new(Persona::GooglePlay, Persona::Clean);
        let audit_path = dir.path().join("audit.jsonl");
        let (lane, _tx, _sid) = wired_lane(direction, Capability::Files, &audit_path);
        daemon.add_lane(lane);

        // The posture is idempotent (both land Killed), but the append-only trail
        // honestly records BOTH teardown events rather than silently rewriting.
        assert_eq!(daemon.shutdown(NOW + 1, "2027-01-01T00:00:00Z").reconciliation, Ok(Reconciliation::Killed));
        assert_eq!(daemon.shutdown(NOW + 2, "2027-01-01T00:00:01Z").reconciliation, Ok(Reconciliation::Killed));

        assert_eq!(
            verify_chain(&audit_path).unwrap(),
            2,
            "two shutdowns → two chained markers, both verifiable"
        );
        let raw = fs::read_to_string(&audit_path).unwrap();
        assert!(raw.contains("2027-01-01T00:00:00Z"));
        assert!(raw.contains("2027-01-01T00:00:01Z"));
        assert_eq!(
            raw.matches(SHUTDOWN_MARKER_REASON).count(),
            2,
            "each shutdown stamps its own terminal marker"
        );
    }

    #[test]
    fn drain_is_bounded_by_max_crossings_per_tick() {
        let dir = tempfile::tempdir().unwrap();
        let orchestrator = Orchestrator::new(ManagedProfileSubstrate::<HostStubDpc>::new(Persona::GooglePlay));
        let config = DaemonConfig {
            paths: StatePaths::under(dir.path()),
            max_crossings_per_tick: 2, // deliberately small
        };
        let mut daemon = Daemon::new(orchestrator, config);

        let direction = Direction::new(Persona::GooglePlay, Persona::Clean);
        let (lane, mut tx_send, sid) =
            wired_lane(direction, Capability::Clipboard, &dir.path().join("audit.jsonl"));
        daemon.add_lane(lane);

        let gate = GateState::consented(GateScope::Session).open_crossing(Capability::Clipboard);
        fs::write(dir.path().join("state.json"), gate.to_gate_json()).unwrap();

        // Queue 5 crossings; only `max_crossings_per_tick` (2) may drain this
        // tick. All 5 must be sealed on ONE sender channel (its counter must
        // advance sequentially to match what the receiver's paired channel
        // expects) — a fresh `endpoints()` pair per crossing would each reset
        // to counter 1 and only the first would ever open successfully.
        let sk: SessionKey = Zeroizing::new([0x77u8; 32]);
        let (mut ch_send, _unused) = endpoints(&sk);
        for i in 0..5u64 {
            let req = crate::crossing::CrossingRequest {
                session_id: crate::crossing::crossing_session_id(&sid),
                req_nonce: [i as u8; 32],
                counter: i + 1,
                capability: Capability::Clipboard,
                from_persona: Persona::GooglePlay,
                payload: b"x".to_vec(),
            };
            let frame = ch_send.seal_frame(&req.encode().unwrap()).unwrap();
            tx_send.send(&frame.to_bytes()).unwrap();
        }

        let first = daemon.tick(NOW, ISO);
        assert_eq!(first.lanes[0].delivered, 2, "bounded by max_crossings_per_tick");

        let second = daemon.tick(NOW + 1, ISO);
        assert_eq!(second.lanes[0].delivered, 2, "drains the next batch");

        let third = daemon.tick(NOW + 2, ISO);
        assert_eq!(third.lanes[0].delivered, 1, "drains the remainder, then the lane is empty");

        let fourth = daemon.tick(NOW + 3, ISO);
        assert_eq!(fourth.lanes[0].delivered, 0, "nothing left to drain — no error, no panic");
    }

    #[test]
    fn read_gate_state_is_fail_closed_and_reusable_standalone() {
        let dir = tempfile::tempdir().unwrap();
        let paths = StatePaths::under(dir.path());
        let (gate, _bytes) = read_gate_state(&paths);
        assert_eq!(gate, GateState::deny_all());
    }
}
