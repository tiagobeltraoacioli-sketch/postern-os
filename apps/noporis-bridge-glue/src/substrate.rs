// SPDX-License-Identifier: MIT OR Apache-2.0
//! The on-device **orchestrator spine**: read the gate state → drive a
//! persona-isolation [`Substrate`] → service the persona switch, the
//! per-capability lane mapping, and the kill-switch, fail-closed — and be the
//! **sole runtime writer** of the two consent state files (`state.json` + the
//! `sloboda-bridge.state` projection).
//!
//! This is the piece the design calls "the spine of *functional*": the small,
//! host-testable control-flow that sits between Dev N-gate's deny-by-default
//! consent state and whatever concrete thing keeps the two personas apart on a
//! real device (an Android managed profile, a Waydroid container). The
//! [`Orchestrator`] owns **no** isolation itself — it reads a [`GateState`]
//! snapshot and issues create / switch / lane / kill commands to a [`Substrate`],
//! which is the seam a real backend implements.
//!
//! ## Wave-1: real backends behind injectable seams
//!
//! The trait, the reconcile control-flow, and the sealed-wallet invariant are
//! **real and tested on the host**. The two backends are now driven through
//! injectable **seams** so the same host-testable control-flow can front either an
//! in-memory reference (default feature `host-stub`, keeps `cargo test` offline and
//! green) **or** a real device driver:
//!
//! - [`ManagedProfileSubstrate`] (near side) drives a [`DpcSeam`] — Porog's shared
//!   managed-profile DPC. On device the seam is implemented by the Kotlin
//!   `labs.postern.persona.lifecycle.PersonaLifecycle` reached over JNI (create /
//!   pause-resume / kill-as-pause). On the host it is [`HostStubDpc`] (isolates
//!   nothing). **VM/device work** — the JNI binding is `UNTESTED-until-device`.
//! - [`WaydroidSubstrate`] (far side) drives a [`SlobodaSeam`]. The real
//!   [`SlobodaCli`] execs the **existing read-only** `apps/sloboda` wrapper
//!   (`sloboda start|stop|kill|status`) — NoporIS does **not** own or boot the
//!   container, it drives sloboda's seam and observes its state. On the host it is
//!   [`HostStubSloboda`]. Real Waydroid boot/kill is `UNTESTED-until-VM` (needs a
//!   binder kernel).
//!
//! The per-capability **lane** bits ([`LaneSet`]) are orchestration state, not a
//! device effect a seam drives: both backends keep their `LaneSet` directly on the
//! substrate struct, deny-by-default, and slam it to [`LaneSet::none`] on every
//! `kill`/`revive`/`close_all_lanes` — a real backend wires a concrete per-lane
//! effect (a cross-profile grant, a `wl-clipboard`/device passthrough) behind
//! [`Substrate::open_lane`] / [`Substrate::close_lane`] later; today it is a bit.
//!
//! ## Sole runtime writer of the state files (plan §5)
//!
//! To keep exactly one writer per artifact, the orchestrator — not the gate-store,
//! not the kill-switch — is the **sole runtime writer** of both files, via
//! temp-file + `fsync` + atomic `rename` ([`write_atomic`]):
//!
//! - `state.json` (canonical `/var/lib/postern/noporis-gate/state.json`) — the
//!   authoritative gate posture, persisted verbatim (Dev C's `gate-store.mjs`
//!   *computes* it; the orchestrator *persists* it).
//! - `sloboda-bridge.state` (canonical `/run/postern/consent/sloboda-bridge.state`)
//!   — the tiny derived projection sloboda/Porog read **read-only**. Its line-1
//!   authority (`enabled`/`disabled`) mirrors Dev C's pure
//!   `projectSlobodaBridgeState(state)`; see [`project_sloboda_line`].
//!
//! ## Honesty rails (carried verbatim)
//!
//! - **Reference-prototype, UNAUDITED.** NoporIS adds **no** new attestation and
//!   nothing here is attested — a real managed-profile / LXC seam may honestly claim
//!   [`Enforcement::OsBoundary`] for its *storage/process* split (that boundary is
//!   the OS's), but that is **not** attestation and no surface relabels the far
//!   side attested.
//! - The Google-Play persona is the **less-private, non-attestable** side by
//!   construction; the substrate that manages it does not change that.
//! - Enforcement in the **host stubs** is **userland, by-construction** — **not**
//!   an OS/kernel boundary. A rooted host defeats every boundary here.
//! - **Deny-by-default per lane.** Every capability lane starts closed; a lane the
//!   gate does not explicitly open stays closed; and the kill-switch / a withdrawn
//!   consent slams *all* of them shut. The orchestrator only ever *narrows* —
//!   open lanes are always a subset of `gate.crossings`, never a superset.
//! - **Cutting the span never destroys sealed wallet state.** The kill path is
//!   structurally incapable of clearing [`SubstrateStatus::sealed_wallet_preserved`]
//!   — a substrate holds no wallet, and no seam is handed one to destroy.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::capability::Capability;
use crate::consent_record::Direction;
use crate::persona::Persona;

/// The number of per-capability lanes a substrate exposes (the five bridges).
const LANES: usize = Capability::ALL.len();

/// The honest enforcement class of a substrate boundary. Pinned so no surface can
/// silently round a userland stub up to a kernel/attested boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enforcement {
    /// A userland, in-process check — a best-effort convenience, **not** a
    /// security boundary. Every host stub in this file is this. A rooted host
    /// defeats it.
    ByConstruction,
    /// The OS/kernel enforces the boundary (an Android managed profile's
    /// storage/process separation, or Waydroid's LXC split). The honest label a
    /// *real* device seam carries for its storage seam — recorded so the seam's
    /// intent is documented. **Not attestation.** A host stub is never this.
    OsBoundary,
}

impl Enforcement {
    /// The stable honest caveat string.
    pub fn honest_label(self) -> &'static str {
        match self {
            Enforcement::ByConstruction => {
                "userland, in-process check — not an OS/kernel boundary; a rooted host defeats it"
            }
            Enforcement::OsBoundary => {
                "OS/kernel-enforced storage/process boundary (managed profile / LXC) — not attestation; a rooted host still defeats it"
            }
        }
    }
}

/// The consent scope carried by the gate's first-entry consent (mirrors the
/// gate-state schema's `consent.scope`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentScope {
    /// Valid for this boot only — re-ask next boot. The safer default.
    Session,
    /// Remembered across boots until revoked.
    Persistent,
}

impl ConsentScope {
    /// The gate-state schema wire value.
    pub fn as_wire(self) -> &'static str {
        match self {
            ConsentScope::Session => "session",
            ConsentScope::Persistent => "persistent",
        }
    }
}

/// The set of per-capability lanes ("crossings") a substrate exposes — the concrete
/// cross-profile / Waydroid plumbing the orchestrator opens for each gate `Allow`.
///
/// **Deny-by-default, always.** Every lane starts closed; a lane the gate does not
/// explicitly open stays closed; and the kill-switch / a withdrawn consent slams
/// *all* of them shut. A closed lane exposes **nothing** — the honest point of the
/// guarded crossing is that nothing crosses that the operator did not hand across.
/// Indexed by [`Capability::ALL`] order so it maps 1:1 onto the gate's five bridges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaneSet {
    open: [bool; LANES],
}

impl Default for LaneSet {
    fn default() -> Self {
        LaneSet::none()
    }
}

fn lane_index(cap: Capability) -> usize {
    Capability::ALL
        .iter()
        .position(|&c| c == cap)
        .expect("Capability is in ALL")
}

impl LaneSet {
    /// No lane open — the fail-closed default the wrapper MUST assume.
    pub const fn none() -> Self {
        LaneSet {
            open: [false; LANES],
        }
    }

    /// Is `cap`'s lane open?
    pub fn is_open(&self, cap: Capability) -> bool {
        self.open[lane_index(cap)]
    }

    /// Builder: set `cap`'s lane open/closed, returning the updated set.
    pub fn with(mut self, cap: Capability, open: bool) -> Self {
        self.open[lane_index(cap)] = open;
        self
    }

    /// Open `cap`'s lane in place.
    pub fn set_open(&mut self, cap: Capability) {
        self.open[lane_index(cap)] = true;
    }

    /// Close `cap`'s lane in place.
    pub fn set_closed(&mut self, cap: Capability) {
        self.open[lane_index(cap)] = false;
    }

    /// How many lanes are open.
    pub fn count(&self) -> usize {
        self.open.iter().filter(|&&o| o).count()
    }

    /// Are all lanes closed (the fail-closed posture)?
    pub fn all_closed(&self) -> bool {
        self.count() == 0
    }

    /// Iterate the currently-open capabilities, in [`Capability::ALL`] order.
    pub fn iter_open(&self) -> impl Iterator<Item = Capability> + '_ {
        Capability::ALL.into_iter().filter(move |&c| self.is_open(c))
    }
}

/// The per-lane crossing **direction** — for each of the five capability lanes,
/// which `from → to` persona flow that lane carries. A lane's direction is a
/// structural fact of the pairing (Composition-UX §2), never something the
/// requester sets: it says which world hands the payload across and which world
/// receives it.
///
/// Orthogonal to [`LaneSet`]'s deny-by-default: `LaneSet` says *whether* a lane is
/// open, `LaneDirections` says *which way* it flows if it is. Carrying it on
/// [`GateState`] lets the orchestrator reconcile an open lane against the
/// direction-pinned [`Direction`] its `ConsentLedger` enforces without re-deriving
/// it — the two can never silently drift apart. The canonical default is
/// `GooglePlay → Clean` (pull a payload from the less-private side into the clean
/// side); the reverse (the operator explicitly pushing outward) is set per-lane.
/// Indexed by [`Capability::ALL`] order so it maps 1:1 onto the five bridges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaneDirections {
    dirs: [Direction; LANES],
}

impl Default for LaneDirections {
    fn default() -> Self {
        LaneDirections::canonical()
    }
}

impl LaneDirections {
    /// Every lane flowing the canonical `GooglePlay → Clean` direction — pulling a
    /// payload from the less-private Google-Play world into the clean side. The
    /// fail-closed default that [`GateState::deny_all`] carries.
    pub fn canonical() -> Self {
        LaneDirections {
            dirs: [Direction::new(Persona::GooglePlay, Persona::Clean); LANES],
        }
    }

    /// The direction `cap`'s lane carries.
    pub fn of(&self, cap: Capability) -> Direction {
        self.dirs[lane_index(cap)]
    }

    /// Builder: pin `cap`'s lane to flow `dir`, returning the updated set. Mirrors
    /// the operator choosing which way a specific crossing runs.
    pub fn with(mut self, cap: Capability, dir: Direction) -> Self {
        self.dirs[lane_index(cap)] = dir;
        self
    }
}

/// A read-only snapshot of Dev N-gate's on-device consent state — exactly the
/// fields the orchestrator needs to reconcile the substrate **and** compute the
/// projection. Field names track `apps/noporis-gate/gate-state.schema.json` 1:1 so
/// this reconciles cleanly with the gate that owns the file:
///
/// | this struct                    | gate-state.schema.json  |
/// |--------------------------------|--------------------------|
/// | `consent_accepted`             | `consent.accepted`      |
/// | `consent_scope`                | `consent.scope`         |
/// | `crossings`                    | `crossings.*.open`      |
/// | `kill_switch_engaged`          | `killSwitch.engaged`    |
/// | `sealed_wallet_preserved`      | `sealedWallet.preserved`|
/// | `directions`                   | *(derived, not in v1)*  |
///
/// Fail-closed by construction: [`GateState::deny_all`] is the value the wrapper
/// MUST use for a missing / unparseable / partial file (see [`GateState::from_gate_json`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateState {
    /// `consent.accepted` — the operator read the honest disclosure and accepted.
    /// Default DENY (`false`): the far side does not run and nothing crosses.
    pub consent_accepted: bool,
    /// `consent.scope` — session vs persistent consent.
    pub consent_scope: ConsentScope,
    /// `crossings.*.open` — which of the five per-capability lanes the operator has
    /// explicitly thrown open. **Deny-by-default**: accepting the bridge
    /// (`consent_accepted`) opens *no* lane by itself; each is an individual,
    /// disclosed, revocable toggle. The orchestrator maps exactly these onto
    /// concrete substrate plumbing — and nothing for a closed one.
    pub crossings: LaneSet,
    /// `killSwitch.engaged` — drop the span: stop the far side, refuse to reopen.
    pub kill_switch_engaged: bool,
    /// `sealedWallet.preserved` — fixed `true` in the schema; the near-side sealed
    /// wallet/keys are never destroyed by the bridge. Carried so the orchestrator
    /// can assert the invariant, never clear it.
    pub sealed_wallet_preserved: bool,
    /// The per-lane crossing direction (`from → to`) each capability lane carries.
    /// **Not** a gate-schema field — direction is derived structurally from the
    /// pairing (Composition-UX §2), carried here so the orchestrator's open lane and
    /// the direction-pinned `ConsentLedger` can be reconciled without re-deriving it.
    /// Fail-closed default: [`LaneDirections::canonical`] (`GooglePlay → Clean`).
    pub directions: LaneDirections,
}

impl GateState {
    /// Derived: **any** of the five `crossings.*.open` is `true` right now. This is
    /// the "a privacy bridge is open" fact the projection's line-1 authority needs
    /// (accepting consent is permission to *run* the far side, not to *share*).
    /// Computed from [`GateState::crossings`] so it can never drift out of sync
    /// with the per-capability truth.
    pub fn any_crossing_open(&self) -> bool {
        !self.crossings.all_closed()
    }

    /// The fail-closed default the wrapper MUST use for a missing / unparseable /
    /// partial gate file: not consented, no lane open, kill-switch clear, session
    /// scope — and the sealed wallet is preserved regardless.
    pub fn deny_all() -> Self {
        GateState {
            consent_accepted: false,
            consent_scope: ConsentScope::Session,
            crossings: LaneSet::none(),
            kill_switch_engaged: false,
            sealed_wallet_preserved: true,
            directions: LaneDirections::canonical(),
        }
    }

    /// A consented, live posture (kill-switch clear). **No lane is open**: standing
    /// on the bridge activates the persona but lends NOTHING by itself
    /// (deny-by-default). Use [`GateState::open_crossing`] to lend a specific
    /// capability.
    pub fn consented(scope: ConsentScope) -> Self {
        GateState {
            consent_accepted: true,
            consent_scope: scope,
            crossings: LaneSet::none(),
            kill_switch_engaged: false,
            sealed_wallet_preserved: true,
            directions: LaneDirections::canonical(),
        }
    }

    /// A consented posture with one representative crossing (clipboard) open — the
    /// state whose projection line-1 reads `enabled`. For a specific capability use
    /// [`GateState::consented`] + [`GateState::open_crossing`].
    pub fn consented_with_crossing(scope: ConsentScope) -> Self {
        GateState::consented(scope).open_crossing(Capability::Clipboard)
    }

    /// Builder: throw one per-capability crossing open on this snapshot. Mirrors the
    /// operator flipping `crossings.<cap>.open` in the gate. Deny-by-default holds —
    /// only the capabilities named here are lent.
    pub fn open_crossing(mut self, cap: Capability) -> Self {
        self.crossings = self.crossings.with(cap, true);
        self
    }

    /// Parse the load-bearing fields out of the gate's `state.json`, **fail-closed**:
    /// any missing discriminator, wrong version/tier, missing field, or parse error
    /// collapses to [`GateState::deny_all`] — the `normalize()` trust boundary the
    /// schema mandates, mirrored so the orchestrator reads the file exactly as
    /// sloboda/Porog would. `sealed_wallet_preserved` is never taken *false* from
    /// input: a file that claims it false is foreign and denies.
    pub fn from_gate_json(json: &str) -> Self {
        fn parse(json: &str) -> Option<GateState> {
            let v: serde_json::Value = serde_json::from_str(json).ok()?;
            // Discriminators — refuse a foreign / future file outright.
            if v.get("schema")?.as_str()? != "postern.noporis-gate.state" {
                return None;
            }
            if v.get("version")?.as_u64()? != 1 {
                return None;
            }
            if v.get("tier")?.as_str()? != "non-attestable" {
                return None;
            }
            // sealedWallet.preserved is fixed true; anything else is foreign.
            if !v.get("sealedWallet")?.get("preserved")?.as_bool()? {
                return None;
            }
            let consent = v.get("consent")?;
            // Missing/non-bool accepted ⇒ deny (false), never a guess.
            let consent_accepted = consent.get("accepted").and_then(|x| x.as_bool()) == Some(true);
            let consent_scope = match consent.get("scope").and_then(|x| x.as_str()) {
                Some("persistent") => ConsentScope::Persistent,
                _ => ConsentScope::Session, // safer default for anything else
            };
            let crossings_json = v.get("crossings")?;
            // Any crossing whose `open` is exactly true. Any non-true (missing,
            // "true" string, null) is "never given" for that lane.
            let mut crossings = LaneSet::none();
            for cap in Capability::ALL {
                let open = crossings_json
                    .get(cap.key())
                    .and_then(|c| c.get("open"))
                    .and_then(|o| o.as_bool())
                    == Some(true);
                crossings = crossings.with(cap, open);
            }
            let kill_switch_engaged = v
                .get("killSwitch")?
                .get("engaged")
                .and_then(|x| x.as_bool())
                == Some(true);
            Some(GateState {
                consent_accepted,
                consent_scope,
                crossings,
                kill_switch_engaged,
                sealed_wallet_preserved: true,
                // v1 state.json does not carry lane direction; it is derived
                // structurally, so a parse fills the canonical GooglePlay → Clean.
                directions: LaneDirections::canonical(),
            })
        }
        parse(json).unwrap_or_else(GateState::deny_all)
    }

    /// Render a **minimal, schema-valid v1** `state.json` for this posture,
    /// enumerating all five per-capability lanes verbatim from [`GateState::crossings`].
    ///
    /// Convenience for standalone/host use — on device the orchestrator persists
    /// the gate's *own* serialized bytes verbatim (see [`Orchestrator::commit`]),
    /// never a lossy re-render.
    pub fn to_gate_json(&self) -> String {
        let cap_json = |name: &str, open: bool| format!("\"{name}\":{{\"open\":{open}}}");
        let crossings = format!(
            "{{{}}}",
            Capability::ALL
                .iter()
                .map(|c| cap_json(c.key(), self.crossings.is_open(*c)))
                .collect::<Vec<_>>()
                .join(",")
        );
        format!(
            "{{\"schema\":\"postern.noporis-gate.state\",\"version\":1,\"tier\":\"non-attestable\",\
             \"consent\":{{\"accepted\":{},\"scope\":\"{}\"}},\
             \"crossings\":{},\
             \"killSwitch\":{{\"engaged\":{}}},\
             \"sealedWallet\":{{\"preserved\":true}}}}",
            self.consent_accepted,
            self.consent_scope.as_wire(),
            crossings,
            self.kill_switch_engaged,
        )
    }
}

// ── The sloboda-bridge.state projection (derived, single-writer) ──────────────

/// The line-1 authority of the `sloboda-bridge.state` projection — an exact mirror
/// of Dev C's pure `projectSlobodaBridgeState(state) → "enabled" | "disabled"`:
/// `enabled` **iff** consent accepted **and** kill-switch clear **and** at least
/// one crossing open; `disabled` otherwise (default, and on kill).
pub fn project_sloboda_line(gate: &GateState) -> &'static str {
    if gate.consent_accepted && !gate.kill_switch_engaged && gate.any_crossing_open() {
        "enabled"
    } else {
        "disabled"
    }
}

/// The full `sloboda-bridge.state` file contents the orchestrator writes.
///
/// Line 1 is the authority ([`project_sloboda_line`]); the additive marker lines
/// are the richer contract `apps/sloboda/bin/paw-lib.sh` reads **read-only**:
///
/// - `container=allowed` when consent is accepted and the kill-switch is clear —
///   the far side may *run* even with no bridge open (`paw_container_allowed`).
/// - `kill=engaged` when the kill-switch is engaged — a defensive override that
///   blocks entry regardless of anything else.
///
/// Per-capability `<cap>=on` enumeration lines are intentionally omitted here: they
/// are cosmetic (`paw_bridge_caps`, non-load-bearing) and the authoritative
/// per-capability set lives in `state.json` (via [`GateState::crossings`]), not in
/// this projection.
pub fn project_sloboda_bridge_state(gate: &GateState) -> String {
    let mut s = String::with_capacity(48);
    s.push_str(project_sloboda_line(gate));
    s.push('\n');
    if gate.consent_accepted && !gate.kill_switch_engaged {
        s.push_str("container=allowed\n");
    }
    if gate.kill_switch_engaged {
        s.push_str("kill=engaged\n");
    }
    // Additive, versioned marker (F2 persistence hardening) — appended LAST so it
    // never disturbs the line-1 authority contract paw-lib.sh reads. Lets a reader
    // (including our own recovery path) refuse to trust the file's meaning if a
    // future/older writer ever changes the format, instead of silently misparsing
    // it. See `parse_sloboda_bridge_schema_version` / `verify_sloboda_bridge_schema`.
    s.push_str(&format!("schema_version={SLOBODA_BRIDGE_SCHEMA_VERSION}\n"));
    s
}

/// Schema version of the `sloboda-bridge.state` projection this orchestrator
/// writes. Bump on any format change to line 1's meaning or the marker lines'
/// semantics. Unlike `state.json` (whose `"version":1` discriminator is Dev C's
/// schema, consumed verbatim — see [`GateState::from_gate_json`]), this projection
/// format is owned entirely by this crate (the orchestrator is its sole writer),
/// so **we** are the ones responsible for versioning it honestly.
pub const SLOBODA_BRIDGE_SCHEMA_VERSION: u32 = 1;

/// Parse the `schema_version=<N>` marker line out of a persisted
/// `sloboda-bridge.state` body. `None` if the line is absent or unparsable —
/// callers must treat that as "unversioned / untrusted", never assume version 1.
pub fn parse_sloboda_bridge_schema_version(body: &str) -> Option<u32> {
    body.lines()
        .find_map(|l| l.strip_prefix("schema_version="))
        .and_then(|v| v.trim().parse::<u32>().ok())
}

/// **Fail-closed** schema check for a persisted `sloboda-bridge.state` body: `Ok`
/// only if it carries exactly the schema version this orchestrator understands.
/// A missing marker (a pre-versioning or corrupted write) or an unrecognized
/// version is a hard refusal to trust the body's line-1 authority — never a
/// silent guess at what `enabled`/`disabled` meant under a format we don't know.
/// This is the read-side half of the versioning; [`project_sloboda_bridge_state`]
/// is the write-side half.
pub fn verify_sloboda_bridge_schema(body: &str) -> Result<(), SubstrateError> {
    match parse_sloboda_bridge_schema_version(body) {
        Some(v) if v == SLOBODA_BRIDGE_SCHEMA_VERSION => Ok(()),
        Some(v) => Err(SubstrateError::Backend(format!(
            "sloboda-bridge.state schema_version {v} is not understood by this orchestrator \
             (expected {SLOBODA_BRIDGE_SCHEMA_VERSION}) — refusing to trust it"
        ))),
        None => Err(SubstrateError::Backend(
            "sloboda-bridge.state is missing schema_version — refusing to trust an \
             unversioned/corrupted projection"
                .to_string(),
        )),
    }
}

/// Canonical paths of the two state files the orchestrator solely writes. Use
/// [`StatePaths::under`] in tests to redirect both into a temp dir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatePaths {
    /// The authoritative gate posture (`/var/lib/postern/noporis-gate/state.json`).
    pub state_json: PathBuf,
    /// The derived toggle sloboda/Porog read (`/run/postern/consent/sloboda-bridge.state`).
    pub sloboda_bridge_state: PathBuf,
}

impl Default for StatePaths {
    fn default() -> Self {
        StatePaths {
            state_json: PathBuf::from("/var/lib/postern/noporis-gate/state.json"),
            sloboda_bridge_state: PathBuf::from("/run/postern/consent/sloboda-bridge.state"),
        }
    }
}

impl StatePaths {
    /// Both files rooted under `dir` (for host tests): `dir/state.json` and
    /// `dir/sloboda-bridge.state`.
    pub fn under(dir: impl AsRef<Path>) -> Self {
        let dir = dir.as_ref();
        StatePaths {
            state_json: dir.join("state.json"),
            sloboda_bridge_state: dir.join("sloboda-bridge.state"),
        }
    }
}

static WRITE_SEQ: AtomicU64 = AtomicU64::new(0);

/// Atomically write `bytes` to `path`: write a uniquely-named temp file in the
/// **same directory**, `fsync` it, then `rename()` over the target so a reader
/// never sees a half-written state. On unix the file is created `0600` (these are
/// consent state files, root-owned on device). Best-effort directory `fsync`.
///
/// The orchestrator is the *sole* runtime writer of the two state files, so the
/// single-writer temp name (pid + monotonic seq) never collides at runtime.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    fs::create_dir_all(&dir)?;

    let stem = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "state".to_string());
    let tmp = dir.join(format!(
        ".{stem}.{}.{}.tmp",
        std::process::id(),
        WRITE_SEQ.fetch_add(1, Ordering::Relaxed),
    ));

    // Write + fsync the temp file, scoping the handle so it is closed before rename.
    {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }

    // Atomic replace. If the rename fails, clean up the temp so we do not litter.
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }

    // Best-effort: fsync the directory so the rename itself is durable.
    if let Ok(d) = fs::File::open(&dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// **Crash-recovery entrypoint.** Reload the persisted [`GateState`] from
/// `paths.state_json`, fail-closed at every step: a missing file, an unreadable
/// file, invalid UTF-8, or any parse/schema failure (unknown `schema`/`version`,
/// a foreign `sealedWallet.preserved`, …handled by [`GateState::from_gate_json`])
/// all collapse to [`GateState::deny_all`] — never a guess, never a partial trust.
///
/// Call this once at process start (after a fresh boot, a restart, or recovery
/// from a `SIGKILL`) **before** the first [`Orchestrator::reconcile`]/[`Orchestrator::commit`]
/// — [`write_atomic`]'s rename-based durability guarantees the file on disk is
/// always either the last fully-committed posture or absent, never torn, so this
/// reload can never observe a half-written state (see the `persistence_recovery`
/// test suite's fault-injection coverage).
pub fn read_gate_state(paths: &StatePaths) -> GateState {
    match fs::read_to_string(&paths.state_json) {
        Ok(s) => GateState::from_gate_json(&s),
        Err(_) => GateState::deny_all(),
    }
}

/// **Fail-closed schema-preflight reader** for the `sloboda-bridge.state`
/// projection — the runtime read-side that closes the gap where
/// [`verify_sloboda_bridge_schema`] existed but was never actually invoked
/// against a file on disk. Mirrors [`read_gate_state`], but for the projection
/// this crate owns and versions itself, and — unlike the gate reader, which
/// collapses anything foreign to [`GateState::deny_all`] — this one **surfaces**
/// a foreign projection as a hard error so a caller can refuse to start rather
/// than silently overwrite a projection written by a version it does not
/// understand (an older/newer/foreign orchestrator).
///
/// Three outcomes, deliberately distinct:
/// - `Ok(None)` — the file is **absent**. That is the normal first-boot / fresh
///   `--state-dir` case: there is nothing to trust or distrust yet, and the
///   orchestrator is free to become its sole writer.
/// - `Ok(Some(body))` — the file is **present and carries exactly the schema
///   version this orchestrator understands** ([`verify_sloboda_bridge_schema`]
///   passed). The verified body is handed back for inspection.
/// - `Err(SubstrateError::Backend(_))` — the file is **present but unreadable, or
///   present with a missing/unknown `schema_version`**. A hard, loud refusal —
///   never a silent guess at what a foreign `enabled`/`disabled` line-1 meant,
///   and never a silent clobber of a projection another writer may still own.
pub fn read_sloboda_bridge_state(paths: &StatePaths) -> Result<Option<String>, SubstrateError> {
    match fs::read_to_string(&paths.sloboda_bridge_state) {
        Ok(body) => verify_sloboda_bridge_schema(&body).map(|()| Some(body)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(SubstrateError::Backend(format!(
            "sloboda-bridge.state is present but unreadable ({e}) — refusing to start on an \
             inaccessible projection rather than silently overwrite a file another writer may own"
        ))),
    }
}

/// An advisory, filesystem-based **sole-writer lock** for one [`StatePaths`] root.
/// Plan §5 says the orchestrator is the *sole runtime writer* of the two state
/// files; this makes that discipline loud instead of merely documented. Hold one
/// for the lifetime of the orchestrator process: a second process racing the same
/// `StatePaths` gets an immediate, explicit refusal from [`WriterLock::acquire`]
/// instead of silently interleaving [`write_atomic`] calls with the first.
///
/// This is **advisory** (an `O_EXCL` marker file, not an flock/fcntl lease): a
/// killed process leaves the lock file behind. There is no silent auto-steal —
/// [`WriterLock::steal`] is the explicit, named recovery path an operator/daemon
/// calls only after establishing out-of-band that no other writer is still live
/// (e.g. the recorded pid is not running). Never wired automatically.
#[derive(Debug)]
pub struct WriterLock {
    path: PathBuf,
}

impl WriterLock {
    fn lock_path(paths: &StatePaths) -> PathBuf {
        let dir = paths
            .state_json
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        dir.join(".noporis-orchestrator.writer.lock")
    }

    /// Acquire the sole-writer lock for `paths`. Fails (`io::ErrorKind::AlreadyExists`)
    /// if another writer already holds it — the caller must not proceed to write
    /// `state.json`/`sloboda-bridge.state` while this returns `Err`.
    pub fn acquire(paths: &StatePaths) -> io::Result<Self> {
        let dir = paths
            .state_json
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        fs::create_dir_all(&dir)?;
        let path = Self::lock_path(paths);
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true); // O_EXCL: fails if it already exists.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&path)?;
        // Best-effort breadcrumb (not load-bearing for correctness): the holding
        // pid, so an operator inspecting a stale lock knows what to check before
        // calling `steal`.
        let _ = f.write_all(std::process::id().to_string().as_bytes());
        let _ = f.sync_all();
        Ok(WriterLock { path })
    }

    /// Explicit, named recovery from a crashed prior writer: remove a stale lock
    /// file (if any) and acquire fresh. Callers assert, out of band, that no other
    /// writer is actually live before calling this — there is no automatic check
    /// here (a host stub cannot portably probe whether a recorded pid still runs).
    pub fn steal(paths: &StatePaths) -> io::Result<Self> {
        let _ = fs::remove_file(Self::lock_path(paths));
        Self::acquire(paths)
    }
}

impl Drop for WriterLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Where a substrate is in its lifecycle, plus the load-bearing invariant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubstrateStatus {
    pub lifecycle: Lifecycle,
    /// The invariant: cutting the span never destroys sealed wallet state on the
    /// near side. A substrate holds no wallet, so nothing here can clear it — it
    /// stays `true` across create / switch / **kill**.
    pub sealed_wallet_preserved: bool,
}

/// The persona-isolation lifecycle the orchestrator drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifecycle {
    /// No isolated persona exists yet (nothing created).
    Absent,
    /// The isolated persona exists but is not foregrounded.
    Ready,
    /// The isolated persona is the active/foreground one.
    Active,
    /// The span is cut (kill-switch): the far side is stopped and refuses to
    /// reopen until the kill-switch is disengaged in the gate.
    Killed,
}

/// A refusal from a substrate operation. Fail-closed: an ambiguous state denies.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SubstrateError {
    /// The kill-switch is engaged; the far side must not be created or foregrounded.
    #[error("kill-switch engaged: the span is cut; refuse to (re)start the far side")]
    KillSwitchEngaged,
    /// A backend/seam operation failed (host stubs never emit this; real ones may).
    #[error("substrate backend error: {0}")]
    Backend(String),
    /// A capability lane was requested before the isolated persona exists. Fail-closed:
    /// no plumbing can be opened into a persona that is not up.
    #[error("persona absent: cannot open a capability lane before the persona exists")]
    PersonaAbsent,
    /// The sealed-wallet invariant was observed violated — a hard stop. This must
    /// be impossible by construction; it exists so a future backend that wired the
    /// wallet in wrongly fails loudly instead of silently destroying keys.
    #[error("INVARIANT VIOLATED: sealed wallet not preserved — refusing to proceed")]
    SealedWalletViolated,
}

/// The seam a persona-isolation backend implements. The [`Orchestrator`] reads the
/// gate state and calls exactly these; a backend never reads the gate itself.
///
/// Every method is fail-closed: on any ambiguity a substrate returns a status that
/// denies crossings, and it NEVER clears the sealed-wallet invariant.
pub trait Substrate {
    /// Which persona this substrate isolates (the far, less-private side).
    fn persona(&self) -> Persona;

    /// The honest enforcement class of this substrate's boundary.
    fn enforcement(&self) -> Enforcement;

    /// Idempotently ensure the isolated persona profile exists. First call:
    /// `Absent → Ready`. Refused while the kill-switch is engaged.
    fn ensure_profile(&mut self) -> Result<SubstrateStatus, SubstrateError>;

    /// Foreground `persona`. If it is this substrate's isolated persona, bring it
    /// active (creating it first if needed). Refused while killed.
    fn switch_to(&mut self, persona: Persona) -> Result<SubstrateStatus, SubstrateError>;

    /// Open the concrete per-capability plumbing for `cap` (the cross-profile /
    /// Waydroid lane the gate's `Allow` maps to). **Deny-by-default**: a lane is
    /// closed until the orchestrator opens it for an explicitly-thrown crossing.
    /// Fail-closed: refused while the span is killed ([`SubstrateError::KillSwitchEngaged`])
    /// or before the isolated persona exists ([`SubstrateError::PersonaAbsent`]) — no
    /// lane can exist into a persona that is not up.
    fn open_lane(&mut self, cap: Capability) -> Result<(), SubstrateError>;

    /// Close the concrete plumbing for `cap`. Always allowed; revocation is
    /// monotonic and immediate.
    fn close_lane(&mut self, cap: Capability);

    /// Close **every** lane at once (the kill-switch / withdraw-consent fan-out).
    /// Always allowed; leaves the far side isolated with nothing lent across.
    fn close_all_lanes(&mut self);

    /// Which per-capability lanes are currently open. Deny-by-default: a fresh /
    /// killed / non-consented substrate exposes [`LaneSet::none`].
    fn open_lanes(&self) -> LaneSet;

    /// Engage the kill-switch: stop the far side, close every lane, and mark it
    /// `Killed`. Always allowed. NEVER touches sealed wallet state (there is none
    /// here to touch).
    fn kill(&mut self) -> SubstrateStatus;

    /// Disengage the kill-switch, allowing the far side to be re-created. Explicit
    /// — a killed span never lapses on a timer.
    fn revive(&mut self) -> SubstrateStatus;

    /// The current status.
    fn status(&self) -> SubstrateStatus;
}

/// The orchestrator: read a [`GateState`] snapshot → drive the [`Substrate`] to
/// the posture that state demands, and be the sole writer of the state files.
pub struct Orchestrator<S: Substrate> {
    substrate: S,
}

/// What the orchestrator did on a [`reconcile`](Orchestrator::reconcile) — a small
/// audit-friendly summary of the action taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reconciliation {
    /// Kill-switch engaged in the gate → far side cut.
    Killed,
    /// Consent not accepted → far side kept absent/stopped, nothing crosses.
    HeldClosedNoConsent,
    /// Consented + live → far side ensured and foregrounded.
    Activated,
}

impl<S: Substrate> Orchestrator<S> {
    pub fn new(substrate: S) -> Self {
        Orchestrator { substrate }
    }

    pub fn substrate(&self) -> &S {
        &self.substrate
    }

    pub fn substrate_mut(&mut self) -> &mut S {
        &mut self.substrate
    }

    /// Which per-capability lanes the substrate currently exposes — a convenience
    /// mirror of [`Substrate::open_lanes`]. Deny-by-default: [`LaneSet::none`]
    /// whenever the span is killed, not consented, or freshly created.
    pub fn open_lanes(&self) -> LaneSet {
        self.substrate.open_lanes()
    }

    /// Drive the substrate to match `gate`. Fail-closed precedence:
    /// 1. **sealed-wallet invariant** — if the gate ever reports the sealed wallet
    ///    not preserved, refuse everything (hard stop) rather than risk a destroy;
    /// 2. **kill-switch** — engaged ⇒ cut the span (`kill`, which also closes every
    ///    lane), regardless of consent;
    /// 3. **consent** — not accepted ⇒ keep the far side closed AND close every lane
    ///    (revive-to-`Ready` is *not* performed; nothing crosses without consent);
    /// 4. otherwise ⇒ ensure the profile, foreground the isolated persona, then
    ///    **map each crossing to concrete plumbing**: open exactly the lanes the
    ///    gate has thrown, close every lane it has not (deny-by-default).
    ///
    /// After any successful action the returned status still reports
    /// `sealed_wallet_preserved == true`, and the open lanes are a subset of
    /// `gate.crossings` (never a superset — the orchestrator can only *narrow*).
    pub fn reconcile(&mut self, gate: &GateState) -> Result<Reconciliation, SubstrateError> {
        // 1. Invariant first — a violated invariant is a hard stop, never a destroy.
        if !gate.sealed_wallet_preserved {
            return Err(SubstrateError::SealedWalletViolated);
        }

        // 2. Kill-switch wins over everything else — the span (and every lane) drops.
        if gate.kill_switch_engaged {
            let st = self.substrate.kill();
            debug_assert!(st.sealed_wallet_preserved, "kill preserves the wallet");
            debug_assert!(self.substrate.open_lanes().all_closed(), "kill closes all lanes");
            return Ok(Reconciliation::Killed);
        }

        // A live span first requires the switch to be disengaged.
        self.substrate.revive();

        // 3. No consent → hold the far side closed; slam every lane shut; nothing crosses.
        if !gate.consent_accepted {
            self.substrate.close_all_lanes();
            return Ok(Reconciliation::HeldClosedNoConsent);
        }

        // 4. Consented + live → create and foreground the isolated persona.
        self.substrate.ensure_profile()?;
        let persona = self.substrate.persona();
        let st = self.substrate.switch_to(persona)?;
        debug_assert!(st.sealed_wallet_preserved, "switch preserves the wallet");

        // …then map each crossing onto concrete plumbing: open exactly what the gate
        // has thrown, close everything else. Deny-by-default per lane.
        self.map_lanes(&gate.crossings)?;
        Ok(Reconciliation::Activated)
    }

    /// Reconcile the substrate's lanes to `want`: open each capability the gate has
    /// thrown, close every capability it has not. Fail-closed: any `open_lane`
    /// refusal aborts and propagates (the caller already foregrounded the persona,
    /// so the only refusals here are a race with a concurrent kill).
    fn map_lanes(&mut self, want: &LaneSet) -> Result<(), SubstrateError> {
        for cap in Capability::ALL {
            if want.is_open(cap) {
                self.substrate.open_lane(cap)?;
            } else {
                self.substrate.close_lane(cap);
            }
        }
        Ok(())
    }

    /// The **sole-writer commit**: persist the two state files atomically, then
    /// drive the substrate to match. The projection is written **before** the
    /// substrate is driven, because the far-side seam (sloboda) reads
    /// `container=allowed` from it to decide whether it may start at all; the kill
    /// projection (`disabled`, `kill=engaged`) likewise lands before the span is
    /// cut, so a consumer polling the toggle sees the span down atomically.
    ///
    /// `state_json` is the gate's own serialized `state.json` bytes (Dev C's
    /// gate-store computes them; the orchestrator persists them verbatim). Pass
    /// `gate.to_gate_json().as_bytes()` for a standalone render.
    pub fn commit(
        &mut self,
        gate: &GateState,
        state_json: &[u8],
        paths: &StatePaths,
    ) -> Result<Reconciliation, SubstrateError> {
        // Persist the authoritative posture first.
        write_atomic(&paths.state_json, state_json)
            .map_err(|e| SubstrateError::Backend(format!("state.json write: {e}")))?;
        // Then the derived projection the far side reads before it acts.
        write_atomic(
            &paths.sloboda_bridge_state,
            project_sloboda_bridge_state(gate).as_bytes(),
        )
        .map_err(|e| SubstrateError::Backend(format!("sloboda-bridge.state write: {e}")))?;
        // Only now drive the substrate to match.
        self.reconcile(gate)
    }
}

// ── Backend #1: Android managed profile (near-side DPC seam) ───────────────────

/// The near-side managed-profile driver seam. The [`ManagedProfileSubstrate`]
/// state machine calls exactly these effect hooks at each lifecycle transition; a
/// seam never reads the gate.
///
/// **On device** this is implemented by a JNI shim over the Kotlin
/// `labs.postern.persona.lifecycle.PersonaLifecycle`:
/// `ensure_profile` ⇒ provisioning gate + `ACTION_PROVISION_MANAGED_PROFILE`,
/// `foreground(true|false)` ⇒ `resumePersona()` / `pausePersona()` (quiet-mode),
/// `kill` ⇒ `killPersona()` (pause + drop cross-profile grants — **not** a wipe;
/// the profile and its FBE storage survive), `revive` ⇒ allow re-provision. That
/// JNI binding is `UNTESTED-until-device`. On the host it is [`HostStubDpc`].
///
/// The per-capability cross-profile **lane** grants are not part of this seam —
/// they are orchestration state the substrate keeps directly (see
/// [`Substrate::open_lane`]); a real DPC would wire a concrete grant per lane later.
pub trait DpcSeam {
    /// The honest enforcement class of this seam's boundary.
    fn enforcement(&self) -> Enforcement;
    /// Ensure the managed profile exists (idempotent). On device: the provisioning
    /// gate + dispatch; enrollment truly completes inside the new profile's DPC.
    fn ensure_profile(&mut self) -> Result<(), SubstrateError>;
    /// Resume (`true`) or pause (`false`) the persona via quiet-mode.
    fn foreground(&mut self, on: bool) -> Result<(), SubstrateError>;
    /// Kill: pause the persona and drop cross-profile grants. Best-effort; never a
    /// wipe, never touches the near-side wallet.
    fn kill(&mut self);
    /// Allow the persona to be (re)created after a kill.
    fn revive(&mut self);
}

/// **Near-side** persona-isolation backend over an Android **managed profile**,
/// driven through a [`DpcSeam`]. The lifecycle state machine (absent → ready →
/// active → killed) and the per-capability [`LaneSet`] live here and are
/// host-testable; the concrete persona-level effects live in the seam
/// ([`HostStubDpc`] on the host, the JNI→`PersonaLifecycle` shim on device).
#[derive(Debug, Clone)]
pub struct ManagedProfileSubstrate<D: DpcSeam> {
    persona: Persona,
    lifecycle: Lifecycle,
    dpc: D,
    /// Per-capability lane state. On a real device each open lane is a concrete
    /// cross-profile grant; here it is just a bit, deny-by-default.
    lanes: LaneSet,
}

#[cfg(feature = "host-stub")]
impl ManagedProfileSubstrate<HostStubDpc> {
    /// A **host-stub** managed-profile substrate for `persona` (typically the far,
    /// less-private Google-Play side). Isolates **nothing** — it runs the state
    /// machine so the orchestration is exercisable by `cargo test`. Behind the
    /// default `host-stub` feature.
    pub fn new(persona: Persona) -> Self {
        ManagedProfileSubstrate::with_seam(persona, HostStubDpc)
    }
}

impl<D: DpcSeam> ManagedProfileSubstrate<D> {
    /// A managed-profile substrate driving `persona` through an explicit `dpc`
    /// seam — the real-backend constructor (inject the device DPC seam here).
    pub fn with_seam(persona: Persona, dpc: D) -> Self {
        ManagedProfileSubstrate {
            persona,
            lifecycle: Lifecycle::Absent,
            dpc,
            lanes: LaneSet::none(),
        }
    }

    /// Borrow the underlying seam (e.g. to observe the device driver).
    pub fn seam(&self) -> &D {
        &self.dpc
    }

    fn ok(&self) -> SubstrateStatus {
        SubstrateStatus {
            lifecycle: self.lifecycle,
            // A substrate holds no wallet — the invariant is fixed true by
            // construction; no method here can make it false.
            sealed_wallet_preserved: true,
        }
    }
}

impl<D: DpcSeam> Substrate for ManagedProfileSubstrate<D> {
    fn persona(&self) -> Persona {
        self.persona
    }

    fn enforcement(&self) -> Enforcement {
        self.dpc.enforcement()
    }

    fn ensure_profile(&mut self) -> Result<SubstrateStatus, SubstrateError> {
        if self.lifecycle == Lifecycle::Killed {
            return Err(SubstrateError::KillSwitchEngaged);
        }
        if self.lifecycle == Lifecycle::Absent {
            self.dpc.ensure_profile()?;
            self.lifecycle = Lifecycle::Ready;
        }
        Ok(self.ok())
    }

    fn switch_to(&mut self, persona: Persona) -> Result<SubstrateStatus, SubstrateError> {
        if self.lifecycle == Lifecycle::Killed {
            return Err(SubstrateError::KillSwitchEngaged);
        }
        if persona == self.persona {
            if self.lifecycle == Lifecycle::Absent {
                self.dpc.ensure_profile()?;
                self.lifecycle = Lifecycle::Ready;
            }
            self.dpc.foreground(true)?; // resume quiet-mode
            self.lifecycle = Lifecycle::Active;
        } else if self.lifecycle == Lifecycle::Active {
            // Switching away from the isolated persona backgrounds it.
            self.dpc.foreground(false)?; // pause quiet-mode
            self.lifecycle = Lifecycle::Ready;
        }
        Ok(self.ok())
    }

    fn open_lane(&mut self, cap: Capability) -> Result<(), SubstrateError> {
        if self.lifecycle == Lifecycle::Killed {
            return Err(SubstrateError::KillSwitchEngaged);
        }
        if self.lifecycle == Lifecycle::Absent {
            return Err(SubstrateError::PersonaAbsent);
        }
        self.lanes.set_open(cap); // STUB/seam: no real cross-profile grant is created yet.
        Ok(())
    }

    fn close_lane(&mut self, cap: Capability) {
        self.lanes.set_closed(cap); // STUB/seam: no real grant is revoked yet.
    }

    fn close_all_lanes(&mut self) {
        self.lanes = LaneSet::none();
    }

    fn open_lanes(&self) -> LaneSet {
        self.lanes
    }

    fn kill(&mut self) -> SubstrateStatus {
        self.dpc.kill(); // pause + drop cross-profile; NEVER a wipe.
        self.lifecycle = Lifecycle::Killed;
        self.lanes = LaneSet::none(); // every lane drops with the span.
        self.ok() // sealed_wallet_preserved stays true.
    }

    fn revive(&mut self) -> SubstrateStatus {
        if self.lifecycle == Lifecycle::Killed {
            self.dpc.revive();
            self.lifecycle = Lifecycle::Absent;
            self.lanes = LaneSet::none(); // a revived span reopens no lane by itself.
        }
        self.ok()
    }

    fn status(&self) -> SubstrateStatus {
        self.ok()
    }
}

/// **Host stub** [`DpcSeam`] — in-memory, isolates nothing, enforces nothing
/// ([`Enforcement::ByConstruction`]). Keeps the near-side orchestration
/// host-testable under the default `host-stub` feature. Replace with the JNI
/// device seam on hardware.
#[cfg(feature = "host-stub")]
#[derive(Debug, Clone, Default)]
pub struct HostStubDpc;

#[cfg(feature = "host-stub")]
impl DpcSeam for HostStubDpc {
    fn enforcement(&self) -> Enforcement {
        Enforcement::ByConstruction // STUB enforces nothing.
    }
    fn ensure_profile(&mut self) -> Result<(), SubstrateError> {
        Ok(()) // STUB: no profile is actually provisioned.
    }
    fn foreground(&mut self, _on: bool) -> Result<(), SubstrateError> {
        Ok(()) // STUB: no real quiet-mode toggle.
    }
    fn kill(&mut self) {} // STUB: no real pause / grant-drop.
    fn revive(&mut self) {}
}

// ── Backend #2: Waydroid container (far-side sloboda seam) ─────────────────────

/// The observed Waydroid session state (mirrors `sloboda status`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// `Session: RUNNING`.
    Running,
    /// `Session: STOPPED`.
    Stopped,
    /// Not determinable (no waydroid, no output) — fail-safe treated as not running.
    Unknown,
}

/// The far-side Waydroid driver seam. The [`WaydroidSubstrate`] state machine calls
/// these; the real [`SlobodaCli`] drives the **existing read-only** `apps/sloboda`
/// wrapper. NoporIS does not own or boot the container — it execs sloboda's seam
/// and observes its state. On the host it is [`HostStubSloboda`].
pub trait SlobodaSeam {
    /// The honest enforcement class (LXC split ⇒ [`Enforcement::OsBoundary`] for the
    /// real CLI; [`Enforcement::ByConstruction`] for the host stub).
    fn enforcement(&self) -> Enforcement;
    /// Bring the Android session up (`sloboda start`).
    fn start(&mut self) -> Result<(), SubstrateError>;
    /// Stop the session (`sloboda stop`).
    fn stop(&mut self) -> Result<(), SubstrateError>;
    /// Kill-switch: `sloboda kill` — stop everything and clear session runtime.
    /// Best-effort and always attempted; the image is untouched.
    fn kill(&mut self);
    /// Observe the session state (`sloboda status`). Default `Unknown`.
    fn probe(&self) -> SessionState {
        SessionState::Unknown
    }
}

/// **Far-side** persona-isolation backend over a **Waydroid container**, driven
/// through a [`SlobodaSeam`]. The lifecycle state machine and the per-capability
/// [`LaneSet`] live here; the concrete container effects live in the seam
/// ([`HostStubSloboda`] on the host, the real [`SlobodaCli`] on a binder-capable
/// host).
#[derive(Debug, Clone)]
pub struct WaydroidSubstrate<S: SlobodaSeam> {
    persona: Persona,
    lifecycle: Lifecycle,
    sloboda: S,
    /// Per-capability lane state (a real lane is Waydroid/LXC device passthrough or
    /// `wl-clipboard`; here it is just a bit, deny-by-default).
    lanes: LaneSet,
}

#[cfg(feature = "host-stub")]
impl WaydroidSubstrate<HostStubSloboda> {
    /// A **host-stub** Waydroid substrate for `persona` (the far, less-private side
    /// that runs in the container). Starts/stops **nothing**. Behind the default
    /// `host-stub` feature.
    pub fn new(persona: Persona) -> Self {
        WaydroidSubstrate::with_seam(persona, HostStubSloboda)
    }
}

impl<S: SlobodaSeam> WaydroidSubstrate<S> {
    /// A Waydroid substrate driving `persona` through an explicit sloboda `seam` —
    /// the real-backend constructor (inject [`SlobodaCli`] here).
    pub fn with_seam(persona: Persona, sloboda: S) -> Self {
        WaydroidSubstrate {
            persona,
            lifecycle: Lifecycle::Absent,
            sloboda,
            lanes: LaneSet::none(),
        }
    }

    /// Borrow the underlying seam (e.g. to `probe()` the live session).
    pub fn seam(&self) -> &S {
        &self.sloboda
    }

    fn ok(&self) -> SubstrateStatus {
        SubstrateStatus {
            lifecycle: self.lifecycle,
            sealed_wallet_preserved: true,
        }
    }
}

impl<S: SlobodaSeam> Substrate for WaydroidSubstrate<S> {
    fn persona(&self) -> Persona {
        self.persona
    }

    fn enforcement(&self) -> Enforcement {
        self.sloboda.enforcement()
    }

    fn ensure_profile(&mut self) -> Result<SubstrateStatus, SubstrateError> {
        if self.lifecycle == Lifecycle::Killed {
            return Err(SubstrateError::KillSwitchEngaged);
        }
        if self.lifecycle == Lifecycle::Absent {
            // "Ensure exists" for Waydroid is provisioning-complete; the session is
            // started on switch (below), not here — `sloboda start` is the run verb.
            self.lifecycle = Lifecycle::Ready;
        }
        Ok(self.ok())
    }

    fn switch_to(&mut self, persona: Persona) -> Result<SubstrateStatus, SubstrateError> {
        if self.lifecycle == Lifecycle::Killed {
            return Err(SubstrateError::KillSwitchEngaged);
        }
        if persona == self.persona {
            if self.lifecycle == Lifecycle::Absent {
                self.lifecycle = Lifecycle::Ready;
            }
            self.sloboda.start()?; // sloboda start → Session: RUNNING
            self.lifecycle = Lifecycle::Active;
        } else if self.lifecycle == Lifecycle::Active {
            self.sloboda.stop()?; // sloboda stop → background the container
            self.lifecycle = Lifecycle::Ready;
        }
        Ok(self.ok())
    }

    fn open_lane(&mut self, cap: Capability) -> Result<(), SubstrateError> {
        if self.lifecycle == Lifecycle::Killed {
            return Err(SubstrateError::KillSwitchEngaged);
        }
        if self.lifecycle == Lifecycle::Absent {
            return Err(SubstrateError::PersonaAbsent);
        }
        self.lanes.set_open(cap); // STUB/seam: no real passthrough is wired yet.
        Ok(())
    }

    fn close_lane(&mut self, cap: Capability) {
        self.lanes.set_closed(cap);
    }

    fn close_all_lanes(&mut self) {
        self.lanes = LaneSet::none();
    }

    fn open_lanes(&self) -> LaneSet {
        self.lanes
    }

    fn kill(&mut self) -> SubstrateStatus {
        self.sloboda.kill(); // sloboda kill → stop + clear session runtime, image intact.
        self.lifecycle = Lifecycle::Killed;
        self.lanes = LaneSet::none(); // every lane drops with the container.
        self.ok()
    }

    fn revive(&mut self) -> SubstrateStatus {
        if self.lifecycle == Lifecycle::Killed {
            self.lifecycle = Lifecycle::Absent;
            self.lanes = LaneSet::none(); // a revived span reopens no lane by itself.
        }
        self.ok()
    }

    fn status(&self) -> SubstrateStatus {
        self.ok()
    }
}

/// **Host stub** [`SlobodaSeam`] — in-memory, boots nothing, enforces nothing
/// ([`Enforcement::ByConstruction`]). Keeps the far-side orchestration
/// host-testable under the default `host-stub` feature.
#[cfg(feature = "host-stub")]
#[derive(Debug, Clone, Default)]
pub struct HostStubSloboda;

#[cfg(feature = "host-stub")]
impl SlobodaSeam for HostStubSloboda {
    fn enforcement(&self) -> Enforcement {
        Enforcement::ByConstruction // STUB enforces nothing.
    }
    fn start(&mut self) -> Result<(), SubstrateError> {
        Ok(()) // STUB: no `waydroid session start`.
    }
    fn stop(&mut self) -> Result<(), SubstrateError> {
        Ok(()) // STUB: no `waydroid session stop`.
    }
    fn kill(&mut self) {} // STUB: no real kill.
}

/// **Real** [`SlobodaSeam`] that execs the `apps/sloboda` wrapper CLI — the
/// far-side driver on a binder-capable host. It drives sloboda's **existing**
/// seam (`start` / `stop` / `kill` / `status`) and reads its state; it never edits
/// sloboda and never writes sloboda's read-only bridge-state file (the orchestrator
/// owns that projection).
///
/// Real Waydroid boot/kill is `UNTESTED-until-VM` (needs a binder kernel); on the
/// host, `sloboda start` fail-closes (no waydroid, container-not-allowed) — which
/// is why host unit tests inject a stub/fake seam and only the argv/parse helpers
/// here are host-exercised.
#[derive(Debug, Clone)]
pub struct SlobodaCli {
    bin: PathBuf,
}

impl SlobodaCli {
    /// Drive the sloboda wrapper at `bin` (e.g. `apps/sloboda/bin/sloboda` or a
    /// packaged `sloboda` on `PATH`).
    pub fn new(bin: impl Into<PathBuf>) -> Self {
        SlobodaCli { bin: bin.into() }
    }

    /// Locate the wrapper from `NOPORIS_SLOBODA_BIN`, else assume `sloboda` on `PATH`.
    pub fn autodetect() -> Self {
        let bin = std::env::var_os("NOPORIS_SLOBODA_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("sloboda"));
        SlobodaCli::new(bin)
    }

    fn run(&self, sub: &str) -> Result<std::process::Output, SubstrateError> {
        Command::new(&self.bin).arg(sub).output().map_err(|e| {
            SubstrateError::Backend(format!("exec `{} {sub}`: {e}", self.bin.display()))
        })
    }

    fn run_ok(&self, sub: &str) -> Result<(), SubstrateError> {
        let out = self.run(sub)?;
        if out.status.success() {
            Ok(())
        } else {
            Err(SubstrateError::Backend(format!(
                "`sloboda {sub}` exited {}: {}",
                out.status
                    .code()
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "signal".to_string()),
                String::from_utf8_lossy(&out.stderr).trim(),
            )))
        }
    }
}

/// Parse the `session:` line of `sloboda status` into a [`SessionState`]. Pure and
/// host-testable. Fail-safe: anything not clearly RUNNING/STOPPED is `Unknown`.
pub fn parse_session_state(status_stdout: &str) -> SessionState {
    for line in status_stdout.lines() {
        if let Some(rest) = line.trim_start().strip_prefix("session:") {
            let v = rest.trim().to_ascii_uppercase();
            if v.starts_with("RUNNING") {
                return SessionState::Running;
            }
            if v.starts_with("STOPPED") {
                return SessionState::Stopped;
            }
        }
    }
    SessionState::Unknown
}

impl SlobodaSeam for SlobodaCli {
    fn enforcement(&self) -> Enforcement {
        // Waydroid's LXC storage/process split is the OS/kernel's — honest for the
        // real driver. NOT attestation; a rooted host still defeats it.
        Enforcement::OsBoundary
    }
    fn start(&mut self) -> Result<(), SubstrateError> {
        self.run_ok("start")
    }
    fn stop(&mut self) -> Result<(), SubstrateError> {
        self.run_ok("stop")
    }
    fn kill(&mut self) {
        // Kill is always attempted, best-effort — a failure to reach the wrapper
        // must not wedge the kill path.
        let _ = self.run("kill");
    }
    fn probe(&self) -> SessionState {
        self.run("status")
            .map(|o| parse_session_state(&String::from_utf8_lossy(&o.stdout)))
            .unwrap_or(SessionState::Unknown)
    }
}

#[cfg(all(test, feature = "host-stub"))]
mod tests {
    use super::*;

    // ── Existing orchestration invariants (host stubs) ─────────────────────────

    #[test]
    fn reconcile_no_consent_holds_the_far_side_closed() {
        let mut orch = Orchestrator::new(ManagedProfileSubstrate::new(Persona::GooglePlay));
        let r = orch.reconcile(&GateState::deny_all()).unwrap();
        assert_eq!(r, Reconciliation::HeldClosedNoConsent);
        assert_eq!(orch.substrate().status().lifecycle, Lifecycle::Absent);
    }

    #[test]
    fn reconcile_consent_activates_the_isolated_persona() {
        let mut orch = Orchestrator::new(WaydroidSubstrate::new(Persona::GooglePlay));
        let r = orch
            .reconcile(&GateState::consented(ConsentScope::Session))
            .unwrap();
        assert_eq!(r, Reconciliation::Activated);
        assert_eq!(orch.substrate().status().lifecycle, Lifecycle::Active);
    }

    #[test]
    fn kill_switch_cuts_the_span_and_blocks_restart() {
        let mut orch = Orchestrator::new(WaydroidSubstrate::new(Persona::GooglePlay));
        orch.reconcile(&GateState::consented(ConsentScope::Session))
            .unwrap();

        let mut gate = GateState::consented(ConsentScope::Session);
        gate.kill_switch_engaged = true;
        let r = orch.reconcile(&gate).unwrap();
        assert_eq!(r, Reconciliation::Killed);
        assert_eq!(orch.substrate().status().lifecycle, Lifecycle::Killed);

        // While the gate still says killed, a direct restart is refused.
        let err = orch.substrate_mut().ensure_profile().unwrap_err();
        assert_eq!(err, SubstrateError::KillSwitchEngaged);
    }

    #[test]
    fn kill_never_clears_the_sealed_wallet_invariant() {
        for mut s in [
            Box::new(ManagedProfileSubstrate::new(Persona::GooglePlay)) as Box<dyn Substrate>,
            Box::new(WaydroidSubstrate::new(Persona::GooglePlay)) as Box<dyn Substrate>,
        ] {
            s.ensure_profile().unwrap();
            let killed = s.kill();
            assert_eq!(killed.lifecycle, Lifecycle::Killed);
            assert!(
                killed.sealed_wallet_preserved,
                "cutting the span must never destroy sealed wallet state"
            );
        }
    }

    #[test]
    fn disengaging_the_kill_switch_reopens_via_reconcile() {
        let mut orch = Orchestrator::new(ManagedProfileSubstrate::new(Persona::GooglePlay));
        let mut gate = GateState::consented(ConsentScope::Session);
        gate.kill_switch_engaged = true;
        orch.reconcile(&gate).unwrap();
        assert_eq!(orch.substrate().status().lifecycle, Lifecycle::Killed);

        // Disengage in the gate → reconcile revives + reactivates.
        gate.kill_switch_engaged = false;
        let r = orch.reconcile(&gate).unwrap();
        assert_eq!(r, Reconciliation::Activated);
        assert_eq!(orch.substrate().status().lifecycle, Lifecycle::Active);
    }

    #[test]
    fn a_violated_wallet_invariant_is_a_hard_stop() {
        let mut orch = Orchestrator::new(WaydroidSubstrate::new(Persona::GooglePlay));
        let mut gate = GateState::consented(ConsentScope::Session);
        gate.sealed_wallet_preserved = false; // must be impossible; fail loudly if seen.
        let err = orch.reconcile(&gate).unwrap_err();
        assert_eq!(err, SubstrateError::SealedWalletViolated);
    }

    #[test]
    fn enforcement_stub_is_userland_never_kernel() {
        let s = ManagedProfileSubstrate::new(Persona::GooglePlay);
        assert_eq!(s.enforcement(), Enforcement::ByConstruction);
        assert!(s.enforcement().honest_label().contains("not an OS/kernel"));
    }

    // ── Per-capability lane mapping (the deepened orchestrator surface) ───────

    #[test]
    fn consent_alone_opens_no_lane_deny_by_default() {
        // Standing on the bridge activates the persona but lends NOTHING.
        let mut orch = Orchestrator::new(WaydroidSubstrate::new(Persona::GooglePlay));
        let r = orch
            .reconcile(&GateState::consented(ConsentScope::Session))
            .unwrap();
        assert_eq!(r, Reconciliation::Activated);
        assert_eq!(orch.substrate().status().lifecycle, Lifecycle::Active);
        assert!(orch.open_lanes().all_closed(), "no crossing thrown ⇒ no lane open");
    }

    #[test]
    fn reconcile_maps_exactly_the_thrown_crossings_to_lanes() {
        let mut orch = Orchestrator::new(ManagedProfileSubstrate::new(Persona::GooglePlay));
        let gate = GateState::consented(ConsentScope::Session)
            .open_crossing(Capability::Clipboard)
            .open_crossing(Capability::Files);
        orch.reconcile(&gate).unwrap();

        let lanes = orch.open_lanes();
        assert!(lanes.is_open(Capability::Clipboard));
        assert!(lanes.is_open(Capability::Files));
        assert!(!lanes.is_open(Capability::Mic), "an un-thrown crossing stays closed");
        assert!(!lanes.is_open(Capability::Camera));
        assert!(!lanes.is_open(Capability::Location));
        assert_eq!(lanes.count(), 2);
        // The orchestrator only ever narrows: open ⊆ gate.crossings.
        for cap in lanes.iter_open() {
            assert!(gate.crossings.is_open(cap));
        }
    }

    #[test]
    fn closing_a_crossing_closes_its_lane_on_the_next_reconcile() {
        let mut orch = Orchestrator::new(WaydroidSubstrate::new(Persona::GooglePlay));
        let open = GateState::consented(ConsentScope::Session)
            .open_crossing(Capability::Clipboard)
            .open_crossing(Capability::Mic);
        orch.reconcile(&open).unwrap();
        assert_eq!(orch.open_lanes().count(), 2);

        // Operator closes just the mic crossing; reconcile must drop that lane only.
        let narrowed = GateState::consented(ConsentScope::Session)
            .open_crossing(Capability::Clipboard);
        orch.reconcile(&narrowed).unwrap();
        let lanes = orch.open_lanes();
        assert!(lanes.is_open(Capability::Clipboard));
        assert!(!lanes.is_open(Capability::Mic), "revocation is monotonic and immediate");
        assert_eq!(lanes.count(), 1);
    }

    #[test]
    fn kill_switch_slams_every_lane_shut() {
        let mut orch = Orchestrator::new(ManagedProfileSubstrate::new(Persona::GooglePlay));
        let open = GateState::consented(ConsentScope::Session)
            .open_crossing(Capability::Clipboard)
            .open_crossing(Capability::Files)
            .open_crossing(Capability::Location);
        orch.reconcile(&open).unwrap();
        assert_eq!(orch.open_lanes().count(), 3);

        let mut killed = open;
        killed.kill_switch_engaged = true;
        let r = orch.reconcile(&killed).unwrap();
        assert_eq!(r, Reconciliation::Killed);
        assert!(orch.open_lanes().all_closed(), "kill drops every lane with the span");
    }

    #[test]
    fn withdrawing_consent_closes_every_lane() {
        let mut orch = Orchestrator::new(WaydroidSubstrate::new(Persona::GooglePlay));
        let open = GateState::consented(ConsentScope::Session)
            .open_crossing(Capability::Clipboard)
            .open_crossing(Capability::Camera);
        orch.reconcile(&open).unwrap();
        assert_eq!(orch.open_lanes().count(), 2);

        // The operator leaves the bridge (consent.accepted → false).
        let mut left = open;
        left.consent_accepted = false;
        let r = orch.reconcile(&left).unwrap();
        assert_eq!(r, Reconciliation::HeldClosedNoConsent);
        assert!(orch.open_lanes().all_closed(), "no consent ⇒ no lane exposed");
    }

    #[test]
    fn a_lane_cannot_be_opened_before_the_persona_exists() {
        let mut s = ManagedProfileSubstrate::new(Persona::GooglePlay);
        // Fresh substrate: persona Absent. A direct lane open is fail-closed.
        assert_eq!(
            s.open_lane(Capability::Clipboard).unwrap_err(),
            SubstrateError::PersonaAbsent
        );
        assert!(s.open_lanes().all_closed());
    }

    #[test]
    fn a_killed_span_refuses_to_open_a_lane() {
        let mut s = WaydroidSubstrate::new(Persona::GooglePlay);
        s.ensure_profile().unwrap();
        s.open_lane(Capability::Clipboard).unwrap();
        s.kill();
        assert_eq!(
            s.open_lane(Capability::Clipboard).unwrap_err(),
            SubstrateError::KillSwitchEngaged
        );
        assert!(s.open_lanes().all_closed(), "kill already closed every lane");
    }

    #[test]
    fn reviving_reopens_no_lane_until_reconcile_maps_them() {
        // Kill → disengage: the span comes back Absent with zero lanes; only a
        // consented reconcile re-maps the thrown crossings.
        let mut orch = Orchestrator::new(ManagedProfileSubstrate::new(Persona::GooglePlay));
        let open = GateState::consented(ConsentScope::Session)
            .open_crossing(Capability::Files);
        orch.reconcile(&open).unwrap();
        assert_eq!(orch.open_lanes().count(), 1);

        let mut killed = open;
        killed.kill_switch_engaged = true;
        orch.reconcile(&killed).unwrap();
        assert!(orch.open_lanes().all_closed());

        // Disengage with the same crossing still thrown ⇒ the lane is re-mapped.
        orch.reconcile(&open).unwrap();
        assert!(orch.open_lanes().is_open(Capability::Files));
        assert_eq!(orch.open_lanes().count(), 1);
    }

    #[test]
    fn lane_set_none_is_the_fail_closed_default() {
        assert!(LaneSet::none().all_closed());
        assert_eq!(LaneSet::default(), LaneSet::none());
        assert!(GateState::deny_all().crossings.all_closed());
        assert!(GateState::consented(ConsentScope::Session).crossings.all_closed());
    }

    // ── A real seam reports its OS boundary honestly ───────────────────────────

    /// A fake sloboda seam that records the calls the substrate made and reports an
    /// OS boundary — proves the substrate state machine drives the *real* seam
    /// verbs and surfaces its honest enforcement class.
    #[derive(Debug, Default)]
    struct FakeSloboda {
        started: u32,
        stopped: u32,
        killed: u32,
        fail_start: bool,
    }
    impl SlobodaSeam for FakeSloboda {
        fn enforcement(&self) -> Enforcement {
            Enforcement::OsBoundary
        }
        fn start(&mut self) -> Result<(), SubstrateError> {
            if self.fail_start {
                return Err(SubstrateError::Backend("boot failed".into()));
            }
            self.started += 1;
            Ok(())
        }
        fn stop(&mut self) -> Result<(), SubstrateError> {
            self.stopped += 1;
            Ok(())
        }
        fn kill(&mut self) {
            self.killed += 1;
        }
        fn probe(&self) -> SessionState {
            if self.started > self.stopped && self.killed == 0 {
                SessionState::Running
            } else {
                SessionState::Stopped
            }
        }
    }

    #[test]
    fn real_seam_backend_drives_start_and_kill_and_reports_os_boundary() {
        let mut sub = WaydroidSubstrate::with_seam(Persona::GooglePlay, FakeSloboda::default());
        assert_eq!(sub.enforcement(), Enforcement::OsBoundary);
        assert!(sub.enforcement().honest_label().contains("not attestation"));

        sub.ensure_profile().unwrap();
        sub.switch_to(Persona::GooglePlay).unwrap();
        assert_eq!(sub.status().lifecycle, Lifecycle::Active);
        assert_eq!(sub.seam().started, 1);
        assert_eq!(sub.seam().probe(), SessionState::Running);

        let st = sub.kill();
        assert_eq!(st.lifecycle, Lifecycle::Killed);
        assert!(st.sealed_wallet_preserved);
        assert_eq!(sub.seam().killed, 1);
        assert_eq!(sub.seam().probe(), SessionState::Stopped);
    }

    #[test]
    fn real_seam_start_failure_is_surfaced_fail_closed() {
        let seam = FakeSloboda {
            fail_start: true,
            ..FakeSloboda::default()
        };
        let mut orch = Orchestrator::new(WaydroidSubstrate::with_seam(Persona::GooglePlay, seam));
        let err = orch
            .reconcile(&GateState::consented(ConsentScope::Session))
            .unwrap_err();
        assert!(matches!(err, SubstrateError::Backend(_)));
        // The span never claims Active on a failed boot.
        assert_ne!(orch.substrate().status().lifecycle, Lifecycle::Active);
    }

    // ── Projection (mirrors Dev C's projectSlobodaBridgeState) ─────────────────

    #[test]
    fn projection_line_is_enabled_only_when_consented_live_and_a_crossing_is_open() {
        // Not consented → disabled.
        assert_eq!(project_sloboda_line(&GateState::deny_all()), "disabled");
        // Consented but no crossing open → disabled (run, not share).
        assert_eq!(
            project_sloboda_line(&GateState::consented(ConsentScope::Session)),
            "disabled"
        );
        // Consented + a crossing open → enabled.
        assert_eq!(
            project_sloboda_line(&GateState::consented_with_crossing(ConsentScope::Session)),
            "enabled"
        );
        // Kill overrides an open crossing → disabled.
        let mut g = GateState::consented_with_crossing(ConsentScope::Session);
        g.kill_switch_engaged = true;
        assert_eq!(project_sloboda_line(&g), "disabled");
    }

    #[test]
    fn projection_file_carries_container_and_kill_markers_paw_lib_reads() {
        // Consented, no crossing: line-1 disabled but container=allowed (may enter).
        let body = project_sloboda_bridge_state(&GateState::consented(ConsentScope::Session));
        let mut lines = body.lines();
        assert_eq!(lines.next(), Some("disabled"));
        assert!(body.contains("container=allowed"));
        assert!(!body.contains("kill=engaged"));

        // Kill: disabled + kill=engaged, no container=allowed.
        let mut g = GateState::consented_with_crossing(ConsentScope::Session);
        g.kill_switch_engaged = true;
        let body = project_sloboda_bridge_state(&g);
        assert!(body.starts_with("disabled\n"));
        assert!(body.contains("kill=engaged"));
        assert!(!body.contains("container=allowed"));

        // Fully open: enabled + container=allowed.
        let body =
            project_sloboda_bridge_state(&GateState::consented_with_crossing(ConsentScope::Session));
        assert!(body.starts_with("enabled\n"));
        assert!(body.contains("container=allowed"));
    }

    // ── Fail-closed gate-state parsing (the normalize() trust boundary) ────────

    #[test]
    fn from_gate_json_parses_a_valid_state() {
        let g = GateState::consented_with_crossing(ConsentScope::Persistent);
        let parsed = GateState::from_gate_json(&g.to_gate_json());
        assert!(parsed.consent_accepted);
        assert_eq!(parsed.consent_scope, ConsentScope::Persistent);
        assert!(parsed.any_crossing_open());
        assert!(parsed.crossings.is_open(Capability::Clipboard));
        assert!(!parsed.kill_switch_engaged);
        assert!(parsed.sealed_wallet_preserved);
    }

    #[test]
    fn from_gate_json_round_trips_every_per_capability_lane() {
        let g = GateState::consented(ConsentScope::Session)
            .open_crossing(Capability::Mic)
            .open_crossing(Capability::Location);
        let parsed = GateState::from_gate_json(&g.to_gate_json());
        assert_eq!(parsed.crossings, g.crossings);
        assert!(parsed.crossings.is_open(Capability::Mic));
        assert!(parsed.crossings.is_open(Capability::Location));
        assert!(!parsed.crossings.is_open(Capability::Clipboard));
    }

    #[test]
    fn from_gate_json_fail_closes_on_garbage_and_foreign_files() {
        for bad in [
            "",
            "not json",
            "{}",
            "{\"schema\":\"something.else\",\"version\":1}",
            // right schema, wrong version → deny
            "{\"schema\":\"postern.noporis-gate.state\",\"version\":2}",
            // right schema+version, sealedWallet.preserved=false → foreign → deny
            "{\"schema\":\"postern.noporis-gate.state\",\"version\":1,\"tier\":\"non-attestable\",\
              \"sealedWallet\":{\"preserved\":false}}",
        ] {
            let g = GateState::from_gate_json(bad);
            assert_eq!(g, GateState::deny_all(), "garbage must deny: {bad}");
        }
    }

    #[test]
    fn from_gate_json_treats_non_true_open_as_never_given() {
        // `open` is the string "true", not the boolean — must be treated as closed.
        let json = "{\"schema\":\"postern.noporis-gate.state\",\"version\":1,\"tier\":\"non-attestable\",\
            \"consent\":{\"accepted\":true,\"scope\":\"session\"},\
            \"crossings\":{\"clipboard\":{\"open\":\"true\"}},\
            \"killSwitch\":{\"engaged\":false},\"sealedWallet\":{\"preserved\":true}}";
        let g = GateState::from_gate_json(json);
        assert!(g.consent_accepted);
        assert!(!g.any_crossing_open(), "a non-boolean `open` is never-given");
    }

    // ── The orchestrator is the sole writer; commit writes both files atomically ─

    #[test]
    fn commit_writes_both_state_files_atomically_and_reconciles() {
        let dir = tempfile::tempdir().unwrap();
        let paths = StatePaths::under(dir.path());
        let mut orch = Orchestrator::new(WaydroidSubstrate::new(Persona::GooglePlay));

        let gate = GateState::consented_with_crossing(ConsentScope::Session);
        let json = gate.to_gate_json();
        let r = orch.commit(&gate, json.as_bytes(), &paths).unwrap();
        assert_eq!(r, Reconciliation::Activated);

        // state.json is the verbatim bytes; the projection is the derived toggle.
        let state = fs::read_to_string(&paths.state_json).unwrap();
        assert_eq!(state, json);
        let proj = fs::read_to_string(&paths.sloboda_bridge_state).unwrap();
        assert!(proj.starts_with("enabled\n"));
        assert!(proj.contains("container=allowed"));

        // Round-trips back to the same load-bearing posture.
        assert_eq!(GateState::from_gate_json(&state), gate);
        // ...and the substrate's lanes were mapped to match the committed crossing.
        assert!(orch.open_lanes().is_open(Capability::Clipboard));
    }

    #[test]
    fn commit_kill_writes_disabled_projection_before_cutting_the_span() {
        let dir = tempfile::tempdir().unwrap();
        let paths = StatePaths::under(dir.path());
        let mut orch = Orchestrator::new(WaydroidSubstrate::new(Persona::GooglePlay));

        // Bring it up first.
        let live = GateState::consented_with_crossing(ConsentScope::Session);
        orch.commit(&live, live.to_gate_json().as_bytes(), &paths)
            .unwrap();

        // Engage the kill-switch and commit.
        let mut gate = live;
        gate.kill_switch_engaged = true;
        let r = orch
            .commit(&gate, gate.to_gate_json().as_bytes(), &paths)
            .unwrap();
        assert_eq!(r, Reconciliation::Killed);
        assert_eq!(orch.substrate().status().lifecycle, Lifecycle::Killed);

        let proj = fs::read_to_string(&paths.sloboda_bridge_state).unwrap();
        assert!(proj.starts_with("disabled\n"));
        assert!(proj.contains("kill=engaged"));
        assert!(!proj.contains("container=allowed"));
        // The sealed wallet invariant survives the kill.
        assert!(orch.substrate().status().sealed_wallet_preserved);
        // ...and every lane dropped with the span.
        assert!(orch.open_lanes().all_closed());
    }

    #[test]
    fn write_atomic_replaces_content_and_leaves_no_temp_files() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("sloboda-bridge.state");
        write_atomic(&target, b"disabled\n").unwrap();
        write_atomic(&target, b"enabled\ncontainer=allowed\n").unwrap();
        assert_eq!(
            fs::read_to_string(&target).unwrap(),
            "enabled\ncontainer=allowed\n"
        );
        // No leftover `.sloboda-bridge.state.*.tmp` files in the dir.
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "atomic write must clean up temp files");
    }

    // ── The real sloboda status parser (pure; no exec) ─────────────────────────

    // ── F2 persistence hardening: projection schema versioning ─────────────────

    #[test]
    fn projection_schema_version_round_trips_and_verifies() {
        let body = project_sloboda_bridge_state(&GateState::consented_with_crossing(ConsentScope::Session));
        assert_eq!(
            parse_sloboda_bridge_schema_version(&body),
            Some(SLOBODA_BRIDGE_SCHEMA_VERSION)
        );
        assert!(verify_sloboda_bridge_schema(&body).is_ok());
        // The versioning marker is additive — line 1 authority is untouched.
        assert!(body.starts_with("enabled\n"));
    }

    #[test]
    fn projection_unknown_schema_version_fails_closed() {
        let forged = "enabled\ncontainer=allowed\nschema_version=99\n";
        assert!(parse_sloboda_bridge_schema_version(forged) == Some(99));
        let err = verify_sloboda_bridge_schema(forged).unwrap_err();
        assert!(matches!(err, SubstrateError::Backend(_)));
    }

    #[test]
    fn projection_missing_schema_version_fails_closed_never_silently_misparsed() {
        // A pre-versioning / corrupted write with no marker line at all.
        let legacy = "enabled\ncontainer=allowed\n";
        assert_eq!(parse_sloboda_bridge_schema_version(legacy), None);
        let err = verify_sloboda_bridge_schema(legacy).unwrap_err();
        assert!(matches!(err, SubstrateError::Backend(_)));
    }

    // ── Schema-reader PREFLIGHT: verify_sloboda_bridge_schema is finally WIRED to
    //    a real on-disk read (read_sloboda_bridge_state). ────────────────────────

    #[test]
    fn read_sloboda_bridge_state_absent_file_is_ok_none_first_boot() {
        // No projection written yet — the fresh-boot case: nothing to distrust,
        // the orchestrator is free to become its sole writer.
        let dir = tempfile::tempdir().unwrap();
        let paths = StatePaths::under(dir.path());
        assert_eq!(read_sloboda_bridge_state(&paths), Ok(None));
    }

    #[test]
    fn read_sloboda_bridge_state_our_own_write_verifies_and_round_trips() {
        // What the orchestrator wrote, the preflight reads back and TRUSTS.
        let dir = tempfile::tempdir().unwrap();
        let paths = StatePaths::under(dir.path());
        let gate = GateState::consented_with_crossing(ConsentScope::Session);
        write_atomic(
            &paths.sloboda_bridge_state,
            project_sloboda_bridge_state(&gate).as_bytes(),
        )
        .unwrap();
        let body = read_sloboda_bridge_state(&paths)
            .expect("a well-formed projection verifies")
            .expect("present, so Some");
        assert!(body.starts_with("enabled\n"));
        assert_eq!(
            parse_sloboda_bridge_schema_version(&body),
            Some(SLOBODA_BRIDGE_SCHEMA_VERSION)
        );
    }

    #[test]
    fn read_sloboda_bridge_state_foreign_schema_is_a_hard_refusal_never_a_silent_clobber() {
        // A projection written by a version this orchestrator does not understand
        // must surface as Err — NOT Ok(None), NOT a silent overwrite. This is the
        // exact gap: verify_sloboda_bridge_schema now actually runs at runtime.
        let dir = tempfile::tempdir().unwrap();
        let paths = StatePaths::under(dir.path());
        fs::create_dir_all(dir.path()).unwrap();
        fs::write(&paths.sloboda_bridge_state, b"enabled\ncontainer=allowed\nschema_version=999\n")
            .unwrap();
        let err = read_sloboda_bridge_state(&paths).unwrap_err();
        assert!(matches!(err, SubstrateError::Backend(_)));
    }

    #[test]
    fn read_sloboda_bridge_state_unversioned_projection_fails_closed() {
        // A pre-versioning / truncated write that dropped its marker line must also
        // refuse — never default-trust an unversioned line-1 authority.
        let dir = tempfile::tempdir().unwrap();
        let paths = StatePaths::under(dir.path());
        fs::create_dir_all(dir.path()).unwrap();
        fs::write(&paths.sloboda_bridge_state, b"enabled\ncontainer=allowed\n").unwrap();
        assert!(read_sloboda_bridge_state(&paths).is_err());
    }

    // ── F2 persistence hardening: crash-recovery reload ─────────────────────────

    #[test]
    fn read_gate_state_denies_on_a_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let paths = StatePaths::under(dir.path().join("never-written"));
        assert_eq!(read_gate_state(&paths), GateState::deny_all());
    }

    #[test]
    fn read_gate_state_recovers_the_last_committed_posture() {
        let dir = tempfile::tempdir().unwrap();
        let paths = StatePaths::under(dir.path());
        let mut orch = Orchestrator::new(WaydroidSubstrate::new(Persona::GooglePlay));
        let gate = GateState::consented(ConsentScope::Persistent)
            .open_crossing(Capability::Mic)
            .open_crossing(Capability::Location);
        orch.commit(&gate, gate.to_gate_json().as_bytes(), &paths).unwrap();

        let recovered = read_gate_state(&paths);
        assert_eq!(recovered, gate, "reload reproduces the exact committed posture");
    }

    #[test]
    fn read_gate_state_fail_closes_on_a_corrupted_file_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let paths = StatePaths::under(dir.path());
        // Directly corrupt state.json (bypassing write_atomic entirely) — models a
        // torn write from something outside this crate's control.
        fs::create_dir_all(dir.path()).unwrap();
        fs::write(&paths.state_json, b"{not even close to json").unwrap();
        assert_eq!(read_gate_state(&paths), GateState::deny_all());
    }

    // ── F2 persistence hardening: sole-writer discipline ────────────────────────

    #[test]
    fn writer_lock_refuses_a_second_concurrent_holder() {
        let dir = tempfile::tempdir().unwrap();
        let paths = StatePaths::under(dir.path());
        let first = WriterLock::acquire(&paths).expect("first writer acquires");
        let second = WriterLock::acquire(&paths);
        assert!(second.is_err(), "a second writer must be refused, not silently interleaved");
        assert_eq!(second.unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        drop(first);
        // Released: a fresh acquire now succeeds.
        assert!(WriterLock::acquire(&paths).is_ok());
    }

    #[test]
    fn writer_lock_steal_recovers_from_a_crashed_holder() {
        let dir = tempfile::tempdir().unwrap();
        let paths = StatePaths::under(dir.path());
        let crashed = WriterLock::acquire(&paths).expect("first writer acquires");
        std::mem::forget(crashed); // simulate a SIGKILL: Drop never runs, lock file lingers.

        assert!(WriterLock::acquire(&paths).is_err(), "the stale lock still blocks a plain acquire");
        let recovered = WriterLock::steal(&paths);
        assert!(recovered.is_ok(), "explicit steal recovers from a crashed holder");
    }

    #[test]
    fn parse_session_state_reads_the_sloboda_status_line() {
        assert_eq!(
            parse_session_state("session:    RUNNING\nimage type: VANILLA\n"),
            SessionState::Running
        );
        assert_eq!(
            parse_session_state("session:    STOPPED\n"),
            SessionState::Stopped
        );
        // No session line, or an odd value → fail-safe Unknown.
        assert_eq!(
            parse_session_state("image type: VANILLA\n"),
            SessionState::Unknown
        );
        assert_eq!(parse_session_state("session: UNKNOWN\n"), SessionState::Unknown);
    }
}
