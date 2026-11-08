<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Waydroid 02 — Consent-gate runtime, kill-switch & host launcher integration

**Architect A8 · Waydroid tier · design / reference-prototype. UNAUDITED — certifies nothing.**

> ## ⚠ HONESTY HEADER — read before trusting anything here
>
> This is the **NON-ATTESTABLE escape-hatch tier** — "Postern for postmarketOS —
> community edition". It is **NOT "Porog"** (the stock-Android managed-profile
> container) and **NEVER "Postern OS"**. Entering Android = **data leaves the
> sealed base**. Play Integrity STRONG fails (banking / Wallet / DRM refuse).
> **Not covered by the Postern Seal** (`os_roothash` says nothing about the
> mutable Waydroid image). The coin is worthless; personal use is free; not legal
> advice. **UNTESTED** — nothing here has booted a container; every `waydroid …`
> call is a scaffold validated only by `shellcheck` + a mock trace.
>
> **Rail this whole document defends:** the wrapper **NEVER opens a privacy
> bridge on its own**. It only **reads** a toggle owned by the consent-gate and
> treats anything but a literal enabled projection as **OFF**. microG-vs-GApps is
> a config input (default `VANILLA`). This document does **not** relax that rail
> — it makes the *writer* side real while keeping the wrapper read-only.

---

## 0 · Scope & the gap this closes

Two halves of the consent story already exist in-repo and **do not yet meet**:

| Half | Where | State it speaks |
|---|---|---|
| **Reader** (the wrapper) | `apps/sloboda/bin/paw-lib.sh` → `paw_bridge_enabled()` | Reads a **flat line-file** `/run/postern/consent/sloboda-bridge.state`; enabled **only if** line 1 is exactly `enabled`. |
| **Writer/model** (the gate) | `apps/sloboda-gate/gate-store.mjs` + `index.html` | Owns a **rich JSON** deny-by-default kernel at `/var/lib/postern/sloboda-gate/state.json` (`consent`/`bridges`/`egress`/`killSwitch`). Today it only persists to **browser localStorage** — no on-device writer exists. |

The wrapper reads a bool; the gate models a full posture; nothing on-device
actually writes the file the wrapper reads. This design supplies the **missing
middle**: a small **consent-gate runtime** that owns and atomically writes the
canonical JSON, **projects** it to the minimal line-file the wrapper reads, and
wires the **kill-switch** and **launcher** flows end-to-end — all provable
offline, with on-device items explicitly fenced off.

The gate's browser UI (`apps/sloboda-gate/index.html`) itself notes the
plan: *"State persists to localStorage … a small separate [writer]"*. This is
that writer.

---

## 1 · The shared consent state-file contract (unify A3 Porog / A5 NoporIS / A8 Waydroid)

The three tiers already converge on **one kernel pattern** — `noporis-gate`'s
README says it *"reuses the deny-by-default kernel pattern from
`apps/sloboda-gate`"*. This section pins that convergence as an explicit
**cross-tier contract** so ONE consent model spans all three.

### 1.1 Contract invariants (identical across all three tiers)

Every tier's state file is a JSON object at
`/var/lib/postern/<product>-gate/state.json` with a shared spine:

```
schema   : "postern.<product>-gate.state"   // discriminator; refuse a foreign file outright
version  : 1                                 // full-deny on an unknown version
tier     : "non-attestable"                  // PINNED true-by-default; input can NEVER relabel as attested
consent  : { accepted:false, scope:"session"|"persistent", acceptedAtIso:null }
killSwitch: { engaged:false, engagedAtIso:null }
lang     : "pt-BR" | "en"                     // cosmetic
<capabilities>: { … per-tier capability object … }   // ALL default DENY
<tier-rails>  : { … per-tier pinned invariants … }
```

**Seven rails that MUST hold in code (not just prose), verified per tier:**

1. **Discriminator + version** — a file whose `schema`/`version` don't match is
   treated as absent → full-deny.
2. **`tier` pinned** — always `non-attestable`; taken from `defaultState()`,
   never from input.
3. **Deny-by-default capabilities** — every capability is `false`/closed unless
   an explicit, disclosed toggle set it; `asBool(v) === (v === true)` (anything
   not exactly `true` is deny).
4. **`normalize()` is the trust boundary** — any input (missing / partial /
   garbage / hostile) collapses to a well-formed full-deny state; `parse()`
   never throws.
5. **Kill-switch is always allowed, never destructive to the sealed base** —
   engaging stops the runtime; it never clears wallet/keys.
6. **Fail-closed decisions** — `containerAllowed = !killSwitch.engaged && (consent.accepted || !requireConsent)`; capability grants are `[]` whenever the container isn't allowed.
7. **No telemetry** — the file never leaves the device; the writer does no
   network I/O.

### 1.2 Where the tiers differ (the only per-tier variation)

| | Waydroid (A8, this doc) | NoporIS (A5) | Porog (A3) |
|---|---|---|---|
| `schema` | `postern.sloboda-gate.state` | `postern.noporis-gate.state` | `postern.porog-gate.state` (proposed) |
| Capability object | `bridges{clipboard,files,mic,camera,location}` (flat bool) | `crossings{…}` (each `{open,scope,openedAtIso}`) | door/profile crossings (A3-defined) |
| Extra rail | `egress{torOnly:true(pinned), torBootstrapped}` — **Tor-only egress, fail-closed** | `sealedWallet{preserved:true(pinned)}` | A3-defined (managed-profile attest) |
| Tor rail? | **Yes** (community edition rail) | **No** (far side uses normal networking) | A3-defined |

**Recommendation to A3/A5 (contract alignment asks):**

- Keep the **spine field names byte-identical** (`schema`/`version`/`tier`/
  `consent`/`killSwitch`/`lang`) so a single validator and a single
  `containerAllowed()` shape reads all three. NoporIS/Porog already match on
  `consent`+`killSwitch`; only the capability object and tier-rail differ — that
  is the *intended* variation, not drift.
- Adopt the **capability sub-object shape** (`{open,scope,openedAtIso}`, as
  NoporIS's `crossing`) as the **v2 target for Waydroid `bridges`** too, so
  per-capability scope/revocation is uniform. v1 keeps the flat bool for
  backward-compat with the shipped `gate-store.mjs`; migration is a `normalize()`
  widening (flat `true` → `{open:true,scope:"session"}`), no reader change.
- **Runtime projection path is standardized** (see §2.3):
  `/run/postern/consent/<product>-bridge.state`. Waydroid already uses
  `/run/postern/consent/sloboda-bridge.state`; NoporIS/Porog should mirror the
  pattern so the *reader* contract (line 1 `enabled`/`disabled`) is identical
  across tiers even though canonical JSON schemas differ.

### 1.3 The two-file model (canonical vs projection) — why both

The wrapper deliberately reads a **dumb line-file**, not the rich JSON, to keep
its trust surface microscopic (a `head -n1 | tr -d space` compare — auditable in
one glance, fail-safe by construction). The gate models a **rich posture**. We
keep **both**, bridged by a projection:

```
 CONSENT UI (index.html / CLI)
        │ user acts (accept / toggle bridge / engage kill)
        ▼
 gate-store.mjs  ── normalize() → decision helpers (the trust boundary)
        │ atomic write
        ▼
 CANONICAL  /var/lib/postern/sloboda-gate/state.json   (0600, root)  ← rich JSON, source of truth
        │ gate daemon compiles a projection
        ▼
 PROJECTION /run/postern/consent/sloboda-bridge.state  (0644, root, tmpfs)  ← minimal line-file
        │ read-only
        ▼
 WRAPPER  paw_bridge_enabled() / (new) paw_container_allowed()   ← never writes either file
```

- **Canonical** = rich, persistent, `0600` root-owned, survives reboot when
  `consent.scope=persistent`.
- **Projection** = minimal, ephemeral (`/run` tmpfs, gone on reboot →
  re-derived), `0644` world-readable (it carries **no** secret, only a public
  posture bool), the *only* thing the wrapper parses.

The projection is a **pure function** of the canonical state — the daemon never
invents state, it compiles it.

---

## 2 · The consent-gate runtime component (the new writer)

Name: **`sloboda-gated`** (the gate **daemon** / writer). Lives under
`apps/sloboda-gate/` alongside the existing `gate-store.mjs` (its logic
kernel) — it is **not** part of `apps/sloboda/` (the wrapper stays a
pure reader, and this document does not add a writer to it).

### 2.1 Responsibilities (and non-responsibilities)

**Owns / does:**
- Reads & validates the canonical JSON via `gate-store.mjs` `parse()` (the
  shipped, tested trust boundary).
- Applies operator intents (`accept`, `withdraw`, `bridge <cap> on|off`,
  `kill on|off`) as **pure transforms** → atomic write of canonical JSON.
- Compiles & atomically writes the **projection** line-file after every change.
- On `kill on`: after persisting `killSwitch.engaged=true` + projecting `disabled`,
  **invokes the wrapper's runtime actuator** `sloboda kill` (§3).
- Sets ownership/permissions; creates dirs `0700 root`.

**Never does (rails):**
- Never opens a bridge on its own — every grant is an explicit operator intent.
- Never lowers `tier`, never clears `egress.torOnly`, never touches wallet/keys.
- No network. No telemetry. Never writes anything the wrapper *executes* as code
  (the projection is data, parsed by a fixed `head`/compare).

### 2.2 State-file schema, ownership, permissions, atomic write

| Property | Canonical | Projection |
|---|---|---|
| Path | `/var/lib/postern/sloboda-gate/state.json` | `/run/postern/consent/sloboda-bridge.state` |
| Owner:group | `root:root` | `root:root` |
| Mode | `0600` (dir `0700`) | `0644` (dir `0755`, on `/run` tmpfs) |
| Format | Rich JSON (`gate-state.schema.json` v1) | Line 1: `enabled`\|`disabled`; optional `KEY=on` lines |
| Lifetime | Persistent (if `scope=persistent`) | Ephemeral; re-derived from canonical on boot |
| Writer | `sloboda-gated` only | `sloboda-gated` only |
| Reader | gate daemon + gate UI | wrapper (`paw-lib.sh`) — read-only |

**Atomic write (both files):** write to a temp file **in the same directory**
(`state.json.<pid>.tmp`), `fsync`, `chmod` to target mode, then `rename()` over
the target (atomic within a filesystem). A crash mid-write leaves either the old
file or nothing — and *nothing* is fail-safe (wrapper reads absent → OFF). This
is the standard rename-swap; it guarantees the wrapper never sees a half-written
posture.

**Projection format (backward-compatible with the shipped reader):**

```
disabled
```
or, when consent accepted, kill clear, and ≥1 bridge open:
```
enabled
clipboard=on
files=on
```

Line 1 is the **only** field the current `paw_bridge_enabled()` reads — its
contract (`== "enabled"`) is unchanged. The optional `KEY=on` lines are additive
for a future per-capability reader (§2.4); an old wrapper ignores them safely.

**Projection derivation (pure):**
```
line1  = (containerAllowed(state) && activeBridges(state).length > 0) ? "enabled" : "disabled"
extras = activeBridges(state).map(k => `${k}=on`)     // only when line1 == enabled
```
`containerAllowed` / `activeBridges` are the **already-shipped, node-tested**
helpers in `gate-store.mjs` (26 assertions green). The daemon adds no new
decision logic — it serializes existing decisions.

### 2.3 Informed-consent flow (what the user is shown before data leaves)

The consent UI (`apps/sloboda-gate/index.html`, already built: honesty
strip, per-capability levers, kill-switch, bilingual pt-BR/en) is the human
surface. The **flip** is default-off and requires informed acceptance:

1. First entry → `consent.accepted=false` → wrapper `start` refuses (§3.4).
2. UI shows the honest disclosure verbatim (the existing panel: *"Your wallet
   keys and the attestable system stay behind… don't type seed phrases into
   Android apps"*), enumerates **exactly which bridges** would carry data out
   (clipboard/files/mic/camera/location — each still individually DENY), and the
   `egress: Tor-only, held until bootstrapped` rail.
3. User accepts → daemon writes `consent.accepted=true`, `acceptedAtIso=<now>`,
   `scope` per the user's session-vs-persistent choice (default the safer
   `session` → re-ask next boot).
4. Bridges remain **off** until each is individually, explicitly toggled — accept
   is *permission to run the container*, not *permission to share*. Anti-round-up:
   `openCrossing`-style one-lever-at-a-time; nothing bundles.

### 2.4 Minimal wrapper changes (still read-only)

The wrapper gains **two** read-only capabilities; it still never writes consent
state:

- **`paw_container_allowed()`** — reads projection line 1; a new `killed` /
  `disabled` posture makes `cmd_start`, `cmd_ui`, `cmd_app`, `cmd_store` **refuse
  with an honest message** ("kill-switch engaged / consent not given — run the
  consent gate"). Today the wrapper only *reports* the bridge; it does not refuse
  entry on kill. This closes that gap while keeping the wrapper a pure reader.
- **(optional) per-capability read** — `paw_bridge_caps()` parses the `KEY=on`
  extras so `status`/`doctor` can name exactly which bridges are open. Non-load-
  bearing; line-1 stays the authority.

Both are additive; the existing `paw_bridge_enabled()` and its `== "enabled"`
contract are untouched. A new `PAW_GATE_STATE` (default
`/var/lib/postern/sloboda-gate/state.json`) is documented for tools that want the
rich view, but the wrapper's hot path stays the projection.

---

## 3 · Kill-switch, end-to-end

**Split of duties (preserves the read-only wrapper rail):** the **gate** owns the
*intent + state*; the **wrapper** owns the *runtime teardown*. The gate is the
actuator's caller.

### 3.1 Flow

```
UI "Engage kill-switch" (index.html)
   │
   ▼
sloboda-gated  kill on
   ├─ 1. state = engageKillSwitch(state, nowIso)        // gate-store.mjs pure transform
   ├─ 2. atomic write canonical  → killSwitch.engaged=true, engagedAtIso set
   ├─ 3. atomic write projection → "disabled"           // wrapper now refuses entry
   └─ 4. exec  sloboda kill                     // RUNTIME actuator (existing cmd_kill)
           ├─ waydroid session stop                     // stop session
           ├─ (root) waydroid container stop / systemctl stop waydroid-container
           └─ rm -rf $XDG_RUNTIME_DIR/waydroid          // clear session runtime state ONLY
```

### 3.2 What is torn down vs preserved

- **Torn down:** live session, LXC container, per-user session runtime dir
  (sockets/markers under `$XDG_RUNTIME_DIR/waydroid`).
- **Preserved (proven by construction):** `cmd_kill` in
  `apps/sloboda/bin/sloboda` explicitly does **not** touch
  `/var/lib/waydroid` or `~/.local/share/waydroid` (the provisioned image) — its
  own log says *"provisioned image is untouched"*. Wiping the image is a separate
  bigger hammer, never on the kill path. The sealed base wallet/keys are on the
  host side, never inside Waydroid, so they are untouched by definition.

### 3.3 Re-startability (the proof obligation)

Because kill clears only **runtime** state and leaves the image intact:
`kill on` → `kill off` (disengage) → `sloboda start` must reach
`Session: RUNNING` again from the **same provisioned image** with no re-`init`.
Offline this is provable against the mock (state STOPPED→RUNNING with image
untouched, §4). On-device it is item (5) below.

### 3.4 Refuse-to-start while engaged

`disengageKillSwitch` clears `engaged`; until then, projection line 1 is
`disabled` and `paw_container_allowed()` makes every entry path refuse. A fresh
file has `engaged:false` (so a fresh state does not wedge a legitimately-enabled
container) but `consent.accepted:false` (so it still won't start without consent)
— the two gates are independent, both fail-closed.

---

## 4 · Host launcher integration (make the grid real)

The mechanics exist (`cmd_launchers`, `paw_write_desktop`, `cmd_install_watch`,
`cmd_prune_launchers`, `share/applications/sloboda.desktop`). "Making it
real" is four concrete pieces:

### 4.1 Grid appearance + click-through

- `.desktop` files land in `PAW_DESKTOP_DIR` (default per-user
  `$XDG_DATA_HOME/applications` — **no root needed**). Each `Exec=` routes back
  through the wrapper (`sloboda app <pkg>`), so the honesty/posture path
  and the **new consent check** (§2.4) always run on click — a launcher click
  while the kill-switch is engaged **refuses**, it does not silently re-open the
  container.
- **Desktop DB refresh:** after writing/pruning, run
  `update-desktop-database "$PAW_DESKTOP_DIR"` (best-effort, guarded by
  `command -v`) so the shell app grid re-indexes without a session restart. On
  postmarketOS/Phosh this is what makes new icons appear promptly. On-device item
  (9).

### 4.2 Write-perm reality

- **Per-user (default):** `~/.local/share/applications` — user-writable, the safe
  default, requires no privilege.
- **System-wide (`/usr/share/applications`):** needs root/packager; that is the
  NixOS module's job, not the wrapper's. The wrapper `mkdir -p`s and fails
  honestly if it cannot write (`cannot create $PAW_DESKTOP_DIR`). Document: point
  `PAW_DESKTOP_DIR` at the system dir only from the packaged/rooted context.

### 4.3 Install-watch sync loop as a service

`bin/sloboda-installwatch` is the stable entrypoint; ship the documented
**user** systemd unit (README already sketches it) — user scope so it writes the
per-user dir with no root. It polls `waydroid app list` every
`PAW_WATCH_INTERVAL`s (no install-event API upstream — a polling scaffold),
writes launchers for present apps, prunes launchers for departed apps. Ordering:
`After=` the graphical session; it is a no-op while the container is down
(`app list` empty → nothing written).

### 4.4 Consent coupling

Launchers are just *shortcuts*; the gate still governs entry. A launcher can
exist for an app while the kill-switch is engaged — clicking it re-enters the
wrapper, which consults the projection and refuses. No launcher path bypasses the
gate.

---

## 5 · Build/test — offline-testable vs on-device

### 5.1 Offline test extensions (add to `apps/sloboda/test/dry-run.sh` + a new gate-daemon test)

All of the following run on the macOS host / any Linux, **no container**:

**A. Gate-daemon unit tests (`sloboda-gate/test-gated.mjs`, node):**
1. Atomic write — canonical + projection written via temp+rename; assert no
   partial file ever observable (write to temp, stat target unchanged until
   rename).
2. Permissions — canonical `0600`, projection `0644`, dirs `0700`/`0755`.
3. `parse()` trust boundary — feed malformed / partial / hostile JSON → daemon
   projects `disabled` (reuses shipped `gate-store.mjs` normalize; assert full-deny).
4. Projection derivation — for a matrix of `{consent, killSwitch, bridges}` states,
   assert line 1 and `KEY=on` extras exactly match `containerAllowed`/`activeBridges`.
5. Foreign/`version`-mismatch file → treated as absent → `disabled`.

**B. Wrapper ↔ projection integration (extend `dry-run.sh`, MODE 2):**
6. **Consent refuse** — projection `disabled` (fresh state) → `start`/`app`/`ui`
   refuse with the honest message; assert non-zero + no mock `session start`.
7. **Consent accept** — daemon writes `enabled` projection → `start` reaches
   RUNNING via mock.
8. **Kill-switch transition** — `gated kill on` → assert (a) canonical
   `killSwitch.engaged=true`, (b) projection `disabled`, (c) `cmd_kill` ran
   (mock `session stop` + runtime dir cleared), (d) image marker file **still
   present** (mock leaves a sentinel `~/.local/share/waydroid/IMAGE` untouched).
9. **Re-startable** — `gated kill off` → `start` reaches RUNNING again from the
   same image with no `init` (mock sentinel unchanged).
10. **Read-only proof (keep existing test)** — wrapper never rewrites either
    consent file; content stays byte-identical to what the daemon wrote (extend
    the existing "wrapper did not rewrite consent-gate state" assertion to the
    canonical JSON too).
11. **Per-capability projection** — `bridge clipboard on` → projection carries
    `clipboard=on`; `status` names it.
12. **Launcher consent-coupling** — with projection `disabled`, invoking a
    generated launcher's `Exec` (`sloboda app com.aurora.store`) refuses.

**C. Mock extensions (`test/mock-waydroid`):**
- Add a persistent **image sentinel** so tests 8–9 can prove image-intact /
  re-startable.
- Keep `session start/stop` state transitions (already present).

Target: the existing `passed: 15 failed: 0` grows to cover the consent + kill +
launcher-consent transitions; the gate-daemon node test adds its own count
alongside the shipped `gate-store` (26) and `noporis-gate` (35) suites.

### 5.2 On-device only (needs the real booted container from A7 — UNTESTED here)

These extend the README's existing on-device list with the consent-runtime
specifics:

1. **Projection on real `/run` tmpfs** — daemon writes `0644` root-owned under
   `/run/postern/consent/`; SELinux/AppArmor label lets the unprivileged wrapper
   `read`.
2. **Canonical `0600` root persistence** across reboot with `scope=persistent`;
   `scope=session` re-asks (file absent on `/run`; canonical `accepted` reset by
   the boot unit).
3. **Kill-switch privileges** — `waydroid container stop` /
   `systemctl stop waydroid-container` actually stop the LXC container (needs
   root); confirm the runtime dir clear drops all sockets.
4. **Image-intact after kill** — `/var/lib/waydroid` + `~/.local/share/waydroid`
   byte-unchanged; **re-start reaches `Session: RUNNING`** with no re-init.
5. **Refuse-to-start enforcement** on a real session (projection `disabled`
   genuinely blocks `waydroid session start`).
6. **Launchers in the shell grid** — `.desktop` appear in Phosh/app-grid,
   `update-desktop-database` refresh works, click re-enters the container;
   `/usr/share/applications` write-perm from the packaged context.
7. **install-watch service** under real user systemd; polling picks up
   install/remove events with acceptable latency.
8. **Daemon ↔ systemd ordering** — gate daemon up before any `start`; projection
   present before the wrapper reads it (no race window).

---

## 6 · Top risks

1. **Two-file skew / race** — canonical and projection could momentarily
   disagree (write canonical, crash before projection). Mitigation: projection is
   *derived last* and rename-atomic; the wrapper fail-safe (absent/`disabled` →
   OFF) means the *worst* skew is over-restrictive, never over-permissive.
   Fail-closed is the whole point.
2. **Projection write-perm / label on-device** — if the wrapper can't `read`
   `/run/postern/consent/...` (SELinux, wrong mode), it reads OFF — safe, but the
   user's *enabled* choice silently doesn't take. Needs the on-device label test
   (5.2 #1). Honest failure mode, but a UX papercut.
3. **Kill-switch privilege gap** — `container stop` needs root; on a non-root
   host the session stops but the LXC container may linger. `cmd_kill` already
   surfaces the manual `systemctl` command honestly; do not pretend the container
   is down when it may not be. On-device item (3).
4. **Consent scope confusion** — `persistent` consent survives reboot; a user who
   forgets they granted it re-enters Android without a fresh prompt. Mitigation:
   default `session`, show granted scope in `status`, make withdraw one action.
5. **v1 flat-bool vs v2 per-capability drift with A3/A5** — if Waydroid stays
   flat-bool while NoporIS ships `{open,scope}`, a shared validator forks.
   Mitigation: the v2 widening in §1.2 is a pure `normalize()` change, reader-
   invisible; align before either ships.
6. **UNTESTED reality** — none of the container-side behavior is proven; the
   whole runtime is a scaffold until A7's booted container exists. The honest
   labels must survive first contact with hardware (README on-device #12 — Play
   Integrity reality).

---

## 7 · Phased dev task-list

**Phase 0 — contract lock (design, no code) · 1 dev**
- Ratify §1 shared contract with A3 (Porog) + A5 (NoporIS): spine field names,
  projection path convention `/run/postern/consent/<product>-bridge.state`, v2
  per-capability widening plan. Output: a 1-page contract note all three cite.

**Phase 1 — gate daemon (writer) · 2 devs**
- `sloboda-gated` CLI: `accept|withdraw|bridge <cap> on|off|kill on|off`,
  built on the shipped `gate-store.mjs` transforms (no new decision logic).
- Atomic writer for canonical JSON + projection line-file; ownership/perm setup.
- `test-gated.mjs` (offline tests §5.1-A).

**Phase 2 — wrapper read-side + refuse-to-start · 1 dev**
- `paw_container_allowed()` + wire `start/ui/app/store` to refuse on
  `disabled`/kill; `paw_bridge_caps()` for `status`/`doctor`.
- Keep `paw_bridge_enabled()` + its `== enabled` contract untouched.
- Extend `dry-run.sh` + `mock-waydroid` (offline tests §5.1-B/C).

**Phase 3 — kill-switch end-to-end · 1 dev**
- `gated kill on` → persist + project + exec `sloboda kill`; disengage
  path; re-startability + image-intact tests (§5.1 tests 8–9).

**Phase 4 — launcher integration real · 1 dev**
- `update-desktop-database` refresh in `cmd_launchers`/`cmd_prune_launchers`;
  ship the user systemd unit for install-watch; consent-coupling test (§5.1 #12);
  document per-user vs system-wide write-perm.

**Phase 5 — on-device bring-up (needs A7 container) · 2 devs, gated on A7**
- Everything in §5.2; reconcile honest labels with observed behavior; SELinux/
  AppArmor labels for the projection; systemd ordering.

**Total: ~6 devs across 6 phases** (Phases 0–4 fully offline-provable on the
macOS host / any Linux; Phase 5 blocks on A7's booted aarch64 container).

---

*Design / scaffold only; UNAUDITED. Do not treat any file here as a security
control. Non-attestable tier — not Sealed. The coin is worthless; personal use
is free; not legal advice.*
