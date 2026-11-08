<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs -->

# NoporIS Wave-1 plan — make the guarded bridge FUNCTIONAL

**Role: PMO / execution plan (not product code).** Consolidates architects A4
(dual-persona), A5 (transport/consent/kill/audit), A9 (trust-boundaries), A10
(build/test/CI infra), and the Google-compliance rulebook into one Wave-1 build
order and a **5-dev, strictly non-overlapping** file partition.

> **Status: PLAN. Reference-prototype, UNAUDITED — certifies nothing.** Wave 1
> makes the loop *real on a substrate*; it does **not** add attestation, does not
> ship, and every honesty rail below is load-bearing, not decorative.

---

## 0. Honesty rails (pinned; this plan may not soften them)

Carried verbatim into every task's acceptance criteria and enforced by
`scripts/check-trust-labels.sh` (CRITICAL 1/2/3):

1. **The Google-Play persona is the LESS-PRIVATE, non-attestable side by
   construction.** It runs GMS and phones home to Google. "Separation, not
   privacy." No surface relabels it attested.
2. **NoporIS adds NO new attestation.** No Seal, no padlock, no measured-boot,
   no StrongBox claim about the workspace. The Google-side crypto is **classical**
   — harvest-now-decrypt-later applies to anything it saw.
3. **Default-SAFE / deny-by-default.** Nothing crosses without a live near-side
   grant **and** a live signed `ConsentRecord` **and** a deny-by-default gate
   `Allow` **and** a disengaged kill-switch. Missing/garbage state = full-deny.
4. **Userland, `ByConstruction` — not a kernel boundary.** Only the substrate's
   own OS storage/process split (Android managed profile / LXC) is an
   `OsBoundary`, and that is the OS's, not ours. A rooted host defeats everything.
5. **Kill-switch drops the span; NEVER destroys sealed wallet state.**
   `sealedWallet.preserved` is pinned `true`, never read from input.
6. **Respect Google/Android licenses.** No GMS redistribution (user brings their
   own Google install), no Play-Integrity/SafetyNet circumvention (honest
   labelling instead), nominative naming only. Guardian is **Yagabona**.
7. **App on stock Android (or a host OS) — NEVER "Postern OS."** "NoporIS/Nopor"
   is a proposed mark pending trademark clearance. BLCH is not a security; buys
   no software; personal use is free. Not legal advice.

---

## 1. Where Wave 0 left us (the foundation this wave extends)

Wave 0 already delivered — **HOST-tested (`cargo test` / `node`) on macOS today,
device-UNTESTED**:

| Piece | File | State |
|---|---|---|
| Orchestrator spine + `Substrate` trait + **STUB** backends | `apps/noporis-bridge-glue/src/substrate.rs` | trait/reconcile REAL & tested; `ManagedProfileSubstrate` + `WaydroidSubstrate` are in-memory **stubs (isolate nothing)** |
| Signed Ed25519 `ConsentRecord` + ledger (mint/verify/revoke/expiry/burn) | `src/consent_record.rs` | REAL, tested |
| SHAKE-256 hash-chained audit ledger (`CrossingRecord`/`AuditTrail`) | `src/audit.rs` | REAL, tested |
| Audited send/receive with the 5-step consent check | `src/bridge.rs` (`send_crossing_audited`/`receive_crossing_audited`) | REAL over **in-memory** `Transport`; the last-inch IPC is Android-specific and absent |
| Deny-by-default consent kernel + `normalize()` trust boundary | `apps/noporis-gate/gate-store.mjs` | REAL, tested; **no** `sloboda-bridge.state` projection yet |
| Two-pairings + world-badged signer + `BridgeKillSwitch` | `apps/noporis-signer-glue/**` | REAL, tested; kill-switch fan-out not wired to state files |
| Per-persona egress policy (fail-closed clean / Google out-of-scope) | `apps/noporis-tor-glue/src/lib.rs` | REAL policy; live Tor behind `feature = "live"` (not built here) |
| Persona switcher + guarded-crossing panel (front-end) | `apps/noporis-switcher/index.html` | REAL UI; **not** wired to an orchestrator |
| End-to-end functional proof (consent→cross→audit→kill→wallet-invariant) | `apps/noporis-bridge-glue/tests/functional_proof.rs` | REAL & green on HOST |
| Android persona DPC / lifecycle / provision scaffolds (Kotlin) | `android-bridge/persona/**`, `android-common/**` | scaffold, **never compiled** (no SDK on host) |
| Waydroid wrapper + mock | `apps/sloboda/**` (`test/mock-waydroid`) | POSIX-sh, boots nothing |

**Headline gap (A4 §2):** the two Substrate backends are stubs and the
cross-profile carrier does not exist. Wave 1 = fill those in and prove the loop.

---

## 2. The functional definition of done (A4 §5 / A5 §7)

NoporIS is "functional" when this loop runs **and is observed on a real
substrate**:

> **create/attach far persona → consent → one item crosses → kill-switch closes
> it → re-verify nothing crosses.**

Wave 1 must make each step real on at least one substrate, honestly labelled by
the tier it was proven in.

---

## 3. Tiers (A10) — devs WRITE code regardless; this marks what can be PROVEN where

- **HOST** = the macOS `bloch-mac` runner *today*: `cargo test`, `node`,
  `shellcheck`. Proves Rust/JS control-flow + every honesty rail. Builds **zero**
  Android APKs, boots **zero** containers.
- **VM** = incoming Linux+Nix VM (x86_64 assumed): Gradle/AGP build of the Kotlin
  scaffolds (flips "built"), work-profile **emulator** (provisioning control-flow,
  **never** StrongBox), **binder-VM** Waydroid boot (session RUNNING, app
  list/launch, kill). x86_64 proves *control-flow*, not aarch64/GPU/Play-Integrity.
- **device** = real aarch64 (Pixel-class for managed profile; binder-capable
  Linux phone for full Waydroid). The only tier where the loop counts as "real,"
  and where Play-Integrity STRONG is confirmed to **fail** on the far side.

`UNTESTED-until-VM` / `UNTESTED-until-device` is a first-class status, never
green-faked. A green HOST test never implies a VM/device truth.

---

## 4. Build order (dependency-ordered; the 5 devs run in parallel from day 1)

The devs are partitioned so they can start **simultaneously**; the ordering below
is the *integration* sequence, not a start-gate.

1. **Contracts frozen first (day 0, PMO):** the `Substrate` trait
   (`substrate.rs`), the `GateState` snapshot fields, the `ConsentLedger` /
   `AuditTrail` public APIs, the `Persona`/`Capability` enums, and the
   `sloboda-bridge.state` projection format (consent-contract) are **frozen**.
   All five devs code against these signatures; changes go through the PMO.
2. **Dev A** fills the real backends behind the frozen trait; **Dev B** fills the
   real carrier behind the frozen `Transport`; both keep the HOST stubs/in-memory
   paths green so **Dev E**'s offline loop never regresses.
3. **Dev C** wires the switcher/gate to *emit* the projection and *call* the
   orchestrator; **Dev D** binds per-persona egress + the kill fan-out signal.
4. **Dev E** re-verifies the offline loop continuously, then stands up the
   emulator/binder-VM harness as those land.
5. Integration checkpoints: (i) HOST offline loop green end-to-end (Dev E owns);
   (ii) VM Gradle build + emulator provisioning + binder-VM Waydroid boot; (iii)
   device runbook (manual, logged, out-of-CI).

---

## 5. The 5-dev partition — STRICT non-overlapping file ownership

**Rule:** every file has exactly one owner. Three devs (A, B, E) hold files
inside the `noporis-bridge-glue` crate, split at the **file** level; `lib.rs` and
`Cargo.toml` are the single integration point, owned by **Dev B**, who applies
one-line re-export/dep edits on A's and E's behalf. No other file is co-edited.

| File / dir | Owner |
|---|---|
| `apps/noporis-bridge-glue/src/substrate.rs` | **A** |
| `android-bridge/persona/app/src/main/java/labs/postern/persona/lifecycle/**` | **A** |
| `android-bridge/persona/app/src/main/java/labs/postern/persona/provision/**` | **A** |
| `android-bridge/persona/app/src/main/java/labs/postern/persona/slot/**` | **A** |
| `android-bridge/persona/app/src/main/java/labs/postern/persona/dpc/NoporIsDeviceAdminReceiver.kt` | **A** |
| `apps/sloboda/bin/**`, `apps/sloboda/config/**` (Waydroid substrate seam only) | **A** |
| `apps/noporis-bridge-glue/src/bridge.rs`, `crossing.rs`, `consent.rs`, `consent_record.rs`, `audit.rs`, `grant.rs`, `capability.rs`, `persona.rs`, `error.rs` | **B** |
| `apps/noporis-bridge-glue/src/lib.rs`, `Cargo.toml`, `examples/crossing.rs` | **B** (coordinates re-exports/deps for A & E) |
| `android-bridge/persona/app/src/main/java/labs/postern/persona/bridge/CrossProfileBrokerService.kt` (**NEW**) | **B** |
| `apps/noporis-switcher/**` | **C** |
| `apps/noporis-gate/**` (`gate-store.mjs`, `gate-state.schema.json`, `index.html`, `test-store.mjs`) | **C** |
| `apps/noporis-tor-glue/**` | **D** |
| `apps/noporis-signer-glue/**` (`world.rs`, `signer.rs`, `pairings.rs`, `killswitch.rs`, `lib.rs`) | **D** |
| `apps/noporis-bridge-glue/tests/functional_proof.rs` | **E** |
| `apps/noporis-e2e/**` (**NEW** harness dir), `scripts/vm/**` (**NEW**) | **E** |

**Frozen in Wave 1 (edit only via PMO coordination):** `apps/consent-contract/**`
(the ratified spine), `android-common/**` (co-owned DPC core — reuse Porog's
plumbing, do **not** fork it), `android-bridge/persona/app/src/main/java/labs/postern/persona/flavor/**`
and `.../play/**` (Play-Integrity disclosure surfaces), `scripts/check-trust-labels.sh`.

### Runtime single-writer reconciliation (avoids a real double-writer bug)

A5 §3.2 sketches both `killswitch.rs` and `gate-store.mjs` "writing the state
files." To keep one writer per artifact at runtime:

- **`gate-store.mjs` (Dev C)** exposes a **pure** projection function
  `projectSlobodaBridgeState(state) → "enabled"|"disabled"` — computes, never
  persists.
- **The orchestrator (Dev A, in `substrate.rs`/its wrapper)** is the **sole
  runtime writer** of `state.json` and `/run/postern/consent/sloboda-bridge.state`
  (temp-file + `fsync` + atomic `rename`), because it is the on-device spine that
  reconciles gate→substrate.
- **`killswitch.rs` (Dev D)** flips the in-memory `BridgeKillSwitch` and the
  `ConsentLedger` revocation; it **signals**, it does not write files.

---

## 6. Per-dev tasks

### Dev A — Real Substrate backends (near + far), replacing the Wave-0 stubs
- **Scope:** implement `ManagedProfileSubstrate` (near-side: create/attach/switch/
  kill the managed profile via Porog's DPC seam) and `WaydroidSubstrate` (far-side:
  drive `apps/sloboda`'s read-only bridge-state + kill) behind the **frozen**
  `Substrate` trait. Make the orchestrator the sole runtime writer of the two
  state files. Keep the HOST stubs compiled behind a default feature so Dev E's
  offline loop stays green.
- **Owns:** `substrate.rs`; `android-bridge/persona/.../{lifecycle,provision,slot}/**`
  + `dpc/NoporIsDeviceAdminReceiver.kt`; `apps/sloboda/bin/**` + `config/**` (seam).
- **Spec refs:** A4 §2 (control-plane / two back-ends), Phase 1; A5 §3 (kill
  semantics), §3.2 (state-file contract); A10 §1 (Porog toolchain), §5.2 steps 4–5.
- **Proving test + tier:** `substrate.rs` reconcile/kill/wallet-invariant unit
  tests — **HOST** (extend the existing ones). Real managed-profile provisioning
  control-flow — **VM** (work-profile AVD; StrongBox is device-only and *not
  needed* — NoporIS adds no attestation). Real Waydroid session RUNNING + kill —
  **VM** (binder kernel). Full aarch64 attach/kill — **device**.
- **Deps:** frozen `Substrate` trait + `GateState` (PMO). Consumes `android-common`
  DPC core (read-only) and `apps/sloboda` wrapper's existing kill (read-only).
- **Shared-file coordination:** any new public type / `pub mod` / dep for the real
  backends → hand the one-line `lib.rs` + `Cargo.toml` edit to **Dev B**. State-file
  format aligned with **Dev C** (`projectSlobodaBridgeState`). Waydroid kill maps to
  the same `sloboda-bridge.state = disabled` **Dev C** projects. Must NOT edit
  `android-common` (coordinate with the Porog lead via PMO if unavoidable).

### Dev B — Cross-profile broker transport + wire ConsentRecord+audit into the real send/receive
- **Scope:** build `CrossProfileBrokerService` — the single-method
  (`deliverCrossing(sealedFrame): DeliveryReceipt`) AndroidX `@CrossProfile`
  bound service that carries the opaque sealed frame; back the Rust `Transport`
  seam with it on device. Keep the double-gate (near grant + far signed consent +
  deny-by-default gate + kill) and zeroizing delivery in `bridge.rs`; confirm the
  audit append (size + SHA-256 digest, never bytes) on every send/deliver/deny.
  No `ContentProvider` URI grants, no implicit intents.
- **Owns:** `bridge.rs`, `crossing.rs`, `consent.rs`, `consent_record.rs`,
  `audit.rs`, `grant.rs`, `capability.rs`, `persona.rs`, `error.rs`, `lib.rs`,
  `Cargo.toml`, `examples/crossing.rs`; **NEW** `.../persona/bridge/CrossProfileBrokerService.kt`.
- **Spec refs:** A5 §1 (transport primitive), §2 (consent protocol), §4 (audit),
  §7 (functional proof), Phase 3/5; A4 §3 (runtime crossing defense-in-depth).
- **Proving test + tier:** the consent→cross→audit flow over the **in-memory**
  `Transport` with real crypto/gate/trail — **HOST** (already green; keep it so).
  Real cross-profile bind + `deliverCrossing` carries a sealed frame with no
  ambient side-channel; unbind-on-kill is immediate — **VM** (work-profile
  emulator) → **device**.
- **Deps:** frozen `postern-pairing` `Transport`/`Channel` (consumed, never
  edited). Dev A's `WaydroidSubstrate`/`ManagedProfileSubstrate` provide the
  process context the broker binds within (integration only).
- **Shared-file coordination:** sole owner of `lib.rs`/`Cargo.toml` — applies A's
  and E's re-export/dep requests. Broker Kotlin file lives in a **NEW** `bridge/`
  package, disjoint from A's `lifecycle/`, `provision/`, `slot/`, `dpc/` files.

### Dev C — Persona-switch UX driving the orchestrator + the state projection
- **Scope:** wire `noporis-switcher` to call the orchestrator (switch world →
  re-point pairing, animate the bridge deck; consent panel → `acceptConsent`;
  per-capability levers → `openCrossing`; kill-switch → engage). Add the pure
  `projectSlobodaBridgeState(state)` function to `gate-store.mjs`
  (`"enabled"` iff `consent.accepted && !killSwitch.engaged && any crossing open`,
  else `"disabled"`) and mirror it in the inline UI copy. Keep every surface
  badged "less private / separation, not privacy / non-attestable."
- **Owns:** `apps/noporis-switcher/**`, `apps/noporis-gate/**`.
- **Spec refs:** A4 §3 (switch UX + two consent gates), Phase 3; A5 §2.2
  (creation gesture), §3.2 (projection); A9 §2.4/§2.5 (less-private + default-closed
  rules).
- **Proving test + tier:** `node test-store.mjs` (state kernel + projection),
  `node --check` on the HTML, `shellcheck` — **HOST** (extend the existing 34+
  checks with projection assertions). Switcher actually driving the on-device
  orchestrator + observed persona foregrounding — **VM/device**.
- **Deps:** frozen `GateState` field names (they already track the schema 1:1) and
  the orchestrator command surface (Dev A). Projection format frozen with PMO.
- **Shared-file coordination:** projection output consumed by **Dev A**'s
  orchestrator (the writer) — align the exact string/format. Does NOT touch
  `consent-contract` (frozen); if the spine needs the projection, coordinate.

### Dev D — Per-persona egress + signer world-badging + kill-switch fan-out signal
- **Scope:** bind `noporis-tor-glue` so the clean persona is fail-closed Tor-only
  and the Google persona carries the `GMS_OUT_OF_SCOPE` caveat on its `Allow`
  (surface the `CORRELATION_CEILING`); stand up the two independent `PairingRecord`
  worlds and the world-badged signer prompt (badge derived from the pairing, never
  the request); block prompt/world mismatch. Extend `BridgeKillSwitch.engage()` to
  signal revocation (flip in-memory switch + drive `ConsentLedger` revoke via its
  public API) — it **signals**, the orchestrator (Dev A) persists.
- **Owns:** `apps/noporis-tor-glue/**`, `apps/noporis-signer-glue/**`.
- **Spec refs:** A4 §4 (identity model / non-leak invariants), Phase 4; A5 §2.5
  (revoke surfaces), §3 (kill); A9 §3.2 (egress does not un-correlate device);
  compliance §5.7 (per-persona attestation truth).
- **Proving test + tier:** `cargo test` in both crates (egress policy, world
  badge, two-pairings separation, kill fan-out) — **HOST** (already green;
  extend). Live Tor circuits (`feature = "live"`, pulls `arti`) + real per-persona
  circuit isolation — **VM/device** (not built in the HOST sandbox).
- **Deps:** consumes `postern-tor`, `postern-pairing`, `postern-policy` (frozen);
  `ConsentLedger` revoke API from Dev B (public, cross-crate call — no shared file).
- **Shared-file coordination:** kill-switch fan-out calls Dev B's `ConsentLedger`
  and hands the persist to Dev A's orchestrator — API contract only, no co-edited
  file. Owns both crates end-to-end, so no intra-crate split.

### Dev E — The E2E offline+emulator harness (create→consent→cross→kill→re-verify)
- **Scope:** own the end-to-end loop assertions. Keep/extend the offline
  functional proof so it exercises the full arc with real crypto on HOST as A/B/C/D
  land. Build a **NEW** `apps/noporis-e2e/` harness + `scripts/vm/` scripts that run
  the same five-step loop against (i) the work-profile **emulator** and (ii) the
  **binder-VM Waydroid** boot, recording pass vs UNTESTED per step with the tier
  label. Assert the tamper/replay/fail-closed branches and the wallet invariant.
- **Owns:** `apps/noporis-bridge-glue/tests/functional_proof.rs`; **NEW**
  `apps/noporis-e2e/**`; **NEW** `scripts/vm/**` (e.g. `waydroid-boot-smoke.sh`,
  the emulator provisioning smoke).
- **Spec refs:** A4 §5 (functional proof + UNTESTED gaps); A5 §7 (the canonical
  proof + on-device UNTESTED list); A10 §2 (T0/T1/T2), §3 (R1–R6 CI honesty), §5.2
  (VM runbook).
- **Proving test + tier:** the offline five-step loop with real pairing crypto —
  **HOST** (owns `functional_proof.rs`; already green). The same loop on
  work-profile AVD + binder-VM Waydroid — **VM**. Full aarch64 dual-substrate loop
  + confirming Play-Integrity STRONG fails on the far side — **device** (manual,
  logged, never CI-green-faked).
- **Deps:** the widest — needs B's transport API, A's substrate backends, C's gate
  projection + switcher, D's egress/kill. Its HOST test depends only on the frozen
  public APIs, so it runs from day 1 against stubs and tightens as reals land.
- **Shared-file coordination:** `functional_proof.rs` is a distinct file from B's
  `src/**` (no collision); any new import it needs re-exported → request from
  **Dev B**. Its VM scripts are a NEW top-level dir (no overlap).

---

## 7. Integration + test strategy

- **HOST gate (green today, must stay green):** `cargo test` across
  `noporis-bridge-glue`, `noporis-signer-glue`, `noporis-tor-glue`;
  `node apps/noporis-gate/test-store.mjs`; `node --check` on the switcher/gate
  HTML; `bash scripts/check-trust-labels.sh` (CRITICAL 0). Dev E's
  `functional_proof.rs` is the single end-to-end HOST assertion of the loop.
- **VM gate (`UNTESTED-until-VM` until the runner exists):** Gradle
  `assembleDebug` + `testDebugUnitTest` for `android-bridge/persona` (flips
  "built"); work-profile AVD provisioning (control-flow only, **no** StrongBox);
  binder-VM `waydroid session start` → RUNNING → app list → kill. Jobs are
  `t1:*`, tier-prefixed; a green `t0` never implies a `t1` truth (A10 R1–R3).
- **device gate (`UNTESTED-until-device`, manual runbook):** dual-substrate loop
  on real aarch64; confirm the broker binds across the managed↔primary split with
  no ambient channel; confirm Porog's enforcement side observes the
  `sloboda-bridge.state` flip; confirm Play-Integrity STRONG **fails** on the far
  side (the honest, expected result). Results land in a signed log +
  `untested-inventory.yml`, never a pipeline exit code.

---

## 8. Top Wave-1 risks

1. **Stub→real regression.** A/B replacing stubs/in-memory paths must keep E's
   HOST loop green; gate real backends behind a feature so `cargo test` stays
   offline-clean.
2. **Double-writer on the state files.** Resolved in §5: orchestrator (A) is the
   sole runtime writer; gate-store (C) computes; killswitch (D) signals.
3. **`lib.rs`/`Cargo.toml` contention.** Resolved: single owner (B) applies A/E
   edits; A keeps new code inside `substrate.rs`, E inside `tests/`.
4. **VM is x86_64 but the product is aarch64.** Emulator/binder-VM prove
   control-flow only; GPU, image channels, Play-Integrity verdicts stay
   device-only and labelled UNTESTED (A10 §6).
5. **Honesty-label bleed.** Any "attested/private/measured-boot/Postern OS" on a
   NoporIS surface fails `check-trust-labels.sh` CRITICAL 2/3 — keep the
   less-private / separation-not-privacy / non-attestable / not-Postern-OS rails
   on every new surface.
6. **License drift.** No GMS redistribution, no Play-Integrity circumvention, no
   padlock on the Google side — enforced in code (`tier` pin, `may_show_attestation`).
