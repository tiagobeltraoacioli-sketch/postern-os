<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Bucket F — PARTITION (5 devs, file-ownership-disjoint, all HOST-tested)

**Base:** `roadmap/fleet2-integrate` (read via `git show roadmap/fleet2-integrate:<path>`
from `/Users/tiagoacioli/dev/bloch-protocol`; NOT checked out/modified by the PMO).
`bp-wt-fleet2` and every other worktree were read-only inputs, never touched.

**Corrections to the original brief, made from reading the actual fleet2 tree**
(stated up front because they change the partition):

1. **Courier hardening is ALREADY DONE**, not a gap. `crates/postern-courier` has
   had sender-auth (hybrid Falcon-1024 ‖ ML-DSA-65 over a signed transcript) +
   anti-replay (`ReplayGuard`: freshness window + nonce cache) **ON BY DEFAULT**
   (`default = ["sender-auth"]`) since commit `c25813c` — well before fleet2 —
   with 8 dedicated tests (forged signature, replayed drop, stale window, wire
   round-trip, wrong-recipient binding, etc. — see
   `crates/postern-courier/src/lib.rs` lines 1190–1356). `docs/gap2/apps-sdk-bridge-remaining.md`
   §0 independently confirms this is closed. **Bucket F4 is reassigned** to a
   different, genuinely-open, HOST-testable crypto-hardening item (Intel TCB-info
   collateral verification) so the dev-day isn't wasted re-doing finished work.
2. **The NoporIS "orchestrator" building blocks already exist** — `Substrate`
   trait, `Orchestrator<S>` reconcile loop, `ManagedProfileSubstrate` /
   `WaydroidSubstrate`, `HostStubDpc`/`HostStubSloboda`, the signed
   per-direction `ConsentRecord`/`ConsentLedger`, and `CrossingReceiver::receive_crossing_audited`
   are all real, host-tested Rust in `apps/noporis-bridge-glue/src/{substrate,consent_record,bridge}.rs`.
   What's genuinely missing — confirmed by `Cargo.toml` having **no `[[bin]]`
   target** — is the thing the brief actually asked for: **a daemon/state-machine
   that composes these library pieces into one running process.** F1/F2 build
   exactly that; they do not re-invent the consent kernel.
3. **SDK Argon2id/XChaCha20 wasm core is real** (`crates/postern-sdk/src/wasm.rs`,
   "kills stand-in S2"). The gap is **wiring**: 6 of 9 front-ends already probe
   `globalThis.PosternSDK` (postern-login, postern-onboard, postern-store, sotto,
   tolmach, vedetta) but **postern-enterprise, tolmach-subscription/client, and
   desktop/src/modules/vault.js do not** — verified by grep, zero
   `PosternSDK`/`KDF_REAL` hits in those three. F3 closes exactly this gap, and
   fills a real test-coverage hole: only 2 of the 6 already-wired apps
   (postern-login, postern-onboard) have a `test-core.mjs` proving the seam
   dispatch; postern-store/sotto/tolmach/vedetta have the wiring but no test.

---

## Dev F1 — NoporIS orchestrator: the daemon/state-machine core

**Files owned (new, disjoint from F2):**
- `apps/noporis-bridge-glue/src/daemon.rs` (NEW)
- `apps/noporis-bridge-glue/src/bin/noporis-orchestrator.rs` (NEW — the `[[bin]]` target)
- `apps/noporis-bridge-glue/tests/daemon_loop.rs` (NEW)
- `apps/noporis-bridge-glue/src/lib.rs` — **one line only**: `pub mod daemon;` +
  re-export `Daemon`/`DaemonConfig`/`DaemonReport` (additive; do not touch any
  other export)
- `apps/noporis-bridge-glue/Cargo.toml` — **one block only**: add the `[[bin]]`
  stanza (`name = "noporis-orchestrator"`, `path = "src/bin/noporis-orchestrator.rs"`).
  No new dependencies needed — everything the daemon needs (`Orchestrator`,
  `CrossingReceiver`, `ConsentLedger`, `GateState`, `write_atomic`) is already a
  crate export.

**Concrete change:** implement `Daemon<S: Substrate, G: GateConsent>`, composing
the already-tested `Orchestrator<S>` (persona-lifecycle reconcile) and
`CrossingReceiver<G>` + `ConsentLedger` (the signed, per-`Direction` crossing
decision) into ONE tick-driven state machine:

```
Daemon::tick(&mut self, now: i64) -> DaemonReport
  1. read GateState (StatePaths) → Orchestrator::reconcile()  (persona create/switch/kill)
  2. drain pending CrossingRequests → receive_crossing_audited() per Direction
  3. kill-switch engaged → halt all crossings + Orchestrator kill path, fail closed
  4. persist via write_atomic(); return a DaemonReport for the caller/test to assert on
```

Ship a `[[bin]] noporis-orchestrator` CLI over `HostStubDpc`/`HostStubSloboda`
(default `host-stub` feature — stays offline) with `--once` (single tick, for
scripted tests) and `--watch <ms>` (bounded-iteration loop, injectable clock) —
this is what a real device's `init`/systemd unit would exec; on host it never
touches Android/Waydroid.

**HOST test command (must be green):**
```
cd apps/noporis-bridge-glue && cargo test daemon
cd apps/noporis-bridge-glue && cargo test --test daemon_loop
```

---

## Dev F2 — NoporIS orchestrator: state/persistence hardening + full-loop E2E tests

**Files owned (disjoint from F1 — no overlap with `daemon.rs`/`bin`/`Cargo.toml`):**
- `apps/noporis-bridge-glue/src/substrate.rs` (EDIT — persistence hardening only)
- `apps/noporis-bridge-glue/tests/orchestrator_e2e_hoststub.rs` (NEW)
- `apps/noporis-bridge-glue/tests/persistence_recovery.rs` (NEW)

**Concrete change:**
1. Version the on-disk state schema: add `schema_version: u32` to the
   `GateState`/`sloboda-bridge.state` projection; reads of an unknown version
   fail closed (never silently misparse) instead of the current implicit trust.
2. Fault-injection persistence tests: truncate/corrupt a state file mid-write,
   assert `write_atomic`'s rename-based durability holds under `SIGKILL`-style
   interruption simulation (never a torn write observed on reload).
3. **The full "5-step" loop the design docs promise, run entirely on HOST
   stubs** (no device): create persona → mint a `Direction`-pinned
   `ConsentRecord` → one capability crosses via `receive_crossing_audited` →
   kill-switch engages → re-verify nothing crosses AND the sealed-wallet
   invariant (`sealedWallet.preserved == true`) still holds. This is exactly
   what B10 (`docs/gap2/apps-sdk-bridge-remaining.md`) says is only "real" on
   hardware for the *device* behavior — F2 proves the *control-flow* half of it
   on host, which is legitimately F-scope and was previously untested as one
   composed loop (only proven piecewise).

**HOST test command (must be green):**
```
cd apps/noporis-bridge-glue && cargo test --test orchestrator_e2e_hoststub
cd apps/noporis-bridge-glue && cargo test --test persistence_recovery
```

---

## Dev F3 — SDK Argon2id/XChaCha20 real-core wiring + parity tests (all apps)

**Files owned:**

Wiring (the 3 confirmed-unwired surfaces):
- `apps/postern-enterprise/index.html` (EDIT — add the `sdk()`/`KDF_REAL`
  seam-dispatch block, following the exact pattern already proven in
  `apps/postern-store/index.html` lines 1013–1043 and `apps/sotto/index.html`
  lines 787–817: probe `globalThis.PosternSDK`, tag real seals
  `"Argon2id-postern-sdk"`, never silently accept a downgrade on read-back)
- `apps/tolmach-subscription/client/index.html` (EDIT — same seam pattern)
- `desktop/src/modules/vault.js` (EDIT — replace the `"backend pending"` stub;
  `desktop/src-tauri` has **no** vault Rust commands today, confirmed by an
  empty grep, so wire the wasm seam directly in the Tauri webview, which has no
  CSP restriction — simpler than the strict-CSP browser apps)

New HOST parity tests (closes the real coverage gap: 4 apps already ship the
wiring with zero test proving it dispatches correctly):
- `apps/postern-enterprise/test-core.mjs` (NEW)
- `apps/tolmach-subscription/client/test-core.mjs` (NEW)
- `apps/postern-store/test-core.mjs` (NEW)
- `apps/sotto/test-core.mjs` (NEW)
- `apps/tolmach/test-core.mjs` (NEW)
- `apps/vedetta/test-core.mjs` (NEW)
- `desktop/src/modules/vault.test.mjs` (NEW)

All new test files follow the exact template already proven in
`apps/postern-login/test-core.mjs` / `apps/postern-onboard/test-core.mjs`:
extract the DOM-free `<script>` block(s) from `index.html` via regex + `eval`,
then assert (a) the honest PBKDF2-labeled stand-in path when `globalThis.PosternSDK`
is absent, (b) the real Argon2id/XChaCha20 path when a stub `PosternSDK` is
installed on `globalThis` before the script runs, (c) a real-core blob never
silently opens/downgrades under the stand-in path (fail closed).

**HOST test command (must be green):**
```
node apps/postern-login/test-core.mjs
node apps/postern-onboard/test-core.mjs
node apps/postern-store/test-core.mjs
node apps/sotto/test-core.mjs
node apps/tolmach/test-core.mjs
node apps/vedetta/test-core.mjs
node apps/postern-enterprise/test-core.mjs
node apps/tolmach-subscription/client/test-core.mjs
node desktop/src/modules/vault.test.mjs
```
(All plain ESM, Node ≥ 18, zero npm dependencies — matches the repo's existing
test-file convention.)

---

## Dev F4 — Intel TCB-info / QE-identity collateral signature verification
### (reassigned from "courier hardening," which is already shipped — see corrections above)

**Files owned:**
- `crates/postern-seal-companion/src/tdx.rs` (EDIT)
- `crates/postern-seal-companion/src/tdx_tcb.rs` (NEW — the collateral parser +
  signature-chain verifier module)
- `crates/postern-seal-companion/tests/tdx_collateral.rs` (EDIT — add offline
  vectors)

**Status quote (verified in-tree, `tdx.rs` line 59–60):** *"Intel TCB-info /
QE-identity JSON collateral **signature** verification (the Intel TCB signing
cert) is not folded in yet; freshness is enforced via the CRL `nextUpdate`."*
The DCAP v4 chain, QE-report binding, and PCK CRL are done and vector-tested
(26 lib + 12 vector tests per `docs/gap2/cloud-seal-remaining.md` D1); this is
the one piece of that path that is genuinely unstarted, pure software, and has
**no external gate** (`docs/gap2/cloud-seal-remaining.md` explicitly: *"pure
software, can start now"*).

**Concrete change:** parse the Intel TCB-info + QE-identity JSON collateral,
verify each document's signature under the Intel TCB signing certificate
(chaining to the already-pinned `PINNED_INTEL_SGX_ROOT_CA_DER` root), enforce
`tcbStatus`/`advisoryIDs` and QE `isvsvn` against the presented quote, and
reject on any signature/chain failure — the same fail-closed discipline the
PCK-CRL path already has. Add offline vectors alongside the existing
`tests/tdx_collateral.rs` (a genuine TCB-info JSON fixture + a
tampered-signature negative control).

**HOST test command (must be green):**
```
cargo test -p postern-seal-companion --features tdx-verify
```

---

## Dev F5 — App-polish eng-time items (wasm artifact, Gramota OCR seam, comms deploy authoring)

**Files owned:**
- `crates/postern-sdk/wasm/build-wasm.sh` — run it (installs/uses
  `wasm-bindgen-cli` pinned to the `Cargo.lock` version) to actually emit
  `postern_sdk.js` + `postern_sdk_bg.wasm` (currently gitignored / never
  produced in-tree — `docs/gap2/apps-sdk-bridge-remaining.md` item A2, the
  prerequisite artifact F3's `globalThis.PosternSDK` seam needs to have
  anything real to install). Output stays gitignored by design (build
  artifact); the HOST test is that the build script's own compile gate passes.
- `apps/gramota-kyc/ocr-engine.js` (NEW) + `apps/gramota-kyc/ocr-engine.test.mjs`
  (EDIT — extend, don't replace; the file already exists with honesty-invariant
  tests for the seam contract) — wire a **real** on-device OCR recognizer
  behind the existing `grm-ocr` adapter seam (`apps/gramota-kyc/index.html`,
  `<script id="grm-ocr">`). Verified in-tree: today the seam's only backend is
  honest MANUAL entry (`text:null`); "OCR is the goal; MANUAL is today" per the
  seam's own test-file header. `docs/gap2/enterprise-gaps` (ent-D1) independently
  confirms no recognizer exists anywhere under `apps/gramota-kyc/`.
- `enterprise/comms/app/deploy/Dockerfile` (NEW)
- `enterprise/comms/app/deploy/fly.toml` (NEW)
- `enterprise/comms/app/deploy/README.md` (NEW)

Follow the **exact precedent** already in the repo for the deploy trio:
`enterprise/cloud/services/console/http/deploy/{Dockerfile,fly.toml,README.md}`.
`enterprise/comms/app/` has zero deploy wiring today (confirmed: no
Dockerfile/fly.toml anywhere under `enterprise/comms/`), per
`docs/gap2/enterprise-gaps` ent-D2 (app half — the legal half is Bucket E, out
of scope for F).

**HOST test command (must be green):**
```
bash crates/postern-sdk/wasm/build-wasm.sh   # compile gate + (if wasm-bindgen-cli present) glue emission
node apps/gramota-kyc/ocr-engine.test.mjs
node apps/gramota-kyc/test-core.mjs           # existing suite must stay green (regression)
node apps/gramota-kyc/review-seam.test.mjs    # existing suite must stay green (regression)
docker build -f enterprise/comms/app/deploy/Dockerfile -t postern-comms-app:host-check .
```
(The `docker build` is a **local build-only** proof — no `fly deploy`, no
secrets, no live endpoint; that stays Bucket C.)
