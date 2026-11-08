# NoporIS + Porog — Completion & Hardening BACKLOG

Base read: `roadmap/buckets-integrate` @ `0ee1af6` (via a read-only detached worktree — `bp-wt-buckets` untouched).

## Honesty rails for this backlog
- **HOST-TESTABLE** items ship with an exact `cargo`/`node`/`bash` command that proves them green on macOS today.
- **BOX-GATED** items are marked `[BOX]`. The on-device Kotlin/Compose (persona + profile apps) **cannot compile on macOS** (no Android SDK/NDK). For those we do the *host-shaped* work (source coherence, pure-logic extraction, wiring) and **label** it — never a false green. The proving command (`./gradlew …`) runs only on the VM/box.
- `scripts/check-trust-labels.sh` must stay **critical:0** after every edit. Baseline confirmed: `critical: 0  warn: 1` (a pre-existing StrongBox/Secure-Enclave WARN on `apps/postern-login`, not in our scope).

## Verified green baseline (the floor we protect)
| Battery | Command (from repo root) | Count |
|---|---|---|
| NoporIS bridge-glue | `cd apps/noporis-bridge-glue && cargo test` | 124 |
| NoporIS signer-glue | `cd apps/noporis-signer-glue && cargo test` | 23 |
| NoporIS tor-glue (egress) | `cd apps/noporis-tor-glue && cargo test` | 7 |
| Porog tor-glue (egress, default) | `cd apps/porog-tor-glue && cargo test` | 5 |
| Porog tor-glue (egress, live-feature) | `cd apps/porog-tor-glue && cargo test --features live --offline` | 9 |
| NoporIS gate-store | `node apps/noporis-gate/test-store.mjs` | 56 |
| Porog reconcile-kernel | `node apps/porog-crossprofile/test-reconcile.mjs` | 321 |
| Persona Play-flavor policy | `node android-bridge/persona/play/policy/test-play-flavor-policy.mjs` | 11 |
| StrongBox **verifier-side** (host) | `cargo test -p postern-seal-companion --features mobile-attest` | 64 |
| Trust-label tripwire | `bash scripts/check-trust-labels.sh` | critical:0 |

> Note: the four `apps/*-glue` crates and `apps/noporis-bridge-glue` are **standalone workspaces** (excluded from the root `[workspace]` members) — you must `cd` into each; `cargo test -p <name>` from the root fails with "did not match any packages". `postern-seal-companion` **is** a root member, so `-p` works for it.

---

## Ranked items

Priority = P1 (blocks a real fail-closed/coherence gap) → P3 (nice-to-have coverage). Each item names the concrete change, the file(s), and the HOST command that proves it green (or `[BOX]` + the box-day command).

### Resolved in this tree (`fleet/porog-poster-3`) — dropped from the ranked list
These two former P1 Porog coherence gaps are **fixed in this worktree** and are now locked as host battery guards (TEST-GATE #11, #12). Kept here only as an honest change-log; they no longer block.
- **Container app junit wiring (was: cannot compile host unit tests).** `android-container/profile/app/build.gradle.kts` now has `testImplementation(libs.junit)`. **Proof (host):** `grep -c 'testImplementation(libs.junit)' android-container/profile/app/build.gradle.kts` → **1**. Box-day `./gradlew :app:testDebugUnitTest` remains the on-box green.
- **Duplicate `CrossProfileReconciler` class (was: two same-named ports).** Resolved the opposite way the original note guessed: rather than a `dpc/`→`GateStateReconciler` rename, the second port (`crossprofile/CrossProfileReconciler`) was retired and `dpc/CrossProfileReconciler.kt` is the single 427-line canonical port, its `decide()` pinned to the ONE kernel by committed `apps/porog-crossprofile/golden-vectors.json` + a `[BOX]` JVM parity test (`CrossProfileReconcilerParityTest`). No `GateStateReconciler` exists. **Proof (host):** `grep -rl '^class CrossProfileReconciler(' android-container/profile/app/src | wc -l` → **1**; `node apps/porog-crossprofile/export-vectors.mjs && git diff --exit-code apps/porog-crossprofile/golden-vectors.json` → clean. Box-day `./gradlew :app:assembleDebug` remains the on-box compile green.

### P1 — the schema-check is not wired to a real reader (NoporIS)
**Gap (confirmed):** `verify_sloboda_bridge_schema` / `parse_sloboda_bridge_schema_version` (`substrate.rs:442–465`) are defined and unit-tested, but **no runtime path ever reads `sloboda-bridge.state` back and verifies it.** The daemon reads `state.json` via `read_gate_state` (`daemon.rs:296`), then *writes* the projection in `Orchestrator::commit` (`substrate.rs:864`) — nothing reads the existing projection to detect a foreign/older writer before overwriting/trusting it.
**Change:** add a free fn `read_sloboda_bridge_state(paths) -> Result<String, SubstrateError>` mirroring `read_gate_state`, that reads the projection and runs `verify_sloboda_bridge_schema` **fail-closed**; call it as a `Daemon` start-up preflight (or first-tick self-check) — *missing* file = fine (first boot), *present-but-unknown-schema* = hard, loud refusal to start (surface it in the bin's exit, like the WriterLock refusal). Fold the outcome into `DaemonReport`.
**Files:** `apps/noporis-bridge-glue/src/substrate.rs`, `apps/noporis-bridge-glue/src/daemon.rs`, `apps/noporis-bridge-glue/src/bin/noporis-orchestrator.rs`, test in `apps/noporis-bridge-glue/tests/persistence_recovery.rs`.
**Proof:** `cd apps/noporis-bridge-glue && cargo test`

### P1 — broker bearer-ceiling ↔ payload-max invariant is prose-only (NoporIS)
**Gap (confirmed):** `CrossingBearerPolicy.MAX_SEALED_FRAME_BYTES = 64 KiB` "must never be below" Rust `MAX_CROSSING_BYTES` (16 KiB) — asserted only in a doc comment (`CrossingBearerPolicy.kt:33–41`). A future change to either side can silently break the fail-closed size ordering.
**Change:** pin `MAX_CROSSING_BYTES` with an explicit Rust test in `crossing.rs` (so a change trips CI), and add a JVM assertion in `CrossingBearerPolicyTest.kt` that `MAX_SEALED_FRAME_BYTES ≥` the documented payload ceiling.
**Files:** `apps/noporis-bridge-glue/src/crossing.rs`, `android-bridge/persona/app/src/test/java/labs/postern/persona/CrossingBearerPolicyTest.kt`.
**Proof (Rust half, runnable now):** `cd apps/noporis-bridge-glue && cargo test`. **Box-day (Kotlin half):** `./gradlew :app:testDebugUnitTest`.

### P1 — StrongBox verifier negative-path completeness (Porog, host)
**Gap:** `verify_key_attestation_detailed` (`crates/postern-seal-companion/src/mobile.rs`) fans out to named `Verdict::Mismatch` guards — nonce, security-level floor, `verifiedBootState`, `deviceLocked`, os-patch-level floor, app-identity (package + signing cert), chain-signature, cert validity, empty-chain, plus `Verdict::Unverified` on no pinned roots. This is the **host-testable** half of attestation (the device `attest()`/`generateKey` in `StrongBoxAttestationGateway.kt` is hardware-gated). `mobile.rs` has 29 tests; ensure **every** Mismatch branch has an explicit fail-closed negative.
**Change:** audit branch-vs-test coverage; add a negative test per uncovered `Verdict::Mismatch`/`Unverified` arm.
**Files:** `crates/postern-seal-companion/src/mobile.rs` (tests mod).
**Proof:** `cargo test -p postern-seal-companion --features mobile-attest`

### P2 — daemon error/recovery accounting is a single bucket (NoporIS)
**Gap:** `LaneReport.errors` collapses tamper / replay / wrong-session / malformed / oversize / audit-IO into one count (`daemon.rs:269–273`) — the finer reason survives only in each lane's `AuditTrail`. Weakens error-path observability the orchestrator brief calls for.
**Change:** split into named counters (e.g. `replay`, `tamper`, `wrong_session`, `audit_io`) derived from the `BridgeError` variant already matched, or attach the last-N rejection reasons to the report. Still fail-closed (every one remains a rejection, never a delivery).
**Files:** `apps/noporis-bridge-glue/src/daemon.rs`, tests in `apps/noporis-bridge-glue/tests/daemon_loop.rs`.
**Proof:** `cd apps/noporis-bridge-glue && cargo test`

### P2 — all-crossing-directions daemon coverage (NoporIS)
**Gap:** daemon tests exercise `GooglePlay→Clean` only. The lane doc promises a *direction-mismatched* lane denies fail-closed (`daemon.rs:186–191`), and both directions must be drivable.
**Change:** add tests for `Clean→GooglePlay`, a two-lane (bidirectional) daemon, and an explicit mismatched-direction lane asserting deny-by-pinning.
**Files:** `apps/noporis-bridge-glue/tests/daemon_loop.rs`.
**Proof:** `cd apps/noporis-bridge-glue && cargo test`

### P2 — WriterLock crash-recovery E2E at daemon level (NoporIS)
**Gap:** `WriterLock::steal` + `--steal-lock` are CLI-tested (`tests/writer_lock_cli.rs`), but there's no end-to-end "crash left a stale lock → second daemon refuses fail-closed → `--steal-lock` recovers and resumes with no torn writes."
**Change:** add that recovery scenario.
**Files:** `apps/noporis-bridge-glue/tests/writer_lock_cli.rs` (or new `tests/recovery_e2e.rs`).
**Proof:** `cd apps/noporis-bridge-glue && cargo test`

### P2 — Porog kernel `crossingOpen` ↔ `reconcile` differential parity (Porog, host)
**Gap:** the kernel promises `crossingOpen` and `reconcile` "can never diverge" (`reconcile-kernel.mjs:409–429`) but there's no exhaustive differential test.
**Change:** table-driven test over every cap × {consent on/off, standing on/off, kill on/off, valid/invalid package, each of `none/p2w/w2p/both`} asserting `crossingOpen(state,cap)` agrees with what `reconcile(state)` exposes for `cap`.
**Files:** `apps/porog-crossprofile/test-reconcile.mjs`.
**Proof:** `node apps/porog-crossprofile/test-reconcile.mjs`

### P2 — Porog kernel normalize/serialize robustness (Porog, host)
**Gap:** no idempotence / round-trip fuzz over hostile blobs.
**Change:** add `normalize(normalize(x))` deep-equals `normalize(x)`, and `parse(serialize(s))` stability, over a corpus of partial/wrong-type/junk-package/stale-direction-with-`open:false` inputs.
**Files:** `apps/porog-crossprofile/test-reconcile.mjs`.
**Proof:** `node apps/porog-crossprofile/test-reconcile.mjs`

### P2 — StrongBox tier "never upgrade" pure invariant + wire-contract fixture (Porog)
**Gap:** the fallback rule "report TEE, never re-label as STRONGBOX" lives inside the device-gated `attest()` (`StrongBoxAttestationGateway.kt:70–88`); the *labeling decision* is pure but untested, and there is no shared golden-DER fixture proving the Kotlin `AttestationEvidence` (leaf-first DER + nonce) feeds `verify_key_attestation` correctly.
**Change:** (a) extract a pure `AttestationTier`/evidence-labeling helper and JVM-test it `[BOX to run]`; (b) add a golden leaf-first-DER + nonce fixture consumed by a `mobile.rs` host test to lock the A↔C wire contract.
**Files:** `android-container/profile/app/src/main/java/labs/postern/container/attest/{AttestationTier,AttestationGateway}.kt`, `crates/postern-seal-companion/src/mobile.rs`.
**Proof (Rust half):** `cargo test -p postern-seal-companion --features mobile-attest`. **Box-day (Kotlin half):** `./gradlew :app:testDebugUnitTest`.

### P2 — privacy / metadata-minimization of the crossing (both)
**Gap:** what leaves the attested profile is asserted in prose (broker is a "dumb bearer", audit is "by digest never bytes") but not enumerated in one place, and the Kotlin `CrossProfileAuditLog` side isn't host-asserted.
**Change:** write `docs/noporis-porog/PRIVACY-CROSSING.md` enumerating the exact leave-set (opaque sealed frame; audit fields = capability, direction, digest+len, ts — never payload/PII). Extend the Rust "audited by digest, never bytes" invariant (`lib.rs` test `delivered_crossing_is_audited_by_digest_never_bytes`) to cover any newly-added audit surface; mirror the assertion into a `CrossProfileAuditLog` host test `[BOX]`.
**Files:** `apps/noporis-bridge-glue/src/audit.rs`, `android-container/profile/app/src/main/java/labs/postern/container/dpc/CrossProfileAuditLog.kt`, new `docs/noporis-porog/PRIVACY-CROSSING.md`.
**Proof (Rust half):** `cd apps/noporis-bridge-glue && cargo test`; then `bash scripts/check-trust-labels.sh` (new doc must keep critical:0).

### P3 — per-crossing consent 5-step negative completeness (NoporIS)
**Change:** ensure each of the signed-consent 5 steps (signature, freshness/expiry, direction pin, session pin, capability pin) in `consent_record.rs` (11 tests) has an explicit fail-closed negative; add any missing.
**Files:** `apps/noporis-bridge-glue/src/consent_record.rs`, `apps/noporis-bridge-glue/src/bridge.rs`.
**Proof:** `cd apps/noporis-bridge-glue && cargo test`

### P3 — audit hash-chain tamper test (NoporIS)
**Change:** confirm/add a test that mutates a middle `AuditTrail` entry and asserts `verify()` fails.
**Files:** `apps/noporis-bridge-glue/src/audit.rs`.
**Proof:** `cd apps/noporis-bridge-glue && cargo test`

### P3 — gate-store direction/standing edge cases (NoporIS)
**Change:** expand `test-store.mjs` for `far-to-near` vs `near-to-far` direction, kill-switch clears direction, schema/version mismatch → full-deny, sealed-wallet pin non-unsettable — add any missing.
**Files:** `apps/noporis-gate/gate-store.mjs`, `apps/noporis-gate/test-store.mjs`.
**Proof:** `node apps/noporis-gate/test-store.mjs`

### P3 — `shutdown` drops `now_iso` (NoporIS)
**Change:** `Daemon::shutdown` ignores `_now_iso` (`daemon.rs:427`); either thread it into a durable shutdown audit marker, or document why the final commit needs no audit entry.
**Files:** `apps/noporis-bridge-glue/src/daemon.rs`.
**Proof:** `cd apps/noporis-bridge-glue && cargo test`

### P3 — Lockdown baseline / container lifecycle pure descriptors (Porog) `[BOX to run]`
**Change:** extract `LockdownPolicy`'s intended posture (screen-capture off, IME allowlist = system-only, cross-profile copy/paste disallowed, unknown-sources blocked, require work challenge) into a pure `LockdownBaseline` descriptor host-assertable without a live DPM; likewise extract `ContainerProfileManager`'s state machine (absent→provisioning→active→panic-locked) into pure transitions with a host test that panic-lock requires a satisfied separate work challenge.
**Files:** `android-container/profile/app/src/main/java/labs/postern/container/dpc/LockdownPolicy.kt`, `.../lifecycle/{ContainerProfileManager,ContainerState}.kt`, new `src/test` guards.
**Box-day:** `./gradlew :app:testDebugUnitTest`.

### P3 — source-coherence sweep for `gradlew assemble` (both) `[BOX compile]`
**Change:** grep-level static pass so box-day compile is clean: every `libs.*` alias both build files reference exists in `gradle/libs.versions.toml`; manifest-declared components exist as classes; `strings.xml` keys referenced in Compose exist; no unresolved imports.
**Files:** both app trees, `gradle/libs.versions.toml`, both `AndroidManifest.xml`.
**Box-day:** `./gradlew assembleDebug` for each app.
