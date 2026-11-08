# NoporIS + Porog — 5-Dev PARTITION (file-ownership-disjoint)

Each bucket owns a **disjoint** file set so five devs can run in parallel with no merge collisions. Every bucket lists its exact files and the HOST command that proves its work green (or the box-day command for `[BOX]` items). Standalone crates need `cd <dir> && cargo test` (they are excluded from the root workspace); `postern-seal-companion` is a root member so `-p` works.

Global rail for all five: after any edit, `bash scripts/check-trust-labels.sh` must stay **critical:0**. No deploy, no git commit, no touching `bp-wt-buckets` / `bp-wt-site`.

Cross-cutting compile rail (not owned by any single bucket): `apps/noporis-tor-glue`'s
`cfg(feature = "live")` surface (`PersonaTor` / `PersonaWorlds`) is only compiled by the
offline **live-feature compile gate** — TEST-GATE.md #3b: `cd apps/noporis-tor-glue &&
cargo check --features live --offline` (or `bash scripts/check-noporis-tor-glue-live.sh`),
green offline against vendored arti/postern-tor. Plain `cargo test` (#3) does **not**
type-check it. Any dev whose change reaches the pure per-persona policy layer that the
live module calls into (`persona_egress_decision`, `persona_egress_note`, the `Decision`
API) must keep #3b green so the feature-gated live path cannot silently rot. It is a
**compile** gate only — the runtime bootstrap stays the network-gated `#[ignore]` smoke
test (`cargo test --features live -- --ignored`). Compile-checked != booted != anonymous.

---

## D1 — NoporIS orchestrator / daemon completeness
**Owns**
- `apps/noporis-bridge-glue/src/daemon.rs`
- `apps/noporis-bridge-glue/src/bin/noporis-orchestrator.rs`
- `apps/noporis-bridge-glue/src/substrate.rs` — **Orchestrator + schema-check region only** (`reconcile`/`commit`/`read_gate_state`/`verify_sloboda_bridge_schema` and the new `read_sloboda_bridge_state`)
- `apps/noporis-bridge-glue/tests/daemon_loop.rs`
- `apps/noporis-bridge-glue/tests/persistence_recovery.rs`
- `apps/noporis-bridge-glue/tests/orchestrator_e2e_hoststub.rs`
- `apps/noporis-bridge-glue/tests/writer_lock_cli.rs`

**Backlog:** P1 schema-check-wired-to-a-real-reader; P2 error/recovery accounting; P2 all-crossing-directions; P2 WriterLock crash-recovery E2E; P3 `shutdown` `now_iso`.
**HOST test command:** `cd apps/noporis-bridge-glue && cargo test`  *(protect ≥124)*

> Disjointness note: D1 and D2 both live in `noporis-bridge-glue` but on **disjoint files**. D1 owns `daemon.rs`, `bin/`, the Orchestrator/schema half of `substrate.rs`, and the daemon/persistence/e2e/writer-lock tests. D2 owns `bridge.rs`, `consent_record.rs`, `crossing.rs`, `audit.rs` and their in-file tests. `substrate.rs` is split by region — if that feels risky, D1 takes all of `substrate.rs` and D2 stays out of it (D2's items don't require substrate edits).

---

## D2 — NoporIS gate + bridge-glue + broker hardening
**Owns**
- `apps/noporis-gate/gate-store.mjs`, `apps/noporis-gate/test-store.mjs`
- `apps/noporis-bridge-glue/src/bridge.rs`
- `apps/noporis-bridge-glue/src/consent_record.rs`
- `apps/noporis-bridge-glue/src/crossing.rs`
- `apps/noporis-bridge-glue/src/audit.rs`
- `android-bridge/persona/app/src/main/java/labs/postern/persona/bridge/{CrossProfileBrokerService,CrossingBearerPolicy,DeliveryReceipt}.kt`
- `android-bridge/persona/app/src/test/java/labs/postern/persona/CrossingBearerPolicyTest.kt`

**Backlog:** P1 bearer-ceiling↔payload-max invariant (`crossing.rs` pin + `CrossingBearerPolicyTest`); P1 (Kotlin half `[BOX]`); P3 consent 5-step negatives; P3 audit tamper test; P3 gate-store direction/standing edges; P2 privacy audit's Rust-side digest-only assertion (shared with D5 doc).
**HOST test commands:**
- `cd apps/noporis-bridge-glue && cargo test`  *(protect ≥124)*
- `node apps/noporis-gate/test-store.mjs`  *(protect ≥56)*
- `[BOX]` Kotlin broker screen tests: `./gradlew :app:testDebugUnitTest` (persona app) — host-shaped now, box-run.

---

## D3 — Porog reconcile-kernel + consent logic
**Owns**
- `apps/porog-crossprofile/reconcile-kernel.mjs` *(the ONE authoritative decision)*
- `apps/porog-crossprofile/test-reconcile.mjs`
- `apps/porog-crossprofile/export-vectors.mjs` + committed `apps/porog-crossprofile/golden-vectors.json` *(the anti-drift pin between kernel and Kotlin port)*
- `android-container/profile/app/src/main/java/labs/postern/container/dpc/CrossProfileReconciler.kt` *(the single canonical 427-line Kotlin port; `decide()` mirrors the kernel, its `Decision`/`IntentDirective`/`ContactsPolicy` are inlined — there is no separate `CrossProfileDirectives.kt`)*
- `android-container/profile/app/src/test/java/labs/postern/container/dpc/CrossProfileReconcilerParityTest.kt` *(the `[BOX]` JVM parity test that replays the golden vectors)*

**Backlog:** *(D5 dedupe done — one canonical `dpc/` port, no `crossprofile/` duplicate.)* Remaining: P2/P3 additional Kotlin parity host cases `[BOX]`. (The `crossingOpen`↔`reconcile` differential and normalize idempotence / serialize→parse round-trip cases have **landed** — they raised the kernel floor 102→321.)
**HOST test command:** `node apps/porog-crossprofile/test-reconcile.mjs`  *(protect ≥321)*
**`[BOX]` Kotlin half:** `./gradlew :app:testDebugUnitTest` (profile app) — `testImplementation(libs.junit)` is now wired, so this compiles on the box (still device/SDK-gated, never a host green).

---

## D4 — Porog DPC-lifecycle + StrongBox verifier-side prep
**Owns**
- `crates/postern-seal-companion/src/mobile.rs` — **the host-testable attestation verifier** (`verify_key_attestation[_detailed]`, `MobileExpected`, `evaluate`)
- `android-container/profile/app/src/main/java/labs/postern/container/attest/{StrongBoxAttestationGateway,AttestationGateway,AttestationTier}.kt`
- `android-container/profile/app/src/main/java/labs/postern/container/dpc/{WorkChallengePolicy,LockdownPolicy}.kt`
- `android-container/profile/app/src/main/java/labs/postern/container/lifecycle/{ContainerProfileManager,ContainerState}.kt`
- `android-container/profile/app/src/test/java/labs/postern/container/dpc/WorkChallengePolicyGuardTest.kt`

**Backlog:** P1 verifier negative-path completeness (every `Verdict::Mismatch`/`Unverified` branch); P2 tier "never upgrade" pure invariant + golden-DER wire-contract fixture; P3 Lockdown baseline + container lifecycle pure descriptors `[BOX]`.
**HOST test command:** `cargo test -p postern-seal-companion --features mobile-attest`  *(protect ≥64)*
**`[BOX]` Kotlin half:** `./gradlew :app:testDebugUnitTest` (profile app) — `testImplementation(libs.junit)` is wired, so this compiles on the box (device/SDK-gated, never a host green).

> The device `attest()` / `KeyGenParameterSpec` / Keystore calls in `StrongBoxAttestationGateway.kt` are **hardware-gated** (StrongBox `SecurityLevel=2` provable only on Pixel 3+/some Samsung). D4 does the verifier-side logic (host) + the pure tier-labeling helper; the device call stays `UNTESTED-until-VM/device` and is labeled, never green-washed.

---

## D5 — Both apps' Android build-readiness + privacy/metadata + coverage
**Owns**
- `android-container/profile/app/build.gradle.kts`  *(`testImplementation(libs.junit)` — now wired)*
- `android-bridge/persona/app/build.gradle.kts`
- `android-container/profile/app/src/main/java/labs/postern/container/dpc/CrossProfileReconciler.kt` *(now the single canonical port; the second `crossprofile/` port was retired)*
- `android-container/profile/app/src/main/java/labs/postern/container/dpc/BridgeStateReceiver.kt` *(call-site — dedupe complete)*
- `android-bridge/persona/gradle/libs.versions.toml`, `android-container/profile/**/libs.versions.toml`
- both `settings.gradle.kts`, both `AndroidManifest.xml`
- `android-container/profile/app/src/main/java/labs/postern/container/dpc/CrossProfileAuditLog.kt`
- new: `docs/noporis-porog/PRIVACY-CROSSING.md`

**Backlog:** *(P1 container `testImplementation(libs.junit)` fix — DONE; P1 duplicate-`CrossProfileReconciler` dedupe — DONE; P2 privacy/metadata-minimization doc — landed as `PRIVACY-CROSSING.md`.)* Remaining: P3 source-coherence sweep for `gradlew assemble`.
**HOST verifies (runnable now, static/coherence):**
- `grep -c 'testImplementation(libs.junit)' android-container/profile/app/build.gradle.kts` → **1** (wired)
- `grep -rl '^class CrossProfileReconciler(' android-container/profile/app/src | wc -l` → **1** (single canonical `dpc/` port)
- `bash scripts/check-trust-labels.sh` → critical:0 (holds with the privacy doc landed)
**`[BOX]` box-day green:** `./gradlew :app:testDebugUnitTest` and `./gradlew :app:assembleDebug` for **both** persona and profile apps.

> D5's junit wiring (done) unblocks D3/D4's Kotlin host tests, and D5 owns all `build.gradle.kts` / manifest / catalog / duplicate-class coherence so the box-day `gradlew assemble` + instrumented run is clean — **without claiming it compiles on macOS.**

---

## Disjointness matrix (quick check)
| Path | Owner |
|---|---|
| `apps/noporis-bridge-glue/src/daemon.rs`, `bin/`, substrate Orchestrator/schema, daemon+persistence+e2e+writerlock tests | D1 |
| `apps/noporis-bridge-glue/src/{bridge,consent_record,crossing,audit}.rs` | D2 |
| `apps/noporis-gate/*` | D2 |
| `apps/porog-crossprofile/*` | D3 |
| `android-*/**/bridge/*` (persona broker) + its `src/test` | D2 |
| `android-*/**/crossprofile/*` + its `src/test` | D3 |
| `crates/postern-seal-companion/src/mobile.rs`, `android-*/**/attest/*`, `**/dpc/{WorkChallengePolicy,LockdownPolicy}.kt`, `**/lifecycle/*` | D4 |
| all `build.gradle.kts`, `libs.versions.toml`, `settings.gradle.kts`, manifests, `dpc/CrossProfileReconciler.kt`, `dpc/BridgeStateReceiver.kt`, `dpc/CrossProfileAuditLog.kt`, new privacy doc | D5 |

**Two coordination points (both now RESOLVED in `fleet/porog-poster-3`):**
1. **CrossProfileReconciler dedupe** — DONE. The `crossprofile/` port was retired; `dpc/CrossProfileReconciler.kt` is the single canonical class and D3 relies on it.
2. **junit wiring** (D5) — DONE. `testImplementation(libs.junit)` is in the container `build.gradle.kts`, unblocking D3/D4 Kotlin host tests on the box.
