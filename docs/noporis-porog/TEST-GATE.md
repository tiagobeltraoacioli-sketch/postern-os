# NoporIS + Porog — HOST TEST-GATE

The complete host battery a dev (or CI) runs on macOS to prove NoporIS + Porog green **without an Android build**. Every command below was executed against `roadmap/buckets-integrate` @ `0ee1af6` and the counts are the verified floor — a bucket's work must **raise or hold** its count, never lower it.

## 0. Prereqs
- Rust toolchain (`cargo`), Node (`node`), bash. **No Android SDK/NDK required** for this gate.
- Run from the repo root. The four `apps/*-glue` dirs and `apps/noporis-bridge-glue` are **standalone workspaces** (not root members) — `cd` into them; `cargo test -p <name>` from the root will *not* find them. `postern-seal-companion` **is** a root member.

## 1. The full HOST battery (copy-paste)

```bash
# --- NoporIS: Rust core (daemon, orchestrator, bridge, consent, audit, substrate) ---
( cd apps/noporis-bridge-glue && cargo test )            # expect: 124 passed, 0 failed
( cd apps/noporis-signer-glue && cargo test )            # expect: 23 passed
( cd apps/noporis-tor-glue    && cargo test )            # expect:  7 passed  (persona egress)

# --- NoporIS: JS gate + persona Play-flavor policy ---
node apps/noporis-gate/test-store.mjs                    # expect: noporis-gate: 56 passed, 0 failed
node android-bridge/persona/play/policy/test-play-flavor-policy.mjs   # expect: pass 11, fail 0

# --- Porog: reconcile decision kernel + egress ---
node apps/porog-crossprofile/test-reconcile.mjs          # expect: reconcile-kernel: 102 passed, 0 failed
( cd apps/porog-tor-glue && cargo test )                 # expect:  5 passed  (container egress, default)
( cd apps/porog-tor-glue && cargo test --features live --offline )  # expect: 9 passed (container egress, live-feature; offline: no network, no bootstrap)
# ^ or, equivalently, the wrapped/labeled form:
bash scripts/check-porog-tor-glue-live.sh                # same gate + honest "compile-checked != booted != anonymous, UNAUDITED" banner

# --- Porog: StrongBox VERIFIER-side (host; the device attest() is hardware-gated) ---
cargo test -p postern-seal-companion --features mobile-attest   # expect: 64 passed, 0 failed

# --- The existential guardrail: honest trust labels ---
bash scripts/check-trust-labels.sh                       # expect: critical: 0   (warn:1 pre-existing, out of scope)
```

## 2. Verified baseline (2026-07 run)
| # | Command | Result |
|---|---|---|
| 1 | `cd apps/noporis-bridge-glue && cargo test` | **124** passed / 0 failed (79 lib + 45 across daemon_loop/functional_proof/orchestrator_e2e/persistence_recovery/writer_lock_cli) |
| 2 | `cd apps/noporis-signer-glue && cargo test` | **23** passed |
| 3 | `cd apps/noporis-tor-glue && cargo test` | **7** passed |
| 4 | `node apps/noporis-gate/test-store.mjs` | **56** passed |
| 5 | `node android-bridge/persona/play/policy/test-play-flavor-policy.mjs` | **11** passed |
| 6 | `node apps/porog-crossprofile/test-reconcile.mjs` | **102** passed |
| 7 | `cd apps/porog-tor-glue && cargo test` | **5** passed (default; container egress) |
| 8 | `cargo test -p postern-seal-companion --features mobile-attest` | **64** passed (29 in `mobile.rs`) |
| 9 | `bash scripts/check-trust-labels.sh` | **critical: 0**, warn: 1 |
| 10 | `cd apps/porog-tor-glue && cargo test --features live --offline` (or `bash scripts/check-porog-tor-glue-live.sh`) | **9** passed (live-feature egress; `--offline` = builds/runs with no network, no Tor bootstrap) |

### Why #10 is an OFFLINE gate, not a live-network test
`cargo test` (#7) exercises the **pure** per-container egress policy — the fail-closed
`Decision`, the anti-round-up guard, the pinned honesty label ("hardened, not
anonymous") — all of which compile and run **without** the heavy `live` feature.
The arti-backed `cfg(feature = "live")` module (`ContainerTor` / `EgressError`,
`src/lib.rs` `mod live`) is therefore **never built** by #7, so it could silently
rot as the pure layer it calls into evolves and no host command would notice. The
runtime bootstrap (`ContainerTor::bootstrap()`) is network-dependent and documented
"not built in this sandbox", so it stays out of the offline battery.

**#10 closes that hole by building AND running the live surface offline** (arti +
postern-tor are vendored in `Cargo.lock` and the local cargo cache, so `--offline`
succeeds with no network). It runs the `live_tests` that behavior-verify the live
path's types (`EgressError`, the `#[from] postern_tor::TorError` conversion) and
re-prove the shared fail-closed rule under the `live` feature — **without**
bootstrapping Tor or claiming any runtime / anonymity property. Compile-checked !=
booted != anonymous — reachability stays out of scope, and this is an **UNAUDITED
reference-prototype**. `scripts/check-porog-tor-glue-live.sh` is the wrapped form
that prints that honest banner.

## 3. Per-dev sub-gate (what each bucket must keep green)
- **D1** → command #1 (≥124). New: schema-reader test, direction tests, recovery E2E land here.
- **D2** → commands #1 (≥124) and #4 (≥56). New: `crossing.rs` `MAX_CROSSING_BYTES` pin.
- **D3** → command #6 (≥102). New: `crossingOpen`↔`reconcile` parity, normalize fuzz.
- **D4** → command #8 (≥64). New: per-`Mismatch`-branch negatives, golden-DER fixture.
- **D5** → command #9 (critical:0) + the static coherence greps below.

## 4. BOX-GATED — prep + label, NOT run on macOS
The persona (`android-bridge/persona`) and profile (`android-container/profile`) Android/Compose apps **cannot compile on macOS** (no Android SDK/NDK). These commands run **only on the VM/box** and are the box-day gate — never reported green from the host:

```bash
# From each app root (android-bridge/persona, android-container/profile), on the box:
./gradlew :app:testDebugUnitTest     # JVM host unit tests (CrossingBearerPolicyTest,
                                     #   CrossProfileDirectivesTest, WorkChallengePolicyGuardTest,
                                     #   PersonaFlavorTest, PersonaSlotPolicyTest, + new pure-logic tests)
./gradlew :app:assembleDebug         # source-coherence / compile
./gradlew :app:connectedAndroidTest  # instrumented (ProfileLifecycleE2ETest) — profile-owner emulator;
                                     #   honestly SKIPS (assumeTrue) off-device, so green never implies device-proven
```

**Host-runnable coherence checks that de-risk the box-day run (run these on macOS now):**
```bash
# Container app must wire junit for its src/test host tests (currently MISSING → fix in D5):
grep -c 'testImplementation(libs.junit)' android-container/profile/app/build.gradle.kts   # want ≥1 (now 0)
grep -c 'testImplementation(libs.junit)' android-bridge/persona/app/build.gradle.kts      # already 1

# No duplicate same-named reconciler after D5 dedupe:
grep -rl 'class CrossProfileReconciler' android-container/profile/app/src                  # want ONE canonical file

# Every src/test host test has a home (both apps):
find android-bridge/persona android-container/profile -path '*/src/test/*' -name '*.kt'
```

## 5. Rails
- No deploy, no `git commit`, no touching `bp-wt-buckets` / `bp-wt-site`.
- `scripts/check-trust-labels.sh` **critical:0** is a release blocker — re-run after any doc/string edit.
- Anything Android-build or hardware (StrongBox `SecurityLevel=2`, DPM calls, cross-profile bind, Keystore attest) stays **UNTESTED-until-VM/device** and is *labeled as such*, never presented as a host pass.
