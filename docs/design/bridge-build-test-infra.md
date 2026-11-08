# Bridge build/test/CI infrastructure — making Porog / NoporIS / Waydroid provably functional

**Author:** Architect A10 (build/test/CI environment architecture — cross-cutting).
**Status:** design. **Coordinates with:** A1/A2 (Porog toolchain), A7 (Waydroid boot),
A9 (honesty labels). **Honesty gates inherited:** G1 built≠designed, G2 built≠booted≠hardware,
G3 attestation is hardware-gated, G4 unaudited-always
(see `docs/design/designed-items-execution-backlog.md`).

> This document owns the *infrastructure* answer only: **what toolchain each
> product needs, WHERE it can run, what each test tier proves, and how CI must
> report the tiers without lying.** It does not implement Porog's DPC, boot
> Waydroid, or verify an attestation — those are A1/A2/A7's product work. It
> tells them what environment makes that work runnable and how to keep the
> pipeline honest about what has *not* been run.

---

## 0. The ground truth this design is built on

Confirmed by inspection of the repo (2026-07):

- **Build host is macOS** (`bloch-mac` self-hosted GitLab shell runner,
  `.gitlab-ci.yml`). It has: the user's Rust toolchain, Homebrew, `ffmpeg`,
  headless Chrome, `node` (≥18), `shellcheck`, `gitleaks`. It has **none** of:
  Android SDK/NDK, Gradle wrapper, Nix, QEMU, Waydroid, an Android emulator.
- **Rust workspace already builds + tests on the host** — `cargo build/test
  --workspace` is the existing `build-and-test` gate. 1,400+ files carry
  `#[test]`. This tier is real and green today.
- **The Android trees are Gradle/Kotlin scaffolds that have never been built:**
  - `android-container/profile/` — **Porog** (Postern Container DPC / managed
    work profile, `ACTION_PROVISION_MANAGED_PROFILE`, StrongBox key-attestation).
  - `android-bridge/persona/` — **NoporIS** persona DPC, incl. a `play/`
    `GOOGLE_PLAY` flavor with Play Integrity disclosure (makes **no** attestation
    claim — the less-private side).
  - `android-common/` — the **one shared DPC core** both consume (co-owned;
    changes need both leads).
  - `mobile/android/` — the wallet app (`StrongBoxKey.kt`); `jniLibs/` and
    `uniffi/bloch_mobile/` are **placeholders** — the real `.so` comes from
    cross-compiling `mobile/core` (Rust, UniFFI-exported) with the NDK.
  - Pinned versions (from the `build.gradle.kts` files): **AGP 8.5.0, Kotlin
    1.9.24, Compose compiler 1.5.14, compileSdk 34, minSdk 30, JDK 17.**
    **No `gradlew` wrapper and no `libs.versions.toml` are committed** — the
    projects cannot even bootstrap Gradle offline as-is.
- **Waydroid tier** = `apps/sloboda/` (POSIX-sh wrapper) + `test/dry-run.sh`
  + `test/mock-waydroid`, with a **13-item "only confirmable on real device"**
  list in its README. NixOS wiring is `os/sloboda-compat.nix` (owned elsewhere).
  Nothing has ever booted an Android container.
- **JS apps** are single self-contained `index.html` files with standalone Node
  test scripts (`test-core.mjs`, `test-store.mjs`) run as `node <file>`
  (Node ≥18). No bundler, no lockfile — verified in `apps/build-offline.md`.
- **Nix flake** (`flake.nix`) is "written, not built": no `flake.lock` because
  Nix can't run on the macOS host.

Everything below is designed **around** those constraints, not in denial of them.

---

## 1. Per-product toolchain + location matrix

Three run-locations exist in this plan:

- **HOST** = the current macOS `bloch-mac` CI runner (today).
- **VM** = the incoming **Linux + Nix VM** (x86_64 assumed; see §5). New CI tier.
- **DEV** = a **real aarch64 device** (Pixel 3+/Samsung for StrongBox; a
  binder-capable Linux phone for full Waydroid). Manual, out-of-CI.

| Product | Build toolchain needed | Where it can BUILD | Runtime/test toolchain | Where it can be PROVEN |
|---|---|---|---|---|
| **Rust workspace** (`crates/*`, `mobile/core`, `desktop/src-tauri`) | host Rust + rev-pinned `bloch*` git dep | HOST ✅ (today) · VM ✅ | `cargo test --workspace` | HOST ✅ (unit/vector level) |
| **Porog** (`android-container/profile` + `android-common`) | JDK 17, Gradle 8.7+, **Android SDK** (cmdline-tools, platform-34, build-tools 34), AGP 8.5.0/Kotlin 1.9.24 | ❌ HOST (no SDK) → **VM ✅** | Gradle unit tests (JVM), **work-profile emulator** (AVD) for provisioning; **StrongBox attestation → real device only** | build/unit: VM · provisioning: VM emulator (partial) · **StrongBox: DEV only** |
| **NoporIS** (`android-bridge/persona` + `play/` flavor + `android-common`) | same as Porog **+** Google Play services SDK path for the `GOOGLE_PLAY` flavor | ❌ HOST → **VM ✅** | Gradle unit tests; emulator for DPC flow; **Play Integrity reality → real device + Play services** | build/unit: VM · **Play Integrity verdict: DEV only** |
| **Wallet app** (`mobile/android`) | Porog toolchain **+ NDK r26**, `cargo-ndk`, `uniffi-bindgen` (to fill `jniLibs/`, `uniffi/`) | ❌ HOST → **VM ✅** (NDK cross-compile of `mobile/core`) | Gradle assemble + instrumented tests | build: VM · StrongBox key-gen: **DEV only** |
| **Porog/NoporIS glue** (`apps/porog-tor-glue`, `apps/noporis-*-glue`, standalone Cargo) | host Rust (own `[workspace]`) | HOST ✅ · VM ✅ | `cargo test` in each glue dir | HOST ✅ |
| **NoporIS/Android gate UIs** (`apps/noporis-gate`, `apps/sloboda-gate`) | Node ≥18 | HOST ✅ | `node test-store.mjs`, `node --check`, `shellcheck` | HOST ✅ |
| **Waydroid wrapper** (`apps/sloboda`) | POSIX sh, `shellcheck`, `node` (UI syntax) | HOST ✅ (lint + mock) | `sh test/dry-run.sh` (mock, boots nothing) → **binder-VM boot** → **phone boot** | mock: HOST ✅ · container control-flow: **VM ✅ (binder kernel)** · full aarch64 story: **DEV only** |
| **NixOS images** (`os/*.nix`, `flake.nix`, `os/sloboda-compat.nix`) | Nix + flakes; QEMU for boot | ❌ HOST → **VM ✅** (`nix flake lock`, `nix build`, QEMU boot) | `nix flake check`; QEMU boot; hardware boot | build/lock: VM · QEMU boot: VM · **PinePhone/aarch64 boot: DEV only** |

**Headline:** the macOS host can build **everything Rust and everything
JS/shell**, and *lint* the Android/Nix scaffolds — but it can **build zero
Android APKs and boot zero containers**. Every Android/Waydroid/Nix build step is
**blocked on the incoming Linux+Nix VM**, and every attestation/StrongBox/Play-
Integrity/aarch64 claim is **blocked on a real device beyond that.**

---

## 2. Tiered test strategy — T0 / T1 / T2

The unit of honesty is the **tier**. A test result is only trustworthy about the
tier it ran in. CI must never let a T0 pass *imply* a T1 or T2 truth.

### T0 — offline / mock (runs in CI on the macOS HOST today)

| What runs | Command | What it PROVES | What it does NOT prove |
|---|---|---|---|
| Rust workspace unit + vector tests | `cargo build/test --workspace` | Core logic: crypto math, transcript/verifier, Seal SNP vectors (real Milan fixture) | Nothing runs on real TEE hardware (own admission in `snp.rs`) |
| Glue crates | `cargo test` per `apps/*-glue`, `apps/porog-tor-glue` | Standalone glue logic compiles + passes | Not wired into a live Android/Tor runtime |
| JS core tests | `node apps/*/test-core.mjs`, `node apps/*/test-store.mjs` | Ceremony/store-state logic (nonce single-use, expiry, canonical bytes) | Not the in-browser or on-device behavior |
| Waydroid wrapper | `shellcheck -x -s sh …`, `sh -n`, `node --check`, `sh test/dry-run.sh` | Wrapper **control flow**: status parsing, wait-ready, `.desktop` gen/prune, read-only bridge check, kill-switch — against `mock-waydroid` | **Boots nothing.** Zero of the 13 device-only items. |
| Android scaffold static checks (**new**) | `ktlint`/`detekt` if added; Kotlin `sh -n`-equivalent is compile — see T1 | Only *style*, not compilation (no SDK on host) | Does not prove the Gradle projects compile |
| Nix scaffold static checks (**new**) | `nix-instantiate --parse` is unavailable on host; fall back to `nixfmt`/`statix` **on VM** | — | Host cannot evaluate Nix at all |
| Policy gates | `scripts/check-trust-labels.sh`, `cargo deny`, `gitleaks` | Trust-label bleed, RUSTSEC/license/source policy, secrets | Not functional correctness |

**T0 is the current green pipeline.** It is real, and it is *narrow*: it proves
cores and control-flow, never Android compilation, never a boot, never hardware.

### T1 — emulator / VM (runs on the incoming Linux+Nix VM; new CI tier `test:vm`)

| What runs | Command (on VM) | What it PROVES | Ceiling (what it still can't prove) |
|---|---|---|---|
| **Porog / NoporIS Gradle build** | `./gradlew :app:assembleDebug :app:testDebugUnitTest` (per project) | The Kotlin/Compose/DPC scaffolds **actually compile** against SDK 34 (flips G1 "built") + JVM unit tests pass | Not that provisioning runs on hardware |
| **Wallet NDK cross-compile** | `cargo ndk -t arm64-v8a build` + `uniffi-bindgen` → real `jniLibs/`, then Gradle assemble | `mobile/core` links into the APK; placeholders replaced | StrongBox key-gen still device-only |
| **Work-profile provisioning** | AVD (system image, API 30–34) + `adb`/DPC test | Managed-profile provisioning flow (`ACTION_PROVISION_MANAGED_PROFILE`), per-profile policy, always-on VPN — the **control path** | **StrongBox on an emulator is not real** — attestation chain roots in an emulator key, not Google's CA (G3 blocks the claim) |
| **Waydroid binder-VM boot** | On a **binder-enabled x86_64 kernel** (`CONFIG_ANDROID_BINDER_IPC` + `_BINDERFS`): `waydroid init`, `waydroid session start` → `Session: RUNNING`, `waydroid app list/launch` under a Wayland compositor | Items **1,4,5,6,7,9,10** of the README's 13-list: binder present, session reaches RUNNING, compositor displays, `app list`/`launch` parse, `.desktop` re-entry, kill-switch privileges | aarch64-specific + GPU (item 11) + Play-Integrity reality (12) + real image channels (2,3,8) need DEV |
| **Nix flake lock + build + QEMU boot** | `nix flake lock`, `nix flake check`, `nix build .#…`, boot in QEMU | Flake evaluates, image builds reproducibly-by-design, **boots in QEMU** (G2 "boots on QEMU") | QEMU ≠ hardware (PinePhone/aarch64 unproven) |

**T1 is what the VM unlocks.** It moves Porog/NoporIS from `design/spec` toward
`built` (G1) and Waydroid from "mock only" to "container control-flow proven on
a binder kernel," and OS images to "boots on QEMU" (G2). It is the single
highest-leverage piece of infra in this whole effort.

### T2 — real device (manual, logged, NEVER CI-green-faked)

| What runs | Where | What it PROVES | Rule |
|---|---|---|---|
| **StrongBox attestation** | Pixel 3+/Samsung with StrongBox | X.509 chain roots in Google's attestation CA; binds verified-boot + patch level; nonce echo verifies via `bloch::attestation::verify` (mobile backend) | **G3:** the *only* thing that flips Porog's attestation to "working." Emulator can NEVER produce this. |
| **Play Integrity reality** | Real device + Play services | STRONG fails on the Waydroid tier as claimed; which specific apps (banking/Wallet/DRM) refuse; NoporIS `GOOGLE_PLAY` verdict | Honest label must match observed verdict (feeds A9) |
| **Phone Waydroid full story** | aarch64 Linux phone w/ binder kernel | README items **2,3,8,11,12** + full 13: real image pulls, microG path, Aurora delivery, GPU (Lima/Panfrost vs SwiftShader), Play-Integrity reality | Manual runbook, logged with device + build IDs |
| **Hardware image boot** | PinePhone / target aarch64 | `os/*.nix` boots on real hardware; measured-boot `os_roothash` | G2 final step: hardware ≠ QEMU |

**T2 results live in a signed manual log, never in a pipeline job's exit code.**
A device test that has not been run is `UNTESTED`, not `passing`.

---

## 3. CI honesty rules — a green pipeline must not imply device-proven

These rules are the infra contract with A9. They are mechanical, not aspirational.

**R1 — Tier is a first-class job-name prefix.** Every CI job is named for the
highest tier it can prove: `t0:*` (host), `t1:*` (VM), `t2:*` (device, and
therefore **manual-only / never automated**). A reader sees the ceiling in the
name. Today's jobs are all `t0:*`.

**R2 — No cross-tier implication.** A `t0:*` pass says nothing about T1/T2. The
pipeline **must not** render an aggregate "✅ all passed" that spans tiers. The
overall badge reflects only the tiers that actually ran, labeled with which.

**R3 — Absent tiers surface as `UNTESTED-until-hardware`, not omitted and not
green.** Until the VM exists, the pipeline emits explicit **manual/blocked
placeholder jobs** for `t1:*` and `t2:*` that report status `UNTESTED` (GitLab:
a `when: manual` job that is *not started*, or an `allow_failure` job whose
script prints the tier's untested inventory and exits non-zero-but-tolerated with
a visible `UNTESTED` message). The point: a viewer scanning the pipeline **sees**
that Android build (T1) and StrongBox (T2) have not run — they are not silently
missing.

**R4 — The 13-item Waydroid list and the StrongBox/Play-Integrity items are a
machine-readable inventory.** A single `docs/design/untested-inventory.yml`
(owned jointly with A9) lists every device-only claim with its tier and current
status. A `t0:honesty-inventory` job asserts that **every item still marked
`UNTESTED` has NOT leaked an attestation/"working"/"verified" word into any
shipping surface** — an extension of the existing `scripts/check-trust-labels.sh`
gate (which already hard-fails on attestation words bleeding onto non-attestable
tiers). This is the enforcement arm of G3.

**R5 — Badges mirror tiers (feeds the site via A9).** Site product badge
transitions are gated on tier, not on "the pipeline is green":
`design/spec` → (T1 Gradle compile + unit tests pass) → `built` →
(T1 emulator/QEMU) → `boots on emulator/QEMU` → (T2 device) → `tested on
hardware`. **`unaudited` never comes off (G4).** No badge may claim a rung the
corresponding tier has not run.

**R6 — Faked-green is a build break.** If any `t2:*` claim is wired to auto-pass
(e.g. a stubbed StrongBox verifier returning OK in CI), `t0:honesty-inventory`
must fail the pipeline. The default posture for an unrun device test is red-or-
manual, never green.

---

## 4. CI structure to add (concrete `.gitlab-ci.yml` deltas)

Keep the existing `bloch-mac` runner and its five `t0` jobs (renamed with the
`t0:` prefix). Add a second runner tag `bloch-linux-vm` for the VM and the new
tiered jobs. Do **not** commit until the VM exists — land the placeholders first
so the honesty surface is present even before the VM.

```yaml
stages: [check, test, test-vm, deploy]   # test-vm is new

# --- existing, renamed for tier clarity (still on bloch-mac) ---
t0:trust-labels:   { stage: check, ... }   # was: trust-labels  (BLOCKING)
t0:supply-chain:   { stage: check, ... }   # was: supply-chain   (BLOCKING)
t0:secret-scan:    { stage: check, ... }
t0:clippy:         { stage: check, ... }
t0:build-and-test: { stage: test,  script: [ cargo build --workspace, cargo test --workspace ] }

# NEW T0: node core tests + waydroid mock + honesty inventory (all host-runnable)
t0:js-core:
  stage: test
  before_script: []
  script:
    - for t in apps/*/test-core.mjs apps/*/test-store.mjs; do node "$t"; done
    - node --check apps/sloboda/ui/index.html || true   # UI syntax
t0:waydroid-mock:
  stage: test
  before_script: []
  script:
    - shellcheck -x -s sh apps/sloboda/bin/* apps/sloboda/test/*
    - sh apps/sloboda/test/dry-run.sh          # mock, boots nothing
t0:honesty-inventory:                                   # BLOCKING (R4/R6)
  stage: check
  before_script: []
  script:
    - bash scripts/check-trust-labels.sh
    - bash scripts/check-untested-inventory.sh          # NEW: enforces R4/R6

# NEW T1: on the Linux+Nix VM. Until the VM is registered, these are the
# UNTESTED placeholders (R3): manual, and printing their untested inventory.
t1:android-build:
  stage: test-vm
  tags: [bloch-linux-vm]
  rules: [ { if: '$BLOCH_VM_READY == "1"' } ]           # else stays absent→placeholder
  script:
    - ( cd android-container/profile && ./gradlew :app:assembleDebug :app:testDebugUnitTest )
    - ( cd android-bridge/persona   && ./gradlew :app:assembleDebug :app:testDebugUnitTest )
    - ( cd mobile/android           && ./gradlew :app:assembleDebug )   # needs jniLibs from cargo-ndk
t1:waydroid-boot:
  stage: test-vm
  tags: [bloch-linux-vm]
  rules: [ { if: '$BLOCH_VM_READY == "1"' } ]
  script: [ bash scripts/vm/waydroid-boot-smoke.sh ]     # binder present → session RUNNING → app list
t1:nix-flake:
  stage: test-vm
  tags: [bloch-linux-vm]
  rules: [ { if: '$BLOCH_VM_READY == "1"' } ]
  script: [ nix flake lock, nix flake check ]

# T2 is NEVER a CI job. It is a manual runbook whose results land in the signed
# device log + untested-inventory.yml. No `t2:*` automated job may exist.
t1:untested-placeholder:                                 # visible R3 surface pre-VM
  stage: test-vm
  when: manual
  script: [ bash scripts/print-untested-tiers.sh ]       # lists T1/T2 as UNTESTED
```

Two new host scripts (`scripts/check-untested-inventory.sh`,
`scripts/print-untested-tiers.sh`) plus one VM script
(`scripts/vm/waydroid-boot-smoke.sh`) are the only new code this design asks for;
they are thin wrappers over the existing label-check + the inventory YAML.

---

## 5. Linux + Nix VM provisioning runbook

Assume the incoming VM is **x86_64 Linux with Nix + flakes** (the realistic
laptop/desktop case). x86_64 proves *control flow* for Android + Waydroid; the
aarch64-only truths stay T2/DEV. If the VM is aarch64, all the better — it then
also covers some T2 items, but do not *assume* it.

### 5.1 What to install

1. **Nix (flakes enabled).** The one hard requirement the flake needs. Then
   `nix flake lock` in the repo to finally freeze `flake.lock` (impossible on
   macOS). Everything else below should ideally be pinned in a `devShell` in
   `flake.nix` so the VM's toolchain is reproducible, not hand-installed.
2. **JDK 17** (`temurin`/`openjdk17`).
3. **Android SDK** via Nix (`androidenv.composeAndroidPackages`) or
   `sdkmanager`: `cmdline-tools;latest`, `platforms;android-34`,
   `build-tools;34.0.0`, `platform-tools`. Accept licenses.
4. **Gradle 8.7+** (AGP 8.5.0's floor). **Also commit a `gradlew` wrapper +
   `gradle-wrapper.properties` to each Android project** — they are currently
   missing, so the VM (and any future contributor) cannot bootstrap Gradle
   offline. This is a prerequisite fix, tracked as an infra task.
5. **Android NDK r26** + `cargo-ndk` + `uniffi-bindgen` — to cross-compile
   `mobile/core` to `arm64-v8a`/`x86_64` `.so` and fill `mobile/android/jniLibs/`
   + `uniffi/bloch_mobile/` (they are placeholders today).
6. **Emulator + a system image** (`system-images;android-33;google_apis;x86_64`)
   for the work-profile provisioning test. Headless: `-no-window -gpu swiftshader`.
   Note: proves provisioning control flow, **never StrongBox**.
7. **Waydroid stack**: `lxc`, `waydroid`, a **binder-enabled kernel**
   (`CONFIG_ANDROID_BINDER_IPC=y` + `CONFIG_ANDROID_BINDERFS=y`; on NixOS set
   `boot.kernelModules`/`boot.kernelPatches` or use `linux_zen`/an anbox-binder
   module), and a **Wayland compositor** (`weston --backend=headless` works
   headless). Verify `/dev/binderfs` mounts and `binder_linux` loads before
   Waydroid.
8. **Rust toolchain + the rev-pinned `bloch*` git dep** (same as host) so the VM
   can also run the T0 suite and act as a second/failover runner.
9. **GitLab runner** registered with tag `bloch-linux-vm`; set CI/CD variable
   `BLOCH_VM_READY=1` to flip the `t1:*` jobs from placeholder to live.

### 5.2 First "prove it boots/builds" runbook (run in this order; each is a gate)

```
# 0. Nix works and the flake finally locks (impossible on macOS)
nix --version && nix flake lock && nix flake check          # → commit flake.lock

# 1. Host-tier still green on Linux (portability check)
cargo build --workspace && cargo test --workspace           # T0 on VM

# 2. Android compiles for the FIRST time (flips G1 "built" for Porog/NoporIS)
( cd android-container/profile && ./gradlew :app:assembleDebug :app:testDebugUnitTest )
( cd android-bridge/persona   && ./gradlew :app:assembleDebug :app:testDebugUnitTest )
#   ^ if gradlew is missing, `gradle wrapper --gradle-version 8.7` first, then commit it.

# 3. Wallet .so cross-compiles and links (kills the jniLibs placeholders)
( cd mobile/core && cargo ndk -t arm64-v8a -t x86_64 build --release )
uniffi-bindgen generate --language kotlin …                 # → mobile/android/uniffi/…
( cd mobile/android && ./gradlew :app:assembleDebug )

# 4. Work-profile emulator provisioning (control flow only; NOT StrongBox)
emulator -avd wp34 -no-window -gpu swiftshader &
adb wait-for-device && adb shell dpm set-profile-owner labs.postern.container/.dpc.PosternDeviceAdminReceiver
#   observe ACTION_PROVISION_MANAGED_PROFILE flow; StrongBox key-gen is expected to
#   produce a NON-attestable emulator key → label UNTESTED-until-hardware (do NOT claim).

# 5. Binder present, then Waydroid reaches RUNNING (README items 1,4,5,6,7,9,10)
zgrep -E 'ANDROID_BINDER_IPC|BINDERFS' /proc/config.gz      # both must be =y
modprobe binder_linux && ls /dev/binderfs                   # binder ready
weston --backend=headless-backend.so &                      # a compositor exists
sudo waydroid init -s VANILLA                               # item 2 (real image pull)
waydroid session start                                       # wait for `Session: RUNNING` (item 4)
waydroid app list                                            # parser matches (item 6)
#   run apps/sloboda/test/dry-run.sh AGAINST REAL waydroid (PAW_DRYRUN=0, no mock on PATH)

# 6. Flip CI on: register runner tag bloch-linux-vm, set BLOCH_VM_READY=1
```

Each numbered step that passes advances exactly one honesty rung (§3 R5) and
updates the matching row in `untested-inventory.yml` — **and no further.** Step 4
does not grant a StrongBox claim; step 5 on x86_64 does not grant the aarch64 or
Play-Integrity claims. Those stay T2/DEV.

---

## 6. Top infra risks

1. **The VM may be x86_64, but the real product is aarch64.** An x86_64 VM proves
   *control flow* for Android emulator + Waydroid binder, but the shipping targets
   (Pixel, PinePhone) are aarch64. GPU path, image channels, and Play-Integrity
   verdicts (README items 2,3,8,11,12) **cannot** be closed on the VM — they are
   permanently T2. Risk: someone reads a green `t1:waydroid-boot` as "Waydroid
   works on the phone." R3/R4 exist precisely to block that read.
2. **Missing `gradlew` wrapper + no `libs.versions.toml`.** The Android projects
   can't bootstrap Gradle offline. Until this is fixed, even the VM can't build.
   Cheap to fix (commit the wrapper) but it is a hard prerequisite, not a nicety.
3. **StrongBox and Play Integrity are irreducibly device-only (G3).** No amount of
   VM/emulator infra can produce a Google-CA-rooted attestation or a real STRONG
   verdict. The temptation to stub these green in CI is the single biggest honesty
   hazard; R6 + `t0:honesty-inventory` are the guardrail.
4. **Binder kernel is fragile on NixOS.** `CONFIG_ANDROID_BINDER_IPC`/`_BINDERFS`
   are not default; a kernel rebuild or a maintained anbox-binder module is
   needed, and it drifts across nixpkgs (same class of drift the flake header
   warns about). Budget for the VM's first Waydroid boot to fail on kernel config
   and need a rebuild.
5. **NDK/UniFFI cross-compile is a real, unrun link step.** `jniLibs/` and
   `uniffi/bloch_mobile/` are placeholders; the first `cargo ndk` + `uniffi-bindgen`
   may surface ABI/symbol mismatches that unit tests never showed. This is where
   `mobile/core`'s "UniFFI export done" claim gets its first *integration* test.
6. **Single self-hosted runner = single point of failure and of trust.** The
   `bloch-mac` runner holds the protocol-dep token; adding the VM runner doubles
   the surface. Both must scope `BLOCH_DEP_TOKEN` read-only and never expose it to
   `t1:*` Android jobs that don't need it.
7. **The flake has never been locked or evaluated.** Step 0 of the runbook
   (`nix flake lock`) is genuinely unrun; the mobile-nixos eval API "evolves
   across revisions" per the flake header, so the first `nix flake check` on the
   VM may need attribute-path fixes before anything downstream (image boot) works.

---

*Design only. Nothing here is built, booted, attested, or audited (G1–G4). This
document describes the infrastructure that would let the product teams change
that, one honest tier at a time.*
