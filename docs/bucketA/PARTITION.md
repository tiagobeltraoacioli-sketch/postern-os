<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- Bucket-A PMO deliverable. File-ownership-disjoint 3-dev partition for the
     box-day execution of RUNBOOK.md. Prepared OFF the box; nothing below has
     been run — this assigns who runs what once the box exists. -->

# Bucket A — 3-Dev PARTITION (file-ownership-disjoint)

Each dev's files are disjoint from the other two — no two devs need to touch
the same file on box-day. Where a file is *read-only consumed* across a
boundary (e.g. Dev C reads Dev A's `os/sloboda-compat.nix` wiring), it is
noted but stays owned by its listed dev.

---

## Dev A · OS images

**Mandate:** perfect the Nix flake image targets + build scripts + roothash
tooling + reproducibility knobs so `nix build` just works on first try on the
box. Add any HOST-runnable dry-check that does NOT need QEMU.

**Files owned:**
- `flake.nix` (root — all `packages.*`, `apps.*`, `nixosConfigurations.*`)
- `os/configuration.nix`, `os/bloch-node.nix`, `os/desktop.nix`, `os/browser.nix`,
  `os/mobile.nix`, `os/telephony.nix`, `os/cloud.nix`, `os/attested.nix`,
  `os/seal-gate.nix`, `os/package.nix`
- `os/seal-gate/README.md`, `os/seal-gate/fill-outputhashes.sh`
- `os/attested/README.md`, `os/attested/extract-roothash.sh`,
  `os/attested/verify-boot-binding.sh`, `os/attested/O2-REQUEST.md`
- `scripts/flake-lock.sh`, `scripts/flake-check.sh`
- `docs/plan/FLAKE-REPRO.md`
- `os/MOBILE.md`, `os/DESKTOP.md`, `os/ATTESTATION.md`, `os/README.md`

**Pre-box HOST-runnable dry-checks (no Nix needed, do these NOW on macOS):**
- `flake.nix` brace/paren/bracket balance check (already done once per the repro
  doc — re-verify after any edit): a quick `python3 -c "s=open('flake.nix').read(); assert s.count('{')==s.count('}')..."`.
- `shellcheck` on every `.sh` in `os/seal-gate/`, `os/attested/`, `scripts/`.
- Static grep-audit of the 5 `lib.fakeHash` sentinel keys in `os/seal-gate.nix`
  against `Cargo.lock`'s git-sourced `name-version`s (cross-check they still
  match; flag if `Cargo.lock` moved and the sentinel keys are stale).
- Confirm the dual-git-rev Cargo.lock collision (`bloch-crypto`/`bloch-sis-pow`/
  `coherence-core` pinned at two revs) is still present or already deduped —
  this determines whether `fill-outputhashes.sh` will exit 3 on first box-day
  run; pre-empt it by proposing the single canonical rev now (coordinate: this
  touches the repo-wide `Cargo.lock`, not solely Dev A's files).

**Box-day command that exercises this dev's work:**
```sh
scripts/flake-lock.sh && scripts/flake-check.sh --all
nix build .#iso .#desktop-iso .#mobile-image .#attested-image .#cloud-image
./os/seal-gate/fill-outputhashes.sh && nix build .#seal-gate
./os/attested/extract-roothash.sh -f . -a attested-image --bind
```
= RUNBOOK.md Rungs 0, 1, 3.

---

## Dev B · Android bridge builds

**Mandate:** own the Gradle build files, dependency declarations,
`testImplementation`/`androidTestImplementation` wiring, adb/emulator harnesses
so `./gradlew assemble` + instrumented tests run on the box. This is the
long-flagged "VM3 owns build files" role — the UI-bridge devs deliberately did
NOT touch `*.gradle.kts`/`gradlew`; Dev B owns them now.

**Files owned:**
- `android-container/profile/app/build.gradle.kts`, `build.gradle.kts`,
  `settings.gradle.kts`, `gradle.properties`, `gradle/libs.versions.toml`,
  `gradlew`, `gradlew.bat`, `gradle/wrapper/*`
- `android-container/profile/toolchain/flake.nix`, `toolchain/README.md`
  (Porog's pinned Android SDK/NDK devshell — the one that exists today)
- `android-container/profile/test/e2e/provision-lifecycle.sh` (adb driver)
- `android-bridge/persona/app/build.gradle.kts`, `build.gradle.kts`,
  `settings.gradle.kts`, `gradle.properties`, `gradle/libs.versions.toml`,
  `gradlew`, `gradlew.bat`, `gradle/wrapper/*` (NoporIS)
- `android-bridge/persona/play/**` gradle-adjacent policy files (`play-flavor-policy.mjs` is JS logic, not Gradle — leave to its existing owner, but the *build wiring* that consumes it is Dev B's)
- `android-common/build.gradle.kts` (the shared managed-profile module both
  Porog and NoporIS consume — Dev B is the one dev touching all three build
  graphs, so is best placed to keep them mutually compatible)
- **NEW, to be created on box-day:** `android-bridge/persona/toolchain/flake.nix`
  — NoporIS has no pinned devshell yet; Dev B should fork/adapt Porog's
  `android-container/profile/toolchain/flake.nix` (same SDK 34 / NDK r26b pins,
  same `google_apis` non-Play system image rationale) rather than invent new pins.
- `.gitlab-ci.yml` — ONLY the `t0:android-static`, `t1:android-assemble-debug`,
  `t1:profile-lifecycle-e2e` jobs (do not touch the Rust/site/deploy jobs).

**Pre-box HOST-runnable dry-checks (already partially done — verify + extend):**
- `t0:android-static` job, runnable today without any Android SDK:
  ```sh
  shellcheck android-container/profile/test/e2e/provision-lifecycle.sh
  sh -n android-container/profile/gradlew
  python3 -c "import tomllib; tomllib.load(open('android-container/profile/gradle/libs.versions.toml','rb'))"
  python3 -c "s=open('android-container/profile/toolchain/flake.nix').read(); assert s.count('{')==s.count('}')"
  ```
- Extend the same static gate to `android-bridge/persona/` (currently
  ungated — its `gradlew`, `libs.versions.toml`, and the new toolchain flake
  should get the identical treatment before box-day).
- Cross-check `android-bridge/persona/app/build.gradle.kts`'s commented-out
  `implementation(project(":android-common"))` line: it is deliberately
  commented pending `android-common` landing. Confirm `android-common` is
  present in `settings.gradle.kts`'s `include(...)` list and uncomment +
  wire it as a pre-box fix (this is a pure text edit, no SDK needed) so the
  first box-day `./gradlew` isn't immediately broken by a stale comment.
- Verify `android-bridge/persona/settings.gradle.kts` includes `:android-common`
  as a project dependency (or a relative `includeBuild`) — same class of
  pre-box text fix as above.

**Box-day command that exercises this dev's work:**
```sh
cd android-container/profile/toolchain && nix develop --command bash -c \
  "cd .. && gradle wrapper --gradle-version 8.9 --distribution-type bin && \
   ./gradlew :app:assembleDebug :app:assembleDebugAndroidTest"
nix run .#avd &
nix develop --command bash -c "adb wait-for-device && cd .. && \
  ./test/e2e/provision-lifecycle.sh --apk app/build/outputs/apk/debug/app-debug.apk \
  --test-apk app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk"
# then repeat the assemble step for android-bridge/persona once its toolchain flake lands
```
= RUNBOOK.md Rungs 6, 7, 8.

---

## Dev C · Waydroid + Tor

**Mandate:** Waydroid launch/bridge scripts (Sloboda) + Tor onion bring-up
(courier) + their integration harnesses, ready-to-run.

**Files owned:**
- `apps/sloboda/bin/sloboda`, `bin/paw-lib.sh`, `bin/sloboda-installwatch`,
  `config/sloboda.conf.sample`, `share/applications/sloboda.desktop`,
  `share/systemd/user/sloboda-installwatch.service`, `ui/index.html`,
  `test/dry-run.sh`, `test/mock-waydroid`
- `scripts/vm/sloboda-waydroid-boot-smoke.sh` (the T1 real-boot smoke — the
  ONLY thing in-repo that boots a real Waydroid container)
- `crates/postern-courier/src/lib.rs` (the `onion-transport`-feature module —
  read/extend the `#[ignore]`d `live_onion_drop_end_to_end` test; do not touch
  the default (non-`onion-transport`) crypto-seal path, which belongs to the
  SDK/crypto track)
- `crates/postern-tor/**` (the in-process Arti wrapper `postern-tor`'s
  onion-service hosting path that courier depends on)
- **Read-only, not owned:** `os/sloboda-compat.nix` / `os/sloboda-vm.nix` (Dev
  A's Nix wiring for the throwaway Waydroid VM host) — Dev C boots against it
  but does not edit it; request changes from Dev A if the VM needs a different
  kernel/compositor knob.

**Pre-box HOST-runnable dry-checks (already done — verify still clean):**
- `shellcheck -x -s sh` across `apps/sloboda/bin/*` and `test/*` — per
  `apps/sloboda/README.md`'s own validation section, already exit-0 clean.
- `sh test/dry-run.sh` — 39/39 passing against the mock waydroid (trace mode +
  mock-exec mode). Re-run after any edit to keep this green.
- `shellcheck scripts/vm/sloboda-waydroid-boot-smoke.sh` — confirm it still
  correctly SKIPs (exit 77) off-VM and refuses to run against the test mock
  (the "cannot fake a real boot green" guard).
- For courier: `cargo build -p postern-courier --features onion-transport`
  (compiles the transport module without running the live network test) and
  `cargo test -p postern-courier` (default features — the offline in-memory
  duplex test, T1 host-test tier) both already pass on macOS per the gap doc's
  "DONE" rating for the courier seal core — re-confirm before box-day.

**Box-day command that exercises this dev's work:**
```sh
nix build .#nixosConfigurations.sloboda-vm.config.system.build.vm
./result/bin/run-sloboda-vm-vm
# inside the guest: zgrep BINDER /proc/config.gz; ls /dev/binderfs; sudo waydroid init -s VANILLA
PAW_VM_SMOKE=1 sh scripts/vm/sloboda-waydroid-boot-smoke.sh

cargo test -p postern-courier --features onion-transport -- --ignored --nocapture
```
= RUNBOOK.md Rungs 9, 10. Note Rung 10 does not need the Nix/QEMU box at all —
it only needs cargo + network — so Dev C can run it in parallel with Rung 9,
or even kick it off first while the Waydroid VM builds.

---

## Cross-cutting, unowned by design

`scripts/check-trust-labels.sh` and `.gitlab-ci.yml`'s non-Android jobs
(`clippy`, `supply-chain`, `secret-scan`, `trust-labels`, `build-and-test`,
`pages`, `deploy-cloudflare`) are **not** part of this 3-dev partition — they
are cross-cutting repo hygiene, already run today on the existing `bloch-mac`
runner, and out of scope for box-day. Advisor 2 (see ADVISORS-CHARTER.md)
re-confirms `check-trust-labels.sh` stays `critical:0` after all three devs'
box-day changes land, but no dev edits that script as part of their bucket.
