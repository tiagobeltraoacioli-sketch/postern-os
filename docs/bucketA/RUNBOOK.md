<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- Bucket-A PMO deliverable. Prepared OFF the box (macOS, no Nix/QEMU/Android
     SDK/TEE). Every command below is WRITTEN AND REVIEWED, NOT YET RUN HERE.
     Do not read a step in this file as evidence it passed — it is a plan. -->

# Bucket A — Box-Day RUNBOOK

**Scope:** OS images (mobile/desktop/enterprise) build→boot→roothash→repro;
Android builds of Porog/NoporIS/Sloboda-adjacent bridge apps; Waydroid
(Sloboda) run; Tor (courier onion) live. All content below is sourced from
`roadmap/fleet2-integrate` (`git -C bloch-protocol show roadmap/fleet2-integrate:<path>`)
as of 2026-07-13. Base repo state is already unusually well-prepared: harnesses,
graders, fixtures, and CI stubs exist for nearly every rung — the box's job is
to *execute* them, not invent them.

> **⚠ FOD-HASH PATH SUPERSEDED — point at the protocol-repo flake instead.**
> Rung 3's `./os/seal-gate/fill-outputhashes.sh` step (fill the 5 `lib.fakeHash`
> sentinels) is the **dead path**. The OS build now sources the `bloch` node
> (and the seal gate) from the **protocol repo's own flake**
> (`gitlab.com/blochsispow-group/BlochSISPoW-project`), which has **zero
> git-sourced crates and no FOD-hash step** — so there are no sentinels to fill
> on the live path. See [`PACKAGE-FOD-HASHES.md`](PACKAGE-FOD-HASHES.md) and
> dossier item 7 ([`../design/RESUME-DOSSIER-2026-07-16.md`](../design/RESUME-DOSSIER-2026-07-16.md)).
> **This pivot is a recorded decision, NOT yet implemented in the tree** —
> `os/package.nix` / `os/seal-gate.nix` still carry the FOD block, `flake.lock`
> is still the empty seed, and **no OS image has ever been built or booted.**
> The rung ladder is otherwise unchanged; only the FOD-fill sub-step is retired.

---

## 1. Box specs (what to provision)

| Requirement | Value | Why |
|---|---|---|
| OS | Linux (x86_64), any distro with working `/dev/kvm` | Nix + QEMU-KVM + Android emulator all need it |
| Nix | ≥ 2.18, flakes enabled (`experimental-features = nix-command flakes`) | `flake.nix` is a flakes-only root flake |
| QEMU | `qemu-system-x86_64` + `qemu-system-aarch64`, TCG (KVM optional but speeds x86) | node/desktop ISO boot + mobile image boot |
| KVM | `/dev/kvm` present, user in `kvm` group | Android emulator (t1 CI jobs are `bloch-android-vm`-tagged and gated on this) |
| Disk | ≥ 200 GB free (Nix store grows fast: node + desktop + mobile + attested + cloud + seal-gate derivations, plus Android SDK/NDK/emulator images ~15–20 GB) | avoid mid-run ENOSPC |
| RAM | ≥ 32 GB (16 GB floor) | parallel Nix builds + a 2–4 GB QEMU guest + a 2–4 GB Android emulator concurrently |
| Android SDK | platform 34, build-tools 34.0.0, platform-tools 34.0.5, NDK r26b (26.1.10909125), cmdline-tools 11.0 | pinned exactly in `android-container/profile/toolchain/flake.nix`; matches `compileSdk`/`targetSdk 34` in the Gradle files |
| Android system image | `system-images;android-34;google_apis;x86_64` (NOT `google_apis_playstore`) | Play-store images block self-enrolled DPC provisioning — documented gotcha already caught in-repo |
| Cargo/Rust | stable toolchain (`rustup`), matches `.gitlab-ci.yml`'s `bloch-mac` runner expectations | Rust workspace build + the courier live-onion test |
| Network egress | required for: `nix build` (fetches nixpkgs/mobile-nixos), `waydroid init` (pulls Android image over network — by design, non-attestable), Tor bootstrap (courier onion test) | disclosed in-repo as the "network is a trust boundary" caveat for Sloboda/courier |
| Git access | read access to `gitlab.com/blochsispow-group/BlochSISPoW-project` (the ownerless protocol git dependency; `bloch`/`bloch-crypto`/`pqcrypto-internals`) | needed for `cargo build`, `nix build .#seal-gate`, and anything pulling the protocol crate |

**Provisioning steps (ordered):**
1. Install Nix (multi-user), enable flakes, add operator to `nixbld`.
2. Install/confirm `qemu-system-x86_64`, `qemu-system-aarch64`, `/dev/kvm` perms.
3. Clone the repo at `roadmap/fleet2-integrate` (or the branch the operator has
   integrated bucket-A prep into) to a fresh directory — do **not** reuse a
   macOS-created worktree; `flake.lock` and Nix store paths must originate here.
4. Confirm outbound network to github.com (nixpkgs/mobile-nixos), gitlab.com
   (protocol dep), and the Tor network (courier test) is not firewalled.
5. `xorriso` should be present (or `bsdtar`/`7z`) for the x86 boot harness's
   ISO kernel/initrd extraction path — install via the devshell/system pkgs.

---

## 2. Ordered command sequence + what goes GREEN at each step

This is one dependency-ordered ladder. Each rung's "GREEN signal" is the
observable, falsifiable thing to look for — not a vibe.

### Rung 0 — flake freeze (prerequisite for everything Nix)
```sh
scripts/flake-lock.sh                 # freezes nixpkgs (24.05) + mobile-nixos revs
git add flake.lock && git commit -m "flake.lock: freeze nixpkgs 24.05 + mobile-nixos"
scripts/flake-check.sh                # host system
scripts/flake-check.sh --all          # all systems
```
**GREEN:** `flake.lock` is no longer the empty seed (`{"nodes":{"root":{}},...}`)
— it has real revs + `narHash` per input. `flake-check.sh` exits 0 (note: does
NOT go fully green until Rung 3 fills the seal-gate hashes — documented,
intentional cross-dependency).

### Rung 1 — OS image builds (depends on Rung 0)
```sh
nix build .#iso                       # node appliance ISO
nix build .#desktop-iso               # hardened GNOME desktop ISO
nix build .#mobile-image              # aarch64 PinePhone image (native aarch64 or cross)
nix build .#attested-image            # dm-verity/UKI measured-boot image
nix build .#cloud-image               # Chiostro confidential-VM guest
```
**GREEN:** each produces a `/nix/store/...` output path (`--print-out-paths`);
`.iso`/image files exist under the result dir. This is `built`, explicitly
**not** `booted` — do not conflate.

### Rung 2 — QEMU boot harnesses (depends on Rung 1)
```sh
nix run .#boot-qemu                                       # aarch64 mobile image
./os/boot-harness-x86/boot-qemu-x86_64.sh --variant node
./os/boot-harness-x86/boot-qemu-x86_64.sh --variant desktop
```
**GREEN:** `check-boot-log.sh` grades the captured serial log against
`success-markers*.txt` and exits 0 — kernel → stage-1 → systemd → getty (or
GDM greeter for desktop) found in order, no panic/emergency-mode markers. A
`.evidence` sidecar (image path, nix hash, sha256, timestamp) is written next
to the log — **commit both** as the first real boot evidence (this closes gap
backlog item #17, the one confirmed x86 overclaim).

### Rung 3 — Seal gate + roothash (depends on Rung 0/1)
> **FOD sub-step superseded — see the banner at the top of this file.** Under
> the protocol-repo-flake path `os/seal-gate.nix` has no `lib.fakeHash`
> sentinels, so the `fill-outputhashes.sh` line is retired; run `nix build
> .#seal-gate` directly. The old FOD command is left below for history.
```sh
./os/seal-gate/fill-outputhashes.sh   # SUPERSEDED (dead FOD path): first run FAILS by design, fills 5 lib.fakeHash sentinels
nix build .#seal-gate                 # postern-seal-gate + postern-seal-verify
R=$(./os/attested/extract-roothash.sh -f . -a attested-image --bind)
```
**GREEN (seal-gate):** clean `nix build .#seal-gate`; `git diff os/seal-gate.nix`
shows 5 real `sha256-…` values, zero `lib.fakeHash` left. Watch for the
documented dual-git-rev Cargo.lock collision (`fill-outputhashes.sh` exits 3 if
hit — needs a `cargo update` dedupe pass, coordinate before regenerating the
repo-wide `Cargo.lock`).
**GREEN (roothash):** a 64-lowercase-hex `os_roothash`, stable across PASS 1
and PASS 2 (the script asserts this itself and dies loudly if not). Pin this
as `Expected.os_roothash` — it stops being a design-reference placeholder here.

### Rung 4 — Boot-binding verification (depends on Rung 2 + Rung 3; run INSIDE the booted attested guest)
```sh
./os/attested/verify-boot-binding.sh -r "$R" -p 8645
```
**GREEN:** `A/cmdline` PASS + `B/report` PASS (software chain — VM-provable).
`C/PCR` will `skip` under plain QEMU/TCG (no vTPM) — that is expected and
correct, not a failure; measured-boot (PCR-to-reference compare) stays
hardware-gated and out of box-day scope unless real TPM2/SEV-SNP/TDX hardware
is also provisioned.

### Rung 5 — Two-builder reproduction (depends on Rung 0, needs a SECOND Nix host)
```sh
# Builder A: nix build .#iso --print-out-paths ; nix path-info --json ./result
# Builder B (fresh host, same commit incl. frozen flake.lock): repeat
```
**GREEN:** `hashA == hashB` store paths for `.#iso` (repeat for `.#desktop-iso`,
`.#mobile-image`, `.#attested-image`, `.#cloud-image`). This is the only thing
that turns "reproducible-by-design" into "reproduced" (backlog item #19). If
only one box is provisioned, this rung is deferred — flag it explicitly in the
readiness report, do not skip silently.

### Rung 6 — Android static gate (no SDK needed — can run before/without Android SDK is up)
```sh
shellcheck android-container/profile/test/e2e/provision-lifecycle.sh
sh -n android-container/profile/gradlew
python3 -c "import tomllib; tomllib.load(open('android-container/profile/gradle/libs.versions.toml','rb'))"
```
**GREEN:** matches `.gitlab-ci.yml`'s `t0:android-static` job exactly — this is
the one Android check that is already a real gate today (runs on `bloch-mac`).
Not box-gated; useful as a pre-flight before Rung 7.

### Rung 7 — Android assemble (depends on box's Android SDK/NDK; independent of Rungs 1–5)
```sh
cd android-container/profile/toolchain && nix develop --command bash -c \
  "cd .. && gradle wrapper --gradle-version 8.9 --distribution-type bin && \
   ./gradlew :app:assembleDebug :app:assembleDebugAndroidTest"     # Porog
# repeat for android-bridge/persona (NoporIS) once its own toolchain flake exists (see PARTITION.md gap)
```
**GREEN:** `app/build/outputs/apk/**/*.apk` produced; mirrors `.gitlab-ci.yml`'s
`t1:android-assemble-debug` job (currently `when: manual`, tagged for a
`bloch-android-vm` runner that "does not exist yet" per the CI file's own
comment — the box **is** that runner once provisioned).

### Rung 8 — Android instrumented tests (depends on Rung 7 + a KVM emulator)
```sh
cd android-container/profile/toolchain && nix run .#avd &         # boots google_apis API-34 AVD
nix develop --command bash -c \
  "adb wait-for-device && cd .. && ./test/e2e/provision-lifecycle.sh \
   --apk app/build/outputs/apk/debug/app-debug.apk \
   --test-apk app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk"
```
**GREEN:** `ProfileLifecycleE2ETest` runs INSIDE the provisioned managed
profile (`am instrument --user <id>`) and reports PASS, not a SKIP
(`assumeTrue` guards make it honestly skip off-device — a green skip is not a
green proof). Mirrors `.gitlab-ci.yml`'s `t1:profile-lifecycle-e2e`.

### Rung 9 — Waydroid (Sloboda) boot (independent of OS-image rungs; needs binder-capable kernel)
```sh
nix build .#nixosConfigurations.sloboda-vm.config.system.build.vm
./result/bin/run-sloboda-vm-vm
# inside the guest:
zgrep -E 'ANDROID_BINDER_IPC|BINDERFS' /proc/config.gz     # both =y
ls /dev/binderfs
sudo waydroid init -s VANILLA                              # pulls image over network
PAW_VM_SMOKE=1 sh scripts/vm/sloboda-waydroid-boot-smoke.sh
```
**GREEN:** `sloboda-waydroid-boot-smoke.sh` exits 0 (not 77-skip) — real
`waydroid` (not the mock) on PATH, session reaches `Session: RUNNING`, app
list/launch + host launchers + kill-switch all assert against the real
container. Explicitly NON-attestable and outside the sealed closure — this is
correct by design (`os/sloboda-compat.nix`'s seal-exclusion assertion trips if
misconfigured onto a read-only sealed root).

### Rung 10 — Tor courier onion, live (independent — just cargo + network, no Nix/QEMU required)
```sh
cargo test -p postern-courier --features onion-transport -- --ignored --nocapture
```
**GREEN:** `live_onion_drop_end_to_end` passes — a real ephemeral `.onion`
service is published (arti), a second in-process Tor client connects, fetches,
and opens the sealed drop. This test needs live Tor bootstrap (minutes) and
network egress; it is `#[ignore]`d in CI on purpose. Can run in parallel with
any OS-image rung once Rust toolchain + network are confirmed — does not block
or get blocked by Nix/QEMU work.

---

## 3. Dependency graph

```
Rung 0 (flake freeze)
  ├─→ Rung 1 (nix build .#iso/.#desktop-iso/.#mobile-image/.#attested-image/.#cloud-image)
  │     ├─→ Rung 2 (QEMU boot harnesses: aarch64 + x86 node/desktop)
  │     ├─→ Rung 3 (seal-gate build + roothash extract)
  │     │     └─→ Rung 4 (boot-binding verify — needs Rung 2's booted attested guest + Rung 3's R)
  │     └─→ Rung 5 (two-builder repro — needs a 2nd Nix host)
  │
Rung 6 (Android static gate) ─→ Rung 7 (gradlew assemble) ─→ Rung 8 (instrumented tests)

Rung 9 (Waydroid/Sloboda boot) — independent, only needs binder kernel + network
Rung 10 (Tor courier onion, live) — independent, only needs cargo + network
```

Rungs 6–8, 9, and 10 have **no dependency** on Rungs 0–5 and can run in
parallel on the same box (different terminals/CI jobs) as long as disk/RAM
budget holds. Rung 5 needs a second machine and is the one rung box-day alone
cannot fully close — flag it, don't skip it silently.

## 4. What does NOT go green on box-day, by design

- **Hardware boot** (PinePhone, bare-metal x86) — HW-gated, a separate rung
  entirely outside "one Linux+Nix+QEMU box."
- **TPM2 PCR-to-reference compare / real SEV-SNP or TDX quote** — Rung 4's `C`
  check will `skip` under TCG; this is correct, not a bug to chase on box-day.
- **StrongBox key-attestation on a real device** — emulator has no StrongBox;
  `mobile-attest` stays fixture-only until real Android hardware is added.
- **NoporIS (`android-bridge/persona`) has no toolchain flake yet** — Porog's
  `android-container/profile/toolchain/flake.nix` is the only pinned Android
  devshell in-repo today. Dev B's box-day work includes cloning/adapting it for
  `android-bridge/persona` (see PARTITION.md) before Rung 7/8 can target NoporIS.
