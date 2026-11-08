<!--
SPDX-License-Identifier: MIT OR Apache-2.0
Postern OS Mobile — QEMU-aarch64 boot harness (Rung 1)
UNAUDITED reference-prototype. built ≠ booted; QEMU ≠ hardware;
reproducible-by-design ≠ reproduced. Never run on the dev host (no Nix/KVM).
-->

# Postern OS Mobile — QEMU-aarch64 boot harness (Rung 1)

The reproducible first-boot check for the **Postern OS Mobile** image — the
Mobile-NixOS `.#mobile-image` (device `pine64-pinephone`). It proves the
**software boot chain** only:

> bootloader → kernel → **Mobile-NixOS stage-1** → systemd → getty / login.

**It proves nothing about a phone.** `qemu-system-aarch64 -M virt` models no
PinePhone device tree, DSI display, touch, modem, or power. **QEMU ≠ hardware.**
The device half is a separate rung (real PinePhone + UART serial + photo),
owned by the hardware-rung dev.

Naming: "Postern OS Mobile" is *only* this reproducible Mobile-NixOS image. The
Alpine/postmarketOS build in `pmos-overlay/` is "Postern for postmarketOS —
community edition" and is **never** "Postern OS".

## Files

| File | What it is |
|---|---|
| `boot-qemu-aarch64.sh` | Builds `.#mobile-image`, boots it under `qemu-system-aarch64` (TCG, no KVM), tees the serial console to a log, writes an evidence sidecar, and grades the log. |
| `check-boot-log.sh` | Grades any serial log against `success-markers.txt`. **Shared** with the hardware rung (and the x86_64 rung, read-only) so all agree on what "booted" means. |
| `success-markers.txt` | The **shared** required-success / must-not-appear grep contract. Jointly owned — neither rung keeps a private list. |
| `run-fixture-tests.sh` | **HOST self-test.** Feeds the grader the `fixtures/*.log` synthetic logs and asserts each expected exit code. Proves the grader LOGIC on a machine with no Nix/QEMU. Runs on the mac. |
| `fixtures/*.log` | Hand-written synthetic serial logs (a passing ladder + one per failure mode). **Not real boots** — inputs to the self-test only. |

## HOST proof — the grader is self-tested (runs on the mac, no boot)

The QEMU boot is VM-gated, but the **grader's logic is pure shell and is
HOST-provable**. `run-fixture-tests.sh` grades seven hand-written fixtures whose
verdicts are known in advance and asserts the exit code for each, covering the
whole contract (0 pass · 1 missing/out-of-order · 2 failure-marker · 3 usage):

```sh
./os/boot-harness/run-fixture-tests.sh   # => "8 passed, 0 failed" ; exit 0
shellcheck os/boot-harness/*.sh          # => clean
```

This proves the grader **logic** only — that it accepts a good ladder, rejects a
missing/out-of-order one, and lets any failure marker veto an otherwise-complete
ladder. It boots **nothing**. `grader-logic-correct ≠ image-boots`.

## Run the actual boot (VM-gated — first QEMU/TCG attempt recorded, see below)

**Status 2026-07-14 — first QEMU/TCG attempt recorded, see `evidence/`:
FAILED at rung 0 (flake eval — no image built, QEMU never launched).** The
harness was run for the first time ever on the Fly Linux+Nix builder
(`postern-os-build`, the x86-evidence host): the verbatim script exits `4`
because `.#mobile-image` only exists under `packages.aarch64-linux` (not
resolvable from an x86_64 host — first-real-run finding, script unmodified),
and the harness-equivalent `nix build .#packages.aarch64-linux.mobile-image`
fails at evaluation (`services.bloch` option undefined in the mobile eval;
the committed `flake.lock` also lacks a `mobile-nixos` pin). Full record,
truncated log, and sidecar: `evidence/README.md`,
`evidence/aarch64-mobile-boot.log`, `evidence/aarch64-mobile-boot.evidence`.
No boot has ever been graded green on this rung.

On a Linux host with Nix + flakes + qemu-system-aarch64:

```sh
# From the repo root. Also available as: nix run .#boot-qemu
./os/boot-harness/boot-qemu-aarch64.sh
# or against a prebuilt artifact:
./os/boot-harness/boot-qemu-aarch64.sh --image /nix/store/…-mobile-image --log /tmp/boot.log
```

The macOS workstation **cannot** run this (no Nix kernel, no KVM, no
qemu-system). Use a Linux host — ideally aarch64, or x86_64 with `binfmt_misc` +
qemu-user for the *build* (see `pmos-overlay/setup-aarch64.sh`); the *boot* here
is `qemu-system` under TCG.

## Definition of done (Rung 1)

1. **Marker ladder passes.** `check-boot-log.sh` finds, in order, `Booting Linux
   on physical CPU` → `systemd[1]:` → `Reached target` → login, and finds **no**
   `Kernel panic`, `Entering emergency mode`, `Unable to mount root fs`, or a
   stage-1 emergency shell. (Exit 0.)
2. **Functional check.** On the emulated console `bloch-wallet --help` prints
   usage (the wallet engine loaded) and `systemctl is-system-running` is
   `running` or `degraded` with known reasons. This is an **interactive / CI-
   expect** follow-up — the headless harness proves boot-to-login; it does not
   type into the console.
3. **Evidence kept.** The serial log plus the `*.evidence` sidecar (image store
   path + `nix hash` + `sha256` + QEMU/machine + timestamp) are retained.
4. **Unattended in CI.** The harness exits non-zero on a failed ladder so a CI
   job can gate on it. *Wiring that CI job into `.gitlab-ci.yml` is a separate
   deliverable* (the current runner is a macOS shell runner that cannot boot a
   VM; a Linux runner must be provisioned first) — this script is what the job
   calls.

Exit codes: `0` passed · `1` required marker missing/out of order · `2` failure
marker present · `4` no bootable artifact produced/located · `5` missing tool.

## Prerequisite: Rung 0 (the artifact must exist)

`boot-qemu-aarch64.sh` runs `nix build .#mobile-image` for you, but that output
only exists because of the root `flake.nix` (this front's other deliverable).
If the pinned `mobile-nixos` revision exposes the bootable artifact under a
different attribute than `outputs.default`, adjust the selector in `flake.nix`
and, if it ships kernel+initrd rather than a runner, the harness fallback picks
them up automatically. This is the "APIs evolve; pin its revision" caveat from
`os/MOBILE.md`, made explicit.

## What a green run does NOT prove

- The PinePhone device tree, DSI display, touch, **modem/telephony**, or power —
  none are modeled by QEMU `virt`. The telephony device path
  (`postern-telephony`, `os/telephony.nix`) is **dead** here and only proves out
  on hardware (roadmap B4).
- Attestation / measured boot — a boot is not attestation (`os/attested.nix` is
  a separate, later chain).
- Reproducibility — nobody has rebuilt the image to a matching hash;
  reproducible-by-design ≠ reproduced.

## Self-test (grader only)

`check-boot-log.sh` is the **shared** grader — both the QEMU rung (here) and
the hardware rung feed it a serial log and trust its exit code. Its own
docstring defines a 4-way contract (`0`/`1`/`2`/`3`); the self-test checks
`check-boot-log.sh` against four hand-written fixture logs plus two no-fixture
usage-error cases (six checks total), so a change to the grader's
matching/ordering logic can be caught without building or booting anything.

| Fixture | Exit code | What it exercises |
|---|---|---|
| `fixtures/pass.log` | `0` | All required markers present, in the documented order, and no failure marker anywhere — the happy path. |
| `fixtures/out-of-order.log` | `1` | Every required marker's substring is present, but one appears before the marker that must precede it — the ordered walk must catch this, not just presence. |
| `fixtures/kernel-panic.log` | `2` | Boot reaches the kernel and then panics — the log is truncated, so later required markers are also missing (alone worth `1`), and the `Kernel panic` failure marker must take precedence and report `2`. |
| `fixtures/stage1-emergency.log` | `2` | Mobile-NixOS stage-1 drops to its rescue shell instead of switching root — a second, independent failure-marker path. |
| *(no fixture — no arguments)* | `3` | Usage error: the grader invoked with no log argument at all. |
| *(no fixture — bad markers path)* | `3` | Usage error: a valid log but an unreadable/nonexistent markers file. |

Run it with:

```sh
sh os/boot-harness/test-check-boot-log.sh
```

This runs on the macOS workstation — it needs only `sh`, `grep`, and `awk`
(the same POSIX tools `check-boot-log.sh` itself uses), no Nix, no KVM, no
`qemu-system`, and no built image.

**Caveat:** the fixtures above are hand-written synthetic logs, not captures
from any real or emulated boot. A green self-test proves only that
`check-boot-log.sh` implements the documented `0`/`1`/`2`/`3` exit contract
correctly against those synthetic inputs — it proves **nothing** about any
real boot. It does not touch QEMU, so it says nothing about QEMU ≠ hardware;
it does not touch a build, so it says nothing about built ≠ booted; and it
does not run against a produced image, so the image remains unaudited. Grader
logic correct ≠ image boots.

### `CHECK_BOOT_LOG` override (proving the self-test can actually fail)

`test-check-boot-log.sh` reads an optional `CHECK_BOOT_LOG` environment
variable naming an alternate grader script to run the fixtures against;
unset, it defaults to the real, in-tree `check-boot-log.sh`. This exists
solely so a *mutation check* can prove the self-test genuinely detects a
regressed grader, rather than passing regardless of what the grader does:

```sh
# Outside this repo, on a throwaway copy — never mutate the in-tree grader.
cp check-boot-log.sh /path/to/mutated-copy.sh
# ...neuter some check in the copy (e.g. the ordering awk filter)...
CHECK_BOOT_LOG=/path/to/mutated-copy.sh sh os/boot-harness/test-check-boot-log.sh
# expect: nonzero exit, with the case exercising the neutered check now FAIL.
```

This has been run once, against a scratchpad copy with the ordering check's
`awk` min-line filter neutered (always-accept instead of enforcing order): the
self-test correctly dropped to `5/6`, flagged `out-of-order.log` as `FAIL`,
and exited nonzero. The in-tree `check-boot-log.sh` was only read for that
copy, never modified, and the default (unset `CHECK_BOOT_LOG`) run still
passes `6/6`. No image was built or booted for this check.
