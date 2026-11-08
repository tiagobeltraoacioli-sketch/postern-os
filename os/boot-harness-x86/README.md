<!--
SPDX-License-Identifier: MIT OR Apache-2.0
Postern OS — QEMU-x86_64 live-ISO boot harness.
UNAUDITED / SCAFFOLD reference-prototype. built != booted; QEMU != hardware;
reproducible-by-design != reproduced. First run 2026-07-14 on postern-os-build
(TCG) — see evidence/ — graded PASS for the NODE ISO only. The desktop ISO and
real hardware remain unrun; the dev host is still macOS (no Nix/QEMU/KVM).
-->

# Postern OS — QEMU-x86_64 boot harness (the honesty fix)

## Why this exists

The site says the node and desktop ISOs are **"boot-validated on QEMU
x86_64."** Before this directory, **no x86 boot harness and no committed x86
boot evidence existed in the repo** — the claim was unbacked (gap-backlog item
#17, A1's one genuine site-vs-repo overclaim). This directory is the missing
harness: it makes the claim **reproducible on a Nix+QEMU host** and **captures
the evidence** a green run must produce.

It is the x86_64 mirror of `os/boot-harness/` (the aarch64 / Mobile-NixOS
harness). It boots:

- `.#iso` (`--variant node`) — the node appliance ISO (`os/configuration.nix`
  on the live installer CD) → **Postern OS shell / getty login**.
- `.#desktop-iso` (`--variant desktop`) — the hardened GNOME desktop ISO
  (`os/desktop.nix`) → **GDM / GNOME graphical login**.

It proves the **x86_64 SOFTWARE boot chain only**:

> BIOS/bootloader → kernel → **NixOS stage-1** → systemd → getty (node) / GDM
> greeter (desktop).

**It proves nothing about real x86 hardware** — TCG emulation models no specific
firmware, TPM, or measured-boot chain. `built != booted`, `QEMU != hardware`,
`reproducible-by-design != reproduced`.

## Honest status — READ THIS

**First run: 2026-07-14 on `postern-os-build` (TCG) — see `evidence/`.** The
dev workstation is still macOS with **no Nix, no QEMU, no KVM**; that run
executed on the Fly `postern-os-build` Linux+Nix host, not here, and on the
mac the only thing that ever ran is `shellcheck` + a **fixture dry-run of the
grader** (see below). The 2026-07-14 run graded **PASS** for the **node** ISO
only (`success-markers-x86.txt`, `check-boot-log.sh` rc 0) — full record,
ISO store path, sha256, and grader output are in `evidence/README.md`. The
**desktop** ISO ladder (`success-markers-x86-desktop.txt`) has **still never
been run** — treat it as WRITTEN, NOT RUN, exactly as before.

That one PASS makes the site's "boot-validated on QEMU x86_64" claim
substantiated **for the node ISO's software boot chain, once, under TCG** —
and nothing more. It is **not** a claim about real x86 hardware, Secure Boot
/ TPM, reproducibility, or the desktop ISO. `built != booted`, `QEMU !=
hardware`, `reproducible-by-design != reproduced` all still hold — see
`evidence/README.md`'s standing caveats before citing this directory as proof
of anything beyond that one graded run.

## Files

| File | What it is |
|---|---|
| `boot-qemu-x86_64.sh` | Builds `.#iso` / `.#desktop-iso`, boots it under `qemu-system-x86_64` (TCG, no KVM), tees the serial console to a log, writes a `*.evidence` sidecar, and grades the log. |
| `success-markers-x86.txt` | The **node** ISO ladder: kernel → stage-1 → systemd → getty. |
| `success-markers-x86-desktop.txt` | The **desktop** ISO ladder: same base + the GDM/GNOME graphical-login rung. |
| `fixtures/` | Hand-written serial logs (`node-pass`, `desktop-pass`, `node-fail-panic`) used for the on-mac grader dry-run. **Synthetic — NOT real boot output.** |
| `evidence/` | Real captured serial logs + `.evidence` sidecars from graded runs, indexed in `evidence/README.md` (record template + the 2026-07-14 node PASS + standing caveats). This is the only place a "boot-validated" claim can be checked against a committed log — the first run of this harness (node, 2026-07-14) lives there. |

**Consumed READ-ONLY** (never edited here): `../boot-harness/check-boot-log.sh`
— Dev O4's shared grader. Using the same grader + the same marker file format
means "booted" means the same thing on x86_64 and aarch64. Any grader change
this harness needs is **requested from O4**, not written here.

## Run (on a Linux host with Nix + flakes + qemu-system-x86_64)

```sh
# From the repo root. Also available as: nix run .#boot-qemu-x86
./os/boot-harness-x86/boot-qemu-x86_64.sh --variant node
./os/boot-harness-x86/boot-qemu-x86_64.sh --variant desktop

# Against a prebuilt ISO (skips nix build):
./os/boot-harness-x86/boot-qemu-x86_64.sh --variant node \
    --iso /nix/store/…-nixos.iso --log /tmp/x86-node.log
```

The macOS workstation **cannot** run this — `qemu-system-x86_64` is absent, so
the script exits `5` ("missing tool") before it ever pretends to boot.

### Serial capture: how it forces a headless console

A NixOS live ISO does not reliably enable a serial getty on its own, and the
grader reads the **serial** log. So the harness, by default, **extracts the
kernel + initrd from the ISO** (via `xorriso` / `bsdtar` / `7z`), reuses the
ISO's own kernel command line (which carries the exact `init=/nix/store/…-init`
path the live root needs), strips any `console=`, and appends
`console=ttyS0,115200` — then boots with `-kernel/-initrd/-append` plus the ISO
attached as a CD so stage-1 finds the live squashfs. If no extractor is present
it falls back to a plain `-cdrom` boot and **warns** that the serial log may be
empty (which the grader will then correctly FAIL). Install `xorriso` on the VM
for the reliable path.

### Eyeballing the desktop greeter

`--variant desktop` grades the **GDM/GNOME journal lines on the serial console**
(unit-start markers) — it does **not** scrape pixels. To actually see the
greeter, drop `-nographic` and attach a display (edit the `boot()` invocation or
run QEMU by hand with `-vga std -display gtk`), then screenshot it as
supplementary evidence.

## Definition of done (mirrors the aarch64 Rung 1)

1. **Marker ladder passes.** `check-boot-log.sh` finds, in order:
   `Linux version` → NixOS stage-1 → `systemd[1]:` → `Reached target` → getty
   (node) / GDM greeter (desktop), and finds **no** `Kernel panic`,
   `Entering emergency mode`, `Unable to mount root fs`, or stage-1 emergency
   shell. (Exit `0`.)
2. **Functional check (interactive / CI-expect follow-up, not done here):**
   node → `bloch-wallet --help` prints usage on the console; desktop → the GDM
   greeter is drawn. The headless harness proves boot-to-login; it does not type
   into the console.
3. **Evidence kept.** The serial log + the `*.evidence` sidecar (ISO store path,
   `nix hash`, `sha256`, QEMU/machine, timestamp, boot mode, grader rc) are
   retained and committed as the **first real x86 boot evidence**.
4. **Unattended in CI.** The harness exits non-zero on a failed ladder so a CI
   job can gate on it. Wiring that job (a Linux runner with Nix+QEMU) is a
   separate deliverable — this script is what the job calls.

Exit codes: `0` passed · `1` required marker missing/out of order · `2` failure
marker present · `4` no bootable ISO produced/located · `5` missing tool.

## On-mac dry-run (the HOST ceiling — this is all that ran on the dev workstation)

This section is scoped to the macOS dev workstation only. The 2026-07-14
node-ISO PASS in `evidence/` ran on the Fly `postern-os-build` host, not
here — see the "Honest status" section above and `evidence/README.md`. On
the mac, `shellcheck` is clean, and the grader was exercised against the
fixtures:

```sh
cd os/boot-harness-x86
sh ../boot-harness/check-boot-log.sh fixtures/node-pass.log        success-markers-x86.txt          # rc 0 PASS
sh ../boot-harness/check-boot-log.sh fixtures/desktop-pass.log     success-markers-x86-desktop.txt  # rc 0 PASS
sh ../boot-harness/check-boot-log.sh fixtures/node-fail-panic.log  success-markers-x86.txt          # rc 2 FAIL (panic)
```

This proves the **marker files parse under O4's grader and the ladder logic is
sound** — it proves **nothing about an actual boot.** The fixtures are
hand-written, not captured from QEMU.

## Flake wiring (requested from Dev O2 — flake owner)

`flake.nix` has exactly one owner (O2). This harness needs a new app attribute;
the snippet to add, mirroring the existing `apps.aarch64-linux.boot-qemu`:

```nix
# nix run .#boot-qemu-x86 -- [--variant node|desktop]
apps.x86_64-linux.boot-qemu-x86 =
  let pkgs = import nixpkgs { system = "x86_64-linux"; };
  in {
    type = "app";
    program = "${pkgs.writeShellApplication {
      name = "postern-boot-qemu-x86_64";
      runtimeInputs = [
        pkgs.qemu pkgs.coreutils pkgs.gnugrep pkgs.gawk
        pkgs.libarchive   # bsdtar, for extracting kernel+initrd from the ISO
        pkgs.xorriso      # preferred ISO extractor
        pkgs.nix
      ];
      text = builtins.readFile ./os/boot-harness-x86/boot-qemu-x86_64.sh;
    }}/bin/postern-boot-qemu-x86_64";
  };
```

## What a green run does NOT prove

- Real x86 firmware, Secure Boot, TPM2 / measured boot — none are modeled by
  TCG. Attestation is a separate chain (`os/attested.nix`).
- Reproducibility — nobody has rebuilt the ISO to a matching hash;
  reproducible-by-design != reproduced.
- The desktop being *usable* — a graded GDM-greeter journal line is boot-to-
  login, not a working session, apps, or input devices.
