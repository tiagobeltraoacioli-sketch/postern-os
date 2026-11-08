<!--
SPDX-License-Identifier: MIT OR Apache-2.0
Postern OS — x86_64 boot-harness evidence log.
UNAUDITED / SCAFFOLD. One graded run is not a fleet, a hardware boot, or a
reproducibility claim. Read every record's caveats before citing it anywhere.
-->

# Boot evidence — os/boot-harness-x86

This directory holds the **raw artifacts** a graded run of
`boot-qemu-x86_64.sh` (or a manual harness-equivalent replay of it) produces,
plus this index of what each run does and does not prove. It is the only
place in the repo where the x86 "boot-validated" claim can be checked against
a real, committed serial log — see `../README.md` for the harness itself and
`../success-markers-x86.txt` / `../success-markers-x86-desktop.txt` for the
grading ladders.

**Standing caveats — apply to every record below, verbatim, no exceptions:**

- `built != booted` — a `nix build` producing an ISO proves nothing about
  whether that ISO boots.
- `QEMU/TCG != hardware` — TCG software emulation models no specific x86
  firmware, TPM, or measured-boot chain. It proves the software boot chain
  only (BIOS/bootloader → kernel → stage-1 → systemd → login), never real
  hardware.
- `reproducible-by-design != reproduced` — nobody has independently rebuilt
  the graded ISO to a matching hash. "Nix should be reproducible" is not
  evidence that this build was.
- **unaudited scaffold** — this harness, its grader, and this evidence
  directory have not been security- or correctness-audited. Treat every PASS
  here as "the procedure worked once," not as a certification.

A record below proves exactly what its own row says and nothing more. A PASS
for the **node** ISO says nothing about the **desktop** ISO or vice versa;
each variant needs its own graded record.

## Record template

Copy this block per run and fill it in from the `*.evidence` sidecar the
harness (or its manual equivalent) writes:

```
### <variant> — <date, UTC> — <PASS|FAIL>

- date            : <ISO-8601 UTC timestamp>
- Fly host        : <e.g. postern-os-build (Fly Linux+Nix builder)>
- kernel/uname    : <e.g. Linux 6.12.91-fly x86_64>
- git rev         : <full sha> (branch: <branch>)
- iso store path  : <full /nix/store/... path to the .iso>
- iso sha256      : <sha256 of the .iso file>
- qemu            : <qemu-system-x86_64 version + machine/accel flags>
- markers file    : <success-markers-x86*.txt used>
- grader          : os/boot-harness/check-boot-log.sh (Dev O4, read-only), rc=<n>
- log file        : <path to the committed serial log, this directory>
- evidence sidecar: <path to the .evidence file, this directory>
- verdict         : <PASS|FAIL> — <one-line grader summary>

Caveats: built != booted; QEMU/TCG != hardware; reproducible-by-design != reproduced;
unaudited scaffold. This run proves the x86_64 SOFTWARE boot chain only, under
TCG, for the <variant> ISO, once. It proves nothing about real x86 hardware,
Secure Boot / TPM, reproducibility, or any other ISO variant.
```

## Records

### node — 2026-07-14 — PASS

- date            : 2026-07-14T19:31:32Z
- Fly host        : `postern-os-build` (Fly Linux+Nix builder)
- kernel/uname    : Linux 6.12.91-fly x86_64
- git rev         : `b366c4a93052394d9b546672003fd3d36c218b08` (branch: `roadmap/consolidate-all`)
- iso store path  : `/nix/store/b4kik0zalx9jmwbb4ifaiz5800hdhfk9-nixos-minimal-25.05.20260102.ac62194-x86_64-linux.iso/iso/nixos-minimal-25.05.20260102.ac62194-x86_64-linux.iso`
- iso sha256      : `8f575705fd437314c9f2dd4a873d523890294b36e3fc323df54cbfea026c0f4b`
- qemu            : QEMU emulator version 10.0.8 (Debian 1:10.0.8+ds-0+deb13u1+b2); `-machine q35,accel=tcg -cpu max -m 3072 -smp 2`
- markers file    : `success-markers-x86.txt` (node ladder)
- grader          : `os/boot-harness/check-boot-log.sh`, rc=0
- log file        : `evidence/x86-boot-node.log`
- evidence sidecar: `evidence/x86-boot-node.evidence`
- verdict         : **PASS** — all 5 required markers matched in order
  (`Linux version` → `<<< NixOS Stage 1 >>>` → `systemd[1]:` → `Reached
  target` → `postern-os login:` / Postern OS MOTD), no failure marker present.
  The log shows the boot reaching `postern-os login: nixos (automatic
  login)` and an interactive prompt before QEMU was terminated by the
  harness's own timeout (`qemu-system-x86_64: terminating on signal 15 …
  (timeout)` — this is the harness killing a boot that had already
  succeeded, not a boot failure; the sidecar's `boot_rc: 124` reflects that
  `timeout` exit code, while `check_rc: 0` is the grader's verdict on the log
  content).

  **Provenance note:** per the evidence sidecar, the packaged
  `boot-qemu-x86_64.sh` had a kernel/initrd-path bug for the 25.05 node ISO
  layout (fixed in-repo — see the "FOUND ON THE FIRST REAL RUN" comment in
  `../boot-qemu-x86_64.sh`); this specific run was a **manual
  harness-equivalent replay** of the script's corrected kernel+initrd branch
  on the Fly host, using a prior-green store ISO (the sidecar notes the
  *current* tree's `.#iso` build was red at replay time — this record backs
  the boot chain for the graded ISO above, not a claim that today's tree
  builds it).

  Caveats: built != booted; QEMU/TCG != hardware; reproducible-by-design !=
  reproduced; unaudited scaffold. This proves the x86_64 SOFTWARE boot chain
  only, under TCG, for the **node** ISO, once, on 2026-07-14. It proves
  nothing about real x86 hardware, Secure Boot / TPM, reproducibility, the
  **desktop** ISO (`success-markers-x86-desktop.txt` — still WRITTEN, NOT
  RUN), or that the current working tree's `.#iso` target builds cleanly.

### desktop — not yet run

No record. `success-markers-x86-desktop.txt` remains WRITTEN, NOT RUN — no
graded log exists for the desktop/GDM ladder. Do not infer a desktop PASS
from the node PASS above; they are different targets graded by different
marker files.
