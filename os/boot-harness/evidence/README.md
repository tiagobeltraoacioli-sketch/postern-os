<!--
SPDX-License-Identifier: MIT OR Apache-2.0
Postern OS Mobile — QEMU-aarch64 boot-harness evidence log.
UNAUDITED / SCAFFOLD. One recorded attempt is not a boot, a phone, or a
reproducibility claim. Read every record's caveats before citing it anywhere.
-->

# Boot evidence — os/boot-harness (QEMU-aarch64, Postern OS Mobile)

This directory holds the **raw artifacts** a graded run (or graded *attempt*)
of `boot-qemu-aarch64.sh` produces, plus this index of what each record does
and does not prove. It is the only place in the repo where any aarch64/mobile
boot claim can be checked against a committed log — see `../README.md` for the
harness itself and `../success-markers.txt` for the shared grading ladder. It
mirrors `os/boot-harness-x86/evidence/`, whose standing-caveats block is
reproduced below (the QEMU/TCG bullet restated for this rung's `-M virt`
board and "ISO" → "image"; the other bullets verbatim).

**Standing caveats — apply to every record below, verbatim, no exceptions:**

- `built != booted` — a `nix build` producing an image proves nothing about
  whether that image boots.
- `QEMU/TCG != hardware` — TCG software emulation with `-M virt` models **NO
  PinePhone device tree, DSI display, touch, modem, or power**. It proves the
  software boot chain only (bootloader → kernel → stage-1 → systemd → login),
  never real hardware.
- `reproducible-by-design != reproduced` — nobody has independently rebuilt
  any graded image to a matching hash. "Nix should be reproducible" is not
  evidence that this build was.
- **unaudited scaffold** — this harness, its grader, and this evidence
  directory have not been security- or correctness-audited. Treat every PASS
  here as "the procedure worked once," not as a certification.

A record below proves exactly what its own row says and nothing more. A
FAILED-attempt record proves only that the attempt was made and where it
stopped; a PASS here would still say nothing about a PinePhone.

## Records

### mobile — 2026-07-14 — FAIL (rung 0: flake eval — no image, no boot, QEMU never launched)

- date            : 2026-07-14T22:52:43Z
- Fly host        : `postern-os-build` (Fly Linux+Nix builder — the same host
  that produced `os/boot-harness-x86/evidence/x86-boot-node.evidence`)
- kernel/uname    : Linux 6.12.91-fly x86_64
- git rev         : `b366c4a93052394d9b546672003fd3d36c218b08` (branch:
  `roadmap/consolidate-all`; working tree dirty: `flake.lock` only — see
  provenance note below)
- image store path: **none** — rung 0 failed; no artifact was produced
- image nix hash / sha256 : n/a — nothing to hash
- qemu            : QEMU emulator version 10.0.8 (Debian
  1:10.0.8+ds-0+deb13u1+b2); `qemu-system-aarch64` was installed on the host
  for this attempt but **NEVER LAUNCHED** (harness defaults would have been
  `-M virt -cpu cortex-a53 -m 2048 -smp 2`, TCG, no KVM)
- markers file    : `success-markers.txt` (unmodified)
- grader          : `os/boot-harness/check-boot-log.sh` (unmodified,
  read-only), rc=1 — all four required markers missing, as expected for a log
  that contains no serial output at all
- log file        : `evidence/aarch64-mobile-boot.log` (truncated attempt log:
  harness output + flake eval error; **no serial console output exists**)
- evidence sidecar: `evidence/aarch64-mobile-boot.evidence`
- verdict         : **FAIL at rung 0** — the ladder never started. This is the
  first time `os/boot-harness/` was ever run against a real host (it was
  WRITTEN/READY, NOT RUN until this attempt), and it stopped before QEMU:

  1. **Harness verbatim** (`./os/boot-harness/boot-qemu-aarch64.sh`): exits
     `4`. Its `nix build .#mobile-image` line cannot resolve on an x86_64
     host — the flake exposes `mobile-image` under
     `packages.aarch64-linux` only, so on the x86_64 builder (binfmt
     qemu-user, `extra-platforms = aarch64-linux`) the attribute lookup
     itself fails. FOUND ON THE FIRST REAL RUN, same class of first-contact
     bug as the x86 harness's kernel-path bug; the harness script is owned by
     the harness dev and was **not** modified for this record.
  2. **Harness-equivalent cross attempt**
     (`nix build .#packages.aarch64-linux.mobile-image`): fails at flake
     **evaluation** — `The option 'services.bloch' does not exist`.
     `os/mobile.nix` sets `services.bloch.enable = lib.mkForce false` but the
     `evalMobile` configuration in `flake.nix` never imports
     `os/bloch-node.nix` (which defines that option). Rung 0 is red in the
     tree itself, before any build, download, or boot.

  **Provenance notes:** (a) the committed `flake.lock` contains **no
  `mobile-nixos` node at all**; the host's dirty `flake.lock` (the only local
  modification) pins `github:mobile-nixos/mobile-nixos/2c132754323fc1915e8d21dcfc0ef68ab084c6fb`,
  and without some such pin the eval cannot even start. (b) An earlier
  off-record build attempt on this host (`/root/mobile-build.log`,
  2026-07-11) failed at a *different* eval point (a missing `svgo` argument
  inside the pinned mobile-nixos `gui-assets`), so at least one further
  eval blocker is known to sit behind the `services.bloch` one. (c)
  `check_rc: 1` in the sidecar is the real grader verdict on the committed
  log — a log with no boot in it correctly fails the ladder; nothing was
  edited to change any verdict.

  Caveats: built != booted; QEMU/TCG != hardware; reproducible-by-design !=
  reproduced; unaudited scaffold. This record proves ONLY that the first-ever
  run of this harness was attempted on 2026-07-14 on a real Linux+Nix host
  and failed at rung 0 (flake eval), exactly as committed here. It proves
  nothing about the image (none exists), QEMU behaviour (never launched), the
  PinePhone, telephony, attestation, or reproducibility. The blockers are in
  `flake.nix` / `os/mobile.nix` / `flake.lock` — outside this evidence
  directory's ownership — and must be fixed there before a rung-1 boot can be
  re-attempted.

### mobile — 2026-07-14 — FOURTH ATTEMPT sidecar entry (svgo overlay fix; still FAIL, unverified)

- The sidecar `aarch64-mobile-boot.evidence` now carries SECOND/THIRD/FOURTH
  ATTEMPT entries. The THIRD ATTEMPT (real Nix host, dry-run eval) verified
  fix_2 and surfaced the next blocker: the pinned mobile-nixos `gui-assets`
  needs a top-level `pkgs.svgo` that the pinned nixos-25.05 does not have.
- The FOURTH ATTEMPT records fix_3: a new nixpkgs overlay
  `os/overlays/svgo.nix` (wired via `nixpkgs.overlays` in `os/mobile.nix`)
  maps `svgo = prev.svgo or final.nodePackages.svgo`. **Unverified fix —
  pending a Nix host**: applied on a macOS workstation with no Nix, so no
  eval or build was re-run; rung 0 remains FAIL / unverified-fix-applied.
  `../verify-mobile-eval-fix.sh` Path A (a real `nix build` on a Nix host) is
  the only thing that may upgrade that status; Path B statically grades the
  fix's presence and the sidecar's honesty only. All standing caveats above
  apply verbatim.
