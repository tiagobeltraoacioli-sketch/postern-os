# SPDX-License-Identifier: MIT OR Apache-2.0
#
# os/sloboda-vm.nix — the throwaway DEV/VM bring-up host for the Waydroid tier.
#
# ===========================================================================
# NON-ATTESTABLE DEV/VM HOST — DELIBERATELY OUTSIDE THE POSTERN SEAL CLOSURE
# ===========================================================================
# This is the boot target for Phase 0/1 of the Waydroid bring-up: a minimal
# x86_64 NixOS VM that imports os/sloboda-compat.nix (binder kernel + Waydroid +
# headless Weston) and boots far enough to reach `Session: RUNNING`. It exists
# ONLY to prove control-flow on a binder-capable kernel in QEMU. It is:
#
#   - NOT attested and NOT sealed. Its root is a mutable, writable qcow2 image
#     (systemd/qemu-vm), the exact OPPOSITE of the read-only dm-verity root that
#     os/attested.nix builds. `os_roothash` says NOTHING about this host and
#     cannot: the Android system image is pulled from the network at
#     `waydroid init`, so nothing here is measured, reproducible, or
#     hardware-backed. Do NOT add this host to the attested `postern-cloud` list.
#   - SCAFFOLD · DESIGN ONLY · UNAUDITED · deferred-to-VM. Authored on a non-Nix
#     macOS host; NEVER evaluated, built, or booted here. built ≠ booted;
#     QEMU ≠ hardware. Play Integrity STRONG is EXPECTED to FAIL on this tier —
#     disclosed, never spoofed.
#
# BUILD + BOOT (on a Linux + Nix host — impossible on the macOS workstation):
#   nix build .#nixosConfigurations.sloboda-vm.config.system.build.vm
#   ./result/bin/run-sloboda-vm-vm            # boots the VM under QEMU (software GL)
# Then, inside the guest (see docs/design/waydroid-01-boot-bringup.md §5.2 and
# the honesty header of os/sloboda-compat.nix):
#   zgrep -E 'ANDROID_BINDER_IPC|BINDERFS' /proc/config.gz   # both must be =y
#   ls /dev/binderfs                                          # binder ready
#   sudo waydroid init -s VANILLA                             # image pull (network)
#   sudo sloboda-gate-smoke                                   # accept → start →
#                                                             #   kill THROUGH the gate
# (`sloboda start` without consent must REFUSE — that refusal is the first
#  assertion of the smoke, not a bug.)
# ===========================================================================
{ config, lib, pkgs, modulesPath, ... }:

let
  # ── VM smoke: accept → start → kill THROUGH the consent gate ────────────────
  # VM-GUEST-ONLY (deferred-to-VM): boots a REAL Android container, so it can
  # never run in host CI and has NEVER run on the authoring host — do not read
  # its presence as a pass. It asserts, in order:
  #   0. withdraw   → projection container=blocked → `sloboda start` REFUSES;
  #   1. accept     → container=allowed, but line 1 stays "disabled" (zero
  #                   bridges): accept is permission to RUN, not to share;
  #   2. start      → the wrapper enters through the gate, waits for RUNNING;
  #   3. kill on    → projection flips (kill=engaged) BEFORE runtime teardown,
  #                   and a re-entry attempt REFUSES.
  # The boot-ordering half (projection re-derived before the FIRST read after a
  # reboot) needs an actual reboot of the guest and stays a manual step (the
  # smoke prints the command). Non-attestable tier; UNAUDITED.
  slobodaGateSmoke = pkgs.writeShellScriptBin "sloboda-gate-smoke" ''
    # sloboda-gate-smoke — consent-gate VM smoke (NON-ATTESTABLE tier, UNAUDITED).
    set -eu
    say()  { printf '%s\n' "sloboda-gate-smoke: $*" >&2; }
    fail() { say "FAIL: $*"; exit 1; }

    [ "$(id -u)" = "0" ] \
      || fail "run as root (writes the 0700 canonical dir; stops the container)"
    command -v waydroid >/dev/null 2>&1 \
      || fail "no waydroid on PATH — run this inside the sloboda-vm guest only"

    proj=/run/postern/consent/sloboda-bridge.state

    say "0. known state: withdraw consent (projection re-derives to blocked)"
    sloboda-gated withdraw
    grep -qx 'container=blocked' "$proj" \
      || fail "projection lacks container=blocked after withdraw"
    if sloboda start; then
      fail "wrapper STARTED without consent — the gate did not hold"
    fi
    say "PASS: start refused before consent"

    say "1. accept (scope=session) — permission to RUN, not permission to share"
    sloboda-gated accept --scope session
    grep -qx 'container=allowed' "$proj" \
      || fail "projection lacks container=allowed after accept"
    head -n 1 "$proj" | grep -qx 'disabled' \
      || fail "line 1 must stay 'disabled' while zero bridges are open"

    say "2. start through the gate (boots the REAL container; waits for RUNNING)"
    sloboda start || fail "sloboda start failed after accept"
    say "PASS: accept -> start"

    say "3. kill through the gate: projection flips BEFORE runtime teardown"
    sloboda-gated kill on \
      || say "WARN: kill actuator returned non-zero (state is persisted + projected regardless)"
    grep -qx 'kill=engaged' "$proj" || fail "projection lacks kill=engaged"
    if sloboda start; then
      fail "wrapper re-entered with the kill-switch ENGAGED"
    fi
    say "PASS: kill engaged -> start refused"
    sloboda-gated kill off

    say "RESULT: accept -> start -> kill exercised THROUGH the gate (VM T1 subset)."
    say "Boot-ordering (projection re-derived before the FIRST read) needs a reboot:"
    say "  reboot, then: systemctl status sloboda-gate-boot; cat $proj"
  '';
in
{
  imports = [
    # The NON-ATTESTABLE Waydroid wiring. This is the ONLY host that imports it.
    ./sloboda-compat.nix
    # qemu-vm.nix gives `config.system.build.vm` (a runnable QEMU launcher) and a
    # mutable disk-image root — so "/" is writable, NOT the sealed read-only root,
    # and the seal-exclusion assertion in sloboda-compat.nix stays satisfied.
    (modulesPath + "/virtualisation/qemu-vm.nix")
  ];

  networking.hostName = lib.mkForce "sloboda-vm";

  # ── Turn the NON-ATTESTABLE Waydroid tier ON for this DEV/VM host only ────────
  postern.slobodaCompat = {
    enable = true;
    compositor = "weston";
    systemType = "VANILLA"; # AOSP, no Google, no microG — the only default.
    westonHeadless = true; # give the display path a live Wayland socket (software GL)
    # Rely on waydroid-container to mount binderfs; flip to true only if the guest
    # shows no /dev/binderfs after boot (see sloboda-compat.nix mountBinderfs).
    mountBinderfs = false;
    # Consent gate ON for the VM: sloboda-gated writer, the sloboda-gate-boot
    # ordering oneshot (projection re-derived + session re-ask BEFORE
    # waydroid-container), sloboda-tor-watch, and the state/projection dirs.
    # This is exactly what the sloboda-gate-smoke below exercises.
    consentGate.enable = true;
  };

  # ── QEMU guest sizing — Waydroid + LXC + an Android userland need headroom ────
  virtualisation = {
    memorySize = 4096; # MiB; Android userland is memory-hungry
    cores = 4;
    diskSize = 8192; # MiB; `waydroid init` pulls a multi-hundred-MB image
    graphics = false; # headless; the compositor is Weston (software GL)
    # QEMU user-mode NAT gives the egress `waydroid init` needs. Forward guest
    # ssh (22) to host 2222 so the VM smoke (Dev E) can drive the wrapper.
    forwardPorts = [{ from = "host"; host.port = 2222; guest.port = 22; }];
  };

  # ── A throwaway dev login so the bring-up smoke can drive the wrapper ─────────
  # VM-only, non-attested host: a weak password is acceptable here and NOWHERE
  # else. `waydroid` group lets the user talk to the container without sudo.
  users.users.dev = {
    isNormalUser = true;
    extraGroups = [ "wheel" "waydroid" "video" "render" ];
    password = "dev"; # THROWAWAY VM credential — never a real secret.
  };
  services.getty.autologinUser = "dev";
  security.sudo.wheelNeedsPassword = false;
  services.openssh = {
    enable = true;
    settings.PermitRootLogin = "no";
  };

  # Software GL stack (llvmpipe / SwiftShader) for headless Weston + Waydroid
  # rendering. There is no GPU in the VM — this proves the SOFTWARE fallback only,
  # never Lima/Panfrost hardware GL (matrix item 11 stays device-only).
  hardware.opengl.enable = true;

  # Ship the wrapper + tools the bring-up runbook uses on PATH. `pkgs.waydroid`
  # and `pkgs.weston` also come in via sloboda-compat.nix; listed here so the
  # smoke has git/curl/util-linux without a rebuild.
  environment.systemPackages = with pkgs; [
    waydroid
    weston
    git
    curl
    util-linux # zgrep, mount, findmnt for the binder checks
    slobodaGateSmoke # accept→start→kill through the gate (VM-guest-only smoke)
  ];

  # Deliberately NO os/attested.nix, NO dm-verity, NO read-only root: this host is
  # the non-attestable escape hatch and must stay mutable. Keeping it out of the
  # attested closure is what makes the seal honest.
  system.stateVersion = "24.05";
}
