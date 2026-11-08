# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Postern OS Mobile — the telephony device path (a Postern Labs product).
#
# This is the mobile-only glue that wires `crates/postern-telephony` into the
# phone image: it enables the GPL system daemons that OWN the modem on a Linux
# phone (ModemManager for SMS/voice, callaudiod for in-call audio routing) and
# ships the Postern telephony tools, which talk to those daemons ONLY over D-Bus
# IPC — a process boundary, not a fork/embed of GPL code (the repo license rule,
# same posture as syscalls into the GPL kernel; see the crate's lib.rs).
#
# HONESTY:
#   - QEMU ≠ hardware. `qemu-system-aarch64 -M virt` models NO modem, so this
#     path is DEAD under emulation: `postern-telephony-probe` prints "no modem".
#     It only lights up on a real PinePhone with a SIM (roadmap item B4).
#   - Carrier SMS/voice is NOT private on the wire (plaintext to the carrier,
#     lawful-intercept-accessible, tower always sees location + IMEI/IMSI). The
#     value here is a hardened LOCAL client (encrypted-at-rest store, no cloud,
#     no telemetry). Anything sensitive belongs on the E2EE Matrix messenger.
{ config, lib, pkgs, ... }:
let
  # Standalone build of the Postern telephony tools (probe + future app cores).
  # Cross-compiling this Rust crate for aarch64 is bring-up territory — it is
  # "written, not built" until a Nix host produces it. Kept as its own package
  # so it cannot break the image eval if the crate is absent on a given tree.
  posternTelephony = pkgs.callPackage ../crates/postern-telephony/package.nix { };
in
{
  # ── The modem stack (GPL system daemons, reached over D-Bus) ────────────────
  # ModemManager owns the modem/SIM and exports org.freedesktop.ModemManager1;
  # postern-telephony is a fresh MIT/Apache client of that stable D-Bus API.
  networking.networkmanager.enable = lib.mkDefault true; # NM drives MM for data
  # Enable ModemManager directly via systemd rather than the stock
  # `networking.modemmanager` NixOS option: the mobile-nixos eval loads a REDUCED
  # module set that does not define that option ("The option
  # `networking.modemmanager' does not exist"), so assigning it aborts the eval.
  # Shipping the package's own systemd unit + wanting it is what that option does
  # under the hood, and it is module-set-independent (eval-safe on any pin).
  systemd.packages = [ pkgs.modemmanager ];
  systemd.services.ModemManager.wantedBy = [ "multi-user.target" ];

  # In-call audio routing on PinePhone-class devices (Mobian's callaudiod).
  # Optional and device-dependent; enable per device port during bring-up.
  # services.callaudiod is not a stock NixOS option everywhere — leave the
  # package available and let the device port wire the unit if needed.
  environment.systemPackages = [
    posternTelephony            # postern-telephony-probe (+ future SMS/dialer)
    pkgs.modemmanager           # `mmcli` for manual modem triage on-device
  ];

  # A real modem/SIM is required; nothing here connects under QEMU. The probe
  # is the B4 smoke check: on hardware it enumerates the modem via ModemManager
  # and reports whether the voice/messaging device path is live.
}
