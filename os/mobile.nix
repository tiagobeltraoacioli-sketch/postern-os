# Postern OS Mobile — the phone profile (wallet-first). A Postern Labs product.
#
# Phones can't meaningfully do Module-SIS PoW, so this is a wallet / key vault,
# not a miner (matches the project scope: "mobile = wallet only, focus is PoW").
# Layered on top of a Mobile NixOS device config (kernel/modem/display come from
# the device module).
{ config, lib, pkgs, blochPkg, ... }:
{
  # The telephony device path (SMS + cellular voice via ModemManager over
  # D-Bus). Mobile-only; dead under QEMU (no modem is modeled) — see os/telephony.nix.
  #
  # ./bloch-node.nix is imported ONLY to define the `services.bloch` option so
  # the `enable = false` below is a valid module-system assignment — without it
  # the mobile flake eval dies with "The option `services.bloch' does not exist"
  # (observed on the Fly builder, 2026-07-14; see
  # os/boot-harness/evidence/aarch64-mobile-boot.evidence). The module system
  # dedupes path imports, and the mkForce false keeps the node service OFF —
  # this does NOT put a mining node on the phone.
  imports = [ ./telephony.nix ./bloch-node.nix ];

  # ./overlays/svgo.nix — the pinned nixpkgs (nixos-25.05) has no top-level
  # `pkgs.svgo`, only `nodePackages.svgo`, but the pinned mobile-nixos overlay
  # calls gui-assets with `final.callPackage ./gui-assets { }` which needs a
  # top-level `svgo`. mobile-nixos composes its overlay via this same
  # `nixpkgs.overlays` option, so this entry lands in the same fixed point.
  # UNVERIFIED FIX — pending a Nix host; see the FOURTH ATTEMPT entry in
  # os/boot-harness/evidence/aarch64-mobile-boot.evidence. On nixpkgs >= 25.11
  # (which ships pkgs.svgo) the overlay is a no-op.
  nixpkgs.overlays = [ (import ./overlays/svgo.nix) ];

  networking.hostName = lib.mkForce "postern-phone";

  # No mining node on a phone — ship the wallet + tooling instead.
  services.bloch.enable = lib.mkForce false;

  # The wallet CLI + the post-quantum crypto stack (byte-identical to the node).
  environment.systemPackages = [ blochPkg ];

  # ── First-boot success markers (what the SHARED boot grader keys on) ──────────
  # os/boot-harness/success-markers.txt requires, as its FINAL rung, a line
  # matching the ERE `(login:|◆ Postern OS Mobile)`. Two independent sources
  # below satisfy it, so a HEADLESS qemu-system-aarch64 serial capture — which
  # never types a password — still reaches an observable marker:
  #
  #   1. login: — the boot harness starts QEMU with `console=ttyAMA0`, so systemd's
  #      serial-getty@ttyAMA0 generator brings a getty up on the captured serial
  #      console; agetty prints `/etc/issue` then `postern-phone login:` BEFORE any
  #      credentials are entered. That `login:` is the REQUIRED marker.
  #   2. ◆ Postern OS Mobile — greetingLine puts the wallet-first banner INTO
  #      /etc/issue, so it is visible PRE-login on the serial console (the `~`
  #      informational marker in success-markers.txt), not only post-login below.
  #
  # This is the login/MOTD banner path ONLY. It has NEVER been booted anywhere
  # (macOS dev host: no Nix, no KVM, no qemu-system); it asserts nothing about a
  # real PinePhone. QEMU ≠ hardware. UNAUDITED/SCAFFOLD.
  services.getty.greetingLine = lib.mkForce
    "◆ Postern OS Mobile — wallet-first · post-quantum  (\\l)";
  services.getty.helpLine = lib.mkForce
    "Your key vault:  bloch-wallet --help   ·   phones hold keys, they don't mine.";

  # DoD #2 — interactive / CI-expect FOLLOW-UP, deliberately NOT graded by the
  # headless boot harness (which proves boot-to-login only and does not type into
  # the console). A separate expect wrapper, once at the `login:` prompt above,
  # logs in and asserts the wallet engine is live:
  #   bloch-wallet --help          # prints usage  => wallet engine loaded
  #   systemctl is-system-running  # running | degraded-with-known-reasons
  users.motd = ''
    ◆ Postern OS Mobile — wallet-first · post-quantum

    Your key vault:  bloch-wallet --help
    Phones don't mine (PoW runs on desktops/nodes) — this holds keys + signs.
    Hybrid Falcon‖ML-DSA · addresses identical to the node.
  '';

  # Phone hygiene: keep it lean, favour battery + privacy.
  documentation.enable = lib.mkDefault false;
  services.openssh.enable = lib.mkDefault false;

  # A touch wallet UI is the app layer on top: reuse the desktop web UI in a
  # mobile shell, or a UniFFI-backed native app over `bloch-mobile`'s WalletCore.
  # (Tracked separately — this profile ships the OS + the wallet engine.)
}
