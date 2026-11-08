# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Postern OS Mobile — mobile-nixos ↔ nixpkgs (nixos-25.05) rename-compat overlay.
#
# The flake pins mobile-nixos rev 2c132754323fc1915e8d21dcfc0ef68ab084c6fb, which
# predates nixos-25.05 and refers to several packages by attrs that 25.05 renamed.
# Each entry below is a VERIFIED rename fix: run on the Fly Nix builder
# (`postern-os-build`), `nix build .#packages.aarch64-linux.mobile-image --dry-run`
# advances PAST each one in turn — svgo → xkeyboard-config → libx11. Each is
# guarded `prev.<new> or throw`, so on a pin that already has the old spelling the
# entry is a no-op (and on a fully-new pin the throw tells the human what to fix).
#
#   svgo             : 25.05 ships nodePackages.svgo, no top-level pkgs.svgo, but
#                      overlay/mobile-nixos/gui-assets/default.nix wants top-level
#                      `svgo` (rung-0 THIRD-ATTEMPT blocker).
#   xkeyboard-config : renamed to xkeyboard_config (initrd-boot-gui.nix).
#   libx11           : lives under xorg.libX11 in 25.05 (initrd-boot-gui.nix).
#
# ── HONEST WALL — this overlay does NOT make the image build ──────────────────
# After these three renames the eval reaches a DEEPER incompatibility that an
# overlay CANNOT paper over: mobile-nixos overrides `libinput` with a `luaSupport`
# argument that nixos-25.05's libinput no longer accepts —
#   error: function 'anonymous lambda' called with unexpected argument 'luaSupport'
#   at «github:NixOS/nixpkgs/…»/pkgs/development/libraries/libinput/default.nix
# That is API drift, not a rename. The REAL fix is to ALIGN the input versions:
# bump the mobile-nixos input to a nixos-25.05-compatible commit, or pin nixpkgs
# to mobile-nixos 2c13275's expected base — a deliberate flake-input decision with
# a wider blast radius, done on purpose, not as a live whack-a-mole. Verified on
# the Fly Nix builder; see os/boot-harness/evidence/aarch64-mobile-boot.evidence
# (attempt 5). Rung-0 REMAINS FAIL; no image is produced and no pass is claimed.
final: prev: {
  svgo = prev.svgo or (final.nodePackages.svgo or (throw "Postern OS Mobile: this nixpkgs pin has neither pkgs.svgo nor nodePackages.svgo — update os/overlays/svgo.nix for the new pin"));
  xkeyboard-config = prev.xkeyboard-config or prev.xkeyboard_config or (throw "Postern OS Mobile: this nixpkgs pin has neither xkeyboard-config nor xkeyboard_config — update os/overlays/svgo.nix");
  libx11 = prev.libx11 or (prev.xorg.libX11 or (throw "Postern OS Mobile: this nixpkgs pin has neither pkgs.libx11 nor xorg.libX11 — update os/overlays/svgo.nix"));
}
