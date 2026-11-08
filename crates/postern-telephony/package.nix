# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Standalone reproducible build of the Postern telephony tools for Postern OS
# Mobile. Ships `postern-telephony-probe` — the B4 live-device smoke check that
# enumerates the modem via ModemManager over D-Bus (see src/probe.rs).
#
# The crate is deliberately self-contained (its own committed Cargo.lock, an
# empty [workspace] table) so it never destabilises the root workspace. Its one
# path dep is the sibling `postern-core`, so `src` spans the whole `crates/`
# tree and the build is pinned to this crate's subdir.
#
# HONESTY: "written, not built" — cross-compiling this (zbus/tokio) for aarch64
# is bring-up territory and has never been built on the dev host (no Nix here).
# zbus is pure-Rust MIT with no libdbus link, so no system D-Bus lib is needed.
{ lib, rustPlatform }:

rustPlatform.buildRustPackage {
  pname = "postern-telephony";
  version = "0.1.0";

  # The whole crates/ dir so the `../postern-core` path dep resolves; the build
  # is scoped to the postern-telephony member below.
  src = lib.cleanSource ../.;
  buildAndTestSubdir = "postern-telephony";
  # The crate's Cargo.lock lives in the postern-telephony subdir, not at the
  # src root (src spans the whole crates/ tree for the ../postern-core path
  # dep). cargoRoot tells the cargo setup hook where to find it, else the build
  # dies with "Missing Cargo.lock from src". Surfaced by the native aarch64
  # mobile-image build (2026-07-15).
  cargoRoot = "postern-telephony";

  cargoLock = {
    lockFile = ./Cargo.lock;
    # crates.io deps only (zbus, tokio, postern-core is a path dep) — no git deps.
  };

  # Pure-Rust deps (zbus has no libdbus link; postern-core is pure AEAD/KDF).
  nativeBuildInputs = [ ];
  buildInputs = [ ];

  # Device-required behaviour can't run in the sandbox (no system bus / modem);
  # the pure codec tests do run, but keep the image build lean — CI runs tests.
  doCheck = false;

  meta = with lib; {
    description = "Postern OS Mobile telephony tools (ModemManager D-Bus client + live-device probe)";
    license = with licenses; [ mit asl20 ];
    platforms = platforms.linux;
    mainProgram = "postern-telephony-probe";
  };
}
