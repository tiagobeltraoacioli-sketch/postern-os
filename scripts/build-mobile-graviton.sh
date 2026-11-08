#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# build-mobile-graviton.sh — build the Postern OS Mobile image on a NATIVE
# aarch64 Linux host (e.g. an AWS Graviton EC2 instance), then optionally
# QEMU-boot it. This exists because the x86_64 Fly builder can EVAL the image
# (rung-0: "777 derivations will be built", rc=0) but cannot BUILD it: the
# aarch64 Rust leg (`bloch-0.1.0`) crashes under qemu-user emulation. On a native
# aarch64 host the Rust build is native — no emulation, no crash.
#
# You run this yourself on YOUR Graviton with YOUR credentials — it needs no
# secrets from anyone else and persists none.
#
# HONESTY: everything here is UNAUDITED, pre-mainnet. A successful build produces
# a reproducible-by-design image; "built" is still not "booted", and a QEMU boot
# is not a hardware boot. Nothing here claims otherwise.
#
# ── Provision (do this once, on your AWS side) ───────────────────────────────
#   * Launch an aarch64 Graviton instance (e.g. c7g.2xlarge / m7g.2xlarge — the
#     Rust + kernel build wants RAM; 16 GB+ and ~40 GB disk recommended).
#   * AMI: Ubuntu 24.04 arm64 or Amazon Linux 2023 arm64.
#   * SSH in. Then run this script (scp it over, or paste it).
#
# ── Usage ────────────────────────────────────────────────────────────────────
#   ./build-mobile-graviton.sh [--boot]
#     (no flag)  build the image and print its store path + sha256
#     --boot     after building, QEMU-boot it (aarch64, TCG) and grade the log
#
# Override the branch/rev with env:
#   BRANCH=roadmap/consolidate-all  REPO=<git-url>  ./build-mobile-graviton.sh

set -euo pipefail

REPO="${REPO:-}"                 # set to your git remote (the ownerless/Postern repo)
BRANCH="${BRANCH:-roadmap/consolidate-all}"
# The nixos-unstable rev the mobile image is pinned against (matches flake.nix
# nixpkgs-mobile). Kept explicit so a native build reproduces the eval-verified set.
UNSTABLE_REV="${UNSTABLE_REV:-18b9261cb3294b6d2a06d03f96872827b8fe2698}"
WORKDIR="${WORKDIR:-$HOME/postern-mobile-build}"
BOOT=0
[ "${1:-}" = "--boot" ] && BOOT=1

say() { printf '\n[graviton-build] %s\n' "$*"; }

# 1) Confirm we are actually on aarch64 — the whole point is NO emulation.
ARCH="$(uname -m)"
case "$ARCH" in
  aarch64|arm64) : ;;
  *) echo "REFUSING: uname -m = $ARCH, not aarch64. This script must run on a NATIVE aarch64 host (a Graviton), or the Rust build will emulate and crash." >&2; exit 2 ;;
esac
say "native arch OK: $ARCH"

# 2) Install Nix (multi-user) if absent, with flakes enabled.
if ! command -v nix >/dev/null 2>&1; then
  say "installing Nix (Determinate installer, flakes on)…"
  curl -fsSL https://install.determinate.systems/nix | sh -s -- install --no-confirm
  . /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh 2>/dev/null || \
    . "$HOME/.nix-profile/etc/profile.d/nix.sh" 2>/dev/null || true
fi
export NIX_CONFIG="experimental-features = nix-command flakes"

# 3) Get the source.
if [ -n "$REPO" ]; then
  mkdir -p "$WORKDIR"; cd "$WORKDIR"
  if [ -d repo/.git ]; then git -C repo fetch --depth 1 origin "$BRANCH"; else git clone --depth 1 -b "$BRANCH" "$REPO" repo; fi
  cd repo
else
  say "REPO not set — assuming you are already inside a checkout of the repo (branch $BRANCH)."
fi
say "HEAD: $(git log -1 --oneline 2>/dev/null || echo '?')"

# 4) Build the image NATIVELY. On aarch64 the flake's blochPkgFor "aarch64-linux"
#    compiles natively (no cross hack, no emulation). Pin nixpkgs-mobile to the
#    eval-verified unstable rev.
say "building .#packages.aarch64-linux.mobile-image (native aarch64 — this is the real build)…"
nix build ".#packages.aarch64-linux.mobile-image" \
  --override-input nixpkgs-mobile "github:NixOS/nixpkgs/${UNSTABLE_REV}" \
  -o ./mobile-result --print-build-logs

IMG="$(readlink -f ./mobile-result)"
say "BUILT: $IMG"
find "$IMG" -maxdepth 2 -type f \( -name '*.img' -o -name '*.img.*' \) -print 2>/dev/null | while read -r f; do
  printf '  %s\n  sha256 %s\n' "$f" "$(sha256sum "$f" | cut -d' ' -f1)"
done

# 5) Optional: QEMU boot (aarch64, TCG). This proves the software boot chain only
#    (bootloader → kernel → stage-1 → systemd → login); it is NOT a hardware boot
#    and NOT attestation.
if [ "$BOOT" = "1" ]; then
  say "attempting a QEMU-aarch64 boot (TCG). Software boot chain only — not a PinePhone."
  command -v qemu-system-aarch64 >/dev/null 2>&1 || {
    say "installing qemu…"; (sudo apt-get update -y && sudo apt-get install -y qemu-system-arm) || sudo dnf install -y qemu-system-aarch64 || true; }
  if [ -x os/boot-harness/boot-qemu-aarch64.sh ]; then
    say "handing off to the repo's graded boot harness…"
    IMG_PATH="$IMG" bash os/boot-harness/boot-qemu-aarch64.sh || say "boot harness returned non-zero — read os/boot-harness/evidence/ for the graded result (an honest FAIL is still evidence)."
  else
    say "os/boot-harness/boot-qemu-aarch64.sh not found — boot the produced .img with qemu-system-aarch64 -M virt manually and capture the serial console."
  fi
fi

say "DONE. Reminder: UNAUDITED. built ≠ booted; QEMU ≠ hardware. Record the result honestly in os/boot-harness/evidence/aarch64-mobile-boot.evidence."
