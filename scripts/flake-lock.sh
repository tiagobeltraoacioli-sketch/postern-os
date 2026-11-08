#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# flake-lock.sh — FREEZE the flake's inputs into a reproducible flake.lock.
#
# This is the ONLY honest way this repo gets a real `flake.lock`: the committed
# lock is an EMPTY SEED (no revisions frozen, no fabricated narHash — see the
# flake.nix header). This script runs on a Linux + Nix host, resolves the moving
# branch refs (`nixpkgs` nixos-24.05, `mobile-nixos` HEAD) to EXACT commit revs,
# and writes them — with their real narHashes computed by Nix — into flake.lock.
# The FILLED lock must then be committed FROM THAT VM. It is never generated on
# the macOS dev host (no Nix there); a hand-fabricated lock would be a lie.
#
#   reproducible-by-design ≠ reproduced — freezing the lock is step 1; a second
#   builder rebuilding `.#iso` to a matching store hash is the actual proof
#   (docs/plan/FLAKE-REPRO.md). This script only does step 1.
#
# Usage:
#   scripts/flake-lock.sh                 # freeze inputs at their current HEADs
#   NIXPKGS_REV=<sha> scripts/flake-lock.sh
#   MOBILE_NIXOS_REV=<sha> scripts/flake-lock.sh
#   NIXPKGS_REV=<sha> MOBILE_NIXOS_REV=<sha> scripts/flake-lock.sh
#
# Env overrides pin an EXACT commit (extra determinism); unset = lock whatever
# the branch ref points at right now, which Nix still records as an exact rev.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"
LOCK="$ROOT/flake.lock"

die() { printf 'flake-lock: %s\n' "$*" >&2; exit 1; }

command -v nix >/dev/null 2>&1 \
  || die "no \`nix\` on PATH. This is a VM-gated step — run it on a Linux + Nix host, NOT the macOS dev workstation."

# Nix needs flakes + the nix-command experimental features.
NIX_FLAGS=(--extra-experimental-features "nix-command flakes")

# Optional exact-rev pins → --override-input pairs.
OVERRIDES=()
if [ -n "${NIXPKGS_REV:-}" ]; then
  OVERRIDES+=(--override-input nixpkgs "github:NixOS/nixpkgs/${NIXPKGS_REV}")
fi
if [ -n "${MOBILE_NIXOS_REV:-}" ]; then
  OVERRIDES+=(--override-input mobile-nixos "github:nix-community/mobile-nixos/${MOBILE_NIXOS_REV}")
fi

if grep -q '"locked"' "$LOCK" 2>/dev/null; then
  printf 'flake-lock: existing flake.lock already carries frozen inputs; re-freezing (bump).\n'
else
  printf 'flake-lock: flake.lock is the empty seed; freezing inputs for the first time.\n'
fi

printf 'flake-lock: freezing nixpkgs + mobile-nixos ...\n'
nix "${NIX_FLAGS[@]}" flake lock "${OVERRIDES[@]}"

# Fail-closed verification: both inputs MUST now be locked, else the lock is not
# reproducible and must not be committed.
for input in nixpkgs mobile-nixos; do
  grep -q "\"${input}\"" "$LOCK" \
    || die "input '${input}' is NOT present in flake.lock after locking — refusing to call this reproducible."
done
grep -q '"locked"' "$LOCK" \
  || die "flake.lock still has no locked revisions — freeze failed."

printf 'flake-lock: frozen input revisions:\n'
nix "${NIX_FLAGS[@]}" flake metadata --json \
  | nix "${NIX_FLAGS[@]}" run nixpkgs#jq -- -r \
      '.locks.nodes | to_entries[] | select(.value.locked != null)
       | "  \(.key): \(.value.locked.rev // .value.locked.narHash)"' \
  2>/dev/null || printf '  (install jq / inspect flake.lock to read the frozen revs)\n'

cat <<'EOF'
flake-lock: DONE. Next:
  1. git add flake.lock && git commit   # commit the FILLED lock FROM THIS VM
  2. scripts/flake-check.sh             # nix flake check against the frozen lock
  3. docs/plan/FLAKE-REPRO.md           # two-builder bit-for-bit reproduction
EOF
