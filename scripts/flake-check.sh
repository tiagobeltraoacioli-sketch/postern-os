#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# flake-check.sh — run `nix flake check` against a FROZEN flake.lock.
#
# FAIL-CLOSED discipline (the whole point): an `nix flake check` run against the
# empty-seed lock re-resolves the moving branch refs and is NOT reproducible.
# This wrapper REFUSES to run until scripts/flake-lock.sh has frozen the inputs,
# so an unpinned check can never masquerade as a reproducible one. It also passes
# --no-update-lock-file so the check uses the committed frozen lock verbatim and
# errors (rather than silently re-locking) if the lock is stale.
#
#   built ≠ booted — a green `nix flake check` evaluates the outputs and builds
#   the packages; it boots nothing and attests nothing. QEMU/boot proof is the
#   harness apps (.#boot-qemu, .#boot-qemu-x86); reproduction proof is the
#   two-builder run in docs/plan/FLAKE-REPRO.md.
#
# NOTE: a FULLY green check additionally needs O1/CS-5 to have filled the 5
# seal-gate `lib.fakeHash` sentinels — until then `.#seal-gate` fail-closes by
# design and `nix flake check` reports that build as failing. That is an
# intentional cross-dev gate, documented in flake.nix, not a defect here.
#
# Usage:
#   scripts/flake-check.sh              # check the host system only
#   scripts/flake-check.sh --all        # check every system (--all-systems)
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"
LOCK="$ROOT/flake.lock"

die() { printf 'flake-check: %s\n' "$*" >&2; exit 1; }

command -v nix >/dev/null 2>&1 \
  || die "no \`nix\` on PATH. This is a VM-gated step — run it on a Linux + Nix host, NOT the macOS dev workstation."

[ -f "$LOCK" ] || die "no flake.lock — run scripts/flake-lock.sh on this Nix host first."

# Fail-closed: the empty seed lock has no "locked" revisions.
grep -q '"locked"' "$LOCK" \
  || die "flake.lock is the empty SEED (no frozen revisions). Reproducibility is unpinned. Run scripts/flake-lock.sh first."

# Both inputs must be pinned.
for input in nixpkgs mobile-nixos; do
  grep -q "\"${input}\"" "$LOCK" \
    || die "input '${input}' is not frozen in flake.lock — refusing to run an unpinned check."
done

NIX_FLAGS=(--extra-experimental-features "nix-command flakes")

CHECK_FLAGS=(--no-update-lock-file --print-build-logs)
if [ "${1:-}" = "--all" ]; then
  CHECK_FLAGS+=(--all-systems)
  printf 'flake-check: checking ALL systems against the frozen lock ...\n'
else
  printf 'flake-check: checking the host system against the frozen lock ...\n'
fi

nix "${NIX_FLAGS[@]}" flake check "${CHECK_FLAGS[@]}"

printf 'flake-check: PASS — outputs evaluated + packages built against the frozen lock.\n'
printf 'flake-check: reminder — built != booted; run the QEMU harness apps + the two-builder reproduction (docs/plan/FLAKE-REPRO.md) for the real claims.\n'
