#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: Postern Labs
#
# verify-build.sh — Postern Browser build-from-source + artifact verifier.
#
# This is the executable companion to VERIFY.md §0. It does NOT prove the
# browser is secure, anonymous, reproduced, or audited. It proves two narrow,
# honest things:
#   1. the published artifact matches the published SHA256SUMS, and
#   2. SHA256SUMS carries a valid minisign signature from the key you pass in.
# A signature proves WHO published, never WHAT was built. "Built" != "repeatable"
# != "reproduced" != "audited". Keep the labels honest: hardened, not anonymous;
# not Tor; UNAUDITED.
#
# Usage:
#   ./verify-build.sh --pubkey <minisign-pubkey-or-file> [options]
#
# Options:
#   --pubkey  P   Published minisign public key (RW..., or path to a .pub file).
#   --dir     D   Directory holding the downloaded artifacts + SHA256SUMS
#                 + SHA256SUMS.minisig + build-manifest.json (default: .).
#   --manifest M  Path to build-manifest.json (default: <dir>/*build-manifest.json).
#   --build       Also rebuild the package from source (nix-build ... -A package)
#                 and print its store path + the pin status.
#   -h, --help    Show this help.
#
# Exit codes: 0 = all checks passed; non-zero = a check failed or a tool/input
# was missing. Any failure is a ship-blocker (see VERIFY.md).

set -eu

PUBKEY=""
DIR="."
MANIFEST=""
DO_BUILD=0

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
note() { printf '  %s\n' "$1"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --pubkey)   PUBKEY="${2:-}"; shift 2 ;;
    --dir)      DIR="${2:-}"; shift 2 ;;
    --manifest) MANIFEST="${2:-}"; shift 2 ;;
    --build)    DO_BUILD=1; shift ;;
    -h|--help)
      sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done

command -v sha256sum >/dev/null 2>&1 || fail "sha256sum not found on PATH."
command -v minisign  >/dev/null 2>&1 || fail "minisign not found on PATH (needed for the signature check)."

[ -d "$DIR" ] || fail "artifact dir not found: $DIR"
SUMS="$DIR/SHA256SUMS"
SIG="$DIR/SHA256SUMS.minisig"
[ -f "$SUMS" ] || fail "missing $SUMS"
[ -f "$SIG" ]  || fail "missing $SIG (the signature written LAST in the publish flip)."

# ── 0.2 step 2: verify the signature FIRST (fail-safe: trust the sig, then the
#     sums it covers, then the artifacts). The pubkey MUST be the independently
#     published key, never one bundled inside the download. ──────────────────────
[ -n "$PUBKEY" ] || fail "--pubkey is required (the PUBLISHED minisign public key)."
printf 'Verifying SHA256SUMS signature (who published)...\n'
if [ -f "$PUBKEY" ]; then
  minisign -Vm "$SUMS" -p "$PUBKEY" || fail "minisign signature verification FAILED."
else
  minisign -Vm "$SUMS" -P "$PUBKEY" || fail "minisign signature verification FAILED."
fi
note "signature OK — but this proves the publisher, NOT that the build is safe."

# ── 0.2 step 1: the artifacts match the signed hashes. ──────────────────────────
printf 'Checking artifact hashes against SHA256SUMS (what was published)...\n'
( cd "$DIR" && sha256sum -c SHA256SUMS ) || fail "one or more artifacts do NOT match SHA256SUMS."
note "all listed artifacts match the signed hashes."

# ── 0.2 step 3: manifest honesty fields must be present and honest. ─────────────
if [ -z "$MANIFEST" ]; then
  MANIFEST=$(ls "$DIR"/*build-manifest.json 2>/dev/null | head -n1 || true)
fi
if [ -n "$MANIFEST" ] && [ -f "$MANIFEST" ]; then
  printf 'Checking manifest honesty fields (%s)...\n' "$MANIFEST"
  for kv in '"reproducible": *false' '"attestable": *false' '"audited": *false' '"status": *"BUILT"'; do
    grep -Eq "$kv" "$MANIFEST" || fail "manifest is missing/at-odds with $kv — publisher must refuse it (build.md §5)."
  done
  note "manifest carries reproducible=false, attestable=false, audited=false, status=BUILT."
else
  printf 'WARN: no build-manifest.json found in %s — cannot check honesty fields.\n' "$DIR" >&2
fi

# ── Optional rebuild-from-source (VERIFY.md §0.1). ──────────────────────────────
if [ "$DO_BUILD" -eq 1 ]; then
  command -v nix-build >/dev/null 2>&1 || fail "--build requested but nix-build not found on PATH."
  HERE=$(CDPATH= cd "$(dirname "$0")" && pwd)
  if grep -q 'TODO(pin)' "$HERE/postern-browser.nix" 2>/dev/null; then
    printf 'WARN: postern-browser.nix still has TODO(pin) inputs — this rebuild is NOT rebuild-verifiable (channel fallback).\n' >&2
  fi
  printf 'Building postern-browser.nix -A package ...\n'
  OUT=$(nix-build "$HERE/postern-browser.nix" -A package --no-out-link) || fail "nix-build failed."
  note "built: $OUT"
fi

printf '\nPASS: published bits match published hashes + signature.\n'
printf 'This is NOT a claim of reproducibility, attestation, security, or anonymity.\n'
printf 'Postern Browser: hardened, not anonymous; not Tor; UNAUDITED.\n'
