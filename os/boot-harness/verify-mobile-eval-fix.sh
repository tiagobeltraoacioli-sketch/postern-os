#!/usr/bin/env sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# verify-mobile-eval-fix.sh — verify the rung-0 fixes for the Mobile image
# (see evidence/aarch64-mobile-boot.evidence, SECOND/THIRD/FOURTH ATTEMPT entries):
#
#   fix 1: os/boot-harness/boot-qemu-aarch64.sh builds the system-qualified
#          `.#packages.aarch64-linux.mobile-image` (bare `.#mobile-image` only
#          resolves ON an aarch64-linux host).
#   fix 2: os/mobile.nix imports ./bloch-node.nix so `services.bloch.enable =
#          lib.mkForce false` is a valid option assignment ("The option
#          `services.bloch' does not exist" otherwise).
#   fix 3: os/overlays/svgo.nix (wired via `nixpkgs.overlays` in os/mobile.nix)
#          provides a top-level `pkgs.svgo` from `nodePackages.svgo` — the
#          pinned nixos-25.05 has no top-level svgo, but mobile-nixos
#          gui-assets requires one ('Function called without required argument
#          "svgo"'). UNVERIFIED FIX — pending a Nix host (Path A below).
#
# Behaviour:
#   * If `nix` is on PATH: re-attempt the REAL build —
#       nix build .#packages.aarch64-linux.mobile-image --no-link --print-out-paths
#     and exit with its result. Exit 0 here is the ONLY thing that upgrades
#     rung 0 from FAIL/unverified-fix-applied (update the evidence sidecar with
#     the printed store path + `nix hash path` when it happens — by hand,
#     honestly; this script never edits evidence).
#   * If `nix` is ABSENT (e.g. the macOS dev workstation): FAIL-CLOSED to
#     static grading — assert the fixes are present in the sources and that the
#     evidence sidecar records the second attempt honestly. Exit 0 means only
#     "fixes are in the tree + evidence is honest", NOT "the build works".
#
# UNAUDITED. built≠booted; QEMU≠hardware. A green static grade proves nothing
# about the build; a green `nix build` proves nothing about booting.
set -u

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)   # os/boot-harness
OSDIR=$(dirname -- "$HERE")                          # os
REPO=$(dirname -- "$OSDIR")                          # repo root

MOBILE_NIX="$OSDIR/mobile.nix"
SVGO_OVERLAY="$OSDIR/overlays/svgo.nix"
HARNESS="$HERE/boot-qemu-aarch64.sh"
EVIDENCE="$HERE/evidence/aarch64-mobile-boot.evidence"
ATTR=".#packages.aarch64-linux.mobile-image"

# ── Path A: Nix is available — run the REAL build, nothing less ───────────────
if command -v nix >/dev/null 2>&1; then
  echo "==> nix found — re-attempting the REAL build: nix build $ATTR"
  echo "    (exit status of this script IS the build's exit status)"
  cd "$REPO" || exit 4
  OUT=$(nix build "$ATTR" --no-link --print-out-paths)
  RC=$?
  if [ "$RC" -eq 0 ]; then
    echo "==> BUILD OK: $OUT"
    echo "==> rung 0 (build) may now be upgraded in $EVIDENCE — record this"
    echo "    store path + 'nix hash path' there BY HAND. built≠booted: rung 1"
    echo "    (QEMU boot) is still a separate, ungraded step."
  else
    echo "==> BUILD STILL FAILING (rc=$RC) — rung 0 remains FAIL. Do NOT" >&2
    echo "    upgrade the evidence sidecar; record the new error verbatim." >&2
  fi
  exit "$RC"
fi

# ── Path B: no Nix — FAIL-CLOSED static grading of the applied fixes ──────────
echo "==> nix NOT on PATH — fail-closing to static grading (this can only"
echo "    confirm the fixes exist in the tree; it CANNOT confirm the build)."

FAIL=0
check() {  # check <description> <file> <ERE>
  desc=$1; file=$2; pattern=$3
  if [ ! -f "$file" ]; then
    echo "FAIL: $desc — missing file: $file" >&2
    FAIL=1
    return
  fi
  if grep -Eq "$pattern" "$file"; then
    echo "ok  : $desc"
  else
    echo "FAIL: $desc — pattern not found in $file: $pattern" >&2
    FAIL=1
  fi
}
check_absent() {  # check_absent <description> <file> <ERE that must NOT match>
  desc=$1; file=$2; pattern=$3
  if [ -f "$file" ] && grep -Eq "$pattern" "$file"; then
    echo "FAIL: $desc — forbidden pattern present in $file: $pattern" >&2
    FAIL=1
  else
    echo "ok  : $desc"
  fi
}

# fix 2: mobile.nix imports bloch-node.nix (defines options.services.bloch)
check "os/mobile.nix imports ./bloch-node.nix" \
  "$MOBILE_NIX" 'imports[[:space:]]*=[[:space:]]*\[[^]]*\./bloch-node\.nix'
check "os/mobile.nix still forces the node OFF on the phone" \
  "$MOBILE_NIX" 'services\.bloch\.enable[[:space:]]*=[[:space:]]*lib\.mkForce[[:space:]]+false'
check "os/bloch-node.nix defines options.services.bloch" \
  "$OSDIR/bloch-node.nix" 'options\.services\.bloch'

# fix 1: harness builds the system-qualified attr, and no longer *builds* the
# bare alias (the bare name may still appear in comments/docs).
check "harness builds the system-qualified attr" \
  "$HARNESS" 'nix build "?\$?\{?ATTR\}?"? |packages\.aarch64-linux\.mobile-image'
check "harness ATTR is .#packages.aarch64-linux.mobile-image" \
  "$HARNESS" 'ATTR="\.#packages\.aarch64-linux\.mobile-image"'
check_absent "harness no longer runs 'nix build .#mobile-image' (bare attr)" \
  "$HARNESS" 'nix build \.#mobile-image'

# fix 3: the svgo overlay exists, maps svgo from nodePackages.svgo, and is
# wired into the mobile profile via nixpkgs.overlays.
check "os/overlays/svgo.nix exists and defines an svgo attr" \
  "$SVGO_OVERLAY" 'svgo[[:space:]]*='
check "os/overlays/svgo.nix sources it from nodePackages.svgo" \
  "$SVGO_OVERLAY" 'nodePackages\.svgo'
check "os/mobile.nix sets nixpkgs.overlays" \
  "$MOBILE_NIX" 'nixpkgs\.overlays'
check "os/mobile.nix wires in overlays/svgo.nix" \
  "$MOBILE_NIX" 'overlays/svgo\.nix'

# evidence honesty: second attempt is recorded, still graded FAIL/unverified,
# with the original errors verbatim and no invented artifacts/hashes.
check "evidence records a second attempt" \
  "$EVIDENCE" 'SECOND ATTEMPT'
check "evidence keeps rung 0 as FAIL / unverified-fix-applied" \
  "$EVIDENCE" 'rung_0_status: FAIL / unverified-fix-applied'
check "evidence records error 1 verbatim (attr resolution)" \
  "$EVIDENCE" "does not provide attribute 'packages\.x86_64-linux\.mobile-image'"
check "evidence records error 2 verbatim (services.bloch option)" \
  "$EVIDENCE" "The option \`services\.bloch' does not exist"
check "evidence states the rebuild was NOT attempted on this host" \
  "$EVIDENCE" 'rebuild     : NOT ATTEMPTED'
check "evidence invents no artifact hashes (nixhash n/a)" \
  "$EVIDENCE" 'image_nixhash: n/a'
check "evidence keeps the caveat line (built≠booted, QEMU≠hardware, UNAUDITED)" \
  "$EVIDENCE" 'UNAUDITED\. built≠booted; QEMU≠hardware'

# fix 3 evidence honesty: fourth attempt recorded, labeled unverified, and no
# entry anywhere in the sidecar claims a build passed or invents an artifact.
check "evidence records a fourth attempt (svgo overlay fix)" \
  "$EVIDENCE" 'FOURTH ATTEMPT'
check "evidence labels fix 3 as unverified, pending a Nix host" \
  "$EVIDENCE" 'unverified fix — pending a Nix host'
check "evidence records error 3 verbatim (svgo argument)" \
  "$EVIDENCE" 'Function called without required argument "svgo"'
check_absent "no evidence entry claims rung 0 passed" \
  "$EVIDENCE" 'rung_0_status:[[:space:]]*(PASS|OK|SUCCESS)'
check_absent "no evidence entry claims a build succeeded" \
  "$EVIDENCE" 'BUILD OK|build_status:[[:space:]]*(PASS|OK|SUCCESS)'
check_absent "no evidence entry invents an image hash" \
  "$EVIDENCE" 'image_(nixhash|sha256):[[:space:]]*(sha256[:-]|[0-9a-f]{16})'

if [ "$FAIL" -ne 0 ]; then
  echo "==> STATIC GRADE: FAIL (one or more checks above failed)" >&2
  exit 1
fi
echo "==> STATIC GRADE: pass — fixes present, evidence honest. This is NOT a"
echo "    build result: rung 0 stays FAIL/unverified-fix-applied until this"
echo "    script exits 0 on a host WITH Nix."
exit 0
