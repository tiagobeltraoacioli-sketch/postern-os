#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# verify-boot-binding.sh — prove the build-time roothash actually bound into the
# running node's boot AND its attestation report. Run this ON the booted attested
# node (a QEMU guest for the software chain; real measured-boot hardware for the
# TPM2 rung). It NEVER runs meaningfully on macOS — there is no /proc/cmdline, no
# running bloch node, no TPM.
#
# It checks three independent bindings and reports each honestly:
#
#   A) CMDLINE    the running kernel cmdline carries `roothash=R` (pass-2 binding
#                 landed) OR the roothash is discoverable from the active
#                 dm-verity target. This proves the OS is running the sealed image.
#   B) REPORT     `getattestation` on the node's JSON-RPC reports os_roothash == R.
#                 This proves the node's attestation surface reports the real value
#                 (turning Expected.os_roothash from a placeholder into a check).
#   C) PCR (HW)   TPM2 PCR 11 (UKI / kernel-cmdline measurement) is present and
#                 non-zero. A *full* proof — that PCR 11 equals the reference
#                 value predicted for exactly this UKI+roothash — needs a
#                 precomputed reference and is HARDWARE-GATED; here we assert the
#                 measurement EXISTS and flag the reference-compare as TODO-HW.
#
# Usage:
#   verify-boot-binding.sh -r ROOTHASH [-p RPCPORT] [-H RPCHOST] [--pcr N]
#     -r ROOTHASH   the 64-hex build-time roothash from extract-roothash.sh (required)
#     -p RPCPORT    node JSON-RPC port (default: 8645, per os/bloch-node.nix)
#     -H RPCHOST    node JSON-RPC host (default: 127.0.0.1)
#     --pcr N       TPM2 PCR index for the UKI/cmdline measurement (default: 11)
#
# Exit: 0 all reachable checks passed; 1 a check FAILED (mismatch); 2 usage;
#       3 ran somewhere with no boot/node surface (e.g. macOS) — nothing proven.
set -euo pipefail

ROOTHASH=""
RPCPORT="8645"
RPCHOST="127.0.0.1"
PCR="11"

usage() { echo "usage: verify-boot-binding.sh -r ROOTHASH [-p RPCPORT] [-H RPCHOST] [--pcr N]" >&2; exit 2; }

while [ "$#" -gt 0 ]; do
  case "$1" in
    -r) ROOTHASH="${2:?-r needs a value}"; shift 2 ;;
    -p) RPCPORT="${2:?-p needs a value}"; shift 2 ;;
    -H) RPCHOST="${2:?-H needs a value}"; shift 2 ;;
    --pcr) PCR="${2:?--pcr needs a value}"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "verify-boot-binding: unknown arg: $1" >&2; usage ;;
  esac
done

[ -n "$ROOTHASH" ] || { echo "verify-boot-binding: -r ROOTHASH is required (the value extract-roothash.sh produced)" >&2; usage; }
printf '%s' "$ROOTHASH" | grep -Eq '^[0-9a-f]{64}$' \
  || { echo "verify-boot-binding: -r must be 64 lowercase hex chars; got '$ROOTHASH'" >&2; exit 2; }

# Bail honestly if we are not on a booted Linux node (the macOS / dev case).
if [ ! -r /proc/cmdline ]; then
  echo "verify-boot-binding: no /proc/cmdline — not a booted Linux node." >&2
  echo "                     This is a VM/hardware-gated step. NOTHING is proven here;" >&2
  echo "                     os_roothash remains a PLACEHOLDER until this runs on the node." >&2
  exit 3
fi

rc=0
pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*" >&2; rc=1; }
skip() { echo "skip  $*"; }

echo "verify-boot-binding: expecting roothash R = ${ROOTHASH}"

# --- A) cmdline / dm-verity binding -------------------------------------------
CMDLINE="$(cat /proc/cmdline)"
if printf '%s' "$CMDLINE" | grep -Eoq "roothash=${ROOTHASH}\b"; then
  pass "A/cmdline: roothash=R present on the running kernel cmdline (pass-2 binding landed)."
elif command -v veritysetup >/dev/null 2>&1 && veritysetup status root 2>/dev/null | grep -qi "$ROOTHASH"; then
  pass "A/verity: active dm-verity target 'root' reports roothash R (discoverable-partitions binding)."
else
  # Distinguish 'some other roothash is bound' (a real mismatch) from 'no roothash
  # visible yet' (pass-2 not run — still a placeholder, not a lie).
  if printf '%s' "$CMDLINE" | grep -Eoq 'roothash=[0-9a-f]{64}'; then
    OTHER="$(printf '%s' "$CMDLINE" | grep -Eo 'roothash=[0-9a-f]{64}' | head -1)"
    fail "A/cmdline: cmdline carries a DIFFERENT roothash ($OTHER) than expected R — image mismatch."
  else
    skip "A: no roothash= on cmdline and no active verity target — pass-2 binding NOT applied; R stays a placeholder here."
  fi
fi

# --- B) getattestation report binding -----------------------------------------
NONCE="$(head -c16 /dev/urandom 2>/dev/null | od -An -tx1 | tr -d ' \n' || echo "00000000000000000000000000000000")"
REQ="$(printf '{"jsonrpc":"2.0","id":1,"method":"getattestation","params":["%s"]}' "$NONCE")"
RESP=""
if command -v curl >/dev/null 2>&1; then
  RESP="$(curl -fsS --max-time 10 -H 'content-type: application/json' -d "$REQ" "http://${RPCHOST}:${RPCPORT}/" 2>/dev/null || true)"
fi
if [ -z "$RESP" ]; then
  skip "B: node JSON-RPC at ${RPCHOST}:${RPCPORT} unreachable (or no curl) — attestation report not checked."
else
  # Pull the reported roothash. Prefer a real JSON path; fall back to a hex scan
  # so we don't hard-depend on the exact field name across RPC schema revisions.
  REPORTED=""
  if command -v jq >/dev/null 2>&1; then
    REPORTED="$(printf '%s' "$RESP" | jq -r '.result.os_roothash // .result.roothash // empty' 2>/dev/null || true)"
  fi
  if [ -z "$REPORTED" ]; then
    REPORTED="$(printf '%s' "$RESP" | grep -Eo '[0-9a-f]{64}' | head -1 || true)"
  fi
  if [ -z "$REPORTED" ]; then
    fail "B/report: getattestation returned no parseable os_roothash. Raw: ${RESP}"
  elif [ "$REPORTED" = "$ROOTHASH" ]; then
    pass "B/report: getattestation reports os_roothash == R. attestation::read_os_roothash is bound to the real value."
  else
    fail "B/report: getattestation reports $REPORTED, expected R=$ROOTHASH — the node is NOT reporting the built image."
  fi
fi

# --- C) TPM2 PCR measurement (HARDWARE-GATED) ---------------------------------
# Full proof = PCR 11 equals the reference value precomputed for this exact
# UKI+cmdline (systemd's `--measure`, or the CVM launch measurement folding it
# in). That reference is HARDWARE/build-specific; here we can only assert the
# measurement chain is live. A green result below is NOT a measured-boot proof.
if [ -c /dev/tpm0 ] || [ -c /dev/tpmrm0 ]; then
  if command -v tpm2_pcrread >/dev/null 2>&1; then
    PCRVAL="$(tpm2_pcrread "sha256:${PCR}" 2>/dev/null | grep -Eo '0x[0-9A-Fa-f]+' | head -1 || true)"
    if [ -n "$PCRVAL" ] && [ "$PCRVAL" != "0x0000000000000000000000000000000000000000000000000000000000000000" ]; then
      pass "C/tpm: PCR ${PCR} is populated ($PCRVAL) — a measurement chain is live."
      echo "info  C is NOT complete: comparing PCR ${PCR} to the reference predicted for this UKI+roothash is HARDWARE-GATED (TODO-HW)."
    else
      skip "C: PCR ${PCR} is zero/unreadable — measured boot not established on this instance."
    fi
  else
    skip "C: TPM present but no tpm2_pcrread — install tpm2-tools to read PCR ${PCR}."
  fi
else
  skip "C: no TPM device — measured-boot PCR binding is HARDWARE-GATED and unprovable here (QEMU/TCG without a vTPM)."
fi

echo
if [ "$rc" -eq 0 ]; then
  echo "verify-boot-binding: reachable checks PASSED."
  echo "  Honest scope: A+B prove the SOFTWARE chain (running image + reported roothash)."
  echo "  Measured boot (C, the actual attestation claim) is only asserted-live, not proven —"
  echo "  the PCR-to-reference compare stays HARDWARE-GATED. os_roothash is real ONLY for the"
  echo "  build R you passed in; nothing here upgrades a placeholder R."
else
  echo "verify-boot-binding: a binding check FAILED (rc=$rc) — do NOT trust this node's attestation." >&2
fi
exit "$rc"
