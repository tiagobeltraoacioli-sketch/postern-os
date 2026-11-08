#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# verify-build.sh — customer-side verification of a signed enterprise delivery.
#
# Verifies, in the ONLY correct order:
#   1. the minisign signature over SHA256SUMS  (authenticates the manifest)
#   2. each artifact's sha256 against SHA256SUMS (authenticates the bytes)
#
# A PASS proves the delivery came from the holder of the pinned signing key and
# is byte-identical to what was signed. It does NOT prove the binaries match any
# source, and it is NOT attestation and NOT an audit. Reproducing from source
# remains the strongest verification (see PACKAGING.md).
#
# Usage:
#   ./verify-build.sh -d <delivery-dir> -P <minisign-pubkey-string>
#   ./verify-build.sh -d <delivery-dir> -p <minisign-pubkey-file>
#
#   -d  directory containing artifacts + SHA256SUMS + SHA256SUMS.minisig (required)
#   -P  minisign public key as a string (e.g. RWS...); mutually exclusive with -p
#   -p  path to a minisign public-key file (e.g. keys/dev-sample.pub)
#   -h  help
#
# Exit status: 0 = verified, non-zero = STOP, do not use the delivery.
set -euo pipefail

die() { printf 'verify-build: %s\n' "$*" >&2; exit 1; }
log() { printf 'verify-build: %s\n' "$*" >&2; }

DIR=""
PUBSTR=""
PUBFILE=""

while getopts ':d:P:p:h' opt; do
	case "$opt" in
		d) DIR="$OPTARG" ;;
		P) PUBSTR="$OPTARG" ;;
		p) PUBFILE="$OPTARG" ;;
		h) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
		:) die "option -$OPTARG needs a value" ;;
		\?) die "unknown option -$OPTARG" ;;
	esac
done

[ -n "$DIR" ] || die "missing -d <delivery-dir> (try -h)"
[ -d "$DIR" ] || die "delivery dir not found: $DIR"
[ -f "$DIR/SHA256SUMS" ]         || die "no SHA256SUMS in $DIR"
[ -f "$DIR/SHA256SUMS.minisig" ] || die "no SHA256SUMS.minisig in $DIR"
command -v minisign >/dev/null 2>&1 || die "minisign not found (install: brew/apt/apk add minisign)"

if [ -n "$PUBSTR" ] && [ -n "$PUBFILE" ]; then
	die "give exactly one of -P (key string) or -p (key file)"
fi
[ -n "$PUBSTR" ] || [ -n "$PUBFILE" ] || die "missing -P <key-string> or -p <key-file>"
if [ -n "$PUBFILE" ]; then [ -f "$PUBFILE" ] || die "pubkey file not found: $PUBFILE"; fi

# Warn if verifying against the DEV/SAMPLE key.
if [ -n "$PUBFILE" ] && grep -q 'DEV SAMPLE' "$PUBFILE" 2>/dev/null; then
	log "NOTE: verifying against the DEV/SAMPLE key — this only proves the flow,"
	log "      not authenticity of a real Postern Enterprise delivery."
fi

# ── Step 1: signature over SHA256SUMS ───────────────────────────────────────
log "step 1/2: verifying minisign signature over SHA256SUMS ..."
if [ -n "$PUBFILE" ]; then
	minisign -Vm "$DIR/SHA256SUMS" -x "$DIR/SHA256SUMS.minisig" -p "$PUBFILE" \
		|| die "SIGNATURE INVALID — STOP. Do not use this delivery."
else
	minisign -Vm "$DIR/SHA256SUMS" -x "$DIR/SHA256SUMS.minisig" -P "$PUBSTR" \
		|| die "SIGNATURE INVALID — STOP. Do not use this delivery."
fi
log "signature OK"

# ── Step 2: each artifact checksum ──────────────────────────────────────────
log "step 2/2: verifying artifact checksums against SHA256SUMS ..."
if command -v sha256sum >/dev/null 2>&1; then
	( cd "$DIR" && sha256sum -c SHA256SUMS ) || die "CHECKSUM MISMATCH — STOP. Do not use this delivery."
elif command -v shasum >/dev/null 2>&1; then
	( cd "$DIR" && shasum -a 256 -c SHA256SUMS ) || die "CHECKSUM MISMATCH — STOP. Do not use this delivery."
else
	die "no sha256sum/shasum found"
fi

log "VERIFIED: signature valid and every artifact matches SHA256SUMS."
log "Reminder: this proves origin + integrity, not reproducibility or audit."
