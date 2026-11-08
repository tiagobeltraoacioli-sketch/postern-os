#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# sign-build.sh — produce a signed enterprise-build manifest for a delivery.
#
# Given a directory of release artifacts, this writes a SHA256SUMS manifest over
# every file and a detached minisign signature (SHA256SUMS.minisig) over that
# manifest. This mirrors the project's existing OS/pmOS convention exactly
# (see ../../../pmos-overlay/FLASH.md and pmos-overlay/publish-to-r2.sh): the
# signature authenticates SHA256SUMS, and SHA256SUMS authenticates each artifact.
#
# WHAT THIS IS / IS NOT:
#   * This is a reproducible-by-design PACKAGING + SIGNING step for enterprise
#     delivery. It is NOT an attestation, NOT a reproducibility proof, and NOT a
#     security/audit sign-off. A valid signature proves only that the bytes came
#     from the holder of the signing key, unmodified since signing.
#   * The signing key is OPERATOR-run. This script never embeds a key. Point it
#     at a secret key you control (-s). The keys/dev-sample.* pair in this repo
#     is a DEV/SAMPLE key for testing the flow ONLY — never sign a real delivery
#     with it, and never ship it as if it were a production key.
#
# Usage:
#   ./sign-build.sh -a <artifacts-dir> -s <minisign-secret-key> [-o <out-dir>] [-t <tag>]
#
#   -a  directory containing the build artifacts to sign (required)
#   -s  path to the minisign secret key (required; operator-held, never committed)
#   -o  output dir for SHA256SUMS + SHA256SUMS.minisig (default: <artifacts-dir>)
#   -t  human tag for the signed trusted-comment (default: "postern-enterprise")
#   -h  help
#
# Env:
#   MINISIGN_PASSWORD  if set, passed to minisign so this can run unattended in
#                      an operator CI. Leave unset for an interactive prompt.
set -euo pipefail

die() { printf 'sign-build: %s\n' "$*" >&2; exit 1; }
log() { printf 'sign-build: %s\n' "$*" >&2; }

ART=""
SECKEY=""
OUT=""
TAG="postern-enterprise"

while getopts ':a:s:o:t:h' opt; do
	case "$opt" in
		a) ART="$OPTARG" ;;
		s) SECKEY="$OPTARG" ;;
		o) OUT="$OPTARG" ;;
		t) TAG="$OPTARG" ;;
		h) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
		:) die "option -$OPTARG needs a value" ;;
		\?) die "unknown option -$OPTARG" ;;
	esac
done

[ -n "$ART" ]    || die "missing -a <artifacts-dir> (try -h)"
[ -d "$ART" ]    || die "artifacts dir not found: $ART"
[ -n "$SECKEY" ] || die "missing -s <minisign-secret-key> (try -h)"
[ -f "$SECKEY" ] || die "secret key not found: $SECKEY"
command -v minisign >/dev/null 2>&1 || die "minisign not found (install: brew/apt/apk add minisign)"

OUT="${OUT:-$ART}"
mkdir -p "$OUT"

# Loud guard: refuse to silently sign with the shipped DEV/SAMPLE key.
case "$SECKEY" in
	*dev-sample*)
		log "WARNING: signing with the DEV/SAMPLE key. This is for testing the"
		log "         pipeline ONLY. The result is NOT a production signature and"
		log "         MUST NOT be delivered to a customer as one."
		;;
esac

# Pick a sha256 tool (GNU coreutils or macOS/BSD shasum), same probe as the repo.
if command -v sha256sum >/dev/null 2>&1; then
	SUM() { sha256sum "$@"; }
elif command -v shasum >/dev/null 2>&1; then
	SUM() { shasum -a 256 "$@"; }
else
	die "no sha256sum/shasum found"
fi

SUMS="$OUT/SHA256SUMS"
SIG="$OUT/SHA256SUMS.minisig"

# Build SHA256SUMS over every regular file in the artifacts dir, EXCLUDING the
# manifest/signature themselves. Paths are recorded relative to the artifacts
# dir so `sha256sum -c` works from there on the customer side.
log "hashing artifacts under $ART ..."
# Stage the manifest OUTSIDE the artifacts dir so the temp file is never itself
# hashed, then move it in once complete.
TMP="$(mktemp "${TMPDIR:-/tmp}/sha256sums.XXXXXX")"
trap 'rm -f "$TMP"' EXIT
( cd "$ART" && find . -type f \
		! -name 'SHA256SUMS' ! -name 'SHA256SUMS.minisig' \
		| LC_ALL=C sort ) | while IFS= read -r rel; do
	rel="${rel#./}"
	( cd "$ART" && SUM "$rel" ) >> "$TMP"
done
mv "$TMP" "$SUMS"
trap - EXIT
COUNT=$(wc -l < "$SUMS" | tr -d ' ')
[ "$COUNT" -gt 0 ] || die "no artifacts to sign in $ART"
log "SHA256SUMS lists $COUNT artifact(s)"

# Sign SHA256SUMS with a descriptive trusted comment (verifiable, tamper-evident).
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
TRUSTED="Postern Enterprise delivery -- $TAG -- signed $TS"
log "signing SHA256SUMS with $SECKEY ..."
if [ -n "${MINISIGN_PASSWORD+set}" ]; then
	printf '%s\n' "$MINISIGN_PASSWORD" | \
		minisign -S -s "$SECKEY" -m "$SUMS" -x "$SIG" -c "detached signature over SHA256SUMS" -t "$TRUSTED"
else
	minisign -S -s "$SECKEY" -m "$SUMS" -x "$SIG" -c "detached signature over SHA256SUMS" -t "$TRUSTED"
fi

log "wrote:"
log "  $SUMS"
log "  $SIG"
log "Deliver BOTH alongside the artifacts. Customer verifies with verify-build.sh."
