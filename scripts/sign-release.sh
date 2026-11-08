#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# sign-release.sh — operator-facing driver for a FULL signed-release bundle.
#
# Given a directory of release artifacts, this drives crates/postern-release's
# `postern-release` binary (Task 1's crate) plus minisign to produce THREE
# files:
#
#   SHA256SUMS          - manifest, one `<sha256-hex>  <relative-path>` line
#                          per artifact. Written by `postern-release sign`
#                          (crates/postern-release), which mirrors the repo's
#                          existing enterprise/pmOS convention byte-for-byte
#                          (see enterprise/deployment/signing/sign-build.sh).
#   SHA256SUMS.minisig  - minisign(Ed25519) detached signature over SHA256SUMS,
#                          the EXACT convention already used by
#                          enterprise/deployment/signing/{sign,verify}-build.sh
#                          and pmos-overlay's publish flow.
#   SHA256SUMS.pqsig    - crates/postern-release's detached HYBRID
#                          Falcon-1024 + ML-DSA-87 signature over the SAME
#                          SHA256SUMS bytes.
#
# WHAT THIS IS / IS NOT:
#   * This is a PACKAGING + SIGNING step, nothing more. It is NOT an
#     attestation, NOT a reproducibility proof, and NOT a security/audit
#     sign-off. A valid signature proves only that the bytes came from the
#     holder of the signing key(s), unmodified since signing.
#   * The minisign leg and the PQ (hybrid Falcon-1024 + ML-DSA-87) leg are
#     COMPLEMENTARY, not redundant — ship and verify BOTH. Neither replaces
#     the other. See verify-release.sh for the only correct verification
#     order.
#   * ml-dsa (pre-1.0, RustCrypto) and pqcrypto-falcon (wraps unaudited
#     PQClean C) are UNAUDITED — see crates/postern-release's crate docs for
#     the full HONESTY section. Treat the PQ leg as experimental
#     defense-in-depth, not a stronger guarantee than minisign's mature
#     Ed25519.
#   * BOTH secret keys are OPERATOR-run. This script never embeds a key and
#     never writes key material anywhere on its own initiative. Point it at
#     keys you control (-s, -k). A `dev-sample`-named key in EITHER slot is
#     DEV/SAMPLE-grade for testing the flow ONLY — never sign a real release
#     with it, and never ship its output as if it were a production
#     signature.
#
# Usage:
#   ./sign-release.sh -a <artifacts-dir> -s <minisign-seckey> -k <pq-key-prefix> \
#                      [-o <out-dir>] [-t <tag>] [-b <postern-release-bin>]
#
#   -a  directory containing the build artifacts to sign (required)
#   -s  path to the minisign secret key (required; operator-held, never
#       committed to this repo)
#   -k  postern-release PQ key-prefix (required; operator-held). A prefix of
#       "some/path/prefix" names FOUR files: prefix.falcon.{pub,sec} and
#       prefix.mldsa.{pub,seed} — produced by
#       `postern-release keygen --out <prefix>`.
#   -o  output dir for SHA256SUMS.minisig + SHA256SUMS.pqsig (default: -a).
#       NOTE: SHA256SUMS itself is always written INTO the artifacts dir by
#       `postern-release sign` (that crate's own design — it builds the
#       manifest over -a, not over -o) — -o only relocates the two signature
#       files, it does not move the manifest.
#   -t  human tag for the minisign signed trusted-comment (default:
#       "postern-release")
#   -b  path to a prebuilt `postern-release` binary. If omitted, this script
#       builds+runs it via
#       `cargo run --manifest-path crates/postern-release/Cargo.toml`.
#   -h  help
#
# Env:
#   MINISIGN_PASSWORD  if set, passed to minisign so this can run unattended
#                      in an operator CI. Leave unset for an interactive
#                      prompt.
#
# Depends on Task 1's crate (crates/postern-release) existing. Does not
# commit or push anything.
set -euo pipefail

die() { printf 'sign-release: %s\n' "$*" >&2; exit 1; }
log() { printf 'sign-release: %s\n' "$*" >&2; }

ART=""
SECKEY=""
KEYPREFIX=""
OUT=""
TAG="postern-release"
PREBUILT=""

while getopts ':a:s:k:o:t:b:h' opt; do
	case "$opt" in
		a) ART="$OPTARG" ;;
		s) SECKEY="$OPTARG" ;;
		k) KEYPREFIX="$OPTARG" ;;
		o) OUT="$OPTARG" ;;
		t) TAG="$OPTARG" ;;
		b) PREBUILT="$OPTARG" ;;
		h) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
		:) die "option -$OPTARG needs a value" ;;
		\?) die "unknown option -$OPTARG" ;;
	esac
done

[ -n "$ART" ]       || die "missing -a <artifacts-dir> (try -h)"
[ -d "$ART" ]       || die "artifacts dir not found: $ART"
[ -n "$SECKEY" ]    || die "missing -s <minisign-secret-key> (try -h)"
[ -f "$SECKEY" ]    || die "minisign secret key not found: $SECKEY"
[ -n "$KEYPREFIX" ] || die "missing -k <pq-key-prefix> (try -h)"
[ -f "${KEYPREFIX}.falcon.sec" ] || die "PQ secret key not found: ${KEYPREFIX}.falcon.sec"
[ -f "${KEYPREFIX}.mldsa.seed" ] || die "PQ secret key not found: ${KEYPREFIX}.mldsa.seed"
command -v minisign >/dev/null 2>&1 || die "minisign not found (install: brew/apt/apk add minisign)"

OUT="${OUT:-$ART}"
mkdir -p "$OUT"

# Loud guard: refuse to silently sign with a shipped DEV/SAMPLE key, in
# either slot. Same convention as enterprise/deployment/signing/sign-build.sh.
case "$SECKEY" in
	*dev-sample*)
		log "WARNING: signing with a DEV/SAMPLE minisign key ($SECKEY). This is"
		log "         for testing the pipeline ONLY. The result is NOT a"
		log "         production signature and MUST NOT be delivered to anyone"
		log "         as one."
		;;
esac
case "$KEYPREFIX" in
	*dev-sample*)
		log "WARNING: signing with a DEV/SAMPLE PQ key prefix ($KEYPREFIX). This"
		log "         is for testing the pipeline ONLY. The result is NOT a"
		log "         production signature and MUST NOT be delivered to anyone"
		log "         as one."
		;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CRATE_MANIFEST="$REPO_ROOT/crates/postern-release/Cargo.toml"

if [ -n "$PREBUILT" ]; then
	[ -x "$PREBUILT" ] || die "prebuilt binary not found/executable: $PREBUILT"
	run_pr() { "$PREBUILT" "$@"; }
else
	command -v cargo >/dev/null 2>&1 || die "cargo not found (needed to build/run postern-release; pass -b <bin> to skip)"
	[ -f "$CRATE_MANIFEST" ] || die "postern-release crate not found at $CRATE_MANIFEST (Task 1 dependency not present)"
	run_pr() { cargo run --quiet --manifest-path "$CRATE_MANIFEST" --bin postern-release -- "$@"; }
fi

SUMS="$ART/SHA256SUMS"
PQSIG="$OUT/SHA256SUMS.pqsig"
MINISIG="$OUT/SHA256SUMS.minisig"

# ── Step 1: build SHA256SUMS + the PQ (hybrid Falcon-1024/ML-DSA-87) leg ───
log "building SHA256SUMS and SHA256SUMS.pqsig over $ART via postern-release ..."
run_pr sign --artifacts "$ART" --key "$KEYPREFIX" --out "$PQSIG"
[ -f "$SUMS" ]  || die "postern-release sign did not produce $SUMS"
[ -f "$PQSIG" ] || die "postern-release sign did not produce $PQSIG"

# ── Step 2: the minisign (Ed25519) leg over the SAME SHA256SUMS bytes ─────
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
TRUSTED="Postern Release -- $TAG -- signed $TS"
log "signing SHA256SUMS with minisign ($SECKEY) ..."
if [ -n "${MINISIGN_PASSWORD+set}" ]; then
	printf '%s\n' "$MINISIGN_PASSWORD" | \
		minisign -S -s "$SECKEY" -m "$SUMS" -x "$MINISIG" -c "detached signature over SHA256SUMS" -t "$TRUSTED"
else
	minisign -S -s "$SECKEY" -m "$SUMS" -x "$MINISIG" -c "detached signature over SHA256SUMS" -t "$TRUSTED"
fi
[ -f "$MINISIG" ] || die "minisign did not produce $MINISIG"

log "wrote:"
log "  $SUMS"
log "  $MINISIG"
log "  $PQSIG"
log "Deliver ALL THREE alongside the artifacts. Verify with verify-release.sh"
log "(checks minisign, then the PQ hybrid leg, then shasum -c, in that order —"
log "the ONLY correct order; see that script's header)."
