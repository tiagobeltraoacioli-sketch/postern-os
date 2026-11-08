#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# verify-release.sh — customer/operator-side verification of a FULL signed
# release bundle (SHA256SUMS + SHA256SUMS.minisig + SHA256SUMS.pqsig),
# produced by sign-release.sh. Drives crates/postern-release's (Task 1's
# crate) `postern-release verify` for the PQ leg.
#
# Verifies, in the ONLY correct order:
#   1. minisign -V over SHA256SUMS              (classical Ed25519 leg)
#   2. `postern-release verify` over SHA256SUMS  (hybrid Falcon-1024 +
#      ML-DSA-87 leg — an AND of BOTH PQ algorithms; see
#      crates/postern-release's crate docs)
#   3. shasum -a 256 -c SHA256SUMS               (each artifact's bytes
#      against the now doubly-authenticated manifest)
#
# This order is NOT arbitrary: steps 1 and 2 authenticate SHA256SUMS itself
# BEFORE step 3 trusts a single byte of it to check artifacts. Running step 3
# first, or either signature check after it, would let a forged SHA256SUMS
# "pass" trivially — `shasum -c` only checks self-consistency with whatever
# SHA256SUMS says, not who wrote it.
#
# WHAT A PASS PROVES / DOES NOT PROVE:
#   * Proves the bundle came from the holder of BOTH the minisign secret key
#     AND both PQ secret keys, and is byte-identical to what was signed —
#     origin + integrity, full stop.
#   * Does NOT prove the binaries match any source. It is NOT attestation,
#     NOT a reproducibility proof, and NOT a security/audit sign-off.
#   * The minisign leg and the PQ leg are COMPLEMENTARY — both must pass;
#     neither replaces the other. ml-dsa (pre-1.0, RustCrypto) and
#     pqcrypto-falcon (wraps unaudited PQClean C) are UNAUDITED — see
#     crates/postern-release's crate docs for the full HONESTY section.
#
# Usage:
#   ./verify-release.sh -d <dir> -P <minisign-pubkey-str> --pq-pubkey <pq-key-prefix>
#   ./verify-release.sh -d <dir> -p <minisign-pubkey-file> --pq-pubkey <pq-key-prefix>
#   ./verify-release.sh --self-test
#
#   -d  directory with SHA256SUMS + SHA256SUMS.minisig + SHA256SUMS.pqsig
#       (required unless --self-test)
#   -P  minisign public key as a base64 string (mutually exclusive with -p)
#   -p  path to a minisign public-key file (mutually exclusive with -P)
#   --pq-pubkey <prefix>  postern-release PQ public-key prefix; names
#                         <prefix>.falcon.pub + <prefix>.mldsa.pub (required
#                         unless --self-test)
#   -b  path to a prebuilt `postern-release` binary. If omitted, this script
#       builds+runs it via
#       `cargo run --manifest-path crates/postern-release/Cargo.toml`.
#   --self-test  FULLY LOCAL, no external creds, no network: generates
#                EPHEMERAL minisign + PQ keys in a throwaway temp dir, signs
#                a throwaway fixture with sign-release.sh, verifies all THREE
#                legs above, and exits 0. Builds the postern-release crate
#                first via cargo if it is not already built. A pass proves
#                the pipeline's wiring — it is not a statement about any real
#                key or artifact.
#   -h  help
#
# Exit status: 0 = verified, non-zero = STOP, do not use the release.
#
# Depends on Task 1's crate (crates/postern-release) existing. Does not
# commit or push anything.
set -euo pipefail

die() { printf 'verify-release: %s\n' "$*" >&2; exit 1; }
log() { printf 'verify-release: %s\n' "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CRATE_MANIFEST="$REPO_ROOT/crates/postern-release/Cargo.toml"

# ── Pre-pass: pull out the long options getopts can't parse on its own ────
SELF_TEST=0
PQ_PUBKEY=""
ARGS=()
while [ $# -gt 0 ]; do
	case "$1" in
		--self-test) SELF_TEST=1; shift ;;
		--pq-pubkey)
			[ $# -ge 2 ] || die "--pq-pubkey needs a value"
			PQ_PUBKEY="$2"; shift 2 ;;
		--pq-pubkey=*) PQ_PUBKEY="${1#*=}"; shift ;;
		--) shift; ARGS+=("$@"); break ;;
		*) ARGS+=("$1"); shift ;;
	esac
done
if [ "${#ARGS[@]}" -gt 0 ]; then
	set -- "${ARGS[@]}"
else
	set --
fi

DIR=""
PUBSTR=""
PUBFILE=""
PREBUILT=""

while getopts ':d:P:p:b:h' opt; do
	case "$opt" in
		d) DIR="$OPTARG" ;;
		P) PUBSTR="$OPTARG" ;;
		p) PUBFILE="$OPTARG" ;;
		b) PREBUILT="$OPTARG" ;;
		h) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
		:) die "option -$OPTARG needs a value" ;;
		\?) die "unknown option -$OPTARG" ;;
	esac
done

command -v minisign >/dev/null 2>&1 || die "minisign not found (install: brew/apt/apk add minisign)"

if command -v sha256sum >/dev/null 2>&1; then
	SUMCHECK() { sha256sum -c "$@"; }
elif command -v shasum >/dev/null 2>&1; then
	SUMCHECK() { shasum -a 256 -c "$@"; }
else
	die "no sha256sum/shasum found"
fi

if [ -n "$PREBUILT" ]; then
	[ -x "$PREBUILT" ] || die "prebuilt binary not found/executable: $PREBUILT"
	run_pr() { "$PREBUILT" "$@"; }
else
	command -v cargo >/dev/null 2>&1 || die "cargo not found (needed to build/run postern-release; pass -b <bin> to skip)"
	[ -f "$CRATE_MANIFEST" ] || die "postern-release crate not found at $CRATE_MANIFEST (Task 1 dependency not present)"
	run_pr() { cargo run --quiet --manifest-path "$CRATE_MANIFEST" --bin postern-release -- "$@"; }
fi

# Run the three-legged verification in the ONLY correct order (see header).
# $2/$3 are the minisign pubkey as (pubstr, pubfile) — exactly one non-empty.
verify_all() {
	local dir="$1" pubstr="$2" pubfile="$3" pqprefix="$4"

	[ -d "$dir" ]                    || die "release dir not found: $dir"
	[ -f "$dir/SHA256SUMS" ]         || die "no SHA256SUMS in $dir"
	[ -f "$dir/SHA256SUMS.minisig" ] || die "no SHA256SUMS.minisig in $dir"
	[ -f "$dir/SHA256SUMS.pqsig" ]   || die "no SHA256SUMS.pqsig in $dir"
	[ -f "${pqprefix}.falcon.pub" ]  || die "PQ public key not found: ${pqprefix}.falcon.pub"
	[ -f "${pqprefix}.mldsa.pub" ]   || die "PQ public key not found: ${pqprefix}.mldsa.pub"

	if [ -n "$pubfile" ] && grep -qi 'dev.sample\|self-test' "$pubfile" 2>/dev/null; then
		log "NOTE: verifying against a DEV/SAMPLE or self-test minisign key --"
		log "      this only proves the flow, not authenticity of a real release."
	fi
	case "$pqprefix" in
		*dev-sample*|*self-test*)
			log "NOTE: verifying against a DEV/SAMPLE or self-test PQ key prefix"
			log "      ($pqprefix) -- flow-only, not a real release."
			;;
	esac

	log "step 1/3: verifying minisign signature over SHA256SUMS ..."
	if [ -n "$pubfile" ]; then
		minisign -Vm "$dir/SHA256SUMS" -x "$dir/SHA256SUMS.minisig" -p "$pubfile" \
			|| die "MINISIGN SIGNATURE INVALID -- STOP. Do not use this release."
	else
		minisign -Vm "$dir/SHA256SUMS" -x "$dir/SHA256SUMS.minisig" -P "$pubstr" \
			|| die "MINISIGN SIGNATURE INVALID -- STOP. Do not use this release."
	fi
	log "minisign leg OK"

	log "step 2/3: verifying hybrid Falcon-1024 + ML-DSA-87 (PQ) signature over SHA256SUMS ..."
	run_pr verify --artifacts "$dir" --pub "$pqprefix" \
		|| die "PQ HYBRID SIGNATURE INVALID -- STOP. Do not use this release."
	log "PQ leg OK (both Falcon-1024 AND ML-DSA-87 verified -- AND, not OR)"

	log "step 3/3: verifying artifact checksums against SHA256SUMS ..."
	( cd "$dir" && SUMCHECK SHA256SUMS ) || die "CHECKSUM MISMATCH -- STOP. Do not use this release."
	log "checksums OK"

	log "VERIFIED: minisign signature valid, PQ hybrid signature valid, and"
	log "every artifact matches SHA256SUMS."
	log "Reminder: this proves origin + integrity via TWO COMPLEMENTARY"
	log "signature schemes -- NOT reproducibility, NOT attestation, NOT an"
	log "audit. The ml-dsa/falcon legs are UNAUDITED."
}

run_self_test() {
	log "--self-test: fully local -- no external creds, no network."
	command -v cargo >/dev/null 2>&1 || die "cargo not found (needed for --self-test to build postern-release)"

	# Deliberately NOT `local`: the EXIT trap below fires after this function
	# returns (traps are script-scoped, not function-scoped, in bash), so
	# these must still be in scope when it runs.
	SELFTEST_TMP="$(mktemp -d "${TMPDIR:-/tmp}/postern-release-selftest.XXXXXX")"
	trap 'rm -rf "$SELFTEST_TMP"' EXIT
	local tmp="$SELFTEST_TMP"

	local art="$tmp/artifacts"
	mkdir -p "$art/nested"
	printf 'throwaway self-test fixture #1 (never a real release)\n' > "$art/fixture.txt"
	printf 'throwaway self-test fixture #2 (never a real release)\n' > "$art/nested/fixture2.txt"

	log "--self-test: generating an EPHEMERAL minisign key pair (password-less, $tmp only) ..."
	minisign -G -f -W -p "$tmp/minisign.pub" -s "$tmp/minisign.sec" >&2

	local pqprefix="$tmp/keys/self-test-dev-sample"
	log "--self-test: generating an EPHEMERAL postern-release PQ key pair ($tmp only) ..."
	run_pr keygen --out "$pqprefix" >&2

	log "--self-test: building the fixture's signed-release bundle via sign-release.sh ..."
	if [ -n "$PREBUILT" ]; then
		"$SCRIPT_DIR/sign-release.sh" -a "$art" -s "$tmp/minisign.sec" -k "$pqprefix" -t "self-test" -b "$PREBUILT" >&2
	else
		"$SCRIPT_DIR/sign-release.sh" -a "$art" -s "$tmp/minisign.sec" -k "$pqprefix" -t "self-test" >&2
	fi

	log "--self-test: now verifying that bundle through all three legs ..."
	verify_all "$art" "" "$tmp/minisign.pub" "$pqprefix"

	log "SELF-TEST PASSED: minisign leg, PQ hybrid leg, and shasum -c all"
	log "verified end-to-end against an ephemeral, throwaway fixture. This"
	log "proves the sign-release.sh / verify-release.sh pipeline wiring --"
	log "it is NOT a statement about any real key or artifact."
}

if [ "$SELF_TEST" -eq 1 ]; then
	run_self_test
	exit 0
fi

[ -n "$DIR" ] || die "missing -d <dir> (try -h)"
if [ -n "$PUBSTR" ] && [ -n "$PUBFILE" ]; then
	die "give exactly one of -P (key string) or -p (key file)"
fi
[ -n "$PUBSTR" ] || [ -n "$PUBFILE" ] || die "missing -P <key-string> or -p <key-file>"
if [ -n "$PUBFILE" ]; then [ -f "$PUBFILE" ] || die "minisign pubkey file not found: $PUBFILE"; fi
[ -n "$PQ_PUBKEY" ] || die "missing --pq-pubkey <prefix> (try -h)"

verify_all "$DIR" "$PUBSTR" "$PUBFILE" "$PQ_PUBKEY"
