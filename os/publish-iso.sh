#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# publish-iso.sh -- fetch a built "Postern OS" ISO from the AWS S3 build-artifact
# bucket, verify its SHA-256, then publish it to the project's Cloudflare R2
# downloads bucket alongside a minisign-signed SHA256SUMS -- the SAME os/v0.1/
# layout, System-B minisign key, and fail-safe upload order already live for
# postern-os-node-x86_64.iso / postern-os-desktop-x86_64.iso /
# postern-os-mobile-pinephone-aarch64.img (see site/downloads.html).
#
#   Product: "Postern OS" (Nix-built; see os/README.md, os/ATTESTATION.md).
#   Hosting + signing a release is NOT attestation. Built is NOT booted.
#   Reproducible-by-design != reproduced by a third party. Mainnet-beta,
#   UNAUDITED. Never let this script, or the page it feeds, claim otherwise.
#
# This is the OS-tier sibling of pmos-overlay/publish-to-r2.sh (System B for
# "Postern for postmarketOS"). Same R2 bucket, same minisign key, same
# fail-safe order -- but a DIFFERENT product name guard ("Postern OS", not
# "Postern for postmarketOS") and a DIFFERENT source: this script starts from
# an S3 build artifact, not a local build/build.sh output. It reuses
# pmos-overlay/build/r2_upload.py unmodified -- that tool is pure R2/S3
# plumbing with no pmOS-specific logic.
#
# ---------------------------------------------------------------------------
# TWO DIFFERENT CREDENTIAL PAIRS -- DO NOT CONFUSE THEM
# ---------------------------------------------------------------------------
#   SOURCE       real AWS, us-west-2, the CI build-artifact bucket:
#     SRC_AWS_ACCESS_KEY_ID / SRC_AWS_SECRET_ACCESS_KEY   (required, real run)
#     SRC_AWS_REGION                                       (default: us-west-2)
#     SRC_BUCKET                                           (default: postern-os-build-1783966602)
#
#   DESTINATION  Cloudflare R2, the public downloads bucket:
#     AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY   an R2 API token (required, real run)
#     R2_BUCKET            (default: postern-downloads)
#     R2_ACCOUNT_ID        endpoint = https://$R2_ACCOUNT_ID.r2.cloudflarestorage.com
#     R2_ENDPOINT_URL      full endpoint URL (overrides R2_ACCOUNT_ID)
#     R2_PUBLIC_BASE_URL   public host (default: https://pub-dca67fd26bfb4a6b98115e596095ecd3.r2.dev)
#     MINISIGN_PASSWORD    secret-key password, piped to minisign (optional; else prompt)
#     MINISIGN_PUBKEY      expected public key (default: the os/v0.1 key below)
#
#   The SRC_* pair is scoped to the single S3 fetch step ONLY, via `env`, never
#   `export` -- so it can never leak into the R2 upload step, which reuses the
#   AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY names for boto3 against R2, per
#   r2_upload.py's own convention. Setting both pairs as plain exported AWS_*
#   vars in your shell before running this script WILL cause the fetch to hit
#   R2 or the upload to hit AWS S3 -- use the SRC_*-prefixed names for the
#   source leg, always.
#
# ---------------------------------------------------------------------------
# HONESTY GUARD (this is the enforcement point -- read before flag-mashing)
# ---------------------------------------------------------------------------
#   * refuses unless --product is exactly "Postern OS";
#   * refuses unless --boot-status is one of the real vocabulary this repo
#     uses (UNBOOTED, QEMU-PENDING, QEMU-PASS:<evidence>@<date>,
#     HARDWARE-BOOTED:<device>@<date>) -- QEMU-PASS / HARDWARE-BOOTED both
#     REQUIRE --boot-evidence (a path or URL to the boot log / .evidence
#     sidecar from os/boot-harness*/check-boot-log.sh); no evidence, no claim;
#   * always prints "UNAUDITED -- mainnet-beta" on the summary; there is no
#     flag to turn that off;
#   * refuses --attestable (attestation is a separate, unaudited chain --
#     os/ATTESTATION.md -- "no attestation claim is adopted until the whole
#     chain is audited"; this script cannot certify that, so it never emits it);
#   * refuses if the downloaded file size doesn't match S3's own
#     Content-Length (truncated-transfer guard);
#   * refuses if --sha256 was given and doesn't match the on-disk hash;
#   * refuses to upload an artifact name that isn't already in the
#     functions/dl/[[path]].js allowlist, UNLESS --allow-new-name is passed
#     (then it prints the exact follow-up edits required before the /dl/
#     redirector will serve it -- publishing to R2 does not, by itself, wire
#     up the counted download link);
#   * refuses if the minisign secret key does not correspond to the published
#     public key.
#
# Fail-safe upload order (clients verify sig -> SHA256SUMS -> image, so the
# signature is the authenticating "flip", written LAST):
#   1. <name>              immutable, long cache
#   2. <name>.sha256       sidecar (short cache; matches build.sh's own convention)
#   3. SHA256SUMS          short cache
#   4. SHA256SUMS.minisig  the flip -- last
#
# Usage:
#   ./os/publish-iso.sh -k builds/2026-07-13/postern-os-node-x86_64.iso \
#       -o postern-os-node-x86_64.iso \
#       -B QEMU-PENDING \
#       -c <expected-sha256> \
#       -s ~/.minisign/postern-os.key \
#       -n            # dry run: fetch + verify + sign locally, NO R2 network
#
#   # real publish (creds from the CI secret store / your env):
#   ./os/publish-iso.sh -k builds/2026-07-13/postern-os-node-x86_64.iso \
#       -o postern-os-node-x86_64.iso -B QEMU-PENDING -c <sha256> \
#       -s ~/.minisign/postern-os.key
#
set -eu

PROG=$(basename "$0")
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
UPLOADER="$SCRIPT_DIR/../pmos-overlay/build/r2_upload.py"

DEFAULT_PUBKEY='RWTSe98wfKKHuVRDnywuQmH/cMyP/HNuD/hFFLQeKdQeAHENliqJpmKs'
DEFAULT_PUBLIC_BASE='https://pub-dca67fd26bfb4a6b98115e596095ecd3.r2.dev'
DEFAULT_SRC_BUCKET='postern-os-build-1783966602'
DEFAULT_SRC_REGION='us-west-2'
DEFAULT_PREFIX='os/v0.1'
DEFAULT_PRODUCT='Postern OS'

# The only filenames the live /dl/ redirector (functions/dl/[[path]].js)
# currently allowlists. Publishing under any OTHER name still lands the bytes
# on R2, but the counted /dl/ link 404s until the allowlist + downloads.html
# are updated -- see the --allow-new-name follow-up printout below.
KNOWN_NAMES='postern-os-node-x86_64.iso postern-os-desktop-x86_64.iso postern-os-mobile-pinephone-aarch64.img'

usage() {
	cat <<'EOF'
usage: publish-iso.sh -k <s3-key> -o <published-name> -B <boot-status>
                       -s <minisign.key> [-c <sha256>] [-b <src-bucket>]
                       [-r <src-region>] [-p os/v0.1] [-P "Postern OS"]
                       [-e <boot-evidence>] [--allow-new-name] [-n]

  -k  S3 key of the built ISO inside the source bucket (required)
  -o  filename to publish it as on R2 (required; must already be in the
      functions/dl allowlist unless --allow-new-name is given)
  -B  boot status, one of:
        UNBOOTED                          nobody has tried to boot it
        QEMU-PENDING                      no QEMU boot log published yet
        QEMU-PASS:<evidence>@<YYYY-MM-DD> QEMU boot graded PASS; -e required
        HARDWARE-BOOTED:<device>@<YYYY-MM-DD>  real hardware boot; -e required
  -e  path/URL to the boot log or .evidence sidecar (required for
      QEMU-PASS / HARDWARE-BOOTED; ignored otherwise)
  -s  path to the minisign SECRET key used to sign SHA256SUMS
      (its public half must match MINISIGN_PUBKEY / the published key)
  -c  expected sha256 of the ISO (recommended -- e.g. from the build log /
      a <key>.sha256 sidecar); if omitted the script only reports the hash,
      it cannot cross-check it against anything
  -b  source S3 bucket (default: postern-os-build-1783966602)
  -r  source S3 region (default: us-west-2)
  -p  R2 key prefix for images (default: os/v0.1)
  -P  product label guard (default: "Postern OS"; the only accepted value)
  --allow-new-name  bypass the KNOWN_NAMES check (prints required follow-ups)
  -n  dry run: fetch, verify, build & sign SHA256SUMS locally; NO R2 network,
      NO R2 creds touched. (The S3 fetch itself still happens -- that part is
      read-only against the source bucket and needed to compute the hash.)

env: SRC_AWS_ACCESS_KEY_ID SRC_AWS_SECRET_ACCESS_KEY [SRC_AWS_REGION] [SRC_BUCKET]
     AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY R2_BUCKET
     R2_ACCOUNT_ID|R2_ENDPOINT_URL [R2_PUBLIC_BASE_URL] [MINISIGN_PASSWORD] [MINISIGN_PUBKEY]
EOF
	exit 2
}

log() { printf '%s\n' "$*"; }
die() { printf '%s: error: %s\n' "$PROG" "$*" >&2; exit 1; }

sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
	else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# ---------------------------------------------------------------- arguments
SRC_KEY='' NAME='' BOOT_STATUS='' BOOT_EVIDENCE='' SECKEY='' EXPECT_SHA=''
SRC_BUCKET="$DEFAULT_SRC_BUCKET" SRC_REGION="$DEFAULT_SRC_REGION"
PREFIX="$DEFAULT_PREFIX" PRODUCT="$DEFAULT_PRODUCT"
ALLOW_NEW_NAME=0 DRY_RUN=0

# getopts has no long-option support in POSIX sh; hand-roll --allow-new-name.
ARGS=""
for a in "$@"; do
	case "$a" in
		--allow-new-name) ALLOW_NEW_NAME=1 ;;
		*) ARGS="$ARGS
$a" ;;
	esac
done
# Rebuild positional params without the long flag so getopts sees only short ones.
set --
OLDIFS=$IFS
IFS='
'
for a in $ARGS; do
	[ -n "$a" ] && set -- "$@" "$a"
done
IFS=$OLDIFS

while getopts k:o:B:e:s:c:b:r:p:P:n opt; do
	case $opt in
		k) SRC_KEY=$OPTARG ;;
		o) NAME=$OPTARG ;;
		B) BOOT_STATUS=$OPTARG ;;
		e) BOOT_EVIDENCE=$OPTARG ;;
		s) SECKEY=$OPTARG ;;
		c) EXPECT_SHA=$OPTARG ;;
		b) SRC_BUCKET=$OPTARG ;;
		r) SRC_REGION=$OPTARG ;;
		p) PREFIX=$OPTARG ;;
		P) PRODUCT=$OPTARG ;;
		n) DRY_RUN=1 ;;
		*) usage ;;
	esac
done
[ -n "$SRC_KEY" ] && [ -n "$NAME" ] && [ -n "$BOOT_STATUS" ] || usage
command -v aws >/dev/null 2>&1 || die "aws CLI required (S3 fetch)"
command -v python3 >/dev/null 2>&1 || die "python3 required (R2 uploader)"
PREFIX=${PREFIX%/}
case $PREFIX in os/*) ;; *) die "prefix must be under os/ (got: $PREFIX)";; esac

log "== Postern OS -- publish ISO to R2 (from AWS S3 build bucket) =="
log "   (hosting + signing a release is NOT attestation; built is NOT booted -- os/ATTESTATION.md)"
log ""

# ------------------------------------------------------------- HONESTY GUARD
[ "$PRODUCT" = "Postern OS" ] \
	|| die "honest-status violation: product must be exactly 'Postern OS' (got '$PRODUCT'). \
This script never publishes under 'Postern for postmarketOS' / 'Postern Android' -- use pmos-overlay/publish-to-r2.sh for that tier."

case $BOOT_STATUS in
	UNBOOTED|QEMU-PENDING)
		[ -z "$BOOT_EVIDENCE" ] || log "NOTE: -e/--boot-evidence given but ignored for boot-status '$BOOT_STATUS' (no boot is being claimed)."
		;;
	QEMU-PASS:*@????-??-??|HARDWARE-BOOTED:*@????-??-??)
		[ -n "$BOOT_EVIDENCE" ] \
			|| die "boot-status '$BOOT_STATUS' claims a real boot -- (-e/--boot-evidence <path-or-url to the boot log / .evidence sidecar>) is required. \
No evidence, no claim (os/boot-harness*/check-boot-log.sh is the source of that evidence; 'do not cite this directory as proof of a boot' until it has actually run)."
		;;
	*)
		die "boot-status must be one of: UNBOOTED, QEMU-PENDING, QEMU-PASS:<evidence>@<YYYY-MM-DD>, HARDWARE-BOOTED:<device>@<YYYY-MM-DD> (got '$BOOT_STATUS')"
		;;
esac
log "boot status: $BOOT_STATUS${BOOT_EVIDENCE:+ (evidence: $BOOT_EVIDENCE)}"
log "attestation: NOT CLAIMED (a separate, unaudited chain -- os/ATTESTATION.md; this script never emits an attestable label)"
log "audit status: UNAUDITED -- mainnet-beta. Not a security or investment claim; the coin is worthless by design."
log ""

case " $KNOWN_NAMES " in
	*" $NAME "*) ;;
	*)
		[ "$ALLOW_NEW_NAME" -eq 1 ] || die "refusing: '$NAME' is not in the current /dl/ allowlist (functions/dl/[[path]].js) and --allow-new-name was not given. \
Known names: $KNOWN_NAMES"
		log "NOTE: '$NAME' is a NEW artifact name -- functions/dl/[[path]].js's ALLOW set and site/downloads.html's table both need a follow-up edit after this publish (printed again at the end)."
		;;
esac

# --------------------------------------------------------------- S3 fetch
WORKDIR=$(mktemp -d) || die "mktemp failed"
trap 'rm -rf "$WORKDIR"' EXIT INT TERM
LOCAL_FILE="$WORKDIR/$NAME"

SRC_ACCESS_ENV=${SRC_AWS_ACCESS_KEY_ID:-}
SRC_SECRET_ENV=${SRC_AWS_SECRET_ACCESS_KEY:-}
[ -n "$SRC_ACCESS_ENV" ] && [ -n "$SRC_SECRET_ENV" ] \
	|| die "set SRC_AWS_ACCESS_KEY_ID and SRC_AWS_SECRET_ACCESS_KEY (the SOURCE S3 bucket creds -- NOT the R2 ones; see the header comment)"
SRC_BUCKET=${SRC_BUCKET:-$DEFAULT_SRC_BUCKET}
SRC_REGION=${SRC_REGION:-$DEFAULT_SRC_REGION}

log "fetching s3://$SRC_BUCKET/$SRC_KEY (region $SRC_REGION) ..."
# Content-Length first, so a truncated download is caught below -- scoped
# with `env`, never `export`, so these creds cannot leak into the R2 step.
REMOTE_LEN=$(env AWS_ACCESS_KEY_ID="$SRC_ACCESS_ENV" AWS_SECRET_ACCESS_KEY="$SRC_SECRET_ENV" AWS_DEFAULT_REGION="$SRC_REGION" \
	aws s3api head-object --bucket "$SRC_BUCKET" --key "$SRC_KEY" --query ContentLength --output text 2>&1) \
	|| die "head-object failed for s3://$SRC_BUCKET/$SRC_KEY -- $REMOTE_LEN"
case $REMOTE_LEN in ''|*[!0-9]*) die "unexpected Content-Length from S3: '$REMOTE_LEN'";; esac
log "source Content-Length: $REMOTE_LEN bytes"

env AWS_ACCESS_KEY_ID="$SRC_ACCESS_ENV" AWS_SECRET_ACCESS_KEY="$SRC_SECRET_ENV" AWS_DEFAULT_REGION="$SRC_REGION" \
	aws s3 cp "s3://$SRC_BUCKET/$SRC_KEY" "$LOCAL_FILE" \
	|| die "s3 cp failed for s3://$SRC_BUCKET/$SRC_KEY"

LOCAL_LEN=$(wc -c < "$LOCAL_FILE" | tr -d ' ')
[ "$LOCAL_LEN" = "$REMOTE_LEN" ] \
	|| die "TRUNCATED TRANSFER: downloaded $LOCAL_LEN bytes, S3 reports $REMOTE_LEN bytes -- do not sign or publish this file, re-fetch"
log "downloaded $LOCAL_LEN bytes, matches S3 Content-Length -- transfer looks intact"

# --------------------------------------------------------------- SHA-256
log "hashing $NAME ..."
IMG_SHA=$(sha256_of "$LOCAL_FILE")
log "sha256: $IMG_SHA"
if [ -n "$EXPECT_SHA" ]; then
	[ "$EXPECT_SHA" = "$IMG_SHA" ] \
		|| die "SHA-256 MISMATCH: expected=$EXPECT_SHA on-disk=$IMG_SHA -- do not sign or publish, the artifact does not match what you verified"
	log "sha256 matches the expected value you supplied with -c"
else
	log "WARNING: no -c/--sha256 was given -- this hash was computed but not cross-checked against anything. \
Cross-check it against the CI build log / a <key>.sha256 sidecar before signing, by hand, before re-running with -c."
fi
log ""

# ------------------------------------------------------------- environment
PUBKEY=${MINISIGN_PUBKEY:-$DEFAULT_PUBKEY}
PUBLIC_BASE=${R2_PUBLIC_BASE_URL:-$DEFAULT_PUBLIC_BASE}
BUCKET=${R2_BUCKET:-postern-downloads}
ENDPOINT=''
if [ "$DRY_RUN" -eq 0 ]; then
	command -v minisign >/dev/null 2>&1 || die "minisign not found (needed to sign SHA256SUMS)"
	[ -n "$SECKEY" ] || die "-s <minisign secret key> is required for a real publish"
	[ -f "$SECKEY" ] || die "minisign secret key not found: $SECKEY"
	[ -f "$UPLOADER" ] || die "uploader missing: $UPLOADER (expected pmos-overlay/build/r2_upload.py)"
	python3 -c 'import boto3' 2>/dev/null || die "boto3 required for upload (pip install boto3)"
	: "${AWS_ACCESS_KEY_ID:?set AWS_ACCESS_KEY_ID (R2 API token Access Key ID -- NOT the SRC_* S3 creds)}"
	: "${AWS_SECRET_ACCESS_KEY:?set AWS_SECRET_ACCESS_KEY (R2 API token Secret Access Key -- NOT the SRC_* S3 creds)}"
	if [ -n "${R2_ENDPOINT_URL:-}" ]; then ENDPOINT=$R2_ENDPOINT_URL
	elif [ -n "${R2_ACCOUNT_ID:-}" ]; then ENDPOINT="https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com"
	else die "set R2_ACCOUNT_ID or R2_ENDPOINT_URL"; fi
else
	if [ -n "${SECKEY:-}" ] && [ ! -f "$SECKEY" ]; then die "minisign secret key not found: $SECKEY"; fi
fi

r2() { R2_ENDPOINT_URL="$ENDPOINT" R2_BUCKET="$BUCKET" python3 "$UPLOADER" "$@"; }

# ------------------------------------------------ assemble & sign SHA256SUMS
SUMS="$WORKDIR/SHA256SUMS"
: > "$SUMS"

if [ "$DRY_RUN" -eq 0 ]; then
	if r2 get --key "$PREFIX/SHA256SUMS" --file "$SUMS" 2>/dev/null; then
		log "merged existing remote SHA256SUMS ($(wc -l < "$SUMS" | tr -d ' ') line(s))"
	else
		log "no existing remote SHA256SUMS -- starting a fresh one"
		: > "$SUMS"
	fi
else
	log "DRY-RUN: not fetching remote SHA256SUMS (starting from empty)"
fi

# Replace any prior line for this name, then append the fresh one; sort stable.
# Exact filename match on field 2 (strip a BSD '*' binary marker) -- never a
# regex, so dots in the name (v0.1, .iso) can't wildcard-match a sibling image.
if [ -s "$SUMS" ]; then
	awk -v f="$NAME" '{ n=$2; sub(/^\*/,"",n); if (n != f) print }' "$SUMS" > "$SUMS.tmp" || : > "$SUMS.tmp"
	mv "$SUMS.tmp" "$SUMS"
fi
printf '%s  %s\n' "$IMG_SHA" "$NAME" >> "$SUMS"
LC_ALL=C sort -o "$SUMS" "$SUMS"
log "SHA256SUMS now lists $(wc -l < "$SUMS" | tr -d ' ') image(s)"

SIG="$SUMS.minisig"
UNTRUSTED="Postern OS image checksums (release-signed; hosting is not attestation)"
TRUSTED="Postern OS -- $PREFIX -- signed $(date -u +%Y-%m-%dT%H:%M:%SZ)"
if [ "$DRY_RUN" -eq 1 ]; then
	if [ -n "$SECKEY" ] && [ -f "$SECKEY" ] && command -v minisign >/dev/null 2>&1; then
		log "DRY-RUN: signing SHA256SUMS locally with $SECKEY (no upload)"
	else
		log "DRY-RUN: would sign SHA256SUMS with minisign (-s not provided or minisign absent)"
		SECKEY=''
	fi
fi

if [ -n "$SECKEY" ]; then
	if [ -n "${MINISIGN_PASSWORD:-}" ]; then
		printf '%s\n' "$MINISIGN_PASSWORD" | minisign -S -s "$SECKEY" -m "$SUMS" -x "$SIG" \
			-c "$UNTRUSTED" -t "$TRUSTED" >/dev/null \
			|| die "minisign signing failed"
	else
		minisign -S -s "$SECKEY" -m "$SUMS" -x "$SIG" -c "$UNTRUSTED" -t "$TRUSTED" \
			|| die "minisign signing failed"
	fi
	# Self-check: the signature MUST verify against the published public key,
	# i.e. we signed with the right secret key. Refuse to upload otherwise.
	minisign -V -m "$SUMS" -x "$SIG" -P "$PUBKEY" >/dev/null \
		|| die "signature does not verify against published pubkey $PUBKEY -- wrong minisign secret key; refusing to publish"
	log "SHA256SUMS signed and verified against pubkey $PUBKEY"
fi

SHA_SIDECAR="$WORKDIR/$NAME.sha256"
printf '%s  %s\n' "$IMG_SHA" "$NAME" > "$SHA_SIDECAR"

# ------------------------------------------------------- dry-run: stop here
if [ "$DRY_RUN" -eq 1 ]; then
	log ""
	log "DRY-RUN plan (bucket=$BUCKET prefix=$PREFIX):"
	log "  1. put  $PREFIX/$NAME            ($LOCAL_LEN bytes, multipart 100MiB, immutable)"
	log "  2. put  $PREFIX/$NAME.sha256"
	log "  3. put  $PREFIX/SHA256SUMS"
	log "  4. put  $PREFIX/SHA256SUMS.minisig   (the authenticating flip, last)"
	log ""
	[ -f "$SIG" ] && log "signed SHA256SUMS.minisig produced at (temp) $SIG"
	log "no R2 credentials used, no R2 network touched. (S3 read against the source bucket already happened above.)"
	exit 0
fi

# ---------------------------------------------------------------- uploads
IMMUTABLE='public, max-age=31536000, immutable'
SHORT='public, max-age=60'

log ""
log "uploading to R2 (fail-safe order; signature last)..."
r2 put --key "$PREFIX/$NAME" --file "$LOCAL_FILE" \
	--content-type application/octet-stream --cache-control "$IMMUTABLE" \
	|| die "image upload failed"
log "uploaded $PREFIX/$NAME"

r2 put --key "$PREFIX/$NAME.sha256" --file "$SHA_SIDECAR" \
	--content-type 'text/plain; charset=utf-8' --cache-control "$SHORT" \
	|| die "sha256 sidecar upload failed"
log "uploaded $PREFIX/$NAME.sha256"

r2 put --key "$PREFIX/SHA256SUMS" --file "$SUMS" \
	--content-type 'text/plain; charset=utf-8' --cache-control "$SHORT" \
	|| die "SHA256SUMS upload failed"
log "uploaded $PREFIX/SHA256SUMS"

r2 put --key "$PREFIX/SHA256SUMS.minisig" --file "$SIG" \
	--content-type 'text/plain; charset=utf-8' --cache-control "$SHORT" \
	|| die "SHA256SUMS.minisig upload failed"
log "uploaded $PREFIX/SHA256SUMS.minisig"

# ------------------------------------------------------------------ summary
log ""
log "== publish complete: $PREFIX/$NAME =="
log ""
log "Download + verify (user-facing; goes on the download page verbatim):"
log "  wget $PUBLIC_BASE/$PREFIX/$NAME"
log "  wget $PUBLIC_BASE/$PREFIX/SHA256SUMS"
log "  wget $PUBLIC_BASE/$PREFIX/SHA256SUMS.minisig"
log "  minisign -Vm SHA256SUMS -P $PUBKEY"
log "  sha256sum -c SHA256SUMS --ignore-missing   # expect: $NAME: OK"
log ""
log "This proves the ISO was published by Postern and is unmodified in transit."
log "It does NOT prove a boot (boot status published: $BOOT_STATUS) and it is NOT"
log "an attestation claim. Mainnet-beta, UNAUDITED; the coin is worthless by design."
log ""
if [ "$ALLOW_NEW_NAME" -eq 1 ]; then
	log "FOLLOW-UP REQUIRED -- '$NAME' is a new artifact name:"
	log "  1. Add \"$NAME\" to the ALLOW set in functions/dl/[[path]].js"
	log "     so /dl/$NAME redirects + counts instead of 404ing."
	log "  2. Add a row to site/downloads.html's OS table with this SHA-256"
	log "     ($IMG_SHA) and the boot-status badge for '$BOOT_STATUS'."
	log "  3. Redeploy the Pages site (wrangler pages deploy --branch main)"
	log "     after ./assemble-public.sh."
else
	log "'$NAME' was already in the /dl/ allowlist -- update its SHA-256 cell on"
	log "site/downloads.html to $IMG_SHA and its status badge to reflect '$BOOT_STATUS',"
	log "then redeploy the Pages site."
fi
