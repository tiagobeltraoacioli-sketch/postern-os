#!/bin/sh
# publish-to-r2.sh -- publish a built "Postern for postmarketOS" disk IMAGE to
# the project's Cloudflare R2 bucket, alongside a minisign-signed SHA256SUMS.
#
#   Product: "Postern for postmarketOS -- community edition"   (NEVER "Postern OS")
#   Signed & publisher-authenticated ONLY. NOT reproducible, NOT attested.
#   The wallet uses a SOFTWARE keystore. See HONESTY.md. Read it first.
#
# This is the IMAGE publisher (whole-disk .img under os/<ver>/), a different
# distribution channel from the apk-overlay repo described in DISTRIBUTION.md
# (that one ships individual signed apks + APKINDEX). Images ride the same R2
# layout as the rest of the project:
#
#   bucket:  postern-downloads
#   host:    https://pub-dca67fd26bfb4a6b98115e596095ecd3.r2.dev
#   prefix:  os/v0.1/
#     os/v0.1/<image>.img
#     os/v0.1/SHA256SUMS          (all images for the prefix, one per line)
#     os/v0.1/SHA256SUMS.minisig  (minisign signature over SHA256SUMS)
#   minisign public key (verify with this; publish refuses if the secret key
#   does not correspond to it):
#     RWTSe98wfKKHuVRDnywuQmH/cMyP/HNuD/hFFLQeKdQeAHENliqJpmKs
#
# HARD GUARDS (this is the honesty enforcement point):
#   * refuses to run unless the manifest carries the honest-status labels
#     (product name, not_product, attestation, reproducible=false, attestable=false);
#   * refuses to upload anything whose manifest status is not "BUILT"
#     (an UNBUILT/scaffold manifest -- e.g. build-manifest.sample.json -- is rejected);
#   * refuses if the on-disk image sha256 does not match the manifest;
#   * refuses if the minisign secret key does not match the published public key.
#
# Multipart uploads (images are multi-GB) go through build/r2_upload.py: fixed
# 100 MiB parts with bytes bodies and checksum-trailers disabled, because R2
# rejects botocore's default streaming checksum trailers.
#
# Credentials & config come from the ENVIRONMENT ONLY -- never hardcoded:
#   AWS_ACCESS_KEY_ID       R2 API token: Access Key ID              (required, real run)
#   AWS_SECRET_ACCESS_KEY   R2 API token: Secret Access Key          (required, real run)
#   R2_BUCKET               target bucket (default: postern-downloads)
#   R2_ACCOUNT_ID           endpoint = https://$R2_ACCOUNT_ID.r2.cloudflarestorage.com
#   R2_ENDPOINT_URL         full endpoint URL (overrides R2_ACCOUNT_ID)
#   R2_PUBLIC_BASE_URL      public host for the printed install snippet
#                           (default: https://pub-dca67fd26bfb4a6b98115e596095ecd3.r2.dev)
#   MINISIGN_PASSWORD       secret-key password, piped to minisign (optional; else prompt)
#   MINISIGN_PUBKEY         expected public key string (default: the key above)
#
# Fail-safe upload order (clients verify sig -> SHA256SUMS -> image, so the
# signature is the authenticating "flip", written LAST):
#   1. <image>.img            immutable, long cache
#   2. <image>.build-manifest.json   operator record
#   3. SHA256SUMS             short cache
#   4. SHA256SUMS.minisig     the flip -- last

set -eu

PROG=$(basename "$0")
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
UPLOADER="$SCRIPT_DIR/build/r2_upload.py"

DEFAULT_PUBKEY='RWTSe98wfKKHuVRDnywuQmH/cMyP/HNuD/hFFLQeKdQeAHENliqJpmKs'
DEFAULT_PUBLIC_BASE='https://pub-dca67fd26bfb4a6b98115e596095ecd3.r2.dev'

usage() {
	cat <<'EOF'
usage: publish-to-r2.sh -i <image.img> -m <build-manifest.json> -s <minisign.key> [-p os/v0.1] [-n]

  -i  path to the built .img (produced by build/build.sh)
  -m  path to its build-manifest.json (must have status=BUILT + honest labels)
  -s  path to the minisign SECRET key used to sign SHA256SUMS
      (its public half must match MINISIGN_PUBKEY / the published key)
  -p  R2 key prefix for images (default: os/v0.1)
  -n  dry run: validate + build & sign SHA256SUMS locally; NO network, NO creds.

env (see header): AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY R2_BUCKET
                  R2_ACCOUNT_ID|R2_ENDPOINT_URL [R2_PUBLIC_BASE_URL]
                  [MINISIGN_PASSWORD] [MINISIGN_PUBKEY]
EOF
	exit 2
}

log() { printf '%s\n' "$*"; }
die() { printf '%s: error: %s\n' "$PROG" "$*" >&2; exit 1; }

sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
	else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# extract a dotted key from the manifest as plain text ("" if absent)
mget() {
	python3 - "$MANIFEST" "$1" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception as e:
    sys.stderr.write("manifest not valid JSON: %s\n" % e); sys.exit(9)
cur = d
for k in sys.argv[2].split('.'):
    if isinstance(cur, dict) and k in cur:
        cur = cur[k]
    else:
        print(""); sys.exit(0)
if isinstance(cur, bool):
    print("true" if cur else "false")
elif isinstance(cur, (dict, list)):
    print(json.dumps(cur))
else:
    print(cur)
PY
}

# ---------------------------------------------------------------- arguments
IMAGE='' MANIFEST='' SECKEY='' PREFIX='os/v0.1' DRY_RUN=0
while getopts i:m:s:p:n opt; do
	case $opt in
		i) IMAGE=$OPTARG ;;
		m) MANIFEST=$OPTARG ;;
		s) SECKEY=$OPTARG ;;
		p) PREFIX=$OPTARG ;;
		n) DRY_RUN=1 ;;
		*) usage ;;
	esac
done
[ -n "$IMAGE" ] && [ -n "$MANIFEST" ] || usage
[ -f "$IMAGE" ]    || die "image not found: $IMAGE"
[ -f "$MANIFEST" ] || die "manifest not found: $MANIFEST"
command -v python3 >/dev/null 2>&1 || die "python3 required (manifest parse + R2 uploader)"
PREFIX=${PREFIX%/}
case $PREFIX in os/*) ;; *) die "prefix must be under os/ (got: $PREFIX)";; esac

log "== Postern for postmarketOS -- publish image to R2 =="
log "   (signed & publisher-authenticated ONLY; NOT reproducible, NOT attested -- HONESTY.md)"
log ""

# ------------------------------------------------- HONEST-STATUS LABEL GUARD
python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$MANIFEST" \
	|| die "manifest is not valid JSON: $MANIFEST"

M_PRODUCT=$(mget product)
M_NOTPRODUCT=$(mget not_product)
M_ATTEST=$(mget attestation)
M_REPRO=$(mget reproducible)
M_ATTESTABLE=$(mget attestable)
M_STATUS=$(mget status)

case $M_PRODUCT in
	*"Postern for postmarketOS"*) ;;
	*) die "honest-status labels missing/wrong: product must say 'Postern for postmarketOS', got '$M_PRODUCT'";;
esac
case $M_PRODUCT in
	"Postern OS"|*"Postern OS"*) die "honest-status violation: product must never be 'Postern OS' (that name is reserved for the Nix/attestable images)";;
esac
[ "$M_NOTPRODUCT" = "Postern OS" ] || die "honest-status labels missing: not_product must be 'Postern OS'"
[ -n "$M_ATTEST" ] || die "honest-status labels missing: 'attestation' label is empty"
[ "$M_REPRO" = "false" ]     || die "honest-status violation: reproducible must be false, got '$M_REPRO'"
[ "$M_ATTESTABLE" = "false" ] || die "honest-status violation: attestable must be false, got '$M_ATTESTABLE'"
log "honest labels OK: '$M_PRODUCT' (not 'Postern OS'); attestation='$M_ATTEST'"

# --------------------------------------------------------- UNBUILT GUARD
[ "$M_STATUS" = "BUILT" ] || die "refusing to publish: manifest status is '$M_STATUS', not 'BUILT'. \
Nothing was built (a scaffold/sample manifest, or an interrupted build). Run build/build.sh to produce a real image."
M_BOOT=$(mget boot_tested)
case $M_BOOT in
	BOOTED*) log "boot_tested: $M_BOOT" ;;
	*) log "NOTE: boot_tested='$M_BOOT' -- image is UNBOOTED (not hardware-smoke-tested). \
Publishing an unbooted image is allowed but MUST be labeled as such on the download page." ;;
esac

# --------------------------------------------------------- IMAGE INTEGRITY
M_IMG_FILE=$(mget image.file)
M_IMG_SHA=$(mget image.sha256)
IMG_BASE=$(basename "$IMAGE")
[ -z "$M_IMG_FILE" ] || [ "$M_IMG_FILE" = "$IMG_BASE" ] \
	|| die "manifest image.file='$M_IMG_FILE' != '$IMG_BASE' (wrong manifest for this image?)"
log "hashing $IMG_BASE ..."
IMG_SHA=$(sha256_of "$IMAGE")
[ -z "$M_IMG_SHA" ] || [ "$M_IMG_SHA" = "$IMG_SHA" ] \
	|| die "image sha256 mismatch: manifest=$M_IMG_SHA on-disk=$IMG_SHA (image changed after build -- rebuild, do not republish)"
log "image sha256: $IMG_SHA"
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
	[ -f "$UPLOADER" ] || die "uploader missing: $UPLOADER"
	python3 -c 'import boto3' 2>/dev/null || die "boto3 required for upload (pip install boto3)"
	: "${AWS_ACCESS_KEY_ID:?set AWS_ACCESS_KEY_ID (R2 API token Access Key ID)}"
	: "${AWS_SECRET_ACCESS_KEY:?set AWS_SECRET_ACCESS_KEY (R2 API token Secret Access Key)}"
	if [ -n "${R2_ENDPOINT_URL:-}" ]; then ENDPOINT=$R2_ENDPOINT_URL
	elif [ -n "${R2_ACCOUNT_ID:-}" ]; then ENDPOINT="https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com"
	else die "set R2_ACCOUNT_ID or R2_ENDPOINT_URL"; fi
fi

# uploader wrapper (endpoint/bucket via env; creds read by boto3 itself)
r2() { R2_ENDPOINT_URL="$ENDPOINT" R2_BUCKET="$BUCKET" python3 "$UPLOADER" "$@"; }

# ------------------------------------------------ assemble & sign SHA256SUMS
WORKDIR=$(mktemp -d) || die "mktemp failed"
trap 'rm -rf "$WORKDIR"' EXIT INT TERM
SUMS="$WORKDIR/SHA256SUMS"
: > "$SUMS"

# Merge with the CURRENT remote SHA256SUMS so we never drop other images already
# published under this prefix. (Authenticated GET, to bypass any CDN cache.)
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

# Replace any prior line for this image, then append the fresh one; sort stable.
# Exact filename match on field 2 (strip a BSD '*' binary marker) -- never a
# regex, so dots in the name (v0.1, .img) can't wildcard-match a sibling image.
if [ -s "$SUMS" ]; then
	awk -v f="$IMG_BASE" '{ n=$2; sub(/^\*/,"",n); if (n != f) print }' "$SUMS" > "$SUMS.tmp" || : > "$SUMS.tmp"
	mv "$SUMS.tmp" "$SUMS"
fi
printf '%s  %s\n' "$IMG_SHA" "$IMG_BASE" >> "$SUMS"
LC_ALL=C sort -o "$SUMS" "$SUMS"
log "SHA256SUMS now lists $(wc -l < "$SUMS" | tr -d ' ') image(s)"

SIG="$SUMS.minisig"
UNTRUSTED="Postern for postmarketOS image checksums (signed, not reproducible/attested)"
TRUSTED="Postern for postmarketOS -- $PREFIX -- signed $(date -u +%Y-%m-%dT%H:%M:%SZ)"
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

# ------------------------------------------------------- dry-run: stop here
MANIFEST_KEY="$PREFIX/${IMG_BASE%.img}.build-manifest.json"
if [ "$DRY_RUN" -eq 1 ]; then
	log ""
	log "DRY-RUN plan (bucket=$BUCKET prefix=$PREFIX):"
	log "  1. put  $PREFIX/$IMG_BASE            ($(wc -c < "$IMAGE" | tr -d ' ') bytes, multipart 100MiB, immutable)"
	log "  2. put  $MANIFEST_KEY"
	log "  3. put  $PREFIX/SHA256SUMS"
	log "  4. put  $PREFIX/SHA256SUMS.minisig   (the authenticating flip, last)"
	log ""
	[ -f "$SIG" ] && log "signed SHA256SUMS.minisig produced at (temp) $SIG"
	log "no credentials used, no network touched."
	exit 0
fi

# ---------------------------------------------------------------- uploads
IMMUTABLE='public, max-age=31536000, immutable'
SHORT='public, max-age=60'

log ""
log "uploading (fail-safe order; signature last)..."
# 1. image -- invisible/unreferenced until SHA256SUMS + sig land
r2 put --key "$PREFIX/$IMG_BASE" --file "$IMAGE" \
	--content-type application/octet-stream --cache-control "$IMMUTABLE" \
	|| die "image upload failed"
log "uploaded $PREFIX/$IMG_BASE"

# 2. per-image manifest (operator record; apk/users never read it)
r2 put --key "$MANIFEST_KEY" --file "$MANIFEST" \
	--content-type application/json --cache-control "$SHORT" \
	|| die "manifest upload failed"
log "uploaded $MANIFEST_KEY"

# 3. SHA256SUMS
r2 put --key "$PREFIX/SHA256SUMS" --file "$SUMS" \
	--content-type 'text/plain; charset=utf-8' --cache-control "$SHORT" \
	|| die "SHA256SUMS upload failed"
log "uploaded $PREFIX/SHA256SUMS"

# 4. signature -- the flip, dead last
r2 put --key "$PREFIX/SHA256SUMS.minisig" --file "$SIG" \
	--content-type 'text/plain; charset=utf-8' --cache-control "$SHORT" \
	|| die "SHA256SUMS.minisig upload failed"
log "uploaded $PREFIX/SHA256SUMS.minisig"

# ------------------------------------------------------------------ summary
log ""
log "== publish complete: $PREFIX/$IMG_BASE =="
log ""
log "Download + verify (put verbatim on the download page, with the HONESTY.md disclosure):"
log "  wget $PUBLIC_BASE/$PREFIX/$IMG_BASE"
log "  wget $PUBLIC_BASE/$PREFIX/SHA256SUMS"
log "  wget $PUBLIC_BASE/$PREFIX/SHA256SUMS.minisig"
log "  minisign -Vm SHA256SUMS -P $PUBKEY"
log "  sha256sum -c SHA256SUMS --ignore-missing   # expect: $IMG_BASE: OK"
log ""
log "This proves the image was published by Postern and is unmodified in transit."
log "It does NOT prove the binary matches the source: Postern for postmarketOS is"
log "signed & publisher-authenticated only -- NOT reproducible, NOT attested. The"
log "attestable images are 'Postern OS' (Mobile NixOS) only. Never say --allow-untrusted."
