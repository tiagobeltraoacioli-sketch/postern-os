#!/bin/sh
# SPDX-License-Identifier: MIT
# publish-apk-repo.sh -- publish the SIGNED apk repository (individual *.apk +
# abuild-signed APKINDEX.tar.gz) for "Postern for postmarketOS -- community
# edition" to the project's Cloudflare R2 bucket. See DISTRIBUTION.md + KEYS.md.
#
#   License: MIT (matches the APKBUILDs).
#
# This is the APK-REPO publisher (System A, ../KEYS.md 1) -- the channel behind
# `apk add postern`. It is DISTINCT from publish-to-r2.sh, which publishes the
# whole-disk .img (System B). DISTRIBUTION.md describes THIS flow (-b/-r/-k); the
# tool now exists here, with the index-signing + write-once + immutability
# hardening that document specifies baked in.
#
# HONESTY (read HONESTY.md first): everything here is SIGNED ONLY -- it proves
# WHO published a package and that it was unmodified in transit. It is NOT
# reproducible, NOT attested, and never "Postern OS". As of this writing NOTHING
# in this overlay has been built or device-tested (HONESTY.md/PUBLISHED.md);
# this script is turnkey but do not stand up a live repo from a scaffold.
#
# HARDENING GUARANTEES (the point of this script):
#   * INDEX SIGNING verified: every arch's APKINDEX.tar.gz must carry a
#     .SIGN.RSA.<name> member whose <name> matches the -k pubkey's basename
#     (apk resolves the signature by that exact filename). Refuse otherwise.
#   * WRITE-ONCE key: keys/<name> is uploaded once; a DIFFERENT existing object
#     under that name aborts the publish (never rename/overwrite a trusted key).
#   * IMMUTABLE apks: an existing remote *.apk of a DIFFERENT size aborts the
#     publish (bump pkgrel, never republish changed bytes under the same ver).
#   * CHECKSUMS: a local SHA256SUMS.txt is written next to the index for
#     out-of-band auditing; every apk is hashed before upload.
#   * FAIL-SAFE ORDER: key -> apks -> signed APKINDEX (the client-visible flip)
#     -> meta/<branch>.json pointer (written dead last).
#
# Credentials/config come from the ENVIRONMENT ONLY (never hardcoded), same as
# publish-to-r2.sh:
#   AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY   R2 API token                (real run)
#   R2_BUCKET                                    target bucket
#   R2_ACCOUNT_ID | R2_ENDPOINT_URL              endpoint
#   R2_PUBLIC_BASE_URL                           public host for the install snippet
#
# Usage:
#   ./publish-apk-repo.sh -b v26.06 -r ~/packages/postern -k ~/.abuild/packages@posternlabs.com-<8hex>.rsa.pub [-p pmos/postern] [-n]
#     -b  pmOS release branch dir (= one Alpine ABI), e.g. v26.06 or edge
#     -r  local abuild output tree ( ~/packages/<repo>/ ; contains <arch>/*.apk )
#     -k  the PUBLIC signing key whose name the APKINDEX signatures must match
#     -p  R2 key prefix for the repo (default: pmos/postern, matching PUBLISHED.md)
#     -n  dry run: validate + hash locally; NO creds, NO network.
set -eu

PROG=$(basename "$0")
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
UPLOADER="$SCRIPT_DIR/build/r2_upload.py"

DEFAULT_PUBLIC_BASE='https://pub-dca67fd26bfb4a6b98115e596095ecd3.r2.dev'
ARCHES="aarch64 x86_64"   # the arches DISTRIBUTION.md publishes

log() { printf '%s\n' "$*"; }
die() { printf '%s: error: %s\n' "$PROG" "$*" >&2; exit 1; }

usage() {
	sed -n '41,47p' "$0"
	exit 2
}

sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
	else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# ---- arguments --------------------------------------------------------------
BRANCH='' REPO='' PUBKEY='' PREFIX='pmos/postern' DRY_RUN=0
while getopts b:r:k:p:n opt; do
	case $opt in
		b) BRANCH=$OPTARG ;;
		r) REPO=$OPTARG ;;
		k) PUBKEY=$OPTARG ;;
		p) PREFIX=$OPTARG ;;
		n) DRY_RUN=1 ;;
		*) usage ;;
	esac
done
[ -n "$BRANCH" ] && [ -n "$REPO" ] && [ -n "$PUBKEY" ] || usage
[ -d "$REPO" ] || die "repo tree not found: $REPO"
[ -f "$PUBKEY" ] || die "signing pubkey not found: $PUBKEY"
PREFIX=${PREFIX%/}
KEY_BASENAME=$(basename "$PUBKEY")
case "$KEY_BASENAME" in
	*.rsa.pub) ;;
	*) die "pubkey name '$KEY_BASENAME' should end in .rsa.pub (apk resolves signatures by this exact filename)";;
esac

log "== Postern for postmarketOS -- publish SIGNED apk repo to R2 =="
log "   (signed & publisher-authenticated ONLY; NOT reproducible, NOT attested -- HONESTY.md)"
log "   branch=$BRANCH prefix=$PREFIX key=$KEY_BASENAME"
log ""

# ---- sanity on the signing key ---------------------------------------------
head -n1 "$PUBKEY" | grep -q -- '-----BEGIN' \
	|| die "pubkey does not look like a PEM public key: $PUBKEY"

# ---- INDEX-SIGNING + STRUCTURE VALIDATION (per arch) ------------------------
# Every published arch must have a non-empty APKINDEX.tar.gz that is SIGNED with
# a member matching the -k pubkey's basename. This is the load-bearing check:
# apk verifies .SIGN.RSA.<KEY_BASENAME> against /etc/apk/keys/<KEY_BASENAME>.
FOUND_ARCHES=''
for arch in $ARCHES; do
	ADIR="$REPO/$arch"
	[ -d "$ADIR" ] || { log "skip: no $arch/ dir in repo tree"; continue; }
	IDX="$ADIR/APKINDEX.tar.gz"
	[ -f "$IDX" ] || die "$arch: missing signed index $IDX (run 'apk index' + 'abuild-sign')"
	[ -s "$IDX" ] || die "$arch: index is empty: $IDX"

	# The signature member inside the index tar must match the pubkey filename.
	# abuild-sign embeds it as .SIGN.RSA.<pubkey-basename>.
	SIGN_MEMBER=".SIGN.RSA.$KEY_BASENAME"
	if ! tar tzf "$IDX" 2>/dev/null | grep -qx "$SIGN_MEMBER"; then
		log "$arch: index signature members present:"
		tar tzf "$IDX" 2>/dev/null | grep '^\.SIGN\.' | sed 's/^/    /' || log "    (none)"
		die "$arch: index is NOT signed with '$KEY_BASENAME' (expected member '$SIGN_MEMBER'). \
Re-sign: abuild-sign -k <privkey matching $KEY_BASENAME> $IDX"
	fi

	# There must be at least one apk to publish.
	set -- "$ADIR"/*.apk
	[ -e "$1" ] || die "$arch: no *.apk in $ADIR"
	_napk=$(find "$ADIR" -maxdepth 1 -name '*.apk' | wc -l | tr -d ' ')
	log "$arch: index signed with $KEY_BASENAME OK; $_napk package(s)"
	FOUND_ARCHES="$FOUND_ARCHES $arch"
done
[ -n "$FOUND_ARCHES" ] || die "no publishable arch dirs found under $REPO (want any of: $ARCHES)"

# ---- CHECKSUM manifest (audit sidecar) --------------------------------------
# Hash every apk + index into a per-arch SHA256SUMS.txt kept next to the index.
# This is not a substitute for the apk signature -- it is an out-of-band audit
# aid (and what a mirror operator diffs).
for arch in $FOUND_ARCHES; do
	ADIR="$REPO/$arch"
	SUMS="$ADIR/SHA256SUMS.txt"
	: > "$SUMS"
	for f in "$ADIR"/*.apk "$ADIR/APKINDEX.tar.gz"; do
		[ -f "$f" ] || continue
		printf '%s  %s\n' "$(sha256_of "$f")" "$(basename "$f")" >> "$SUMS"
	done
	LC_ALL=C sort -o "$SUMS" "$SUMS"
	log "$arch: wrote checksum audit sidecar $SUMS ($(wc -l < "$SUMS" | tr -d ' ') entries)"
done

# ---- environment / uploader (real run only) --------------------------------
PUBLIC_BASE=${R2_PUBLIC_BASE_URL:-$DEFAULT_PUBLIC_BASE}
BUCKET=${R2_BUCKET:-} ENDPOINT=''
if [ "$DRY_RUN" -eq 0 ]; then
	command -v python3 >/dev/null 2>&1 || die "python3 required (R2 uploader)"
	[ -f "$UPLOADER" ] || die "uploader missing: $UPLOADER"
	python3 -c 'import boto3' 2>/dev/null || die "boto3 required for upload (pip install boto3)"
	: "${AWS_ACCESS_KEY_ID:?set AWS_ACCESS_KEY_ID (R2 API token Access Key ID)}"
	: "${AWS_SECRET_ACCESS_KEY:?set AWS_SECRET_ACCESS_KEY (R2 API token Secret Access Key)}"
	BUCKET=${R2_BUCKET:?set R2_BUCKET}
	if [ -n "${R2_ENDPOINT_URL:-}" ]; then ENDPOINT=$R2_ENDPOINT_URL
	elif [ -n "${R2_ACCOUNT_ID:-}" ]; then ENDPOINT="https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com"
	else die "set R2_ACCOUNT_ID or R2_ENDPOINT_URL"; fi
fi

r2() { R2_ENDPOINT_URL="$ENDPOINT" R2_BUCKET="$BUCKET" python3 "$UPLOADER" "$@"; }

# remote object size, or empty string if absent (uses r2_upload.py head)
remote_size() {
	_key=$1
	_out=$(r2 head --key "$_key" 2>/dev/null) || return 1
	[ "$_out" = "MISSING" ] && { echo ""; return 0; }
	echo "$_out"
}

# ---- dry-run: stop before any network --------------------------------------
IMMUTABLE='public, max-age=31536000, immutable'
SHORT='public, max-age=60'
KEY_OBJ="$PREFIX/keys/$KEY_BASENAME"

if [ "$DRY_RUN" -eq 1 ]; then
	log ""
	log "DRY-RUN plan (no creds, no network):"
	log "  1. put  $KEY_OBJ                      (write-once; abort if a different key exists there)"
	for arch in $FOUND_ARCHES; do
		for f in "$REPO/$arch"/*.apk; do
			log "  2. put  $PREFIX/$arch/$(basename "$f")   (immutable; abort if remote size differs)"
		done
	done
	for arch in $FOUND_ARCHES; do
		log "  3. put  $PREFIX/$arch/APKINDEX.tar.gz     (the client-visible flip)"
	done
	log "  4. put  $PREFIX/meta/$BRANCH.json          (operator pointer, dead last)"
	log ""
	log "validation passed: signed indexes, write-once/immutable checks are ENFORCED on the real run."
	log "no credentials used, no network touched."
	exit 0
fi

# ---- 1. write-once key ------------------------------------------------------
log ""
log "uploading (fail-safe order; signed index is the flip)..."
KEY_SHA=$(sha256_of "$PUBKEY")
if EXIST=$(remote_size "$KEY_OBJ"); then
	if [ -n "$EXIST" ]; then
		# object exists -- verify it is byte-identical; a DIFFERENT key is fatal.
		TMPK=$(mktemp) || die "mktemp failed"
		if r2 get --key "$KEY_OBJ" --file "$TMPK" 2>/dev/null; then
			if [ "$(sha256_of "$TMPK")" != "$KEY_SHA" ]; then
				rm -f "$TMPK"
				die "WRITE-ONCE VIOLATION: $KEY_OBJ already exists with DIFFERENT content. \
Never overwrite a trusted key -- rotate to a NEW filename instead (KEYS.md 5)."
			fi
			log "key already published and identical -- skipping ($KEY_OBJ)"
		fi
		rm -f "$TMPK"
	fi
else
	die "could not query $KEY_OBJ on R2"
fi
if [ -z "${EXIST:-}" ]; then
	r2 put --key "$KEY_OBJ" --file "$PUBKEY" \
		--content-type 'application/x-pem-file' --cache-control "$SHORT" \
		|| die "key upload failed"
	log "uploaded $KEY_OBJ (fingerprint $KEY_SHA)"
fi

# ---- 2. immutable apks (invisible to clients until the index lands) ---------
for arch in $FOUND_ARCHES; do
	for f in "$REPO/$arch"/*.apk; do
		bn=$(basename "$f")
		okey="$PREFIX/$arch/$bn"
		local_size=$(wc -c < "$f" | tr -d ' ')
		if rsize=$(remote_size "$okey"); then
			if [ -n "$rsize" ] && [ "$rsize" != "$local_size" ]; then
				die "IMMUTABILITY VIOLATION: $okey exists remotely with size $rsize != local $local_size. \
Never republish changed bytes under the same pkgver-pkgrel -- bump pkgrel."
			fi
		fi
		r2 put --key "$okey" --file "$f" \
			--content-type application/octet-stream --cache-control "$IMMUTABLE" \
			|| die "apk upload failed: $okey"
		log "uploaded $okey"
	done
	# checksum audit sidecar alongside the apks
	r2 put --key "$PREFIX/$arch/SHA256SUMS.txt" --file "$REPO/$arch/SHA256SUMS.txt" \
		--content-type 'text/plain; charset=utf-8' --cache-control "$SHORT" \
		|| die "checksum sidecar upload failed: $arch"
done

# ---- 3. signed APKINDEX per arch -- the client-visible flip -----------------
for arch in $FOUND_ARCHES; do
	okey="$PREFIX/$arch/APKINDEX.tar.gz"
	r2 put --key "$okey" --file "$REPO/$arch/APKINDEX.tar.gz" \
		--content-type application/octet-stream --cache-control "$SHORT" \
		|| die "index upload failed: $okey"
	log "uploaded $okey (the flip)"
done

# ---- 4. meta pointer -- dead last (proves the publish completed) ------------
META_KEY="$PREFIX/meta/$BRANCH.json"
METAFILE=$(mktemp) || die "mktemp failed"
{
	printf '{\n'
	printf '  "schema": "postern-pmos-apk-repo-pointer/v1",\n'
	printf '  "product": "Postern for postmarketOS — community edition",\n'
	printf '  "not_product": "Postern OS",\n'
	printf '  "attestation": "none — signed & publisher-authenticated only; NOT reproducible, NOT attested",\n'
	printf '  "reproducible": false,\n'
	printf '  "attestable": false,\n'
	printf '  "branch": "%s",\n' "$BRANCH"
	printf '  "signing_key": "%s",\n' "$KEY_BASENAME"
	printf '  "signing_key_sha256": "%s",\n' "$KEY_SHA"
	printf '  "published_at": "%s"\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	printf '}\n'
} > "$METAFILE"
r2 put --key "$META_KEY" --file "$METAFILE" \
	--content-type application/json --cache-control "$SHORT" \
	|| { rm -f "$METAFILE"; die "meta pointer upload failed"; }
rm -f "$METAFILE"
log "uploaded $META_KEY"

# ---- summary ----------------------------------------------------------------
log ""
log "== apk repo publish complete: $PREFIX ($BRANCH) =="
log ""
log "End-user install (put verbatim on the install page WITH the HONESTY.md disclosure):"
log "  wget -P /etc/apk/keys $PUBLIC_BASE/$PREFIX/keys/$KEY_BASENAME"
log "  sha256sum /etc/apk/keys/$KEY_BASENAME     # cross-check against KEYS.md 6: $KEY_SHA"
log "  echo \"$PUBLIC_BASE/$PREFIX\" >> /etc/apk/repositories"
log "  apk update && apk add postern"
log ""
log "Never --allow-untrusted. The signature proves who published these packages and"
log "that they were unmodified in transit -- NOT that the binary matches the source."
log "Postern for postmarketOS is signed & publisher-authenticated only: NOT reproducible,"
log "NOT attested. The attestable images are 'Postern OS' (Mobile NixOS) only."
