#!/bin/sh
# SPDX-License-Identifier: MIT
# postern-keygen.sh -- generate / rotate the signing keys for
# "Postern for postmarketOS -- community edition".  See ../KEYS.md.
#
#   License: MIT (matches the APKBUILDs' license=MIT).
#
# HONESTY: signatures made with these keys prove WHO published an artifact and
# that it was unmodified in transit -- NOT reproducibility, NOT attestation
# (Alpine/pmOS is not bit-reproducible; there is no Nix closure, no hardware
# anchor). This is "Postern for postmarketOS", never "Postern OS". The coin is
# worthless and none of this is a security/financial/legal claim.
#
# This tool produces LOCAL key material ONLY. It never uploads and never writes
# into the git tree. It REFUSES to overwrite an existing key (no silent clobber
# of a private key). NO private key is generated or committed in the repo -- a
# human runs this on a trusted, offline-capable host.
#
# Two independent signing systems (../KEYS.md 1):
#   apk    System A: 4096-bit RSA (openssl), abuild-sign compatible, signs the
#                    apk repo's APKINDEX + packages. Pubkey FILENAME is
#                    load-bearing for apk (/etc/apk/keys/<name>) -- write-once.
#   image  System B: minisign (Ed25519), signs the disk image's SHA256SUMS.
#
# Usage:
#   postern-keygen.sh apk          --email packages@posternlabs.com --out ~/.abuild
#   postern-keygen.sh image        --out ~/.minisign/postern-image
#   postern-keygen.sh rotate-apk   --email packages@posternlabs.com --out ~/.abuild
#   postern-keygen.sh rotate-image --out ~/.minisign/postern-image
#   postern-keygen.sh fingerprint  --file <pubkey>            # print the fingerprint users cross-check
#
# After generating, publish the PUBLIC key to >=2 independent places with
# matching fingerprints (../KEYS.md 6). Never commit the private half.
set -eu

EMAIL=''
OUTDIR=''
FILE=''

msg()  { printf '\033[1;32m>>>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mWARN:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mFATAL:\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
	sed -n '25,33p' "$0"
	exit 2
}

# ---- arg parsing (subcommand first, then --flags) ---------------------------
CMD="${1:-}"
[ -n "$CMD" ] || usage
shift 2>/dev/null || true
while [ $# -gt 0 ]; do
	case "$1" in
		--email) EMAIL="${2:?--email needs a value}"; shift 2 ;;
		--out)   OUTDIR="${2:?--out needs a value}";  shift 2 ;;
		--file)  FILE="${2:?--file needs a value}";   shift 2 ;;
		-h|--help) usage ;;
		*) die "unknown argument: $1" ;;
	esac
done

# 8 hex chars of entropy for the apk key name suffix (matches abuild-keygen's
# <name>-<hex> convention; the filename is load-bearing for apk).
_hex8() {
	if command -v openssl >/dev/null 2>&1; then
		openssl rand -hex 4
	else
		# portable fallback: 4 bytes from /dev/urandom -> 8 hex chars
		od -An -tx1 -N4 /dev/urandom | tr -d ' \n'
	fi
}

# fingerprint a public key file the same way users cross-check it (../KEYS.md 6)
_fingerprint() {
	_f="$1"
	[ -f "$_f" ] || die "no such file: $_f"
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$_f"
	else shasum -a 256 "$_f"; fi
}

_publish_checklist() {
	_pub="$1"; _kind="$2"
	msg ""
	msg "NEXT -- publish the PUBLIC key in >=2 independent places (../KEYS.md 6):"
	msg "  1. R2:      upload $_pub  (System A key objects are WRITE-ONCE -- never overwrite/rename)"
	msg "  2. git:     record its fingerprint in ../KEYS.md 6 fingerprint table"
	msg "  3. website: posternlabs.com download page, next to the HONESTY.md disclosure"
	msg "  4. release: restate name + fingerprint in the release notes"
	msg ""
	msg "Fingerprint (must be IDENTICAL in every location):"
	_fingerprint "$_pub" | sed 's/^/    /'
	msg ""
	warn "Keep the PRIVATE key off this repo and out of git, forever."
	case "$_kind" in
	apk)   warn "System A: distribute this pubkey to clients (postern-repo-keys pkg / all locations) BEFORE signing anything with it (../KEYS.md 5)." ;;
	image) warn "System B: if this is a rotation, also publish a transition statement signed with the OLD key (../KEYS.md 5)." ;;
	esac
}

# ---- System A: apk repo RSA key (openssl; abuild-sign compatible) -----------
gen_apk() {
	[ -n "$EMAIL" ]  || die "apk key needs --email (role address, e.g. packages@posternlabs.com)"
	[ -n "$OUTDIR" ] || die "apk key needs --out <dir> (e.g. ~/.abuild)"
	command -v openssl >/dev/null 2>&1 || die "openssl required to generate the RSA key"
	mkdir -p "$OUTDIR"

	NAME="$EMAIL-$(_hex8)"
	PRIV="$OUTDIR/$NAME.rsa"
	PUB="$PRIV.pub"
	# NEVER clobber an existing private key.
	[ -e "$PRIV" ] && die "refusing to overwrite existing key: $PRIV"
	[ -e "$PUB" ]  && die "refusing to overwrite existing pubkey: $PUB"

	msg "generating 4096-bit RSA apk signing key: $NAME"
	msg "  (this is the stable-release form per ../KEYS.md 3; the alpha key is builder-6a52d247)"
	# 4096-bit RSA, matching abuild-keygen. abuild-sign uses this key directly.
	openssl genrsa -out "$PRIV" 4096 2>/dev/null || die "openssl genrsa failed"
	chmod 600 "$PRIV"
	openssl rsa -in "$PRIV" -pubout -out "$PUB" 2>/dev/null || die "openssl rsa -pubout failed"
	chmod 644 "$PUB"

	msg "private key: $PRIV   (chmod 600 -- NEVER commit, NEVER upload)"
	msg "public  key: $PUB"
	msg ""
	msg "Wire abuild-sign to it (abuild.conf), then sign the index with publish-apk-repo.sh:"
	msg "  echo 'PACKAGER_PRIVKEY=\"$PRIV\"' >> ~/.abuild/abuild.conf"
	msg "  ../publish-apk-repo.sh -b v26.06 -r ~/packages/postern -k $PUB   # (dry-run adds -n)"
	msg ""
	msg "Install the PUBKEY on a client under its EXACT name (filename is load-bearing):"
	msg "  wget -P /etc/apk/keys <repo-base>/keys/$NAME.rsa.pub"
	_publish_checklist "$PUB" apk
}

# ---- System B: image minisign key -------------------------------------------
gen_image() {
	[ -n "$OUTDIR" ] || die "image key needs --out <path-prefix> (e.g. ~/.minisign/postern-image)"
	command -v minisign >/dev/null 2>&1 || die "minisign required (apk add minisign / brew install minisign)"
	mkdir -p "$(dirname "$OUTDIR")"

	SEC="$OUTDIR.key"
	PUB="$OUTDIR.pub"
	[ -e "$SEC" ] && die "refusing to overwrite existing secret key: $SEC"
	[ -e "$PUB" ] && die "refusing to overwrite existing pubkey: $PUB"

	msg "generating minisign image-signing key -> $SEC / $PUB"
	msg "  (choose a strong passphrase; the secret key lives in CI secret store or offline)"
	# minisign prompts for the passphrase interactively (we never pass -W: an
	# unencrypted secret key is not acceptable for a release key).
	minisign -G -p "$PUB" -s "$SEC" || die "minisign -G failed"
	chmod 600 "$SEC" 2>/dev/null || true

	msg "secret key: $SEC   (NEVER commit, NEVER upload)"
	msg "public key: $PUB"
	msg ""
	msg "This pubkey STRING is the identity users verify against. At cutover, set it as"
	msg "publish-to-r2.sh DEFAULT_PUBKEY and in FLASH.md / aarch64-build.md:"
	sed -n '2p' "$PUB" 2>/dev/null | sed 's/^/    /' || true
	msg ""
	msg "Sign an image checksum file with:"
	msg "  ../publish-to-r2.sh -i <img> -m <manifest.json> -s $SEC   # (dry-run adds -n)"
	_publish_checklist "$PUB" image
}

case "$CMD" in
	apk)          gen_apk ;;
	image)        gen_image ;;
	rotate-apk)
		msg "ROTATION (System A / apk) -- ship-new-key-FIRST, then switch signing (../KEYS.md 5):"
		msg "  1. generate the NEW key now (below), publish its pubkey to ALL locations,"
		msg "     and ship it to clients (postern-repo-keys pkg) BEFORE signing with it."
		msg "  2. only then switch publish-apk-repo.sh -k to the NEW pubkey."
		msg "  3. keep serving the OLD pubkey so historical artifacts still verify; never"
		msg "     delete or overwrite keys/<old> (write-once filename)."
		msg ""
		gen_apk
		;;
	rotate-image)
		msg "ROTATION (System B / image) -- publish-new-pubkey-FIRST + transition statement (../KEYS.md 5):"
		msg "  1. generate the NEW minisign key now (below), publish its pubkey everywhere."
		msg "  2. sign a dated transition statement with the OLD secret key and publish it."
		msg "  3. update publish-to-r2.sh DEFAULT_PUBKEY + docs; re-sign SHA256SUMS with NEW key."
		msg ""
		gen_image
		;;
	fingerprint)
		[ -n "$FILE" ] || die "fingerprint needs --file <pubkey>"
		_fingerprint "$FILE"
		;;
	-h|--help)    usage ;;
	*)            die "unknown subcommand: $CMD (want: apk | image | rotate-apk | rotate-image | fingerprint)" ;;
esac
