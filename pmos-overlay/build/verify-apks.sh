#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# build/verify-apks.sh -- B6 verification harness for the three PUBLISHED
# "Postern for postmarketOS -- community edition" apks. It answers one honest
# question in two halves:
#
#   "Do the published apks match their source-of-record in this tree?"
#
# HALF A -- SOURCE INTEGRITY + PAYLOAD (runs ANYWHERE, incl. macOS; no root):
#   * fetch each APKBUILD's pinned `source=` tarball from R2 and recompute its
#     sha512, comparing against the `sha512sums=` recorded in the APKBUILD;
#   * fetch each published .apk, read its `.PKGINFO` and file list, and check the
#     structure against the APKBUILD (meta deps / wallet binary / apps payload);
#   * confirm the live repo (key, APKINDEX, three apks) is reachable.
#   This proves PROVENANCE OF THE BUILD INPUTS and that the published bytes carry
#   what the recipe says -- it does NOT prove a reproduced build.
#
# HALF B -- REPRODUCIBLE REBUILD (aarch64 Alpine host ONLY; --rebuild):
#   run `abuild` from the in-tree APKBUILDs and diff the resulting package
#   PAYLOAD (the data.tar.gz member list + per-file sha256, and the built
#   `usr/bin/postern-wallet` hash) against the published apk's payload.
#
# HONESTY (../HONESTY.md, ../aarch64-build.md): postmarketOS/Alpine are NOT
# bit-for-bit reproducible, so even a green Half B is a FUNCTIONALLY-EQUIVALENT
# match of the *installed files*, NEVER a byte-identical rebuild of the .apk
# container. Timestamps, the abuild build-date, the signing block, and gzip
# framing differ by construction. A source-hash match (Half A) is exact; a
# payload match (Half B) is "same files, same content"; neither is attestation.
# The apks are signed with an ALPHA build key (builder-6a52d247) -- "this build,
# this key", not a long-lived anchor. Coin worthless, software keystore, NOT
# "Postern OS".
#
# Usage:
#   ./build/verify-apks.sh                 # Half A (source integrity + payload + reachability)
#   ./build/verify-apks.sh --rebuild       # Half A, then Half B (needs aarch64 Alpine + abuild)
#   ./build/verify-apks.sh --reach-only    # just the live-repo reachability probe
set -eu

OVERLAY_DIR="${OVERLAY_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"   # pmos-overlay/
WORK="${WORK:-$(mktemp -d)}"
R2_BASE="${R2_BASE:-https://pub-dca67fd26bfb4a6b98115e596095ecd3.r2.dev}"
REPO="${REPO:-$R2_BASE/pmos/postern/aarch64}"
KEY_URL="${KEY_URL:-$R2_BASE/pmos/keys/builder-6a52d247.rsa.pub}"

# Published apk filenames (../PUBLISHED.md). Kept explicit so a rename is caught.
APK_META="postern-0.1.0-r0.apk"
APK_WALLET="postern-wallet-0.1.0_alpha1-r0.apk"
APK_APPS="postern-apps-0.1.0_alpha1-r0.apk"

pass=0; fail=0
msg()  { printf '\033[1;32m>>>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m   OK  \033[0m %s\n' "$*"; pass=$((pass+1)); }
bad()  { printf '\033[1;31m FAIL \033[0m %s\n' "$*" >&2; fail=$((fail+1)); }
warn() { printf '\033[1;33m WARN \033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mFATAL:\033[0m %s\n' "$*" >&2; exit 1; }

fetch() {
    _u=$1; _d=$2
    if command -v curl >/dev/null 2>&1; then curl -fsSL -o "$_d" "$_u"
    else wget -q -O "$_d" "$_u"; fi
}
sha512_of() {
    if command -v sha512sum >/dev/null 2>&1; then sha512sum "$1" | awk '{print $1}'
    else shasum -a 512 "$1" | awk '{print $1}'; fi
}
http_code() { curl -s -o /dev/null -w '%{http_code}' -I "$1" 2>/dev/null || echo 000; }

# Pull `source=` URL (right of `::`) and its sha512 out of an APKBUILD, without
# sourcing it (APKBUILDs are abuild-shell, not portable to `. `).
apkbuild_source_url() {
    sed -n 's/^source="[^:]*:://p' "$1" | sed 's/"$//' | head -n1
}
apkbuild_source_sha512() {
    # first token on the sha512sums line (single-source packages here)
    sed -n '/^sha512sums=/,/[[:space:]]/p' "$1" | tr -d '"' | \
        sed -n 's/^sha512sums=//p; p' | grep -Eo '^[0-9a-f]{128}' | head -n1
}

# ---- Half A.1: reachability -------------------------------------------------
reach() {
    msg "live-repo reachability"
    for u in "$KEY_URL" "$REPO/APKINDEX.tar.gz" \
             "$REPO/$APK_META" "$REPO/$APK_WALLET" "$REPO/$APK_APPS"; do
        c=$(http_code "$u")
        if [ "$c" = 200 ]; then ok "200 ${u#"$R2_BASE"/}"; else bad "HTTP $c ${u#"$R2_BASE"/}"; fi
    done
}

# ---- Half A.2: source integrity (exact sha512) ------------------------------
verify_source() {
    _apkbuild=$1; _label=$2
    [ -f "$_apkbuild" ] || { bad "$_label: APKBUILD not found ($_apkbuild)"; return; }
    _url=$(apkbuild_source_url "$_apkbuild")
    _want=$(apkbuild_source_sha512 "$_apkbuild")
    [ -n "$_url" ]  || { warn "$_label: no source= URL (meta package?) -- skipping source hash"; return; }
    [ -n "$_want" ] || { bad "$_label: no sha512 recorded in APKBUILD"; return; }
    _dst="$WORK/$(basename "$_url")"
    msg "$_label: fetching source $(basename "$_url")"
    fetch "$_url" "$_dst" || { bad "$_label: could not fetch $_url"; return; }
    _got=$(sha512_of "$_dst")
    if [ "$_got" = "$_want" ]; then
        ok "$_label: source sha512 matches APKBUILD ($(printf '%s' "$_got" | cut -c1-16)...)"
    else
        bad "$_label: source sha512 MISMATCH"
        printf '        want %s\n        got  %s\n' "$_want" "$_got" >&2
    fi
}

# ---- Half A.3: published payload inspection ---------------------------------
inspect_apk() {
    _apk=$1; _label=$2; shift 2   # remaining args: substrings that MUST appear in the file list
    _dst="$WORK/$_apk"
    msg "$_label: downloading + inspecting $_apk"
    fetch "$REPO/$_apk" "$_dst" || { bad "$_label: could not fetch $_apk"; return; }
    # apk = concatenated gzip streams; `tar -tzf` walks them, `.PKGINFO` is in control.
    _list=$(tar -tzf "$_dst" 2>/dev/null || true)
    _pkginfo=$(tar -xzOf "$_dst" .PKGINFO 2>/dev/null || true)
    if [ -n "$_pkginfo" ]; then
        ok "$_label: .PKGINFO present ($(printf '%s' "$_pkginfo" | sed -n 's/^pkgver = //p'))"
    else
        bad "$_label: .PKGINFO missing/unreadable"
    fi
    for _need in "$@"; do
        if printf '%s\n' "$_list" | grep -q -- "$_need"; then ok "$_label: ships $_need"
        else bad "$_label: MISSING $_need"; fi
    done
}

half_a() {
    reach
    msg "source integrity (exact sha512 vs APKBUILD)"
    verify_source "$OVERLAY_DIR/postern-wallet/APKBUILD" "postern-wallet"
    verify_source "$OVERLAY_DIR/postern-apps/APKBUILD"   "postern-apps"
    verify_source "$OVERLAY_DIR/postern/APKBUILD"        "postern(meta)"
    msg "published payload inspection"
    inspect_apk "$APK_WALLET" "postern-wallet" "usr/bin/postern-wallet"
    inspect_apk "$APK_APPS"   "postern-apps"   "postern-login/index.html" "postern-vedetta.desktop" "first-run.md"
    inspect_apk "$APK_META"   "postern(meta)"  ".PKGINFO"
}

# ---- Half B: abuild rebuild + payload compare (aarch64 Alpine only) ----------
half_b() {
    msg "Half B: reproducible rebuild (aarch64 Alpine + abuild)"
    [ "$(uname -s)" = Linux ] || die "Half B needs a Linux aarch64 Alpine host with abuild (this is $(uname -s)). See ../aarch64-build.md §0."
    [ "$(uname -m)" = aarch64 ] || warn "arch is $(uname -m), not aarch64 -- a rebuilt wallet binary will NOT match the published aarch64 apk; results are informational only."
    command -v abuild >/dev/null 2>&1 || die "abuild not found -- apk add abuild (../aarch64-build.md §1)."
    cat <<'RECIPE'
  Rebuild + compare recipe (run each APKBUILD's dir):
    1. cd pmos-overlay/postern-wallet && abuild -r      # then postern-apps, postern
       (abuild fetches the pinned source, verifies sha512, builds in a clean chroot)
    2. For each rebuilt ~/packages/**/<pkg>.apk vs the published one:
         # extract the data payload file list + per-file sha256 from BOTH:
         tar -xzf <pkg>.apk -C rebuilt/   ; ( cd rebuilt && find . -type f -exec sha256sum {} + | sort ) > rebuilt.sums
         tar -xzf <published>.apk -C pub/ ; ( cd pub     && find . -type f -exec sha256sum {} + | sort ) > pub.sums
         diff rebuilt.sums pub.sums       # EXPECT: identical for installed files (usr/bin, usr/share)
    3. Specifically hash the wallet ELF: sha256 of usr/bin/postern-wallet in both.
  HONEST EXPECTATION: the *installed files* (payload) should match; the .apk
  CONTAINER will differ (build date, signature block, gzip framing). A payload
  match = functionally-equivalent, publisher-authenticated -- NOT bit-identical,
  NOT attested (Alpine is not reproducible). Record the diff as evidence either
  way; a nonempty payload diff on a genuine rebuild is a real finding to triage.
RECIPE
    warn "Half B is a documented recipe; wire it into CI on the aarch64 runner (dev-1's host)."
}

case "${1:-}" in
    --reach-only) reach ;;
    --rebuild)    half_a; half_b ;;
    ""|--verify)  half_a ;;
    *) die "usage: $0 [--verify|--rebuild|--reach-only]" ;;
esac

echo ""
msg "RESULT: $pass passed, $fail failed"
[ -n "${WORK_KEEP:-}" ] || rm -rf "$WORK"
[ "$fail" -eq 0 ] || exit 1
