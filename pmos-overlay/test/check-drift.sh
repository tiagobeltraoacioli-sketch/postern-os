#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# pmos-overlay/test/check-drift.sh -- cross-file consistency (drift) guard for
# the pmOS community-edition overlay. Pure text processing (grep/sed only, no
# `abuild`, no sourcing of any APKBUILD, no network). It answers:
#
#   "Do pkgname/pkgver/pkgrel in the three published APKBUILDs still compose
#    the exact .apk filenames that PUBLISHED.md and build/verify-apks.sh
#    claim are published, and does the signing-key basename still agree
#    between verify-apks.sh and PUBLISHED.md?"
#
# It intentionally does NOT build anything and does NOT contact the network --
# see build/verify-apks.sh for the (network-using) "is the published bit
# actually reachable/correct" check. This script only catches the cheaper,
# purely-textual failure mode: someone bumped a pkgver/pkgrel in an APKBUILD
# (or renamed the signing key) and forgot to update PUBLISHED.md and/or
# build/verify-apks.sh to match.
#
# Usage:
#   sh pmos-overlay/test/check-drift.sh
#
# SRC_ROOT override (for testing this script itself, e.g. a mutation test):
#   SRC_ROOT=/path/to/a/copy/of/pmos-overlay sh pmos-overlay/test/check-drift.sh
#   When unset, SRC_ROOT defaults to the pmos-overlay/ directory that contains
#   this test/ directory (i.e. the real tree). Point it at a scratch copy to
#   verify the gate bites without touching the real tree.
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
SRC_ROOT="${SRC_ROOT:-$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)}"

POSTERN_APKBUILD="$SRC_ROOT/postern/APKBUILD"
WALLET_APKBUILD="$SRC_ROOT/postern-wallet/APKBUILD"
APPS_APKBUILD="$SRC_ROOT/postern-apps/APKBUILD"
FLAVOR_APKBUILD="$SRC_ROOT/flavor/postern-flavor/APKBUILD"
PUBLISHED="$SRC_ROOT/PUBLISHED.md"
VERIFY_SCRIPT="$SRC_ROOT/build/verify-apks.sh"

fail=0

msg()  { printf '\033[1;34m>>>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m   OK  \033[0m %s\n' "$*"; }
note() { printf '\033[1;33m NOTE \033[0m %s\n' "$*"; }
drift() {
    # drift <message>  -- always names the mismatched string + both locations
    printf '\033[1;31m DRIFT\033[0m %s\n' "$*" >&2
    fail=1
}
require_file() {
    [ -f "$1" ] || { printf '\033[1;31mFATAL:\033[0m missing required file: %s\n' "$1" >&2; exit 2; }
}

# ---- field extraction (grep/sed only, no sourcing) --------------------------

# get_field <APKBUILD> <name>  -> unquoted value of a top-level "<name>=..." line
get_field() {
    _file=$1; _name=$2
    grep -E "^${_name}=" "$_file" | head -n1 | sed -E "s/^${_name}=//" | sed -E 's/^"(.*)"$/\1/'
}

# compose_apk <pkgname> <pkgver> <pkgrel> -> canonical apk filename
compose_apk() {
    printf '%s-%s-r%s.apk' "$1" "$2" "$3"
}

# get_verify_var <name> -> literal apk filename assigned to <name>= in
# build/verify-apks.sh, i.e. the text after `:=`/`=` on a line like
#   APK_META="postern-0.1.0-r0.apk"
# stripping any ${VAR:-...} wrapper down to the default value.
get_verify_var() {
    _name=$1
    _line=$(grep -E "^${_name}=" "$VERIFY_SCRIPT" | head -n1)
    _val=$(printf '%s\n' "$_line" | sed -E "s/^${_name}=//" | sed -E 's/^"(.*)"$/\1/')
    # shellcheck disable=SC2016 # '${'* below is a literal glob prefix, not an expansion
    case "$_val" in
        '${'*)
            _val=$(printf '%s\n' "$_val" | sed -E 's/^\$\{[^:]*:-(.*)\}$/\1/')
            ;;
    esac
    printf '%s' "$_val"
}

# ---- (1) parse pkgname/pkgver/pkgrel and compose filenames -----------------

require_file "$POSTERN_APKBUILD"
require_file "$WALLET_APKBUILD"
require_file "$APPS_APKBUILD"
require_file "$PUBLISHED"
require_file "$VERIFY_SCRIPT"

msg "parsing pkgname/pkgver/pkgrel from the three published APKBUILDs"

POSTERN_NAME=$(get_field "$POSTERN_APKBUILD" pkgname)
POSTERN_VER=$(get_field "$POSTERN_APKBUILD" pkgver)
POSTERN_REL=$(get_field "$POSTERN_APKBUILD" pkgrel)
POSTERN_APK=$(compose_apk "$POSTERN_NAME" "$POSTERN_VER" "$POSTERN_REL")

WALLET_NAME=$(get_field "$WALLET_APKBUILD" pkgname)
WALLET_VER=$(get_field "$WALLET_APKBUILD" pkgver)
WALLET_REL=$(get_field "$WALLET_APKBUILD" pkgrel)
WALLET_APK=$(compose_apk "$WALLET_NAME" "$WALLET_VER" "$WALLET_REL")

APPS_NAME=$(get_field "$APPS_APKBUILD" pkgname)
APPS_VER=$(get_field "$APPS_APKBUILD" pkgver)
APPS_REL=$(get_field "$APPS_APKBUILD" pkgrel)
APPS_APK=$(compose_apk "$APPS_NAME" "$APPS_VER" "$APPS_REL")

ok "postern       -> $POSTERN_APK  (from $POSTERN_APKBUILD)"
ok "postern-wallet -> $WALLET_APK  (from $WALLET_APKBUILD)"
ok "postern-apps   -> $APPS_APK  (from $APPS_APKBUILD)"

# ---- (2) each composed filename vs PUBLISHED.md and verify-apks.sh ---------

check_triple() {
    # check_triple <label> <composed_apk> <verify_var_name>
    _label=$1; _composed=$2; _verify_var=$3

    msg "$_label: filename triple check for $_composed"

    if grep -qF -- "$_composed" "$PUBLISHED"; then
        ok "$_label: '$_composed' found verbatim in $PUBLISHED"
    else
        drift "$_label: composed filename '$_composed' (from APKBUILD pkgname/pkgver/pkgrel) does NOT appear verbatim in $PUBLISHED"
    fi

    _verify_val=$(get_verify_var "$_verify_var")
    if [ "$_verify_val" = "$_composed" ]; then
        ok "$_label: $_verify_var=\"$_verify_val\" in $VERIFY_SCRIPT matches"
    else
        drift "$_label: $_verify_var=\"$_verify_val\" in $VERIFY_SCRIPT does NOT match composed filename '$_composed'"
        printf '        composed (from APKBUILD): %s\n        %s (in %s): %s\n' \
            "$_composed" "$_verify_var" "$VERIFY_SCRIPT" "$_verify_val" >&2
    fi
}

check_triple "postern"       "$POSTERN_APK" APK_META
check_triple "postern-wallet" "$WALLET_APK" APK_WALLET
check_triple "postern-apps"   "$APPS_APK"   APK_APPS

# ---- (3) signing-key basename: verify-apks.sh KEY_URL vs PUBLISHED.md ------

msg "signing-key basename check"

_key_url=$(get_verify_var KEY_URL)
_key_basename=${_key_url##*/}

if [ -n "$_key_basename" ]; then
    ok "verify-apks.sh KEY_URL basename -> $_key_basename"
else
    drift "could not extract a KEY_URL basename from $VERIFY_SCRIPT"
fi

_published_key_line=$(grep -i 'signing key' "$PUBLISHED" || true)

if [ -n "$_key_basename" ] && printf '%s\n' "$_published_key_line" | grep -qF -- "$_key_basename"; then
    ok "'$_key_basename' found in $PUBLISHED's 'Signing key' line"
else
    drift "signing-key basename mismatch: verify-apks.sh KEY_URL basename is '$_key_basename' but $PUBLISHED's 'Signing key' line does not contain it"
    printf '        %s (KEY_URL basename): %s\n        %s (Signing key line): %s\n' \
        "$VERIFY_SCRIPT" "$_key_basename" "$PUBLISHED" "$_published_key_line" >&2
fi

# ---- (4) flavor/postern-flavor pkgver drift -- ONLY if PUBLISHED.md claims -
# a postern-flavor apk is published. Today it does not, and this script must
# never invent that claim -- so absence of a mention is a pass (with a note),
# not a check that gets silently skipped without saying why.

msg "postern-flavor: conditional drift check"

if grep -qE 'postern-flavor-[^`[:space:]]*\.apk' "$PUBLISHED"; then
    require_file "$FLAVOR_APKBUILD"
    FLAVOR_NAME=$(get_field "$FLAVOR_APKBUILD" pkgname)
    FLAVOR_VER=$(get_field "$FLAVOR_APKBUILD" pkgver)
    FLAVOR_REL=$(get_field "$FLAVOR_APKBUILD" pkgrel)
    FLAVOR_APK=$(compose_apk "$FLAVOR_NAME" "$FLAVOR_VER" "$FLAVOR_REL")
    if grep -qF -- "$FLAVOR_APK" "$PUBLISHED"; then
        ok "postern-flavor: '$FLAVOR_APK' found verbatim in $PUBLISHED"
    else
        drift "postern-flavor: PUBLISHED.md mentions a postern-flavor apk but composed filename '$FLAVOR_APK' (from $FLAVOR_APKBUILD) does not appear verbatim in $PUBLISHED"
    fi
else
    note "postern-flavor: $PUBLISHED does not claim a postern-flavor apk is published -- correctly skipping the filename check (not inventing that claim)"
fi

# ---- result ------------------------------------------------------------

echo ""
if [ "$fail" -eq 0 ]; then
    msg "RESULT: no drift detected"
else
    msg "RESULT: DRIFT DETECTED -- see DRIFT lines above" >&2
fi
[ "$fail" -eq 0 ] || exit 1
