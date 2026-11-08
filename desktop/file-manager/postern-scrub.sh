#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# postern-scrub.sh — the file-manager embed hook for Postern Hygiene.
#
# This is the ONE piece of glue both the Linux (Nautilus/Files .desktop action /
# Nautilus script) and the macOS (Automator Quick Action) integrations call. It
# pipes each selected file through the already-shipping stdin/stdout embed mode
# of the scrubber:
#
#     postern-hygiene scrub -   < FILE > FILE-scrubbed-sibling
#
# and writes the result to a *sibling* file (the original is opened read-only and
# never touched — same guarantee the CLI makes). It fills the roadmap gap
# "OS/file-manager embed not wired yet": the core has shipped `scrub -`/`check -`
# and been black-box tested for a while; this is the missing wiring to a
# right-click action.
#
# Usage:  postern-scrub.sh FILE [FILE ...]
#
# Binary resolution order (first hit wins):
#   1. $POSTERN_HYGIENE_BIN            (explicit override — used by the tests and
#                                       by the installer when it records an
#                                       absolute path)
#   2. postern-hygiene on $PATH
#   3. a `postern-hygiene` next to this script (portable/dev checkout)
#   4. common dev build outputs under the repo's target/ (debug then release)
#
# Output naming:  /a/b/photo.jpg  ->  /a/b/photo.scrubbed.jpg
#                 /a/b/README     ->  /a/b/README.scrubbed
# The extension is preserved (so the scrubbed copy still opens in the right app),
# and an existing sibling is never clobbered — a numeric suffix is added instead.
#
# Fail-closed contract (mirrors the CLI's, see crates/postern-hygiene bin docs):
# `scrub -` emits scrubbed bytes to stdout ONLY after the in-memory scrub fully
# succeeds; on any failure it exits non-zero and stdout is unusable. This script
# therefore treats a non-zero exit as "discard": it deletes the partial sibling
# so a failed scrub can never leave a truncated/half-scrubbed file behind.
#
# HONESTY: the core is UNAUDITED (like everything pre-mainnet in this repo). This
# script adds no crypto and makes no new claim — it only wires the existing pipe.

set -eu

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

# --- locate the scrubber binary --------------------------------------------
find_bin() {
    if [ -n "${POSTERN_HYGIENE_BIN:-}" ]; then
        printf '%s\n' "$POSTERN_HYGIENE_BIN"
        return 0
    fi
    if command -v postern-hygiene >/dev/null 2>&1; then
        command -v postern-hygiene
        return 0
    fi
    if [ -x "$SELF_DIR/postern-hygiene" ]; then
        printf '%s\n' "$SELF_DIR/postern-hygiene"
        return 0
    fi
    # dev checkout: this script lives at desktop/file-manager/, the crate's
    # build output is at <repo>/target/{debug,release}/postern-hygiene.
    for cand in \
        "$SELF_DIR/../../target/debug/postern-hygiene" \
        "$SELF_DIR/../../target/release/postern-hygiene"; do
        if [ -x "$cand" ]; then
            printf '%s\n' "$cand"
            return 0
        fi
    done
    return 1
}

BIN=$(find_bin) || {
    echo "postern-scrub: cannot find the 'postern-hygiene' binary." >&2
    echo "  Install it on your PATH, or set POSTERN_HYGIENE_BIN=/path/to/postern-hygiene." >&2
    exit 3
}

# --- per-file scrub ---------------------------------------------------------
# Compute the non-clobbering scrubbed sibling path for "$1".
sibling_path() {
    _in=$1
    _dir=$(dirname -- "$_in")
    _base=$(basename -- "$_in")
    case $_base in
        *.*)
            _stem=${_base%.*}
            _ext=.${_base##*.}
            ;;
        *)
            _stem=$_base
            _ext=
            ;;
    esac
    _out="$_dir/$_stem.scrubbed$_ext"
    _n=1
    while [ -e "$_out" ]; do
        _out="$_dir/$_stem.scrubbed-$_n$_ext"
        _n=$((_n + 1))
    done
    printf '%s\n' "$_out"
}

rc=0
scrubbed_count=0
for f in "$@"; do
    if [ ! -f "$f" ]; then
        echo "postern-scrub: not a regular file, skipping: $f" >&2
        rc=1
        continue
    fi
    out=$(sibling_path "$f")
    # Pipe through the embed mode. stderr (the honest report) is forwarded so a
    # GUI wrapper can surface it; stdout is the scrubbed document only.
    if "$BIN" scrub - <"$f" >"$out"; then
        echo "postern-scrub: scrubbed '$f' -> '$out'" >&2
        scrubbed_count=$((scrubbed_count + 1))
    else
        # Fail closed: a non-zero exit means stdout is not a complete, fully
        # scrubbed document — never keep it.
        rm -f "$out"
        echo "postern-scrub: FAILED to scrub '$f' (no output written)" >&2
        rc=1
    fi
done

if [ "$scrubbed_count" -eq 0 ] && [ "$rc" -eq 0 ]; then
    echo "postern-scrub: no files given" >&2
    rc=1
fi
exit "$rc"
