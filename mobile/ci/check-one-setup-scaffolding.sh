#!/usr/bin/env bash
# CI gate (Dev-F1 UniFFI convergence): assert the tree ships EXACTLY ONE UniFFI
# `setup_scaffolding!()`.
#
# Why: two `setup_scaffolding!()` in one linked cdylib collide (duplicate FFI
# symbols / duplicate metadata) and the app layer can't tell which surface it
# bound. The whole product suite must fold into the ONE `postern_sdk` facade
# (crates/postern-sdk). This check fails the build if a second scaffolding
# re-appears (e.g. someone re-adds `mobile/core/src/ffi.rs`'s surface).
#
# It counts REAL macro invocations only — lines that are, after leading
# whitespace, `uniffi::setup_scaffolding!(` — so doc comments / prose that
# mention the macro don't inflate the count.
#
# Runs anywhere (mac CI included): pure grep, no toolchain. NOTE: this is a
# static source check. End-to-end binding validation (cargo-ndk build +
# uniffi-bindgen over the linked library, and a Kotlin/Swift compile of the app
# shells) is DEFERRED — the current mac CI has no Linux+Android/iOS SDK runner.
set -euo pipefail

# Repo root = two levels up from this script (mobile/ci/ -> repo).
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

EXPECTED=1

# Match, per line: optional leading whitespace, then `uniffi::setup_scaffolding!(`.
matches="$(grep -rniE --include='*.rs' \
    --exclude-dir=target --exclude-dir=.git --exclude-dir=.claude --exclude-dir=node_modules \
    '^[[:space:]]*uniffi::setup_scaffolding!\(' "$ROOT" || true)"

if [ -z "$matches" ]; then
  count=0
else
  count="$(printf '%s\n' "$matches" | grep -c .)"
fi

echo "==> setup_scaffolding! invocations found: $count (expected $EXPECTED)"
if [ -n "$matches" ]; then
  printf '%s\n' "$matches" | sed "s#^$ROOT/##"
fi

if [ "$count" -ne "$EXPECTED" ]; then
  echo "ERROR: expected exactly $EXPECTED uniffi::setup_scaffolding!() in the tree, found $count." >&2
  echo "       The single shipped UniFFI surface is crates/postern-sdk. Fold any new" >&2
  echo "       product FFI into that facade instead of registering a second scaffolding." >&2
  exit 1
fi

echo "==> OK: exactly one UniFFI scaffolding (the crates/postern-sdk facade)."
