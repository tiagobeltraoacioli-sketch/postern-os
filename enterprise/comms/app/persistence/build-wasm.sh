#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
#
# Build the REAL in-process seal for the Bloch comms sealed-store.
#
# Compiles seal-wasm/ (Rust, wraps the canonical postern-core seal) to a
# standalone WebAssembly module. Once built, `sealed-store.mjs` uses it as the
# DEFAULT seal automatically (postern-seal-wasm.mjs discovers the artifact); no
# other wiring is needed. Until then, the store runs on the clearly-labelled
# AES-256-GCM reference fallback.
#
# Usage:  ./build-wasm.sh            # release build (default)
#         ./build-wasm.sh --debug    # faster build, larger/slower module
#
# Requires: a Rust toolchain with the wasm32-unknown-unknown target:
#   rustup target add wasm32-unknown-unknown
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE="$HERE/seal-wasm"
TARGET="wasm32-unknown-unknown"
PROFILE="release"
PROFILE_FLAG="--release"

if [[ "${1:-}" == "--debug" ]]; then
  PROFILE="debug"
  PROFILE_FLAG=""
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "build-wasm: cargo not found — install a Rust toolchain (https://rustup.rs)." >&2
  exit 1
fi

if ! rustup target list --installed 2>/dev/null | grep -q "$TARGET"; then
  echo "build-wasm: adding rust target $TARGET ..." >&2
  rustup target add "$TARGET"
fi

echo "build-wasm: compiling seal-wasm ($PROFILE) for $TARGET ..." >&2
# shellcheck disable=SC2086
cargo build --manifest-path "$CRATE/Cargo.toml" $PROFILE_FLAG --target "$TARGET"

ART="$CRATE/target/$TARGET/$PROFILE/bloch_comms_seal_wasm.wasm"
if [[ -f "$ART" ]]; then
  echo "build-wasm: OK -> $ART" >&2
else
  echo "build-wasm: expected artifact not found at $ART" >&2
  exit 1
fi
