#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Build the postern-sdk browser seam (wasm) and generate the JS glue the
# reference loader (postern-sdk.js) imports.
#
# HONEST STATUS (built ≠ produced): the crate COMPILES to wasm32-unknown-unknown
# today —
#     cargo build -p postern-sdk --target wasm32-unknown-unknown \
#           --no-default-features --features wasm --lib
# succeeds and is the CI gate for this seam. Producing the browser-ready
# `postern_sdk.js` + `postern_sdk_bg.wasm` additionally needs `wasm-bindgen-cli`
# (or `wasm-pack`), which is NOT assumed present on the dev host. This script
# checks for it and tells you how to install it rather than pretending.
#
# What the seam does / does not back is fixed in code, not here:
#   * REAL: Argon2id(64 MiB,t=3) at-rest KDF + XChaCha20-Poly1305 AEAD (kills S2).
#   * NOT in this build: hybrid PQ signing (bloch-crypto PQClean C ≠ wasm) — S1
#     stays a labeled classical stand-in in the browser.
set -euo pipefail

CRATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-$CRATE_DIR/wasm/pkg}"
PROFILE="${PROFILE:-release}"

echo "postern-sdk browser seam build"
echo "  crate:   $CRATE_DIR"
echo "  out dir: $OUT_DIR"
echo

# 1. The compile gate — always runnable, no extra tooling.
echo "[1/2] cargo build --target wasm32-unknown-unknown (compile gate)"
BUILD_FLAGS=(--target wasm32-unknown-unknown --no-default-features --features wasm --lib)
[ "$PROFILE" = "release" ] && BUILD_FLAGS+=(--release)
( cd "$CRATE_DIR" && cargo build -p postern-sdk "${BUILD_FLAGS[@]}" )
echo "  ok — the wasm seam compiles."
echo

# 2. Glue generation — needs wasm-bindgen-cli.
echo "[2/2] wasm-bindgen glue (postern_sdk.js + postern_sdk_bg.wasm)"
if ! command -v wasm-bindgen >/dev/null 2>&1; then
  cat <<'EOF'
  SKIPPED — wasm-bindgen-cli is not installed on this host.
  The compile gate above already proves the seam builds. To emit the browser
  glue the reference loader imports, install the CLI (version MUST match the
  wasm-bindgen crate version in Cargo.lock) and re-run:

      cargo install wasm-bindgen-cli --version <matching-version>
      # then:
      wasm-bindgen \
        target/wasm32-unknown-unknown/release/postern_sdk.wasm \
        --out-dir wasm/pkg --target web

  (or use `wasm-pack build --target web crates/postern-sdk -- \
        --no-default-features --features wasm`).
EOF
  exit 0
fi

WASM_PATH="$CRATE_DIR/../../target/wasm32-unknown-unknown/$PROFILE/postern_sdk.wasm"
mkdir -p "$OUT_DIR"
wasm-bindgen "$WASM_PATH" --out-dir "$OUT_DIR" --target web
echo "  ok — glue written to $OUT_DIR"
echo "  copy wasm/postern-sdk.js next to it and import { installPosternSDK }."
