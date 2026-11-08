#!/usr/bin/env bash
# Build the Postern Wallet — mobile WASM crypto core and ship it next to index.html.
#
# Why wasi-sdk + wasm32-wasip1: the wallet crypto is the REAL pqcrypto (PQClean C
# for ML-DSA-65 and Falcon-1024). Apple's system clang has no WebAssembly backend,
# and on wasm32-unknown-unknown `libc` provides no C types (c_int/size_t), so the
# only wasm target on which this compiles here is wasm32-wasip1, where the
# pqcrypto build scripts pick up the wasi-sysroot headers via --sysroot. The
# resulting module imports 5 wasi_snapshot_preview1 functions; wallet-live.js
# ships a ~40-line browser shim for them. (wasm-bindgen does not support wasip1,
# so we marshal strings across a small hand-written C ABI: bw_alloc/bw_free/bw_call.)
#
# One-time: install wasi-sdk and point $WASI_SDK at it:
#   https://github.com/WebAssembly/wasi-sdk/releases
set -euo pipefail
cd "$(dirname "$0")"

WASI_SDK="${WASI_SDK:-$HOME/.local/share/wasi-sdk-33.0-x86_64-macos}"
if [ ! -x "$WASI_SDK/bin/clang" ]; then
  echo "ERROR: wasi-sdk clang not found at $WASI_SDK/bin/clang" >&2
  echo "Set WASI_SDK to a wasi-sdk install (https://github.com/WebAssembly/wasi-sdk/releases)." >&2
  exit 1
fi

CARGO="${CARGO:-$HOME/.cargo/bin/cargo}"
export WASI_SDK_DIR="$WASI_SDK/share/wasi-sysroot"
export CC_wasm32_wasip1="$WASI_SDK/bin/clang"
export AR_wasm32_wasip1="$WASI_SDK/bin/llvm-ar"

echo "==> cargo build --release (target wasm32-wasip1)"
"$CARGO" build --release

SRC="target/wasm32-wasip1/release/bloch_wallet_wasm.wasm"
# Ship the module next to index.html so assemble-public.sh copies it verbatim.
DEST="../bloch_wallet_wasm.wasm"
cp "$SRC" "$DEST"
echo "==> shipped $DEST ($(wc -c < "$DEST" | tr -d ' ') bytes)"
