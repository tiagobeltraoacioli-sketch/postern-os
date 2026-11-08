#!/usr/bin/env bash
# Build the Ezekiel 1 governance engine to WebAssembly and generate the
# wasm-bindgen glue that the shipping browser console loads.
#
# It REFUSES to fabricate an artifact: if the wasm32 target or the wasm-bindgen
# CLI is missing, it prints exactly what to install and exits non-zero. There is
# no fallback that writes a fake .wasm — an absent build is reported as absent.
#
# Outputs (under crates/ezekiel1/wasm/):
#   pkg-web/    wasm-bindgen `web` target      (ES module; for a bundler/dev-serve)
#   pkg-node/   wasm-bindgen `nodejs` target   (CommonJS; used by parity.mjs)
#   pkg-inline/ wasm-bindgen `no-modules` glue + the raw .wasm (for CSP-safe
#               inlining into the console — no network fetch; see README)
#   ezekiel1.wasm  a copy of the optimized module (the asset the site assembles)
set -euo pipefail

CRATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"     # crates/ezekiel1
REPO_ROOT="$(cd "$CRATE_DIR/../.." && pwd)"
OUT="$CRATE_DIR/wasm"
TARGET_WASM="$REPO_ROOT/target/wasm32-unknown-unknown/release/ezekiel1.wasm"

fail() { echo "ezekiel1-wasm: $*" >&2; exit 1; }

command -v cargo >/dev/null 2>&1 || fail "cargo not found."

if ! rustup target list --installed 2>/dev/null | grep -qx wasm32-unknown-unknown; then
  fail "wasm32-unknown-unknown target missing. Install: rustup target add wasm32-unknown-unknown"
fi

if ! command -v wasm-bindgen >/dev/null 2>&1; then
  fail "wasm-bindgen CLI missing. Install a version matching Cargo.toml's wasm-bindgen dep: cargo install wasm-bindgen-cli --version 0.2.126"
fi

echo "ezekiel1-wasm: cargo build --release --features wasm --target wasm32-unknown-unknown"
( cd "$REPO_ROOT" && cargo build -p ezekiel1 --release --features wasm --target wasm32-unknown-unknown )

[ -f "$TARGET_WASM" ] || fail "expected $TARGET_WASM after build, but it is absent."

for pair in "web:pkg-web" "nodejs:pkg-node" "no-modules:pkg-inline"; do
  t="${pair%%:*}"; d="${pair##*:}"
  echo "ezekiel1-wasm: wasm-bindgen --target $t -> $OUT/$d"
  rm -rf "${OUT:?}/$d"
  wasm-bindgen "$TARGET_WASM" --out-dir "$OUT/$d" --target "$t" --omit-default-module-path
done

cp "$OUT/pkg-inline/ezekiel1_bg.wasm" "$OUT/ezekiel1.wasm"
echo "ezekiel1-wasm: built $(wc -c < "$OUT/ezekiel1.wasm") bytes -> $OUT/ezekiel1.wasm"
echo "ezekiel1-wasm: done. Run the parity proof: node crates/ezekiel1/wasm/parity.mjs"
