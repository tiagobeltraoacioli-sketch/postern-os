#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
#
# Build the IN-PROCESS (WebAssembly) seal module for the SHIELD work-container.
#
# This produces enterprise/shield/container/seal-wasm/target/wasm32-unknown-unknown/
# release/postern_shield_seal_wasm.wasm, which src/real-seal-engine.mjs loads with
# Node's built-in `WebAssembly` so the seal runs in-process — the 32-byte key is
# never serialized to a pipe / argv / another process (the gap the ../seal/ CLI
# backend has). No wasm-bindgen, no wasm-pack, no npm build deps: just cargo + the
# wasm32-unknown-unknown target and Node.
#
# STATUS: reference prototype — UNAUDITED, pre-production. The seal is real; the
# container around it is still containment BY CONSTRUCTION (a rooted phone / a
# debugger on this process / a RAM capture defeats it), and wasm linear memory is
# this process's address space, NOT a TEE / enclave.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
crate="$here/seal-wasm"
target="wasm32-unknown-unknown"

echo "[build-wasm] ensuring the $target rust target is installed…"
if ! rustup target list --installed 2>/dev/null | grep -q "^$target$"; then
  rustup target add "$target"
fi

echo "[build-wasm] compiling postern-shield-seal-wasm ($target, release)…"
( cd "$crate" && cargo build --release --target "$target" )

out="$crate/target/$target/release/postern_shield_seal_wasm.wasm"
if [[ ! -f "$out" ]]; then
  echo "[build-wasm] ERROR: expected artifact not found: $out" >&2
  exit 1
fi

size="$(wc -c < "$out" | tr -d ' ')"
echo "[build-wasm] OK -> $out ($size bytes)"
echo "[build-wasm] the container's real-seal engine will now use the IN-PROCESS wasm backend."
echo "[build-wasm] verify: node $here/self-check.mjs   (expect 49/49, backend = wasm)"
