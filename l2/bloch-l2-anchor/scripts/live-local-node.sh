#!/usr/bin/env bash
#
# live-local-node.sh — reproducibly UNBLOCK the LIVE anchor round-trip acceptance
# by spawning a LOCAL Bloch testnet node, mining a few blocks on it, and running
# the network-gated `tests/live_rpc.rs` integration test against it. Then tears
# the node down.
#
# HONESTY / SAFETY (non-negotiable):
#   * READ-ONLY against the node: the test only calls getblockcount /
#     getblockhash / getblockbyheight. It never writes, restarts, or
#     reconfigures anything.
#   * The node is a LOCAL, zero-security **testnet** node (`--testnet`, relaxed
#     PoW regime) that YOU spawn on an isolated port + throwaway data dir. It is
#     NEVER the mainnet node3/seeds. The test derives the canonical L2V0 anchor
#     chain over real local blocks; that chain is legitimately EMPTY (no L2 is
#     live), which the test asserts honestly. The point proven is that the HTTP
#     client talks to a REAL node and the reader consumes REAL blocks — zero
#     fabricated data.
#
# Usage:
#   ./scripts/live-local-node.sh
#
# Env overrides:
#   BLOCH_NODE_BIN   path to a prebuilt `bloch` node binary (else it is built
#                    from BLOCH_REPO with `cargo build --release -p bloch`).
#   BLOCH_REPO       path to the bloch-blockchain repo (default: ~/dev/bloch-blockchain).
#   RPC_PORT         local RPC port for the node (default: 18545).
#   P2P_PORT         local libp2p listen port (default: 18546).
#   MIN_BLOCKS       wait until getblockcount reaches at least this (default: 32).
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"   # crate root
BLOCH_REPO="${BLOCH_REPO:-$HOME/dev/bloch-blockchain}"
RPC_PORT="${RPC_PORT:-18545}"
P2P_PORT="${P2P_PORT:-18546}"
MIN_BLOCKS="${MIN_BLOCKS:-32}"
RPC_URL="http://127.0.0.1:${RPC_PORT}/"

DATA_DIR="$(mktemp -d "${TMPDIR:-/tmp}/bloch-l2-localnet.XXXXXX")"
LOG="${DATA_DIR}/node.log"
NODE_PID=""

cleanup() {
  if [[ -n "${NODE_PID}" ]] && kill -0 "${NODE_PID}" 2>/dev/null; then
    echo "[live-local-node] stopping local node (pid ${NODE_PID})"
    kill "${NODE_PID}" 2>/dev/null || true
    wait "${NODE_PID}" 2>/dev/null || true
  fi
  rm -rf "${DATA_DIR}"
}
trap cleanup EXIT INT TERM

# ── 1. Resolve the node binary ───────────────────────────────────────────────
BIN="${BLOCH_NODE_BIN:-}"
if [[ -z "${BIN}" ]]; then
  if [[ ! -d "${BLOCH_REPO}" ]]; then
    echo "[live-local-node] ERROR: bloch-blockchain repo not found at ${BLOCH_REPO}." >&2
    echo "  Set BLOCH_REPO or BLOCH_NODE_BIN. NEVER point this at a mainnet node." >&2
    exit 2
  fi
  echo "[live-local-node] building the node from ${BLOCH_REPO} (release)…"
  ( cd "${BLOCH_REPO}" && cargo build --release -p bloch )
  BIN="${BLOCH_REPO}/target/release/bloch"
fi
if [[ ! -x "${BIN}" ]]; then
  echo "[live-local-node] ERROR: node binary not executable: ${BIN}" >&2
  exit 2
fi
echo "[live-local-node] node binary: ${BIN}"

# ── 2. Spawn a LOCAL testnet mining node (isolated port + throwaway data) ─────
echo "[live-local-node] spawning local TESTNET mining node on 127.0.0.1:${RPC_PORT} …"
RUST_LOG="${RUST_LOG:-info}" "${BIN}" \
  --testnet --mine --mine-threads 4 \
  --data-dir "${DATA_DIR}/data" \
  --rpc-bind 127.0.0.1 --rpc-port "${RPC_PORT}" \
  --listen "/ip4/127.0.0.1/tcp/${P2P_PORT}" \
  > "${LOG}" 2>&1 &
NODE_PID="$!"

# ── 3. Wait for the RPC to come up and mine at least MIN_BLOCKS ───────────────
rpc_count() {
  curl -s -m 5 -X POST "${RPC_URL}" -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}' \
    2>/dev/null | sed -n 's/.*"result":\([0-9]*\).*/\1/p'
}

echo "[live-local-node] waiting for >= ${MIN_BLOCKS} blocks …"
count=""
for _ in $(seq 1 60); do
  if ! kill -0 "${NODE_PID}" 2>/dev/null; then
    echo "[live-local-node] ERROR: node exited early. Last log lines:" >&2
    tail -20 "${LOG}" >&2 || true
    exit 3
  fi
  count="$(rpc_count || true)"
  if [[ -n "${count}" && "${count}" -ge "${MIN_BLOCKS}" ]]; then
    echo "[live-local-node] node is up: getblockcount=${count}"
    break
  fi
  sleep 1
done
if [[ -z "${count}" || "${count}" -lt "${MIN_BLOCKS}" ]]; then
  echo "[live-local-node] ERROR: node did not reach ${MIN_BLOCKS} blocks in time." >&2
  tail -20 "${LOG}" >&2 || true
  exit 3
fi

# ── 4. Run the READ-ONLY live integration test against the local node ─────────
echo "[live-local-node] running tests/live_rpc.rs against ${RPC_URL} (READ-ONLY) …"
BLOCH_ANCHOR_RPC_URL="${RPC_URL}" \
  cargo test --manifest-path "${HERE}/Cargo.toml" \
  --features http --test live_rpc -- --ignored --nocapture

echo "[live-local-node] OK — live anchor round-trip verified against a local node."
