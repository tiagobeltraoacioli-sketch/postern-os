<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# bloch-l2-anchor

**SCAFFOLD, UNAUDITED, NOT A WORKING L2.** Reference codec for the **L2V0
COMMIT anchor envelope** — an *off-consensus reader convention* with **zero
consensus change**: the (designed, unbuilt) Bloch EVM L2 writes batch
commitments into ordinary zero-value Bloch transaction outputs, and **Bloch
nodes never parse this**. Spec: `docs/specs/BLOCH-L2-EVM-DESIGN.md` (§1
"Interfaces / formats", §2 anchor layer). Byte-for-byte in the TKV0 idiom of
`crates/bloch-tokens`.

## Honesty box

- This is a **first-iteration compiling scaffold** from a design doc, not a
  working L2. There is no sequencer, no prover, no verifier, no bridge, and
  no node client here. Nothing is audited; nothing is safe for value.
- A decoded envelope is an **unverified claim** by whoever paid the Bloch
  fee. Proof/DA/depth verification belongs to other (unbuilt) components.
- The base chain is untouched: a malformed envelope is an anchor-layer no-op
  and never invalidates the carrying Bloch transaction. Anyone can run an
  independent reader; no party is privileged at the base layer.

## Wire format (L2V0 COMMIT, fixed 173 bytes)

`script_pubkey` of a **zero-value** output; all integers little-endian;
strict decode (exact magic, exact version, exact length); malformed ⇒ no-op.

| offset | size | field |
|---:|---:|---|
| 0 | 4 | magic ASCII `"L2V0"` (`4C 32 56 30`) |
| 4 | 1 | version `u8` = `0x00` |
| 5 | 32 | `rollup_id` (keccak of the L2 genesis header) |
| 37 | 8 | `batch_index` `u64` LE |
| 45 | 32 | `prev_state_root` |
| 77 | 32 | `new_state_root` |
| 109 | 32 | `da_commitment` |
| 141 | 32 | `vkey_hash` (SP1 program vkey hash) |

## What is real vs stubbed

- **REAL + TESTED** (`src/envelope.rs`): strict encode/decode with typed
  errors (never panics), zero-value extraction (`extract_anchor`, one
  envelope per tx, lowest-output-index-first-wins, TKV0 caveat E.1), and the
  pure canonical-chain check `link` (same rollup, `batch_index` strictly +1,
  `prev_state_root == prior new_state_root`). `tests/vectors.rs` pins the
  layout with a hand-written golden hex vector.
- **REAL + TESTED, offline** (`src/source.rs`): the `BlockSource` read trait
  (`getblockcount` / `getblockhash` / `getblockbyheight`) and the
  deterministic `MockChain` stand-in that forces reorgs, mirroring
  `bloch-tokens`' `stream` module.
- **REAL + TESTED** (`src/manager.rs`): `AnchorManager::sync` — the
  reorg-aware reader (per-height block-hash journal, fork-point rewind,
  forward replay) that derives the canonical anchor chain from any
  `BlockSource`, reusing `bloch-tokens`' journal discipline. It derives an
  **unverified** anchor chain from bytes only (no SP1 proof / DA / finality
  check).
- **REAL, read-only, behind the `http` feature** (`src/source.rs`,
  `HttpBlockSource`): a live Bloch JSON-RPC client wiring `BlockSource` to a
  node over HTTP. Hand-rolled on `std` only (own HTTP/1.1 POST + minimal JSON
  reader) so the crate stays **zero third-party deps even with the feature
  on**. It is strictly READ and maps the node's in-`result` method-error quirk
  (HTTP 200 carrying `{"result":{"error":…}}` for an unknown/pruned height) to
  `SourceError::HeightNotFound`. It never writes to, restarts, or reconfigures
  a node. Still SCAFFOLD/UNAUDITED — reading real blocks verifies nothing.

## Build

Standalone crate with its own empty `[workspace]` (excluded from the product
root workspace). The **default build is zero-dependency and offline**:

```sh
cd l2/bloch-l2-anchor && cargo test
```

The optional, OFF-by-default `http` feature enables the real read-only
JSON-RPC client (still zero third-party deps):

```sh
cargo test --features http           # offline unit tests of the client + parser

# Live, network-gated integration test — READ-ONLY against a node you point it
# at (your own local node, or a read-only public node). #[ignore] + env-gated,
# so the default suite never touches the network:
BLOCH_ANCHOR_RPC_URL=http://127.0.0.1:16210/ \
  cargo test --features http --test live_rpc -- --ignored --nocapture
```

To run that live round-trip end-to-end against a **self-spawned local node**
(no mainnet, no external service), use the runbook script. It builds/locates the
`bloch` node, spawns a throwaway zero-security `--testnet --mine` node on an
isolated port + temp data dir, mines a few blocks, runs the READ-ONLY
`live_rpc` test against it, and tears the node down:

```sh
# Point it at a prebuilt node binary, or set BLOCH_REPO to build one:
BLOCH_NODE_BIN=/path/to/bloch ./scripts/live-local-node.sh
```

Verified locally: `HttpBlockSource` reads real `getblockcount` / `getblockhash`
/ `getblockbyheight`, the window's selected-chain contiguity is proven from the
blocks' real DAG `parents`, and `AnchorManager::sync` replays the live block
window — deriving the canonical L2V0 anchor chain (legitimately **empty** on a
chain with no live L2). Zero fabricated data; the node is never touched
destructively.

## License

MIT OR Apache-2.0.
