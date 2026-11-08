<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# bloch-l2-sequencer

**SCAFFOLD, UNAUDITED, not a working L2.** This is a first-iteration compiling
scaffold of the *pure ordering / fee logic* of the Bloch EVM L2 sequencer — a
**single disclosed operator** design per
[`docs/specs/BLOCH-L2-EVM-DESIGN.md`](../../docs/specs/BLOCH-L2-EVM-DESIGN.md)
§4. There is **no network, no EVM execution, no signing, no proving, no
anchoring, no DA** in this crate. Nothing here is safe, audited, or holding
value; the L2 it belongs to is DESIGN ONLY, testnet/zero-value gated.

## What is REAL and tested here (pure, deterministic functions)

| Module | Spec anchor | Contents |
|---|---|---|
| `fees` | §1 (`baseFee: {elasticity: 2, denominator: 250, initial: 1 gwei}`, 30M gas, 2 s blocks) | EIP-1559 `next_basefee` in u128 math (overflow bounds documented), EIP-1559 effective-tip semantics |
| `mempool` | §4 mempool policy | Two-lane FIFO ordering: priority lane (effective tip ≥ threshold) drained before standard lane, strict FIFO by arrival seq within a lane, per-sender nonce-contiguous eligibility; admission rules nonce-gap ≤ 16, per-sender pending cap 64, ≥10% replacement bump, tx ≤ 128 KiB, min-base-fee floor, type-3 blob + type-`0x7E` deposit rejection |
| `txtype` | §1 delta list (type-3 blob txs rejected at the sequencer) | Panic-free EIP-2718 leading-byte classification (`Legacy`/`0x01`/`0x02`/`0x03`/`0x7E`/unknown) and the user-submittable boundary; blob (type-3) txs are refused as on OP-Stack L2s, deposits are system-only |
| `deposit` | §5 (`BlochDepositTx`, EIP-2718 type `0x7E`, OP-Stack pattern) | Deposit struct, `source_hash = keccak256(deposit_id ‖ l1_block_hash)`, canonical byte encoding with strict round-trip decode |
| `block` | §4/§5 | Block assembly rule: deposits execute FIRST and cannot be dropped once derived; user txs follow in mempool inclusion order under the gas limit |
| `batch` | §4 batcher (300 s cadence OR 256 KiB, whichever first) | `BatchSealer` producing `Batch { batch_index, l2_block_first, l2_block_last, tx_list, compressed, batch_data_hash }`; `compressed` is the deterministic zstd -19 DA payload and `batch_data_hash = SHA3-256(compressed)`, matching the L2V0 BATCH envelope (round-trip + golden-vector tested) |
| `receipt` | §4 signed inclusion receipt | `InclusionReceipt { tx_hash, seq_no, soft_block, timestamp, sig }` with a deterministic signing payload; **signing itself is stubbed** |
| `hash` | — | Self-contained Keccak-f[1600] sponge (keccak-256 + SHA3-256) checked against FIPS-202/known vectors — hashing stays in-crate |

## Cross-crate correspondence (documentation only — no code dependency)

`Batch` fields line up one-to-one with the `L2V0` BATCH envelope (op `0x02`)
that the sibling `bloch-l2-anchor` crate commits to Bloch (§4 wire format):
`batch_index ↔ batch_no`, `l2_block_first/l2_block_last ↔ l2_block_first/last`,
`batch_data_hash ↔ batch_data_hash`. `post_state_root` / `withdrawal_root`
come from execution, which does not exist in this crate. The crates stay
disjoint on purpose (standalone-workspace pattern).

## Honestly STUBBED (`// SCAFFOLD:` markers, `stubs` module)

- revm execution hookup (no EVM anywhere in this crate)
- `eth_*` JSON-RPC server
- anchor posting to Bloch (`bloch-l2-anchor`'s job)
- DA publication (Mode-A chunks / Mode-B mirror)
- forced-inclusion `FORCE_TX` scanning of the Bloch chain
- inclusion-receipt signing (sequencer key; `sig` is opaque bytes)

## Build & test

```
cargo build && cargo test
```

One deliberate dependency — `zstd` (pinned `=0.13.3`, bundling libzstd 1.5.7)
for deterministic batch compression; own empty `[workspace]`, excluded from
the product root workspace. The `batch_data_hash` golden vector is bound to
that libzstd version: zstd guarantees DEcompression across versions, but exact
compressed bytes only within an encoder version, so a production
sequencer/verifier pair must pin the encoder (as OP Stack does). The §4
"dictionary trained on EVM calldata" ratio optimization is deferred and does
not change the hash definition. MIT OR Apache-2.0.
