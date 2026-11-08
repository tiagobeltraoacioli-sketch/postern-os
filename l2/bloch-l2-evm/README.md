<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# bloch-l2-evm

> **SCAFFOLD, UNAUDITED, not a working L2.** This crate is a first-iteration,
> compiling skeleton of the execution layer described in
> [`docs/specs/BLOCH-L2-EVM-DESIGN.md`](../../docs/specs/BLOCH-L2-EVM-DESIGN.md) §1.
> Nothing here is audited, safe, deployed, or value-bearing, and **no claim of
> ethereum/tests or EEST conformance is made anywhere**. It is not a node, not
> a sequencer, not a prover, and not a Reth embedding — it is the
> state-transition core those would call, plus honest labelled stubs.

> **The reorg gate (from the design, read first).** An L2 inherits its L1's
> finality. Bloch today is k=4 forgeable, 51%-attackable, unaudited — a Bloch
> reorg can unwind L2 state anchored to reorged blocks. Real value is gated on
> Bloch mainnet security (k=8 ramp, WAN hashrate, checkpoint finality) + a
> third-party audit + legal review. Everything below is **testnet /
> zero-value** until then.

The L2 is an **owned Postern product** (it has a sequencer/operator) that
anchors to the ownerless Bloch-SIS-PoW base as ordinary transactions — the
base gains no operator and needs no consensus change. The native gas token is
an L2 representation of **bridged BLCH**: zero issuance, never sold, never
burned.

## Version pins (normative for this scaffold)

| dependency | pin | why |
|---|---|---|
| `revm` | **`=41.0.0`** (exact) | The design requires ONE pinned revm so the native node and the future SP1 guest re-execute byte-identical code; any bump is a documented program upgrade. |
| `alloy-primitives` | `1.6.0` (resolves to the same version revm 41.0.0 uses) | `Address`/`U256`/`B256` are one type family across the crate. |
| hardfork | `SpecId::CANCUN` | Cancun at genesis per the design; Prague only via a coordinated, height-gated upgrade. |

`Cargo.lock` is committed (determinism contract, design §1).

## What is REAL and tested (`cargo test`, 22 tests)

* **`ChainSpec`** (`src/chainspec.rs`) — the design's genesis knobs:
  `chain_id = 700771` (testnet placeholder pending ethereum-lists/chains
  registration), `gas_limit = 30_000_000`, EIP-1559 `elasticity = 2` /
  `denominator = 250`, initial base fee 1 gwei, **block reward = 0**,
  COINBASE = fee-vault address. Includes a tested integer-only EIP-1559
  next-base-fee computation with those knobs.
* **Exact sats⇄wei scaling** (`src/scale.rs`) — `ATOM_SCALE = 10^10`: u64 L1
  sats (8 decimals) scale exactly to U256 L2 wei (18 decimals); the reverse
  direction fails (never rounds) on non-aligned amounts. 1 BLCH = 10^18 wei.
* **`L2State`** (`src/state.rs`) — an account/state layer over revm's
  `CacheDB`/`InMemoryDB` with **deposit-mint**: credits *exactly* the
  escrow-derived wei; provenance is a single-variant enum (**bridged BLCH
  only** — no admin mint, no reward, no other asset). Tracks total minted
  supply; tests assert `total supply == sum of mints` (zero issuance).
* **`execute_block`** (`src/executor.rs`) — runs **UNMODIFIED revm** at
  `SpecId::CANCUN`: applies deposit mints at block start, executes
  transactions, routes the basefee to the `BaseFeeVault`
  (`0x4200…0019`) and the priority fee to the `SequencerFeeVault`
  (`0x4200…0011`, the block beneficiary) — **never burns** bridged BLCH, so
  the L1 escrow always balances. Rejects type-3 (blob) transactions at the
  sequencer boundary, as on OP-Stack L2s. Tests execute a value transfer and
  a contract deploy+call against in-memory state and assert post balances,
  nonces, gas accounting, vault routing, and supply conservation.
* **keccak-256 MPT state root** (`src/stateroot.rs`) — a real, standard
  Ethereum keccak-256 hexary Merkle-Patricia trie root over the
  post-execution account trie + per-account storage tries, built with
  `alloy-trie`'s `HashBuilder` (the primitive reth uses) and accounts/storage
  RLP-encoded exactly as Ethereum does. Empty accounts (EIP-161) and
  zero-valued slots are excluded, so an empty state hashes to the canonical
  `EMPTY_ROOT_HASH`. `execute_block` fills `ExecutionOutcome.state_root` with
  this computed root (no placeholder). Tests assert the empty-root identity,
  determinism, insertion-order independence, and balance-sensitivity.

## What is honestly STUBBED (`todo!()` / `unimplemented!()`, `// SCAFFOLD:`)

* `eth_*` JSON-RPC, txpool, and the Reth-SDK node embedding (`src/stubs.rs`)
  — the design mandates Reth's stack precisely so this surface is *not*
  hand-rolled.
* the SP1 guest (riscv32im) build target and ExecutionWitness plumbing
  (`src/stubs.rs::sp1_guest`) — full revm-in-SP1 proving is a multi-month
  integration (the RSP pattern), not a scaffold deliverable.
* genesis alloc / predeploy bytecode (the vault addresses exist as plain
  balance-holding accounts here, not deployed Solidity vaults).

## Layout / build

Standalone cargo crate with its own empty `[workspace]` table (the
`crates/bloch-tokens` pattern) so it stays outside the product root workspace
and carries the heavy revm tree independently.

```sh
cd l2/bloch-l2-evm
cargo build
cargo test   # 22 tests, all passing at the time of writing
```

License: MIT OR Apache-2.0. `publish = false`, version `0.0.0-scaffold`.
