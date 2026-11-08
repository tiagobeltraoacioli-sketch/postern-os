<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# bloch-l2-bridge

**SCAFFOLD, UNAUDITED, not a working L2. The v1 L1 vault is CUSTODY, full
stop — nothing here moves value.**

Bridge *types* for the (design-only) Bloch EVM L2, implementing the wire
formats and pure math of [`docs/specs/BLOCH-L2-EVM-DESIGN.md`](../../docs/specs/BLOCH-L2-EVM-DESIGN.md)
§5 (L1<->L2 Bridge). This crate contains no networking, no keys, no chain
interaction, and no contract compilation. It is a first-iteration compiling
scaffold produced so the byte formats and tree constructions are pinned by
tests before anything real is built.

## Honesty block (carried verbatim from the design, §5)

* **THE VAULT IS CUSTODY, FULL STOP.** v1 BLCH deposits are operator-held;
  quorum policy is organizational, not cryptographic (no production
  threshold ML-DSA). Colluding keyholders — or Postern itself — can steal
  reserves; proof-of-reserves DETECTS theft after the fact, it does not
  PREVENT it.
* **BLOCH REORGS BREAK BOTH DIRECTIONS.** Bloch today is k=4, low-hashrate,
  51%-attackable, unaudited, with NO finality gadget. `K(amount)` only
  prices out casual reorgs; NO finite depth is safe against a majority
  attacker. No `K` may ever be represented as finality.
* **THE VALIDITY PROOF DOES NOT PROVE L1 CANONICALITY.** A proof is about a
  named L1 view; a reorg below that view leaves the proof "valid" about a
  dead branch.
* **BRIDGES ARE THE MOST-EXPLOITED CONSTRUCT IN THE SPACE.** Nothing here is
  built, audited, or safe; testnet / zero-value until the
  POSTERNDEX-BRIDGE-DESIGN §0 gates clear (k=8 ramp, WAN hashrate,
  checkpoint finality, third-party audit, legal review).
* The L2 itself is an **owned Postern product** (single disclosed
  sequencer). Only the anchoring rail is ownerless. Conflating the two is
  the overclaim this project forbids.

## What is REAL and TESTED here

| Module | Contents |
|---|---|
| `envelope` | `L2D0` deposit envelope codec, byte-exact per §5: `"L2D0"` (4B) \| version `u8=0x00` \| op `u8=0x01` \| `l2_chain_id` u64 LE \| `l2_recipient` 20B — exactly 34 bytes, strict decode (typed errors, no trailing, malformed ⇒ layer no-op), zero-value-output extraction with lowest-index-wins (TKV0 rule C.1). Round-trip + golden-vector + malformed-class tests. |
| `atoms` | `ATOM_SCALE = 10^10` (8-decimal L1 sats → 18-decimal L2 wei) with exactness invariants: conversion is lossless by construction, and the `withdraw()` rule `wei % ATOM_SCALE == 0` is a tested pure predicate. |
| `withdrawal` | Withdrawal message + canonical ABI-style leaf encoding: `leaf = keccak256(abi.encode(nonce u64, l2_sender address, l1_recipient bytes20, amount_atoms u64, epoch_number u64))` — 5×32-byte words, documented padding, golden-vector tested. |
| `merkle` | keccak256 **incremental Merkle tree, depth 32** (Ethereum-deposit-contract construction: precomputed zero-subtree hashes, insert-append, current root) + `verify_inclusion(leaf, index, branch[32], root)`. Tested: empty-tree root equals the zero-hash cascade, insert-then-prove round-trips, tampered branch/index/leaf rejected. |
| `status` | `DepositEvent` / `WithdrawalStatus` (`Queued \| Provable \| ReleaseEligible \| Frozen \| Halted`) per §2/§5, and the `K(amount)` confirmation-depth schedule (24 / 96 / 288 / 288+operator-review tiers) as a pure function. |
| `harness` | Deploy **harness config** (types + validation only, NOT a live deploy): parses [`deploy/testnet.json`](deploy/testnet.json) describing the WBLCH predeploy (`contracts/wblch/WBLCH.sol`, fixed address `0x4200…0006`, solc `^0.8.24`) and the *unchanged* Uniswap-v2 factory/router artifacts (hashes are labelled placeholders; chain_id 700771 is itself a placeholder pending registration). A test asserts the referenced `WBLCH.sol` exists and hashes stably. |

## What is honestly STUBBED (`// SCAFFOLD:`)

* Vault keyholder / release-agent logic (the §5 release checklist) — types
  only, every method returns `NotImplemented`.
* The L1 watcher over node RPC (would reuse `crates/bloch-tokens` indexer
  replay verbatim) — not wired here.
* `FederatedGateway` / outside assets (wBTC/wUSDT/wETH) — explicitly OUT OF
  SCOPE: v1 is WBLCH only, per `contracts/wblch/`.
* Any actual contract compilation, deployment, or chain interaction.

## Build / test

```sh
cd l2/bloch-l2-bridge && cargo test
```

Standalone crate with its own empty `[workspace]` (the `crates/bloch-tokens`
pattern) — deliberately excluded from the product root workspace.

## License

MIT OR Apache-2.0.
