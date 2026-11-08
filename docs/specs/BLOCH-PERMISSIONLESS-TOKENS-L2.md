# Bloch — permissionless tokens, forks & L2s (design)

> **Status: DESIGN SCAFFOLD.** Nothing here is built, activated, audited, or
> operational. No security claim. The base runs a k=4, unaudited, 51%-attackable
> mainnet-beta; the coin is not a security and not an asset. This document
> describes a *neutral capability*, not a product and not investment advice.

## The one-line thesis

Bloch is **ownerless**. This capability keeps it that way: **anyone — with no
privileges, no permission, no gatekeeper — can issue a token, fork the chain, or
build an L2 on top of Bloch.** Exactly the way anyone deploys an ERC-20, forks
Bitcoin, or builds a rollup — the protocol is a neutral rail, not an operator.

**Postern Labs holds no privilege here.** Postern may build *one* token/L2
product (e.g. FFG) — but only as **one builder among many** on a base open to
all. The base is the commons; the things built on it have owners.

## Three primitives

### 1. Fork (already true)
The protocol software is open and every node is a seed. Anyone may fork the code,
change parameters, and run their own chain. No one can stop a fork; no one blesses
one. The market of node operators — not a foundation — decides which chain lives.

### 2. Tokens (permissionless issuance)
A neutral token layer so anyone can mint/transfer a token that settles on Bloch —
the ERC-20 *model* (a standard interface), not the EVM. Because Bloch is a
**pure-PoW BlockDAG, not a smart-contract VM**, the honest design options are:

- **(a) Metadata/UTXO "colored" issuance** — a minimal `issue`/`transfer` token
  standard encoded in ordinary transaction outputs + a documented indexing rule.
  Lightest; no VM; validated by convention + reproducible indexers, not consensus.
- **(b) A constrained covenant/script layer** — a small, non-Turing-complete
  predicate language (spend conditions), soft-forked in behind a height gate, so
  token rules are consensus-enforced. Heavier; a real protocol change.
- **(c) L2 settlement** — tokens live on an L2 (below) and only *anchor* to Bloch.
  Keeps the base minimal; richest token semantics off-chain.

Recommendation: start at **(a)** (a documented standard + open indexers, zero
consensus change), and treat (b)/(c) as opt-in, later, soft-fork-gated work.

#### Primitive (a) wire format — TKV0 (draft)

> **Status: DESIGN SCAFFOLD — unaudited, pre-mainnet.** This is an
> *off-consensus convention* plus a reproducible indexing rule. It is **not**
> a fork of the node, not a new consensus rule, and requires **zero consensus
> change**. Token state under TKV0 is **NOT consensus-enforced** — it exists
> only in the eyes of indexers that follow this rule. Anyone can run an
> indexer; no party (Postern included) is privileged. A reference
> implementation lives at `crates/bloch-tokens` in this repo (MIT OR
> Apache-2.0), one indexer among any number of equal ones.

##### A. The envelope

A TKV0 message is one ordinary `TxOutput` inside one ordinary Bloch
`Transaction` — the exact shapes defined in the Bloch-SIS-PoW repo,
`crates/bloch-crypto/src/core/mod.rs`:

```rust
pub struct TxOutput { pub value: u64, pub script_pubkey: Vec<u8> }
pub struct Transaction { pub version: u32, pub inputs: Vec<TxInput>,
                         pub outputs: Vec<TxOutput>, pub locktime: u32 }
```

`script_pubkey` is a free-form `Vec<u8>`. Node validation
(`validate_tx_inputs` in the node's `src/main.rs`) constrains only the
script_pubkey of the UTXO being **spent** (it must equal
`SHA3-256(pubkey)[..20]` of the spender's key); it **never constrains the
script_pubkey of a newly created output**. An envelope output is therefore
accepted by every unmodified node today — provably a
**zero consensus change**.

Envelope output layout (`value` MUST be `0`; see caveat E.1):

| offset | size | type      | field                                   |
|-------:|-----:|-----------|-----------------------------------------|
| 0      | 4    | bytes     | magic — ASCII `"TKV0"` (`54 4B 56 30`) |
| 4      | 1    | `u8`      | version — `0x00` for this draft         |
| 5      | 1    | `u8`      | op — `0x01` ISSUE, `0x02` TRANSFER      |
| 6      | var  | bytes     | op-payload (below)                      |

All multi-byte integers are **little-endian**. Any output whose
`script_pubkey` does not begin with the 4-byte magic is not an envelope and
is ignored by this standard.

##### B. Ops

**ISSUE (op = `0x01`)** — creates a new token. The token's identity is
`token_id := txid` of the transaction carrying the ISSUE envelope (32 bytes,
globally unique, no registry, no gatekeeper). Payload, offsets from the start
of `script_pubkey`:

| offset | size | type   | field                                                    |
|-------:|-----:|--------|-----------------------------------------------------------|
| 6      | 1    | `u8`   | `decimals` — display decimals; MUST be ≤ 18                |
| 7      | 1    | `u8`   | `flags` — bit 0 = mint-closed; in v0 bit 0 MUST be 1 (fixed supply) and bits 1–7 MUST be 0 |
| 8      | 8    | `u64`  | `supply` — total supply in base units; MUST be > 0         |
| 16     | 1    | `u8`   | `symbol_len` — MUST be 1..=8                               |
| 17     | var  | bytes  | `symbol` — `symbol_len` bytes, ASCII `[A-Z0-9]` only       |
| 17+sl  | 1    | `u8`   | `name_len` — MUST be 0..=32                                |
| 18+sl  | var  | bytes  | `name` — `name_len` bytes, valid UTF-8                     |

The payload MUST end exactly at `18 + symbol_len + name_len` (no trailing
bytes). Maximum envelope size: 58 bytes. On a valid ISSUE, the full `supply`
is assigned to **output 0** of the issuing transaction (the envelope output
MUST NOT be output 0; if it is, the ISSUE is malformed).

**TRANSFER (op = `0x02`)** — moves token amounts from the transaction's
inputs to its outputs. Token amounts ride **colored outpoints**: a `(txid,
vout)` that an indexer has assigned token units to. BLCH values on those
outpoints are completely untouched — color is bookkeeping in the indexer,
never a change to any BLCH amount. Payload:

| offset    | size | type   | field                                          |
|----------:|-----:|--------|------------------------------------------------|
| 6         | 32   | bytes  | `token_id` — txid of the issuing transaction    |
| 38        | 1    | `u8`   | `n` — assignment count; MUST be 1..=16          |
| 39 + 12·i | 4    | `u32`  | `vout` of assignment *i* (0 ≤ i < n)            |
| 43 + 12·i | 8    | `u64`  | `amount` of assignment *i*; MUST be > 0         |

The payload MUST end exactly at `39 + 12·n`. Maximum envelope size: 231
bytes. Each `vout` MUST be a valid output index of the carrying transaction,
MUST NOT be the envelope output's own index, and MUST NOT repeat within the
list.

##### C. Deterministic validity rules

Applied by every indexer, in this exact order, so that **equal replays yield
equal state**:

1. **At most one envelope per transaction — first-wins.** The envelope is
   the *lowest-index* output whose `script_pubkey` begins with `"TKV0"`. Any
   later output starting with the magic is ignored entirely (it is not "a
   second envelope"; it does not exist to the token layer).
2. **Malformed ⇒ token-layer no-op.** Any violation of section A/B (bad
   version, unknown op, wrong lengths, trailing bytes, `value != 0`, symbol
   charset, decimals > 18, flags, `n` out of range, duplicate or
   out-of-range `vout`, …) makes the envelope a **no-op for the token layer
   only**. The Bloch transaction itself remains perfectly valid and
   confirms normally — nothing at this layer can ever invalidate a Bloch
   transaction.
3. **Checked arithmetic only.** All token sums use checked `u64` arithmetic.
   Any overflow anywhere (summing input color, summing assignments) ⇒ the
   envelope is a no-op.
4. **TRANSFER accounting.** Input color for `token_id` = checked sum of the
   token amounts on the colored outpoints this transaction spends. If the
   checked sum of the assignment amounts **exceeds** input color, the
   TRANSFER is an **over-spend ⇒ no-op** (and, since the colored inputs are
   spent regardless, their color is burned per rule 5). Otherwise each
   `(vout, amount)` colors that outpoint.
5. **Unassigned input color is burned.** There is no implicit change output.
   Any input color not explicitly re-assigned by a valid TRANSFER — including
   color on inputs of a transaction with no envelope, a malformed envelope,
   an over-spending envelope, or an envelope for a different `token_id` — is
   destroyed. Spending a colored outpoint always consumes its color.
6. **ISSUE uniqueness is free.** `token_id` is a txid, so collisions are
   impossible; no name/symbol uniqueness exists or is promised.

##### D. The indexing rule (replay + reorg)

An indexer derives token state purely by reading the chain over the node's
documented JSON-RPC API (`docs/openapi.yaml` in the Bloch-SIS-PoW repo):

1. **Replay.** Call **`getblockcount`** for the selected-chain tip height.
   For each height `h` from 0 to the tip: call **`getblockhash`**`(h)`,
   record it, and fetch the block with
   **`getblockbyheight`**`(h, verbose=true)`. Apply transactions **in block
   order**, and within each transaction scan outputs **by index** (rule C.1).
   This makes replay a pure function of the selected chain: two independent
   indexers replaying the same chain reach byte-identical token state.
2. **Reorg.** Keep the `height → block hash` map from step 1. On each sync,
   re-check recent heights with `getblockhash`; a **hash mismatch** at height
   `h` means a reorg. Rewind token state to the last matching height (the
   fork point) — via undo records or by replaying from genesis/a pre-fork
   snapshot — then replay forward per step 1. Both strategies are equivalent;
   determinism, not mechanism, is normative.
3. **Confirmation depth.** The base is a k=4, unaudited, **51%-attackable
   mainnet-beta**. Indexers SHOULD treat token state as tentative until a
   depth of **K = 24 blocks** (6× the DAG parameter), and applications
   SHOULD scale K up with value at risk. Honestly: on a 51%-attackable
   chain **no finite K is safe against a majority attacker** — K only
   prices out casual reorgs. Do not represent any K as finality.

##### E. Honest caveats (normative)

1. **Envelope outputs are unspendable by convention only.** No consensus
   rule makes them unspendable. Worse, the node's `storage/indexer.rs`
   reads `script_pubkey[..20]` as an address hash whenever
   `script_pubkey.len() >= 20`, so an envelope can be mis-indexed as an
   address by the node's own address index. This is why `value` **MUST**
   be `0`: no BLCH may ever ride an envelope output (a nonzero value is
   malformed per C.2, and the BLCH would be practically stranded).
2. **Token state is NOT consensus-enforced.** Nodes neither know nor care
   about TKV0. The only guarantee is reproducibility: **anyone can run an
   indexer, and equal replays of the same selected chain yield equal
   state.** There is no privileged indexer, no official one, and Postern's
   (if it runs one) is exactly as authoritative as yours: not at all.
3. **BLCH is never a token under this standard.** TKV0 issues *other*
   tokens; it adds no BLCH mechanism, no burn, no revenue link, nothing
   that touches the base coin's not-a-security posture.
4. **The issuer bears the securities responsibility.** A TKV0 token's legal
   status is its issuer's problem, exactly as an ERC-20's is on Ethereum —
   the rail is neutral and neither performs nor polices issuance
   (Ethereum-neutral).
5. **Design scaffold, unaudited, pre-mainnet.** Nothing here is a security
   claim, an activation, or a promise. Byte layouts may change before any
   v1.

### 3. L2 (anyone anchors to Bloch)
Anyone can build an L2 that **reads** Bloch (headers, accumulated PoW work, the
canonical tip) and **writes** its state commitments back as **ordinary
transactions**. No privileged bridge, no admin key required by the base. This is
the same anchoring the FFG notary uses — the point is that **it is open to
everyone**, not a Postern monopoly.

## The burn model — where the line is (read carefully)

A token issuer *may* design their token however they like, including a
**revenue-funded buyback-and-burn** of **their own** token. That is the issuer's
choice and the issuer's legal responsibility — like a scam or a legitimate
ERC-20, Bloch (ownerless) neither performs nor polices it.

**Hard lines the base and Postern must not cross:**
- ❌ **BLCH (the base coin) is never revenue-burned.** No Postern (or anyone's)
  revenue buys back and burns BLCH. A promoter using company revenue to reduce
  supply of a coin they premined is a **textbook securities profile** (Howey:
  expectation of profit from the promoter's efforts). BLCH stays not-a-security:
  no sale, no listing, no price, no burn-for-value.
- ❌ **Bloch does not operate, endorse, or market any token.** Neutral rail only.
- ✅ A **third party's** token with its own burn model is *their* product and
  *their* liability — Bloch is Ethereum-neutral about it.

If Postern ever wants a token in a product (FFG/RWA/BaaS), that is a **separate,
owned, disclosed product decision** requiring its own securities-law review — and
it still must not touch BLCH's not-a-security posture.

## Why this stays consistent with everything else

- **Ownerless / no privilege:** the capability is open to all; Postern gets no
  special power (matches PRINCIPLES + the "Two Layers" doc + the Why-Postern film).
- **Pure PoW preserved:** (a) needs no consensus change; (b)/(c) are opt-in
  soft-forks that node operators individually adopt — no board, no override.
- **Not-a-security shield preserved for BLCH:** the base coin is untouched by any
  revenue/burn/promoter mechanism.

## Honest open questions (before any build)
1. Which primitive first — (a) standard-only, or straight to (c) L2? (Recommend a.)
2. Double-spend / reorg semantics for token state under the BlockDAG.
3. A securities-counsel review for **any** Postern-owned token product (not the base).
4. Anti-abuse: the neutral rail will attract scam tokens; the honest answer is the
   Ethereum one — the protocol can't police them; users verify; Postern warns.

---
*Design scaffold, unaudited, pre-mainnet. The base is a zero-security beta; BLCH is
not a security and not an asset. This is not legal or investment advice.*
