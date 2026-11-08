# bloch-tokens

> **DESIGN SCAFFOLD — unaudited, pre-mainnet, not an offering.** This crate is
> a reference implementation of a draft convention. It has had no security
> audit, is not deployed anywhere, and nothing here is a sale, a listing, or
> investment advice. A token issued under this standard is its **issuer's**
> product and its **issuer's** legal/securities responsibility — not Bloch's
> and not this crate's (the Ethereum-neutrality posture: a neutral rail
> neither performs nor polices what is built on it).

Neutral reference implementation of the **Bloch token-envelope standard
(TKV0)**: an *off-consensus* byte convention for issuing and transferring
tokens by embedding a small, strictly-validated payload ("envelope") in a
zero-value output of an ordinary Bloch transaction — plus the deterministic
state machine and reproducible indexer that read that state back out of the
chain.

The normative wire layout, golden byte vectors, and indexer rules live in
[`SPEC.md`](./SPEC.md) next to this file (see especially **§1 Envelope
carrier**, **§2 Golden vectors**, and **§3 Indexer rules**). If the code and
the spec ever disagree, `tests/vectors.rs` fails.

## Neutrality guarantees (first-class, non-negotiable)

1. **ZERO consensus change.** This crate never touches the node, PoW, block
   or transaction validation. It is **not a node fork and adds no consensus
   rule**. The chain neither knows nor cares about envelopes: token state is
   derived entirely by *readers* (indexers) that **READ** already-valid
   transactions through the node's documented JSON-RPC surface
   (`getblockcount`, `getblockhash`, `getblockbyheight` — see
   `docs/openapi.yaml` in the BlochSISPoW repo), or through the in-crate
   `MockChain` test double. By construction the token layer can never
   invalidate a chain transaction: applying a transaction is total
   (`ApplyOutcome` has no error variant), and BLCH values are never even
   modeled, let alone modified.

2. **Bloch stays ownerless.** The standard is fully specified by `SPEC.md`
   and this crate's byte layout and indexer rules. **Anyone** can run this
   indexer — or write their own from the spec — against **any** node
   (their own included), with no key, no registration, and no gatekeeper.
   Equal replays yield equal state: independent indexers fed the same chain
   converge to identical token state, including across deep reorgs
   (asserted by equality in `tests/determinism.rs`; all state containers are
   `BTreeMap`s so no observable output depends on hash-iteration order).
   **No party — Postern Labs included — holds any privilege** over the
   standard, the indexing, or the tokens. Reproducibility replaces trust.

3. **BLCH is untouched.** This standard issues **other** tokens; BLCH, the
   base coin, is never a token under it and is never wrapped by it. The
   standard contains **no revenue, buyback, burn, or promoter mechanism for
   the base coin** of any kind. Token-layer "burns" in the spec (e.g.
   unassigned color on transfer) affect only the issuer's own token
   accounting — never a satoshi-equivalent of BLCH. BLCH's not-a-security
   posture (no sale, no listing, no burn-for-value) is preserved intact.

4. **Honesty.** This is a **design scaffold**: unaudited, pre-mainnet, not
   deployed, not an offering, and not legal or investment advice. Do not
   rely on it for value. The neutral rail cannot police what is issued on
   it; users must verify issuers, and **a token's securities status is its
   issuer's responsibility, not Bloch's** — exactly as an ERC-20's status
   is its deployer's problem, not Ethereum's.

5. **License: MIT OR Apache-2.0.** The repo-root
   [`LICENSE-MIT`](../../LICENSE-MIT) and
   [`LICENSE-APACHE`](../../LICENSE-APACHE) apply to this crate as to every
   subdirectory of the repository. Because this crate is deliberately
   **re-homeable** (its own standalone `[workspace]`, zero dependencies),
   crate-local copies of both license files are also included here
   ([`LICENSE-MIT`](./LICENSE-MIT), [`LICENSE-APACHE`](./LICENSE-APACHE)) so
   the licensing travels with the crate wherever it goes. Use it, fork it,
   re-implement it — permissionlessly.

## Run your own indexer (no permission needed)

Against `MockChain` (in real use, implement the three-method `BlockSource`
trait over your own node's public read JSON-RPC — it is ~50 lines with any
HTTP client; see `src/stream.rs` for the exact method mapping):

```rust
use bloch_tokens::{ChainTx, Indexer, MockChain, TokenOp, TxOut, FLAG_MINT_CLOSED};

// One ordinary chain transaction: output 0 receives the supply, output 1 is
// a zero-value TKV0 ISSUE envelope (token_id := the issuing txid).
let op = TokenOp::Issue {
    decimals: 2,
    flags: FLAG_MINT_CLOSED,
    supply: 1_000,
    symbol: "DEMO".into(),
    name: "Demo token".into(),
};
let holder = vec![0xA1; 20];
let tx = ChainTx {
    txid: [2; 32],
    inputs: vec![],
    outputs: vec![
        TxOut { value: 1, script_pubkey: holder.clone() },
        TxOut { value: 0, script_pubkey: op.encode() },
    ],
};

let mut chain = MockChain::new(); // 1. a chain source (mock of the node's read RPC)
chain.append(vec![tx]); // 2. the chain accepts an ordinary transaction
let mut indexer = Indexer::new(); // 3. YOUR indexer — no permission, no privilege
indexer.sync(&chain).unwrap(); // 4. replay the chain (reorg-safe: rewind + replay)
assert_eq!(indexer.state().balance(&holder, &[2; 32]), 1_000); // 5. derived token state
```

This snippet compiles and passes against the crate as-is. Reorgs are handled
by `Indexer::sync` automatically: a hash mismatch in its per-height journal
triggers rewind-then-replay, and the result equals a fresh replay of the new
chain (`MockChain::replace_suffix` forces this in tests).

## Layout

| module         | contents                                                                 |
|----------------|--------------------------------------------------------------------------|
| `envelope`     | TKV0 wire format: `TokenOp` encode/decode, typed `EnvelopeError`, `extract_envelope` (first envelope wins; zero-value rule) |
| `chain`        | Minimal read model: `OutPoint`, `ChainTx` — the subset of the node's `Transaction` schema the token layer reads |
| `state`        | Deterministic state machine: `TokenState::apply_tx` (total, never an error), registry, colored outpoints, balances |
| `stream`       | `BlockSource` trait shaped exactly on the node's JSON-RPC + `MockChain` (reorg-capable test double) |
| `indexer`      | Reproducible reference indexer: `Indexer::sync` — replay, per-height journal, snapshot rewind on reorg |

Zero dependencies; builds and tests fully offline (`cargo test` in this
directory). A real RPC client is deliberately out of scope.
