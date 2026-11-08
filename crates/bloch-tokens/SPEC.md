# Bloch token-envelope standard — wire layout & indexer rules (TKV0 draft)

> **Status: DESIGN SCAFFOLD — unaudited, pre-mainnet.** This is an
> **off-consensus convention**: zero consensus change, no fork, no new node
> rule. The chain neither knows nor cares about envelopes; token state is
> derived by *readers* (indexers) that scan already-valid transactions via the
> documented node RPC (or a mock). Bloch stays **ownerless** — anyone may run
> an indexer; no party, Postern included, is privileged. **BLCH is untouched**:
> this standard issues *other* tokens, never wraps BLCH, and carries no
> revenue/burn/promoter mechanism. A token's securities status is its
> **issuer's** responsibility, not Bloch's (Ethereum-neutral posture).
> License: MIT OR Apache-2.0.

Reference implementation: this crate (`bloch-tokens`). The tables below are
**normative**; `tests/vectors.rs` pins them with hand-written golden byte
vectors — if code and table ever disagree, those tests fail.

## 1. Envelope carrier

An envelope is the `script_pubkey` of a **zero-value** output of an ordinary
Bloch transaction. All multi-byte integers are **little-endian**. Decoding is
**strict**: exact magic, exact version, known op, no truncation, no trailing
bytes, validated strings/flags/decimals, non-zero amounts, no duplicate
`vout` inside one assignment list.

### 1.1 Common header (6 bytes)

| offset | size | field   | value / range                      |
|-------:|-----:|---------|------------------------------------|
| 0      | 4    | magic   | ASCII `"TKV0"` = `54 4B 56 30`     |
| 4      | 1    | version | `0x00`                             |
| 5      | 1    | op      | `0x01` = ISSUE, `0x02` = TRANSFER  |

### 1.2 ISSUE body (op `0x01`)

| offset | size | field    | value / range                                     |
|-------:|-----:|----------|---------------------------------------------------|
| 6      | 1    | decimals | 0 ..= 18 (presentational only)                    |
| 7      | 1    | flags    | bit 0 = mint-closed, **MUST be 1** in v0; bits 1–7 MUST be 0 |
| 8      | 8    | supply   | u64 LE, **>= 1** (base units)                     |
| 16     | 1    | sym_len  | 1 ..= 8                                           |
| 17     | S    | symbol   | ASCII, each byte in `A–Z` or `0–9`                |
| 17+S   | 1    | name_len | 0 ..= 32                                          |
| 18+S   | N    | name     | valid UTF-8 (may be empty)                        |

Total length: exactly `18 + S + N` bytes.

### 1.3 TRANSFER body (op `0x02`)

| offset  | size | field    | value / range                                    |
|--------:|-----:|----------|--------------------------------------------------|
| 6       | 32   | token_id | txid of the issuing transaction                  |
| 38      | 1    | n        | assignment count, 1 ..= 16                       |
| 39+12·i | 4    | vout_i   | u32 LE, no duplicates within the list            |
| 43+12·i | 8    | amount_i | u64 LE, **>= 1** (base units)                    |

Total length: exactly `39 + 12·n` bytes.

## 2. Golden vectors (normative)

ISSUE — decimals 8, flags mint-closed, supply 21 000 000, symbol `ACME`,
name `Acme Token`:

```
544B5630 00 01 08 01 406F400100000000 04 41434D45 0A 41636D6520546F6B656E
```

TRANSFER — token_id `000102…1F`, assignments `(vout 0, 1000)`, `(vout 2, 45)`:

```
544B5630 00 02 000102030405060708090A0B0C0D0E0F
               101112131415161718191A1B1C1D1E1F
               02 00000000 E803000000000000 02000000 2D00000000000000
```

## 3. Indexer rules (normative — `src/state.rs` R1–R6)

1. **R1 — consumption.** Every spent outpoint carrying color is consumed
   (removed from the colored-outpoint map, debited from its holder's
   balance) for *every* transaction, envelope or not: the base layer
   destroyed those outputs regardless. Applying a transaction yields a total
   outcome — **never an error** — so the token layer cannot invalidate a
   chain transaction by construction. BLCH values are never read or changed.
2. **R2 — no usable envelope ⇒ burn.** A transaction without an envelope
   (or with a malformed one — first magic-bearing output fails strict §1
   decode or rides a non-zero-value output) burns all color it consumed.
   *First envelope wins*: the lowest-index magic-bearing output is *the*
   candidate; later magic-bearing outputs are ignored.
3. **R3 — ISSUE.** `token_id := txid` of the issuing transaction, so
   registration happens exactly once (duplicate txid is impossible on a real
   chain; the guard also makes any attempted re-issue a no-op, and since v0
   mandates the mint-closed flag, every v0 token is mint-closed). The full
   supply is assigned to **output 0**, which must exist and must not be the
   envelope output. An ISSUE never forwards color: color its inputs carried
   burns.
4. **R4 — TRANSFER.** `token_id` must already be issued. Color consumed from
   the spent inputs is re-assigned per the explicit `(vout, amount)` list.
   Each `vout` must reference an existing output that is not the envelope
   output. **Over-assignment** (list total exceeds the color consumed for
   that token) makes the whole envelope a token-layer no-op — the consumed
   color burns (R1+R2). Unassigned remainder **burns** (no implicit change;
   list your change output explicitly). Color of *other* tokens consumed by
   the same transaction burns (one envelope, one token).
5. **R5 — checked arithmetic.** Every envelope-influenced sum is checked;
   overflow is a no-op, never a wrap. `u64::MAX` supplies must round-trip
   and index without overflow or panic.
6. **R6 — determinism.** State containers are ordered maps (`BTreeMap`);
   no observable output — state, iteration order, outcome ordering — may
   depend on hash-iteration order. Two independent indexers fed the same
   history MUST reach identical state.
7. **Reorgs.** Indexers keep a per-height block-hash journal; a reorg is a
   hash mismatch at an already-indexed height (`getblockhash`). Recovery is
   rewind-then-replay: truncate above the fork point, restore the snapshot
   at the fork (fresh state if none), replay the new branch in height order.
   The result must equal a fresh indexer's replay of the post-reorg chain
   (asserted by equality in `src/indexer.rs` tests).

## 4. Malformed classes (all must be rejected, typed, panic-free)

Bad magic; bad version; unknown op; truncation at any prefix; trailing
bytes; decimals over 18; flags with mint-closed unset or reserved bits set;
symbol empty / over 8 / outside `A–Z0–9`; name over 32 / invalid UTF-8; zero
supply; zero transfer amount; assignment count 0 or over 16; duplicate
`vout` in one list; envelope on a non-zero-value output; transfer of an
unissued token_id; assignment to a missing vout or to the envelope output;
over-assignment beyond consumed inputs; assignment sums overflowing u64.

## 5. Read RPC mapping (`src/stream.rs`)

The indexer reads the chain through three methods of the node's documented
JSON-RPC surface (`docs/openapi.yaml`, BlochSISPoW repo): `getblockcount`
(tip height = count − 1), `getblockhash(height)`, and
`getblockbyheight(height, verbose=true)`. All are public reads on every
node — no key, no privilege.

The **default** build is zero-dependency and offline-buildable; `MockChain`
stands in for the node in tests, including forced reorgs. The optional
`rpc-client` feature wires `stream::rpc::RpcBlockSource` — a **real,
read-only** `BlockSource` that speaks the JSON-RPC above to a live node over
a hand-rolled plain-HTTP `POST /` on std `TcpStream` (no async runtime, no
HTTP crate; only `serde_json` for parsing). It maps the node's non-standard
method-level failure (`result` is `{"error": …}` with HTTP 200) on
`getblockhash`/`getblockbyheight` to `SourceError::HeightNotFound`, and
de-chunks `Transfer-Encoding: chunked` responses. The verbose `transactions[]`
JSON (`format_tx`: `txid`, `inputs[].{prev_txid,prev_index}`,
`outputs[].{value,script_pubkey}`) maps straight onto the `ChainTx` read
model; BLCH values pass through untouched.

**End-to-end verification (off-consensus, unaudited).** The same reference
indexer was driven against a locally-spawned zero-value **testnet** node
(`bloch --testnet --mine`): a TKV0 token was ISSUEd and then TRANSFERred using
ordinary transactions each carrying the envelope in a **zero-value output**,
and a deliberately **malformed** envelope was mined in a third ordinary tx.
Replaying the live chain over `getblockcount`/`getblockhash`/
`getblockbyheight`, the indexer reconstructed the token (symbol, decimals,
mint-closed supply) and reflected the transfer to the recipient script — while
the malformed envelope was a token-layer **no-op** that never invalidated its
(perfectly valid) carrying transaction. This exercises the live client but
changes **nothing** about consensus: it is one indexer among many, reading a
chain that neither knows nor cares about envelopes. The live path is an
`#[ignore]`d, feature-gated integration test (`tests/live_rpc.rs`) so the
default suite stays hermetic and zero-dependency.
