<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# postern-bft-finality

**SCAFFOLD, UNAUDITED — designed != built != booted. Testnet, zero value.**
A post-quantum (**ML-DSA-65 / FIPS 204, NO BLS**) **BFT finality overlay**: a
committee of **the miners themselves, weighted by hashrate**, co-signs epoch
checkpoints with individual ML-DSA-65 signatures, and a **`> 2/3` of the frozen
`total_weight`** quorum finalizes a base height. Checkpoints are anchored to the
**ownerless** Bloch-SIS-PoW base as ordinary **zero-value transactions** (the
L2V0/TKV0 idiom) — **not** a base-consensus change, **coins do not vote**, the
base gains no operator. Spec: `docs/specs/POSTERN-FFG-BFT-FINALITY.md`.

## Why BFT is back

Postern rejected BFT on 2026-07-12 because **BLS/DKG aggregation is not
post-quantum** (BLS12-381 is Shor-breakable). The unlock: do BFT with
**individual ML-DSA-65 signatures — no aggregation, no DKG, no BLS anywhere**.
That is PQ-coherent end to end. BLS / threshold-BLS / DKG are **banned**. The
cost is size (no aggregation, so a quorum cert is tens-to-hundreds of KB); the
checkpoint overlay amortizes one expensive cert over a whole epoch.

## Why weighted, not count-based (supersedes `2f+1`)

An earlier draft used a count-based `2f+1` (`f = (N-1)/3`) quorum. Adversarial
review proved the intersection identity `2(2f+1) - (3f+1) = f+1` is sound **only
when `N = 3f+1`**; for other `N` (e.g. `N = 21`) it silently yields a quorum
below safety. The correct general form — and the one this crate ships — is a
**weighted `> 2/3`** rule: a checkpoint is finalized iff distinct valid signers
cover `covered_weight * 3 > total_weight * 2` of the epoch's **frozen**
`total_weight`. Two `> 2/3`-weight quorums intersect in
`w(A) + w(B) - w(A∪B) > 2W/3 + 2W/3 - W = W/3` weight — at least one honest,
attributable seat — for **any** weight distribution, with no `N = 3f+1`
precondition. Weight = a miner's **block-share in a trailing window**
(hashrate proxy), **pure, no per-miner cap**.

## Honesty box

- A design scaffold from a spec, not a working gadget. There is **no live
  committee round** (propose/co-sign/gossip/timers/transport). The ML-DSA-65
  verify seam is now filled **by default** with a **real** FIPS-204 primitive
  (RustCrypto `ml-dsa`, **UNAUDITED, pre-1.0** — real crypto, not a security
  claim); `--no-default-features` falls back to the accept-nothing stub. Nothing
  here is audited; nothing is safe for value.
- **Hashrate-weighted finality is only as decentralized as the hashrate.**
  Today the hashrate is concentrated → the committee is effectively
  Postern-controlled until miners decentralize, and a **`> 2/3`-hashrate entity
  still breaks finality** (it becomes `> 2/3` weight *and* controls the base).
  It **mitigates** 51% (raises the safety bar 51%→67% + adds no-deep-reorg
  finality below each checkpoint), it does not eliminate it. This is the
  defining fact, not a buried disclaimer.
- **Accountable safety, honest liveness.** Equivocation by a seat is
  detectable and attributable (individual ML-DSA signatures are
  attribution-native). **No slashing this phase** — detection + reputation only.
  Finality **halts** (never forks) if departed weight `> 1/3`.
- **Finality is capped by the base:** `min(base, committee)` security. The base
  is a mainnet-beta (`k`-forgeable, `51%`-attackable, unaudited today), so a
  "finalized" checkpoint is **not settlement finality** while the base is weak.

## Rotation + replacement (fixed committee per epoch)

- **Rotation:** epoch = a fixed block interval (~120 blocks / ~1h). Membership
  for an epoch is re-snapshotted from the trailing window; a miner is eligible
  iff it has a **registered ML-DSA key bound to its coinbase** and block-share
  `>= min_share`. Deterministic and on-chain re-derivable.
- **Replacement (safety-first):** the committee and `total_weight` are **FIXED
  for the whole epoch, never re-normalized mid-epoch** (shrinking the
  denominator would break intersection). A departing member simply stops voting;
  if departed weight `> 1/3`, finality **halts** (liveness, never a fork).
  Replacement **is** the next rotation (the departed miner auto-drops; live
  miners take the weight). An **emergency early rotation** re-snapshots after
  `R` (~40) blocks with no finalization. Pre-registered keys ⇒ no backfill gap.
- **Hand-off:** at the epoch boundary the outgoing committee's `> 2/3` quorum
  signs a checkpoint whose `committee_commitment` names the incoming committee
  (a weak-subjectivity anchor, cross-checked by independent re-derivation).

## `BFT0` checkpoint-anchor wire format (fixed 165 bytes, version `0x01`)

`script_pubkey` of a **zero-value** output; all integers little-endian; strict
decode (exact magic, exact version, exact length); malformed ⇒ layer no-op.
The retired 117-byte `v0x00` layout is rejected by the decoder.

| offset | size | field |
|---:|---:|---|
| 0 | 4 | magic ASCII `"BFT0"` (`42 46 54 30`) |
| 4 | 1 | version `u8` = `0x01` |
| 5 | 8 | `committee_epoch` `u64` LE |
| 13 | 8 | `finalized_height` `u64` LE |
| 21 | 32 | `finalized_block_hash` |
| 53 | 32 | `prev_checkpoint_hash` (chain spine; genesis = zero) |
| 85 | 32 | `quorum_commitment` (commitment to the co-signature set) |
| 117 | 32 | `committee_commitment` (this epoch's roster+weights) |
| 149 | 16 | `total_weight` `u128` LE (frozen denominator) |

`link()` enforces that within one `committee_epoch` the `committee_commitment`
and `total_weight` are **equal** across checkpoints (on-base enforcement of the
no-mid-epoch-re-normalization rule).

## What is real vs stubbed

- **REAL + TESTED (default build; the deterministic core needs no network):**
  - `committee.rs` — the weighted committee (`{coinbase_addr, ml_dsa_pubkey,
    weight}`, frozen `total_weight`), `weighted_quorum_reached(covered, total)`
    = `covered*3 > total*2` (u128, strict, overflow-safe), membership invariants
    (distinct id/coinbase/key, `weight >= min_share`).
  - `rotation.rs` — trailing-window block-share → weighted committee, eligibility
    filter, deterministic re-derivation, emergency-early-rotation predicate.
  - `checkpoint.rs` — strict codecs for the checkpoint transcript (incl.
    `committee_commitment` + `total_weight`) and the co-signature set +
    domain-separated signing payload.
  - `quorum.rs` — distinct-seat **weight** summation against the `> 2/3` rule,
    with a denominator cross-check, over the `CheckpointVerifier` seam.
  - `anchor.rs` — the 165-byte `v0x01` `BFT0` zero-value envelope: strict
    encode/decode, zero-value extraction (first-wins), canonical-chain `link`.
  - equivocation evidence — third-party offline-checkable detection.
- **REAL BY DEFAULT / OUT OF SCOPE (behind seams):**
  - ML-DSA-65 verify — by **default** the `CheckpointVerifier` seam is filled by
    `RustCryptoMlDsa65Verifier`, a genuine FIPS-204 verify (paired with
    `RustCryptoMlDsa65Signer`) backed by the **UNAUDITED, pre-1.0 (`0.1.1`)**
    RustCrypto `ml-dsa` crate — so a plain `cargo test` finalizes a real
    weighted `> 2/3` quorum and rejects tampered signatures, with **no**
    `--features` flag. The offline `MockVerifier` (scripted) and
    `RejectingStubVerifier` (accepts nothing) remain for `--no-default-features`
    builds. Real crypto here is not a security claim: a production deployment
    still supplies its own **independently-audited** verifier (e.g. the repo's
    wired `bloch_crypto::crypto::verify`).
  - The live committee round — an intrinsically live-networking object,
    deliberately not in this offline crate.

## Build

Standalone crate with its own empty `[workspace]` (excluded from the product
root workspace). The **default** build wires in the real (UNAUDITED, pre-1.0)
ML-DSA-65 primitive; a default `cargo test` runs
`tests/real_mldsa65_quorum.rs`, where 14 of 21 hashrate-weighted seats co-sign a
checkpoint with genuine ML-DSA-65 signatures over
`Checkpoint::canonical_signing_payload` and reach the weighted `> 2/3` quorum,
while a 13-seat sub-quorum (and any single-byte-mutated signature) does not:

```sh
cd bft/postern-bft-finality && cargo test
```

For a fully offline, zero-dependency stub build (the `RejectingStubVerifier`
posture, which asserts nothing and reaches no quorum), drop the default feature:

```sh
cd bft/postern-bft-finality && cargo test --no-default-features
```

## License

MIT OR Apache-2.0.
