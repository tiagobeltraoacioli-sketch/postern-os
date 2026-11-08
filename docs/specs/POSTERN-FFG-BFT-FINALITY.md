<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Postern FFG-BFT — Post-Quantum Hashrate-Weighted Finality — design
**Status: DESIGN + CRATE-SEAM SCAFFOLD. Not built, not booted, not audited, not safe. Testnet / zero-value.** A **finality overlay** for the ownerless Bloch-SIS-PoW base: the **miners themselves, weighted by hashrate**, read the base's selected chain and co-sign epoch **checkpoints** with **individual ML-DSA-65 signatures (FIPS 204) — no BLS, no threshold-BLS, no DKG, no aggregation anywhere** — anchoring each checkpoint back to the base as an **ordinary zero-value transaction** (the `L2V0`/`TKV0`/`DATA0` idiom). It is an **overlay, not a base-consensus change**: the base gains no operator, no reserved namespace, no new validity rule; **coins do not vote — hashrate does**, and hashrate is the same Sybil-resistance already securing the base. Companion / substrate: [`BLOCH-L2-EVM-DESIGN.md`](BLOCH-L2-EVM-DESIGN.md), [`BLOCH-PERMISSIONLESS-TOKENS-L2.md`](BLOCH-PERMISSIONLESS-TOKENS-L2.md); the scaffold it evolves is `ffg/` (`postern-ffg`, the single-operator notary) and its own crate `bft/postern-bft-finality`.

> **This REVISITS the 2026-07-12 rejection of BFT — read first.** On 2026-07-12 BFT finality was rejected for one specific, correct reason: **the finality primitive everyone reaches for (BLS12-381 / threshold-BLS aggregation over a DKG'd committee) is Shor-breakable**, so it cannot anchor a chain whose whole reason to exist is post-quantum hardness. The rejection was **not** "no committees ever." The unlock — and the entire reason this design exists — is doing BFT with **individual ML-DSA-65 signatures, one per seat, with NO aggregation of any kind.** Every place a classical gadget reaches for BLS, this design instead carries N raw ~3.3 KB signatures (or an on-base commitment to them) and pays the O(N) cost honestly (§7). **BLS / threshold-BLS / DKG / pairing-based aggregation are BANNED here** — not deprecated, banned; the only sanctioned future path to constant-size certs is hash-based pqSTARK recursion (§7, out of v1 scope), never pairings.

> **This SUPERSEDES the count-based `2f+1` committee.** An earlier draft of this spec used a count-based Byzantine committee: `N` disclosed seats, quorum `= 2f+1`, safety from `N ≥ 3f+1`. **A review proved that design unsafe whenever `N ≠ 3f+1`** — the `2(2f+1) − (3f+1) = f+1` overlap bound is only sound at the exact `N = 3f+1` boundary; for `N > 3f+1` two `2f+1` quorums can fail to overlap in an honest seat, so accountable safety does not hold in general. **The correct general form is a WEIGHTED quorum**: votes must cover **> 2/3 of the epoch's total weight**, and the quorum-intersection guarantee then holds for **any** weight distribution (§3.2). This locked design (founder, 2026-07-16) replaces the count-based committee with a **hashrate-weighted** one: the committee is the miners, weighted by block-share.

> **The reorg gate (read second).** A finality gadget inherits its base's security. Bloch today is `k=4` forgeable, `51%`-attackable, unaudited — `BaseAnchorRef.accumulated_work` is hashcash cumulative work, **not** lattice hardness. **BFT finality over a forgeable base is capped at `min(base security, committee security)`** and is not settlement finality. The `Finalized` name and the removal of the honest caveat strings are **gated on the base moving off `k=4`/51%-attackable, independently of this crate.** Everything below is testnet / zero-value until that gate clears.

_Winner of a 3-design bake-off (FFG checkpoint overlay vs Tendermint instant-finality vs minimal committee-notary), re-anchored on a hashrate-weighted committee. The FFG checkpoint overlay wins on PQ-cost amortization and offline-testability; it grafts Tendermint's crisp quorum-intersection accountable-safety proof (§3.2), generalized to a weighted quorum, and the minimal-notary's on-base roster/weights commitment (§4.6)._

---

## 0. Why FFG-overlay won, and why the committee is the miners

**The bake-off.** Three PQ-BFT finality designs were scored on five axes: real 51%/reorg mitigation, PQ-coherence (ML-DSA only, zero BLS), keeping the base ownerless (overlay-anchored, not an L1 consensus change), honesty of the trust surface (no decentralization theater), and offline-testability of a scaffold crate.

- **Winner — FFG-style justify/finalize checkpoint overlay.** It reasons only about **epoch-boundary checkpoints**, never every block. This is the decisive PQ property: because ML-DSA has no aggregation, a quorum cert is hundreds of KB (§7), so **per-block BFT is PQ-infeasible** — the overlay amortizes one expensive PQ justification over a whole epoch of base blocks. Its deterministic core (weighted quorum arithmetic, checkpoint codec, anchor codec, reorg-safe reader) is entirely offline-testable; only the live round + real verify are stubbed behind a seam.
- **Runner-up — Tendermint / CometBFT instant single-slot finality.** Lower latency but couples liveness far harder and multiplies the O(N) PQ signature cost. **Grafted from it:** the crisp quorum-intersection accountable-safety proof (§3.2), which this design **generalizes from count to weight** (the `> 2/3` weighted form is the correct general statement).
- **Third — minimal committee-notary.** **Grafted from it:** the **on-base roster/weights commitment** (§4.6) that binds "who is the committee this epoch, and with what weight" to the ownerless base so it cannot be silently rewritten.

**The committee-selection shift (the locked decision).** The earlier drafts assumed the committee was a **curated set of disclosed independent operators** — which forced a phased "prove independence" honesty gate and a fragile count-based quorum. The locked design drops that entirely: **the committee IS the miners, weighted by hashrate**, where hashrate is proxied by **block-share in a trailing look-back window**. This has three honest virtues: (1) no separate trust set to bootstrap or attest — finality weight is the **same work that already secures the base**; (2) Sybil-resistance is free — you cannot fake block-share without actually doing the work; (3) the quorum becomes a clean **`> 2/3` of total weight**, whose intersection guarantee holds for **any** distribution (§3.2), fixing the count-based `N ≠ 3f+1` unsafety. Its cost is stated plainly and shipped in the spec: **finality is only as decentralized as the hashrate (§9 caveat).**

---

## 1. Overview + weighted committee model

**Architecture.** Each epoch, the **set of miners who produced blocks in a trailing look-back window** forms the finality committee, **each weighted by its block-share** in that window (a hashrate proxy). The committee does not produce base blocks *as a committee*, votes no coins, holds no consensus privilege beyond the hashrate it already has on the base. Each epoch it (a) reads the base's selected chain via public JSON-RPC, (b) forms an FFG `source → target` checkpoint link, (c) each seat signs the link's canonical payload with the **individual ML-DSA-65 key it registered against its coinbase address**, (d) once signatures covering **> 2/3 of the epoch's total weight** have signed the same link the target is *justified*, and a source with a justified direct-child link is *finalized*, and (e) the finalized checkpoint is anchored to the base as one zero-value `BFT0` transaction carrying a **commitment** to the weighted quorum and to the epoch's membership+weights (raw signatures travel out-of-band, §4/§7). The base does not know the committee exists. The one honest sentence: **this adds accountable, attributable finality weighted by the same hashrate that already secures the base, for anyone who opts into reading it, without giving anyone ownership of the base.**

### 1.1 How weight derives from block-share
- **Weight = block-share in a trailing look-back window.** For epoch `N`, snapshot the base blocks in a trailing window (the look-back precedes the epoch, so weights are fixed *before* the epoch that uses them). A miner's **weight is the count of blocks it produced in that window**, attributed by coinbase address. Block-share is a **hashrate proxy**: over a window, expected block-share ≈ hashrate-share.
- **PURE block-share, NO per-miner cap.** A miner with 40% of the window's blocks gets 40% of the weight. There is **no artificial cap** flattening large miners — a cap would misrepresent the real security distribution and invite splitting (register two coinbase addresses to dodge the cap). Honesty over cosmetics: the weights **are** the hashrate distribution, concentration included. The §9 caveat states what that means when hashrate is concentrated.
- **Weights are integers** (block counts), summed to a `total_weight` per epoch. The quorum threshold is derived from `total_weight` (§3), and both are **frozen at rotation** and committed on-base (§4.6) so every reader agrees on the exact denominator.

### 1.2 Committee membership, size, and the PQ size cap
- **Membership = miners eligible for epoch `N`** (§3 rotation): produced ≥ 1 block in the trailing window, `block-share ≥ min_share` (drops dust miners), and hold **a registered ML-DSA-65 key bound to the coinbase address**. Determined entirely from on-chain data — **deterministic and on-chain-re-derivable** (§3.1).
- **Committee size is bounded by the PQ signature cap, in the low hundreds** (a quorum carries hundreds of raw ~3.3 KB signatures, §7). `min_share` is the tuning knob that keeps the eligible set inside that cap while covering the overwhelming majority of hashrate — dust miners below `min_share` are excluded but collectively hold little weight, so their exclusion does not meaningfully move `total_weight`.
- Seats hold **individual ML-DSA-65 keys** (FIPS 204; pubkey 1952 B, sig 3309 B). **No shared key, no threshold key, no DKG** — that is the whole PQ-coherence commitment. Miners can never be forced into a DKG ceremony precisely because there is no DKG.
- **Key registration** binds an ML-DSA-65 pubkey to a coinbase address via an on-base registration record (a zero-value envelope, same idiom). Miners **pre-register** keys so a miner rising into eligibility already has a key on record — no gap when it enters the committee (§3.3). Duplicate-pubkey and duplicate-coinbase are rejected (anti-Sybil / one-key-one-seat).

**No "prove independence" phase.** The earlier draft needed a phased gate to argue the disclosed operators were distinct entities. That gate is **gone**: seats are miners, distinctness is coinbase-attributed, and Sybil-resistance is the base's own PoW. What replaces it is the **honest concentration caveat (§9)** — a hashrate-weighted committee is exactly as decentralized as the hashrate, no more. **We do not dress concentration up as decentralization.**

---

## 2. The FFG justify/finalize primitive (PQ-signed, weighted)

**The gadget reasons only about checkpoints at epoch boundaries, never per block** (per-block BFT is PQ-infeasible, §7).

- A **vote** is a seat's ML-DSA-65 signature over a `(source_checkpoint → target_checkpoint)` link, using the deterministic canonical signing payload (§4.2).
- A **supermajority link** `s → t` exists when votes whose **summed weight exceeds `2/3` of the epoch's `total_weight`** sign the *same* `s → t`.
- **Justification:** target `t` is *justified* when a supermajority (weighted) link exists from an already-justified source `s → t` (genesis justified by definition).
- **Finalization:** `s` is *finalized* when there is a supermajority link `s → t` **and** `t` is the direct child epoch of `s` (Casper `k=1` finalization).

`ConfidenceLevel` (re-semanticized under weighted BFT):
- `Observed` — seen, no quorum.
- `SoftJustified` — 1 justified epoch.
- `HardNotarized` — 2 consecutive justified epochs (Casper-style finalization).
- **`Finalized`** — `HardNotarized` graduates to genuine `Finalized` **only when the reorg gate holds** (base off `k=4`/51%-attackable). Until then the honest string stays: *"hashrate-weighted committee attestation with accountable safety, capped at base security"* — and the `finalized` RPC alias stays forbidden.

---

## 3. Rotation + replacement (safety-first)

### 3.1 Rotation criterion — deterministic re-derivation
- **Epoch = a fixed block interval, cadence ~120 blocks (~1 h).** The epoch boundary is purely a height rule (`height % EPOCH_BLOCKS == 0`), no committee vote needed to rotate.
- **Membership for epoch `N` is re-snapshotted from the trailing window** (a fixed number of blocks ending before epoch `N` begins). A miner is **eligible for epoch `N` iff both**: (a) it holds a **registered ML-DSA-65 key bound to its coinbase address** on the base, **and** (b) its **block-share in the trailing window ≥ `min_share`** (drops dust). Weight = its block count in the window.
- **Deterministic + on-chain-re-derivable.** Every input — the window's blocks, coinbase addresses, registered keys, `min_share`, `EPOCH_BLOCKS`, window length — is on the base. Any reader re-derives the identical committee and weights for any epoch from base data alone. No off-chain roster, no operator list. The on-base **committee/weights commitment (§4.6)** lets a reader confirm the committee that *actually signed* matches the one the rules *should* have produced.

### 3.2 Replacement criterion — fixed committee per epoch, halt-not-fork
The single most important safety rule, and the reason the design is weighted rather than count-based:

- **The committee and its `total_weight` are FIXED for the whole epoch. They are NEVER re-normalized mid-epoch.** Shrinking `total_weight` when a member leaves would lower the `2/3` denominator and **break quorum-intersection** — two quorums computed against different totals need not overlap. So the denominator is frozen at rotation and pinned on-base (§4.6).
- **A member that leaves just stops voting.** Its weight stays in `total_weight` (the denominator does not shrink); it simply no longer contributes to any quorum's numerator.
- **If departed/offline weight exceeds `1/3`, finality HALTS — it never forks.** With `> 1/3` of the frozen total unable to sign, no link can reach `> 2/3`, so **no checkpoint finalizes**. The base keeps producing blocks; only *finality* stalls. **Safety is never traded for liveness.**
- **Replacement = the next rotation.** A departed miner **auto-drops** at the next epoch boundary (it produces no blocks in the new trailing window, so it is not eligible); live miners' block-share rises to fill the window, so their weight rises naturally. No mid-epoch surgery.
- **Emergency early rotation.** If **no checkpoint finalizes for `R` blocks** (`R < EPOCH_BLOCKS`, ~40), an early rotation triggers: re-snapshot the trailing window at the current height, forming a fresh committee from whoever is currently mining. This restores liveness after a large miner exits mid-epoch, **without ever re-normalizing the halted epoch's frozen total** — the early rotation starts a *new* epoch with a *new* frozen total; it does not retroactively finalize anything under a shrunken denominator.
- **Pre-registered keys ⇒ no backfill gap.** Because miners pre-register ML-DSA keys (§1.2), any miner picked up by an emergency (or normal) rotation already has a key on record and can sign immediately.
- **Mid-epoch dynamic backfill / re-normalization is REJECTED.** No adding members, no re-weighting, no changing `total_weight` inside an epoch. The *only* membership/weight changes happen at a rotation boundary, against a fresh frozen snapshot.

### 3.3 Hand-off checkpoint (weak-subjectivity anchor, continuous finality)
At each epoch boundary the **OUTGOING committee signs a hand-off checkpoint that commits the INCOMING committee's membership+weights.** Concretely, the boundary checkpoint (the one whose `committee_epoch` increments) is signed by a `> 2/3` weighted quorum of the **outgoing** epoch's committee, and its `committee_commitment` field (§4.4) carries the **incoming** committee's membership+weights commitment. A reader verifies that checkpoint's signatures against the **committee_commitment it already holds** (the outgoing one), then **adopts the new `committee_commitment` from the field** for all subsequent checkpoints. This chains finality across rotations without a trust gap: the incoming committee's authority is vouched for by the outgoing committee's weighted quorum, all the way back to a trusted weak-subjectivity checkpoint (§6). Because the incoming committee+weights are *also* independently re-derivable from base data (§3.1), the hand-off commitment is a **convenience and cross-check**, not a new trust root.

---

## 4. Checkpoint format + the `BFT0` / CKPT anchor byte layout

### 4.1 Full checkpoint (the off-base object the committee assembles)
```
BftCheckpoint {
  height_range:         HeightRange { start, end }      // inclusive base heights covered
  base_anchor:          BaseAnchorRef {                  // OBSERVATION of the base, not authority
                          block_height, block_hash:[u8;32], accumulated_work:u128 }
  committee_epoch:      u64
  committee_commitment: [u8;32]        // SHAKE-256 over sorted (coinbase_addr ‖ ml_dsa_pubkey ‖ weight) — membership+weights
  total_weight:         u128           // FROZEN total weight of the signing committee (never re-normalized mid-epoch)
  source_ref:           CheckpointRef                    // the justified source (FFG s→t link source)
  confidence:           ConfidenceLevel
  weighted_votes:       Vec<SeatSignature>               // signers whose summed weight is > 2/3 of total_weight
}
SeatSignature { coinbase_addr:[u8;20], ml_dsa_pubkey:[..], weight:u64, signature: MlDsa65Signature (3309 B) }
```
This full object is large: a quorum carries hundreds of ~3.3 KB signatures (§7). It is **not** what rides on-base (§4.3); the on-base envelope carries *commitments*, sigs out-of-band.

### 4.2 What is signed
Each seat signs `canonical_signing_payload()` — the domain-separated, length-prefixed big-endian concat of all fields **except `weighted_votes`** (including `committee_commitment` and `total_weight`, so each seat attests the exact epoch membership+weights and the frozen denominator), under domain tag `POSTERN-FFG-BFT-CHECKPOINT-v1` (explicitly not an audited wire format). Signature material is carried as **opaque bytes**; the crate never re-implements crypto and verifies only through a `CheckpointVerifier` seam (§6, §8).

### 4.3 Why the base carries commitments, not raw signatures
A full ML-DSA-65 sig is 3309 B; a quorum is tens-to-hundreds of KB — far too large to ride a `script_pubkey`. So the fixed envelope carries a **`quorum_commitment`** (SHAKE-256 over the sorted signer set) and a **`committee_commitment`** (SHAKE-256 over the sorted membership+weights), plus the frozen **`total_weight`**. The raw signatures and the roster preimage travel out-of-band (committee gossip / a side DA store / the committee's published bundle); the on-base commitments bind them. A verifier reconstructs the quorum + roster from the out-of-band bundle, checks them against the on-base commitments, **sums the verified signers' weights, and confirms that sum is `> 2/3 · total_weight`**. This keeps the base footprint at a fixed 165 bytes regardless of committee size.

### 4.4 Wire format — fixed length, all multi-byte ints little-endian (mirrors `l2/bloch-l2-anchor/src/envelope.rs`)
```
offset size field
0      4    magic ASCII "BFT0"            (42 46 54 30)   // distinct from L2V0/TKV0/DATA0
4      1    version u8 = 0x01                             // 0x01 = weighted; 0x00 was the retired count-based layout
5      8    committee_epoch      u64 LE                   // which epoch/committee signed
13     8    finalized_height     u64 LE                   // base height this checkpoint finalizes
21     32   finalized_block_hash [u8;32]                  // block hash at finalized_height
53     32   prev_checkpoint_hash [u8;32]                  // SHAKE-256 of prev BFT0 canonical bytes; genesis = [0;32]
85     32   quorum_commitment    [u8;32]                  // SHAKE-256 over the sorted weighted-signer set (> 2/3 of total_weight)
117    32   committee_commitment [u8;32]                  // SHAKE-256 over sorted (coinbase_addr ‖ ml_dsa_pubkey ‖ weight);
                                                          //   on a hand-off checkpoint this names the INCOMING committee
149    16   total_weight         u128 LE                  // FROZEN epoch total weight of the signing committee
165 = total
```
`165 = 4+1+8+8+32+32+32+16`. The value is normative and pinned by golden-vector tests exactly as `bloch-tokens` pins TKV0. **Layout `version 0x00` (the count-based `2f+1`, 117-byte envelope) is retired** — a reader that sees `0x00` treats it as an unsupported version (reader no-op), never as a valid weighted checkpoint.

### 4.5 Codec + extraction (clone the `L2V0`/`TKV0` discipline verbatim, all rules load-bearing)
```rust
pub const ENVELOPE_MAGIC:[u8;4] = *b"BFT0";
pub const ENVELOPE_VERSION:u8   = 0x01;
pub const ENVELOPE_LEN:usize    = 165;

pub struct CheckpointEnvelope {
  committee_epoch:u64, finalized_height:u64,
  finalized_block_hash:[u8;32], prev_checkpoint_hash:[u8;32],
  quorum_commitment:[u8;32], committee_commitment:[u8;32], total_weight:u128,
}
impl CheckpointEnvelope {
  pub fn encode(&self) -> Vec<u8>;                     // magic|ver|epoch|height|32|32|32|32|16
  pub fn decode(&[u8]) -> Result<Self, EnvelopeError>; // strict, bounds-checked Cursor, never panics
}
pub enum EnvelopeError { BadMagic, BadVersion(u8), Truncated, TrailingBytes, NonZeroValue(u64) }
```
- **Mirror types, not imports.** `Tx`/`TxIn`/`TxOut` are hand-copied mirrors of `bloch_crypto::core::{Transaction,TxInput,TxOutput}` @ `dd8df35` so the reader crate stays zero-dep/offline; signature material is omitted (the node already validated the tx).
- **Zero-value rule (caveat E.1):** the carrying output's `value` MUST be `0`; `decode_anchor_output` rejects non-zero value with `NonZeroValue`.
- **Extract-first-wins, no fall-through:** `extract_anchor(tx) -> Option<(usize, CheckpointEnvelope)>` picks the **lowest-index** magic-bearing output; if malformed / non-zero-value / wrong-version ⇒ `None`. A later valid envelope is never promoted.
- **Strict decode never panics** (proven by an xorshift garbage-soup test): exact magic → exact version → fields → `is_exhausted()` (reject trailing).

### 4.6 Checkpoint-chain linkage + committee/weights commitment
```rust
pub fn link(prev:&CheckpointEnvelope, prev_canonical_hash:&[u8;32], next:&CheckpointEnvelope)
  -> Result<(), LinkError>
// holds iff:
//   next.prev_checkpoint_hash == prev_canonical_hash              // the chain spine
//   next.committee_epoch      >= prev.committee_epoch             // epoch monotonic
//   next.finalized_height      > prev.finalized_height            // finality strictly advances (checked_*, no wrap)
//   INTRA-EPOCH (next.committee_epoch == prev.committee_epoch):
//     next.committee_commitment == prev.committee_commitment      // committee frozen within an epoch
//     next.total_weight         == prev.total_weight              // denominator frozen (NEVER re-normalized)
//   HAND-OFF (next.committee_epoch  > prev.committee_epoch):
//     next.committee_commitment  may differ (it names the INCOMING committee, vouched by the outgoing quorum, §3.3)
```
`LinkError { PrevHashMismatch, EpochRegressed, HeightNotAdvancing, CommitteeChangedWithinEpoch, TotalWeightChangedWithinEpoch }`. The intra-epoch equality checks are the on-chain enforcement of the **no-mid-epoch-re-normalization** invariant (§3.2): a checkpoint that tries to shrink `total_weight` or swap the committee without incrementing the epoch is rejected by every honest reader.

**Committee/weights commitment.** `committee_commitment` = SHAKE-256 over the sorted `(coinbase_addr ‖ ml_dsa_pubkey ‖ weight)` set for the epoch, so the reader's notion of "who is the committee this epoch and with what weight" is bound to the ownerless base and cannot be silently rewritten. It is also independently **re-derivable** from base data (§3.1), and its per-boundary value delivers the hand-off (§3.3). `total_weight` on-base pins the frozen `2/3` denominator so quorum can be checked without trusting the out-of-band roster's sum.

### 4.7 Reader (reuse `stream.rs` / `manager.rs` / `source.rs` verbatim)
Same `BlockSource` trait (`getblockcount`/`getblockhash`/`getblockbyheight` — public, permissionless RPC), same `MockChain` for tests. A `CheckpointIndexer` runs `extract_anchor` per block, verifies `link` against the last accepted checkpoint, and **optionally** verifies the quorum: reconstruct the signer bundle + roster preimage from out-of-band data, recompute `quorum_commitment` and `committee_commitment`, verify each seat sig via `bloch_crypto::crypto::verify(pk, canonical_signing_bytes, sig)`, **sum verified signers' weights, and confirm `> 2/3 · total_weight`**. Inherits the journal + per-height snapshot + fork-point recovery: idempotent, fails closed on hostile `tip == u64::MAX`, post-reorg state exactly equals a fresh replay from genesis. `anchor.rs`'s client (`BlochAnchorClient` etc.) is reused as-is; `canonical_tip()` is an observation, never authority.

### 4.8 What makes this ownerless-safe
The checkpoint is an **ordinary zero-value output** whoever pays the BLCH fee can broadcast. Bloch nodes never parse `BFT0`: no consensus rule, no operator, no permission, no reserved namespace. A malformed / unsigned / wrong-version envelope is a **reader-layer no-op** that never invalidates the carrying base transaction. All finality meaning lives in the opt-in off-consensus reader; the base stays exactly what it was. **Coins do not vote; hashrate does — and hashrate is already the base's security, so the overlay introduces no new ownership.**

---

## 5. The exact `> 2/3` WEIGHTED quorum rule + accountable safety

### 5.1 The weighted counting rule
`verify_finalized(checkpoint, votes, committee, verifier)` counts **distinct-coinbase** signatures that verify against committee members, **dedups repeated seats** (one seat, one counted vote — first valid occurrence wins), **sums the verified signers' weights**, and compares to the weighted threshold. Outcome `FinalityOutcome::{Finalized | NotFinalized}{covered_weight, total_weight}`.

**The quorum predicate is strict `> 2/3`, computed in integer/`u128` to avoid overflow and rounding drift:**
```
is_quorum(covered_weight, total_weight)  ⇔  covered_weight * 3 > total_weight * 2
```
No `≥`, no floats. This is the exact "covers more than two-thirds of the total weight" test. `total_weight` is the **frozen** epoch total from the committee snapshot (§3.2), never a live re-sum of present signers.

Verification is **O(N) independent ML-DSA verifies** — each fast per-op, size-dominated not compute-dominated, with **no single-pairing shortcut** because there is no aggregation. This is the accepted PQ cost (§7).

### 5.2 Weighted quorum-intersection accountable-safety argument
**Claim:** two conflicting checkpoints cannot both reach a `> 2/3`-weight quorum unless seats holding **> 1/3 of the total weight** provably signed both — and that overlap contains **≥ 1 attributable seat** whose two conflicting signatures are self-authenticating equivocation evidence. **This holds for ANY weight distribution — there is no `N = 3f+1` constraint.**

**Weighted quorum-intersection proof.** Let `W` be the frozen `total_weight`. Two finalized checkpoints each carry a signer set of weight `> 2W/3`. Let `A`, `B` be the two signer sets, `w(A), w(B) > 2W/3`. Then
```
w(A ∩ B) = w(A) + w(B) − w(A ∪ B) > 2W/3 + 2W/3 − W = W/3.
```
So the **overlap has weight `> W/3`** — strictly positive for any distribution of the per-seat weights, because it is an inequality on the *total* weights of the sets, not on their cardinalities. A non-empty overlap of positive weight contains **at least one seat** that signed **both** conflicting checkpoints at overlapping height — a detectable **equivocation**. Because each vote is an **individual ML-DSA signature** (no threshold key to hide inside), that offender is **cryptographically named**: anyone can exhibit its two conflicting signed payloads and verify them offline with `bloch_crypto::crypto::verify`.

**Why this fixes the count-based bug.** The retired count design proved intersection via `2(2f+1) − (3f+1) = f+1`, which is only valid at `N = 3f+1`; for `N > 3f+1` two `2f+1` sets can miss each other in the honest region. The weighted `> 2/3` form has **no such precondition** — `w(A) + w(B) − w(A∪B) > W/3` is an identity plus the two threshold inequalities, true for every weight vector. **Generality is the whole point of going weighted.**

**The two equivocation faults (Casper commandments), each an ML-DSA double-signature:**
1. *No double vote*: no seat signs two distinct targets at the same epoch height.
2. *No surround vote*: no seat signs links `s₁→t₁` and `s₂→t₂` with `h(s₁) < h(s₂) < h(t₂) < h(t₁)`.

The general accountable-safety margin for threshold `p` is `2p − 1` of the weight, maximized in usefulness at `p = 2/3` → the **`1/3`-weight** attributable bound. **Attribution requires per-signer signatures** — BLS aggregation would have to be un-aggregated to attribute blame; individual ML-DSA sigs are attribution-native. The "no aggregation, no DKG" choice forced by PQ-coherence is exactly what accountable safety wants.

**What this buys concretely:** a block finalized under a checkpoint **cannot be reorged past that checkpoint** without seats holding `> 1/3` of the epoch weight producing signed evidence of their own fault — capped at `min(base security, committee security)`.

### 5.3 Equivocation evidence + detector (offline-checkable)
```
EquivocationEvidence {
  coinbase_addr: [u8;20],
  height:        HeightRange,      // same/overlapping target height
  sig_a: MlDsa65Signature, payload_a: Vec<u8>,   // signs checkpoint C
  sig_b: MlDsa65Signature, payload_b: Vec<u8>,   // signs conflicting C'
}
```
Verifiable by **any third party** offline: both sigs verify under the seat's registered pubkey, both payloads bind the same/overlapping height, `C ≠ C'`. A `detect_equivocation()` routine scans accepted checkpoints and emits this. **v1 has NO slashing** — detection + attribution + exclusion-at-next-rotation + published reputation only (economic slashing needs bonding, deferred). The evidence is the deterrent and the audit trail.

---

## 6. Liveness + weak-subjectivity / bootstrap

**Liveness (honest, not guaranteed).**
- Finality **lags by an epoch** by construction (FFG): a checkpoint finalizes only after the next epoch's supermajority link. This is the deliberate FFG-overlay trade: **the overlay decouples finality from block production** — the base keeps producing blocks even when finality stalls.
- Finality needs signers covering **`> 2/3` of the frozen epoch weight** each epoch. With **`> 1/3` of the weight offline/departed, finality HALTS** — the base keeps advancing, only finality halts (§3.2). Safety is never traded for liveness. Emergency early rotation (§3.2) restores liveness with a fresh frozen snapshot after `R` blocks without a finalization.
- The live vote round is O(N²) gossip of 3.3 KB sigs — another reason the committee stays in the low hundreds (§7).

| Live weight (of frozen total) | Finality | Base block production |
|---|---|---|
| `> 2/3` | advances (justify → finalize) | advances |
| `1/3 .. 2/3` | **halts** (no supermajority link); early rotation after `R` blocks | advances |
| adversary `≥ 1/3` but honest `> 2/3` present | safe — no false finalization | advances |

**Weak subjectivity & bootstrap (reuses the existing snapshot model).** Like every finality-by-signature system, a departed seat holding old keys could sign an alternate history (long-range). So a newly-syncing or long-offline node must **bootstrap from a recent trusted weak-subjectivity checkpoint**, not from genesis alone. This maps *exactly* onto the existing signed **k=8 snapshot in R2 + fresh-node onboarding runbook**: the WS checkpoint is the latest `Finalized`/`HardNotarized` `BFT0` checkpoint + its `committee_commitment`, distributed the same way the k=8 snapshot already is. A bootstrapping node trusts that checkpoint's committee, then follows the **hand-off chain (§3.3)** forward — each boundary checkpoint's outgoing quorum vouches the next committee — cross-checking every epoch's committee against the independent on-chain re-derivation (§3.1). No change to the base's permissionless sync; honest nodes can always fall back to pure base PoW (capped at base security).

---

## 7. PQ signature cost — the binding constraint, stated plainly

ML-DSA has **no native aggregation** (the price of dropping BLS). Classical gadgets use BLS12-381 to collapse N signatures into one ~96-byte aggregate — and **Shor breaks the discrete-log under BLS**, so the aggregate is quantum-forgeable. Going PQ-coherent puts the O(N) checkpoint cost *back*.

| Scheme | Pub key | Signature |
|---|---|---|
| BLS12-381 (classical, aggregated) | 48 B | 96 B (one aggregate for all N) |
| ML-DSA-65 (FIPS 204, L3, this design) | 1,952 B | **3,309 B, one per seat** |

| Committee `N` (signers to reach `> 2/3` weight) | raw cert @ 3309 B/sig |
|---|---|
| ~30 | ~70 KB |
| ~100 | ~222 KB |
| ~180 | ~400 KB |
| 1,000,000 (Eth-scale) | ~2.2 GB — infeasible |

**Consequences, all honest:** (1) the committee is hard-capped at the **low hundreds** — `min_share` (§3.1) is tuned to keep the eligible miner set inside that cap while covering the great majority of hashrate; (2) **per-block BFT is forbidden** — hence the FFG *checkpoint* overlay amortizing one cert over an epoch; (3) the on-base envelope carries fixed commitments (§4.3), sigs out-of-band, so the base footprint is a fixed 165 bytes; (4) verification is O(N) independent verifies, no pairing shortcut. **Escape hatch, explicitly out of v1 scope:** pqSTARK recursive aggregation → constant-size checkpoints, but it adds heavy prover cost + latency and rests PQ security on the hash function, not lattices — and it is **hash-based recursion, never pairings**; BLS remains banned.

---

## 8. Threat model — a `> 2/3`-hashrate entity vs a dishonest quorum

State honestly. The committee is the miners weighted by block-share; a dishonest quorum is seats covering `> 2/3` of the frozen epoch weight; a `> 2/3`-hashrate entity is a miner (or cartel) that will *become* `> 2/3` of the committee weight at the next snapshot.

### 8.1 A dishonest quorum (`> 2/3` of the epoch weight, colluding) — CANNOT
- **Cannot touch the base.** No seat, and no quorum, can produce, censor, or reorg a base block, mint BLCH, or change any base consensus rule *by virtue of being on the committee*. Base ordering/production is the SIS-PoW chain's. The gadget only *observes* the base and writes zero-value data. **Coins do not vote; the base gains no operator.**
- **Cannot equivocate silently.** Any conflicting finalization requires seats holding `> 1/3` of the weight to sign contradictory checkpoints, and those ML-DSA signatures are **self-authenticating evidence** any third party verifies offline (§5.2/§5.3). Safety violations are always attributable.
- **Cannot forge a quorum from less weight.** Sigs are individual ML-DSA (no threshold key, no DKG); reaching `> 2/3` weight requires the real private keys of miners holding that block-share. There is no shared secret to steal, no DKG transcript to subvert.
- **Cannot re-normalize the denominator mid-epoch to cheat the threshold.** `total_weight` is frozen and pinned on-base; a checkpoint that shrinks it without a rotation is rejected by `link` (§4.6).

### 8.2 A dishonest quorum — CAN
- **Finalize a false checkpoint, capped at `min(base security, committee security)`.** A `finalized_block_hash` contradicting the base's own selected chain is *wrong* and rejected by any node that independently reads the base; if a seat also signed the true chain, that is attributable equivocation. A coordinated `> 2/3`-weight cartel that lies in lockstep and never signs the truth produces a checkpoint attributable-as-a-set. **This is exactly the §9 caveat:** because the committee is hashrate-weighted, a `> 2/3`-weight cartel *is* a `> 2/3`-hashrate cartel — the honesty of finality reduces to the decentralization of hashrate.
- **Stall finality** (adversary `≥ 1/3` weight): a liveness attack, never a safety violation; triggers emergency rotation (§3.2).
- **Withhold checkpoints:** cannot forge past ones; the base keeps advancing without the gadget.
- **In v1 the consequence of a caught fault is exposure + exclusion-at-next-rotation, not slashing** (§5.3).

### 8.3 A `> 2/3`-hashrate entity — CAN and CANNOT
- **CAN break it.** A single entity with `> 2/3` of the hashrate becomes `> 2/3` of the committee weight at the next snapshot and can then finalize whatever it likes — and, being the majority miner, can also make the base chain it finalizes the base's own selected chain, so its false finality is not even contradicted by an honest base. **A `> 2/3`-hashrate entity defeats this gadget.** This design does not claim otherwise.
- **CANNOT do it cheaply or silently below `> 2/3`.** Below `2/3` weight the entity cannot finalize alone; at `1/3..2/3` it can only *halt* finality (liveness), not forge it. And it cannot forge the ML-DSA signatures of miners it does not control.
- **What the gadget actually buys vs a 51% miner.** On today's `k=4`/51%-attackable base a **51%** miner can reorg to arbitrary depth. With this overlay, rewriting a **finalized** prefix requires **`> 2/3` of the committee weight** (i.e. `> 2/3` hashrate, not 51%) *and* leaves attributable equivocation evidence. So the overlay **raises the bar from 51% to 67%** for rewriting finalized history and adds **no-deep-reorg finality below the last checkpoint** — a real mitigation, capped at `min(base, committee)`, **worth nothing if one entity already holds `> 2/3` hashrate** (§9).

---

## 9. Honest concentration caveat (ships verbatim on every finality claim)

> **Hashrate-weighted finality is only as decentralized as the hashrate; today concentrated ⇒ effectively Postern-controlled until miners decentralize; a `> 2/3`-hashrate entity still breaks it. It MITIGATES 51% (raises the safety bar 51% → 67% + no-deep-reorg finality below), does not eliminate it.**

This is not a disclaimer to bury — it is the defining honest fact of the design and must ride **every** surface that reports finality, exactly as the scaffold's other rails do. Because the committee *is* the miners weighted by block-share, the security of finality **equals** the decentralization of hashrate: with concentrated hashrate (as today), a `> 2/3`-weight quorum is a `> 2/3`-hashrate entity, and if that is Postern-adjacent mining then "BFT finality" is, honestly, Postern-attested finality wearing a weighted hat. **We say so.** The mitigation is real and worth shipping — 51%→67% plus attributable, no-deep-reorg finality below each checkpoint — but it is a **mitigation, not an elimination**, and it becomes genuine decentralized finality **only as the hashrate itself decentralizes**, which this overlay cannot manufacture. No decentralization theater.

---

## 10. Offline-testable core vs stubbed live round (SCAFFOLD honesty)

Mirrors the honesty of `l2/bloch-l2-anchor` + `ffg/` + the current `bft/postern-bft-finality`. The crate — **`bft/postern-bft-finality`**, detached `[workspace]`, zero/low default deps — cleanly separates the *real* deterministic core from *honest stubs* for anything needing crypto or a network.

**REAL, offline-testable (`cargo test`, default features):**
- **Weighted quorum arithmetic** (`committee.rs`): per-seat weights, frozen `total_weight`, `is_quorum(covered, total) ⇔ covered*3 > total*2` (u128), membership/dup-coinbase/dup-pubkey invariants.
- **Weighted finality counting** (`quorum.rs`): distinct-seat dedup + membership + verifier-seam check + **weight summation** + `> 2/3` compare.
- **Rotation/eligibility** (`rotation.rs`, new): trailing-window block-share → weights, `min_share` + registered-key eligibility filter, deterministic re-derivation; emergency-early-rotation trigger predicate (`R` blocks without finalization).
- **Checkpoint codec** (`checkpoint.rs`): `canonical_signing_payload()` determinism (now including `committee_commitment` + `total_weight`), struct (de)serialization.
- **Anchor codec** (`anchor.rs`): `BFT0` v`0x01` `encode`/`decode` (strict, bounds-checked, never-panics, garbage-soup), `extract_anchor` first-wins/zero-value/version rules, `link` chaining with `checked_*` **and the intra-epoch frozen-committee/frozen-total checks**.
- **Reader**: `CheckpointIndexer` over `MockChain` — journal + snapshot + fork-point reorg recovery, converges-to-fresh-replay, fails-closed on `tip == u64::MAX`.
- **Equivocation-evidence verification** (`detect_equivocation`, third-party-checkable).

**HONEST STUBS behind a seam (designed, not booted):**
- **ML-DSA verify** — the crate carries signatures as **opaque bytes** and verifies only through the `CheckpointVerifier` trait; it **never re-implements crypto.** Default `RejectingStubVerifier` accepts nothing, so **default offline builds never reach a real quorum** (`MockVerifier` scripts validity for tests only). Real path: `bloch_crypto::crypto::verify(pk, msg, sig) -> bool` behind an off-by-default feature.
- **Live committee round** (propose → weighted-sign → gather `> 2/3` weight → assemble → anchor): the networking, weight-gossip, and round-timing are an **honest stub behind a seam**; the crate consumes an already-assembled weighted signer set and marks the live logic designed-not-built. No socket, no timer, no P2P.

**Every doc rail stays honest.** `SCAFFOLD_DISCLAIMER` + `TRUST_SURFACE_DISCLAIMER` + the **§9 concentration caveat** ride every surface. Until the reorg gate clears, this is an interface and a codec, not a settlement claim.

---

## 11. Phased build plan

**Phase 0 — offline scaffold (buildable now, zero-value, no security claim).**
- Rework `committee.rs` from count-based `2f+1` to **weighted** (`Validator{coinbase_addr, ml_dsa_pubkey, weight}`, frozen `total_weight`, `is_quorum` weighted predicate); delete `fault_tolerance()`/`quorum_threshold()`.
- Rework `quorum.rs` `verify_finalized` to **sum weights** and compare `> 2/3`; `FinalityOutcome{covered_weight,total_weight}`.
- New `rotation.rs`: trailing-window block-share → weights, `min_share`/registered-key eligibility, deterministic re-derivation, emergency-rotation predicate.
- Extend `checkpoint.rs` + `anchor.rs` to **`BFT0` v0x01** (add `committee_commitment` + `total_weight`, 165 bytes, domain `-v1`); `link` intra-epoch frozen-committee/frozen-total checks; golden vectors + garbage-soup.
- `EquivocationEvidence` + `detect_equivocation`.
- Verifier seam with `RejectingStubVerifier` default; real verify behind an off-by-default feature.
- Update `SCAFFOLD_DISCLAIMER`/`TRUST_SURFACE_DISCLAIMER` + add the §9 caveat string. **Deliverable: compiling, offline, deterministic weighted core + honest stubs. Nothing booted.**

**Phase 1 — live committee round (testnet).**
- Implement the round transport: propose / weighted-sign / gather-`>2/3`-weight / assemble / anchor, leader rotation, timeouts, O(N²) gossip + out-of-band cert distribution; key-registration envelope + pre-registration flow.
- Wire real `bloch_crypto::crypto::verify`; boot a testnet committee derived from real block-share. **§9 caveat rides everything: concentrated testnet hashrate = concentrated finality.**

**Phase 2 — settlement gates (external, not this crate).**
- Base off `k=4`/51%-attackable → graduate `HardNotarized`→`Finalized`, drop the honest-caveat strings *for the base-security cap* (the §9 hashrate-concentration caveat stays until hashrate actually decentralizes), allow the `finalized` RPC alias.
- Bonding + a live external slasher (now non-self-referential) → real economic security.
- Third-party audit of base + committee + anchor reader.

**Explicitly deferred (honest gaps):** bonding + slasher; base hardening (external); pqSTARK recursive aggregation (the only sanctioned constant-size-cert path — hash-based, never pairings); genuine hashrate decentralization (a mining-ecosystem outcome this overlay cannot force).

---

*Everything here is a plan. The weighted quorum rule, checkpoint codec, anchor codec, rotation/eligibility derivation, and reorg-safe reader are real and offline; the live round and real verify are honest stubs behind a seam. Nothing is decentralized, hardened, audited, or holding value — and it will say so on every screen until the reorg gate clears and the hashrate itself decentralizes. The base stays ownerless throughout: coins do not vote, hashrate does, and hashrate is the base's own security.*
