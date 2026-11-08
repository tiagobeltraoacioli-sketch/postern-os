<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# FFG-BFT — activation plan (target: block 1,000,000)

**Decision (founder, 2026-07-17):** FFG-BFT finality is adopted on the Bloch base
at **block `1_000_000`** — recorded as `FFG_ACTIVATION_HEIGHT` in
`bft/postern-bft-finality/src/lib.rs`. At ~404k and 30 s blocks that is
**~595,758 blocks ≈ 207 days ≈ 6.8 months** of runway.

> **It is a DECLARED TARGET, not a live gate.** The crate is still a scaffold;
> nothing runs at that height today. FFG is a **Bloch protocol item, not a
> Postern product.**

## Current state
`bft/postern-bft-finality` — a compiling, tested **scaffold** (weighted committee,
`> 2/3` weighted quorum, ML-DSA-65 checkpoint votes, BFT0 anchor envelope; 54
tests). **No BLS / DKG / aggregation, ever** (PQ-coherent by construction).
**Not integrated into the node. Not active.**

## Phased path to activation (in order — each gates the next)
1. **Base stable** *(prerequisite, in progress)* — sync/convergence resolved and
   the network holding one chain. FFG work does **not** start concurrently with
   node stabilization.
2. **Integrate into the node** — the real build: committee = miners weighted by
   hashrate over a trailing block-share window; per-seat ML-DSA-65 vote
   collection into a quorum certificate; BFT0 checkpoint anchoring to the
   ownerless base; wire the finality overlay into consensus + RPC; gate all of it
   on `FFG_ACTIVATION_HEIGHT`.
3. **Test** — unit + integration + a testnet dry-run of a full epoch (committee
   freeze → votes → quorum cert → finalized checkpoint → next epoch).
4. **Audit** — third-party review. It is a **finality/settlement overlay**;
   safety-critical. No activation without it.
5. **Coordinated deploy** — ship the integrated binary to a **super-majority of
   hashrate ahead of block 1,000,000**, so activation is **fork-safe** (same
   discipline as the reachability upgrade). Un-upgraded miners must be a minority
   by the activation height.
6. **Activate at block 1,000,000** — the overlay begins finalizing epochs.
7. **Announce on the site** — **only once steps 2–5 are done and verified OK.**
   Never announce before it is coded, tested, and confirmed working.

## Invariants (locked)
- PQ end-to-end: **ML-DSA-65 (FIPS 204) only**, individual signatures, no
  aggregation, no BLS, no DKG.
- Finality is **strict `> 2/3` of the epoch's frozen `total_weight`** (weighted,
  never count-based `2f+1`).
- Committee = **miners weighted by hashrate** (pure trailing block-share, no
  per-miner cap); anchored to the **ownerless base** via the BFT0 envelope.
- Checkpoint (epoch) overlay, not per-block — one expensive cert amortized over
  an epoch.

See `docs/specs/POSTERN-FFG-BFT-FINALITY.md` for the full design.
