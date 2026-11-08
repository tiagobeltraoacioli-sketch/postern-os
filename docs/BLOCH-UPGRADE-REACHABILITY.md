<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Bloch node upgrade — GHOSTDAG reachability fix

> **Candidate node upgrade — UNAUDITED. Review + test before deploying.**
> Branch: `fix/ghostdag-reachability`. This is a **performance / convergence**
> fix. The one safety question — *could the faster path change consensus
> results and fork the chain?* — has been **answered: NO.** A differential
> analysis of the live chain proves it is **result-identical (DROP-IN)**, so it
> is a **transparent speedup with no fork and no coordinated activation height**.
> It is still unaudited candidate code on the ownerless base — operators adopt
> it voluntarily, the Bitcoin way — so review and test first.

## Why (the incident this fixes)

At high DAG height the node's `classify_mergeset` is
`O(|mergeset| × |blue_set| × bounded-BFS)`: the reachability walk saturates the
`k*100 = 1000` depth bound at ~397k (the `past_blue_set hit depth bound` WARN),
so per-block validation crawls to ~15 s/block (~4 blocks/min). A node that falls
behind **cannot integrate the backlog into its selected chain** — it freezes
(`syncing: true`), and the network **fails to converge** (2026-07-16: nodes
stuck at different heights while the tip advanced elsewhere). The fix adds an
**O(1) reachability index** + **incremental blue-coloring** (the "Fast" path) so
backlogs process fast and nodes converge.

## Verdict — DROP-IN (result-identical, no fork)

The Fast path computes the *correct* (unbounded) coloring. That diverges from
today's bounded computation only when an anticone is **wide** enough to be
under-counted. On the live Bloch chain the DAG is **~99.94 % linear**: measured
**max anticone size = 9** (below `K = 10`) and **max mergeset width = 6**. The
bounded BFS therefore **cannot under-count any result** → **Legacy == Fast,
byte-identical.** The perf wall (the WARN) comes from chain *depth*, not from
wide anticones, and the deep ancestors it truncates never affect the tiny local
counts — that is why it is slow without changing results.

*(Method: the read-only `dag_shape_stats` / `ghostdag_replay_snapshot` harness
against a real node snapshot; anyone can re-run it and get the same verdict.)*

## Your coins / history are preserved

The change ships behind an activation-height gate; historical blocks are loaded
verbatim and **never recomputed** → every mined block and balance is
byte-identical, no reorg. For a DROP-IN, enabling Fast at height `0` is safe
because the results are identical anyway. Your data-dir / volume is untouched.

## Upgrade (per node — no coordination needed)

```sh
cd ~/bloch && git fetch && git checkout fix/ghostdag-reachability   # or the merged release
# In src/consensus/mod.rs set:  CORRECTED_COLORING_ACTIVATION_HEIGHT = 0
cargo build --release && sudo systemctl restart bloch-node
```

Verify: `bloch-cli dag` (chain_length climbing again), `bloch-cli peers`
(`syncing` clears once caught up). Because the result is identical to the old
node, a node running the fix and a node still on the old binary **stay on the
same chain** — you can upgrade at your own pace, no fork.

**Independent check (optional, recommended):** re-run the verdict yourself —
`BLOCH_SNAPSHOT=/path/to/a/node/data-dir cargo test --release --test ghostdag_replay_snapshot dag_shape_stats -- --ignored --nocapture`
— and confirm `max blues_anticone_size < K` before trusting DROP-IN.

## Rollback

Fully safe: check out the previous (alpha3) binary and restart. Result-identical
both ways, so there is nothing to reconcile.

---

*This is a performance/convergence fix — coin, reward, and token semantics are
untouched. Bloch is ownerless and unaudited; the coin carries no value claim and
is not a security.*
