# Dual-AND proof-of-work — design

A block is valid only if it carries **both** a SHA-256d proof and a Module-SIS
proof, each meeting its own target. Not "either algorithm" (OR) — "both,
simultaneously" (AND).

Status: **design only.** Not implemented, not scheduled. This document exists so
the decision is mature when the network is ready for it, without touching consensus
code today. **Do not implement before the network syncs** — see §7.

## Why AND, not OR

The obvious multi-algorithm design accepts a block sealed by *either* algorithm.
That **weakens** security: an attacker rewrites history by out-hashing whichever
algorithm is cheaper, so reorg cost is `min(cost_sha, cost_sis)`. Myriad, Digibyte
and every small multi-algo chain lives with this — a rented SHA-256 flood reorgs
them for the price of a few hours.

AND requires both proofs on every block. Reorg cost becomes `max(cost_sha,
cost_sis)`: an attacker must out-hash SHA-256 **and** solve Module-SIS for the same
depth, in the same blocks. Neither market alone suffices.

| Composition | A block needs | Reorg cost | Effect |
|---|---|---|---|
| OR (multi-algo) | either proof | min(A, B) | **weakens** |
| **AND (this)** | **both proofs** | **max(A, B)** | **strengthens** |
| Merged / AuxPoW | parent-chain proof | inherited | derived, not summed |

The Module-SIS half also keeps the post-quantum mining thesis alive: even with
SHA-256 hashrate rentable and abundant, an attacker still has to solve the lattice
problem, for which no ASIC and no rental market exist.

## Block structure

Each block header gains a second PoW witness. The two proofs commit to the *same*
block, so a proof cannot be lifted from one block onto another.

```
BlockHeader {
    ...existing consensus fields...
    sha256d_nonce:   u64,          // the SHA-256d search nonce
    sis_nonce:       u64,          // the Module-SIS search nonce
    sis_solution:    [i32; 256],   // the Module-SIS witness (as today)
}
```

Validation (both must pass, order fixed for determinism):

1. `pow_hash_sha256d(header_without_sis) <= target_sha`
2. `verify_sis_pow(pow_preimage(header), sis_nonce, sis_solution, bits, height)`

**Binding.** The SIS preimage must include the SHA-256d nonce (and vice-versa the
SHA-256d preimage commits to the SIS solution's hash), so the two proofs are welded
to one block. Without this, a "SHA miner" and a "SIS miner" could each mine
independently and staple unrelated proofs together — which is the coordination
attack, not honest dual mining.

## Difficulty — two independent retargets

Each algorithm retargets on its own observed solve rate, because their hardware and
supply are unrelated. `bits_sha` and `bits_sis` are separate fields, each running
the existing ASERT retarget over the trailing window of *its own* proof times.

The block interval is governed by whichever proof lands last — so the effective
target time is set by the SLOWER of the two per block. Calibrate both so their
expected solve times are comparable; if one is chronically faster, it contributes
no marginal security (the slow one gates every block) and just wastes energy.

## The coordination problem — the real cost of AND

A block needs both proofs. Three ways a miner obtains them:

1. **Solo dual.** One operator runs both a SHA-256 rig and a lattice miner, binds
   the proofs, submits. Simplest; needs both kinds of hardware.
2. **Pairing pool.** SHA miners and SIS miners register to a pool that pairs them
   per candidate block and splits the reward by contributed work. This is the path
   that lets specialised hardware participate — and it is real protocol work
   (matching, escrow, reward split), not a small addition.
3. **Sequential template.** The pool builds a block template, has the SIS miner
   solve first (slow, coarse-grained), then hands the near-final template to SHA
   miners for the fast search. Bounds who can grief whom.

**This coordination is the price of AND, and it must be designed, not bolted on.**
A naive pairing scheme reintroduces exactly the OR weakness: if the pairing lets an
attacker supply their own cheap proof for half the pair, `max` collapses back to
`min`. The binding in the block structure is what prevents that at the protocol
level; the pool design must not undo it off-chain.

## Reward split

Coinbase splits between the SHA contributor and the SIS contributor. Two honest
defaults, to be chosen deliberately:

- **By marginal security:** weight the split toward the algorithm that is *harder
  to rent*, since that is what actually raises reorg cost. Today that is Module-SIS.
- **By expected cost:** weight toward whichever proof costs more energy to produce,
  so neither side is underpaid and drifts away.

Getting this wrong drives one side out and collapses the chain to a single
algorithm — which is the OR failure by attrition.

## Migration path

Dual-AND is not a from-scratch launch; it is an **activation** on an existing
chain, gated exactly like the reachability soft-fork:

- Ship the code with a `DUAL_AND_ACTIVATION_HEIGHT` constant at `u64::MAX` (off).
- Below the height: single-algorithm rules, unchanged. At/above: both proofs
  required.
- Every miner must be dual-capable (or paired) BEFORE the height, or they stop
  producing valid blocks at activation. Announce with the same runway discipline
  the reachability upgrade uses.

A block mined under single-PoW rules stays valid forever (historical blocks are not
re-validated); only new blocks at/above the height need both proofs. That makes it a
clean soft-fork on the mining side.

## §7 — Do not implement before the network syncs

As of this writing the network cannot bootstrap a new node past ~408,000: the
reachability index rebuild is being fixed and no activation height has been
published. Dual-AND is a consensus change to block validity and the wire format —
the exact layer where this project spent a long night finding bugs (suppressed
request nonces, divergent DAG colouring).

Stacking a second consensus change onto consensus that does not yet converge would
make both impossible to debug. The order is not negotiable:

1. Reachability rebuild fixed and its activation height published — network syncs.
2. Genesis-2 (or the live chain) stable, one algorithm, verified.
3. **Then** Dual-AND as a security upgrade, on a chain that already works.

Dual-AND raises the ceiling. It does nothing for a chain that cannot get off the
floor.

---

*Design only. Unaudited, pre-1.0. BLCH is worthless by design and is not a security.*
