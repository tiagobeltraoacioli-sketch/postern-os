# FFG committee rotation — analysis window, eligibility, replacement, activation

Design for how the finality committee is derived, how seats change hands, and the
condition under which finality becomes real rather than nominal.

Status: **design**. `bft/postern-bft-finality` implements the quorum arithmetic and
the `RotationMeta` shape; the derivation of the member set from base blocks is an
explicit out-of-scope seam in that crate, and this document specifies it.

## Principle

The committee is not appointed. **It is the miners, weighted by the work they did**,
measured as block-share over a trailing window. Nobody grants a seat and nobody can
revoke one — you hold weight because you mined, and you lose it because you stopped.

This is what makes the schedule honest: finality becomes decentralised exactly when
hashrate does, and not one epoch sooner.

## Parameters

Measured cadence of the live chain: ~240 blocks/hour (~5,760/day).

| Parameter | Value | Blocks | Why |
|---|---|---|---|
| **Epoch** | 1 day | 5,760 | How often weights are recomputed. Short enough that a new miner is seated within a day. |
| **Look-back window** | 7 days | 40,320 | The window whose block-share defines weight. |
| **Eligibility floor** | 1% of window | 403 | Below this, no seat. Prevents dust seats and Sybil spam from diluting the arithmetic. |
| **Quorum** | > 2/3 of epoch weight | — | Already implemented in `quorum.rs`. |

### Why the window is 7× the epoch

The window must be long enough that **capturing a seat requires sustained work, not a
burst**. If window == epoch, an attacker rents hashrate for one day, takes weight, and
votes. At 7 days, the same attack costs seven days of rental to reach the same share,
and the weight decays over seven more days after they stop.

The cost is responsiveness: an honest miner who joins today reaches full weight in a
week. That is the right trade — this committee protects finality, and finality should
not be reachable by anyone who showed up this morning.

### Weights are frozen before the epoch that uses them

The window **precedes** the epoch it serves (`RotationMeta.window_blocks`, already in
the crate). A validator therefore cannot mine during an epoch to increase its own
voting weight in that same epoch. Weight for epoch *N* is fixed by blocks in the
window ending at the start of *N*.

## Eligibility and key registration

A seat requires two things:

1. **Block-share ≥ 1%** of the window, attributed by coinbase address.
2. **A registered ML-DSA-65 public key bound to that coinbase**, published on-chain
   before the epoch begins.

The binding matters: the key is registered *against* the coinbase address, so a seat's
votes can only be cast by whoever controls the address that earned the weight. Mining
under an address you do not hold the key for gets you weight and no vote.

Registration is permissionless. Nobody approves a validator.

## Replacement

There is no replacement procedure, because there are no appointments. Each epoch, the
set is recomputed from the window:

- **Joins** happen when a miner's share crosses 1% — automatically, that epoch.
- **Departures** happen when it falls below — automatically, as the window rolls past
  their last block. A miner who stops is fully out after 7 days.
- **Weight changes** every epoch, continuously, with no threshold or ceremony.

A validator that goes silent is not punished, ejected, or voted out. It simply stops
having weight, and the quorum arithmetic stops counting it. Liveness of the committee
is therefore a property of the mining set, not of an administrative process.

## Activation gate — when finality becomes real

Finality **must not activate at a block height**. A height is a date, and a date says
nothing about whether the committee means anything.

> **Activation condition:** for **14 consecutive epochs** (2 weeks), no single coinbase
> address holds **≥ 1/3** of total epoch weight.

The 1/3 line is not arbitrary. Above 1/3, a single party can **block** finality by
withholding votes. Above 2/3, it can **finalise alone**. A committee where one address
sits above 1/3 does not provide finality — it provides that address's permission.

This condition is computable by anyone from chain data: sum the coinbases in the
window, divide. No trusted announcement, no insider knowledge.

### What it means today

The founder address currently holds roughly **95%** of block-share. The gate does not
pass, will not pass by waiting, and cannot be made to pass by us. It passes when other
people mine — which is the point.

Until then, finality is provided by **explicitly-labelled founder checkpoints**, and
should be described as exactly that: centralised, temporary, with this document's gate
as the published condition for removal.

## The limit of coinbase attribution — read this before trusting the gate

**A coinbase address does not prove a distinct operator.** One miner can split hashrate
across any number of addresses and appear as many seats. That is not a bug in this
design; it is a property of permissionless mining, and no on-chain rule fixes it.

Consequences, stated plainly:

- The founder could satisfy the activation gate by splitting into four addresses. The
  arithmetic would pass and nothing would have decentralised. **We commit not to, and
  that commitment is worth exactly what a commitment is worth** — which is why the
  next point matters more.
- The gate is a **necessary condition, not a sufficient one**. It proves that weight is
  distributed across addresses; it cannot prove those addresses are distinct people.
- Meaningful evidence is **external**: operators publicly identifying themselves,
  distinct network origins, independent parties reproducing the chain state and
  disagreeing when something is wrong.

Anyone evaluating whether this chain's finality is real should weigh the external
evidence above the on-chain arithmetic, and should treat a passing gate with a silent
committee as a failing one.

## Why ML-DSA-65 and not a threshold scheme

A threshold/DKG scheme (Gennaro over BLS12-381, secp256k1, or Curve25519) would let the
committee emit **one small aggregate signature** instead of stacking one per seat —
roughly 96 bytes against ~46 KB for 14 seats. It is the obvious engineering answer and
it is the wrong one here.

Every one of those curves is broken by Shor. Finality signed with them means a quantum
adversary can **forge votes and reverse blocks the chain declared irreversible** — while
the coins themselves, signed with ML-DSA-65 ‖ Falcon-1024, remain safe. The weakest link
would be the irreversibility promise, which is the one thing finality exists to provide.

Post-quantum threshold signatures over lattices are an open research area with nothing
production-ready. So the committee stacks individual ML-DSA-65 signatures and pays the
bandwidth. That cost — not the cryptography — is the real constraint on committee size,
and it is why the eligibility floor exists.

---

*Design only. Not implemented, not activated. `FFG_ACTIVATION_HEIGHT` remains a
constant in a crate with no integration into the node.*
