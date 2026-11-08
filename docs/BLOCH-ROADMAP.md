<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Bloch-SIS-PoW — open protocol items (ownerless; not a roadmap anyone owns)

**Layer: the ownerless protocol.** This document lists **open protocol items**
for Bloch-SIS-PoW — the post-quantum, pure-Proof-of-Work BlockDAG base layer.
It is deliberately **not** a company roadmap, because the protocol has no
company behind it:

- **No owner, no authority, no schedule.** Bloch-SIS-PoW follows the Bitcoin
  model: nobody owns it, nobody can commit to dates on its behalf, and nobody's
  signature makes an item "official." The items below are **candidate
  improvements** — the way Bitcoin has BIPs — that **any node operator,
  researcher, or community member may pursue**, or ignore.
- **The community may organize itself if it chooses** — including creating a
  foundation or stewardship group someday. That is the community's prerogative,
  **not Postern Labs'**. Postern does not drive, schedule, or gate the
  protocol; it is one builder among many on an open base.
- **Anything with an operator is not on this list.** The rule (see the
  Two-Layers doc): *the base is ownerless; anything with an operator, a
  service, or a "who runs it?" answer is a Postern Labs product* — see
  [`POSTERN-ROADMAP.md`](POSTERN-ROADMAP.md). In particular, **FFG / BFT /
  finality-gadget services are Postern products, never protocol items** (see
  "Explicitly NOT on this list," below).

This document and [`POSTERN-ROADMAP.md`](POSTERN-ROADMAP.md) together
**replace the old single "Future Roadmap" PDF**, which mixed the ownerless
protocol and the owned products in one plan. That mixing was a mistake; these
two documents exist to keep the layers separate. Companions:
[`POSTERN-LABS.md`](POSTERN-LABS.md) (the two-layers split; also published as
`public/Postern-Two-Layers.pdf`), [`PROJECT-STATUS.md`](PROJECT-STATUS.md)
(verified state), [`EVOLUTION.md`](EVOLUTION.md) (analysis).

> ## Hard caveat — read first
> The chain runs the **relaxed k=4 regime today: the PoW work is trivially
> forgeable and no security is claimed.** The network is nascent (very few
> nodes, low hashrate, 51%-attackable). **Unaudited** — the third-party audit
> is contracted but not done; the no-shortcut proof and the IACR ePrint are
> outstanding. The coin (BLCH) is **not a security and not an asset** — no
> sale, no listing, no price, no value claim; the 17% founder premine is
> disclosed. "Mainnet beta" is a designation, not a security claim. Nothing
> below is a promise; there is no one who *could* promise it.

**Status markers:** `done` · `in-progress` · `candidate` (open for anyone to
pick up) · `blocked-on-audit-or-hardware` (needs money, third parties, or
physical hardware).

---

## 1. Mainnet-candidate gates

The honest bar for calling this chain a *mainnet candidate*. No one schedules
these; they are simply what would have to be true. (Gate chain detailed in
[`EVOLUTION.md`](EVOLUTION.md) §1.)

| Item | Status | Notes |
|---|---|---|
| PoW hardness research (estimator screen + frontier sweep) | `done` | `deploy/pow-estimator/SCREEN-RESULTS.md` + `docs/research/POW-CANONICAL-frontier.md`. Conclusion: a trapdoorless PoW cannot be lattice-hard *and* mineable — security is hashcash cumulative work; the SIS gate is a structural filter. |
| **k=8 gate re-activation (progressive ramp + matched difficulty)** | `in-progress` | k=8 soft-forked at block 213,000 but **reverted**: it multiplied difficulty ~4096× and the low hashrate stalled the chain. Re-activation must ramp progressively with a matched difficulty reduction so ~30 s block time holds. Until then the forgeable k=4 regime applies. |
| Difficulty-knob split (β frozen as security floor; leading-zeros on `H(s)` as the ASERT-tuned knob) | `candidate` | Specified; a consensus change — best done before a public testnet grows roots. Needs the same equivalence/regression testing the k-row optimization got. |
| No-shortcut / asymmetry proof for the SIS gate | `candidate` | The novel piece with no external verdict yet. |
| BDD cross-check + final difficulty calibration | `candidate` | Follows the estimator numbers. |
| IACR ePrint parameter rationale | `candidate` | Free external scrutiny of the novel PoW framing; anyone may author or co-author it. |
| **Live multi-node WAN network** + adversarial harness | `candidate` | Networking is verified on LAN only (9 tests); no multi-node WAN network has ever run. Anyone can stand up nodes — there is no official infrastructure to wait for. Adversarial matrix: equivocation, invalid blocks, eclipse. |
| **Third-party audit** (PoW params, consensus/reorg, hybrid sigs, serialization) | `blocked-on-audit-or-hardware` | Contracted, **not done**. The only paid gate. Until it lands, every claim stays behind "unaudited." |

## 2. Networking (every node is a seed)

| Item | Status | Notes |
|---|---|---|
| Self-bootstrapping P2P (mDNS + identify + PEX self-advertise; `DEFAULT_SEEDS` empty) | `done` | Verified on LAN. No privileged seed exists to capture or switch off. |
| WAN cold-start: optional, non-privileged, anyone-can-replicate DNS-seed fallback | `candidate` | Documented as a convenience, never required, never privileged; `DEFAULT_SEEDS` stays empty; docs must show how to run your own. |

## 3. Coherence (shielded transactions — no privacy claim today)

Built but **latent**: shielded txs are consensus-integrated yet `RejectAll`
until the verifier lands — a safe default. **Zero privacy claim** until the
items below and Coherence's own audit gate clear.

| Item | Status | Notes |
|---|---|---|
| C0/C1 spec + `coherence-core` + ShieldedEngine + mempool + reorg-undo | `done` | Built + tested; reorg-undo audited correct in isolation. |
| SP1 prove/verify on the toolchain | `candidate` | Prover scaffold exists (`crates/coherence-prover`). |
| U.4 live reorg wiring (selected-chain connect/disconnect + re-admission) + submit/gossip entry point | `candidate` | Must land with the SP1 verifier. |
| C3/C4 review; lattice RingCT as post-audit alternative | `candidate` | — |
| Coherence audit gate | `blocked-on-audit-or-hardware` | Separate from (and after) the base audit; the shielded pool can stay disabled at any launch. |

## 4. Neutral permissionless capability — tokens, forks, L2s

The base is a neutral rail: **anyone — no permission, no gatekeeper — may
issue a token, fork the chain, or build an L2** (spec:
[`specs/BLOCH-PERMISSIONLESS-TOKENS-L2.md`](specs/BLOCH-PERMISSIONLESS-TOKENS-L2.md)).
Postern Labs holds **no privilege** here; anything it builds on this rail is
one product among any number of equals.

| Item | Status | Notes |
|---|---|---|
| Fork capability | `done` | Already true by construction: open code, every node a seed. Nobody blesses a fork. |
| TKV0 token convention (metadata/UTXO issuance; zero consensus change) | `in-progress` | Draft wire format in the spec; reference indexer at `crates/bloch-tokens` — explicitly *one indexer among many*, not consensus-enforced, unaudited. |
| Covenant/script layer (consensus-enforced token rules) | `candidate` | A real soft-fork behind a height gate; heavier; only if the community wants it. |
| L2 anchoring pattern (commitments as ordinary txs) | `done` | Needs nothing from the base — anyone can anchor today. L2s themselves are products of whoever builds them. |

## 5. Explicitly NOT on this list

- **FFG / BFT / any finality gadget.** The BFT/FFG gadget and oracles were
  **removed from consensus — the base is pure PoW.** The only "finality" in
  the base is **checkpoint reorg-depth protection** (reorgs below a stored
  depth are rejected) — a normal PoW-chain feature, not a gadget and not
  governance. A finality *service* has an operator, so it is by definition a
  product: Postern's version (Postern-FFG) lives on the
  [Postern roadmap](POSTERN-ROADMAP.md), anchored to this base as ordinary
  transactions. If the whole signer set of any such service vanished, this
  chain would continue unchanged.
- **Governance.** An ownerless chain has no governance authority to roadmap.
  Coins don't vote; there is no foundation (unless the community someday
  creates one — its call); consensus changes happen the Bitcoin way: someone
  proposes, node operators adopt or don't.
- **Official infrastructure.** No official website, explorer, seed, or API
  host will ever appear here. Explorers, wallets, and dashboards are products
  of whoever builds them.

---

*Anyone may pick up any `candidate` item. There is no one to ask permission
of — that is the point.*
