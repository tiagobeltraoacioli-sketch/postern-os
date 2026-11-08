<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# PosternDex + Bloch Bridge — design

**Status: DESIGN ONLY. Nothing here is built, audited, or safe.** This document
designs (a) **PosternDex**, an AMM/DEX on the ownerless Bloch-SIS-PoW base, and
(b) a **Bridge** for wrapping outside assets (BTC/ETH/USDT) into Bloch tokens,
with **third-party liquidity providers ("AMMs") earning swap fees**. It is
deliberately conservative and honesty-first: the hard problems are named before
the features.

---

## 0. Read this first — the four gates that bound everything

A DEX+bridge that holds real value has to clear four gates. Until they clear,
**everything below is testnet, zero-value, reference-only**, exactly like the
rest of the project.

1. **Chain security (the blocker).** Bloch today runs the **relaxed k=4 regime —
   trivially forgeable, low-hashrate, 51%-attackable, unaudited.** On a
   reorg-able chain, **any wrapped-asset supply can be double-spent by a reorg**
   (mint against a deposit, reorg the deposit away, keep the wrapped tokens).
   So **no real asset may be bridged until the mainnet-candidate gates clear**
   (k=8 progressive ramp, live WAN hashrate, checkpoint finality depth, and the
   contracted third-party audit). Before that: **testnet wrapped assets with no
   value**, purely to prove the mechanism.
2. **Contract/covenant audit.** The swap and bridge logic must be
   externally audited. Bridges are the single most-exploited construct in the
   space (billions lost). No exceptions.
3. **Legal review.** A custody bridge is likely **money transmission**; an AMM
   with fee-earning LPs and any listed asset touches **securities / commodities**
   law across jurisdictions. Legal review is a **hard gate before any real
   value**, and Postern's incorporation is still in process. This is not legal
   advice.
4. **Honesty of the trust model.** Every component states exactly whom you trust
   (custodians, a sequencer, a light client, no one) — see §3.

**Money hygiene (unchanged project rule):** BLCH is worthless-by-design, not a
security, never sold. LP fees are a **utility cut of swap fees for providing
liquidity** — a service, **not** a yield product, not an investment, no promised
return; impermanent loss is disclosed. Any PosternDex "governance" follows the
Bitcoin model — **coins do not vote.**

---

## 1. Layer placement (the two-layer discipline still holds)

| Component | Layer | Owner |
|---|---|---|
| Token standard (TKV0 → covenant layer), AMM pool primitive, atomic-swap HTLCs | **ownerless Bloch base** | nobody — anyone deploys/forks |
| The **PosternDex interface** (the posternlabs.com tab, an aggregator/frontend) | **owned Postern product** | Postern (like Uniswap Labs' frontend vs the protocol) |
| The **bridge** (if custodial/federated) and the **L2 sequencer** (if used) | **owned product / disclosed consortium** | has an operator ⇒ a product, by the rule |

**The rule that governs the whole thing:** *the base is ownerless; anything with
an operator, a custodian, or a "who runs it?" answer is a product* — never part
of the commons. A pool or a fork of PosternDex that anyone deploys is neutral;
the hosted frontend and any asset custodian are products.

---

## 2. Foundation — the token layer

PosternDex tokens (pool shares, wrapped assets, user tokens) are **TKV0 tokens**
(`crates/bloch-tokens` — the neutral, off-consensus standard: envelopes in
zero-value `TxOutput` script_pubkeys, `token_id := txid`, balances derived by any
indexer, zero consensus change). TKV0 gives ERC-20-like **issuance and transfer**
for free, permissionlessly.

**But TKV0 alone cannot back a DEX or a bridge.** Off-consensus indexers observe
state; they cannot *enforce* it — nothing stops a malformed or double-spending
envelope from being written; consensus just ignores it, and each indexer must
agree. A swap ("atomically give X, receive Y or revert") and a custody vault
("this UTXO may only be spent to honor a redemption") need **enforced** rules.
Two honest ways to get enforcement on a pure-PoW UTXO chain:

- **(E1) Covenant/script soft-fork** — add covenant opcodes so a *pool UTXO*
  enforces the constant-product invariant on spend, and a *vault UTXO* enforces
  redemption rules. Bitcoin-covenant-style. Most trust-minimized, native to the
  ownerless base, but a **consensus change** that node operators must adopt
  (BIP-style; nobody can force it). Heaviest to build and prove.
- **(E2) Layer-2** — swaps/custody run in an L2 that posts state commitments +
  validity (or fraud) proofs to Bloch as ordinary transactions. Postern can ship
  an L2 **without any base consensus change** (it anchors like FFG/RWA/BaaS do).
  Faster to build; the L2 has a **sequencer** (an operator ⇒ a product), whose
  trust model must be disclosed (validity-proof L2 ⇒ trust math, not the operator,
  for validity; still trust it for liveness/censorship).

**Recommended path:** **E2 (L2) first** for a working PosternDex (no soft-fork
needed, ships as a Postern product), with **E1 (covenants)** as the long-term
ownerless-native option if the community wants it. The design below is written to
work on either substrate.

---

## 2a. A DEX WITHOUT a bridge — the recommended v1

**The DEX does not need the bridge.** A DEX only needs *tradeable tokens on the
same ledger*. If those tokens are **native to Bloch** — BLCH plus any **TKV0
tokens** anyone issues — you get a **fully functional AMM with zero bridge**: no
custody, no foreign-chain trust, no proof-of-reserves, and none of the
bridge's audit/legal/reorg-of-a-wrapped-supply exposure. The bridge is a
**separate, later, optional module** that only exists to bring *outside* assets
(BTC/ETH/USDT) in.

**So the honest, low-risk shipping order is: DEX first (native tokens only),
bridge later (gated behind §0).** The bridge is where all the hardest risk lives;
the DEX standalone sidesteps every bit of it.

Two nuances:
- **On Bloch L1 directly (covenant path E1): truly zero bridge** — pools and
  tokens live on the base chain; nothing crosses a boundary.
- **On an L2 (path E2): you still need an L1↔Bloch *rollup* deposit/withdraw
  path** to move native tokens on/off the L2 — but that is a **trust-minimized
  rollup primitive** (validity/fraud-proven), **not** the risky outside-asset
  *custody* bridge of §3. It never holds a foreign chain's coins.
- **Honest limit:** a bridge-less DEX trades only *native* tokens, which today
  have **no external value** (BLCH is worthless-by-design; most TKV0 tokens are
  test/worthless). That is fine for a testnet/bootstrapping DEX — it proves the
  mechanism and lets native tokens trade — but "a working DEX" is not "a DEX with
  valuable assets" until either the chain matures organically or a bridge (§3)
  brings valued assets in. Say so on-screen.

---

## 3. The Bridge — wrapping BTC / ETH / USDT (the hard part, OPTIONAL / later)

Goal: a user locks BTC/ETH/USDT on its native chain and receives a 1:1 **wrapped
TKV0 token** (wBTC/wETH/wUSDT) on Bloch; burning the wrapped token releases the
native asset. The honest design is a **spectrum of trust**, presented so users
choose eyes-open:

- **(B1) Custodial / federated (M-of-N) — trusted.** A disclosed set of
  custodians hold the native assets in an M-of-N multisig/MPC vault; a deposit
  proven to the federation mints wBTC; a burn triggers an M-of-N release. **You
  trust the custodians** (collusion or key-compromise of M steals the reserves).
  Honest requirements: publish the custodian set, M-of-N, the vault addresses,
  **proof-of-reserves**, and the attack surface. This is what most "wrapped BTC"
  is. It is a **product with an operator** (Postern and/or a consortium).
- **(B2) Light-client / SPV — trust-minimized.** Bloch verifies the source
  chain's headers to prove deposits without a custodian's say-so. **BTC SPV is
  feasible** (verify PoW headers + a Merkle proof of the deposit tx). **ETH is
  heavy** (verifying Ethereum consensus/finality on Bloch is a large build).
  Redemption still needs a way to move the native asset out — usually a
  collateralized/threshold signer set, so pure B2 rarely eliminates all trust.
- **(B3) Atomic swaps / HTLC — no custody, no wrapping.** Direct cross-chain
  swaps (BTC↔Bloch) via hash-time-locked contracts: no bridge, no wrapped
  supply, **nobody holds your asset** — but only for *point-in-time swaps*, not
  persistent on-Bloch liquidity or an ERC-20-like standing balance. The most
  trust-minimized, and the honest **v1 for BTC** while the chain is unproven.

**USDT is special and must be disclosed:** USDT is a **centralized issuer
(Tether)** asset. Any wUSDT is only as trustworthy as (a) the bridge custodian
**and** (b) Tether itself (freeze/blacklist/redemption risk). It **cannot be
trust-minimized** — it is inherently custodial twice over. Wrapping it is
possible but must carry that double-custody disclosure.

**Gating (non-negotiable):** real BTC/ETH/USDT may be bridged **only after** the
§0 gates. Until then the bridge runs with **testnet/zero-value assets** to
demonstrate mint/burn/proof-of-reserves mechanics honestly.

---

## 4. PosternDex — the AMM

**Model:** constant-product AMM (`x·y=k`, **Uniswap-v2-style**) as the neutral pool
primitive, running on the E2 (L2) or E1 (covenant) substrate from §2.

**Uniswap alignment (what maps, and the one thing that cannot):**

| Uniswap (Ethereum) | PosternDex (Bloch) |
|---|---|
| `UniswapV2Factory` — deploys pair contracts | pool-creation primitive (covenant template on E1, or L2 state on E2) — permissionless |
| `UniswapV2Pair` — holds reserves, enforces `x·y=k`, mints/burns LP tokens | a **pool UTXO** (E1 covenant) or an **L2 pool account** (E2) doing the same |
| `UniswapV2Router` — swap/add/remove-liquidity entry | the PosternDex client + a router primitive |
| LP tokens (ERC-20) | LP tokens (**TKV0**) |
| 0.30% fee to LPs, optional 0.05% protocol fee (off by default) | identical — default all-to-LPs |
| Uniswap **Labs frontend** ≠ Uniswap **Protocol** | PosternDex **frontend (owned)** ≠ the **pool primitive (ownerless)** |

**The one fundamental difference — and the whole engineering problem:** Uniswap
is a set of **EVM smart contracts**; Ethereum *executes arbitrary code* per
transaction, so "deploy Uniswap" is just deploying contracts. **Bloch has no EVM
and no smart contracts** — it is a pure-PoW UTXO chain. So the Uniswap *logic*
(the Pair's `x·y=k` enforcement, LP mint/burn) has **nowhere to run natively**.
That execution environment must be *added*, which is precisely §2's choice:
**E1 covenants** (give the UTXO script enough power to enforce the pair invariant
on spend — a consensus soft-fork) or **E2 an L2** (run the Uniswap-equivalent
logic off-chain and prove it to Bloch). Everything else about PosternDex is
"Uniswap v2 as-is"; this substrate is the part Uniswap gets from Ethereum for
free and Bloch has to build. (A later **Uniswap-v3-style concentrated liquidity**
variant is possible on the same substrate once v2 works.)

**Pools:** any pair of TKV0 tokens — `wBTC/BLCH`, `wUSDT/wBTC`, `<user-token>/BLCH`,
etc. Anyone can **permissionlessly create a pool** (neutral rail); the PosternDex
frontend just surfaces the ones it chooses to list (and discloses that listing ≠
endorsement, and that most tokens are worthless/scams — same honesty as the app
badges).

**Swap:** a swap spends into the pool honoring `x·y=k` minus the fee; on E2 the L2
validity proof enforces it, on E1 the covenant enforces it on-chain. Slippage and
the fee are shown before signing.

**Third-party liquidity providers = the "AMMs" you asked for:**
- Anyone deposits **both sides** of a pair and receives **LP tokens** (TKV0)
  representing their pro-rata share of the pool.
- Each swap charges a fee (e.g. **0.30%**), which accrues to the pool; LPs redeem
  their LP tokens for their share **plus accrued fees**. That is the
  "remunerated as an AMM" mechanism — **fees for providing liquidity**, nothing
  more.
- **Permissionless:** no gatekeeper decides who may be an LP; it is open to
  third parties by construction (the point of an AMM).
- **Honest LP risks, shown in-product:** *impermanent loss* (you can withdraw
  worth less than you deposited if prices move), *smart-contract/covenant risk*
  (unaudited ⇒ funds can be lost to a bug), *reorg risk* (until mainnet
  security), *no yield promise* (fees are variable and can be zero). This is a
  **service fee for a service rendered, not an investment product** — and it is
  labelled that way, loudly.

**Optional fee split:** a small protocol fee (e.g. 0.05% of the 0.30%) *could*
fund Postern's operation of the frontend/L2 — but **it is fiat-equivalent utility
revenue for running software, never a buyback/burn of BLCH and never a token
pitch** (consistent with the neutral-rail / no-revenue-touches-the-token rule).
Default v1: **no protocol fee** (all fees to LPs) to keep it clean.

---

## 5. The posternlabs.com "PosternDex" tab

A new tab, honestly framed as a **testnet DEX / design preview** until the gates
clear. Panes:
- **Swap** — pick pair, see price/slippage/fee, sign. Loud banner: *testnet,
  zero-value, unaudited, reorg-risk, not investment advice.*
- **Pools / Provide liquidity** — deposit a pair, get LP tokens, view accrued
  fees, withdraw. Impermanent-loss + risk disclosure inline.
- **Bridge** — deposit/redeem wrapped assets, with the **trust-model badge**
  (custodial-federated / SPV / atomic-swap) and, for custody, live
  **proof-of-reserves**. wUSDT carries the double-custody (Tether) disclosure.
- Same CSP-strict, zero-network-beyond-its-node discipline as the rest of the
  site; wallet is the Postern PQ wallet / phone-as-signer.

---

## 6. Phasing

- **Phase 0 — design.** This document.
- **Phase 1 — testnet primitives (zero value).** TKV0 pool/LP tokens; the L2 (E2)
  AMM prototype; a testnet bridge showing mint/burn/proof-of-reserves; the
  PosternDex UI on testnet. All UNAUDITED, all zero-value, all labelled.
- **Phase 2 — the gates.** Third-party audit of the AMM + bridge; legal review;
  Bloch mainnet-candidate security (k=8 ramp, WAN hashrate, finality). Atomic-swap
  (B3) BTC path can precede full custody since it holds nothing.
- **Phase 3 — real value.** Only after Phase 2: real bridged assets, real LP fees,
  disclosed custodians + proof-of-reserves. Covenant (E1) path opened to the
  community if desired.

---

## 7. What is neutral vs owned, restated

- **Neutral (ownerless Bloch):** the token standard, the AMM pool math, HTLC
  atomic swaps, the right for anyone to deploy a pool or fork the whole interface.
  Postern holds **no privilege** here.
- **Owned (Postern products):** the PosternDex frontend, the L2 sequencer, the
  custodial bridge federation, the hosted indexers/proof-of-reserves service.
  These have operators and are honestly labelled as such.

---

## 8. Open questions to resolve before Phase 1

- E1 (covenant soft-fork) vs E2 (L2) as the first substrate — recommend E2.
- Bridge v1 asset + model — recommend **BTC via B3 atomic swaps** (no custody)
  first; wBTC/wUSDT custody only post-audit+legal.
- Whether Postern operates the only L2/bridge or bootstraps a consortium
  (ownership/decentralization of the operated pieces).
- Legal structure for custody + LP fees per target jurisdiction.
- Cross-chain finality assumptions (how many source-chain confirmations before a
  mint; how Bloch reorgs interact with in-flight bridge ops — the reason Phase 3
  waits for finality).

*Everything here is a plan. Nothing is decentralized, audited, safe, or holding
real value — and it will say so on every screen until it is.*
