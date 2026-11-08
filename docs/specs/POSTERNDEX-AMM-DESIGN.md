<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# PosternDex AMM — design (native tokens, no bridge)

**Status: DESIGN ONLY. Not built, not audited, not safe. Testnet / zero-value.**
Companion to [`POSTERNDEX-BRIDGE-DESIGN.md`](POSTERNDEX-BRIDGE-DESIGN.md) (§2a:
the DEX ships **without** the bridge, on native tokens) and the L2-EVM design.

---

## 0. The honest headline: don't reinvent the AMM — reuse Uniswap v2

On the recommended substrate (an **EVM L2**, designed separately), PosternDex's
core **is the unmodified, battle-tested Uniswap v2 contract set**, deployed
as-is. Uniswap v2 is one of the most-audited, most-attacked, most-survived pieces
of financial code in existence; **rewriting it would only add risk.** The design
work is therefore *integration + honest framing + the substrate*, **not** a new
AMM. (Uniswap v2 is GPL-3.0-with-an-additional-use-grant for the periphery /
BUSL-then-GPL history — **verify the exact license of the version you deploy**
before shipping; the *interfaces* and the constant-product math are not
copyrightable, so a clean MIT/Apache re-implementation of the same math is the
fallback if the license doesn't fit the project's permissive rule.)

---

## 1. Components (Uniswap-v2 shape)

| Contract | Role |
|---|---|
| **Factory** | permissionless `createPair(tokenA, tokenB)` → deploys a Pair; one canonical pair per unordered token set |
| **Pair** | holds the two reserves, enforces `x·y=k` on every swap, mints/burns **LP tokens** (an ERC-20 per pair), accrues the fee into the reserves, exposes the cumulative-price **TWAP oracle** |
| **Router** | user entry: `swapExactTokensForTokens` (multi-hop path routing through pairs), `addLiquidity`, `removeLiquidity`; slippage bounds + deadline |
| **WBLCH** | canonical wrapped-native (like WETH) so BLCH trades through the ERC-20 Pair interface uniformly |

All tokens are **native to Bloch/the L2**: BLCH (as WBLCH) + **TKV0 tokens** that
anyone issues (bridged onto the L2 via the trust-minimized rollup deposit path —
**not** the outside-asset custody bridge, which is out of v1 scope).

---

## 2. The math (Uniswap v2, unchanged)

- **Swap (0.30% fee to LPs):**
  `amountOut = (amountIn · 997 · reserveOut) / (reserveIn · 1000 + amountIn · 997)`
  — the invariant `reserve0 · reserve1` is non-decreasing across a swap (the fee
  is what grows `k`, and that growth is the LP yield).
- **First liquidity:** `LP_minted = sqrt(amount0 · amount1) − MINIMUM_LIQUIDITY`
  (the tiny `MINIMUM_LIQUIDITY` is burned to dead-address to avoid the
  divide-by-zero / first-depositor attack — keep it).
- **Subsequent liquidity:** `LP_minted = min(amount0·totalLP/reserve0,
  amount1·totalLP/reserve1)` (deposit must be balanced or the excess is a gift to
  the pool).
- **Withdraw:** burn LP → receive `LP/totalLP` of each reserve (principal **plus**
  the accrued fees, since fees grew the reserves). That is the entire "remunerated
  as an AMM" mechanism — no separate reward emission, no yield token, no staking.
- **Protocol fee switch:** Uniswap's optional `feeTo` mints 1/6 of the LP-fee
  growth to a protocol address. **Default OFF** (all fees to LPs). If ever ON, it
  is fiat-equivalent utility revenue for running the frontend/L2 — **never a
  buyback/burn of BLCH, never a token pitch.**

---

## 3. Third-party liquidity providers (the "AMMs")

- **Permissionless:** anyone calls `addLiquidity` on any pair and becomes an LP;
  no gatekeeper. This is the AMM being open to third parties by construction.
- **Remuneration = the fee growth in their share.** Withdraw returns principal +
  fees. Variable, can be zero, **not a promised return.**
- **Risks shown in-product, loudly, before deposit:**
  - **Impermanent loss** — if the price ratio moves, withdrawing can be worth less
    than depositing; the classic AMM risk. Show a worked example.
  - **Smart-contract / substrate risk** — even reused Uniswap v2 is only as safe
    as the L2 it runs on; the L2 is unaudited ⇒ funds can be lost to a bug.
  - **Reorg risk** — inherited from Bloch (k=4, 51%-attackable) until mainnet
    security; an L1 reorg can unwind L2 state.
  - **Scam-token / listing risk** — listing ≠ endorsement; most tokens are
    worthless or malicious; the frontend must say so (same honesty as the app
    badges) and never present a token as "valuable" or "investment".
  - **No yield promise** — fees ≠ interest; this is a service fee, not a security.

---

## 4. Oracle, and what NOT to do

- Use Uniswap v2's **cumulative-price TWAP** for on-chain price reads, and warn
  that **spot price from a low-liquidity pool is trivially manipulable** (flash
  swaps, thin pools) — never use the raw spot for anything security-critical.
- **Do NOT** add: leverage/margin, lending against LP, "auto-compounding vaults",
  reward-emission farming, or anything that reads as a yield/APY product. Those
  are exactly the constructs that turn "a DEX" into "an unregistered security /
  a rug factory." PosternDex v1 = swap + provide-liquidity, nothing more.

---

## 5. Substrate options (recap)

- **EVM L2 (recommended):** deploy Uniswap v2 as-is. Fastest, most-audited, no
  base consensus change. The L2 (its sequencer, DA, proving) is the thing that
  must be built + audited — see the L2-EVM design.
- **Bloch L1 covenant (native, later):** a covenant-enforced pool UTXO
  implementing the same `x·y=k` on spend. Ownerless-native, no operator, but a
  consensus soft-fork and a much larger build; only if the community wants it.

---

## 6. Phasing

- **P0** — this design.
- **P1 (testnet, zero value):** stand up the L2 (or covenant prototype), deploy
  the AMM (reused Uniswap v2), the Factory/Router/Pair + WBLCH, the PosternDex
  Swap + Pools tab, all labelled testnet/unaudited. Native TKV0 tokens only.
- **P2 (gates):** audit the L2 + the deployment/integration (the contracts are
  reused-audited, but the *deployment on this substrate* is not); legal review of
  the operated pieces + LP-fee posture; Bloch mainnet security.
- **P3:** the bridge (separate module) can later add valued assets — but the AMM
  itself is complete without it.

*Everything is a plan. Nothing is decentralized, audited, safe, or holding real
value — and it will say so on every screen until it is.*
