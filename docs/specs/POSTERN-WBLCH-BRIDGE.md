<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# wBLCH — index / redirect

**This is a pointer, not a design.** The wBLCH + bridge + DEX-launch space is
already designed, far more thoroughly and coherently, in the specs below (produced
by a 16-agent design fleet). Read those, not a competing sketch.

## The canonical design (read these)

- **[`BLOCH-L2-EVM-DESIGN.md`](BLOCH-L2-EVM-DESIGN.md)** — the Bloch **EVM L2**, a
  zk-validity rollup (unmodified revm + SP1 + Reth SDK) where BLCH is the native
  gas token, **bridged from L1 by the rollup itself** (deposit-mint / withdraw
  proven against the anchored state root). This is the trust-minimized L1↔L2
  path — no federation for wBLCH.
- **`contracts/wblch/WBLCH.sol`** (+ its README) — the canonical **WETH9-style
  wrapper**: native L2 BLCH ↔ WBLCH at a strict 1:1, `totalSupply() ≡
  address(this).balance`. No owner, no mint privilege, no custodian. This is what
  "wBLCH" is — the native wrapper on the L2, not a federated peg.
- **[`POSTERNDEX-AMM-DESIGN.md`](POSTERNDEX-AMM-DESIGN.md)** — PosternDex is
  **unmodified Uniswap v2** deployed on the L2. "A Postern product for whoever
  wants to launch a pool" = deploying the standard Uniswap contracts +
  permissionless pool creation, nothing bespoke.
- **[`BLOCH-PERMISSIONLESS-TOKENS-L2.md`](BLOCH-PERMISSIONLESS-TOKENS-L2.md)** —
  the neutral, permissionless token / fork / L2 capability: anyone issues a token
  or creates a pool, no gatekeeper.
- **[`BLOCH-BRIDGE-DESIGN.md`](BLOCH-BRIDGE-DESIGN.md)** /
  **[`POSTERNDEX-BRIDGE-DESIGN.md`](POSTERNDEX-BRIDGE-DESIGN.md)** — the SEPARATE,
  LATER, gated **outside-asset** bridge (wBTC/wETH/wUSDT) via a disclosed M-of-N
  FROST/TSS federation. This is the "federated custody" model — it applies to
  *foreign* assets, **not** to wBLCH.

## The two things people conflate (the honest distinction)

1. **wBLCH** = the L2's own native BLCH, wrapped WETH-style. **Trust = the L2
   rollup** (sequencer/DA/proving), disclosed. No custodian, no proof-of-reserves
   surface, no foreign-chain trust. `contracts/wblch/WBLCH.sol`.
2. **wBTC/wETH/wUSDT** = *outside* assets, wrapped via a **federated custodian
   vault**. **Trust = ≥M honest custodians, full stop** — the risky, most-exploited
   construct, kept as a separate gated module. `BLOCH-BRIDGE-DESIGN.md`.

## Gates (bind everything, from the canonical specs)

Bloch is k=4-forgeable, 51%-attackable, unaudited. An L2 inherits its L1's
finality, so **no real value** until Bloch mainnet security (k-ramp, WAN hashrate,
checkpoint finality) **+ a third-party audit + legal review** clear. Everything is
testnet / zero-value until then. BLCH is not a security and claims no value;
wBLCH inherits that. Not legal or financial advice.
