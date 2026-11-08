<!-- SPDX-License-Identifier: MIT -->

# WBLCH — Wrapped BLCH (bridge v1: wBLCH only)

**UNAUDITED REFERENCE. Inert.** Cannot be deployed or tested until the Bloch EVM
L2 exists (design-only today — [`docs/specs/BLOCH-L2-EVM-DESIGN.md`](../../docs/specs/BLOCH-L2-EVM-DESIGN.md)),
and even then it stays inert until PosternDex's published activation gate clears
(chain security + audit + legal — see `posternlabs.com/posterndex`).

## Scope (deliberate)

The bridge's **v1 does ONLY wBLCH** — wrapping the L2's own native BLCH into a
canonical ERC-20 at a strict 1:1 peg. **No wBTC / wETH / wUSDT.** Outside-asset
custody (the risky, most-exploited construct) is a **separate, later, gated
module** ([`docs/specs/BLOCH-BRIDGE-DESIGN.md`](../../docs/specs/BLOCH-BRIDGE-DESIGN.md)),
not this. Starting with wBLCH means **zero custody, zero foreign-chain trust,
zero proof-of-reserves surface** — the safe first step.

## Why wBLCH exists

Uniswap v2 `Pair`s trade **ERC-20** tokens. The L2's native BLCH (itself
deposit-minted from Bloch L1 by the rollup) is not an ERC-20, so — exactly like
WETH on Ethereum — a canonical wrapper lets BLCH trade uniformly in pools.
`WBLCH.sol` is a faithful, minimal **WETH9-style** wrapper:

- `deposit()` / `receive()` — send native BLCH, get WBLCH 1:1.
- `withdraw(wad)` — burn WBLCH, get native BLCH 1:1.
- `totalSupply()` ≡ `address(this).balance` — the wrapped supply is *always*
  exactly the native BLCH escrowed here. No owner, no mint privilege, no
  upgradeability, no fee. Intentionally boring.

## Trust model

**Trust-minimized, not custodial.** WBLCH holds no outside asset and no
counterparty's funds — only the L2's own native balance, redeemable 1:1 by its
own holder at any time. The only thing you trust is the L2 itself (its
sequencer/DA/proving), which is disclosed as an owned Postern product. This is
*not* the federated custody bridge; it is the canonical native wrapper.

## Testing (when the L2 exists)

No Solidity toolchain is wired into this repo yet (the L2 is design-only). Once
it lands, test with Foundry:

```
forge test           # deposit/withdraw round-trip, supply==balance invariant,
                     # transfer/approve/transferFrom, withdraw-more-than-balance revert
```

Until then this is a reviewable reference, not a deployed contract. Nothing here
is audited or safe.
