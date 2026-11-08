# Attic — Swap / PosternDex (withdrawn 2026-07-18)

Working, tested code that was **removed from the shipped surfaces** — not deleted,
not abandoned. It comes back when the thing it needs exists.

## Why it was withdrawn

Nothing here is broken. The problem is that the code is finished and the **network
it targets is not**:

- `chain_id 700771` is **unregistered**
- no L2 node / RPC / prover runs
- `WBLCH` is a genesis predeploy that was **never actually deployed**
- **no pools exist**
- the v1 bridge vault is **CUSTODY** — release is a manual operator action

So the quote math and the calldata were real and tested, while nothing could be
signed or broadcast. The pane badged itself "live" on every desktop build (it gated
on `api.isReal("swap_quote")`, and the backend really did register `swap_quote`).
A live *quote* is not a live *swap*. It was moved to preview first, then withdrawn
entirely, so a swap screen cannot be mistaken for a usable one.

The bridge is the sharper version of the same problem: activating BLCH → wBLCH would
have taken real BLCH into a custodial vault with **no chain on the other side**.

## What is here

| Path | Was |
|---|---|
| `desktop-pane/swap.js` | the Swap pane (`desktop/src/modules/swap.js`) |
| `desktop-pane/swap.test.mjs` | its tests (`desktop/src/modules/swap.test.mjs`) |
| `desktop-pane/api-preview-engine.js` | the browser preview engine, `desktop/src/api.js` lines 899–1007 |
| `desktop-backend/swap.rs` | the Tauri backend (`desktop/src-tauri/src/swap.rs`) |
| `site/posterndex.html` | the PosternDex page |
| `site/build-js-page-entry.js` | its page definition from `site/build.js` |

**Left in the repo on purpose** (not user-facing surfaces, still useful):
`contracts/wblch/WBLCH.sol`, `l2/*` (anchor, bridge, sequencer, prover, evm),
`docs/specs/POSTERNDEX-*.md`, `docs/specs/POSTERN-WBLCH-BRIDGE.md`,
`docs/specs/BLOCH-L2-EVM-DESIGN.md`.

## How to restore

Only once a real L2 devnet answers — that is the whole condition.

1. `desktop-pane/swap.js` → `desktop/src/modules/swap.js`; same for `swap.test.mjs`.
2. `desktop-backend/swap.rs` → `desktop/src-tauri/src/swap.rs`; re-add `mod swap;`
   and the three `swap::swap_quote / swap_build_tx / swap_l2_probe` entries to
   `generate_handler!` in `main.rs`.
3. Paste `desktop-pane/api-preview-engine.js` back into `desktop/src/api.js` just
   before the final `})();`, and re-add the three commands to the REAL set.
4. Add `<script src="modules/swap.js"></script>` to `desktop/src/index.html`.
5. In `desktop/src/modules/panes.test.mjs`: add `"swap.js"` to `MODULE_FILES` and
   the three commands to `BACKEND_REGISTERED`.
6. Site: `site/posterndex.html` back, plus the page entry and the nav row.

**Do not restore the old badge gate.** `live: () => api.isReal("swap_quote")` is what
made this dishonest — the command is registered whether or not an L2 exists. Gate on
capability instead, the way `messenger.js` gates on `vestnik_matrix_status.built`:

```js
live: () => api.isReal("swap_quote") && l2Reachable === true,
```

where `l2Reachable` comes from an affirmative `swap_l2_probe`. Then the badge tracks
what a user can actually do, and it flips on its own the day the devnet answers —
no flag day, no second withdrawal.
