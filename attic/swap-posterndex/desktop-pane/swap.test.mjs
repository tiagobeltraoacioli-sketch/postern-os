// desktop/src/modules/swap.test.mjs — run with: node --test desktop/src/modules/
//
// Proves the Swap / DEX pane's REAL parts (the honest half of the design):
//
//   1. swap_quote is the REAL Uniswap-v2 constant-product getAmountOut with the
//      pool fee — asserted against known vectors, incl. 18-dp wei that overflow
//      53-bit floats (BigInt), fee-applied, price-impact monotonic in amount-in,
//      slippage floor exact, and ZERO-LIQUIDITY / zero-input FAIL CLOSED.
//   2. swap_build_tx emits REAL EVM calldata — correct 4-byte selectors, ABI
//      head/tail (path offset + array), approve+swap ordering, and the WBLCH
//      deposit/withdraw bridge on-ramp. UNSIGNED by construction.
//   3. The pane + the commands carry the honesty rails (design-scaffold, L2 not
//      live, execution preview, worthless) and the shared privacy caveat.
//   4. swap_l2_probe never fabricates a chain/hash in the preview (not reachable).
//
// The JS preview engine here computes the SAME real math the Rust backend
// (swap.rs, its own #[cfg(test)]) does — BigInt ⇄ U256 — so this file is a
// faithful offline check of the shipping quote/calldata contract. Mock-level:
// no network, no Tauri, no live L2.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { webcrypto } from "node:crypto";

if (!globalThis.crypto) globalThis.crypto = webcrypto;
globalThis.window = globalThis;
{
  const mem = new Map();
  globalThis.localStorage = {
    getItem: (k) => (mem.has(k) ? mem.get(k) : null),
    setItem: (k, v) => { mem.set(k, String(v)); },
    removeItem: (k) => { mem.delete(k); },
    clear: () => mem.clear(),
  };
}
function stubEl() {
  return {
    innerHTML: "", value: "", textContent: "", title: "", disabled: false,
    checked: false, hidden: false, isConnected: false, style: {}, dataset: {}, files: [],
    classList: { add() {}, remove() {}, toggle() {}, contains: () => false },
    addEventListener() {}, appendChild() {}, removeChild() {}, remove() {}, focus() {},
    querySelector: () => stubEl(), querySelectorAll: () => [],
  };
}
globalThis.document = {
  createElement: () => stubEl(), getElementById: () => stubEl(),
  querySelector: () => stubEl(), querySelectorAll: () => [],
  body: stubEl(), documentElement: stubEl(),
};

const here = path.dirname(fileURLToPath(import.meta.url));
const src = (rel) => readFileSync(path.join(here, rel), "utf8");
const load = (rel) => (0, eval)(src(rel));

load("../ui.js");
load("../api.js");
const P = window.Postern;
const api = P.api;

const WEI = 10n ** 18n;
const wei = (n) => (BigInt(n) * WEI).toString();

// ── 1 · REAL constant-product quote ─────────────────────────────────────────
test("swap_quote matches the canonical Uniswap v2 vector getAmountOut(1000,5000,10000)=1662", async () => {
  const q = await api.invoke("swap_quote", { amountIn: "1000", reserveIn: "5000", reserveOut: "10000", feeBps: 30 });
  assert.equal(q.amountOut, "1662");
});

test("swap_quote applies the 0.30% fee (a no-fee quote would be strictly larger)", async () => {
  const withFee = await api.invoke("swap_quote", { amountIn: "1000", reserveIn: "5000", reserveOut: "10000", feeBps: 30 });
  const noFee = await api.invoke("swap_quote", { amountIn: "1000", reserveIn: "5000", reserveOut: "10000", feeBps: 0 });
  assert.ok(BigInt(withFee.amountOut) < BigInt(noFee.amountOut), "fee must reduce the output");
});

test("swap_quote is exact on 18-dp wei that overflow a 53-bit float (BigInt path)", async () => {
  // 1000 wBLCH into a 1,000,000 / 3,500,000 pool, all in 18-dp wei.
  const q = await api.invoke("swap_quote", {
    amountIn: wei(1000), reserveIn: wei(1_000_000), reserveOut: wei(3_500_000), feeBps: 30,
  });
  // Hand-computed with BigInt: floor(1000e18*9970*3.5e24 / (1e24*10000 + 1000e18*9970)).
  const ain = 1000n * WEI, ri = 1_000_000n * WEI, ro = 3_500_000n * WEI;
  const aif = ain * 9970n;
  const expected = (aif * ro) / (ri * 10000n + aif);
  assert.equal(q.amountOut, expected.toString());
  assert.ok(BigInt(q.amountOut) > 0n && BigInt(q.amountOut) < ro);
});

test("swap_quote price impact is monotonic non-decreasing in amount-in and ~0 for a dust trade", async () => {
  const ri = wei(1_000_000), ro = wei(1_000_000);
  let last = -1;
  for (const a of ["1000", "10000", "100000", "500000"]) {
    const q = await api.invoke("swap_quote", { amountIn: wei(a), reserveIn: ri, reserveOut: ro, feeBps: 30 });
    assert.ok(q.priceImpactBps >= last, `impact must not decrease (a=${a})`);
    last = q.priceImpactBps;
  }
  assert.ok(last > 3000, "a 50%-of-reserve trade should show >30% impact");
  // A dust trade (1 whole token into a 1M-token pool) floors near the fee
  // (~0.30%) — the impact I report is realized-vs-mid, i.e. it INCLUDES the LP
  // fee. It must be small, and far below the whale trade above.
  const dust = await api.invoke("swap_quote", { amountIn: wei(1), reserveIn: ri, reserveOut: ro, feeBps: 30 });
  assert.ok(dust.priceImpactBps <= 60, `dust impact must be tiny (got ${dust.priceImpactBps} bps)`);
  assert.ok(dust.priceImpactBps < last, "dust impact must be far below a whale trade");
});

test("swap_quote slippage floor is exact (0.50% on 1662 → 1653)", async () => {
  const q = await api.invoke("swap_quote", { amountIn: "1000", reserveIn: "5000", reserveOut: "10000", feeBps: 30, slippageBps: 50 });
  assert.equal(q.amountOut, "1662");
  assert.equal(q.minReceived, "1653"); // floor(1662 * 9950 / 10000)
});

test("swap_quote FAILS CLOSED on zero liquidity and zero input — never a fabricated number", async () => {
  await assert.rejects(() => api.invoke("swap_quote", { amountIn: "100", reserveIn: "0", reserveOut: "10000" }), /LIQUIDITY/);
  await assert.rejects(() => api.invoke("swap_quote", { amountIn: "100", reserveIn: "5000", reserveOut: "0" }), /LIQUIDITY/);
  await assert.rejects(() => api.invoke("swap_quote", { amountIn: "0", reserveIn: "5000", reserveOut: "10000" }), /INPUT_AMOUNT/);
});

// ── 2 · REAL EVM calldata builder ───────────────────────────────────────────
test("swap_build_tx (swap) emits approve + swapExactTokensForTokens with correct selectors, ABI + ordering", async () => {
  const r = await api.invoke("swap_build_tx", {
    kind: "swap", amountIn: "1000", amountOutMin: "990",
    tokenIn: "0x4200000000000000000000000000000000000006",
    tokenOut: "0x00000000000000000000000000000000000000aa",
    recipient: "0x00000000000000000000000000000000000000bb",
    deadline: "1893456000",
  });
  assert.equal(r.signed, false, "built tx must be UNSIGNED");
  assert.equal(r.steps.length, 2, "approve then swap");
  const [approve, swap] = r.steps;
  // approve(address spender, uint256 amount) selector 0x095ea7b3
  assert.ok(approve.data.startsWith("0x095ea7b3"), "approve selector");
  assert.ok(approve.data.toLowerCase().includes("7a250d5630b4cf539739df2c5dacb4c659f2488d"), "approve spender = router");
  // swapExactTokensForTokens selector 0x38ed1739
  assert.ok(swap.data.startsWith("0x38ed1739"), "swap selector");
  const body = swap.data.slice(2);
  const word = (i) => body.slice(8 + 64 * i, 8 + 64 * (i + 1)); // skip the 4-byte selector
  // word[2] (path array offset) == 0xa0 (160)
  assert.equal(word(2), "00000000000000000000000000000000000000000000000000000000000000a0");
  // word[5] (path length) == 2, then the two addresses
  assert.equal(word(5), "0000000000000000000000000000000000000000000000000000000000000002");
  assert.ok(body.includes("4200000000000000000000000000000000000006"), "path[0] = wBLCH");
  assert.ok(word(3).endsWith("00000000000000000000000000000000000000bb"), "to = recipient");
  assert.ok(word(7).endsWith("00000000000000000000000000000000000000aa"), "path[1] = token OUT");
  assert.ok(body.endsWith("00000000000000000000000000000000000000aa"), "last word is path[1] (token OUT)");
  assert.equal(swap.chainId, 700771);
});

test("swap_build_tx (wrap/unwrap) is the real WBLCH deposit()/withdraw(wad) bridge on-ramp", async () => {
  const wrap = await api.invoke("swap_build_tx", { kind: "wrap", amountIn: "5" });
  assert.equal(wrap.steps.length, 1);
  assert.equal(wrap.steps[0].to, "0x4200000000000000000000000000000000000006");
  assert.equal(wrap.steps[0].data, "0xd0e30db0", "deposit() selector, no args");
  assert.equal(wrap.steps[0].value, "5", "wrap sends native BLCH as msg.value");

  const unwrap = await api.invoke("swap_build_tx", { kind: "unwrap", amountIn: "7" });
  assert.ok(unwrap.steps[0].data.startsWith("0x2e1a7d4d"), "withdraw(uint256) selector");
  assert.ok(unwrap.steps[0].data.endsWith("0000000000000000000000000000000000000000000000000000000000000007"), "wad = 7");
  assert.equal(unwrap.steps[0].value, "0", "unwrap sends no native value");
});

test("swap_build_tx rejects an unknown kind and a malformed address (fail closed)", async () => {
  await assert.rejects(() => api.invoke("swap_build_tx", { kind: "rug", amountIn: "1" }), /unknown build kind/);
  await assert.rejects(() => api.invoke("swap_build_tx", {
    kind: "swap", amountIn: "1", amountOutMin: "1", tokenIn: "0xnothex", tokenOut: "0x00000000000000000000000000000000000000aa",
    recipient: "0x00000000000000000000000000000000000000bb", deadline: "1",
  }), /20 bytes|hex/);
});

// ── 3 · Honesty rails ────────────────────────────────────────────────────────
test("every swap command response carries the design-scaffold / execution-preview honesty", async () => {
  const q = await api.invoke("swap_quote", { amountIn: "1", reserveIn: "10", reserveOut: "10" });
  const b = await api.invoke("swap_build_tx", { kind: "wrap", amountIn: "1" });
  for (const h of [q.honesty, b.honesty]) {
    assert.match(h, /DESIGN-SCAFFOLD, NOT live/);
    assert.match(h, /EXECUTION is PREVIEW/);
    assert.match(h, /worthless/);
  }
});

test("swap_l2_probe preview never fabricates a live chain or a hash", async () => {
  const p = await api.invoke("swap_l2_probe", { rpcUrl: "http://127.0.0.1:8545" });
  assert.equal(p.reachable, false);
  assert.equal(p.chainId, null);
  assert.equal(p.isBlochL2, false);
  assert.match(p.note, /design-scaffold|BUILT \+ READY/);
});

test("the swap pane renders the shared privacy caveat + the honesty rails (design-scaffold, execution preview)", async () => {
  P.modules.length = 0;
  load("swap.js");
  const mod = P.modules.find((m) => m.id === "swap");
  assert.ok(mod, "swap module registered");
  assert.equal(mod.group, "Advanced · testnet (zero value)", "swap sits in the zero-value group");
  const root = stubEl();
  await mod.render(root);
  const html = root.innerHTML;
  assert.ok(html.includes("pane-caveat"), "shared privacy caveat block");
  assert.ok(/DESIGN-SCAFFOLD/i.test(html), "pane says design-scaffold");
  assert.ok(html.includes("chain_id 700771 is unregistered"), "pane discloses the unregistered chain id");
  assert.ok(/execution is PREVIEW/i.test(html), "pane says execution is preview");
  assert.ok(html.includes("no tx hash is ever faked") || html.includes("no tx hash"), "pane promises no faked hash");
  assert.ok(/worthless/i.test(html), "pane says worthless");
  // The pane is UNCONDITIONALLY preview. It must NOT gate on api.isReal(...):
  // swap_quote really is registered by the Tauri backend (the constant-product
  // math and the EVM calldata are real and tested), so any isReal gate badges
  // this pane "live" on every desktop build — while chain_id 700771 stays
  // unregistered, WBLCH stays undeployed, no pools exist, nothing is signed or
  // broadcast, and the v1 bridge vault is CUSTODY. A live QUOTE is not a live
  // SWAP, and the badge is what a user reads before trusting a swap screen.
  //
  // When a real L2 devnet exists, the gate comes back as a CAPABILITY check
  // (api.isReal("swap_quote") && an affirmative swap_l2_probe), mirroring the
  // messenger pane's vestnik_matrix_status.built. Re-assert this test then.
  const isRealGate = [...src("swap.js").matchAll(/live:\s*\(\)\s*=>\s*api\.isReal\(/g)];
  assert.equal(isRealGate.length, 0, "swap must not badge live off a registered-command check");
  assert.match(src("swap.js"), /live:\s*\(\)\s*=>\s*false/, "swap declares itself preview outright");
  assert.equal(mod.live(), false, "and the module actually reports preview");
});
