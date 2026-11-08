// modules/swap.js — Swap / DEX: PosternDex (Uniswap-v2-model AMM) + wBLCH on the
// (design-only) Bloch EVM L2. Wired to the REAL swap_quote / swap_build_tx /
// swap_l2_probe Tauri commands (swap.rs) — with a REAL browser preview too:
// the constant-product quote math and the EVM calldata are pure and run
// identically (BigInt ⇄ U256) whether or not a backend is present.
//
// HONESTY RAILS (non-negotiable, surfaced verbatim in the pane): PosternDex and
// the Bloch EVM L2 are DESIGN-SCAFFOLD, NOT live — chain_id 700771 is
// unregistered, the L2 node/RPC/prover are stubs, WBLCH is a genesis predeploy
// that has never been deployed, and no pools exist. So the QUOTE and the swap
// transaction BUILD are REAL and tested; on-chain EXECUTION is PREVIEW until a
// live L2 (or a local devnet) exists. Nothing here is signed or broadcast, and
// no fake tx hash is ever produced. The v1 bridge vault is CUSTODY. Zero-value;
// BLCH/wBLCH are worthless; unaudited.
(function () {
  "use strict";
  const P = window.Postern, UI = P.ui, api = P.api;

  // The L2 EVM RPC endpoint the Swap button will PROBE for liveness (optional).
  // Stored in local settings only, never committed. Empty by default (no live
  // L2 exists); a local devnet would be a loopback http URL.
  const L2_RPC_LS = "postern.swap.l2rpc";
  const l2RpcGet = () => (localStorage.getItem(L2_RPC_LS) || "").trim();
  const l2RpcSet = (v) => {
    const t = (v || "").trim();
    if (t) localStorage.setItem(L2_RPC_LS, t); else localStorage.removeItem(L2_RPC_LS);
  };

  // Canonical placeholders (l2/bloch-l2-bridge/deploy/testnet.json).
  const WBLCH = "0x4200000000000000000000000000000000000006";
  const L2_CHAIN_ID = 700771;
  const EX_TOKEN = "0x00000000000000000000000000000000000000aa"; // hypothetical L2 token
  const ZERO_ADDR = "0x0000000000000000000000000000000000000000";
  const WEI = 1000000000000000000n; // 1e18 — the L2's 18-dp native/wBLCH scale

  // token-unit string → wei (18 dp) string. Fail-closed on malformed input.
  function toWei(amt) {
    const s = String(amt == null ? "" : amt).trim();
    if (!/^\d+(\.\d+)?$/.test(s)) throw new Error(`enter a positive amount (got '${s}')`);
    const [i, f = ""] = s.split(".");
    const frac = (f + "0".repeat(18)).slice(0, 18);
    return (BigInt(i || "0") * WEI + BigInt(frac || "0")).toString();
  }
  // wei string → trimmed decimal token-unit string (for display).
  function fromWei(wei) {
    const w = BigInt(wei);
    const int = (w / WEI).toString();
    const frac = (w % WEI).toString().padStart(18, "0").replace(/0+$/, "");
    return frac ? `${int}.${frac}` : int;
  }

  P.register({
    id: "swap",
    title: "Swap / DEX",
    short: "Swap",
    desc: "PosternDex (Uniswap-v2 AMM) + wBLCH on the Bloch L2 — real constant-product quote & tx build; execution is preview (L2 not live).",
    group: "Advanced · testnet (zero value)",
    order: 3,
    // PREVIEW, unconditionally — the badge tracks what a user can DO here, not
    // what compiles. Gating on api.isReal("swap_quote") badged the pane "live"
    // on every Tauri build, because the backend really does register swap_quote:
    // the constant-product math and the EVM calldata ARE real and tested. But a
    // live QUOTE is not a live SWAP. chain_id 700771 is unregistered, no L2
    // node/RPC/prover runs, WBLCH is a genesis predeploy that was never deployed,
    // and no pools exist — so nothing here can be signed or broadcast, and the
    // v1 bridge vault is CUSTODY. A "live" badge over that is an overclaim, and
    // the one place a user decides whether to trust a swap screen is the badge.
    //
    // This flips back on capability, not on a flag day: swap_l2_probe already
    // answers honestly whether an L2 endpoint is reachable, so the gate becomes
    // `api.isReal("swap_quote") && l2Reachable` once a devnet exists — the same
    // capability-gated pattern the messenger pane uses for
    // vestnik_matrix_status.built. Until then: preview.
    live: () => false,
    icon: `<svg viewBox="0 0 24 24"><path d="M7 7h11l-3-3M17 17H6l3 3" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>`,

    render(root) {
      const live = api.isReal("swap_quote");
      root.innerHTML = `
        <div class="stack">
          <div class="callout callout-warn">
            <strong>PosternDex + the Bloch L2 are DESIGN-SCAFFOLD — NOT live.</strong>
            <ul style="margin:8px 0 0 18px;padding:0">
              <li><strong>chain_id 700771 is unregistered</strong>; the L2 node / RPC / prover are stubs, and
                  <strong>WBLCH is a genesis predeploy that has never been deployed</strong>. <strong>No pools exist.</strong></li>
              <li>The <strong>quote math</strong> (constant-product <code>x·y=k</code> with the pool fee) and the
                  <strong>swap-transaction BUILD</strong> (EVM calldata) are <strong>REAL and tested</strong>.</li>
              <li><strong>On-chain execution is PREVIEW.</strong> Nothing here is signed or broadcast, and
                  <strong>no tx hash is ever faked</strong>. It will execute once a live L2 devnet/mainnet exists.</li>
              <li>The v1 bridge vault is <strong>CUSTODY</strong>. Zero-value; <strong>BLCH/wBLCH are worthless</strong>; unaudited.</li>
            </ul>
          </div>

          <section class="card">
            <div class="card-head"><h2>1 · Bridge on-ramp <span class="muted">— BLCH ↔ wBLCH (1:1)</span></h2><div class="spacer"></div>
              ${live ? UI.liveBadge("live · real WBLCH calldata") : UI.stubBadge("preview — real calldata, execution needs a live L2")}
            </div>
            <p class="note">PosternDex trades <strong>L2 ERC-20 tokens</strong>, so native BLCH must first be wrapped.
              <strong>Lock BLCH → mint wBLCH 1:1</strong> via the WBLCH predeploy <code class="mono">${WBLCH}</code>
              (WETH9-style). This builds the real <code>deposit()</code> / <code>withdraw(wad)</code> calldata.</p>
            <div class="field-row">
              <label class="field"><span>Amount (BLCH ⇄ wBLCH)</span>
                <input id="sw-wrap-amt" class="mono" placeholder="1.0" value="1"></label>
              <div class="actions" style="align-items:flex-end">
                <button class="btn" id="sw-wrap">Build wrap (deposit)</button>
                <button class="btn" id="sw-unwrap">Build unwrap (withdraw)</button>
              </div>
            </div>
            <div class="kv hidden" id="sw-bridge-out"></div>
          </section>

          <section class="card">
            <div class="card-head"><h2>2 · Swap <span class="muted">— PosternDex AMM (wBLCH ↔ L2 token)</span></h2><div class="spacer"></div>
              ${live ? UI.liveBadge("live · real constant-product quote") : UI.stubBadge("preview — real quote math (BigInt)")}
            </div>
            <p class="note">Constant-product <code>x·y=k</code> with a <strong>0.30% pool fee</strong> (the PosternDex/Uniswap-v2
              default, accruing to LPs). <strong>No live pool exists to read</strong>, so enter hypothetical reserves — the
              quote below is the real <code>getAmountOut</code> either way.</p>
            <div class="grid2">
              <label class="field"><span>Pool reserve — token IN (wBLCH)</span>
                <input id="sw-ri" class="mono" value="1000000"></label>
              <label class="field"><span>Pool reserve — token OUT</span>
                <input id="sw-ro" class="mono" value="3500000"></label>
            </div>
            <div class="field-row">
              <label class="field"><span>Token IN address</span>
                <input id="sw-tin" class="mono" value="${WBLCH}"></label>
              <label class="field"><span>Token OUT address <span class="muted">(hypothetical)</span></span>
                <input id="sw-tout" class="mono" value="${EX_TOKEN}"></label>
            </div>
            <div class="field-row">
              <label class="field"><span>Amount IN (wBLCH)</span>
                <input id="sw-amt" class="mono" value="1000"></label>
              <label class="field"><span>Slippage tolerance</span>
                <select id="sw-slip">
                  <option value="10">0.10%</option>
                  <option value="50" selected>0.50%</option>
                  <option value="100">1.00%</option>
                  <option value="300">3.00%</option>
                </select></label>
              <label class="field"><span>Recipient (L2 / EVM address)</span>
                <input id="sw-to" class="mono" placeholder="${ZERO_ADDR}"></label>
            </div>

            <div class="kv" style="margin-top:8px">
              <div class="kv-row"><span class="k">est. received</span><b class="mono accent" id="sw-out" style="font-size:16px">—</b></div>
              <div class="kv-row"><span class="k">price impact</span><span class="v" id="sw-impact">—</span></div>
              <div class="kv-row"><span class="k">min received (after slippage)</span><span class="v mono" id="sw-min">—</span></div>
              <div class="kv-row"><span class="k">fee</span><span class="v">0.30% → LPs</span></div>
            </div>
            <p class="result-line muted" id="sw-qerr"></p>

            <details style="margin-top:10px">
              <summary class="muted" style="cursor:pointer">L2 RPC endpoint (optional — for the liveness probe)</summary>
              <p class="note" style="margin-top:8px">Leave blank (there is no live L2). A <strong>local devnet</strong> would be a
                loopback URL like <code class="mono">http://127.0.0.1:8545</code>; a remote endpoint needs the same
                user-confirmed custom-endpoint trust as the node RPC. The probe makes a real
                <code>eth_chainId</code> call and reports exactly what answers — never a fake chain.</p>
              <label class="field"><span>L2 EVM RPC URL</span>
                <input id="sw-l2rpc" class="mono" placeholder="(none — L2 not live)"></label>
            </details>

            <div class="actions" style="margin-top:12px">
              <button class="btn btn-primary" id="sw-swap">Build &amp; check swap</button>
              <span class="result-line muted" id="sw-swapres"></span>
            </div>
            <div class="kv hidden" id="sw-swap-out"></div>
          </section>

          ${UI.privacyCaveat()}
        </div>`;

      const qErr = UI.qs("#sw-qerr", root);
      const l2Field = UI.qs("#sw-l2rpc", root);
      if (l2Field) {
        l2Field.value = l2RpcGet();
        const save = () => l2RpcSet(l2Field.value);
        l2Field.addEventListener("change", save);
        l2Field.addEventListener("blur", save);
      }

      // ── live quote (real getAmountOut) — recomputed on every edit ──────────
      async function updateQuote() {
        try {
          const amountIn = toWei(UI.qs("#sw-amt", root).value);
          const reserveIn = toWei(UI.qs("#sw-ri", root).value);
          const reserveOut = toWei(UI.qs("#sw-ro", root).value);
          const slippageBps = parseInt(UI.qs("#sw-slip", root).value, 10) || 0;
          const q = await api.invoke("swap_quote", { amountIn, reserveIn, reserveOut, feeBps: 30, slippageBps });
          UI.qs("#sw-out", root).textContent = `${fromWei(q.amountOut)}`;
          const pct = (q.priceImpactBps / 100).toFixed(2);
          const impEl = UI.qs("#sw-impact", root);
          impEl.textContent = `${pct}%`;
          impEl.className = "v " + (q.priceImpactBps >= 500 ? "err" : q.priceImpactBps >= 100 ? "" : "accent");
          UI.qs("#sw-min", root).textContent = fromWei(q.minReceived);
          UI.setResult(qErr, "", "muted");
          return q;
        } catch (e) {
          UI.qs("#sw-out", root).textContent = "—";
          UI.qs("#sw-impact", root).textContent = "—";
          UI.qs("#sw-min", root).textContent = "—";
          UI.setResult(qErr, `quote: ${e.message || e}`, "err");
          return null;
        }
      }
      ["sw-amt", "sw-ri", "sw-ro"].forEach((id) => {
        const el = UI.qs("#" + id, root);
        if (el) el.addEventListener("input", updateQuote);
      });
      const slipEl = UI.qs("#sw-slip", root);
      if (slipEl) slipEl.addEventListener("change", updateQuote);
      updateQuote(); // fire-and-forget; self-catches

      // ── bridge on-ramp: build real deposit()/withdraw() calldata ───────────
      async function buildBridge(kind) {
        const box = UI.qs("#sw-bridge-out", root);
        try {
          const r = await api.invoke("swap_build_tx", { kind, amountIn: toWei(UI.qs("#sw-wrap-amt", root).value) });
          renderSteps(box, r, kind === "wrap"
            ? "Ready wrap tx (UNSIGNED, PREVIEW — L2 not live). Locks BLCH, mints wBLCH 1:1."
            : "Ready unwrap tx (UNSIGNED, PREVIEW — L2 not live). Burns wBLCH, releases BLCH 1:1.");
        } catch (e) {
          box.classList.remove("hidden");
          box.innerHTML = `<div class="kv-row"><span class="k">error</span><span class="v err">${UI.esc(e.message || String(e))}</span></div>`;
        }
      }
      UI.qs("#sw-wrap", root).addEventListener("click", () => buildBridge("wrap"));
      UI.qs("#sw-unwrap", root).addEventListener("click", () => buildBridge("unwrap"));

      // ── swap: quote → build calldata → probe L2 → honest preview state ─────
      UI.qs("#sw-swap", root).addEventListener("click", async () => {
        const res = UI.qs("#sw-swapres", root);
        const box = UI.qs("#sw-swap-out", root);
        const btn = UI.qs("#sw-swap", root);
        btn.disabled = true;
        UI.setResult(res, "quoting + building the swap tx…", "muted");
        box.classList.add("hidden");
        try {
          const q = await updateQuote();
          if (!q) throw new Error("fix the quote inputs first");
          const to = (UI.qs("#sw-to", root).value || "").trim() || ZERO_ADDR;
          const deadline = Math.floor(Date.now() / 1000) + 1200; // now + 20 min
          const built = await api.invoke("swap_build_tx", {
            kind: "swap",
            amountIn: toWei(UI.qs("#sw-amt", root).value),
            amountOutMin: q.minReceived,
            tokenIn: (UI.qs("#sw-tin", root).value || WBLCH).trim(),
            tokenOut: (UI.qs("#sw-tout", root).value || EX_TOKEN).trim(),
            recipient: to,
            deadline: String(deadline),
          });

          // Probe a configured L2 RPC for liveness (honest; never faked).
          const rpc = l2RpcGet();
          let probe = null;
          if (rpc) {
            UI.setResult(res, "tx built — probing the configured L2 RPC…", "muted");
            probe = await api.invoke("swap_l2_probe", { rpcUrl: rpc, allowCustom: P.rpcAllowCustom() })
              .catch((e) => ({ reachable: false, note: String(e.message || e) }));
          }
          const caption = rpc
            ? (probe && probe.reachable
                ? (probe.isBlochL2
                    ? "L2 reachable (chain 700771 — a local/self-hosted devnet). Tx is BUILT + READY but UNSIGNED — no EVM signer is wired, so execution stays PREVIEW."
                    : "An EVM endpoint answered but its chain_id is NOT 700771 — not the Bloch L2. Refusing to submit. Tx is BUILT + READY (PREVIEW).")
                : `No live L2 reachable at the configured RPC. Tx is BUILT + READY (PREVIEW). ${probe ? UI.esc(probe.note || "") : ""}`)
            : "No L2 RPC configured (expected — the L2 is design-scaffold). Tx is BUILT + READY, UNSIGNED (PREVIEW).";
          renderSteps(box, built, caption);
          UI.setResult(res, "✓ swap tx BUILT + READY — PREVIEW only (nothing signed or broadcast; no fake hash)", "ok");
        } catch (e) {
          UI.setResult(res, `✖ ${e.message || e}`, "err");
        }
        btn.disabled = false;
      });

      // Render a built tx (ordered steps) with the honest preview caption.
      function renderSteps(box, r, caption) {
        box.classList.remove("hidden");
        const steps = (r.steps || []).map((s, i) => {
          const dataId = `sw-data-${i}-${Math.random().toString(36).slice(2, 8)}`;
          return `<div class="kv-row"><span class="k">step ${i + 1}</span><span class="v">${UI.esc(s.label)}</span></div>` +
            `<div class="kv-row"><span class="k">to</span><span class="v mono">${UI.esc(s.to)}</span></div>` +
            `<div class="kv-row"><span class="k">value</span><span class="v mono">${UI.esc(fromWeiSafe(s.value))} BLCH</span></div>` +
            `<div class="kv-row"><span class="k">calldata</span><span class="v mono" id="${dataId}" style="flex:1;word-break:break-all">${UI.esc(s.data)}</span><button class="copy-btn" data-copy="${UI.esc(s.data)}">copy</button></div>`;
        }).join("");
        box.innerHTML =
          `<div class="kv-row"><span class="k">chainId</span><span class="v mono">${UI.esc(String(r.chainId))} <span class="muted">(placeholder — unregistered)</span></span></div>` +
          `<div class="kv-row"><span class="k">signed</span><span class="v">${r.signed ? "yes" : "no — READY, UNSIGNED"}</span></div>` +
          steps +
          `<div class="kv-row"><span class="k">status</span><span class="v accent">${UI.esc(caption)}</span></div>` +
          `<p class="note" style="margin-top:8px">${UI.esc(r.note || "")}</p>`;
        if (UI.wireCopies) UI.wireCopies(box);
      }
      function fromWeiSafe(v) { try { return fromWei(v); } catch { return String(v); } }
    },
  });
})();
