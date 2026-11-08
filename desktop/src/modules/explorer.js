// modules/explorer.js — Explorer: chain overview, recent blocks, lookups.
// Wired to the REAL `rpc` Tauri command (the node's JSON-RPC surface:
// getnetworkinfo, getchainstats, getdaginfo, getrecentblocks,
// getblockbyheight, getblock, getaddressinfo). Renders defensively — unknown
// response shapes fall back to a raw JSON view.
(function () {
  "use strict";
  const P = window.Postern, UI = P.ui, api = P.api;

  async function rpc(method, params = []) {
    const r = await api.invoke("rpc", { url: P.rpcUrl(), method, params });
    if (r && r.error) throw new Error(r.error.message || JSON.stringify(r.error));
    return r ? r.result : undefined;
  }

  P.register({
    id: "explorer",
    title: "Explorer",
    desc: "Chain telemetry on the node's RPC — blocks, DAG state, address lookups.",
    group: "Operate",
    order: 3,
    live: () => api.isReal("rpc"),
    icon: `<svg viewBox="0 0 24 24"><circle cx="10.5" cy="10.5" r="6.5" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M15.5 15.5L21 21" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>`,

    render(root) {
      const live = api.isReal("rpc");
      root.innerHTML = `
        <div class="stack">
          <section class="card">
            <div class="card-head"><h2>Chain overview</h2><div class="spacer"></div>
              ${live ? UI.liveBadge("live · json-rpc") : UI.stubBadge("preview — simulated chain")}
              <button class="btn btn-ghost btn-sm" id="xp-refresh">↻ refresh</button>
            </div>
            <div class="stats">
              <div class="stat"><b class="accent" id="xp-height">—</b><span>height</span></div>
              <div class="stat"><b id="xp-peers">—</b><span>peers</span></div>
              <div class="stat"><b id="xp-mempool">—</b><span>mempool</span></div>
              <div class="stat"><b id="xp-tips">—</b><span>dag tips</span></div>
              <div class="stat"><b id="xp-diff">—</b><span>difficulty</span></div>
              <div class="stat"><b id="xp-hash">—</b><span>hashrate</span></div>
            </div>
            <div id="xp-err" style="margin-top:10px"></div>
          </section>

          <section class="card">
            <div class="card-head"><h2>Recent blocks</h2></div>
            <div class="scroll-x">
              <table class="data" id="xp-blocks">
                <thead><tr><th>height</th><th>hash</th><th>txs</th><th class="num">size</th><th>time</th></tr></thead>
                <tbody><tr><td colspan="5">${UI.loadingState("fetching recent blocks…")}</td></tr></tbody>
              </table>
            </div>
          </section>

          <section class="card">
            <div class="card-head"><h2>Lookup</h2></div>
            <div class="actions" style="margin-top:0">
              <select id="xp-kind" class="input" style="width:auto">
                <option value="height">block height</option>
                <option value="hash">block hash</option>
                <option value="address">address</option>
              </select>
              <input id="xp-q" class="input mono" style="flex:1;min-width:220px" placeholder="e.g. 12873">
              <button class="btn btn-primary" id="xp-go">Look up</button>
            </div>
            <pre class="json-view" id="xp-result">—</pre>
          </section>

          ${UI.privacyCaveat()}
        </div>`;

      const errEl = UI.qs("#xp-err", root);
      const set = (id, v) => { UI.qs("#" + id, root).textContent = v ?? "—"; };

      async function refresh() {
        errEl.innerHTML = "";
        try {
          const net = await rpc("getnetworkinfo");
          set("xp-height", UI.fmtNum(net?.blocks));
          set("xp-peers", UI.fmtNum(net?.peers));
          set("xp-mempool", UI.fmtNum(net?.mempool));
        } catch (e) {
          errEl.innerHTML = UI.errorState(e);
          return;
        }
        // optional richer stats — tolerate nodes that don't expose them
        try {
          const dag = await rpc("getdaginfo");
          set("xp-tips", UI.fmtNum(dag?.tips));
        } catch { set("xp-tips", "—"); }
        try {
          const cs = await rpc("getchainstats");
          set("xp-diff", cs?.difficulty ?? "—");
          set("xp-hash", cs?.hashrate ?? "—");
        } catch { set("xp-diff", "—"); set("xp-hash", "—"); }
        try {
          const blocks = await rpc("getrecentblocks", [15]);
          renderBlocks(Array.isArray(blocks) ? blocks : blocks?.blocks || []);
        } catch { /* leave table as-is */ }
      }

      function renderBlocks(blocks) {
        const tb = UI.qs("#xp-blocks tbody", root);
        if (!blocks.length) { tb.innerHTML = `<tr><td colspan="5">${UI.emptyState("No blocks returned.")}</td></tr>`; return; }
        tb.innerHTML = blocks.map((b) => `
          <tr data-hash="${UI.esc(b.hash || "")}" style="cursor:pointer" title="click for full block">
            <td>${UI.esc(b.height ?? "—")}</td>
            <td title="${UI.esc(b.hash || "")}">${UI.esc(UI.shortHex(b.hash, 10))}</td>
            <td>${UI.esc(b.txs ?? b.tx_count ?? "—")}</td>
            <td class="num">${UI.esc(b.size != null ? UI.fmtBytes(b.size) : "—")}</td>
            <td>${UI.esc(b.time ? UI.timeAgo(b.time) : "—")}</td>
          </tr>`).join("");
        UI.qsa("tr[data-hash]", tb).forEach((tr) =>
          tr.addEventListener("click", () => lookup("hash", tr.dataset.hash)));
      }

      async function lookup(kind, q) {
        const out = UI.qs("#xp-result", root);
        if (!q) { out.innerHTML = UI.emptyState("Enter a query first."); return; }
        out.innerHTML = UI.loadingState("querying…");
        try {
          let res;
          if (kind === "height") res = await rpc("getblockbyheight", [parseInt(q, 10)]);
          else if (kind === "hash") res = await rpc("getblock", [q]);
          else res = await rpc("getaddressinfo", [q]);
          out.textContent = JSON.stringify(res, null, 2);
        } catch (e) {
          out.innerHTML = UI.errorState(e);
        }
      }

      UI.qs("#xp-refresh", root).addEventListener("click", refresh);
      UI.qs("#xp-go", root).addEventListener("click", () =>
        lookup(UI.qs("#xp-kind", root).value, UI.qs("#xp-q", root).value.trim()));
      UI.qs("#xp-q", root).addEventListener("keydown", (e) => {
        if (e.key === "Enter") lookup(UI.qs("#xp-kind", root).value, UI.qs("#xp-q", root).value.trim());
      });

      refresh();
      this._timer = setInterval(() => { if (root.isConnected) refresh(); }, 6000);
    },

    onHide() {
      if (this._timer) { clearInterval(this._timer); this._timer = null; }
    },
  });
})();
