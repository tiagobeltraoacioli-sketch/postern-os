// main.js — Postern Desktop app shell: navigation, status chips, polling.
// Loads after ui.js, api.js and every modules/*.js (classic scripts, no build).
(function () {
  "use strict";
  const P = window.Postern, UI = P.ui, api = P.api;

  const GROUPS = ["Operate", "Protect", "Transmit", "Verify"];
  // Demoted panes (node/wallet/miner) live here: rendered LAST in the nav,
  // collapsed by default. The label itself is the honesty statement.
  const ADVANCED_GROUP = "Advanced · testnet (zero value)";
  const content = document.getElementById("content");
  let current = null;

  // ── theme ───────────────────────────────────────────────────────────────
  function applyTheme(t) {
    document.documentElement.dataset.theme = t;
    P.state.settings.theme = t;
    P.saveSettings();
  }
  applyTheme(P.state.settings.theme || "dark");
  // Mobile nav collapse. The button only shows below 720px (CSS); toggling
  // .nav-collapsed on .app shrinks the sidebar to its brand bar and gives the
  // content the full screen. Starts collapsed on a phone so the first thing you
  // see is a pane, not a menu.
  const appEl = document.querySelector(".app");
  const navToggle = document.getElementById("navToggle");
  const setNav = (collapsed) => {
    appEl.classList.toggle("nav-collapsed", collapsed);
    if (navToggle) navToggle.setAttribute("aria-expanded", String(!collapsed));
  };
  if (navToggle) {
    navToggle.addEventListener("click", () => setNav(!appEl.classList.contains("nav-collapsed")));
  }
  // Collapse by default on a narrow screen.
  if (window.matchMedia("(max-width: 720px)").matches) setNav(true);
  // Expose so navigate() can auto-collapse after a pick.
  P._collapseNavOnMobile = () => {
    if (window.matchMedia("(max-width: 720px)").matches) setNav(true);
  };

  document.getElementById("themeToggle").addEventListener("click", () => {
    applyTheme(P.state.settings.theme === "dark" ? "light" : "dark");
  });

  // ── navigation ──────────────────────────────────────────────────────────
  const nav = document.getElementById("nav");
  function navButton(m) {
    const live = typeof m.live === "function" ? m.live() : !!m.live;
    const btn = document.createElement("button");
    btn.className = "nav-item";
    btn.dataset.module = m.id;
    btn.innerHTML = `${m.icon}<span>${UI.esc(m.short || m.title)}</span><span class="nav-flag ${live ? "live" : ""}">${live ? "live" : "preview"}</span>`;
    btn.addEventListener("click", () => P.navigate(m.id));
    return btn;
  }
  const groupMods = (g) => P.modules.filter((m) => m.group === g).sort((a, b) => a.order - b.order);
  for (const g of GROUPS) {
    const mods = groupMods(g);
    if (!mods.length) continue;
    const box = document.createElement("div");
    box.className = "nav-group";
    box.innerHTML = `<div class="nav-group-label">${UI.esc(g)}</div>`;
    for (const m of mods) box.appendChild(navButton(m));
    nav.appendChild(box);
  }
  // Advanced · testnet (zero value) — always last, collapsed by default.
  {
    const mods = groupMods(ADVANCED_GROUP);
    if (mods.length) {
      const det = document.createElement("details");
      det.className = "nav-group nav-group-advanced"; // no `open` attr → collapsed
      const sum = document.createElement("summary");
      sum.className = "nav-group-label";
      sum.textContent = ADVANCED_GROUP;
      det.appendChild(sum);
      for (const m of mods) det.appendChild(navButton(m));
      nav.appendChild(det);
    }
  }

  P.navigate = (id) => {
    const mod = P.modules.find((m) => m.id === id);
    if (!mod) return;
    // On a phone, picking a pane hides the menu so you land on the pane itself.
    if (P._collapseNavOnMobile) P._collapseNavOnMobile();
    if (current && current.onHide) { try { current.onHide(); } catch (e) { console.error(e); } }
    current = mod;
    P.setState({ route: id });
    try { localStorage.setItem("postern.route", id); } catch { /* private mode */ }
    location.hash = "#/" + id;

    UI.qsa(".nav-item", nav).forEach((b) => b.classList.toggle("active", b.dataset.module === id));
    // Landing on a demoted pane (deep link, chip click) unfolds its group.
    const activeBtn = UI.qs(".nav-item.active", nav);
    const activeDetails = activeBtn && activeBtn.closest ? activeBtn.closest("details.nav-group-advanced") : null;
    if (activeDetails) activeDetails.open = true;
    document.getElementById("moduleTitle").textContent = mod.title;
    document.getElementById("moduleDesc").textContent = mod.desc;

    content.innerHTML = "";
    const box = document.createElement("div");
    box.className = "module";
    content.appendChild(box);
    Promise.resolve(mod.render(box)).catch((e) => {
      console.error(e);
      box.innerHTML = `<div class="callout callout-crit"><strong>Module failed to render.</strong> ${UI.esc(e.message || e)}</div>`;
    });
    content.scrollTop = 0;
    content.focus({ preventScroll: true });
  };

  window.addEventListener("hashchange", () => {
    const id = location.hash.replace(/^#\//, "");
    if (id && id !== P.state.route) P.navigate(id);
  });

  // ── top-bar chips ───────────────────────────────────────────────────────
  const chipNode = document.getElementById("chipNode");
  const chipTor = document.getElementById("chipTor");
  const chipSeal = document.getElementById("chipSeal");
  chipNode.addEventListener("click", () => P.navigate("node"));
  chipTor.addEventListener("click", () => P.navigate("node"));
  chipSeal.addEventListener("click", () => P.navigate("seal"));

  function renderChips(st) {
    const nd = document.getElementById("chipNodeDot");
    const nt = document.getElementById("chipNodeText");
    if (st.node.running) {
      nd.className = "dot ok pulse";
      nt.textContent = st.node.height != null ? `node · h ${UI.fmtNum(st.node.height)}` : "node · running";
      chipNode.classList.add("on");
    } else {
      nd.className = "dot";
      nt.textContent = "node off";
      chipNode.classList.remove("on");
    }

    const td = document.getElementById("chipTorDot");
    const tt = document.getElementById("chipTorText");
    td.className = { ready: "dot ok", bootstrapping: "dot warn pulse", error: "dot crit" }[st.tor] || "dot";
    tt.textContent = { ready: "tor ready", bootstrapping: "tor bootstrap…", error: "tor error" }[st.tor] || "tor idle";
    chipTor.classList.toggle("on", st.tor === "ready");

    const stx = document.getElementById("chipSealText");
    chipSeal.classList.remove("seal-genuine", "seal-compromised");
    if (st.seal.verdict === "genuine") {
      chipSeal.classList.add("seal-genuine");
      stx.textContent = "SEAL · GENUINE";
    } else if (st.seal.verdict === "compromised") {
      chipSeal.classList.add("seal-compromised");
      stx.textContent = "SEAL · COMPROMISED";
    } else {
      // No genuine/compromised verdict. In preview the seal subsystem isn't
      // wired (verdict is honestly capped at unverified), so say so explicitly;
      // with a real backend an unverified result stays UNVERIFIED.
      stx.textContent = st.seal.preview ? "SEAL · PREVIEW" : "SEAL · UNVERIFIED";
    }
  }
  P.onState(renderChips);

  // ── environment badge (honesty: which backend is REALLY serving calls) ──
  // Three truthful states, from api.backendKind:
  //   "tauri"   — native Tauri IPC backend connected.
  //   "browser" — the browser backend: the real hybrid-PQ WASM core actually
  //               LOADED + the same-origin /rpc proxy. Read-only node access;
  //               no node runs in the browser and no mining is possible.
  //   otherwise — no backend at all: labelled browser preview.
  // backendKind flips to "browser" only once the WASM core has really loaded
  // (it initialises async), so we re-render on the poll tick instead of
  // stamping a one-shot value that would lie in either direction.
  function renderEnvBadge() {
    const kind = api.backendKind || (api.hasBackend ? "tauri" : "none");
    document.getElementById("envBadge").innerHTML =
      kind === "tauri"
        ? `tauri backend · <span style="color:var(--ok)">connected</span>`
        : kind === "browser"
          ? `browser backend · <span style="color:var(--ok)">real PQ core + public node (read-only, no mining)</span>`
          : `no backend · <span style="color:var(--warn)">browser preview</span>`;
  }
  renderEnvBadge();

  // ── node polling ────────────────────────────────────────────────────────
  // Two independent facts: (1) is a LOCAL node process running (node_status —
  // only meaningful in sovereign mode), and (2) is the ACTIVE RPC endpoint
  // reachable. We poll the active RPC ALWAYS — in the default public mode a
  // fresh install has no local node yet must still show live chain state — so
  // "connected to the public node" works on download, not "connection refused".
  async function poll() {
    const node = { ...P.state.node };
    try {
      const st = await api.invoke("node_status");
      node.running = !!st.running;
      node.pid = st.pid ?? null;
    } catch { /* backend unreachable — keep last local-process state */ }
    try {
      // Reads only — never a key/mnemonic/password. Allowlist-pinned in Rust.
      const r = await P.rpc("getnetworkinfo", []);
      const info = r && !r.error ? r.result : null;
      if (info) {
        node.height = info.blocks ?? node.height;
        node.peers = info.peers ?? node.peers;
        node.mempool = info.mempool ?? node.mempool;
        node.syncing = !!info.syncing;
        node.rpcOk = true;
      } else {
        node.rpcOk = false;
      }
    } catch { node.rpcOk = false; }
    P.setState({ node });
    renderEnvBadge(); // backendKind may flip once the async WASM core loads
  }
  setInterval(poll, 2500);
  poll();

  // ── Panic Lock (global) ─────────────────────────────────────────────────
  P.doPanic = async () => {
    // Panic must fail-CLOSED and fail-LOUD. If the seal call errors we do not
    // silently show the reassuring overlay — we re-check the vault, and only
    // stay quiet when it is genuinely sealed (e.g. nothing was open to seal).
    // A vault left unlocked after a panic is a real failure the user must see.
    let sealFailed = false;
    try {
      await api.invoke("panic");
    } catch {
      try {
        const v = await api.invoke("vault_status");
        sealFailed = !!v.unlocked;
      } catch { sealFailed = true; } // can't even confirm state → warn
    }
    try { P.setState({ vault: await api.invoke("vault_status") }); } catch { /* status unavailable */ }
    const ov = document.getElementById("panicOverlay");
    ov.hidden = false;
    setTimeout(() => { ov.hidden = true; }, 2600);
    if (sealFailed) {
      UI.toast("Panic may NOT have sealed the vault — re-lock manually in the Vault pane.", "err", 7000);
    }
    if (P.state.route === "vault" || P.state.route === "panic") P.navigate(P.state.route); // re-render locked view
  };
  document.getElementById("globalPanic").addEventListener("click", P.doPanic);
  ["keydown"].forEach((ev) =>
    window.addEventListener(ev, (e) => {
      // Ctrl/Cmd+Shift+L — panic from anywhere
      if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key.toLowerCase() === "l") {
        e.preventDefault();
        P.doPanic();
      }
    }));
  document.getElementById("panicOverlay").addEventListener("click", (e) => { e.currentTarget.hidden = true; });

  // ── initial vault status ────────────────────────────────────────────────
  api.invoke("vault_status").then((v) => P.setState({ vault: v })).catch(() => {});

  // ── boot ────────────────────────────────────────────────────────────────
  // Default landing: the first visible (non-advanced) nav item — node/wallet
  // are demoted to the collapsed Advanced · testnet group and no longer boot.
  const firstVisible = (GROUPS.flatMap(groupMods)[0] || P.modules[0] || {}).id;
  const initial = location.hash.replace(/^#\//, "")
    || (() => { try { return localStorage.getItem("postern.route"); } catch { return null; } })()
    || firstVisible;
  P.navigate(P.modules.some((m) => m.id === initial) ? initial : firstVisible);
  renderChips(P.state);

  if (!api.hasBackend) {
    if (api.backendKind === "browser") {
      UI.toast("Browser backend — real hybrid-PQ WASM core; node access is read-only via /rpc. No node runs in the browser and no mining is possible; native-only surfaces stay labelled preview.", "info", 7000);
    } else {
      UI.toast("Browser preview — no Tauri backend. Live commands are replaced by clearly-labeled local previews.", "warn", 6000);
    }
  }
})();
