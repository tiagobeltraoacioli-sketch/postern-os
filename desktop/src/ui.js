// ui.js — Postern shared namespace, tiny store, and DOM helpers.
// Classic script (no ES modules) so the app also runs from file:// previews.
(function () {
  "use strict";

  const P = (window.Postern = window.Postern || {});
  P.modules = [];
  P.register = (mod) => P.modules.push(mod);

  // Strict TCP-port validation: an integer 1–65535 → the number, anything
  // else → null. rpcPort is persisted (localStorage) and interpolated into
  // URLs and HTML, so a poisoned value like `80@evil.com` (URL-authority
  // swap) or `"><img onerror=…>` (attribute breakout) must never pass
  // through — digits only, no signs, no trailing garbage. Declared before
  // P.state below because loadSettings() runs during that initializer.
  const DEFAULT_RPC_PORT = 8645;
  function sanePort(v) {
    const s = String(v ?? "").trim();
    if (!/^[0-9]{1,5}$/.test(s)) return null;
    const n = Number(s);
    return n >= 1 && n <= 65535 ? n : null;
  }
  P.sanePort = sanePort;

  // The canonical MAINNET bootstrap peer (node3). Kept in sync with the Rust
  // backend's CANONICAL_PEER_MULTIADDR — a fresh local node needs at least one
  // bootstrap peer or it never learns the tip and stays stuck at genesis.
  // Declared before P.state below because loadSettings() runs during that
  // initializer (same reason as DEFAULT_RPC_PORT above).
  const CANONICAL_PEER = "/ip4/45.32.154.137/tcp/16110";
  P.CANONICAL_PEER = CANONICAL_PEER;

  // Frontend mirror of the backend validate_peer_multiaddr: accepts ONLY a
  // strict /ip4/<IPv4>/tcp/<port> multiaddr, returns the trimmed value or null.
  // Defense in depth — the backend still fails closed.
  function sanePeer(v) {
    const s = String(v ?? "").trim();
    const m = /^\/ip4\/(\d{1,3}(?:\.\d{1,3}){3})\/tcp\/(\d{1,5})$/.exec(s);
    if (!m) return null;
    if (m[1].split(".").some((o) => Number(o) > 255)) return null;
    if (sanePort(m[2]) === null) return null;
    return s;
  }
  P.sanePeer = sanePeer;

  // ── connectivity model ───────────────────────────────────────────────────
  // A freshly-installed desktop wallet must work immediately with NO local
  // node, so the DEFAULT is a REMOTE public node (thin-client). The user can
  // switch to their own local node (sovereign) or a confirmed custom endpoint.
  // HONESTY: remote means trusting that node for balance display + broadcast;
  // keys/mnemonics/passwords NEVER leave the device (signing is 100% local) —
  // only reads and already-signed sendrawtransaction bytes touch the RPC.
  // The official public RPC is the same-origin `/rpc` proxy on posternlabs.com —
  // a Cloudflare Pages Function that forwards reads + already-signed
  // `sendrawtransaction` bytes to the CANONICAL Bloch node over HTTPS. (Replaces
  // the old blochv-node.fly.dev relay, which had fallen onto a lighter fork.)
  const OFFICIAL_PUBLIC_RPC = "https://posternlabs.com/rpc";
  P.OFFICIAL_PUBLIC_RPC = OFFICIAL_PUBLIC_RPC;
  P.OFFICIAL_PUBLIC_RPC_HOST = "posternlabs.com";

  // Frontend mirror of the backend allowlist (main.rs validate_rpc_url). Used
  // to vet a user-typed custom endpoint before it is confirmed. Returns the
  // normalized url string or null. Mirrors, but does not replace, the backend
  // gate (defense in depth — the backend still fails closed).
  function saneRpcUrl(v) {
    const s = String(v ?? "").trim();
    let m = /^(https?):\/\/([^/?#]+)([/?#].*)?$/i.exec(s);
    if (!m) return null;
    const authority = m[2];
    if (authority.includes("@")) return null;      // userinfo authority swap
    // host[:port] — reject an unbracketed IPv6, validate an explicit port.
    let host = authority, port = null;
    if (authority.startsWith("[")) {
      const end = authority.indexOf("]");
      if (end < 0) return null;
      host = authority.slice(1, end);
      const after = authority.slice(end + 1);
      if (after) { if (after[0] !== ":") return null; port = after.slice(1); }
    } else if (authority.includes(":")) {
      const i = authority.lastIndexOf(":");
      host = authority.slice(0, i); port = authority.slice(i + 1);
      if (host.includes(":")) return null;
    }
    if (!host) return null;
    if (port !== null && sanePort(port) === null) return null;
    return s;
  }
  P.saneRpcUrl = saneRpcUrl;

  const RPC_MODES = new Set(["public", "local", "custom"]);

  // True when the BROWSER backend (the PWA's PosternBrowser registry) is the
  // active backend — api.js sets api.backendKind. Evaluated at call time, not
  // load time: ui.js loads before api.js, and the flag never changes after
  // boot. In browser mode ALL RPC goes through the RELATIVE same-origin
  // `/rpc` path (the Cloudflare Pages Function in functions/rpc.js): the
  // browser cannot reach a local node (plain HTTP = mixed content) or a
  // custom endpoint (CORS), so offering those modes would be an overclaim.
  const browserBackend = () => !!(P.api && P.api.backendKind === "browser");

  // ── tiny observable state ───────────────────────────────────────────────
  const listeners = new Set();
  P.state = {
    route: null,
    node: { running: false, pid: null, height: null, peers: null, mempool: null, syncing: false, rpcOk: false },
    tor: "idle", // idle | bootstrapping | ready | error
    seal: { verdict: "unverified", preview: true }, // unverified | genuine | compromised
    vault: { exists: false, unlocked: false, count: 0 },
    settings: loadSettings(),
  };
  P.setState = (patch) => {
    Object.assign(P.state, patch);
    listeners.forEach((f) => { try { f(P.state); } catch (e) { console.error(e); } });
  };
  P.onState = (f) => { listeners.add(f); return () => listeners.delete(f); };

  function loadSettings() {
    const def = {
      binary: "bloch", dataDir: "./bloch-data", rpcPort: DEFAULT_RPC_PORT,
      // Canonical chain is MAINNET; a fresh node must not mine and must not run
      // testnet (the public chain is mainnet). Bootstrap from the canonical peer.
      mine: false, testnet: false, peer: CANONICAL_PEER, theme: "dark",
      // Default = remote public node so a fresh install works with no local node.
      rpcMode: "public", rpcCustom: "", rpcCustomConfirmed: false,
    };
    let s;
    try { s = Object.assign(def, JSON.parse(localStorage.getItem("postern.settings") || "{}")); }
    catch { s = def; }
    // Sanitize persisted values at the trust boundary: localStorage is
    // attacker-influenceable state, never a source of URL/HTML fragments.
    s.rpcPort = sanePort(s.rpcPort) ?? DEFAULT_RPC_PORT;
    if (!RPC_MODES.has(s.rpcMode)) s.rpcMode = "public";
    s.rpcCustom = saneRpcUrl(s.rpcCustom) ? String(s.rpcCustom).trim() : "";
    // A confirmation only counts if the custom URL is still present + well-formed.
    s.rpcCustomConfirmed = !!s.rpcCustomConfirmed && !!s.rpcCustom;
    // A poisoned/absent peer falls back to the canonical mainnet peer rather than
    // an empty field (which would spawn a node that never syncs).
    s.peer = sanePeer(s.peer) ?? CANONICAL_PEER;
    s.mine = !!s.mine;
    s.testnet = !!s.testnet;
    return s;
  }
  P.saveSettings = () => {
    try { localStorage.setItem("postern.settings", JSON.stringify(P.state.settings)); } catch { /* private mode */ }
  };

  // Resolve the active RPC URL from the selected connectivity mode. Every mode
  // yields an allowlisted URL (see validate_rpc_url on the backend); a custom
  // endpoint that isn't confirmed+valid falls back to the public node rather
  // than silently pointing nowhere. Re-validated at call time so a runtime-
  // mutated setting can never smuggle an authority/path in.
  P.rpcUrl = () => {
    // Browser (PWA) backend: ALWAYS the same-origin proxy, as a RELATIVE path
    // — the browser resolves it against the page's own origin, so no absolute
    // origin is ever hardcoded here (and the no-external-origin scan stays
    // honest with zero allowlist edits).
    if (browserBackend()) return "/rpc";
    const s = P.state.settings;
    if (s.rpcMode === "local") {
      return `http://127.0.0.1:${sanePort(s.rpcPort) ?? DEFAULT_RPC_PORT}`;
    }
    if (s.rpcMode === "custom" && s.rpcCustomConfirmed) {
      const u = saneRpcUrl(s.rpcCustom);
      if (u) return u;
    }
    return OFFICIAL_PUBLIC_RPC; // default: remote public node
  };
  // True only for a confirmed custom endpoint — the backend requires this to
  // accept a non-allowlisted host (explicit user confirmation, fail-closed).
  P.rpcAllowCustom = () => {
    // Browser backend: NEVER. A custom endpoint is unreachable from a browser
    // (CORS + mixed content), and pretending otherwise is exactly the
    // overclaim this repo forbids — the only endpoint is the same-origin
    // `/rpc` proxy.
    if (browserBackend()) return false;
    const s = P.state.settings;
    return s.rpcMode === "custom" && s.rpcCustomConfirmed && !!saneRpcUrl(s.rpcCustom)
      && P.rpcUrl() !== OFFICIAL_PUBLIC_RPC;
  };
  // Honest human label for the active trust mode (remote vs local).
  P.rpcTrustLabel = () => {
    if (browserBackend()) {
      // Name the actual upstream. "a public node" tells a user nothing they can
      // act on; the honest question behind this label is "whose node am I
      // trusting, and with what?", and it deserves a concrete answer.
      return "canonical public node 45.32.154.137, reached through this site's same-origin /rpc proxy. "
           + "The proxy adds reachability, not security: it forwards READS (balance, height, UTXOs) and "
           + "the single WRITE that matters (sendrawtransaction, i.e. broadcasting a transaction you already "
           + "signed on this device). That node can therefore show you a stale or wrong balance, or drop a "
           + "broadcast — it can NOT spend, because it never sees a key or a seed phrase: signing happens "
           + "in the WASM core in this tab. To depend on nobody, run your own node and use the desktop app.";
    }
    const s = P.state.settings;
    if (s.rpcMode === "local") return "your own node (local · sovereign)";
    if (P.rpcAllowCustom()) return "custom node (remote — you trust it for reads + broadcast)";
    return `public node (remote — trusting ${P.OFFICIAL_PUBLIC_RPC_HOST} for reads + broadcast; keys stay on-device)`;
  };
  // Convenience: an allowlist-pinned read/broadcast RPC call on the active
  // endpoint. Keys/mnemonics/passwords are NEVER passed here — only reads and
  // already-locally-signed sendrawtransaction bytes.
  P.rpc = (method, params) =>
    P.api.invoke("rpc", { url: P.rpcUrl(), method, params, allowCustom: P.rpcAllowCustom() });
  // Onboarding hint when the active RPC is unreachable — never a raw
  // "connection refused". Steers the user to the alternative trust mode.
  P.rpcReachHint = () => {
    if (browserBackend()) {
      // No "start your own node" steer here: in a browser the Node pane is a
      // labelled preview and cannot spawn anything.
      return "the same-origin /rpc proxy (or the canonical node behind it) is unreachable — check your network and retry";
    }
    const s = P.state.settings;
    if (s.rpcMode === "local") {
      return "no local node reachable — start it in the Node pane, or switch to the public node in Connection";
    }
    return `no node reachable at ${P.OFFICIAL_PUBLIC_RPC_HOST} — check your network, or start your own node in the Node pane`;
  };

  // ── DOM helpers ─────────────────────────────────────────────────────────
  const UI = (P.ui = {});

  UI.qs = (sel, root) => (root || document).querySelector(sel);
  UI.qsa = (sel, root) => Array.from((root || document).querySelectorAll(sel));

  UI.esc = (s) =>
    String(s ?? "").replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  UI.toast = (msg, kind = "info", ms = 3200) => {
    const box = document.getElementById("toasts");
    if (!box) return;
    const t = document.createElement("div");
    t.className = `toast ${kind}`;
    t.textContent = msg;
    box.appendChild(t);
    setTimeout(() => t.remove(), ms);
  };

  UI.copy = async (text, label = "Copied") => {
    try {
      await navigator.clipboard.writeText(text);
      UI.toast(label, "ok", 1600);
    } catch {
      // clipboard API can be unavailable in plain file:// previews
      const ta = document.createElement("textarea");
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand("copy"); UI.toast(label, "ok", 1600); }
      catch { UI.toast("Copy failed", "err"); }
      ta.remove();
    }
  };

  UI.download = (name, data, mime = "application/octet-stream") => {
    const blob = data instanceof Blob ? data : new Blob([data], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 4000);
  };

  // ── formatting ──────────────────────────────────────────────────────────
  UI.fmtNum = (n) => (n == null || n === "" ? "—" : Number(n).toLocaleString("en-US"));
  UI.fmtBytes = (n) => {
    if (n == null) return "—";
    const u = ["B", "KB", "MB", "GB"];
    let i = 0, v = n;
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${u[i]}`;
  };
  UI.shortHex = (h, n = 8) => {
    const s = String(h ?? "");
    return s.length <= n * 2 + 1 ? s : `${s.slice(0, n)}…${s.slice(-n)}`;
  };
  UI.timeAgo = (tsSec) => {
    if (!tsSec) return "—";
    const d = Math.max(0, Math.floor(Date.now() / 1000 - tsSec));
    if (d < 60) return `${d}s ago`;
    if (d < 3600) return `${Math.floor(d / 60)}m ago`;
    if (d < 86400) return `${Math.floor(d / 3600)}h ago`;
    return `${Math.floor(d / 86400)}d ago`;
  };
  UI.nowHHMM = () => {
    const d = new Date();
    return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
  };

  // ── bytes / encoding ────────────────────────────────────────────────────
  UI.randBytes = (n) => crypto.getRandomValues(new Uint8Array(n));
  UI.randHex = (n) => UI.toHex(UI.randBytes(n));
  UI.toHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  UI.fromHex = (hex) => {
    const clean = String(hex).trim().replace(/^0x/, "");
    const out = new Uint8Array(clean.length >> 1);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
    return out;
  };
  UI.toB64 = (bytes) => {
    let s = "";
    const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    for (let i = 0; i < arr.length; i += 0x8000) s += String.fromCharCode.apply(null, arr.subarray(i, i + 0x8000));
    return btoa(s);
  };
  UI.fromB64 = (b64) => Uint8Array.from(atob(String(b64).trim()), (c) => c.charCodeAt(0));
  UI.utf8 = (s) => new TextEncoder().encode(s);
  UI.utf8dec = (b) => new TextDecoder().decode(b);
  UI.sha256 = async (bytes) => new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));

  // ── shared HTML snippets ────────────────────────────────────────────────
  /** Consistent loading placeholder — use wherever a pane is fetching data. */
  UI.loadingState = (msg = "loading…") =>
    `<div class="state state-loading" role="status" aria-live="polite"><span class="state-dot" aria-hidden="true"></span><span>${UI.esc(msg)}</span></div>`;

  /** Consistent empty placeholder — use wherever a fetched list has no items. */
  UI.emptyState = (msg = "Nothing here yet.", hint = "") =>
    `<div class="state state-empty"><span>${UI.esc(msg)}</span>${hint ? `<span class="state-hint">${UI.esc(hint)}</span>` : ""}</div>`;

  /** Consistent error block — accepts an Error or any throwable value. */
  UI.errorState = (err) => {
    const msg = String((err && err.message) || err || "unknown error");
    return `<div class="state state-error" role="alert"><span>✖ ${UI.esc(msg)}</span></div>`;
  };

  /** One shared, honest privacy caveat — rendered unconditionally in every pane.
      The marker text is fixed; tests assert it verbatim. Never weaken it. */
  UI.privacyCaveat = () =>
    `<div class="pane-caveat">UNAUDITED · hardened, not anonymous — metadata (who talks to whom, when) is not hidden; not a TEE until real hardware; zero-value pre-mainnet testnet.</div>`;

  /** Honest-stub badge: shown wherever the backing Tauri command doesn't exist yet. */
  UI.stubBadge = (note = "preview — backend pending") =>
    `<span class="badge badge-stub" title="This flow runs on a local, clearly-labeled preview engine. The audited Rust core is not wired to the desktop backend yet.">${UI.esc(note)}</span>`;

  UI.liveBadge = (note = "live") =>
    `<span class="badge badge-live" title="Wired to a real Tauri backend command.">${UI.esc(note)}</span>`;

  UI.copyBtn = (value, label = "copy") =>
    `<button class="copy-btn" data-copy="${UI.esc(value)}">${UI.esc(label)}</button>`;

  /** Wire all [data-copy] buttons inside root. */
  UI.wireCopies = (root) => {
    UI.qsa("[data-copy]", root).forEach((b) => {
      b.addEventListener("click", () => UI.copy(b.dataset.copy));
    });
  };

  /** Wire a dropzone: click + drag&drop → cb(File). */
  UI.wireDropzone = (zone, input, cb) => {
    zone.addEventListener("click", () => input.click());
    zone.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); input.click(); } });
    input.addEventListener("change", () => { if (input.files[0]) cb(input.files[0]); input.value = ""; });
    ["dragover", "dragenter"].forEach((ev) =>
      zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.add("drag"); }));
    ["dragleave", "drop"].forEach((ev) =>
      zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.remove("drag"); }));
    zone.addEventListener("drop", (e) => {
      const f = e.dataTransfer?.files?.[0];
      if (f) cb(f);
    });
  };

  UI.setResult = (el, msg, kind = "muted") => {
    el.className = `result-line ${kind}`;
    el.textContent = msg;
  };
})();
