// desktop/src/browser/rpc.js — the BROWSER backend's `rpc` command: a POST to
// the RELATIVE same-origin `/rpc` path (the Cloudflare Pages Function in
// functions/rpc.js, already live on posternlabs.com), registered into the
// PosternBrowser registry so api.invoke("rpc", …) routes here when
// api.backendKind === "browser".
//
// Classic script (no ES modules), matching ui.js / api.js / modules/*.js.
//
// TRUST / HONESTY (mirrors functions/rpc.js verbatim)
// ---------------------------------------------------
// - Reads come from the PUBLIC CANONICAL node via the same-origin proxy. The
//   proxy adds REACHABILITY (HTTPS same-origin for a browser that cannot speak
//   the node's plain-HTTP RPC), NOT security — you are trusting that node for
//   read answers exactly as the desktop's "public node" mode does.
// - The ONLY write is `sendrawtransaction`: already-locally-signed bytes.
//   Keys / mnemonics / passwords NEVER pass through here.
// - The method allowlist below is a client-side MIRROR of the edge Function's
//   READ_METHODS/WRITE_METHODS. Fail-closed: anything outside it throws HERE,
//   before any fetch — the pane can never issue a method the edge would
//   bounce. Mining writes (submitblock/getblocktemplate) are NOT exposed.
// - No custom endpoint in browser mode, ever: a browser cannot reach a user's
//   node over plain HTTP (mixed content) or a foreign origin (CORS), and
//   pretending otherwise would be an overclaim. This handler talks to the
//   RELATIVE `/rpc` path and nothing else; a foreign url argument throws.
// - On HTTP 200 the upstream JSON-RPC envelope ({jsonrpc,id,result} or
//   {…,error}) is returned verbatim — panes already handle `.error`. On a
//   network failure / non-200 / unparseable body this THROWS, so panes render
//   the honest reach hint instead of a fabricated height.
(function () {
  "use strict";

  // ── client-side mirror of functions/rpc.js READ_METHODS ─────────────────
  const READ_METHODS = new Set([
    // chain state
    "getnetworkinfo", "getblockcount", "getdaginfo", "getmempoolinfo",
    "getpeerinfo", "getpeers", "getchainstats", "gethashrate",
    "getsupplydistribution", "getdifficultyhistory", "getblocktimepercentiles",
    "getpools", "getattestation", "gettipinfo",
    // blocks
    "getblockhash", "getblock", "getblockbyheight", "getrecentblocks",
    // transactions
    "gettransaction", "gettxstatus", "decoderawtransaction",
    // addresses / wallet reads
    "getbalance", "getaddressbalance", "getaddressbalance_at_height",
    "getaddressinfo", "getaddresscount", "getutxos", "listtransactions",
  ]);
  // The ONLY write the proxy forwards — already-signed tx bytes. The edge
  // attaches its server-side X-API-Key secret to this method alone.
  const WRITE_METHODS = new Set(["sendrawtransaction"]);

  // The one endpoint this backend will ever talk to: the RELATIVE same-origin
  // proxy path. Never an absolute URL — the browser resolves it against the
  // page's own origin, which is also what keeps the no-external-origin test
  // honest with zero allowlist edits.
  const RPC_PATH = "/rpc";

  const FETCH_TIMEOUT_MS = 12000;

  /**
   * Browser `rpc` command. Args mirror the Tauri command's surface
   * ({ url, method, params, allowCustom }) so P.rpc()/panes need no changes:
   * - `method`/`params` → forwarded as a JSON-RPC 2.0 POST to `/rpc`.
   * - `url` → must be the relative `/rpc` (P.rpcUrl() in browser mode) or
   *   absent; any other value throws (fail-closed — no foreign origins).
   * - `allowCustom` → meaningless here (P.rpcAllowCustom() is false in
   *   browser mode); a truthy value throws rather than silently ignoring an
   *   intent this backend cannot honor.
   */
  async function rpcBrowser(args) {
    const { url, method, params, allowCustom } = args || {};

    if (typeof method !== "string" || !method) {
      throw new Error("rpc: missing method");
    }
    // Fail-closed allowlist gate — BEFORE any network I/O.
    if (!READ_METHODS.has(method) && !WRITE_METHODS.has(method)) {
      throw new Error(
        `rpc ${method}: not in the same-origin /rpc proxy allowlist — refused client-side (the edge would reject it too)`);
    }
    if (url !== undefined && url !== RPC_PATH) {
      throw new Error(
        `rpc ${method}: the browser backend only talks to the same-origin ${RPC_PATH} proxy — custom endpoints need the native desktop app`);
    }
    if (allowCustom) {
      throw new Error(
        `rpc ${method}: custom endpoints are not reachable from the browser (CORS/mixed content) — use the native desktop app`);
    }

    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), FETCH_TIMEOUT_MS);
    let resp;
    try {
      resp = await fetch(RPC_PATH, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params: params || [] }),
        signal: ctl.signal,
      });
    } catch (e) {
      clearTimeout(timer);
      // Honest reach failure — the panes render P.rpcReachHint(), never a
      // fabricated height.
      throw new Error(`rpc ${method}: same-origin /rpc proxy unreachable (network error)`);
    }
    clearTimeout(timer);

    if (!resp.ok) {
      throw new Error(`rpc ${method}: /rpc proxy error (HTTP ${resp.status})`);
    }
    let envelope;
    try {
      envelope = await resp.json();
    } catch (e) {
      throw new Error(`rpc ${method}: /rpc proxy returned a non-JSON body`);
    }
    // HTTP 200 envelope verbatim — including JSON-RPC {error:…} answers (the
    // edge normalizes upstream failures to those); panes already check .error.
    return envelope;
  }

  // ── registration into the PosternBrowser backend registry ───────────────
  // Load-order tolerant seam: if the registry script loaded first and exposes
  // register(), use it; otherwise park the handler in the shared `commands`
  // map on the same window.PosternBrowser object, which the registry adopts
  // when it boots. Either way the command name is exactly "rpc" — the same
  // name api.js's REAL set and the panes already use.
  const PB = (window.PosternBrowser = window.PosternBrowser || {});
  PB.commands = PB.commands || {};
  PB.commands.rpc = rpcBrowser;
  if (typeof PB.register === "function") PB.register("rpc", rpcBrowser);

  // Exposed for tests + other browser-backend modules (e.g. wallet_send needs
  // to know sendrawtransaction is the one legal write). Frozen: nobody widens
  // the allowlist at runtime.
  PB.rpcReadMethods = Object.freeze([...READ_METHODS]);
  PB.rpcWriteMethods = Object.freeze([...WRITE_METHODS]);
  PB.rpcPath = RPC_PATH;
})();
