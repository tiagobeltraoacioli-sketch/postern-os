// desktop/src/modules/security.test.mjs — run with: node --test desktop/src/modules/
// (also runs standalone: node security.test.mjs; Node >= 18)
//
// Security regressions for the frontend half of the desktop hardening pass:
//
//   1. UI.esc() must escape ALL five HTML-special characters, including the
//      single quote (&#39;) — a single-quote gap lets any esc()'d value that
//      ever lands in a single-quoted attribute break out of it.
//   2. P.sanePort() must accept only integers 1–65535, digits-only — no
//      trailing garbage, no signs, no floats — because rpcPort is persisted
//      in localStorage and interpolated into BOTH a URL (`http://127.0.0.1:
//      ${port}` — a value like `80@evil.com` swaps the URL authority) and
//      HTML (node pane's `value="${port}"` — a value like `"><img
//      onerror=…>` breaks out of the attribute).
//   3. loadSettings() sanitizes a poisoned persisted rpcPort at load, and
//      P.rpcUrl() re-validates at call time, so the RPC URL's authority is
//      loopback by construction no matter what settings hold.
//   4. The node pane's rendered HTML never carries a poisoned rpcPort.
//
// Like the sibling suite.test.mjs, ui.js/api.js/modules are classic browser
// scripts loaded via indirect eval over a stub window. Mock-level tests
// only: no network, no Tauri, no real backend.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { webcrypto } from "node:crypto";

if (!globalThis.crypto) globalThis.crypto = webcrypto;
globalThis.window = globalThis;

// ---- minimal localStorage polyfill, PRE-SEEDED with hostile settings ----
// The poisoned rpcPort is planted BEFORE ui.js loads so loadSettings() runs
// against attacker-influenceable persisted state (the actual trust boundary).
const XSS_PORT = '8645"><img src=x onerror=alert(1)>';
{
  const mem = new Map();
  globalThis.localStorage = {
    getItem: (k) => (mem.has(k) ? mem.get(k) : null),
    setItem: (k, v) => { mem.set(k, String(v)); },
    removeItem: (k) => { mem.delete(k); },
    clear: () => mem.clear(),
  };
  localStorage.setItem("postern.settings", JSON.stringify({ rpcPort: XSS_PORT }));
}

const here = path.dirname(fileURLToPath(import.meta.url));
const src = (rel) => readFileSync(path.join(here, rel), "utf8");
const load = (rel) => (0, eval)(src(rel));

load("../ui.js");
const P = window.Postern;
const UI = P.ui;

// ═════════ 1. esc() — all five specials, single quote included ════════════

test("esc() escapes the single quote as &#39; (single-quoted-attribute breakout)", () => {
  assert.equal(UI.esc("it's"), "it&#39;s");
  const payload = "' onmouseover='alert(1)";
  const escaped = UI.esc(payload);
  assert.ok(!escaped.includes("'"), `no raw single quote may survive esc(): ${escaped}`);
  assert.equal(escaped, "&#39; onmouseover=&#39;alert(1)");
});

test("esc() escapes all five HTML-special characters", () => {
  assert.equal(
    UI.esc(`<a href='x' title="y">&z</a>`),
    "&lt;a href=&#39;x&#39; title=&quot;y&quot;&gt;&amp;z&lt;/a&gt;",
  );
  // null/undefined normalize to "" instead of the string "null"/"undefined"
  assert.equal(UI.esc(null), "");
  assert.equal(UI.esc(undefined), "");
});

// ═════════ 2. sanePort() — strict 1–65535 integer, digits only ════════════

test("sanePort accepts exactly the valid TCP port range", () => {
  assert.equal(P.sanePort(1), 1);
  assert.equal(P.sanePort(8645), 8645);
  assert.equal(P.sanePort(65535), 65535);
  assert.equal(P.sanePort("8645"), 8645);
  assert.equal(P.sanePort(" 443 "), 443, "surrounding whitespace tolerated");
});

test("sanePort rejects out-of-range, non-integer, and injection-shaped values", () => {
  for (const bad of [
    0, "0", -1, "-80", 65536, "99999",
    86.5, "86.5", "1e3", "0x50",
    "8645abc",                      // trailing garbage (parseInt would take this!)
    "80@evil.com",                  // URL-authority swap
    "8645/path", "8645?q=1", "8645#f",
    XSS_PORT,                       // HTML attribute breakout
    "", "   ", null, undefined, true, false, NaN, {},
  ]) {
    assert.equal(P.sanePort(bad), null, `sanePort must reject ${JSON.stringify(bad)}`);
  }
});

// ═════════ 3. settings-load sanitization + rpcUrl authority pinning ═══════

test("loadSettings() sanitized the poisoned persisted rpcPort to the default", () => {
  assert.equal(P.state.settings.rpcPort, 8645);
});

test("rpcUrl() default is the official public HTTPS RPC (thin-client on fresh install)", () => {
  // No persisted rpcMode → default "public" → remote node, so a fresh install
  // works with no local node (not a loopback "connection refused").
  assert.equal(P.state.settings.rpcMode, "public");
  assert.equal(P.rpcUrl(), P.OFFICIAL_PUBLIC_RPC);
  assert.equal(P.rpcUrl(), "https://posternlabs.com/rpc");
  assert.equal(P.rpcAllowCustom(), false, "public mode is not a 'custom' endpoint");
});

test("rpcUrl() in LOCAL mode stays loopback-pinned even when the port is mutated at runtime", () => {
  const saved = { ...P.state.settings };
  try {
    P.state.settings.rpcMode = "local";
    for (const bad of ["80@evil.com", "9001/pwn", XSS_PORT, 0, 99999]) {
      P.state.settings.rpcPort = bad;
      const url = P.rpcUrl();
      assert.equal(url, "http://127.0.0.1:8645", `poisoned port ${JSON.stringify(bad)} must fall back`);
      const u = new URL(url);
      assert.equal(u.hostname, "127.0.0.1");
      assert.equal(u.username, "");
    }
    // and a legitimate custom port still works:
    P.state.settings.rpcPort = 9001;
    assert.equal(P.rpcUrl(), "http://127.0.0.1:9001");
    assert.equal(P.rpcAllowCustom(), false, "local loopback is not a 'custom' endpoint");
  } finally {
    Object.assign(P.state.settings, saved);
  }
});

test("CUSTOM endpoint requires an explicit, valid confirmation; else falls back to public", () => {
  const saved = { ...P.state.settings };
  try {
    P.state.settings.rpcMode = "custom";
    // Unconfirmed → fall back to the public node, and never flag allowCustom.
    P.state.settings.rpcCustom = "https://my-node.example.org:8645";
    P.state.settings.rpcCustomConfirmed = false;
    assert.equal(P.rpcUrl(), P.OFFICIAL_PUBLIC_RPC, "unconfirmed custom must not be used");
    assert.equal(P.rpcAllowCustom(), false);
    // Confirmed + valid → used, and allowCustom is set so the backend accepts it.
    P.state.settings.rpcCustomConfirmed = true;
    assert.equal(P.rpcUrl(), "https://my-node.example.org:8645");
    assert.equal(P.rpcAllowCustom(), true);
    // A malformed / userinfo-swap custom URL is rejected by saneRpcUrl → fallback.
    for (const bad of ["http://user@evil.com", "ftp://x", "not a url", "http://"]) {
      P.state.settings.rpcCustom = bad;
      assert.equal(P.saneRpcUrl(bad), null, `saneRpcUrl must reject ${JSON.stringify(bad)}`);
      assert.equal(P.rpcUrl(), P.OFFICIAL_PUBLIC_RPC, `bad custom ${JSON.stringify(bad)} must fall back`);
      assert.equal(P.rpcAllowCustom(), false);
    }
  } finally {
    Object.assign(P.state.settings, saved);
  }
});

// ═════════ 4. node pane render — poisoned rpcPort never reaches HTML ══════

// same stub-DOM shape as suite.test.mjs
function stubEl() {
  return {
    innerHTML: "", value: "", textContent: "", title: "", disabled: false,
    checked: false, hidden: false, isConnected: false,
    style: {}, dataset: {}, files: [],
    classList: { add() {}, remove() {}, toggle() {}, contains: () => false },
    addEventListener() {}, appendChild() {}, removeChild() {}, remove() {}, focus() {},
    querySelector: () => stubEl(),
    querySelectorAll: () => [],
  };
}

test("node pane HTML carries the sanitized port, never the injected markup", async () => {
  load("../api.js");
  load("node.js");
  const mod = P.modules.find((m) => m.id === "node");
  assert.ok(mod, "node module registered");

  const saved = P.state.settings.rpcPort;
  try {
    P.state.settings.rpcPort = XSS_PORT;
    const root = stubEl();
    await mod.render(root);
    assert.ok(!root.innerHTML.includes("onerror"), "injected attribute must not appear in pane HTML");
    assert.ok(!root.innerHTML.includes("<img src=x"), "injected element must not appear in pane HTML");
    assert.ok(root.innerHTML.includes('value="8645"'), "port input falls back to the sane default");
  } finally {
    P.state.settings.rpcPort = saved;
    if (mod.onHide) mod.onHide();
  }
});
