// desktop/src/modules/vestnik.test.mjs — run with: node desktop/src/modules/vestnik.test.mjs
//
// HONESTY NOTE — Vestnik has TWO backends and this file proves only ONE:
//
//   1. Inside the shipped desktop app, vestnik_* (create_session/register_peer/
//      encrypt/decrypt/status) is a REAL native Tauri command
//      (desktop/src-tauri/src/vestnik.rs) backed by the postern-messenger
//      DEFAULT native channel — real vodozemac Megolm E2EE, run in-process, no
//      homeserver, no account, no live network. That path is proven by the
//      Rust side (cargo test on vestnik.rs / vestnik_core.rs), is NOT reachable
//      from Node, and this file does not re-prove it — vestnik.js calls
//      api.invoke(...) and trusts api.isReal() to route there.
//   2. This test proves the OTHER path the pane self-serves when there is NO
//      Tauri backend (plain browser preview): the module's OWN labelled
//      AES-GCM PREVIEW engine (in modules/vestnik.js, exposed on the registered
//      pane as `previewEngine`). It is explicitly NOT Megolm and never
//      presented as the real ratchet — this test asserts exactly that honesty,
//      then exercises the Megolm-SHAPED create -> encrypt -> decrypt roundtrip,
//      the ratchet-index bookkeeping, and replay rejection.
//
// Harness mirrors vault.test.mjs / panes.test.mjs: ui.js / api.js / the module
// are classic (non-module) browser scripts loaded via indirect eval after
// stubbing the minimum window/DOM surface they touch.
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";

if (!globalThis.crypto) globalThis.crypto = webcrypto;
if (!globalThis.navigator) globalThis.navigator = {};
globalThis.window = globalThis;

// ---- minimal localStorage polyfill (api.js touches it at load for other engines) ----
{
  const mem = new Map();
  globalThis.localStorage = {
    getItem: (k) => (mem.has(k) ? mem.get(k) : null),
    setItem: (k, v) => { mem.set(k, String(v)); },
    removeItem: (k) => { mem.delete(k); },
    clear: () => mem.clear(),
  };
}

// ---- minimal DOM stub (used only by the render smoke check) ----
function stubEl() {
  return {
    innerHTML: "", value: "", textContent: "", title: "", disabled: false,
    checked: false, hidden: false, isConnected: false, scrollTop: 0, scrollHeight: 0,
    style: {}, dataset: {}, files: [],
    classList: { add() {}, remove() {}, toggle() {}, contains: () => false },
    addEventListener() {}, appendChild() {}, removeChild() {}, remove() {}, focus() {},
    querySelector: () => stubEl(),
    querySelectorAll: () => [],
  };
}
globalThis.document = {
  createElement: () => stubEl(),
  getElementById: () => stubEl(),
  querySelector: () => stubEl(),
  querySelectorAll: () => [],
  body: stubEl(),
  documentElement: stubEl(),
};

const here = new URL(".", import.meta.url);
const src = (rel) => readFileSync(new URL(rel, here), "utf8");
const load = (rel) => (0, eval)(src(rel));

load("../ui.js");
const P = window.Postern;
assert.ok(P && P.ui && typeof P.register === "function", "ui.js loaded, Postern namespace present");

load("../api.js");
assert.ok(P.api && typeof P.api.invoke === "function", "api.js loaded, Postern.api present");
assert.equal(P.api.hasBackend, false, "no window.__TAURI__ in Node — this IS the preview-engine surface");
assert.equal(P.api.isReal("vestnik_create_session"), false,
  "isReal requires hasBackend — confirms we exercise the module's own preview engine, not the native vodozemac command");

load("vestnik.js");
const vestnik = P.modules.find((m) => m.id === "vestnik");
assert.ok(vestnik, "vestnik pane registered");
const eng = vestnik.previewEngine;
assert.ok(eng && typeof eng.create === "function", "the pane exposes its labelled preview engine");

let passed = 0;
const t = (name, fn) => Promise.resolve().then(fn).then(() => { passed++; console.log("  ok — " + name); });

// ─────────────────────────────────────────────────────────────────────────
await t("honesty/tier strings: the engine is labelled a PREVIEW, never the real Megolm ratchet", () => {
  const h = vestnik.honestyPreview;
  assert.match(h, /PREVIEW \(no backend\)/, "must self-label as a no-backend preview");
  assert.match(h, /NOT the real vodozemac Megolm ratchet/, "must deny being the real ratchet");
  assert.match(h, /AES-GCM/, "must name the honest stand-in primitive");
  // the module source keeps its live/preview routing + honesty callout intact
  const s = src("vestnik.js");
  assert.match(s, /Real Megolm E2EE — offline, no homeserver\./, "callout headline intact");
  assert.match(s, /vodozemac Megolm ratchet/, "names the real core");
  assert.match(s, /const HONESTY_PREVIEW =/, "HONESTY_PREVIEW constant intact");
  assert.match(s, /if \(isLive\(\)\) return api\.invoke\(cmd, args\);/, "live/preview routing in invoke() intact");
});

await t("create: fresh session reports index 0, the E2EE (Postern) tier badge, and the preview honesty", async () => {
  const s = await eng.create();
  assert.equal(typeof s.sessionId, "string");
  assert.ok(s.sessionId.length > 0, "session id present");
  assert.equal(typeof s.sessionKey, "string");
  assert.equal(s.index, 0, "ratchet index starts at 0");
  assert.equal(s.tierBadge, "E2EE (Postern)", "tier badge is the internal Postern E2EE tier");
  assert.equal(s.honesty, vestnik.honestyPreview, "carries the labelled preview honesty");
});

await t("roundtrip: create -> encrypt -> decrypt returns the exact plaintext and echoes the frame session id", async () => {
  await eng.create();
  const enc = await eng.encrypt("attack at dawn", 0);
  assert.equal(typeof enc.frame.sessionId, "string");
  assert.match(enc.frame.ciphertext, /\./, "frame ciphertext is iv.ct");
  assert.equal(enc.honesty, vestnik.honestyPreview, "encrypt frame is labelled preview");

  const dec = await eng.decrypt(enc.frame, 0);
  assert.equal(dec.plaintext, "attack at dawn", "decrypt recovers the exact plaintext");
  assert.equal(dec.messageIndex, 0, "decrypt reports the ratchet index it opened");
  assert.equal(dec.sessionId, enc.frame.sessionId, "decrypt echoes the frame's session id");
  assert.equal(dec.honesty, vestnik.honestyPreview, "decrypt result is labelled preview");
});

await t("ratchet bookkeeping advances: distinct indices seal + open independently", async () => {
  await eng.create();
  const opened = [];
  for (let i = 0; i < 4; i++) {
    const enc = await eng.encrypt(`msg #${i}`, i);
    const dec = await eng.decrypt(enc.frame, i);
    assert.equal(dec.plaintext, `msg #${i}`);
    assert.equal(dec.messageIndex, i, "each message opens at its own advancing index");
    opened.push(dec.messageIndex);
  }
  assert.deepEqual(opened, [0, 1, 2, 3], "the ratchet index bookkeeping advances monotonically");
});

await t("replay rejected: opening an already-seen index throws — no silent double-accept", async () => {
  await eng.create(); // fresh session → fresh seen-set
  const enc = await eng.encrypt("once only", 7);
  const dec = await eng.decrypt(enc.frame, 7);
  assert.equal(dec.plaintext, "once only");
  await assert.rejects(() => eng.decrypt(enc.frame, 7), /replayed message \(index 7 already seen\)/,
    "a replayed ratchet index must be rejected");
});

await t("tamper/wrong-index rejected: the bound index is authenticated (AEAD), not decorative", async () => {
  await eng.create();
  const enc = await eng.encrypt("bound to its index", 3);
  // decrypting the frame under a DIFFERENT index must fail the AEAD tag check
  await assert.rejects(() => eng.decrypt(enc.frame, 4),
    "the ratchet index is bound as associated data — a mismatched index must not open");
});

await t("render smoke: the pane renders the new 'Receive a frame' control that drives the incoming (them) path", async () => {
  const root = stubEl();
  await vestnik.render(root);
  const html = root.innerHTML;
  assert.match(html, /Receive a frame/, "the new receive card is rendered");
  assert.match(html, /id="vk-recv"/, "the paste textarea is present");
  assert.match(html, /id="vk-recv-btn"/, "the decrypt button is present");
  // the receive handler is what activates the previously-dead them:true bubble
  const s = src("vestnik.js");
  assert.match(s, /vestnik_decrypt", \{ frame, previewIndex: idx \}/, "receive handler calls vestnik_decrypt on the pasted frame");
  assert.match(s, /them: true/, "receive handler pushes an incoming (them:true) bubble");
  assert.match(s, /m\.them \? " them"/, "renderMsgs styles the them bubble — the path is now reached");
});

console.log(`\ndesktop vestnik (preview-engine) core: ${passed} checks passed`);
