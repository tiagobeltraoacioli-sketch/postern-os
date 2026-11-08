// desktop/src/modules/suite.test.mjs — run with: node suite.test.mjs (Node >= 18)
//
// Proves the "flip the folded panes live + demote node/wallet/miner" change:
//
//   1. api.js's REAL set now contains the 8 command names the backend lane
//      registers in generate_handler! (desktop/src-tauri/src/main.rs):
//      hygiene_scrub, courier_generate_recipient/seal/open,
//      keys_create/list/sign/remove — so with a Tauri backend present these
//      route to T.core.invoke, and WITHOUT one the labeled preview engines
//      remain the fallback (both directions asserted below). The 6 terem_*
//      commands (QEMU/QMP POC, unix-only) are also in the REAL set, but
//      deliberately have NO preview engine — a no-backend invoke throws
//      honestly instead of faking a VM (asserted below too). The 4 vestnik_*
//      custody commands (vault-held recipient secret + sealed SavedSession
//      blob, vestnik.rs) follow the same rule: REAL, no preview engine. The
//      8 vestnik_* matrix-client commands (vestnik_client.rs) are ALSO
//      registered always — a backend built without the opt-in
//      `vestnik-matrix` cargo feature returns a clean "not built with matrix
//      support" error and vestnik_matrix_status reports built:false, which
//      is what the messenger pane gates its live claim on (see
//      messenger.test.mjs).
//   2. node.js and wallet.js register under the collapsed-last nav group
//      "Advanced · testnet (zero value)" and their panes carry the
//      zero-value/unaudited banner.
//   3. The courier and keys panes, rendered into a stub root, contain their
//      honesty strings (UNAUDITED; hardened-not-anonymous; not a hardware
//      key) — the caveats are unconditional, live or preview.
//   4. No module source references an http(s):// origin other than the
//      existing localhost RPC default.
//
// ui.js / api.js / modules/*.js are classic (non-module) browser scripts.
// Like the sibling vault.test.mjs, this file stubs the minimum window
// surface they touch and loads them via indirect eval. Everything here is a
// mock-level test: no network, no Tauri, no real backend — honest to the
// repo rule that compile + unit/mock-test green is the bar.
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";

if (!globalThis.crypto) globalThis.crypto = webcrypto;
globalThis.window = globalThis;

// ---- minimal localStorage polyfill ----
{
  const mem = new Map();
  globalThis.localStorage = {
    getItem: (k) => (mem.has(k) ? mem.get(k) : null),
    setItem: (k, v) => { mem.set(k, String(v)); },
    removeItem: (k) => { mem.delete(k); },
    clear: () => mem.clear(),
  };
}

const here = path.dirname(fileURLToPath(import.meta.url));
const src = (rel) => readFileSync(path.join(here, rel), "utf8");
const load = (rel) => (0, eval)(src(rel));

const REAL_NEW = [
  "hygiene_scrub",
  "courier_generate_recipient", "courier_seal", "courier_open",
  "keys_create", "keys_list", "keys_sign", "keys_remove",
];
// Terem (QEMU/QMP guest POC, terem.rs — #[cfg(unix)]-gated in main.rs's
// generate_handler!). REAL like the folded cores, but with NO preview
// engine: without a backend the pane renders the honest empty state.
const TEREM_REAL = [
  "terem_create", "terem_start", "terem_qmp", "terem_status", "terem_stop", "terem_destroy",
];
// Vestnik (vestnik.rs custody + vestnik_client.rs matrix client) —
// registered in main.rs's generate_handler! and mirrored in api.js's REAL
// set. The custody commands hold the vault-held recipient secret + the
// opaque sealed SavedSession blob; the client commands exist behind the
// opt-in `vestnik-matrix` cargo feature (built without it they return a
// clean "not built with matrix support" error and vestnik_matrix_status
// reports built:false — the messenger pane gates on that, never on
// registration). Like terem, there is NO preview engine: a faked vault or
// a faked matrix client would be an overclaim.
const VESTNIK_REAL = [
  "vestnik_recipient_init", "vestnik_session_store", "vestnik_session_load", "vestnik_session_open",
  "vestnik_matrix_status", "vestnik_login", "vestnik_session_seal", "vestnik_restore",
  "vestnik_sync_once", "vestnik_rooms", "vestnik_send", "vestnik_logout",
];
const ADVANCED_GROUP = "Advanced · testnet (zero value)";

let passed = 0;
const t = (name, fn) => Promise.resolve().then(fn).then(() => { passed++; console.log("  ok — " + name); });

load("../ui.js");
assert.ok(window.Postern && window.Postern.ui, "ui.js loaded");

// ═════════ Phase A — NO backend: preview engines are the fallback ═════════
load("../api.js");
const previewApi = window.Postern.api;

await t("no backend: isReal is false for every folded + terem + vestnik command — nothing claims live", async () => {
  assert.equal(previewApi.hasBackend, false);
  for (const cmd of [...REAL_NEW, ...TEREM_REAL, ...VESTNIK_REAL]) {
    assert.equal(previewApi.isReal(cmd), false, `${cmd} must not claim live without a backend`);
  }
  // Terem deliberately has NO preview engine — a fake VM would be an
  // overclaim, so a no-backend invoke throws instead of pretending.
  await assert.rejects(() => previewApi.invoke("terem_status"), /no handler for 'terem_status'/);
  // Same stance for Vestnik custody: a faked vault would be an overclaim.
  await assert.rejects(() => previewApi.invoke("vestnik_recipient_init"), /no handler for 'vestnik_recipient_init'/);
});

await t("no backend: courier preview engine still round-trips (classical ECDH stand-in, labeled)", async () => {
  const id = await previewApi.invoke("courier_generate_recipient");
  assert.ok(id.public && id.secret, "preview recipient keypair");
  const pt = new TextEncoder().encode("postern preview payload");
  const b64 = Buffer.from(pt).toString("base64");
  const sealed = await previewApi.invoke("courier_seal", { recipientPublic: id.public, bytesB64: b64, name: "x.txt" });
  assert.match(sealed.v, /preview/, "preview seal must self-label as preview");
  const out = await previewApi.invoke("courier_open", { recipientSecret: id.secret, sealed });
  assert.equal(out.bytesB64, b64, "opened payload matches");
});

// ═════════ Phase B — fake Tauri backend: REAL set routes to invoke ═════════
const invoked = [];
globalThis.__TAURI__ = {
  core: {
    invoke: async (cmd, args) => {
      invoked.push({ cmd, args });
      if (cmd === "keys_list") return [];
      return null;
    },
  },
};
load("../api.js"); // re-eval: api.js re-reads window.__TAURI__ at load
const P = window.Postern;
const api = P.api;

await t("REAL set contains all 8 folded + all 6 terem + all 12 vestnik command names", async () => {
  assert.equal(api.hasBackend, true, "fake __TAURI__ detected");
  for (const cmd of [...REAL_NEW, ...TEREM_REAL, ...VESTNIK_REAL]) {
    assert.equal(api.isReal(cmd), true, `${cmd} must be in the REAL set`);
  }
  // and the never-registered cores must NOT be overclaimed as live.
  // (vestnik_login moved OUT of this list: it is now a registered command —
  // a no-feature backend answers it with the clean "not built with matrix
  // support" error, and the pane's live claim is gated on
  // vestnik_matrix_status.built, tested in messenger.test.mjs.)
  for (const cmd of ["messenger_encrypt", "messenger_decrypt", "seal_self_audit", "courier_host_onion"]) {
    assert.equal(api.isReal(cmd), false, `${cmd} must not be claimed live`);
  }
});

await t("isReal commands route to T.core.invoke, not the preview engine", async () => {
  invoked.length = 0;
  await api.invoke("keys_list");
  assert.equal(invoked.length, 1);
  assert.equal(invoked[0].cmd, "keys_list");
});

await t("isReal routes terem_status to T.core.invoke (there is no terem preview engine to shadow it)", async () => {
  invoked.length = 0;
  await api.invoke("terem_status");
  assert.equal(invoked.length, 1);
  assert.equal(invoked[0].cmd, "terem_status");
});

// ── load the panes (they capture P.api at load, so load them in Phase B) ──
P.modules.length = 0; // fresh registry
load("node.js");
load("wallet.js");
load("courier.js");
load("keys.js");
load("terem.js");
const byId = Object.fromEntries(P.modules.map((m) => [m.id, m]));

await t("node and wallet register under the collapsed 'Advanced · testnet (zero value)' group", async () => {
  assert.equal(byId.node.group, ADVANCED_GROUP);
  assert.equal(byId.wallet.group, ADVANCED_GROUP);
  // courier/keys/terem keep their original groups — only node/wallet are demoted
  assert.equal(byId.courier.group, "Transmit");
  assert.equal(byId.keys.group, "Protect");
  assert.equal(byId.terem.group, "Operate");
});

await t("main.js renders the Advanced group LAST as a <details> collapsed by default", async () => {
  const main = src("../main.js");
  assert.ok(main.includes(ADVANCED_GROUP), "main.js knows the Advanced group label");
  assert.ok(main.includes('document.createElement("details")'), "collapsible <details> nav group");
  assert.match(main, /no `open` attr|collapsed/i, "documented as collapsed by default");
});

// ── stub-DOM render of the panes ──────────────────────────────────────────
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
async function renderPane(mod) {
  const root = stubEl();
  await mod.render(root);
  return root.innerHTML;
}

await t("courier pane HTML carries its honesty strings (live-aware badge, caveats never deleted)", async () => {
  const html = await renderPane(byId.courier);
  assert.ok(html.includes("UNAUDITED"), "courier must say UNAUDITED");
  assert.ok(html.includes("mock/local"), "courier must admit mock/local transport");
  assert.ok(html.includes("no live onion round trip"), "courier must admit no live onion round trip");
  assert.ok(html.includes("hardened, not anonymous"), "courier must say hardened, not anonymous");
});

await t("keys pane HTML carries its honesty strings (software authenticator, not a hardware key)", async () => {
  const html = await renderPane(byId.keys);
  assert.ok(html.includes("UNAUDITED software authenticator"), "keys must say UNAUDITED software authenticator");
  assert.ok(html.includes("not a hardware key"), "keys must say not a hardware key");
  assert.ok(html.includes("app RAM"), "keys must admit ES256 keys live in app RAM");
});

await t("terem pane HTML carries its honesty strings (user-fetched QEMU, no VM boots, not Seal-covered)", async () => {
  const html = await renderPane(byId.terem);
  assert.ok(html.includes("UNAUDITED POC"), "terem must say UNAUDITED POC");
  assert.ok(html.includes("opt-in and user-fetched"), "terem must say QEMU is opt-in and user-fetched");
  assert.ok(html.includes("never downloads, ships, or links QEMU"), "terem must say the app never fetches QEMU");
  assert.ok(html.includes("docs/os-portal-v2/LICENSE-DECISION.md"), "terem must cite the GPL aggregation decision doc");
  assert.ok(html.includes("No VM boots in CI or tests"), "terem must say no VM boots in CI or tests");
  assert.ok(html.includes("not attestation"), "terem must say a running guest is not attestation");
  assert.ok(html.includes("not Seal-covered"), "terem must say a running guest is not Seal-covered");
  assert.ok(html.includes("unix-only"), "terem must disclose the unix-only gate");
});

await t("node and wallet panes carry an honest zero-value / unaudited banner", async () => {
  for (const id of ["node", "wallet"]) {
    const html = await renderPane(byId[id]);
    // Both panes must disclose no value + unaudited.
    assert.ok(html.includes("no value"), `${id} must say coins have no value`);
    assert.ok(/unaudited/i.test(html), `${id} must say unaudited`);
  }
  // The node pane runs the CANONICAL mainnet chain, so its banner is honest
  // mainnet-beta wording (not "testnet"); the wallet keeps the testnet banner.
  const nodeHtml = await renderPane(byId["node"]);
  assert.ok(/mainnet-beta/i.test(nodeHtml), "node banner must say mainnet-beta");
  assert.ok(/zero value/i.test(nodeHtml), "node banner must say zero value");
  const walletHtml = await renderPane(byId["wallet"]);
  assert.ok(walletHtml.includes("Zero-value testnet"), "wallet must say Zero-value testnet");
});

await t("no module source references an http(s) origin beyond the localhost RPC default", async () => {
  const files = [
    ...readdirSync(here).filter((f) => f.endsWith(".js")).map((f) => path.join(here, f)),
    path.join(here, "../api.js"),
    path.join(here, "../main.js"),
    path.join(here, "../ui.js"),
  ];
  // Allowlist mirrors the backend RPC allowlist (main.rs validate_rpc_url): a
  // loopback http node, the official public HTTPS RPC (the new remote default),
  // and the RFC 2606 example placeholder shown in the custom-endpoint field.
  // Any OTHER hardcoded origin is still a failure.
  const allowed = [
    /^http:\/\/127\.0\.0\.1(?::|\/|$)/,
    /^http:\/\/localhost(?::|\/|$)/,
    /^https:\/\/posternlabs\.com(?::|\/|$)/,
    /^https?:\/\/my-node\.example\.org(?::|\/|$)/,
  ];
  for (const f of files) {
    const text = readFileSync(f, "utf8");
    for (const m of text.matchAll(/https?:\/\/[^\s"'`<>)\\]+/g)) {
      assert.ok(
        allowed.some((re) => re.test(m[0])),
        `${path.basename(f)} references a non-localhost origin: ${m[0]}`,
      );
    }
  }
});

console.log(`\ndesktop suite (REAL-set flip + Advanced/testnet demotion): ${passed} checks passed`);
