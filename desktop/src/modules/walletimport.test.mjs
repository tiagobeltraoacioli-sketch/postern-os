// desktop/src/modules/walletimport.test.mjs — run: node walletimport.test.mjs (Node >= 18)
//
// Proves the "import a bloch-cli wallet.json" surface added to the desktop
// wallet, at the level this Node harness can actually reach (no Tauri, no real
// `bloch` crate):
//
//   1. The three new commands (wallet_import_keystore / wallet_import_hd /
//      wallet_keystore_send) are in api.js's REAL set, so WITH a Tauri backend
//      they route straight to T.core.invoke (the native walletjson.rs decoders
//      that reuse the `bloch` crate's own keystore readers). The real
//      decrypt + address round-trip is proven by walletjson.rs's own Rust
//      tests (`cargo test -p bloch-desktop`), NOT here.
//   2. WITHOUT a backend there is deliberately NO honest browser preview — you
//      cannot fake decrypting a real Argon2id/AES-256-GCM keystore — so a
//      no-backend invoke throws a clear "needs the native Postern Desktop app"
//      message rather than pretending (both directions asserted).
//   3. wallet.js wires the imported keystore to the send path (branches to
//      wallet_keystore_send) and carries the "round-trip"/verify honesty copy.
//
// Same eval-load harness as the sibling suite.test.mjs / vault.test.mjs.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import assert from "node:assert/strict";
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

const here = path.dirname(fileURLToPath(import.meta.url));
const src = (rel) => readFileSync(path.join(here, rel), "utf8");
const load = (rel) => (0, eval)(src(rel));

const IMPORT_CMDS = ["wallet_import_keystore", "wallet_import_hd", "wallet_keystore_send"];

let passed = 0;
const t = (name, fn) => Promise.resolve().then(fn).then(() => { passed++; console.log("  ok — " + name); });

load("../ui.js");
assert.ok(window.Postern && window.Postern.ui, "ui.js loaded");

// ── Phase A — NO backend: import is honestly unavailable, never faked ──
load("../api.js");
const previewApi = window.Postern.api;

await t("no backend: import commands are not claimed live", async () => {
  assert.equal(previewApi.hasBackend, false);
  for (const cmd of IMPORT_CMDS) {
    assert.equal(previewApi.isReal(cmd), false, `${cmd} must not claim live without a backend`);
  }
});

await t("no backend: import invokes throw an honest 'needs the native app' error (not a fake decrypt)", async () => {
  for (const cmd of IMPORT_CMDS) {
    await assert.rejects(
      () => previewApi.invoke(cmd, {}),
      /needs the native Postern Desktop app/,
      `${cmd} preview must refuse honestly`,
    );
  }
});

// ── Phase B — fake Tauri backend: REAL set routes to invoke ──
const invoked = [];
globalThis.__TAURI__ = {
  core: {
    invoke: async (cmd, args) => {
      invoked.push({ cmd, args });
      if (cmd === "wallet_import_keystore") return { kind: "simple", address: "bloch1t000", pubkey: "aa", network: "testnet", verified: true };
      if (cmd === "wallet_import_hd") return { kind: "hd", network: "testnet", verified: true, addresses: [{ index: 0, address: "bloch1t000", label: "primary" }] };
      if (cmd === "wallet_keystore_send") return "deadbeef";
      return null;
    },
  },
};
load("../api.js"); // re-eval: api.js re-reads window.__TAURI__ at load
const api = window.Postern.api;

await t("REAL set contains the three import commands, routing to T.core.invoke", async () => {
  assert.equal(api.hasBackend, true, "fake __TAURI__ detected");
  for (const cmd of IMPORT_CMDS) {
    assert.equal(api.isReal(cmd), true, `${cmd} must be in the REAL set`);
  }
  invoked.length = 0;
  await api.invoke("wallet_import_keystore", { json: "{}", password: "x" });
  await api.invoke("wallet_keystore_send", { json: "{}", password: "x", rpcUrl: "http://127.0.0.1:8645", to: "bloch1t1", amount: 1, fee: "medium" });
  assert.deepEqual(invoked.map((i) => i.cmd), ["wallet_import_keystore", "wallet_keystore_send"]);
});

// ── Phase C — wallet.js source wires import → verify → send honestly ──
await t("wallet.js wires the import commands + carries round-trip/verify copy", async () => {
  const walletSrc = src("wallet.js");
  for (const cmd of IMPORT_CMDS) {
    assert.ok(walletSrc.includes(cmd), `wallet.js must call ${cmd}`);
  }
  // The imported simple keystore must spend through wallet_keystore_send, and
  // the pane must speak to the round-trip verification (honest interop claim).
  assert.match(walletSrc, /imported\s*\?/, "send branches on an imported keystore");
  assert.match(walletSrc, /round-trip/i, "import copy states the round-trip guarantee");
  assert.match(walletSrc, /bloch-cli/i, "import copy names the bloch-cli source format");
});

console.log(`\n${passed} passed`);
