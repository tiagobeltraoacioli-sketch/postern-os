// desktop/src/browser/browser-backend.test.mjs — run with:
//   node --test desktop/src/browser/*.test.mjs
//
// Proves the THIRD backend behind api.js's seam actually EXECUTES (a rendered
// screen is not a working screen):
//
//   Phase A — wasm fetch BLOCKED: nothing registers, api.backendKind stays
//     'preview', isReal() stays false, the wallet pane renders its labelled
//     preview badge (never a broken live one), and import invokes throw the
//     honest "needs a real backend" error.
//
//   Phase B — wasm SERVED (the real bloch_wallet_wasm.wasm shipping in
//     apps/mobile-wallet-pwa/public/): registration is golden-vector-gated
//     (same assertion as apps/mobile-wallet/test-wasm.mjs — SHA3-256 of the
//     ML-DSA-65 pk half for seed 0x11*32 equals the hash the NODE pins),
//     api.backendKind === 'browser', wallet_generate returns a real bloch1q
//     address, a REAL bloch-cli wallet.json (apps/mobile-wallet/testdata,
//     written by bloch-crypto itself) decrypts and re-derives its own address,
//     and wallet_send runs getutxos → local hybrid-PQ sign → sendrawtransaction
//     through a registry 'rpc' stand-in — with the mnemonic PROVABLY never
//     crossing the rpc boundary.
//
// Mock-level only at the edges (no network, no Tauri): the wasm core and the
// keystore decrypts are the real thing.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { webcrypto } from "node:crypto";

if (!globalThis.crypto) globalThis.crypto = webcrypto;
globalThis.window = globalThis;

// ---- minimal localStorage polyfill (ui.js touches it) ----
{
  const mem = new Map();
  globalThis.localStorage = {
    getItem: (k) => (mem.has(k) ? mem.get(k) : null),
    setItem: (k, v) => { mem.set(k, String(v)); },
    removeItem: (k) => { mem.delete(k); },
    clear: () => mem.clear(),
  };
}

// ---- minimal DOM stub (panes render into innerHTML strings) ----
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
globalThis.document = {
  createElement: () => stubEl(),
  getElementById: () => stubEl(),
  querySelector: () => stubEl(),
  querySelectorAll: () => [],
  body: stubEl(),
  documentElement: stubEl(),
};

const here = path.dirname(fileURLToPath(import.meta.url));
const src = (rel) => readFileSync(path.join(here, rel), "utf8");
const load = (rel) => (0, eval)(src(rel));

// The real shipping wasm + the real bloch-cli keystore fixtures.
const repoRoot = path.join(here, "../../..");
const WASM_PATH = path.join(repoRoot, "apps/mobile-wallet-pwa/public/bloch_wallet_wasm.wasm");
const TESTDATA = path.join(repoRoot, "apps/mobile-wallet/testdata");
const FX = JSON.parse(readFileSync(path.join(TESTDATA, "cli-fixtures.json"), "utf8"));
const simpleJson = readFileSync(path.join(TESTDATA, "cli-simple.json"), "utf8");
const hdJson = readFileSync(path.join(TESTDATA, "cli-hd.json"), "utf8");

// fetch stand-in: Phase A blocks the wasm, Phase B serves the real bytes.
let wasmBlocked = true;
globalThis.fetch = async (url) => {
  if (wasmBlocked) throw new Error("wasm fetch blocked (test phase A)");
  const bytes = readFileSync(WASM_PATH);
  return {
    ok: true,
    status: 200,
    clone() { return this; },
    async arrayBuffer() {
      return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    },
  };
};

// ── boot: registry BEFORE api.js, then core + wallet providers + the pane ──
load("../ui.js");
const P = window.Postern;

// withRpc=false reproduces a build where the /rpc layer is absent. It is NOT the
// normal shape: index.html loads rpc.js before wallet.js precisely so the send
// guard can see it. Keep the load order here identical to index.html's, or these
// tests stop describing the app that ships.
function bootBrowserBackend({ withRpc = true } = {}) {
  delete window.PosternBrowser;
  delete window.PosternBrowserCore;
  delete window.PosternBrowserWallet;
  delete window.PosternBrowserRpc;
  P.modules.length = 0;
  load("registry.js");   // must precede api.js
  load("core.js");
  if (withRpc) load("rpc.js");   // MUST precede wallet.js — the send guard reads it
  load("../api.js");
  load("wallet.js");     // kicks off the async, fail-loud core load
  load("../modules/wallet.js"); // the EXISTING pane — must work unchanged
  return { api: P.api, walletPane: P.modules.find((m) => m.id === "wallet") };
}

async function renderPane(mod) {
  const root = stubEl();
  await mod.render(root);
  return root.innerHTML;
}

// ═════════ Phase A — wasm fetch blocked: honest preview, nothing half-live ══
// (Phase B boots INSIDE its first test, after Phase A's assertions ran — the
// registry globals are per-boot, and node:test runs this file's tests in order.)
const phaseA = bootBrowserBackend();
const phaseAReady = window.PosternBrowserWallet.whenRegistered;

test("wasm blocked: nothing registers — backendKind 'preview', isReal false, preview badge (never a broken live one)", async () => {
  assert.equal(await phaseAReady, false, "registration must fail loud");
  // backendKind describes WHETHER a browser backend is present, not whether every
  // command in it works — per-command truth is api.isReal(), asserted below. With
  // the core unloadable but the same-origin /rpc layer up, reads (balances, height,
  // explorer) genuinely do work, so "browser" is accurate and "preview" would
  // understate it. What must never happen is a WALLET command claiming real: no
  // core means no keygen and no signing, and that is what the loop below pins.
  assert.equal(phaseA.api.backendKind, "browser");
  assert.equal(window.PosternBrowser.has("rpc"), true, "the rpc layer is independent of the wasm core");
  // The rpc layer does NOT depend on the wasm core (it is just the same-origin
  // /rpc proxy), so it stays registered. What must be empty is every WALLET
  // command: with no core there is no keygen and no signing.
  assert.deepEqual(
    window.PosternBrowser.list().filter((c) => c !== "rpc"), [],
    "no wallet command may register when the core failed to load",
  );
  for (const cmd of ["wallet_generate", "wallet_from_mnemonic", "wallet_send",
                     "wallet_import_keystore", "wallet_import_hd", "wallet_keystore_send", "core_version"]) {
    assert.equal(phaseA.api.isReal(cmd), false, `${cmd} must not claim real with the core unloadable`);
  }
  assert.equal(phaseA.walletPane.live(), false, "wallet pane must not claim live");
  const html = await renderPane(phaseA.walletPane);
  assert.ok(html.includes("badge-stub"), "wallet pane shows the stub/preview badge");
  assert.ok(!html.includes("badge-live"), "wallet pane must NOT show a live badge");
  await assert.rejects(() => phaseA.api.invoke("wallet_import_keystore", {}),
    /needs the native Postern Desktop app|cannot decrypt a real keystore/,
    "import falls back to the honest preview refusal");
});

// ═════════ Phase B — wasm served: the REAL core registers and executes ═════
let phaseB;

test("wasm served: golden-vector-gated registration → backendKind 'browser', pane goes live", async () => {
  wasmBlocked = false;
  phaseB = bootBrowserBackend();
  assert.equal(await window.PosternBrowserWallet.whenRegistered, true, "core loaded + golden vector passed");
  assert.equal(phaseB.api.hasBackend, false, "hasBackend still means Tauri only");
  assert.equal(phaseB.api.backendKind, "browser");
  for (const cmd of ["wallet_generate", "wallet_from_mnemonic", "wallet_send",
                     "wallet_import_keystore", "wallet_import_hd", "wallet_keystore_send", "core_version"]) {
    assert.equal(phaseB.api.isReal(cmd), true, `${cmd} is real in browser mode`);
  }
  // The blocking gap stays honest: NO address-at-index op exists in the core.
  assert.equal(phaseB.api.isReal("wallet_address_at"), false,
    "wallet_address_at must stay preview — the core has no index-derivation op");
  assert.equal(phaseB.walletPane.live(), true, "wallet pane gates live on wallet_generate");
  const html = await renderPane(phaseB.walletPane);
  assert.ok(html.includes("badge-live"), "wallet pane shows the live badge");
  // core self-identifies as the real hybrid scheme
  const v = await phaseB.api.invoke("core_version", {});
  assert.match(v.version, /ML-DSA-65/);
  assert.match(v.version, /Falcon-1024/);
});

test("keygen golden vector matches the node's pinned KAT (WASM keygen == node keygen)", () => {
  const { hash } = window.PosternBrowserCore.call("debug_seed_mldsa_pk_hash", { seed_hex: "11".repeat(32) });
  assert.equal(hash, "bb34618ab597cc394fcfa9c9c5791d4767baacce3648285e8069742a55e2de37");
});

test("wallet_generate returns a real bloch1q address + 24-word mnemonic; restore re-derives it byte-identically", async () => {
  const w = await phaseB.api.invoke("wallet_generate", { testnet: false });
  assert.equal(w.mnemonic.trim().split(/\s+/).length, 24, "24-word BIP39 mnemonic");
  assert.ok(w.address.startsWith("bloch1q"), "real mainnet address: " + w.address);
  assert.match(w.pubkey, /^[0-9a-f]{100,}$/, "real hybrid pubkey hex (thousands of bytes)");
  // deterministic: the SAME Tauri-shaped wallet_from_mnemonic round-trips it
  const r = await phaseB.api.invoke("wallet_from_mnemonic", { phrase: w.mnemonic, testnet: false });
  assert.equal(r.address, w.address, "restore derives the identical address");
  assert.equal(r.pubkey, w.pubkey, "…and the identical pubkey");
  // and the ML-DSA pk-half hash of this pubkey re-derives the address (network prefix only flips)
  const t = await phaseB.api.invoke("wallet_from_mnemonic", { phrase: w.mnemonic, testnet: true });
  assert.ok(t.address.startsWith("bloch1t"), "testnet flips only the prefix");
  assert.equal(t.pubkey, w.pubkey, "same key across network prefixes");
});

test("importing a REAL bloch-cli wallet.json decrypts (Argon2id/AES-256-GCM) and re-derives its own address", async () => {
  const r = await phaseB.api.invoke("wallet_import_keystore", { json: simpleJson, password: FX.password });
  assert.equal(r.kind, "simple");
  assert.equal(r.address, FX.simple.address, "address is byte-identical to what the crate recorded");
  assert.equal(r.verified, true);
  assert.ok(!("private_key_hex" in r) && !JSON.stringify(r).includes("private_key"),
    "like the native command, the private key is NOT handed to the UI layer");
  // wrong password fails closed
  await assert.rejects(() => phaseB.api.invoke("wallet_import_keystore", { json: simpleJson, password: "wrong" }),
    /decrypt failed/);
});

test("importing a REAL bloch-cli HD wallet.json opens the v1/v2 master-key path and lists verified addresses", async () => {
  const r = await phaseB.api.invoke("wallet_import_hd", {
    json: hdJson, mnemonic: FX.hd.mnemonic, passphrase: "", password: FX.password,
  });
  assert.equal(r.kind, "hd");
  assert.equal(r.network, FX.hd.network);
  assert.equal(r.addresses[0].address, FX.hd.primary_address);
  assert.ok(!JSON.stringify(r).includes("private_key"), "no private key returned to the UI layer");
});

test("wallet_send: rpc getutxos → REAL local hybrid-PQ sign → rpc sendrawtransaction; the mnemonic never crosses rpc", async () => {
  const MNEMONIC = "legal winner thank year wave sausage worth useful legal winner thank yellow";
  const self = await phaseB.api.invoke("wallet_from_mnemonic", { phrase: MNEMONIC, testnet: true });
  const rpcCalls = [];
  // Stand-in for the /rpc proxy layer (owned by the rpc track) — the registry
  // is the only coupling, exactly as in production.
  window.PosternBrowser.register("rpc", ({ url, method, params, allowCustom }) => {
    rpcCalls.push({ url, method, params, allowCustom });
    if (method === "getutxos") {
      return { jsonrpc: "2.0", id: 1, result: { utxos: [{ txid: "aa".repeat(32), index: 0, value: 500000000 }] } };
    }
    if (method === "sendrawtransaction") return { jsonrpc: "2.0", id: 1, result: "accepted" };
    throw new Error("unexpected rpc method " + method);
  });
  const txid = await phaseB.api.invoke("wallet_send", {
    rpcUrl: "/rpc", mnemonic: MNEMONIC, testnet: true,
    to: self.address, amount: 100000000, fee: "medium", allowCustom: false,
  });
  assert.match(txid, /^[0-9a-f]{64}$/, "32-byte txid hex returned");
  assert.deepEqual(rpcCalls.map((c) => c.method), ["getutxos", "sendrawtransaction"],
    "exactly the two allowed rpc calls, in order");
  assert.deepEqual(rpcCalls[0].params, [self.address], "getutxos sees only the PUBLIC address");
  const rawHex = rpcCalls[1].params[0];
  assert.ok(/^[0-9a-f]+$/.test(rawHex) && rawHex.length > 4000,
    "broadcast carries a real signed tx (hybrid Falcon‖ML-DSA sig is thousands of bytes): " + rawHex.length);
  // KEY BOUNDARY: nothing secret ever crossed the rpc seam.
  const wire = JSON.stringify(rpcCalls);
  assert.ok(!wire.includes("legal winner"), "the mnemonic must NEVER appear in any rpc call");
  // cross-network send fails closed before any broadcast
  const mainnetSelf = await phaseB.api.invoke("wallet_from_mnemonic", { phrase: MNEMONIC, testnet: false });
  rpcCalls.length = 0;
  await assert.rejects(() => phaseB.api.invoke("wallet_send", {
    rpcUrl: "/rpc", mnemonic: MNEMONIC, testnet: true,
    to: mainnetSelf.address, amount: 1, fee: "slow", allowCustom: false,
  }), /cross-network/);
  assert.ok(!rpcCalls.some((c) => c.method === "sendrawtransaction"), "nothing was broadcast");
});

test("wallet_keystore_send: decrypt → sign with the raw imported keypair → broadcast (password never crosses rpc)", async () => {
  const rpcCalls = [];
  // re-register the rpc stand-in fresh for this test
  window.PosternBrowser.register("rpc", ({ method, params }) => {
    rpcCalls.push({ method, params });
    if (method === "getutxos") {
      return { jsonrpc: "2.0", id: 1, result: { utxos: [{ txid: "bb".repeat(32), index: 0, value: 500000000 }] } };
    }
    if (method === "sendrawtransaction") return { jsonrpc: "2.0", id: 1, result: "accepted" };
    throw new Error("unexpected rpc method " + method);
  });
  const txid = await phaseB.api.invoke("wallet_keystore_send", {
    json: simpleJson, password: FX.password, rpcUrl: "/rpc",
    to: FX.simple.address, amount: 100000000, fee: "next", allowCustom: false,
  });
  assert.match(txid, /^[0-9a-f]{64}$/);
  assert.deepEqual(rpcCalls.map((c) => c.method), ["getutxos", "sendrawtransaction"]);
  const wire = JSON.stringify(rpcCalls);
  assert.ok(!wire.includes(FX.password), "the keystore password must NEVER appear in any rpc call");
});

test("no rpc layer → the send paths are NOT REGISTERED AT ALL (no live badge over a dead button)", async () => {
  // The old shape registered wallet_send unconditionally, so api.isReal() said
  // true while every send threw "no browser-backend handler for 'rpc'". The pane
  // reads isReal() to pick its badge, so that produced a literal
  // "live · signed on-device" label over a button that could never send.
  // Registering IS the claim of realness: if broadcast is impossible, do not
  // register, and let the pane render its labelled preview instead.
  wasmBlocked = false;
  const fresh = bootBrowserBackend({ withRpc: false });
  assert.equal(await window.PosternBrowserWallet.whenRegistered, true, "keygen/import still register — signing is local");
  assert.equal(window.PosternBrowser.has("rpc"), false);

  for (const cmd of ["wallet_send", "wallet_keystore_send"]) {
    assert.equal(window.PosternBrowser.has(cmd), false, `${cmd} must not be registered without an rpc layer`);
    assert.equal(fresh.api.isReal(cmd), false, `${cmd} must not claim real without an rpc layer`);
  }
  // …while the purely-local half stays real: keygen and import never touch rpc.
  for (const cmd of ["wallet_generate", "wallet_from_mnemonic", "wallet_import_keystore"]) {
    assert.equal(fresh.api.isReal(cmd), true, `${cmd} is local-only and stays real`);
  }
  // And the pane must not paint the live send badge in that state.
  const html = await renderPane(fresh.walletPane);
  assert.ok(!html.includes("live · signed on-device"), "no live send badge without an rpc layer");
});
