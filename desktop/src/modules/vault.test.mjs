// desktop/src/modules/vault.test.mjs — run with: node vault.test.mjs (Node >= 18)
//
// HONESTY NOTE — this app has TWO real backends, and this file proves only
// one of them:
//
//   1. Inside the shipped desktop app, vault_* (vault_status/create/unlock/
//      lock/list/get/put/remove/discard) is a REAL native Tauri command
//      (desktop/src-tauri/src/main.rs) backed by the `postern-vault` crate —
//      audited-shape Argon2id + XChaCha20-Poly1305, no wasm involved at all.
//      That path is proven by the crate's own Rust tests
//      (`cargo test -p postern-vault`), NOT reachable from Node, and this
//      file does not re-prove it — vault.js just calls `api.invoke(...)` and
//      trusts api.isReal() to route there, which is already the case
//      (confirmed in-tree: main.rs registers all 9 vault_* commands in
//      `generate_handler!`, and api.js's REAL set lists them).
//   2. This test instead proves the OTHER real path this change adds: the
//      JS-side PREVIEW engine in desktop/src/api.js, which only runs when
//      there is NO Tauri backend (hasBackend === false — e.g. iterating on
//      the UI in a plain browser). That preview engine now probes
//      globalThis.PosternSDK (the same postern-sdk wasm seam the browser
//      front-ends use) and seals with the SAME real Argon2id +
//      XChaCha20-Poly1305 primitive when present, instead of unconditionally
//      falling back to the classical PBKDF2 stand-in. That is the surface
//      this Node test can actually reach and exercise.
//
// ui.js and api.js are classic (non-module) scripts written for a browser
// `window`/`document`/`localStorage` environment. This file stubs the
// minimum surface they touch at LOAD time (they don't touch `document` at
// load time — only inside DOM-driven callbacks this test never calls) and
// then loads them via indirect eval, exactly like the sibling app
// test-core.mjs files extract inline <script> blocks from index.html.
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { webcrypto, createHash } from "node:crypto";

if (!globalThis.crypto) globalThis.crypto = webcrypto;
if (!globalThis.navigator) globalThis.navigator = {}; // vaultMem persist() checks navigator.storage (absent here — fine, optional)
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

const uiSrc = readFileSync(new URL("../ui.js", import.meta.url), "utf8");
(0, eval)(uiSrc);
assert.ok(window.Postern && window.Postern.ui, "ui.js loaded, Postern.ui namespace present");

const apiSrc = readFileSync(new URL("../api.js", import.meta.url), "utf8");
(0, eval)(apiSrc);
const P = window.Postern;
assert.ok(P.api && typeof P.api.invoke === "function", "api.js loaded, Postern.api present");
assert.equal(P.api.hasBackend, false, "no window.__TAURI__ in Node — this IS the preview-engine surface");
assert.equal(P.api.isReal("vault_status"), false, "isReal requires hasBackend — confirms we're exercising the preview path, not the native Tauri command");

/* ============================================================
   MOCK PosternSDK — a TEST DOUBLE for the frozen contract
   (crates/postern-sdk/wasm/postern-sdk.js). NOT real crypto — see the
   sibling app test-core.mjs files for the full contract note.
   ============================================================ */
function concatBytes(...arrs) {
  const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0));
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}
// F3-flake fix: the mock previously derived its keystream/tag with FNV-1a (a
// 32-bit non-cryptographic hash meant for hash-table dispersion, not
// collision/preimage resistance) and truncated the AEAD tag to 4 bytes. That
// combination measured an ~11% false-accept rate for a WRONG passphrase in
// the "wrong passphrase rejected" parity assertions — i.e. flaky, not just
// theoretically weak. Fixed by (a) using SHA-256 (real avalanche/diffusion,
// still just a synchronous test double — not claiming this IS the wasm
// core's Argon2id/XChaCha20-Poly1305) and (b) widening the tag from 4 to 16
// bytes, so accidental collision is now ~2^-128, not ~1-in-9.
function sha256(bytes) {
  return new Uint8Array(createHash("sha256").update(bytes).digest());
}
function mockDerive(passBytes, saltBytes) {
  return sha256(concatBytes(saltBytes, new Uint8Array([0x1f]), passBytes));
}
function mockStream(keyBytes, ctxBytes, nonce, len) {
  // SHA-256(key‖ctx‖nonce‖counter) blocks, concatenated and truncated to len
  // — a simple, deterministic, synchronous stand-in for a real XChaCha20
  // keystream (not itself claimed to be that primitive).
  const out = new Uint8Array(len);
  let o = 0, counter = 0;
  while (o < len) {
    const block = sha256(concatBytes(keyBytes, ctxBytes, nonce, new Uint8Array([counter & 0xff, (counter >>> 8) & 0xff])));
    const take = Math.min(block.length, len - o);
    out.set(block.subarray(0, take), o);
    o += take; counter++;
  }
  return out;
}
function mockTag(keyBytes, ctxBytes, nonce, ct) {
  return sha256(concatBytes(keyBytes, ctxBytes, new Uint8Array([0xa5]), ct, nonce)).subarray(0, 16);
}
class MockVaultKey {
  constructor(bytes) { this.k = bytes; this.freed = false; }
  aeadSeal(ctx, pt) {
    const nonce = crypto.getRandomValues(new Uint8Array(8));
    const ks = mockStream(this.k, ctx, nonce, pt.length);
    const ct = new Uint8Array(pt.length);
    for (let i = 0; i < pt.length; i++) ct[i] = pt[i] ^ ks[i];
    const tag = mockTag(this.k, ctx, nonce, ct);
    return concatBytes(nonce, tag, ct);
  }
  aeadOpen(ctx, blob) {
    const nonce = blob.slice(0, 8), tag = blob.slice(8, 24), ct = blob.slice(24);
    const expect = mockTag(this.k, ctx, nonce, ct);
    for (let i = 0; i < 16; i++) if (tag[i] !== expect[i]) throw new Error("mock aead: tag mismatch — all-or-nothing");
    const ks = mockStream(this.k, ctx, nonce, ct.length);
    const pt = new Uint8Array(ct.length);
    for (let i = 0; i < ct.length; i++) pt[i] = ct[i] ^ ks[i];
    return pt;
  }
  free() { this.freed = true; }
}
function installMockSDK() {
  globalThis.PosternSDK = {
    __postern: true, version: "test-double", backend: "mock",
    kdf: {
      available: true,
      label: "Argon2id (m=65536 KiB, t=3, p=1)",
      generateSalt: () => crypto.getRandomValues(new Uint8Array(16)),
      deriveKey: (pass, salt) => new MockVaultKey(mockDerive(pass, salt)),
      seal: (k, ctx, pt) => k.aeadSeal(ctx, pt),
      open: (k, ctx, blob) => k.aeadOpen(ctx, blob),
    },
  };
}
function uninstallSDK() { delete globalThis.PosternSDK; }
uninstallSDK(); // default posture: no host shell has loaded the wasm core

let passed = 0;
const t = (name, fn) => Promise.resolve().then(fn).then(() => { passed++; console.log("  ok — " + name); });

function resetVault() { localStorage.removeItem("postern.preview.vault"); }

await t("SEAM absent by default: vault_create seals under the honest PBKDF2 stand-in, and it round-trips", async () => {
  resetVault();
  const created = await P.api.invoke("vault_create", { passphrase: "correct horse battery" });
  assert.equal(created.exists, true);
  assert.equal(created.unlocked, true);
  assert.match(created.cipher, /PBKDF2-SHA-256 stand-in/);
  assert.ok(!/real Argon2id/.test(created.cipher), "must never claim real when the seam is absent");

  await P.api.invoke("vault_put", { name: "github-token", secret: "ghp_abc123" });
  await P.api.invoke("vault_lock");
  const locked = await P.api.invoke("vault_status");
  assert.equal(locked.unlocked, false);

  const unlocked = await P.api.invoke("vault_unlock", { passphrase: "correct horse battery" });
  assert.equal(unlocked.unlocked, true);
  assert.equal(await P.api.invoke("vault_get", { name: "github-token" }), "ghp_abc123");

  await assert.rejects(P.api.invoke("vault_unlock", { passphrase: "wrong-pass" })); // wrong pass after re-lock attempt
});

await t("SEAM present: vault_create routes to the REAL Argon2id/XChaCha20 core and tags it REAL", async () => {
  resetVault();
  installMockSDK();
  try {
    const created = await P.api.invoke("vault_create", { passphrase: "host-shell-pass" });
    assert.equal(created.exists, true);
    assert.match(created.cipher, /XChaCha20-Poly1305 \(real Argon2id, via postern-sdk\)/);

    await P.api.invoke("vault_put", { name: "api-key", secret: "sk-ant-real-core-secret" });
    await P.api.invoke("vault_lock");

    const unlocked = await P.api.invoke("vault_unlock", { passphrase: "host-shell-pass" });
    assert.equal(unlocked.unlocked, true);
    assert.equal(await P.api.invoke("vault_get", { name: "api-key" }), "sk-ant-real-core-secret");

    await P.api.invoke("vault_lock");
    await assert.rejects(P.api.invoke("vault_unlock", { passphrase: "wrong-host-pass" })); // real core: all-or-nothing
  } finally {
    uninstallSDK();
  }
});

await t("fail-closed: a real-core vault CANNOT unlock once the seam is gone — no silent downgrade, honest error", async () => {
  // realVault was created + locked in the previous case, with globalThis.PosternSDK now removed.
  const status = await P.api.invoke("vault_status");
  assert.equal(status.exists, true);
  assert.match(status.cipher, /real Argon2id/, "the on-disk record is still honestly tagged REAL even though the seam is gone");
  await assert.rejects(
    P.api.invoke("vault_unlock", { passphrase: "host-shell-pass" }), // correct passphrase, but no core loaded
    /postern-sdk|host shell/,
    "must refuse — never fall back to PBKDF2 to open a vault sealed by the real core",
  );
});

await t("vault_discard evicts memory and clears the on-disk record regardless of which KDF sealed it", async () => {
  installMockSDK();
  try {
    await P.api.invoke("vault_discard");
    const status = await P.api.invoke("vault_status");
    assert.equal(status.exists, false);
    assert.equal(status.cipher, null);
  } finally {
    uninstallSDK();
  }
});

console.log(`\ndesktop vault (preview-engine seam) core: ${passed} checks passed`);
