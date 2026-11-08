// POSTERN-STORE core tests — run with: node test-core.mjs   (Node >= 18)
//
// postern-store's KeySeal (LS/store/KeySeal, all DOM-free) is extracted
// straight out of index.html's single CSP-hash-pinned <script> by locating
// the "const LS = {" ... KeySeal IIFE span with indexOf (there is no id-
// tagged block to regex-match here — the whole page is one pinned script).
// Exercises the real postern-sdk SEAM dispatch: (a) the honest labeled
// PBKDF2 stand-in when globalThis.PosternSDK is absent, (b) the REAL
// Argon2id/XChaCha20-Poly1305 path when a stub PosternSDK is installed, and
// (c) fail-closed — a real-core blob never silently opens under the
// stand-in path.
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { webcrypto, createHash } from "node:crypto";

if (!globalThis.crypto) globalThis.crypto = webcrypto;

// ---- minimal localStorage polyfill (KeySeal's `store` wrapper needs it) ----
{
  const mem = new Map();
  globalThis.localStorage = {
    getItem: (k) => (mem.has(k) ? mem.get(k) : null),
    setItem: (k, v) => { mem.set(k, String(v)); },
    removeItem: (k) => { mem.delete(k); },
    clear: () => mem.clear(),
  };
}

const html = readFileSync(new URL("./index.html", import.meta.url), "utf8");
const start = html.indexOf("const LS = {");
assert.ok(start !== -1, "LS block found");
const ksStart = html.indexOf("const KeySeal = (() => {", start);
assert.ok(ksStart !== -1, "KeySeal IIFE found");
const ksEnd = html.indexOf("\n})();", ksStart);
assert.ok(ksEnd !== -1, "KeySeal IIFE close found");
const code = html.slice(start, ksEnd + "\n})();".length)
  + "\nglobalThis.__KeySeal = KeySeal; globalThis.__store = store; globalThis.__LS = LS;";
(0, eval)(code);
const KeySeal = globalThis.__KeySeal;
const store = globalThis.__store;
const LS = globalThis.__LS;
assert.ok(KeySeal && typeof KeySeal.lock === "function" && typeof KeySeal.unlock === "function", "KeySeal loaded, DOM-free");

/* ============================================================
   MOCK PosternSDK — a TEST DOUBLE for the frozen contract
   (crates/postern-sdk/wasm/postern-sdk.js). NOT real crypto — a
   synchronous, reversible, context-authenticated transform standing in for
   the wasm Argon2id(64 MiB,t=3) + XChaCha20-Poly1305 core, purely to
   exercise KeySeal's dispatch / round-trip / labels. The REAL Argon2id
   proof lives in the postern-sdk wasm crate (compile-gated) and is not
   reproduced here — this double only proves the app routes onto the
   contract correctly and stays honest when it's absent.
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
uninstallSDK(); // default posture: plain browser tab, no host shell

let passed = 0;
const t = (name, fn) => Promise.resolve().then(fn).then(() => { passed++; console.log("  ok — " + name); });

await t("SEAM absent by default: KeySeal.real() is false, never claims REAL", () => {
  assert.equal(KeySeal.real(), false);
});

await t("stand-in path: lock() seals under the labeled PBKDF2/AES-GCM stand-in and round-trips", async () => {
  store.set(LS.SEALED, undefined); store.del(LS.SEALED);
  await KeySeal.lock("correct horse battery", "sk-ant-plaintext-1");
  assert.equal(KeySeal.isSealed(), true);
  assert.match(KeySeal.cipherLabel(), /PBKDF2-SHA-256 stand-in/);
  KeySeal.forget();
  assert.equal(KeySeal.isLocked(), true);
  const ok = await KeySeal.unlock("correct horse battery");
  assert.equal(ok, true);
  assert.equal(KeySeal.key(), "sk-ant-plaintext-1");
  const bad = await KeySeal.unlock("wrong pass");
  assert.equal(bad, false); // all-or-nothing, GCM tag fails
});

let realSealedPresent = false;
await t("SEAM present: lock() routes to the REAL Argon2id/XChaCha20 core and flips the label to REAL", async () => {
  KeySeal.forget();
  store.del(LS.SEALED);
  installMockSDK();
  try {
    assert.equal(KeySeal.real(), true);
    await KeySeal.lock("host-shell-pass", "sk-ant-real-core-secret");
    assert.match(KeySeal.cipherLabel(), /XChaCha20-Poly1305 \(real Argon2id, via postern-sdk\)/);
    KeySeal.forget();
    const ok = await KeySeal.unlock("host-shell-pass");
    assert.equal(ok, true);
    assert.equal(KeySeal.key(), "sk-ant-real-core-secret");
    const bad = await KeySeal.unlock("wrong-host-pass");
    assert.equal(bad, false); // real core: all-or-nothing too
    realSealedPresent = true;
  } finally {
    uninstallSDK();
  }
});

await t("fail-closed: a real-core blob CANNOT open in a plain tab — no silent downgrade, honest refusal", async () => {
  assert.ok(realSealedPresent, "have a real-core-sealed record from the SDK-present run");
  KeySeal.forget();
  uninstallSDK(); // back to a plain browser tab
  const ok = await KeySeal.unlock("host-shell-pass"); // correct passphrase, but no core loaded
  assert.equal(ok, false, "must refuse — never fall back to PBKDF2 to 'open' bytes sealed by the real core");
});

await t("dispatch is on the stored kdf.algo, not current seam state (stand-in blob still opens with SDK present)", async () => {
  KeySeal.forget();
  store.del(LS.SEALED);
  uninstallSDK();
  await KeySeal.lock("mixed-state-pass", "sk-ant-mixed");
  assert.match(KeySeal.cipherLabel(), /PBKDF2-SHA-256 stand-in/);
  KeySeal.forget();
  installMockSDK();
  try {
    const ok = await KeySeal.unlock("mixed-state-pass"); // opens via the tagged PBKDF2 branch, not real
    assert.equal(ok, true);
    assert.equal(KeySeal.key(), "sk-ant-mixed");
  } finally {
    uninstallSDK();
  }
});

console.log(`\npostern-store core: ${passed} checks passed`);
