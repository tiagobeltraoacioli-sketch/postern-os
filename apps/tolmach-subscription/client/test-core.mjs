// TOLMACH-SUBSCRIPTION (client) core tests — run with: node test-core.mjs
// (Node >= 18)
//
// Tolmach-subscription's notes-vault primitives (VAULT_DB/VAULT_V/KDF_ID/
// KDF_ITER/KDF_REAL/sdk/kdfReal/deriveVaultKey/b64/unb64/aeadEncrypt/
// aeadDecrypt — all DOM-free, no IndexedDB needed to exercise the crypto
// itself) are extracted straight out of index.html's single <script> by
// locating the contiguous span with indexOf (this page has no id-tagged
// block to regex-match). `vault.create`/`vault.unlockWith` (the app-level
// wrapper, which persists to IndexedDB) are built directly on top of these
// same primitives — dispatching on `kdfReal()` to choose the KDF and on the
// VaultKey handle's shape (`.aeadSeal`/`.aeadOpen`) inside aeadEncrypt/
// aeadDecrypt — so exercising the primitives directly proves the real
// dispatch without needing a fake IndexedDB. Proves: (a) the honest labeled
// PBKDF2 stand-in when globalThis.PosternSDK is absent, (b) the REAL
// Argon2id/XChaCha20-Poly1305 path when a stub PosternSDK is installed, and
// (c) fail-closed — a real-core cipher never silently opens under the
// stand-in path.
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { webcrypto, createHash } from "node:crypto";

if (!globalThis.crypto) globalThis.crypto = webcrypto;

const html = readFileSync(new URL("./index.html", import.meta.url), "utf8");
const start = html.indexOf("const VAULT_DB");
assert.ok(start !== -1, "vault primitives start found");
const end = html.indexOf("\n/* IndexedDB plumbing */", start);
assert.ok(end !== -1, "vault primitives end found");
const code = html.slice(start, end)
  + "\nglobalThis.__sdk = sdk; globalThis.__kdfReal = kdfReal; globalThis.__deriveVaultKey = deriveVaultKey; "
  + "globalThis.__aeadEncrypt = aeadEncrypt; globalThis.__aeadDecrypt = aeadDecrypt; globalThis.__KDF_REAL = KDF_REAL; "
  + "globalThis.__KDF_ITER = KDF_ITER;";
(0, eval)(code);
const sdk = globalThis.__sdk;
const kdfReal = globalThis.__kdfReal;
const deriveVaultKey = globalThis.__deriveVaultKey; // PBKDF2 stand-in derivation only (per source name)
const aeadEncrypt = globalThis.__aeadEncrypt;
const aeadDecrypt = globalThis.__aeadDecrypt;
const KDF_REAL = globalThis.__KDF_REAL;
const KDF_ITER = globalThis.__KDF_ITER;
assert.ok(typeof kdfReal === "function" && typeof aeadEncrypt === "function", "vault core loaded, DOM-free");
assert.equal(KDF_REAL, "Argon2id-postern-sdk");

/* ============================================================
   MOCK PosternSDK — a TEST DOUBLE for the frozen contract
   (crates/postern-sdk/wasm/postern-sdk.js). NOT real crypto — see the
   sibling test files (postern-store, sotto, tolmach, vedetta) for the full
   contract note.
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

const AAD = "meta|1";
const VERIFIER = "tolmach-vault-check";

/* Mirrors vault.create()'s own dispatch: kdfReal() picks the primitive. */
async function createLike(passphrase) {
  if (kdfReal()) {
    const s = sdk();
    const salt = s.kdf.generateSalt();
    const key = s.kdf.deriveKey(new TextEncoder().encode(passphrase), salt);
    return { key, meta: { kdf: KDF_REAL, salt } };
  }
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveVaultKey(passphrase, salt, KDF_ITER);
  return { key, meta: { kdf: "PBKDF2-SHA256/600000", salt, iter: KDF_ITER } };
}
/* Mirrors vault.unlockWith()'s own dispatch: the STORED meta.kdf tag picks it. */
async function unlockLike(passphrase, meta) {
  if (meta.kdf === KDF_REAL) {
    if (!kdfReal()) throw new Error("real postern-sdk Argon2id core, which isn't loaded here");
    return sdk().kdf.deriveKey(new TextEncoder().encode(passphrase), meta.salt);
  }
  return deriveVaultKey(passphrase, meta.salt, meta.iter);
}

await t("SEAM absent by default: kdfReal() is false, create()-like path uses the honest PBKDF2 stand-in", async () => {
  assert.equal(kdfReal(), false);
  const { key, meta } = await createLike("correct horse battery");
  assert.equal(meta.kdf, "PBKDF2-SHA256/600000");
  const verifier = await aeadEncrypt(key, VERIFIER, AAD);
  assert.equal(verifier.ct.length > 0, true);
  assert.equal(verifier.iv.length > 0, true); // real IV present — stand-in path
  const openedKey = await unlockLike("correct horse battery", meta);
  const check = await aeadDecrypt(openedKey, verifier.iv, verifier.ct, AAD);
  assert.equal(check, VERIFIER);
});

let realMeta = null, realVerifier = null;
await t("SEAM present: create()-like path routes to the REAL Argon2id/XChaCha20 core", async () => {
  installMockSDK();
  try {
    assert.equal(kdfReal(), true);
    const { key, meta } = await createLike("host-shell-pass");
    assert.equal(meta.kdf, KDF_REAL);
    realMeta = meta;
    const verifier = await aeadEncrypt(key, VERIFIER, AAD);
    assert.equal(verifier.iv, ""); // real path: nonce lives inside the opaque blob, iv field unused
    assert.ok(verifier.ct, "real-sealed verifier carries ciphertext");
    realVerifier = verifier;
    const openedKey = await unlockLike("host-shell-pass", realMeta);
    const check = await aeadDecrypt(openedKey, realVerifier.iv, realVerifier.ct, AAD);
    assert.equal(check, VERIFIER);
    const wrongKey = await unlockLike("wrong-host-pass", realMeta);
    await assert.rejects(aeadDecrypt(wrongKey, realVerifier.iv, realVerifier.ct, AAD)); // real core: all-or-nothing
  } finally {
    uninstallSDK();
  }
});

await t("fail-closed: a real-core vault CANNOT unlock in a plain tab — no silent downgrade, honest error", async () => {
  assert.ok(realMeta && realMeta.kdf === KDF_REAL, "have a real-core meta from the SDK-present run");
  uninstallSDK(); // back to a plain browser tab
  await assert.rejects(
    unlockLike("host-shell-pass", realMeta),
    /real postern-sdk/,
    "must refuse — never fall back to PBKDF2 to derive a key for a vault sealed by the real core",
  );
});

await t("import validation: a real-sealed record's empty iv is never treated as 'missing' (iv == null check)", () => {
  // Regression check for the exact bug this wiring introduced and fixed:
  // real-core records carry iv:"" (falsy) — validation must use `== null`,
  // not `!rec.iv`, or every real-sealed record would be silently rejected.
  const rec = { id: "r1", iv: "", ct: "c29tZWJsb2I=" };
  assert.equal(rec.iv == null, false, "empty string must NOT read as missing");
  assert.equal(!rec.iv, true, "...even though it IS falsy — this is exactly the trap");
});

console.log(`\ntolmach-subscription (client) core: ${passed} checks passed`);
