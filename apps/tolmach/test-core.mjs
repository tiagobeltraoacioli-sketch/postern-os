// TOLMACH core tests — run with: node test-core.mjs   (Node >= 18)
//
// Tolmach's notes-vault primitives (te/td/b64/unb64/VSDK/deriveVaultKey/
// aeadEncrypt/cipherOf/aeadDecrypt — all DOM-free, no IndexedDB needed to
// exercise the crypto itself) are extracted straight out of index.html's
// single CSP-hash-pinned <script> by locating the contiguous span with
// indexOf (there is no id-tagged block to regex-match — the whole page is
// one pinned script). This proves the real postern-sdk SEAM dispatch these
// primitives already implement: (a) the honest labeled PBKDF2 stand-in when
// globalThis.PosternSDK is absent, (b) the REAL Argon2id/XChaCha20-Poly1305
// path when a stub PosternSDK is installed, and (c) fail-closed — a
// real-core cipher never silently opens under the stand-in path.
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { webcrypto, createHash } from "node:crypto";

if (!globalThis.crypto) globalThis.crypto = webcrypto;

const html = readFileSync(new URL("./index.html", import.meta.url), "utf8");
const start = html.indexOf("const te = new TextEncoder();");
assert.ok(start !== -1, "vault primitives start found");
const end = html.indexOf("\n/* IndexedDB plumbing */", start);
assert.ok(end !== -1, "vault primitives end found");
const code = html.slice(start, end)
  + "\nglobalThis.__VSDK = VSDK; globalThis.__KDF_REAL = KDF_REAL; globalThis.__deriveVaultKey = deriveVaultKey; "
  + "globalThis.__aeadEncrypt = aeadEncrypt; globalThis.__aeadDecrypt = aeadDecrypt; globalThis.__cipherOf = cipherOf;";
(0, eval)(code);
const VSDK = globalThis.__VSDK;
const KDF_REAL = globalThis.__KDF_REAL;
const deriveVaultKey = globalThis.__deriveVaultKey;
const aeadEncrypt = globalThis.__aeadEncrypt;
const aeadDecrypt = globalThis.__aeadDecrypt;
assert.ok(VSDK && typeof deriveVaultKey === "function" && typeof aeadEncrypt === "function", "vault core loaded, DOM-free");
assert.equal(KDF_REAL, "Argon2id-postern-sdk");

/* ============================================================
   MOCK PosternSDK — a TEST DOUBLE for the frozen contract
   (crates/postern-sdk/wasm/postern-sdk.js). NOT real crypto — see the
   sibling test files (postern-store, sotto) for the full contract note.
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

const te = new TextEncoder();
const AAD = "tolmach.notes.v1";
const PLAINTEXT = JSON.stringify({ title: "call notes", body: "the deal points" });

await t("SEAM absent by default: VSDK.real() is false, deriveVaultKey uses the honest PBKDF2 stand-in", async () => {
  assert.equal(VSDK.real(), false);
  const kw = await deriveVaultKey("correct horse battery", crypto.getRandomValues(new Uint8Array(16)), 600000, VSDK.real());
  assert.equal(kw.real, false);
  const cipher = await aeadEncrypt(kw, PLAINTEXT, AAD);
  assert.equal(cipher.algo, "AES-256-GCM");
  const opened = await aeadDecrypt(kw, cipher, AAD);
  assert.equal(opened, PLAINTEXT);
});

let realCipher = null, realSalt = null;
await t("SEAM present: deriveVaultKey/aeadEncrypt route to the REAL Argon2id/XChaCha20 core", async () => {
  installMockSDK();
  try {
    assert.equal(VSDK.real(), true);
    realSalt = crypto.getRandomValues(new Uint8Array(16));
    const kw = await deriveVaultKey("host-shell-pass", realSalt, 0, VSDK.real());
    assert.equal(kw.real, true);
    assert.match(kw.label, /Argon2id/);
    const cipher = await aeadEncrypt(kw, PLAINTEXT, AAD);
    assert.equal(cipher.algo, "XChaCha20-Poly1305");
    assert.ok(cipher.blob, "sealed cipher carries a blob");
    realCipher = cipher;
    const opened = await aeadDecrypt(kw, realCipher, AAD);
    assert.equal(opened, PLAINTEXT);
    const wrongKw = await deriveVaultKey("wrong-host-pass", realSalt, 0, true);
    await assert.rejects(aeadDecrypt(wrongKw, realCipher, AAD)); // real core: all-or-nothing
  } finally {
    uninstallSDK();
  }
});

await t("fail-closed: a real-core cipher CANNOT open in a plain tab — no silent downgrade, honest error", async () => {
  assert.ok(realCipher && realCipher.algo === "XChaCha20-Poly1305", "have a real-core cipher from the SDK-present run");
  uninstallSDK(); // back to a plain browser tab
  const standinKw = await deriveVaultKey("host-shell-pass", realSalt, 600000, false); // keyWrap.real === false now
  await assert.rejects(
    aeadDecrypt(standinKw, realCipher, AAD),
    /real postern-sdk core/,
    "must refuse — never fall back to PBKDF2 to 'open' bytes sealed by the real core",
  );
});

await t("cipherOf normalizes legacy untagged {iv,ct} records as AES-256-GCM (never mistaken for real)", () => {
  const legacy = { iv: "AAAA", ct: "BBBB" };
  const c = globalThis.__cipherOf(legacy);
  assert.equal(c.algo, "AES-256-GCM");
});

await t("fail-closed the OTHER direction: a stand-in AES-256-GCM cipher CANNOT open under a real-core keyWrap", async () => {
  // Mirror of the existing "real cipher can't open in a plain tab" check, but
  // for the direction that wasn't yet exercised: aeadDecrypt's dispatch reads
  // cipher.algo, so a stand-in-sealed record must stay closed even when the
  // caller holds a "real" (postern-sdk) keyWrap — no accidental WebCrypto
  // fallback that would treat the real keyWrap's opaque key object as a
  // CryptoKey and produce a false accept or partial plaintext.
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const standinKw = await deriveVaultKey("some passphrase", salt, 600000, false);
  const standinCipher = await aeadEncrypt(standinKw, PLAINTEXT, AAD);
  assert.equal(standinCipher.algo, "AES-256-GCM");

  installMockSDK();
  try {
    const realKw = await deriveVaultKey("host-shell-pass", salt, 0, true);
    assert.equal(realKw.real, true);
    await assert.rejects(
      aeadDecrypt(realKw, standinCipher, AAD),
      "must refuse — a real-core keyWrap must never be handed to crypto.subtle.decrypt as if it were a CryptoKey",
    );
  } finally {
    uninstallSDK();
  }
});

console.log(`\ntolmach core: ${passed} checks passed`);
