// VEDETTA core tests — run with: node test-core.mjs   (Node >= 18)
//
// Vedetta's at-rest vault primitives (VSDK/KDF_REAL/b64/unb64/deriveVaultKey/
// aeadEncrypt/aeadDecrypt — DOM-free) are extracted straight out of
// index.html's single CSP-hash-pinned <script> by locating the contiguous
// span with indexOf (there is no id-tagged block to regex-match — the whole
// page is one pinned script). `te`/`td` are declared much earlier in the
// same script (shared with the KeySeal block for the API keys) — they are
// reconstructed here rather than re-sliced, since TextEncoder/TextDecoder
// are pure globals with no state. This proves the real postern-sdk SEAM
// dispatch these primitives implement (the SAME construction KeySeal reuses
// for the Anthropic/Finnhub API keys via deriveVaultKey/aeadEncrypt/
// aeadDecrypt): (a) the honest labeled PBKDF2 stand-in when
// globalThis.PosternSDK is absent, (b) the REAL Argon2id/XChaCha20-Poly1305
// path when a stub PosternSDK is installed, and (c) fail-closed — a
// real-core cipher never silently opens under the stand-in path.
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { webcrypto, createHash } from "node:crypto";

if (!globalThis.crypto) globalThis.crypto = webcrypto;

const html = readFileSync(new URL("./index.html", import.meta.url), "utf8");
const start = html.indexOf("const VSDK = {");
assert.ok(start !== -1, "VSDK block start found");
const end = html.indexOf("\nlet vaultSalt = null", start);
assert.ok(end !== -1, "VSDK block end found");
const code = "const te = new TextEncoder(); const td = new TextDecoder();\n"
  + html.slice(start, end)
  + "\nglobalThis.__VSDK = VSDK; globalThis.__KDF_REAL = KDF_REAL; globalThis.__deriveVaultKey = deriveVaultKey; "
  + "globalThis.__aeadEncrypt = aeadEncrypt; globalThis.__aeadDecrypt = aeadDecrypt;";
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
   sibling test files (postern-store, sotto, tolmach) for the full contract
   note.
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

const AAD = "vedetta.apikeys.v1";
const PLAINTEXT = JSON.stringify({ key: "sk-ant-plain", finnhub: "fh-token" });

await t("SEAM absent by default: VSDK.real() is false, deriveVaultKey uses the honest PBKDF2 stand-in", async () => {
  assert.equal(VSDK.real(), false);
  const kw = await deriveVaultKey("correct horse battery", crypto.getRandomValues(new Uint8Array(16)), 310000, VSDK.real());
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
  const standinKw = await deriveVaultKey("host-shell-pass", realSalt, 310000, false); // keyWrap.real === false now
  await assert.rejects(
    aeadDecrypt(standinKw, realCipher, AAD),
    /real postern-sdk core/,
    "must refuse — never fall back to PBKDF2 to 'open' bytes sealed by the real core",
  );
});

/* ============================================================
   CSP / XSS-sink regression guards -- static checks over the raw
   HTML source (not the extracted VSDK block). Added by the
   harden/sotto-vedetta pass, which moved script-src off a bare
   'unsafe-inline' onto a hash pin of the exact inline <script>
   content (the sha256 source is honored by CSP2+ browsers, which
   ignore 'unsafe-inline' once a hash-source is present; the
   'unsafe-inline' token stays only as a no-op fallback for pre-CSP2
   browsers). These tests keep that pin honest and guard against a
   future innerHTML/setStatus call site, or a widened connect-src,
   sneaking in unnoticed.
   ============================================================ */
const cspMatch = html.match(/<meta http-equiv="Content-Security-Policy" content="([^"]+)">/);

await t("CSP: no unsafe-eval hole, default-src/base-uri/form-action stay locked to 'none'", () => {
  assert.ok(cspMatch, "CSP meta tag found");
  const csp = cspMatch[1];
  assert.doesNotMatch(csp, /unsafe-eval/, "no unsafe-eval hole");
  assert.match(csp, /default-src 'none'/);
  assert.match(csp, /base-uri 'none'/);
  assert.match(csp, /form-action 'none'/);
});

await t("CSP: script-src is hash-pinned to the exact inline <script> content, not bare 'unsafe-inline'", () => {
  const csp = cspMatch[1];
  const scriptSrcMatch = csp.match(/script-src ([^;]+);/);
  assert.ok(scriptSrcMatch, "script-src directive found");
  const hashMatch = scriptSrcMatch[1].match(/'sha256-([^']+)'/);
  assert.ok(hashMatch, "script-src carries a sha256 hash source, not just 'unsafe-inline'");
  const scriptStart = html.indexOf('<script>\n"use strict') + "<script>".length;
  const scriptEnd = html.indexOf("</script>", scriptStart);
  const scriptContent = html.slice(scriptStart, scriptEnd);
  const actualHash = createHash("sha256").update(scriptContent, "utf8").digest("base64");
  assert.equal(hashMatch[1], actualHash, "declared CSP hash must match the actual inline script content -- catches a stale hash after edits");
});

await t("CSP: connect-src is exactly the disclosed providers -- Anthropic + the 4 market-data hosts, nothing else", () => {
  const csp = cspMatch[1];
  const connectSrcMatch = csp.match(/connect-src ([^;]+);/);
  assert.ok(connectSrcMatch);
  const origins = connectSrcMatch[1].trim().split(/\s+/).sort();
  assert.deepEqual(origins, [
    "https://api.anthropic.com",
    "https://api.coingecko.com",
    "https://api.frankfurter.dev",
    "https://finnhub.io",
    "https://query1.finance.yahoo.com",
  ].sort());
});

await t("XSS guard: every setStatus() call passes a string literal or an escapeHtml()-wrapped value", () => {
  const scriptSrc = html.slice(html.indexOf("<script>"));
  const callRe = /setStatus\(/g;
  let m, checked = 0;
  while ((m = callRe.exec(scriptSrc))) {
    const before = scriptSrc.slice(Math.max(0, m.index - 9), m.index);
    if (before.endsWith("function ")) continue; // skip the function's own definition
    const after = scriptSrc.slice(m.index + "setStatus(".length, m.index + "setStatus(".length + 24).trimStart();
    const ok = after.startsWith("escapeHtml(") || /^['"`]/.test(after);
    assert.ok(ok, `setStatus() call at offset ${m.index} is neither a literal nor escapeHtml()-wrapped: ...${after}`);
    checked++;
  }
  assert.ok(checked >= 10, `expected to find and vet several setStatus() call sites, found ${checked}`);
});

await t("XSS guard: every .innerHTML assignment is a clear, a literal, or the vetted setStatus(html) sink", () => {
  const scriptSrc = html.slice(html.indexOf("<script>"));
  const assigns = [...scriptSrc.matchAll(/\.innerHTML\s*=\s*([^;]+);/g)].map(mm => mm[1].trim());
  assert.ok(assigns.length >= 5, "found innerHTML assignment sites to vet");
  for (const rhs of assigns) {
    const ok = rhs === '""' || rhs === "''" || /^['"`]/.test(rhs) || rhs === "html";
    assert.ok(ok, `unvetted dynamic innerHTML assignment: ${rhs}`);
  }
});

await t("XSS guard: quote-provider responses (name/price fields) reach the DOM only via textContent (td_/th_ helpers), never innerHTML", () => {
  const scriptSrc = html.slice(html.indexOf("<script>"));
  assert.match(scriptSrc, /function td_\(cls, text\) \{ const c = document\.createElement\("td"\);.*c\.textContent = text;/,
    "td_() helper must assign via textContent");
});

console.log(`\nvedetta core: ${passed} checks passed`);
