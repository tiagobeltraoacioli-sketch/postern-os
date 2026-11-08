// SPDX-License-Identifier: MIT OR Apache-2.0
// Issuance regression — run with: node issuance.test.mjs   (Node >= 18)
// Proves the ADDITIVE `kyc` token field is canonical-safe: master.js still issues,
// the vendor signature still verifies, a token WITHOUT kyc (old shape) verifies, and
// the bound `kyc` verdict is PII-free and comes BY REFERENCE from KV (no self-inflate).
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
if (!globalThis.crypto) globalThis.crypto = webcrypto;

const master = await import(new URL("../../functions/license/master.js", import.meta.url));

// canonical() is identical to the one inside master.js (byte-for-byte contract).
function canonical(obj) {
  if (Array.isArray(obj)) return "[" + obj.map(canonical).join(",") + "]";
  if (obj && typeof obj === "object") return "{" + Object.keys(obj).sort().map((k) => JSON.stringify(k) + ":" + canonical(obj[k])).join(",") + "}";
  return JSON.stringify(obj);
}
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const b64d = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

// A vendor keypair for the test deployment.
const vendorKp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
const vendorPrivB64 = b64(new Uint8Array(await crypto.subtle.exportKey("pkcs8", vendorKp.privateKey)));

function makeKV(seed = {}) { const m = new Map(Object.entries(seed)); return { m, get: async (k) => m.get(k) ?? null, put: async (k, v) => { m.set(k, v); } }; }
function dnbFound() {
  return async (url) => {
    if (String(url).includes("/token")) return { ok: true, json: async () => ({ access_token: "x" }) };
    return { ok: true, status: 200, json: async () => ({ organization: { primaryName: "Acme Widgets LLC", primaryAddress: { addressCountry: { isoAlpha2Code: "US" } } } }) };
  };
}
function req(bodyObj) { return new Request("https://x/license/master", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(bodyObj) }); }
async function issue(env, bodyObj) {
  globalThis.fetch = dnbFound(); // master.js verifyDunsWithDnB uses global fetch
  const res = await master.onRequestPost({ request: req(bodyObj), env, waitUntil: () => {} });
  return { status: res.status, json: JSON.parse(await res.text()) };
}
async function verifyBundle(j) {
  const vpk = await crypto.subtle.importKey("raw", new Uint8Array(await crypto.subtle.exportKey("raw", vendorKp.publicKey)), { name: "Ed25519" }, false, ["verify"]);
  return crypto.subtle.verify({ name: "Ed25519" }, vpk, b64d(j.master_sig), new TextEncoder().encode(canonical(j.master_token)));
}

let passed = 0;
const t = async (name, fn) => { await fn(); passed++; console.log("  ok — " + name); };

// ---- parity: self-declared issuance, no kyc_ref ---------------------------
await t("corporate master issues + verifies; kyc = self-declared LoA-0 (parity)", async () => {
  const env = { VENDOR_PRIV_PKCS8_B64: vendorPrivB64, DNB_BEARER: "b", LICENSES: makeKV() };
  const { status, json } = await issue(env, { tier: "corporate-master", duns: "150483782", role: "owner", attestation: true });
  assert.equal(status, 200);
  assert.ok(await verifyBundle(json), "vendor signature verifies WITH the new kyc field");
  assert.equal(json.master_token.kyc.loa, 0);
  assert.deepEqual(json.master_token.kyc.methods.sort(), ["dnb-entity", "self-declared"]);
  assert.equal(json.master_token.kyc.self_declared, true);
});

// ---- bind an authoritative verdict by reference ---------------------------
await t("kyc_ref binds the AUTHORITATIVE stored verdict (loa 2) into the token", async () => {
  const stored = { duns: "150483782", loa: 2, methods: ["self-declared", "dnb-entity", "corp-domain", "ocr-ondevice"], ocr: { onDevice: true, match: true, fieldsMatched: ["legalName", "country"], liveness: false }, domain: "acme.example", idvRef: null, verifiedAt: 111 };
  const env = { VENDOR_PRIV_PKCS8_B64: vendorPrivB64, DNB_BEARER: "b", LICENSES: makeKV({ "kyc:abc123": JSON.stringify(stored) }) };
  const { json } = await issue(env, { tier: "corporate-master", duns: "150483782", role: "owner", attestation: true, kyc_ref: "abc123" });
  assert.ok(await verifyBundle(json));
  assert.equal(json.master_token.kyc.loa, 2);
  assert.equal(json.master_token.kyc.ocr.onDevice, true);
  assert.equal(json.master_token.kyc.domain, "acme.example");
});

// ---- anti-swap: a ref issued for a DIFFERENT duns is ignored ---------------
await t("kyc_ref for a different DUNS is NOT bound (falls back to parity)", async () => {
  const stored = { duns: "999999999", loa: 3, methods: ["idv"], idvRef: "x", verifiedAt: 1 };
  const env = { VENDOR_PRIV_PKCS8_B64: vendorPrivB64, DNB_BEARER: "b", LICENSES: makeKV({ "kyc:zzz": JSON.stringify(stored) }) };
  const { json } = await issue(env, { tier: "corporate-master", duns: "150483782", role: "owner", attestation: true, kyc_ref: "zzz" });
  assert.equal(json.master_token.kyc.loa, 0, "cannot bind another DUNS's verdict");
});

// ---- old-shape compatibility: a token WITHOUT kyc still verifies -----------
await t("a legacy token (no kyc key) still verifies under the same canonical()", async () => {
  const legacy = { v: 1, typ: "master", tier: "corporate-master", duns: "150483782", seats: "unlimited", iat: 1, exp: 2, master_pub: "AA==", attestation: { role: "owner", self_declared: true }, jti: "aa", kid: "bb", iss: "posternlabs.com", dnb: { verified: true, source: "dnb-direct-plus", checkedAt: 1 } };
  const vk = await crypto.subtle.importKey("pkcs8", b64d(vendorPrivB64), { name: "Ed25519" }, false, ["sign"]);
  const sig = b64(new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, vk, new TextEncoder().encode(canonical(legacy)))));
  assert.ok(await verifyBundle({ master_token: legacy, master_sig: sig }));
});

// ---- freemium unchanged ---------------------------------------------------
await t("business-freemium issues with no kyc field (unchanged)", async () => {
  const env = { VENDOR_PRIV_PKCS8_B64: vendorPrivB64, LICENSES: makeKV() };
  const { status, json } = await issue(env, { tier: "business-freemium" });
  assert.equal(status, 200);
  assert.equal(json.master_token.kyc, undefined);
  assert.ok(await verifyBundle(json));
});

// ---- rate limit hardening: the corporate-master path that drives D&B lookups
// (hardening, pairs with review.js's 429/"rate-limited" handling) ----------
await t("corporate-master requests over the configured cap are refused 429 before touching D&B/signing", async () => {
  const env = { VENDOR_PRIV_PKCS8_B64: vendorPrivB64, DNB_BEARER: "b", LICENSES: makeKV(), MASTER_RATE_LIMIT_PER_MIN: 2 };
  const bodyObj = { tier: "corporate-master", duns: "150483782", role: "owner", attestation: true };
  const r1 = await issue(env, bodyObj);
  const r2 = await issue(env, bodyObj);
  const r3 = await issue(env, bodyObj);
  assert.equal(r1.status, 200);
  assert.equal(r2.status, 200);
  assert.equal(r3.status, 429, "3rd request in the same window must be rate-limited");
  assert.ok(r3.json.retryAfterSeconds > 0);
});
await t("the rate limiter counts per-window, not globally forever (a fresh window resets it)", async () => {
  const env = { VENDOR_PRIV_PKCS8_B64: vendorPrivB64, DNB_BEARER: "b", LICENSES: makeKV(), MASTER_RATE_LIMIT_PER_MIN: 1 };
  const bodyObj = { tier: "corporate-master", duns: "150483782", role: "owner", attestation: true };
  const r1 = await issue(env, bodyObj);
  const r2 = await issue(env, bodyObj);
  assert.equal(r1.status, 200);
  assert.equal(r2.status, 429);
  // simulate the same request landing in the NEXT rate-limit window by seeding
  // a fresh KV (equivalent to the bucketed key expiring/rolling over).
  const env2 = { ...env, LICENSES: makeKV() };
  const r3 = await issue(env2, bodyObj);
  assert.equal(r3.status, 200, "a fresh window must not still be limited");
});
await t("business-freemium is NOT subject to the D&B rate limiter (it never calls D&B)", async () => {
  const env = { VENDOR_PRIV_PKCS8_B64: vendorPrivB64, LICENSES: makeKV(), MASTER_RATE_LIMIT_PER_MIN: 1 };
  const r1 = await issue(env, { tier: "business-freemium" });
  const r2 = await issue(env, { tier: "business-freemium" });
  assert.equal(r1.status, 200);
  assert.equal(r2.status, 200, "freemium issuance must not be throttled by the corporate-master/D&B limiter");
});
await t("no LICENSES KV bound -> rate limiter is a no-op (fails open, matching this endpoint's existing outage posture)", async () => {
  const env = { VENDOR_PRIV_PKCS8_B64: vendorPrivB64, DNB_BEARER: "b", MASTER_RATE_LIMIT_PER_MIN: 1 }; // no LICENSES
  const bodyObj = { tier: "corporate-master", duns: "150483782", role: "owner", attestation: true };
  const r1 = await issue(env, bodyObj);
  const r2 = await issue(env, bodyObj);
  assert.equal(r1.status, 200);
  assert.equal(r2.status, 200, "without KV bound there is no counter to enforce, so it must not hard-fail issuance");
});

console.log("\n" + passed + " passed");
