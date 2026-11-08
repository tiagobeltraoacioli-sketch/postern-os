// SPDX-License-Identifier: MIT OR Apache-2.0
// Gramota review.js SEAM tests — run with: node review-seam.test.mjs (Node >= 18)
// Exercises kycGate (the seam Dev-1's onboarding consumes), the PII/image tripwire,
// and the authoritative LoA math with a STUBBED D&B fetch + an in-memory KV.
// OFFLINE / no live D&B call: every D&B interaction here goes through a local
// in-process stub (dnbStub) that fabricates the D&B HTTP response shape — never
// a real network request. Node's `fetch` is only ever monkey-patched to this stub.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { webcrypto } from "node:crypto";
if (!globalThis.crypto) globalThis.crypto = webcrypto;

const mod = await import(new URL("../../functions/license/review.js", import.meta.url));
const { kycGate, scanForPII, sanitizeClientVerdict, computeLoa, onRequestPost } = mod;

let passed = 0;
const t = async (name, fn) => { await fn(); passed++; console.log("  ok — " + name); };
const origFetch = globalThis.fetch;

// in-memory KV + a D&B stub that resolves a known DUNS and 404s another.
function makeKV() { const m = new Map(); return { m, get: async (k) => m.get(k) ?? null, put: async (k, v) => { m.set(k, v); } }; }
function dnbStub({ found = true } = {}) {
  return async (url) => {
    if (String(url).includes("/token")) return { ok: true, json: async () => ({ access_token: "x" }) };
    if (!found) return { ok: false, status: 404, json: async () => ({}) };
    return { ok: true, status: 200, json: async () => ({ organization: { primaryName: "Acme Widgets LLC", primaryAddress: { addressCountry: { isoAlpha2Code: "US" } } } }) };
  };
}
const CREDS = { DNB_BEARER: "test-bearer" };

// ---- tripwire -------------------------------------------------------------
await t("tripwire rejects an image field", () => {
  assert.ok(scanForPII({ duns: "123456789", image: "iVBOR..." }));
  assert.ok(scanForPII({ kyc: { ocr: { documentNumber: "A123" } } }));
  assert.ok(scanForPII({ note: "data:image/png;base64,AAAA" }));
});
await t("tripwire rejects over-long strings + blocked name/dob keys", () => {
  assert.ok(scanForPII({ blob: "x".repeat(600) }));
  assert.ok(scanForPII({ fullName: "Jane Doe" }));
  assert.ok(scanForPII({ dob: "1990-01-01" }));
});
await t("tripwire PASSES a clean minimal verdict", () => {
  assert.equal(scanForPII({ duns: "123456789", role: "owner", attestation: true, kyc: { ocr: { onDevice: true, match: true, fieldsMatched: ["legalName", "country"], liveness: false } } }), null);
});
await t("tripwire boundary: exactly MAX_STRING (512) passes, 513 rejects", () => {
  assert.equal(scanForPII({ note: "x".repeat(512) }), null);
  assert.ok(scanForPII({ note: "x".repeat(513) }));
});
await t("tripwire catches a data: URI nested arbitrarily deep inside kyc.ocr", () => {
  assert.ok(scanForPII({ duns: "123456789", kyc: { ocr: { onDevice: true, extra: { blob: "data:image/jpeg;base64,/9j/4AAQ" } } } }));
});
await t("tripwire catches a data: URI inside an array element", () => {
  assert.ok(scanForPII({ attachments: ["data:application/pdf;base64,JVBERi0="] }));
});
await t("tripwire rejects every PII key class: doc numbers, address, tax IDs, contact info", () => {
  ["documentNumber", "passportNumber", "mrz", "ssn", "cpf", "cnpj", "taxId", "address", "street", "city",
    "postalCode", "email", "phone", "telephone", "selfie", "scan", "attachment"].forEach((k) => {
    assert.ok(scanForPII({ [k]: "x" }), `expected "${k}" to be blocked`);
  });
});
await t("tripwire is case/punctuation-insensitive on blocked keys (Full-Name, FULLNAME, full_name)", () => {
  assert.ok(scanForPII({ "Full-Name": "Jane Doe" }));
  assert.ok(scanForPII({ FULLNAME: "Jane Doe" }));
  assert.ok(scanForPII({ full_name: "Jane Doe" }));
});

// ---- sanitize -------------------------------------------------------------
await t("sanitize keeps only allowed field names + booleans", () => {
  const s = sanitizeClientVerdict({ ocr: { onDevice: true, match: true, fieldsMatched: ["legalName", "country", "evil", "ssn"], liveness: true }, idvRef: "opq-123", domain: "acme.example" });
  assert.deepEqual(s.ocr.fieldsMatched, ["legalName", "country"]);
  assert.equal(s.idvRef, "opq-123");
  assert.equal(s.domain, "acme.example");
  assert.equal(s.corpDomain, true);
});

// ---- kycGate: parity when UNCONFIGURED (no regression) ---------------------
await t("kycGate default-unconfigured => pass, loa 0, enforced:false (parity)", async () => {
  const env = { LICENSES: makeKV() }; // no KYC_MODE, no D&B creds
  const v = await kycGate(env, { duns: "123456789", role: "owner", attestation: true, fetchImpl: dnbStub() });
  assert.equal(v.decision, "pass");
  assert.equal(v.loa, 0);
  assert.equal(v.enforced, false);
});

// ---- kycGate: enforced caps LoA-0 at provisional --------------------------
await t("kycGate enforced + self-declared only => provisional", async () => {
  const env = { KYC_MODE: "enforce", LICENSES: makeKV() };
  const v = await kycGate(env, { duns: "123456789", role: "owner", attestation: true, fetchImpl: dnbStub() });
  assert.equal(v.decision, "provisional");
  assert.equal(v.loa, 0);
});

// ---- kycGate: D&B not-found => refuse (fail-closed) ------------------------
await t("kycGate refuses when D&B says DUNS is not a real entity", async () => {
  const env = { ...CREDS, LICENSES: makeKV() };
  const v = await kycGate(env, { duns: "999999999", role: "owner", attestation: true, fetchImpl: dnbStub({ found: false }) });
  assert.equal(v.decision, "refuse");
  assert.equal(v.ref, null);
});

// ---- kycGate: stores authoritative verdict under kyc:<ref> -----------------
await t("kycGate persists the verdict under kyc:<ref> for issuance to bind", async () => {
  const kv = makeKV();
  const env = { ...CREDS, LICENSES: kv };
  const v = await kycGate(env, { duns: "123456789", role: "owner", attestation: true, fetchImpl: dnbStub(), kyc: { ocr: { onDevice: true, match: true, fieldsMatched: ["legalName", "country"], liveness: true } } });
  assert.ok(v.ref, "ref issued");
  const stored = JSON.parse(await kv.get("kyc:" + v.ref));
  assert.equal(stored.duns, "123456789");
  assert.equal(stored.loa, 3); // OCR validated + liveness
  assert.equal(stored.ocr.onDevice, true);
  // The token-BOUND projection (what master.js binds — loa/methods/ocr/etc, WITHOUT
  // the entity `dnb` echo) carries no requester PII: only booleans + field NAMES.
  const bound = { loa: stored.loa, methods: stored.methods, ocr: stored.ocr, principalMatch: stored.principalMatch, domain: stored.domain, idvRef: stored.idvRef, verifiedAt: stored.verifiedAt };
  assert.equal(scanForPII(bound), null);
  stored.ocr.fieldsMatched.forEach((f) => assert.ok(["legalName", "country", "officer"].includes(f)));
});

// ---- HTTP surface: onRequestPost refuses at the actual handler, not just ---
// the bare scanForPII function. This is what a real attacker hits — the unit
// tests above prove the tripwire logic is correct, these prove it's actually
// wired into the endpoint BEFORE any D&B call or KV write happens.
function req(bodyObj) {
  return new Request("https://x/license/review", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(bodyObj) });
}
async function post(env, bodyObj) {
  const res = await onRequestPost({ request: req(bodyObj), env });
  return { status: res.status, json: JSON.parse(await res.text()) };
}

await t("onRequestPost 400s a document-image field before touching D&B or KV", async () => {
  globalThis.fetch = async () => { throw new Error("must not call D&B — tripwire should short-circuit first"); };
  const kv = makeKV();
  const { status, json } = await post({ ...CREDS, LICENSES: kv }, { duns: "123456789", role: "owner", attestation: true, kyc: { ocr: { onDevice: true, match: true, fieldsMatched: ["legalName"], documentImage: "iVBORw0K...".repeat(60) } } });
  assert.equal(status, 400);
  assert.match(json.error, /privacy violation/i);
  assert.equal(kv.m.size, 0, "no KV write happened — refused before any persistence");
});
await t("onRequestPost 400s a data: URI payload", async () => {
  globalThis.fetch = async () => { throw new Error("must not call D&B"); };
  const { status, json } = await post({ ...CREDS, LICENSES: makeKV() }, { duns: "123456789", role: "owner", attestation: true, kyc: { ocr: { onDevice: true, match: true, fieldsMatched: ["legalName", "country"] } }, evidence: "data:image/png;base64,AAAAAAAA" });
  assert.equal(status, 400);
  assert.match(json.error, /privacy violation/i);
});
await t("onRequestPost 400s an over-long string (raw-text/image-blob presumption)", async () => {
  globalThis.fetch = async () => { throw new Error("must not call D&B"); };
  const { status, json } = await post({ ...CREDS, LICENSES: makeKV() }, { duns: "123456789", role: "owner", attestation: true, blob: "y".repeat(600) });
  assert.equal(status, 400);
  assert.match(json.error, /privacy violation/i);
});
await t("onRequestPost 400s a blocked PII key nested in kyc.ocr (e.g. name/dob)", async () => {
  globalThis.fetch = async () => { throw new Error("must not call D&B"); };
  const { status, json } = await post({ ...CREDS, LICENSES: makeKV() }, { duns: "123456789", role: "owner", attestation: true, kyc: { ocr: { onDevice: true, match: true, fieldsMatched: ["legalName", "country"], holderName: "Jane Doe" } } });
  assert.equal(status, 400);
  assert.match(json.error, /privacy violation/i);
});
await t("onRequestPost ACCEPTS the real minimal on-device shape end-to-end (200, verdict issued)", async () => {
  globalThis.fetch = dnbStub();
  const kv = makeKV();
  const { status, json } = await post({ ...CREDS, LICENSES: kv }, { duns: "123456789", role: "owner", attestation: true, kyc: { ocr: { onDevice: true, match: true, fieldsMatched: ["legalName", "country"], liveness: true } } });
  assert.equal(status, 200);
  assert.ok(json.ref);
  // The response legitimately echoes the D&B ENTITY's public legalName/country
  // (business data, already public — see the header note on Mode 1/verdict
  // design) so scanForPII's blocked-key list (tuned for REQUEST bodies, where a
  // "legalName" key would mean requester PII) isn't the right probe for the
  // response. What matters here: no raw-OCR/image field, and fieldsMatched
  // carries only allow-listed field NAMES, never a value.
  assert.equal(json.ocr.fieldsMatched.every((f) => ["legalName", "country", "officer"].includes(f)), true);
  assert.equal(Object.prototype.hasOwnProperty.call(json, "image"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(json, "documentImage"), false);
});
globalThis.fetch = origFetch;

// ---- computeLoa parity with client ---------------------------------------
await t("server computeLoa matches the faithful table", () => {
  assert.equal(computeLoa({ selfDeclared: true, dnbVerified: true }).loa, 0);
  assert.equal(computeLoa({ corpDomain: true, ocr: { onDevice: true, match: true, fieldsMatched: ["legalName", "country"] } }).loa, 2);
});

// ---- DEVICE <-> SERVER SHAPE SYNC ------------------------------------------
// The whole "OCR runs on-device" claim is only honest if the payload the device
// actually builds (index.html's GRM.buildOcrVerdict) is EXACTLY what this server
// accepts — no server-side field silently dropped or silently smuggled through
// beyond what the device produces, and no server-required field the device
// forgets to send. Extract the real client script (not a re-typed copy) and
// prove exact shape equality against the server's own sanitize/allow-list.
const html = readFileSync(new URL("./index.html", import.meta.url), "utf8");
const grmMatch = html.match(/<script id="grm-core">([\s\S]*?)<\/script>/);
assert.ok(grmMatch, "device grm-core script block found in index.html");
(0, eval)(grmMatch[1]);
const GRM = globalThis.GRM;
assert.ok(GRM && typeof GRM.buildOcrVerdict === "function", "device GRM core loaded");

await t("device buildOcrVerdict() output keys are EXACTLY {onDevice,match,fieldsMatched,liveness} — the shape the server's sanitizeClientVerdict expects", () => {
  const validation = GRM.validateOcrAgainstEntity(
    { legalName: "Acme Widgets Inc", country: "United States", officerName: "Jane Doe" },
    { legalName: "Acme Widgets, LLC", country: "US", principals: ["Jane Doe"] });
  const deviceOcr = GRM.buildOcrVerdict(validation, { liveness: true });
  assert.deepEqual(Object.keys(deviceOcr).sort(), ["fieldsMatched", "liveness", "match", "onDevice"]);

  // Round-trip through the server's sanitizer: every field the device sends
  // must survive UNCHANGED (server accepts exactly what device sends), and the
  // server must not manufacture any field the device didn't produce.
  const serverSide = sanitizeClientVerdict({ ocr: deviceOcr });
  assert.deepEqual(Object.keys(serverSide.ocr).sort(), ["fieldsMatched", "liveness", "match", "onDevice"]);
  assert.equal(serverSide.ocr.onDevice, deviceOcr.onDevice);
  assert.equal(serverSide.ocr.match, deviceOcr.match);
  assert.equal(serverSide.ocr.liveness, deviceOcr.liveness);
  assert.deepEqual(serverSide.ocr.fieldsMatched, deviceOcr.fieldsMatched);
});

await t("device and server agree byte-for-byte on the allowed OCR field-NAME allow-list ({legalName,country,officer})", () => {
  const deviceAllowedMatch = html.match(/var ALLOWED_FIELDS\s*=\s*\{([^}]*)\};/);
  assert.ok(deviceAllowedMatch, "device ALLOWED_FIELDS literal found");
  const deviceAllowed = [...deviceAllowedMatch[1].matchAll(/([a-zA-Z]+)\s*:\s*1/g)].map((m) => m[1]).sort();
  // ALLOWED_FIELDS is server-internal (not exported); assert via sanitizeClientVerdict's
  // observable behavior instead of reaching into module internals.
  const probe = sanitizeClientVerdict({ ocr: { onDevice: true, match: true, fieldsMatched: [...deviceAllowed, "ssn", "notAField"], liveness: false } });
  assert.deepEqual(probe.ocr.fieldsMatched.sort(), deviceAllowed, "server keeps exactly the device's allowed field names, drops everything else");
});

await t("a full end-to-end device-shaped payload is never flagged by the server tripwire", () => {
  const validation = GRM.validateOcrAgainstEntity({ legalName: "Acme Widgets Inc", country: "US" }, { legalName: "Acme Widgets LLC", country: "US" });
  const devicePayload = { duns: "123456789", role: "owner", attestation: true, kyc: { ocr: GRM.buildOcrVerdict(validation, { liveness: false }) } };
  assert.equal(scanForPII(devicePayload), null);
});

console.log("\n" + passed + " passed");
