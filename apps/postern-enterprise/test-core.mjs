// apps/postern-enterprise/test-core.mjs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Node-importable seam onto the Postern Business console's browser-only
// crypto/license/audit code, for conformance testing. ZERO edits to
// index.html or console.html — this file only *reads* those two files at
// runtime, regex/slice-extracts the exact <script> bodies that ship to the
// browser, and evaluates THOSE EXACT BYTES in Node via `new Function(...)`.
// There is no reimplementation here: loadPecCore()/loadPosternLicense() hand
// back the real PEC / PosternLicense objects built from the same source text
// the browser parses — these tests exercise the exact bytes shipped in the
// HTML, not a copy, not a port, not a paraphrase.
//
// Drift detection: if either extraction marker below fails to match (source
// edited, script id renamed, closing brace moved), the loader THROWS rather
// than silently evaluating stale or wrong code. That throw is the point —
// it means this harness and the shipped HTML have drifted apart and must be
// reconciled before any test result here can be trusted.
//
// ---------------------------------------------------------------------------
// HONEST CAVEATS — copied verbatim from the HTML sources this file loads.
// Do not soften, do not drop, do not upgrade the status of anything below.
//
// 1) "Reference prototype — unaudited, pre-production."
//    (index.html: style-block header comment line 21, card banner line 401,
//    footer line 671; console.html: header comment line 15, card banner
//    line 116.) This status applies to everything loadPecCore() and
//    loadPosternLicense() return — including when every test here passes.
//
// 2) "Officer & admin keys: Ed25519 / P-256 via WebCrypto — classical
//    stand-ins for Falcon-1024 ‖ ML-DSA-65 in each person's device TEE.
//    Keyfiles sealed with AES-256-GCM under PBKDF2 (310k it.) — stand-in for
//    Argon2id (64 MiB, t=3), the bloch-crypto construction."
//    (index.html, lines 443-445; see also lines 729-730, 812, 1715 and
//    console.html lines 11-15.) Plainly: every Ed25519/P-256 signature and
//    every PBKDF2 (310,000 iterations) key derivation these loaders exercise
//    is a CLASSICAL STAND-IN for the real design of record — hybrid
//    Falcon-1024 ‖ ML-DSA-65 signatures in a device TEE, and Argon2id
//    (64 MiB, t=3) key derivation. Nothing post-quantum ships in these bytes.
//
// 3) "Every sensitive act — provision, role change, wall binding, escrow
//    approval, revocation, wipe — is an entry with hash = SHA-256(entry ‖
//    prev-hash). Honest limit: in this demo the whole chain lives in this
//    browser's localStorage, so "Verify" catches accidental edits, not a
//    local attacker — anyone who can edit localStorage can rewrite an entry
//    and recompute every hash after it."
//    (index.html, lines 587-591, audit tab.) Equivalently: the
//    localStorage-demo audit chain only catches accidental edits — a root
//    admin (or anyone who can write to that browser's localStorage) can
//    rewrite the whole chain and recompute every downstream hash, and
//    auditVerify() will not catch it. The real tamper-evidence arrives only
//    in the product, where the chain head is countersigned and replicated
//    outside IT's custody.
//
// This module makes no claim of post-quantum, audited, or production status
// for anything it loads or tests. None of that is true of the code it wraps;
// do not add such a claim here later.
// ---------------------------------------------------------------------------

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const __dirname = dirname(fileURLToPath(import.meta.url));

// On Node 22, globalThis.crypto already IS require('crypto').webcrypto (a
// getter-defined global, present out of the box) — so this is a no-op in
// practice. It's defensive: `new Function(...)`-evaluated source below
// references the bare global `crypto` exactly as the browser does, and
// globalThis.crypto is not a plain writable property, so a bare `=`
// assignment throws ("Cannot set property crypto of #<Object> which has
// only a getter"). Object.defineProperty makes the intent explicit and safe
// on any Node version where the global isn't already wired up.
function ensureWebCrypto() {
  const { webcrypto } = require("crypto");
  if (globalThis.crypto !== webcrypto) {
    Object.defineProperty(globalThis, "crypto", {
      value: webcrypto,
      configurable: true,
      writable: true,
      enumerable: true,
    });
  }
  return webcrypto;
}

/**
 * Loads the CONSIGLIO/PEC core exactly as shipped in index.html.
 *
 * Reads index.html, regex-extracts the body of
 * <script id="pec-core">...</script>, and evaluates it with
 * `new Function(src + "; return PEC;")` — the exact bytes the browser
 * parses, unmodified. globalThis.crypto is set to Node's WebCrypto
 * (require('crypto').webcrypto) before evaluation, since the extracted
 * source references the bare global `crypto` (crypto.subtle,
 * crypto.getRandomValues) exactly as it does in a browser.
 *
 * Throws if the <script id="pec-core"> marker is not found in index.html
 * (drift detection — see header).
 *
 * @returns {Promise<object>} the live PEC object: wallCheck, rbacCheck,
 *   auditAppend, auditVerify, sealJSON/openJSON, signObj/verifyObj, etc.
 */
export async function loadPecCore() {
  const html = readFileSync(join(__dirname, "index.html"), "utf8");
  const match = html.match(/<script id="pec-core">([\s\S]*?)<\/script>/);
  if (!match) {
    throw new Error(
      'loadPecCore: <script id="pec-core">...</script> not found in index.html — ' +
        "extraction marker drift. The HTML changed shape; do not silently evaluate " +
        "stale code — fix the extractor against the current source."
    );
  }
  const src = match[1];

  ensureWebCrypto();

  const factory = new Function(src + "\n; return PEC;");
  return factory();
}

/**
 * Loads the Postern licensing chain verifier/minter exactly as shipped in
 * console.html.
 *
 * Reads console.html, slices the source from the literal marker
 * 'var VENDOR_PUB_RAW_B64' through the makePosternLicense closing marker
 * 'CRL_STATUS_PATH};\n}' (i.e. the `var VENDOR_PUB_RAW_B64 = "...";` line
 * plus the full `function makePosternLicense(subtle){ ... }` declaration,
 * and nothing past its closing brace — the console.html-only auto-invocation
 * on window is deliberately excluded), evaluates that slice with
 * `new Function(src + "; return makePosternLicense;")`, and then calls
 * `makePosternLicense(require('crypto').webcrypto.subtle)` explicitly so the
 * returned object is bound to Node's WebCrypto rather than any ambient
 * global.
 *
 * Throws if either the start marker ('var VENDOR_PUB_RAW_B64') or the end
 * marker ('CRL_STATUS_PATH};\n}') is not found in console.html (drift
 * detection — see header).
 *
 * @returns {Promise<object>} the live PosternLicense object: canonicalJson,
 *   verifyChain, mintSub, VENDOR_PUB_RAW_B64.
 */
export async function loadPosternLicense() {
  const html = readFileSync(join(__dirname, "console.html"), "utf8");

  const startMarker = "var VENDOR_PUB_RAW_B64";
  const start = html.indexOf(startMarker);
  if (start === -1) {
    throw new Error(
      "loadPosternLicense: start marker 'var VENDOR_PUB_RAW_B64' not found in " +
        "console.html — extraction marker drift. Do not silently evaluate stale " +
        "code — fix the extractor against the current source."
    );
  }

  const endMarker = "CRL_STATUS_PATH};\n}";
  const endMarkerIdx = html.indexOf(endMarker, start);
  if (endMarkerIdx === -1) {
    throw new Error(
      "loadPosternLicense: end marker 'CRL_STATUS_PATH};\\n}' (the " +
        "makePosternLicense closing brace) not found in console.html after the " +
        "start marker — extraction marker drift. Do not silently evaluate stale " +
        "code — fix the extractor against the current source."
    );
  }
  const end = endMarkerIdx + endMarker.length;

  const src = html.slice(start, end);

  const webcrypto = ensureWebCrypto();

  const factory = new Function(src + "\n; return makePosternLicense;");
  const makePosternLicense = factory();
  return makePosternLicense(webcrypto.subtle);
}

// ===========================================================================
// License-chain conformance tests (node:test).
//
// PL below is the REAL object loadPosternLicense() hands back — the exact
// canonicalJson/verifyChain/mintSub bytes shipped in console.html, evaluated
// verbatim. Nothing here reimplements, stubs, or weakens that code.
//
// verifyChain(vendorPubB64, masterToken, masterSig, sub, now) takes the
// vendor public key as a PARAMETER — there is no pinned-key bypass and this
// suite adds no capability to the shipped code. Every test below mints a
// FRESH vendor Ed25519 keypair with WebCrypto and passes its own public key
// in; console.html's hardcoded VENDOR_PUB_RAW_B64 is never touched here.
// ===========================================================================
import { test } from "node:test";
import assert from "node:assert/strict";

const PL = await loadPosternLicense();

const webcryptoForTests = ensureWebCrypto();
const subtleForTests = webcryptoForTests.subtle;

function b64(buf) {
  return Buffer.from(buf).toString("base64");
}

async function genKeypair() {
  const kp = await subtleForTests.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const pubRaw = await subtleForTests.exportKey("raw", kp.publicKey);
  const privPkcs8 = await subtleForTests.exportKey("pkcs8", kp.privateKey);
  return { privateKey: kp.privateKey, publicKey: kp.publicKey, pubB64: b64(pubRaw), pkcs8B64: b64(privPkcs8) };
}

async function signWithKey(privateKey, payloadObj) {
  const bytes = new TextEncoder().encode(PL.canonicalJson(payloadObj));
  const sig = await subtleForTests.sign({ name: "Ed25519" }, privateKey, bytes);
  return b64(sig);
}

function randHex(n) {
  const bytes = new Uint8Array(n);
  webcryptoForTests.getRandomValues(bytes);
  return Array.from(bytes).map((x) => x.toString(16).padStart(2, "0")).join("");
}

const NOW_SEC = Math.floor(Date.parse("2026-07-14T00:00:00Z") / 1000);
const NOW = new Date(NOW_SEC * 1000);
const ONE_YEAR = 365 * 86400;

async function mintMaster(vendor, overrides = {}) {
  const masterKp = await genKeypair();
  const payload = Object.assign(
    {
      v: 1,
      typ: "master",
      tier: "corporate-master",
      duns: "123456789",
      seats: 50,
      iat: NOW_SEC,
      exp: NOW_SEC + ONE_YEAR,
      jti: randHex(16),
      iss: "postern-vendor",
      master_pub: masterKp.pubB64,
    },
    overrides,
  );
  const sig = await signWithKey(vendor.privateKey, payload);
  return { masterKp, token: payload, sig };
}

// ---- (a) valid master verifies ok with level 'master' ----------------------
test("valid master verifies ok with level 'master'", async () => {
  const vendor = await genKeypair();
  const { token, sig } = await mintMaster(vendor);
  const r = await PL.verifyChain(vendor.pubB64, token, sig, null, NOW);
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.level, "master");
  assert.equal(r.tier, "corporate-master");
  assert.equal(r.duns, "123456789");
  assert.equal(r.expired, false);
});

// ---- (b) any field tamper after signing -> bad-master-signature -----------
test("flipping duns after signing -> bad-master-signature", async () => {
  const vendor = await genKeypair();
  const { token, sig } = await mintMaster(vendor);
  const tampered = { ...token, duns: "999999999" };
  const r = await PL.verifyChain(vendor.pubB64, tampered, sig, null, NOW);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "bad-master-signature");
});
test("flipping exp after signing -> bad-master-signature", async () => {
  const vendor = await genKeypair();
  const { token, sig } = await mintMaster(vendor);
  const tampered = { ...token, exp: token.exp + 1000 };
  const r = await PL.verifyChain(vendor.pubB64, tampered, sig, null, NOW);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "bad-master-signature");
});

// ---- (c) expiry / malformed-master / bad-duns ------------------------------
test("exp in the past -> ok:true but expired:true", async () => {
  const vendor = await genKeypair();
  const { token, sig } = await mintMaster(vendor, { exp: NOW_SEC - 1 });
  const r = await PL.verifyChain(vendor.pubB64, token, sig, null, NOW);
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.expired, true);
});
test("malformed typ -> malformed-master", async () => {
  const vendor = await genKeypair();
  const { token, sig } = await mintMaster(vendor, { typ: "not-master" });
  const r = await PL.verifyChain(vendor.pubB64, token, sig, null, NOW);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "malformed-master");
});
test("non-9-digit duns on corporate-master -> bad-duns", async () => {
  const vendor = await genKeypair();
  const { token, sig } = await mintMaster(vendor, { duns: "12345" });
  const r = await PL.verifyChain(vendor.pubB64, token, sig, null, NOW);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "bad-duns");
});

// ---- (d) mintSub + full vendor->master->sub chain --------------------------
test("mintSub produces payload.master_pub === master.master_pub; full chain verifies at level 'sub'", async () => {
  const vendor = await genKeypair();
  const { masterKp, token, sig } = await mintMaster(vendor);
  const sub = await PL.mintSub(masterKp.pkcs8B64, token, { sub: "laptop-1", exp: token.exp, now: NOW });
  assert.equal(sub.payload.master_pub, token.master_pub);
  const r = await PL.verifyChain(vendor.pubB64, token, sig, sub, NOW);
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.level, "sub");
  assert.equal(r.subJti, sub.payload.jti);
});

// ---- (e) sub signed by wrong key / master_pub swapped ----------------------
test("sub signed by a DIFFERENT keypair -> bad-sub-signature", async () => {
  const vendor = await genKeypair();
  const { masterKp, token, sig } = await mintMaster(vendor);
  const otherKp = await genKeypair();
  // Sign with a different private key while still claiming the real
  // master_pub, so the mismatch check passes and the signature check is
  // what has to catch it.
  const sub = await PL.mintSub(otherKp.pkcs8B64, token, { sub: "laptop-1", exp: token.exp, now: NOW });
  const r = await PL.verifyChain(vendor.pubB64, token, sig, sub, NOW);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "bad-sub-signature");
});
test("sub with payload.master_pub swapped -> sub-master-mismatch", async () => {
  const vendor = await genKeypair();
  const { masterKp, token, sig } = await mintMaster(vendor);
  const sub = await PL.mintSub(masterKp.pkcs8B64, token, { sub: "laptop-1", exp: token.exp, now: NOW });
  const otherKp = await genKeypair();
  const swapped = { payload: { ...sub.payload, master_pub: otherKp.pubB64 }, sig: sub.sig };
  const r = await PL.verifyChain(vendor.pubB64, token, sig, swapped, NOW);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "sub-master-mismatch");
});

// ---- (f) sub.exp > master.exp; mintSub caps opts.exp at master.exp --------
test("mintSub caps opts.exp at master.exp", async () => {
  const vendor = await genKeypair();
  const { masterKp, token } = await mintMaster(vendor);
  const sub = await PL.mintSub(masterKp.pkcs8B64, token, { sub: "laptop-1", exp: token.exp + 999999, now: NOW });
  assert.equal(sub.payload.exp, token.exp);
});
test("sub.exp > master.exp -> sub-outlives-master", async () => {
  const vendor = await genKeypair();
  const { masterKp, token, sig } = await mintMaster(vendor);
  const sub = await PL.mintSub(masterKp.pkcs8B64, token, { sub: "laptop-1", exp: token.exp, now: NOW });
  // Bypass mintSub's own cap to construct a sub whose exp genuinely exceeds
  // the master's, re-signed correctly by the real master key, so the exp
  // check itself (not the signature check) is what must fire.
  const forced = { ...sub.payload, exp: token.exp + 1 };
  const forcedSig = await signWithKey(masterKp.privateKey, forced);
  const r = await PL.verifyChain(vendor.pubB64, token, sig, { payload: forced, sig: forcedSig }, NOW);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "sub-outlives-master");
});

// ---- (g) tampering sub payload after minting -> bad-sub-signature ---------
test("tampering sub payload after minting -> bad-sub-signature", async () => {
  const vendor = await genKeypair();
  const { masterKp, token, sig } = await mintMaster(vendor);
  const sub = await PL.mintSub(masterKp.pkcs8B64, token, { sub: "laptop-1", exp: token.exp, now: NOW });
  const tampered = { payload: { ...sub.payload, sub: "laptop-2" }, sig: sub.sig };
  const r = await PL.verifyChain(vendor.pubB64, token, sig, tampered, NOW);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "bad-sub-signature");
});

// ===========================================================================
// Brewer-Nash wall + RBAC/clearance conformance tests (node:test).
//
// PEC below is the REAL object loadPecCore() hands back — the exact
// wallCheck/rbacCheck bytes shipped in index.html (lines ~942-959),
// evaluated verbatim. PEC.ROLES / PEC.SOD are used as-is from that same
// object — this file does not redefine or reimplement the role catalog.
//
// HONESTY: the shipped console implements ONLY the no-read-up clearance
// gate — rbacCheck denies a subject whose user.attrs.clearance is lower
// than vol.clearance ("read up"). There is no write path anywhere in this
// UI (no volume-write action exists to gate) and therefore no no-write-down
// (Bell-LaPadula "*-property") check in the shipped code. This suite tests
// only what ships: the no-read-up gate. It does not claim, simulate, or
// test a no-write-down/*-property control, because none exists to test.
//
// wallCheck's Brewer-Nash history-based lockout is exercised here by
// mirroring accessVolume's own broker guard (index.html ~line 1522-1531):
// accessVolume calls wallCheck, and on `!w.ok` it `return`s immediately —
// BEFORE `user.accessed.push(volId)` runs. So a denied wallCheck call never
// mutates accessed history and never binds the user to the conflicting
// group. The helper below, simulateAccess(), reproduces that exact
// guard-then-mutate order (check first, mutate only if ok) so the tests
// assert the real broker semantics, not a reimplementation of wallCheck
// itself (wallCheck is called unmodified, straight from PEC).
// ===========================================================================

const PEC = await loadPecCore();

// Mirrors accessVolume's guard order (index.html ~1522-1531): rbacCheck is
// skipped here on purpose — these tests target wallCheck's history-based
// lockout in isolation, so only PEC.wallCheck (unmodified) is invoked, and
// the "release the key" mutation (push into user.accessed) happens only
// when wallCheck says ok — exactly as accessVolume does.
function simulateAccess(user, vol, volumes) {
  const w = PEC.wallCheck(user, vol, volumes);
  if (!w.ok) return w; // mandatory: no override path; accessed is NOT mutated
  if (!(user.accessed || []).includes(vol.id)) {
    user.accessed = user.accessed || [];
    user.accessed.push(vol.id);
  }
  return w;
}

function makeCoiVolumes() {
  // One COI class "class-x" with two conflicting groups (A, B), plus one
  // volume in a different COI class ("class-y"), plus one general-pool
  // volume (classId: null).
  return [
    { id: "vol-a1", name: "A1", family: "engineering", groupId: "group-a", classId: "class-x", clearance: 0 },
    { id: "vol-a2", name: "A2", family: "engineering", groupId: "group-a", classId: "class-x", clearance: 0 },
    { id: "vol-b1", name: "B1", family: "engineering", groupId: "group-b", classId: "class-x", clearance: 0 },
    { id: "vol-y1", name: "Y1", family: "engineering", groupId: "group-y", classId: "class-y", clearance: 0 },
    { id: "vol-gp", name: "GP", family: "engineering", groupId: null, classId: null, clearance: 0 },
  ];
}

// ---- (h) fresh user (accessed:[]) passes wallCheck for any volume ---------
test("wallCheck: user with accessed:[] passes for any volume in any group/class", () => {
  const volumes = makeCoiVolumes();
  const user = { id: "u1", accessed: [] };
  for (const vol of volumes) {
    const r = PEC.wallCheck(user, vol, volumes);
    assert.equal(r.ok, true, `expected ok for ${vol.id}, got ${JSON.stringify(r)}`);
  }
});

// ---- (i) first access binds; conflicting-group access in same class is denied,
//          and the broker's key-release guard means accessed history is
//          UNCHANGED by that denial (key never released, no binding recorded) --
test("wallCheck: after binding to group A in class-x, group-B volume in class-x is denied and accessed history is unchanged", () => {
  const volumes = makeCoiVolumes();
  const user = { id: "u1", accessed: [] };

  // First access: vol-a1 (group A, class-x) — should succeed and bind.
  const first = simulateAccess(user, volumes.find(v => v.id === "vol-a1"), volumes);
  assert.equal(first.ok, true, JSON.stringify(first));
  assert.deepEqual(user.accessed, ["vol-a1"]);

  const historyBefore = [...user.accessed];

  // Conflicting attempt: vol-b1 (group B, SAME class-x) — must be denied,
  // bound to the group already held (group-a), per Brewer-Nash mandatory
  // lockout (no discretionary override).
  const conflict = simulateAccess(user, volumes.find(v => v.id === "vol-b1"), volumes);
  assert.equal(conflict.ok, false, "conflicting-group access must be denied");
  assert.equal(conflict.boundTo, "group-a", "must report the group the user is already bound to");

  // Broker semantics: the guard returns on !w.ok BEFORE user.accessed is
  // mutated (mirrors accessVolume's `if (!w.ok) return;`), so the key is
  // never released and no binding to the conflicting group is recorded —
  // accessed history must be byte-for-byte identical to before the denial.
  assert.deepEqual(user.accessed, historyBefore, "accessed history must be unchanged after a denial — key never released");
  assert.equal(user.accessed.includes("vol-b1"), false, "denied volume must never appear in accessed history");
});

// ---- (j) second volume in the SAME group stays ok, and does not disturb binding --
test("wallCheck: second volume in the SAME group (class-x) stays ok", () => {
  const volumes = makeCoiVolumes();
  const user = { id: "u1", accessed: [] };

  const first = simulateAccess(user, volumes.find(v => v.id === "vol-a1"), volumes);
  assert.equal(first.ok, true, JSON.stringify(first));

  // vol-a2 is also group-a, class-x — same group as the bound one.
  const second = simulateAccess(user, volumes.find(v => v.id === "vol-a2"), volumes);
  assert.equal(second.ok, true, JSON.stringify(second));
  assert.deepEqual(user.accessed, ["vol-a1", "vol-a2"]);
});

// ---- (k) a volume in a DIFFERENT COI class stays ok regardless of binding --
test("wallCheck: a volume in a DIFFERENT COI class (class-y) stays ok even after binding in class-x", () => {
  const volumes = makeCoiVolumes();
  const user = { id: "u1", accessed: [] };

  const first = simulateAccess(user, volumes.find(v => v.id === "vol-a1"), volumes);
  assert.equal(first.ok, true, JSON.stringify(first));

  const other = simulateAccess(user, volumes.find(v => v.id === "vol-y1"), volumes);
  assert.equal(other.ok, true, JSON.stringify(other));
  assert.deepEqual(user.accessed, ["vol-a1", "vol-y1"]);
});

// ---- (l) classId:null (general pool) is always ok, regardless of history --
test("wallCheck: classId:null (general pool) is always ok, even after binding elsewhere", () => {
  const volumes = makeCoiVolumes();
  const user = { id: "u1", accessed: [] };

  // General pool is ok before any history.
  const beforeAny = PEC.wallCheck(user, volumes.find(v => v.id === "vol-gp"), volumes);
  assert.equal(beforeAny.ok, true, JSON.stringify(beforeAny));

  // Bind to group A, class-x.
  const first = simulateAccess(user, volumes.find(v => v.id === "vol-a1"), volumes);
  assert.equal(first.ok, true, JSON.stringify(first));

  // General pool is still ok after binding — classId:null short-circuits
  // wallCheck (`if (!vol.classId) return { ok: true };`) regardless of history.
  const afterBind = simulateAccess(user, volumes.find(v => v.id === "vol-gp"), volumes);
  assert.equal(afterBind.ok, true, JSON.stringify(afterBind));
  assert.deepEqual(user.accessed, ["vol-a1", "vol-gp"]);
});

// ===========================================================================
// rbacCheck: RBAC role-entitlement gate + BLP-style no-read-up clearance gate.
//
// HONESTY (repeated at point of use, verbatim intent from the header above):
// the console implements ONLY the no-read-up clearance gate — there is no
// write path and no no-write-down check in the shipped UI, so none is
// claimed or tested here.
// ===========================================================================

// ---- (m) clearance below required -> denied, why contains 'clearance' -----
test("rbacCheck: user.attrs.clearance < vol.clearance -> denied, why contains 'clearance'", () => {
  const vol = { id: "vol-fin", family: "finance", clearance: 3 };
  const user = { id: "u1", status: "active", role: "finance-analyst", attrs: { clearance: 2 } };
  const r = PEC.rbacCheck(user, vol, PEC.ROLES);
  assert.equal(r.ok, false);
  assert.match(r.why, /clearance/);
});

// ---- (n) clearance equal -> allowed -----------------------------------------
test("rbacCheck: user.attrs.clearance === vol.clearance -> allowed", () => {
  const vol = { id: "vol-fin", family: "finance", clearance: 3 };
  const user = { id: "u1", status: "active", role: "finance-analyst", attrs: { clearance: 3 } };
  const r = PEC.rbacCheck(user, vol, PEC.ROLES);
  assert.equal(r.ok, true, JSON.stringify(r));
});

// ---- (o) clearance greater -> allowed ---------------------------------------
test("rbacCheck: user.attrs.clearance > vol.clearance -> allowed", () => {
  const vol = { id: "vol-fin", family: "finance", clearance: 1 };
  const user = { id: "u1", status: "active", role: "finance-analyst", attrs: { clearance: 5 } };
  const r = PEC.rbacCheck(user, vol, PEC.ROLES);
  assert.equal(r.ok, true, JSON.stringify(r));
});

// ---- (p) unknown role -> denied with why === 'no role' ---------------------
test("rbacCheck: unknown role.id -> denied, why === 'no role'", () => {
  const vol = { id: "vol-fin", family: "finance", clearance: 0 };
  const user = { id: "u1", status: "active", role: "not-a-real-role", attrs: { clearance: 10 } };
  const r = PEC.rbacCheck(user, vol, PEC.ROLES);
  assert.equal(r.ok, false);
  assert.equal(r.why, "no role");
});

// ---- (q) role not entitled to the volume family -> denied ------------------
test("rbacCheck: role not entitled to the volume's family -> denied", () => {
  // "engineer" role (PEC.ROLES, as-shipped) is entitled to volumes: ["engineering"] only.
  const vol = { id: "vol-fin", family: "finance", clearance: 0 };
  const user = { id: "u1", status: "active", role: "engineer", attrs: { clearance: 10 } };
  const r = PEC.rbacCheck(user, vol, PEC.ROLES);
  assert.equal(r.ok, false);
  assert.match(r.why, /not entitled/);
});

// ===========================================================================
// Audit-chain conformance tests (node:test) — PEC.auditAppend / PEC.auditVerify.
//
// PEC.auditAppend/auditVerify above are the REAL functions loadPecCore()
// hands back — the exact hash-linked-chain bytes shipped in index.html's
// <script id="pec-core">, evaluated verbatim (chain[i].hash =
// SHA-256(stableStringify({seq,ts,actor,action,detail,prev}))), where prev
// is the previous entry's hash, or the literal string "GENESIS" for entry 1.
// Nothing here reimplements, stubs, or weakens that code.
//
// HONEST CAVEAT — restated from this file's header and from index.html's own
// audit-tab copy (index.html lines 587-591): this chain lives in browser
// localStorage in the shipped demo. auditVerify() catches ACCIDENTAL edits —
// any single-field mutation, or any break in the prev/hash linkage. It does
// NOT catch a DELIBERATE, WHOLESALE rewrite by whoever controls the store:
// an admin (or attacker) with write access to that browser's localStorage
// can regenerate the entire chain from scratch — including recomputing every
// hash correctly for a fabricated history — and auditVerify() will report
// {ok:true} on the forgery, because it only checks INTERNAL consistency
// (does each hash commit to its neighbors), never who authored the bytes or
// when. Real tamper-evidence needs the chain head countersigned and
// replicated outside the actor's own custody; nothing in this localStorage
// demo provides that. The tests below exercise only the "catches accidental
// edits" half of that claim; none of them claim (nor could they) to catch a
// wholesale admin rewrite, since a wholesale rewrite with hashes recomputed
// is, by auditVerify()'s own definition, indistinguishable from a genuine
// chain.
// ===========================================================================

test("auditAppend: N entries chain prev-linkage from 'GENESIS'; auditVerify -> {ok:true,count:N}", async () => {
  const chain = [];
  const N = 7;
  for (let i = 0; i < N; i++) {
    await PEC.auditAppend(chain, `actor-${i}`, `action-${i}`, { i });
  }
  assert.equal(chain.length, N);
  assert.equal(chain[0].prev, "GENESIS");
  for (let i = 1; i < N; i++) {
    assert.equal(chain[i].prev, chain[i - 1].hash);
  }
  const r = await PEC.auditVerify(chain);
  assert.deepEqual(r, { ok: true, count: N });
});

test("auditVerify: mutating a middle entry's detail -> {ok:false, at:<that seq>}", async () => {
  const chain = [];
  for (let i = 0; i < 5; i++) await PEC.auditAppend(chain, "a", "act", { i });
  chain[2].detail = { i: "tampered" };
  const r = await PEC.auditVerify(chain);
  assert.equal(r.ok, false);
  assert.equal(r.at, chain[2].seq);
});

test("auditVerify: mutating a middle entry's actor -> {ok:false, at:<that seq>}", async () => {
  const chain = [];
  for (let i = 0; i < 5; i++) await PEC.auditAppend(chain, "actor-orig", "act", { i });
  chain[3].actor = "actor-tampered";
  const r = await PEC.auditVerify(chain);
  assert.equal(r.ok, false);
  assert.equal(r.at, chain[3].seq);
});

test("auditVerify: mutating a middle entry's action -> {ok:false, at:<that seq>}", async () => {
  const chain = [];
  for (let i = 0; i < 5; i++) await PEC.auditAppend(chain, "a", "act-orig", { i });
  chain[1].action = "act-tampered";
  const r = await PEC.auditVerify(chain);
  assert.equal(r.ok, false);
  assert.equal(r.at, chain[1].seq);
});

test("auditVerify: mutating a middle entry's ts -> {ok:false, at:<that seq>}", async () => {
  const chain = [];
  for (let i = 0; i < 5; i++) await PEC.auditAppend(chain, "a", "act", { i });
  chain[4].ts = new Date(0).toISOString();
  const r = await PEC.auditVerify(chain);
  assert.equal(r.ok, false);
  assert.equal(r.at, chain[4].seq);
});

test("auditVerify: editing a middle entry's prev breaks linkage -> ok:false", async () => {
  const chain = [];
  for (let i = 0; i < 5; i++) await PEC.auditAppend(chain, "a", "act", { i });
  chain[2].prev = "deadbeef".repeat(8);
  const r = await PEC.auditVerify(chain);
  assert.equal(r.ok, false);
  assert.equal(r.at, chain[2].seq);
});

test("auditVerify: deleting a middle entry breaks linkage -> ok:false", async () => {
  const chain = [];
  for (let i = 0; i < 5; i++) await PEC.auditAppend(chain, "a", "act", { i });
  chain.splice(2, 1); // drop seq-3; seq-4's prev now points at a hash no longer present
  const r = await PEC.auditVerify(chain);
  assert.equal(r.ok, false);
});

test("auditVerify: reordering two middle entries breaks linkage -> ok:false", async () => {
  const chain = [];
  for (let i = 0; i < 5; i++) await PEC.auditAppend(chain, "a", "act", { i });
  const tmp = chain[1];
  chain[1] = chain[2];
  chain[2] = tmp;
  const r = await PEC.auditVerify(chain);
  assert.equal(r.ok, false);
});

test("auditVerify: recomputing a tampered entry's own hash without fixing successors still fails at the NEXT entry (chain property: hash = SHA-256(entry ‖ prev-hash))", async () => {
  const chain = [];
  for (let i = 0; i < 5; i++) await PEC.auditAppend(chain, "a", "act", { i });

  // Tamper entry[2]'s detail, then recompute ONLY entry[2]'s own hash so it
  // becomes internally self-consistent again (hash matches its own,
  // now-tampered, fields ‖ its unchanged prev). This is exactly what an
  // attacker who fixes just the one entry — but not everything downstream —
  // would produce.
  chain[2].detail = { i: "tampered-but-locally-rehashed" };
  chain[2].hash = await PEC.sha256Hex(
    PEC.stableStringify({
      seq: chain[2].seq,
      ts: chain[2].ts,
      actor: chain[2].actor,
      action: chain[2].action,
      detail: chain[2].detail,
      prev: chain[2].prev,
    })
  );

  // Prove entry[2] is now self-consistent in isolation: a prefix ending at
  // entry[2] verifies clean (its own hash matches; the GENESIS/prev chain up
  // to it is untouched).
  const prefixCheck = await PEC.auditVerify(chain.slice(0, 3));
  assert.deepEqual(prefixCheck, { ok: true, count: 3 });

  // But entry[3].prev still commits to entry[2]'s ORIGINAL (pre-tamper)
  // hash, not the freshly recomputed one — so the FULL chain must fail
  // exactly at the next entry, seq 4. This is the chain property doing its
  // job: fixing an entry's own hash does not "fix" it unless every
  // downstream entry's prev/hash is also recomputed.
  const r = await PEC.auditVerify(chain);
  assert.equal(r.ok, false);
  assert.equal(r.at, chain[3].seq);
});

