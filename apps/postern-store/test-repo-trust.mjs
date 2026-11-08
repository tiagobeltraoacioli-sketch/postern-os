// POSTERN-STORE multi-repo trust + key-rotation tests — run with:
//   node test-repo-trust.mjs   (Node >= 18, needs webcrypto Ed25519 support)
//
// Extracts the REAL trust-state + key-rotation logic straight out of
// index.html's single CSP-hash-pinned <script>, the same DOM-free
// extraction technique test-core.mjs already uses for KeySeal: locate the
// span by indexOf against stable markers, concatenate a few
// `globalThis.__x = x;` exposer lines onto the END of that exact source
// (so they share the same eval scope and can reach `let`-scoped locals
// like _ed25519Probe), then run it all through one indirect eval(). This
// tests the shipped code, not a hand-copied duplicate that could drift.
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";

if (!globalThis.crypto) globalThis.crypto = webcrypto;

const html = readFileSync(new URL("./index.html", import.meta.url).pathname, "utf8");

const start = html.indexOf("const TRUST = Object.freeze({");
assert.ok(start !== -1, "TRUST block found");
const endMarker = "/* ===== end pure repo-trust logic (extracted verbatim by test-repo-trust.mjs) ===== */";
const endIdx = html.indexOf(endMarker);
assert.ok(endIdx !== -1, "repo-trust end marker found");
const code = html.slice(start, endIdx) +
  "\nglobalThis.__REPO_TRUST = REPO_TRUST;" +
  "\nglobalThis.__resolveRepoTrust = resolveRepoTrust;" +
  "\nglobalThis.__verifyKeyRotation = verifyKeyRotation;" +
  "\nglobalThis.__rotationTransitionMessage = rotationTransitionMessage;" +
  "\nglobalThis.__b64ToBytes = b64ToBytes;" +
  "\nglobalThis.__breakEd25519 = function(){ crypto.subtle.__realGenerateKey = crypto.subtle.generateKey; crypto.subtle.generateKey = function(){ return Promise.reject(new Error('no Ed25519 (test)')); }; _ed25519Probe = null; };" +
  "\nglobalThis.__fixEd25519 = function(){ if (crypto.subtle.__realGenerateKey) crypto.subtle.generateKey = crypto.subtle.__realGenerateKey; _ed25519Probe = null; };";
(0, eval)(code);

const REPO_TRUST = globalThis.__REPO_TRUST;
const resolveRepoTrust = globalThis.__resolveRepoTrust;
const verifyKeyRotation = globalThis.__verifyKeyRotation;
const rotationTransitionMessage = globalThis.__rotationTransitionMessage;
const b64ToBytes = globalThis.__b64ToBytes;
assert.ok(REPO_TRUST && resolveRepoTrust && verifyKeyRotation, "repo-trust logic loaded, DOM-free");

/* ---------- crypto helpers for building test fixtures (independent of the extracted code) ---------- */
const { subtle } = webcrypto;
function b64(bytes) { return Buffer.from(bytes).toString("base64"); }
async function genKey() {
  const kp = await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const pub = new Uint8Array(await subtle.exportKey("raw", kp.publicKey));
  return { kp, pubB64: b64(pub) };
}
async function sign(privateKey, bytes) { return new Uint8Array(await subtle.sign({ name: "Ed25519" }, privateKey, bytes)); }
function enc(s) { return new TextEncoder().encode(s); }

let passed = 0;
const t = (name, fn) => Promise.resolve().then(fn).then(() => { passed++; console.log("  ok — " + name); });

const REPO_ID = "test-repo";

await t("VERIFIED: valid signature against the pinned key adopts the index", async () => {
  const A = await genKey();
  const doc = { schema: "postern.repo/v1", repo: { id: REPO_ID, pubkey_b64: A.pubB64 }, apps: [] };
  const bytes = enc(JSON.stringify(doc));
  const sig = await sign(A.kp.privateKey, bytes);
  const result = await resolveRepoTrust({ repo_id: REPO_ID, pubkey_b64: A.pubB64 }, bytes, sig);
  assert.equal(result.state, REPO_TRUST.VERIFIED);
  assert.ok(result.index, "parsed index attached on VERIFIED");
});

await t("UNSIGNED: no signature bytes at all", async () => {
  const A = await genKey();
  const bytes = enc(JSON.stringify({ schema: "postern.repo/v1", repo: {}, apps: [] }));
  const result = await resolveRepoTrust({ repo_id: REPO_ID, pubkey_b64: A.pubB64 }, bytes, null);
  assert.equal(result.state, REPO_TRUST.UNSIGNED);
});

await t("UNSIGNED: no key pinned yet (TOFU candidate, nothing to compare)", async () => {
  const bytes = enc(JSON.stringify({ schema: "postern.repo/v1", repo: {}, apps: [] }));
  const result = await resolveRepoTrust({ repo_id: REPO_ID, pubkey_b64: null }, bytes, null);
  assert.equal(result.state, REPO_TRUST.UNSIGNED);
});

await t("TAMPERED: signature invalid for the pinned key, no key_rotation at all", async () => {
  const A = await genKey();
  const Mallory = await genKey();
  const bytes = enc(JSON.stringify({ schema: "postern.repo/v1", repo: { id: REPO_ID }, apps: [] }));
  const badSig = await sign(Mallory.kp.privateKey, bytes); // signed by the WRONG key
  const result = await resolveRepoTrust({ repo_id: REPO_ID, pubkey_b64: A.pubB64 }, bytes, badSig);
  assert.equal(result.state, REPO_TRUST.TAMPERED);
  assert.ok(!result.newPubkeyB64, "no candidate new key is ever surfaced on a bare mismatch");
});

await t("RED-TEAM FIX #5: a repo announcing a new key with a FORGED/garbage transition is hard TAMPERED, never offered as a click-through", async () => {
  const oldKey = await genKey();
  const newKey = await genKey();
  const ts = Date.now();
  const garbageSig = webcrypto.getRandomValues(new Uint8Array(64)); // NOT signed by oldKey
  const doc = {
    schema: "postern.repo/v1",
    repo: { id: REPO_ID, key_rotation: { old_pubkey_b64: oldKey.pubB64, new_pubkey_b64: newKey.pubB64, timestamp: ts, transition_signature_b64: b64(garbageSig) } },
    apps: [],
  };
  const bytes = enc(JSON.stringify(doc));
  const sig = await sign(newKey.kp.privateKey, bytes); // index genuinely signed by the NEW key
  const result = await resolveRepoTrust({ repo_id: REPO_ID, pubkey_b64: oldKey.pubB64 }, bytes, sig);
  assert.equal(result.state, REPO_TRUST.TAMPERED, "must reject outright, not prompt");
  assert.ok(!result.newPubkeyB64, "no accept-able new key on an invalid transition");
  assert.match(result.reason, /never offered as a click-through/i);
});

await t("RED-TEAM FIX #5 (variant): key_rotation present but MISSING entirely from an otherwise mismatched index is still TAMPERED", async () => {
  const oldKey = await genKey();
  const newKey = await genKey();
  const doc = { schema: "postern.repo/v1", repo: { id: REPO_ID }, apps: [] }; // no key_rotation block at all
  const bytes = enc(JSON.stringify(doc));
  const sig = await sign(newKey.kp.privateKey, bytes);
  const result = await resolveRepoTrust({ repo_id: REPO_ID, pubkey_b64: oldKey.pubB64 }, bytes, sig);
  assert.equal(result.state, REPO_TRUST.TAMPERED);
});

await t("TAMPERED: key_rotation.old_pubkey_b64 does not match what's actually pinned", async () => {
  const oldKey = await genKey();
  const impostorOld = await genKey(); // attacker claims a DIFFERENT "old" key than what's really pinned
  const newKey = await genKey();
  const ts = Date.now();
  const transitionSig = await sign(impostorOld.kp.privateKey, rotationTransitionMessage(REPO_ID, impostorOld.pubB64, newKey.pubB64, ts));
  const doc = {
    schema: "postern.repo/v1",
    repo: { id: REPO_ID, key_rotation: { old_pubkey_b64: impostorOld.pubB64, new_pubkey_b64: newKey.pubB64, timestamp: ts, transition_signature_b64: b64(transitionSig) } },
    apps: [],
  };
  const bytes = enc(JSON.stringify(doc));
  const sig = await sign(newKey.kp.privateKey, bytes);
  const result = await resolveRepoTrust({ repo_id: REPO_ID, pubkey_b64: oldKey.pubB64 }, bytes, sig); // pinned key != impostorOld
  assert.equal(result.state, REPO_TRUST.TAMPERED);
});

await t("ROTATION_PENDING: a transition genuinely signed by the OLD pinned key is the ONLY way to reach this state", async () => {
  const oldKey = await genKey();
  const newKey = await genKey();
  const ts = Date.now();
  const transitionSig = await sign(oldKey.kp.privateKey, rotationTransitionMessage(REPO_ID, oldKey.pubB64, newKey.pubB64, ts));
  const doc = {
    schema: "postern.repo/v1",
    repo: { id: REPO_ID, key_rotation: { old_pubkey_b64: oldKey.pubB64, new_pubkey_b64: newKey.pubB64, timestamp: ts, transition_signature_b64: b64(transitionSig) } },
    apps: [{ id: "demo" }],
  };
  const bytes = enc(JSON.stringify(doc));
  const sig = await sign(newKey.kp.privateKey, bytes); // index itself signed by the announced new key
  const result = await resolveRepoTrust({ repo_id: REPO_ID, pubkey_b64: oldKey.pubB64 }, bytes, sig);
  assert.equal(result.state, REPO_TRUST.ROTATION_PENDING);
  assert.equal(result.newPubkeyB64, newKey.pubB64);
});

await t("TAMPERED: valid transition statement, but the index's own signature does not verify against the announced new key", async () => {
  const oldKey = await genKey();
  const newKey = await genKey();
  const someoneElse = await genKey();
  const ts = Date.now();
  const transitionSig = await sign(oldKey.kp.privateKey, rotationTransitionMessage(REPO_ID, oldKey.pubB64, newKey.pubB64, ts));
  const doc = {
    schema: "postern.repo/v1",
    repo: { id: REPO_ID, key_rotation: { old_pubkey_b64: oldKey.pubB64, new_pubkey_b64: newKey.pubB64, timestamp: ts, transition_signature_b64: b64(transitionSig) } },
    apps: [],
  };
  const bytes = enc(JSON.stringify(doc));
  const sig = await sign(someoneElse.kp.privateKey, bytes); // NOT signed by newKey — inconsistent index
  const result = await resolveRepoTrust({ repo_id: REPO_ID, pubkey_b64: oldKey.pubB64 }, bytes, sig);
  assert.equal(result.state, REPO_TRUST.TAMPERED);
});

await t("UNVERIFIABLE: this engine's WebCrypto has no Ed25519 — honest 'can't verify here', never a guess", async () => {
  // Generate + sign BEFORE breaking generateKey — __breakEd25519 only knocks
  // out the capability-probe path (generateKey), matching what
  // ed25519Available() actually calls; sign()/verify() on an already-held
  // key still work, same as this test's own fixture-building would need.
  const A = await genKey();
  const bytes = enc(JSON.stringify({ schema: "postern.repo/v1", repo: {}, apps: [] }));
  const sig = await sign(A.kp.privateKey, bytes);
  globalThis.__breakEd25519();
  try {
    const result = await resolveRepoTrust({ repo_id: REPO_ID, pubkey_b64: A.pubB64 }, bytes, sig);
    assert.equal(result.state, REPO_TRUST.UNVERIFIABLE);
  } finally {
    globalThis.__fixEd25519();
  }
});

await t("verifyKeyRotation directly: malformed base64 in the rotation block is rejected, not thrown", async () => {
  const oldKey = await genKey();
  const r = await verifyKeyRotation({ repo_id: REPO_ID, pubkey_b64: oldKey.pubB64 }, {
    repo: { key_rotation: { old_pubkey_b64: oldKey.pubB64, new_pubkey_b64: "not-valid-base64!!!", transition_signature_b64: "also-not-valid!!!", timestamp: Date.now() } },
  });
  assert.equal(r.ok, false);
});

console.log(`\npostern-store repo-trust: ${passed} checks passed`);
