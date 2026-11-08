// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Gramota IDENTITY KYC SEAM tests — run with: node kyc-seam.test.mjs (Node >= 18)
// Exercises functions/gramota/kyc-seam.js: the pluggable kycGate (honest default
// no-op + injection-and-defer) and the fail-closed normalizeResult matrix.
//
// STATUS: real unit tests for an UNAUDITED reference-prototype seam. Fully OFFLINE:
// no network, no KV, no D&B — the seam has no side effects, so nothing is stubbed
// except an in-process injected gate (a plain async function) and Date.now().
import assert from "node:assert/strict";

const mod = await import(new URL("../../functions/gramota/kyc-seam.js", import.meta.url));
const { kycGate, normalizeResult } = mod;

let passed = 0;
const t = async (name, fn) => { await fn(); passed++; console.log("  ok — " + name); };

// A fixed clock so "fresh timestamp" assertions are exact, not flaky. Restored
// after each use so no test leaks a frozen Date onto another.
const REAL_NOW = Date.now;
const FROZEN_MS = 1_800_000_000_000; // 2027-01-15T08:00:00Z, arbitrary but stable
const FROZEN_SEC = Math.floor(FROZEN_MS / 1000);
// Awaits fn() before restoring the clock so async callers (kycGate) still see
// the frozen Date.now() at the moment they actually read it, post-await.
async function withFrozenClock(fn) {
  Date.now = () => FROZEN_MS;
  try { return await fn(); } finally { Date.now = REAL_NOW; }
}

// ---- exports & contract shape --------------------------------------------
await t("module exports kycGate + normalizeResult (named) and as default", () => {
  assert.equal(typeof kycGate, "function");
  assert.equal(typeof normalizeResult, "function");
  assert.equal(typeof mod.default, "object");
  assert.equal(mod.default.kycGate, kycGate);
  assert.equal(mod.default.normalizeResult, normalizeResult);
});

// ---- kycGate: honest default when NO provider is configured ---------------
await t("kycGate with no provider => {pass, self-declared, ref:kyc-not-configured}", async () => {
  const v = await withFrozenClock(() => kycGate({}, { duns: "123456789", role: "owner" }));
  assert.equal(v.decision, "pass");
  assert.equal(v.assurance, "self-declared");
  assert.equal(v.ref, "kyc-not-configured");
  assert.equal(v.checkedAt, FROZEN_SEC);
});

await t("kycGate tolerates a null/undefined env (no provider) => honest default", async () => {
  for (const env of [null, undefined, {}, { KYC_GATE: null }, { KYC_GATE: "not-a-fn" }, { KYC_GATE: 42 }]) {
    const v = await kycGate(env, { duns: "123456789", role: "manager" });
    assert.equal(v.decision, "pass", `env=${JSON.stringify(env)}`);
    assert.equal(v.ref, "kyc-not-configured");
    assert.equal(v.assurance, "self-declared");
  }
});

// ---- kycGate: INJECTION — an env.KYC_GATE function is deferred to ----------
await t("kycGate defers wholesale to an injected env.KYC_GATE, passing (env, ctx)", async () => {
  let sawEnv, sawCtx, calls = 0;
  const env = {
    KYC_GATE: async (e, c) => {
      calls++; sawEnv = e; sawCtx = c;
      return { decision: "pass", ref: "prov-abc-123", assurance: "document", checkedAt: 1700000000 };
    },
  };
  const ctx = { duns: "123456789", role: "owner" };
  const v = await kycGate(env, ctx);
  assert.equal(calls, 1, "injected gate called exactly once");
  assert.equal(sawEnv, env, "injected gate received the env (so it can read its own bindings)");
  assert.equal(sawCtx, ctx, "injected gate received the applicant ctx");
  // A clean provider result survives normalization unchanged.
  assert.deepEqual(v, { decision: "pass", ref: "prov-abc-123", assurance: "document", checkedAt: 1700000000 });
});

await t("an injected gate's result is ALWAYS run through normalizeResult (garbage in => fail-closed out)", async () => {
  // Provider returns junk: bogus decision, unknown assurance, no ref, NaN clock.
  const env = { KYC_GATE: async () => ({ decision: "APPROVED", assurance: "palm-vein", checkedAt: Number.NaN }) };
  const v = await withFrozenClock(() => kycGate(env, { duns: "123456789", role: "owner" }));
  assert.equal(v.decision, "fail", "unrecognized decision from provider is normalized to fail");
  assert.equal(v.assurance, "self-declared", "unknown assurance is downgraded to self-declared");
  assert.equal(v.ref, "kyc-unknown", "missing ref becomes kyc-unknown");
  assert.equal(v.checkedAt, FROZEN_SEC, "non-finite checkedAt is replaced with a fresh timestamp");
});

await t("an injected gate returning null/garbage type is normalized, not crashed", async () => {
  for (const bad of [null, undefined, "yes", 7, []]) {
    const v = await withFrozenClock(() => kycGate({ KYC_GATE: async () => bad }, {}));
    assert.equal(v.decision, "fail");
    assert.equal(v.assurance, "self-declared");
    assert.equal(v.ref, "kyc-unknown");
    assert.equal(v.checkedAt, FROZEN_SEC);
  }
});

// ---- normalizeResult: the FAIL-CLOSED matrix, branch by branch -------------
await t("normalizeResult passes through a fully valid result untouched", () => {
  const clean = { decision: "pass", ref: "opaque-ref-1", assurance: "liveness", checkedAt: 1699999999 };
  assert.deepEqual(normalizeResult(clean), clean);
});

await t("normalizeResult accepts each legit decision (pass|pending|fail) verbatim", () => {
  for (const d of ["pass", "pending", "fail"]) {
    assert.equal(normalizeResult({ decision: d, ref: "r", assurance: "document", checkedAt: 1 }).decision, d);
  }
});

await t("normalizeResult maps a garbled/absent decision => 'fail'", () => {
  for (const bad of [undefined, null, "", "PASS", "approved", "ok", 1, true, {}]) {
    assert.equal(normalizeResult({ decision: bad, ref: "r", assurance: "document", checkedAt: 1 }).decision, "fail",
      `decision=${JSON.stringify(bad)} should fail-close`);
  }
  assert.equal(normalizeResult({}).decision, "fail");
  assert.equal(normalizeResult(null).decision, "fail");
  assert.equal(normalizeResult(undefined).decision, "fail");
});

await t("normalizeResult accepts each legit assurance (self-declared|document|liveness|ubo) verbatim", () => {
  for (const a of ["self-declared", "document", "liveness", "ubo"]) {
    assert.equal(normalizeResult({ decision: "pass", ref: "r", assurance: a, checkedAt: 1 }).assurance, a);
  }
});

await t("normalizeResult maps an unknown/absent assurance => 'self-declared'", () => {
  for (const bad of [undefined, null, "", "biometric", "DOCUMENT", "kyc", 3, true]) {
    assert.equal(normalizeResult({ decision: "pass", ref: "r", assurance: bad, checkedAt: 1 }).assurance, "self-declared",
      `assurance=${JSON.stringify(bad)} should downgrade`);
  }
});

await t("normalizeResult maps a missing/empty ref => 'kyc-unknown', but stringifies a present one", () => {
  assert.equal(normalizeResult({ decision: "pass", assurance: "document", checkedAt: 1 }).ref, "kyc-unknown");
  assert.equal(normalizeResult({ decision: "pass", ref: "", assurance: "document", checkedAt: 1 }).ref, "kyc-unknown");
  assert.equal(normalizeResult({ decision: "pass", ref: 0, assurance: "document", checkedAt: 1 }).ref, "kyc-unknown");
  assert.equal(normalizeResult({ decision: "pass", ref: 555, assurance: "document", checkedAt: 1 }).ref, "555");
  assert.equal(normalizeResult({ decision: "pass", ref: "opq-9", assurance: "document", checkedAt: 1 }).ref, "opq-9");
});

await t("normalizeResult replaces a non-finite/absent checkedAt with a fresh timestamp, keeps a finite one", async () => {
  for (const bad of [undefined, null, Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, "1699999999"]) {
    const v = await withFrozenClock(() => normalizeResult({ decision: "pass", ref: "r", assurance: "document", checkedAt: bad }));
    assert.equal(v.checkedAt, FROZEN_SEC, `checkedAt=${String(bad)} should be refreshed`);
  }
  // A finite numeric clock (incl. 0) is trusted and preserved verbatim.
  assert.equal(normalizeResult({ decision: "pass", ref: "r", assurance: "document", checkedAt: 0 }).checkedAt, 0);
  assert.equal(normalizeResult({ decision: "pass", ref: "r", assurance: "document", checkedAt: 1699999999 }).checkedAt, 1699999999);
});

await t("normalizeResult full worst-case matrix: every field garbled at once => fully fail-closed", async () => {
  const v = await withFrozenClock(() => normalizeResult({ decision: "maybe", ref: "", assurance: "retina", checkedAt: "soon" }));
  assert.deepEqual(v, { decision: "fail", ref: "kyc-unknown", assurance: "self-declared", checkedAt: FROZEN_SEC });
});

console.log("\n" + passed + " passed");
