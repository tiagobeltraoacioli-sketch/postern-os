// SPDX-License-Identifier: MIT OR Apache-2.0
// Bucket D (Dev D1) — DNB Direct+ client test suite. Run with:
//   node apps/gramota-kyc/dnb-client.test.mjs
// Plain ESM, custom assert-based runner (no framework), matching the existing
// review-seam.test.mjs convention. NO real network calls anywhere — every path
// is fixture/mock-driven. See docs/bucketD/{PARTITION,RUNBOOK,READINESS}.md.
//
// Coverage (docs/bucketD/PARTITION.md §3, points 1-13):
//  1. no-creds short-circuit (fetchImpl never called)
//  2. static DNB_BEARER skips the token exchange
//  3. OAuth token HTTP failure (401/500)
//  4. OAuth token response missing access_token
//  5. Data lookup 404 -> not-found
//  6. Data lookup non-404 error: 500 -> unavailable; 429 -> its OWN
//     "rate-limited" status (hardening — no longer folded into "unavailable",
//     since that let a quota-exhaustion 429 silently degrade like a genuine
//     outage). 6b: dnbDecisionFrom/kycGate never silently promote
//     "rate-limited" to a full pass.
//  7. Data lookup 200 but malformed body -> not-found (fail-CLOSED)
//  8. Thrown/rejected fetch -> unavailable, never an unhandled rejection
//  9. Successful mapping, fixture-driven (incl. missing addressCountry edge case)
// 10. Timeout/hang -> unavailable/dnb-timeout within the configured bound (F2 fix)
// 11. Cross-file parity: review.js vs master.js vs renew.js's copies
// 12. computeLoa full fail-closed matrix
// 13. kycGate x KYC_MODE=enforce full 2x2
// 14. KYC_MODE normalization hardening: mixed-case/whitespace enforces,
//     unrecognized value warns (not silent bypass), unset stays off
//
// Plus the F1 reconciliation: a cross-model equivalence matrix between
// review.js's computeLoa and apps/gramota-kyc/kyc-loa.mjs's evidenceToLoa.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { webcrypto } from "node:crypto";
if (!globalThis.crypto) globalThis.crypto = webcrypto;

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");

const review = await import(new URL("../../functions/license/review.js", import.meta.url));
const master = await import(new URL("../../functions/license/master.js", import.meta.url));
const { evidenceToLoa } = await import(new URL("./kyc-loa.mjs", import.meta.url));

const {
  verifyDunsWithDnB, dnbDecisionFrom, computeLoa, kycGate, ocrValidated,
} = review;

let passed = 0;
const t = async (name, fn) => { await fn(); passed++; console.log("  ok — " + name); };

// ---------------------------------------------------------------------------
// Fixture loader.
// ---------------------------------------------------------------------------
const FIXDIR = join(HERE, "fixtures", "dnb");
function fx(name) {
  const raw = JSON.parse(readFileSync(join(FIXDIR, name + ".json"), "utf8"));
  assert.ok(typeof raw._synthetic === "string" && /SYNTHETIC/.test(raw._synthetic),
    `fixture ${name} must carry the SYNTHETIC header field`);
  return raw;
}

// ---------------------------------------------------------------------------
// fetchImpl factories — everything mock/fixture-driven, no live network calls.
// ---------------------------------------------------------------------------
function neverCallFetch() {
  return async () => { throw new Error("fetchImpl must NOT be called (short-circuit expected)"); };
}
function spyFetch(behavior) {
  const calls = [];
  const wrapped = async (url, opts) => { calls.push(String(url)); return behavior(url, opts); };
  wrapped.calls = calls;
  return wrapped;
}
function dnbStub({ tokenStatus = 200, tokenBody = fx("oauth-token-success"), dataStatus = 200, dataBody = fx("company-l1-success") } = {}) {
  return async (url) => {
    if (String(url).includes("/v3/token")) {
      return { ok: tokenStatus >= 200 && tokenStatus < 300, status: tokenStatus, json: async () => tokenBody };
    }
    return { ok: dataStatus >= 200 && dataStatus < 300, status: dataStatus, json: async () => dataBody };
  };
}
function hangingFetch() {
  return async (_url, opts) => new Promise((_resolve, reject) => {
    if (opts && opts.signal) {
      if (opts.signal.aborted) { const e = new Error("aborted"); e.name = "AbortError"; reject(e); return; }
      opts.signal.addEventListener("abort", () => { const e = new Error("aborted"); e.name = "AbortError"; reject(e); });
    }
    // otherwise: never resolves, simulating a hung upstream.
  });
}
const CREDS = { DNB_CLIENT_ID: "id", DNB_CLIENT_SECRET: "secret" };
const BEARER_CREDS = { DNB_BEARER: "static-test-bearer" };

// =============================================================================
// 1. No creds configured -> short-circuit, fetchImpl never called.
// =============================================================================
await t("1. no creds configured -> dnb-not-configured, fetchImpl never called", async () => {
  const r = await verifyDunsWithDnB("123456789", {}, neverCallFetch());
  assert.equal(r.status, "unavailable");
  assert.equal(r.reason, "dnb-not-configured");
});

// =============================================================================
// 2. Static DNB_BEARER skips the token exchange entirely.
// =============================================================================
await t("2. DNB_BEARER path never hits /v3/token", async () => {
  const spy = spyFetch(async (url) => {
    if (String(url).includes("/v3/token")) throw new Error("must not call token endpoint with a static bearer");
    return { ok: true, status: 200, json: async () => fx("company-l1-success") };
  });
  const r = await verifyDunsWithDnB("123456789", BEARER_CREDS, spy);
  assert.equal(r.status, "verified");
  assert.ok(spy.calls.every((u) => !u.includes("/v3/token")));
  assert.equal(spy.calls.length, 1);
});

// =============================================================================
// 3. OAuth token HTTP failure (401 / 500).
// =============================================================================
await t("3. OAuth token 401 -> dnb-auth-http-401", async () => {
  const r = await verifyDunsWithDnB("123456789", CREDS, dnbStub({ tokenStatus: 401, tokenBody: fx("oauth-token-error-401") }));
  assert.equal(r.status, "unavailable");
  assert.equal(r.reason, "dnb-auth-http-401");
});
await t("3. OAuth token 500 -> dnb-auth-http-500", async () => {
  const r = await verifyDunsWithDnB("123456789", CREDS, dnbStub({ tokenStatus: 500, tokenBody: {} }));
  assert.equal(r.status, "unavailable");
  assert.equal(r.reason, "dnb-auth-http-500");
});

// =============================================================================
// 4. OAuth token response missing access_token/accessToken.
// =============================================================================
await t("4. OAuth 200 but no access_token -> dnb-auth-no-token", async () => {
  const r = await verifyDunsWithDnB("123456789", CREDS, dnbStub({ tokenBody: { token_type: "bearer", expires_in: 900 } }));
  assert.equal(r.status, "unavailable");
  assert.equal(r.reason, "dnb-auth-no-token");
});

// =============================================================================
// 5. Data lookup 404 -> not-found.
// =============================================================================
await t("5. data lookup 404 -> not-found / dnb-duns-not-found", async () => {
  const r = await verifyDunsWithDnB("999999999", CREDS, dnbStub({ dataStatus: 404, dataBody: fx("duns-not-found-404") }));
  assert.equal(r.status, "not-found");
  assert.equal(r.reason, "dnb-duns-not-found");
});

// =============================================================================
// 6. Data lookup non-404 error: 429 (rate-limited, its OWN status) vs 500
//    (unavailable). HARDENING: 429 used to be folded into "unavailable" the
//    same as any 5xx, which let an attacker who exhausts D&B's quota induce
//    the same fail-open-to-format-only degrade as a genuine outage. It is now
//    its own "rate-limited" status so kycGate can refuse to silently promote
//    it to a full pass (see the "rate-limited" section further down).
// =============================================================================
await t("6. data lookup 429 -> rate-limited / dnb-data-http-429 (NOT folded into unavailable)", async () => {
  const r = await verifyDunsWithDnB("123456789", CREDS, dnbStub({ dataStatus: 429, dataBody: fx("data-rate-limit-429") }));
  assert.equal(r.status, "rate-limited");
  assert.equal(r.reason, "dnb-data-http-429");
});
await t("6. token exchange 429 -> rate-limited / dnb-auth-http-429", async () => {
  const r = await verifyDunsWithDnB("123456789", CREDS, dnbStub({ tokenStatus: 429, tokenBody: fx("data-rate-limit-429") }));
  assert.equal(r.status, "rate-limited");
  assert.equal(r.reason, "dnb-auth-http-429");
});
await t("6. data lookup 500 -> unavailable / dnb-data-http-500 (genuine outage, unchanged)", async () => {
  const r = await verifyDunsWithDnB("123456789", CREDS, dnbStub({ dataStatus: 500, dataBody: {} }));
  assert.equal(r.status, "unavailable");
  assert.equal(r.reason, "dnb-data-http-500");
});

// =============================================================================
// 6b. dnbDecisionFrom / kycGate on a rate-limited result: never a silent
//     format-only pass. This is the actual attacker-facing behavior change —
//     6's status split is the plumbing, this is the payoff.
// =============================================================================
await t("6b. dnbDecisionFrom on a rate-limited result -> source 'rate-limited', NOT 'format-only'", () => {
  const d = dnbDecisionFrom({ status: "rate-limited", reason: "dnb-data-http-429" }, 999);
  assert.equal(d.verified, false);
  assert.equal(d.source, "rate-limited");
  assert.notEqual(d.source, "format-only");
  assert.equal(d.fallbackReason, "dnb-data-http-429");
});
await t("6b. kycGate: 429/rate-limited holds at 'provisional' even UNENFORCED with strong client evidence (no silent pass)", async () => {
  const env = { ...CREDS, LICENSES: makeKV() }; // KYC_MODE unset: parity would normally be an unconditional "pass"
  const v = await kycGate(env, {
    duns: "123456789", role: "owner", attestation: true,
    fetchImpl: dnbStub({ dataStatus: 429, dataBody: fx("data-rate-limit-429") }),
    kyc: { domain: "acme.example", domainProofAt: 1 }, // otherwise sufficient for an immediate "pass"
  });
  assert.equal(v.decision, "provisional");
  assert.equal(v.dnb.source, "rate-limited");
});
await t("6b. kycGate: 429/rate-limited holds at 'provisional' when ENFORCED too (not a new bypass either)", async () => {
  const env = { KYC_MODE: "enforce", ...CREDS, LICENSES: makeKV() };
  const v = await kycGate(env, {
    duns: "123456789", role: "owner", attestation: true,
    fetchImpl: dnbStub({ dataStatus: 429, dataBody: fx("data-rate-limit-429") }),
  });
  assert.equal(v.decision, "provisional");
});
await t("6b. kycGate: rate-limited is NOT a hard refuse (an attacker must not be able to turn self-inflicted 429s into a DoS on everyone else)", async () => {
  const env = { ...CREDS, LICENSES: makeKV() };
  const v = await kycGate(env, { duns: "123456789", role: "owner", attestation: true, fetchImpl: dnbStub({ dataStatus: 429, dataBody: fx("data-rate-limit-429") }) });
  assert.notEqual(v.decision, "refuse");
  assert.ok(v.ref, "still issues a ref (provisional, not blocked outright)");
});

// =============================================================================
// 7. Data lookup 200 but malformed body -> not-found (fail-CLOSED, not unavailable).
// =============================================================================
await t("7. 200 with no `organization` key -> not-found / dnb-no-organization", async () => {
  const r = await verifyDunsWithDnB("123456789", CREDS, dnbStub({ dataBody: fx("company-l1-malformed-no-organization") }));
  assert.equal(r.status, "not-found");
  assert.equal(r.reason, "dnb-no-organization");
});
await t("7. 200 with organization but no primaryName -> not-found / dnb-no-organization", async () => {
  const r = await verifyDunsWithDnB("123456789", CREDS, dnbStub({ dataBody: fx("company-l1-malformed-no-primaryname") }));
  assert.equal(r.status, "not-found");
  assert.equal(r.reason, "dnb-no-organization");
});

// =============================================================================
// 8. Thrown/rejected fetch -> unavailable, never an unhandled rejection/crash.
// =============================================================================
await t("8. network error thrown by fetchImpl -> unavailable / dnb-network-error", async () => {
  const r = await verifyDunsWithDnB("123456789", CREDS, async () => { throw new TypeError("simulated network failure"); });
  assert.equal(r.status, "unavailable");
  assert.equal(r.reason, "dnb-network-error");
});
await t("8. rejected token fetch -> unavailable / dnb-network-error", async () => {
  const r = await verifyDunsWithDnB("123456789", CREDS, async (url) => {
    if (String(url).includes("/v3/token")) return Promise.reject(new Error("boom"));
    return { ok: true, status: 200, json: async () => fx("company-l1-success") };
  });
  assert.equal(r.status, "unavailable");
  assert.equal(r.reason, "dnb-network-error");
});

// =============================================================================
// 9. Successful mapping — fixture-driven, incl. the missing-addressCountry edge.
// =============================================================================
await t("9. maps organization.primaryName + country from the success fixture", async () => {
  const r = await verifyDunsWithDnB("804735132", CREDS, dnbStub({ dataBody: fx("company-l1-success") }));
  assert.equal(r.status, "verified");
  assert.equal(r.legalName, "Acme Widgets LLC");
  assert.equal(r.country, "US");
  const now = 12345;
  const d = dnbDecisionFrom(r, now);
  assert.equal(d.verified, true);
  assert.equal(d.source, "dnb-direct-plus");
  assert.equal(d.legalName, "Acme Widgets LLC");
  assert.equal(d.country, "US");
  assert.equal(d.checkedAt, now);
});
await t("9. primaryAddress present but no addressCountry -> country '' (never throws)", async () => {
  const r = await verifyDunsWithDnB("111222333", CREDS, dnbStub({ dataBody: fx("company-l1-no-country") }));
  assert.equal(r.status, "verified");
  assert.equal(r.legalName, "Borderless Trading Co");
  assert.equal(r.country, "");
});
await t("9. dnbDecisionFrom on an unavailable result -> format-only fallback, no over-claim", () => {
  const d = dnbDecisionFrom({ status: "unavailable", reason: "dnb-not-configured" }, 999);
  assert.equal(d.verified, false);
  assert.equal(d.source, "format-only");
  assert.equal(d.fallbackReason, "dnb-not-configured");
});

// =============================================================================
// 10. Timeout / hang -> unavailable/dnb-timeout within the configured bound (F2).
// =============================================================================
await t("10. hanging token fetch times out -> unavailable / dnb-timeout, bounded", async () => {
  const start = Date.now();
  const r = await verifyDunsWithDnB("123456789", { ...CREDS, DNB_TIMEOUT_MS: 30 }, hangingFetch());
  const elapsed = Date.now() - start;
  assert.equal(r.status, "unavailable");
  assert.equal(r.reason, "dnb-timeout");
  assert.ok(elapsed < 2000, `timeout should resolve quickly, took ${elapsed}ms`);
  assert.notEqual(r.status, "not-found", "a timeout must never be confused with not-found");
});
await t("10. hanging data-lookup fetch (bearer path) times out -> dnb-timeout", async () => {
  const start = Date.now();
  const r = await verifyDunsWithDnB("123456789", { ...BEARER_CREDS, DNB_TIMEOUT_MS: 30 }, hangingFetch());
  const elapsed = Date.now() - start;
  assert.equal(r.status, "unavailable");
  assert.equal(r.reason, "dnb-timeout");
  assert.ok(elapsed < 2000, `timeout should resolve quickly, took ${elapsed}ms`);
});
await t("10. every fetchImpl call receives a real AbortSignal (the timeout wiring is live, not decorative)", async () => {
  let sawTokenSignal = false, sawDataSignal = false;
  const spy = async (url, opts) => {
    const hasSignal = !!(opts && opts.signal && typeof opts.signal.aborted === "boolean");
    if (String(url).includes("/v3/token")) { sawTokenSignal = hasSignal; return { ok: true, status: 200, json: async () => fx("oauth-token-success") }; }
    sawDataSignal = hasSignal;
    return { ok: true, status: 200, json: async () => fx("company-l1-success") };
  };
  await verifyDunsWithDnB("804735132", CREDS, spy);
  assert.equal(sawTokenSignal, true, "token fetch must carry an AbortSignal");
  assert.equal(sawDataSignal, true, "data fetch must carry an AbortSignal");
});

// =============================================================================
// 11. Cross-file parity — review.js vs master.js vs renew.js's copies.
// =============================================================================
// Extraction helper (same brace-matching technique already used by
// apps/gramota-kyc/inline-parity-check.mjs / self-check.mjs for other
// inlined/duplicated copies in this repo).
function extractFn(src, name) {
  let start = src.indexOf("function " + name + "(");
  if (start < 0) return null;
  // Include a preceding "async " keyword (dropping it turns `await` inside the
  // extracted body into a syntax error under `new Function`).
  const asyncPrefix = "async ";
  if (start >= asyncPrefix.length && src.slice(start - asyncPrefix.length, start) === asyncPrefix) {
    start -= asyncPrefix.length;
  }
  let i = src.indexOf("{", start), depth = 0, end = -1;
  for (; i < src.length; i++) {
    if (src[i] === "{") depth++;
    else if (src[i] === "}") { depth--; if (depth === 0) { end = i + 1; break; } }
  }
  return end < 0 ? null : src.slice(start, end);
}
const renewSrc = readFileSync(join(ROOT, "functions", "license", "renew.js"), "utf8");
const renewVerifyFnSrc = extractFn(renewSrc, "verifyDunsWithDnB");
const renewDecisionFnSrc = extractFn(renewSrc, "dnbDecisionFrom");
assert.ok(renewVerifyFnSrc, "expected to find verifyDunsWithDnB in renew.js source");
assert.ok(renewDecisionFnSrc, "expected to find dnbDecisionFrom in renew.js source");
// renew.js does not `export` these (confirmed: no `export` keyword on either
// function) — per PARTITION.md §3 point 11, extract-and-invoke the source
// directly instead of settling for a documented byte-diff, so this suite gets
// REAL coverage of renew.js's copy, not just a note that it exists.
const renewPreamble = 'var DNB_AUTH_URL="https://plus.dnb.com/v3/token"; var DNB_DATA_URL="https://plus.dnb.com/v1/data/duns"; var DNB_TIMEOUT_MS_DEFAULT=8000;\n';
// eslint-disable-next-line no-new-func
const renewFns = new Function(renewPreamble + renewVerifyFnSrc + "\n" + renewDecisionFnSrc + "\nreturn { verifyDunsWithDnB, dnbDecisionFrom };")();

await t("11. review.js, master.js, and renew.js's copies agree on the SUCCESS fixture", async () => {
  const cases = [
    ["review.js", verifyDunsWithDnB],
    ["master.js", master.verifyDunsWithDnB],
    ["renew.js", renewFns.verifyDunsWithDnB],
  ];
  for (const [label, fn] of cases) {
    const r = await fn("804735132", CREDS, dnbStub({ dataBody: fx("company-l1-success") }));
    assert.equal(r.status, "verified", label);
    assert.equal(r.legalName, "Acme Widgets LLC", label);
    assert.equal(r.country, "US", label);
  }
});
await t("11. review.js, master.js, and renew.js's copies agree on not-found / malformed / auth-fail", async () => {
  const cases = [
    ["review.js", verifyDunsWithDnB],
    ["master.js", master.verifyDunsWithDnB],
    ["renew.js", renewFns.verifyDunsWithDnB],
  ];
  // §7's full malformed-body matrix (fail-CLOSED -> not-found/dnb-no-organization),
  // not just the "no organization key at all" case. A copy that loosens ONLY the
  // "organization present but primaryName missing" branch must fail here too --
  // driving a single fixture through wasn't enough to catch that class of drift
  // (confirmed by mutation testing: loosening the primaryName check in one
  // file-copy alone left the suite green).
  const malformedFixtures = [
    ["company-l1-malformed-no-organization", "dnb-no-organization"],
    ["company-l1-malformed-no-primaryname", "dnb-no-organization"],
  ];
  for (const [label, fn] of cases) {
    const notFound = await fn("999999999", CREDS, dnbStub({ dataStatus: 404, dataBody: fx("duns-not-found-404") }));
    assert.deepEqual(notFound, { status: "not-found", reason: "dnb-duns-not-found" }, label);

    for (const [fixtureName, reason] of malformedFixtures) {
      const malformed = await fn("123456789", CREDS, dnbStub({ dataBody: fx(fixtureName) }));
      assert.deepEqual(malformed, { status: "not-found", reason }, `${label} / ${fixtureName}`);
    }

    const authFail = await fn("123456789", CREDS, dnbStub({ tokenStatus: 401, tokenBody: fx("oauth-token-error-401") }));
    assert.deepEqual(authFail, { status: "unavailable", reason: "dnb-auth-http-401" }, label);

    const notConfigured = await fn("123456789", {}, neverCallFetch());
    assert.deepEqual(notConfigured, { status: "unavailable", reason: "dnb-not-configured" }, label);
  }
});
await t("11. dnbDecisionFrom agrees across all three copies", () => {
  const now = 42;
  const okResult = { status: "verified", legalName: "Acme Widgets LLC", country: "US" };
  const badResult = { status: "unavailable", reason: "dnb-not-configured" };
  for (const [label, fn] of [["review.js", dnbDecisionFrom], ["master.js", master.dnbDecisionFrom], ["renew.js", renewFns.dnbDecisionFrom]]) {
    assert.deepEqual(fn(okResult, now), { verified: true, source: "dnb-direct-plus", legalName: "Acme Widgets LLC", country: "US", checkedAt: now }, label);
    assert.deepEqual(fn(badResult, now), { verified: false, source: "format-only", checkedAt: now, fallbackReason: "dnb-not-configured" }, label);
  }
});
await t("11. review.js, master.js, and renew.js's copies agree on timeout -> dnb-timeout", async () => {
  // The F2 timeout fix (AbortController + dnb-timeout) has now landed in all
  // three copies (the former Bucket C hand-off is complete — see
  // docs/bucketD/DEV-D1-HANDOFF.md for the original unified-diff hunks this
  // fix carried out). Assert real timeout-equivalence across the copies,
  // not just document the gap.
  const cases = [
    ["review.js", verifyDunsWithDnB],
    ["master.js", master.verifyDunsWithDnB],
    ["renew.js", renewFns.verifyDunsWithDnB],
  ];
  for (const [label, fn] of cases) {
    const r = await fn("804735132", { ...CREDS, DNB_TIMEOUT_MS: 20 }, hangingFetch());
    assert.deepEqual(r, { status: "unavailable", reason: "dnb-timeout" }, label);
  }
});

// =============================================================================
// 12. computeLoa full fail-closed matrix.
// =============================================================================
await t("12. D&B-verified-alone-with-nothing-else stays at LoA 0 (entity real != person authorized)", () => {
  const r = computeLoa({ selfDeclared: true, dnbVerified: true });
  assert.equal(r.loa, 0);
});
await t("12. corp-domain-alone caps at LoA 1", () => {
  const r = computeLoa({ selfDeclared: true, dnbVerified: true, corpDomain: true });
  assert.equal(r.loa, 1);
});
await t("12. OCR-match WITHOUT corp-domain never reaches LoA 2 (rung gating)", () => {
  const r = computeLoa({ selfDeclared: true, ocr: { onDevice: true, match: true, fieldsMatched: ["legalName", "country"] } });
  assert.ok(r.loa < 2, `expected loa < 2 without corp-domain, got ${r.loa}`);
});
await t("12. OCR-match-without-liveness caps at LoA 2 (needs corp-domain too)", () => {
  const r = computeLoa({ selfDeclared: true, corpDomain: true, ocr: { onDevice: true, match: true, fieldsMatched: ["legalName", "country"], liveness: false } });
  assert.equal(r.loa, 2);
});
await t("12. principal-match + corp-domain reaches LoA 2 without OCR", () => {
  const r = computeLoa({ selfDeclared: true, corpDomain: true, principalMatch: true });
  assert.equal(r.loa, 2);
});
await t("12. OCR + liveness (+ corp-domain) reaches LoA 3", () => {
  // NOTE: computeLoa reads `liveness` off the TOP-LEVEL evidence object (mirroring
  // kycGate's call site: `liveness: cv.ocr ? cv.ocr.liveness : false`), not off
  // `ocr.liveness` directly — this is the real call contract, asserted here.
  const r = computeLoa({ selfDeclared: true, corpDomain: true, liveness: true, ocr: { onDevice: true, match: true, fieldsMatched: ["legalName", "country"], liveness: true } });
  assert.equal(r.loa, 3);
});
await t("12. full external IDV pass reaches LoA 3 independent of the ladder", () => {
  const r = computeLoa({ selfDeclared: true, idvPass: true });
  assert.equal(r.loa, 3);
});
await t("12. ocrValidated requires onDevice+match+legalName+country fields, fails closed on partial", () => {
  assert.equal(ocrValidated({ onDevice: true, match: true, fieldsMatched: ["legalName"] }), false);
  assert.equal(ocrValidated({ onDevice: true, match: false, fieldsMatched: ["legalName", "country"] }), false);
  assert.equal(ocrValidated({ onDevice: false, match: true, fieldsMatched: ["legalName", "country"] }), false);
  assert.equal(ocrValidated({ onDevice: true, match: true, fieldsMatched: ["legalName", "country"] }), true);
});

// =============================================================================
// 13. kycGate x KYC_MODE=enforce full 2x2 (D&B verified/not-configured) x
//     (evidence sufficient/insufficient).
// =============================================================================
function makeKV() { const m = new Map(); return { get: async (k) => m.get(k) ?? null, put: async (k, v) => { m.set(k, v); } }; }

await t("13. [verified] x [insufficient evidence] -> provisional (already the refuse-adjacent floor)", async () => {
  const env = { KYC_MODE: "enforce", ...CREDS, LICENSES: makeKV() };
  const v = await kycGate(env, { duns: "804735132", role: "owner", attestation: true, fetchImpl: dnbStub({ dataBody: fx("company-l1-success") }) });
  assert.equal(v.dnb.verified, true);
  assert.equal(v.decision, "provisional");
  assert.equal(v.loa, 0);
});
await t("13. [verified] x [sufficient evidence] -> pass, loa >= 1", async () => {
  const env = { KYC_MODE: "enforce", ...CREDS, LICENSES: makeKV() };
  const v = await kycGate(env, {
    duns: "804735132", role: "owner", attestation: true,
    fetchImpl: dnbStub({ dataBody: fx("company-l1-success") }),
    kyc: { domain: "acme.example", domainProofAt: 1 },
  });
  assert.equal(v.dnb.verified, true);
  assert.equal(v.decision, "pass");
  assert.ok(v.loa >= 1);
});
await t("13. [not-configured/unavailable] x [insufficient evidence] -> provisional, never a hard failure", async () => {
  const env = { KYC_MODE: "enforce", LICENSES: makeKV() }; // no D&B creds -> unavailable/format-only
  const v = await kycGate(env, { duns: "804735132", role: "owner", attestation: true, fetchImpl: neverCallFetch() });
  assert.equal(v.dnb.verified, false);
  assert.equal(v.dnb.source, "format-only");
  assert.equal(v.decision, "provisional");
});
await t("13. [not-configured/unavailable] x [sufficient evidence] -> pass (outage must not be a hard DoS)", async () => {
  const env = { KYC_MODE: "enforce", LICENSES: makeKV() }; // no D&B creds -> unavailable/format-only
  const v = await kycGate(env, {
    duns: "804735132", role: "owner", attestation: true, fetchImpl: neverCallFetch(),
    kyc: { domain: "acme.example", domainProofAt: 1 },
  });
  assert.equal(v.dnb.verified, false);
  assert.equal(v.dnb.source, "format-only");
  assert.equal(v.decision, "pass");
  assert.ok(v.loa >= 1);
});
await t("13. D&B not-found still refuses outright even with strong client evidence (fail-closed, not a 2x2 cell)", async () => {
  const env = { KYC_MODE: "enforce", ...CREDS, LICENSES: makeKV() };
  const v = await kycGate(env, {
    duns: "999999999", role: "owner", attestation: true,
    fetchImpl: dnbStub({ dataStatus: 404, dataBody: fx("duns-not-found-404") }),
    kyc: { domain: "acme.example", domainProofAt: 1 },
  });
  assert.equal(v.decision, "refuse");
  assert.equal(v.ref, null);
});

// =============================================================================
// 14. KYC_MODE normalization hardening.
//
// BUG FIXED: `env.KYC_MODE === "enforce"` was a raw case-sensitive exact match.
// "Enforce", "ENFORCE", or a trailing space would silently fail the compare and
// DISABLE enforcement — exactly backwards for a flag whose entire job is to
// turn hardening ON. FIX: trim+lowercase normalization, plus a loud
// console.warn when the value is SET but does not normalize to a recognized
// mode (so a typo during a hardened rollout is visible, not a silent bypass).
// =============================================================================
async function captureWarn(fn) {
  const calls = [];
  const orig = console.warn;
  console.warn = (...args) => calls.push(args.join(" "));
  try { return { result: await fn(), calls }; } finally { console.warn = orig; }
}

await t("14. KYC_MODE mixed-case/whitespace variants all enforce (the bug: these used to silently DISABLE enforcement)", async () => {
  for (const raw of ["enforce", "Enforce", "ENFORCE", "EnForce", " enforce", "enforce ", " Enforce \t"]) {
    const env = { KYC_MODE: raw, ...CREDS, LICENSES: makeKV() };
    const v = await kycGate(env, { duns: "804735132", role: "owner", attestation: true, fetchImpl: dnbStub({ dataBody: fx("company-l1-success") }) });
    assert.equal(v.enforced, true, `KYC_MODE=${JSON.stringify(raw)} must enforce`);
    assert.equal(v.decision, "provisional", `KYC_MODE=${JSON.stringify(raw)} + insufficient evidence must be provisional, not a silent pass`);
  }
});
await t("14. GRAMOTA_KYC mixed-case also enforces (both flags normalized identically)", async () => {
  const env = { GRAMOTA_KYC: "ENFORCE", ...CREDS, LICENSES: makeKV() };
  const v = await kycGate(env, { duns: "804735132", role: "owner", attestation: true, fetchImpl: dnbStub({ dataBody: fx("company-l1-success") }) });
  assert.equal(v.enforced, true);
});
await t("14. unset KYC_MODE stays OFF (parity, no regression) and does not warn", async () => {
  const env = { ...CREDS, LICENSES: makeKV() }; // no KYC_MODE / GRAMOTA_KYC at all
  const { result: v, calls } = await captureWarn(() =>
    kycGate(env, { duns: "804735132", role: "owner", attestation: true, fetchImpl: dnbStub({ dataBody: fx("company-l1-success") }) }));
  assert.equal(v.enforced, false);
  assert.equal(v.decision, "pass");
  assert.equal(calls.length, 0);
});
await t("14. a SET-but-unrecognized KYC_MODE warns loudly and resolves to OFF (not a silent bypass)", async () => {
  const env = { KYC_MODE: "enforced", ...CREDS, LICENSES: makeKV() }; // typo: "enforced" != "enforce"
  const { result: v, calls } = await captureWarn(() =>
    kycGate(env, { duns: "804735132", role: "owner", attestation: true, fetchImpl: dnbStub({ dataBody: fx("company-l1-success") }) }));
  assert.equal(v.enforced, false, "unrecognized value must NOT silently enforce OR silently no-op into some other state — it resolves to the safe default (off)");
  assert.ok(calls.length >= 1, "an unrecognized-but-set KYC_MODE must warn loudly");
  assert.ok(calls.some((c) => c.includes("KYC_MODE") && c.includes("enforced")), "warning must name the offending var + value");
});
await t("14. blank/whitespace-only KYC_MODE stays OFF without warning (blank is 'unset', not a typo)", async () => {
  const env = { KYC_MODE: "   ", ...CREDS, LICENSES: makeKV() };
  const { result: v, calls } = await captureWarn(() =>
    kycGate(env, { duns: "804735132", role: "owner", attestation: true, fetchImpl: dnbStub({ dataBody: fx("company-l1-success") }) }));
  assert.equal(v.enforced, false);
  assert.equal(calls.length, 0);
});

// =============================================================================
// F1 reconciliation — cross-model equivalence matrix: review.js's computeLoa vs
// apps/gramota-kyc/kyc-loa.mjs's evidenceToLoa on identical evidence.
// =============================================================================
await t("F1: computeLoa (server) and evidenceToLoa (client mirror) agree across an evidence matrix", () => {
  const bools = [false, true];
  let combos = 0;
  for (const dnbVerified of bools) for (const corpDomain of bools) for (const principalMatch of bools)
    for (const onDevice of bools) for (const match of bools) for (const liveness of bools) for (const idvPass of bools) {
      for (const fieldsMatched of [[], ["legalName"], ["legalName", "country"]]) {
        // `liveness` is read off the TOP-LEVEL evidence object by both computeLoa
        // and evidenceToLoa (mirroring kycGate's call site:
        // `liveness: cv.ocr ? cv.ocr.liveness : false`), not off `ocr.liveness`.
        const evidence = {
          selfDeclared: true, dnbVerified, corpDomain, principalMatch, liveness,
          ocr: { onDevice, match, fieldsMatched, liveness }, idvPass,
        };
        const server = computeLoa(evidence);
        const client = evidenceToLoa(evidence);
        assert.deepEqual(client, server, `mismatch on ${JSON.stringify(evidence)}`);
        combos++;
      }
    }
  assert.ok(combos > 300, `expected a wide matrix, got ${combos} combos`);
});
await t("F1: evidenceToLoa alone reproduces the three named invariants asserted for computeLoa in §12", () => {
  assert.equal(evidenceToLoa({ selfDeclared: true, dnbVerified: true }).loa, 0);
  assert.equal(evidenceToLoa({ selfDeclared: true, corpDomain: true }).loa, 1);
  assert.equal(evidenceToLoa({ selfDeclared: true, ocr: { onDevice: true, match: true, fieldsMatched: ["legalName", "country"] } }).loa < 2, true);
});

console.log("\n" + passed + " passed");
