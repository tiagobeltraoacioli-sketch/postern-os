// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// GRAMOTA inline-build parity check — run: node inline-parity-check.mjs (Node >= 18)
//
// assemble-public.sh ships apps/gramota/index.html VERBATIM as a single
// self-contained file. Its inline <script> carries a condensed hand-port of the
// on-device KYC/LoA ladder whose SOURCE OF TRUTH is the modular
// apps/gramota-kyc/kyc-loa.mjs (`makeKycLadder`) — the index.html header says so
// literally ("Inline byte-compatible copy of apps/gramota-kyc/kyc-loa.mjs …").
//
// This is the GATE that keeps the shipped bundle from going stale: if kyc-loa.mjs
// is edited but the inline copy in index.html is not (or vice-versa), the two
// drift and this check fails BEFORE a stale single-file bundle can ship. The
// inline copy is deliberately condensed (var/function/arguments style vs the
// module's arrow/destructuring style) so it is NOT byte-identical — what is
// proved here is BEHAVIOURAL parity across a wide corpus, plus:
//   - the inline <script> actually parses in isolation;
//   - the inline factory exposes exactly the same public surface as the module;
//   - index.html is self-contained (no external script/style/asset reference).
//
// HONESTLY: this checks the shipped page against the .mjs source of truth and its
// self-containment. It does NOT test a browser, a DOM, or the network seam — the
// module and page are reference-prototype / UNAUDITED (see kyc-loa.mjs header).

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { makeKycLadder as makeKycLadderMjs } from "../gramota-kyc/kyc-loa.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const html = readFileSync(join(here, "index.html"), "utf8");

let passed = 0;
const t = (name, fn) => Promise.resolve().then(fn).then(() => { passed++; console.log("  ok — " + name); });

// The one executable inline <script> body (gramota ships exactly one).
function extractSingleScript() {
  const opens = [...html.matchAll(/<script(\s[^>]*)?>/g)];
  assert.equal(opens.length, 1, "gramota index.html must have exactly one inline <script>, found " + opens.length);
  const closes = [...html.matchAll(/<\/script>/g)];
  assert.equal(closes.length, 1, "expected exactly one </script>, found " + closes.length);
  const start = opens[0].index + opens[0][0].length;
  assert.ok(closes[0].index > start, "close tag must follow open tag");
  return html.slice(start, closes[0].index);
}

// Pull a `function NAME(` declaration out of source by brace-matching.
function extractFn(src, name) {
  const start = src.indexOf("function " + name + "(");
  assert.ok(start >= 0, "function " + name + "() must be present in the inline script");
  let i = src.indexOf("{", start), depth = 0, end = -1;
  for (; i < src.length; i++) {
    if (src[i] === "{") depth++;
    else if (src[i] === "}") { depth--; if (depth === 0) { end = i + 1; break; } }
  }
  assert.ok(end > 0, "could not brace-match " + name + "()");
  return src.slice(start, end);
}

// Instantiate the inline makeKycLadder() factory in isolation (no DOM, no page).
function loadInlineLadder() {
  const script = extractSingleScript();
  const body = extractFn(script, "makeKycLadder");
  // eslint-disable-next-line no-new-func
  return new Function('"use strict";' + body + "\nreturn makeKycLadder;")();
}

// Compare two verdicts ignoring the non-deterministic fields (ref, checkedAt).
function stripVolatile(v) {
  if (!v || typeof v !== "object") return v;
  const { ref, checkedAt, ...rest } = v;
  // ref must exist and follow the kyc-<hex> shape; checkedAt must be an ISO time.
  assert.ok(/^kyc-[0-9a-f]{16}$/.test(ref), "ref must be a kyc-<16hex> token, got: " + ref);
  assert.ok(!Number.isNaN(Date.parse(checkedAt)), "checkedAt must be an ISO timestamp");
  return rest;
}

await t("inline <script> parses in isolation", () => {
  // eslint-disable-next-line no-new-func
  new Function('"use strict";' + extractSingleScript());
});

await t("inline makeKycLadder factory exposes the same surface as kyc-loa.mjs", () => {
  const inline = loadInlineLadder()();
  const mjs = makeKycLadderMjs();
  assert.deepEqual(Object.keys(inline).sort(), Object.keys(mjs).sort(),
    "inline ladder public surface drifted from kyc-loa.mjs");
  assert.deepEqual(Object.keys(inline).sort(),
    ["corpEmailProof", "idv", "maxLoa", "ocrMatch", "selfDeclare"]);
});

await t("selfDeclare parity (inline vs kyc-loa.mjs)", () => {
  const I = loadInlineLadder()(), M = makeKycLadderMjs();
  assert.deepEqual(stripVolatile(I.selfDeclare({})), stripVolatile(M.selfDeclare({})));
});

await t("corpEmailProof parity across a valid/invalid/hostile corpus", () => {
  const I = loadInlineLadder()(), M = makeKycLadderMjs();
  const corpus = [
    { email: "dana@acme.com", domain: "acme.com" },  // valid
    { email: "dana@acme.com", domain: "other.com" }, // domain mismatch
    { email: "a@x@acme.com", domain: "acme.com" },   // double-@ hostile
    { email: "", domain: "acme.com" },               // empty email
    { email: "dana@acme.com", domain: "" },          // empty domain
    { email: "DANA@ACME.COM", domain: "acme.com" },  // case-insensitive
    { email: "  dana@acme.com  ", domain: "acme.com" }, // whitespace
  ];
  for (const c of corpus) {
    assert.deepEqual(stripVolatile(I.corpEmailProof(c)), stripVolatile(M.corpEmailProof(c)),
      "corpEmailProof drift on " + JSON.stringify(c));
  }
});

await t("ocrMatch parity across full/partial/empty/hostile field sets", () => {
  const I = loadInlineLadder()(), M = makeKycLadderMjs();
  const corpus = [
    { ocrFields: { legalName: "Acme", principal: "Dana" }, dnbRecord: { legalName: "Acme", principal: "Dana" } }, // full
    { ocrFields: { legalName: "Acme", principal: "Dana" }, dnbRecord: { legalName: "Acme", principal: "Bob" } },  // partial
    { ocrFields: { legalName: "" }, dnbRecord: { legalName: "" } }, // empty values don't count
    { ocrFields: {}, dnbRecord: {} },                               // no fields
    { ocrFields: { legalName: "ACME" }, dnbRecord: { legalName: "acme" } }, // case-insensitive match
    { ocrFields: { legalName: "Acme", extra: "x" }, dnbRecord: { legalName: "Acme" } }, // key only in ocr
    {}, // both missing
  ];
  for (const c of corpus) {
    assert.deepEqual(stripVolatile(I.ocrMatch(c)), stripVolatile(M.ocrMatch(c)),
      "ocrMatch drift on " + JSON.stringify(c));
  }
});

await t("idv parity — fail-closed unconfigured, pass only with a provider", () => {
  const I = loadInlineLadder()(), M = makeKycLadderMjs();
  for (const c of [{}, { provider: "" }, { provider: "acme-idv" }, undefined]) {
    assert.deepEqual(stripVolatile(I.idv(c)), stripVolatile(M.idv(c)),
      "idv drift on " + JSON.stringify(c));
  }
});

await t("maxLoa parity — fail-closed ceiling across mixed verdicts", () => {
  const I = loadInlineLadder()(), M = makeKycLadderMjs();
  const pass2 = { decision: "pass", loa: 2 };
  const fail3 = { decision: "fail", loa: 3 };
  const pass1 = { decision: "pass", loa: 1 };
  const cases = [
    [pass2, fail3, pass1],
    [fail3],
    [],
    [pass1, pass2],
    [null, undefined, pass2],
  ];
  for (const args of cases) {
    assert.equal(I.maxLoa(...args), M.maxLoa(...args),
      "maxLoa drift on " + JSON.stringify(args));
  }
});

// Self-containment — the shipped single-file bundle must reference nothing remote.
await t("index.html is self-contained (no external script/style/asset)", () => {
  assert.ok(!/<script[^>]*\bsrc\s*=/i.test(html), "no external <script src> allowed");
  for (const link of [...html.matchAll(/<link\b[^>]*>/gi)].map((m) => m[0])) {
    assert.ok(!/rel\s*=\s*["']?stylesheet/i.test(link), "no external stylesheet <link>: " + link);
  }
  for (const [, ref] of html.matchAll(/\b(?:src|href)\s*=\s*["']([^"']+)["']/gi)) {
    assert.ok(!/^https?:\/\//i.test(ref), "no remote resource reference: " + ref);
  }
});

console.log(`\ngramota inline-build parity: ${passed} checks passed`);
