// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// GRAMOTA BYOK privacy-wiring tests — run with: node byok-privacy.test.mjs  (Node >= 18)
//
// The redactor itself (core.redactPII / core.assertNoPII) is unit-tested in
// test-core.mjs. THIS file tests the app.js ORCHESTRATION SEAM — byokAssist() —
// which is the privacy-critical wiring that decides WHAT (if anything) crosses
// the network to a third-party model. It drives the REAL exported byokAssist()
// with an injected fake fetch that captures the outgoing request body, and pins
// two load-bearing guarantees:
//
//   1. REDACT-BEFORE-SEND: when the call proceeds, the ONLY thing put on the
//      wire is exactly core.redactPII(rawText, known) — no DUNS run and no
//      known legalName survives into the request body.
//   2. FAIL-CLOSED: if core.assertNoPII() THROWS, byokAssist sends NOTHING AT
//      ALL — fetch is never invoked — and surfaces a skip notice instead.
//
// byokAssist is imported from app.js directly (its DOM boot is guarded behind a
// `typeof document` check, so importing under Node is side-effect-free).

import assert from "node:assert/strict";
import core from "./core.js";
import { byokAssist, ANTHROPIC_ENDPOINT } from "./app.js";

let passed = 0;
const t = (name, fn) => Promise.resolve().then(fn).then(() => { passed++; console.log("  ok — " + name); });

// A fake fetch that records every call and returns a benign classification.
function recordingFetch(reply = { content: [{ text: "owner" }] }) {
  const calls = [];
  const fn = async (url, opts) => {
    calls.push({ url, opts });
    return { ok: true, status: 200, json: async () => reply };
  };
  fn.calls = calls;
  return fn;
}

// A fetch that MUST NOT be called — fails the test loudly if it ever is.
function forbiddenFetch() {
  const fn = async (url, opts) => {
    throw new Error("privacy violation: byokAssist called the network — url=" + url +
      " body=" + (opts && opts.body));
  };
  fn.calls = [];
  return fn;
}

// The DUNS + legalName that must NEVER reach the wire.
const DUNS = "150483782";
const LEGAL = "Beltrao Widgets GmbH";

// ==========================================================================
// 1. REDACT-BEFORE-SEND — only core.redactPII output crosses the network.
// ==========================================================================
await t("byokAssist sends ONLY core.redactPII(rawText) — no DUNS / legalName survives", async () => {
  const rawText = `I'm the owner of ${LEGAL}, our D-U-N-S is ${DUNS}, set me up unlimited`;
  const session = { state: "role", collected: { duns: DUNS, legalName: LEGAL } };
  const byok = { enabled: true, key: "sk-ant-fake-key" };
  const fetchImpl = recordingFetch();
  const input = { text: rawText };

  await byokAssist(rawText, input, { core, session, byok, fetchImpl });

  // Exactly one request, to the Anthropic endpoint, and nowhere else.
  assert.equal(fetchImpl.calls.length, 1, "expected exactly one outgoing request");
  assert.equal(fetchImpl.calls[0].url, ANTHROPIC_ENDPOINT, "must only ever reach the Anthropic endpoint");

  const sentBody = fetchImpl.calls[0].opts.body;
  assert.equal(typeof sentBody, "string", "the request body must be a serialized string");

  // The PII must not survive ANYWHERE in the raw serialized payload.
  assert.ok(!sentBody.includes(DUNS), "the DUNS number must NOT survive into the request body");
  assert.ok(!sentBody.includes(LEGAL), "the legal name must NOT survive into the request body");
  // Also reject a DUNS-shaped run in general (belt-and-suspenders).
  assert.ok(!/\d[\d\s.\-]{4,}\d/.test(sentBody), "no DUNS-shaped digit run may survive into the request body");

  // And prove the content sent is EXACTLY the redactor's output — not more, not less.
  const expectedSafe = core.redactPII(rawText, { duns: DUNS, legalName: LEGAL });
  const parsed = JSON.parse(sentBody);
  assert.equal(parsed.messages.length, 1);
  assert.equal(parsed.messages[0].role, "user");
  assert.equal(parsed.messages[0].content, expectedSafe,
    "the ONLY user content on the wire must be exactly core.redactPII(rawText)");
  // Sanity: the redacted content DID carry the intent through as placeholders.
  assert.ok(parsed.messages[0].content.includes("[NAME]") && parsed.messages[0].content.includes("[DUNS]"),
    "redacted placeholders should be present so the model still sees non-PII intent");
});

// ==========================================================================
// 2. FAIL-CLOSED — if core.assertNoPII throws, NOTHING is sent at all.
// ==========================================================================
await t("byokAssist sends NOTHING when core.assertNoPII throws (fail-closed)", async () => {
  const rawText = "some intent text " + DUNS;
  const session = { state: "role", collected: { duns: DUNS, legalName: LEGAL } };
  const byok = { enabled: true, key: "sk-ant-fake-key" };
  const fetchImpl = forbiddenFetch();
  const input = { text: rawText };

  // Stub core so redactPII "leaks" and assertNoPII rejects it — simulating a
  // redactor regression. The seam MUST bail before any network call.
  let assertSaw = null;
  const skips = [];
  const leakyCore = {
    redactPII: (txt) => txt, // pretend the redactor failed to strip anything
    assertNoPII: (safe) => { assertSaw = safe; throw new Error("redaction failed: a DUNS-shaped value would reach the model"); },
  };

  await byokAssist(rawText, input, {
    core: leakyCore,
    session,
    byok,
    fetchImpl,
    botSys: (m) => skips.push(m),
  });

  assert.equal(fetchImpl.calls.length, 0, "fetch must NOT be called once assertNoPII throws");
  assert.ok(assertSaw !== null, "assertNoPII must actually be invoked as the gate");
  assert.equal(skips.length, 1, "a single skip notice must be surfaced");
  assert.match(skips[0], /Skipped model call/, "the skip notice must state the call was skipped");
  // The input intent fields were never mutated by a (never-received) model reply.
  assert.ok(!("role" in input) && !("tier" in input), "no model-derived intent may be applied when the call is skipped");
});

// ==========================================================================
// 3. The gate is not skippable — even when byok.enabled is true and the model
//    would answer, the rawText itself is NEVER what crosses the wire. Prove the
//    body carries the redacted form, never the verbatim input, whenever the two
//    differ (i.e. the redactor actually did something).
// ==========================================================================
await t("the verbatim rawText never crosses the wire when redaction changed it", async () => {
  const rawText = `owner of ${LEGAL} — DUNS ${DUNS}`;
  const session = { state: "role", collected: { duns: DUNS, legalName: LEGAL } };
  const byok = { enabled: true, key: "sk-ant-fake-key" };
  const fetchImpl = recordingFetch();

  await byokAssist(rawText, { text: rawText }, { core, session, byok, fetchImpl });

  assert.equal(fetchImpl.calls.length, 1);
  const body = fetchImpl.calls[0].opts.body;
  const safe = core.redactPII(rawText, { duns: DUNS, legalName: LEGAL });
  assert.notEqual(safe, rawText, "precondition: redaction must actually change this input");
  assert.ok(!body.includes(rawText), "the verbatim rawText must never appear on the wire");
  assert.ok(body.includes(JSON.stringify(safe).slice(1, -1)), "only the redacted form is carried");
});

console.log(`\ngramota byok privacy wiring: ${passed} checks passed`);
