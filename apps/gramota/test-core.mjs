// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// GRAMOTA core tests — run with: node test-core.mjs   (Node >= 18)
//
// Pins the honesty invariants of the registration walker and validators, and
// asserts the browser core (core.js) stays in PARITY with the canonical server
// walker (functions/gramota/registrar.js) so the two can never silently drift.
//
// The load-bearing fail-closed guarantees under test:
//   - the bot cannot mint a token (it only emits an `action` intent);
//   - the bot cannot tick attestation (advance blocks without attestation===true);
//   - the bot cannot talk past a D&B not-found or a KYC fail;
//   - PII (DUNS/names) never survives redaction into a model payload.

import assert from "node:assert/strict";
import C from "./core.js";
import R from "../../functions/gramota/registrar.js";

let passed = 0;
const t = (name, fn) => Promise.resolve().then(fn).then(() => { passed++; console.log("  ok — " + name); });

// -------- parity: browser core mirrors the canonical server walker ---------
await t("STATES table is byte-identical between core.js and registrar.js", () => {
  assert.equal(JSON.stringify(C.STATES), JSON.stringify(R.STATES));
});
await t("walker parity across the full corporate happy path", () => {
  const scenario = [
    { in: { tier: "corporate-master" } },
    { in: { duns: "150483782" } },
    { in: { role: "owner" } },
    { in: { attestation: true } },
    { in: { kyc: "pass" } },
  ];
  let cs = C.newSession(), rs = R.newSession();
  for (const step of scenario) {
    const cr = C.stepRegistrar(cs, step.in);
    const rr = R.stepRegistrar(rs, step.in);
    assert.deepEqual(cr, rr, "step diverged: " + JSON.stringify(step.in));
    cs = { state: cr.state, collected: cr.collected };
    rs = { state: rr.state, collected: rr.collected };
  }
  assert.equal(cs.state, "issue_corporate");
});
await t("redaction parity core.js === registrar.js", () => {
  const text = "our DUNS is 15-04-83-782 and the company is Acme Widgets";
  const known = { legalName: "Acme Widgets" };
  assert.equal(C.redactPII(text, known), R.redactPII(text, known));
});

// -------- fail-closed: attestation is a real human boolean -----------------
await t("bot cannot advance past attestation without attestation===true", () => {
  let s = { state: "attestation", collected: { tier: "corporate-master", duns: "150483782", role: "owner" } };
  // empty / false / truthy-non-true are all refused
  for (const bad of [{}, { attestation: false }, { attestation: "yes" }, { attestation: 1 }, { text: "yes I agree" }]) {
    const r = C.stepRegistrar(s, bad);
    assert.equal(r.state, "attestation", "must stay put for " + JSON.stringify(bad));
    assert.ok(r.error, "must surface an error");
  }
  const ok = C.stepRegistrar(s, { attestation: true });
  assert.equal(ok.state, "kyc");
});

// -------- fail-closed: cannot pass a D&B not-found -------------------------
await t("bot cannot talk past a D&B not-found hint", () => {
  const s = { state: "duns", collected: { tier: "corporate-master" } };
  const r = C.stepRegistrar(s, { duns: "150483782", dnb: "not-found" });
  assert.equal(r.state, "refused");
  assert.equal(r.terminal, true);
});

// -------- fail-closed: cannot pass a KYC fail; pending holds ---------------
await t("KYC fail → refused; pending → pending_kyc; pass → issue_corporate", () => {
  const base = { state: "kyc", collected: { tier: "corporate-master", duns: "150483782", role: "owner", attestation: true } };
  assert.equal(C.stepRegistrar(base, { kyc: "fail" }).state, "refused");
  assert.equal(C.stepRegistrar(base, { kyc: "pending" }).state, "pending_kyc");
  assert.equal(C.stepRegistrar(base, { kyc: "pass" }).state, "issue_corporate");
  // seam-not-configured default is self-declared/pass (merged behavior parity)
  assert.equal(C.stepRegistrar(base, {}).state, "issue_corporate");
});

// -------- fail-closed: the bot never mints — only emits an intent ----------
await t("issue states emit an action INTENT, never a token or key", () => {
  const s = { state: "issue_corporate", collected: { tier: "corporate-master", duns: "150483782", role: "owner", attestation: true } };
  const r = C.stepRegistrar(s, {});
  assert.equal(r.action.type, "issue");
  assert.deepEqual(r.action.body, { tier: "corporate-master", duns: "150483782", role: "owner", attestation: true });
  assert.ok(!("token" in r) && !("master_private_key_pkcs8" in r), "no token/key ever appears in a walker result");
});
await t("applyIssuance only reaches issued_* on a real ok=true; ok=false → refused", () => {
  const s = { state: "issue_corporate", collected: { tier: "corporate-master" } };
  assert.equal(C.applyIssuance(s, true, "corporate-master").state, "issued_corporate");
  assert.equal(C.applyIssuance(s, false, "corporate-master").state, "refused");
});

// -------- attestation body is never fabricated -----------------------------
await t("issue_corporate action carries attestation===true ONLY if collected true", () => {
  const s = { state: "issue_corporate", collected: { tier: "corporate-master", duns: "150483782", role: "owner" } };
  const r = C.stepRegistrar(s, {});
  assert.equal(r.action.body.attestation, false, "not fabricated when never attested");
});

// -------- PII wall: redaction + hard assert --------------------------------
await t("redactPII strips DUNS runs and known names to placeholders", () => {
  const out = C.redactPII("D-U-N-S 150 483 782 for Beltrao GmbH", { legalName: "Beltrao GmbH" });
  assert.ok(!/\d[\d\s.\-]{4,}\d/.test(out), "no DUNS-shaped run survives");
  assert.ok(!out.includes("Beltrao GmbH"), "no known name survives");
  assert.ok(out.includes("[DUNS]") && out.includes("[NAME]"));
});
await t("assertNoPII throws if a DUNS-shaped value or known name would reach a model", () => {
  assert.throws(() => C.assertNoPII("call 150483782", {}));
  assert.throws(() => C.assertNoPII("hi Acme Widgets", { legalName: "Acme Widgets" }));
  assert.doesNotThrow(() => C.assertNoPII("intent: owner, unlimited seats", {}));
});

// -------- deterministic parsers --------------------------------------------
await t("normalizeDuns pulls 9 digits from noisy input, rejects wrong lengths", () => {
  assert.equal(C.normalizeDuns("our D-U-N-S is 15 04 83 782"), "150483782");
  assert.equal(C.normalizeDuns("1234"), null);
  assert.equal(C.normalizeDuns("1234567890"), null);
});
await t("parseRole / parseTier keyword maps are deterministic", () => {
  assert.equal(C.parseRole("I own the company"), "owner");
  assert.equal(C.parseRole("I'm an authorized manager"), "manager");
  assert.equal(C.parseRole("dunno"), null);
  assert.equal(C.parseTier("we need unlimited users"), "corporate-master");
  assert.equal(C.parseTier("just 3 desktops"), "business-freemium");
});

// -------- validators mirror master.js server guards ------------------------
await t("validateCorporate mirrors master.js guards (DUNS, role, attestation)", () => {
  assert.equal(C.validateCorporate({ duns: "abc", role: "owner", attestation: true }).ok, false);
  assert.equal(C.validateCorporate({ duns: "150483782", role: "nope", attestation: true }).ok, false);
  assert.equal(C.validateCorporate({ duns: "150483782", role: "owner", attestation: false }).ok, false);
  const ok = C.validateCorporate({ duns: "15-0483-782", role: "manager", attestation: true });
  assert.deepEqual(ok, { ok: true, body: { tier: "corporate-master", duns: "150483782", role: "manager", attestation: true } });
});

// -------- absorb planner ----------------------------------------------------
await t("planAbsorb re-mints ≤3 labels at zero seat cost and states the honest notes", () => {
  const plan = C.planAbsorb([{ label: "A" }, { label: "B" }, { label: "C" }, { label: "D" }], "revoke");
  assert.equal(plan.mint.length, 3, "freemium could only have held 3");
  assert.equal(plan.seatCost, 0);
  assert.equal(plan.retire, "revoke");
  assert.ok(plan.notes.some((n) => /RE-MINTED, not migrated/.test(n)));
  assert.equal(C.planAbsorb([{ label: "A" }], "let-expire").retire, "let-expire");
});

console.log(`\ngramota core: ${passed} checks passed`);
