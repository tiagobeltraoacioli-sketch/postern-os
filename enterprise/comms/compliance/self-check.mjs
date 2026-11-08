// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern Comms (Enterprise) — compliance layer self-check.
//
// Dependency-free. Run: `node self-check.mjs`. Verifies the honest invariants of
// the compliance tooling (NOT a compliance certification — see COMPLIANCE.md).
// Also parses/validates the shipped JSON (config, ROPA, schema) so a broken file
// is caught here rather than in the app.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import dm, { VISIBILITY, classesEmployerCanServe } from "./data-model.mjs";
import re from "./rights-engine.mjs";
import ret from "./retention.mjs";
import { AuditTrail } from "./audit-trail.mjs";
import { transparencyNotice } from "./transparency.mjs";
import { assessBreach } from "./breach.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
let pass = 0,
  fail = 0;
const fails = [];
function ok(name, cond) {
  if (cond) pass++;
  else {
    fail++;
    fails.push(name);
  }
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}`);
}

// 1. E2EE content is honestly un-producible by the employer.
{
  const { cannot } = classesEmployerCanServe("produce");
  ok("1 E2EE content is NOT employer-producible", cannot.some((d) => d.id === "message.content.e2ee"));
}

// 2. Access request refuses E2EE content with a self-serve path (no over-promising).
{
  const r = re.handleAccess({ requestId: "r1", subjectId: "emp-1", right: "access", requestedAt: "2026-07-12T00:00:00Z" });
  const e2ee = r.refused.find((x) => x.id === "message.content.e2ee");
  ok("2 access refuses E2EE honestly with self-serve", !!e2ee && !!e2ee.selfServe && r.requiresLegalReview === true);
}

// 3. Erasure of audit trail is refused (accountability, not covert deletion).
{
  const r = re.handleErasure({ requestId: "r2", subjectId: "emp-1", right: "erasure", requestedAt: "x" });
  ok("3 erasure refuses admin-audit deletion", r.refused.some((x) => x.id === "audit.admin-action"));
}

// 4. Every right maps to both an LGPD and a GDPR article.
{
  const allMapped = Object.values(re.RIGHTS).every((a) => a.lgpd && a.gdpr);
  ok("4 every right maps to LGPD + GDPR articles", allMapped);
}

// 5. Retention policy file validates.
{
  const pol = JSON.parse(readFileSync(join(HERE, "retention-policy.json"), "utf8"));
  const v = ret.validatePolicy(pol);
  ok("5 retention-policy.json validates", v.ok || (console.log("   ", v.errors), false));
}

// 6. Retention: E2EE operator-held ciphertext must declare 'ciphertext' or it fails validation.
{
  const bad = {
    schema: "postern.comms.retention/1",
    rules: [{ dataClass: "message.content.e2ee", channelClass: "*", retainDays: 30, retainedBy: "operator", disclosed: true, basis: "keeping messages" }],
  };
  const v = ret.validatePolicy(bad);
  ok("6 retention rejects operator 'reading' E2EE content", v.ok === false);
}

// 7. Covert retention (disclosed:false) is rejected.
{
  const bad = {
    schema: "postern.comms.retention/1",
    rules: [{ dataClass: "message.metadata", channelClass: "*", retainDays: 30, retainedBy: "operator", disclosed: false, basis: "routing" }],
  };
  ok("7 undisclosed retention rejected", ret.validatePolicy(bad).ok === false);
}

// 8. Retention evaluate deletes items past window.
{
  const pol = JSON.parse(readFileSync(join(HERE, "retention-policy.json"), "utf8"));
  const items = [
    { id: "m-old", dataClass: "message.metadata", createdAt: "2020-01-01T00:00:00Z" },
    { id: "m-new", dataClass: "message.metadata", createdAt: new Date().toISOString() },
  ];
  const plan = ret.evaluate(pol, items, new Date("2026-07-12T00:00:00Z"));
  ok("8 retention deletes stale metadata, keeps fresh", plan.delete.some((d) => d.id === "m-old") && plan.keep.some((k) => k.id === "m-new"));
}

// 9. Audit trail: allowed event appends & chain verifies.
{
  const t = new AuditTrail();
  t.append({ actor: "admin-1", event: "admin.policy-change", detail: { change: "retention 90d" } });
  t.append({ actor: "admin-1", event: "admin.dsar-served", subject: "emp-1" });
  ok("9 audit chain verifies", t.verify().ok && t.records.every((r) => r.employeeVisible === true));
}

// 10. Audit trail refuses covert/content events.
{
  const t = new AuditTrail();
  let threw = false;
  try {
    t.append({ actor: "admin-1", event: "admin.read-message.content", detail: {} });
  } catch {
    threw = true;
  }
  ok("10 audit refuses covert/content event", threw);
}

// 11. Audit tamper is detected.
{
  const t = new AuditTrail();
  t.append({ actor: "a", event: "admin.provision-user", subject: "emp-1" });
  t.append({ actor: "a", event: "admin.deprovision-user", subject: "emp-2" });
  t.records[0].detail = { tampered: true };
  ok("11 audit detects tampering", t.verify().ok === false);
}

// 12. Transparency notice never claims to read E2EE content.
{
  const n = transparencyNotice({ orgName: "Acme" });
  const cannot = n.cannotSee.some((d) => /encrypt/i.test(d.why));
  // No POSITIVE absolute claim anywhere the org "sells" privacy (keyFacts/canSee),
  // and the honest limits MUST explicitly disclaim "100% private".
  const salesSurface = JSON.stringify({ canSee: n.canSee, keyFacts: n.keyFacts });
  const noPositiveClaim = !/100% private|unhackable/i.test(salesSurface);
  const disclaimsAbsolute = n.honestLimits.some((s) => /not.*100% private|not.*unhackable/i.test(s));
  ok("12 transparency: E2EE disclosed, no absolute claims", cannot && noPositiveClaim && disclaimsAbsolute);
}

// 13. Breach clock: 72h target computed; ciphertext-only mitigation surfaced but not concluded.
{
  const b = assessBreach(
    { detectedAt: "2026-07-11T00:00:00Z", exposed: ["content-ciphertext-only", "metadata"], affectedSubjects: 10, description: "test", residency: "eu" },
    new Date("2026-07-12T00:00:00Z"),
  );
  ok("13 breach 72h clock + ciphertext mitigation + still needs review", b.clock.deadline72h === "2026-07-14T00:00:00.000Z" && b.ciphertextMitigationApplies === true && b.requiresLegalReview === true);
}

// 14. Breach with plaintext/keys flags subject notification.
{
  const b = assessBreach({ detectedAt: "2026-07-11T00:00:00Z", exposed: ["keys", "content-ciphertext-only"], affectedSubjects: 5, description: "keys leaked" });
  ok("14 breach with keys → subject notification likely required", b.subjectNotificationLikelyRequired === true && b.ciphertextMitigationApplies === false);
}

// 15. Shipped JSON all parses (ROPA, residency, export schema).
{
  let allOk = true;
  for (const f of ["ropa.template.json", "residency.config.json", join("schemas", "export.schema.json")]) {
    try {
      JSON.parse(readFileSync(join(HERE, f), "utf8"));
    } catch (e) {
      allOk = false;
      console.log("   parse error in", f, e.message);
    }
  }
  ok("15 all shipped JSON parses", allOk);
}

// 16. Portability + objection return an EXTENDED result without throwing. These
// extend the frozen ServedResult (export{} / mode); a naive Object.assign onto
// the frozen base throws — regression guard for that (both are reached via the
// runtime's serveDsar and the app's DSAR panel).
{
  let threw = false;
  let port = null,
    obj = null;
  try {
    port = re.handle({ requestId: "r16a", subjectId: "emp-1", right: "portability", requestedAt: "x" }, {});
    obj = re.handle({ requestId: "r16b", subjectId: "emp-1", right: "objection", requestedAt: "x" }, { flagger: () => {} });
  } catch {
    threw = true;
  }
  ok(
    "16 portability + objection extend the frozen result (no Object.assign-on-frozen throw)",
    !threw &&
      !!port && port.export && port.requiresLegalReview === true &&
      !!obj && obj.mode === "object" && Object.isFrozen(port) && Object.isFrozen(obj),
  );
}

// 17. Honest self-disclosure: the transparency notice's E2EE claim can NEVER be
// read as a shipped/certified guarantee. The honestLimits MUST flag that this is
// unaudited, pre-production, and compliance-BY-DESIGN (not certified) — so the
// employee sees the E2EE promise is a design property of reference software, not
// an audited shipping guarantee. (The E2EE bodies are not sealed by a shipped,
// audited transport; this disclosure is what keeps the claim honest.)
{
  const n = transparencyNotice({ orgName: "Acme" });
  const limits = n.honestLimits.join(" ").toLowerCase();
  const flagsUnaudited = /unaudited/.test(limits);
  const flagsPreProduction = /pre-production|reference/.test(limits);
  const flagsNotCertified = /not certified|by-design|by design/.test(limits);
  const claimsE2ee = n.keyFacts.some((f) => /end-to-end encrypted/i.test(f));
  ok(
    "17 E2EE claim is disclosed as unaudited/pre-production/not-certified (not a shipped guarantee)",
    claimsE2ee && flagsUnaudited && flagsPreProduction && flagsNotCertified,
  );
}

console.log(`\n${pass} passed, ${fail} failed`);
if (fail) {
  console.log("FAILURES:", fails.join(", "));
  process.exit(1);
}
