// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Bloch Shield (Enterprise) — DLP layer smoke test / demo.
// No test framework: `node enterprise/shield/dlp/self-check.mjs`. Non-zero on fail.

import {
  classify,
  mayShareWithThirdParty,
  emptySharingPolicy,
  CLASSES,
  PERSONAL,
} from "./classification.mjs";
import { EgressTrail } from "./audit-trail.mjs";
import { gateEgress } from "./egress-gate.mjs";
import { transparencyNotice, transparencyText } from "./transparency.mjs";

let failures = 0;
const ok = (cond, msg) => {
  console.log(`${cond ? "  ok  " : " FAIL "} ${msg}`);
  if (!cond) failures++;
};
const threws = (fn) => {
  try {
    fn();
    return false;
  } catch {
    return true;
  }
};

const NOW = new Date("2026-07-12T00:00:00Z");
const FUTURE = "2027-01-01T00:00:00Z";
const PAST = "2026-01-01T00:00:00Z";

// ---------------------------------------------------------------------------
// 1. CLASSIFICATION — corporate taxonomy + fail-closed under-classification.
console.log("\n# classification");
ok(CLASSES.length === 4, "four corporate classes: public/internal/confidential/restricted");
ok(classify({ scope: "corporate", classId: "internal" }).class === "internal", "explicit class honored");
ok(classify({ scope: "corporate", tags: ["contract"] }).class === "confidential", "tag 'contract' => confidential");
ok(
  classify({ scope: "corporate", tags: ["internal", "secret"] }).class === "restricted",
  "most-sensitive tag wins (secret => restricted)",
);
const unlabelled = classify({ scope: "corporate" });
ok(unlabelled.class === "restricted" && unlabelled.corporate === true, "unlabelled corporate data FAILS CLOSED to restricted");

// 2. THE RED LINE — personal data is recognised and left alone.
console.log("\n# the red line (personal scope)");
const pers = classify({ scope: "personal" });
ok(pers.class === PERSONAL.id && pers.corporate === false, "personal-scope data classified PERSONAL, corporate:false");
ok(classify({ scope: "whatsapp-personal" }).corporate === false, "any non-corporate origin is treated as personal/out-of-scope");
ok(threws(() => mayShareWithThirdParty("personal", "acme-vendor")), "asking to share PERSONAL data THROWS (category error / red line)");

// 3. mayShareWithThirdParty — fail-closed, no-widening verdicts.
console.log("\n# may-share verdicts (fail-closed)");
ok(mayShareWithThirdParty("public", { id: "x", trust: "unknown" }, { now: NOW }).verdict === "allow", "public => allow anywhere");
ok(
  mayShareWithThirdParty("internal", { id: "partner", trust: "known" }, { now: NOW }).verdict === "warn",
  "internal to a known dest => warn (default floor)",
);
ok(
  mayShareWithThirdParty("internal", { id: "rando", trust: "unknown" }, { now: NOW }).verdict === "block",
  "internal to an UNKNOWN dest => block",
);
ok(
  mayShareWithThirdParty("confidential", { id: "vendor", trust: "vetted-processor" }, { now: NOW }).verdict === "block",
  "confidential with NO grant => block (silence is no)",
);
ok(
  mayShareWithThirdParty("restricted", { id: "vendor", trust: "vetted-processor", dpa: true }, { now: NOW }).verdict === "block",
  "restricted => block ALWAYS (un-widenable; no grant can open it)",
);

// 4. Grants: required future expiry, revocation, DPA for confidential.
console.log("\n# sharing-policy grants");
const policy = emptySharingPolicy();
policy.org = "Acme Ltda.";
policy.grants.push({ class: "confidential", destination: "acme-payroll", verdict: "allow", expires: FUTURE, dpa: true });
policy.grants.push({ class: "confidential", destination: "no-dpa-vendor", verdict: "allow", expires: FUTURE, dpa: false });
policy.grants.push({ class: "confidential", destination: "expired-vendor", verdict: "allow", expires: PAST, dpa: true });
policy.grants.push({ class: "confidential", destination: "revoked-vendor", verdict: "allow", expires: FUTURE, dpa: true, revoked: true });

ok(
  mayShareWithThirdParty("confidential", { id: "acme-payroll", trust: "vetted-processor" }, { policy, now: NOW }).verdict === "allow",
  "confidential + unexpired grant + DPA => allow",
);
ok(
  mayShareWithThirdParty("confidential", { id: "no-dpa-vendor", trust: "vetted-processor" }, { policy, now: NOW }).verdict === "block",
  "confidential grant WITHOUT a DPA => block",
);
ok(
  mayShareWithThirdParty("confidential", { id: "expired-vendor", trust: "vetted-processor" }, { policy, now: NOW }).verdict === "block",
  "EXPIRED grant => treated as never given => block",
);
ok(
  mayShareWithThirdParty("confidential", { id: "revoked-vendor", trust: "vetted-processor" }, { policy, now: NOW }).verdict === "block",
  "REVOKED grant => treated as never given => block",
);

// 5. TRACEABILITY TRAIL — corporate egress only, master/sub scoped, hash-chained.
console.log("\n# traceability trail");
const trail = new EgressTrail();
const r1 = trail.append(
  { masterId: "acme", subAccessId: "sub-3", class: "confidential", destination: "acme-payroll", verdict: "allow", reason: "grant" },
  NOW,
);
trail.append(
  { masterId: "acme", subAccessId: "sub-7", class: "internal", destination: "partner", verdict: "warn", reason: "floor" },
  NOW,
);
ok(trail.records.length === 2 && r1.seq === 0, "two corporate-egress records appended");
ok(trail.verify().ok === true, "hash chain verifies intact");

// tamper detection
const tampered = new EgressTrail(JSON.parse(JSON.stringify(trail.records)));
tampered.records[0].destination = "somewhere-else";
ok(tampered.verify().ok === false && tampered.verify().brokenAt === 0, "tampering with a record is DETECTED by the chain");

// master/sub scoping + employee-visible disclosure
ok(trail.visibleTo("sub-3").length === 1 && trail.visibleTo("sub-3")[0].class === "confidential", "visibleTo scopes to one sub-access identity");
ok(trail.forMaster("acme").length === 2, "forMaster returns the org's egress");

// THE RED LINE at the trail: personal / surveillance-shaped records are REFUSED.
ok(threws(() => trail.append({ masterId: "acme", subAccessId: "sub-3", class: "personal", destination: "x", verdict: "allow" })), "trail REFUSES a personal-class record");
ok(threws(() => trail.append({ masterId: "acme", subAccessId: "sub-3", class: "internal", destination: "x", verdict: "allow", corporate: false })), "trail REFUSES a non-corporate record");
ok(threws(() => trail.append({ masterId: "acme", subAccessId: "sub-3", class: "internal", destination: "keystroke-logger", verdict: "allow" })), "trail REFUSES a surveillance-shaped record (keystroke)");
ok(threws(() => trail.append({ masterId: "acme", subAccessId: "sub-3", class: "internal", destination: "x", verdict: "allow", reason: "captured screen and location" })), "trail REFUSES a record whose reason resembles screen/location capture");

// 6. EGRESS GATE — end to end, and personal egress is NOT traced.
console.log("\n# egress gate (end-to-end)");
const gTrail = new EgressTrail();
const gCorp = gateEgress({
  data: { scope: "corporate", classId: "confidential" },
  destination: { id: "acme-payroll", trust: "vetted-processor" },
  identity: { masterId: "acme", subAccessId: "sub-3" },
  policy,
  trail: gTrail,
  now: NOW,
});
ok(gCorp.verdict === "allow" && gCorp.traced === true && gTrail.records.length === 1, "corporate egress gated => allow AND traced");

const gPers = gateEgress({
  data: { scope: "personal" },
  destination: { id: "friend-chat", trust: "unknown" },
  identity: { masterId: "acme", subAccessId: "sub-3" },
  policy,
  trail: gTrail,
  now: NOW,
});
ok(gPers.traced === false && gPers.corporate === false && gTrail.records.length === 1, "PERSONAL egress is NOT gated and NOT traced (trail length unchanged)");

const gBlock = gateEgress({
  data: { scope: "corporate", classId: "restricted" },
  destination: { id: "anywhere", trust: "vetted-processor", dpa: true },
  identity: { masterId: "acme", subAccessId: "sub-9" },
  policy,
  trail: gTrail,
  now: NOW,
});
ok(gBlock.verdict === "block" && gBlock.traced === true, "restricted egress => block, and the blocked attempt IS traced (accountability)");

// 7. TRANSPARENCY — the disclosure says corporate-only, personal never.
console.log("\n# transparency");
const notice = transparencyNotice({ orgName: "Acme Ltda." });
ok(notice.tracked.length === 1 && notice.tracked[0].events[0] === "corporate.third-party-egress", "notice tracks exactly the corporate-egress event");
ok(notice.notTracked.some((s) => /personal/i.test(s)), "notice explicitly states personal activity is NOT tracked");
const text = transparencyText({ orgName: "Acme Ltda." });
ok(/WHAT IS NEVER TRACED/.test(text) && /compliance-BY-DESIGN/i.test(text), "banner text carries the red line + the not-certified caveat");

// ---------------------------------------------------------------------------
console.log(`\n${failures === 0 ? "ALL OK" : `${failures} FAILURE(S)`}`);
process.exit(failures === 0 ? 0 : 1);
