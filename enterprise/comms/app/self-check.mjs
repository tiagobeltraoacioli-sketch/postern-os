// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Bloch — org internal messenger (Business edition). Smoke test / demo.
// No test framework: `node enterprise/comms/app/self-check.mjs`. Non-zero on fail.

import { createSubAccessManager } from "../../features/sub-access.mjs";
import { resolveLicense, commsAllowed, refusalReason } from "./src/license-bridge.mjs";
import { createCommsOrg, CommsRefused } from "./src/comms-core.mjs";
import { buildTransparency, transparencyText, transparencyBanner } from "./src/transparency.mjs";
import { resolveComplianceDisclosure } from "./src/compliance-hook.mjs";
import {
  createSealedStore,
  openSealedStore,
  generateStoreKey,
  SealError,
} from "./persistence/sealed-store.mjs";
import {
  createDeviceVerifier,
  Trust,
  UnverifiedDeviceError,
} from "./verification/device-verification.mjs";
import { createComplianceRuntime, createMetadataStore } from "./src/compliance-runtime.mjs";

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

const NOW = new Date("2026-07-12");
const MASTER_EXP = "2027-01-11";

// 1. TIER FLOOR: a fresh install with no token is the free BUSINESS-FREEMIUM
// tier (the task's allowed "business tier"), never corporate/unlimited.
const fresh = resolveLicense({ injected: undefined, installDate: NOW, now: NOW });
ok(fresh.state === "business-freemium" && commsAllowed(fresh), "fresh install => business-freemium (free floor) => allowed");
ok(fresh.tier !== "corporate" && fresh.seatsUnlimited !== true, "the free floor is NEVER upgraded to corporate/unlimited");
// A FORGED partial gate is not accepted verbatim and never yields corporate.
const forged = resolveLicense({ injected: { gate: { enterpriseFeaturesAllowed: true } }, installDate: NOW, now: NOW });
ok(forged.source !== "injected-gate" && forged.tier !== "corporate", "a malformed injected gate is rejected — never becomes corporate");

// 2. Master token present but NO offline verifier => unverified, refuses.
const unverified = resolveLicense({ masterToken: "MASTER-acme", now: NOW });
ok(unverified.state === "unverified" && !commsAllowed(unverified), "token without offline verifier => unverified => refuses");
ok(/could not be verified/i.test(refusalReason(unverified)), "refusal reason is honest about the unverified token");

// 3. Master token verified OFFLINE => corporate-master => allowed.
const verify = (t) =>
  t === "MASTER-acme" ? { valid: true, orgName: "Acme Ltda.", duns: "00-123-4567", seats: "unlimited", expires: MASTER_EXP } : null;
const gate = resolveLicense({ masterToken: "MASTER-acme", verify, now: NOW });
ok(gate.state === "corporate-master" && commsAllowed(gate), "verified master token => corporate-master => Bloch may run");
ok(gate.orgName === "Acme Ltda." && gate.personalUnaffected === true, "org name carried; personal apps unaffected");

// 4. comms-core refuses to build without an allowed gate.
const roster0 = createSubAccessManager({ master: { token: "MASTER-acme", masterKey: "K", expires: MASTER_EXP }, now: NOW });
let refusedErr = null;
try {
  createCommsOrg({ gate: unverified, subAccess: roster0, now: NOW });
} catch (e) {
  refusedErr = e;
}
ok(refusedErr instanceof CommsRefused, "comms-core throws CommsRefused when the gate is not enterprise-allowed");

// 5. Org roster comes from the enterprise sub-access model.
const subAccess = createSubAccessManager({
  master: { token: "MASTER-acme", masterKey: "MASTERKEY", orgName: "Acme Ltda.", expires: MASTER_EXP },
  now: NOW,
});
const ana = subAccess.mintSubAccess({ label: "Ana — Engineering" });
const bruno = subAccess.mintSubAccess({ label: "Bruno — Sales" });
const org = createCommsOrg({ gate, subAccess, now: NOW });
ok(org.roster().length === 3, "roster = admin + 2 active subs (org-scoped membership from sub-access)");
ok(org.isMember("Ana — Engineering") && !org.isMember("Nobody"), "membership is exactly the active sub-access grants");

// 6. Channels + DMs, org-scoped; non-members are refused.
const chan = org.createChannel({ name: "eng", founder: "Ana — Engineering", members: ["Bruno — Sales"] });
ok(chan.members.length === 2 && chan.tier === "E2EE (Postern)", "channel created, InternalE2ee tier from the messenger crate");
ok(threws(() => org.createChannel({ name: "x", founder: "Ghost" })), "channel refuses a founder who is not on the roster");
ok(threws(() => org.addToChannel(chan.id, "Nobody")), "adding a non-roster person to a channel is refused");
const dm = org.openDm("Ana — Engineering", "Bruno — Sales");
ok(dm.type === "dm" && dm.members.length === 2, "DM opened between two roster members");
ok(org.openDm("Bruno — Sales", "Ana — Engineering").id === dm.id, "DM is order-independent / reused");

// 7. Posting: sender must be a conversation member; tier stamped; body NEVER
//    stored as cleartext (routed through the body transport as an envelope).
const m = await org.post(chan.id, "Ana — Engineering", "ship it");
ok(m.tier === "E2EE (Postern)" && m.sender === "Ana — Engineering", "message stamped with the E2EE tier badge");
ok(m.body === undefined && typeof m.size === "number", "post() returns envelope metadata only — NO plaintext body field");
const convView = org.conversation(chan.id);
const rawStored = JSON.stringify(convView);
ok(!rawStored.includes("ship it"), "the stored/rendered message carries NO cleartext body (transport envelope only)");
ok(org.bodyE2ee === false && /reference/i.test(org.bodyTransportLabel), "reference body transport is honestly e2ee:false (real Megolm not wired) — never over-claimed");
// The reference transport CAN round-trip the body (it holds the in-process key).
ok((await org.readBody(chan.id, m.id)) === "ship it", "readBody round-trips via the transport (reference transport can open; a real E2EE transport would refuse the operator)");
let nonMemberPost = false;
try { await org.post(chan.id, "Bruno — Sales but wrong", "hi"); } catch { nonMemberPost = true; }
ok(nonMemberPost, "a non-member cannot post");

// 8. Revoking a sub removes them from the org roster automatically.
subAccess.revoke(bruno.id);
ok(!org.isMember("Bruno — Sales"), "revoking a sub-access grant removes the person from the roster");

// 9. Transparency: honest by default (no compliance layer wired).
const t = buildTransparency({ gate });
ok(t.compliance.injected === false, "no compliance layer => disclosure marked NOT injected (fail-honest)");
ok(/UNKNOWN/i.test(t.compliance.retention), "retention posture is stated UNKNOWN, never faked as 'nothing retained'");
ok(t.refusals.some((r) => /employer-run/i.test(r)), "refuses to claim '100% private' — discloses it is an employer-run tool");
ok(t.employerVisibility.length >= 1 && t.e2ee.encrypted.some((s) => /Megolm/.test(s)), "states what IS E2EE and the employer-visibility wrinkle");
ok(/METADATA/.test(transparencyBanner({ gate })), "banner discloses metadata is visible to the org");

// 10. Transparency picks up an injected compliance disclosure.
const injectedCompliance = {
  disclosure: () => ({
    summary: "Acme retains channel metadata 90 days; message bodies are never retained server-side.",
    retention: "Metadata (membership, timestamps) retained 90 days for security; bodies not retained.",
    employerVisible: ["Conversation metadata", "Admin audit trail of provisioning actions"],
    e2ee: ["All message bodies (Megolm)"],
    notRetained: ["Message plaintext bodies"],
    contact: "dpo@acme.example",
  }),
};
const disc = resolveComplianceDisclosure({ injected: injectedCompliance });
ok(disc.injected === true && disc.source === "compliance-layer", "injected compliance disclosure is used when present");
ok(disc.notRetained.includes("Message plaintext bodies"), "compliance-owned policy text flows through untouched");

// 11. The compliance layer's OWN export shape (postern.comms.transparency/1) is
// consumed directly — no adapter needed by the deployment.
const realNotice = {
  schema: "postern.comms.transparency/1",
  heading: "About privacy on Acme's Postern Comms",
  canSee: [{ what: "Routing metadata (who/when/channel/size)", why: "legitimate interest" }],
  cannotSee: [{ what: "Message content", why: "end-to-end encrypted" }],
  keyFacts: ["Your message content is end-to-end encrypted; the employer holds only ciphertext."],
  retention: "Metadata minimised and time-limited; see published policy.",
  yourRights: { how: "Contact your DPO", articles: "LGPD Art. 18; GDPR Arts. 15–22." },
};
const viaNotice = resolveComplianceDisclosure({ injected: { transparencyNotice: () => realNotice } });
ok(viaNotice.injected === true && viaNotice.employerVisible.length === 1, "compliance layer's transparencyNotice() export is consumed directly");
ok(viaNotice.e2ee.includes("Message content") && /LGPD/.test(viaNotice.legalBasis), "notice canSee->employerVisible, cannotSee->e2ee, articles->legalBasis mapped honestly");
ok(resolveComplianceDisclosure({ injected: realNotice }).injected === true, "a raw notice object is accepted too");

console.log("\n--- transparency (no compliance layer wired) ---\n" + transparencyText({ gate }));

// 12 + 13 use the WebCrypto-backed reference seal / SAS digest -> async.
await (async () => {
  // 12. PERSISTENCE: message/session storage sealed at rest survives a "restart".
  const store = createSealedStore();
  store.putSession("dev-ana", { megolm: "opaque-session-blob", updatedAt: NOW.toISOString() });
  store.putConversation({ id: chan.id, type: "channel", members: chan.members, tier: chan.tier });
  store.appendMessage(chan.id, { sender: "Ana — Engineering", tier: chan.tier, at: NOW.toISOString(), envelope: "ct-ref-1" });

  const key = generateStoreKey();
  ok(key.length === 32, "persistence: local store key is 32 bytes (kept on-device, never uploaded)");
  const sealed = await store.seal(key);
  ok(sealed instanceof Uint8Array && sealed.length > 0, "persistence: store seals to an opaque at-rest blob");
  // The plaintext session material must NOT be visible in the sealed bytes.
  const asText = Buffer.from(sealed).toString("latin1");
  ok(!asText.includes("opaque-session-blob"), "persistence: sealed blob does not leak plaintext session material");

  // "Restart": reopen from the sealed bytes with the local key.
  const reopened = await openSealedStore(sealed, key);
  ok(reopened.getSession("dev-ana").megolm === "opaque-session-blob", "persistence: sessions SURVIVE restart when reopened with the local key");
  ok(reopened.messagesFor(chan.id).length === 1, "persistence: message envelopes survive restart");

  // Fail-closed: wrong key -> SealError, no store, no plaintext.
  let wrongKeyErr = null;
  try {
    await openSealedStore(sealed, generateStoreKey());
  } catch (e) {
    wrongKeyErr = e;
  }
  ok(wrongKeyErr instanceof SealError, "persistence: a wrong key FAILS CLOSED (SealError, no partial open)");

  // Tampered blob -> authentication fails.
  const tampered = Uint8Array.from(sealed);
  tampered[tampered.length - 1] ^= 0x01;
  let tamperErr = null;
  try {
    await openSealedStore(tampered, key);
  } catch (e) {
    tamperErr = e;
  }
  ok(tamperErr instanceof SealError, "persistence: a tampered blob FAILS CLOSED (authenticated seal)");

  // 13. DEVICE VERIFICATION: fail-closed identity-key verification.
  const dv = createDeviceVerifier();
  // Unknown / unobserved device is Unverified and NOT trusted (fail-closed).
  ok(dv.status("ghost").state === Trust.UNVERIFIED && !dv.isTrusted("ghost"), "verification: unknown device is UNVERIFIED / not trusted (fail-closed)");

  dv.observe("dev-ana", "ED 25519 AAAA-BBBB", "Ana — Engineering");
  ok(dv.status("dev-ana").state === Trust.UNVERIFIED, "verification: a freshly observed device starts UNVERIFIED (a flag, never silent trust)");
  // guardSend refuses toward an unverified device.
  let sendErr = null;
  try {
    dv.guardSend("dev-ana");
  } catch (e) {
    sendErr = e;
  }
  ok(sendErr instanceof UnverifiedDeviceError, "verification: guardSend REFUSES an unverified device (never silently trusted)");

  // Out-of-band exact match verifies; mismatch blocks.
  const verified = dv.verifyOutOfBand("dev-ana", "ed 25519 aaaa-bbbb");
  ok(verified.state === Trust.VERIFIED && dv.isTrusted("dev-ana"), "verification: out-of-band EXACT fingerprint match => VERIFIED");
  ok(dv.guardSend("dev-ana") === true, "verification: guardSend permits a verified device");

  dv.observe("dev-bruno", "ED-BBBB", "Bruno — Sales");
  const blocked = dv.verifyOutOfBand("dev-bruno", "ED-WRONG");
  ok(blocked.state === Trust.BLOCKED && !dv.isTrusted("dev-bruno"), "verification: a fingerprint MISMATCH => BLOCKED (possible MITM, fail-closed)");

  // SAS is order-independent: both sides derive the same short auth string.
  const sasA = await dv.beginSas("dev-ana", "ED-SELF", "attempt-1");
  const dv2 = createDeviceVerifier();
  dv2.observe("dev-ana", "ED-SELF", "Ana's peer");
  const sasB = await dv2.beginSas("dev-ana", "ED 25519 AAAA-BBBB", "attempt-1");
  ok(sasA.emoji.length === 7 && JSON.stringify(sasA.decimal) === JSON.stringify(sasB.decimal), "verification: reference SAS is order-independent (both sides match) and yields 7 emoji");

  // Identity-key CHANGE on a verified device re-flags it Unverified (TOFU break).
  dv.observe("dev-ana", "ED-CHANGED-CCCC");
  ok(dv.status("dev-ana").state === Trust.UNVERIFIED && dv.status("dev-ana").keyChanged, "verification: identity-key CHANGE on a verified device => re-flagged UNVERIFIED (TOFU break, never auto-trusted)");

  // A verified device snapshot can be persisted into the sealed store.
  dv2.confirmSas("dev-ana", true);
  const s2 = createSealedStore();
  s2.putDevice("dev-ana", dv2.status("dev-ana"));
  const sealed2 = await s2.seal(key);
  const back = await openSealedStore(sealed2, key);
  ok(back.getDevice("dev-ana").trusted === true, "persistence+verification: a verified-device snapshot survives restart sealed at rest");
})();

// 14. MOUNTED EXECUTION LAYER: seal + audit + retention/DSAR/breach wired into
//     the app, executing (not just injected as text).
await (async () => {
  const metaStore = createMetadataStore({
    directory: { "Ana — Engineering": { name: "Ana", email: "ana@acme.example", team: "eng" } },
  });
  const compliance = createComplianceRuntime({ store: metaStore });
  const atRest = createSealedStore();

  // A mounted org: bodies sealed via transport, envelopes persisted at rest,
  // metadata recorded into the compliance runtime.
  const subAccess2 = createSubAccessManager({
    master: { token: "MASTER-acme", masterKey: "MK", orgName: "Acme Ltda.", expires: MASTER_EXP }, now: NOW,
  });
  subAccess2.mintSubAccess({ label: "Ana — Engineering" });
  const morg = createCommsOrg({ gate, subAccess: subAccess2, store: atRest, compliance, now: NOW });
  const mchan = morg.createChannel({ name: "ops", founder: "Ana — Engineering" });
  const posted = await morg.post(mchan.id, "Ana — Engineering", "secret ops note");

  ok(atRest.messagesFor(mchan.id).length === 1, "mount: message ENVELOPE persisted into the at-rest sealed store");
  ok(compliance.store.count() === 1, "mount: message METADATA recorded into the compliance runtime (org-visible, no body)");
  ok(compliance.audit.verify().ok, "mount: admin-audit chain is intact");

  // Retention: a do-not-retain rule DELETES the metadata — but LEGAL HOLD wins.
  const policy = {
    schema: "postern.comms.retention/1",
    rules: [{ dataClass: "message.metadata", channelClass: "*", retainDays: 0, retainedBy: "operator", disclosed: true, basis: "minimisation default" }],
  };
  compliance.setLegalHold("Ana — Engineering", { actor: "carol (compliance)" });
  const heldRun = compliance.runRetention(policy, { actor: "carol (compliance)" }, new Date(NOW));
  ok(heldRun.deleted.length === 0 && heldRun.heldBack.includes(posted.id), "retention executor: LEGAL HOLD suspends deletion of the held subject's item");
  compliance.releaseLegalHold("Ana — Engineering", { actor: "carol (compliance)" });
  const freeRun = compliance.runRetention(policy, { actor: "carol (compliance)" }, new Date(NOW));
  ok(freeRun.deleted.includes(posted.id) && compliance.store.count() === 0, "retention executor: after release, the do-not-retain item is actually DELETED");

  // DSAR: identity verification enforced; deadline tracked; served with audit.
  let unverifiedRefused = false;
  try { compliance.receiveDsar({ subjectId: "Ana — Engineering", right: "access" }, { actor: "carol (compliance)" }); }
  catch { unverifiedRefused = true; }
  ok(unverifiedRefused, "DSAR: an UNVERIFIED identity is refused (fail-closed, never served)");
  const intake = compliance.receiveDsar(
    { subjectId: "Ana — Engineering", right: "access", verifiedIdentity: "passport-checked" }, { actor: "carol (compliance)" }, new Date(NOW));
  ok(intake.requestId && intake.dueBy && compliance.dsarStatus(intake.requestId).status === "open", "DSAR: intake tracked with a response deadline (clock started)");
  const served = compliance.serveDsar(intake.requestId, { actor: "carol (compliance)" }, new Date(NOW));
  ok(served.requiresLegalReview === true && served.refused.some((r) => /encrypted/i.test(r.reason)), "DSAR: served honestly — refuses the E2EE body it cannot read, flags legal review");
  ok(compliance.dsarStatus(intake.requestId).status === "served", "DSAR: request marked served after fulfilment");

  // Breach: assessed + persisted as a case; nobody auto-notified.
  const { caseId, assessment } = compliance.declareBreach(
    { detectedAt: NOW, exposed: ["content-ciphertext-only", "metadata"], affectedSubjects: 3, description: "misconfigured backup bucket", residency: "eu" },
    { actor: "carol (compliance)" }, new Date(NOW));
  ok(caseId && compliance.breachCase(caseId) && assessment.ciphertextMitigationApplies === true, "breach: assessed (ciphertext-mitigation factor) and PERSISTED as a case — draft only, nobody auto-notified");

  // Every admin act above is on the disclosed, employee-visible audit trail.
  const anaSees = compliance.auditVisibleTo("Ana — Engineering");
  ok(anaSees.some((r) => r.event === "admin.dsar-served") && anaSees.some((r) => r.event === "admin.legal-hold-set"), "audit: the subject can SEE the admin acts touching them (legal hold, DSAR) — disclosed, never covert");
  ok(compliance.audit.verify().ok, "audit: the whole hash-chain still verifies after all admin acts");
})();

if (failures) {
  console.error(`\n${failures} check(s) failed`);
  process.exit(1);
}
console.log("\nAll checks passed.");
