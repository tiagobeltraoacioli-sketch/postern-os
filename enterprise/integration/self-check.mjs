// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern Enterprise — integration layer END-TO-END SELF-CHECK.
//
// No test framework. Run: `node enterprise/integration/self-check.mjs`.
// Exercises the REAL modules through the integration adapters and PROVES the
// headline flow:
//
//   install master -> mint sub -> sub unlocks comms + shield -> revoke -> both refuse
//
// plus the fail-closed rails (forged master => nothing runs; tampered sub =>
// verify rejects) and the disclosure()<->transparencyNotice() adapter. Exits
// non-zero on any failure.

import {
  wireEnterprise,
  noticeToDisclosure,
  makeMasterTokenVerifier,
} from "./src/index.mjs";
import {
  generateKeypair,
  CommsRefused,
  AccessRefused,
  GrantRevoked,
  shieldDlpNotice,
  commsComplianceNotice,
  commsAllowed,
} from "./src/siblings.mjs";
import { createEnterpriseConsole } from "./src/identity.mjs";

let pass = 0;
let fail = 0;
const fails = [];
function ok(name, cond) {
  if (cond) pass++;
  else {
    fail++;
    fails.push(name);
  }
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}`);
}
function threw(fn, Type) {
  try {
    fn();
    return false;
  } catch (e) {
    return Type ? e instanceof Type : true;
  }
}
// Async variant: comms post() is async (sealing is async, as real crypto is),
// so a rejection is a REJECTED PROMISE, never a synchronous throw. Awaiting it
// is the only correct way to assert the revoked-post refusal.
async function threwAsync(fn, Type) {
  try {
    await fn();
    return false;
  } catch (e) {
    return Type ? e instanceof Type : true;
  }
}

// A frozen clock inside the corporate free window, used consistently so the
// grant/gate/roster all agree.
const NOW = new Date("2026-07-12T00:00:00Z");

console.log("=== Postern Enterprise integration — end-to-end self-check ===\n");

// ── (1) INSTALL MASTER ────────────────────────────────────────────────────────
const org = wireEnterprise({ orgName: "Acme Ltda.", duns: "123456789", now: NOW });
ok("1.1 master issued & gate resolved from offline verifyChain", !!org.gate);
ok("1.2 gate is corporate-master, enterprise features ALLOWED", org.gate.enterpriseFeaturesAllowed === true && org.gate.tier === "corporate");
ok("1.3 comms license bridge agrees the gate is allowed", commsAllowed(org.gate) === true);
ok("1.4 org name + unlimited seats carried onto the gate", org.gate.orgName === "Acme Ltda." && org.gate.seatsUnlimited === true);

// ── (2) MINT SUB (one identity, fanned to comms + shield) ──────────────────────
const alice = org.mintIdentity({ label: "alice@acme", employeeId: "alice@acme" });
ok("2.1 sub minted & SIGNED (real ORG-master signature via licensing lib)", alice.subToken && alice.grant && org.console.subAccess.list()[0].signed === true);
ok("2.2 sub-access manager verifies the vendor->master->sub chain OFFLINE", org.console.subAccess.verify(alice.subToken).valid === true);

// ── (3) SUB UNLOCKS COMMS ──────────────────────────────────────────────────────
const bloch = org.openComms("Acme Ltda. — admin");
ok("3.1 Bloch messenger built (enterprise gate permitted it)", !!bloch && bloch.orgName === "Acme Ltda.");
ok("3.2 alice is on the roster via her active sub-access grant", bloch.isMember("alice@acme") === true);
const chan = bloch.createChannel({ name: "eng", founder: "alice@acme" });
// post() is ASYNC and returns METADATA ONLY — the E2EE rail means the plaintext
// body is never retained, so the returned view exposes {sender, at, size, ...}
// but NO `body`. Asserting `body === "hello team"` would defeat that rail.
const posted = await bloch.post(chan.id, "alice@acme", "hello team");
ok(
  "3.3 alice can create a channel and post while her sub is live (metadata-only envelope; no plaintext body retained)",
  posted.sender === "alice@acme" && posted.body === undefined && typeof posted.size === "number",
);

// ── (4) SUB UNLOCKS SHIELD ─────────────────────────────────────────────────────
const shield = org.shieldFor(alice.id);
ok("4.1 shield container + broker built for the same identity", !!shield.broker && shield.container.orgId === "123456789");
const opened = shield.broker.openSession(NOW);
ok("4.2 broker opened a session (license + live grant + verifyChain sub-token + container)", opened.gates.container === "unlocked" && opened.gates.subToken === "ok");
shield.container.put("corp/secret.txt", "acme quarterly numbers", NOW);
const readBack = new TextDecoder().decode(shield.container.get("corp/secret.txt"));
ok("4.3 corporate data round-trips inside the unlocked container", readBack === "acme quarterly numbers");

// ── (5) REVOKE -> BOTH REFUSE ──────────────────────────────────────────────────
org.revokeIdentity(alice.id, "left the company");

// comms refuses
ok("5.1 comms: revoked identity drops off the roster", bloch.isMember("alice@acme") === false);
ok("5.2 comms: posting as the revoked identity is REFUSED", await threwAsync(() => bloch.post(chan.id, "alice@acme", "still here?")));

// shield refuses + self-wipes
ok("5.3 shield: the grant is no longer live (releaseKeyMaterial throws)", threw(() => alice.grant.releaseKeyMaterial(NOW), GrantRevoked));
const refuse = threw(() => shield.broker.openSession(NOW), AccessRefused);
ok("5.4 shield: broker REFUSES a new session (fail-closed)", refuse);
ok("5.5 shield: container self-wiped its corporate data on de-provisioning", shield.container.isWiped() === true);

// ── (6) FAIL-CLOSED RAILS ──────────────────────────────────────────────────────
// A master presented against the WRONG vendor key never verifies => unverified,
// and the enterprise-only comms app refuses to run at all.
const wrongVendor = generateKeypair().publicKey;
const badConsole = createEnterpriseConsole({ ...org.prov, vendorPublicKey: wrongVendor }, { now: NOW });
ok("6.1 forged/wrong-key master => gate NOT allowed (never faked 'licensed')", badConsole.gate.enterpriseFeaturesAllowed === false);
ok("6.2 comms REFUSES to run under an unverified gate (CommsRefused)", threw(() => badConsole.openComms("admin"), CommsRefused));

// A tampered sub token fails the offline chain verdict.
const tampered = (() => {
  const t = JSON.parse(alice.subToken);
  t.payload.sub = "mallory@acme"; // subject changed, signature no longer matches
  return JSON.stringify(t);
})();
ok("6.3 tampered sub token => verifyChain rejects it", org.console.subAccess.verify(tampered).valid === false);

// The verifier itself returns null (fail-closed) for a garbage token.
const v = makeMasterTokenVerifier({ vendorPublicKey: org.prov.vendorPublicKey });
ok("6.4 master verifier fails closed on unparseable input", v("not-json") === null);

// ── (7) DISCLOSURE ADAPTER (disclosure()<->transparencyNotice()) ───────────────
const shieldDisc = noticeToDisclosure(shieldDlpNotice({ orgName: "Acme Ltda." }));
ok("7.1 shield DLP notice maps to a non-empty disclosure() shape", shieldDisc.employerVisible.length > 0 && shieldDisc.logged.length > 0 && shieldDisc.notCollected.length > 0);
const commsDisc = noticeToDisclosure(commsComplianceNotice({ orgName: "Acme Ltda." }));
ok("7.2 comms compliance notice maps (e2ee = what employer CANNOT read)", commsDisc.employerVisible.length > 0 && commsDisc.e2ee.length > 0);

const sT = org.shieldTransparency();
ok("7.3 shield transparency panel shows the INJECTED DLP disclosure", sT.dlp.injected === true && sT.dlp.source === "shield-dlp-layer");
const cT = org.commsTransparency();
ok("7.4 comms transparency panel shows the INJECTED compliance disclosure", cT.compliance.injected === true);
ok("7.5 honest employer-visibility wrinkle preserved (never '100% private')", org.commsBanner().includes("METADATA") && org.shieldBanner().toLowerCase().includes("rooted"));

// ── summary ────────────────────────────────────────────────────────────────────
console.log("\n--- shield employee banner ---\n" + org.shieldBanner());
console.log("\n--- comms employee banner ---\n" + org.commsBanner());

console.log(`\n${pass} passed, ${fail} failed`);
if (fail) {
  console.error("FAILURES: " + fails.join("; "));
  process.exit(1);
}
console.log("\nAll integration checks passed. install master -> sub -> comms + shield -> revoke -> both refuse.");
