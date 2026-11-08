// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Tiny smoke test / demo for the enterprise feature layer. No test framework —
// just `node enterprise/features/self-check.mjs`. Exits non-zero on failure.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { emptyPolicy, evaluatePolicy, assertAdditive, ADDITIVE_STATEMENT } from "./org-policy.mjs";
import { createLicenseGate, FREEMIUM_SEATS, FREEMIUM_DAYS, CORPORATE_EVAL_DAYS } from "./license-hook.mjs";
import { createSubAccessManager } from "./sub-access.mjs";
import { privacyText } from "./privacy.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const catalog = JSON.parse(readFileSync(join(here, "app-catalog.json"), "utf8"));

let failures = 0;
const ok = (cond, msg) => {
  console.log(`${cond ? "  ok  " : " FAIL "} ${msg}`);
  if (!cond) failures++;
};

// 1. Every personal app is always available, regardless of policy.
const policy = emptyPolicy();
policy.org = "Acme Ltda.";
const evald = evaluatePolicy(catalog, policy, { team: "engineering" });
const personal = evald.apps.filter((a) => a.tier === "personal-free");
ok(personal.length >= 7, `catalog carries the personal suite (${personal.length} apps)`);
ok(personal.every((a) => a.available === true), "every personal app is available under a blank policy");

// 2. Enabling an additive feature does not remove the base app.
policy.teams.engineering = { "izbushka:fleet-grant-policy": true };
const evald2 = evaluatePolicy(catalog, policy, { team: "engineering" });
const izb = evald2.apps.find((a) => a.id === "izbushka");
ok(izb.available === true, "izbushka still available after enabling a fleet feature");
ok(izb.enterpriseFeatures.find((f) => f.id === "fleet-grant-policy").enabled === true, "additive feature toggled on for the team");

// 3. The additive boundary refuses an app-disable smuggle.
let threw = false;
try {
  assertAdditive(catalog, { teams: { engineering: { "izbushka:app-disabled": true } } });
} catch {
  threw = true;
}
ok(threw, "policy that tries to disable a personal app is rejected");

// 4. License gate: fresh install, no token => business-freemium (3 desktops, 2yr).
const fresh = createLicenseGate({ installDate: Date.now() });
ok(fresh.state === "business-freemium" && fresh.seats === FREEMIUM_SEATS, `fresh install => freemium, ${FREEMIUM_SEATS} desktops`);
ok(fresh.daysRemaining === FREEMIUM_DAYS && fresh.enterpriseFeaturesAllowed === true, "freemium allowed with full 2-year window");

// 5. Freemium elapsed => expired (no server, no login involved).
const old = createLicenseGate({ installDate: new Date(Date.now() - (FREEMIUM_DAYS + 5) * 86400000) });
ok(old.state === "expired" && old.masterTokenPresent === false, "2-year freemium elapsed => expired");

// 6. Master token present but no offline verifier wired => unverified (never corporate).
const noVerify = createLicenseGate({ masterToken: "MASTER-abc" });
ok(noVerify.state === "unverified" && noVerify.enterpriseFeaturesAllowed === false, "master token, no verifier => unverified (fails closed)");

// 7. Master token verified OFFLINE => corporate-master, unlimited seats, 6-month eval.
const corp = createLicenseGate({
  masterToken: "MASTER-acme",
  verify: (t) => (t === "MASTER-acme" ? { valid: true, orgName: "Acme Ltda.", duns: "00-123-4567", seats: "unlimited" } : null),
});
ok(corp.state === "corporate-master" && corp.seatsUnlimited === true, "verified master token => corporate, unlimited seats");
ok(corp.daysRemaining === CORPORATE_EVAL_DAYS && corp.orgName === "Acme Ltda.", "corporate eval window ~6 months, org name carried");
ok(corp.personalUnaffected === true, "personal apps unaffected by any tier");

// 8. Sub-access delegation: master mints subs; sub.exp <= master.exp; revoke works.
const masterExp = "2027-01-11";
const mgr = createSubAccessManager({
  master: { token: "MASTER-acme", masterKey: "MASTERKEY-secret", orgName: "Acme Ltda.", expires: masterExp },
  now: new Date("2026-07-12"),
});
const s1 = mgr.mintSubAccess({ label: "Ana — Engineering" });
ok(s1.expires === masterExp && s1.signed === false, "sub defaults to master expiry; unsigned demo token when no signer wired");
let subThrew = false;
try {
  mgr.mintSubAccess({ label: "too long", expires: "2030-01-01" });
} catch {
  subThrew = true;
}
ok(subThrew, "sub minted beyond master expiry is rejected (sub.exp <= master.exp)");
const s2 = mgr.mintSubAccess({ label: "Bruno — Sales", expires: "2026-12-01" });
ok(mgr.list().length === 2, "unlimited subs listed under one master");
const revoked = mgr.revoke(s2.id);
ok(revoked.status === "revoked", "revoke-by-expiry marks the sub revoked");
ok(mgr.verify("anything").valid === false, "verify without an offline verifier reports unverified (honest)");

// 9. With an injected offline chain verifier, a good chain verifies.
const mgr2 = createSubAccessManager({
  master: { token: "MASTER-acme", masterKey: "K", expires: masterExp },
  mintSub: (key, claims) => "SIGNED." + claims.label,
  verifyChain: (tok) => ({ valid: tok.startsWith("SIGNED."), label: "x", expires: "2026-10-01", chain: ["vendor", "master", "sub"] }),
});
const s3 = mgr2.mintSubAccess({ label: "Carla" });
ok(s3.signed === true, "injected signer produces a signed sub token");
ok(mgr2.verify(s3.token).valid === true, "injected verifier confirms vendor->master->sub chain offline");

console.log("\n--- additive boundary ---\n" + ADDITIVE_STATEMENT);
console.log("\n--- privacy ---\n" + privacyText());

if (failures) {
  console.error(`\n${failures} check(s) failed`);
  process.exit(1);
}
console.log("\nAll checks passed.");
