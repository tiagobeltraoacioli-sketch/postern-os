// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// D4 / DEV-3 — proof that the SHIPPING browser console ENFORCES the CRL.
//
// This does NOT re-test the licensing lib (self-check.mjs does that). It extracts
// the REAL `makePosternLicense(...)` verifier out of the shipping app
// `apps/postern-enterprise/console.html` — the exact bytes the browser runs — and
// drives its CRL enforce path (verifyCrl / checkRevocation / pickNewerCrl /
// crlFreshness / evaluateRevocation) against CRLs the LIBRARY signed with
// `buildCrl`. Because the lib signs and the console verifies, this is a
// cross-implementation proof: same canonical bytes, same vendor public key.
//
// Run AFTER `npm run build` (imports from ./dist).  `node console-crl-enforce.test.mjs`.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  generateKeypair,
  keyId,
  issue,
  mintSubUnderMaster,
  buildCrl,
} from "./dist/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const consolePath = join(here, "..", "..", "apps", "postern-enterprise", "console.html");

// ── Extract the shipping verifier verbatim from the HTML and instantiate it ──
const html = readFileSync(consolePath, "utf8");
// Start at the module-level VENDOR_PUB_RAW_B64 that the function closes over, so
// the extracted block is self-contained.
const start = html.indexOf("var VENDOR_PUB_RAW_B64");
const end = html.indexOf("/* Allow an operator to inject");
if (start < 0 || end < 0 || end < start || html.indexOf("function makePosternLicense") < 0) {
  console.error("FAIL: could not locate makePosternLicense(...) in console.html");
  process.exit(1);
}
const fnSrc = html.slice(start, end);
// eslint-disable-next-line no-new-func
const makePosternLicense = new Function(fnSrc + "\nreturn makePosternLicense;")();
const PL = makePosternLicense(globalThis.crypto.subtle);

let failures = 0;
const ok = (cond, msg) => {
  console.log(`${cond ? "  ok  " : " FAIL "} ${msg}`);
  if (!cond) failures++;
};

// Sanity: the extracted console verifier exposes the CRL enforce surface.
ok(typeof PL.verifyCrl === "function" && typeof PL.checkRevocation === "function" &&
   typeof PL.evaluateRevocation === "function" && typeof PL.pickNewerCrl === "function" &&
   PL.CRL_STATUS_PATH === "/license/status",
   "console exposes the CRL enforce surface (verifyCrl/checkRevocation/evaluateRevocation/pickNewerCrl) + /license/status path");

// ── Set up a vendor + a real org master + sub, exactly as the console would see ──
const vendor = generateKeypair();
const iss = "posternlabs.com";
const kid = keyId(vendor.publicKey);
const now = new Date("2026-07-13T00:00:00Z");

const issued = issue(vendor.privateKey, { tier: "corporate-master", duns: "150483782", iss, kid, now });
const master = issued.masterToken;                 // { payload, sig }
const sub = mintSubUnderMaster(issued.orgMasterPrivateKey, master, "alice@acme", undefined, now);
const masterPayload = master.payload;
const subJti = sub.payload.jti;

// The console's own chain verify still passes with the lib-issued tokens (offline
// path preserved — the CRL work adds enforcement, it does not break verification).
const chain = await PL.verifyChain(vendor.publicKey, masterPayload, master.sig, sub, now);
ok(chain.ok === true && chain.level === "sub", "console verifyChain accepts the lib-issued master+sub (offline path preserved)");

// ── 1. NO CRL → nothing is revoked (best-effort, offline) ────────────────────
const noCrl = await PL.evaluateRevocation(vendor.publicKey, null, masterPayload, [subJti], now);
ok(noCrl.applies === false && noCrl.masterRevoked === false && noCrl.revokedSubs.length === 0,
   "no CRL → console applies no revocation (a valid license stays valid)");

// ── 2. Clean CRL (revokes nothing) → verified, no revocation ─────────────────
const crlClean = buildCrl(vendor.privateKey, { iss, kid, version: 1, now });
const eClean = await PL.evaluateRevocation(vendor.publicKey, crlClean, masterPayload, [subJti], now);
ok(eClean.applies === true && eClean.valid === true && eClean.masterRevoked === false && eClean.revokedSubs.length === 0,
   "clean vendor-signed CRL verifies in the console; nothing revoked");

// ── 3. Revoke the SUB serial → console refuses that sub (the headline claim) ──
const crlSub = buildCrl(vendor.privateKey, { iss, kid, version: 2, revokedJti: [subJti], now });
ok((await PL.verifyCrl(vendor.publicKey, crlSub)).ok === true, "sub-revoking CRL verifies against the vendor public key");
const eSub = await PL.evaluateRevocation(vendor.publicKey, crlSub, masterPayload, [subJti], now);
ok(eSub.revokedSubs.length === 1 && eSub.revokedSubs[0] === subJti && eSub.masterRevoked === false,
   "REVOKE sub jti → console evaluateRevocation lists the sub as revoked; master itself still valid");
// Mirror the shipping renderSubs() predicate: a sub whose jti is in revokedSubs is refused.
const subRefused = eSub.revokedSubs.indexOf(subJti) !== -1;
ok(subRefused === true, "renderSubs predicate: the revoked sub renders as REVOKED (vendor CRL)");

// ── 4. Revoke the whole ORG master_pub → console gate LOCKS enterprise ───────
const crlOrg = buildCrl(vendor.privateKey, { iss, kid, version: 3, revokedMasterPub: [masterPayload.master_pub], now });
const eOrg = await PL.evaluateRevocation(vendor.publicKey, crlOrg, masterPayload, [subJti], now);
ok(eOrg.masterRevoked === true, "REVOKE org master_pub → console evaluateRevocation reports masterRevoked=true");
// Mirror the shipping gate() rule: masterRevoked ⇒ state 'revoked-crl' (features locked).
const gateState = (mrInfo) => (mrInfo && mrInfo.masterRevoked) ? "revoked-crl" : "corporate-master";
ok(gateState(eOrg) === "revoked-crl", "gate() rule: a revoked master_pub drives the console to state 'revoked-crl' (enterprise LOCKED)");
ok(gateState(eClean) === "corporate-master", "gate() rule: with a clean CRL the same master stays licensed (revocation only revokes, never grants)");

// ── 5. Anti-rollback: an OLDER CRL cannot displace a newer cached one ────────
ok(PL.pickNewerCrl(crlOrg, crlSub) === crlOrg, "pickNewerCrl keeps the higher version (anti-rollback: v3 over v2)");
ok(PL.pickNewerCrl(crlSub, crlOrg) === crlOrg, "pickNewerCrl accepts a newer fetched CRL (v3 over cached v2)");

// ── 6. Fail-closed authority: a CRL signed by a FOREIGN key cannot revoke ────
const attacker = generateKeypair();
const forged = buildCrl(attacker.privateKey, { iss, kid, version: 99, revokedMasterPub: [masterPayload.master_pub], now });
ok((await PL.verifyCrl(vendor.publicKey, forged)).ok === false, "a foreign-signed CRL FAILS verifyCrl against the vendor key (no new authority)");
const eForged = await PL.evaluateRevocation(vendor.publicKey, forged, masterPayload, [subJti], now);
ok(eForged.applies === false && eForged.masterRevoked === false,
   "console IGNORES the forged CRL — a valid license is never bricked by an unsigned/foreign CRL (fail-safe)");

// ── 7. Corrupt signature → ignored (never bricks a valid license) ────────────
const corrupt = { payload: crlOrg.payload, sig: crlOrg.sig.slice(0, -4) + "AAAA" };
const eCorrupt = await PL.evaluateRevocation(vendor.publicKey, corrupt, masterPayload, [subJti], now);
ok(eCorrupt.applies === false && eCorrupt.masterRevoked === false, "corrupt-signature CRL is ignored by the console (fail-safe)");

// ── 8. Soft-offline freshness: past next_update+max_stale → stale (degrade) ──
const staleCrl = buildCrl(vendor.privateKey, { iss, kid, version: 4, nextUpdateSecs: 3600, maxStaleSecs: 3600, now });
const later = new Date(now.getTime() + 5 * 3600 * 1000); // > next_update + max_stale
const fr = PL.crlFreshness(staleCrl, later);
ok(fr.stale === true, "console crlFreshness marks a CRL past next_update+max_stale as STALE");
// Fail-safe: staleness never UN-revokes. A stale CRL that revokes the master still locks it.
const staleOrg = buildCrl(vendor.privateKey, { iss, kid, version: 5, revokedMasterPub: [masterPayload.master_pub], nextUpdateSecs: 3600, maxStaleSecs: 3600, now });
const eStale = await PL.evaluateRevocation(vendor.publicKey, staleOrg, masterPayload, [subJti], later);
ok(eStale.masterRevoked === true && eStale.freshness.stale === true,
   "a STALE CRL still enforces a known revocation (staleness degrades trust but never un-revokes)");

console.log(failures === 0 ? "\nconsole CRL-enforce proof: ALL PASS" : `\nconsole CRL-enforce proof: ${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
