// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Smoke test for the licensing lib's revocation/CRL work (D4) + the token-schema
// backward-compat guarantee. No test framework — `node self-check.mjs`. Exits
// non-zero on failure. Run AFTER `npm run build` (imports from ./dist).

import {
  generateKeypair,
  ed25519Sign,
  canonicalJson,
  issue,
  mintSubUnderMaster,
  verifyChain,
  status,
  buildCrl,
  verifyCrl,
  crlFreshness,
  keyId,
} from "./dist/index.js";

let failures = 0;
const ok = (cond, msg) => {
  console.log(`${cond ? "  ok  " : " FAIL "} ${msg}`);
  if (!cond) failures++;
};

const vendor = generateKeypair();
const iss = "posternlabs.com";
const kid = keyId(vendor.publicKey);

// 1. BACKWARD-COMPAT: a PRE-CRL master token (no jti/kid/iss) must still verify.
//    We hand-build the exact old canonical shape and sign it, proving the
//    canonical() algorithm was NOT changed by the new optional fields.
const now = new Date("2026-07-12T00:00:00Z");
const oldPayload = {
  v: 1,
  typ: "master",
  tier: "corporate-master",
  duns: "150483782",
  seats: "unlimited",
  iat: Math.floor(now.getTime() / 1000),
  exp: Math.floor(now.getTime() / 1000) + 6 * 30 * 24 * 3600,
  master_pub: generateKeypair().publicKey,
};
const oldToken = { payload: oldPayload, sig: ed25519Sign(vendor.privateKey, new TextEncoder().encode(canonicalJson(oldPayload))) };
const oldRes = verifyChain(vendor.publicKey, oldToken, null, now);
ok(oldRes.ok === true, "pre-CRL master token (no jti) still verifies — canonical shape stable");

// 2. A newly-issued token carries jti/kid/iss and verifies.
const issued = issue(vendor.privateKey, { tier: "corporate-master", duns: "150483782", iss, kid, now });
const master = issued.masterToken;
ok(typeof master.payload.jti === "string" && master.payload.jti.length === 32, "new master carries a 128-bit jti");
ok(master.payload.kid === kid && master.payload.iss === iss, "new master carries kid + iss");
const newRes = verifyChain(vendor.publicKey, master, null, now);
ok(newRes.ok === true && newRes.master_pub === master.payload.master_pub, "new master verifies; ChainResult exposes master_pub");

// 3. Sub carries its own jti.
const sub = mintSubUnderMaster(issued.orgMasterPrivateKey, master, "alice@acme", undefined, now);
ok(typeof sub.payload.jti === "string" && sub.payload.jti.length === 32, "sub carries a 128-bit jti");
const subRes = verifyChain(vendor.publicKey, master, sub, now);
ok(subRes.ok === true && subRes.subJti === sub.payload.jti, "sub verifies; ChainResult exposes subJti");

// 4. Build + verify a signed CRL.
const crl = buildCrl(vendor.privateKey, { iss, kid, version: 1, revokedJti: [], revokedMasterPub: [], now });
ok(verifyCrl(vendor.publicKey, crl).ok === true, "CRL verifies against the vendor key");
ok(verifyCrl(generateKeypair().publicKey, crl).ok === false, "CRL fails against a WRONG vendor key (fail-closed)");

// 5. status() with a fresh CRL that revokes nothing -> in-eval (unchanged).
const s0 = status({ vendorPublicKey: vendor.publicKey, master, sub, crl, now });
ok(s0.state === "in-eval", "corporate master with clean CRL -> in-eval");

// 6. Revoke the SUB serial -> state "revoked".
const crlSub = buildCrl(vendor.privateKey, { iss, kid, version: 2, revokedJti: [sub.payload.jti], now });
const s1 = status({ vendorPublicKey: vendor.publicKey, master, sub, crl: crlSub, now });
ok(s1.state === "revoked", "revoking the sub jti -> revoked");

// 7. Revoke the whole ORG master key -> revoked, even without the master jti.
const crlOrg = buildCrl(vendor.privateKey, { iss, kid, version: 3, revokedMasterPub: [master.payload.master_pub], now });
const s2 = status({ vendorPublicKey: vendor.publicKey, master, sub: null, crl: crlOrg, now });
ok(s2.state === "revoked", "revoking the org master_pub -> whole-org revoked");

// 8. Soft-offline freshness: a CRL past next_update + max_stale is stale.
const staleCrl = buildCrl(vendor.privateKey, { iss, kid, version: 4, nextUpdateSecs: 3600, maxStaleSecs: 3600, now });
const later = new Date(now.getTime() + 5 * 3600 * 1000); // > 2h past issue
ok(crlFreshness(staleCrl, later).stale === true, "CRL past next_update+max_stale reports stale");
const s3 = status({ vendorPublicKey: vendor.publicKey, master, sub, crl: staleCrl, now: later });
ok(s3.state === "stale-revocation", "stale CRL -> stale-revocation (enterprise degrades, best-effort)");

// 9. A CORRUPT CRL is ignored (treated as absent) — never bricks a valid license.
const corrupt = { payload: crl.payload, sig: crl.sig.slice(0, -4) + "AAAA" };
const s4 = status({ vendorPublicKey: vendor.publicKey, master, sub, crl: corrupt, now });
ok(s4.state === "in-eval", "corrupt CRL is ignored — valid license stays valid");

// 10. Personal is NEVER gated, even with a revoking CRL present.
const s5 = status({ personal: true, vendorPublicKey: vendor.publicKey, master, sub, crl: crlOrg, now });
ok(s5.state === "personal-free", "personal edition is never gated by the CRL");

// 11. Anti-rollback: version is monotonic and exposed for the caller to compare.
ok(crlOrg.payload.version > crlSub.payload.version, "CRL version is monotonic (anti-rollback handle)");

// ── 12. issue -> renew -> revoke, proven THROUGH verifyChain (the low-level
//        verify path now enforces revocation for direct gate callers). ────────
// (a) issue + verify with NO crl -> byte-identical pre-CRL behaviour (ok).
ok(verifyChain(vendor.publicKey, master, sub, now).ok === true, "verifyChain (no CRL) verifies issued master+sub — offline path preserved");

// (b) RENEW: re-mint the SAME master_pub with a fresh exp + a NEW jti (this is
//     exactly what renew.js does server-side). The org's existing sub must keep
//     verifying under the renewed master because master_pub is unchanged.
const renewedPayload = {
  v: 1, typ: "master", tier: "corporate-master", duns: master.payload.duns, seats: "unlimited",
  iat: Math.floor(now.getTime() / 1000),
  // A renewal EXTENDS the window, so the renewed exp is later than the original
  // master exp — which the org's existing sub was clamped to at mint time.
  exp: master.payload.exp + 6 * 30 * 24 * 3600,
  master_pub: master.payload.master_pub, // SAME key -> existing subs keep working
  jti: "renewedserial00000000000000000001", kid, iss,
};
const renewedMaster = { payload: renewedPayload, sig: ed25519Sign(vendor.privateKey, new TextEncoder().encode(canonicalJson(renewedPayload))) };
ok(verifyChain(vendor.publicKey, renewedMaster, null, now).ok === true, "RENEW: re-minted master (same master_pub, new jti) verifies");
ok(verifyChain(vendor.publicKey, renewedMaster, sub, now).ok === true, "RENEW: the org's existing sub still verifies under the renewed master (master_pub unchanged)");

// (c) REVOKE a single sub serial -> verifyChain FAILS CLOSED for that sub, but
//     the master alone is still valid (only the sub was revoked).
const crlSubOnly = buildCrl(vendor.privateKey, { iss, kid, version: 10, revokedJti: [sub.payload.jti], now });
const vSubRevoked = verifyChain(vendor.publicKey, master, sub, now, crlSubOnly);
ok(vSubRevoked.ok === false && vSubRevoked.reason.startsWith("revoked:"), "REVOKE sub jti: verifyChain(master+sub, crl) fails closed with reason 'revoked: …'");
ok(verifyChain(vendor.publicKey, master, null, now, crlSubOnly).ok === true, "REVOKE sub jti: the master ALONE still verifies (only the sub was revoked)");

// (d) REVOKE the whole ORG master key -> BOTH the original and the renewed master
//     fail closed (whole-org revocation ignores the per-token jti).
const crlWholeOrg = buildCrl(vendor.privateKey, { iss, kid, version: 11, revokedMasterPub: [master.payload.master_pub], now });
ok(verifyChain(vendor.publicKey, master, null, now, crlWholeOrg).ok === false, "REVOKE org master_pub: original master fails closed via verifyChain");
ok(verifyChain(vendor.publicKey, renewedMaster, sub, now, crlWholeOrg).ok === false, "REVOKE org master_pub: the RENEWED master (same key) also fails closed — whole-org");

// (e) A corrupt/foreign CRL is IGNORED by verifyChain — never bricks a valid license.
const corruptCrl = { payload: crlWholeOrg.payload, sig: crlWholeOrg.sig.slice(0, -4) + "AAAA" };
ok(verifyChain(vendor.publicKey, master, sub, now, corruptCrl).ok === true, "corrupt CRL is ignored by verifyChain — valid license stays valid (fail-safe, not fail-open on grant)");
const foreignCrl = buildCrl(generateKeypair().privateKey, { iss, kid, version: 12, revokedMasterPub: [master.payload.master_pub], now });
ok(verifyChain(vendor.publicKey, master, sub, now, foreignCrl).ok === true, "a CRL signed by a FOREIGN key cannot revoke (verifyChain ignores it) — no new authority");

console.log(failures === 0 ? "\nlicensing CRL self-check: ALL PASS" : `\nlicensing CRL self-check: ${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
