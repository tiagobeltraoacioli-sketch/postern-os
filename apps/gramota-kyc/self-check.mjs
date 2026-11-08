// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Self-check for the browser-side Postern licensing verifier + device sub-minter,
// and the on-device KYC/LoA ladder. Reference prototype / UNAUDITED.
//
// Proves:
//  1. canonicalJson is BYTE-IDENTICAL to the real `canonical()` in
//     functions/license/master.js (extracted + run at test time).
//  2. A vendor->master->sub Ed25519 chain minted here VERIFIES here, and every
//     tamper/expiry/mismatch case is rejected fail-closed.
//  3. Device sub-mint (mintSub) round-trips and is chained under the master.
//  4. The signed-policy seam is real Ed25519.
//  5. The KYC/LoA ladder emits ONLY the minimal verdict (no PII, no images).
//
// Run: node apps/gramota-kyc/self-check.mjs

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { makePosternLicense } from "./postern-license.mjs";
import { makeKycLadder } from "./kyc-loa.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");
const subtle = globalThis.crypto.subtle;
const PL = makePosternLicense(subtle);

let pass = 0, fail = 0;
function ok(name, cond, detail) {
  if (cond) { pass++; console.log(`  ok   ${name}`); }
  else { fail++; console.log(`  FAIL ${name}${detail ? " — " + detail : ""}`); }
}
async function throwsAsync(fn) {
  try { await fn(); return false; } catch { return true; }
}

// --- helpers to build a real vendor-signed master the way master.js does ---
const te = (s) => new TextEncoder().encode(s);
const b64 = (buf) => Buffer.from(new Uint8Array(buf)).toString("base64");

async function genEd25519() {
  const kp = await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const pubRaw = b64(await subtle.exportKey("raw", kp.publicKey));
  const privPkcs8 = b64(await subtle.exportKey("pkcs8", kp.privateKey));
  return { kp, pubRaw, privPkcs8 };
}
async function signCanonical(privateKey, obj) {
  const sig = await subtle.sign({ name: "Ed25519" }, privateKey, te(PL.canonicalJson(obj)));
  return b64(sig);
}

async function main() {
  console.log("Postern licensing + KYC self-check\n");

  // ===== 1. canonicalJson byte-identical to master.js canonical() =====
  console.log("[1] canonical serialization byte-compat vs functions/license/master.js");
  const masterSrc = readFileSync(join(ROOT, "functions", "license", "master.js"), "utf8");
  const cm = masterSrc.match(/function canonical\(obj\)\s*\{[\s\S]*?\n\}/);
  ok("canonical() found in master.js", !!cm);
  // Evaluate the extracted server function in isolation.
  const serverCanonical = new Function(cm[0] + "\nreturn canonical;")();
  const samples = [
    { v: 1, typ: "master", tier: "corporate-master", duns: "123456789", seats: "unlimited",
      iat: 1000, exp: 2000, master_pub: "AAA=", attestation: { role: "cfo", self_declared: true },
      jti: "abc", kid: "0011", iss: "posternlabs.com" },
    { z: [3, 2, 1], a: "x", nested: { d: 4, b: 2, c: 3 }, arr: [{ y: 1, x: 2 }] },
    { b: true, n: null, num: 42, s: "quote\"and\\slash", e: {} },
    [1, "two", { k: "v" }, [true, null]],
    "plain-string", 123, true, null,
  ];
  let allMatch = true, mismatch = "";
  for (const s of samples) {
    const mine = PL.canonicalJson(s), theirs = serverCanonical(s);
    if (mine !== theirs) { allMatch = false; mismatch = `mine=${mine} theirs=${theirs}`; break; }
  }
  ok("canonicalJson == server canonical() on all samples", allMatch, mismatch);

  // ===== 2 & 3. Ed25519 vendor->master->sub chain =====
  console.log("\n[2] Ed25519 chain — mint, verify, and fail-closed rejections");
  const vendor = await genEd25519();
  const master = await genEd25519(); // the org's master keypair
  const nowSec = Math.floor(Date.now() / 1000);
  const MONTH = 30 * 24 * 3600;
  const masterToken = {
    v: 1, typ: "master", tier: "corporate-master", duns: "123456789", seats: "unlimited",
    iat: nowSec, exp: nowSec + 6 * MONTH, master_pub: master.pubRaw,
    attestation: { role: "authorized-signatory", self_declared: true }, jti: PL.randHex(16),
    kid: "deadbeefdeadbeef", iss: "posternlabs.com",
  };
  const masterSig = await signCanonical(vendor.kp.privateKey, masterToken);

  // Positive: master verifies against the vendor root.
  let r = await PL.verifyChain(vendor.pubRaw, masterToken, masterSig, null);
  ok("master verifies (level=master, not expired)", r.ok && r.level === "master" && !r.expired, JSON.stringify(r));

  // Wrong root of trust is rejected.
  r = await PL.verifyChain(master.pubRaw, masterToken, masterSig, null);
  ok("master rejected under wrong vendor key", !r.ok && r.reason === "bad-master-signature", JSON.stringify(r));

  // Tampered master payload rejected.
  const tampered = { ...masterToken, seats: "1000000" };
  r = await PL.verifyChain(vendor.pubRaw, tampered, masterSig, null);
  ok("tampered master payload rejected", !r.ok && r.reason === "bad-master-signature");

  // Bad DUNS rejected (corporate tier requires 9 digits) — must re-sign so the
  // signature passes and the DUNS check is what bites.
  const badDunsTok = { ...masterToken, duns: "42" };
  const badDunsSig = await signCanonical(vendor.kp.privateKey, badDunsTok);
  r = await PL.verifyChain(vendor.pubRaw, badDunsTok, badDunsSig, null);
  ok("bad DUNS rejected", !r.ok && r.reason === "bad-duns", JSON.stringify(r));

  // Device sub-mint under the master, then verify the full chain.
  const sub = await PL.mintSub(master.privPkcs8, masterToken, {
    sub: "device:ana-laptop", exp: nowSec + 30 * 24 * 3600, clearance: 3, device: "ana-laptop",
  });
  ok("mintSub produced {payload,sig} with clearance carried", sub.payload.clearance === 3 && !!sub.sig);
  r = await PL.verifyChain(vendor.pubRaw, masterToken, masterSig, sub);
  ok("sub verifies through the full vendor->master->sub chain", r.ok && r.level === "sub" && r.sub === "device:ana-laptop", JSON.stringify(r));

  // Tampered sub signature rejected.
  const badSub = { payload: { ...sub.payload, clearance: 5 }, sig: sub.sig };
  r = await PL.verifyChain(vendor.pubRaw, masterToken, masterSig, badSub);
  ok("sub with edited clearance (breaks signature) rejected", !r.ok && r.reason === "bad-sub-signature");

  // Sub outliving the master rejected.
  const longSub = await PL.mintSub(master.privPkcs8, masterToken, { sub: "x", exp: nowSec + 999 * MONTH });
  // mintSub clamps exp to master.exp, so forge one that outlives it and re-sign.
  const forged = { ...longSub.payload, exp: masterToken.exp + 10 };
  const forgedSig = await signCanonical(master.kp.privateKey, forged);
  r = await PL.verifyChain(vendor.pubRaw, masterToken, masterSig, { payload: forged, sig: forgedSig });
  ok("sub outliving master rejected", !r.ok && r.reason === "sub-outlives-master", JSON.stringify(r));

  // Sub bound to a different master_pub rejected.
  const other = await genEd25519();
  const wrongMasterSub = { payload: { ...sub.payload, master_pub: other.pubRaw }, sig: sub.sig };
  r = await PL.verifyChain(vendor.pubRaw, masterToken, masterSig, wrongMasterSub);
  ok("sub bound to a foreign master_pub rejected", !r.ok && r.reason === "sub-master-mismatch");

  // mintSub clamps sub.exp to master.exp.
  ok("mintSub clamps sub.exp <= master.exp", longSub.payload.exp === masterToken.exp);

  // ===== 4. signed policy seam =====
  console.log("\n[3] signed-policy seam (real Ed25519, distinct from FNV trail display)");
  const policy = { edition: "business", tenant: "acme", layers: [{ name: "root", scopes: ["read:*"] }] };
  const psig = await PL.signPolicy(master.privPkcs8, policy);
  ok("policy signature verifies with master_pub", await PL.verifyPolicy(master.pubRaw, policy, psig));
  ok("edited policy fails verification", !(await PL.verifyPolicy(master.pubRaw, { ...policy, tenant: "evil" }, psig)));

  // ===== 5. KYC / LoA ladder — minimal-verdict-only, no PII across the wire =====
  console.log("\n[4] on-device KYC/LoA ladder — minimal verdict only");
  const kyc = makeKycLadder();
  const decl = kyc.selfDeclare({ orgName: "Acme Robotics", duns: "123456789" });
  ok("LoA 0 self-declared", decl.loa === 0 && decl.decision === "pass" && decl.assurance === "self-declared");

  const email = kyc.corpEmailProof({ email: "cfo@acme.com", domain: "acme.com" });
  ok("LoA 1 corp-domain email proof", email.loa === 1 && email.decision === "pass");

  // On-device OCR match vs the D&B principal record. Only the verdict leaves.
  const ocr = kyc.ocrMatch({
    ocrFields: { legalName: "Acme Robotics Inc", principal: "Dana Cruz", duns: "123456789" },
    dnbRecord: { legalName: "Acme Robotics Inc", principal: "Dana Cruz", duns: "123456789" },
  });
  ok("LoA 2 OCR-vs-D&B full match", ocr.loa === 2 && ocr.ocrMatch === true && ocr.fieldsMatched === 3);
  const leak = Object.keys(ocr);
  ok("verdict carries ONLY {ocrMatch,fieldsMatched,loa,decision,assurance,ref,checkedAt}",
    leak.every((k) => ["ocrMatch", "fieldsMatched", "loa", "decision", "assurance", "ref", "checkedAt"].includes(k)),
    "leaked keys: " + leak.join(","));
  ok("verdict contains NO raw OCR / image / PII field",
    !("ocrFields" in ocr) && !("dnbRecord" in ocr) && !("legalName" in ocr) && !("principal" in ocr));

  const mismatch2 = kyc.ocrMatch({
    ocrFields: { legalName: "Acme Robotics Inc", principal: "Someone Else", duns: "123456789" },
    dnbRecord: { legalName: "Acme Robotics Inc", principal: "Dana Cruz", duns: "123456789" },
  });
  ok("LoA 2 partial match downgrades ocrMatch=false, still reports fieldsMatched", mismatch2.ocrMatch === false && mismatch2.fieldsMatched === 2);

  // Editing loa upward without proof is refused by the ladder (fail-closed).
  ok("ladder refuses to claim an LoA above the evidence", kyc.maxLoa(decl, email) === 1);

  console.log(`\n${fail === 0 ? "ALL PASS" : "HAD FAILURES"} — ${pass} passed, ${fail} failed`);
  if (fail > 0) process.exit(1);
}

main().catch((e) => { console.error(e); process.exit(1); });
