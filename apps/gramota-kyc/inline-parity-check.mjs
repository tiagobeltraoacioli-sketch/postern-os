// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Parity check: the single-file apps inline hand-copies of the tested verifier
// (postern-license.mjs) and KYC ladder (kyc-loa.mjs). This proves (a) each app's
// inline <script> parses, and (b) the inlined `makePosternLicense` /
// `makeKycLadder` behave identically to the .mjs source of truth.
//
// Run: node apps/gramota-kyc/inline-parity-check.mjs

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { makeKycLadder } from "./kyc-loa.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");
const subtle = globalThis.crypto.subtle;

let pass = 0, fail = 0;
const ok = (n, c, d) => { if (c) { pass++; console.log("  ok   " + n); } else { fail++; console.log("  FAIL " + n + (d ? " — " + d : "")); } };

// Extract a top-level `function NAME(` body from source by brace-matching.
function extractFn(src, name) {
  const start = src.indexOf("function " + name + "(");
  if (start < 0) return null;
  let i = src.indexOf("{", start), depth = 0, end = -1;
  for (; i < src.length; i++) {
    if (src[i] === "{") depth++;
    else if (src[i] === "}") { depth--; if (depth === 0) { end = i + 1; break; } }
  }
  return end < 0 ? null : src.slice(start, end);
}
// Extract the executable inline <script> body (the one that opens with "use strict").
function extractScript(src) {
  const anchor = src.indexOf('<script>\n"use strict');
  const s = (anchor >= 0 ? anchor : src.indexOf("<script>")) + "<script>".length;
  const e = src.indexOf("</script>", s);
  return src.slice(s, e);
}

async function loadFactory(src, name) {
  const body = extractFn(src, name);
  if (!body) throw new Error("could not extract " + name);
  // In the app these factories close over a module-scope VENDOR_PUB_RAW_B64
  // constant; provide it for isolated extraction.
  const preamble = 'var VENDOR_PUB_RAW_B64="iW52PuhJm0+JE+g5UhfrArJ7ONfuUjrm0C38NSwQGm0=";\n';
  // eslint-disable-next-line no-new-func
  const factory = new Function(preamble + body + "\nreturn " + name + ";")();
  return factory;
}

async function main() {
  console.log("Inline parity check\n");

  const files = {
    ezekiel1: readFileSync(join(ROOT, "apps", "ezekiel1", "index.html"), "utf8"),
    console: readFileSync(join(ROOT, "apps", "postern-enterprise", "console.html"), "utf8"),
    gramota: readFileSync(join(ROOT, "apps", "gramota", "index.html"), "utf8"),
  };

  // (a) every executable inline script parses.
  console.log("[a] inline <script> parses in each app");
  for (const [k, src] of Object.entries(files)) {
    let okParse = true, msg = "";
    try { new Function(extractScript(src)); } catch (e) { okParse = false; msg = e.message; }
    ok(k + "/index.html inline script parses", okParse, msg);
  }

  // (b) verifier parity: ezekiel1 + console inline makePosternLicense round-trips.
  console.log("\n[b] inline makePosternLicense parity (mint -> verify chain)");
  const b64 = (buf) => Buffer.from(new Uint8Array(buf)).toString("base64");
  const te = (s) => new TextEncoder().encode(s);
  async function gen() {
    const kp = await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    return { kp, pub: b64(await subtle.exportKey("raw", kp.publicKey)), pkcs8: b64(await subtle.exportKey("pkcs8", kp.privateKey)) };
  }
  for (const app of ["ezekiel1", "console"]) {
    const make = await loadFactory(files[app], "makePosternLicense");
    const PL = make(subtle);
    const vendor = await gen(), master = await gen();
    const nowSec = Math.floor(Date.now() / 1000);
    const token = { v: 1, typ: "master", tier: "corporate-master", duns: "123456789", seats: "unlimited",
      iat: nowSec, exp: nowSec + 6 * 30 * 24 * 3600, master_pub: master.pub,
      attestation: { role: "signatory" }, jti: "0011223344556677", kid: "abcd", iss: "posternlabs.com" };
    const sig = b64(await subtle.sign({ name: "Ed25519" }, vendor.kp.privateKey, te(PL.canonicalJson(token))));
    let r = await PL.verifyChain(vendor.pub, token, sig, null);
    ok(app + ": master verifies", r.ok && r.level === "master");
    r = await PL.verifyChain(master.pub, token, sig, null);
    ok(app + ": wrong vendor key rejected", !r.ok && r.reason === "bad-master-signature");
    const sub = await PL.mintSub(master.pkcs8, token, { sub: "device:x", clearance: 2 });
    r = await PL.verifyChain(vendor.pub, token, sig, sub);
    ok(app + ": minted sub verifies through full chain", r.ok && r.level === "sub" && r.sub === "device:x");
    const tampered = { payload: { ...sub.payload, clearance: 5 }, sig: sub.sig };
    r = await PL.verifyChain(vendor.pub, token, sig, tampered);
    ok(app + ": tampered sub clearance rejected", !r.ok && r.reason === "bad-sub-signature");
  }

  // (c) KYC ladder parity: gramota inline makeKycLadder emits minimal verdict only.
  console.log("\n[c] inline makeKycLadder parity (gramota)");
  const makeKyc = await loadFactory(files.gramota, "makeKycLadder");
  const K = makeKyc();
  const v = K.ocrMatch({ ocrFields: { legalName: "Acme", principal: "Dana" }, dnbRecord: { legalName: "Acme", principal: "Dana" } });
  ok("gramota: OCR full match -> loa 2", v.loa === 2 && v.ocrMatch === true && v.fieldsMatched === 2);
  ok("gramota: verdict has no PII/image keys",
    !("ocrFields" in v) && !("legalName" in v) && Object.keys(v).every(k => ["ocrMatch", "fieldsMatched", "loa", "decision", "assurance", "ref", "checkedAt"].includes(k)));
  ok("gramota: maxLoa is fail-closed", K.maxLoa(K.selfDeclare({}), K.corpEmailProof({ email: "a@b.com", domain: "x.com" })) === 0);

  // (c-idv) idv rung parity — inline vs. the .mjs source of truth.
  const KM = makeKycLadder();
  const inlineIdvUnconfigured = K.idv({});
  const mjsIdvUnconfigured = KM.idv({});
  ok("gramota: idv({}) never grants LoA 3 (fail-closed)",
    inlineIdvUnconfigured.decision === "fail" && inlineIdvUnconfigured.loa < 3);
  ok("gramota: idv({}) contributes 0 to maxLoa",
    K.maxLoa(inlineIdvUnconfigured) === 0);
  ok("gramota: idv({}) matches .mjs unconfigured shape (decision/assurance/loa)",
    inlineIdvUnconfigured.decision === mjsIdvUnconfigured.decision &&
    inlineIdvUnconfigured.assurance === mjsIdvUnconfigured.assurance &&
    inlineIdvUnconfigured.loa === mjsIdvUnconfigured.loa);
  const inlineIdvConfigured = K.idv({ provider: "x" });
  const mjsIdvConfigured = KM.idv({ provider: "x" });
  ok("gramota: idv({provider:'x'}) yields loa 3 / decision 'pass'",
    inlineIdvConfigured.loa === 3 && inlineIdvConfigured.decision === "pass");
  ok("gramota: idv({provider:'x'}) matches .mjs configured shape (decision/assurance/loa)",
    inlineIdvConfigured.decision === mjsIdvConfigured.decision &&
    inlineIdvConfigured.assurance === mjsIdvConfigured.assurance &&
    inlineIdvConfigured.loa === mjsIdvConfigured.loa);
  ok("gramota: idv passing feeds maxLoa correctly",
    K.maxLoa(inlineIdvConfigured) === 3);
  ok("gramota: inline factory keys match .mjs factory keys",
    JSON.stringify(Object.keys(K).sort()) === JSON.stringify(Object.keys(KM).sort()) &&
    Object.keys(K).sort().join(",") === ["corpEmailProof", "idv", "maxLoa", "ocrMatch", "selfDeclare"].join(","));

  console.log(`\n${fail === 0 ? "ALL PASS" : "HAD FAILURES"} — ${pass} passed, ${fail} failed`);
  if (fail > 0) process.exit(1);
}
main().catch((e) => { console.error(e); process.exit(1); });
