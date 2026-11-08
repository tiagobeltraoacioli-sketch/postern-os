// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// OCR-ENGINE INLINE PARITY TEST — proves the single-file app (index.html) carries
// a BEHAVIORALLY IDENTICAL copy of the tested OCR engine (ocr-engine.js) behind
// the honest <script id="grm-ocr"> seam. gramota-kyc ships as ONE self-contained
// HTML file, so the real ICAO 9303 MRZ engine (TD3 parse + check digits +
// calendar-valid dates + opt-in asOf expiry) has to live INLINE — and an inline
// hand-copy silently drifts. Commit 2304500 added opt/asOf expiry + calendar
// validity to ocr-engine.js; if the inline copy in index.html does not carry the
// same logic, an expired or calendar-impossible document parses differently in
// the shipped app than in the tested source of truth. That drift is exactly the
// regression this file catches.
//
// Method: extract the marked GRM-OCR-ENGINE-INLINE block from index.html, evaluate
// it in isolation to recover its GRM_OCR_ENGINE, and assert its output is deep-equal
// to the .mjs/.js source of truth across a matrix of MRZ inputs — including the
// date-semantics cases (expiry, calendar-impossible dates) that a pre-2304500 inline
// copy would get wrong. Any behavioral divergence -> a failed check -> nonzero exit.
//
// Run: node apps/gramota-kyc/ocr-inline-parity.test.mjs

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createRequire } from "node:module";

const HERE = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

// ---- source of truth ------------------------------------------------------
const SRC = require("./ocr-engine.js");

// ---- inline copy: extract the marked block from index.html and evaluate it -
function loadInlineEngine() {
  const html = readFileSync(join(HERE, "index.html"), "utf8");
  const begin = html.indexOf("GRM-OCR-ENGINE-INLINE:BEGIN");
  const end = html.indexOf("GRM-OCR-ENGINE-INLINE:END");
  if (begin < 0 || end < 0 || end < begin) {
    throw new Error("inline engine markers not found in index.html (BEGIN/END)");
  }
  // Take the UMD IIFE that follows the BEGIN banner, up to the END marker.
  const iifeStart = html.indexOf("(function (root, factory) {", begin);
  if (iifeStart < 0 || iifeStart > end) {
    throw new Error("inline engine IIFE not found between markers");
  }
  // End the slice at the IIFE's own close (`});`) that precedes the END marker,
  // so the trailing END comment is not sliced mid-token.
  const iifeEnd = html.lastIndexOf("});", end);
  if (iifeEnd < iifeStart) throw new Error("inline engine IIFE close not found before END marker");
  const block = html.slice(iifeStart, iifeEnd + 3);
  // The UMD wrapper assigns module.exports when `module` looks like CJS; give it
  // a private module object and read the engine back from it. No globals touched.
  const mod = { exports: {} };
  // eslint-disable-next-line no-new-func
  new Function("module", "globalThis", block)(mod, {});
  if (!mod.exports || typeof mod.exports.parseTd3 !== "function") {
    throw new Error("inline engine did not export a usable GRM_OCR_ENGINE");
  }
  return mod.exports;
}

// ---- harness --------------------------------------------------------------
let pass = 0,
  fail = 0;
const failures = [];
function ok(name, cond, detail) {
  if (cond) {
    pass++;
    console.log("  ok   " + name);
  } else {
    fail++;
    failures.push(name + (detail ? " — " + detail : ""));
    console.log("  FAIL " + name + (detail ? " — " + detail : ""));
  }
}
const norm = (v) => JSON.stringify(v);
// Assert the inline engine and the source produce deep-equal output for the same call.
function parity(name, fnName, args) {
  let a, b, ea, eb;
  try {
    a = INLINE[fnName].apply(null, args);
  } catch (e) {
    ea = e;
  }
  try {
    b = SRC[fnName].apply(null, args);
  } catch (e) {
    eb = e;
  }
  if (ea || eb) {
    ok(name, !!ea === !!eb && String(ea && ea.message) === String(eb && eb.message), "throw mismatch: inline=" + ea + " src=" + eb);
    return;
  }
  ok(name, norm(a) === norm(b), "inline=" + norm(a) + " src=" + norm(b));
}

const INLINE = loadInlineEngine();

// SYNTHETIC ICAO 9303 Part 3 worked example (a textbook reference vector — NOT a
// real person's document). Expiry 120415 = 2012-04-15; DOB 740812 = 1974-08-12.
const ICAO_LINE1 = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<";
const ICAO_LINE2 = "L898902C36UTO7408122F1204159ZE184226B<<<<<10";
const ICAO_TRANSCRIPT = "SYNTHETIC ID SCAN — NOT A REAL DOCUMENT\n\n" + ICAO_LINE1 + "\n" + ICAO_LINE2 + "\n";

// A checksum-VALID line2 whose date-of-birth month is calendar-impossible (13),
// with a recomputed DOB check digit so ONLY calendar validity — not a checksum —
// can reject it. This is precisely the case a pre-2304500 inline copy mis-handles.
const badDob = "139999";
const dobCheck = SRC.mrzCheckDigit(badDob);
const CAL_BAD_LINE2 = ICAO_LINE2.slice(0, 13) + badDob + dobCheck + ICAO_LINE2.slice(20);

// A line2 with a tampered expiry check digit (checksum-broken).
const CHK_BAD_LINE2 = ICAO_LINE2.slice(0, 27) + (ICAO_LINE2[27] === "9" ? "0" : "9") + ICAO_LINE2.slice(28);

const AUTHORITY_DOC =
  "BOARD RESOLUTION\nACME WIDGETS INCORPORATED\nUnited States\nThe undersigned directors hereby resolve...\n";

async function main() {
  console.log("OCR-engine inline parity (index.html <-> ocr-engine.js)\n");

  // [0] the whole shipped <script id=\"grm-ocr\"> block must be valid JS.
  console.log("[0] shipped inline script sanity");
  {
    const html = readFileSync(join(HERE, "index.html"), "utf8");
    const s = html.indexOf('<script id="grm-ocr">') + '<script id="grm-ocr">'.length;
    const e = html.indexOf("</script>", s);
    let parses = true,
      msg = "";
    try {
      // eslint-disable-next-line no-new-func
      new Function(html.slice(s, e));
    } catch (err) {
      parses = false;
      msg = err.message;
    }
    ok("grm-ocr <script> parses as valid JS", parses, msg);
    ok("inline engine exports match source keys", norm(Object.keys(INLINE).sort()) === norm(Object.keys(SRC).sort()), norm(Object.keys(INLINE).sort()));
  }

  // [1] check-digit + basic date primitives.
  console.log("\n[1] primitives");
  parity("mrzCheckDigit(docnum)", "mrzCheckDigit", ["L898902C3"]);
  parity("mrzCheckDigit(expiry)", "mrzCheckDigit", ["120415"]);
  parity("mrzCheckDigit(garbage char)", "mrzCheckDigit", ["ABC!23"]);
  parity("parseYyMmDd valid (ICAO expiry)", "parseYyMmDd", ["120415"]);
  parity("parseYyMmDd impossible month=13", "parseYyMmDd", ["139999"]); // <- date semantics
  parity("parseYyMmDd month=00", "parseYyMmDd", ["000101"]); // <- date semantics
  parity("parseYyMmDd day=31 in April", "parseYyMmDd", ["000431"]); // <- date semantics
  parity("parseYyMmDd day=00", "parseYyMmDd", ["001200"]); // <- date semantics
  parity("parseYyMmDd Feb 30", "parseYyMmDd", ["000230"]); // <- date semantics
  parity("parseYyMmDd non-numeric", "parseYyMmDd", ["12A415"]);

  // [2] resolveMrzYear (century-aware strict validity — catches Feb-29 non-leap).
  console.log("\n[2] resolveMrzYear (century-aware)");
  parity("resolveMrzYear valid", "resolveMrzYear", [{ yy: "12", mm: "04", dd: "15" }, 2000]); // <- date semantics
  parity("resolveMrzYear Feb-29 non-leap (2001)", "resolveMrzYear", [{ yy: "01", mm: "02", dd: "29" }, 2000]); // <- date semantics
  parity("resolveMrzYear Feb-29 leap (2000)", "resolveMrzYear", [{ yy: "00", mm: "02", dd: "29" }, 2000]); // <- date semantics
  parity("resolveMrzYear null input", "resolveMrzYear", [null, 2000]);

  // [3] parseTd3 — structural + date semantics (opts/asOf expiry).
  console.log("\n[3] parseTd3");
  parity("parseTd3 valid, no asOf", "parseTd3", [ICAO_LINE1, ICAO_LINE2]); // datesValid + expired:null
  parity("parseTd3 valid, asOf AFTER expiry -> expired", "parseTd3", [ICAO_LINE1, ICAO_LINE2, { asOf: "2026-07-17T00:00:00Z" }]); // <- date semantics
  parity("parseTd3 valid, asOf BEFORE expiry -> live", "parseTd3", [ICAO_LINE1, ICAO_LINE2, { asOf: "2010-01-01T00:00:00Z" }]); // <- date semantics
  parity("parseTd3 boundary: on expiry day -> not expired", "parseTd3", [ICAO_LINE1, ICAO_LINE2, { asOf: "2012-04-15T23:00:00Z" }]); // <- date semantics
  parity("parseTd3 boundary: day after expiry -> expired", "parseTd3", [ICAO_LINE1, ICAO_LINE2, { asOf: "2012-04-16T00:00:00Z" }]); // <- date semantics
  parity("parseTd3 asOf epoch-ms number", "parseTd3", [ICAO_LINE1, ICAO_LINE2, { asOf: 1752710400000 }]); // <- date semantics
  parity("parseTd3 asOf unparseable string -> not evaluated", "parseTd3", [ICAO_LINE1, ICAO_LINE2, { asOf: "not-a-date" }]); // <- date semantics
  parity("parseTd3 calendar-impossible DOB (checksum ok) -> invalid", "parseTd3", [ICAO_LINE1, CAL_BAD_LINE2]); // <- date semantics
  parity("parseTd3 broken expiry checksum -> invalid", "parseTd3", [ICAO_LINE1, CHK_BAD_LINE2]);
  parity("parseTd3 wrong length -> null", "parseTd3", [ICAO_LINE1, "TOO<SHORT"]);
  parity("parseTd3 non-string -> null", "parseTd3", [ICAO_LINE1, 42]);

  // [4] extractMrz / extractIdFields / extractFields (asOf threads through).
  console.log("\n[4] extractors (asOf threads through)");
  parity("extractMrz valid transcript", "extractMrz", [ICAO_TRANSCRIPT]);
  parity("extractMrz asOf AFTER expiry", "extractMrz", [ICAO_TRANSCRIPT, { asOf: "2026-07-17T00:00:00Z" }]); // <- date semantics
  parity("extractIdFields no asOf", "extractIdFields", [ICAO_TRANSCRIPT]);
  parity("extractIdFields live (asOf before expiry) -> fields", "extractIdFields", [ICAO_TRANSCRIPT, { asOf: "2010-01-01T00:00:00Z" }]); // <- date semantics
  parity("extractIdFields EXPIRED (asOf after) -> NO field credit", "extractIdFields", [ICAO_TRANSCRIPT, { asOf: "2026-07-17T00:00:00Z" }]); // <- date semantics
  parity("extractFields id path threads asOf (expired)", "extractFields", [ICAO_TRANSCRIPT, { asOf: "2026-07-17T00:00:00Z" }]); // <- date semantics
  parity("extractFields id path threads asOf (live)", "extractFields", [ICAO_TRANSCRIPT, { asOf: "2010-01-01T00:00:00Z" }]); // <- date semantics
  parity("extractFields heuristic authority doc", "extractFields", [AUTHORITY_DOC]);
  parity("extractFields kind:id with no MRZ", "extractFields", ["no mrz here", { kind: "id" }]);
  parity("extractAuthorityDocFields", "extractAuthorityDocFields", [AUTHORITY_DOC]);

  console.log(`\n${fail === 0 ? "ALL PASS" : "HAD FAILURES"} — ${pass} passed, ${fail} failed`);
  if (fail > 0) {
    console.log("\nDrift detected (inline index.html diverges from ocr-engine.js):");
    for (const f of failures) console.log("  - " + f);
    process.exit(1);
  }
}
main().catch((e) => {
  console.error(e);
  process.exit(1);
});
