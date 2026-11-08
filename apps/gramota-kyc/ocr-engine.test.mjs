// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// GRAMOTA on-device OCR ENGINE SEAM tests — run with: node ocr-engine.test.mjs
//
// Extracts the DOM-free <script id="grm-ocr"> block from index.html (the single
// source of the engine contract) and the <script id="grm-core"> validators, then
// pins the load-bearing HONESTY invariants of the reader seam:
//
//   • No engine is bundled -> the default is honest MANUAL entry (text:null).
//   • The engine NEVER fabricates a read: no file, an empty/whitespace read, an
//     unknown result shape, or an adapter that THROWS all fail closed to manual.
//   • A real adapter's transcript is passed through VERBATIM (never mutated).
//   • read() emits ONLY { engine, manual, text } — never a match / LoA / decision.
//   • A successful read ALONE does not lift LoA: assurance still requires a real
//     field match through GRM (a document read is not proof of authority).
//
// This is a reference prototype / UNAUDITED. OCR is the goal; MANUAL is today.
//
// EXTENDED below (do not remove the section above) with tests for the REAL
// engine layer in ocr-engine.js: a genuine ICAO 9303 MRZ checksum parser, a
// structured-text file adapter that plugs into the seam above, and a
// fail-closed free-text field extractor. See ocr-engine.js's own header for
// exactly what is real vs. the deliberately-pluggable raster-OCR boundary.
// All fixtures under fixtures/*.txt are labeled SYNTHETIC in-file; the MRZ
// vector is the published ICAO Doc 9303 worked example (a textbook reference
// vector, not a real person's document) used to prove the checksum algorithm
// against an externally-known-correct value, not just self-consistency.

import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import ENGINE from "./ocr-engine.js";

const html = readFileSync(new URL("./index.html", import.meta.url), "utf8");

function evalBlock(id) {
  const m = html.match(new RegExp('<script id="' + id + '">([\\s\\S]*?)</script>'));
  assert.ok(m, `<script id="${id}"> block found`);
  (0, eval)(m[1]);
}
evalBlock("grm-core");
evalBlock("grm-ocr");

const OCR = globalThis.GRM_OCR;
const G = globalThis.GRM;
assert.ok(OCR && typeof OCR.makeOcrEngine === "function", "GRM_OCR loaded");
assert.ok(G && typeof G.computeLoa === "function", "GRM loaded");

let passed = 0;
const t = (name, fn) => fn().then(() => { passed++; console.log("  ok — " + name); });
const FILE = { name: "doc.png" }; // stand-in for a File/Blob; the adapter is what reads it

// A faithful Tesseract-shaped adapter that returns a fixed transcript.
const tesseractLike = (text) => ({ recognize: async (_f, _lang) => ({ data: { text } }) });

const tests = [];

// ---- no engine -> honest manual, no fabrication ---------------------------
tests.push(t("no adapter => manual on-device entry, text:null (nothing fabricated)", async () => {
  const e = OCR.makeOcrEngine(null);
  assert.equal(e.available, false);
  assert.equal(e.name, "none");
  const r = await e.read(FILE);
  assert.equal(r.manual, true);
  assert.equal(r.text, null);
  assert.equal(r.reason, "no-engine");
}));

// ---- real adapter -> verbatim transcript ----------------------------------
tests.push(t("Tesseract-shaped adapter => transcript passed through VERBATIM", async () => {
  const e = OCR.makeOcrEngine(tesseractLike("ACME ROBOTICS INC\nDelaware, USA"));
  assert.equal(e.available, true);
  assert.equal(e.name, "tesseract");
  const r = await e.read(FILE);
  assert.equal(r.manual, false);
  assert.equal(r.text, "ACME ROBOTICS INC\nDelaware, USA"); // not mutated
  assert.equal(r.engine, "tesseract");
}));

// ---- adapter shape flexibility (all normalize the same) -------------------
tests.push(t("flat {text}, {data:{text}}, and bare-function adapters all read alike", async () => {
  const a = await OCR.makeOcrEngine({ name: "flat", read: async () => "hello" }).read(FILE);
  const b = await OCR.makeOcrEngine(tesseractLike("hello")).read(FILE);
  const fn = async () => ({ data: { text: "hello" } });
  const c = await OCR.makeOcrEngine(fn).read(FILE);
  assert.equal(a.text, "hello");
  assert.equal(b.text, "hello");
  assert.equal(c.text, "hello");
  assert.equal(a.manual, false);
}));

// ---- fail-closed: no file -------------------------------------------------
tests.push(t("adapter present but NO file => manual, no fabricated read", async () => {
  const r = await OCR.makeOcrEngine(tesseractLike("x")).read(null);
  assert.equal(r.manual, true);
  assert.equal(r.text, null);
  assert.equal(r.reason, "no-file");
}));

// ---- fail-closed: empty / whitespace read is not a read -------------------
tests.push(t("empty / whitespace transcript => manual (a blank read is not a read)", async () => {
  const r1 = await OCR.makeOcrEngine(tesseractLike("")).read(FILE);
  const r2 = await OCR.makeOcrEngine(tesseractLike("   \n\t ")).read(FILE);
  assert.equal(r1.manual, true); assert.equal(r1.text, null); assert.equal(r1.reason, "empty-read");
  assert.equal(r2.manual, true); assert.equal(r2.text, null);
}));

// ---- fail-closed: unknown result shape ------------------------------------
tests.push(t("unknown result shape (number / no text key) => manual, never coerced", async () => {
  const r1 = await OCR.makeOcrEngine({ recognize: async () => 42 }).read(FILE);
  const r2 = await OCR.makeOcrEngine({ recognize: async () => ({ foo: "bar" }) }).read(FILE);
  assert.equal(r1.manual, true); assert.equal(r1.text, null);
  assert.equal(r2.manual, true); assert.equal(r2.text, null);
}));

// ---- fail-closed: adapter that THROWS -------------------------------------
tests.push(t("adapter that throws => fail-closed to manual (no partial/garbage read)", async () => {
  const r = await OCR.makeOcrEngine({ recognize: async () => { throw new Error("wasm blew up"); } }).read(FILE);
  assert.equal(r.manual, true);
  assert.equal(r.text, null);
  assert.equal(r.reason, "engine-error");
}));

// ---- the engine emits NO verdict ------------------------------------------
tests.push(t("read() returns ONLY { engine, manual, text } — never match/loa/decision", async () => {
  const r = await OCR.makeOcrEngine(tesseractLike("ACME INC")).read(FILE);
  assert.deepEqual(Object.keys(r).sort(), ["engine", "manual", "text"]);
  for (const forbidden of ["match", "loa", "decision", "assurance", "ocrMatch", "fieldsMatched"]) {
    assert.ok(!(forbidden in r), `verdict key '${forbidden}' must not leak from the reader`);
  }
}));

// ---- a read ALONE does not lift LoA (read != proof of authority) ----------
tests.push(t("a successful on-device read alone does NOT lift LoA (still needs a match)", async () => {
  const read = await OCR.makeOcrEngine(tesseractLike("ACME ROBOTICS INC\nUSA")).read(FILE);
  assert.equal(read.manual, false);
  // Feed the transcript into the flow WITHOUT a field match: LoA stays 0.
  const ocrReadButUnmatched = { onDevice: true, match: false, fieldsMatched: [] };
  assert.equal(G.computeLoa({ selfDeclared: true, dnbVerified: true, ocr: ocrReadButUnmatched }).loa, 0);
  // Only a REAL validated match (legalName + country) lifts it, and only atop LoA 1.
  const validated = { onDevice: true, match: true, fieldsMatched: ["legalName", "country"] };
  assert.equal(G.computeLoa({ corpDomain: true, ocr: validated }).loa, 2);
}));

// ============================================================================
// REAL ENGINE — ICAO 9303 MRZ checksum parser (ocr-engine.js)
// ============================================================================
// The canonical published ICAO Doc 9303 worked example. This is a textbook
// reference vector reproduced across many independent MRZ-parser test suites
// — NOT a real person's document. Used here so the checksum algorithm is
// verified against an EXTERNALLY-known-correct value, not merely
// self-consistent with the code under test.
const ICAO_LINE1 = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<";
const ICAO_LINE2 = "L898902C36UTO7408122F1204159ZE184226B<<<<<10";
const ICAO_TRANSCRIPT =
  "SYNTHETIC ID SCAN — NOT A REAL DOCUMENT\n\n" + ICAO_LINE1 + "\n" + ICAO_LINE2 + "\n";

tests.push(t("mrzCheckDigit matches the published ICAO 9303 worked example's own check digits", async () => {
  assert.equal(ENGINE.mrzCheckDigit("L898902C3"), "6");   // document number
  assert.equal(ENGINE.mrzCheckDigit("740812"), "2");       // date of birth
  assert.equal(ENGINE.mrzCheckDigit("120415"), "9");       // date of expiry
  assert.equal(ENGINE.mrzCheckDigit("ZE184226B<<<<<"), "1"); // personal number
  assert.equal(ENGINE.mrzCheckDigit("L898902C3674081221204159ZE184226B<<<<<1"), "0"); // composite
}));

tests.push(t("extractMrz finds the MRZ block inside a noisy transcript and decodes it (SYNTHETIC)", async () => {
  const mrz = ENGINE.extractMrz(ICAO_TRANSCRIPT);
  assert.ok(mrz, "MRZ block found");
  assert.equal(mrz.format, "TD3");
  assert.equal(mrz.documentNumber, "L898902C3");
  assert.equal(mrz.surname, "ERIKSSON");
  assert.equal(mrz.givenNames, "ANNA MARIA");
  assert.equal(mrz.nationality, "UTO");
  assert.equal(mrz.sex, "F");
  assert.deepEqual(mrz.dateOfBirth, { yy: "74", mm: "08", dd: "12" });
  assert.deepEqual(mrz.dateOfExpiry, { yy: "12", mm: "04", dd: "15" });
  assert.equal(mrz.valid, true, "every check digit agrees with the published example");
  assert.ok(Object.values(mrz.checks).every(Boolean), "no individual check digit failed");
}));

tests.push(t("a single tampered MRZ check digit fails the WHOLE block closed (never partially trusted)", async () => {
  const tamperedLine2 = ICAO_LINE2.slice(0, 9) + (ICAO_LINE2[9] === "6" ? "5" : "6") + ICAO_LINE2.slice(10);
  const mrz = ENGINE.parseTd3(ICAO_LINE1, tamperedLine2);
  assert.ok(mrz, "still parses structurally (shape is intact)");
  assert.equal(mrz.checks.docNumber, false);
  assert.equal(mrz.checks.composite, false, "composite catches the tamper too");
  assert.equal(mrz.valid, false, "fail-closed: a wrong digit invalidates the block");
}));

tests.push(t("extractIdFields: a VALID MRZ yields confidence-1 fields; an INVALID one yields NONE", async () => {
  const good = ENGINE.extractIdFields(ICAO_TRANSCRIPT);
  assert.equal(good.source, "mrz");
  assert.equal(good.valid, true);
  assert.equal(good.fields.officerName.value, "ANNA MARIA ERIKSSON");
  assert.equal(good.fields.officerName.confidence, 1);
  assert.equal(good.fields.country.value, "UTO");
  assert.equal(good.fields.documentNumber.value, "L898902C3");

  const tamperedLine2 = ICAO_LINE2.slice(0, 27) + (ICAO_LINE2[27] === "9" ? "0" : "9") + ICAO_LINE2.slice(28);
  const tamperedTranscript = "SYNTHETIC ID SCAN\n" + ICAO_LINE1 + "\n" + tamperedLine2 + "\n";
  const bad = ENGINE.extractIdFields(tamperedTranscript);
  assert.equal(bad.valid, false);
  assert.deepEqual(bad.fields, {}, "an invalid checksum block trusts NOTHING, not even the parts that 'look' fine");
}));

tests.push(t("extractMrz returns null (not a guess) when no MRZ block is present", async () => {
  assert.equal(ENGINE.extractMrz("just some ordinary prose\nwith no machine-readable zone at all"), null);
  assert.equal(ENGINE.extractIdFields("no mrz here").source, "none");
}));

// ============================================================================
// REAL ENGINE — fail-closed free-text field extractor (authority document)
// ============================================================================
const authorityDocFixture = readFileSync(
  new URL("./fixtures/synthetic-authority-doc.txt", import.meta.url),
  "utf8"
);

tests.push(t("extractAuthorityDocFields proposes legalName/country ABOVE the confidence floor (SYNTHETIC fixture)", async () => {
  const r = ENGINE.extractAuthorityDocFields(authorityDocFixture);
  assert.ok(r.fields.legalName, "a legal-name candidate was proposed");
  assert.equal(r.fields.legalName.value, "ACME ROBOTICS SYNTHETIC TESTCASE INCORPORATED");
  assert.ok(r.fields.legalName.confidence >= ENGINE.CONFIDENCE_FLOOR);
  assert.ok(r.fields.country, "a country candidate was proposed");
  assert.equal(r.fields.country.value, "United States");
  assert.ok(r.fields.country.confidence >= ENGINE.CONFIDENCE_FLOOR);
}));

tests.push(t("extractAuthorityDocFields returns null (not a low-confidence guess) on unrelated prose", async () => {
  const r = ENGINE.extractAuthorityDocFields(
    "The quick brown fox jumps over the lazy dog. Lorem ipsum dolor sit amet."
  );
  assert.equal(r.fields.legalName, null);
  assert.equal(r.fields.country, null);
}));

tests.push(t("extractFields never throws on garbage/empty/non-string input and never fabricates", async () => {
  for (const bad of [null, undefined, "", "   ", 42, {}]) {
    const r = ENGINE.extractFields(bad);
    assert.ok(r && typeof r === "object");
    assert.deepEqual(Object.keys(r.fields || {}).filter((k) => r.fields[k] != null), []);
  }
}));

tests.push(t("extractFields routes to the MRZ path for ID text, heuristic path for free text", async () => {
  assert.equal(ENGINE.extractFields(ICAO_TRANSCRIPT).source, "mrz");
  assert.equal(ENGINE.extractFields(authorityDocFixture).source, "heuristic");
}));

// ============================================================================
// REAL ENGINE — structured-text adapter, wired through the EXISTING grm-ocr
// seam contract (GRM_OCR.makeOcrEngine). Reads REAL bytes of a checked-in
// fixture file; honestly refuses images (the pluggable raster boundary).
// ============================================================================
const idMrzFixturePath = new URL("./fixtures/synthetic-id-mrz.txt", import.meta.url);
const idMrzFixtureBytes = readFileSync(idMrzFixturePath, "utf8");

tests.push(t("structured-text adapter reads REAL bytes of a checked-in fixture, verbatim, through the seam", async () => {
  const adapter = ENGINE.makeStructuredTextAdapter();
  const engine = OCR.makeOcrEngine(adapter);
  assert.equal(engine.available, true);
  assert.equal(engine.name, "structured-text");
  const file = new File([idMrzFixtureBytes], "synthetic-id-mrz.txt", { type: "text/plain" });
  const r = await engine.read(file);
  assert.equal(r.manual, false);
  assert.equal(r.text, idMrzFixtureBytes, "the transcript is the ACTUAL file bytes, not a canned string");
  // The real transcript decodes for real through the same MRZ parser tested above.
  const fields = ENGINE.extractIdFields(r.text);
  assert.equal(fields.valid, true);
  assert.equal(fields.fields.documentNumber.value, "L898902C3");
}));

tests.push(t("structured-text adapter HONESTLY REFUSES an image — fails closed, never fabricates pixels-to-text", async () => {
  const adapter = ENGINE.makeStructuredTextAdapter();
  const engine = OCR.makeOcrEngine(adapter);
  const imgFile = new File([new Uint8Array([0x89, 0x50, 0x4e, 0x47])], "authority-doc.png", { type: "image/png" });
  const r = await engine.read(imgFile);
  assert.equal(r.manual, true, "an image handed to a text-only adapter falls back to manual — never a guess");
  assert.equal(r.text, null);
  assert.equal(r.reason, "engine-error");
}));

tests.push(t("structured-text adapter fails closed on no file / unreadable file (no fabrication)", async () => {
  const adapter = ENGINE.makeStructuredTextAdapter();
  const engine = OCR.makeOcrEngine(adapter);
  const r1 = await engine.read(null);
  assert.equal(r1.manual, true); assert.equal(r1.reason, "no-file");
  const r2 = await engine.read({ name: "mystery.bin" }); // no .type, no .text(), no .content
  assert.equal(r2.manual, true); assert.equal(r2.reason, "engine-error");
}));

// ============================================================================
// REAL ENGINE — MRZ date semantics: calendar validity + expiry, fail-closed
// ============================================================================
// The ICAO 9303 date field is a bare 6-digit YYMMDD with no century and no
// check that the digits form a REAL date. A check digit only proves the digits
// arrived intact; "749913" (month 99) or "740230" (Feb 30) can pass their own
// check digit yet be calendar-impossible. parseYyMmDd is the shared TD1/TD2/TD3
// date primitive; these tests pin (a) valid, (b) boundary, (c) invalid-calendar
// rejection, and (d) expiry against the SYNTHETIC ICAO worked example.

// ---- (a) valid + (b) boundary dates round-trip ----------------------------
tests.push(t("parseYyMmDd accepts valid + boundary dates (incl. Feb-29, Dec-31, month/day edges)", async () => {
  assert.deepEqual(ENGINE.parseYyMmDd("740812"), { yy: "74", mm: "08", dd: "12" }); // ICAO DOB
  assert.deepEqual(ENGINE.parseYyMmDd("120415"), { yy: "12", mm: "04", dd: "15" }); // ICAO expiry
  assert.deepEqual(ENGINE.parseYyMmDd("000101"), { yy: "00", mm: "01", dd: "01" }); // Jan 1 boundary
  assert.deepEqual(ENGINE.parseYyMmDd("991231"), { yy: "99", mm: "12", dd: "31" }); // Dec 31 boundary
  assert.deepEqual(ENGINE.parseYyMmDd("000229"), { yy: "00", mm: "02", dd: "29" }); // Feb 29 (real in leap yrs)
  assert.deepEqual(ENGINE.parseYyMmDd("040430"), { yy: "04", mm: "04", dd: "30" }); // Apr 30 boundary
}));

// ---- (c) impossible calendar dates are REJECTED (fail-closed -> null) ------
tests.push(t("parseYyMmDd rejects impossible dates (mm>12, mm=00, dd>31, dd=00, Feb 30, Apr 31)", async () => {
  assert.equal(ENGINE.parseYyMmDd("741312"), null); // month 13
  assert.equal(ENGINE.parseYyMmDd("749912"), null); // month 99
  assert.equal(ENGINE.parseYyMmDd("740012"), null); // month 00
  assert.equal(ENGINE.parseYyMmDd("740832"), null); // day 32
  assert.equal(ENGINE.parseYyMmDd("740800"), null); // day 00
  assert.equal(ENGINE.parseYyMmDd("740230"), null); // Feb 30 — never exists
  assert.equal(ENGINE.parseYyMmDd("740431"), null); // Apr 31 — Apr has 30
  assert.equal(ENGINE.parseYyMmDd("740631"), null); // Jun 31
  assert.equal(ENGINE.parseYyMmDd("74081"), null);  // wrong length
  assert.equal(ENGINE.parseYyMmDd("7408AB"), null); // non-numeric
}));

// ---- (c') century-aware strict check catches Feb-29 in a NON-leap year -----
tests.push(t("resolveMrzYear rejects Feb-29 in a non-leap resolved year, accepts it in a leap year", async () => {
  // 2000 is a leap year (÷400); 2100 is NOT (÷100 but not ÷400); 2013 is not.
  assert.ok(ENGINE.resolveMrzYear({ yy: "00", mm: "02", dd: "29" }, 2000)); // 2000-02-29 exists
  assert.equal(ENGINE.resolveMrzYear({ yy: "13", mm: "02", dd: "29" }, 2000), null); // 2013-02-29 does not
  assert.equal(ENGINE.resolveMrzYear({ yy: "00", mm: "02", dd: "29" }, 2100), null); // 2100-02-29 does not
}));

// ---- (c'') a checksum-VALID but calendar-garbage date fails the block closed
tests.push(t("a checksum-valid MRZ whose date is calendar-impossible fails the WHOLE block closed", async () => {
  // Craft line2 with an impossible date-of-birth month (13) but a CORRECT
  // check digit for those very digits, so only the calendar rule can catch it.
  const badDob = "741399"; // month 13, day 99 — impossible, but digits are self-consistent
  const dobCheck = ENGINE.mrzCheckDigit(badDob); // matches the bad digits
  // Rebuild line2 around the ICAO example: [0..13)=docnum(+chk)+nat, [13..19)=dob,
  // [19]=dobCheck, then the rest unchanged. Composite will also move, so recompute it.
  let l2 = ICAO_LINE2.slice(0, 13) + badDob + dobCheck + ICAO_LINE2.slice(20);
  const compositeInput = l2.slice(0, 10) + l2.slice(13, 20) + l2.slice(21, 28) + l2.slice(28, 43);
  l2 = l2.slice(0, 43) + ENGINE.mrzCheckDigit(compositeInput);
  const mrz = ENGINE.parseTd3(ICAO_LINE1, l2);
  assert.equal(mrz.checks.dob, true, "the date-of-birth CHECK DIGIT itself is satisfied");
  assert.equal(mrz.checks.composite, true, "and the composite check digit is satisfied");
  assert.equal(mrz.dateOfBirth, null, "but the date is calendar-impossible -> parsed as null");
  assert.equal(mrz.datesValid, false, "so datesValid is false");
  assert.equal(mrz.valid, false, "fail-closed: a calendar-impossible date invalidates the block");
}));

// ---- (d) expiry: the SYNTHETIC ICAO example (expires 2012-04-15) -----------
tests.push(t("parseTd3 flags expired:true when asOf is AFTER the date-of-expiry (ICAO example, exp 2012-04-15)", async () => {
  // No asOf -> expiry is NOT evaluated (deterministic; no hidden clock).
  const noRef = ENGINE.parseTd3(ICAO_LINE1, ICAO_LINE2);
  assert.equal(noRef.valid, true, "structurally valid regardless of expiry");
  assert.equal(noRef.expired, null, "expired not evaluated without a reference time");

  // asOf strictly AFTER 2012-04-15 -> expired.
  const later = ENGINE.parseTd3(ICAO_LINE1, ICAO_LINE2, { asOf: "2026-07-17T00:00:00Z" });
  assert.equal(later.expired, true);
  assert.equal(later.valid, true, "expiry is orthogonal to structural validity");

  // asOf BEFORE 2012-04-15 -> not expired.
  const earlier = ENGINE.parseTd3(ICAO_LINE1, ICAO_LINE2, { asOf: "2010-01-01T00:00:00Z" });
  assert.equal(earlier.expired, false);

  // Boundary: valid THROUGH the whole expiry day; expired strictly after it.
  const onDay = ENGINE.parseTd3(ICAO_LINE1, ICAO_LINE2, { asOf: "2012-04-15T23:00:00Z" });
  assert.equal(onDay.expired, false, "still valid on the expiry day itself");
  const nextDay = ENGINE.parseTd3(ICAO_LINE1, ICAO_LINE2, { asOf: "2012-04-16T00:00:00Z" });
  assert.equal(nextDay.expired, true, "expired the day after");
}));

// ---- (d') an expired document earns NO field credit (=> no LoA lift) -------
tests.push(t("extractIdFields: an EXPIRED MRZ yields NO trusted fields (no LoA credit); an unexpired one does", async () => {
  // Unexpired (asOf before expiry): full confidence-1 fields, as before.
  const live = ENGINE.extractIdFields(ICAO_TRANSCRIPT, { asOf: "2010-01-01T00:00:00Z" });
  assert.equal(live.valid, true);
  assert.equal(live.expired, false);
  assert.equal(live.fields.documentNumber.value, "L898902C3");

  // Expired (asOf after expiry): valid:false, expired:true, EMPTY fields.
  const dead = ENGINE.extractIdFields(ICAO_TRANSCRIPT, { asOf: "2026-07-17T00:00:00Z" });
  assert.equal(dead.valid, false);
  assert.equal(dead.expired, true);
  assert.deepEqual(dead.fields, {}, "an expired document trusts NOTHING — no field survives to lift LoA");

  // And the "no LoA credit" is concrete downstream: an on-device read that did
  // not yield a validated match leaves LoA at 0 (mirrors the read!=authority
  // invariant already pinned above).
  const expiredOcrOutcome = { onDevice: true, match: false, fieldsMatched: [] };
  assert.equal(G.computeLoa({ selfDeclared: true, dnbVerified: true, ocr: expiredOcrOutcome }).loa, 0);
}));

// ---- TD1/TD2 equivalence: the SAME date primitive validates their fields ---
tests.push(t("parseYyMmDd is the shared TD1/TD2/TD3 date validator (identical YYMMDD field encoding)", async () => {
  // A TD1 (ID-1) line2 encodes birth date at [0..6) and expiry at [8..14); a
  // TD2 (ID-2) line2 encodes birth date at [0..6) and expiry at [8..14) too —
  // both are the exact same 6-digit YYMMDD slice this primitive validates. We
  // do not yet ship full TD1/TD2 structural parsers, but their date fields are
  // byte-identical, so calendar validity is proven here once for all three.
  const td1Line2 = "7408122F1204159UTO<<<<<<<<<<<6"; // ...DOB=740812, EXP=120415...
  assert.deepEqual(ENGINE.parseYyMmDd(td1Line2.slice(0, 6)), { yy: "74", mm: "08", dd: "12" });
  assert.deepEqual(ENGINE.parseYyMmDd(td1Line2.slice(8, 14)), { yy: "12", mm: "04", dd: "15" });
  // And the impossible-date rejection holds identically on a TD2-shaped slice.
  const td2BadExpiry = "6001019M99131<UTO"; // expiry slice "991313" -> month 99, impossible
  assert.equal(ENGINE.parseYyMmDd("991313"), null);
  assert.equal(ENGINE.parseYyMmDd(td2BadExpiry.slice(8, 14)), null);
}));

await Promise.all(tests);
console.log(`\nGRAMOTA ocr-engine seam: ${passed} checks passed`);
