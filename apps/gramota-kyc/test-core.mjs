// SPDX-License-Identifier: MIT OR Apache-2.0
// GRAMOTA core tests — run with: node test-core.mjs   (Node >= 18)
// Extracts the DOM-free <script id="grm-core"> block from index.html and exercises
// the fail-closed validators. The invariant pinned here: an unmatched field earns
// NO assurance credit, and a document read never lifts LoA on its own — a document
// read is not proof of authority.
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";

const html = readFileSync(new URL("./index.html", import.meta.url), "utf8");
const m = html.match(/<script id="grm-core">([\s\S]*?)<\/script>/);
assert.ok(m, "grm-core script block found");
(0, eval)(m[1]);
const G = globalThis.GRM;
assert.ok(G && typeof G.validateOcrAgainstEntity === "function", "GRM core loaded");

let passed = 0;
const t = (name, fn) => { fn(); passed++; console.log("  ok — " + name); };

// ---- normalizers ----------------------------------------------------------
t("legal-name normalize strips suffix + punctuation + case", () => {
  assert.equal(G.normalizeLegalName("ACME Widgets, Inc."), "acme widgets");
  assert.equal(G.normalizeLegalName("Açaí Comércio LTDA"), "acai comercio");
  assert.equal(G.normalizeLegalName("Smith & Sons Co."), "smith and sons");
});
t("country normalize maps names + alpha-2, unknown => '' (fail-closed)", () => {
  assert.equal(G.normalizeCountry("United States"), "US");
  assert.equal(G.normalizeCountry("Brasil"), "BR");
  assert.equal(G.normalizeCountry("us"), "US");
  assert.equal(G.normalizeCountry("Ruritania"), ""); // unknown -> no match downstream
});

// ---- matchField -----------------------------------------------------------
t("legal-name matches across suffix/case/diacritics", () => {
  assert.equal(G.matchField("legalName", "ACME WIDGETS INC", "Acme Widgets, LLC").matched, true);
});
t("legal-name mismatch does not match", () => {
  assert.equal(G.matchField("legalName", "Globex Corporation", "Acme Widgets Inc").matched, false);
});
t("country exact-after-normalize; mismatch fails", () => {
  assert.equal(G.matchField("country", "United States", "US").matched, true);
  assert.equal(G.matchField("country", "Brazil", "US").matched, false);
});
t("missing side => no match (fail-closed)", () => {
  assert.equal(G.matchField("legalName", "", "Acme Inc").matched, false);
  assert.equal(G.matchField("country", "US", "").matched, false);
});
t("officer name matches on token set (middle name / order tolerant)", () => {
  assert.equal(G.matchField("officer", "Maria A. Silva", "Maria Silva").matched, true);
  assert.equal(G.matchField("officer", "John Smith", "Robert Brown").matched, false);
});

// ---- validateOcrAgainstEntity: fail-closed --------------------------------
t("all required fields match => requiredMatched true, fields listed", () => {
  const v = G.validateOcrAgainstEntity(
    { legalName: "Acme Widgets Inc", country: "United States", officerName: "Jane Doe" },
    { legalName: "Acme Widgets, LLC", country: "US", principals: ["Jane Doe"] });
  assert.equal(v.requiredMatched, true);
  assert.deepEqual(v.fieldsMatched.sort(), ["country", "legalName", "officer"]);
});
t("country mismatch => requiredMatched false; only legalName credited", () => {
  const v = G.validateOcrAgainstEntity(
    { legalName: "Acme Widgets Inc", country: "Brazil" },
    { legalName: "Acme Widgets LLC", country: "US" });
  assert.equal(v.requiredMatched, false);
  assert.deepEqual(v.fieldsMatched, ["legalName"]);
});
t("entity name mismatch => no legalName credit (anti-abuse of another DUNS)", () => {
  const v = G.validateOcrAgainstEntity(
    { legalName: "Totally Different Co", country: "US" },
    { legalName: "Acme Widgets LLC", country: "US" });
  assert.equal(v.fieldsMatched.includes("legalName"), false);
  assert.equal(v.requiredMatched, false);
});

// ---- buildOcrVerdict: minimal + PII-free ----------------------------------
t("verdict carries booleans + field NAMES only (no values)", () => {
  const v = G.validateOcrAgainstEntity(
    { legalName: "Acme Widgets Inc", country: "US" },
    { legalName: "Acme Widgets LLC", country: "US" });
  const out = G.buildOcrVerdict(v, { liveness: false });
  assert.deepEqual(Object.keys(out).sort(), ["fieldsMatched", "liveness", "match", "onDevice"]);
  assert.equal(out.onDevice, true);
  assert.equal(out.match, true);
  // no value strings — only allowed field names
  out.fieldsMatched.forEach((f) => assert.ok(["legalName", "country", "officer"].includes(f)));
});

// ---- computeLoa: faithful, fail-closed table ------------------------------
t("self-declared only => LoA 0 (parity)", () => {
  assert.equal(G.computeLoa({ selfDeclared: true, dnbVerified: true }).loa, 0);
});
t("on-device OCR validated ALONE does not lift LoA (doc read != proof)", () => {
  const ocr = { onDevice: true, match: true, fieldsMatched: ["legalName", "country"], liveness: false };
  assert.equal(G.computeLoa({ selfDeclared: true, dnbVerified: true, ocr }).loa, 0);
});
t("domain proof => LoA 1; + OCR validated => LoA 2", () => {
  const ocr = { onDevice: true, match: true, fieldsMatched: ["legalName", "country"] };
  assert.equal(G.computeLoa({ corpDomain: true }).loa, 1);
  assert.equal(G.computeLoa({ corpDomain: true, ocr }).loa, 2);
  assert.equal(G.computeLoa({ corpDomain: true, principalMatch: true }).loa, 2);
});
t("OCR validated + liveness => LoA 3; IDV pass => LoA 3", () => {
  const ocr = { onDevice: true, match: true, fieldsMatched: ["legalName", "country"] };
  assert.equal(G.computeLoa({ ocr, liveness: true }).loa, 3);
  assert.equal(G.computeLoa({ idvPass: true }).loa, 3);
});
t("OCR with a missing required field is NOT validated => no lift", () => {
  const ocr = { onDevice: true, match: false, fieldsMatched: ["legalName"], liveness: true };
  assert.equal(G.computeLoa({ corpDomain: true, ocr, liveness: true }).loa, 1);
});

console.log("\n" + passed + " passed");
