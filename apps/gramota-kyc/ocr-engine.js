// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// GRAMOTA on-device OCR ENGINE — the REAL layer that plugs behind the honest
// <script id="grm-ocr"> seam in index.html (GRM_OCR.makeOcrEngine). Reference
// prototype / UNAUDITED. This file does not change the seam's contract; it adds
// a real, deterministic capability an adapter or the UI can call *through* it.
//
// ============================================================================
// WHAT IS REAL HERE (genuine, deterministic, checksum-verified — not a stub):
// ============================================================================
//   1. A full ICAO 9303 Machine-Readable-Zone (MRZ) parser + check-digit
//      verifier for the TD3 (passport) format. Given TEXT (however it was
//      obtained — typed, pasted, or the output of a real pixel-recognition
//      engine), it decodes document number, nationality, date of birth, sex,
//      date of expiry, and name, and cryptographically-style validates EVERY
//      check digit (weights 7/3/1 mod 10, ICAO 9303 Part 4 / Part 3 §4.9)
//      *plus* the composite check digit. This is the same algorithm every
//      real passport reader implements — verified in ocr-engine.test.mjs
//      against the canonical published ICAO worked example (not a stub value).
//      A single wrong digit fails the whole block CLOSED (`valid:false`);
//      nothing downstream is trusted from a block that doesn't check out.
//   2. A structured-text adapter (`makeStructuredTextAdapter`) that reads the
//      REAL bytes of a text-bearing File/Blob (text/plain, .txt, .mrz) via the
//      standard `Blob.text()` API and plugs directly into the EXISTING
//      `GRM_OCR.makeOcrEngine()` seam contract (`{name, read(file)}`) — a
//      genuine adapter that reads real file bytes, not a canned string.
//   3. A fail-closed heuristic extractor for the free-text authority document
//      (articles of incorporation / board resolution) that proposes a
//      legalName/country candidate ONLY when its confidence clears a floor
//      (`CONFIDENCE_FLOOR`); below the floor it returns `null`, never a
//      guessed value silently presented as a read. The KYC UI's existing
//      "review & correct every field" step (index.html step 2) is exactly
//      where a human closes any remaining gap — this module never removes
//      that step, it only replaces the previous naive `firstLine()` guess
//      with a scored, floor-gated one.
//
// ============================================================================
// WHAT IS DELIBERATELY NOT HERE — THE PLUGGABLE ENGINE BOUNDARY (labeled, not
// faked):
// ============================================================================
//   Raster (pixel-to-text) recognition of a PHOTOGRAPH of a document — i.e.
//   actual optical character recognition of image bytes — is NOT implemented
//   in this file. Doing that for real requires either a trained OCR model
//   (Tesseract WASM + several MB of language data) or heavy native/ML
//   dependencies — not feasible HOST-side without heavy deps for this seam.
//   Faking it (returning plausible-looking text for an image nothing here
//   ever actually looked at) would be a FORGED read, not a real one — exactly
//   the honesty invariant this seam exists to protect (see ocr-engine.test.mjs
//   header, and grm-ocr's own comments in index.html). So: an image (image/*)
//   handed to `makeStructuredTextAdapter` is honestly refused — it throws,
//   which the existing seam's `read()` wrapper turns into a fail-closed
//   "engine-error" -> manual entry, exactly like any other adapter failure.
//   Nothing is fabricated. The documented path for raster images stays what
//   it always was: plug in a REAL pixel-recognition engine as
//   `window.Tesseract` / `window.PosternOcr` (self-hosted, on-device, never
//   bundled here) — and this module's field-extraction layer (`extractFields`)
//   runs on ITS output text exactly the same way it runs on structured-text
//   input. That boundary is the pluggable seam; this file does not pretend to
//   close it with fabricated pixels-to-text magic.
//
// SYNTHETIC test fixtures used by ocr-engine.test.mjs (including the
// well-known ICAO 9303 published worked example, which is a textbook
// reference vector — not any real person's document) are clearly labeled
// SYNTHETIC. Nothing in this module or its tests claims a real government
// document was read or verified.

"use strict";

(function (root, factory) {
  var mod = factory();
  if (typeof module === "object" && module && module.exports) module.exports = mod;
  if (root) root.GRM_OCR_ENGINE = mod;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  // ==========================================================================
  // ICAO 9303 check-digit primitive (real algorithm, weights 7/3/1 mod 10)
  // ==========================================================================
  var WEIGHTS = [7, 3, 1];
  function charValue(c) {
    if (c >= "0" && c <= "9") return c.charCodeAt(0) - 48;
    if (c >= "A" && c <= "Z") return c.charCodeAt(0) - 55; // A=10 .. Z=35
    if (c === "<") return 0;
    return null; // invalid MRZ character -> cannot score, fail closed
  }
  function mrzCheckDigit(field) {
    var sum = 0;
    for (var i = 0; i < field.length; i++) {
      var v = charValue(field[i]);
      if (v === null) return null;
      sum += v * WEIGHTS[i % 3];
    }
    return String(sum % 10);
  }
  // A field that is entirely filler ('<') and whose printed check digit is
  // also '<' is a documented real-world convention for "unused optional
  // field" (some issuers skip computing a check digit for an empty personal-
  // number field). Anywhere else, the digit must match exactly.
  function checkDigitOk(field, digit) {
    if (field.replace(/</g, "").length === 0 && digit === "<") return true;
    var expect = mrzCheckDigit(field);
    return expect !== null && expect === digit;
  }

  // ==========================================================================
  // TD3 (passport, 2 lines x 44 chars) parser — the most common cross-border
  // government photo-ID format the KYC flow's step 2 asks for.
  // ==========================================================================
  // --------------------------------------------------------------------------
  // MRZ date semantics (ICAO 9303 §3 / §4 — the SAME 6-digit YYMMDD field
  // encoding is used by TD1, TD2 AND TD3, so this primitive is the shared
  // TD1/TD2/TD3 date validator; the TD1/TD2 structural parsers are not yet
  // implemented here, but their date fields are byte-for-byte the same YYMMDD
  // slices this function validates — see ocr-engine.test.mjs for the proof).
  //
  // Fail-closed calendar validity. Century is intentionally NOT known from a
  // bare MRZ date, so the max-day table is the century-agnostic ceiling: Feb
  // caps at 29 (a real day in leap years — it cannot be disproven without a
  // century and is therefore NOT rejected here; the century-aware strict check
  // in `resolveMrzYear` rejects a genuine Feb-29-in-a-non-leap-year once a
  // concrete year is resolved for expiry). Everything genuinely impossible for
  // ANY century — mm<1, mm>12, dd<1, dd>31, Feb 30/31, Apr/Jun/Sep/Nov 31 — is
  // rejected outright (returns null), so no downstream layer ever trusts a
  // calendar-impossible date.
  // --------------------------------------------------------------------------
  var MONTH_MAX_DAYS = [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  var EXPIRY_CENTURY_BASE = 2000; // in-circulation / recently-expired travel docs

  function parseYyMmDd(s) {
    if (!/^\d{6}$/.test(s)) return null;
    var yy = s.slice(0, 2);
    var mm = s.slice(2, 4);
    var dd = s.slice(4, 6);
    var m = parseInt(mm, 10);
    var d = parseInt(dd, 10);
    if (m < 1 || m > 12) return null; // impossible month (00, 13..99)
    if (d < 1 || d > MONTH_MAX_DAYS[m - 1]) return null; // impossible day for that month
    return { yy: yy, mm: mm, dd: dd };
  }

  // Resolve a validated {yy,mm,dd} to a concrete UTC instant at the END of that
  // calendar day for a KNOWN century base, and re-check strict calendar
  // validity now that the century is fixed (this is what catches Feb 29 in a
  // non-leap year — JS Date would roll it over to Mar 1, which we detect and
  // reject by returning null). Returns a Date, or null if the date does not
  // exist in the resolved year (fail-closed).
  function resolveMrzYear(ymd, centuryBase) {
    if (!ymd) return null;
    var year = centuryBase + parseInt(ymd.yy, 10);
    var m = parseInt(ymd.mm, 10);
    var d = parseInt(ymd.dd, 10);
    var dt = new Date(Date.UTC(year, m - 1, d, 23, 59, 59, 999));
    if (dt.getUTCFullYear() !== year || dt.getUTCMonth() !== m - 1 || dt.getUTCDate() !== d) {
      return null; // rolled over -> non-existent day in this concrete year
    }
    return dt;
  }

  // Coerce a caller-supplied "as-of" reference (Date | epoch-ms | ISO string)
  // to epoch-ms, or null if absent/unparseable. No implicit clock is read here:
  // expiry is only evaluated when the CALLER supplies a reference time, keeping
  // this module purely deterministic (production callers pass `new Date()`).
  function asOfToMs(asOf) {
    if (asOf == null) return null;
    if (asOf instanceof Date) return isNaN(asOf.getTime()) ? null : asOf.getTime();
    if (typeof asOf === "number") return isFinite(asOf) ? asOf : null;
    if (typeof asOf === "string") {
      var t = Date.parse(asOf);
      return isNaN(t) ? null : t;
    }
    return null;
  }
  function parseNameField(raw) {
    var parts = raw.replace(/<+$/, "").split("<<");
    var surname = (parts[0] || "").replace(/</g, " ").trim();
    var given = (parts[1] || "").replace(/</g, " ").trim();
    return { surname: surname, given: given };
  }
  function parseTd3(line1, line2, opts) {
    opts = opts || {};
    if (typeof line1 !== "string" || typeof line2 !== "string") return null;
    if (line1.length !== 44 || line2.length !== 44) return null;
    if (line1[0] !== "P") return null; // passport document code
    if (!/^[A-Z<]{44}$/.test(line1) || !/^[A-Z0-9<]{44}$/.test(line2)) return null;

    var issuingCountry = line1.slice(2, 5).replace(/</g, "");
    var name = parseNameField(line1.slice(5, 44));

    var docNumber = line2.slice(0, 9);
    var docNumberCheck = line2[9];
    var nationality = line2.slice(10, 13).replace(/</g, "");
    var dob = line2.slice(13, 19);
    var dobCheck = line2[19];
    var sex = line2[20];
    var expiry = line2.slice(21, 27);
    var expiryCheck = line2[27];
    var personalNumber = line2.slice(28, 42);
    var personalNumberCheck = line2[42];
    var compositeCheck = line2[43];
    var compositeInput =
      line2.slice(0, 10) + line2.slice(13, 20) + line2.slice(21, 28) + line2.slice(28, 43);

    var checks = {
      docNumber: checkDigitOk(docNumber, docNumberCheck),
      dob: checkDigitOk(dob, dobCheck),
      expiry: checkDigitOk(expiry, expiryCheck),
      personalNumber: checkDigitOk(personalNumber, personalNumberCheck),
      composite: checkDigitOk(compositeInput, compositeCheck),
    };
    // Calendar semantics: a check digit only proves the DIGITS transmitted
    // intact — it says NOTHING about whether "749913" is a real date. So we
    // additionally parse each date field for calendar validity (fail-closed:
    // an impossible date -> null). `datesValid` folds into the gate below so a
    // checksum-valid-but-calendar-garbage date can never be trusted.
    var dobParsed = parseYyMmDd(dob);
    var expiryParsed = parseYyMmDd(expiry);
    var datesValid = dobParsed !== null && expiryParsed !== null;

    // Expiry evaluation is opt-in via a caller-supplied `asOf` (keeps this
    // deterministic — no hidden clock). When supplied, we resolve the expiry
    // to a concrete year (2000+YY, the practical century for a travel document
    // in or recently out of circulation), re-check strict calendar validity
    // for that concrete year, and flag `expired` fail-closed.
    var expired = null; // null = not evaluated (no reference time supplied)
    var asOfMs = asOfToMs(opts.asOf);
    if (asOfMs !== null && expiryParsed !== null) {
      var expiryInstant = resolveMrzYear(expiryParsed, EXPIRY_CENTURY_BASE);
      if (expiryInstant === null) {
        datesValid = false; // e.g. Feb 29 in a non-leap resolved year
      } else {
        // Valid THROUGH the whole expiry day; expired strictly after it.
        expired = asOfMs > expiryInstant.getTime();
      }
    }

    // Fail-closed: the document-number, DOB, expiry, and composite check
    // digits all have to agree, AND every date must be a real calendar date.
    // (personalNumber's own check digit is reported but not gating on its own —
    // real-world issuers are inconsistent about computing it for an optional
    // field; the composite digit already covers the literal bytes of that
    // field, so tampering there still trips `checks.composite`.)
    var allValid =
      checks.docNumber && checks.dob && checks.expiry && checks.composite && datesValid;

    return {
      format: "TD3",
      issuingCountry: issuingCountry,
      nationality: nationality,
      documentNumber: docNumber.replace(/</g, ""),
      surname: name.surname,
      givenNames: name.given,
      sex: sex === "<" ? null : sex,
      dateOfBirth: dobParsed,
      dateOfExpiry: expiryParsed,
      personalNumber: personalNumber.replace(/</g, "") || null,
      checks: checks,
      datesValid: datesValid,
      expired: expired, // true | false | null(not evaluated)
      valid: allValid,
    };
  }

  // Scan raw transcript text for a TD3 MRZ block (two consecutive 44-char
  // lines). Returns null if none found — a document simply not containing an
  // MRZ is not an error, just nothing to extract structurally.
  function extractMrz(text, opts) {
    if (typeof text !== "string") return null;
    var lines = text
      .split(/\r\n|\r|\n/)
      .map(function (l) {
        return l.trim().toUpperCase();
      })
      .filter(function (l) {
        return l.length > 0;
      });
    for (var i = 0; i < lines.length - 1; i++) {
      var td3 = parseTd3(lines[i], lines[i + 1], opts);
      if (td3) return td3;
    }
    return null;
  }

  // ==========================================================================
  // Structured-text adapter: plugs directly into the EXISTING grm-ocr seam
  // contract (`{name, read(file)}` — see GRM_OCR.normalizeAdapter in
  // index.html). Reads REAL bytes of a text-bearing File/Blob. Refuses images
  // outright rather than fabricate a "read" of pixels it never inspected.
  // ==========================================================================
  function looksLikeImage(file) {
    var t = (file && file.type) || "";
    if (t) return /^image\//i.test(t);
    var n = (file && file.name) || "";
    return /\.(png|jpe?g|gif|webp|bmp|heic|heif|tiff?)$/i.test(n);
  }
  function makeStructuredTextAdapter() {
    return {
      name: "structured-text",
      read: async function (file) {
        if (!file) throw new Error("no-file");
        if (looksLikeImage(file)) {
          // Honest refusal: raster pixel recognition is the pluggable
          // boundary this module does not implement (see file header).
          throw new Error(
            "unsupported-raster-format: structured-text adapter does not perform pixel OCR; " +
              "wire a real raster engine (Tesseract etc.) as window.Tesseract / window.PosternOcr"
          );
        }
        if (typeof file.text === "function") return await file.text(); // real File/Blob bytes
        if (typeof file.content === "string") return file.content; // plain test stand-in
        throw new Error("unreadable-file");
      },
    };
  }

  // ==========================================================================
  // Field extraction for the KYC flow — layered ABOVE the raw transcript.
  // Fail-closed on low confidence: below-floor fields come back `null`, never
  // silently proposed as if read with certainty. This is what should replace
  // the UI's previous naive `firstLine(text)` guess (index.html step 2).
  // ==========================================================================
  var CONFIDENCE_FLOOR = 0.6;

  // ID-document path: only trust fields pulled from a checksum-VALID MRZ
  // block. A block that parses but fails its checksums is worse than no
  // block at all (it looks plausible) — so it is reported invalid with EMPTY
  // fields, never partially trusted.
  function extractIdFields(text, opts) {
    var mrz = extractMrz(text, opts);
    if (!mrz) return { source: "none", valid: false, fields: {} };
    // Fail-closed on BOTH a broken block (bad checksum / impossible date) and
    // an EXPIRED document: an expired ID is genuine but no longer confers
    // assurance, so it earns NO field credit (empty fields -> no LoA lift
    // downstream, exactly like an invalid block). Expiry is only asserted when
    // the caller supplied a reference time via opts.asOf; without one, expiry
    // is not evaluated (mrz.expired === null) and only structural validity
    // gates — production callers pass the current date to enforce expiry.
    var expired = mrz.expired === true;
    if (!mrz.valid || expired) {
      return {
        source: "mrz",
        format: mrz.format,
        valid: false,
        expired: expired,
        fields: {},
        raw: mrz,
      };
    }
    var officerName = [mrz.givenNames, mrz.surname].filter(Boolean).join(" ").trim();
    return {
      source: "mrz",
      format: mrz.format,
      valid: true,
      expired: false,
      fields: {
        officerName: officerName ? { value: officerName, confidence: 1 } : null,
        country: mrz.nationality ? { value: mrz.nationality, confidence: 1 } : null,
        documentNumber: mrz.documentNumber ? { value: mrz.documentNumber, confidence: 1 } : null,
      },
      raw: mrz,
    };
  }

  // Free-text authority-document path (articles / board resolution — not a
  // standardized machine-readable format, so extraction is inherently
  // probabilistic). Kept deliberately local/independent from the
  // authoritative validator in <script id="grm-core"> — this is a candidate
  // GUESS for the UI to pre-fill, always subject to G.validateOcrAgainstEntity
  // and human review; it is never itself an assurance verdict.
  var LEGAL_SUFFIX_RE =
    /\b(inc|incorporated|corp|corporation|llc|ltd|limited|llp|gmbh|sa|sas|sarl|srl|spa|plc|bv|nv|pty|kg|sl|lp|pllc|pc)\b\.?/i;
  var COUNTRY_CANDIDATES = [
    "united states",
    "usa",
    "brazil",
    "brasil",
    "united kingdom",
    "germany",
    "france",
    "canada",
    "spain",
    "portugal",
    "netherlands",
    "italy",
    "ireland",
    "australia",
    "india",
    "japan",
    "china",
    "mexico",
    "switzerland",
  ];

  function scoreLegalNameLine(line) {
    var t = String(line || "").trim();
    if (!t || t.length > 120) return 0;
    if (!LEGAL_SUFFIX_RE.test(t)) return 0;
    var letters = t.replace(/[^A-Za-z]/g, "");
    var upperRatio = letters.length ? letters.replace(/[^A-Z]/g, "").length / letters.length : 0;
    var score = 0.55;
    if (upperRatio > 0.9) score += 0.2; // ALL CAPS letterhead-style line
    else if (/^[A-Z]/.test(t)) score += 0.1; // Title-cased
    if (t.split(/\s+/).length <= 8) score += 0.1; // plausible name length, not a sentence
    return Math.min(score, 0.95); // a heuristic alone never claims certainty
  }
  function scoreCountryLine(line) {
    var t = String(line || "").trim();
    var lower = t.toLowerCase();
    if (!lower) return { value: null, score: 0 };
    for (var i = 0; i < COUNTRY_CANDIDATES.length; i++) {
      var c = COUNTRY_CANDIDATES[i];
      if (lower === c) return { value: t, score: 0.9 }; // the whole line is just the country
      if (new RegExp("\\b" + c + "\\b").test(lower)) return { value: t, score: 0.65 }; // embedded in a longer line
    }
    return { value: null, score: 0 };
  }
  function extractAuthorityDocFields(text) {
    if (typeof text !== "string" || !text.trim()) return { fields: { legalName: null, country: null } };
    var lines = text.split(/\r\n|\r|\n/);
    var bestName = { value: null, score: 0 };
    var bestCountry = { value: null, score: 0 };
    lines.forEach(function (line) {
      var s = scoreLegalNameLine(line);
      if (s > bestName.score) bestName = { value: line.trim(), score: s };
      var c = scoreCountryLine(line);
      if (c.score > bestCountry.score) bestCountry = c;
    });
    return {
      fields: {
        legalName:
          bestName.score >= CONFIDENCE_FLOOR
            ? { value: bestName.value, confidence: bestName.score }
            : null,
        country:
          bestCountry.score >= CONFIDENCE_FLOOR
            ? { value: bestCountry.value, confidence: bestCountry.score }
            : null,
      },
    };
  }

  // Unified entry point. Tries the ID-document MRZ path first (checksum-
  // verified, confidence exactly 1 or nothing at all); falls back to the
  // fail-closed authority-document heuristic. Never throws; never fabricates;
  // always safe to call with untrusted/garbage text.
  function extractFields(text, opts) {
    opts = opts || {};
    var id = extractIdFields(text, opts);
    if (id.source === "mrz") return id; // report the ID-document outcome honestly, valid or not
    if (opts.kind === "id") return id; // caller told us this was an ID read; nothing structural found
    return { source: "heuristic", valid: null, fields: extractAuthorityDocFields(text).fields };
  }

  return {
    mrzCheckDigit: mrzCheckDigit,
    parseYyMmDd: parseYyMmDd, // shared TD1/TD2/TD3 date primitive (calendar-valid, fail-closed)
    resolveMrzYear: resolveMrzYear,
    parseTd3: parseTd3,
    extractMrz: extractMrz,
    extractIdFields: extractIdFields,
    extractAuthorityDocFields: extractAuthorityDocFields,
    extractFields: extractFields,
    makeStructuredTextAdapter: makeStructuredTextAdapter,
    CONFIDENCE_FLOOR: CONFIDENCE_FLOOR,
  };
});
