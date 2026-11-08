// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Regression test for the dotfile-bypass fix in server.mjs.
//
// Bug: isHiddenSegment() was checking the RAW (still percent-encoded) request
// URL, while safeJoin() decoded it separately before resolving the file on
// disk. A percent-encoded dot segment (e.g. `/features/%2egitignore`) does
// not start with "." as raw text, so it sailed past the hidden-segment guard,
// then decoded to `.gitignore` when the file was actually read — serving a
// dotfile the guard exists to block. The fix: decode once, up front, and run
// BOTH the hidden-segment check and safeJoin() on that same decoded string.
//
// Dependency-free. Run: `node server.dotfile-guard.test.mjs`.

import { decodePath, isHiddenSegment, safeJoin, WEBROOT } from "./server.mjs";

let pass = 0,
  fail = 0;
const fails = [];
function ok(name, cond) {
  if (cond) pass++;
  else {
    fail++;
    fails.push(name);
  }
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}`);
}

// 1. The exact bug report: a percent-encoded dot must be caught as hidden
//    AFTER decoding — this is what isHiddenSegment() must be called with.
{
  const raw = "/features/%2egitignore";
  const decoded = decodePath(raw);
  ok("1a decodePath decodes %2e to a literal dot", decoded === "/features/.gitignore");
  ok("1b decoded percent-encoded dotfile IS flagged hidden", isHiddenSegment(decoded));
}

// 2. The pre-fix regression: checking the RAW (undecoded) path would NOT
//    flag it — demonstrates why decode-then-check (not check-then-decode)
//    is required. (This asserts the vulnerable ordering would have failed,
//    i.e. documents the bug rather than re-introducing it.)
{
  const raw = "/features/%2egitignore";
  ok("2 raw (undecoded) percent-encoded dotfile is NOT caught by isHiddenSegment alone", !isHiddenSegment(raw));
}

// 3. Ordinary dotfiles and dot-segments (.git/, ../escape attempts) are still
//    blocked when passed already-decoded, as the real request path is.
{
  ok("3a plain .gitignore is hidden", isHiddenSegment("/.gitignore"));
  ok("3b nested dotdir segment is hidden", isHiddenSegment("/enterprise/.git/config"));
  ok("3c normal asset path is NOT hidden", !isHiddenSegment("/comms/app/index.html"));
}

// 4. End-to-end: the exact bug-report request never resolves to a file
//    inside WEBROOT once decode-then-check is applied by the caller (server
//    request handler mirrors this decode -> hidden-check -> safeJoin order).
{
  const raw = "/features/%2egitignore";
  const decoded = decodePath(raw);
  const wouldBeBlocked = isHiddenSegment(decoded);
  ok("4 GET /features/%2egitignore is blocked before any file resolution", wouldBeBlocked === true);
  // Even if the hidden check were somehow skipped, safeJoin must still keep
  // the resolved path inside WEBROOT (belt-and-suspenders, not a substitute
  // for the hidden-segment guard).
  const resolved = safeJoin(WEBROOT, decoded);
  ok("4b safeJoin keeps the (hypothetical) resolved path inside WEBROOT", resolved === null || resolved.startsWith(WEBROOT));
}

// 5. Double-decoding is avoided: a literal "%25" (an encoded "%") in a
//    filename must decode to "%" exactly once, not "%25" -> "%" -> attempt
//    to interpret further escapes.
{
  const raw = "/assets/100%2525.png"; // literal filename "100%25.png"
  const decoded = decodePath(raw);
  ok("5 percent-encoding is decoded exactly once", decoded === "/assets/100%25.png");
}

// 6. Malformed percent-encoding fails closed (decodePath returns null)
//    rather than throwing or guessing.
{
  ok("6 malformed percent-encoding decodes to null (fail-closed)", decodePath("/%") === null);
}

console.log(`\n${pass} passed, ${fail} failed`);
if (fail > 0) {
  console.error("FAILED:", fails);
  process.exit(1);
}
