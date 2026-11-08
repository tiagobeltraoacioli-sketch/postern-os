"use strict";
/* ============================================================================
   UI/store parity check for the Postern Android Gate.

   index.html inlines a LOGIC-IDENTICAL COPY of gate-store.mjs so the browser
   can run the same toggle-state rules with no build step and no imports (the
   gate ships with CSP connect-src 'none' — no bundler, no <script src>). The
   inline copy is deliberately condensed (different variable layout, a
   different — but behaviourally equivalent — options-destructuring style in
   containerAllowed()), so it is NOT byte-identical to gate-store.mjs. What
   this file proves, mechanically, is that it is BEHAVIOURALLY identical:

     1. it extracts the inline block straight out of index.html (between the
        "INLINED, LOGIC-IDENTICAL COPY" and "Persistence + UI wiring" markers)
        so the check runs against exactly what ships in the browser, not a
        hand-copied stand-in;
     2. it evaluates that block in node with `new Function` (no eval of the
        rest of the page, no DOM, no localStorage);
     3. it runs both the inline copy and the canonical gate-store.mjs module
        against the same hostile-input corpus and the same
        consent/kill-switch/tor/bridge truth table and asserts identical
        results at every point.

   If the inline copy and gate-store.mjs ever drift — a fixed default changed
   in one but not the other, a rail loosened in one but not the other — this
   file fails loudly (and exit 1s) instead of silently going stale. It does
   NOT test the (non-existent) on-device Waydroid wrapper; that stays
   UNTESTED until the hardware harness exists (see gate-store.mjs).
   Dependency-free: only node:assert, node:fs, node:path, node:url. No DOM.
   Run: node test-ui-parity.mjs
   ============================================================================ */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import S from "./gate-store.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const htmlPath = path.join(__dirname, "index.html");
const html = readFileSync(htmlPath, "utf8");

/* ---- 1. extract the inline logic block from index.html ------------------- */

const scriptMatch = html.match(/<script>([\s\S]*?)<\/script>/);
assert.ok(scriptMatch, "could not find a <script>...</script> block in index.html");
const scriptBody = scriptMatch[1];

const START_MARKER = "INLINED, LOGIC-IDENTICAL COPY";
const END_MARKER = "Persistence + UI wiring";

const startMarkerIdx = scriptBody.indexOf(START_MARKER);
const endMarkerIdx = scriptBody.indexOf(END_MARKER);
assert.ok(startMarkerIdx !== -1, `could not find "${START_MARKER}" marker in index.html <script>`);
assert.ok(endMarkerIdx !== -1, `could not find "${END_MARKER}" marker in index.html <script>`);
assert.ok(endMarkerIdx > startMarkerIdx, "markers are out of order in index.html <script>");

// The inline code starts right after the "*/" that closes the comment block
// containing START_MARKER...
const codeStart = scriptBody.indexOf("*/", startMarkerIdx) + 2;
// ...and ends right before the "/*" that opens the comment block containing
// END_MARKER (i.e. it excludes the "Persistence + UI wiring" section itself).
const codeEnd = scriptBody.lastIndexOf("/*", endMarkerIdx);
assert.ok(codeStart > 1, "failed to locate the end of the INLINED-COPY comment header");
assert.ok(codeEnd > codeStart, "failed to locate the start of the Persistence-wiring comment header");

const inlineSrc = scriptBody.slice(codeStart, codeEnd);
assert.ok(inlineSrc.includes("function normalize"), "extracted block does not look like the inline store logic");

/* ---- 2. evaluate the extracted block in node, no DOM ---------------------- */

const EXPORTED = [
  "defaultState", "normalize", "parse", "serialize",
  "containerAllowed", "activeBridges", "egressAllowed", "BRIDGE_KEYS",
];

let UI;
try {
  const build = new Function(`"use strict";\n${inlineSrc}\nreturn { ${EXPORTED.join(", ")} };`);
  UI = build();
} catch (err) {
  throw new Error(`extracted inline block failed to evaluate: ${err.message}`);
}
for (const key of EXPORTED) {
  assert.ok(typeof UI[key] !== "undefined", `extracted inline block did not define '${key}'`);
}

/* ---- 3. behavioural parity assertions ------------------------------------- */

let pass = 0, fail = 0;
const ok = (name, cond) => {
  if (cond) { pass++; } else { fail++; console.error("FAIL:", name); }
};
const deepOk = (name, a, b) => {
  try {
    assert.deepStrictEqual(a, b);
    pass++;
  } catch (err) {
    fail++;
    console.error("FAIL:", name);
    console.error("  gate-store:", JSON.stringify(a));
    console.error("  inline    :", JSON.stringify(b));
  }
};

// -- defaultState() -----------------------------------------------------
deepOk("defaultState() parity", S.defaultState(), UI.defaultState());

// -- normalize() over a hostile corpus -----------------------------------
const HOSTILE_CORPUS = [
  null,
  undefined,
  "nope",
  42,
  [],
  {},
  { bridges: { mic: 1 } },                                      // truthy-not-true bridge (number)
  { bridges: { mic: "true" } },                                 // truthy-not-true bridge (string)
  { bridges: { clipboard: true, mic: 1, camera: [] } },         // mixed valid + invalid bridges
  { tier: "attested" },                                         // hostile tier relabel — never survives normalize()
  { schema: "evil", version: 999 },                             // schema/version override attempt
  { egress: { torOnly: false } },                               // egress downgrade attempt
  { egress: { torOnly: false, torBootstrapped: true } },        // downgrade + bootstrapped together
  { egress: { torBootstrapped: 1 } },                           // truthy-not-true torBootstrapped
  { egress: { torBootstrapped: "true" } },                      // truthy-not-true torBootstrapped (string)
  { consent: { accepted: true, scope: "forever" } },            // bad/unknown scope
  { consent: { accepted: "yes" } },                             // truthy-not-true consent
  { consent: null, bridges: null, egress: null, killSwitch: null }, // null sub-objects
  { killSwitch: { engaged: "yes" } },                           // truthy-not-true kill-switch
  { lang: "fr" },                                               // unsupported lang
  {
    consent: { accepted: true, scope: "persistent", acceptedAtIso: "2026-01-01T00:00:00Z" },
    bridges: { clipboard: true, files: true, mic: true, camera: true, location: true },
    egress: { torOnly: true, torBootstrapped: true },
    killSwitch: { engaged: false },
    lang: "pt-BR",
  },
];

for (const input of HOSTILE_CORPUS) {
  const label = `normalize(${JSON.stringify(input)})`;
  deepOk(label, S.normalize(input), UI.normalize(input));
}

// -- parse() over corrupt/valid JSON text --------------------------------
const PARSE_CORPUS = [
  "{not json",
  "",
  "null",
  "42",
  '"nope"',
  JSON.stringify({ tier: "attested" }),                         // hostile relabel text — refused (tier stays pinned)
  JSON.stringify({ consent: { accepted: true }, bridges: { mic: true } }),
];
for (const text of PARSE_CORPUS) {
  deepOk(`parse(${JSON.stringify(text)})`, S.parse(text), UI.parse(text));
}

// -- containerAllowed / activeBridges / egressAllowed truth table -------
const BOOLS = [true, false];
const OPTS_VARIANTS = [undefined, {}, { requireConsent: false }, { requireConsent: true }];
const BRIDGE_SUBSETS = [
  { clipboard: false, files: false, mic: false, camera: false, location: false },
  { clipboard: true, files: false, mic: false, camera: false, location: false },
  { clipboard: true, files: true, mic: true, camera: true, location: true },
  { clipboard: false, files: true, mic: false, camera: true, location: false },
];

let tableCases = 0;
for (const consentAccepted of BOOLS) {
  for (const killEngaged of BOOLS) {
    for (const torBootstrapped of BOOLS) {
      for (const bridges of BRIDGE_SUBSETS) {
        for (const opts of OPTS_VARIANTS) {
          const state = {
            consent: { accepted: consentAccepted, scope: "session" },
            bridges,
            egress: { torOnly: true, torBootstrapped },
            killSwitch: { engaged: killEngaged },
          };
          const label = `truth-table consent=${consentAccepted} kill=${killEngaged} tor=${torBootstrapped} bridges=${JSON.stringify(bridges)} opts=${JSON.stringify(opts)}`;
          tableCases++;
          ok(`containerAllowed ${label}`, S.containerAllowed(state, opts) === UI.containerAllowed(state, opts));
          deepOk(`activeBridges ${label}`, S.activeBridges(state, opts), UI.activeBridges(state, opts));
          ok(`egressAllowed ${label}`, S.egressAllowed(state, opts) === UI.egressAllowed(state, opts));
        }
      }
    }
  }
}
ok("truth table actually ran cases", tableCases > 0);

// -- serialize() round-trip equality -------------------------------------
const SERIALIZE_STATES = [
  S.defaultState(),
  { consent: { accepted: true }, bridges: { mic: true } },
  { tier: "attested", egress: { torOnly: false, torBootstrapped: 1 } }, // hostile input
];
for (const state of SERIALIZE_STATES) {
  const label = `serialize(${JSON.stringify(state)})`;
  const a = S.serialize(state);
  const b = UI.serialize(state);
  ok(`${label} byte-equal string`, a === b);
  deepOk(`${label} round-trip parity`, S.parse(a), UI.parse(b));
}

console.log(`test-ui-parity: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
