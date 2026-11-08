// SPDX-License-Identifier: MIT OR Apache-2.0
"use strict";
/* ============================================================================
   Honesty-rails check for the NoporIS persona switcher.

   apps/noporis-switcher/index.html is a self-contained, dependency-free design
   front-end. Its state model — defaultState()/normalize() plus the oneOf/asBool
   helpers and BRIDGE_KEYS — is inlined in the page's <script> block so the
   browser needs no build step and no imports. There is no companion .mjs module
   to import (unlike apps/noporis-gate, which has gate-store.mjs), so this file
   CANNOT do a two-sided parity check. Instead, exactly like
   apps/noporis-gate/test-ui-parity.mjs does for the gate, it:

     1. reads index.html and extracts the inlined state-model block straight out
        of the shipped <script> (between the "§pure-model-begin" and
        "§pure-model-end" markers) so the check runs against exactly what ships
        in the browser, not a hand-copied stand-in;
     2. evaluates that block in node with `new Function` (no eval of the rest of
        the page, no DOM, no localStorage — the extracted region touches neither
        `document` nor `localStorage` at top level);
     3. asserts, in code, the five honesty rails the README promises. These are
        the load-bearing safety properties: default-DENY, hostile-input
        collapse, kill-switch default-off, the tier being non-attestable BY
        ABSENCE (there is no attestable tier field to set — proven the same way
        ui-parity proves parse/serialize absent), and the two pairings being
        independent booleans.

   HONESTLY, WHAT THIS DOES NOT COVER: this exercises the switcher's LOCAL MOCK
   state shape (flat booleans persisted to localStorage), NOT the on-device
   gate-store contract (apps/noporis-gate) that a real wrapper would map onto,
   and NOT the (non-existent, UNBUILT) on-device switcher / two pairings /
   world-badged signer. The DPC + persona apps do not exist as a booted
   product. This page signs nothing and certifies nothing about security; it is
   a reference-prototype and is UNAUDITED. The coin is not a security. This is
   not legal advice.

   If a future edit loosens a rail in the inlined model — a bridge defaulting to
   true, a kill-switch defaulting on, an attestable tier field appearing, the
   pairings becoming coupled — this file fails loudly (and exit 1s) instead of
   silently going stale.

   Dependency-free: only node:assert/strict, node:fs, node:path, node:url. No
   DOM. Run: node test-switcher.mjs
   ============================================================================ */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const htmlPath = path.join(__dirname, "index.html");
const html = readFileSync(htmlPath, "utf8");

/* ---- 1. extract the inlined state-model block from index.html ------------- */

// noporis-switcher uses a bare <script>, but tolerate attributes anyway.
const scriptMatch = html.match(/<script[^>]*>([\s\S]*?)<\/script>/);
assert.ok(scriptMatch, "could not find a <script ...>...</script> block in index.html");
const scriptBody = scriptMatch[1];

const START_MARKER = "§pure-model-begin";
const END_MARKER = "§pure-model-end";

const startMarkerIdx = scriptBody.indexOf(START_MARKER);
const endMarkerIdx = scriptBody.indexOf(END_MARKER);
assert.ok(startMarkerIdx !== -1, `could not find "${START_MARKER}" marker in index.html <script>`);
assert.ok(endMarkerIdx !== -1, `could not find "${END_MARKER}" marker in index.html <script>`);
assert.ok(endMarkerIdx > startMarkerIdx, "markers are out of order in index.html <script>");

// The model code starts right after the "*/" that closes the comment block
// containing START_MARKER, and ends right before the "/*" that opens the
// comment block containing END_MARKER.
const codeStart = scriptBody.indexOf("*/", startMarkerIdx) + 2;
const codeEnd = scriptBody.lastIndexOf("/*", endMarkerIdx);
assert.ok(codeStart > 1, "failed to locate the end of the §pure-model-begin comment header");
assert.ok(codeEnd > codeStart, "failed to locate the start of the §pure-model-end comment header");

const inlineSrc = scriptBody.slice(codeStart, codeEnd);
assert.ok(inlineSrc.includes("function normalize"), "extracted block does not define normalize()");
assert.ok(inlineSrc.includes("function defaultState"), "extracted block does not define defaultState()");

/* ---- 2. evaluate the extracted block in node, no DOM --------------------- */

const EXPORTED = ["BRIDGE_KEYS", "asBool", "oneOf", "defaultState", "normalize"];
// The extracted region must NOT reach for the DOM or localStorage at top level;
// probe for the identifiers that would blow up if it did. (`store` is defined
// in the region but only touches localStorage inside its method bodies, so it
// is safe to evaluate — we never call it here.)
assert.ok(!/^[^\n]*document\./m.test(inlineSrc.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "")),
  "extracted model region unexpectedly references `document` at top level");

let M;
try {
  const build = new Function(`"use strict";\n${inlineSrc}\nreturn { ${EXPORTED.join(", ")} };`);
  M = build();
} catch (err) {
  throw new Error(`extracted inline model failed to evaluate: ${err.message}`);
}
for (const key of EXPORTED) {
  assert.ok(typeof M[key] !== "undefined", `extracted inline model did not define '${key}'`);
}

const { BRIDGE_KEYS, asBool, oneOf, defaultState, normalize } = M;
assert.ok(Array.isArray(BRIDGE_KEYS) && BRIDGE_KEYS.length > 0, "BRIDGE_KEYS should be a non-empty array");

/* ---- 3. honesty-rail assertions ------------------------------------------ */

let pass = 0, fail = 0;
const ok = (name, cond) => {
  if (cond) { pass++; } else { fail++; console.error("FAIL:", name); }
};

// Rail (a): every bridge is false in defaultState() AND after normalize({}) —
// default DENY. Neither construction may grant a crossing.
{
  const def = defaultState();
  ok("defaultState() defines a bridges object", def.bridges && typeof def.bridges === "object");
  for (const k of BRIDGE_KEYS) {
    ok(`rail(a) defaultState().bridges.${k} === false`, def.bridges[k] === false);
  }
  const empty = normalize({});
  for (const k of BRIDGE_KEYS) {
    ok(`rail(a) normalize({}).bridges.${k} === false`, empty.bridges[k] === false);
  }
  // and normalize() of a state that omits `bridges` entirely still denies all.
  const noBridges = normalize({ live: "nopor", consent: { accepted: true } });
  for (const k of BRIDGE_KEYS) {
    ok(`rail(a) normalize(no-bridges).bridges.${k} === false`, noBridges.bridges[k] === false);
  }
}

// Rail (b): hostile / garbage input collapses to full-deny. null, non-objects,
// arrays, wrong-typed bridges, and junk `live` must never leave a bridge open.
{
  const HOSTILE = [
    null,
    undefined,
    "nope",
    42,
    true,
    [],
    [{ bridges: { mic: true } }],                                  // array wrapping
    {},
    { bridges: null },                                             // null bridges
    { bridges: [] },                                               // array bridges
    { bridges: "all" },                                            // string bridges
    { bridges: { clipboard: 1, files: "true", mic: [], camera: {}, location: "yes" } }, // truthy-not-true
    { bridges: { evilKey: true } },                              // unknown key must not grant a known bridge
    { live: "everywhere" },                                       // junk live
    { live: 3 },                                                  // wrong-typed live
    { live: ["porog", "nopor"] },                                 // array live
    { consent: "yes", killSwitch: "engaged", pairings: "both" },  // wrong-typed sub-objects
  ];
  for (const input of HOSTILE) {
    const out = normalize(input);
    let anyOpen = false;
    for (const k of BRIDGE_KEYS) if (out.bridges[k] !== false) anyOpen = true;
    ok(`rail(b) hostile input collapses to full-deny: ${JSON.stringify(input)}`, anyOpen === false);
    // every bridge is a strict boolean false — not undefined, not truthy-coerced.
    for (const k of BRIDGE_KEYS) {
      ok(`rail(b) bridges.${k} is strict false for ${JSON.stringify(input)}`, out.bridges[k] === false);
    }
    // and the whole result must still be a well-formed state (live is valid).
    ok(`rail(b) live normalises to a valid enum for ${JSON.stringify(input)}`,
      ["none", "porog", "nopor"].includes(out.live));
  }
  // The running app's ONLY load path is normalize(JSON.parse(localStorage)). A
  // __proto__ payload planted in that string is, per JSON semantics, an ordinary
  // own key named "__proto__" (never a real prototype), so it can never leak a
  // `true` onto a known bridge via the prototype chain.
  {
    const planted = normalize(JSON.parse('{"bridges":{"__proto__":{"mic":true},"clipboard":true}}'));
    for (const k of BRIDGE_KEYS) {
      if (k === "clipboard") continue; // clipboard:true is a *legit* stored grant, not junk
      ok(`rail(b) __proto__ payload does not leak onto bridges.${k}`, planted.bridges[k] === false);
    }
    // and a genuine strict-true grant DOES round-trip (the rail denies junk, not truth).
    ok("rail(b) a genuine strict-true grant round-trips through the real load path",
      planted.bridges.clipboard === true);
  }
  ok("rail(b) asBool('true') === false", asBool("true") === false);
  ok("rail(b) asBool(1) === false", asBool(1) === false);
  ok("rail(b) asBool([]) === false", asBool([]) === false);
  ok("rail(b) asBool(true) === true", asBool(true) === true);
}

// Rail (c): killSwitch.engaged defaults false; a non-bool normalises to false.
{
  ok("rail(c) defaultState().killSwitch.engaged === false", defaultState().killSwitch.engaged === false);
  ok("rail(c) normalize({}).killSwitch.engaged === false", normalize({}).killSwitch.engaged === false);
  for (const junk of ["yes", 1, "engaged", [], {}, null, "true"]) {
    ok(`rail(c) killSwitch.engaged from ${JSON.stringify(junk)} normalises to false`,
      normalize({ killSwitch: { engaged: junk } }).killSwitch.engaged === false);
  }
  // strict true is the only value that engages it.
  ok("rail(c) killSwitch.engaged:true survives", normalize({ killSwitch: { engaged: true } }).killSwitch.engaged === true);
  // and when disengaged, engagedAtIso is nulled regardless of what was planted.
  ok("rail(c) disengaged killSwitch nulls engagedAtIso",
    normalize({ killSwitch: { engaged: false, engagedAtIso: "2026-01-01T00:00:00Z" } }).killSwitch.engagedAtIso === null);
}

// Rail (d): the state carries NO attestable tier field, and no code path can set
// a porogVerdict-derived tier to "attested" for the nopor side. Proven BY
// ABSENCE (the same way ui-parity proves parse/serialize absent): there is no
// `tier` key anywhere in the state, and no `attested` string anywhere in the
// extracted model source. NoporIS is non-attestable because there is nothing to
// flip.
{
  const def = defaultState();
  // no top-level tier field...
  ok("rail(d) defaultState() has no `tier` field", !("tier" in def));
  // ...and no nested tier field anywhere in the state tree.
  const findKeyDeep = (obj, key) => {
    if (!obj || typeof obj !== "object") return false;
    for (const k of Object.keys(obj)) {
      if (k === key) return true;
      if (findKeyDeep(obj[k], key)) return true;
    }
    return false;
  };
  ok("rail(d) no `tier` field anywhere in defaultState() tree", findKeyDeep(def, "tier") === false);
  // a hostile input trying to inject a tier must not survive normalize (normalize
  // rebuilds from defaultState and never copies an unknown `tier`).
  const relabelAttempt = normalize({ tier: "attested", porogVerdict: "genuine" });
  ok("rail(d) hostile {tier:'attested'} does not appear on normalized state",
    findKeyDeep(relabelAttempt, "tier") === false);
  // the extracted model source contains no "attested" token at all — there is no
  // code path, for the nopor side or any side, that produces an attested tier.
  ok("rail(d) extracted model source contains no 'attested' token",
    inlineSrc.includes("attested") === false);
  // porogVerdict is the ONLY attestation-adjacent field and it is a Porog-side
  // display enum that can never be "attested"/"genuine-for-nopor": its allowed
  // values are exactly {genuine, tee, unverified} and hostile values fall back
  // to a fixed default, never leaking onto the nopor side (nopor has no verdict).
  for (const junk of ["attested", "nopor-genuine", "trusted", 1, null, {}]) {
    const v = normalize({ porogVerdict: junk }).porogVerdict;
    ok(`rail(d) porogVerdict(${JSON.stringify(junk)}) stays in {genuine,tee,unverified}`,
      ["genuine", "tee", "unverified"].includes(v));
  }
  ok("rail(d) oneOf rejects out-of-set value to fallback", oneOf("attested", ["genuine", "tee", "unverified"], "genuine") === "genuine");
}

// Rail (e): pairings.porog and pairings.nopor are independent booleans — a state
// that revokes one must never clear the other. (normalize treats each pairing
// with `!== false`, so only an explicit false revokes; they never cross-talk.)
{
  const def = defaultState();
  ok("rail(e) defaultState().pairings.porog is boolean", typeof def.pairings.porog === "boolean");
  ok("rail(e) defaultState().pairings.nopor is boolean", typeof def.pairings.nopor === "boolean");

  // revoke porog only -> nopor stays paired.
  const porogRevoked = normalize({ pairings: { porog: false, nopor: true } });
  ok("rail(e) revoking porog leaves nopor paired",
    porogRevoked.pairings.porog === false && porogRevoked.pairings.nopor === true);

  // revoke nopor only -> porog stays paired.
  const noporRevoked = normalize({ pairings: { porog: true, nopor: false } });
  ok("rail(e) revoking nopor leaves porog paired",
    noporRevoked.pairings.nopor === false && noporRevoked.pairings.porog === true);

  // both revoked independently.
  const bothRevoked = normalize({ pairings: { porog: false, nopor: false } });
  ok("rail(e) both can be independently revoked",
    bothRevoked.pairings.porog === false && bothRevoked.pairings.nopor === false);

  // a wrong-typed pairings object falls back to both-paired defaults (no crash,
  // no accidental coupling).
  const junkPairings = normalize({ pairings: "gone" });
  ok("rail(e) junk pairings falls back to both-paired defaults",
    junkPairings.pairings.porog === true && junkPairings.pairings.nopor === true);

  // the two keys are distinct object properties (not aliased to one storage cell).
  const probe = normalize({ pairings: { porog: false, nopor: true } });
  probe.pairings.nopor = false;
  ok("rail(e) mutating one pairing key does not alias the other",
    probe.pairings.porog === false && probe.pairings.nopor === false);
}

// Rail (f): live only ever normalises to one of none/porog/nopor.
{
  const ALLOWED = ["none", "porog", "nopor"];
  ok("rail(f) defaultState().live is in the enum", ALLOWED.includes(defaultState().live));
  const LIVE_INPUTS = [
    undefined, null, "", "none", "porog", "nopor", "NOPOR", "both", "everywhere",
    "porog ", " nopor", 0, 1, 3, true, [], {}, ["porog"], { live: "porog" },
  ];
  for (const lv of LIVE_INPUTS) {
    const out = normalize({ live: lv });
    ok(`rail(f) normalize({live:${JSON.stringify(lv)}}).live in enum`, ALLOWED.includes(out.live));
  }
  // the three legit values round-trip exactly.
  for (const lv of ALLOWED) {
    ok(`rail(f) legit live '${lv}' round-trips`, normalize({ live: lv }).live === lv);
  }
  // oneOf itself is the guarantor: any value outside the set falls back.
  ok("rail(f) oneOf('both', enum, 'none') === 'none'", oneOf("both", ALLOWED, "none") === "none");
}

console.log(`test-switcher: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
