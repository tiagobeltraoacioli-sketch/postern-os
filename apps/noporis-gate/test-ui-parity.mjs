// SPDX-License-Identifier: MIT OR Apache-2.0
"use strict";
/* ============================================================================
   UI/store parity check for the NoporIS Gate.

   index.html inlines a condensed, behavior-equivalent port of gate-store.mjs so
   the browser can run the same crossing-state rules with no build step and no
   imports. The inline copy is deliberately condensed (different variable
   layout, arrow-function style for helpers instead of function declarations),
   so it is NOT byte-identical to gate-store.mjs. What this file proves,
   mechanically, is that it is BEHAVIOURALLY identical for everything the
   inline copy actually implements:

     1. it extracts the inline block straight out of index.html (between the
        "condensed, behavior-equivalent port of gate-store.mjs" and
        "UI (demo only" markers) so the check runs against exactly what ships
        in the browser, not a hand-copied stand-in;
     2. it evaluates that block in node with `new Function` (no eval of the
        rest of the page, no DOM, no localStorage);
     3. it runs both the inline copy and the canonical gate-store.mjs module
        against the same hostile-input corpus and the same
        consent/kill-switch/crossing truth table and asserts identical results
        at every point.

   HONESTLY, WHAT THIS DOES NOT COVER: the inline copy in index.html omits
   parse(), serialize(), and revokeAllCrossings() on purpose — the demo page
   never reads/writes a state file and never needs a "revoke everything at
   once" button. Those three are asserted ABSENT from the inline copy (by
   design), not parity-checked against gate-store.mjs, because there is
   nothing on the UI side to compare them against. If a wrapper implementer
   needs parse/serialize/revokeAllCrossings, gate-store.mjs is the canonical
   reference for those — this file says nothing about them.

   This file also does NOT test the (non-existent) on-device NoporIS wrapper
   that would actually read/write /var/lib/postern/noporis-gate/state.json;
   that stays UNTESTED until the hardware harness exists (see gate-store.mjs).
   gate-store.mjs itself is a reference-prototype and is UNAUDITED. The coin
   is not a security. This is not legal advice.

   If the inline copy and gate-store.mjs ever drift on the functions both
   sides share — a fixed default changed in one but not the other, a rail
   loosened in one but not the other — this file fails loudly (and exit 1s)
   instead of silently going stale.

   Dependency-free: only node:assert/strict, node:fs, node:path, node:url, and
   ./gate-store.mjs. No DOM.
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

// noporis-gate uses <script type="module">, so the regex must tolerate
// attributes on the opening tag (unlike a bare <script>).
const scriptMatch = html.match(/<script[^>]*>([\s\S]*?)<\/script>/);
assert.ok(scriptMatch, "could not find a <script ...>...</script> block in index.html");
const scriptBody = scriptMatch[1];

const START_MARKER = "condensed, behavior-equivalent port of gate-store.mjs";
const END_MARKER = "UI (demo only";

const startMarkerIdx = scriptBody.indexOf(START_MARKER);
const endMarkerIdx = scriptBody.indexOf(END_MARKER);
assert.ok(startMarkerIdx !== -1, `could not find "${START_MARKER}" marker in index.html <script>`);
assert.ok(endMarkerIdx !== -1, `could not find "${END_MARKER}" marker in index.html <script>`);
assert.ok(endMarkerIdx > startMarkerIdx, "markers are out of order in index.html <script>");

// The inline code starts right after the "*/" that closes the comment block
// containing START_MARKER...
const codeStart = scriptBody.indexOf("*/", startMarkerIdx) + 2;
// ...and ends right before the "/*" that opens the comment block containing
// END_MARKER (i.e. it excludes the "UI (demo only" section itself).
const codeEnd = scriptBody.lastIndexOf("/*", endMarkerIdx);
assert.ok(codeStart > 1, "failed to locate the end of the condensed-port comment header");
assert.ok(codeEnd > codeStart, "failed to locate the start of the UI-(demo-only) comment header");

const inlineSrc = scriptBody.slice(codeStart, codeEnd);
assert.ok(inlineSrc.includes("function normalize"), "extracted block does not look like the inline store logic");

/* ---- 2. evaluate the extracted block in node, no DOM ---------------------- */

const EXPORTED = [
  "SCHEMA_ID", "SCHEMA_VERSION", "TIER", "CROSSING_KEYS", "CONSENT_SCOPES",
  "LANGS", "LESS_PRIVATE_FAR_SIDE", "WALLET_PRESERVED", "STATE_PATH",
  "CROSSING_DIRECTIONS", "DEFAULT_DIRECTION",
  "BRIDGE_STATE_ENABLED", "BRIDGE_STATE_DISABLED",
  "defaultState", "normalize",
  "bridgeStanding", "activeCrossings", "walletPreserved",
  "projectNoporisBridgeState",
  "acceptConsent", "withdrawConsent",
  "openCrossing", "revokeCrossing",
  "engageKillSwitch", "disengageKillSwitch",
];

// Functions the inline copy deliberately omits. Probed with `typeof` INSIDE the
// evaluated block (not just absent from the returned object) so that if someone
// later adds an inline copy of one of these, the absent-by-design assertion
// below fails loudly and forces it onto the parity-checked list.
const OMITTED = ["parse", "loadState", "serialize", "revokeAllCrossings",
  "slobodaBridgeToggle", "slobodaBridgeStateFile"];

let UI;
try {
  const probes = OMITTED.map((n) => `${n}: typeof ${n} === "undefined" ? undefined : ${n}`);
  const build = new Function(`"use strict";\n${inlineSrc}\nreturn { ${EXPORTED.join(", ")}, ${probes.join(", ")} };`);
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

// deep clone / deep freeze helpers for the "inputs must not be mutated"
// checks below: each transformer is called with a DEEP-FROZEN state, so any
// attempted in-place mutation throws (strict mode) instead of silently
// passing, and we additionally re-compare the frozen input against a
// pristine snapshot taken before the call to prove it is unchanged.
const deepClone = (v) => JSON.parse(JSON.stringify(v));
const deepFreeze = (obj) => {
  if (obj && typeof obj === "object") {
    for (const k of Object.getOwnPropertyNames(obj)) deepFreeze(obj[k]);
    Object.freeze(obj);
  }
  return obj;
};
// run `fn` (module + inline) against a deep-frozen clone of `state` and
// assert: (1) both sides agree (deep-equal), (2) neither side mutated the
// frozen input in place (compared against a pristine snapshot taken before
// either call ran).
const parityNoMutate = (label, state, run) => {
  const pristine = deepClone(state);
  const frozenForS = deepFreeze(deepClone(state));
  const frozenForUI = deepFreeze(deepClone(state));
  const resultS = run(S, frozenForS);
  const resultUI = run(UI, frozenForUI);
  deepOk(label, resultS, resultUI);
  deepOk(`${label} [gate-store input not mutated]`, frozenForS, pristine);
  deepOk(`${label} [inline input not mutated]`, frozenForUI, pristine);
};

// -- constants parity -----------------------------------------------------
deepOk("SCHEMA_ID parity", S.SCHEMA_ID, UI.SCHEMA_ID);
deepOk("SCHEMA_VERSION parity", S.SCHEMA_VERSION, UI.SCHEMA_VERSION);
deepOk("TIER parity", S.TIER, UI.TIER);
deepOk("CROSSING_KEYS parity", S.CROSSING_KEYS, UI.CROSSING_KEYS);
deepOk("CONSENT_SCOPES parity", S.CONSENT_SCOPES, UI.CONSENT_SCOPES);
deepOk("LANGS parity", S.LANGS, UI.LANGS);
deepOk("LESS_PRIVATE_FAR_SIDE parity", S.LESS_PRIVATE_FAR_SIDE, UI.LESS_PRIVATE_FAR_SIDE);
deepOk("WALLET_PRESERVED parity", S.WALLET_PRESERVED, UI.WALLET_PRESERVED);
deepOk("STATE_PATH parity", S.STATE_PATH, UI.STATE_PATH);
deepOk("CROSSING_DIRECTIONS parity", S.CROSSING_DIRECTIONS, UI.CROSSING_DIRECTIONS);
deepOk("DEFAULT_DIRECTION parity", S.DEFAULT_DIRECTION, UI.DEFAULT_DIRECTION);
deepOk("BRIDGE_STATE_ENABLED parity", S.BRIDGE_STATE_ENABLED, UI.BRIDGE_STATE_ENABLED);
deepOk("BRIDGE_STATE_DISABLED parity", S.BRIDGE_STATE_DISABLED, UI.BRIDGE_STATE_DISABLED);

// -- functions the inline copy deliberately omits: assert absent-by-design --
// (parse/serialize/revokeAllCrossings are NOT parity-checked against
// gate-store.mjs because the inline copy does not implement them at all;
// the demo page has no state file to parse/serialize and no single button
// that revokes every crossing at once.)
for (const omitted of OMITTED) {
  ok(`inline copy omits '${omitted}' (by design, not parity-checked)`, typeof UI[omitted] === "undefined");
}

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
  { crossings: { mic: { open: 1 } } },                          // truthy-not-true crossing (number)
  { crossings: { mic: { open: "true" } } },                     // truthy-not-true crossing (string)
  { crossings: { clipboard: { open: true }, mic: { open: 1 }, camera: { open: [] } } }, // mixed valid + invalid
  { tier: "attested" },                                         // hostile tier relabel — never survives normalize()
  { schema: "evil", version: 999 },                             // schema/version override attempt
  { sealedWallet: { preserved: false } },                       // wallet-destroyed relabel attempt
  { consent: { accepted: true, scope: "forever" } },            // bad/unknown scope
  { consent: { accepted: "yes" } },                             // truthy-not-true consent
  { consent: null, crossings: null, killSwitch: null, sealedWallet: null }, // null sub-objects
  { killSwitch: { engaged: "yes" } },                           // truthy-not-true kill-switch
  { lang: "fr" },                                               // unsupported lang
  { crossings: { files: { open: true, direction: "both" } } },  // lane-widening attempt (must pin near-to-far)
  { crossings: { files: { open: true, direction: "far-to-near" } } }, // legit ingest lane, chosen on purpose
  { crossings: { files: { open: true, direction: 42 } } },      // garbage direction
  {
    consent: { accepted: true, scope: "persistent", acceptedAtIso: "2026-01-01T00:00:00Z" },
    crossings: {
      clipboard: { open: true, scope: "persistent", openedAtIso: "2026-01-01T00:00:00Z" },
      files: { open: true, scope: "session", openedAtIso: "2026-01-01T00:00:00Z" },
      mic: { open: true, scope: "session", openedAtIso: "2026-01-01T00:00:00Z" },
      camera: { open: true, scope: "session", openedAtIso: "2026-01-01T00:00:00Z" },
      location: { open: true, scope: "session", openedAtIso: "2026-01-01T00:00:00Z" },
    },
    killSwitch: { engaged: false, engagedAtIso: null },
    lang: "pt-BR",
  },
];

for (const input of HOSTILE_CORPUS) {
  const label = `normalize(${JSON.stringify(input)})`;
  deepOk(label, S.normalize(input), UI.normalize(input));
  // the load-bearing runtime "enabled"|"disabled" string must agree on every
  // hostile input too — this is the projection the orchestrator persists.
  ok(`projectNoporisBridgeState(${JSON.stringify(input)}) parity`,
    S.projectNoporisBridgeState(input) === UI.projectNoporisBridgeState(input));
}

// -- bridgeStanding / activeCrossings / walletPreserved truth table -------
const BOOLS = [true, false];
const OPTS_VARIANTS = [undefined, {}, { requireConsent: false }, { requireConsent: true }];
const CROSSING_SUBSETS = [
  { clipboard: false, files: false, mic: false, camera: false, location: false },
  { clipboard: true, files: false, mic: false, camera: false, location: false },
  { clipboard: true, files: true, mic: true, camera: true, location: true },
  { clipboard: false, files: true, mic: false, camera: true, location: false },
];

const crossingsFromSubset = (subset) => {
  const out = {};
  for (const k of S.CROSSING_KEYS) {
    out[k] = { open: subset[k], scope: "session", openedAtIso: subset[k] ? "2026-01-01T00:00:00Z" : null };
  }
  return out;
};

let tableCases = 0;
for (const consentAccepted of BOOLS) {
  for (const killEngaged of BOOLS) {
    for (const subset of CROSSING_SUBSETS) {
      for (const opts of OPTS_VARIANTS) {
        const state = {
          consent: { accepted: consentAccepted, scope: "session", acceptedAtIso: null },
          crossings: crossingsFromSubset(subset),
          killSwitch: { engaged: killEngaged, engagedAtIso: null },
        };
        const label = `truth-table consent=${consentAccepted} kill=${killEngaged} crossings=${JSON.stringify(subset)} opts=${JSON.stringify(opts)}`;
        tableCases++;
        ok(`bridgeStanding ${label}`, S.bridgeStanding(state, opts) === UI.bridgeStanding(state, opts));
        deepOk(`activeCrossings ${label}`, S.activeCrossings(state, opts), UI.activeCrossings(state, opts));
        ok(`walletPreserved ${label}`, S.walletPreserved(state) === UI.walletPreserved(state));
        // projection parity + semantic pin: "enabled" iff any crossing is
        // active under DEFAULT opts (the projection takes no opts by design).
        const projS = S.projectNoporisBridgeState(state);
        ok(`projectNoporisBridgeState ${label}`, projS === UI.projectNoporisBridgeState(state));
        ok(`projection semantic pin ${label}`,
          projS === (S.activeCrossings(state).length > 0 ? S.BRIDGE_STATE_ENABLED : S.BRIDGE_STATE_DISABLED));
      }
    }
  }
}
ok("truth table actually ran cases", tableCases > 0);

// -- acceptConsent() / withdrawConsent() parity ----------------------------
const CONSENT_ARG_VARIANTS = [
  undefined,
  {},
  { scope: "session" },
  { scope: "persistent", atIso: "2026-01-01T00:00:00Z" },
  { scope: "bogus", atIso: "2026-01-01T00:00:00Z" }, // hostile scope
];
for (const args of CONSENT_ARG_VARIANTS) {
  const base = S.defaultState();
  const label = `acceptConsent(defaultState(), ${JSON.stringify(args)})`;
  parityNoMutate(label, base, (mod, state) => mod.acceptConsent(state, args));
}
{
  const consented = S.acceptConsent(S.defaultState(), { scope: "persistent", atIso: "2026-01-01T00:00:00Z" });
  const withCrossings = S.openCrossing(consented, "mic", { atIso: "2026-01-01T00:00:00Z" });
  parityNoMutate(
    "withdrawConsent(consented+crossing) parity — clears all crossings",
    withCrossings,
    (mod, state) => mod.withdrawConsent(state)
  );
  const withdrawn = S.withdrawConsent(withCrossings);
  ok(
    "withdrawConsent clears all crossings (gate-store)",
    S.CROSSING_KEYS.every((k) => withdrawn.crossings[k].open === false)
  );
  const withdrawnUI = UI.withdrawConsent(deepFreeze(deepClone(withCrossings)));
  ok(
    "withdrawConsent clears all crossings (inline)",
    S.CROSSING_KEYS.every((k) => withdrawnUI.crossings[k].open === false)
  );
}

// -- openCrossing() / revokeCrossing() parity ------------------------------
const consentedState = S.acceptConsent(S.defaultState(), { scope: "session", atIso: "2026-01-01T00:00:00Z" });
const notConsentedState = S.defaultState();
const killedState = S.engageKillSwitch(consentedState, { atIso: "2026-01-01T00:00:00Z" });
// "root" is called out explicitly (unknown capability, must be a no-op on
// both sides) alongside a generically-named unknown key.
const OPEN_KEY_VARIANTS = [...S.CROSSING_KEYS, "root", "unknown-capability", "", undefined, null];
const OPEN_ARG_VARIANTS = [
  undefined, {}, { scope: "session" }, { scope: "persistent", atIso: "2026-01-01T00:00:00Z" },
  { direction: "far-to-near" },                                        // deliberate ingest lane
  { direction: "both" },                                               // hostile widening attempt
  { scope: "persistent", direction: "far-to-near", atIso: "2026-01-01T00:00:00Z" },
];
const UNKNOWN_OPEN_KEYS = ["root", "unknown-capability", "", undefined, null];

for (const [baseLabel, base] of [
  ["consentedState", consentedState],
  ["notConsentedState", notConsentedState],
  ["killedState", killedState],
]) {
  for (const key of OPEN_KEY_VARIANTS) {
    for (const args of OPEN_ARG_VARIANTS) {
      const label = `openCrossing(${baseLabel}, ${JSON.stringify(key)}, ${JSON.stringify(args)})`;
      parityNoMutate(label, base, (mod, state) => mod.openCrossing(state, key, args));

      // explicit NO-OP assertions per spec: not consented, kill engaged,
      // or unknown key must never grant a crossing.
      if (baseLabel === "notConsentedState" || baseLabel === "killedState" || UNKNOWN_OPEN_KEYS.includes(key)) {
        const resultS = S.openCrossing(base, key, args);
        const resultUI = UI.openCrossing(deepFreeze(deepClone(base)), key, args);
        deepOk(`${label} is a NO-OP (gate-store === input)`, resultS, S.normalize(base));
        deepOk(`${label} is a NO-OP (inline === input)`, resultUI, S.normalize(base));
      } else if (baseLabel === "consentedState" && S.CROSSING_KEYS.includes(key)) {
        // the bridge is standing and the key is real: this must GRANT.
        const resultS = S.openCrossing(base, key, args);
        const resultUI = UI.openCrossing(deepFreeze(deepClone(base)), key, args);
        ok(`${label} grants when standing (gate-store)`, resultS.crossings[key].open === true);
        ok(`${label} grants when standing (inline)`, resultUI.crossings[key].open === true);
      }
    }
    const revokeLabel = `revokeCrossing(${baseLabel}, ${JSON.stringify(key)})`;
    parityNoMutate(revokeLabel, base, (mod, state) => mod.revokeCrossing(state, key));
  }
}

// -- engageKillSwitch() / disengageKillSwitch() parity ---------------------
const KILL_ARG_VARIANTS = [undefined, {}, { atIso: "2026-01-01T00:00:00Z" }];
for (const [baseLabel, base] of [["defaultState", S.defaultState()], ["consentedState", consentedState]]) {
  for (const args of KILL_ARG_VARIANTS) {
    const label = `engageKillSwitch(${baseLabel}, ${JSON.stringify(args)})`;
    parityNoMutate(label, base, (mod, state) => mod.engageKillSwitch(state, args));

    // the sealed-wallet invariant is the honesty rail this whole test file
    // exists to protect: assert it explicitly (not just via deep-equal,
    // which would pass if BOTH sides drifted identically) on both sides.
    const resultS = S.engageKillSwitch(base, args);
    const resultUI = UI.engageKillSwitch(deepFreeze(deepClone(base)), args);
    ok(`${label} sealedWallet.preserved === true (gate-store)`, resultS.sealedWallet.preserved === true);
    ok(`${label} sealedWallet.preserved === true (inline)`, resultUI.sealedWallet.preserved === true);
  }
  parityNoMutate(
    `disengageKillSwitch(killedState) parity [base=${baseLabel}]`,
    killedState,
    (mod, state) => mod.disengageKillSwitch(state)
  );
}

console.log(`test-ui-parity: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
