// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
"use strict";
/* ============================================================================
   UI/kernel parity check for the NoporIS persona-switch prototype.

   noporis-persona-switch.html inlines a condensed, behavior-equivalent port of
   consent-kernel.mjs so the browser can run the same deny-by-default consent
   rules with no build step and no imports. The inline copy is deliberately
   condensed (single-page layout, no export statements), so it is NOT
   byte-identical to consent-kernel.mjs. What this file proves, mechanically,
   is that it is BEHAVIOURALLY identical for everything the inline copy
   actually implements:

     1. it extracts the inline block straight out of noporis-persona-switch.html
        (between the "condensed, behavior-equivalent port of consent-kernel.mjs"
        and "UI (demo only" markers) so the check runs against exactly what
        ships in the browser, not a hand-copied stand-in;
     2. it evaluates that block in node with `new Function` (no eval of the
        rest of the page, no DOM);
     3. it runs both the inline copy and the canonical consent-kernel.mjs
        module against the same hostile-input corpus (null / garbage /
        foreign-schema / prototype-pollution shapes), the same
        onBridge x killSwitch x capabilities truth table, the same transform
        matrix, and BYTE-EQUAL signerBadge output for every
        (tier, capability, scope) combination — and asserts identical results
        at every point.

   HONESTLY, WHAT THIS DOES NOT COVER: the inline copy's TIERS objects carry
   ONLY { id, product, farLabel } — exactly the fields signerBadge derives the
   world badge from. The canonical kernel's farTier / role / attestable /
   sealCovered flags and the long `honesty` prose are deliberately OMITTED
   from the inline JS constants: the page shows its honesty copy in the
   VISIBLE banner and footer instead of in dead constants, and the .mjs stays
   the single programmatic authority for that prose. Those fields are asserted
   ABSENT from the inline copy (by design), not parity-checked, and this file
   separately asserts the page's visible honesty strings are still present in
   the HTML verbatim. porog-onboarding.html and sloboda-entry.html are OUT OF
   SCOPE this iteration: they do not inline the kernel today, and this file
   says nothing about them.

   This file also does NOT test the (non-existent) on-device switcher, the two
   pairings, or the world-badged signer prompt — those stay UNTESTED until the
   hardware harness exists. consent-kernel.mjs itself is a reference-prototype
   and is UNAUDITED — it is UX-layer logic only, not a security control. The
   coin is not a security. This is not legal advice.

   If the inline copy and consent-kernel.mjs ever drift on the functions both
   sides share — a fixed default changed in one but not the other, a rail
   loosened in one but not the other, a badge string reworded in one but not
   the other — this file fails loudly (and exit 1s) instead of silently going
   stale.

   Dependency-free: only node:assert/strict, node:fs, node:path, node:url, and
   ./consent-kernel.mjs. No DOM.
   Run: node test-kernel-parity.mjs
   ============================================================================ */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import S from "./consent-kernel.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const htmlPath = path.join(__dirname, "noporis-persona-switch.html");
const html = readFileSync(htmlPath, "utf8");

/* ---- 1. extract the inline logic block from noporis-persona-switch.html --- */

// the page uses <script type="module">, so the regex must tolerate
// attributes on the opening tag.
const scriptMatch = html.match(/<script[^>]*>([\s\S]*?)<\/script>/);
assert.ok(scriptMatch, "could not find a <script ...>...</script> block in noporis-persona-switch.html");
const scriptBody = scriptMatch[1];

const START_MARKER = "condensed, behavior-equivalent port of consent-kernel.mjs";
const END_MARKER = "UI (demo only";

const startMarkerIdx = scriptBody.indexOf(START_MARKER);
const endMarkerIdx = scriptBody.indexOf(END_MARKER);
assert.ok(startMarkerIdx !== -1, `could not find "${START_MARKER}" marker in the page <script>`);
assert.ok(endMarkerIdx !== -1, `could not find "${END_MARKER}" marker in the page <script>`);
assert.ok(endMarkerIdx > startMarkerIdx, "markers are out of order in the page <script>");

// The inline code starts right after the "*/" that closes the comment block
// containing START_MARKER...
const codeStart = scriptBody.indexOf("*/", startMarkerIdx) + 2;
// ...and ends right before the "/*" that opens the comment block containing
// END_MARKER (i.e. it excludes the "UI (demo only" section itself).
const codeEnd = scriptBody.lastIndexOf("/*", endMarkerIdx);
assert.ok(codeStart > 1, "failed to locate the end of the condensed-port comment header");
assert.ok(codeEnd > codeStart, "failed to locate the start of the UI-(demo-only) comment header");

const inlineSrc = scriptBody.slice(codeStart, codeEnd);
assert.ok(inlineSrc.includes("function normalize"), "extracted block does not look like the inline kernel logic");

/* ---- 2. evaluate the extracted block in node, no DOM ---------------------- */

const EXPORTED = [
  "CAPABILITIES", "LOUD_CAPABILITIES", "SCOPES", "CAP_INFO", "TIERS",
  "safeDefault", "normalize",
  "bridgeStanding", "activeCapabilities", "sealedBasePreserved",
  "standOnBridge", "leaveBridge",
  "openCapability", "revokeCapability",
  "engageKillSwitch", "disengageKillSwitch",
  "signerBadge",
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
    console.error("  kernel:", JSON.stringify(a));
    console.error("  inline:", JSON.stringify(b));
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
  deepOk(`${label} [kernel input not mutated]`, frozenForS, pristine);
  deepOk(`${label} [inline input not mutated]`, frozenForUI, pristine);
};

// -- constants parity -----------------------------------------------------
deepOk("CAPABILITIES parity", S.CAPABILITIES, UI.CAPABILITIES);
deepOk("LOUD_CAPABILITIES parity", S.LOUD_CAPABILITIES, UI.LOUD_CAPABILITIES);
deepOk("SCOPES parity", S.SCOPES, UI.SCOPES);
deepOk("CAP_INFO parity (labels, honest what-crosses copy, direction notes)", S.CAP_INFO, UI.CAP_INFO);

// TIERS: the inline copy carries ONLY the badge inputs (id/product/farLabel).
const TIER_IDS = Object.keys(S.TIERS);
deepOk("TIERS ids parity", TIER_IDS, Object.keys(UI.TIERS));
for (const t of TIER_IDS) {
  deepOk(`TIERS.${t} badge inputs parity (id/product/farLabel)`,
    { id: S.TIERS[t].id, product: S.TIERS[t].product, farLabel: S.TIERS[t].farLabel },
    { id: UI.TIERS[t].id, product: UI.TIERS[t].product, farLabel: UI.TIERS[t].farLabel });
  // deliberately omitted from the inline copy: the page's honesty ships in the
  // visible banner/footer, not as dead JS constants (see header). Asserted
  // ABSENT so a half-copied TIERS never masquerades as the full kernel one.
  for (const omitted of ["farTier", "role", "attestable", "sealCovered", "honesty"]) {
    ok(`inline TIERS.${t} omits '${omitted}' (by design, not parity-checked)`,
      typeof UI.TIERS[t][omitted] === "undefined");
  }
}

// -- safeDefault() across tier ids ----------------------------------------
const SAFE_DEFAULT_TIER_ARGS = [undefined, "noporis", "porog", "sloboda", "bogus-tier"];
for (const t of SAFE_DEFAULT_TIER_ARGS) {
  deepOk(`safeDefault(${JSON.stringify(t)}) parity`,
    t === undefined ? S.safeDefault() : S.safeDefault(t),
    t === undefined ? UI.safeDefault() : UI.safeDefault(t));
}
ok("safeDefault restores openedAtIso on every capability (inline)",
  S.CAPABILITIES.every((k) => UI.safeDefault().capabilities[k].openedAtIso === null));
ok("safeDefault restores engagedAtIso on the kill-switch (inline)",
  UI.safeDefault().killSwitch.engagedAtIso === null);
ok("safeDefault restores the tier field (inline)", UI.safeDefault("noporis").tier === "noporis");

// -- normalize() over a hostile corpus ------------------------------------
// [label, value] pairs — labels are literals because some hostile shapes
// (inherited properties, own-"__proto__" keys) do not JSON.stringify usefully.
const HOSTILE_CORPUS = [
  ["null", null],
  ["undefined", undefined],
  ["string", "nope"],
  ["number", 42],
  ["array", []],
  ["empty object", {}],
  ["truthy-not-true onBridge (number)", { onBridge: 1 }],
  ["truthy-not-true onBridge (string)", { onBridge: "true" }],
  ["truthy-not-true kill", { killSwitch: { engaged: "yes" } }],
  ["truthy-not-true capability", { capabilities: { mic: { open: 1 } } }],
  ["mixed valid + invalid capabilities", { onBridge: true, capabilities: { clipboard: { open: true }, mic: { open: 1 }, camera: { open: [] } } }],
  ["unknown scope", { onBridge: true, scope: "forever" }],
  ["unknown capability scope", { onBridge: true, capabilities: { files: { open: true, scope: "forever" } } }],
  ["sealedBase relabel attempt", { sealedBase: { preserved: false } }],
  ["null sub-objects", { capabilities: null, killSwitch: null, sealedBase: null }],
  ["foreign schema (noporis-gate state file)", { schema: "postern.noporis-gate.state", version: 1, consent: { accepted: true }, crossings: { mic: { open: true } } }],
  ["foreign schema (sloboda-gate state file)", { schema: "postern.sloboda-gate.state", version: 1, bridges: { clipboard: true } }],
  ["own-'__proto__' key (JSON.parse pollution shape)", JSON.parse('{"__proto__":{"onBridge":true}}')],
  ["own-'__proto__' key inside capabilities", { onBridge: true, capabilities: JSON.parse('{"__proto__":{"open":true}}') }],
  ["constructor/prototype pollution shape", JSON.parse('{"constructor":{"prototype":{"onBridge":true}},"onBridge":"x"}')],
  ["inherited onBridge via Object.create", Object.create({ onBridge: true, killSwitch: { engaged: true } })],
  ["fully-open honest shape", {
    onBridge: true, scope: "persistent",
    capabilities: {
      clipboard: { open: true, scope: "persistent", openedAtIso: "2026-01-01T00:00:00Z" },
      files: { open: true, scope: "session", openedAtIso: "2026-01-01T00:00:00Z" },
      location: { open: true, scope: "single", openedAtIso: "2026-01-01T00:00:00Z" },
      mic: { open: true, scope: "session", openedAtIso: "2026-01-01T00:00:00Z" },
      camera: { open: true, scope: "session", openedAtIso: "2026-01-01T00:00:00Z" },
    },
    killSwitch: { engaged: false, engagedAtIso: null },
  }],
];
const NORMALIZE_TIER_ARGS = [undefined, "noporis", "porog", "sloboda"];
for (const [label, input] of HOSTILE_CORPUS) {
  for (const t of NORMALIZE_TIER_ARGS) {
    const name = `normalize(<${label}>, ${JSON.stringify(t)})`;
    deepOk(name,
      t === undefined ? S.normalize(input) : S.normalize(input, t),
      t === undefined ? UI.normalize(input) : UI.normalize(input, t));
  }
  // deny-by-default sanity on the inline side for every genuinely hostile shape
  if (label !== "fully-open honest shape" && label !== "mixed valid + invalid capabilities"
      && label !== "unknown scope" && label !== "unknown capability scope") {
    ok(`inline normalize(<${label}>) yields no active capabilities`,
      UI.activeCapabilities(UI.normalize(input)).length === 0);
  }
}

// -- bridgeStanding / activeCapabilities / sealedBasePreserved truth table --
const BOOLS = [true, false];
const CAP_SUBSETS = [
  { clipboard: false, files: false, location: false, mic: false, camera: false },
  { clipboard: true, files: false, location: false, mic: false, camera: false },
  { clipboard: true, files: true, location: true, mic: true, camera: true },
  { clipboard: false, files: true, location: false, mic: false, camera: true },
];
const capsFromSubset = (subset) => {
  const out = {};
  for (const k of S.CAPABILITIES) {
    out[k] = { open: subset[k], scope: "session", openedAtIso: subset[k] ? "2026-01-01T00:00:00Z" : null };
  }
  return out;
};

let tableCases = 0;
for (const onBridge of BOOLS) {
  for (const killEngaged of BOOLS) {
    for (const subset of CAP_SUBSETS) {
      const state = {
        tier: "noporis",
        onBridge,
        scope: "session",
        capabilities: capsFromSubset(subset),
        killSwitch: { engaged: killEngaged, engagedAtIso: killEngaged ? "2026-01-01T00:00:00Z" : null },
        sealedBase: { preserved: true },
      };
      const label = `truth-table onBridge=${onBridge} kill=${killEngaged} caps=${JSON.stringify(subset)}`;
      tableCases++;
      ok(`bridgeStanding ${label}`, S.bridgeStanding(state) === UI.bridgeStanding(state));
      parityNoMutate(`activeCapabilities ${label}`, state, (mod, s) => mod.activeCapabilities(s));
      ok(`sealedBasePreserved ${label}`, S.sealedBasePreserved(state) === UI.sealedBasePreserved(state));
      // the fail-closed rail, asserted explicitly on BOTH sides (not just via
      // parity, which would pass if both drifted identically): kill or
      // not-on-bridge must yield NOTHING.
      if (killEngaged || !onBridge) {
        ok(`${label} lends nothing (kernel)`, S.activeCapabilities(state).length === 0);
        ok(`${label} lends nothing (inline)`, UI.activeCapabilities(state).length === 0);
      }
    }
  }
}
ok("truth table actually ran cases", tableCases > 0);

// -- standOnBridge() / leaveBridge() parity --------------------------------
const STAND_ARG_VARIANTS = [
  undefined,
  {},
  { scope: "session" },
  { scope: "persistent", atIso: "2026-01-01T00:00:00Z" },
  { scope: "bogus", atIso: "2026-01-01T00:00:00Z" }, // hostile scope
];
for (const args of STAND_ARG_VARIANTS) {
  const base = S.safeDefault("noporis");
  const label = `standOnBridge(safeDefault(), ${JSON.stringify(args)})`;
  parityNoMutate(label, base, (mod, state) => (args === undefined ? mod.standOnBridge(state) : mod.standOnBridge(state, args)));
}
{
  const standing = S.standOnBridge(S.safeDefault("noporis"), { scope: "persistent", atIso: "2026-01-01T00:00:00Z" });
  const withCaps = S.openCapability(standing, "mic", { atIso: "2026-01-01T00:00:00Z" });
  parityNoMutate(
    "leaveBridge(standing+capability) parity — withdraws every capability",
    withCaps,
    (mod, state) => mod.leaveBridge(state)
  );
  const left = S.leaveBridge(withCaps);
  ok("leaveBridge withdraws all capabilities (kernel)",
    S.CAPABILITIES.every((k) => left.capabilities[k].open === false));
  const leftUI = UI.leaveBridge(deepFreeze(deepClone(withCaps)));
  ok("leaveBridge withdraws all capabilities (inline)",
    S.CAPABILITIES.every((k) => leftUI.capabilities[k].open === false));
}

// -- openCapability() / revokeCapability() parity ---------------------------
const standingState = S.standOnBridge(S.safeDefault("noporis"), { scope: "session", atIso: "2026-01-01T00:00:00Z" });
const notStandingState = S.safeDefault("noporis");
const killedState = S.engageKillSwitch(standingState, { atIso: "2026-01-01T00:00:00Z" });
// "root" is called out explicitly (unknown capability, must be a no-op on
// both sides) alongside a generically-named unknown key.
const OPEN_KEY_VARIANTS = [...S.CAPABILITIES, "root", "unknown-capability", "", undefined, null];
const OPEN_ARG_VARIANTS = [undefined, {}, { scope: "session" }, { scope: "persistent", atIso: "2026-01-01T00:00:00Z" }];
const UNKNOWN_OPEN_KEYS = ["root", "unknown-capability", "", undefined, null];

for (const [baseLabel, base] of [
  ["standingState", standingState],
  ["notStandingState", notStandingState],
  ["killedState", killedState],
]) {
  for (const key of OPEN_KEY_VARIANTS) {
    for (const args of OPEN_ARG_VARIANTS) {
      const label = `openCapability(${baseLabel}, ${JSON.stringify(key)}, ${JSON.stringify(args)})`;
      parityNoMutate(label, base, (mod, state) => (args === undefined ? mod.openCapability(state, key) : mod.openCapability(state, key, args)));

      // explicit NO-OP assertions per spec: not standing, kill engaged,
      // or unknown key must never grant a capability (no silent grant).
      if (baseLabel === "notStandingState" || baseLabel === "killedState" || UNKNOWN_OPEN_KEYS.includes(key)) {
        const resultS = args === undefined ? S.openCapability(base, key) : S.openCapability(base, key, args);
        const resultUI = args === undefined ? UI.openCapability(deepFreeze(deepClone(base)), key) : UI.openCapability(deepFreeze(deepClone(base)), key, args);
        deepOk(`${label} is a NO-OP (kernel === normalized input)`, resultS, S.normalize(base, base.tier));
        deepOk(`${label} is a NO-OP (inline === normalized input)`, resultUI, S.normalize(base, base.tier));
      } else if (baseLabel === "standingState" && S.CAPABILITIES.includes(key)) {
        // the bridge is standing and the key is real: this must GRANT exactly one.
        const resultS = args === undefined ? S.openCapability(base, key) : S.openCapability(base, key, args);
        const resultUI = args === undefined ? UI.openCapability(deepFreeze(deepClone(base)), key) : UI.openCapability(deepFreeze(deepClone(base)), key, args);
        ok(`${label} grants when standing (kernel)`, resultS.capabilities[key].open === true);
        ok(`${label} grants when standing (inline)`, resultUI.capabilities[key].open === true);
        ok(`${label} never bundles (kernel: only '${key}' opens)`,
          S.CAPABILITIES.filter((k) => resultS.capabilities[k].open).join() === key);
        ok(`${label} never bundles (inline: only '${key}' opens)`,
          S.CAPABILITIES.filter((k) => resultUI.capabilities[k].open).join() === key);
      }
    }
    const revokeLabel = `revokeCapability(${baseLabel}, ${JSON.stringify(key)})`;
    parityNoMutate(revokeLabel, base, (mod, state) => mod.revokeCapability(state, key));
  }
}

// -- engageKillSwitch() / disengageKillSwitch() parity ----------------------
const KILL_ARG_VARIANTS = [undefined, {}, { atIso: "2026-01-01T00:00:00Z" }];
for (const [baseLabel, base] of [["safeDefault", S.safeDefault("noporis")], ["standingState", standingState]]) {
  for (const args of KILL_ARG_VARIANTS) {
    const label = `engageKillSwitch(${baseLabel}, ${JSON.stringify(args)})`;
    parityNoMutate(label, base, (mod, state) => (args === undefined ? mod.engageKillSwitch(state) : mod.engageKillSwitch(state, args)));

    // the sealed-base invariant is the honesty rail this whole test file
    // exists to protect: assert it explicitly (not just via deep-equal,
    // which would pass if BOTH sides drifted identically) on both sides.
    const resultS = args === undefined ? S.engageKillSwitch(base) : S.engageKillSwitch(base, args);
    const resultUI = args === undefined ? UI.engageKillSwitch(deepFreeze(deepClone(base))) : UI.engageKillSwitch(deepFreeze(deepClone(base)), args);
    ok(`${label} sealedBase.preserved === true (kernel)`, resultS.sealedBase.preserved === true);
    ok(`${label} sealedBase.preserved === true (inline)`, resultUI.sealedBase.preserved === true);
  }
  parityNoMutate(
    `disengageKillSwitch(killedState) parity [base=${baseLabel}]`,
    killedState,
    (mod, state) => mod.disengageKillSwitch(state)
  );
}

// -- signerBadge(): BYTE-EQUAL for every (tier, capability, scope) ----------
// The world badge is the WYSIWYS line the signer core would fold into
// peer_device — the one string that must never fork between the canonical
// kernel and what the page shows a human before they hold-to-sign.
const BADGE_TIER_ARGS = [undefined, "noporis", "porog", "sloboda", "bogus-tier"];
const BADGE_CAPS = [...S.CAPABILITIES, "unknown-cap"];
const BADGE_PEERS = ["the paired device", "Tiago's Chromebook"];
let badgeCases = 0;
for (const tierId of BADGE_TIER_ARGS) {
  for (const capability of BADGE_CAPS) {
    for (const scope of S.SCOPES) {
      for (const peer of BADGE_PEERS) {
        const args = tierId === undefined ? { capability, scope, peer } : { tierId, capability, scope, peer };
        const a = S.signerBadge(args);
        const b = UI.signerBadge(args);
        badgeCases++;
        ok(`signerBadge byte-equal tier=${JSON.stringify(tierId)} cap=${capability} scope=${scope} peer=${peer}`, a === b);
        // resolved-noporis badges (including the unknown-tier fallback and the
        // undefined default) must state the honest posture exactly once each:
        // ONE "less private", ONE "non-attestable" — never the duplicated
        // qualifier the pre-fix kernel emitted, never a spoofable relabel.
        if (tierId === undefined || tierId === "noporis" || tierId === "bogus-tier") {
          ok(`noporis badge has exactly one 'less private' [${capability}/${scope}/${peer}]`,
            (a.match(/less private/g) || []).length === 1);
          ok(`noporis badge states 'non-attestable' [${capability}/${scope}/${peer}]`,
            a.includes("non-attestable"));
        }
      }
    }
  }
}
ok("signerBadge matrix actually ran cases", badgeCases > 0);
// pinned per-tier honesty qualifiers survive in the badge, byte-for-byte
ok("porog badge carries 'key-attested device — not a measured-boot workspace'",
  S.signerBadge({ tierId: "porog" }).includes("key-attested device — not a measured-boot workspace") &&
  UI.signerBadge({ tierId: "porog" }).includes("key-attested device — not a measured-boot workspace"));
ok("sloboda badge carries 'non-attestable escape hatch — data leaves the sealed base'",
  S.signerBadge({ tierId: "sloboda" }).includes("non-attestable escape hatch — data leaves the sealed base") &&
  UI.signerBadge({ tierId: "sloboda" }).includes("non-attestable escape hatch — data leaves the sealed base"));
ok("no badge ever claims 'attested workspace' or 'measured-boot workspace' unqualified",
  BADGE_TIER_ARGS.every((tierId) => {
    const badge = tierId === undefined ? S.signerBadge({}) : S.signerBadge({ tierId });
    return !/(?<!not a )measured-boot workspace/.test(badge) && !badge.includes("attested workspace");
  }));
ok("signerBadge default args parity (no-arg call)", S.signerBadge() === UI.signerBadge());

// -- the page's VISIBLE honesty copy is still present, verbatim -------------
// (the inline TIERS deliberately omits the honesty prose — see header — so
// the page-level banner/footer strings are pinned here instead.)
for (const mustShip of [
  "UNAUDITED",
  "Less private · non-attestable",
  "phones home to Google",
  "not sealed",
  "never “Postern OS”",
  "The coin is not a security; personal use is free;",
]) {
  ok(`page still ships honesty string: ${JSON.stringify(mustShip)}`, html.includes(mustShip));
}

console.log(`test-kernel-parity: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
