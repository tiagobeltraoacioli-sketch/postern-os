// SPDX-License-Identifier: MIT OR Apache-2.0
"use strict";
/* Dependency-free proof of the shared consent-spine contract. Run: node test-spine.mjs
   Proves the seven rails hold in code across all three tiers (Porog / NoporIS /
   Waydroid), that the projection is a PURE function, and that the spine is
   byte-compatible (deep-equal normalize) with the two SHIPPED gate-store.mjs
   kernels so 0.4/0.5/0.6 align. It does NOT test any (non-existent) on-device
   wrapper — that stays UNTESTED until real hardware exists. */
import { deepStrictEqual } from "node:assert";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import S from "./consent-spine.mjs";
import slobodaStore from "../sloboda-gate/gate-store.mjs";
import noporisStore from "../noporis-gate/gate-store.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; } else { fail++; console.error("FAIL:", name); } };
const eq = (name, a, b) => { try { deepStrictEqual(a, b); pass++; } catch { fail++; console.error("FAIL:", name); } };

/* ===========================================================================
   0. The spine is IDENTICAL across all three tiers.
   =========================================================================== */
for (const id of S.PRODUCT_IDS) {
  const d = S.defaultState(id);
  ok(`${id}: spine has schema/version/tier/consent/killSwitch/lang`,
    typeof d.schema === "string" && d.version === 1 && typeof d.tier === "string" &&
    d.consent && d.killSwitch && typeof d.lang === "string");
  ok(`${id}: schema id follows postern.<product>-gate.state`, d.schema === S.PRODUCTS[id].schema);
  ok(`${id}: consent denied by default`, d.consent.accepted === false);
  ok(`${id}: kill clear by default`, d.killSwitch.engaged === false);
  ok(`${id}: state path is /var/lib/postern/<product>-gate/state.json`,
    /^\/var\/lib\/postern\/[a-z]+-gate\/state\.json$/.test(S.PRODUCTS[id].statePath));
  ok(`${id}: projection path is /run/postern/consent/<product>-bridge.state`,
    /^\/run\/postern\/consent\/[a-z]+-bridge\.state$/.test(S.PRODUCTS[id].projectionPath));
}

/* ===========================================================================
   RAIL 2 — pinned tier (per product), never from input.
   =========================================================================== */
ok("sloboda tier pinned non-attestable", S.defaultState("sloboda").tier === "non-attestable");
ok("noporis tier pinned non-attestable", S.defaultState("noporis").tier === "non-attestable");
ok("porog tier pinned key-attested-device", S.defaultState("porog").tier === "key-attested-device");
for (const id of S.PRODUCT_IDS) {
  ok(`${id}: cannot relabel tier via input`,
    S.normalize({ tier: "attested", schema: "hax", version: 99 }, id).tier === S.PRODUCTS[id].tier);
  ok(`${id}: schema/version pinned from descriptor, not input`,
    S.normalize({ tier: "attested", schema: "hax", version: 99 }, id).schema === S.PRODUCTS[id].schema &&
    S.normalize({ version: 99 }, id).version === 1);
}

/* ===========================================================================
   RAIL 3 — deny-by-default capabilities across every shape.
   =========================================================================== */
ok("sloboda bridges all false by default",
  S.PRODUCTS.sloboda.cap.keys.every((k) => S.defaultState("sloboda").bridges[k] === false));
ok("noporis crossings all closed by default",
  S.PRODUCTS.noporis.cap.keys.every((k) => S.defaultState("noporis").crossings[k].open === false));
ok("porog crossings all closed + direction none by default",
  S.PRODUCTS.porog.cap.keys.every((k) => {
    const c = S.defaultState("porog").crossings[k];
    return c.open === false && c.direction === "none";
  }));
ok("porog calendar/connectedApp carry package:null; others have no package",
  S.defaultState("porog").crossings.calendar.package === null &&
  S.defaultState("porog").crossings.connectedApp.package === null &&
  !("package" in S.defaultState("porog").crossings.intents));
// truthy-but-not-true never opens (all shapes)
ok("sloboda: bridge open only on exactly true",
  S.normalize({ bridges: { mic: 1 } }, "sloboda").bridges.mic === false &&
  S.normalize({ bridges: { mic: "true" } }, "sloboda").bridges.mic === false);
ok("noporis: crossing open only on exactly true",
  S.normalize({ crossings: { mic: { open: 1 } } }, "noporis").crossings.mic.open === false);
ok("porog: crossing open only on exactly true; bad direction => none",
  S.normalize({ crossings: { files: { open: true, direction: "sideways" } } }, "porog").crossings.files.direction === "none");

/* ===========================================================================
   RAIL 4 — normalize() is the trust boundary: any input => well-formed full-deny.
   =========================================================================== */
for (const id of S.PRODUCT_IDS) {
  eq(`${id}: null input => default`, S.normalize(null, id), S.defaultState(id));
  eq(`${id}: string input => default`, S.normalize("nope", id), S.defaultState(id));
  eq(`${id}: array input => default`, S.normalize([1, 2, 3], id), S.defaultState(id));
  ok(`${id}: normalize never throws on hostile input`, (() => {
    try { S.normalize({ consent: 5, crossings: "x", bridges: null, killSwitch: [] }, id); return true; } catch { return false; }
  })());
  ok(`${id}: parse of corrupt JSON => full-deny, never throws`,
    S.parse("{not json", id).consent.accepted === false);
}

/* ===========================================================================
   RAIL 1 + version — loadState refuses foreign schema / unknown version => full-deny.
   =========================================================================== */
for (const id of S.PRODUCT_IDS) {
  const good = S.serialize({ consent: { accepted: true } }, id);
  ok(`${id}: loadState accepts a well-formed file`, S.loadState(good, id).consent.accepted === true);
  // foreign schema => full-deny (as if absent)
  const foreign = JSON.stringify({ ...JSON.parse(good), schema: "postern.someone-else.state" });
  eq(`${id}: foreign schema => full-deny`, S.loadState(foreign, id), S.defaultState(id));
  // unknown version => full-deny
  const badVer = JSON.stringify({ ...JSON.parse(good), version: 2 });
  eq(`${id}: unknown version => full-deny`, S.loadState(badVer, id), S.defaultState(id));
  // corrupt / non-object => full-deny
  eq(`${id}: corrupt json via loadState => full-deny`, S.loadState("{oops", id), S.defaultState(id));
  eq(`${id}: json literal null via loadState => full-deny`, S.loadState("null", id), S.defaultState(id));
}

/* ===========================================================================
   RAIL 6 — the projection is a PURE function: enabled iff consented && !killed &&
   at least one capability open. Same rule, all three tiers.
   =========================================================================== */
function projCase(id, mutate) {
  const s = mutate(S.defaultState(id));
  return S.projectionLine1(s, id);
}
const openOne = {
  sloboda: (s) => { s.bridges.clipboard = true; return s; },
  noporis: (s) => { s.crossings.clipboard.open = true; return s; },
  porog: (s) => { s.crossings.files.open = true; s.crossings.files.direction = "w2p"; return s; },
};
for (const id of S.PRODUCT_IDS) {
  ok(`${id}: fresh state projects disabled`, projCase(id, (s) => s) === "disabled");
  ok(`${id}: consent alone (no cap) projects disabled`,
    projCase(id, (s) => { s.consent.accepted = true; return s; }) === "disabled");
  ok(`${id}: cap open but no consent projects disabled`,
    projCase(id, (s) => openOne[id](s)) === "disabled");
  ok(`${id}: consented + one cap open projects enabled`,
    projCase(id, (s) => { s.consent.accepted = true; return openOne[id](s); }) === "enabled");
  ok(`${id}: kill overrides consented+open => disabled`,
    projCase(id, (s) => { s.consent.accepted = true; s.killSwitch.engaged = true; return openOne[id](s); }) === "disabled");
  // purity: same input => same output, no mutation of the argument
  const s = openOne[id](Object.assign(S.defaultState(id), { consent: { accepted: true, scope: "session", acceptedAtIso: null } }));
  const snapshot = JSON.stringify(s);
  const r1 = S.projectionLine1(s, id), r2 = S.projectionLine1(s, id);
  ok(`${id}: projection is deterministic & non-mutating`, r1 === r2 && JSON.stringify(s) === snapshot);
}
// projection FILE carries KEY=on extras only when enabled; line 1 is the authority
ok("sloboda projectionFile enabled carries clipboard=on extra",
  S.projectionFile((() => { const s = S.defaultState("sloboda"); s.consent.accepted = true; s.bridges.clipboard = true; return s; })(), "sloboda")
    === "enabled\nclipboard=on\n");
ok("noporis projectionFile disabled is exactly 'disabled\\n'",
  S.projectionFile(S.defaultState("noporis"), "noporis") === "disabled\n");
// porog: open WITHOUT a real direction installs no grant => disabled (fail-closed)
ok("porog: open crossing with direction none => not active => disabled",
  S.projectionLine1((() => { const s = S.defaultState("porog"); s.consent.accepted = true; s.crossings.files.open = true; return s; })(), "porog") === "disabled");

/* ===========================================================================
   RAIL 5 — kill-switch is non-destructive: pinned rails survive; caps masked not wiped.
   =========================================================================== */
ok("sloboda: engage kill preserves egress.torOnly, masks bridges, no egress",
  (() => {
    let s = S.defaultState("sloboda"); s.consent.accepted = true; s.bridges.files = true;
    s = S.engageKillSwitch(s, "sloboda", { atIso: "2026-07-13T00:00:00Z" });
    return s.egress.torOnly === true && s.killSwitch.engaged === true &&
      s.bridges.files === true /* masked, not wiped */ && S.activeCaps(s, "sloboda").length === 0;
  })());
ok("noporis: engage kill preserves sealedWallet, masks crossings; disengage restores",
  (() => {
    let s = S.defaultState("noporis"); s.consent.accepted = true; s.crossings.mic.open = true;
    s = S.engageKillSwitch(s, "noporis");
    const masked = S.activeCaps(s, "noporis").length === 0 && s.sealedWallet.preserved === true;
    s = S.disengageKillSwitch(s, "noporis");
    return masked && S.activeCaps(s, "noporis").length === 1 && s.crossings.mic.open === true;
  })());
ok("porog: engage kill preserves sealedWallet",
  (() => {
    let s = S.defaultState("porog"); s.consent.accepted = true; s.crossings.files.open = true; s.crossings.files.direction = "w2p";
    s = S.engageKillSwitch(s, "porog");
    return s.sealedWallet.preserved === true && S.activeCaps(s, "porog").length === 0;
  })());
// pinned rails cannot be flipped by hostile input, even under kill
ok("sloboda egress.torOnly cannot be cleared by input", S.normalize({ egress: { torOnly: false } }, "sloboda").egress.torOnly === true);
ok("noporis sealedWallet cannot be un-preserved by input", S.normalize({ sealedWallet: { preserved: false } }, "noporis").sealedWallet.preserved === true);
ok("porog sealedWallet cannot be un-preserved by input", S.normalize({ sealedWallet: { preserved: false } }, "porog").sealedWallet.preserved === true);

/* ===========================================================================
   RAIL 7 — no telemetry: the module does zero network I/O (source scan).
   =========================================================================== */
ok("spine source contains no network primitives", (() => {
  const src = readFileSync(join(HERE, "consent-spine.mjs"), "utf8");
  return !/\bfetch\s*\(|XMLHttpRequest|WebSocket|node:net|node:http|node:https|require\(['"](?:net|http|https|dgram)['"]\)/.test(src);
})());

/* ===========================================================================
   BYTE-COMPAT — the spine normalize() deep-equals the two SHIPPED gate-store
   kernels field-for-field, so 0.4 (Waydroid) / 0.5 (NoporIS) align on it.
   =========================================================================== */
const slobodaInputs = [
  undefined, null, "garbage", {},
  { consent: { accepted: true, scope: "persistent", acceptedAtIso: "2026-07-13T00:00:00Z" }, bridges: { clipboard: true, mic: 1 }, egress: { torOnly: false, torBootstrapped: true }, killSwitch: { engaged: true, engagedAtIso: "2026-07-13T00:00:00Z" }, lang: "pt-BR", tier: "attested", schema: "x", version: 5 },
  { bridges: { files: true, camera: "yes", location: true }, consent: { accepted: false, scope: "forever" } },
];
for (const [i, inp] of slobodaInputs.entries()) {
  eq(`byte-compat sloboda normalize #${i}`, S.normalize(inp, "sloboda"), slobodaStore.normalize(inp));
}
const noporisInputs = [
  undefined, null, "garbage", {},
  { consent: { accepted: true, scope: "session" }, crossings: { clipboard: { open: true, scope: "persistent", openedAtIso: "2026-07-13T00:00:00Z" }, mic: { open: 1 } }, killSwitch: { engaged: true, engagedAtIso: "2026-07-13T00:00:00Z" }, sealedWallet: { preserved: false }, lang: "pt-BR" },
  { crossings: { files: { open: true }, camera: "yes" } },
];
for (const [i, inp] of noporisInputs.entries()) {
  eq(`byte-compat noporis normalize #${i}`, S.normalize(inp, "noporis"), noporisStore.normalize(inp));
}
// default states are field-identical too (order-independent deep-equal)
eq("byte-compat sloboda defaultState", S.defaultState("sloboda"), slobodaStore.defaultState());
eq("byte-compat noporis defaultState", S.defaultState("noporis"), noporisStore.defaultState());
// and the shared decision helpers agree
ok("byte-compat sloboda containerAllowed agrees",
  S.containerAllowed({ consent: { accepted: true } }, "sloboda") === slobodaStore.containerAllowed({ consent: { accepted: true } }));
ok("byte-compat noporis bridgeStanding agrees",
  S.containerAllowed({ consent: { accepted: true } }, "noporis") === noporisStore.bridgeStanding({ consent: { accepted: true } }));

/* ===========================================================================
   ROUND-TRIP — serialize -> loadState is identity; example files load clean.
   =========================================================================== */
for (const id of S.PRODUCT_IDS) {
  eq(`${id}: serialize -> loadState round-trips`, S.loadState(S.serialize(S.defaultState(id), id), id), S.defaultState(id));
  eq(`${id}: example default file loads to defaultState`,
    S.loadState(readFileSync(join(HERE, "examples", `${id}.state.json`), "utf8"), id), S.defaultState(id));
  ok(`${id}: consented example projects enabled`,
    S.projectionLine1(S.loadState(readFileSync(join(HERE, "examples", `${id}.consented.state.json`), "utf8"), id), id) === "enabled");
}

/* ===========================================================================
   SCHEMA VALIDATION — a small, dependency-free draft-07-subset validator that
   checks the example JSON files against consent-spine.schema.json ITSELF
   (not just behaviorally via S.loadState/S.normalize as above). Node
   built-ins only; no package.json/node_modules in this repo and the
   permissive-license rule forbids vendoring a JSON Schema library.

   Supports exactly the constructs this schema uses: $ref into
   #/definitions, oneOf, type (including union types like ["string","null"]),
   const, enum, required, properties, additionalProperties:false, and the
   object/boolean/string/integer primitives. It is intentionally NOT a
   general JSON Schema validator — anything this schema doesn't use
   (patternProperties, array items, if/then/else, $ref outside
   #/definitions, ...) is unsupported by design.
   =========================================================================== */
const SCHEMA = JSON.parse(readFileSync(join(HERE, "consent-spine.schema.json"), "utf8"));

function schemaTypeOk(type, data) {
  switch (type) {
    case "object": return typeof data === "object" && data !== null && !Array.isArray(data);
    case "array": return Array.isArray(data);
    case "string": return typeof data === "string";
    case "boolean": return typeof data === "boolean";
    case "integer": return typeof data === "number" && Number.isInteger(data);
    case "number": return typeof data === "number";
    case "null": return data === null;
    default: return false;
  }
}
function schemaTypesMatch(t, data) {
  return (Array.isArray(t) ? t : [t]).some((one) => schemaTypeOk(one, data));
}
function schemaDeepEqual(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}
/* Validates `data` against schema fragment `node`, resolving $ref against
   `defs` (the schema's #/definitions). Pushes a human-readable reason onto
   `errs` on failure. Returns true/false. */
function validateNode(node, data, defs, errs, path) {
  if (node.$ref) {
    const name = node.$ref.replace("#/definitions/", "");
    const target = defs[name];
    if (!target) { errs.push(`${path}: unresolved $ref ${node.$ref}`); return false; }
    return validateNode(target, data, defs, errs, path);
  }
  if (node.oneOf) {
    const matches = node.oneOf.filter((sub) => validateNode(sub, data, defs, [], path));
    if (matches.length !== 1) { errs.push(`${path}: oneOf matched ${matches.length} branches, want exactly 1`); return false; }
    return true;
  }
  if (node.const !== undefined) {
    if (!schemaDeepEqual(data, node.const)) { errs.push(`${path}: expected const ${JSON.stringify(node.const)}, got ${JSON.stringify(data)}`); return false; }
    return true;
  }
  if (node.enum) {
    if (!node.enum.some((e) => schemaDeepEqual(e, data))) { errs.push(`${path}: ${JSON.stringify(data)} not in enum ${JSON.stringify(node.enum)}`); return false; }
    return true;
  }
  if (node.type && !schemaTypesMatch(node.type, data)) {
    errs.push(`${path}: type mismatch, expected ${JSON.stringify(node.type)}, got ${data === null ? "null" : typeof data}`);
    return false;
  }
  if (node.type === "object" || node.properties || node.required) {
    if (typeof data !== "object" || data === null || Array.isArray(data)) {
      errs.push(`${path}: expected object`); return false;
    }
    for (const req of node.required || []) {
      if (!(req in data)) { errs.push(`${path}: missing required '${req}'`); return false; }
    }
    for (const key of Object.keys(node.properties || {})) {
      if (key in data && !validateNode(node.properties[key], data[key], defs, errs, `${path}.${key}`)) return false;
    }
    if (node.additionalProperties === false) {
      const allowed = new Set(Object.keys(node.properties || {}));
      for (const key of Object.keys(data)) {
        if (!allowed.has(key)) { errs.push(`${path}: additional property '${key}' not permitted`); return false; }
      }
    }
  }
  return true;
}
/* Returns the array of indices into SCHEMA.oneOf that `data` matches at the
   top level — used to assert "exactly one branch, and it's the right one". */
function topLevelMatches(data) {
  return SCHEMA.oneOf
    .map((sub, i) => (validateNode(sub, data, SCHEMA.definitions, [], "$") ? i : -1))
    .filter((i) => i >= 0);
}
/* True iff `data` validates against the whole schema (exactly one oneOf branch). */
function validatesSchema(data) {
  return topLevelMatches(data).length === 1;
}

// oneOf branch order in the schema: [slobodaState, noporisState, porogState]
const ONEOF_INDEX = { sloboda: 0, noporis: 1, porog: 2 };

for (const id of S.PRODUCT_IDS) {
  for (const variant of ["state", "consented.state"]) {
    const data = JSON.parse(readFileSync(join(HERE, "examples", `${id}.${variant}.json`), "utf8"));
    const matches = topLevelMatches(data);
    ok(`${id}.${variant}.json: matches exactly one oneOf branch of the schema`, matches.length === 1);
    ok(`${id}.${variant}.json: the matched branch is ${id}'s own definition`, matches[0] === ONEOF_INDEX[id]);
  }
}

/* Negative checks — a mutated copy of a real example must FAIL validation. */
{
  // (a) unknown extra key => additionalProperties:false on every branch rejects it.
  const base = JSON.parse(readFileSync(join(HERE, "examples", "sloboda.state.json"), "utf8"));
  const mutated = { ...base, extraUnknownField: "not in the schema" };
  ok("negative: unknown extra top-level key fails schema validation", validatesSchema(mutated) === false);
}
{
  // (b) tier swapped to another product's pinned tier value (porog's, on a sloboda file).
  const base = JSON.parse(readFileSync(join(HERE, "examples", "sloboda.state.json"), "utf8"));
  const mutated = { ...base, tier: "key-attested-device" };
  ok("negative: tier swapped to another product's tier fails schema validation", validatesSchema(mutated) === false);
}
{
  // (c) consent.scope set to a value outside its enum (["session","persistent"]).
  const base = JSON.parse(readFileSync(join(HERE, "examples", "noporis.state.json"), "utf8"));
  const mutated = { ...base, consent: { ...base.consent, scope: "forever" } };
  ok("negative: consent.scope out-of-enum value fails schema validation", validatesSchema(mutated) === false);
}

/* ===========================================================================
   BYTE-PINNING — the example files are the serializer's OWN output, byte for
   byte. Two identities are pinned for ALL SIX example files:
     (1) serialize(loadState(fileText)) === fileText  — loading an example and
         re-serializing it is a byte-identical round trip, so an example can
         never silently lag the schema (normalize() quietly filling in a new
         field — as happened when NoporIS crossings grew 'direction' — now
         fails HERE loudly instead);
     (2) serialize(defaultState(id)) === <id>.state.json — the default example
         IS the default state, byte for byte.
   Any future schema evolution must regenerate the examples in the same
   commit, or this section exit-1s.
   =========================================================================== */
for (const id of S.PRODUCT_IDS) {
  for (const variant of ["state", "consented.state"]) {
    const fileText = readFileSync(join(HERE, "examples", `${id}.${variant}.json`), "utf8");
    ok(`${id}.${variant}.json: serialize(loadState(file)) is BYTE-identical (example not stale)`,
      S.serialize(S.loadState(fileText, id), id) === fileText);
  }
  ok(`${id}.state.json: BYTE-equal to serialize(defaultState('${id}'))`,
    S.serialize(S.defaultState(id), id) === readFileSync(join(HERE, "examples", `${id}.state.json`), "utf8"));
}
// the evolved NoporIS crossing shape carries its single-lane 'direction' ON DISK
ok("noporis examples carry 'direction' on every crossing (on disk, not just after normalize)", (() => {
  for (const variant of ["state", "consented.state"]) {
    const raw = JSON.parse(readFileSync(join(HERE, "examples", `noporis.${variant}.json`), "utf8"));
    for (const k of S.PRODUCTS.noporis.cap.keys) {
      if (typeof raw.crossings[k].direction !== "string") return false;
    }
  }
  return true;
})());
// the consented example DELIBERATELY keeps the far→near ingest lane closed:
// every lane is the safer near-to-far default (no far-to-near showcased).
ok("noporis consented example is far-to-near-free (every lane is near-to-far)", (() => {
  const raw = JSON.parse(readFileSync(join(HERE, "examples", "noporis.consented.state.json"), "utf8"));
  return S.PRODUCTS.noporis.cap.keys.every((k) => raw.crossings[k].direction === "near-to-far");
})());

console.log(`consent-spine: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
