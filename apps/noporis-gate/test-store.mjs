// SPDX-License-Identifier: MIT OR Apache-2.0
"use strict";
/* Minimal, dependency-free checks for gate-store.mjs. Run: node test-store.mjs
   These assert the guarded-crossing honesty rails hold in code (default-deny,
   fixed non-attestable tier, anti-round-up / no silent grant, malformed-in =>
   safe-out, and the sealed-wallet invariant the kill-switch may never break).
   They do NOT test the (non-existent) on-device wrapper — that stays UNTESTED
   until real hardware exists. */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import S from "./gate-store.mjs";

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; } else { fail++; console.error("FAIL:", name); } };

const d = S.defaultState();

// --- defaults: everything denied, tier fixed, wallet preserved ---
ok("tier fixed non-attestable", d.tier === "non-attestable");
ok("consent denied by default", d.consent.accepted === false);
ok("all crossings closed by default", S.CROSSING_KEYS.every((k) => d.crossings[k].open === false));
ok("kill-switch clear by default", d.killSwitch.engaged === false);
ok("sealed wallet preserved by default", d.sealedWallet.preserved === true);
ok("far side flagged less-private", S.LESS_PRIVATE_FAR_SIDE === true);

// --- malformed / hostile input must collapse to safe default ---
ok("garbage normalizes to deny", S.normalize(null).consent.accepted === false);
ok("string input is safe", JSON.stringify(S.normalize("nope")) === JSON.stringify(d));
ok("truthy-but-not-true crossing denied", S.normalize({ crossings: { mic: { open: 1 } } }).crossings.mic.open === false);
ok("non-object crossing denied", S.normalize({ crossings: { camera: "yes" } }).crossings.camera.open === false);
ok("cannot relabel tier", S.normalize({ tier: "attested" }).tier === "non-attestable");
ok("cannot un-preserve sealed wallet via input", S.normalize({ sealedWallet: { preserved: false } }).sealedWallet.preserved === true);
ok("unknown consent scope falls back to session", S.normalize({ consent: { accepted: true, scope: "forever" } }).consent.scope === "session");
ok("unknown crossing scope falls back to session", S.normalize({ crossings: { files: { open: true, scope: "forever" } } }).crossings.files.scope === "session");
ok("closed crossing has null openedAt", S.normalize({ crossings: { files: { open: false, openedAtIso: "2026-01-01T00:00:00Z" } } }).crossings.files.openedAtIso === null);

// --- parse of corrupt JSON => safe default, never throws ---
ok("corrupt json => default", S.parse("{not json").consent.accepted === false);

// --- loadState: the STRICT on-disk rail (foreign schema / unknown version =>
//     full-deny BEFORE normalize; matches sloboda-gate's loadState, the shared
//     consent-contract spine, and the Rust orchestrator's from_gate_json) ---
const consentedFileText = S.serialize(S.openCrossing(S.acceptConsent(S.defaultState(), { scope: "session" }), "mic"));
ok("loadState accepts a well-formed own-schema file",
  S.loadState(consentedFileText).crossings.mic.open === true);
ok("loadState: foreign schema => full-deny (grants dropped)",
  (() => {
    const foreign = JSON.parse(consentedFileText);
    foreign.schema = "com.evil.other.state";
    const s = S.loadState(JSON.stringify(foreign));
    return JSON.stringify(s) === JSON.stringify(d);
  })());
ok("loadState: unknown/future version => full-deny (grants dropped)",
  (() => {
    const future = JSON.parse(consentedFileText);
    future.version = 2;
    const s = S.loadState(JSON.stringify(future));
    return JSON.stringify(s) === JSON.stringify(d);
  })());
ok("loadState: missing discriminator => full-deny",
  S.loadState(JSON.stringify({ consent: { accepted: true }, crossings: { mic: { open: true } } })).consent.accepted === false);
ok("loadState: corrupt json => full-deny", JSON.stringify(S.loadState("{oops")) === JSON.stringify(d));
ok("loadState: json literal null => full-deny", JSON.stringify(S.loadState("null")) === JSON.stringify(d));
ok("loadState: non-object json => full-deny", S.loadState("42").consent.accepted === false);
ok("loadState refuses a SIBLING-product schema (sloboda-gate id => full-deny)",
  S.loadState(JSON.stringify({ schema: "postern.sloboda-gate.state", version: 1, consent: { accepted: true } })).consent.accepted === false);
ok("loadState: projection of a hostile foreign file is disabled (never enabled)",
  (() => {
    const foreign = JSON.parse(consentedFileText);
    foreign.schema = "com.evil.other.state";
    return S.projectNoporisBridgeState(S.loadState(JSON.stringify(foreign))) === "disabled";
  })());
ok("loadState round-trips serialize(defaultState())",
  JSON.stringify(S.loadState(S.serialize(d))) === JSON.stringify(d));
// parse() stays TOLERANT by design (in-memory/partial states); loadState is the
// strict boundary — assert the split explicitly so it cannot silently invert.
ok("parse is tolerant where loadState is strict (documented split)",
  (() => {
    const foreign = JSON.parse(consentedFileText);
    foreign.schema = "com.evil.other.state";
    const text = JSON.stringify(foreign);
    return S.parse(text).crossings.mic.open === true && S.loadState(text).crossings.mic.open === false;
  })());

// --- decision helpers: bridge standing ---
ok("bridge down without consent", S.bridgeStanding(d) === false);
ok("bridge stands once consented", S.bridgeStanding({ consent: { accepted: true } }) === true);
ok("kill-switch overrides consent", S.bridgeStanding({ consent: { accepted: true }, killSwitch: { engaged: true } }) === false);
ok("requireConsent=false bypasses consent", S.bridgeStanding(d, { requireConsent: false }) === true);

// --- active crossings: fail-closed, only-explicit ---
ok("no crossings active without consent",
  S.activeCrossings({ crossings: { clipboard: { open: true } } }).length === 0);
ok("only explicit crossings active when consented",
  JSON.stringify(S.activeCrossings({ consent: { accepted: true }, crossings: { clipboard: { open: true }, mic: { open: true } } })) ===
  JSON.stringify(["clipboard", "mic"]));
ok("kill-switch masks all crossings",
  S.activeCrossings({ consent: { accepted: true }, crossings: { clipboard: { open: true } }, killSwitch: { engaged: true } }).length === 0);

// --- anti-round-up: openCrossing never silently grants ---
ok("openCrossing is a no-op without consent (no silent grant)",
  S.openCrossing(d, "clipboard").crossings.clipboard.open === false);
ok("openCrossing is a no-op under kill-switch",
  S.openCrossing({ consent: { accepted: true }, killSwitch: { engaged: true } }, "clipboard").crossings.clipboard.open === false);
ok("openCrossing opens exactly one capability",
  (() => {
    const s = S.openCrossing({ consent: { accepted: true } }, "clipboard");
    return s.crossings.clipboard.open === true &&
      S.CROSSING_KEYS.filter((k) => k !== "clipboard").every((k) => s.crossings[k].open === false);
  })());
ok("openCrossing refuses unknown capability",
  JSON.stringify(S.openCrossing({ consent: { accepted: true } }, "contacts")) ===
  JSON.stringify(S.normalize({ consent: { accepted: true } })));

// --- revocation: collapse to never-given ---
ok("revokeCrossing collapses to never-given",
  (() => {
    let s = S.openCrossing({ consent: { accepted: true } }, "camera", { scope: "persistent", atIso: "2026-01-01T00:00:00Z" });
    s = S.revokeCrossing(s, "camera");
    return JSON.stringify(s.crossings.camera) === JSON.stringify({ open: false, scope: "session", direction: "near-to-far", openedAtIso: null });
  })());
ok("revokeAllCrossings clears every crossing",
  (() => {
    let s = S.normalize({ consent: { accepted: true } });
    for (const k of S.CROSSING_KEYS) s = S.openCrossing(s, k);
    s = S.revokeAllCrossings(s);
    return S.CROSSING_KEYS.every((k) => s.crossings[k].open === false);
  })());
ok("withdrawConsent drops bridge AND clears crossings",
  (() => {
    let s = S.openCrossing({ consent: { accepted: true } }, "files");
    s = S.withdrawConsent(s);
    return s.consent.accepted === false && s.crossings.files.open === false;
  })());

// --- kill-switch: drops span, NEVER destroys sealed wallet ---
ok("walletPreserved always true", S.walletPreserved(d) === true && S.walletPreserved({ sealedWallet: { preserved: false } }) === true);
ok("engageKillSwitch preserves sealed wallet",
  (() => {
    let s = S.openCrossing({ consent: { accepted: true } }, "clipboard");
    s = S.engageKillSwitch(s, { atIso: "2026-07-12T00:00:00Z" });
    return s.killSwitch.engaged === true && s.sealedWallet.preserved === true && S.activeCrossings(s).length === 0;
  })());
ok("kill-switch masks (does not wipe) crossings; disengage restores",
  (() => {
    let s = S.openCrossing({ consent: { accepted: true } }, "mic");
    s = S.engageKillSwitch(s);
    const maskedGone = S.activeCrossings(s).length === 0;
    s = S.disengageKillSwitch(s);
    return maskedGone && S.activeCrossings(s).length === 1 && s.crossings.mic.open === true;
  })());

// --- runtime bridge-state projection: the single string the orchestrator writes ---
ok("projection value constants are the two literals",
  S.BRIDGE_STATE_ENABLED === "enabled" && S.BRIDGE_STATE_DISABLED === "disabled");
ok("projection disabled by default (default-closed)",
  S.projectNoporisBridgeState(d) === "disabled");
ok("projection disabled when consented but NO crossing open",
  S.projectNoporisBridgeState({ consent: { accepted: true } }) === "disabled");
ok("projection ENABLED only when consented AND a crossing open",
  S.projectNoporisBridgeState(S.openCrossing({ consent: { accepted: true } }, "clipboard")) === "enabled");
ok("projection disabled without consent even if a crossing looks open",
  S.projectNoporisBridgeState({ crossings: { clipboard: { open: true } } }) === "disabled");
ok("projection disabled under kill-switch even with a crossing open",
  (() => {
    let s = S.openCrossing({ consent: { accepted: true } }, "mic");
    s = S.engageKillSwitch(s);
    return S.projectNoporisBridgeState(s) === "disabled";
  })());
ok("projection collapses malformed/hostile input to disabled",
  S.projectNoporisBridgeState("nope") === "disabled" &&
  S.projectNoporisBridgeState(null) === "disabled" &&
  S.projectNoporisBridgeState({ crossings: { clipboard: { open: 1 } }, consent: { accepted: true } }) === "disabled");
ok("projection agrees with activeCrossings (never disagree)",
  (() => {
    let s = S.openCrossing({ consent: { accepted: true } }, "files");
    const enabled = S.projectNoporisBridgeState(s) === "enabled";
    return enabled === (S.activeCrossings(s).length > 0);
  })());
ok("projection is pure — does not mutate its input",
  (() => {
    const s = S.openCrossing({ consent: { accepted: true } }, "location");
    const before = JSON.stringify(s);
    S.projectNoporisBridgeState(s);
    return JSON.stringify(s) === before;
  })());

// --- direction (DPM lane): single lane, never widened, fail-closed default ---
ok("crossing direction defaults to near-to-far", d.crossings.clipboard.direction === "near-to-far");
ok("unknown direction falls back to near-to-far (never both)",
  S.normalize({ crossings: { files: { open: true, direction: "both" } } }).crossings.files.direction === "near-to-far");
ok("far-to-near ingest lane is honoured when chosen on purpose",
  S.normalize({ crossings: { files: { open: true, direction: "far-to-near" } } }).crossings.files.direction === "far-to-near");
ok("openCrossing pins the requested lane",
  S.openCrossing({ consent: { accepted: true } }, "clipboard", { direction: "far-to-near" }).crossings.clipboard.direction === "far-to-near");
ok("openCrossing with garbage direction collapses to near-to-far",
  S.openCrossing({ consent: { accepted: true } }, "clipboard", { direction: "sideways" }).crossings.clipboard.direction === "near-to-far");

// --- sloboda-bridge.state projection (noporis-02 §3.2): SOLE-writer derived toggle ---
ok("toggle disabled by default (fail-closed)", S.slobodaBridgeToggle(d) === "disabled");
ok("toggle disabled when consented but nothing crossing",
  S.slobodaBridgeToggle({ consent: { accepted: true } }) === "disabled");
ok("toggle enabled only when standing AND a crossing is lent",
  S.slobodaBridgeToggle(S.openCrossing({ consent: { accepted: true } }, "clipboard")) === "enabled");
ok("kill-switch flips toggle to disabled at once",
  (() => {
    let s = S.openCrossing({ consent: { accepted: true } }, "clipboard");
    s = S.engageKillSwitch(s);
    return S.slobodaBridgeToggle(s) === "disabled";
  })());
ok("withdrawn consent projects disabled",
  S.slobodaBridgeToggle(S.withdrawConsent(S.openCrossing({ consent: { accepted: true } }, "mic"))) === "disabled");
ok("garbage state projects disabled", S.slobodaBridgeToggle("nope") === "disabled");
ok("state-file line 1 is the load-bearing toggle",
  (() => {
    const body = S.slobodaBridgeStateFile(S.openCrossing({ consent: { accepted: true } }, "files"));
    return body.split("\n")[0] === "enabled" && body.endsWith("\n");
  })());
ok("state-file default first line is disabled",
  S.slobodaBridgeStateFile(d).split("\n")[0] === "disabled");

// --- cross-language golden: the killed (disabled) projection body is pinned
//     byte-for-byte against the SAME fixture the Rust writer is pinned to
//     (apps/noporis-bridge-glue/tests/cross_lang_conformance.rs). The killed
//     posture — line 1 `disabled`, `kill=engaged`, `schema_version=1` — is the
//     exact body a polling consumer relies on to see the span DROP; both writers
//     MUST emit these identical bytes. The golden was authored by THIS JS writer. ---
const disabledGolden = readFileSync(
  join(
    dirname(fileURLToPath(import.meta.url)),
    "..", "noporis-bridge-glue", "tests", "golden", "sloboda-bridge.disabled.state",
  ),
  "utf8",
);
ok("cross-lang golden is the exact kill-switch contract bytes",
  disabledGolden === "disabled\nkill=engaged\nschema_version=1\n");
ok("JS slobodaBridgeStateFile emits the golden byte-for-byte on a kill-switched state",
  (() => {
    let killed = S.openCrossing(S.acceptConsent(S.defaultState()), "clipboard");
    killed = S.engageKillSwitch(killed);
    return S.slobodaBridgeStateFile(killed) === disabledGolden;
  })());
ok("every distinct killed posture collapses to the SAME golden bytes",
  (() => {
    const consentedKilled = S.engageKillSwitch(S.acceptConsent(S.defaultState(), { scope: "persistent" }));
    const denyAllKilled = S.engageKillSwitch(S.defaultState());
    return S.slobodaBridgeStateFile(consentedKilled) === disabledGolden
        && S.slobodaBridgeStateFile(denyAllKilled) === disabledGolden;
  })());
ok("the pinned schema_version mirrors the Rust writer's constant",
  disabledGolden.trimEnd().endsWith("schema_version=" + S.SLOBODA_BRIDGE_SCHEMA_VERSION));
ok("the enabled projection differs from the pinned disabled golden",
  (() => {
    const enabled = S.slobodaBridgeStateFile(S.openCrossing(S.acceptConsent(S.defaultState()), "files"));
    return enabled !== disabledGolden && enabled.startsWith("enabled\ncontainer=allowed\n");
  })());

// --- round-trip ---
ok("serialize round-trips", JSON.stringify(S.parse(S.serialize(d))) === JSON.stringify(d));

/* ============================================================================
   Dependency-free draft-07 SUBSET JSON Schema validator (self-written here,
   MIT OR Apache-2.0, no npm deps — same terms as this file's SPDX header).

   Covers EXACTLY the draft-07 vocabulary gate-state.schema.json actually uses:
   type (including ["string","null"] unions), const, enum, required,
   properties, additionalProperties:false, and $ref resolution into
   #/definitions/<name>. It is NOT a general-purpose JSON Schema validator —
   no allOf/anyOf/oneOf, no patternProperties, no numeric/string keywords, no
   remote $ref, no format. That subset is sufficient to prove the one schema
   file in this directory and its one example file agree, and to prove a
   handful of hostile mutations of that example are rejected by the schema.

   HONEST SCOPE: this validates only the schema/example PAIR that ships in
   this directory (gate-state.schema.json <-> state.example.json). It says
   NOTHING about the (non-existent) on-device NoporIS wrapper that would read
   a live state file on real hardware — that wrapper remains UNTESTED, same
   as documented at the top of gate-store.mjs and in this file's header
   comment. Schema conformance is not attestation, not an audit, and not a
   security boundary; it is a shape check on two files in a repo.
   ============================================================================ */

function resolveRef(ref, root) {
  if (typeof ref !== "string" || !ref.startsWith("#/")) {
    throw new Error(`unsupported $ref (only local #/... refs are handled): ${ref}`);
  }
  return ref
    .slice(2)
    .split("/")
    .reduce((node, key) => {
      if (node == null || !(key in node)) throw new Error(`$ref path not found: ${ref}`);
      return node[key];
    }, root);
}

function typeOf(value) {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value; // "object" | "string" | "number" | "boolean"
}

/* Validate `data` against `schema` (a draft-07 SUBSET node), resolving $ref
   against `root`. Appends human-readable messages to `errors` at `path`.
   Pure function; never throws on a mismatch (only on a malformed schema,
   e.g. a dangling $ref, which is a bug in the schema file itself). */
function validateNode(schema, data, root, path, errors) {
  if (schema.$ref) {
    validateNode(resolveRef(schema.$ref, root), data, root, path, errors);
    return;
  }

  if (Object.prototype.hasOwnProperty.call(schema, "const")) {
    if (data !== schema.const) {
      errors.push(`${path}: expected const ${JSON.stringify(schema.const)}, got ${JSON.stringify(data)}`);
      return;
    }
  }

  if (Object.prototype.hasOwnProperty.call(schema, "enum")) {
    if (!schema.enum.includes(data)) {
      errors.push(`${path}: ${JSON.stringify(data)} is not one of enum ${JSON.stringify(schema.enum)}`);
      return;
    }
  }

  if (schema.type !== undefined) {
    const allowed = Array.isArray(schema.type) ? schema.type : [schema.type];
    const actual = typeOf(data);
    if (!allowed.includes(actual)) {
      errors.push(`${path}: expected type ${JSON.stringify(schema.type)}, got "${actual}"`);
      return;
    }
  }

  const typesInPlay = schema.type === undefined ? [] : Array.isArray(schema.type) ? schema.type : [schema.type];
  const treatAsObject = typesInPlay.includes("object") && typeOf(data) === "object";
  if (treatAsObject) {
    if (Array.isArray(schema.required)) {
      for (const key of schema.required) {
        if (!Object.prototype.hasOwnProperty.call(data, key)) {
          errors.push(`${path}: missing required property "${key}"`);
        }
      }
    }
    const propSchemas = schema.properties || {};
    for (const key of Object.keys(propSchemas)) {
      if (Object.prototype.hasOwnProperty.call(data, key)) {
        validateNode(propSchemas[key], data[key], root, `${path}/${key}`, errors);
      }
    }
    if (schema.additionalProperties === false) {
      const allowedKeys = new Set(Object.keys(propSchemas));
      for (const key of Object.keys(data)) {
        if (!allowedKeys.has(key)) {
          errors.push(`${path}: additional property "${key}" is not allowed`);
        }
      }
    }
  }
}

/* Validate `data` against a full draft-07-SUBSET schema document. Returns
   { valid, errors }. Never throws for ordinary schema mismatches. */
function validateAgainstSchema(schema, data) {
  const errors = [];
  validateNode(schema, data, schema, "$", errors);
  return { valid: errors.length === 0, errors };
}

const __dirname = dirname(fileURLToPath(import.meta.url));
const schemaText = readFileSync(join(__dirname, "gate-state.schema.json"), "utf8");
const exampleText = readFileSync(join(__dirname, "state.example.json"), "utf8");
const schema = JSON.parse(schemaText);
const example = JSON.parse(exampleText);

// (a) the shipped example must conform to the shipped schema.
const exampleResult = validateAgainstSchema(schema, example);
ok(
  "state.example.json validates against gate-state.schema.json" +
    (exampleResult.valid ? "" : ` (errors: ${exampleResult.errors.join("; ")})`),
  exampleResult.valid,
);

// (b) round-trip pin: serialize(defaultState()) must be BYTE-EQUAL to the
// example file on disk — the example is not just schema-valid, it is the
// literal, canonical output of this module's own defaults.
ok("serialize(defaultState()) is byte-equal to state.example.json", S.serialize(S.defaultState()) === exampleText);

// (c) hostile mutations of an otherwise-valid state must FAIL validation.
const mutateTierAttested = JSON.parse(exampleText); // hostile relabel fixture — never valid
mutateTierAttested.tier = "attested"; // relabel attempt — refused by the schema below
ok(
  'hostile mutation tier:"attested" is refused by the schema',
  validateAgainstSchema(schema, mutateTierAttested).valid === false,
);

const mutateWalletUnpreserved = JSON.parse(exampleText);
mutateWalletUnpreserved.sealedWallet.preserved = false;
ok(
  "hostile mutation sealedWallet.preserved:false is rejected by the schema",
  validateAgainstSchema(schema, mutateWalletUnpreserved).valid === false,
);

const mutateExtraProperty = JSON.parse(exampleText);
mutateExtraProperty.backdoor = true;
ok(
  "hostile mutation with an unknown top-level property is rejected by the schema",
  validateAgainstSchema(schema, mutateExtraProperty).valid === false,
);

// --- schema/version mismatch => pinned + full-deny (a foreign/older writer cannot
//     relabel the store or smuggle an open crossing past normalize) ---
ok("foreign schema id is re-pinned, never trusted",
  S.normalize({ schema: "evil.other.schema", consent: { accepted: true } }).schema === S.SCHEMA_ID);
ok("foreign version is re-pinned to the canonical version",
  S.normalize({ version: 999, consent: { accepted: true } }).version === S.SCHEMA_VERSION);
ok("a foreign-schema blob cannot smuggle an open crossing without consent",
  S.activeCrossings({ schema: "evil", version: 999, crossings: { mic: { open: true } } }).length === 0);
ok("projection ignores schema/version and keys only off consent+crossing",
  S.projectNoporisBridgeState({ schema: "evil", version: 42, crossings: { clipboard: { open: true } } }) === "disabled");

// --- sealed-wallet pin is non-unsettable across EVERY mutation path ---
ok("withdrawConsent keeps sealed wallet preserved",
  S.walletPreserved(S.withdrawConsent(S.openCrossing({ consent: { accepted: true } }, "files"))) === true);
ok("revokeAllCrossings keeps sealed wallet preserved",
  S.walletPreserved(S.revokeAllCrossings(S.normalize({ consent: { accepted: true } }))) === true);
ok("disengageKillSwitch keeps sealed wallet preserved",
  S.walletPreserved(S.disengageKillSwitch(S.engageKillSwitch(S.normalize({ consent: { accepted: true } })))) === true);

// --- kill-switch MASKS (never wipes) the chosen direction; revoke resets it ---
ok("kill-switch masks a far-to-near crossing but preserves its pinned direction",
  (() => {
    let s = S.openCrossing({ consent: { accepted: true } }, "files", { direction: "far-to-near" });
    s = S.engageKillSwitch(s);
    // Masked from active set…
    const masked = S.activeCrossings(s).length === 0;
    // …but the persisted lane is untouched (not silently widened or reset while masked).
    const laneKept = s.crossings.files.direction === "far-to-near" && s.crossings.files.open === true;
    s = S.disengageKillSwitch(s);
    const restored = S.activeCrossings(s).length === 1 && s.crossings.files.direction === "far-to-near";
    return masked && laneKept && restored;
  })());
ok("revokeCrossing resets a far-to-near lane back to the near-to-far default",
  (() => {
    let s = S.openCrossing({ consent: { accepted: true } }, "clipboard", { direction: "far-to-near" });
    s = S.revokeCrossing(s, "clipboard");
    return s.crossings.clipboard.direction === "near-to-far" && s.crossings.clipboard.open === false;
  })());
ok("withdrawConsent resets direction to the safe default on every lane",
  (() => {
    let s = S.openCrossing({ consent: { accepted: true } }, "mic", { direction: "far-to-near" });
    s = S.withdrawConsent(s);
    return s.crossings.mic.direction === "near-to-far" && s.crossings.mic.open === false;
  })());

console.log(`noporis-gate: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
