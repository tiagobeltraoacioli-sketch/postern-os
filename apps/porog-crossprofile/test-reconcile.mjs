"use strict";
/* Minimal, dependency-free checks for reconcile-kernel.mjs. Run:
     node test-reconcile.mjs
   These assert the honesty rails hold IN CODE (default-deny, fail-closed on
   malformed, anti-round-up, direction mapping, standing-cap stronger-consent
   gate, kill-switch clears everything, schema-version mismatch => full-deny,
   the `open` primary deny gate, and package-cap validity).
   They do NOT test the (later/VM) Kotlin DPC that applies these directives. */
import K from "./reconcile-kernel.mjs";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const HERE = fileURLToPath(new URL(".", import.meta.url));
const readJson = (name) => JSON.parse(readFileSync(HERE + name, "utf8"));

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; } else { fail++; console.error("FAIL:", name); } };

// A well-formed base state: recognised schema/version, consented, no crossings.
const base = (over = {}) => ({
  schema: K.SCHEMA_ID,
  version: K.SCHEMA_VERSION,
  consent: { accepted: true },
  ...over,
});
const stand = (over) => base({ consent: { accepted: true, standing: true }, ...over });
const hasFilter = (d, cap) => d.intentFilters.find((f) => f.capability === cap);
const hasPkg = (d, cap) => d.crossProfilePackages.find((p) => p.capability === cap);

/* ---- defaults & honesty pins ------------------------------------------- */
const def = K.defaultState();
ok("tier pinned key-attested-device", def.tier === "key-attested-device");
ok("consent denied by default", def.consent.accepted === false);
ok("standing consent off by default", def.consent.standing === false);
ok("every crossing 'none' by default", K.CROSSING_KEYS.every((c) => def.crossings[c].direction === "none"));
ok("every crossing closed by default", K.CROSSING_KEYS.every((c) => def.crossings[c].open === false));
ok("kill-switch clear by default", def.killSwitch.engaged === false);
ok("sealedWallet.preserved pinned true", def.sealedWallet.preserved === true);
ok("cannot relabel tier", K.normalize({ tier: "measured-boot-workspace" }).tier === "key-attested-device");
ok("cannot unpin sealedWallet", K.normalize({ sealedWallet: { preserved: false } }).sealedWallet.preserved === true);

/* ---- default-deny: the empty/absent state opens nothing ---------------- */
const dDeny = K.reconcile(K.defaultState()); // recognised schema, but not consented
ok("default state is not open", dDeny.open === false);
ok("default state installs no intent filters", dDeny.intentFilters.length === 0);
ok("default state empties the allowlist", dDeny.crossProfilePackages.length === 0);
ok("default state keeps copy/paste disallowed", dDeny.copyPasteDisallowed === true);
ok("default state closes the contacts policy", dDeny.contactsPolicy.open === false);
ok("default state blocks inbound share", dDeny.shareIntoManagedProfileDisallowed === true);

/* ---- fail-closed on malformed / unknown schema => FULL-DENY ------------- */
ok("null input => full-deny", K.reconcile(null).open === false);
ok("string input => full-deny", K.reconcile("nope").open === false);
ok("missing schema => full-deny", K.reconcile({ consent: { accepted: true } }).open === false);
ok("wrong schema id => full-deny", K.reconcile(base({ schema: "some.other" })).open === false);
ok("wrong version => full-deny", K.reconcile(base({ version: 2 })).open === false);
ok("stringified version => full-deny", K.reconcile(base({ version: "1" })).open === false);
ok("schema-mismatch reason names it", K.reconcile(base({ version: 999 })).reason.includes("schema"));
ok("unparseable text => full-deny", K.reconcileText("{not json").open === false);
ok("full-deny still empties everything",
  (() => { const d = K.reconcile(base({ version: 7 }));
    return d.intentFilters.length === 0 && d.crossProfilePackages.length === 0 && d.copyPasteDisallowed === true; })());

/* ---- anti-round-up: partial-true never opens --------------------------- */
ok("truthy-but-not-true consent stays denied",
  K.reconcile(base({ consent: { accepted: 1 } })).open === false);
ok("crossing set but no consent => closed",
  K.reconcile({ schema: K.SCHEMA_ID, version: K.SCHEMA_VERSION, consent: { accepted: false },
    crossings: { intents: { direction: "both" } } }).open === false);
ok("garbage direction normalises to none",
  K.normalize({ crossings: { intents: { direction: "sideways" } } }).crossings.intents.direction === "none");
ok("garbage-direction crossing installs nothing",
  hasFilter(K.reconcile(base({ crossings: { intents: { direction: "sideways" } } })), "intents") === undefined);

/* ---- direction-flag mapping: p2w / w2p / both / none ------------------- */
const dirState = (dir) => base({ crossings: { intents: { direction: dir } } });
ok("p2w => PARENT_CAN_ACCESS_MANAGED only",
  JSON.stringify(hasFilter(K.reconcile(dirState("p2w")), "intents").flags) ===
  JSON.stringify(["FLAG_PARENT_CAN_ACCESS_MANAGED"]));
ok("w2p => MANAGED_CAN_ACCESS_PARENT only",
  JSON.stringify(hasFilter(K.reconcile(dirState("w2p")), "intents").flags) ===
  JSON.stringify(["FLAG_MANAGED_CAN_ACCESS_PARENT"]));
ok("both => both flags",
  JSON.stringify(hasFilter(K.reconcile(dirState("both")), "intents").flags) ===
  JSON.stringify(["FLAG_PARENT_CAN_ACCESS_MANAGED", "FLAG_MANAGED_CAN_ACCESS_PARENT"]));
ok("none => no intent filter for that cap",
  hasFilter(K.reconcile(dirState("none")), "intents") === undefined);
ok("files crossing also maps via intent filter",
  JSON.stringify(hasFilter(K.reconcile(base({ crossings: { files: { direction: "w2p" } } })), "files").flags) ===
  JSON.stringify(["FLAG_MANAGED_CAN_ACCESS_PARENT"]));

/* ---- clipboard: governed by the copy/paste restriction ----------------- */
const clip = K.reconcile(base({ crossings: { clipboard: { direction: "p2w" } } }));
ok("open clipboard lifts copy/paste disallow", clip.copyPasteDisallowed === false);
ok("open clipboard records direction", clip.clipboardDirection === "p2w");
ok("clipboard is NOT an intent filter", hasFilter(clip, "clipboard") === undefined);
ok("closed clipboard keeps copy/paste disallowed",
  K.reconcile(base({ crossings: { clipboard: { direction: "none" } } })).copyPasteDisallowed === true);

/* ---- standing / ambient caps: stronger-consent gate -------------------- */
// contacts is a POLICY (setManagedProfile*AccessPolicy), not a package allowlist.
const contactsNoStanding = K.reconcile(base({ crossings: { contacts: { direction: "both" } } }));
ok("contacts CLOSED without standing consent", contactsNoStanding.contactsPolicy.open === false);
ok("standing cap absence does not deny the whole decision", contactsNoStanding.open === true);
const contactsStanding = K.reconcile(base({
  consent: { accepted: true, standing: true },
  crossings: { contacts: { direction: "both" } },
}));
ok("contacts OPEN with standing consent", contactsStanding.contactsPolicy.open === true);
ok("contacts carries its direction", contactsStanding.contactsPolicy.direction === "both");
ok("contacts is a POLICY, not a package allowlist", hasPkg(contactsStanding, "contacts") === undefined);
ok("contacts is not an intent filter", hasFilter(contactsStanding, "contacts") === undefined);
ok("user-mediated cap does NOT need standing consent",
  hasFilter(K.reconcile(base({ crossings: { intents: { direction: "p2w" } } })), "intents") !== undefined);
ok("standing consent alone (no crossing) opens nothing",
  (() => { const d = K.reconcile(base({ consent: { accepted: true, standing: true } }));
    return d.crossProfilePackages.length === 0 && d.contactsPolicy.open === false; })());
ok("calendar + connectedApp also gated by standing consent",
  (() => {
    const cr = { calendar: { direction: "p2w", package: "com.android.calendar" },
                 connectedApp: { direction: "w2p", package: "com.example.link" } };
    const off = K.reconcile(base({ crossings: cr }));
    const on = K.reconcile(base({ consent: { accepted: true, standing: true }, crossings: cr }));
    return off.crossProfilePackages.length === 0 && on.crossProfilePackages.length === 2;
  })());

/* ---- `open` is the primary deny gate (design §3.3: open == true exactly) --- */
ok("open:false + real direction => crossing CLOSED (user-mediated)",
  hasFilter(K.reconcile(base({ crossings: { intents: { open: false, direction: "both" } } })), "intents") === undefined);
ok("open:false + real direction => crossing CLOSED (standing, even with standing consent)",
  hasPkg(K.reconcile(stand({ crossings: { calendar: { open: false, direction: "p2w", package: "com.android.calendar" } } })), "calendar") === undefined);
ok("open OMITTED + real direction => still open (backward compat)",
  hasFilter(K.reconcile(base({ crossings: { intents: { direction: "p2w" } } })), "intents") !== undefined);
ok("open:true + real direction => open",
  hasFilter(K.reconcile(base({ crossings: { intents: { open: true, direction: "p2w" } } })), "intents") !== undefined);
ok("open:true + direction none => nothing installed",
  hasFilter(K.reconcile(base({ crossings: { intents: { open: true, direction: "none" } } })), "intents") === undefined);
ok("normalize carries open (derived from direction when omitted)",
  K.normalize({ schema: K.SCHEMA_ID, version: K.SCHEMA_VERSION, crossings: { files: { direction: "w2p" } } }).crossings.files.open === true);
ok("normalize honours explicit open:false over stale direction",
  K.normalize({ crossings: { files: { open: false, direction: "w2p" } } }).crossings.files.open === false);

/* ---- package caps (calendar / connectedApp): ONE valid named package ---- */
const calNoPkg = K.reconcile(stand({ crossings: { calendar: { open: true, direction: "p2w" } } }));
ok("calendar open+standing but NO package => not installed", hasPkg(calNoPkg, "calendar") === undefined);
const calPkg = K.reconcile(stand({ crossings: { calendar: { open: true, direction: "p2w", package: "com.android.calendar" } } }));
ok("calendar open+standing+package => installed", hasPkg(calPkg, "calendar") !== undefined);
ok("calendar entry carries the package name", hasPkg(calPkg, "calendar").package === "com.android.calendar");
ok("calendar entry carries calendarPackages DPM mechanism", hasPkg(calPkg, "calendar").mechanism === "calendarPackages");
ok("normalize drops a non-string package to null",
  K.normalize({ crossings: { calendar: { open: true, direction: "p2w", package: 42 } } }).crossings.calendar.package === null);
const connPkg = K.reconcile(stand({ crossings: { connectedApp: { open: true, direction: "w2p", package: "com.example.link" } } }));
ok("connectedApp entry carries connectedAppPackages DPM mechanism", hasPkg(connPkg, "connectedApp").mechanism === "connectedAppPackages");
ok("package cap with NO package stays closed (anti-round-up)",
  hasPkg(K.reconcile(stand({ crossings: { calendar: { direction: "both" } } })), "calendar") === undefined);
ok("package cap with malformed package stays closed",
  hasPkg(K.reconcile(stand({ crossings: { connectedApp: { direction: "p2w", package: "not a package" } } })), "connectedApp") === undefined);
ok("package cap with single-label package stays closed",
  hasPkg(K.reconcile(stand({ crossings: { connectedApp: { direction: "p2w", package: "android" } } })), "connectedApp") === undefined);
ok("malformed package normalises to null",
  K.normalize({ crossings: { calendar: { direction: "p2w", package: "../etc" } } }).crossings.calendar.package === null);
ok("valid package normalises through",
  K.normalize({ schema: K.SCHEMA_ID, version: K.SCHEMA_VERSION, crossings: { calendar: { direction: "p2w", package: "com.a.b" } } }).crossings.calendar.package === "com.a.b");
ok("PACKAGE_CAPS is calendar + connectedApp",
  JSON.stringify(K.PACKAGE_CAPS) === JSON.stringify(["calendar", "connectedApp"]));
ok("PACKAGE_REQUIRED_CAPS aliases PACKAGE_CAPS",
  JSON.stringify(K.PACKAGE_REQUIRED_CAPS) === JSON.stringify(["calendar", "connectedApp"]));

/* ---- contacts: a policy toggle, not a package allowlist ----------------- */
const contactsOn = K.reconcile(stand({ crossings: { contacts: { open: true, direction: "both" } } }));
ok("contacts opens via contactsPolicy (policy toggle)", contactsOn.contactsPolicy.open === true);
ok("contacts entry carries no package", hasPkg(contactsOn, "contacts") === undefined);
ok("contacts DPM mechanism is contactsAccessPolicy", K.DPM_MECHANISM.contacts === "contactsAccessPolicy");

/* ---- DISALLOW_SHARE_INTO_MANAGED_PROFILE (inbound-share control) --------- */
ok("default-deny => inbound share blocked", dDeny.shareIntoManagedProfileDisallowed === true);
ok("w2p-only files crossing keeps inbound share blocked",
  K.reconcile(base({ crossings: { files: { open: true, direction: "w2p" } } })).shareIntoManagedProfileDisallowed === true);
ok("p2w files crossing CLEARS inbound-share restriction",
  K.reconcile(base({ crossings: { files: { open: true, direction: "p2w" } } })).shareIntoManagedProfileDisallowed === false);
ok("both-direction intents crossing CLEARS inbound-share restriction",
  K.reconcile(base({ crossings: { intents: { open: true, direction: "both" } } })).shareIntoManagedProfileDisallowed === false);
ok("clipboard alone does NOT lift inbound share block",
  K.reconcile(base({ crossings: { clipboard: { direction: "p2w" } } })).shareIntoManagedProfileDisallowed === true);
ok("open decision does not revoke standing URI grants",
  K.reconcile(base({ crossings: { files: { direction: "p2w" } } })).revokeOutstandingUriGrants === false);

/* ---- kill-switch clears EVERYTHING ------------------------------------- */
const killed = K.reconcile(base({
  consent: { accepted: true, standing: true },
  killSwitch: { engaged: true },
  crossings: {
    intents: { direction: "both" }, files: { direction: "p2w" }, clipboard: { direction: "both" },
    contacts: { direction: "both" },
    calendar: { direction: "both", package: "com.example.cal" },
    connectedApp: { direction: "both", package: "com.example.app" },
  },
}));
ok("kill-switch => not open", killed.open === false);
ok("kill-switch => cleared flag set", killed.cleared === true);
ok("kill-switch clears all intent filters", killed.intentFilters.length === 0);
ok("kill-switch empties the allowlist", killed.crossProfilePackages.length === 0);
ok("kill-switch closes the contacts policy", killed.contactsPolicy.open === false);
ok("kill-switch re-imposes DISALLOW_CROSS_PROFILE_COPY_PASTE", killed.copyPasteDisallowed === true);
ok("kill-switch shuts clipboard direction", killed.clipboardDirection === "none");
ok("kill-switch re-imposes inbound share block", killed.shareIntoManagedProfileDisallowed === true);
ok("kill-switch revokes outstanding URI grants", killed.revokeOutstandingUriGrants === true);
ok("kill-switch reason names it", killed.reason.includes("kill-switch"));

/* ---- honest bounds carried on every decision --------------------------- */
ok("caveats present on open decision", K.reconcile(dirState("p2w")).caveats.length >= 1);
ok("caveats present on deny decision", dDeny.caveats.length >= 1);
ok("caveat states the phone-not-workspace bound",
  K.CAVEATS.some((c) => /key-attested device/i.test(c) && /not.*workspace/i.test(c)));
ok("caveat states it cannot recall already-crossed bytes",
  K.CAVEATS.some((c) => /already/i.test(c) && /cross/i.test(c)));
ok("caveat states clipboard restriction is directionless",
  K.CAVEATS.some((c) => /directionless/i.test(c)));
ok("caveat states a package crossing needs a named package",
  K.CAVEATS.some((c) => /package/i.test(c) && /closed/i.test(c)));
ok("caveat states the inbound-share block condition",
  K.CAVEATS.some((c) => /DISALLOW_SHARE_INTO_MANAGED_PROFILE/i.test(c)));
ok("every decision pins sealedWalletPreserved true",
  K.reconcile(dirState("p2w")).sealedWalletPreserved === true && killed.sealedWalletPreserved === true);

/* ---- crossingOpen helper mirrors reconcile ----------------------------- */
ok("crossingOpen agrees: intents p2w open", K.crossingOpen(dirState("p2w"), "intents") === true);
ok("crossingOpen agrees: contacts closed without standing",
  K.crossingOpen(base({ crossings: { contacts: { direction: "both" } } }), "contacts") === false);
ok("crossingOpen agrees: clipboard open", K.crossingOpen(base({ crossings: { clipboard: { direction: "w2p" } } }), "clipboard") === true);
ok("crossingOpen agrees: contacts open with standing", K.crossingOpen(stand({ crossings: { contacts: { direction: "both" } } }), "contacts") === true);
ok("crossingOpen agrees: calendar needs a package",
  K.crossingOpen(stand({ crossings: { calendar: { direction: "p2w" } } }), "calendar") === false &&
  K.crossingOpen(stand({ crossings: { calendar: { direction: "p2w", package: "com.a.b" } } }), "calendar") === true);
ok("crossingOpen unknown cap => false", K.crossingOpen(base(), "telepathy") === false);

/* ---- new constants exported for the Kotlin DPC mapping ------------------ */
ok("DPM_MECHANISM maps the three standing caps",
  K.DPM_MECHANISM.contacts === "contactsAccessPolicy" &&
  K.DPM_MECHANISM.calendar === "calendarPackages" &&
  K.DPM_MECHANISM.connectedApp === "connectedAppPackages");
ok("SHARE_INTO_MANAGED_RESTRICTION names the parent restriction",
  K.SHARE_INTO_MANAGED_RESTRICTION === "DISALLOW_SHARE_INTO_MANAGED_PROFILE");

/* ---- round-trip -------------------------------------------------------- */
ok("serialize round-trips", JSON.stringify(K.parse(K.serialize(def))) === JSON.stringify(def));

/* ---- anti-laundering: a foreign blob must NOT be re-stamped with our
   pinned schema/version and read back as recognised/open. parse()/normalize()
   must collapse ANY schema-unrecognised input straight to defaultState(),
   with nothing from the foreign blob surviving. ---------------------------- */
const wrongSchemaText = JSON.stringify({
  schema: "some.other.schema",
  version: K.SCHEMA_VERSION,
  consent: { accepted: true, standing: true, scope: "persistent" },
  killSwitch: { engaged: false },
  crossings: { intents: { direction: "both" }, contacts: { direction: "both" } },
});
ok("parse() of wrong-schema blob collapses to defaultState",
  JSON.stringify(K.parse(wrongSchemaText)) === JSON.stringify(def));
ok("parse() of wrong-schema blob with accepted:true still denies consent",
  K.parse(wrongSchemaText).consent.accepted === false);
ok("reconcile(parse(wrongSchemaText)) is not open",
  K.reconcile(K.parse(wrongSchemaText)).open === false);
ok("reconcile(parse(wrongSchemaText)) installs no intent filters",
  K.reconcile(K.parse(wrongSchemaText)).intentFilters.length === 0);
ok("reconcile(parse(wrongSchemaText)) empties the allowlist",
  K.reconcile(K.parse(wrongSchemaText)).crossProfilePackages.length === 0);

const wrongVersionBlob = JSON.stringify({
  schema: K.SCHEMA_ID,
  version: 999,
  consent: { accepted: true, standing: true },
  crossings: { clipboard: { direction: "both" } },
});
ok("serialize(parse(wrongVersionBlob)) round-trips to defaultState",
  JSON.stringify(K.parse(K.serialize(K.parse(wrongVersionBlob)))) === JSON.stringify(def));
ok("serialize(parse(wrongVersionBlob)) text itself equals serialize(defaultState())",
  K.serialize(K.parse(wrongVersionBlob)) === K.serialize(def));


/* ======================================================================== *
 * D3 HARDENING (host-provable) — the kernel is the SOLE authority the single Kotlin
 * port (dpc/CrossProfileReconciler.decide) mirrors, so it must be exhaustively fail-closed:
 *   A. crossingOpen ↔ reconcile ↔ independent-oracle 3-way differential parity
 *      over the full cap × direction × consent × standing × kill × open × pkg
 *      matrix (the P2 "can never diverge" claim, proved not asserted).
 *   B. normalize idempotence + serialize→parse / reconcileText round-trip fuzz
 *      over a hostile corpus (P2).
 *   C. all four directions across every capability (P2).
 *   D. exhaustive invalid-package matrix (P3 anti-round-up).
 *   E. extra fail-closed negatives (unknown schema, hostile top types, kill &
 *      open-gate overrides across ALL caps).
 * ======================================================================== */

const jeq = (a, b) => JSON.stringify(a) === JSON.stringify(b);

/* An INDEPENDENT oracle for "should crossing `cap` be open?" — derived straight
   from the honesty rails WITHOUT calling reconcile()/crossingOpen(), so a drift
   in either of those is caught by the 3-way check below. */
function oracleOpen(state, cap) {
  if (!K.CROSSING_KEYS.includes(cap)) return false;
  if (!K.schemaRecognized(state)) return false;
  const s = K.normalize(state);
  if (s.killSwitch.engaged) return false;
  if (!s.consent.accepted) return false;
  const c = s.crossings[cap];
  if (c.open !== true) return false;
  if (c.direction === "none") return false;
  if (K.CAP_CLASS[cap] === "standing" && s.consent.standing !== true) return false;
  if (K.PACKAGE_CAPS.includes(cap) && !c.package) return false;
  return true;
}

/* Read whether `cap` is open straight out of a reconcile() directive set —
   independent of crossingOpen()'s own implementation. */
function capOpenInDirectives(d, cap) {
  if (!d.open) return false;
  switch (K.CAP_MECHANISM[cap]) {
    case "intentFilter": return d.intentFilters.some((f) => f.capability === cap);
    case "packageAllowlist": return d.crossProfilePackages.some((p) => p.capability === cap);
    case "contactsPolicy": return d.contactsPolicy.open === true;
    case "copyPasteRestriction": return d.clipboardDirection !== "none";
    default: return false;
  }
}

/* ---- A. 3-way differential parity over the full matrix ------------------ */
const PKG_VARIANTS = [undefined, "com.example.app", "android", "not a pkg", 42, ""];
let matrixCombos = 0, matrixMismatch = 0;
for (const cap of K.CROSSING_KEYS) {
  const pkgAxis = K.PACKAGE_CAPS.includes(cap) ? PKG_VARIANTS : [undefined];
  for (const direction of K.DIRECTIONS) {
    for (const accepted of [false, true]) {
      for (const standing of [false, true]) {
        for (const engaged of [false, true]) {
          for (const openMode of ["omit", true, false]) {
            for (const pkg of pkgAxis) {
              const entry = { direction };
              if (openMode !== "omit") entry.open = openMode;
              if (pkg !== undefined) entry.package = pkg;
              const state = {
                schema: K.SCHEMA_ID, version: K.SCHEMA_VERSION,
                consent: { accepted, standing },
                killSwitch: { engaged },
                crossings: { [cap]: entry },
              };
              matrixCombos++;
              const co = K.crossingOpen(state, cap);
              const oracle = oracleOpen(state, cap);
              const fromRec = capOpenInDirectives(K.reconcile(state), cap);
              if (!(co === oracle && oracle === fromRec)) {
                matrixMismatch++;
                if (matrixMismatch <= 5) {
                  console.error("PARITY MISMATCH", cap, JSON.stringify(entry),
                    { accepted, standing, engaged, co, oracle, fromRec });
                }
              }
            }
          }
        }
      }
    }
  }
}
ok(`crossingOpen↔reconcile↔oracle 3-way parity across ${matrixCombos} combos`, matrixMismatch === 0);

/* Parity also holds for unrecognised-schema inputs and unknown caps. */
ok("parity: unknown schema => all caps closed everywhere",
  K.CROSSING_KEYS.every((c) => {
    const st = { schema: "other", version: 1, consent: { accepted: true, standing: true },
      crossings: { [c]: { open: true, direction: "both", package: "com.a.b" } } };
    return K.crossingOpen(st, c) === false && oracleOpen(st, c) === false &&
           capOpenInDirectives(K.reconcile(st), c) === false;
  }));
ok("parity: unknown cap name => false everywhere", K.crossingOpen(base(), "telepathy") === false && oracleOpen(base(), "telepathy") === false);

/* A single fully-open multi-cap state: every cap's three views must agree. */
const bigOpen = base({
  consent: { accepted: true, standing: true },
  crossings: {
    intents: { open: true, direction: "both" },
    files: { open: true, direction: "p2w" },
    clipboard: { open: true, direction: "w2p" },
    contacts: { open: true, direction: "both" },
    calendar: { open: true, direction: "p2w", package: "com.cal.x" },
    connectedApp: { open: true, direction: "w2p", package: "com.link.y" },
  },
});
const bigOpenD = K.reconcile(bigOpen);
for (const c of K.CROSSING_KEYS) {
  ok(`multi-cap parity: ${c}`,
    K.crossingOpen(bigOpen, c) === capOpenInDirectives(bigOpenD, c) &&
    K.crossingOpen(bigOpen, c) === oracleOpen(bigOpen, c) &&
    K.crossingOpen(bigOpen, c) === true);
}

/* ---- B. normalize idempotence + serialize/round-trip fuzz -------------- */
const CORPUS = [
  null, undefined, "nope", 42, true, [], {}, [1, 2, 3],
  { schema: K.SCHEMA_ID },
  { schema: K.SCHEMA_ID, version: "1" },
  { schema: K.SCHEMA_ID, version: 1, consent: { accepted: 1 } },
  { schema: K.SCHEMA_ID, version: 1, consent: "yes" },
  { crossings: { intents: { direction: "sideways" } } },
  { crossings: { intents: "p2w" } },
  { crossings: ["junk"] },
  { crossings: { calendar: { open: true, direction: "p2w", package: 42 } } },
  { crossings: { calendar: { open: true, direction: "p2w", package: "../etc" } } },
  { crossings: { files: { open: false, direction: "w2p" } } },
  { crossings: { files: { direction: "w2p" } } },
  { crossings: { connectedApp: { direction: "both", package: "com.a.b" } } },
  { tier: "measured-boot-workspace", sealedWallet: { preserved: false } },
  { killSwitch: { engaged: "yes", engagedAtIso: 5 } },
  { consent: { accepted: true, scope: "forever", acceptedAtIso: 123 } },
  { lang: "xx" },
  { extra: "ignored", crossings: { clipboard: { open: true, direction: "p2w" } } },
  { schema: K.SCHEMA_ID, version: 1, consent: { accepted: true, standing: true },
    crossings: { contacts: { open: true, direction: "both" },
      calendar: { open: true, direction: "p2w", package: "com.cal.x" },
      connectedApp: { open: false, direction: "both", package: "com.x.y" } },
    killSwitch: { engaged: false } },
];
for (let i = 0; i < CORPUS.length; i++) {
  const x = CORPUS[i];
  const n1 = K.normalize(x);
  ok(`normalize idempotent [#${i}]`, jeq(K.normalize(n1), n1));
  ok(`parse(serialize) stable [#${i}]`, jeq(K.parse(K.serialize(x)), n1));
  ok(`normalize pins tier/schema/wallet [#${i}]`,
    n1.tier === K.TIER && n1.schema === K.SCHEMA_ID && n1.version === K.SCHEMA_VERSION &&
    n1.sealedWallet.preserved === true);
  // serialize pins the schema, so reconcileText∘serialize must equal reconcile∘normalize.
  ok(`reconcileText∘serialize == reconcile∘normalize [#${i}]`,
    jeq(K.reconcileText(K.serialize(x)), K.reconcile(n1)));
}

/* ---- C. all four directions across every capability -------------------- */
const IF_FLAGS = {
  p2w: ["FLAG_PARENT_CAN_ACCESS_MANAGED"],
  w2p: ["FLAG_MANAGED_CAN_ACCESS_PARENT"],
  both: ["FLAG_PARENT_CAN_ACCESS_MANAGED", "FLAG_MANAGED_CAN_ACCESS_PARENT"],
};
for (const cap of K.CROSSING_KEYS) {
  for (const dir of ["p2w", "w2p", "both"]) {
    const entry = { open: true, direction: dir };
    if (K.PACKAGE_CAPS.includes(cap)) entry.package = "com.example.app";
    const st = stand({ crossings: { [cap]: entry } });
    ok(`all-directions: ${cap} ${dir} opens`, K.crossingOpen(st, cap) === true);
  }
  const stNone = stand({ crossings: { [cap]: { open: true, direction: "none", package: "com.a.b" } } });
  ok(`all-directions: ${cap} none stays closed`, K.crossingOpen(stNone, cap) === false);
}
// intent-filter caps carry exactly the right flags for each direction.
for (const cap of ["intents", "files"]) {
  for (const [dir, flags] of Object.entries(IF_FLAGS)) {
    const d = K.reconcile(base({ crossings: { [cap]: { open: true, direction: dir } } }));
    ok(`flags: ${cap} ${dir}`, jeq(hasFilter(d, cap).flags, flags));
  }
}

/* ---- D. exhaustive invalid-package matrix (anti-round-up) --------------- */
const BAD_PKGS = ["", " ", "android", "com", ".com", "com.", "com..b", "com .b",
  "1com.b", "com.1b", "not a package", "../etc/passwd", "com/foo", "com-foo",
  "com.foo.", "@com.foo", 42, null, {}, [], true];
const GOOD_PKGS = ["com.a.b", "com.example.app", "a.b.c.d", "com_x.y_z"];
for (const cap of K.PACKAGE_CAPS) {
  for (const p of BAD_PKGS) {
    const st = stand({ crossings: { [cap]: { open: true, direction: "both", package: p } } });
    ok(`invalid-pkg ${cap} closed: ${JSON.stringify(p)}`,
      hasPkg(K.reconcile(st), cap) === undefined &&
      K.normalize(st).crossings[cap].package === null &&
      K.crossingOpen(st, cap) === false);
  }
  for (const p of GOOD_PKGS) {
    const st = stand({ crossings: { [cap]: { open: true, direction: "p2w", package: p } } });
    ok(`valid-pkg ${cap} opens: ${p}`,
      hasPkg(K.reconcile(st), cap)?.package === p &&
      K.normalize(st).crossings[cap].package === p &&
      K.crossingOpen(st, cap) === true);
  }
}

/* ---- E. extra fail-closed negatives ------------------------------------ */
ok("array top input => full-deny", K.reconcile([]).open === false);
ok("number top input => full-deny", K.reconcile(42).open === false);
ok("boolean top input => full-deny", K.reconcile(true).open === false);
ok("consent object missing => default-deny", K.reconcile({ schema: K.SCHEMA_ID, version: K.SCHEMA_VERSION }).open === false);
ok("consent null => default-deny", K.reconcile(base({ consent: null })).open === false);
ok("consent.accepted string 'true' => denied", K.reconcile(base({ consent: { accepted: "true" } })).open === false);
ok("negative version => full-deny", K.reconcile(base({ version: -1 })).open === false);
ok("float version => full-deny", K.reconcile(base({ version: 1.5 })).open === false);
ok("null version => full-deny", K.reconcile(base({ version: null })).open === false);
ok("crossings as array => nothing installs",
  (() => { const d = K.reconcile(base({ consent: { accepted: true, standing: true }, crossings: ["intents"] }));
    return d.open === true && d.intentFilters.length === 0 && d.crossProfilePackages.length === 0; })());
ok("reconcileText empty string => full-deny", K.reconcileText("").open === false);
ok("reconcileText 'null' => full-deny", K.reconcileText("null").open === false);
ok("reconcileText '[]' => full-deny", K.reconcileText("[]").open === false);
ok("reconcileText valid-json-wrong-schema => full-deny",
  K.reconcileText(JSON.stringify({ schema: "x", version: 1 })).open === false);
ok("reconcileText well-formed-no-consent => not open",
  K.reconcileText(JSON.stringify({ schema: K.SCHEMA_ID, version: K.SCHEMA_VERSION, consent: { accepted: false } })).open === false);
// standing caps never open on base-only consent — all three, via crossingOpen.
ok("standing caps closed without standing consent (all 3)",
  K.STANDING_CAPS.every((c) => {
    const e = { open: true, direction: "both" };
    if (K.PACKAGE_CAPS.includes(c)) e.package = "com.a.b";
    return K.crossingOpen(base({ crossings: { [c]: e } }), c) === false;
  }));
// open:false forces every cap closed even with full consent + valid package.
ok("open:false forces closed across ALL caps",
  K.CROSSING_KEYS.every((c) => {
    const e = { open: false, direction: "both" };
    if (K.PACKAGE_CAPS.includes(c)) e.package = "com.a.b";
    return K.crossingOpen(stand({ crossings: { [c]: e } }), c) === false;
  }));
// kill-switch overrides full consent + every cap wide open.
ok("kill-switch overrides all caps (crossingOpen)",
  K.CROSSING_KEYS.every((c) => {
    const e = { open: true, direction: "both" };
    if (K.PACKAGE_CAPS.includes(c)) e.package = "com.a.b";
    return K.crossingOpen(base({ consent: { accepted: true, standing: true },
      killSwitch: { engaged: true }, crossings: { [c]: e } }), c) === false;
  }));
// omitted `open` + real direction still opens the user-mediated caps (back-compat).
ok("open omitted + real direction opens user-mediated caps",
  ["intents", "files", "clipboard"].every((c) => K.crossingOpen(base({ crossings: { [c]: { direction: "p2w" } } }), c) === true));

/* ======================================================================== *
 * SCHEMA ↔ KERNEL PARITY GUARD (gate-state.schema.json cannot drift)
 *
 * The schema and the reconcile kernel are two independent statements of the
 * SAME domains (directions, crossing caps, the pinned honesty rails). If the
 * kernel gains a direction or a crossing cap and the schema is not updated in
 * lock-step, the schema goes silently permissive/stale — it would keep
 * validating states the kernel now interprets differently. These assertions
 * pin them together so a kernel-only change to K.DIRECTIONS / K.CROSSING_KEYS /
 * K.TIER fails LOUDLY here until the schema is brought back in line.
 *
 * Also: a small draft-07 SUBSET validator (dependency-free — no ajv) checks
 * state.example.json actually satisfies gate-state.schema.json, so the example
 * shipped as "a fresh, fully-safe state" is provably a valid state document,
 * not just a hand-kept JSON blob.
 * ======================================================================== */

const SCHEMA = readJson("gate-state.schema.json");
const asSet = (a) => JSON.stringify([...a].slice().sort());
const setEq = (a, b) => asSet(a) === asSet(b);

/* ---- enum parity: schema directions == K.DIRECTIONS -------------------- */
// Both crossing shapes ('crossing' and 'packagedCrossing') carry the direction
// enum; each must equal the kernel's DIRECTIONS domain exactly (as a set).
ok("schema crossing.direction enum == K.DIRECTIONS",
  setEq(SCHEMA.definitions.crossing.properties.direction.enum, K.DIRECTIONS));
ok("schema packagedCrossing.direction enum == K.DIRECTIONS",
  setEq(SCHEMA.definitions.packagedCrossing.properties.direction.enum, K.DIRECTIONS));
// The two schema direction enums must also agree with each other.
ok("schema's two direction enums agree",
  setEq(SCHEMA.definitions.crossing.properties.direction.enum,
        SCHEMA.definitions.packagedCrossing.properties.direction.enum));

/* ---- cap parity: schema crossings keys == K.CROSSING_KEYS --------------- */
// The set of declared crossing capabilities (and the `required` list that
// forces every one of them present) must equal the kernel's CROSSING_KEYS.
ok("schema crossings property keys == K.CROSSING_KEYS",
  setEq(Object.keys(SCHEMA.properties.crossings.properties), K.CROSSING_KEYS));
ok("schema crossings.required == K.CROSSING_KEYS",
  setEq(SCHEMA.properties.crossings.required, K.CROSSING_KEYS));
// The package-backed caps in the schema (those pointing at packagedCrossing)
// must equal the kernel's PACKAGE_CAPS — a kernel that makes a new cap
// package-required, or drops one, without re-pointing its $ref fails here.
const schemaPackageCaps = Object.entries(SCHEMA.properties.crossings.properties)
  .filter(([, v]) => v.$ref === "#/definitions/packagedCrossing")
  .map(([k]) => k);
ok("schema packagedCrossing caps == K.PACKAGE_CAPS",
  setEq(schemaPackageCaps, K.PACKAGE_CAPS));

/* ---- pinned honesty rails: schema consts == kernel pins ----------------- */
ok("schema tier const == K.TIER", SCHEMA.properties.tier.const === K.TIER);
ok("schema schema-id const == K.SCHEMA_ID", SCHEMA.properties.schema.const === K.SCHEMA_ID);
ok("schema version const == K.SCHEMA_VERSION", SCHEMA.properties.version.const === K.SCHEMA_VERSION);
ok("schema sealedWallet.preserved const pinned true (== K.SEALED_WALLET_PRESERVED)",
  SCHEMA.properties.sealedWallet.properties.preserved.const === true &&
  SCHEMA.properties.sealedWallet.properties.preserved.const === K.SEALED_WALLET_PRESERVED);

/* ---- draft-07 SUBSET validator: state.example.json ⊨ gate-state.schema --- */
// Supports exactly what this schema uses: local $ref, type (incl. union &
// integer), const, enum, pattern, required, properties, additionalProperties.
function validate(node, sc, path, errs) {
  const ref = sc.$ref;
  if (ref) {
    const key = ref.replace(/^#\/definitions\//, "");
    return validate(node, SCHEMA.definitions[key], path, errs);
  }
  const typeOk = (t) => {
    switch (t) {
      case "object": return node !== null && typeof node === "object" && !Array.isArray(node);
      case "array": return Array.isArray(node);
      case "string": return typeof node === "string";
      case "boolean": return typeof node === "boolean";
      case "integer": return typeof node === "number" && Number.isInteger(node);
      case "number": return typeof node === "number";
      case "null": return node === null;
      default: return true;
    }
  };
  if (sc.type !== undefined) {
    const types = Array.isArray(sc.type) ? sc.type : [sc.type];
    if (!types.some(typeOk)) errs.push(`${path}: type != ${JSON.stringify(sc.type)}`);
  }
  if ("const" in sc && JSON.stringify(node) !== JSON.stringify(sc.const))
    errs.push(`${path}: const != ${JSON.stringify(sc.const)}`);
  if (sc.enum && !sc.enum.some((e) => JSON.stringify(e) === JSON.stringify(node)))
    errs.push(`${path}: not in enum ${JSON.stringify(sc.enum)}`);
  if (sc.pattern && typeof node === "string" && !new RegExp(sc.pattern).test(node))
    errs.push(`${path}: does not match /${sc.pattern}/`);
  if (node !== null && typeof node === "object" && !Array.isArray(node)) {
    const props = sc.properties || {};
    for (const r of sc.required || [])
      if (!(r in node)) errs.push(`${path}: missing required '${r}'`);
    if (sc.additionalProperties === false)
      for (const k of Object.keys(node))
        if (!(k in props)) errs.push(`${path}: additional property '${k}'`);
    for (const [k, v] of Object.entries(node))
      if (props[k]) validate(v, props[k], `${path}/${k}`, errs);
  }
  return errs;
}
const exampleErrs = validate(readJson("state.example.json"), SCHEMA, "$", []);
ok("state.example.json validates against gate-state.schema.json (0 errors)",
  exampleErrs.length === 0);
if (exampleErrs.length) console.error("SCHEMA VALIDATION ERRORS:", exampleErrs);
// The kernel must ALSO accept the example unchanged: normalize is a no-op fixed
// point on it (proves the example is already the kernel's canonical safe state).
ok("kernel normalize(state.example) round-trips (canonical safe state)",
  JSON.stringify(K.normalize(readJson("state.example.json"))) ===
  JSON.stringify(K.normalize(K.normalize(readJson("state.example.json")))));

console.log(`reconcile-kernel: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
