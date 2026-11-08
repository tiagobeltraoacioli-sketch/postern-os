"use strict";
/* Minimal, dependency-free checks for gate-store.mjs. Run: node test-store.mjs
   These assert the honesty rails hold in code (default-deny, fixed tier,
   malformed-in => safe-out). They do NOT test the (non-existent) on-device
   wrapper — that stays UNTESTED until Waydroid hardware exists. */
import S from "./gate-store.mjs";

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; } else { fail++; console.error("FAIL:", name); } };

const d = S.defaultState();
ok("tier fixed non-attestable", d.tier === "non-attestable");
ok("consent denied by default", d.consent.accepted === false);
ok("all bridges deny by default", S.BRIDGE_KEYS.every((k) => d.bridges[k] === false));
ok("kill-switch clear by default", d.killSwitch.engaged === false);

// malformed / hostile input must collapse to safe default
ok("garbage normalizes to deny", S.normalize(null).consent.accepted === false);
ok("string input is safe", JSON.stringify(S.normalize("nope")) === JSON.stringify(d));
ok("truthy-but-not-true bridge denied", S.normalize({ bridges: { mic: 1 } }).bridges.mic === false);
ok("cannot relabel tier", S.normalize({ tier: "attested" }).tier === "non-attestable");
ok("unknown scope falls back to session", S.normalize({ consent: { accepted: true, scope: "forever" } }).consent.scope === "session");

// parse of corrupt JSON => safe default, never throws
ok("corrupt json => default", S.parse("{not json").consent.accepted === false);

// loadState — the STRICT on-disk boundary (schema discriminator + version guard).
// A foreign / wrong-version file is treated as absent => full-deny, even when it
// carries an accepted consent. This is the shared-contract rail parse() omits.
const good = S.serialize({ consent: { accepted: true, acceptedAtIso: "2026-01-01T00:00:00Z" } });
ok("loadState accepts a well-formed same-schema file", S.loadState(good).consent.accepted === true);
ok("loadState refuses a FOREIGN schema (=> full-deny)",
  S.loadState(JSON.stringify({ schema: "postern.noporis-gate.state", version: 1, consent: { accepted: true } })).consent.accepted === false);
ok("loadState refuses an unknown version (=> full-deny)",
  S.loadState(JSON.stringify({ schema: S.SCHEMA_ID, version: 999, consent: { accepted: true } })).consent.accepted === false);
ok("loadState on a missing schema => full-deny",
  S.loadState(JSON.stringify({ consent: { accepted: true } })).consent.accepted === false);
ok("loadState corrupt json => default (never throws)", S.loadState("{not json").consent.accepted === false);
ok("loadState non-object => default", S.loadState("42").consent.accepted === false);

// decision helpers
ok("container blocked without consent", S.containerAllowed(d) === false);
ok("container allowed once consented", S.containerAllowed({ consent: { accepted: true } }) === true);
ok("kill-switch overrides consent", S.containerAllowed({ consent: { accepted: true }, killSwitch: { engaged: true } }) === false);
ok("requireConsent=false bypasses consent", S.containerAllowed(d, { requireConsent: false }) === true);
ok("no bridges active without consent", S.activeBridges({ bridges: { clipboard: true } }).length === 0);
ok("only explicit bridges active when consented",
  JSON.stringify(S.activeBridges({ consent: { accepted: true }, bridges: { clipboard: true, mic: true } })) ===
  JSON.stringify(["clipboard", "mic"]));

// egress: Tor-only rail + fail-closed
ok("egress torOnly pinned true by default", d.egress.torOnly === true);
ok("egress denies until Tor up by default", d.egress.torBootstrapped === false);
ok("cannot downgrade egress to clearnet", S.normalize({ egress: { torOnly: false } }).egress.torOnly === true);
ok("truthy-but-not-true torBootstrapped denied", S.normalize({ egress: { torBootstrapped: 1 } }).egress.torBootstrapped === false);
ok("no egress without consent even if Tor up",
  S.egressAllowed({ egress: { torBootstrapped: true } }) === false);
ok("no egress when consented but Tor down",
  S.egressAllowed({ consent: { accepted: true } }) === false);
ok("egress allowed when consented AND Tor up",
  S.egressAllowed({ consent: { accepted: true }, egress: { torBootstrapped: true } }) === true);
ok("kill-switch also kills egress",
  S.egressAllowed({ consent: { accepted: true }, egress: { torBootstrapped: true }, killSwitch: { engaged: true } }) === false);

// round-trip
ok("serialize round-trips", JSON.stringify(S.parse(S.serialize(d))) === JSON.stringify(d));

console.log(`gate-store: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
