// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
"use strict";
/* ============================================================================
   Postern Consent Spine — the ONE shared consent state-file contract across the
   three tiers (Porog / NoporIS / Waydroid). DOM-free, dependency-free, no clock,
   no network, no telemetry, no imports.

   WHY THIS EXISTS
   Three products already ship a deny-by-default consent kernel that converged on
   the same shape (see docs/design/{waydroid-02,porog-03,noporis-02}). This module
   FORMALIZES that convergence as ONE contract so a single validator + a single
   projection rule reads all three. It is byte-compatible (same field names) with
   the shipped apps/sloboda-gate/gate-store.mjs and apps/noporis-gate/
   gate-store.mjs — proven by test-spine.mjs deep-equalling their normalize().

   THE SPINE (identical across all three tiers)
     schema     : "postern.<product>-gate.state"   // discriminator; foreign => full-deny
     version    : 1                                  // unknown version => full-deny
     tier       : PINNED per product, never from input
                    Porog   = "key-attested-device"  (attests the PHONE, not the workspace)
                    NoporIS = "non-attestable"        (Google side; less-private)
                    Waydroid= "non-attestable"        (community edition; not Sealed)
     consent    : { accepted:false, scope:"session"|"persistent", acceptedAtIso:null }
     killSwitch : { engaged:false, engagedAtIso:null }
     lang       : "pt-BR" | "en"                     // cosmetic

   THE ONLY PER-TIER VARIATION
     capability object : bridges   (Waydroid, flat bool)
                         crossings (NoporIS, {open,scope,openedAtIso})
                         crossings (Porog,  {open,direction,scope,openedAtIso[,package]})
     tier rail         : egress{torOnly:true(pinned),torBootstrapped} (Waydroid)
                         sealedWallet{preserved:true(pinned)}         (NoporIS/Porog)

   SEVEN RAILS ENFORCED IN CODE (not just prose)
     1. schema discriminator  — loadState() refuses a foreign schema  => full-deny
     2. pinned tier + version — tier never read from input; bad version => full-deny
     3. deny-by-default caps  — a capability is open ONLY on exactly `true`
     4. normalize() boundary  — any input (missing/partial/garbage/hostile) => a
                                well-formed full-deny state; never throws
     5. non-destructive kill  — engaging never clears the pinned wallet/egress rail
     6. fail-closed decisions — unknown/malformed/not-consented/killed => full-deny,
                                projection derivation is a PURE function of state
     7. no telemetry          — no network I/O; the file never leaves the device

   USERLAND consent gate, NOT a kernel boundary: a rooted / unlocked / compromised
   host defeats it. Reference-prototype, UNAUDITED — certifies nothing. The coin
   is not a security; personal use is free; not legal advice.
   ============================================================================ */

export const SCHEMA_VERSION = 1;
export const CONSENT_SCOPES = ["session", "persistent"];
export const LANGS = ["pt-BR", "en"];
/* Porog per-crossing direction vocabulary. "none" is the closed/no-direction
   default; a crossing open without a real direction installs no grant. */
export const DIRECTIONS = ["p2w", "w2p", "both"];

/* NoporIS per-crossing direction vocabulary (its own, distinct from Porog's):
   a crossing is authorised for exactly ONE lane, never "both". The default is
   the less-dangerous near→far (the clean side hands something to the Google
   side); the ingest lane far→near must be chosen on purpose. Unlike Porog there
   is no "none": an open NoporIS crossing always carries a real, single lane. */
export const CROSSING_DIRECTIONS_NOPORIS = ["near-to-far", "far-to-near"];
export const DEFAULT_DIRECTION_NOPORIS = "near-to-far";

/* ---------------------------------------------------------------------------
   Product descriptors — the whole cross-tier contract, data-driven so ONE
   validator serves all three. `tail` fixes the serialized field order after the
   capability object so output matches each shipped store byte-for-byte.
   --------------------------------------------------------------------------- */
export const PRODUCTS = {
  // Waydroid tier — "Postern for postmarketOS, community edition". NON-ATTESTABLE.
  sloboda: {
    id: "sloboda",
    label: "Waydroid — Postern for postmarketOS (community edition)",
    schema: "postern.sloboda-gate.state",
    tier: "non-attestable",
    statePath: "/var/lib/postern/sloboda-gate/state.json",
    projectionPath: "/run/postern/consent/sloboda-bridge.state",
    cap: { field: "bridges", shape: "bool", keys: ["clipboard", "files", "mic", "camera", "location"], packageKeys: [] },
    tail: ["egress", "killSwitch"],
  },
  // NoporIS bridge — guarded crossing to a far Google-Play persona. NON-ATTESTABLE.
  noporis: {
    id: "noporis",
    label: "NoporIS — guarded persona bridge",
    schema: "postern.noporis-gate.state",
    tier: "non-attestable",
    statePath: "/var/lib/postern/noporis-gate/state.json",
    projectionPath: "/run/postern/consent/noporis-bridge.state",
    cap: { field: "crossings", shape: "crossing-noporis", keys: ["clipboard", "files", "mic", "camera", "location"], packageKeys: [] },
    tail: ["killSwitch", "sealedWallet"],
  },
  // Porog door — stock-Android managed-profile cross-profile boundary.
  // KEY-ATTESTED-DEVICE: attests the phone, NOT the workspace (never measured-boot).
  porog: {
    id: "porog",
    label: "Porog — cross-profile door (managed profile)",
    schema: "postern.porog-gate.state",
    tier: "key-attested-device",
    statePath: "/var/lib/postern/porog-gate/state.json",
    projectionPath: "/run/postern/consent/porog-bridge.state",
    cap: {
      field: "crossings",
      shape: "crossing-directional",
      keys: ["intents", "clipboard", "files", "contacts", "calendar", "connectedApp"],
      packageKeys: ["calendar", "connectedApp"],
    },
    tail: ["killSwitch", "sealedWallet"],
  },
};

export const PRODUCT_IDS = Object.keys(PRODUCTS);

function descriptor(productId) {
  const d = PRODUCTS[productId];
  if (!d) throw new Error(`unknown product: ${productId}`);
  return d;
}

/* ---------------------------------------------------------------------------
   Primitive coercers — the deny-by-default building blocks.
   --------------------------------------------------------------------------- */
const asBool = (v) => v === true; // anything not exactly true is deny
const oneOf = (v, allowed, fallback) => (allowed.includes(v) ? v : fallback);
const asIso = (v) => (typeof v === "string" && v.length > 0 ? v : null);
const asDir = (v) => (DIRECTIONS.includes(v) ? v : "none");
const asDirNoporis = (v) => (CROSSING_DIRECTIONS_NOPORIS.includes(v) ? v : DEFAULT_DIRECTION_NOPORIS);
const asPackage = (v) => (typeof v === "string" && v.length > 0 ? v : null);

/* ---------------------------------------------------------------------------
   Capability shape helpers — the ONLY per-tier variation.
   --------------------------------------------------------------------------- */
function defaultCapValue(shape, hasPackage) {
  if (shape === "bool") return false;
  if (shape === "crossing") return { open: false, scope: "session", openedAtIso: null };
  // crossing-noporis (NoporIS): a plain crossing plus a single-lane direction
  // (its own vocabulary, default near→far); no package, no "none".
  if (shape === "crossing-noporis") {
    return { open: false, scope: "session", direction: DEFAULT_DIRECTION_NOPORIS, openedAtIso: null };
  }
  // crossing-directional (Porog)
  const v = { open: false, direction: "none", scope: "session", openedAtIso: null };
  if (hasPackage) v.package = null;
  return v;
}

function normalizeCapValue(x, shape, hasPackage) {
  if (shape === "bool") return asBool(x); // deny unless exactly true
  const o = x && typeof x === "object" ? x : {};
  const open = asBool(o.open);
  if (shape === "crossing") {
    return { open, scope: oneOf(o.scope, CONSENT_SCOPES, "session"), openedAtIso: open ? asIso(o.openedAtIso) : null };
  }
  if (shape === "crossing-noporis") {
    // NoporIS crossing: plain open/scope/openedAtIso plus a pinned single lane.
    // An unknown/absent direction collapses to the less-dangerous near→far
    // default, never widens (matches apps/noporis-gate/gate-store.mjs).
    return {
      open,
      scope: oneOf(o.scope, CONSENT_SCOPES, "session"),
      direction: asDirNoporis(o.direction),
      openedAtIso: open ? asIso(o.openedAtIso) : null,
    };
  }
  // crossing-directional (Porog): direction that isn't a real value collapses to "none"
  const v = {
    open,
    direction: asDir(o.direction),
    scope: oneOf(o.scope, CONSENT_SCOPES, "session"),
    openedAtIso: open ? asIso(o.openedAtIso) : null,
  };
  if (hasPackage) v.package = asPackage(o.package);
  return v;
}

/* True iff this capability is actually lent right now (before the standing check).
   Directional crossings additionally require a real direction — open without a
   direction installs no grant (fail-closed, per Porog reconcile). */
function capIsOpen(value, shape) {
  if (shape === "bool") return value === true;
  if (shape === "crossing") return value.open === true;
  // NoporIS: direction is always a real single lane, so open-ness is just `open`
  // (unlike Porog, where an open crossing with direction "none" installs nothing).
  if (shape === "crossing-noporis") return value.open === true;
  return value.open === true && value.direction !== "none";
}

/* ---------------------------------------------------------------------------
   Tier rails — the pinned per-tier invariants no input can flip.
   --------------------------------------------------------------------------- */
function defaultRail(name) {
  if (name === "egress") return { torOnly: true, torBootstrapped: false };
  if (name === "sealedWallet") return { preserved: true };
  throw new Error(`unknown rail: ${name}`);
}

function normalizeRail(name, input) {
  if (name === "egress") {
    const e = input && typeof input === "object" ? input : {};
    // torOnly is PINNED true (never from input); only the live "is Tor up" signal
    // is read, and only exactly-true counts (fail-closed until Tor bootstrapped).
    return { torOnly: true, torBootstrapped: asBool(e.torBootstrapped) };
  }
  if (name === "sealedWallet") {
    // preserved is PINNED true; no input and no kill path can clear it.
    return { preserved: true };
  }
  throw new Error(`unknown rail: ${name}`);
}

/* ---------------------------------------------------------------------------
   defaultState / normalize / parse / loadState / serialize.
   --------------------------------------------------------------------------- */

/* A fresh, fully-SAFE state: not consented, every capability closed, kill clear,
   pinned rails set. This is what a reader MUST assume when the file is absent. */
export function defaultState(productId) {
  const d = descriptor(productId);
  const out = {
    schema: d.schema,
    version: SCHEMA_VERSION,
    tier: d.tier,
    lang: "en",
    consent: { accepted: false, scope: "session", acceptedAtIso: null },
  };
  out[d.cap.field] = {};
  for (const k of d.cap.keys) out[d.cap.field][k] = defaultCapValue(d.cap.shape, d.cap.packageKeys.includes(k));
  for (const seg of d.tail) {
    if (seg === "killSwitch") out.killSwitch = { engaged: false, engagedAtIso: null };
    else out[seg] = defaultRail(seg);
  }
  return out;
}

/* Rail 4 — the trust boundary. Normalise ANY input into a valid full-deny-safe
   state. Never throws. schema/version/tier and the pinned rails come from
   defaultState(), never from input. */
export function normalize(input, productId) {
  const d = descriptor(productId);
  const out = defaultState(productId);
  if (!input || typeof input !== "object") return out;

  const c = input.consent && typeof input.consent === "object" ? input.consent : {};
  out.consent.accepted = asBool(c.accepted);
  out.consent.scope = oneOf(c.scope, CONSENT_SCOPES, "session");
  out.consent.acceptedAtIso = out.consent.accepted ? asIso(c.acceptedAtIso) : null;

  const caps = input[d.cap.field] && typeof input[d.cap.field] === "object" ? input[d.cap.field] : {};
  for (const k of d.cap.keys) {
    out[d.cap.field][k] = normalizeCapValue(caps[k], d.cap.shape, d.cap.packageKeys.includes(k));
  }

  const ks = input.killSwitch && typeof input.killSwitch === "object" ? input.killSwitch : {};
  out.killSwitch.engaged = asBool(ks.engaged);
  out.killSwitch.engagedAtIso = out.killSwitch.engaged ? asIso(ks.engagedAtIso) : null;

  for (const seg of d.tail) {
    if (seg === "killSwitch") continue;
    out[seg] = normalizeRail(seg, input[seg]);
  }

  out.lang = oneOf(input.lang, LANGS, "en");
  return out;
}

/* Tolerant parse (matches the shipped stores): corrupt JSON => full-deny default,
   otherwise normalize. Does NOT enforce the schema discriminator — see loadState
   for the strict boundary that a reader loading a file off disk should use. */
export function parse(text, productId) {
  let raw = null;
  try { raw = JSON.parse(text); } catch { return defaultState(productId); }
  return normalize(raw, productId);
}

/* Rails 1+2 — the STRICT on-disk trust boundary. Corrupt JSON, a foreign schema,
   or an unknown version each collapse to full-deny (as if the file were absent),
   BEFORE normalize. This is what a reader loading state.json should call. */
export function loadState(text, productId) {
  const d = descriptor(productId);
  let raw = null;
  try { raw = JSON.parse(text); } catch { return defaultState(productId); }
  if (!raw || typeof raw !== "object") return defaultState(productId);
  if (raw.schema !== d.schema) return defaultState(productId);       // foreign file => full-deny
  if (raw.version !== SCHEMA_VERSION) return defaultState(productId); // unknown version => full-deny
  return normalize(raw, productId);
}

/* Serialize for writing the state file (stable key order, trailing newline). */
export function serialize(state, productId) {
  return JSON.stringify(normalize(state, productId), null, 2) + "\n";
}

/* ---------------------------------------------------------------------------
   Decision helpers — fail-closed, pure. The ONLY questions a reader should ask.
   --------------------------------------------------------------------------- */

/* Rail 6 — may the container/bridge run at all? Consent accepted AND kill clear.
   requireConsent=false is the only bypass and must be an explicit operator
   choice, never a default. */
export function containerAllowed(state, productId, { requireConsent = true } = {}) {
  const s = normalize(state, productId);
  if (s.killSwitch.engaged) return false;
  if (requireConsent && !s.consent.accepted) return false;
  return true;
}

/* The capability keys actually lent right now: only ones explicitly open, and
   only while the container/bridge is allowed. Killed/not-consented => [] . */
export function activeCaps(state, productId, opts) {
  const d = descriptor(productId);
  const s = normalize(state, productId);
  if (!containerAllowed(s, productId, opts)) return [];
  return d.cap.keys.filter((k) => capIsOpen(s[d.cap.field][k], d.cap.shape));
}

/* THE PROJECTION RULE (identical across all three tiers, PURE function of state):
     enabled  iff  consent.accepted && !killSwitch.engaged && activeCaps.length > 0
     disabled otherwise (default, and on kill). */
export function projectionEnabled(state, productId, opts) {
  return activeCaps(state, productId, opts).length > 0;
}

export function projectionLine1(state, productId, opts) {
  return projectionEnabled(state, productId, opts) ? "enabled" : "disabled";
}

/* The dumb read-only line-file the wrappers consume. Line 1 is the ONLY field
   the existing wrappers read (== "enabled"); the KEY=on extras are additive and
   ignored by an old reader. Ephemeral: /run/postern/consent/<product>-bridge.state */
export function projectionFile(state, productId, opts) {
  const enabled = projectionEnabled(state, productId, opts);
  if (!enabled) return "disabled\n";
  const extras = activeCaps(state, productId, opts).map((k) => `${k}=on`);
  return ["enabled", ...extras].join("\n") + "\n";
}

/* Egress decision — Waydroid only. Fail-closed: container allowed + Tor-only rail
   pinned + Tor actually bootstrapped. Absent product egress => false. */
export function egressAllowed(state, productId, opts) {
  const d = descriptor(productId);
  if (!d.tail.includes("egress")) return false;
  const s = normalize(state, productId);
  if (!containerAllowed(s, productId, opts)) return false;
  if (s.egress.torOnly !== true) return false;
  return s.egress.torBootstrapped === true;
}

/* ---------------------------------------------------------------------------
   Minimal transforms — enough to prove Rail 5 (non-destructive kill). Rich
   per-tier transforms (openCrossing, etc.) live in each product's gate-store;
   the spine only owns the shared, safety-critical ones.
   --------------------------------------------------------------------------- */

/* Rail 5 — engage the kill-switch. Drops the span; NEVER clears the pinned wallet
   or egress rail; masks (does not wipe) capabilities so disengage restores. */
export function engageKillSwitch(state, productId, { atIso = null } = {}) {
  const s = normalize(state, productId);
  s.killSwitch = { engaged: true, engagedAtIso: asIso(atIso) };
  return s; // pinned rails already reaffirmed by normalize()
}

export function disengageKillSwitch(state, productId) {
  const s = normalize(state, productId);
  s.killSwitch = { engaged: false, engagedAtIso: null };
  return s;
}

export default {
  SCHEMA_VERSION, CONSENT_SCOPES, LANGS, DIRECTIONS, PRODUCTS, PRODUCT_IDS,
  defaultState, normalize, parse, loadState, serialize,
  containerAllowed, activeCaps, projectionEnabled, projectionLine1, projectionFile, egressAllowed,
  engageKillSwitch, disengageKillSwitch,
};
