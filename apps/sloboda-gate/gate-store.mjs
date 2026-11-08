"use strict";
/* ============================================================================
   Sloboda Gate — toggle-state store (DOM-free, dependency-free)

   The single source of truth for the shape of the state the Waydroid wrapper
   reads. The browser UI (index.html) inlines a logic-identical copy of this
   module (parity-tested by test-ui-parity.mjs, not byte-identical — the
   inline copy is condensed); this module is the canonical, node-testable
   reference and doubles as the contract a wrapper implementer can port.

   NAMING: this state governs the NON-ATTESTABLE Waydroid tier — "Postern for
   postmarketOS — community edition". It is NOT "Porog" (the stock-Android
   managed-profile container, a different product) and NEVER "Postern OS".

   HONESTY RAILS enforced here in code, not just prose:
     - tier is ALWAYS "non-attestable" (never relabelled as attested).
     - egress is ALWAYS Tor-only (`egress.torOnly` is pinned true, like tier);
       input can never widen it to clearnet, and egress stays DENIED until Tor
       reports bootstrapped (`egress.torBootstrapped`) — fail-closed, no leak.
     - every bridge DEFAULTS TO DENY; unknown/missing input => deny.
     - a malformed or partial blob normalises to full-deny + not-consented,
       so a corrupt file can never silently open a bridge.
   No network, no telemetry, no imports.
   UNTESTED: the on-device wrapper that consumes this shape does not exist yet.
   ============================================================================ */

export const SCHEMA_ID = "postern.sloboda-gate.state";
export const SCHEMA_VERSION = 1;
export const TIER = "non-attestable"; // fixed by design; see design-android-container.md

export const BRIDGE_KEYS = ["clipboard", "files", "mic", "camera", "location"];
export const CONSENT_SCOPES = ["session", "persistent"];
export const LANGS = ["pt-BR", "en"];

/* Egress rail: the container's network egress is Tor-only, always. `torOnly` is
   pinned true (never taken from input, exactly like `tier`) so no state file can
   ever downgrade the container to a clearnet leak. `torBootstrapped` is the ONLY
   egress input the wrapper/Tor-glue writes: it is the live signal from
   postern-tor that a circuit is up. Until it is true, egress is DENIED
   (fail-closed) — a half-open Tor is treated as no Tor. Tor here is CLIENT-ONLY
   and is metadata-reduction, NOT anonymity: "hardened, not anonymous". */
export const EGRESS_TOR_ONLY = true;

/* The canonical path the wrapper reads. Documented, not enforced here. */
export const STATE_PATH = "/var/lib/postern/sloboda-gate/state.json";

/* A fresh, fully-safe state: not consented, every bridge denied, kill-switch
   clear. This is what the wrapper MUST assume when the file is absent. */
export function defaultState() {
  return {
    schema: SCHEMA_ID,
    version: SCHEMA_VERSION,
    tier: TIER,
    lang: "en",
    consent: { accepted: false, scope: "session", acceptedAtIso: null },
    bridges: { clipboard: false, files: false, mic: false, camera: false, location: false },
    egress: { torOnly: EGRESS_TOR_ONLY, torBootstrapped: false },
    killSwitch: { engaged: false, engagedAtIso: null },
  };
}

const asBool = (v) => v === true; // anything not exactly true is deny
const oneOf = (v, allowed, fallback) => (allowed.includes(v) ? v : fallback);
const asIso = (v) => (typeof v === "string" && v.length > 0 ? v : null);

/* Normalise ANY input into a valid state. Never throws. Missing/garbage in a
   field collapses to that field's safe default. This is the trust boundary:
   downstream code may assume the result is well-formed and deny-by-default. */
export function normalize(input) {
  const out = defaultState();
  if (!input || typeof input !== "object") return out;

  const c = input.consent && typeof input.consent === "object" ? input.consent : {};
  out.consent.accepted = asBool(c.accepted);
  out.consent.scope = oneOf(c.scope, CONSENT_SCOPES, "session");
  out.consent.acceptedAtIso = out.consent.accepted ? asIso(c.acceptedAtIso) : null;

  const b = input.bridges && typeof input.bridges === "object" ? input.bridges : {};
  for (const k of BRIDGE_KEYS) out.bridges[k] = asBool(b[k]);

  const e = input.egress && typeof input.egress === "object" ? input.egress : {};
  // torOnly stays pinned true from defaultState() — never taken from input, so a
  // hostile/garbage file can never open a clearnet path. Only the live "is Tor up"
  // signal is read, and only "exactly true" counts (fail-closed).
  out.egress.torBootstrapped = asBool(e.torBootstrapped);

  const ks = input.killSwitch && typeof input.killSwitch === "object" ? input.killSwitch : {};
  out.killSwitch.engaged = asBool(ks.engaged);
  out.killSwitch.engagedAtIso = out.killSwitch.engaged ? asIso(ks.engagedAtIso) : null;

  out.lang = oneOf(input.lang, LANGS, "en");
  // tier/schema/version are pinned by defaultState() and never taken from input.
  return out;
}

/* Parse the on-disk JSON text into a normalized state. On ANY parse error the
   wrapper gets the safe default (full-deny), never an exception. TOLERANT: it
   does NOT enforce the schema/version discriminator — use loadState() for the
   strict on-disk boundary. Kept byte-compatible with the shared spine's
   parse() (apps/consent-contract/consent-spine.mjs). */
export function parse(text) {
  let raw = null;
  try { raw = JSON.parse(text); } catch { return defaultState(); }
  return normalize(raw);
}

/* Rails 1+2 (shared consent contract, apps/consent-contract/CONTRACT.md) — the
   STRICT on-disk trust boundary. Corrupt JSON, a FOREIGN `schema`, or an unknown
   `version` each collapse to full-deny (as if the file were absent), BEFORE
   normalize. This is what a reader loading state.json off disk should call so a
   foreign file can never carry `consent.accepted` across. Mirrors the shared
   spine's loadState() for product "sloboda" (discriminator + version guard);
   deny-by-default output stays v1 flat-bool, byte-compatible with the spine. */
export function loadState(text) {
  let raw = null;
  try { raw = JSON.parse(text); } catch { return defaultState(); }
  if (!raw || typeof raw !== "object") return defaultState();
  if (raw.schema !== SCHEMA_ID) return defaultState();       // foreign file => full-deny
  if (raw.version !== SCHEMA_VERSION) return defaultState();  // unknown version => full-deny
  return normalize(raw);
}

/* Serialize for writing the state file (stable key order, trailing newline). */
export function serialize(state) {
  const s = normalize(state);
  return JSON.stringify(s, null, 2) + "\n";
}

/* The wrapper's decision helpers — the ONLY questions it should ask. */

/* May the container run? Consent must be accepted AND the kill-switch clear.
   requireConsent=false in the NixOS module is the only way to bypass the
   consent half, and that is an explicit operator choice recorded there. */
export function containerAllowed(state, { requireConsent = true } = {}) {
  const s = normalize(state);
  if (s.killSwitch.engaged) return false;
  if (requireConsent && !s.consent.accepted) return false;
  return true;
}

/* The set of bridges the wrapper should actually expose: only ones explicitly
   true, and only if the container is allowed to run at all. */
export function activeBridges(state, opts) {
  const s = normalize(state);
  if (!containerAllowed(s, opts)) return [];
  return BRIDGE_KEYS.filter((k) => s.bridges[k] === true);
}

/* May the container reach the network AT ALL? Three fail-closed conditions:
   the container must be allowed to run (consent + kill-switch), egress must be
   pinned Tor-only, and Tor must be live (torBootstrapped). A false/absent
   torBootstrapped => no egress: the wrapper must hold traffic until the
   Tor-glue (see the porog-tor-glue shim over postern-tor) reports a circuit is
   up. This is the toggle the gate drives for the always-on Tor requirement.
   NOTE: this is a userland consent-gate decision, NOT a kernel network
   boundary — a rooted host or a leak below the wrapper defeats it. */
export function egressAllowed(state, opts) {
  const s = normalize(state);
  if (!containerAllowed(s, opts)) return false;
  if (s.egress.torOnly !== true) return false;      // rail; pinned true, defensive
  return s.egress.torBootstrapped === true;         // fail-closed until Tor is up
}

export default {
  SCHEMA_ID, SCHEMA_VERSION, TIER, EGRESS_TOR_ONLY, BRIDGE_KEYS, CONSENT_SCOPES, LANGS, STATE_PATH,
  defaultState, normalize, parse, loadState, serialize, containerAllowed, activeBridges, egressAllowed,
};
