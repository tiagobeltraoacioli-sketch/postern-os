// SPDX-License-Identifier: MIT OR Apache-2.0
"use strict";
/* ============================================================================
   NoporIS Gate — the GUARDED CROSSING consent store (DOM-free, dependency-free)

   NoporIS is the guarded *bridge* (the Kalinov crossing): a controlled passage
   between two personas on one stock handset — a near/clean side and a far
   Google-Play side — that both keep existing. This module is the single source
   of truth for the shape of the state the on-device bridge wrapper reads. The
   browser UI (index.html) inlines a condensed, behavior-equivalent port of this
   logic (it omits parse/loadState/serialize/revokeAllCrossings and the
   sloboda-bridge file helpers, which the demo page does not need) — kept in
   sync by hand, not generated. This module is the
   canonical, node-testable reference and the contract a wrapper implementer
   can port.

   NAMING: this is NoporIS — the guarded BRIDGE. It is NOT "Porog" (the
   stock-Android managed-profile *door*, a different product), NOT the Waydroid
   community edition (`apps/sloboda-gate`, a different tier), and NEVER
   "Postern OS". NoporIS is an app on stock Android; it does not own the kernel,
   bootloader, baseband, or TEE. "Nopor" is a coined mark, not folklore.

   HONESTY RAILS enforced here in code, not just prose:
     - tier is ALWAYS "non-attestable". The far (Google-Play) side is the
       LESS-PRIVATE side by construction — it phones home to Google; there is no
       Seal, no measured boot, and nothing here can relabel it as attested.
     - every crossing DEFAULTS TO DENY (never given). Unknown/missing input =>
       deny. A crossing is a deliberate, per-capability hand-over the human
       throws, disclosed and individually revocable. Nothing crosses that the
       user did not hand across. Anti-round-up: opening never bundles — one
       lever, one capability — never widens its direction, and never fires
       without consent (no silent grant).
     - the kill-switch DROPS THE SPAN (stops the far side) but the sealed
       wallet/keys on the near side ARE NEVER DESTROYED. `sealedWallet.preserved`
       is pinned true (like `tier`): no state file and no kill-switch can flip it.
     - a malformed or partial blob normalises to full-deny + not-consented, so a
       corrupt file can never silently open a crossing or claim the wallet gone.

   This is a USERLAND consent gate, NOT a kernel boundary: a rooted / unlocked /
   compromised host defeats the separation. "Sandboxed, not secure." Separation
   and convenience — NOT privacy on the Google side.

   No network, no telemetry, no imports, no clock (timestamps are caller-supplied
   so the logic stays deterministic and testable).
   UNTESTED: the on-device wrapper that consumes this shape does not exist yet.
   Reference-prototype, UNAUDITED. The coin is not a security. Not legal advice.
   ============================================================================ */

export const SCHEMA_ID = "postern.noporis-gate.state";
export const SCHEMA_VERSION = 1;
export const TIER = "non-attestable"; // fixed by design — the far side is never attested

export const CROSSING_KEYS = ["clipboard", "files", "mic", "camera", "location"];
export const CONSENT_SCOPES = ["session", "persistent"];
export const LANGS = ["pt-BR", "en"];

/* Per-crossing DIRECTION — the DPM (data-policy / crossing-direction) key the
   cross-persona bridge glue (apps/noporis-bridge-glue) reads. A crossing is
   authorised for exactly ONE lane, never "both": lending clipboard/files near→far
   does NOT also authorise the far side to push far→near. This mirrors the signed
   per-direction ConsentRecord in noporis-02 §2 ("Clipboard-to-Google does not
   authorize clipboard-from-Google"). Default is the SINGLE, less-dangerous lane
   `near-to-far` (the clean side hands something to the Google side); the ingest
   lane `far-to-near` (Google pushes INTO the hardened side) must be chosen on
   purpose. Anti-round-up: opening a crossing never widens its direction. */
export const CROSSING_DIRECTIONS = ["near-to-far", "far-to-near"];
export const DEFAULT_DIRECTION = "near-to-far";

/* Honesty rail (documentation constant): the far/Google-Play side is the
   less-private side by construction. Unlike the Waydroid tier there is NO
   Tor-only egress here — the far persona uses normal networking and phones home
   to Google; that is the cost of the convenience, and every surface says so. */
export const LESS_PRIVATE_FAR_SIDE = true;

/* Rail: cutting the bridge must never destroy sealed wallet state on the near
   side. Pinned true, exactly like `tier` — never taken from input, never
   cleared by the kill-switch. The door and its keys survive the span dropping. */
export const WALLET_PRESERVED = true;

/* The canonical path the wrapper reads. Documented, not enforced here. */
export const STATE_PATH = "/var/lib/postern/noporis-gate/state.json";

/* The tiny derived toggle file the Waydroid wrapper (apps/sloboda) and Porog's
   cross-profile enforcement side read (noporis-02 §3.2). NoporIS is the SOLE
   writer; those consumers are read-only. It is a PROJECTION of this state — line
   1 is exactly `enabled` iff the span is genuinely up and lending something, else
   `disabled`. See slobodaBridgeToggle/slobodaBridgeStateFile below. */
export const SLOBODA_BRIDGE_PATH = "/run/postern/consent/sloboda-bridge.state";

/* The two — and ONLY two — literal values of the runtime bridge-state
   projection. Default-CLOSED: any value that is not exactly "enabled" MUST be
   read as off (matches the Waydroid tier's `paw-lib.sh`, which treats anything
   but `enabled` as off). Downstream never string-guesses; it compares to these. */
export const BRIDGE_STATE_ENABLED = "enabled";
export const BRIDGE_STATE_DISABLED = "disabled";

/* A fresh crossing: never given. Denied, session-scoped, no timestamp, and the
   single default direction (never "both"). */
function closedCrossing() {
  return { open: false, scope: "session", direction: DEFAULT_DIRECTION, openedAtIso: null };
}

/* A fresh, fully-safe state: not consented, every crossing denied, kill-switch
   clear, sealed wallet preserved. This is what the wrapper MUST assume when the
   file is absent. */
export function defaultState() {
  return {
    schema: SCHEMA_ID,
    version: SCHEMA_VERSION,
    tier: TIER,
    lang: "en",
    consent: { accepted: false, scope: "session", acceptedAtIso: null },
    crossings: {
      clipboard: closedCrossing(),
      files: closedCrossing(),
      mic: closedCrossing(),
      camera: closedCrossing(),
      location: closedCrossing(),
    },
    killSwitch: { engaged: false, engagedAtIso: null },
    sealedWallet: { preserved: WALLET_PRESERVED },
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

  const cr = input.crossings && typeof input.crossings === "object" ? input.crossings : {};
  for (const k of CROSSING_KEYS) {
    const x = cr[k] && typeof cr[k] === "object" ? cr[k] : {};
    const open = asBool(x.open); // exactly true, else never-given
    out.crossings[k] = {
      open,
      scope: oneOf(x.scope, CONSENT_SCOPES, "session"),
      // Direction is always pinned to one lane; an unknown/absent value collapses
      // to the less-dangerous near→far default, never widens to both.
      direction: oneOf(x.direction, CROSSING_DIRECTIONS, DEFAULT_DIRECTION),
      openedAtIso: open ? asIso(x.openedAtIso) : null,
    };
  }

  const ks = input.killSwitch && typeof input.killSwitch === "object" ? input.killSwitch : {};
  out.killSwitch.engaged = asBool(ks.engaged);
  out.killSwitch.engagedAtIso = out.killSwitch.engaged ? asIso(ks.engagedAtIso) : null;

  out.lang = oneOf(input.lang, LANGS, "en");
  // tier/schema/version and sealedWallet.preserved are pinned by defaultState()
  // and never taken from input: no file can relabel the tier as attested, nor
  // claim the sealed wallet was destroyed.
  return out;
}

/* Parse JSON text into a normalized state. On ANY parse error the caller gets
   the safe default (full-deny), never an exception. TOLERANT: it does NOT
   enforce the schema/version discriminator — use loadState() for the strict
   on-disk boundary. Kept byte-compatible with the shared spine's parse()
   (apps/consent-contract/consent-spine.mjs). */
export function parse(text) {
  let raw = null;
  try { raw = JSON.parse(text); } catch { return defaultState(); }
  return normalize(raw);
}

/* Rails 1+2 (shared consent contract, apps/consent-contract/CONTRACT.md) — the
   STRICT on-disk trust boundary. Corrupt JSON, a FOREIGN `schema`, or an unknown
   `version` each collapse to full-deny (as if the file were absent), BEFORE
   normalize. This is what the wrapper loading state.json off disk MUST call so a
   foreign or future-version file can never carry `consent.accepted` or an open
   crossing across (the schema's "refuse a foreign file outright" / "full-deny on
   an unknown version" contract). Mirrors the shared spine's loadState() for
   product "noporis" and the Rust orchestrator's GateState::from_gate_json
   (apps/noporis-bridge-glue/src/substrate.rs), which already refuses these —
   keeping JS and Rust readers of the same file in agreement. */
export function loadState(text) {
  let raw = null;
  try { raw = JSON.parse(text); } catch { return defaultState(); }
  if (!raw || typeof raw !== "object") return defaultState();
  if (raw.schema !== SCHEMA_ID) return defaultState();       // foreign file => full-deny
  if (raw.version !== SCHEMA_VERSION) return defaultState(); // unknown version => full-deny
  return normalize(raw);
}

/* Serialize for writing the state file (stable key order, trailing newline). */
export function serialize(state) {
  const s = normalize(state);
  return JSON.stringify(s, null, 2) + "\n";
}

/* ---------------------------------------------------------------------------
   Decision helpers — the ONLY questions the wrapper should ask.
   --------------------------------------------------------------------------- */

/* Is the bridge standing (may anything cross at all)? Consent must be accepted
   AND the kill-switch clear. requireConsent=false is the only bypass and must be
   an explicit, recorded operator choice — never a default. */
export function bridgeStanding(state, { requireConsent = true } = {}) {
  const s = normalize(state);
  if (s.killSwitch.engaged) return false;         // span dropped => nothing crosses
  if (requireConsent && !s.consent.accepted) return false; // entered on purpose, or not at all
  return true;
}

/* The capabilities actually lent across the bridge right now: only crossings the
   user explicitly opened, and only while the bridge is standing. A kill-switch or
   missing consent yields NOTHING crossing (fail-closed). */
export function activeCrossings(state, opts) {
  const s = normalize(state);
  if (!bridgeStanding(s, opts)) return [];
  return CROSSING_KEYS.filter((k) => s.crossings[k].open === true);
}

/* Is the sealed wallet on the near side preserved? Always true by construction —
   the invariant is pinned and no input/kill-switch path can clear it. Exposed as
   a helper so the wrapper/UI can assert it out loud rather than assume it. */
export function walletPreserved(state) {
  return normalize(state).sealedWallet.preserved === true;
}

/* ---------------------------------------------------------------------------
   sloboda-bridge.state projection — the tiny derived toggle Porog (A3) and the
   Waydroid wrapper (apps/sloboda) read (noporis-02 §3.2). NoporIS is the SOLE
   writer; both are read-only consumers that honour their existing contract: the
   span is up ONLY IF line 1 is exactly `enabled`. This is a pure DERIVED view of
   the gate state — it can never open a crossing, only reflect one already open.
   --------------------------------------------------------------------------- */

/* projectNoporisBridgeState — the SINGLE runtime string the on-device
   orchestrator (the sole file writer, Dev A) persists to the bridge-state file
   that the enforcement side reads. This function is PURE: it computes, it never
   persists, never touches the clock, never does I/O — the double-writer bug is
   avoided by construction (gate-store computes; orchestrator writes; killswitch
   only signals).

   Contract: returns the literal "enabled" IFF the bridge is genuinely carrying
   something right now —
       consent.accepted  &&  !killSwitch.engaged  &&  (any crossing open)
   — otherwise the literal "disabled". Because it normalises first (via
   `activeCrossings`, the same fail-closed decision helper), malformed / partial /
   hostile input collapses to full-deny and can therefore NEVER project "enabled":
   a corrupt file cannot silently stand the bridge up. Reusing `activeCrossings`
   guarantees the projection and the per-capability decision can never disagree.

   NoporIS adds no attestation: "enabled" means a policy crossing is open on the
   less-private side, NOT that anything is attested, sealed, or private. */
export function projectNoporisBridgeState(state) {
  return activeCrossings(state).length > 0 ? BRIDGE_STATE_ENABLED : BRIDGE_STATE_DISABLED;
}

/* The single toggle word Porog / the Waydroid wrapper key off. Semantically
   identical to projectNoporisBridgeState (`enabled` iff standing + lending);
   kept as its own name because those consumers reference it by this name.
   Delegates to the single projection so the two can never drift apart. */
export function slobodaBridgeToggle(state) {
  return projectNoporisBridgeState(state);
}

/* The schema version of the sloboda-bridge.state projection BODY (not state.json).
   This projection format is owned entirely by NoporIS — the sole writer — so the
   version is ours to bump on any change to line 1's meaning or the marker lines'
   semantics. Deliberately mirrors the Rust orchestrator's
   `SLOBODA_BRIDGE_SCHEMA_VERSION` (apps/noporis-bridge-glue/src/substrate.rs): the
   two writers MUST stay byte-for-byte identical, pinned by the cross-language
   golden fixtures tests/golden/sloboda-bridge.*.state in that crate. */
export const SLOBODA_BRIDGE_SCHEMA_VERSION = 1;

/* The full file body the wrapper writes to SLOBODA_BRIDGE_PATH. Byte-for-byte
   identical to the Rust orchestrator's `project_sloboda_bridge_state()` (Dev A,
   apps/noporis-bridge-glue) — the on-device sole writer — so a polling consumer
   sees exactly the same bytes no matter which writer produced them:

     line 1                the load-bearing toggle (`enabled` / `disabled`); the
                           ONLY line the consumer (paw-lib.sh, Porog) keys off.
     container=allowed     iff consent accepted AND kill-switch clear — the far
                           side may *run* even with no crossing open.
     kill=engaged          iff the kill-switch is engaged — a defensive override
                           that blocks entry regardless of anything else.
     schema_version=<N>    additive, versioned marker (appended LAST) so a reader
                           refuses to trust a future/older format instead of
                           silently misparsing it. See the Rust read-side
                           `verify_sloboda_bridge_schema`.

   At most one of container/kill is present (they are mutually exclusive by their
   guards). Trailing newline; write atomically (temp + fsync + rename). NEVER
   claims privacy on the far side — it is the less-private, non-attestable Google
   world by construction; `disabled` (and a missing file) is the safe default. */
export function slobodaBridgeStateFile(state) {
  const s = normalize(state);
  let body = slobodaBridgeToggle(s) + "\n";
  if (s.consent.accepted && !s.killSwitch.engaged) body += "container=allowed\n";
  if (s.killSwitch.engaged) body += "kill=engaged\n";
  body += "schema_version=" + SLOBODA_BRIDGE_SCHEMA_VERSION + "\n";
  return body;
}

/* ---------------------------------------------------------------------------
   Pure state transformers — the levers the human throws. Each returns a NEW
   normalized state; none mutate the input; none touch the clock (caller supplies
   any timestamp). These encode anti-round-up + fail-closed + revocable-by-design.
   --------------------------------------------------------------------------- */

/* Record first-entry consent to stand on the bridge (read the honest disclosure,
   accepted). scope 'session' (default, safer: re-ask next boot) or 'persistent'. */
export function acceptConsent(state, { scope = "session", atIso = null } = {}) {
  const s = normalize(state);
  s.consent = {
    accepted: true,
    scope: oneOf(scope, CONSENT_SCOPES, "session"),
    acceptedAtIso: asIso(atIso),
  };
  return s;
}

/* Withdraw consent: the bridge is no longer entered. All crossings collapse to
   never-given at decision time via bridgeStanding; here we also clear them so the
   persisted file cannot re-open them behind a later re-consent. */
export function withdrawConsent(state) {
  const s = normalize(state);
  s.consent = { accepted: false, scope: "session", acceptedAtIso: null };
  for (const k of CROSSING_KEYS) s.crossings[k] = closedCrossing();
  return s;
}

/* Throw ONE crossing open — a single, deliberate, per-capability hand-over.
   Anti-round-up: opens exactly the named capability and nothing else, in exactly
   ONE lane (never both), and ONLY if the bridge is standing (consented + not
   killed). Otherwise it is a no-op: NEVER a silent grant. Unknown capability =>
   no-op. An unknown direction collapses to the near→far default, never widens. */
export function openCrossing(state, key, { scope = "session", direction = DEFAULT_DIRECTION, atIso = null } = {}) {
  const s = normalize(state);
  if (!CROSSING_KEYS.includes(key)) return s; // unknown capability: refuse
  if (!bridgeStanding(s)) return s;           // no consent / killed: never silently grant
  s.crossings[key] = {
    open: true,
    scope: oneOf(scope, CONSENT_SCOPES, "session"),
    // One lane only; an unknown direction collapses to near→far, never both.
    direction: oneOf(direction, CROSSING_DIRECTIONS, DEFAULT_DIRECTION),
    openedAtIso: asIso(atIso),
  };
  return s;
}

/* Revoke ONE crossing (soft, per-capability): collapse it to "never given".
   A revoked or expired hand-over is indistinguishable from one never made. */
export function revokeCrossing(state, key) {
  const s = normalize(state);
  if (!CROSSING_KEYS.includes(key)) return s;
  s.crossings[key] = closedCrossing();
  return s;
}

/* Revoke every crossing at once (still leaves the bridge standing/consented). */
export function revokeAllCrossings(state) {
  const s = normalize(state);
  for (const k of CROSSING_KEYS) s.crossings[k] = closedCrossing();
  return s;
}

/* Engage the kill-switch — DROP THE SPAN. Stops the far side entirely; nothing
   crosses while engaged. Reaffirms the sealed-wallet invariant: cutting the
   bridge NEVER destroys the near side's sealed wallet/keys. Consent and the
   persisted crossings are left intact (masked, not wiped) so disengaging restores
   the prior posture — but the door and its keys were never at risk. */
export function engageKillSwitch(state, { atIso = null } = {}) {
  const s = normalize(state);
  s.killSwitch = { engaged: true, engagedAtIso: asIso(atIso) };
  s.sealedWallet = { preserved: WALLET_PRESERVED }; // invariant, reaffirmed
  return s;
}

/* Disengage the kill-switch — allow the bridge to stand again (still gated by
   consent). Does not by itself re-open any crossing. */
export function disengageKillSwitch(state) {
  const s = normalize(state);
  s.killSwitch = { engaged: false, engagedAtIso: null };
  return s;
}

export default {
  SCHEMA_ID, SCHEMA_VERSION, TIER, LESS_PRIVATE_FAR_SIDE, WALLET_PRESERVED,
  BRIDGE_STATE_ENABLED, BRIDGE_STATE_DISABLED,
  CROSSING_KEYS, CONSENT_SCOPES, CROSSING_DIRECTIONS, DEFAULT_DIRECTION, LANGS,
  STATE_PATH, SLOBODA_BRIDGE_PATH, SLOBODA_BRIDGE_SCHEMA_VERSION,
  defaultState, normalize, parse, loadState, serialize,
  bridgeStanding, activeCrossings, walletPreserved, projectNoporisBridgeState,
  slobodaBridgeToggle, slobodaBridgeStateFile,
  acceptConsent, withdrawConsent,
  openCrossing, revokeCrossing, revokeAllCrossings,
  engageKillSwitch, disengageKillSwitch,
};
