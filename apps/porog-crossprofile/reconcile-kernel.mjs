"use strict";
/* ============================================================================
   Porog cross-profile reconcile kernel — the DECISION CORE of the work↔personal
   boundary (DOM-free, dependency-free, host-testable on macOS / Node).

   Porog (Slavic: threshold / soleira — the door between two worlds) is the
   stock-Android managed-profile container. This module is the pure decision
   function a Device Policy Controller (DPC) would consume: it turns the shared
   consent state into the exact set of cross-profile intent-filter directives —
   which `addCrossProfileIntentFilter` flags to install, which cross-profile
   packages to allowlist, and whether DISALLOW_CROSS_PROFILE_COPY_PASTE stays in
   force. The Kotlin DPC that APPLIES these directives is later/VM work; the
   decision logic is provable here, today, with no Android in the loop.

   It mirrors the fail-closed egress seam (apps/porog-tor-glue `egress_decision`
   ↔ apps/noporis-gate `egressAllowed`) and the house style of
   apps/sloboda-gate/gate-store.mjs.

   HONESTY RAILS enforced in code, not just prose:
     - TIER is ALWAYS "key-attested-device": Porog attests the PHONE, not the
       workspace — a key-attested device, NOT a measured-boot workspace, and
       NEVER a Postern Seal. `tier` is pinned, never taken from input.
     - DEFAULT-DENY. Every crossing defaults to `direction: "none"` (and
       `open: false`). Unknown or mismatched schema/version => FULL-DENY. A
       malformed/partial blob normalises to full-deny, so a corrupt file can
       never open a bridge.
     - `open` is the PRIMARY deny gate (design porog-03 §3.3: install only when
       `open == true` exactly). For BACKWARD COMPATIBILITY a crossing that omits
       `open` inherits open-ness from a real direction; an EXPLICIT `open:false`
       always forces the crossing closed even if a stale direction lingers.
     - DIRECTION is first-class: p2w / w2p / both / none map to explicit DPC
       flags; a partial-true blob never "rounds up" to open.
     - STANDING / AMBIENT caps (contacts, calendar, connectedApp) are hard-deny:
       they require the STRONGER standing consent, not just per-crossing consent.
     - A standing package crossing (calendar / connectedApp) opens ONLY when it
       names exactly one VALID package; a missing or malformed package leaves it
       closed — an empty/malformed allowlist never rounds up to an open one.
     - contacts is enforced by setManagedProfile*AccessPolicy (a POLICY over the
       whole contacts surface), not a package allowlist, so it is tracked
       separately from the package-backed caps and carries no package.
     - KILL-SWITCH => clear ALL directives, re-impose
       DISALLOW_CROSS_PROFILE_COPY_PASTE, re-impose the inbound-share block, and
       revoke outstanding content:// URI grants.
     - sealedWallet.preserved is pinned true; input can never unpin it.

   THE HONEST BOUND (documented, not pretended): this kernel governs ONLY the
   managed (work) profile the DPC owns. It has no authority over the personal
   profile, and it cannot un-send bytes that have ALREADY crossed — closing a
   crossing stops FUTURE crossings, it does not recall past ones.

   Reference/prototype, UNAUDITED. No network, no telemetry, no imports.
   ============================================================================ */

export const SCHEMA_ID = "postern.porog-gate.state";
export const SCHEMA_VERSION = 1;

/* Porog attests the phone (key-attested device), not the workspace. Pinned by
   design exactly like the sloboda-gate's `tier`; never taken from input. */
export const TIER = "key-attested-device";

/* The canonical path the DPC reads (shared contract with Dev 0.1). Documented,
   not enforced here. */
export const STATE_PATH = "/var/lib/postern/porog-gate/state.json";

export const CONSENT_SCOPES = ["session", "persistent"];
export const LANGS = ["pt-BR", "en"];

/* A cross-profile crossing may flow in one of four directions. `none` is the
   default and means the bridge stays closed. */
export const DIRECTIONS = ["none", "p2w", "w2p", "both"];

/* Capability classes.
   USER-MEDIATED — the user mediates each crossing at use time (a share sheet, a
   file picker, a paste). Per-crossing `direction` + base consent is enough.
   STANDING / AMBIENT — once open these grant background, un-mediated data
   access. They are HARD-DENY by default and require the STRONGER standing
   consent on top of a direction. */
export const USER_MEDIATED_CAPS = ["intents", "files", "clipboard"];
export const STANDING_CAPS = ["contacts", "calendar", "connectedApp"];
export const CROSSING_KEYS = [...USER_MEDIATED_CAPS, ...STANDING_CAPS];

/* Caps that allowlist EXACTLY ONE NAMED PACKAGE (setCrossProfileCalendarPackages
   / setCrossProfilePackages). Per the A3 map: "allowlist exactly one named
   package." A crossing here that names no valid package has NOTHING to allowlist,
   so it stays CLOSED — you cannot round up an empty allowlist into an open one.
   Exported under both names: `PACKAGE_CAPS` and `PACKAGE_REQUIRED_CAPS` (kept as
   aliases of the same array — two branches of this kernel's history named the
   same concept differently; both names are honoured going forward). */
export const PACKAGE_CAPS = ["calendar", "connectedApp"];
export const PACKAGE_REQUIRED_CAPS = PACKAGE_CAPS;

export const CAP_CLASS = Object.freeze({
  intents: "user-mediated",
  files: "user-mediated",
  clipboard: "user-mediated",
  contacts: "standing",
  calendar: "standing",
  connectedApp: "standing",
});

/* Which Android DPC mechanism enforces each capability:
   - intentFilter        => addCrossProfileIntentFilter(admin, filter, flags)
   - copyPasteRestriction => the DISALLOW_CROSS_PROFILE_COPY_PASTE user restriction
   - contactsPolicy      => setManagedProfileContactsAccessPolicy /
                            setManagedProfileCallerIdAccessPolicy (a POLICY, not a
                            package allowlist — contacts names no package)
   - packageAllowlist    => setCrossProfileCalendarPackages /
                            setCrossProfilePackages (allowlist ONE named package) */
export const CAP_MECHANISM = Object.freeze({
  intents: "intentFilter",
  files: "intentFilter",
  clipboard: "copyPasteRestriction",
  contacts: "contactsPolicy",
  calendar: "packageAllowlist",
  connectedApp: "packageAllowlist",
});

/* The PRECISE DevicePolicyManager call each STANDING cap maps to (§2 table).
   This lets the Kotlin DPC pick the exact API + its SDK_INT fail-closed
   fallback:
   - contactsAccessPolicy    => setManagedProfileContactsAccessPolicy (API 34+),
                                fallback setCrossProfileContactsSearchDisabled +
                                setCrossProfileCallerIdDisabled (< 34). No package.
   - calendarPackages        => setCrossProfileCalendarPackages(admin, Set) (API 30+).
                                Needs a named package; empty set = closed.
   - connectedAppPackages    => setCrossProfilePackages(admin, Set) (API 30+).
                                Needs a named package; empty set = closed. */
export const DPM_MECHANISM = Object.freeze({
  contacts: "contactsAccessPolicy",
  calendar: "calendarPackages",
  connectedApp: "connectedAppPackages",
});

/* The parent restriction that blocks INBOUND share into the managed profile. It
   is cleared only when a personal->managed (p2w / both) files or intents crossing
   is actually open; otherwise it stays set (default-deny inbound). */
export const SHARE_INTO_MANAGED_RESTRICTION = "DISALLOW_SHARE_INTO_MANAGED_PROFILE";

/* Direction -> the exact addCrossProfileIntentFilter flags a DPC installs.
   p2w = personal(parent) can resolve intents in work(managed) => PARENT_CAN_ACCESS_MANAGED.
   w2p = work(managed) can resolve intents in personal(parent) => MANAGED_CAN_ACCESS_PARENT. */
export const DIRECTION_FLAGS = Object.freeze({
  none: [],
  p2w: ["FLAG_PARENT_CAN_ACCESS_MANAGED"],
  w2p: ["FLAG_MANAGED_CAN_ACCESS_PARENT"],
  both: ["FLAG_PARENT_CAN_ACCESS_MANAGED", "FLAG_MANAGED_CAN_ACCESS_PARENT"],
});

/* The user restriction that keeps the clipboard from crossing profiles. */
export const COPY_PASTE_RESTRICTION = "DISALLOW_CROSS_PROFILE_COPY_PASTE";

/* Pinned true: the sealed wallet is preserved across every reconcile. Input can
   never unpin it (mirrors the sloboda-gate's `egress.torOnly`). */
export const SEALED_WALLET_PRESERVED = true;

/* The honest bounds, carried on every decision so no surface can round up what
   the kernel actually guarantees. */
export const CAVEATS = Object.freeze([
  "Porog attests the phone (key-attested device), NOT the workspace — not a measured-boot workspace, never a Postern Seal.",
  "This kernel is the DECISION CORE only; the Android managed-profile boundary (DPC user restrictions + cross-profile intent filters) is what actually enforces these directives.",
  "The kernel governs ONLY the managed (work) profile the DPC owns; it has no authority over the personal profile (user 0).",
  "It cannot un-send bytes that have ALREADY crossed — closing a crossing stops future crossings, it does not recall past ones.",
  "DISALLOW_CROSS_PROFILE_COPY_PASTE is directionless at the OS level: any non-'none' clipboard crossing lifts it in BOTH directions, so clipboard direction is advisory, not OS-enforced.",
  "A standing package crossing (calendar / connectedApp) opens ONLY when it names exactly one package; a missing or malformed package leaves it closed — an empty allowlist never rounds up to an open one.",
  "contacts is enforced by setManagedProfile*AccessPolicy (a POLICY over the whole contacts surface), not a package allowlist, so its direction is advisory, not a per-package grant.",
  "DISALLOW_SHARE_INTO_MANAGED_PROFILE stays imposed (inbound share blocked) unless a p2w files/intents crossing is open; the kill-switch re-imposes it and revokes outstanding content:// URI grants, but it cannot recall bytes already shared.",
  "Reference/prototype, UNAUDITED — no security guarantee until an audit gate.",
]);

/* A fresh, fully-safe state: not consented, no standing grant, every crossing
   closed, kill-switch clear. This is what the DPC MUST assume when the file is
   absent. */
export function defaultState() {
  return {
    schema: SCHEMA_ID,
    version: SCHEMA_VERSION,
    tier: TIER,
    lang: "en",
    consent: { accepted: false, scope: "session", acceptedAtIso: null, standing: false },
    killSwitch: { engaged: false, engagedAtIso: null },
    crossings: {
      intents: { open: false, direction: "none" },
      files: { open: false, direction: "none" },
      clipboard: { open: false, direction: "none" },
      contacts: { open: false, direction: "none" },
      // package caps carry the ONE named package to allowlist; null => nothing to
      // allowlist => the crossing stays closed regardless of direction/open.
      calendar: { open: false, direction: "none", package: null },
      connectedApp: { open: false, direction: "none", package: null },
    },
    sealedWallet: { preserved: SEALED_WALLET_PRESERVED },
  };
}

const asBool = (v) => v === true; // anything not exactly true is deny
const oneOf = (v, allowed, fallback) => (allowed.includes(v) ? v : fallback);
const asIso = (v) => (typeof v === "string" && v.length > 0 ? v : null);
const asDirection = (v) => oneOf(v, DIRECTIONS, "none");

/* A valid Android package name for the ONE-package allowlist caps: a dotted
   identifier (at least one dot), conservative charset. Anything else — missing,
   empty, non-string, single label, junk — normalises to null, which keeps the
   crossing CLOSED (there is nothing to allowlist). Fail-closed on the name too. */
const PKG_RE = /^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$/;
const asPackage = (v) => (typeof v === "string" && PKG_RE.test(v) ? v : null);

/* Does the input declare EXACTLY our schema + version? Anything else — a missing
   field, a stringified version, a future schema — is unrecognised and drives a
   full-deny. We refuse to normalise a blob we don't understand. */
export function schemaRecognized(input) {
  return (
    !!input &&
    typeof input === "object" &&
    input.schema === SCHEMA_ID &&
    input.version === SCHEMA_VERSION
  );
}

/* Normalise ANY input into a valid state. Never throws. Missing/garbage in a
   field collapses to that field's safe default. This is the trust boundary:
   downstream code may assume the result is well-formed and deny-by-default.
   schema / version / tier / sealedWallet.preserved are PINNED here and never
   taken from input.

   A blob that fails schemaRecognized() (wrong/missing schema id, wrong/missing
   version) is a FOREIGN blob, not ours to interpret — we do NOT re-stamp it
   with our pinned schema/version and cherry-pick fields out of it (that would
   be schema laundering: a wrong-schema blob with consent.accepted:true could
   otherwise survive normalisation and read back as a recognised, possibly-open
   state). Unrecognised input collapses to defaultState() in full, with nothing
   from the foreign blob surviving. */
export function normalize(input) {
  const out = defaultState();
  if (!schemaRecognized(input)) return out;

  const c = input.consent && typeof input.consent === "object" ? input.consent : {};
  out.consent.accepted = asBool(c.accepted);
  out.consent.scope = oneOf(c.scope, CONSENT_SCOPES, "session");
  out.consent.standing = asBool(c.standing);
  out.consent.acceptedAtIso = out.consent.accepted ? asIso(c.acceptedAtIso) : null;

  const ks = input.killSwitch && typeof input.killSwitch === "object" ? input.killSwitch : {};
  out.killSwitch.engaged = asBool(ks.engaged);
  out.killSwitch.engagedAtIso = out.killSwitch.engaged ? asIso(ks.engagedAtIso) : null;

  const cr = input.crossings && typeof input.crossings === "object" ? input.crossings : {};
  for (const cap of CROSSING_KEYS) {
    const entry = cr[cap] && typeof cr[cap] === "object" ? cr[cap] : {};
    const direction = asDirection(entry.direction);
    out.crossings[cap].direction = direction;
    // `open` is the primary deny gate (design porog-03 §3.3: install only when
    // `open == true` exactly). For BACKWARD COMPATIBILITY a crossing that omits
    // `open` inherits open-ness from a real direction; an EXPLICIT `open:false`
    // always forces the crossing closed even if a stale direction lingers
    // (fail-closed against a corrupt/hostile writer that clears open but not dir).
    out.crossings[cap].open = "open" in entry ? asBool(entry.open) : direction !== "none";
    if (PACKAGE_CAPS.includes(cap)) {
      out.crossings[cap].package = asPackage(entry.package);
    }
  }

  out.lang = oneOf(input.lang, LANGS, "en");
  // tier / schema / version / sealedWallet.preserved stay pinned from defaultState().
  return out;
}

/* Parse the on-disk JSON text into a normalized state. On ANY parse error the
   DPC gets the safe default (full-deny), never an exception. */
export function parse(text) {
  let raw = null;
  try { raw = JSON.parse(text); } catch { return defaultState(); }
  return normalize(raw);
}

/* Serialize for writing the state file (stable key order, trailing newline). */
export function serialize(state) {
  const s = normalize(state);
  return JSON.stringify(s, null, 2) + "\n";
}

/* The fully-closed directive set: no cross-profile intent filters, no allowlist,
   copy/paste disallowed, clipboard shut. This is what the DPC applies whenever
   the kernel denies — malformed input, unknown schema, no consent, or kill. */
function closedDirectives(reason, { cleared = false } = {}) {
  return {
    schema: SCHEMA_ID,
    version: SCHEMA_VERSION,
    tier: TIER,
    open: false,
    cleared,
    reason,
    intentFilters: [],          // no addCrossProfileIntentFilter calls
    contactsPolicy: { open: false, direction: "none" }, // most-restrictive policy
    crossProfilePackages: [],   // empty calendar/connectedApp allowlists
    copyPasteDisallowed: true,  // DISALLOW_CROSS_PROFILE_COPY_PASTE in force
    clipboardDirection: "none",
    // Inbound-share block imposed; outstanding content:// grants revoked. On a
    // full-deny we always close the inbound door and revoke — fail-closed.
    shareIntoManagedProfileDisallowed: true,
    revokeOutstandingUriGrants: true,
    sealedWalletPreserved: SEALED_WALLET_PRESERVED,
    caveats: CAVEATS,
  };
}

/* THE DECISION FUNCTION. state -> the set of cross-profile directives a DPC
   would apply. Fail-closed at every step, default-deny, direction-first.

   Order of the fail-closed chain:
     1. schema/version not EXACTLY ours  => full-deny (unknown blob).
     2. kill-switch engaged              => clear ALL, re-impose copy/paste deny.
     3. consent not accepted             => default-deny.
     4. otherwise, build per-capability directives from each crossing's `open`
        + direction; standing/ambient caps additionally require standing
        consent, and package-backed caps additionally require a valid package. */
export function reconcile(input) {
  if (!schemaRecognized(input)) {
    return closedDirectives("unknown or mismatched schema/version — full-deny");
  }

  const s = normalize(input);

  if (s.killSwitch.engaged) {
    return closedDirectives(
      "kill-switch engaged — all cross-profile bridges cleared and copy/paste re-disallowed",
      { cleared: true },
    );
  }

  if (!s.consent.accepted) {
    return closedDirectives("consent not accepted — default-deny");
  }

  const intentFilters = [];
  const crossProfilePackages = [];
  let contactsPolicy = { open: false, direction: "none" };
  let clipboardDirection = "none";

  for (const cap of CROSSING_KEYS) {
    const c = s.crossings[cap];
    const dir = c.direction;
    // Primary deny gate: install ONLY when the crossing is explicitly open AND
    // carries a real direction (design §3.3 `open == true` + direction).
    if (c.open !== true) continue;
    if (dir === "none") continue; // open but no direction — nothing to install

    // Standing/ambient caps need the STRONGER consent, not just base consent.
    if (CAP_CLASS[cap] === "standing" && s.consent.standing !== true) continue;

    const mech = CAP_MECHANISM[cap];
    if (mech === "intentFilter") {
      intentFilters.push({ capability: cap, direction: dir, flags: DIRECTION_FLAGS[dir] });
    } else if (mech === "packageAllowlist") {
      // Must name EXACTLY one valid package; no valid name => nothing to
      // allowlist => stays closed. Anti-round-up on the package, not just the
      // direction.
      const pkg = c.package;
      if (!pkg) continue;
      crossProfilePackages.push({
        capability: cap,
        direction: dir,
        mechanism: DPM_MECHANISM[cap],
        package: pkg,
      });
    } else if (mech === "contactsPolicy") {
      // contacts is a POLICY toggle over the whole contacts surface, not a
      // package allowlist — tracked separately, carries no package.
      contactsPolicy = { open: true, direction: dir };
    } else if (mech === "copyPasteRestriction") {
      clipboardDirection = dir;
    }
  }

  // Copy/paste stays disallowed unless the clipboard crossing is explicitly
  // opened. Note the OS restriction is directionless (see CAVEATS): opening it
  // lifts copy/paste in both directions regardless of `clipboardDirection`.
  const copyPasteDisallowed = clipboardDirection === "none";

  // DISALLOW_SHARE_INTO_MANAGED_PROFILE is lifted ONLY when a p2w files/intents
  // crossing is open (data flowing INTO the managed profile). Any other posture
  // keeps inbound share blocked. w2p-only crossings do not lift it.
  const inboundOpen = intentFilters.some(
    (f) =>
      (f.capability === "files" || f.capability === "intents") &&
      (f.direction === "p2w" || f.direction === "both"),
  );
  const shareIntoManagedProfileDisallowed = !inboundOpen;

  return {
    schema: SCHEMA_ID,
    version: SCHEMA_VERSION,
    tier: TIER,
    open: true,
    cleared: false,
    reason: "consented — cross-profile directives reconciled",
    intentFilters,
    contactsPolicy,
    crossProfilePackages,
    copyPasteDisallowed,
    clipboardDirection,
    shareIntoManagedProfileDisallowed,
    // Grants stand while consented; nothing to revoke on the open path.
    revokeOutstandingUriGrants: false,
    sealedWalletPreserved: SEALED_WALLET_PRESERVED,
    caveats: CAVEATS,
  };
}

/* Convenience: reconcile straight from on-disk JSON text. A parse failure yields
   `reconcile(null)` => unrecognised schema => full-deny. Never throws. */
export function reconcileText(text) {
  let raw = null;
  try { raw = JSON.parse(text); } catch { return closedDirectives("unparseable state file — full-deny"); }
  return reconcile(raw);
}

/* Boolean helper: is a single crossing open for the given state? Mirrors the
   reconcile gate exactly (base consent, kill-switch, standing consent for
   standing caps, package validity for package caps), so the two can never
   diverge. */
export function crossingOpen(state, cap) {
  if (!CROSSING_KEYS.includes(cap)) return false;
  const d = reconcile(state);
  if (!d.open) return false;
  const mech = CAP_MECHANISM[cap];
  if (mech === "intentFilter") {
    return d.intentFilters.some((f) => f.capability === cap);
  }
  if (mech === "packageAllowlist") {
    return d.crossProfilePackages.some((p) => p.capability === cap);
  }
  if (mech === "contactsPolicy") {
    return d.contactsPolicy.open === true;
  }
  // clipboard
  return d.clipboardDirection !== "none";
}

export default {
  SCHEMA_ID, SCHEMA_VERSION, TIER, STATE_PATH,
  CONSENT_SCOPES, LANGS, DIRECTIONS,
  USER_MEDIATED_CAPS, STANDING_CAPS, PACKAGE_CAPS, PACKAGE_REQUIRED_CAPS, CROSSING_KEYS,
  CAP_CLASS, CAP_MECHANISM, DPM_MECHANISM,
  DIRECTION_FLAGS, COPY_PASTE_RESTRICTION, SHARE_INTO_MANAGED_RESTRICTION,
  SEALED_WALLET_PRESERVED, CAVEATS,
  defaultState, normalize, parse, serialize,
  schemaRecognized, reconcile, reconcileText, crossingOpen,
};
