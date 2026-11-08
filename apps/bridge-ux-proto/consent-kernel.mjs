// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
"use strict";
/* ============================================================================
   bridge-ux-proto — the SHARED consent-UX kernel (DOM-free, dependency-free)

   This is the canonical, node-checkable reference the three prototype pages
   (noporis-persona-switch.html / porog-onboarding.html / sloboda-entry.html)
   each inline a copy of. It is UX-layer logic only: it decides what the SURFACE
   should say and which action is the safe one — it moves no data, signs nothing,
   opens no bridge. The bridge devs own the functional plumbing; this only shapes
   the honest picture the human is shown.

   HONESTY RAILS baked in as pinned constants (never taken from input):
     - Every tier is `non-attestable` on its FAR/escape side. Nothing here can
       relabel a less-private surface as attested, sealed, or measured-boot.
     - Porog attests the PHONE (a key-attested device), NEVER the workspace, and
       is NEVER a measured-boot workspace — that property is Postern OS Mobile's
       alone. The qualifier travels with the claim, always.
     - Sloboda is the non-attestable escape hatch: entering Android = data leaves
       the sealed base; Play Integrity STRONG fails; never Seal-covered.
     - DENY-BY-DEFAULT. Missing / garbage / absent input normalises to full-deny
       + not-consented. Refusing, closing, and the kill-switch are always safe.

   Reference-prototype, UNAUDITED. Certifies nothing. The coin is not a security;
   personal use is free; not legal advice. No network, no telemetry, no clock
   (timestamps are caller-supplied so the logic is deterministic + testable).
   ============================================================================ */

/* --- the five cross-persona capabilities, in loudness order (quietest first) - */
export const CAPABILITIES = ["clipboard", "files", "location", "mic", "camera"];

/* The two loudest capabilities sit behind a SECOND micro-consent (a live sensor
   feed leaving the clean side is the highest-consequence hand-over). */
export const LOUD_CAPABILITIES = ["mic", "camera"];

export const SCOPES = ["single", "session", "persistent"]; // 'single' = one item, then re-ask

/* Human copy for each capability: what data, and the honest direction note. */
export const CAP_INFO = {
  clipboard: { label: "Clipboard", what: "The text or image currently copied on the clean side.", dir: "clean → less-private" },
  files:     { label: "Files",     what: "The one file or folder you pick — nothing else on the clean side.", dir: "clean → less-private" },
  location:  { label: "Location",  what: "A single coarse or precise GPS fix, when asked.", dir: "clean → less-private" },
  mic:       { label: "Microphone",what: "A live audio feed from the clean side's mic. Loud tier.", dir: "clean → less-private" },
  camera:    { label: "Camera",    what: "A live video feed from the clean side's camera. Loud tier.", dir: "clean → less-private" },
};

/* --- the three tiers, pinned. `tier` is the honesty posture, never from input - */
export const TIERS = {
  noporis: {
    id: "noporis",
    product: "NoporIS",
    role: "the guarded bridge",
    farTier: "non-attestable",        // the Google-Play persona — always
    farLabel: "Google-Play side · less private",
    attestable: false,                // no padlock on the far side, ever
    sealCovered: false,
    honesty:
      "The Google-Play persona is the LESS-PRIVATE side by construction: it runs " +
      "Google Play Services and phones home to Google. NoporIS sells separation and " +
      "convenience — not privacy on that side. Sandboxed by Android's work profile, " +
      "not sealed: a rooted or compromised phone defeats the separation.",
  },
  porog: {
    id: "porog",
    product: "Porog",
    role: "the guarded door",
    farTier: "key-attested device",   // attests the PHONE, not the workspace
    farLabel: "key-attested device — not a measured-boot workspace",
    attestable: true,                 // ONLY the phone's device key; NOT the workspace
    sealCovered: false,               // no Postern Seal / measured boot for Porog
    honesty:
      "Porog is a key-attested device, not a measured-boot workspace: Android Key " +
      "Attestation measures the PHONE (its keystore, boot and patch state) and names " +
      "the app — it says NOTHING about the workspace's code or contents. No Postern " +
      "Seal, no measured boot, no os_roothash covers Porog. Play Integrity STRONG will " +
      "fail on rooted / unlocked / custom-ROM devices, and we report the real verdict.",
  },
  sloboda: {
    id: "sloboda",
    product: "Sloboda",
    role: "the settlement beyond the wall",
    farTier: "non-attestable",        // the Waydroid escape hatch — always
    farLabel: "non-attestable escape hatch — data leaves the sealed base",
    attestable: false,
    sealCovered: false,               // os_roothash says nothing about the mutable image
    honesty:
      "Sloboda is the NON-ATTESTABLE escape hatch: a full Google/AOSP Android in a " +
      "Waydroid container. Entering it means data LEAVES THE SEALED BASE. Play Integrity " +
      "STRONG fails (banking, Wallet/Pay, DRM refuse) — by design, not a bug. It is NEVER " +
      "covered by the Postern Seal and is NEVER 'Postern OS'.",
  },
};

/* --- deny-by-default state model (mirrors the shipped noporis-gate shape) ----- */
const asBool = (v) => v === true;                         // anything not exactly true = deny
const oneOf = (v, allowed, fb) => (allowed.includes(v) ? v : fb);
const asIso = (v) => (typeof v === "string" && v.length > 0 ? v : null);

const closedCap = () => ({ open: false, scope: "single", openedAtIso: null });

/* A fresh, fully-SAFE posture: not standing on the bridge, every capability
   denied, kill-switch clear, sealed base preserved. This is what a surface MUST
   assume when it has no trustworthy state. */
export function safeDefault(tierId = "noporis") {
  const caps = {};
  for (const k of CAPABILITIES) caps[k] = closedCap();
  return {
    tier: tierId,
    onBridge: false,                                 // first-entry consent not given
    scope: "session",
    capabilities: caps,
    killSwitch: { engaged: false, engagedAtIso: null },
    sealedBase: { preserved: true },                 // pinned — the kill-switch never destroys it
  };
}

/* The trust boundary: normalise ANY input to a well-formed full-deny-capable
   state. Never throws. Missing/garbage collapses to that field's safe default. */
export function normalize(input, tierId = "noporis") {
  const out = safeDefault(tierId);
  if (!input || typeof input !== "object") return out;
  out.onBridge = asBool(input.onBridge);
  out.scope = oneOf(input.scope, SCOPES, "session");
  const ci = input.capabilities && typeof input.capabilities === "object" ? input.capabilities : {};
  for (const k of CAPABILITIES) {
    const x = ci[k] && typeof ci[k] === "object" ? ci[k] : {};
    const open = asBool(x.open);
    out.capabilities[k] = { open, scope: oneOf(x.scope, SCOPES, "single"), openedAtIso: open ? asIso(x.openedAtIso) : null };
  }
  const ks = input.killSwitch && typeof input.killSwitch === "object" ? input.killSwitch : {};
  out.killSwitch.engaged = asBool(ks.engaged);
  out.killSwitch.engagedAtIso = out.killSwitch.engaged ? asIso(ks.engagedAtIso) : null;
  // sealedBase.preserved is pinned by safeDefault and never read from input.
  return out;
}

/* Is the bridge standing at all? Consent given AND kill-switch clear. */
export function bridgeStanding(state) {
  const s = normalize(state, state && state.tier);
  return !s.killSwitch.engaged && s.onBridge === true;
}

/* Which capabilities are actually lent right now — only while standing. A missing
   consent or an engaged kill-switch yields NOTHING (fail-closed). */
export function activeCapabilities(state) {
  const s = normalize(state, state && state.tier);
  if (!bridgeStanding(s)) return [];
  return CAPABILITIES.filter((k) => s.capabilities[k].open === true);
}

export function sealedBasePreserved(state) {
  return normalize(state, state && state.tier).sealedBase.preserved === true;
}

/* --- pure transforms: the levers a human throws. Each returns a NEW state. ---- */
export function standOnBridge(state, { scope = "session", atIso = null } = {}) {
  const s = normalize(state, state && state.tier);
  s.onBridge = true;
  s.scope = oneOf(scope, SCOPES, "session");
  s.acceptedAtIso = asIso(atIso);
  return s;
}

export function leaveBridge(state) {
  const s = normalize(state, state && state.tier);
  s.onBridge = false;
  for (const k of CAPABILITIES) s.capabilities[k] = closedCap(); // withdraw everything with it
  return s;
}

/* Open exactly ONE capability — never bundles (anti-round-up), never fires
   without the bridge standing (no silent grant). Unknown key = no-op. */
export function openCapability(state, key, { scope = "single", atIso = null } = {}) {
  const s = normalize(state, state && state.tier);
  if (!CAPABILITIES.includes(key)) return s;
  if (!bridgeStanding(s)) return s;
  s.capabilities[key] = { open: true, scope: oneOf(scope, SCOPES, "single"), openedAtIso: asIso(atIso) };
  return s;
}

export function revokeCapability(state, key) {
  const s = normalize(state, state && state.tier);
  if (!CAPABILITIES.includes(key)) return s;
  s.capabilities[key] = closedCap();
  return s;
}

/* Engage the kill-switch — drop the span. Reaffirms the sealed-base invariant:
   cutting the bridge NEVER destroys the near side's wallet/keys. */
export function engageKillSwitch(state, { atIso = null } = {}) {
  const s = normalize(state, state && state.tier);
  s.killSwitch = { engaged: true, engagedAtIso: asIso(atIso) };
  s.sealedBase = { preserved: true };
  return s;
}

export function disengageKillSwitch(state) {
  const s = normalize(state, state && state.tier);
  s.killSwitch = { engaged: false, engagedAtIso: null };
  return s;
}

/* --- WYSIWYS: the exact one-line badge the signer core would fold into the
   `peer_device` field. The world label is derived from the pairing/tier, never
   from anything the far side controls, so the less-private side cannot spoof the
   clean side. Used for the "signed-consent moment". --------------------------- */
export function signerBadge({ tierId = "noporis", capability = "clipboard", peer = "the paired device", scope = "single" } = {}) {
  const t = TIERS[tierId] || TIERS.noporis;
  const cap = CAP_INFO[capability] ? CAP_INFO[capability].label.toLowerCase() : capability;
  // NoporIS honesty qualifier, pinned: farLabel already says "less private" ONCE;
  // the badge adds the non-attestable fact (never a duplicated "less private").
  // Keyed off the resolved tier so an unknown tierId still gets the honest suffix.
  const qual = t.id === "noporis" ? " · non-attestable" : "";
  return `${t.product} · ${t.farLabel}${qual} · ${cap} (${scope}) · ${peer}`;
}

export default {
  CAPABILITIES, LOUD_CAPABILITIES, SCOPES, CAP_INFO, TIERS,
  safeDefault, normalize, bridgeStanding, activeCapabilities, sealedBasePreserved,
  standOnBridge, leaveBridge, openCapability, revokeCapability,
  engageKillSwitch, disengageKillSwitch, signerBadge,
};
