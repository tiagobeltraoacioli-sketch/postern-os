"use strict";
/* ============================================================================
   SPDX-License-Identifier: MIT OR Apache-2.0
   SPDX-FileCopyrightText: 2026 Postern Labs

   NoporIS — GOOGLE-PLAY persona flavor: the policy invariants (DOM-free,
   dependency-free, node-testable).

   This is the canonical reference for the Play flavor's post-provisioning
   policy: WHICH system apps the profile owner may `enableSystemApp` (un-hide)
   inside the managed profile, WHICH packages are forbidden here (wallet/signing
   keys never live on the Google side), and the honesty rails that no config
   file may flip. The Kotlin PlayFlavorPolicy consumes this same contract; this
   module is what a reviewer runs.

   It governs FLAVOR B of NoporIS's ONE second persona (see
   Postern-NoporIS-Mechanism-Design.md §3.3). Flavor A (business/clean, == Porog)
   never enables Play/GMS and is NOT this module's concern.

   ── HONESTY / LICENSING RAILS, enforced here in code, not just prose ────────
     - This is the LESS-PRIVATE side by construction: GMS phones home. `LESS_PRIVATE`
       is pinned true and `PROVIDES_PRIVACY` pinned false — no input can flip them.
     - Postern does NOT redistribute Google Play / GMS. `REDISTRIBUTES_GMS` is
       pinned false. We only `enableSystemApp` (un-hide) packages ALREADY present
       on the user's Google-certified device; the user brings their own Google
       account and installs from Play themselves. If a package is absent (e.g. a
       de-Googled ROM), enabling it is a platform no-op — we plant nothing.
     - We do NOT circumvent SafetyNet / Play Integrity. `CIRCUMVENTS_INTEGRITY`
       is pinned false; the verdict is DISCLOSED honestly, never spoofed.
     - NO wallet / signing keys on this side. `HOSTS_WALLET_KEYS` is pinned false;
       any wallet-owned package is force-denied even if a config lists it.
     - Deny-by-default: a package is enable-able only if it is on the explicit
       Play/GMS allowlist AND not wallet-owned. A malformed config normalises to
       "enable nothing, wallet excluded, less-private labelled".
   No network, no telemetry, no imports.

   Status: DESIGN ONLY / reference-prototype / UNAUDITED. The on-device DPC that
   consumes this contract is a scaffold; it has never run on hardware. A rooted /
   kernel-compromised host defeats the profile boundary entirely.
   ============================================================================ */

export const SCHEMA_ID = "noporis.persona.play.flavor";
export const SCHEMA_VERSION = 1;

/* The flavor this module governs. Pinned — the clean flavor is a different code
   path and must never be relabelled into this one. */
export const FLAVOR = "google-play";

/* Honesty rails pinned in code (the anti-round-up primitives, like the gate's
   TIER="non-attestable"). None is ever read from input. */
export const LESS_PRIVATE = true;           // GMS phones home; say so in-product.
export const PROVIDES_PRIVACY = false;      // separation + convenience, NOT privacy.
export const REDISTRIBUTES_GMS = false;     // user brings their own Google account + install.
export const CIRCUMVENTS_INTEGRITY = false; // disclose attestation; never spoof/bypass.
export const HOSTS_WALLET_KEYS = false;     // no wallet/signing keys on the Google side.

/* Nominative-use only: these are Google's package identifiers, named to say what
   we interoperate with. Enabling = un-hiding a system app the certified device
   already ships; it is NOT bundling or redistributing Google software. On a
   device without GMS, enableSystemApp is a no-op — nothing is planted. */
export const PLAY_STORE_PACKAGE = "com.android.vending";
export const GMS_CORE_PACKAGE = "com.google.android.gms";
export const GSF_PACKAGE = "com.google.android.gsf"; // Google Services Framework

/* The explicit allowlist of system apps the Play flavor may `enableSystemApp`
   INSIDE the managed profile only. Kept minimal: the store + the two GMS anchors
   the user needs to sign in and install. Anything not on this list is denied. */
export const PLAY_SYSTEM_APP_ALLOWLIST = Object.freeze([
  PLAY_STORE_PACKAGE,
  GMS_CORE_PACKAGE,
  GSF_PACKAGE,
]);

/* Wallet / signing-key ownership: packages and Keystore-alias prefixes that
   carry Postern wallet or signer material. These NEVER exist in the Google
   persona. Force-denied for enableSystemApp AND asserted absent at policy apply.
   `labs.postern.*` covers the wallet/container apps; the alias prefixes cover
   the StrongBox key material (mobile/android StrongBoxKey.kt). */
export const WALLET_FORBIDDEN_PACKAGE_PREFIXES = Object.freeze([
  "labs.postern.wallet",
  "labs.postern.container",
  "labs.postern.signer",
]);
export const WALLET_FORBIDDEN_KEY_ALIAS_PREFIXES = Object.freeze([
  "postern.wallet.",
  "postern.seal.",
  "postern.signer.",
]);

const isString = (v) => typeof v === "string" && v.length > 0;
const startsWithAny = (s, prefixes) =>
  isString(s) && prefixes.some((p) => s === p || s.startsWith(p + ".") || s.startsWith(p));

/* Is this package wallet/signer-owned (⇒ forbidden on the Google side)? */
export function isWalletOwnedPackage(pkg) {
  return startsWithAny(pkg, WALLET_FORBIDDEN_PACKAGE_PREFIXES);
}

/* Is this Keystore alias wallet/seal/signer material (⇒ must not exist here)? */
export function isWalletKeyAlias(alias) {
  return startsWithAny(alias, WALLET_FORBIDDEN_KEY_ALIAS_PREFIXES);
}

/* THE decision the DPC asks before `enableSystemApp(admin, pkg)`.
   Deny-by-default: allow only if pkg is on the Play/GMS allowlist AND is not
   wallet-owned. Wallet ownership wins over any allowlist entry (defence in depth
   — a wallet package could never legitimately be on the allowlist, but we refuse
   it regardless). Returns { allow, reason }. */
export function mayEnableSystemApp(pkg) {
  if (!isString(pkg)) return { allow: false, reason: "no package named; deny-by-default" };
  if (isWalletOwnedPackage(pkg)) {
    return { allow: false, reason: "wallet/signer package is forbidden on the Google-Play persona" };
  }
  if (!PLAY_SYSTEM_APP_ALLOWLIST.includes(pkg)) {
    return { allow: false, reason: "not on the Play/GMS allowlist; deny-by-default" };
  }
  return { allow: true, reason: "on the Play/GMS allowlist and not wallet-owned" };
}

/* The concrete set of packages the DPC should `enableSystemApp`, derived from the
   allowlist through the same gate. Any wallet package that somehow appeared is
   filtered out here too. */
export function systemAppsToEnable() {
  return PLAY_SYSTEM_APP_ALLOWLIST.filter((p) => mayEnableSystemApp(p).allow);
}

/* Fail-closed guard for the "NO wallet keys on this side" invariant. Given the
   set of Keystore aliases and installed packages the DPC observes in the Play
   profile, return the violations. An empty array means the invariant holds.
   The caller (policy apply / a self-check) treats any violation as a hard stop. */
export function walletExclusionViolations({ keyAliases = [], packages = [] } = {}) {
  const bad = [];
  for (const a of keyAliases) if (isWalletKeyAlias(a)) bad.push({ kind: "keyAlias", value: a });
  for (const p of packages) if (isWalletOwnedPackage(p)) bad.push({ kind: "package", value: p });
  return bad;
}

/* Normalise ANY flavor config into a safe, fully-labelled Play-flavor state.
   Never throws. Garbage/partial input collapses to: enable nothing, wallet
   excluded, less-private labelled, integrity disclosed-not-circumvented. The
   honesty rails are pinned from constants and never taken from input, so no
   config file can downgrade a label or open a forbidden path. */
export function normalize(input) {
  const src = input && typeof input === "object" ? input : {};

  // The only genuinely variable input: which of the ALLOWLISTED apps the user's
  // provisioning asked us to enable. Default = all allowlisted (the point of the
  // flavor), but always re-gated so wallet packages can never slip through.
  const requested = Array.isArray(src.enableSystemApps)
    ? src.enableSystemApps.filter(isString)
    : PLAY_SYSTEM_APP_ALLOWLIST.slice();

  const enabled = requested.filter((p) => mayEnableSystemApp(p).allow);

  return {
    schema: SCHEMA_ID,
    version: SCHEMA_VERSION,
    flavor: FLAVOR,                    // pinned
    lessPrivate: LESS_PRIVATE,         // pinned true
    providesPrivacy: PROVIDES_PRIVACY, // pinned false
    redistributesGms: REDISTRIBUTES_GMS,       // pinned false
    circumventsIntegrity: CIRCUMVENTS_INTEGRITY, // pinned false
    hostsWalletKeys: HOSTS_WALLET_KEYS,          // pinned false
    // Enumerated de-dup, stable order = allowlist order.
    enableSystemApps: PLAY_SYSTEM_APP_ALLOWLIST.filter((p) => enabled.includes(p)),
    // Cross-persona sharing stays OFF here exactly as flavor A: the Play persona
    // must never see the clean persona's data. This module does not open bridges;
    // the persona-root bridge panel (Dev N-persona) is the only opener, deny-by-default.
    crossPersonaSharing: false,
  };
}

/* Serialize for writing/echoing the applied Play-flavor policy (stable order). */
export function serialize(state) {
  return JSON.stringify(normalize(state), null, 2) + "\n";
}

export default {
  SCHEMA_ID, SCHEMA_VERSION, FLAVOR,
  LESS_PRIVATE, PROVIDES_PRIVACY, REDISTRIBUTES_GMS, CIRCUMVENTS_INTEGRITY, HOSTS_WALLET_KEYS,
  PLAY_STORE_PACKAGE, GMS_CORE_PACKAGE, GSF_PACKAGE,
  PLAY_SYSTEM_APP_ALLOWLIST, WALLET_FORBIDDEN_PACKAGE_PREFIXES, WALLET_FORBIDDEN_KEY_ALIAS_PREFIXES,
  isWalletOwnedPackage, isWalletKeyAlias, mayEnableSystemApp, systemAppsToEnable,
  walletExclusionViolations, normalize, serialize,
};
