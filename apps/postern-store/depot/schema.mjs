// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Postern Labs and Postern community contributors
//
// Depot — shared vocabulary for the multi-repo `postern.catalog/v1` client.
// Mirrors the constants already enforced in apps/postern-store/index.html's
// normalizeEntry so both the legacy single-catalog page and the multi-repo
// Depot client apply the SAME honesty spine — this file exists so neither
// copy drifts out of sync with the other conceptually (index.html's copy is
// the shipping one; this is Depot's, extended per docs/store-fdroid/01-architecture.md).

export const CATEGORIES = new Set([
  "communication", "files", "security", "media", "network",
  "finance", "assistants", "system", "developer",
]);

export const SOURCE_LABELS = new Set([
  "native-linux", "flatpak", "fdroid", "waydroid-android", "web", "postern-apk",
]);

/** The trust lane. Only attestable-nix can ever earn the ATTESTED badge (01-architecture.md §4). */
export const TIER_LABELS = new Set(["attestable-nix", "pmos-overlay", "sloboda-compat", "browser"]);

export const LICENSE_CLASS_LABELS = new Set(["permissive", "weak-copyleft", "strong-copyleft", "proprietary"]);

/** Of these, only attest/mirror/overlay-build may ever set hosted_by_us = true. */
export const DIST_LABELS = new Set(["attest", "mirror", "overlay-build", "link", "proxy"]);
export const HOSTED_MODELS = new Set(["attest", "mirror", "overlay-build"]);

/** Only `attest` can carry a reproducible_build record at all (01-architecture.md §4 table). */
export const REPRODUCIBLE_CAPABLE_MODELS = new Set(["attest"]);

export const SECURITY_LABELS = new Set([
  "post-quantum", "attestable", "over-tor", "tee-sealed", "on-device-only",
]);

export const PRIVACY_RANK = { "local-only": 3, "e2e": 2, "metadata-exposed": 1 };

/** Per-model badge when the model's own claim is honored at face value (no attestation upgrade). */
export const BASE_BADGE_LABELS = {
  attest: "NIX-BUILT · UNATTESTED", // upgraded to "ATTESTED" only by a trusted PASS record — see normalize.mjs
  mirror: "MIRRORED · SIGNED",
  "overlay-build": "OVERLAY · SIGNED",
  link: "LINK ONLY",
  proxy: "PROXY ONLY",
};

/** Catalog- and repo-signature trust states. Per-repo, generalized from index.html's single-catalog TRUST enum. */
export const TRUST = Object.freeze({
  CHECKING:     "checking",
  UNSIGNED:     "unsigned",      // no key pinned and/or no .sig present
  VERIFIED:     "verified",      // .sig present AND valid for the pinned key
  TAMPERED:     "tampered",      // .sig present, well-formed, but INVALID for the pinned key
  UNVERIFIABLE: "unverifiable",  // check could not be run at all (no Ed25519 engine, or malformed
                                  // pinned key material) — never conflate with TAMPERED, which
                                  // means the check WAS run and failed
  REVOKED:      "revoked",       // .sig verifies against the pinned key, but the Depot CRL lists
                                  // that key as revoked (depot-crl.mjs) — a stronger rejection
                                  // than TAMPERED: the key itself, not just this one payload, is untrusted
});

/** postern.catalog/v1 is extended in place, never forked (01-architecture.md §1). */
export const SCHEMA_ID = "postern.catalog/v1";

/** signing.state values a version/entry may carry. "failed" per 02-reproducible-builds.md §5 —
 * treated identically to "unpublished" for badge purposes, but preserved for curator visibility. */
export const SIGNING_STATES = new Set(["unpublished", "published", "failed", "upstream", "vendor", "none"]);
