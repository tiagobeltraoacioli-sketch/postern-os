// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Postern Labs and Postern community contributors
//
// Direct, logic-preserving port of normalizeEntry() from
// apps/postern-store/index.html (lines ~235-296 of the page's inline
// script). A-repo-client.md §3.3 is explicit that this exact function is
// what the multi-repo client re-runs "on every entry from every repo,
// identically, regardless of which repo's key signed it" — a repo's Ed25519
// signature proves who asserted a claim, never that the claim is true, and
// this is the ONLY thing that strips a structurally dishonest claim
// (proprietary+hosted, attestable-off-tier, unpublished-but-checksummed).
//
// Vocab tables are copied verbatim from index.html's inline script (same
// dictionaries govern postern.catalog/v1 today and postern.repo/v1 in this
// POC — A-repo-client.md §1.1 says the per-app shape and vocab block are
// reused "verbatim").

export const TIER_LABELS = {
  "attestable-nix": "attestable · Nix-native",
  "pmos-overlay": "pmOS overlay · signed",
  "sloboda-compat": "Sloboda",
  "browser": "browser / web",
};

export const DIST_LABELS = {
  attest: "attested (Nix)",
  mirror: "mirrored (signed)",
  "overlay-build": "overlay build (signed)",
  link: "link only",
  proxy: "proxy only",
};

export const HOSTED_MODELS = new Set(["attest", "mirror", "overlay-build"]);

/**
 * Is this license block a proprietary claim? Case- and type-ROBUST on
 * purpose: the naive `lic.class === "proprietary" || lic.foss === false` is
 * a strict-equality gate on attacker-controlled JSON, and a signed-but-
 * dishonest repo can dodge INVARIANT 1 (proprietary can never be hosted)
 * with a one-character change — `class: "Proprietary"` (wrong case) or
 * `foss: "false"` (the STRING, not the boolean) both make the naive check
 * evaluate false, so none of the "strip hosting/checksum" logic ever runs
 * even though the repo's own data plainly claims proprietary. This
 * normalizes both fields (trim + lowercase the class string; treat the
 * string "false" the same as the boolean false for foss) before comparing.
 */
function isProprietaryClaim(lic) {
  const cls = typeof lic?.class === "string" ? lic.class.trim().toLowerCase() : "";
  const foss = lic?.foss;
  const fossIsFalse = foss === false || (typeof foss === "string" && foss.trim().toLowerCase() === "false");
  return cls === "proprietary" || fossIsFalse;
}

export const SECURITY_LABELS = {
  "post-quantum": "post-quantum",
  attestable: "attestable",
  "over-tor": "over-Tor",
  "tee-sealed": "TEE-sealed",
  "on-device-only": "on-device only",
};

/**
 * The three honesty invariants, unchanged from index.html:
 *   1. proprietary can never be hosted_by_us:true — coerced to `link`.
 *   2. the `attestable` security tag survives only on tier:attestable-nix.
 *   3. signing.state !== "published" => checksum treated as null
 *      ("unpublished"), regardless of what the index claims.
 *
 * Returns the normalized entry AND a `stripped[]` list of exactly which
 * dishonest claims were removed, so the POC's tests can assert on them
 * without re-deriving the diff.
 */
export function normalizeEntry(a) {
  const lic = a.license || {};
  const dist = a.distribution || {};
  const proprietary = isProprietaryClaim(lic);
  const stripped = [];

  // INVARIANT 1: proprietary can only ever be link/proxy, never hosted.
  let model = DIST_LABELS[dist.model] ? dist.model : "link";
  let hostedByUs = !!dist.hosted_by_us;
  let coerced = null;
  if (proprietary && (hostedByUs || !["link", "proxy"].includes(model))) {
    coerced = "proprietary app cannot be hosted — forced to link";
    stripped.push("hosted_by_us:true on proprietary (coerced hosted_by_us=false, model=link)");
    hostedByUs = false;
    if (!["link", "proxy"].includes(model)) model = "link";
  }
  if (hostedByUs && !HOSTED_MODELS.has(model)) hostedByUs = false;

  const tier = TIER_LABELS[a.tier] ? a.tier : "browser";

  // INVARIANT 2: the attestable badge survives only in the Nix-native tier.
  let security = Array.isArray(a.security) ? a.security.filter((s) => SECURITY_LABELS[s]) : [];
  if (tier !== "attestable-nix" && security.includes("attestable")) {
    stripped.push(`attestable claimed on tier:${a.tier} (not attestable-nix) — stripped`);
  }
  if (tier !== "attestable-nix") security = security.filter((s) => s !== "attestable");

  const signing = dist.signing || {};
  const published = signing.state === "published";
  if (!published && dist.checksum) {
    stripped.push(`checksum present but signing.state:${signing.state || "none"} !== "published" — checksum nulled`);
  }

  return {
    entry: {
      id: String(a.id),
      name: a.name,
      publisher: a.publisher || "unknown",
      tier,
      license: {
        class: lic.class || (proprietary ? "proprietary" : "permissive"),
        foss: lic.foss !== false && !proprietary,
      },
      dist: {
        model,
        hostedByUs,
        coerced,
        checksum: published ? dist.checksum || null : null,
        signing: { scheme: signing.scheme || "none", state: signing.state || "none" },
        published,
      },
      security,
    },
    stripped,
  };
}

/** Repo-scoped identity per A-repo-client.md §3.3: "an app id is scoped to
 *  (repo pubkey, id), never flattened to a bare id across repos." */
export function scopedId(repoPubkeyB64, appId) {
  return `${repoPubkeyB64}::${appId}`;
}
