// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Postern Labs and Postern community contributors
//
// Depot's honesty spine — a generalization of apps/postern-store/index.html's
// normalizeEntry() to (a) run per-repo, not just for one embedded first-party
// catalog, and (b) run per-VERSION too (red-team finding #3: `versions[]` was
// unvalidated — a repo could put a lie in a version entry that never went
// through the top-level checks). Every invariant index.html already enforces
// is reproduced here unchanged; nothing is loosened for third-party repos —
// see 01-architecture.md §3: "The honesty-spine normalization runs
// IDENTICALLY on every repo's entries, first-party or third-party."
//
// NEW invariant this file adds (red-team finding #2, the critical one):
// the `attestable` badge is no longer earned by `tier === "attestable-nix"`
// alone. It additionally requires a `reproducible_build` record whose
// PASS verdict is independently signed by a builder identity the CLIENT
// pins as trusted — never just because the JSON says so. See
// verifyReproducibleBuildRecord() and reproducible-build-record.mjs.
//
// Depot M4 fix: this file used to define its OWN `reproducible_build` record
// shape (flat: `result` a bare string, `builder_identity` a bare string) —
// a faithful port of the stale placeholder JSON literally embedded in
// docs/store-fdroid/01-architecture.md §1b. repro-verifier/lib/{build-record,
// verify-record}.mjs meanwhile implemented a DIFFERENT, nested shape
// matching docs/store-fdroid/02-reproducible-builds.md §5 — the doc
// 01-architecture.md's own prose says actually OWNS this record's shape
// ("Its shape is the interface contract with 02-reproducible-builds.md").
// A record honestly produced by repro-verifier's real signing pipeline could
// never be recognized here (`record.result !== "PASS"` because `result` was
// an object; `typeof record.builder_identity === "string"` was false
// because it was an object) — the two schemas could silently drift, and a
// record valid under one was simply mis-parsed by the other. This file now
// delegates entirely to the ONE canonical schema + validator + decision
// algorithm in apps/postern-store/reproducible-build-record.mjs (see that
// file's header for the full account), supplying only depot's own async
// Ed25519 primitive (crypto-bridge.mjs, built on enterprise/licensing).
//
// ADVERSARIAL-REVIEW FIX (case-/type-robust proprietary detection): the
// proprietary check that gates INVARIANT 1 ("proprietary can never be
// hosted") used to be a strict `===` on attacker-controlled JSON —
// `license.class: "Proprietary"` (wrong case) or `foss: "false"` (a string,
// not a boolean) both dodged it entirely, keeping `hosted_by_us:true` and a
// surfaced checksum. See isProprietaryClaim() below — normalized (trim +
// lowercase, string "false" treated as false) before comparing.

import { CATEGORIES, SOURCE_LABELS, TIER_LABELS, LICENSE_CLASS_LABELS, DIST_LABELS,
  HOSTED_MODELS, REPRODUCIBLE_CAPABLE_MODELS, SECURITY_LABELS, PRIVACY_RANK,
  BASE_BADGE_LABELS, SIGNING_STATES } from "./schema.mjs";
import { ed25519Verify } from "./crypto-bridge.mjs";
import { isBuilderKeyRevoked } from "./depot-crl.mjs";
import { decideBadge, canonicalRecordBytes, BADGE } from "../reproducible-build-record.mjs";

/**
 * Is this license block a proprietary claim? Case- and type-ROBUST on
 * purpose (adversarial-review fix): the naive `lic.class === "proprietary"
 * || lic.foss === false` is a strict-equality gate on attacker-controlled
 * JSON, and a signed-but-dishonest repo can dodge INVARIANT 1 (proprietary
 * can never be hosted) with a one-character change — `class: "Proprietary"`
 * (wrong case) or `foss: "false"` (the STRING, not the boolean) both make
 * the naive check evaluate false, so none of the "strip hosting/checksum"
 * logic ever runs even though the repo's own data plainly claims
 * proprietary. This normalizes both fields (trim + lowercase the class
 * string; treat the string "false" the same as the boolean false for foss)
 * before comparing, so those dodges land on the SAME conservative branch a
 * lowercase `class:"proprietary"`/boolean `foss:false` would.
 */
function isProprietaryClaim(lic) {
  const cls = typeof lic?.class === "string" ? lic.class.trim().toLowerCase() : "";
  const foss = lic?.foss;
  const fossIsFalse = foss === false || (typeof foss === "string" && foss.trim().toLowerCase() === "false");
  return cls === "proprietary" || fossIsFalse;
}

/**
 * Verify a reproducible_build attestation record's OWN independent signature
 * against a pinned set of trusted builder identities, using the ONE
 * canonical record schema (reproducible-build-record.mjs) both depot and
 * repro-verifier now share.
 *
 * This is the fix for red-team finding #2: today a repo could forge
 * `reproducible_build: { result: { verdict: "PASS" } }` signed only by its
 * own index key (or not signed at all) and the client had no way to tell
 * that apart from a real attestation. This function refuses to trust a
 * record unless:
 *   0. the record's SHAPE matches the one canonical schema exactly — a
 *      foreign/legacy shape is rejected outright, not partially read
 *      (Depot M4 fix),
 *   0b. (if `expectedAppId`/`expectedVersion` are given) the record's own
 *      `app_id`/`version` fields match the catalog entry/version it is
 *      being read for — a genuine, trusted, PASS record cannot be replayed
 *      onto a DIFFERENT app or version,
 *   1. result.verdict === "PASS" (no ambiguous middle state, per 02-reproducible-builds.md §5),
 *   2. builder_identity is a key the CLIENT itself pinned (trustedBuilders),
 *      not merely a string the record asserts about itself,
 *   3. the builder's pinned key is not on the Depot CRL,
 *   4. the record carries a signature over its OWN canonical bytes (minus the
 *      signature field itself — can't sign over bytes containing itself)
 *      that verifies against the key EMBEDDED in the record's own
 *      `builder_identity.pubkey_b64` — which step 2 has already confirmed is
 *      EXACTLY the client's pinned key for that builder id, never a
 *      self-vouching key the record supplies with no matching pin.
 *
 * @param {object|null|undefined} record - the versions[].reproducible_build value
 * @param {Map<string,{pubkey_b64: string, label: string}>} trustedBuilders - builder_identity.id -> pinned trust entry (reproducible-build-record.mjs's makeTrustStore() shape)
 * @param {object|null} [crl] - a verified Depot CRL (depot-crl.mjs); a builder key on it is never honored even if pinned
 * @param {string|null} [expectedAppId] - the catalog entry id this record must claim to be about
 * @param {string|null} [expectedVersion] - the version_name this record must claim to be about
 * @returns {Promise<{trusted: boolean, reason: string, detail: object}>}
 */
export async function verifyReproducibleBuildRecord(record, trustedBuilders, crl = null, expectedAppId = null, expectedVersion = null) {
  if (!record || typeof record !== "object") {
    return { trusted: false, reason: "no reproducible_build record present", detail: null };
  }
  // Resolve signature validity ourselves (depot's Ed25519 primitive is
  // async; the shared decision core takes a synchronous callback), then let
  // the shared, canonical decision algorithm do everything else identically
  // to how repro-verifier decides it.
  let signatureOk = false;
  if (record && typeof record === "object" && record.builder_identity && typeof record.builder_identity === "object" && record.signature && typeof record.signature.signature_b64 === "string") {
    try {
      const bytes = canonicalRecordBytes(record);
      signatureOk = await ed25519Verify(record.builder_identity.pubkey_b64, bytes, record.signature.signature_b64);
    } catch {
      signatureOk = false;
    }
  }
  const decision = decideBadge({
    record,
    trustStore: trustedBuilders,
    verifySignature: () => signatureOk,
    crl,
    isRevoked: isBuilderKeyRevoked,
    expectedAppId,
    expectedVersion,
  });
  return { trusted: decision.badge === BADGE.ATTESTED, reason: decision.reason, detail: decision };
}

/**
 * Normalize one versions[] entry. Applies the SAME per-field honesty
 * invariants normalizeEntry applies at the top level (proprietary ⇒ no
 * artifact/checksum, signing.state !== "published" ⇒ no checksum), plus the
 * reproducible_build trust check above. `ctx.proprietary` and `ctx.model`
 * come from the ALREADY-normalized top-level entry so a version can't grant
 * itself a laxer rule than its own app entry has.
 *
 * @returns {Promise<object>} normalized version record
 */
export async function normalizeVersion(v, ctx) {
  const { proprietary, model, tier, trustedBuilders, crl = null, appId = null } = ctx;
  const src = v.source || {};
  const build = v.build || {};
  const artifactIn = v.artifact || {};
  const signingIn = v.signing || {};
  const published = signingIn.state === "published";
  const versionName = String(v.version_name || v.version || "unknown");

  // INVARIANT (per-version, mirrors top-level INVARIANT 1): a proprietary
  // app's version history may never carry a downloadable/checksummed artifact.
  let sha256 = published ? (artifactIn.sha256 || null) : null;
  let urls = Array.isArray(artifactIn.urls) ? artifactIn.urls.slice() : [];
  let coerced = null;
  if (proprietary && (urls.length > 0 || sha256)) {
    coerced = "proprietary app: version artifact/checksum stripped";
    urls = [];
    sha256 = null;
  }

  // reproducible_build is only even meaningful for the attest model
  // (01-architecture.md §4 — mirror/overlay-build are structurally
  // non-reproducible; link/proxy hold no artifact of ours to attest).
  let attestation = null;
  if (REPRODUCIBLE_CAPABLE_MODELS.has(model) && v.reproducible_build) {
    const check = await verifyReproducibleBuildRecord(v.reproducible_build, trustedBuilders, crl, appId, versionName);
    attestation = {
      present: true,
      trusted: check.trusted,
      reason: check.reason,
      // Keep the raw claimed fields for display, but NEVER let a UI treat
      // `claimedResult` as equivalent to `trusted` — that conflation is
      // exactly finding #2.
      claimedResult: v.reproducible_build.result ?? null,
      claimedBuilderIdentity: v.reproducible_build.builder_identity ?? null,
    };
  } else if (v.reproducible_build) {
    // A record exists on a model that structurally can't carry one (e.g. a
    // repo put reproducible_build on a `mirror` entry). Never honored,
    // regardless of what it claims.
    attestation = { present: true, trusted: false, reason: `model "${model}" cannot carry a reproducible_build record`, claimedResult: v.reproducible_build.result ?? null, claimedBuilderIdentity: v.reproducible_build.builder_identity ?? null };
  }

  const earnedAttestedBadge = tier === "attestable-nix" && model === "attest" && !!attestation?.trusted;

  return {
    version_name: versionName,
    version_code: Number.isFinite(v.version_code) ? v.version_code : null,
    released: v.released || "",
    source: {
      repo_url: src.repo_url || "",
      commit: src.commit || "",
      tag: src.tag || "",
    },
    build: {
      builder: build.builder || "",
      toolchain: build.toolchain || "",
      started: build.started || "",
      finished: build.finished || "",
    },
    artifact: {
      filename: artifactIn.filename || "",
      urls,
      size_bytes: Number.isFinite(artifactIn.size_bytes) ? artifactIn.size_bytes : null,
      sha256,
    },
    signing: {
      scheme: signingIn.scheme || "none",
      state: SIGNING_STATES.has(signingIn.state) ? signingIn.state : "none",
      signature: published ? (signingIn.signature ?? null) : null,
    },
    published,
    coerced,
    attestation,
    earnedAttestedBadge,
  };
}

/**
 * Normalize one apps[] entry from a repo's index — a straight generalization
 * of index.html's normalizeEntry, extended to (a) accept a repo context
 * (repoId/repoLabel, for id-collision display — never merges), (b) walk
 * versions[] through normalizeVersion with the SAME invariants, and (c) gate
 * the ATTESTED badge behind a trusted reproducible_build record, not tier alone.
 *
 * @param {object} a - raw catalog app entry
 * @param {{repoId: string, repoLabel: string, repoPriority: number, trustedBuilders: Map<string,{pubkey_b64: string, label: string}>}} ctx
 * @returns {Promise<object>} normalized entry
 */
export async function normalizeEntry(a, ctx) {
  const lic = a.license || {};
  const dist = a.distribution || {};
  const proprietary = isProprietaryClaim(lic);

  /* INVARIANT 1 (unchanged from index.html): proprietary can only ever be link/proxy, never hosted. */
  let model = DIST_LABELS.has(dist.model) ? dist.model : "link";
  let hostedByUs = !!dist.hosted_by_us;
  let coerced = null;
  if (proprietary && (hostedByUs || !["link", "proxy"].includes(model))) {
    coerced = "proprietary app cannot be hosted — forced to link";
    hostedByUs = false;
    if (!["link", "proxy"].includes(model)) model = "link";
  }
  if (hostedByUs && !HOSTED_MODELS.has(model)) hostedByUs = false;

  const tier = TIER_LABELS.has(a.tier) ? a.tier : "browser";

  /* Normalize versions[] FIRST (per-version invariants), so the top-level
     attestation gate below can honestly reflect whether ANY version earned it. */
  const rawVersions = Array.isArray(a.versions) ? a.versions : [];
  const versions = [];
  for (const v of rawVersions) {
    if (!v || typeof v !== "object") continue;
    versions.push(await normalizeVersion(v, { proprietary, model, tier, trustedBuilders: ctx.trustedBuilders, crl: ctx.crl ?? null, appId: String(a.id) }));
  }
  // Backward compatibility (01-architecture.md §1b): no versions[] at all is
  // read as a single implicit version built from today's flat `distribution{}`
  // block — this is what makes today's catalog.json (zero versions[]) still
  // valid under the extended schema without migration.
  const anyVersionEarnedAttested = versions.some(v => v.earnedAttestedBadge);

  /* INVARIANT 2 (STRENGTHENED — red-team fix #2): the attestable badge/tag
     survives only for tier attestable-nix AND (if versions[] is present) at
     least one version whose reproducible_build record is independently
     signed by a PINNED, trusted builder. A bare tier string, or a
     self-vouching/unsigned/untrusted-builder PASS claim, is stripped —
     exactly the same posture as index.html stripping the tag for the wrong tier. */
  let security = Array.isArray(a.security) ? a.security.filter(s => SECURITY_LABELS.has(s)) : [];
  const tierEligible = tier === "attestable-nix";
  const attestedEarned = tierEligible && (versions.length === 0 ? false : anyVersionEarnedAttested);
  if (!attestedEarned) security = security.filter(s => s !== "attestable");

  const signing = dist.signing || {};
  const published = signing.state === "published";

  const badge = model === "attest"
    ? (attestedEarned ? "ATTESTED" : BASE_BADGE_LABELS.attest)
    : (BASE_BADGE_LABELS[model] || "LINK ONLY");

  return {
    id: String(a.id), name: String(a.name), glyph: a.glyph || "·",
    publisher: a.publisher || "unknown",
    category: CATEGORIES.has(a.category) ? a.category : "developer",
    platform: ["mobile", "desktop", "both"].includes(a.platform) ? a.platform : "both",
    source: SOURCE_LABELS.has(a.source) ? a.source : "web",
    tier,
    oneliner: a.oneliner || "",
    license: {
      spdx: lic.spdx || "unknown",
      class: LICENSE_CLASS_LABELS.has(lic.class) ? lic.class : (proprietary ? "proprietary" : "permissive"),
      foss: lic.foss !== false && !proprietary,
      redistribute: proprietary ? false : lic.redistribute !== false,
      rebrand: proprietary ? false : !!lic.rebrand,
      trademark: !!lic.trademark,
      note: lic.note || "",
    },
    dist: {
      model, hostedByUs, coerced,
      upstream: dist.upstream || "",
      artifact: hostedByUs ? (dist.artifact || "") : "",
      checksum: published ? (dist.checksum || null) : null,
      signing: { scheme: signing.scheme || "none", state: SIGNING_STATES.has(signing.state) ? signing.state : "none", key_id: signing.key_id || "" },
      published,
      verify: dist.verify || "",
    },
    privacy: {
      level: PRIVACY_RANK[a.privacy?.level] ? a.privacy.level : "metadata-exposed",
      stays: a.privacy?.stays || "", leaves: a.privacy?.leaves || "",
    },
    security,
    capabilities: Array.isArray(a.capabilities) ? a.capabilities : [],
    tags: Array.isArray(a.tags) ? a.tags : [],
    limits: a.limits || "",
    versions,
    attestedEarned,
    badge,
    // Provenance — WHICH repo is vouching for this listing. Never collapsed
    // away (01-architecture.md §3: "A card never claims a badge without also
    // showing which repo is vouching for it").
    repo: { id: ctx.repoId, label: ctx.repoLabel, priority: ctx.repoPriority },
  };
}
