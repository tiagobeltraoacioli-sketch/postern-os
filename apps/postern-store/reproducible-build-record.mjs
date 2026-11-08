// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Postern Labs and Postern community contributors
//
// THE canonical `reproducible_build` attestation record schema, shape
// validator, canonical byte encoding, builder-trust store, and badge-
// decision logic — shared by depot/normalize.mjs and
// repro-verifier/lib/verify-record.mjs so a record produced by either
// producer (depot's test fixtures, repro-verifier's build-record.mjs) is
// parsed and judged IDENTICALLY by either consumer.
//
// WHY THIS FILE EXISTS (Depot red-team finding M4):
// Before this file, `depot/normalize.mjs` and
// `repro-verifier/lib/{build-record,verify-record}.mjs` each independently
// implemented a `reproducible_build` record: depot's was a flat shape
// (`{ result: "PASS", builder_identity: "<string id>", ... }`, matching the
// stale placeholder JSON literally embedded in
// `docs/store-fdroid/01-architecture.md` §1b) while repro-verifier's was a
// nested shape (`{ result: { verdict: "PASS", ... }, builder_identity: {
// id, pubkey_b64 }, ... }`, matching `docs/store-fdroid/
// 02-reproducible-builds.md` §5 — the doc 01-architecture.md's own prose
// says OWNS this record's shape: "Its shape is the interface contract with
// 02-reproducible-builds.md"). A record honestly produced by
// repro-verifier's real signing pipeline could never be recognized by
// depot's parser (`record.result !== "PASS"` because `result` was an
// object, not a string; `typeof record.builder_identity === "string"` was
// false because it was an object) — an honest PASS would silently render as
// unattested, and — more dangerously — nothing stopped a THIRD, ad hoc
// shape from sneaking past either check, since neither side positively
// validated the record's full shape before reading individual fields off
// it. This file is the fix: ONE schema, ONE strict validator that rejects
// anything else, ONE canonicalization, ONE builder-trust store shape, ONE
// badge-decision algorithm. depot and repro-verifier each keep their own
// Ed25519 primitive (depot: enterprise/licensing via crypto-bridge.mjs,
// async, browser-buildable; repro-verifier: node:crypto directly, sync,
// deliberately dependency-free of any sibling POC per its own header) and
// inject it into `decideBadge()` below rather than this file picking one.
//
// Nothing here weakens any prior check: signature verification, CRL
// revocation, and builder-trust pinning are preserved with the SAME
// semantics repro-verifier's already-audited implementation used (see
// repro-verifier/test/record.test.mjs, unchanged by this fix). This file
// ADDS one previously-absent check the task callout named explicitly:
// `app_id`/`version` BINDING — until now nothing verified that a
// `reproducible_build` record embedded in one app's `versions[]` entry
// actually claims to be ABOUT that app id and that version; a genuine,
// validly-signed, trusted-builder record for app A version 1.0 could be
// silently replayed onto app B's (or app A's OTHER version's) entry and
// still earn ATTESTED. `decideBadge()`'s `expectedAppId`/`expectedVersion`
// parameters close that gap.

/** Self-declared schema id every canonical record must carry — makes a
 *  foreign/legacy shape (e.g. depot's old flat `postern.depot.attestation/v1`)
 *  mechanically rejectable by a single field check, not fragile duck-typing. */
export const REPRODUCIBLE_BUILD_SCHEMA = "postern.depot.reproducible-build/v1";

export const VERDICTS = Object.freeze(["PASS", "FAIL_NONDETERMINISM", "FAIL_DIVERGENCE"]);

export const BADGE = Object.freeze({
  ATTESTED: "ATTESTED",
  STRIPPED: "STRIPPED",
});

function isNonEmptyString(v) {
  return typeof v === "string" && v.length > 0;
}
function isStringOrNull(v) {
  return v === null || typeof v === "string";
}
function isPlainObject(v) {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

/**
 * Strictly validate a `reproducible_build` record against the ONE canonical
 * shape (docs/store-fdroid/02-reproducible-builds.md §5, extended with the
 * `builder_identity`/richer `signature` fields the red-team #2 fix added).
 * Returns `{ ok: true }` or `{ ok: false, reason }` — NEVER throws, and
 * never partially trusts a record that fails any single field check. A
 * record in the old flat depot shape, or any other foreign shape, is
 * rejected here with a specific reason rather than silently misread.
 *
 * @param {unknown} record
 * @returns {{ok: true} | {ok: false, reason: string}}
 */
export function validateRecordShape(record) {
  if (!isPlainObject(record)) {
    return { ok: false, reason: "reproducible_build record is missing or not an object" };
  }
  if (record.schema !== REPRODUCIBLE_BUILD_SCHEMA) {
    return {
      ok: false,
      reason: `reproducible_build record has schema "${record.schema ?? "(missing)"}", expected "${REPRODUCIBLE_BUILD_SCHEMA}" — foreign or legacy shape, not parsed`,
    };
  }
  if (!isNonEmptyString(record.app_id)) return { ok: false, reason: "record.app_id must be a non-empty string" };
  if (!isNonEmptyString(record.version)) return { ok: false, reason: "record.version must be a non-empty string" };

  const source = record.source;
  if (!isPlainObject(source)) return { ok: false, reason: "record.source must be an object" };
  for (const f of ["repo_url", "commit", "build_expr", "build_expr_source", "flake_lock_rev"]) {
    if (!isNonEmptyString(source[f])) return { ok: false, reason: `record.source.${f} must be a non-empty string` };
  }
  if (source.build_expr_source !== "nixpkgs" && source.build_expr_source !== "first-party") {
    return { ok: false, reason: `record.source.build_expr_source must be "nixpkgs" or "first-party", got "${source.build_expr_source}"` };
  }

  const buildEnv = record.build_env;
  if (!isPlainObject(buildEnv)) return { ok: false, reason: "record.build_env must be an object" };
  for (const f of ["nix_version", "system", "sandbox"]) {
    if (!isNonEmptyString(buildEnv[f])) return { ok: false, reason: `record.build_env.${f} must be a non-empty string` };
  }
  if (!Array.isArray(buildEnv.builder_hosts) || buildEnv.builder_hosts.length === 0 || !buildEnv.builder_hosts.every(isNonEmptyString)) {
    return { ok: false, reason: "record.build_env.builder_hosts must be a non-empty array of strings" };
  }

  const output = record.output;
  if (!isPlainObject(output)) return { ok: false, reason: "record.output must be an object" };
  for (const f of ["store_path", "nar_hash", "shipped_artifact_hash"]) {
    if (!isNonEmptyString(output[f])) return { ok: false, reason: `record.output.${f} must be a non-empty string` };
  }

  const result = record.result;
  if (!isPlainObject(result)) return { ok: false, reason: "record.result must be an object (not a bare string — that is the legacy shape)" };
  if (typeof result.rebuild_match !== "boolean") return { ok: false, reason: "record.result.rebuild_match must be a boolean" };
  if (result.shipped_match !== null && typeof result.shipped_match !== "boolean") {
    return { ok: false, reason: "record.result.shipped_match must be a boolean or null" };
  }
  if (!VERDICTS.includes(result.verdict)) {
    return { ok: false, reason: `record.result.verdict must be one of ${VERDICTS.join("/")}, got "${result.verdict}"` };
  }
  if (!isStringOrNull(result.diagnostic)) return { ok: false, reason: "record.result.diagnostic must be a string or null" };

  const run = record.run;
  if (!isPlainObject(run)) return { ok: false, reason: "record.run must be an object" };
  for (const f of ["timestamp", "run_by", "verifier_version"]) {
    if (!isNonEmptyString(run[f])) return { ok: false, reason: `record.run.${f} must be a non-empty string` };
  }

  const builderIdentity = record.builder_identity;
  if (!isPlainObject(builderIdentity)) {
    return { ok: false, reason: "record.builder_identity must be an object { id, pubkey_b64 } (not a bare string — that is the legacy shape)" };
  }
  if (!isNonEmptyString(builderIdentity.id)) return { ok: false, reason: "record.builder_identity.id must be a non-empty string" };
  if (!isNonEmptyString(builderIdentity.pubkey_b64)) return { ok: false, reason: "record.builder_identity.pubkey_b64 must be a non-empty string" };

  const signature = record.signature;
  if (!isPlainObject(signature)) return { ok: false, reason: "record.signature must be an object" };
  if (!isNonEmptyString(signature.scheme)) return { ok: false, reason: "record.signature.scheme must be a non-empty string" };
  if (!isNonEmptyString(signature.signature_b64)) return { ok: false, reason: "record.signature.signature_b64 must be a non-empty string" };
  if (signature.signed_bytes_sha256 !== undefined && !isStringOrNull(signature.signed_bytes_sha256)) {
    return { ok: false, reason: "record.signature.signed_bytes_sha256 must be a string or null when present" };
  }
  if (signature.chain_anchor !== undefined && !isStringOrNull(signature.chain_anchor)) {
    return { ok: false, reason: "record.signature.chain_anchor must be a string or null when present" };
  }

  return { ok: true };
}

/**
 * Canonical byte encoding for a `reproducible_build` record: deterministic
 * sorted-key JSON of every field EXCEPT `signature` (a signature cannot
 * cover its own bytes). Both producers (depot/test/fixtures.mjs,
 * repro-verifier/lib/build-record.mjs signRecord()) and both consumers
 * (depot/normalize.mjs, repro-verifier/lib/verify-record.mjs) MUST call this
 * exact function or signatures will not round-trip.
 */
export function canonicalRecordBytes(record) {
  const { signature, ...rest } = record ?? {};
  const canonical = JSON.stringify(sortDeep(rest));
  return new Uint8Array(Buffer.from(canonical, "utf8"));
}

function sortDeep(value) {
  if (Array.isArray(value)) return value.map(sortDeep);
  if (value && typeof value === "object") {
    const out = {};
    for (const key of Object.keys(value).sort()) {
      if (value[key] === undefined) continue;
      out[key] = sortDeep(value[key]);
    }
    return out;
  }
  return value;
}

/** @typedef {{ id: string, pubkey_b64: string }} BuilderIdentity */

/**
 * Build a trust store from a plain array of pinned builder entries.
 * @param {Array<{id: string, pubkey_b64: string, label?: string}>} entries
 * @returns {Map<string, {pubkey_b64: string, label: string}>}
 */
export function makeTrustStore(entries) {
  const map = new Map();
  for (const e of entries ?? []) {
    if (!e?.id || !e?.pubkey_b64) continue;
    map.set(e.id, { pubkey_b64: e.pubkey_b64, label: e.label ?? e.id });
  }
  return map;
}

/**
 * @param {Map<string, {pubkey_b64: string}>} trustStore
 * @param {BuilderIdentity} builderIdentity
 * @returns {boolean}
 */
export function isTrustedBuilder(trustStore, builderIdentity) {
  if (!trustStore || !builderIdentity) return false;
  const { id, pubkey_b64 } = builderIdentity;
  if (!id || !pubkey_b64) return false;
  const pinned = trustStore.get(id);
  if (!pinned) return false; // unknown builder id -> untrusted, full stop
  // Pin match, not id match: a forged record cannot borrow a trusted id and
  // swap in a different key.
  return pinned.pubkey_b64 === pubkey_b64;
}

/**
 * THE unified badge decision. Order of checks (preserved from
 * repro-verifier's already-audited implementation, repro-verifier/test/
 * record.test.mjs, which this file must keep passing verbatim):
 *   0. shape must validate against the ONE canonical schema.
 *   0b. (NEW, app_id/version binding) if the caller knows which app/version
 *       this record is being read FOR, the record must claim to be about
 *       exactly that app_id/version — otherwise a validly-signed,
 *       trusted-builder record for a DIFFERENT app/version could be
 *       replayed here and still earn ATTESTED.
 *   1. the record's signature must verify against the KEY EMBEDDED IN THE
 *      RECORD ITSELF (`builder_identity.pubkey_b64`) — self-consistency,
 *      never trust.
 *   2. that embedded (id, pubkey_b64) pair must EXACTLY match what the
 *      caller's trust store pins for that id — trust, never self-assertion.
 *   3. the builder's pinned key must not be on the CRL, if one is supplied.
 *   4. `result.verdict` must be exactly "PASS".
 *
 * `verifySignature(pubkeyB64, bytes, signatureB64) -> boolean` is injected
 * so this file never picks (or depends on) either package's Ed25519
 * primitive — callers must invoke it SYNCHRONOUSLY (repro-verifier can call
 * this function directly; depot, whose crypto-bridge.mjs is async, resolves
 * the signature check itself first and passes a synchronous closure over
 * the already-known boolean — see depot/normalize.mjs).
 *
 * @param {object} opts
 * @param {object} opts.record
 * @param {Map} opts.trustStore
 * @param {(pubkeyB64: string, bytes: Uint8Array, signatureB64: string) => boolean} opts.verifySignature
 * @param {object|null} [opts.crl]
 * @param {(crl: object|null, pubkeyB64: string) => boolean} [opts.isRevoked]
 * @param {string|null} [opts.expectedAppId] - if given, record.app_id must equal this
 * @param {string|null} [opts.expectedVersion] - if given, record.version must equal this
 */
export function decideBadge({
  record,
  trustStore,
  verifySignature,
  crl = null,
  isRevoked = null,
  expectedAppId = null,
  expectedVersion = null,
}) {
  const shape = validateRecordShape(record);
  if (!shape.ok) {
    return {
      shapeValid: false, signatureValid: false, builderTrusted: false, revoked: false,
      bindingValid: null, verdict: null, badge: BADGE.STRIPPED, reason: shape.reason,
    };
  }

  const verdict = record.result.verdict;
  const base = {
    shapeValid: true, signatureValid: false, builderTrusted: false, revoked: false,
    bindingValid: null, verdict, badge: BADGE.STRIPPED, reason: "",
  };

  if (expectedAppId != null || expectedVersion != null) {
    if (expectedAppId != null && record.app_id !== expectedAppId) {
      return {
        ...base, bindingValid: false,
        reason: `record.app_id "${record.app_id}" does not match this catalog entry's id "${expectedAppId}" — a record must be bound to the app it is attesting, badge stripped`,
      };
    }
    if (expectedVersion != null && record.version !== expectedVersion) {
      return {
        ...base, bindingValid: false,
        reason: `record.version "${record.version}" does not match this version entry's version "${expectedVersion}" — a record must be bound to the version it is attesting, badge stripped`,
      };
    }
    base.bindingValid = true;
  }

  const bytes = canonicalRecordBytes(record);
  let signatureValid = false;
  try {
    signatureValid = !!verifySignature(record.builder_identity.pubkey_b64, bytes, record.signature.signature_b64);
  } catch {
    signatureValid = false;
  }
  if (!signatureValid) {
    return {
      ...base,
      reason: "signature over the record's canonical bytes does NOT verify against the claimed builder_identity key — forged or corrupted, badge stripped",
    };
  }
  base.signatureValid = true;

  const builderTrusted = isTrustedBuilder(trustStore, record.builder_identity);
  if (!builderTrusted) {
    return {
      ...base,
      reason: `record signature is internally valid, but builder_identity "${record.builder_identity.id}" is NOT a client-pinned trusted builder — a self-consistent signature is not trust (red-team #2 fix); badge stripped`,
    };
  }
  base.builderTrusted = true;

  if (isRevoked && isRevoked(crl, record.builder_identity.pubkey_b64)) {
    return {
      ...base, revoked: true,
      reason: `builder_identity "${record.builder_identity.id}"'s pinned key is on the CRL — revoked, never honored regardless of signature validity`,
    };
  }

  if (verdict !== "PASS") {
    return {
      ...base,
      reason: `builder is trusted and signature is valid, but verdict is ${verdict} — only a PASS verdict unlocks ATTESTED (02-reproducible-builds.md §1d/§2)`,
    };
  }

  return {
    ...base, badge: BADGE.ATTESTED,
    reason: "signature valid, builder_identity is pinned-trusted, verdict PASS — ATTESTED honored",
  };
}

/**
 * Full client-side badge decision: the catalog's `tier` claim (necessary but
 * never sufficient) PLUS the independently verified build record.
 * @param {{tier: string} & Parameters<typeof decideBadge>[0]} opts
 */
export function decideAttestedBadge({ tier, ...rest }) {
  if (tier !== "attestable-nix") {
    return {
      badge: BADGE.STRIPPED,
      reason: `tier is "${tier}", not attestable-nix — ATTESTED is never eligible regardless of any record (CURATION.md invariant 2)`,
    };
  }
  const rec = decideBadge(rest);
  return { badge: rec.badge, reason: rec.reason, detail: rec };
}
