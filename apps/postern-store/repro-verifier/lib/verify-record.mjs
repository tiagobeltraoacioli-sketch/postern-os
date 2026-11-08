// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Postern Labs and Postern community contributors
//
// Verifies a `reproducible_build` record and decides whether the ATTESTED
// badge (CURATION.md's "attestable" security tag /
// 02-reproducible-builds.md §2's verdict->badge table) may be honored.
//
// The record-shape validation, canonicalization, trust-store, and
// per-record badge-decision ALGORITHM now live in
// apps/postern-store/reproducible-build-record.mjs (Depot M4 fix — this
// package's `reproducible_build` schema and depot/normalize.mjs's had
// drifted into two incompatible shapes; see that file's header). This
// module is a thin, SYNCHRONOUS adapter over that shared core: it supplies
// this package's own Ed25519 primitive (`ed25519VerifyRaw`, node:crypto,
// deliberately dependency-free of any sibling POC — see lib/keys.mjs's
// header), keeps this package's historical `appId`/`version` parameter
// names (the shared core calls them `expectedAppId`/`expectedVersion`) so
// every existing caller (record.test.mjs, scripts/verify-record-cli.mjs,
// scripts/two-builder-check.mjs) keeps working unmodified, and layers Depot
// finding H1's TWO-BUILDER QUORUM on top: `decideAttestedBadge()` takes
// `records` (plural, not `record`) and only honors ATTESTED once at least
// `quorum` (default 2) of them independently pass every per-record check AND
// resolve to pairwise DISTINCT pinned builder keys — see
// verifyTwoBuilderQuorum() below. A single record, however valid, can never
// alone earn the client-facing ATTESTED badge.
//
// This is where the red-team #2 fix actually bites at decision time: the
// naive/vulnerable rule was "tier === attestable-nix AND the record SAYS
// PASS" — both trivially satisfiable by a dishonest repo operator writing
// arbitrary JSON. The fixed rule requires ALL of:
//   1. the record's shape matches the ONE canonical schema exactly (a
//      foreign/legacy shape is rejected outright, never partially read),
//   2. the record carries a signature that verifies over its own canonical
//      bytes (build-record.mjs / canonical.mjs),
//   3. the signature's `builder_identity` is a CLIENT-PINNED trusted builder
//      (builder-trust.mjs) — never "whatever the record itself claims",
//   4. (if `appId`/`version` are given) the record's own `app_id`/`version`
//      match the catalog entry this decision is FOR — a validly-signed,
//      trusted, PASS record for a DIFFERENT app/version is a replay, not
//      proof (adversarial-review fix),
//   5. the record's own `result.verdict` is exactly "PASS" (nondeterminism
//      and divergence FAILs never earn the badge even from a trusted,
//      correctly-signed builder — see §1d),
//   6. (DEPOT FINDING H1) at least `quorum` of the supplied records passing
//      1-5 resolve to PAIRWISE DISTINCT pinned builder keys — a single
//      builder (host, operator, or key) is one party's word; 02-reproducible-
//      builds.md §1b step 2 requires the rebuild to happen on at least two
//      independent build hosts precisely because one signer, however
//      trusted and however honest its signature, is not "two independent
//      builds agreed". Two records that both resolve to the SAME pinned
//      signer (whether literally duplicated or freshly re-signed) collapse
//      to one distinct key and never reach quorum,
//   7. the catalog's own `tier` is `attestable-nix` (necessary but never
//      sufficient — §2's existing rule, unchanged, checked independently of
//      any record so a record can never upgrade an ineligible tier).
// Never throws — a missing/malformed record is a STRIPPED decision, not an
// exception, matching repo-poc's verify.mjs "never throws, degrades
// honestly" rule.

import { ed25519VerifyRaw } from "./keys.mjs";
import { decideBadge, BADGE } from "../../reproducible-build-record.mjs";

export { BADGE };

/** Adapts this package's sync, Buffer-based Ed25519 verifier to the shared
 *  core's `(pubkeyB64, bytes, signatureB64) -> boolean` sync interface. */
function verifySignature(pubkeyB64, bytes, signatureB64) {
  let sigBytes;
  try {
    sigBytes = Buffer.from(signatureB64, "base64");
  } catch {
    return false;
  }
  return ed25519VerifyRaw(pubkeyB64, bytes, sigBytes);
}

/**
 * Verify ONE record's signature + builder trust + (optional) app/version
 * binding + verdict, independent of any catalog tier claim or two-builder
 * quorum. This is the per-record check; verifyTwoBuilderQuorum() /
 * decideAttestedBadge() below layer quorum + the tier gate on top.
 *
 * @param {{record: object, trustStore: Map, crl?: object|null, isRevoked?: Function|null, appId?: string|null, version?: string|null}} opts
 *   `appId`/`version` are the identity of the catalog entry this record is being evaluated FOR; when supplied, the
 *   record's own `app_id`/`version` fields must match exactly, or the record is rejected as a replay regardless of
 *   signature/trust validity (adversarial-review fix).
 */
export function verifyBuildRecord({ record, trustStore, crl = null, isRevoked = null, appId = null, version = null }) {
  return decideBadge({ record, trustStore, verifySignature, crl, isRevoked, expectedAppId: appId, expectedVersion: version });
}

/**
 * THE TWO-BUILDER QUORUM CHECK (Depot finding H1 fix). Runs
 * verifyBuildRecord() on every supplied record independently, then requires
 * at least `quorum` (default 2) of them to (a) individually earn ATTESTED on
 * their own merits (valid shape, valid signature, pinned-trusted builder,
 * correct app/version binding, not revoked, PASS verdict) AND (b) resolve to
 * PAIRWISE DISTINCT pinned builder keys. Distinctness is checked on the
 * trust store's PINNED `pubkey_b64` for each record's `builder_identity.id`
 * — not the claimed id string and not the key the record itself carries —
 * so two records that reuse the same trusted id (impossible to fake past
 * isTrustedBuilder's pin check) or that are simply the same record submitted
 * twice both collapse to exactly one distinct signer, never two.
 *
 * Never throws; degrades to `{ ok: false }`-shaped output on bad input, same
 * discipline as verifyBuildRecord().
 *
 * @param {{records: object[], trustStore: Map, crl?: object|null, isRevoked?: Function|null, appId?: string|null, version?: string|null, quorum?: number}} opts
 * @returns {{ok: boolean, reason: string, distinctBuilderCount: number, qualifyingCount: number, perRecord: Array<{record: object, verdict: object}>}}
 */
export function verifyTwoBuilderQuorum({ records, trustStore, crl = null, isRevoked = null, appId = null, version = null, quorum = 2 }) {
  const list = Array.isArray(records) ? records : [];

  const perRecord = list.map((record) => ({ record, verdict: verifyBuildRecord({ record, trustStore, crl, isRevoked, appId, version }) }));

  // Only records that individually pass EVERY per-record check (shape,
  // signature, binding, trust, revocation, PASS verdict) are even eligible
  // to count toward quorum.
  const qualifying = perRecord.filter((r) => r.verdict.badge === BADGE.ATTESTED);

  // Distinctness on the PINNED key (resolved via the trust store), not the
  // record's own claimed id/key — this is what actually closes finding H1:
  // "two records" that both resolve to the same pinned signer are one signer.
  const distinctBuilderKeys = new Set(
    qualifying.map((r) => trustStore?.get(r.record.builder_identity.id)?.pubkey_b64).filter(Boolean)
  );

  if (distinctBuilderKeys.size < quorum) {
    let reason;
    if (list.length === 0) {
      reason = `no reproducible_build records supplied — ${quorum} distinct trusted builder signatures are required for ATTESTED`;
    } else if (qualifying.length === 0) {
      // Surface the most informative single-record failure reason (they're
      // typically the same root cause — untrusted/unsigned/wrong-verdict/
      // misbound — across a batch), while still being explicit that quorum
      // is the ultimate reason none of them individually counted.
      reason = `0 of ${list.length} supplied record(s) independently earned trust (first reason: "${perRecord[0].verdict.reason}") — ${quorum} distinct trusted builders required for ATTESTED`;
    } else {
      reason = `only ${distinctBuilderKeys.size} distinct pinned trusted builder(s) among ${qualifying.length} otherwise-valid record(s) — ${quorum} DISTINCT builders required (closes Depot finding H1: two records collapsing to one signer/key must never earn ATTESTED)`;
    }
    return { ok: false, reason, distinctBuilderCount: distinctBuilderKeys.size, qualifyingCount: qualifying.length, perRecord };
  }

  return {
    ok: true,
    reason: `${distinctBuilderKeys.size} distinct pinned trusted builders each independently signed a valid, bound PASS record — two-builder quorum satisfied`,
    distinctBuilderCount: distinctBuilderKeys.size,
    qualifyingCount: qualifying.length,
    perRecord,
  };
}

/**
 * Full client-side badge decision: the catalog's `tier` claim (necessary but
 * never sufficient, 02-reproducible-builds.md §2) PLUS the two-builder-
 * quorum-verified build records (necessary, and — after the H1 fix — no
 * longer spoofable by tier string, a single self-signed record, a foreign
 * record shape, or two records that collapse to one builder identity/key).
 *
 * @param {{tier: string, records: object[], trustStore: Map, crl?: object|null, isRevoked?: Function|null, appId?: string|null, version?: string|null, quorum?: number}} opts
 *   `records` is the FULL set of reproducible_build records offered for this catalog entry — plural, on purpose
 *   (see verifyTwoBuilderQuorum() above); `appId`/`version` identify the catalog entry this decision is FOR and are
 *   forwarded to each record's binding check; `quorum` defaults to 2 distinct trusted builders.
 */
export function decideAttestedBadge({ tier, records, trustStore, crl = null, isRevoked = null, appId = null, version = null, quorum = 2 }) {
  if (tier !== "attestable-nix") {
    return {
      badge: BADGE.STRIPPED,
      reason: `tier is "${tier}", not attestable-nix — ATTESTED is never eligible regardless of any record (CURATION.md invariant 2)`,
    };
  }
  const q = verifyTwoBuilderQuorum({ records, trustStore, crl, isRevoked, appId, version, quorum });
  return { badge: q.ok ? BADGE.ATTESTED : BADGE.STRIPPED, reason: q.reason, detail: q };
}
