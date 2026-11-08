// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Postern Labs and Postern community contributors
//
// Depot CRL — revocation for the multi-repo Depot client, built on exactly
// the pattern enterprise/licensing/src/crl.ts already ships for master/sub
// license tokens: a signed, monotonically-versioned list an operator
// publishes, and a pure predicate the client checks. Same rails:
//   - offline verification preserved: an absent CRL means "no revocation
//     info available" (best-effort, disclosed), never "revocation failed".
//   - the CRL only ever REVOKES, never grants — a missing entry is not proof
//     of trust, only absence of a known-bad marker.
//   - `version` is monotonic; a rolled-back (older) CRL loses to a cached
//     newer one — pickNewerDepotCrl mirrors crl.ts's pickNewerCrl exactly.
//
// Depot's revocation namespace differs from licensing's (jti/master_pub):
// here we revoke REPO signing keys (a compromised repo operator), BUILDER
// identities (a compromised/decommissioned reproducible-build attestor —
// this is what makes builder-trust.mjs's pinning meaningful over time, not
// just a fixed set with no way to react to a compromise), and specific
// ARTIFACT hashes (a shipped build later found to be malicious/broken, even
// if its signatures were valid at publish time).

import { canonicalJson, utf8, ed25519Sign, ed25519Verify } from "./crypto-bridge.mjs";

export const DEPOT_CRL_DEFAULT_NEXT_UPDATE_SECS = 24 * 3600;
export const DEPOT_CRL_DEFAULT_MAX_STALE_SECS = 14 * 24 * 3600;

function nowSec(now) {
  return Math.floor(now.getTime() / 1000);
}

/**
 * Sign a Depot CRL over revoked repo keys / builder keys / artifact hashes.
 * Mirrors crl.ts's buildCrl() field-for-field where the concept carries over.
 *
 * @param {string} signerPrivB64 - the Depot-ops signing key (distinct from any one repo's index key)
 * @param {object} opts
 */
export async function buildDepotCrl(signerPrivB64, opts) {
  const now = opts.now ?? new Date();
  const issued_at = nowSec(now);
  const nextUpdate = opts.nextUpdateSecs ?? DEPOT_CRL_DEFAULT_NEXT_UPDATE_SECS;
  const maxStale = opts.maxStaleSecs ?? DEPOT_CRL_DEFAULT_MAX_STALE_SECS;
  const revoked_repo_keys = [...new Set(opts.revokedRepoKeys ?? [])].sort();
  const revoked_builder_keys = [...new Set(opts.revokedBuilderKeys ?? [])].sort();
  const revoked_artifact_sha256 = [...new Set(opts.revokedArtifactSha256 ?? [])].sort();

  const payload = {
    v: 1,
    typ: "depot-crl",
    iss: opts.iss,
    kid: opts.kid,
    version: opts.version,
    issued_at,
    next_update: issued_at + nextUpdate,
    max_stale_secs: maxStale,
    revoked_repo_keys,
    revoked_builder_keys,
    revoked_artifact_sha256,
  };
  const sig = await ed25519Sign(signerPrivB64, await utf8(await canonicalJson(payload)));
  return { payload, sig };
}

/** Verify a Depot CRL's signature + basic structure against the pinned Depot-ops public key. */
export async function verifyDepotCrl(signerPubB64, crl) {
  const p = crl?.payload;
  if (!p || p.v !== 1 || p.typ !== "depot-crl") return { ok: false, reason: "malformed-depot-crl" };
  if (!Array.isArray(p.revoked_repo_keys) || !Array.isArray(p.revoked_builder_keys) || !Array.isArray(p.revoked_artifact_sha256)) {
    return { ok: false, reason: "malformed-depot-crl-lists" };
  }
  if (typeof p.version !== "number" || p.version < 0) return { ok: false, reason: "bad-depot-crl-version" };
  const bytes = await utf8(await canonicalJson(p));
  if (!(await ed25519Verify(signerPubB64, bytes, crl.sig))) {
    return { ok: false, reason: "bad-depot-crl-signature" };
  }
  return { ok: true };
}

/** Anti-rollback pick: higher `version` wins; ties favor the freshly-fetched one. Mirrors crl.ts's pickNewerCrl. */
export function pickNewerDepotCrl(cached, fetched) {
  if (!cached) return fetched;
  if (!fetched) return cached;
  return fetched.payload.version >= cached.payload.version ? fetched : cached;
}

/** Soft-offline freshness, identical shape to crl.ts's crlFreshness. */
export function depotCrlFreshness(crl, now = new Date()) {
  const t = nowSec(now);
  const p = crl.payload;
  const hardDeadline = p.next_update + p.max_stale_secs;
  const ageDays = Math.max(0, Math.floor((t - p.issued_at) / 86_400));
  if (t <= p.next_update) return { fresh: true, ageing: false, stale: false, ageDays, note: "Depot CRL is within its update window" };
  if (t <= hardDeadline) return { fresh: false, ageing: true, stale: false, ageDays, note: "Depot CRL is past its update window but inside the soft-offline grace" };
  return { fresh: false, ageing: false, stale: true, ageDays, note: "Depot CRL is older than the freshness window; revocation can no longer be trusted" };
}

export function isRepoKeyRevoked(crl, pubkeyB64) {
  return !!crl && !!pubkeyB64 && crl.payload.revoked_repo_keys.includes(pubkeyB64);
}
export function isBuilderKeyRevoked(crl, pubkeyB64) {
  return !!crl && !!pubkeyB64 && crl.payload.revoked_builder_keys.includes(pubkeyB64);
}
export function isArtifactRevoked(crl, sha256) {
  return !!crl && !!sha256 && crl.payload.revoked_artifact_sha256.includes(sha256);
}
