// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Postern Labs and Postern community contributors
//
// Signed, versioned Certificate Revocation List (CRL) — D4, the critical gap.
//
// STATUS: reference prototype, UNAUDITED, pre-production.
//
// WHY THIS EXISTS
// ---------------
// Before this, offline tokens lived until `exp` with NO way to revoke a leaked
// master or sub. This module adds a VENDOR-signed, monotonically-versioned CRL:
//   - `buildCrl()`  — the vendor (site Function / ops) signs a CRL over a set of
//     revoked serials (`jti`) and revoked org master keys (`master_pub`).
//   - `verifyCrl()` — an install verifies the CRL's Ed25519 signature against the
//     same vendor PUBLIC key it already trusts for tokens. No new authority.
//   - `crlFreshness()` — computes whether a cached CRL is still inside its
//     disclosed freshness window (soft-offline). Past `next_update + max_stale`,
//     revocation can no longer be trusted and enterprise features degrade.
//   - `isRevoked()` — pure predicate: is a token's serial or org key listed.
//
// RAILS
//   - Offline verification is PRESERVED: the CRL only ever REVOKES, never grants.
//     A missing/absent CRL means "no revocation info" — best-effort, disclosed.
//   - The CRL is PUBLIC data (revoked serials carry no secret). Fetch is
//     opportunistic; a client that fetches reveals only that it checked.
//   - `version` is monotonic so a rolled-back (older) CRL is rejected in favour
//     of a newer cached one — a network attacker cannot un-revoke by replay.
//   - The personal-free base is NEVER gated by any of this.

import { canonicalJson, utf8 } from "./encoding.js";
import { ed25519Sign, ed25519Verify } from "./keys.js";
import type { Crl, CrlPayload, MasterPayload, SubPayload } from "./types.js";

/** Sensible defaults for the freshness window (disclosed, tunable). */
export const CRL_DEFAULT_NEXT_UPDATE_SECS = 24 * 3600; // publish daily
export const CRL_DEFAULT_MAX_STALE_SECS = 14 * 24 * 3600; // 14-day soft-offline grace

export interface BuildCrlOptions {
  readonly iss: string;
  readonly kid: string;
  /** Monotonic; MUST be greater than any previously-published version. */
  readonly version: number;
  readonly revokedJti?: readonly string[];
  readonly revokedMasterPub?: readonly string[];
  /** Seconds until the next CRL is expected (default 24h). */
  readonly nextUpdateSecs?: number;
  /** Soft-offline grace beyond next_update (default 14d). */
  readonly maxStaleSecs?: number;
  readonly now?: Date;
}

function nowSec(now: Date): number {
  return Math.floor(now.getTime() / 1000);
}

/** Vendor-sign a CRL over the revoked sets. Mirrors token detached-Ed25519. */
export function buildCrl(vendorPrivateKey: string, opts: BuildCrlOptions): Crl {
  const now = opts.now ?? new Date();
  const issued_at = nowSec(now);
  const nextUpdate = opts.nextUpdateSecs ?? CRL_DEFAULT_NEXT_UPDATE_SECS;
  const maxStale = opts.maxStaleSecs ?? CRL_DEFAULT_MAX_STALE_SECS;
  // De-duplicate + sort so the signed bytes are stable for a given input set.
  const revoked_jti = [...new Set(opts.revokedJti ?? [])].sort();
  const revoked_master_pub = [...new Set(opts.revokedMasterPub ?? [])].sort();

  const payload: CrlPayload = {
    v: 1,
    typ: "crl",
    iss: opts.iss,
    kid: opts.kid,
    version: opts.version,
    issued_at,
    next_update: issued_at + nextUpdate,
    max_stale_secs: maxStale,
    revoked_jti,
    revoked_master_pub,
  };
  const sig = ed25519Sign(vendorPrivateKey, utf8(canonicalJson(payload)));
  return { payload, sig };
}

export interface CrlVerifyResult {
  readonly ok: boolean;
  readonly reason?: string;
}

/**
 * Verify a CRL's signature and structure against the vendor PUBLIC key. Does NOT
 * check freshness (see `crlFreshness`) — a structurally-valid but stale CRL is
 * still authentic; freshness is a separate, disclosed policy decision.
 */
export function verifyCrl(vendorPublicKey: string, crl: Crl | null | undefined): CrlVerifyResult {
  const p = crl?.payload;
  if (!p || p.v !== 1 || p.typ !== "crl") return { ok: false, reason: "malformed-crl" };
  if (!Array.isArray(p.revoked_jti) || !Array.isArray(p.revoked_master_pub)) {
    return { ok: false, reason: "malformed-crl-lists" };
  }
  if (typeof p.version !== "number" || p.version < 0) return { ok: false, reason: "bad-crl-version" };
  if (!ed25519Verify(vendorPublicKey, utf8(canonicalJson(p)), crl!.sig)) {
    return { ok: false, reason: "bad-crl-signature" };
  }
  return { ok: true };
}

/**
 * Pick the CRL to trust between a freshly-fetched one and a cached one, enforcing
 * monotonic `version` (anti-rollback). Both should already be signature-verified.
 * Returns whichever has the higher version (ties -> the fetched one).
 */
export function pickNewerCrl(cached: Crl | null, fetched: Crl | null): Crl | null {
  if (!cached) return fetched;
  if (!fetched) return cached;
  return fetched.payload.version >= cached.payload.version ? fetched : cached;
}

export interface CrlFreshness {
  /** Inside the normal window (now <= next_update). */
  readonly fresh: boolean;
  /** Past next_update but within the max_stale grace — still usable, ageing. */
  readonly ageing: boolean;
  /** Past next_update + max_stale — too stale to trust; enterprise degrades. */
  readonly stale: boolean;
  /** Whole days since the CRL was issued. */
  readonly ageDays: number;
  readonly note: string;
}

/** Compute the soft-offline freshness of a cached CRL. */
export function crlFreshness(crl: Crl, now: Date = new Date()): CrlFreshness {
  const t = nowSec(now);
  const p = crl.payload;
  const hardDeadline = p.next_update + p.max_stale_secs;
  const ageDays = Math.max(0, Math.floor((t - p.issued_at) / 86_400));
  if (t <= p.next_update) {
    return { fresh: true, ageing: false, stale: false, ageDays, note: "CRL is within its update window" };
  }
  if (t <= hardDeadline) {
    return {
      fresh: false,
      ageing: true,
      stale: false,
      ageDays,
      note: "CRL is past its update window but inside the soft-offline grace; fetch a fresher CRL soon",
    };
  }
  return {
    fresh: false,
    ageing: false,
    stale: true,
    ageDays,
    note: "CRL is older than the freshness window; revocation can no longer be trusted — enterprise features degrade until refreshed",
  };
}

/** Is a specific serial or org master key on the CRL? */
export function isSerialRevoked(crl: Crl, jti: string | null | undefined): boolean {
  return !!jti && crl.payload.revoked_jti.includes(jti);
}
export function isMasterKeyRevoked(crl: Crl, masterPub: string | null | undefined): boolean {
  return !!masterPub && crl.payload.revoked_master_pub.includes(masterPub);
}

export interface RevocationCheck {
  readonly revoked: boolean;
  readonly reason?: string;
}

/**
 * Is a verified master (+ optional sub) revoked by this CRL? Checks the org
 * master key, then the master serial, then the sub serial.
 */
export function checkRevocation(
  crl: Crl,
  master: MasterPayload,
  sub?: SubPayload | null,
): RevocationCheck {
  if (isMasterKeyRevoked(crl, master.master_pub)) {
    return { revoked: true, reason: "org master key is revoked (whole-org revocation)" };
  }
  if (isSerialRevoked(crl, master.jti)) {
    return { revoked: true, reason: "master token serial is revoked" };
  }
  if (sub && isSerialRevoked(crl, sub.jti)) {
    return { revoked: true, reason: "sub token serial is revoked" };
  }
  return { revoked: false };
}
