// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Postern Labs and Postern community contributors
//
// The local, offline `status()` entitlement API. This is the single function an
// application calls to decide what to show the user. It runs the offline
// verification chain (vendor -> master -> optional sub) and combines it with
// the clock. It performs NO network I/O and no telemetry.

import { verifyChain } from "./token.js";
import { checkRevocation, crlFreshness, verifyCrl } from "./crl.js";
import type {
  Crl,
  EntitlementState,
  MasterToken,
  SubToken,
} from "./types.js";

export interface StatusInput {
  /** If the running edition is Personal, set true -> free forever, no token. */
  personal?: boolean;
  /** The vendor public key that ships with the software (base64 raw Ed25519). */
  vendorPublicKey: string;
  /** The org's vendor-signed master token (business/corporate). */
  master?: MasterToken | null;
  /** An optional sub token minted by the org master key for this user. */
  sub?: SubToken | null;
  /**
   * An optional, vendor-signed CRL (D4). When supplied, the chain is additionally
   * checked for revocation and CRL freshness (soft-offline). When omitted,
   * behaviour is byte-identical to the pre-CRL library — offline verification is
   * preserved and revocation is simply "unknown / best-effort". A CRL that fails
   * its own signature check is ignored (treated as absent) so a corrupt CRL can
   * never brick an otherwise-valid license.
   */
  crl?: Crl | null;
  /** Override the clock (tests). Defaults to now. */
  now?: Date;
}

function daysRemaining(expSec: number, now: Date): number {
  return Math.max(0, Math.ceil((expSec * 1000 - now.getTime()) / 86_400_000));
}

/**
 * Resolve the entitlement state locally. Precedence:
 *   1. Personal -> always free, never gated. Tokens ignored.
 *   2. Authentic, in-window chain:
 *        business-freemium -> "valid"
 *        corporate-master  -> "in-eval" (free now, pricing TBD)
 *   3. Authentic but past its window -> "expired" (graceful; never destructive).
 *   4. Missing/broken chain -> "invalid" (still non-destructive).
 */
export function status(input: StatusInput): EntitlementState {
  const now = input.now ?? new Date();

  // (1) Personal is free forever. We never even look at a token.
  if (input.personal) {
    return { state: "personal-free", tier: "personal" };
  }

  if (!input.master) {
    return { state: "invalid", tier: "unknown", reason: "no-master-token" };
  }

  const result = verifyChain(input.vendorPublicKey, input.master, input.sub ?? null, now);
  if (!result.ok) {
    return { state: "invalid", tier: "unknown", reason: result.reason };
  }

  const expiresAt = new Date(result.exp * 1000).toISOString();

  if (result.expired) {
    return {
      state: "expired",
      tier: result.tier,
      seats: result.seats,
      level: result.level,
      duns: result.duns,
      expiredAt: expiresAt,
      ...(result.sub ? { sub: result.sub } : {}),
    };
  }

  // (D4) Soft-offline revocation + freshness. Only applied when a CRL is
  // supplied AND it verifies against the SAME vendor key. Never gates personal.
  if (input.crl && verifyCrl(input.vendorPublicKey, input.crl).ok) {
    const rev = checkRevocation(input.crl, input.master.payload, input.sub?.payload ?? null);
    if (rev.revoked) {
      return {
        state: "revoked",
        tier: result.tier,
        seats: result.seats,
        level: result.level,
        duns: result.duns,
        reason: rev.reason ?? "revoked",
        ...(result.sub ? { sub: result.sub } : {}),
      };
    }
    const fresh = crlFreshness(input.crl, now);
    if (fresh.stale) {
      return {
        state: "stale-revocation",
        tier: result.tier,
        seats: result.seats,
        level: result.level,
        duns: result.duns,
        expiresAt,
        crlAgeDays: fresh.ageDays,
        ...(result.sub ? { sub: result.sub } : {}),
      };
    }
  }

  const base = {
    tier: result.tier,
    seats: result.seats,
    level: result.level,
    duns: result.duns,
    expiresAt,
    daysRemaining: daysRemaining(result.exp, now),
    ...(result.sub ? { sub: result.sub } : {}),
  };

  // corporate-master is the disclosed "free now, pricing TBD" window.
  if (result.tier === "corporate-master") {
    return { state: "in-eval", ...base };
  }
  return { state: "valid", ...base };
}

/** One-line human summary of a state, suitable for a status bar / CLI. */
export function describeState(s: EntitlementState): string {
  switch (s.state) {
    case "personal-free":
      return "Personal edition — free forever. No license required.";
    case "valid": {
      const who = s.sub ? ` for ${s.sub}` : "";
      const seats = s.seats === "unlimited" ? "unlimited seats" : `${s.seats} seats`;
      return `Licensed (${s.tier}, ${seats}, ${s.level}${who}) — ${s.daysRemaining} day(s) left, until ${s.expiresAt}.`;
    }
    case "in-eval": {
      const who = s.sub ? ` for ${s.sub}` : "";
      const dun = s.duns ? `, DUNS ${s.duns}` : "";
      return `Free corporate window (${s.tier}, unlimited seats, ${s.level}${who}${dun}) — ${s.daysRemaining} day(s) left, until ${s.expiresAt}. Free now, pricing TBD.`;
    }
    case "expired":
      return `Entitlement ended (${s.tier}, ${s.level}) on ${s.expiredAt}. A license is required for continued business use. Your data is untouched.`;
    case "revoked":
      return `Entitlement REVOKED (${s.tier}, ${s.level}): ${s.reason}. Enterprise features are disabled; personal apps and your data are untouched.`;
    case "stale-revocation":
      return `Revocation data is stale (${s.crlAgeDays} day(s) old) — enterprise features degrade to best-effort until a fresher CRL is fetched. Personal apps are unaffected. (${s.tier}, ${s.level}, in-window until ${s.expiresAt}.)`;
    case "invalid":
      return `No valid entitlement (${s.tier}): ${s.reason}.`;
  }
}
