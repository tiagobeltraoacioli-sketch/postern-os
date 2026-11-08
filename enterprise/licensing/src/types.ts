// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Postern Labs and Postern community contributors
//
// Canonical token types for the Postern licensing/entitlement library.
//
// Design stance (see LICENSING-MODEL.md):
//   - PERSONAL is FREE FOREVER and needs NO TOKEN AT ALL. It is never gated by,
//     or checked against, this library. No token, no clock, no tracking.
//   - BUSINESS-FREEMIUM: a vendor-signed MASTER token grants up to 3 desktops
//     for 2 years (seats=3, exp=iat+24mo, duns=null).
//   - CORPORATE-MASTER: a company with a DUNS number gets a vendor-signed
//     MASTER token — seats="unlimited", exp=iat+6mo (free now, pricing TBD).
//   - MASTER -> SUB hierarchy: at issuance the org receives its own master
//     keypair. The org keeps the master PRIVATE key and mints SUB tokens for
//     its users. Sub tokens are signed by the ORG master key, and each verifies
//     OFFLINE as a chain rooted in the vendor key.
//   - Paid in ordinary currency (fiat), never any token or coin.
//   - Verification is entirely LOCAL and OFFLINE. Expiry degrades GRACEFULLY;
//     it never destroys or locks data.

/** The licensing tier a master token grants. Personal never needs a token. */
export type Tier = "personal" | "business-freemium" | "corporate-master";

/** Seat allowance: a finite integer, or "unlimited" for a corporate master. */
export type Seats = number | "unlimited";

/**
 * MASTER token payload — signed by the VENDOR key. Canonical JSON with sorted
 * keys is what gets signed (detached Ed25519, base64).
 *
 * {
 *   "v":1, "typ":"master",
 *   "tier":"corporate-master"|"business-freemium",
 *   "duns":"<9-digit>"|null,
 *   "seats":"unlimited"|3,
 *   "iat":<unix>, "exp":<unix>,
 *   "master_pub":"<base64 ed25519 pubkey of THIS org's master keypair>"
 * }
 */
export interface MasterPayload {
  readonly v: 1;
  readonly typ: "master";
  readonly tier: "corporate-master" | "business-freemium";
  /** 9-digit DUNS for corporate-master; null for business-freemium. */
  readonly duns: string | null;
  readonly seats: Seats;
  /** Issued-at, unix seconds. */
  readonly iat: number;
  /** Expiry, unix seconds. */
  readonly exp: number;
  /** base64 raw Ed25519 public key of the org's master keypair. */
  readonly master_pub: string;

  // --- Revocation/CRL contract (ADDITIVE, D4) --------------------------------
  // These are OPTIONAL. Tokens issued BEFORE this change do not carry them and
  // still verify byte-identically (canonicalJson is unchanged and simply omits
  // absent keys). Tokens issued AFTER carry them so a serial can be revoked and
  // the signing vendor key can be identified/rotated.
  //
  /** Random 128-bit serial (hex), unique per master. Enables CRL revocation. */
  readonly jti?: string;
  /** Vendor key id that signed this token (for key rotation + whole-key revoke). */
  readonly kid?: string;
  /** Issuer identifier, e.g. "posternlabs.com". */
  readonly iss?: string;
  /** Real Dun & Bradstreet verification decision bound into the token (D5). */
  readonly dnb?: DnbDecision;
}

/**
 * Dun & Bradstreet verification decision, cryptographically bound into a
 * corporate-master token (D5). `verified:false` is honest: it means D&B was
 * unavailable/unconfigured and issuance fell back to format-only, flagged for
 * manual review at renewal — NEVER a silent pass claiming real KYC.
 */
export interface DnbDecision {
  /** True only if a live D&B lookup resolved the DUNS to a real legal entity. */
  readonly verified: boolean;
  /** "dnb-direct-plus" on a real lookup; "format-only" on graceful fallback. */
  readonly source: "dnb-direct-plus" | "format-only";
  /** Legal entity name from D&B (present only when verified). */
  readonly legalName?: string;
  /** ISO alpha-2 country from D&B (present only when verified). */
  readonly country?: string;
  /** Unix seconds when the check ran. */
  readonly checkedAt: number;
  /** Set when verified:false — why the real lookup did not run/resolve. */
  readonly fallbackReason?: string;
}

/**
 * SUB token payload — signed by the ORG's MASTER key (minted by the master
 * holder). Unlimited subs may exist under a corporate master.
 *
 * {
 *   "v":1, "typ":"sub",
 *   "master_pub":"<the org master pubkey>",
 *   "sub":"<user/label>",
 *   "iat":<unix>, "exp":<unix ≤ master.exp>
 * }
 */
export interface SubPayload {
  readonly v: 1;
  readonly typ: "sub";
  /** Must equal the master token's `master_pub`. */
  readonly master_pub: string;
  /** Free-form user or label the sub is issued to. */
  readonly sub: string;
  readonly iat: number;
  readonly exp: number;
  /**
   * Random 128-bit serial (hex), unique per sub (ADDITIVE, D4). Optional so
   * pre-CRL sub tokens still verify byte-identically. Present on newly-minted
   * subs so an individual sub can be put on the CRL without revoking the org.
   */
  readonly jti?: string;
}

/**
 * A signed, versioned Certificate Revocation List (CRL), D4.
 *
 * The CRL is VENDOR-signed (same detached-Ed25519-over-canonicalJson scheme as
 * tokens) and is PUBLIC. It lists revoked serials (`revoked_jti`) and revoked
 * org master keys (`revoked_master_pub`, which kills a whole org at once). It is
 * fetched opportunistically and cached; offline verification is preserved — the
 * CRL only ever REVOKES (never grants), and its freshness window is disclosed as
 * best-effort. `version` is monotonic so a stale cached copy can never be rolled
 * back over a newer one.
 */
export interface CrlPayload {
  readonly v: 1;
  readonly typ: "crl";
  /** Issuer identifier, matches the token `iss`. */
  readonly iss: string;
  /** Vendor key id that signs this CRL (matches token `kid`). */
  readonly kid: string;
  /** Monotonic version. A verifier rejects a CRL older than the one it cached. */
  readonly version: number;
  /** Unix seconds this CRL was published. */
  readonly issued_at: number;
  /** Unix seconds by which a fresher CRL is expected to exist. */
  readonly next_update: number;
  /**
   * Grace (seconds) beyond `next_update` before an install treats the cached CRL
   * as too stale to trust and DEGRADES enterprise features (never the personal
   * base). This is the "soft-offline" freshness window, disclosed as best-effort.
   */
  readonly max_stale_secs: number;
  /** Revoked token serials (master and/or sub `jti`). */
  readonly revoked_jti: readonly string[];
  /** Revoked org master public keys — revokes every token under that org. */
  readonly revoked_master_pub: readonly string[];
}

export type Crl = SignedToken<CrlPayload>;

/**
 * A signed token = canonical-JSON payload + detached base64 Ed25519 signature.
 * The signature is computed over `canonicalJson(payload)` (sorted keys).
 */
export interface SignedToken<T> {
  readonly payload: T;
  readonly sig: string;
}

export type MasterToken = SignedToken<MasterPayload>;
export type SubToken = SignedToken<SubPayload>;

/** Which link of the chain granted the entitlement. */
export type Level = "master" | "sub";

/**
 * The entitlement state the application acts on. Returned by `status()` after
 * verifying the chain offline against the vendor public key and the clock.
 * Carries {tier, seats, valid|in-eval|expired, duns?, level}.
 */
export type EntitlementState =
  /** Personal edition: free forever. No token, no clock, no gate. */
  | { state: "personal-free"; tier: "personal" }
  /** A verified, in-window entitlement (business-freemium). */
  | {
      state: "valid";
      tier: Tier;
      seats: Seats;
      level: Level;
      duns: string | null;
      expiresAt: string;
      daysRemaining: number;
      sub?: string;
    }
  /**
   * A verified, in-window entitlement whose end is a disclosed free-now window
   * (corporate-master "free now, pricing TBD"). "in-eval-until" == expiresAt.
   */
  | {
      state: "in-eval";
      tier: Tier;
      seats: Seats;
      level: Level;
      duns: string | null;
      expiresAt: string;
      daysRemaining: number;
      sub?: string;
    }
  /**
   * The window has ended. The app MUST degrade GRACEFULLY: show "entitlement
   * ended — a license is required for continued business use". It MUST NOT
   * destroy or lock data.
   */
  | {
      state: "expired";
      tier: Tier;
      seats: Seats;
      level: Level;
      duns: string | null;
      expiredAt: string;
      sub?: string;
    }
  /**
   * The chain verified, but the token's serial (or its org master key) is on the
   * signed CRL (D4). Enterprise features degrade; the personal-free base is never
   * affected. Non-destructive — data is untouched.
   */
  | {
      state: "revoked";
      tier: Tier;
      seats: Seats;
      level: Level;
      duns: string | null;
      reason: string;
      sub?: string;
    }
  /**
   * The chain verified and is in-window, but the cached CRL is older than its
   * freshness window (issued past `next_update + max_stale_secs`) so revocation
   * can no longer be trusted (D4, soft-offline). Enterprise features degrade to
   * best-effort until a fresher CRL is fetched; the personal base is unaffected.
   */
  | {
      state: "stale-revocation";
      tier: Tier;
      seats: Seats;
      level: Level;
      duns: string | null;
      expiresAt: string;
      crlAgeDays: number;
      sub?: string;
    }
  /** A token was supplied but the offline chain did not verify. */
  | { state: "invalid"; tier: Tier | "unknown"; reason: string };
