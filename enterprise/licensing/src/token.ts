// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Postern Labs and Postern community contributors
//
// Canonical token format + issue()/mintSub()/verifyChain().
//
// FORMAT (identical on the serverless issuer and in the shipped apps):
//   A signed token is  { "payload": <canonical JSON>, "sig": "<base64>" }
//   where `sig` is a detached Ed25519 signature over the UTF-8 bytes of
//   canonicalJson(payload) (keys sorted at every level). `canonicalJson`
//   guarantees signer and verifier agree on the exact bytes.
//
// This module is portable and dependency-free beyond `node:crypto`, so:
//   - the SITE's Cloudflare Pages Function reuses issue() (holding the VENDOR
//     private key as a server secret), and
//   - the org's admin CONSOLE reuses mintSub() (holding the ORG master private
//     key), and
//   - the shipped desktop apps reuse verifyChain()/status() with ONLY the
//     vendor PUBLIC key — fully offline, no telemetry.

import { canonicalJson, utf8 } from "./encoding.js";
import { ed25519Sign, ed25519Verify, generateKeypair, randomSerial } from "./keys.js";
import { addMonthsUtc } from "./eval.js";
import { checkRevocation, verifyCrl } from "./crl.js";
import type {
  Crl,
  DnbDecision,
  Level,
  MasterPayload,
  MasterToken,
  Seats,
  SubPayload,
  SubToken,
  Tier,
} from "./types.js";

export const CORPORATE_MASTER_MONTHS = 6;
export const BUSINESS_FREEMIUM_MONTHS = 24;
export const BUSINESS_FREEMIUM_SEATS = 3;

/** DUNS numbers are exactly 9 digits. FORMAT-only check (honor system TODO). */
export function isValidDunsFormat(duns: string | null | undefined): boolean {
  return typeof duns === "string" && /^[0-9]{9}$/.test(duns);
}

function nowSec(now: Date): number {
  return Math.floor(now.getTime() / 1000);
}

function expSec(now: Date, months: number): number {
  return Math.floor(addMonthsUtc(now, months).getTime() / 1000);
}

/** Detached-sign any payload -> a SignedToken. */
function signPayload<T>(privB64: string, payload: T): { payload: T; sig: string } {
  const sig = ed25519Sign(privB64, utf8(canonicalJson(payload)));
  return { payload, sig };
}

/** Verify a SignedToken's detached signature (crypto only). */
function verifySig<T>(pubB64: string, token: { payload: T; sig: string }): boolean {
  return ed25519Verify(pubB64, utf8(canonicalJson(token.payload)), token.sig);
}

export interface IssueMasterOptions {
  readonly tier: "corporate-master" | "business-freemium";
  /** Required (9 digits) for corporate-master; ignored/null for freemium. */
  readonly duns?: string | null;
  /** Override the clock (tests). */
  readonly now?: Date;
  // --- Revocation/CRL contract (ADDITIVE, D4) ---
  /** Issuer identifier bound into the token (e.g. "posternlabs.com"). */
  readonly iss?: string;
  /** Vendor key id bound into the token (see keyId()); enables rotation. */
  readonly kid?: string;
  /** Override the generated serial (tests). Defaults to a fresh 128-bit jti. */
  readonly jti?: string;
  /** D&B verification decision to bind into the token (D5). */
  readonly dnb?: DnbDecision;
}

export interface IssuedMaster {
  /** The vendor-signed master token to hand to the org. */
  readonly masterToken: MasterToken;
  /**
   * The org's master keypair, generated at issuance. Return the PRIVATE key to
   * the org (over a secure channel) so it can mint sub tokens. The site MUST
   * NOT retain it.
   */
  readonly orgMasterPrivateKey: string;
  readonly orgMasterPublicKey: string;
}

/**
 * Issue a vendor-signed master token. Generates the org's master keypair,
 * embeds its public key as `master_pub`, and signs with the VENDOR private key.
 * Reused verbatim by the site's serverless issuer.
 */
export function issue(vendorPrivateKey: string, opts: IssueMasterOptions): IssuedMaster {
  const now = opts.now ?? new Date();
  const org = generateKeypair();

  let seats: Seats;
  let months: number;
  let duns: string | null;

  if (opts.tier === "corporate-master") {
    if (!isValidDunsFormat(opts.duns ?? null)) {
      throw new Error("corporate-master requires a 9-digit DUNS number");
    }
    duns = opts.duns as string;
    seats = "unlimited";
    months = CORPORATE_MASTER_MONTHS;
  } else {
    duns = null;
    seats = BUSINESS_FREEMIUM_SEATS;
    months = BUSINESS_FREEMIUM_MONTHS;
  }

  const payload: MasterPayload = {
    v: 1,
    typ: "master",
    tier: opts.tier,
    duns,
    seats,
    iat: nowSec(now),
    exp: expSec(now, months),
    master_pub: org.publicKey,
    // Optional CRL/KYC fields (D4/D5). Only present when supplied — absent keys
    // are dropped by canonicalJson so pre-CRL tokens verify unchanged.
    jti: opts.jti ?? randomSerial(),
    ...(opts.iss !== undefined ? { iss: opts.iss } : {}),
    ...(opts.kid !== undefined ? { kid: opts.kid } : {}),
    ...(opts.dnb !== undefined ? { dnb: opts.dnb } : {}),
  };

  return {
    masterToken: signPayload(vendorPrivateKey, payload),
    orgMasterPrivateKey: org.privateKey,
    orgMasterPublicKey: org.publicKey,
  };
}

export interface MintSubOptions {
  /** The org master public key (must match the master token's master_pub). */
  readonly masterPublicKey: string;
  /** User/label the sub is issued to. */
  readonly sub: string;
  /** Sub expiry, unix seconds. MUST be <= the master's exp. */
  readonly exp: number;
  /** Override the clock (tests). */
  readonly now?: Date;
  /** Override the generated serial (tests). Defaults to a fresh 128-bit jti (D4). */
  readonly jti?: string;
}

/**
 * Mint a sub token, signed by the ORG master PRIVATE key. Reused by the org's
 * admin console. Callers should clamp `exp` to the master token's exp; this
 * function does not know the master exp on its own.
 */
export function mintSub(masterPrivateKey: string, opts: MintSubOptions): SubToken {
  const now = opts.now ?? new Date();
  const payload: SubPayload = {
    v: 1,
    typ: "sub",
    master_pub: opts.masterPublicKey,
    sub: opts.sub,
    iat: nowSec(now),
    exp: opts.exp,
    // Per-sub serial so an individual sub can be put on the CRL (D4).
    jti: opts.jti ?? randomSerial(),
  };
  return signPayload(masterPrivateKey, payload);
}

/** Convenience: mint a sub under a known master token, clamping exp to it. */
export function mintSubUnderMaster(
  masterPrivateKey: string,
  master: MasterToken,
  sub: string,
  subExp?: number,
  now: Date = new Date(),
): SubToken {
  const clamped = Math.min(subExp ?? master.payload.exp, master.payload.exp);
  return mintSub(masterPrivateKey, {
    masterPublicKey: master.payload.master_pub,
    sub,
    exp: clamped,
    now,
  });
}

/** Normalised result of the offline verification chain. */
export type ChainResult =
  | {
      ok: true;
      level: Level;
      tier: Tier;
      seats: Seats;
      duns: string | null;
      /** Effective expiry (unix seconds); min(sub.exp, master.exp) for subs. */
      exp: number;
      sub?: string;
      /** Whether the effective window has closed at `now`. */
      expired: boolean;
      /** Org master public key — the CRL revokes a whole org by this (D4). */
      master_pub: string;
      /** Master serial, if the token carries one (D4). */
      masterJti?: string;
      /** Sub serial, if a sub was verified and carries one (D4). */
      subJti?: string;
    }
  | { ok: false; reason: string };

/**
 * OFFLINE verification chain:
 *   ed25519_verify(VENDOR_PUB, master_json, master_sig) && master.exp > now
 *     -> extract master.master_pub
 *     -> (if sub) ed25519_verify(master.master_pub, sub_json, sub_sig)
 *        && sub.exp > now && sub.exp <= master.exp
 *        && sub.master_pub == master.master_pub
 *     -> (if a CRL is supplied) NOT revoked by that CRL
 *
 * `expired` is reported separately from `ok` so the caller can degrade
 * gracefully (an authentic-but-expired token is `ok:true, expired:true`, never
 * a hard failure).
 *
 * REVOCATION (D4) — ADDITIVE, fail-closed, offline-preserving:
 *   Pass an optional `crl` to thread `checkRevocation` INTO the verify path. When
 *   supplied AND the CRL verifies against the SAME vendor key, a revoked org
 *   master key or a revoked master/sub serial makes the chain fail closed:
 *   `{ ok:false, reason:"revoked: <why>" }`. This is the low-level counterpart to
 *   `status()`'s richer "revoked"/"stale-revocation" states — for direct gate
 *   callers (Ezekiel1 admitTenant, Consiglio sub-access) that only need a
 *   valid/invalid verdict. RAILS: the CRL ONLY ever revokes, never grants; a
 *   missing CRL is byte-identical to the pre-CRL behaviour (offline verification
 *   preserved); a corrupt/foreign CRL is IGNORED (treated as absent) so it can
 *   never brick an otherwise-valid license. The personal-free base never reaches
 *   here.
 */
export function verifyChain(
  vendorPublicKey: string,
  master: MasterToken,
  sub: SubToken | null | undefined,
  now: Date = new Date(),
  crl?: Crl | null,
): ChainResult {
  const m = master?.payload;
  if (!m || m.v !== 1 || m.typ !== "master") return { ok: false, reason: "malformed-master" };
  if (!verifySig(vendorPublicKey, master)) return { ok: false, reason: "bad-master-signature" };
  if (m.tier === "corporate-master" && !isValidDunsFormat(m.duns)) {
    return { ok: false, reason: "bad-duns" };
  }

  const t = nowSec(now);
  const masterExpired = m.exp <= t;

  // Revocation gate (only when a CRL that verifies against THIS vendor key is
  // supplied). A corrupt/foreign CRL fails verifyCrl and is silently ignored so
  // it can never brick a valid license; a missing CRL means "no revocation info".
  const revokedReason = (subPayload: SubPayload | null): string | null => {
    if (!crl || !verifyCrl(vendorPublicKey, crl).ok) return null;
    const rev = checkRevocation(crl, m, subPayload);
    return rev.revoked ? rev.reason ?? "revoked" : null;
  };

  if (!sub) {
    const rr = revokedReason(null);
    if (rr) return { ok: false, reason: "revoked: " + rr };
    return {
      ok: true,
      level: "master",
      tier: m.tier,
      seats: m.seats,
      duns: m.duns,
      exp: m.exp,
      expired: masterExpired,
      master_pub: m.master_pub,
      ...(m.jti !== undefined ? { masterJti: m.jti } : {}),
    };
  }

  const s = sub.payload;
  if (!s || s.v !== 1 || s.typ !== "sub") return { ok: false, reason: "malformed-sub" };
  if (s.master_pub !== m.master_pub) return { ok: false, reason: "sub-master-mismatch" };
  if (s.exp > m.exp) return { ok: false, reason: "sub-outlives-master" };
  if (!verifySig(m.master_pub, sub)) return { ok: false, reason: "bad-sub-signature" };

  const rr = revokedReason(s);
  if (rr) return { ok: false, reason: "revoked: " + rr };

  const effectiveExp = Math.min(s.exp, m.exp);
  return {
    ok: true,
    level: "sub",
    tier: m.tier,
    seats: m.seats,
    duns: m.duns,
    exp: effectiveExp,
    sub: s.sub,
    expired: masterExpired || effectiveExp <= t,
    master_pub: m.master_pub,
    ...(m.jti !== undefined ? { masterJti: m.jti } : {}),
    ...(s.jti !== undefined ? { subJti: s.jti } : {}),
  };
}

export { signPayload, verifySig };
