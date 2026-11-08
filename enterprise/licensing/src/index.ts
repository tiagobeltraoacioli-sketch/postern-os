// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Postern Labs and Postern community contributors
//
// Public entry point for @postern/licensing.
//
// Privacy-preserving, offline-verifiable license/entitlement library for the
// Postern Business/Corporate editions, with a master -> sub hierarchy.
//
//   - PERSONAL editions are FREE FOREVER and need no token at all; this library
//     never gates them.
//   - BUSINESS-FREEMIUM: vendor-signed master, up to 3 desktops for 2 years.
//   - CORPORATE-MASTER: DUNS-scoped vendor-signed master, unlimited seats,
//     6-month "free now, pricing TBD" window; the org mints unlimited sub
//     tokens with its own master key.
//   - Verification is 100% local/offline: no telemetry, no phone-home.
//   - Paid in ordinary currency (fiat) — never any token or coin.
//
// SCAFFOLD / pre-production / UNAUDITED. Not a security product; do not rely on
// it for anything safety- or compliance-critical without an independent review.

export type {
  Tier,
  Seats,
  Level,
  MasterPayload,
  SubPayload,
  SignedToken,
  MasterToken,
  SubToken,
  EntitlementState,
  DnbDecision,
  CrlPayload,
  Crl,
} from "./types.js";

export {
  generateKeypair,
  ed25519Sign,
  ed25519Verify,
  randomSerial,
  keyId,
  type RawKeyPair,
} from "./keys.js";

export {
  buildCrl,
  verifyCrl,
  crlFreshness,
  pickNewerCrl,
  checkRevocation,
  isSerialRevoked,
  isMasterKeyRevoked,
  CRL_DEFAULT_NEXT_UPDATE_SECS,
  CRL_DEFAULT_MAX_STALE_SECS,
  type BuildCrlOptions,
  type CrlVerifyResult,
  type CrlFreshness,
  type RevocationCheck,
} from "./crl.js";

export {
  issue,
  mintSub,
  mintSubUnderMaster,
  verifyChain,
  isValidDunsFormat,
  CORPORATE_MASTER_MONTHS,
  BUSINESS_FREEMIUM_MONTHS,
  BUSINESS_FREEMIUM_SEATS,
  type IssueMasterOptions,
  type IssuedMaster,
  type MintSubOptions,
  type ChainResult,
} from "./token.js";

export {
  addMonthsUtc,
  windowMonthsForTier,
  disclosureForMaster,
} from "./eval.js";

export { status, describeState, type StatusInput } from "./status.js";

export { b64urlEncode, b64urlDecode, canonicalJson } from "./encoding.js";
