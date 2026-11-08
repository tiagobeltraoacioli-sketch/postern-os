// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Postern Labs and Postern community contributors
//
// Ed25519 key handling for the repro-verifier POC. Direct, unmodified-logic
// port of apps/postern-store/repo-poc/lib/keys.mjs (itself a port of
// enterprise/licensing/src/keys.ts) — same raw 32-byte keys, same DER
// prefixes, same node:crypto primitives, same keyId() scheme. Reused here
// rather than imported across the repo-poc/repro-verifier boundary because
// this directory must stand alone and be testable/committable independent of
// repo-poc's presence (repo-poc is not yet committed anywhere in this repo's
// history as of this branch).
//
// This is the signing primitive docs/store-fdroid/02-reproducible-builds.md
// §5's `signature` block names as a placeholder ("no PQ signature exists for
// build-attestation records; only Consiglio login uses the Falcon-1024‖
// ML-DSA-65 hybrid today") — Ed25519 is the honest, real, non-placeholder
// scheme this implementation actually ships today. SIGNING.md's own framing
// ("Ed25519-now is forward-compatible... a subset of what TUF roles carry")
// applies identically to per-build-record signing.

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as nodeSign,
  verify as nodeVerify,
} from "node:crypto";

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

function b64(bytes) {
  return Buffer.from(bytes).toString("base64");
}

function unb64(s) {
  return Buffer.from(s, "base64");
}

/** Generate a fresh Ed25519 keypair as raw base64 material. */
export function generateKeypair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const jwkPub = publicKey.export({ format: "jwk" });
  const jwkPriv = privateKey.export({ format: "jwk" });
  if (!jwkPub.x || !jwkPriv.d) throw new Error("failed to export Ed25519 JWK");
  return {
    publicKey: b64(Buffer.from(jwkPub.x, "base64url")),
    privateKey: b64(Buffer.from(jwkPriv.d, "base64url")),
  };
}

function publicKeyObject(rawPubB64) {
  const raw = unb64(rawPubB64);
  if (raw.length !== 32) throw new Error("Ed25519 public key must be 32 bytes");
  const der = Buffer.concat([ED25519_SPKI_PREFIX, raw]);
  return createPublicKey({ key: der, format: "der", type: "spki" });
}

function privateKeyObject(rawPrivB64) {
  const raw = unb64(rawPrivB64);
  if (raw.length !== 32) throw new Error("Ed25519 private seed must be 32 bytes");
  const der = Buffer.concat([ED25519_PKCS8_PREFIX, raw]);
  return createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

/** Detached-sign `message` (Uint8Array/Buffer) with a raw private key. Returns RAW 64-byte Buffer. */
export function ed25519SignRaw(rawPrivB64, message) {
  return nodeSign(null, Buffer.from(message), privateKeyObject(rawPrivB64));
}

/** Verify a RAW 64-byte detached signature over `message` with a raw public key.
 *  Never throws — a malformed key/sig is a verification FAILURE, not an exception,
 *  matching repo-poc's "never throws, degrades honestly" rule. */
export function ed25519VerifyRaw(rawPubB64, message, sigBytes) {
  try {
    if (!sigBytes || sigBytes.length !== 64) return false;
    return nodeVerify(null, Buffer.from(message), publicKeyObject(rawPubB64), Buffer.from(sigBytes));
  } catch {
    return false;
  }
}

/** Same keyId() scheme as enterprise/licensing/src/keys.ts and repo-poc: first 16
 *  hex chars of sha256(pubkey_b64). Used here to derive a short builder key
 *  fingerprint for display, independent of the builder's own chosen `id` string. */
export function keyId(rawPubB64) {
  return createHash("sha256").update(rawPubB64).digest("hex").slice(0, 16);
}

export function sha256Hex(bytes) {
  return createHash("sha256").update(Buffer.from(bytes)).digest("hex");
}
