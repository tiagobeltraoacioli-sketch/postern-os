// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Postern Labs and Postern community contributors
//
// Ed25519 key handling for the postern.repo/v1 POC — a direct, unmodified-logic
// port of enterprise/licensing/src/keys.ts to plain ESM (this POC is a
// HOST-side Node script, not a browser build, so node:crypto is used exactly
// as the license spine already uses it: no third-party crypto dependency,
// raw 32-byte keys / standard base64, same DER prefixes, same keyId() scheme).
//
// This is the SAME primitive docs/store-fdroid/A-repo-client.md §2.1 specifies
// for index.json.sig ("detached Ed25519 over the exact served bytes") — the
// only difference from apps/postern-store/SIGNING.md's browser-side verifier
// is the runtime (node:crypto here vs SubtleCrypto in index.html); the maths
// and the byte-exactness rule are identical.

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

/** Detached-sign `message` (Uint8Array/Buffer) with a raw private key. Returns RAW 64-byte Buffer,
 *  matching SIGNING.md's "raw 64 bytes, NOT base64-wrapped" requirement for index.json.sig. */
export function ed25519SignRaw(rawPrivB64, message) {
  return nodeSign(null, Buffer.from(message), privateKeyObject(rawPrivB64));
}

/** Verify a RAW 64-byte detached signature over `message` with a raw public key.
 *  Never throws — a malformed key/sig is a verification FAILURE, not an exception,
 *  matching resolveCatalogTrust()'s "never throws, degrades honestly" rule. */
export function ed25519VerifyRaw(rawPubB64, message, sigBytes) {
  try {
    if (!sigBytes || sigBytes.length !== 64) return false;
    return nodeVerify(null, Buffer.from(message), publicKeyObject(rawPubB64), Buffer.from(sigBytes));
  } catch {
    return false;
  }
}

/** Same keyId() scheme as enterprise/licensing/src/keys.ts and the short id
 *  A-repo-client.md §1.2 says the client persists a repo record under
 *  ("reuse keyId() from enterprise/licensing/src/keys.ts, first 16 hex chars
 *  of sha256(pubkey_b64), unchanged"). */
export function keyId(rawPubB64) {
  return createHash("sha256").update(rawPubB64).digest("hex").slice(0, 16);
}

export function sha256Hex(bytes) {
  return createHash("sha256").update(Buffer.from(bytes)).digest("hex");
}
