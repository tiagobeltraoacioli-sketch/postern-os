// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Postern Labs and Postern community contributors
//
// Ed25519 key handling using Node's built-in `node:crypto` (no third-party
// crypto dependency). Keys are represented as RAW 32-byte values, standard
// base64 — the shape the canonical token format expects for `master_pub` and
// for detached signatures.
//
// We chose Ed25519 for this scaffold because it is available natively in every
// supported Node runtime (and in Cloudflare Workers via WebCrypto) with zero
// deps and produces compact signatures. The token format is versioned (`v:1`)
// so a post-quantum scheme can be introduced later under a new version tag.
//
// KEY MODEL:
//   - The VENDOR holds a private signing key. It is a SERVER SECRET (the site's
//     Pages Function that issues master tokens). It NEVER ships with the apps.
//     Only the vendor PUBLIC key ships, so verification is fully local/offline.
//   - Each ORG that is issued a master token gets its OWN master keypair,
//     generated at issuance. The org keeps the master PRIVATE key to mint sub
//     tokens; the master PUBLIC key travels inside the vendor-signed master
//     token as `master_pub`.
//   - keys/dev-vendor.pub.json holds the clearly-marked SAMPLE/DEV vendor
//     public key used by the CLI demo and docs.

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign as nodeSign,
  verify as nodeVerify,
  type KeyObject,
} from "node:crypto";

// Fixed ASN.1/DER prefixes for Ed25519 keys. Prepending these to a raw 32-byte
// key yields the SPKI (public) / PKCS#8 (private) DER that Node's KeyObject
// importers accept. This lets us carry keys as raw base64 while still using the
// built-in signer.
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

/** A raw Ed25519 keypair, standard base64 (32-byte each). */
export interface RawKeyPair {
  /** base64 of the 32-byte public key. */
  readonly publicKey: string;
  /** base64 of the 32-byte private (seed) key. KEEP SECRET. */
  readonly privateKey: string;
}

function b64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

function unb64(s: string): Buffer {
  return Buffer.from(s, "base64");
}

/** Generate a fresh Ed25519 keypair as raw base64 material. */
export function generateKeypair(): RawKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const jwkPub = publicKey.export({ format: "jwk" }) as { x?: string };
  const jwkPriv = privateKey.export({ format: "jwk" }) as { d?: string };
  if (!jwkPub.x || !jwkPriv.d) throw new Error("failed to export Ed25519 JWK");
  // JWK components are base64url of the raw 32-byte values; re-encode standard.
  return {
    publicKey: b64(Buffer.from(jwkPub.x, "base64url")),
    privateKey: b64(Buffer.from(jwkPriv.d, "base64url")),
  };
}

function publicKeyObject(rawPubB64: string): KeyObject {
  const raw = unb64(rawPubB64);
  if (raw.length !== 32) throw new Error("Ed25519 public key must be 32 bytes");
  const der = Buffer.concat([ED25519_SPKI_PREFIX, raw]);
  return createPublicKey({ key: der, format: "der", type: "spki" });
}

function privateKeyObject(rawPrivB64: string): KeyObject {
  const raw = unb64(rawPrivB64);
  if (raw.length !== 32) throw new Error("Ed25519 private seed must be 32 bytes");
  const der = Buffer.concat([ED25519_PKCS8_PREFIX, raw]);
  return createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

/** Detached-sign `message` with a raw private key; returns base64 signature. */
export function ed25519Sign(rawPrivB64: string, message: Uint8Array): string {
  const sig = nodeSign(null, Buffer.from(message), privateKeyObject(rawPrivB64));
  return b64(new Uint8Array(sig));
}

/** Verify a base64 detached signature over `message` with a raw public key. */
export function ed25519Verify(rawPubB64: string, message: Uint8Array, sigB64: string): boolean {
  try {
    return nodeVerify(null, Buffer.from(message), publicKeyObject(rawPubB64), unb64(sigB64));
  } catch {
    return false;
  }
}

/**
 * A random 128-bit serial (hex) for a token `jti` (D4). CSPRNG-backed. 128 bits
 * is collision-safe for the revocation namespace and carries no meaning of its
 * own — it is only an opaque handle the CRL can list.
 */
export function randomSerial(): string {
  return randomBytes(16).toString("hex");
}

/**
 * A deterministic, short key id (`kid`) for a vendor PUBLIC key (D4). It is the
 * first 16 hex chars of SHA-256(raw-pubkey-base64) — enough to identify which
 * vendor key signed a token/CRL and to drive key rotation. Not a secret.
 */
export function keyId(rawPubB64: string): string {
  return createHash("sha256").update(rawPubB64).digest("hex").slice(0, 16);
}
