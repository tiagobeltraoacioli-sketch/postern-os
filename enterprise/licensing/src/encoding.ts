// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Postern Labs and Postern community contributors
//
// Base64url + canonical-JSON helpers. Canonicalisation matters: the signed
// bytes must be reproducible byte-for-byte on the verifying side, so we sort
// object keys deterministically before signing and before checking a signature.

/** Encode bytes as unpadded base64url. */
export function b64urlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/** Decode unpadded (or padded) base64url to bytes. */
export function b64urlDecode(s: string): Uint8Array {
  const norm = s.replace(/-/g, "+").replace(/_/g, "/");
  return new Uint8Array(Buffer.from(norm, "base64"));
}

/**
 * Deterministic JSON serialisation: object keys are emitted in sorted order at
 * every level, arrays keep their order. Undefined-valued keys are dropped.
 * This is what we sign over, so signer and verifier agree on the exact bytes.
 */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortDeep(value));
}

function sortDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortDeep);
  if (value && typeof value === "object") {
    const src = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(src).sort()) {
      if (src[key] === undefined) continue;
      out[key] = sortDeep(src[key]);
    }
    return out;
  }
  return value;
}

/** UTF-8 encode a string to bytes. */
export function utf8(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "utf8"));
}
