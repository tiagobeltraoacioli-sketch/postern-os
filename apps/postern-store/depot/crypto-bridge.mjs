// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Postern Labs and Postern community contributors
//
// Depot's ONLY crypto entry point. Every primitive here is re-exported,
// not reimplemented, from enterprise/licensing/src/{keys.ts,encoding.ts} —
// the same Ed25519 (node:crypto, raw 32-byte keys) and canonical-JSON
// (sorted-key JSON.stringify) code the licensing/CRL stack already ships
// and has its own test coverage for. Depot does not vendor a second Ed25519
// implementation.
//
// enterprise/licensing is a `tsc`-built package (dist/ is gitignored,
// per enterprise/licensing/.gitignore). This bridge builds it on first use
// if dist/index.js is missing, so `node test/test-depot.mjs` works out of
// the box on a clean checkout — matching the "HOST-testable" bar: no manual
// prep step required beyond having npm/node available.
//
// NOTE ON THE STORE'S EXISTING SCHEME vs THIS ONE:
// apps/postern-store/SIGNING.md signs the EXACT SERVED BYTES of catalog.json
// with a raw 64-byte detached signature (no canonicalization — signer and
// verifier agree on bytes trivially because nothing reserializes the file).
// Depot's per-repo INDEX signature (repo-client.mjs) keeps that exact
// same scheme unchanged (bytes-as-served) — that is what makes it
// backward-compatible with today's catalog.json.sig. Canonical JSON
// (encoding.ts's canonicalJson) is used ONLY for the NEW, second signature
// this build adds: the reproducible_build attestation record's own
// independent signature (red-team fix #2) and the Depot CRL — both are
// small in-band records with no "exact served bytes" file to sign, so they
// need a reproducible serialization instead, which is exactly what
// canonicalJson is for.

import { existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const licensingDir = join(here, "..", "..", "..", "enterprise", "licensing");
const distEntry = join(licensingDir, "dist", "index.js");

let _mod = null;
async function licensing() {
  if (_mod) return _mod;
  if (!existsSync(distEntry)) {
    // Build once, synchronously, exactly like console-crl-enforce.test.mjs's
    // own documented precondition ("Run AFTER `npm run build`") — we just
    // don't require the caller to remember to do it by hand.
    if (!existsSync(join(licensingDir, "node_modules"))) {
      execFileSync("npm", ["install", "--no-audit", "--no-fund"], { cwd: licensingDir, stdio: "inherit" });
    }
    execFileSync("npm", ["run", "build"], { cwd: licensingDir, stdio: "inherit" });
  }
  _mod = await import(join(licensingDir, "dist", "index.js"));
  return _mod;
}

// index.ts's public barrel doesn't re-export `utf8` (encoding.ts's own,
// narrower public surface for @postern/licensing) — reach it directly off
// the built encoding.js module rather than widening licensing's package API
// just for Depot's convenience.
let _encodingMod = null;
async function encodingModule() {
  if (_encodingMod) return _encodingMod;
  await licensing(); // ensures dist/ is built first
  _encodingMod = await import(join(licensingDir, "dist", "encoding.js"));
  return _encodingMod;
}

/** Detached-sign `message` (Uint8Array) with a raw base64 Ed25519 private key. Returns base64 signature. */
export async function ed25519Sign(rawPrivB64, message) {
  const { ed25519Sign: sign } = await licensing();
  return sign(rawPrivB64, message);
}

/** Verify a base64 detached signature over `message` (Uint8Array) with a raw base64 Ed25519 public key. */
export async function ed25519Verify(rawPubB64, message, sigB64) {
  const { ed25519Verify: verify } = await licensing();
  return verify(rawPubB64, message, sigB64);
}

/** Generate a fresh raw-base64 Ed25519 keypair (enterprise/licensing/src/keys.ts). */
export async function generateKeypair() {
  const { generateKeypair: gen } = await licensing();
  return gen();
}

/** Short deterministic key id: first 16 hex chars of SHA-256(raw pubkey base64). */
export async function keyId(rawPubB64) {
  const { keyId: kid } = await licensing();
  return kid(rawPubB64);
}

/** Deterministic sorted-key JSON serialization (enterprise/licensing/src/encoding.ts). */
export async function canonicalJson(value) {
  const { canonicalJson: cj } = await licensing();
  return cj(value);
}

/** UTF-8 encode a string to bytes (enterprise/licensing/src/encoding.ts). */
export async function utf8(s) {
  const { utf8: u8 } = await encodingModule();
  return u8(s);
}

/** base64 -> Uint8Array (standard, not url-safe — matches raw sig/key encoding throughout this scheme). */
export function b64ToBytes(s) {
  return new Uint8Array(Buffer.from(s, "base64"));
}

/** Uint8Array -> base64 (standard). */
export function bytesToB64(bytes) {
  return Buffer.from(bytes).toString("base64");
}

/**
 * Verify a RAW 64-byte detached Ed25519 signature over exact bytes — the
 * scheme apps/postern-store/SIGNING.md already ships (openssl pkeyutl
 * -rawin, no base64 wrapper, no canonicalization). This is the primitive
 * repo-client.mjs's per-repo index-signature check is built on, generalized
 * from one hardcoded CATALOG_PUBKEY_B64 to any pinned repo key.
 *
 * Returns a tri-state, mirroring index.html's resolveCatalogTrust():
 *   - { ok: true }                         signature verifies
 *   - { ok: false, throws: false }         signature present, well-formed, does NOT verify (TAMPERED)
 *   - { ok: false, throws: true, error }   key material or signature bytes could not even be
 *                                          checked (e.g. pinned key is not a valid 32-byte
 *                                          Ed25519 point) — UNVERIFIABLE, not TAMPERED: we could
 *                                          not run the check at all, so we must not claim we did.
 */
export async function verifyRawDetached(pubkeyB64, sigBytes, messageBytes) {
  if (!(sigBytes instanceof Uint8Array) || sigBytes.length !== 64) {
    return { ok: false, throws: true, error: "signature is not exactly 64 raw bytes" };
  }
  // keys.ts's ed25519Verify swallows key-material errors internally (returns
  // false, not a throw) — validate key shape HERE first so a malformed
  // pinned key surfaces as UNVERIFIABLE ("could not check"), never TAMPERED
  // ("checked, and it's wrong"). A wrong-but-well-formed key legitimately
  // falls through to a clean `false` below, which IS a real TAMPERED.
  let pubBytes;
  try {
    pubBytes = b64ToBytes(pubkeyB64);
  } catch (err) {
    return { ok: false, throws: true, error: `pinned key is not valid base64: ${err.message}` };
  }
  if (pubBytes.length !== 32) {
    return { ok: false, throws: true, error: `pinned key is ${pubBytes.length} bytes, not the required 32` };
  }
  try {
    const ok = await ed25519Verify(pubkeyB64, messageBytes, bytesToB64(sigBytes));
    return { ok, throws: false };
  } catch (err) {
    return { ok: false, throws: true, error: String(err && err.message ? err.message : err) };
  }
}

/** Sign exact bytes with the raw-64-byte-detached scheme; returns Uint8Array(64). */
export async function signRawDetached(privB64, messageBytes) {
  const sigB64 = await ed25519Sign(privB64, messageBytes);
  const bytes = b64ToBytes(sigB64);
  if (bytes.length !== 64) throw new Error("unexpected Ed25519 signature length");
  return bytes;
}
