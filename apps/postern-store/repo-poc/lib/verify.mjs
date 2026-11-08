// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Postern Labs and Postern community contributors
//
// The client-side verifier for a postern.repo/v1 index. This is a
// HOST-side (Node) port of resolveCatalogTrust() (apps/postern-store/
// index.html) generalized per A-repo-client.md §3.2 from "the one hardcoded
// key" to "the pinned key of the repo being fetched" — same trust states,
// same ordering (verify signature -> check anti-rollback -> adopt -> re-run
// honesty invariants), same "never throws, degrades honestly" rule.
//
// Trust states, verbatim from A-repo-client.md §3.2's table:
//   UNSIGNED      no .sig present, or nothing pinned yet to compare against
//   VERIFIED      .sig valid against THIS repo's pinned key
//   TAMPERED      .sig present but invalid for the pinned key — fetch rejected
//   UNVERIFIABLE  this engine's WebCrypto (here: this host) has no Ed25519
//
// Honest note found while building this POC (see final report): the doc's
// table has no separate state for "the index verifies, but against a
// DIFFERENT key than the one the client pinned." Per §3.1 ("a mismatch is
// refused outright") that case IS a rejection, and mechanically it takes the
// TAMPERED branch below — attempting to verify bytes with the wrong public
// key fails signature verification exactly like a bit-flipped payload does.
// UNVERIFIABLE is reserved, per the doc, for "this engine cannot check
// Ed25519 signatures at all" (a capability gap), not "the wrong key was
// supplied." This module keeps that distinction instead of collapsing it.

import { ed25519VerifyRaw, sha256Hex } from "./keys.mjs";
import { normalizeEntry } from "./normalize.mjs";

export const TRUST = Object.freeze({
  UNSIGNED: "UNSIGNED",
  VERIFIED: "VERIFIED",
  TAMPERED: "TAMPERED",
  UNVERIFIABLE: "UNVERIFIABLE",
});

/**
 * @param {object} opts
 * @param {Buffer|Uint8Array} opts.indexBytes   exact served bytes of index.json
 * @param {Buffer|Uint8Array|null} opts.sigBytes raw 64-byte detached signature, or null/absent
 * @param {string|null} opts.pinnedPubKeyB64    the client's pinned key for this repo record (null = TOFU candidate, nothing pinned yet)
 * @param {boolean} [opts.engineHasEd25519=true] simulates ed25519Available() — false reproduces the "this browser can't verify" honest fallback
 * @param {number|null} [opts.previousTimestamp=null] last-adopted repo.timestamp for this pinned key (anti-rollback, §1.3)
 * @param {Record<string, Buffer|Uint8Array>} [opts.artifacts={}] appId -> actual fetched bytes, for per-package checksum verification (§1.4)
 */
export function verifyRepoIndex(opts) {
  const {
    indexBytes,
    sigBytes,
    pinnedPubKeyB64,
    engineHasEd25519 = true,
    previousTimestamp = null,
    artifacts = {},
  } = opts;

  const base = { adopted: false, index: null, apps: [], strippedByApp: {}, checksumResults: [], rollback: false };

  if (!pinnedPubKeyB64) {
    return { ...base, state: TRUST.UNSIGNED, reason: "No key pinned for this repo yet — nothing to compare a signature against (TOFU candidate)." };
  }
  if (!sigBytes || sigBytes.length !== 64) {
    return { ...base, state: TRUST.UNSIGNED, reason: "No detached signature (index.json.sig) is published alongside the index, or it is not exactly 64 raw bytes." };
  }
  if (!engineHasEd25519) {
    return { ...base, state: TRUST.UNVERIFIABLE, reason: "This engine's Ed25519 verifier is unavailable — honest 'can't verify here', never a guess." };
  }

  const ok = ed25519VerifyRaw(pinnedPubKeyB64, indexBytes, sigBytes);
  if (!ok) {
    return {
      ...base,
      state: TRUST.TAMPERED,
      reason: "Signature is present but does NOT verify against this repo's pinned key — the fetched copy is rejected; any previously-cached verified index stands.",
    };
  }

  // Signature verifies against the pinned key. Now parse and run the
  // remaining, non-cryptographic checks §3.2/§1.3 require before adoption.
  let parsed;
  try {
    parsed = JSON.parse(Buffer.from(indexBytes).toString("utf8"));
  } catch {
    return { ...base, state: TRUST.TAMPERED, reason: "Signature verified, but the bytes are not valid JSON — treated as tampered/corrupt, rejected." };
  }

  const result = { ...base, state: TRUST.VERIFIED, index: parsed };

  // §1.1: repo.pubkey_b64 MUST equal the key that produced the signature —
  // redundant-but-checked. It already does (we just verified against it),
  // but a repo that publishes a mismatching self-declared pubkey_b64 is lying
  // about its own identity block, which is itself worth flagging.
  if (parsed?.repo?.pubkey_b64 && parsed.repo.pubkey_b64 !== pinnedPubKeyB64) {
    result.selfDeclaredKeyMismatch = true;
  }

  // §1.3 anti-rollback: reject adoption (not the signature) of a stale timestamp.
  const ts = parsed?.repo?.timestamp;
  if (previousTimestamp !== null && typeof ts === "number" && ts < previousTimestamp) {
    result.rollback = true;
    result.reason = `Signature valid, but repo.timestamp (${ts}) is older than the last-adopted timestamp (${previousTimestamp}) for this pinned key — rejected as a rollback attempt, not adopted.`;
    return result; // adopted stays false
  }

  result.adopted = true;
  result.reason = "Detached Ed25519 signature is valid for this repo's pinned key, and repo.timestamp is not a rollback.";

  // §3.3: re-run normalizeEntry's honesty invariants on EVERY entry, from
  // every repo, regardless of the (valid) signature — a signed lie is still
  // a lie; the signature only proves who told it.
  const apps = Array.isArray(parsed.apps) ? parsed.apps : [];
  for (const raw of apps) {
    const { entry, stripped } = normalizeEntry(raw);
    result.apps.push(entry);
    if (stripped.length) result.strippedByApp[entry.id] = stripped;
  }

  // §1.4: per-package integrity. Only meaningful because the index that
  // carries the checksum already verified above — a checksum inside an
  // unsigned/tampered index proves nothing (this function never reaches here
  // unless the index verified).
  for (const entry of result.apps) {
    const claimed = entry.dist.checksum; // "sha256:<hex>" or null
    if (!claimed) continue;
    const actualBytes = artifacts[entry.id];
    if (!actualBytes) {
      result.checksumResults.push({ id: entry.id, status: "not-fetched", claimed });
      continue;
    }
    const [, hex] = claimed.split(":");
    const actualHex = sha256Hex(actualBytes);
    result.checksumResults.push({
      id: entry.id,
      status: actualHex === hex ? "match" : "mismatch",
      claimed,
      actual: `sha256:${actualHex}`,
    });
  }

  return result;
}
