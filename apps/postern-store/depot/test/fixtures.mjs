// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Postern Labs and Postern community contributors
//
// Test fixtures for the Depot multi-repo client. Builds real
// postern.catalog/v1 repo documents and signs them with the SAME recipe
// SIGNING.md documents for catalog.json: a raw 64-byte detached Ed25519
// signature over the exact served (UTF-8) bytes of the file, no
// canonicalization. `reproducible_build` attestation records use the ONE
// canonical schema + canonical byte encoding in
// apps/postern-store/reproducible-build-record.mjs (Depot M4 fix) — the
// SAME shape and SAME canonicalization repro-verifier/lib/build-record.mjs
// produces, so a record built HERE (signed with depot's own async
// crypto-bridge Ed25519) and a record built there (signed with
// repro-verifier's own sync node:crypto Ed25519) are interchangeable: either
// one verifies identically through either consumer. See
// depot/test/test-depot.mjs's "cross-producer" test for the proof.

import { generateKeypair, ed25519Sign, signRawDetached } from "../crypto-bridge.mjs";
import { REPRODUCIBLE_BUILD_SCHEMA, canonicalRecordBytes } from "../../reproducible-build-record.mjs";

export async function makeKeypair() {
  return generateKeypair(); // { publicKey, privateKey } raw base64
}

/**
 * Build + sign a repo index. `apps` is an array of raw (pre-normalization)
 * app entries, exactly the shape a repo operator would author by hand.
 * Returns the exact served bytes + detached signature, ready to feed
 * DepotClient.loadRepoIndex().
 */
export async function buildSignedRepo({ repoId, repoName, url, priority = 10, apps, privateKey }) {
  const doc = {
    schema: "postern.catalog/v1",
    generated: "2026-07-13",
    publisher: repoName,
    repo: { id: repoId, name: repoName, url, mirrors: [], description: `${repoName} test fixture repo`, priority },
    apps,
  };
  const bodyStr = JSON.stringify(doc);
  const bytes = new TextEncoder().encode(bodyStr);
  const sigBytes = await signRawDetached(privateKey, bytes);
  return { bytes, sigBytes, doc, bodyStr };
}

/** Tamper with served bytes (flip visible content) while leaving the old signature in place — must fail verification. */
export function tamperBytes(bytes) {
  const s = new TextDecoder().decode(bytes);
  const tampered = s.replace('"generated":"2026-07-13"', '"generated":"2099-01-01"');
  if (tampered === s) throw new Error("tamper fixture didn't find its anchor string");
  return new TextEncoder().encode(tampered);
}

/** Baseline unsigned canonical record fields shared by every fixture below —
 *  one place matching apps/postern-store/reproducible-build-record.mjs's
 *  schema exactly, so a shape drift breaks a fixture loudly, not silently. */
function baseUnsignedRecord({ appId, version, resultOverrides = {} }) {
  return {
    schema: REPRODUCIBLE_BUILD_SCHEMA,
    app_id: appId,
    version,
    source: {
      repo_url: `https://example.invalid/${appId}`,
      commit: "a".repeat(40),
      build_expr: `nixpkgs#${appId}`,
      build_expr_source: "nixpkgs",
      flake_lock_rev: "b".repeat(40),
    },
    build_env: {
      nix_version: "2.24.0",
      system: "x86_64-linux",
      sandbox: "hermetic",
      builder_hosts: ["fixture-builder-a", "fixture-builder-b"],
    },
    output: {
      store_path: `/nix/store/FIXTURE-${appId}-${version}`,
      nar_hash: "sha256:" + "c".repeat(64),
      shipped_artifact_hash: "sha256:" + "d".repeat(64),
    },
    result: { rebuild_match: true, shipped_match: true, verdict: "PASS", diagnostic: null, ...resultOverrides },
    run: { timestamp: "2026-07-13T00:00:00Z", run_by: "fixture-ci@depot-test", verifier_version: "depot-test-fixtures@0.0.0" },
  };
}

/**
 * Build a reproducible_build attestation record and independently sign it
 * with a BUILDER key (never the repo's index key) — the fix for red-team
 * finding #2. `tamperAfterSigning`, if true, mutates the record post-signature
 * so the record and its own signature disagree (forced FAIL of the sig check
 * while still superficially "looking" like a signed PASS record).
 */
export async function buildAttestationRecord({ appId, version, builderIdentity, builderPrivateKey, builderPublicKey, resultOverrides = {}, tamperAfterSigning = false }) {
  const unsigned = {
    ...baseUnsignedRecord({ appId, version, resultOverrides }),
    builder_identity: { id: builderIdentity, pubkey_b64: builderPublicKey },
  };
  const bytes = canonicalRecordBytes(unsigned);
  const signature_b64 = await ed25519Sign(builderPrivateKey, bytes);
  const record = { ...unsigned, signature: { scheme: "ed25519", signature_b64, signed_bytes_sha256: null, chain_anchor: null } };
  if (tamperAfterSigning) {
    record.output = { ...record.output, nar_hash: "sha256:" + "e".repeat(64) }; // mutate post-sign; signature now stale
  }
  return record;
}

/** A record that CLAIMS a builder identity but is entirely unsigned — the naive forgery. */
export function buildForgedAttestationRecord({ appId, version, builderIdentity }) {
  return {
    ...baseUnsignedRecord({ appId, version }),
    builder_identity: { id: builderIdentity, pubkey_b64: "not-a-real-pinned-key==" },
    signature: { scheme: "ed25519", signature_b64: "", signed_bytes_sha256: null, chain_anchor: null }, // no independent signature at all — a repo just typed "PASS"
  };
}

/** A record signed, but by a key the CLIENT never pinned as trusted for that builder_identity. */
export async function buildRecordSignedByUntrustedKey({ appId, version, claimedBuilderIdentity, actualPrivateKey, actualPublicKey }) {
  const unsigned = {
    ...baseUnsignedRecord({ appId, version }),
    builder_identity: { id: claimedBuilderIdentity, pubkey_b64: actualPublicKey }, // id-squatting: claims the trusted id, embeds the ATTACKER's own key
  };
  const bytes = canonicalRecordBytes(unsigned);
  const signature_b64 = await ed25519Sign(actualPrivateKey, bytes);
  return { ...unsigned, signature: { scheme: "ed25519", signature_b64, signed_bytes_sha256: null, chain_anchor: null } };
}
