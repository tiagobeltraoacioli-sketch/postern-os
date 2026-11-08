// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Postern Labs and Postern community contributors
//
// Constructs and signs a `reproducible_build` attestation record — the
// interface docs/store-fdroid/02-reproducible-builds.md §5 defines for
// 01-architecture.md's index format, extended here with the two fields that
// close the red-team #2 gap: `builder_identity` (who signed this) and a
// real (not placeholder) `signature` over the record's own canonical bytes.
//
// §5's own placeholder comment says: "Today: no PQ signature exists for
// build-attestation records... This field is a placeholder for when the
// Depot anchors this record's hash to the chain and signs it." This module
// fills that placeholder in for real, with Ed25519 (the same primitive
// SIGNING.md already uses for catalog.json, and the same one
// A-repo-client.md uses for index.json) — honest about scope: this is
// today's real signing scheme, not the future Falcon-1024‖ML-DSA-65 hybrid
// `chain_anchor` field still reserves room for.

import { ed25519SignRaw, sha256Hex } from "./keys.mjs";
import { canonicalRecordBytes } from "./canonical.mjs";
import { REPRODUCIBLE_BUILD_SCHEMA } from "../../reproducible-build-record.mjs";

/**
 * Assemble the unsigned fields of a `reproducible_build` record, matching
 * 02-reproducible-builds.md §5's schema (source/build_env/output/result/run)
 * verbatim, plus `builder_identity`/`signature` left null until signRecord()
 * fills them in. The `schema` marker is the Depot M4 fix's addition — see
 * apps/postern-store/reproducible-build-record.mjs's header — so any
 * consumer can positively identify (and reject a foreign/legacy shape of)
 * this record with one field check.
 */
export function buildRecord({ appId, version, source, buildEnv, output, result, run }) {
  return {
    schema: REPRODUCIBLE_BUILD_SCHEMA,
    app_id: appId,
    version,
    source,
    build_env: buildEnv,
    output,
    result,
    run,
    builder_identity: null, // filled by signRecord()
    signature: null, // filled by signRecord()
  };
}

/**
 * Sign a record with ONE builder's own Ed25519 key — this is the record's
 * OWN independent signature (red-team #2's fix), distinct from and never a
 * substitute for the repo/catalog's own Ed25519 signature over the whole
 * index (SIGNING.md / A-repo-client.md). A repo operator holding the
 * catalog signing key does NOT thereby gain the ability to author a valid
 * build-record signature — that requires a specific builder's own key,
 * which the verifying client must separately have pinned as trusted
 * (builder-trust.mjs) for the badge to mean anything.
 *
 * @param {object} record   output of buildRecord()
 * @param {{builderId: string, builderPrivKeyB64: string, builderPubKeyB64: string}} builder
 */
export function signRecord(record, { builderId, builderPrivKeyB64, builderPubKeyB64 }) {
  if (!builderId || !builderPrivKeyB64 || !builderPubKeyB64) {
    throw new Error("signRecord requires builderId, builderPrivKeyB64, and builderPubKeyB64");
  }
  const unsigned = {
    ...record,
    builder_identity: { id: builderId, pubkey_b64: builderPubKeyB64 },
    signature: null,
  };
  const bytes = canonicalRecordBytes(unsigned); // canonicalRecordBytes always strips `signature` regardless
  const sigBytes = ed25519SignRaw(builderPrivKeyB64, bytes);
  return {
    ...unsigned,
    signature: {
      scheme: "ed25519", // real, today's scheme — see header comment re: §5's PQ placeholder
      signature_b64: sigBytes.toString("base64"),
      signed_bytes_sha256: sha256Hex(bytes), // integrity aid for CI logs/debugging, not itself load-bearing
      chain_anchor: null, // still future, per §5 — unchanged by this implementation
    },
  };
}
