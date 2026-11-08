// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Postern Labs and Postern community contributors
//
// Canonical byte encoding for `reproducible_build` attestation records.
//
// MOVED to apps/postern-store/reproducible-build-record.mjs as part of the
// Depot M4 fix (two independently-invented `reproducible_build` schemas —
// this package's and depot/normalize.mjs's — could silently drift; see that
// file's header for the full story). This module now re-exports the shared
// implementation unchanged, so every existing import of `./canonical.mjs`
// in this package keeps working without modification.
//
// Unlike apps/postern-store/repo-poc's index.json ("sign the file, don't
// canonicalize it" — A-repo-client.md §1.3, valid there because signer and
// verifier both hold the exact same served bytes end to end), a
// `reproducible_build` record is a small JSON object that gets embedded,
// re-serialized, and re-nested inside larger documents (a catalog entry, a
// CI log, this repo's own test fixtures) between the moment a builder signs
// it and the moment a client verifies it. There is no single "exact served
// bytes" both sides are guaranteed to hold byte-identically. So this
// record's signature covers CANONICAL bytes instead: a deterministic,
// sorted-key JSON serialization of the record with the `signature` field
// itself excluded (a signature cannot cover its own bytes). Both
// build-record.mjs's signRecord() and verify-record.mjs's
// verifyBuildRecord() MUST call this same function on the same shape
// (signature stripped) or signatures will not round-trip — deliberate, not
// a shortcut.

export { canonicalRecordBytes } from "../../reproducible-build-record.mjs";
