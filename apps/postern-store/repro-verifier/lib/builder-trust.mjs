// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Postern Labs and Postern community contributors
//
// THE RED-TEAM #2 FIX.
//
// MOVED to apps/postern-store/reproducible-build-record.mjs as part of the
// Depot M4 fix (unifying the two independently-invented `reproducible_build`
// schemas — this package's and depot/normalize.mjs's — into one canonical
// shape depot now also consumes via this same trust-store implementation).
// This module now re-exports the shared implementation unchanged, so every
// existing import of `./builder-trust.mjs` in this package keeps working
// without modification.
//
// Bug being closed: a naive client-side badge decision that trusts
// `tier === "attestable-nix" && record.result.verdict === "PASS"` alone is
// forgeable by ANY repo operator — they just write a `reproducible_build`
// JSON block claiming PASS, no build ever ran, no independent party checked
// anything. Adding a signature on the record (build-record.mjs) closes half
// of that: now the record can't be *tampered* silently. But a bare signature
// check alone is still forgeable, because a self-consistent signature proves
// only "whoever wrote this record also held the private key for the public
// key embedded right next to it" — an attacker can generate their own
// keypair, embed their own pubkey as `builder_identity`, and sign with the
// matching privkey. The signature verifies. The badge would still be earned.
// That is the exact shape of the red-team #2 finding.
//
// The fix: `builder_identity` is only meaningful if it resolves against a
// TRUST STORE THE CLIENT ITSELF PINS — a small, out-of-band list of builder
// ids the client (or its operator/curator) has decided to trust, each pinned
// to one specific Ed25519 public key. A record's claimed `builder_identity`
// is honored ONLY if:
//   1. its `id` exists in the pinned trust store, AND
//   2. its `pubkey_b64` matches EXACTLY what the trust store pins for that
//      id (not merely "some pubkey the record happens to also carry") —
//      this closes the id-squatting variant, where a forged record reuses a
//      trusted builder's `id` string but substitutes an attacker-controlled
//      key.
// An unknown id, or a known id with a substituted key, is UNTRUSTED — full
// stop, regardless of whether the record's own signature is internally
// valid. A repo (or the record itself) can never self-issue trust; trust is
// pinned by the verifying side, exactly like `CATALOG_PUBKEY_B64` /
// A-repo-client.md's per-repo pinned key, never asserted by the thing being
// verified.

export { makeTrustStore, isTrustedBuilder } from "../../reproducible-build-record.mjs";
