// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Postern Labs and Postern community contributors
//
// Tests for the UNAUDITED minimal TUF-style role layer (lib/tuf-roles.mjs)
// over the postern.repo/v1 PoC: full-chain happy path, threshold refusal,
// expiry refusal (fail-closed), per-role anti-rollback, root rotation
// authorized vs unauthorized by the OLD root, and tampered bytes. Run with:
//   node --test test/tuf-roles.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";

import { generateKeypair } from "../lib/keys.mjs";
import { buildSignedIndex } from "../lib/build-index.mjs";
import {
  buildRoot,
  buildTargets,
  buildSnapshot,
  buildTimestamp,
  signRole,
  verifyTufChain,
  TUF_STATE,
  TUF_REFUSAL,
} from "../lib/tuf-roles.mjs";

// Deterministic clock: every expiry below is relative to this fixed "now".
const NOW = Date.parse("2026-07-14T00:00:00Z");
const FRESH = "2027-01-01T00:00:00Z"; // in the future relative to NOW
const STALE = "2026-01-01T00:00:00Z"; // in the past relative to NOW

// Role keypairs. Root gets TWO keys with threshold 2 so both the threshold
// and the rotation tests exercise a real multi-signature requirement.
const rootKp1 = generateKeypair();
const rootKp2 = generateKeypair();
const targetsKp = generateKeypair();
const snapshotKp = generateKeypair();
const timestampKp = generateKeypair();

// The index being protected is the PoC's real signed index — this layer is
// additive over it, so reuse the existing builder for the exact served bytes.
const repoKp = generateKeypair();
const { indexBytes } = buildSignedIndex({
  privateKeyB64: repoKp.privateKey,
  publicKeyB64: repoKp.publicKey,
  timestamp: 1_800_000_000,
});

function buildChain(overrides = {}) {
  const rootSigned = buildRoot({
    version: 1,
    expires: FRESH,
    roleKeys: {
      root: [rootKp1.publicKey, rootKp2.publicKey],
      targets: [targetsKp.publicKey],
      snapshot: [snapshotKp.publicKey],
      timestamp: [timestampKp.publicKey],
    },
    thresholds: { root: 2, targets: 1, snapshot: 1, timestamp: 1 },
    ...overrides.root,
  });
  const rootEnvelope = signRole(rootSigned, overrides.rootSigners ?? [rootKp1, rootKp2]);

  const targetsSigned = buildTargets({ version: 1, expires: FRESH, indexBytes, ...overrides.targets });
  const targetsEnvelope = signRole(targetsSigned, overrides.targetsSigners ?? [targetsKp]);

  const snapshotSigned = buildSnapshot({ version: 1, expires: FRESH, targetsSigned, ...overrides.snapshot });
  const snapshotEnvelope = signRole(snapshotSigned, [snapshotKp]);

  const timestampSigned = buildTimestamp({ version: 1, expires: overrides.timestampExpires ?? FRESH, snapshotSigned });
  const timestampEnvelope = signRole(timestampSigned, [timestampKp]);

  return { rootEnvelope, targetsEnvelope, snapshotEnvelope, timestampEnvelope };
}

test("1. happy path: full chain root -> timestamp -> snapshot -> targets -> index bytes verifies", () => {
  const chain = buildChain();
  const result = verifyTufChain({ ...chain, indexBytes, nowMs: NOW });

  assert.equal(result.state, TUF_STATE.VERIFIED, result.reason);
  assert.equal(result.code, null);
  assert.deepEqual(result.roleVersions, { root: 1, timestamp: 1, snapshot: 1, targets: 1 });
});

test("2. signature threshold not met -> REFUSED (root role needs 2, gets 1)", () => {
  const chain = buildChain({ rootSigners: [rootKp1] }); // one of two required root sigs
  const result = verifyTufChain({ ...chain, indexBytes, nowMs: NOW });

  assert.equal(result.state, TUF_STATE.REFUSED);
  assert.equal(result.role, "root");
  assert.equal(result.code, TUF_REFUSAL.THRESHOLD_NOT_MET);
});

test("2b. duplicate signatures by the SAME key cannot fake a threshold", () => {
  const chain = buildChain({ rootSigners: [rootKp1, rootKp1] }); // same key twice
  const result = verifyTufChain({ ...chain, indexBytes, nowMs: NOW });

  assert.equal(result.state, TUF_STATE.REFUSED);
  assert.equal(result.code, TUF_REFUSAL.THRESHOLD_NOT_MET, "two signatures from one key must count as one");
});

test("3. expired role -> REFUSED (timestamp expired; every role is expiry-checked)", () => {
  const chain = buildChain({ timestampExpires: STALE });
  const result = verifyTufChain({ ...chain, indexBytes, nowMs: NOW });

  assert.equal(result.state, TUF_STATE.REFUSED);
  assert.equal(result.role, "timestamp");
  assert.equal(result.code, TUF_REFUSAL.EXPIRED);
});

test("3b. missing/unparseable expiry is FAIL-CLOSED, not a pass", () => {
  const chain = buildChain({ timestampExpires: "not-a-date" });
  const result = verifyTufChain({ ...chain, indexBytes, nowMs: NOW });

  assert.equal(result.state, TUF_STATE.REFUSED);
  assert.equal(result.role, "timestamp");
  assert.equal(result.code, TUF_REFUSAL.MALFORMED);
});

test("4. per-role version rollback -> REFUSED (client already adopted snapshot v5)", () => {
  const chain = buildChain(); // snapshot version 1
  const result = verifyTufChain({
    ...chain,
    indexBytes,
    nowMs: NOW,
    previousVersions: { snapshot: 5 },
  });

  assert.equal(result.state, TUF_STATE.REFUSED);
  assert.equal(result.role, "snapshot");
  assert.equal(result.code, TUF_REFUSAL.ROLLBACK);
});

test("5. root rotation signed by a threshold of the OLD root's keys -> accepted", () => {
  // Old root (v1): root threshold 2 over rootKp1+rootKp2.
  const oldChain = buildChain();
  const trustedRoot = oldChain.rootEnvelope;

  // New root (v2): entirely NEW keys for every role.
  const newRootKp = generateKeypair();
  const newTargetsKp = generateKeypair();
  const newSnapshotKp = generateKeypair();
  const newTimestampKp = generateKeypair();

  const newRootSigned = buildRoot({
    version: 2,
    expires: FRESH,
    roleKeys: {
      root: [newRootKp.publicKey],
      targets: [newTargetsKp.publicKey],
      snapshot: [newSnapshotKp.publicKey],
      timestamp: [newTimestampKp.publicKey],
    },
    thresholds: { root: 1, targets: 1, snapshot: 1, timestamp: 1 },
  });
  // Signed by BOTH old root keys (meets the old threshold of 2) AND the new
  // root key (meets its own declared threshold) — TUF's dual requirement.
  const newRootEnvelope = signRole(newRootSigned, [rootKp1, rootKp2, newRootKp]);

  const targetsSigned = buildTargets({ version: 1, expires: FRESH, indexBytes });
  const snapshotSigned = buildSnapshot({ version: 1, expires: FRESH, targetsSigned });
  const timestampSigned = buildTimestamp({ version: 1, expires: FRESH, snapshotSigned });

  const result = verifyTufChain({
    rootEnvelope: newRootEnvelope,
    targetsEnvelope: signRole(targetsSigned, [newTargetsKp]),
    snapshotEnvelope: signRole(snapshotSigned, [newSnapshotKp]),
    timestampEnvelope: signRole(timestampSigned, [newTimestampKp]),
    indexBytes,
    trustedRoot,
    nowMs: NOW,
  });

  assert.equal(result.state, TUF_STATE.VERIFIED, result.reason);
  assert.equal(result.roleVersions.root, 2);
});

test("6. root rotation NOT signed by the old root -> REFUSED as unauthorized", () => {
  const oldChain = buildChain();
  const trustedRoot = oldChain.rootEnvelope;

  // Attacker mints a "new root" over keys they control and signs it ONLY
  // with those new keys — nobody the client currently trusts vouched for it.
  const attackerRootKp = generateKeypair();
  const attackerRoleKp = generateKeypair();
  const attackerRootSigned = buildRoot({
    version: 2,
    expires: FRESH,
    roleKeys: {
      root: [attackerRootKp.publicKey],
      targets: [attackerRoleKp.publicKey],
      snapshot: [attackerRoleKp.publicKey],
      timestamp: [attackerRoleKp.publicKey],
    },
    thresholds: { root: 1, targets: 1, snapshot: 1, timestamp: 1 },
  });
  const attackerRootEnvelope = signRole(attackerRootSigned, [attackerRootKp]); // self-signed only

  const targetsSigned = buildTargets({ version: 1, expires: FRESH, indexBytes });
  const snapshotSigned = buildSnapshot({ version: 1, expires: FRESH, targetsSigned });
  const timestampSigned = buildTimestamp({ version: 1, expires: FRESH, snapshotSigned });

  const result = verifyTufChain({
    rootEnvelope: attackerRootEnvelope,
    targetsEnvelope: signRole(targetsSigned, [attackerRoleKp]),
    snapshotEnvelope: signRole(snapshotSigned, [attackerRoleKp]),
    timestampEnvelope: signRole(timestampSigned, [attackerRoleKp]),
    indexBytes,
    trustedRoot,
    nowMs: NOW,
  });

  assert.equal(result.state, TUF_STATE.REFUSED);
  assert.equal(result.role, "root");
  assert.equal(result.code, TUF_REFUSAL.ROTATION_UNAUTHORIZED);
});

test("6b. root rotation to an OLDER version than the trusted root -> REFUSED as rollback", () => {
  const chainV1 = buildChain();
  const rootV2Signed = buildRoot({
    version: 2,
    expires: FRESH,
    roleKeys: {
      root: [rootKp1.publicKey, rootKp2.publicKey],
      targets: [targetsKp.publicKey],
      snapshot: [snapshotKp.publicKey],
      timestamp: [timestampKp.publicKey],
    },
    thresholds: { root: 2 },
  });
  const trustedRootV2 = signRole(rootV2Signed, [rootKp1, rootKp2]);

  // Present the (validly signed!) v1 root against a client that trusts v2.
  const result = verifyTufChain({ ...chainV1, indexBytes, trustedRoot: trustedRootV2, nowMs: NOW });

  assert.equal(result.state, TUF_STATE.REFUSED);
  assert.equal(result.role, "root");
  assert.equal(result.code, TUF_REFUSAL.ROLLBACK);
});

test("7. tampered targets metadata -> REFUSED (snapshot's hash binding catches it)", () => {
  const chain = buildChain();

  // Tamper AFTER snapshot bound it: point index.json's hash at attacker bytes.
  const evilBytes = Buffer.from("attacker-substituted index payload\n");
  const tamperedSigned = buildTargets({ version: 1, expires: FRESH, indexBytes: evilBytes });
  // Even a *validly re-signed* tampered targets is refused, because snapshot
  // binds the exact bytes of the targets metadata the chain was built with.
  const tamperedEnvelope = signRole(tamperedSigned, [targetsKp]);

  const result = verifyTufChain({ ...chain, targetsEnvelope: tamperedEnvelope, indexBytes: evilBytes, nowMs: NOW });

  assert.equal(result.state, TUF_STATE.REFUSED);
  assert.equal(result.role, "snapshot");
  assert.equal(result.code, TUF_REFUSAL.META_MISMATCH);
});

test("7b. tampered target FILE bytes (metadata chain intact) -> REFUSED as target mismatch", () => {
  const chain = buildChain();
  const tamperedIndex = Buffer.concat([Buffer.from(indexBytes)]);
  tamperedIndex[0] ^= 0xff; // flip one bit of the served index.json

  const result = verifyTufChain({ ...chain, indexBytes: tamperedIndex, nowMs: NOW });

  assert.equal(result.state, TUF_STATE.REFUSED);
  assert.equal(result.role, "targets");
  assert.equal(result.code, TUF_REFUSAL.TARGET_MISMATCH);
});

test("8. never throws: garbage inputs degrade to typed refusals, not exceptions", () => {
  const result = verifyTufChain({
    rootEnvelope: { signed: { _type: "root" } }, // no version, no keys, no sigs
    timestampEnvelope: null,
    snapshotEnvelope: undefined,
    targetsEnvelope: 42,
    indexBytes: null,
    nowMs: NOW,
  });
  assert.equal(result.state, TUF_STATE.REFUSED);
  assert.equal(result.code, TUF_REFUSAL.MALFORMED);

  const empty = verifyTufChain(undefined);
  assert.equal(empty.state, TUF_STATE.REFUSED);
});
