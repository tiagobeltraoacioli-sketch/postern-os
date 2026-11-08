// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Postern Labs and Postern community contributors
//
// UNAUDITED reference prototype / design preview of the Depot "TUF core"
// (docs/POSTERN-APPS-ROADMAP.md, Depot row: "start the TUF core early").
//
// This is a FROM-SCRATCH, deliberately minimal TUF-style role-metadata layer
// written for this POC — it is NOT the AWS `tough` crate (MIT/Apache), which
// remains the candidate for the production Rust core, and it is NOT a full
// implementation of the TUF specification (no delegations, no mirrors, no
// consistent snapshots, single target file). No F-Droid code and no GPL/AGPL
// code was read or used, per the roadmap's license note. Classical Ed25519
// only for now (via node:crypto through lib/keys.mjs, zero new dependencies);
// PQ signing is a separate future step and is deliberately NOT claimed here.
//
// What it layers over the existing postern.repo/v1 PoC:
//   root      — the trust anchor: the set of role keys, a per-role signature
//               threshold, a version, and an RFC-3339 expiry. Root rotation
//               is only accepted when the NEW root meets the signature
//               threshold of the OLD (currently-trusted) root's root role
//               (and its own, per TUF spec §5.3.4's dual requirement).
//   targets   — binds the exact served bytes of index.json (the PoC's signed
//               app index) by length + sha256. The index's own detached
//               Ed25519 signature (lib/verify.mjs) is unchanged and still
//               applies; this layer is additive.
//   snapshot  — binds the targets metadata (version + sha256 of its signed
//               portion) so a mix-and-match of role files is detectable.
//   timestamp — binds the snapshot metadata the same way; the short-lived,
//               frequently re-signed freshness root of the chain.
//
// Verification chain (verifyTufChain): root -> timestamp -> snapshot ->
// targets -> index bytes, enforcing per role: (a) signature thresholds,
// (b) expiry — fail-closed: a missing/unparseable `expires` is a refusal,
// never a pass, (c) monotonic version anti-rollback (extending the PoC's
// existing repo.timestamp anti-rollback idea to every role), and
// (d) old-root authorization for rotation.
//
// Byte discipline: role metadata is signed over canonicalJson() of the
// `signed` portion (lib/encoding.mjs). This is deliberately the OPPOSITE
// choice from index.json ("sign the file, don't canonicalize it") because
// role metadata has MULTIPLE independent signers who must each produce a
// signature over identical bytes without ever exchanging a serialized file —
// exactly the case A-repo-client.md reserves canonical JSON for. Simplified
// vs the TUF spec: snapshot/timestamp hashes cover the canonical bytes of
// the referenced role's `signed` portion, not the whole metadata file
// (signatures vary per signer and are authenticated separately).
//
// Style: same "never throws, degrades honestly" result-object rule as
// lib/verify.mjs — every outcome is a typed state + machine-readable
// refusal code + human-readable reason; no exceptions cross this API.

import { ed25519SignRaw, ed25519VerifyRaw, keyId, sha256Hex } from "./keys.mjs";
import { canonicalJson } from "./encoding.mjs";

export const TUF_SCHEMA = "postern.depot.tuf/v1-poc";

export const ROLE_NAMES = Object.freeze(["root", "targets", "snapshot", "timestamp"]);

/** Top-level outcome states, mirroring lib/verify.mjs's TRUST enum shape. */
export const TUF_STATE = Object.freeze({
  VERIFIED: "VERIFIED", // full chain verified: thresholds met, nothing expired, no rollback, bytes match
  REFUSED: "REFUSED", // fail-closed refusal — `code` + `role` say exactly why and where
});

/** Machine-readable refusal codes (the `code` field on a REFUSED result). */
export const TUF_REFUSAL = Object.freeze({
  MALFORMED: "MALFORMED", // structurally wrong metadata (wrong _type, missing fields, unparseable expiry — fail-closed)
  THRESHOLD_NOT_MET: "THRESHOLD_NOT_MET", // fewer distinct valid signatures than the role's threshold
  EXPIRED: "EXPIRED", // role's RFC-3339 expiry is in the past
  ROLLBACK: "ROLLBACK", // role version is lower than the last version the client adopted for that role
  ROTATION_UNAUTHORIZED: "ROTATION_UNAUTHORIZED", // new root not signed by a threshold of the OLD root's keys
  META_MISMATCH: "META_MISMATCH", // snapshot/timestamp binding (version or sha256) does not match the actual role metadata
  TARGET_MISMATCH: "TARGET_MISMATCH", // index bytes do not match targets' declared length/sha256
});

/** Exact bytes that get signed/hashed for a role: canonical JSON of `signed`. */
export function roleBytes(signed) {
  return Buffer.from(canonicalJson(signed), "utf8");
}

/**
 * Wrap a role's `signed` object in an envelope with detached Ed25519
 * signatures from each keypair ({ publicKey, privateKey } raw-b64, as
 * produced by lib/keys.mjs generateKeypair()).
 */
export function signRole(signed, keypairs) {
  const bytes = roleBytes(signed);
  return {
    signed,
    signatures: keypairs.map((kp) => ({
      keyid: keyId(kp.publicKey),
      sig_b64: ed25519SignRaw(kp.privateKey, bytes).toString("base64"),
    })),
  };
}

/**
 * Build a root role `signed` object.
 * @param {object} opts
 * @param {number} opts.version              monotonically increasing per rotation
 * @param {string} opts.expires              RFC-3339 (e.g. "2027-01-01T00:00:00Z")
 * @param {Record<string,string[]>} opts.roleKeys   role name -> array of raw-b64 Ed25519 public keys
 * @param {Record<string,number>} [opts.thresholds] role name -> required distinct valid signatures (default 1)
 */
export function buildRoot({ version, expires, roleKeys, thresholds = {} }) {
  const keys = {};
  const roles = {};
  for (const role of ROLE_NAMES) {
    const pubs = roleKeys?.[role] ?? [];
    for (const pub of pubs) keys[keyId(pub)] = { keytype: "ed25519", pubkey_b64: pub };
    roles[role] = { keyids: pubs.map((p) => keyId(p)), threshold: thresholds[role] ?? 1 };
  }
  return { _type: "root", schema: TUF_SCHEMA, version, expires, keys, roles };
}

/** Build a targets role `signed` object binding the exact served index bytes. */
export function buildTargets({ version, expires, indexBytes }) {
  const bytes = Buffer.from(indexBytes);
  return {
    _type: "targets",
    schema: TUF_SCHEMA,
    version,
    expires,
    targets: {
      "index.json": { length: bytes.length, hashes: { sha256: sha256Hex(bytes) } },
    },
  };
}

/** Build a snapshot role `signed` object binding the targets metadata. */
export function buildSnapshot({ version, expires, targetsSigned }) {
  return {
    _type: "snapshot",
    schema: TUF_SCHEMA,
    version,
    expires,
    meta: {
      "targets.json": {
        version: targetsSigned.version,
        hashes: { sha256: sha256Hex(roleBytes(targetsSigned)) },
      },
    },
  };
}

/** Build a timestamp role `signed` object binding the snapshot metadata. */
export function buildTimestamp({ version, expires, snapshotSigned }) {
  return {
    _type: "timestamp",
    schema: TUF_SCHEMA,
    version,
    expires,
    meta: {
      "snapshot.json": {
        version: snapshotSigned.version,
        hashes: { sha256: sha256Hex(roleBytes(snapshotSigned)) },
      },
    },
  };
}

// ---------------------------------------------------------------------------
// Verification internals — every helper returns null on success or a refusal
// result object on failure; nothing in this file throws across the API.
// ---------------------------------------------------------------------------

function refusal(role, code, reason) {
  return { state: TUF_STATE.REFUSED, role, code, reason, roleVersions: null };
}

/** Count DISTINCT authorized keyids with a valid signature over the envelope's
 *  signed bytes. Duplicate signatures by the same keyid count once; signatures
 *  by keys outside the role's keyid list count zero — both per the TUF spec. */
function countValidSignatures(envelope, keyMap, roleKeyids) {
  const bytes = roleBytes(envelope.signed);
  const valid = new Set();
  const sigs = Array.isArray(envelope.signatures) ? envelope.signatures : [];
  for (const s of sigs) {
    if (!s || typeof s.keyid !== "string" || valid.has(s.keyid)) continue;
    if (!roleKeyids.includes(s.keyid)) continue;
    const pub = keyMap?.[s.keyid]?.pubkey_b64;
    if (!pub) continue;
    let sigBytes;
    try {
      sigBytes = Buffer.from(String(s.sig_b64 ?? ""), "base64");
    } catch {
      continue;
    }
    if (ed25519VerifyRaw(pub, bytes, sigBytes)) valid.add(s.keyid);
  }
  return valid.size;
}

/** Threshold check of `envelope` against the role definition inside `rootSigned`. */
function checkThreshold(envelope, roleName, rootSigned, context) {
  const roleDef = rootSigned?.roles?.[roleName];
  if (!roleDef || !Array.isArray(roleDef.keyids) || !Number.isInteger(roleDef.threshold) || roleDef.threshold < 1) {
    return refusal(roleName, TUF_REFUSAL.MALFORMED, `Root metadata has no usable '${roleName}' role definition (keyids + integer threshold >= 1) — fail-closed refusal.`);
  }
  const got = countValidSignatures(envelope, rootSigned.keys, roleDef.keyids);
  if (got < roleDef.threshold) {
    return refusal(
      roleName,
      TUF_REFUSAL.THRESHOLD_NOT_MET,
      `${context}: ${got} distinct valid signature(s) from authorized '${roleName}' keys, but the threshold is ${roleDef.threshold} — refused.`
    );
  }
  return null;
}

/** Expiry check — FAIL-CLOSED: missing or unparseable `expires` is a refusal. */
function checkExpiry(signed, roleName, nowMs) {
  const raw = signed?.expires;
  const t = typeof raw === "string" ? Date.parse(raw) : NaN;
  if (Number.isNaN(t)) {
    return refusal(roleName, TUF_REFUSAL.MALFORMED, `Role '${roleName}' has a missing or unparseable RFC-3339 'expires' — fail-closed: unverifiable freshness is a refusal, never a pass.`);
  }
  if (nowMs >= t) {
    return refusal(roleName, TUF_REFUSAL.EXPIRED, `Role '${roleName}' expired at ${raw} — refused (freshness is load-bearing for every role, per TUF).`);
  }
  return null;
}

/** Monotonic per-role anti-rollback (extends the PoC's repo.timestamp idea). */
function checkRollback(signed, roleName, previousVersions) {
  const prev = previousVersions?.[roleName];
  if (typeof prev !== "number") return null; // nothing adopted yet for this role
  if (!Number.isInteger(signed?.version)) {
    return refusal(roleName, TUF_REFUSAL.MALFORMED, `Role '${roleName}' has no integer 'version' — fail-closed refusal.`);
  }
  if (signed.version < prev) {
    return refusal(
      roleName,
      TUF_REFUSAL.ROLLBACK,
      `Role '${roleName}' version ${signed.version} is older than the last-adopted version ${prev} — refused as a rollback attempt.`
    );
  }
  return null;
}

/** Structural sanity for an envelope of the expected role type. */
function checkShape(envelope, roleName) {
  if (!envelope || typeof envelope !== "object" || !envelope.signed || typeof envelope.signed !== "object") {
    return refusal(roleName, TUF_REFUSAL.MALFORMED, `Missing or malformed '${roleName}' metadata envelope ({ signed, signatures }).`);
  }
  if (envelope.signed._type !== roleName) {
    return refusal(roleName, TUF_REFUSAL.MALFORMED, `Envelope presented as '${roleName}' declares _type '${String(envelope.signed._type)}' — role confusion, refused.`);
  }
  if (!Number.isInteger(envelope.signed.version) || envelope.signed.version < 1) {
    return refusal(roleName, TUF_REFUSAL.MALFORMED, `Role '${roleName}' has no positive integer 'version' — refused.`);
  }
  return null;
}

/** Check a snapshot/timestamp `meta` binding against the actual role metadata. */
function checkMetaBinding(metaEntry, referencedSigned, roleName, binderName) {
  if (!metaEntry || typeof metaEntry !== "object") {
    return refusal(binderName, TUF_REFUSAL.MALFORMED, `'${binderName}' metadata does not bind '${roleName}' (missing meta entry) — refused.`);
  }
  if (metaEntry.version !== referencedSigned.version) {
    return refusal(
      binderName,
      TUF_REFUSAL.META_MISMATCH,
      `'${binderName}' binds '${roleName}' version ${metaEntry.version}, but the presented '${roleName}' metadata is version ${referencedSigned.version} — mix-and-match refused.`
    );
  }
  const actual = sha256Hex(roleBytes(referencedSigned));
  if (metaEntry?.hashes?.sha256 !== actual) {
    return refusal(
      binderName,
      TUF_REFUSAL.META_MISMATCH,
      `'${binderName}' binds '${roleName}' by sha256 ${String(metaEntry?.hashes?.sha256)}, but the presented '${roleName}' metadata hashes to ${actual} — refused.`
    );
  }
  return null;
}

/**
 * Verify the full TUF-style chain: root -> timestamp -> snapshot -> targets
 * -> index bytes. Never throws; returns a typed result object.
 *
 * @param {object} opts
 * @param {object} opts.rootEnvelope        the root metadata being presented ({ signed, signatures })
 * @param {object} opts.timestampEnvelope
 * @param {object} opts.snapshotEnvelope
 * @param {object} opts.targetsEnvelope
 * @param {Buffer|Uint8Array} opts.indexBytes  exact served bytes of index.json (the single target)
 * @param {object|null} [opts.trustedRoot=null] the client's currently-trusted root envelope.
 *        When present, the presented root MUST meet the trusted root's root-role
 *        threshold (this is what makes rotation safe: a new root not signed by
 *        a threshold of the OLD root's keys is refused) AND its own root-role
 *        threshold (TUF spec §5.3.4). When null, the presented root is the
 *        bootstrap trust anchor (out-of-band pinning / TOFU — same caveat as
 *        the PoC's pinned repo key) and is checked against itself only.
 * @param {Record<string,number>} [opts.previousVersions={}] role name -> last
 *        version this client adopted; any lower presented version is refused.
 * @param {number} [opts.nowMs=Date.now()]   injectable clock for expiry checks.
 */
export function verifyTufChain(opts) {
  const {
    rootEnvelope,
    timestampEnvelope,
    snapshotEnvelope,
    targetsEnvelope,
    indexBytes,
    trustedRoot = null,
    previousVersions = {},
    nowMs = Date.now(),
  } = opts ?? {};

  // --- 1. root ------------------------------------------------------------
  let fail = checkShape(rootEnvelope, "root");
  if (fail) return fail;
  const root = rootEnvelope.signed;

  if (trustedRoot) {
    const shapeFail = checkShape(trustedRoot, "root");
    if (shapeFail) {
      return refusal("root", TUF_REFUSAL.MALFORMED, "The client's trusted root is itself malformed — refusing to evaluate any rotation against it.");
    }
    // Rotation anti-rollback: the presented root may never be OLDER than the
    // trusted one (equal is fine — that's just re-fetching the same root).
    if (root.version < trustedRoot.signed.version) {
      return refusal(
        "root",
        TUF_REFUSAL.ROLLBACK,
        `Presented root version ${root.version} is older than the trusted root version ${trustedRoot.signed.version} — refused.`
      );
    }
    // Rotation authorization: the presented root must satisfy the OLD root's
    // root-role threshold. A "new root" nobody currently trusted signed off
    // on is exactly the attack this exists to stop.
    const oldAuth = checkThreshold(rootEnvelope, "root", trustedRoot.signed, "Root rotation check against the currently-trusted (old) root");
    if (oldAuth) {
      return refusal(
        "root",
        TUF_REFUSAL.ROTATION_UNAUTHORIZED,
        `Presented root (version ${root.version}) is not signed by a threshold of the currently-trusted root's keys — rotation refused. (${oldAuth.reason})`
      );
    }
  }
  // Self-consistency: the presented root must also meet its OWN declared
  // root-role threshold (TUF §5.3.4's second half; also the whole check in
  // the bootstrap/no-trusted-root case).
  fail = checkThreshold(rootEnvelope, "root", root, trustedRoot ? "New root check against its own declared root role" : "Bootstrap root self-check");
  if (fail) return fail;
  fail = checkRollback(root, "root", previousVersions);
  if (fail) return fail;
  fail = checkExpiry(root, "root", nowMs);
  if (fail) return fail;

  // --- 2. timestamp (freshness root, signed by root's timestamp role) ------
  fail = checkShape(timestampEnvelope, "timestamp");
  if (fail) return fail;
  fail = checkThreshold(timestampEnvelope, "timestamp", root, "Timestamp role");
  if (fail) return fail;
  fail = checkRollback(timestampEnvelope.signed, "timestamp", previousVersions);
  if (fail) return fail;
  fail = checkExpiry(timestampEnvelope.signed, "timestamp", nowMs);
  if (fail) return fail;

  // --- 3. snapshot (must be the exact one timestamp binds) -----------------
  fail = checkShape(snapshotEnvelope, "snapshot");
  if (fail) return fail;
  fail = checkMetaBinding(timestampEnvelope.signed?.meta?.["snapshot.json"], snapshotEnvelope.signed, "snapshot", "timestamp");
  if (fail) return fail;
  fail = checkThreshold(snapshotEnvelope, "snapshot", root, "Snapshot role");
  if (fail) return fail;
  fail = checkRollback(snapshotEnvelope.signed, "snapshot", previousVersions);
  if (fail) return fail;
  fail = checkExpiry(snapshotEnvelope.signed, "snapshot", nowMs);
  if (fail) return fail;

  // --- 4. targets (must be the exact one snapshot binds) -------------------
  fail = checkShape(targetsEnvelope, "targets");
  if (fail) return fail;
  fail = checkMetaBinding(snapshotEnvelope.signed?.meta?.["targets.json"], targetsEnvelope.signed, "targets", "snapshot");
  if (fail) return fail;
  fail = checkThreshold(targetsEnvelope, "targets", root, "Targets role");
  if (fail) return fail;
  fail = checkRollback(targetsEnvelope.signed, "targets", previousVersions);
  if (fail) return fail;
  fail = checkExpiry(targetsEnvelope.signed, "targets", nowMs);
  if (fail) return fail;

  // --- 5. the target file itself: exact served bytes of index.json ---------
  const decl = targetsEnvelope.signed?.targets?.["index.json"];
  if (!decl || typeof decl !== "object") {
    return refusal("targets", TUF_REFUSAL.MALFORMED, "Targets metadata declares no 'index.json' target — nothing to verify the index against, refused.");
  }
  const bytes = Buffer.from(indexBytes ?? []);
  if (decl.length !== bytes.length || decl?.hashes?.sha256 !== sha256Hex(bytes)) {
    return refusal(
      "targets",
      TUF_REFUSAL.TARGET_MISMATCH,
      `index.json bytes (${bytes.length} bytes, sha256 ${sha256Hex(bytes)}) do not match the signed targets declaration (${decl.length} bytes, sha256 ${String(decl?.hashes?.sha256)}) — refused. The role chain verified, but the served artifact is not the one the targets role signed.`
    );
  }

  return {
    state: TUF_STATE.VERIFIED,
    role: null,
    code: null,
    reason:
      "Full chain verified: root (threshold" +
      (trustedRoot ? " + old-root rotation authorization" : ", bootstrap self-check") +
      ") -> timestamp -> snapshot -> targets, every role unexpired and non-rolled-back, and index.json matches the signed length/sha256.",
    roleVersions: {
      root: root.version,
      timestamp: timestampEnvelope.signed.version,
      snapshot: snapshotEnvelope.signed.version,
      targets: targetsEnvelope.signed.version,
    },
  };
}
