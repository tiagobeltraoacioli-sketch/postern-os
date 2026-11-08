// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Postern Labs and Postern community contributors
//
// Depot — HOST tests. Run with: node apps/postern-store/depot/test/test-depot.mjs
// (Node >= 18; auto-builds enterprise/licensing's dist/ on first run — see
// crypto-bridge.mjs). No network, no DOM, no browser — everything here runs
// on a plain Node host, which is the bar the task set ("real,
// HOST-testable code").
//
// Covers: multi-repo signed-index verification (VERIFIED/TAMPERED/
// UNVERIFIABLE/REVOKED), the red-team fix #2 (reproducible_build must not be
// self-vouching — a forged/unsigned/untrusted-builder PASS record never
// earns the ATTESTED badge), per-version honesty invariants, id-collision
// non-merge across repos, backward compatibility with today's real
// catalog.json, and Depot CRL revocation.

import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { DepotClient, resolveRepoTrust } from "../repo-client.mjs";
import { TRUST } from "../schema.mjs";
import { normalizeEntry, verifyReproducibleBuildRecord } from "../normalize.mjs";
import { buildDepotCrl } from "../depot-crl.mjs";
import {
  makeKeypair, buildSignedRepo, tamperBytes, buildAttestationRecord,
  buildForgedAttestationRecord, buildRecordSignedByUntrustedKey,
} from "./fixtures.mjs";
import { makeTrustStore, validateRecordShape } from "../../reproducible-build-record.mjs";
// Cross-producer proof (Depot M4 fix): repro-verifier's OWN producer/signer,
// imported here ONLY for a test that proves a record it builds and signs
// (different Ed25519 backend, different package) verifies IDENTICALLY
// through depot's consumer as a record depot's own fixtures build and sign.
import { buildRecord as reproBuildRecord, signRecord as reproSignRecord } from "../../repro-verifier/lib/build-record.mjs";
import { generateKeypair as reproGenerateKeypair } from "../../repro-verifier/lib/keys.mjs";

const here = dirname(fileURLToPath(import.meta.url));

let passed = 0;
const t = (name, fn) => Promise.resolve().then(fn).then(() => { passed++; console.log("  ok — " + name); });

/* ---------- shared fixtures ---------- */

function attestApp({ id = "acme-app", versions = [] } = {}) {
  return {
    id, name: "Acme App", publisher: "Acme", glyph: "A", category: "security",
    platform: "both", source: "native-linux", tier: "attestable-nix",
    oneliner: "test fixture", license: { spdx: "MIT", class: "permissive", foss: true, redistribute: true, rebrand: true, trademark: false, note: "" },
    distribution: { model: "attest", hosted_by_us: true, upstream: "https://example.invalid", artifact: "nix-store://x", checksum: null, signing: { scheme: "nix-store+verity", state: "unpublished" }, verify: "" },
    privacy: { level: "local-only", stays: "", leaves: "" },
    security: ["attestable"],
    capabilities: [], tags: [], limits: "",
    versions,
  };
}

/* ===================================================================
   1. Multi-repo signed index -> VERIFIED
   =================================================================== */
await t("multi-repo: two independently-keyed repos both resolve VERIFIED and merge", async () => {
  const keyA = await makeKeypair();
  const keyB = await makeKeypair();
  const repoA = await buildSignedRepo({
    repoId: "repo-a", repoName: "Repo A", url: "https://a.invalid/index.json", priority: 0,
    apps: [attestApp({ id: "app-a" })], privateKey: keyA.privateKey,
  });
  const repoB = await buildSignedRepo({
    repoId: "repo-b", repoName: "Repo B", url: "https://b.invalid/index.json", priority: 10,
    apps: [attestApp({ id: "app-b" })], privateKey: keyB.privateKey,
  });

  const client = new DepotClient();
  client.addRepo({ repo_id: "repo-a", url: repoA.doc.repo.url, pubkey_b64: keyA.publicKey, label: "Repo A", priority: 0 });
  client.addRepo({ repo_id: "repo-b", url: repoB.doc.repo.url, pubkey_b64: keyB.publicKey, label: "Repo B", priority: 10 });

  const resA = await client.loadRepoIndex("repo-a", repoA.bytes, repoA.sigBytes);
  const resB = await client.loadRepoIndex("repo-b", repoB.bytes, repoB.sigBytes);
  assert.equal(resA.trust.state, TRUST.VERIFIED);
  assert.equal(resB.trust.state, TRUST.VERIFIED);

  const merged = client.mergedListing();
  assert.equal(merged.length, 2);
  assert.ok(merged.some(m => m.entry.id === "app-a" && m.repoId === "repo-a"));
  assert.ok(merged.some(m => m.entry.id === "app-b" && m.repoId === "repo-b"));
});

/* ===================================================================
   2. Tampered index -> TAMPERED, reject + fall back to last VERIFIED
   =================================================================== */
await t("tampered index: served-bytes mismatch -> TAMPERED, fetched copy rejected, last VERIFIED snapshot kept", async () => {
  const key = await makeKeypair();
  const good = await buildSignedRepo({
    repoId: "repo-t", repoName: "Repo T", url: "https://t.invalid/index.json", priority: 10,
    apps: [attestApp({ id: "app-t" })], privateKey: key.privateKey,
  });

  const client = new DepotClient();
  client.addRepo({ repo_id: "repo-t", url: good.doc.repo.url, pubkey_b64: key.publicKey, label: "Repo T", priority: 10 });

  const first = await client.loadRepoIndex("repo-t", good.bytes, good.sigBytes);
  assert.equal(first.trust.state, TRUST.VERIFIED);
  assert.equal(first.entries.length, 1);

  const tampered = tamperBytes(good.bytes); // same old signature, mutated body
  const second = await client.loadRepoIndex("repo-t", tampered, good.sigBytes);
  assert.equal(second.trust.state, TRUST.TAMPERED);
  // fail-safe: the merged listing must still reflect the LAST VERIFIED snapshot, not the tampered one
  assert.equal(second.entries.length, 1);
  assert.equal(second.entries[0].id, "app-t");
  assert.equal(second.staleFallback, true);
});

/* ===================================================================
   3. Wrong key -> UNVERIFIABLE (malformed pin), vs a well-formed-but-wrong
      key -> TAMPERED (the check ran and failed) — the two are NOT the same
      state and this proves the client tells them apart honestly.
   =================================================================== */
await t("wrong key: malformed pinned key material -> UNVERIFIABLE (check could not run at all)", async () => {
  const key = await makeKeypair();
  const repo = await buildSignedRepo({
    repoId: "repo-w", repoName: "Repo W", url: "https://w.invalid/index.json", priority: 10,
    apps: [attestApp({ id: "app-w" })], privateKey: key.privateKey,
  });
  const trust = await resolveRepoTrust({ bytes: repo.bytes, sigBytes: repo.sigBytes, pinnedPubkeyB64: "not-a-valid-32-byte-key==" });
  assert.equal(trust.state, TRUST.UNVERIFIABLE);
});

await t("wrong key: well-formed but DIFFERENT pinned key -> TAMPERED (checked, and it fails)", async () => {
  const key = await makeKeypair();
  const otherKey = await makeKeypair(); // well-formed, just not the signer
  const repo = await buildSignedRepo({
    repoId: "repo-w2", repoName: "Repo W2", url: "https://w2.invalid/index.json", priority: 10,
    apps: [attestApp({ id: "app-w2" })], privateKey: key.privateKey,
  });
  const trust = await resolveRepoTrust({ bytes: repo.bytes, sigBytes: repo.sigBytes, pinnedPubkeyB64: otherKey.publicKey });
  assert.equal(trust.state, TRUST.TAMPERED);
});

/* ===================================================================
   4. CRITICAL — forged reproducible_build:PASS -> badge STRIPPED
   =================================================================== */
await t("forged attestation: unsigned reproducible_build:PASS is NOT honored — badge stripped", async () => {
  const record = buildForgedAttestationRecord({ appId: "forge-app", version: "1.0.0", builderIdentity: "trusted-builder@ci" });
  const app = attestApp({ id: "forge-app", versions: [{ version_name: "1.0.0", version_code: 1, source: {}, build: {}, artifact: {}, signing: { state: "unpublished" }, reproducible_build: record }] });

  const trustedBuilders = makeTrustStore([{ id: "trusted-builder@ci", pubkey_b64: (await makeKeypair()).publicKey }]); // a DIFFERENT key than any that signed this record
  const norm = await normalizeEntry(app, { repoId: "repo-forge", repoLabel: "Forge Repo", repoPriority: 10, trustedBuilders, crl: null });

  assert.equal(norm.attestedEarned, false);
  assert.equal(norm.badge, "NIX-BUILT · UNATTESTED");
  assert.ok(!norm.security.includes("attestable"), "the 'attestable' security tag must be stripped");
  assert.equal(norm.versions[0].attestation.trusted, false);
});

await t("forged attestation: PASS signed by an UNTRUSTED key (not the pinned builder key) is NOT honored", async () => {
  const attackerKey = await makeKeypair();
  const legitKey = await makeKeypair();
  const record = await buildRecordSignedByUntrustedKey({
    appId: "forge-app-2", version: "1.0.0", claimedBuilderIdentity: "trusted-builder@ci",
    actualPrivateKey: attackerKey.privateKey, actualPublicKey: attackerKey.publicKey,
  });
  const app = attestApp({ id: "forge-app-2", versions: [{ version_name: "1.0.0", version_code: 1, source: {}, build: {}, artifact: {}, signing: { state: "unpublished" }, reproducible_build: record }] });

  const trustedBuilders = makeTrustStore([{ id: "trusted-builder@ci", pubkey_b64: legitKey.publicKey }]); // pinned key differs from attackerKey
  const norm = await normalizeEntry(app, { repoId: "repo-forge2", repoLabel: "Forge Repo 2", repoPriority: 10, trustedBuilders, crl: null });

  assert.equal(norm.attestedEarned, false);
  assert.equal(norm.badge, "NIX-BUILT · UNATTESTED");
  assert.match(norm.versions[0].attestation.reason, /NOT a client-pinned trusted builder/);
});

await t("forged attestation: repo self-declares tier attestable-nix with no reproducible_build at all — still stripped", async () => {
  const app = attestApp({ id: "bare-tier-app", versions: [{ version_name: "1.0.0", version_code: 1, source: {}, build: {}, artifact: {}, signing: { state: "unpublished" } }] });
  const norm = await normalizeEntry(app, { repoId: "repo-bare", repoLabel: "Bare Repo", repoPriority: 10, trustedBuilders: new Map(), crl: null });
  assert.equal(norm.attestedEarned, false);
  assert.ok(!norm.security.includes("attestable"));
});

await t("positive control: a GENUINE trusted-builder-signed PASS record DOES earn ATTESTED", async () => {
  const builderKey = await makeKeypair();
  const record = await buildAttestationRecord({ appId: "real-app", version: "1.0.0", builderIdentity: "trusted-builder@ci", builderPrivateKey: builderKey.privateKey, builderPublicKey: builderKey.publicKey });
  const app = attestApp({ id: "real-app", versions: [{ version_name: "1.0.0", version_code: 1, source: {}, build: {}, artifact: {}, signing: { state: "unpublished" }, reproducible_build: record }] });

  const trustedBuilders = makeTrustStore([{ id: "trusted-builder@ci", pubkey_b64: builderKey.publicKey }]);
  const norm = await normalizeEntry(app, { repoId: "repo-real", repoLabel: "Real Repo", repoPriority: 10, trustedBuilders, crl: null });

  assert.equal(norm.attestedEarned, true);
  assert.equal(norm.badge, "ATTESTED");
  assert.ok(norm.security.includes("attestable"));
});

await t("forged attestation: record mutated AFTER signing (tampered PASS) fails its own signature check", async () => {
  const builderKey = await makeKeypair();
  const record = await buildAttestationRecord({ appId: "mut-app", version: "1.0.0", builderIdentity: "trusted-builder@ci", builderPrivateKey: builderKey.privateKey, builderPublicKey: builderKey.publicKey, tamperAfterSigning: true });
  const app = attestApp({ id: "mut-app", versions: [{ version_name: "1.0.0", version_code: 1, source: {}, build: {}, artifact: {}, signing: { state: "unpublished" }, reproducible_build: record }] });
  const trustedBuilders = makeTrustStore([{ id: "trusted-builder@ci", pubkey_b64: builderKey.publicKey }]);
  const norm = await normalizeEntry(app, { repoId: "repo-mut", repoLabel: "Mut Repo", repoPriority: 10, trustedBuilders, crl: null });
  assert.equal(norm.attestedEarned, false);
});

/* ===================================================================
   5. Per-version honesty invariants (red-team finding #3)
   =================================================================== */
await t("per-version invariants: proprietary app's version artifact/checksum is stripped even if the JSON tries to sneak one in", async () => {
  const app = {
    id: "closed-app", name: "Closed App", publisher: "Vendor", glyph: "C", category: "media",
    platform: "both", source: "web", tier: "browser",
    oneliner: "proprietary fixture",
    license: { spdx: "LicenseRef-Proprietary", class: "proprietary", foss: false, redistribute: false, rebrand: false, trademark: true, note: "" },
    distribution: { model: "attest", hosted_by_us: true, upstream: "https://vendor.invalid", artifact: "https://vendor.invalid/bin", checksum: "sha256:deadbeef", signing: { scheme: "none", state: "published" }, verify: "" },
    privacy: { level: "metadata-exposed", stays: "", leaves: "" },
    security: [], capabilities: [], tags: [], limits: "",
    versions: [{
      version_name: "9.9.9", version_code: 9, source: {}, build: {},
      artifact: { filename: "closed.bin", urls: ["https://vendor.invalid/closed.bin"], size_bytes: 100, sha256: "sha256:deadbeef" },
      signing: { state: "published" },
    }],
  };
  const norm = await normalizeEntry(app, { repoId: "repo-c", repoLabel: "C Repo", repoPriority: 10, trustedBuilders: new Map(), crl: null });

  // top-level invariant (unchanged behavior)
  assert.equal(norm.dist.hostedByUs, false);
  assert.equal(norm.dist.model, "link");
  assert.ok(norm.dist.coerced);

  // NEW per-version invariant (red-team #3)
  assert.equal(norm.versions[0].artifact.urls.length, 0);
  assert.equal(norm.versions[0].artifact.sha256, null);
  assert.ok(norm.versions[0].coerced, "version-level coercion note must be set");
});

await t("per-version invariants: signing.state !== published forces the version's checksum to null even if the JSON sets one", async () => {
  const app = attestApp({
    id: "unpub-app",
    versions: [{
      version_name: "1.0.0", version_code: 1, source: {}, build: {},
      artifact: { filename: "x", urls: ["https://x.invalid/x"], size_bytes: 1, sha256: "sha256:notreally" },
      signing: { state: "unpublished" }, // NOT published
    }],
  });
  const norm = await normalizeEntry(app, { repoId: "repo-u", repoLabel: "U Repo", repoPriority: 10, trustedBuilders: new Map(), crl: null });
  assert.equal(norm.versions[0].published, false);
  assert.equal(norm.versions[0].artifact.sha256, null, "unpublished version must never carry a live checksum");
});

await t("per-version invariants: reproducible_build on a non-attest model (e.g. mirror) is never honored", async () => {
  const app = {
    id: "mirror-app", name: "Mirror App", publisher: "Up", glyph: "M", category: "media", platform: "both",
    source: "postern-apk", tier: "pmos-overlay",
    oneliner: "", license: { spdx: "MIT", class: "permissive", foss: true, redistribute: true, rebrand: true, trademark: false, note: "" },
    distribution: { model: "mirror", hosted_by_us: true, upstream: "", artifact: "", checksum: null, signing: { scheme: "abuild-rsa", state: "unpublished" }, verify: "" },
    privacy: { level: "local-only", stays: "", leaves: "" }, security: [], capabilities: [], tags: [], limits: "",
    versions: [{ version_name: "1.0.0", version_code: 1, source: {}, build: {}, artifact: {}, signing: { state: "unpublished" }, reproducible_build: { result: "PASS", builder_identity: "x" } }],
  };
  const norm = await normalizeEntry(app, { repoId: "repo-m", repoLabel: "M Repo", repoPriority: 10, trustedBuilders: new Map([["x", "whatever"]]), crl: null });
  assert.equal(norm.versions[0].attestation.trusted, false);
  assert.match(norm.versions[0].attestation.reason, /cannot carry a reproducible_build record/);
});

/* ===================================================================
   6. Id-collision non-merge across repos
   =================================================================== */
await t("id collision: two repos listing the same app id NEVER merge into one card", async () => {
  const keyFirst = await makeKeypair();
  const keyOther = await makeKeypair();
  const firstParty = await buildSignedRepo({
    repoId: "postern-store", repoName: "Postern Store", url: "https://posternlabs.com/store/catalog.json", priority: 0,
    apps: [attestApp({ id: "signal-android" })], privateKey: keyFirst.privateKey,
  });
  const thirdParty = await buildSignedRepo({
    repoId: "third-party", repoName: "Some Third Party", url: "https://third.invalid/index.json", priority: 20,
    apps: [attestApp({ id: "signal-android" })], privateKey: keyOther.privateKey,
  });

  const client = new DepotClient();
  client.addRepo({ repo_id: "postern-store", url: firstParty.doc.repo.url, pubkey_b64: keyFirst.publicKey, label: "Postern Store", priority: 0 });
  client.addRepo({ repo_id: "third-party", url: thirdParty.doc.repo.url, pubkey_b64: keyOther.publicKey, label: "Some Third Party", priority: 20 });
  await client.loadRepoIndex("postern-store", firstParty.bytes, firstParty.sigBytes);
  await client.loadRepoIndex("third-party", thirdParty.bytes, thirdParty.sigBytes);

  const merged = client.mergedListing();
  const signalListings = merged.filter(m => m.entry.id === "signal-android");
  assert.equal(signalListings.length, 2, "must be two DISTINCT listings, never merged into one");
  assert.notEqual(signalListings[0].repoId, signalListings[1].repoId);

  const thirdPartyListing = signalListings.find(l => l.repoId === "third-party");
  const firstPartyListing = signalListings.find(l => l.repoId === "postern-store");
  assert.ok(thirdPartyListing.shadowNote, "the non-first-party listing must carry a cross-reference note");
  assert.equal(firstPartyListing.shadowNote, null, "the first-party listing is authoritative — no shadow note on it");
});

await t("id collision: within ONE repo's own index, a duplicate id keeps only the first (no silent overwrite-merge either)", async () => {
  const key = await makeKeypair();
  const repo = await buildSignedRepo({
    repoId: "dup-repo", repoName: "Dup Repo", url: "https://dup.invalid/index.json", priority: 10,
    apps: [attestApp({ id: "dup-app" }), { ...attestApp({ id: "dup-app" }), name: "Second Copy — should be ignored" }],
    privateKey: key.privateKey,
  });
  const client = new DepotClient();
  client.addRepo({ repo_id: "dup-repo", url: repo.doc.repo.url, pubkey_b64: key.publicKey, label: "Dup Repo", priority: 10 });
  const res = await client.loadRepoIndex("dup-repo", repo.bytes, repo.sigBytes);
  assert.equal(res.entries.length, 1);
  assert.equal(res.entries[0].name, "Acme App"); // the first one, not "Second Copy"
});

/* ===================================================================
   7. Depot CRL revocation (crl.ts pattern, generalized)
   =================================================================== */
await t("revocation: a repo key on the Depot CRL resolves REVOKED, not VERIFIED, even with a valid signature", async () => {
  const key = await makeKeypair();
  const opsKey = await makeKeypair();
  const repo = await buildSignedRepo({
    repoId: "repo-rev", repoName: "Repo Rev", url: "https://rev.invalid/index.json", priority: 10,
    apps: [attestApp({ id: "app-rev" })], privateKey: key.privateKey,
  });
  const crl = await buildDepotCrl(opsKey.privateKey, { iss: "depot-ops", kid: "k1", version: 1, revokedRepoKeys: [key.publicKey] });

  const client = new DepotClient();
  client.addRepo({ repo_id: "repo-rev", url: repo.doc.repo.url, pubkey_b64: key.publicKey, label: "Repo Rev", priority: 10 });
  client.pinDepotOpsKey(opsKey.publicKey);
  const setResult = await client.setCrl(crl);
  assert.equal(setResult.ok, true, setResult.reason);
  const res = await client.loadRepoIndex("repo-rev", repo.bytes, repo.sigBytes);
  assert.equal(res.trust.state, TRUST.REVOKED);
});

/* ===================================================================
   7b. ADVERSARIAL-REVIEW FIX (MEDIUM): DepotClient.setCrl must verify the
   CRL's own signature against a pinned Depot-ops key before applying it —
   previously it stored ANY object handed to it, signed or not.
   =================================================================== */
await t("CRL signature: an UNSIGNED (forged) Depot CRL is REJECTED by setCrl — never applied", async () => {
  const opsKey = await makeKeypair();
  const forgedCrl = { payload: { v: 1, typ: "depot-crl", iss: "depot-ops", kid: "k1", version: 999, issued_at: 0, next_update: 0, max_stale_secs: 0, revoked_repo_keys: [], revoked_builder_keys: [], revoked_artifact_sha256: [] }, sig: "" };

  const client = new DepotClient();
  client.pinDepotOpsKey(opsKey.publicKey);
  const result = await client.setCrl(forgedCrl);

  assert.equal(result.ok, false);
  assert.equal(client.crl, null, "an unsigned CRL must never be applied, even though setCrl() was called with it");
});

await t("CRL signature: a BADLY-SIGNED (tampered payload, stale signature) Depot CRL is REJECTED by setCrl", async () => {
  const opsKey = await makeKeypair();
  const attackerKey = await makeKeypair();
  const key = await makeKeypair();
  // Signed by an attacker's key, not the pinned Depot-ops key.
  const badCrl = await buildDepotCrl(attackerKey.privateKey, { iss: "depot-ops", kid: "k1", version: 1, revokedRepoKeys: [key.publicKey] });

  const client = new DepotClient();
  client.pinDepotOpsKey(opsKey.publicKey);
  const result = await client.setCrl(badCrl);

  assert.equal(result.ok, false);
  assert.equal(client.crl, null);

  // And even if a repo key SHOULD be revoked per the forged CRL's content, it must NOT be enforced —
  // an unverified CRL must never take effect.
  const repo = await buildSignedRepo({ repoId: "repo-badcrl", repoName: "Repo BadCrl", url: "https://badcrl.invalid/index.json", priority: 10, apps: [attestApp({ id: "app-badcrl" })], privateKey: key.privateKey });
  client.addRepo({ repo_id: "repo-badcrl", url: repo.doc.repo.url, pubkey_b64: key.publicKey, label: "Repo BadCrl", priority: 10 });
  const res = await client.loadRepoIndex("repo-badcrl", repo.bytes, repo.sigBytes);
  assert.equal(res.trust.state, TRUST.VERIFIED, "the (unapplied) forged CRL must not cause a legitimately-signed repo to be treated as revoked");
});

await t("CRL signature: a GENUINELY-SIGNED Depot CRL (matching the pinned Depot-ops key) IS applied by setCrl", async () => {
  const opsKey = await makeKeypair();
  const key = await makeKeypair();
  const crl = await buildDepotCrl(opsKey.privateKey, { iss: "depot-ops", kid: "k1", version: 1, revokedRepoKeys: [key.publicKey] });

  const client = new DepotClient();
  client.pinDepotOpsKey(opsKey.publicKey);
  const result = await client.setCrl(crl);

  assert.equal(result.ok, true);
  assert.equal(client.crl, crl);
});

await t("CRL signature: setCrl rejects any CRL when no Depot-ops key has been pinned yet (fail closed, not fail open)", async () => {
  const opsKey = await makeKeypair();
  const key = await makeKeypair();
  const crl = await buildDepotCrl(opsKey.privateKey, { iss: "depot-ops", kid: "k1", version: 1, revokedRepoKeys: [key.publicKey] });

  const client = new DepotClient(); // pinDepotOpsKey() never called
  const result = await client.setCrl(crl);

  assert.equal(result.ok, false);
  assert.equal(client.crl, null);
});

await t("revocation: a revoked builder key strips an otherwise-genuine PASS attestation", async () => {
  const builderKey = await makeKeypair();
  const opsKey = await makeKeypair();
  const record = await buildAttestationRecord({ appId: "rev-app", version: "1.0.0", builderIdentity: "trusted-builder@ci", builderPrivateKey: builderKey.privateKey, builderPublicKey: builderKey.publicKey });
  const app = attestApp({ id: "rev-app", versions: [{ version_name: "1.0.0", version_code: 1, source: {}, build: {}, artifact: {}, signing: { state: "unpublished" }, reproducible_build: record }] });
  const trustedBuilders = makeTrustStore([{ id: "trusted-builder@ci", pubkey_b64: builderKey.publicKey }]);
  const crl = await buildDepotCrl(opsKey.privateKey, { iss: "depot-ops", kid: "k1", version: 1, revokedBuilderKeys: [builderKey.publicKey] });

  const norm = await normalizeEntry(app, { repoId: "repo-revb", repoLabel: "RevB Repo", repoPriority: 10, trustedBuilders, crl });
  assert.equal(norm.attestedEarned, false);
  assert.match(norm.versions[0].attestation.reason, /revoked/);
});

/* ===================================================================
   7c. ADVERSARIAL-REVIEW FIX: proprietary detection must be case-/type-
   robust — a dishonest repo dodging INVARIANT 1 with `class: "Proprietary"`
   (wrong case) or `foss: "false"` (string, not boolean) must still be
   coerced exactly like the canonical lowercase/boolean form.
   =================================================================== */
await t("proprietary detection: wrong-case class (\"Proprietary\") still coerces to link-only/not-hosted", async () => {
  const app = {
    id: "sneaky-case-app", name: "Sneaky Case App", publisher: "Vendor", glyph: "S", category: "media",
    platform: "both", source: "web", tier: "browser",
    oneliner: "adversarial fixture — wrong-case class",
    license: { spdx: "LicenseRef-Proprietary", class: "Proprietary", foss: true, redistribute: true, rebrand: true, trademark: true, note: "" },
    distribution: { model: "attest", hosted_by_us: true, upstream: "https://vendor.invalid", artifact: "https://vendor.invalid/bin", checksum: "sha256:deadbeef", signing: { scheme: "none", state: "published" }, verify: "" },
    privacy: { level: "metadata-exposed", stays: "", leaves: "" },
    security: [], capabilities: [], tags: [], limits: "",
    versions: [],
  };
  const norm = await normalizeEntry(app, { repoId: "repo-case", repoLabel: "Case Repo", repoPriority: 10, trustedBuilders: new Map(), crl: null });

  assert.equal(norm.dist.hostedByUs, false, "wrong-case 'Proprietary' must still be recognized as proprietary and forced un-hosted");
  assert.equal(norm.dist.model, "link");
  assert.ok(norm.dist.coerced);
  assert.equal(norm.license.class, "proprietary");
  assert.equal(norm.license.foss, false);
  assert.equal(norm.license.redistribute, false);
});

await t("proprietary detection: foss as the STRING \"false\" (not the boolean) still coerces to link-only/not-hosted", async () => {
  const app = {
    id: "sneaky-string-foss-app", name: "Sneaky String Foss App", publisher: "Vendor", glyph: "S", category: "media",
    platform: "both", source: "web", tier: "browser",
    oneliner: "adversarial fixture — foss as a string",
    license: { spdx: "LicenseRef-Proprietary", class: "unknown-class", foss: "false", redistribute: true, rebrand: true, trademark: true, note: "" },
    distribution: { model: "mirror", hosted_by_us: true, upstream: "https://vendor.invalid", artifact: "https://vendor.invalid/bin", checksum: "sha256:deadbeef", signing: { scheme: "none", state: "published" }, verify: "" },
    privacy: { level: "metadata-exposed", stays: "", leaves: "" },
    security: [], capabilities: [], tags: [], limits: "",
    versions: [{ version_name: "1.0.0", version_code: 1, source: {}, build: {}, artifact: { filename: "x", urls: ["https://vendor.invalid/x"], size_bytes: 1, sha256: "sha256:deadbeef" }, signing: { state: "published" } }],
  };
  const norm = await normalizeEntry(app, { repoId: "repo-strfoss", repoLabel: "StrFoss Repo", repoPriority: 10, trustedBuilders: new Map(), crl: null });

  assert.equal(norm.dist.hostedByUs, false, "foss:\"false\" (string) must still be treated as proprietary and forced un-hosted");
  assert.equal(norm.dist.model, "link");
  assert.ok(norm.dist.coerced);
  assert.equal(norm.license.foss, false);
  // Per-version invariant must also apply once the entry is correctly recognized as proprietary.
  assert.equal(norm.versions[0].artifact.urls.length, 0);
  assert.equal(norm.versions[0].artifact.sha256, null);
});

await t("proprietary detection: leading/trailing whitespace on class (\" proprietary \") still coerces", async () => {
  const app = {
    id: "sneaky-ws-app", name: "Sneaky Whitespace App", publisher: "Vendor", glyph: "S", category: "media",
    platform: "both", source: "web", tier: "browser",
    oneliner: "adversarial fixture — whitespace-padded class",
    license: { spdx: "LicenseRef-Proprietary", class: " proprietary ", foss: true, redistribute: true, rebrand: true, trademark: true, note: "" },
    distribution: { model: "attest", hosted_by_us: true, upstream: "https://vendor.invalid", artifact: "nix-store://x", checksum: null, signing: { scheme: "none", state: "unpublished" }, verify: "" },
    privacy: { level: "metadata-exposed", stays: "", leaves: "" },
    security: [], capabilities: [], tags: [], limits: "",
    versions: [],
  };
  const norm = await normalizeEntry(app, { repoId: "repo-ws", repoLabel: "WS Repo", repoPriority: 10, trustedBuilders: new Map(), crl: null });
  assert.equal(norm.dist.hostedByUs, false, "whitespace-padded ' proprietary ' must still be recognized and force un-hosted");
  assert.equal(norm.dist.model, "link");
  assert.ok(norm.dist.coerced);
  assert.equal(norm.license.class, "proprietary");
});

/* ===================================================================
   8. Backward compatibility: today's REAL catalog.json still verifies
   =================================================================== */
await t("backward compat: the real shipping catalog.json + catalog.json.sig verifies VERIFIED under the multi-repo client", async () => {
  const catalogPath = join(here, "..", "..", "catalog.json");
  const sigPath = join(here, "..", "..", "catalog.json.sig");
  const bytes = new Uint8Array(readFileSync(catalogPath));
  const sigBytes = new Uint8Array(readFileSync(sigPath));
  const REAL_PUBKEY_B64 = "xhW1EymjaCs8nAwYbFglWeGrTs4gMo8uoc2oV7nnAes=";

  const client = new DepotClient();
  client.addRepo({ repo_id: "postern-store", url: "https://posternlabs.com/store/catalog.json", pubkey_b64: REAL_PUBKEY_B64, label: "Postern Store", priority: 0 });
  const res = await client.loadRepoIndex("postern-store", bytes, sigBytes);
  assert.equal(res.trust.state, TRUST.VERIFIED, res.trust.reason);
  assert.ok(res.entries.length > 15, `expected the real catalog's ~20 apps, got ${res.entries.length}`);
  // zero versions[] in today's file — must still normalize cleanly (no migration required)
  assert.ok(res.entries.every(e => Array.isArray(e.versions) && e.versions.length === 0));
  // and the existing per-tier stripping still holds through the new code path
  const proprietaryEntries = res.entries.filter(e => e.license.class === "proprietary");
  assert.ok(proprietaryEntries.length > 0, "fixture assumption: catalog.json has at least one proprietary app");
  assert.ok(proprietaryEntries.every(e => e.dist.hostedByUs === false));
});

/* ===================================================================
   9. Depot M4 — the two reproducible_build schemas are now ONE canonical
   schema; a record from EITHER producer validates IDENTICALLY through the
   unified path, and a malformed/foreign-shape record is rejected outright.
   =================================================================== */
await t("M4: a record built+signed by repro-verifier's OWN producer (different Ed25519 backend, different package) earns ATTESTED through depot's consumer, identically to depot's own fixture", async () => {
  const builderKey = reproGenerateKeypair(); // repro-verifier's sync node:crypto keypair, NOT depot's crypto-bridge
  const unsigned = reproBuildRecord({
    appId: "cross-producer-app",
    version: "1.0.0",
    source: { repo_url: "https://example.invalid/cross", commit: "a".repeat(40), build_expr: "nixpkgs#cross", build_expr_source: "nixpkgs", flake_lock_rev: "b".repeat(40) },
    buildEnv: { nix_version: "2.24.0", system: "x86_64-linux", sandbox: "hermetic", builder_hosts: ["h-a", "h-b"] },
    output: { store_path: "/nix/store/CROSS-cross-producer-app-1.0.0", nar_hash: "sha256:" + "c".repeat(64), shipped_artifact_hash: "sha256:" + "d".repeat(64) },
    result: { rebuild_match: true, shipped_match: true, verdict: "PASS", diagnostic: null },
    run: { timestamp: "2026-07-13T00:00:00Z", run_by: "repro-verifier-ci@builder-a", verifier_version: "repro-verifier@0.0.0" },
  });
  const record = reproSignRecord(unsigned, { builderId: "cross-builder@ci", builderPrivKeyB64: builderKey.privateKey, builderPubKeyB64: builderKey.publicKey });

  // Sanity: this is genuinely a repro-verifier-shaped record, not depot's.
  assert.equal(validateRecordShape(record).ok, true);

  const app = attestApp({ id: "cross-producer-app", versions: [{ version_name: "1.0.0", version_code: 1, source: {}, build: {}, artifact: {}, signing: { state: "unpublished" }, reproducible_build: record }] });
  const trustedBuilders = makeTrustStore([{ id: "cross-builder@ci", pubkey_b64: builderKey.publicKey }]);
  const norm = await normalizeEntry(app, { repoId: "repo-cross", repoLabel: "Cross Repo", repoPriority: 10, trustedBuilders, crl: null });

  assert.equal(norm.attestedEarned, true, norm.versions[0].attestation.reason);
  assert.equal(norm.badge, "ATTESTED");

  // And the SAME record, run DIRECTLY through depot's own record-level
  // verifier (not just the full normalizeEntry path), independently confirms
  // trust — proving the unification, not just a passing end-to-end fixture.
  const direct = await verifyReproducibleBuildRecord(record, trustedBuilders, null, "cross-producer-app", "1.0.0");
  assert.equal(direct.trusted, true, direct.reason);
});

await t("M4: a record built+signed by depot's OWN fixtures validates through the same shared decideBadge() core repro-verifier uses", async () => {
  const builderKey = await makeKeypair(); // depot's async crypto-bridge keypair
  const record = await buildAttestationRecord({
    appId: "depot-producer-app", version: "1.0.0",
    builderIdentity: "depot-builder@ci", builderPrivateKey: builderKey.privateKey, builderPublicKey: builderKey.publicKey,
  });
  assert.equal(validateRecordShape(record).ok, true);

  const app = attestApp({ id: "depot-producer-app", versions: [{ version_name: "1.0.0", version_code: 1, source: {}, build: {}, artifact: {}, signing: { state: "unpublished" }, reproducible_build: record }] });
  const trustedBuilders = makeTrustStore([{ id: "depot-builder@ci", pubkey_b64: builderKey.publicKey }]);
  const norm = await normalizeEntry(app, { repoId: "repo-depot-producer", repoLabel: "Depot Producer Repo", repoPriority: 10, trustedBuilders, crl: null });

  assert.equal(norm.attestedEarned, true, norm.versions[0].attestation.reason);
  assert.equal(norm.badge, "ATTESTED");
});

await t("M4: the OLD depot-only flat schema (postern.depot.attestation/v1 — result as a bare string, builder_identity as a bare string) is now a foreign shape and is REJECTED, not silently misread", async () => {
  const legacyFlatRecord = {
    schema: "postern.depot.attestation/v1",
    app_id: "legacy-app",
    version: "1.0.0",
    result: "PASS", // bare string, not { verdict: "PASS", ... }
    input_hash: "sha256:" + "a".repeat(64),
    output_hash: "sha256:" + "b".repeat(64),
    builder_identity: "trusted-builder@ci", // bare string, not { id, pubkey_b64 }
    timestamp: "2026-07-13T00:00:00Z",
    report_url: "https://example.invalid/reports/legacy-app-1.0.0.json",
    signature: { scheme: "ed25519-detached", signature_b64: "deadbeef" },
  };
  assert.equal(validateRecordShape(legacyFlatRecord).ok, false);

  const app = attestApp({ id: "legacy-app", versions: [{ version_name: "1.0.0", version_code: 1, source: {}, build: {}, artifact: {}, signing: { state: "unpublished" }, reproducible_build: legacyFlatRecord }] });
  const trustedBuilders = makeTrustStore([{ id: "trusted-builder@ci", pubkey_b64: "whatever-key==" }]);
  const norm = await normalizeEntry(app, { repoId: "repo-legacy", repoLabel: "Legacy Repo", repoPriority: 10, trustedBuilders, crl: null });

  assert.equal(norm.attestedEarned, false);
  assert.equal(norm.versions[0].attestation.trusted, false);
  assert.match(norm.versions[0].attestation.reason, /schema/);
});

await t("M4: a record whose app_id/version does not match the catalog entry it is embedded in is rejected (app/version binding)", async () => {
  const builderKey = await makeKeypair();
  // Genuinely signed by a genuinely trusted builder, verdict PASS — but for
  // a DIFFERENT app ("other-app") than the one it is embedded under here.
  const record = await buildAttestationRecord({
    appId: "other-app", version: "1.0.0",
    builderIdentity: "trusted-builder@ci", builderPrivateKey: builderKey.privateKey, builderPublicKey: builderKey.publicKey,
  });
  const app = attestApp({ id: "replay-target-app", versions: [{ version_name: "1.0.0", version_code: 1, source: {}, build: {}, artifact: {}, signing: { state: "unpublished" }, reproducible_build: record }] });
  const trustedBuilders = makeTrustStore([{ id: "trusted-builder@ci", pubkey_b64: builderKey.publicKey }]);
  const norm = await normalizeEntry(app, { repoId: "repo-replay", repoLabel: "Replay Repo", repoPriority: 10, trustedBuilders, crl: null });

  assert.equal(norm.attestedEarned, false);
  assert.equal(norm.versions[0].attestation.trusted, false);
  assert.match(norm.versions[0].attestation.reason, /does not match this catalog entry's id/);
});

/* ===================================================================
   10. ADVERSARIAL-REVIEW FIX: a genuine, trusted-builder-signed PASS record
   for app X@1.0.0 is replayed onto app X@2.0.0 (SAME app, DIFFERENT
   version) -> STRIPPED for that version, not ATTESTED — proves the binding
   fix is precise (per-version), not an over-broad "any record present"
   check.
   =================================================================== */
await t("REPLAY (same app, different version): a genuine, trusted-builder-signed PASS record for app-c@1.0.0 does NOT earn ATTESTED when replayed onto app-c@2.0.0", async () => {
  const builderKey = await makeKeypair();
  const trustedBuilders = makeTrustStore([{ id: "trusted-builder@ci", pubkey_b64: builderKey.publicKey }]);
  const recordForV1 = await buildAttestationRecord({
    appId: "app-c", version: "1.0.0", builderIdentity: "trusted-builder@ci", builderPrivateKey: builderKey.privateKey, builderPublicKey: builderKey.publicKey,
  });
  // Same app id, but the SAME record is attached to a DIFFERENT version.
  const app = attestApp({
    id: "app-c",
    versions: [
      { version_name: "1.0.0", version_code: 1, source: {}, build: {}, artifact: {}, signing: { state: "unpublished" }, reproducible_build: recordForV1 },
      { version_name: "2.0.0", version_code: 2, source: {}, build: {}, artifact: {}, signing: { state: "unpublished" }, reproducible_build: recordForV1 },
    ],
  });
  const norm = await normalizeEntry(app, { repoId: "repo-replay-v", repoLabel: "Replay Repo V", repoPriority: 10, trustedBuilders, crl: null });

  assert.equal(norm.versions[0].attestation.trusted, true, "sanity: version 1.0.0 legitimately earns it");
  assert.equal(norm.versions[1].attestation.trusted, false, "version 2.0.0 must NOT earn it from a record signed for version 1.0.0");
  assert.match(norm.versions[1].attestation.reason, /does not match this version entry's version "2\.0\.0"/);
  // Overall entry still earns ATTESTED because version 1.0.0 legitimately does — proves the fix is precise
  // (per-version binding), not an over-broad "any mismatch anywhere strips the whole entry" hammer.
  assert.equal(norm.attestedEarned, true);
});

console.log(`\ndepot: ${passed} checks passed`);
