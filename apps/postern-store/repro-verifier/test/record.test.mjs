// Real, executable proof that the signed `reproducible_build` record +
// builder-identity trust check (the red-team #2 fix) actually works: a
// record signed by a pinned-trusted builder earns ATTESTED; a repo forging
// a PASS record with an untrusted/self-signed builder identity does NOT,
// even though tier says attestable-nix and the record's own signature is
// internally self-consistent; nondeterminism and divergence verdicts never
// earn the badge even from a trusted, correctly-signed builder; a tampered
// signature is rejected; nothing here ever throws on bad input.
//
// Also covers the DEPOT FINDING H1 fix (two-builder quorum): decideAttestedBadge()
// now takes `records` (plural) and requires >=2 of them to independently verify
// AND resolve to DISTINCT pinned trusted-builder keys — a single record (however
// valid) or two records that collapse to one signer must never earn ATTESTED.
import { test } from "node:test";
import assert from "node:assert/strict";

import { generateKeypair } from "../lib/keys.mjs";
import { buildRecord, signRecord } from "../lib/build-record.mjs";
import { verifyBuildRecord, verifyTwoBuilderQuorum, decideAttestedBadge, BADGE } from "../lib/verify-record.mjs";
import { makeTrustStore, isTrustedBuilder } from "../lib/builder-trust.mjs";

const TRUSTED_BUILDER_ID = "postern-ci-builder-1";
const TRUSTED_BUILDER_ID_2 = "postern-ci-builder-2";
const trustedKp = generateKeypair();
const trustedKp2 = generateKeypair();
const attackerKp = generateKeypair(); // NOT pinned anywhere — the "self" builder identity

const trustStore = makeTrustStore([
  { id: TRUSTED_BUILDER_ID, pubkey_b64: trustedKp.publicKey, label: "Postern CI builder #1 (pinned)" },
  { id: TRUSTED_BUILDER_ID_2, pubkey_b64: trustedKp2.publicKey, label: "Postern CI builder #2 (pinned, independent host)" },
]);

function baseRecord(resultOverrides = {}) {
  return buildRecord({
    appId: "keepassxc",
    version: "2.7.x@" + "a".repeat(40),
    source: {
      repo_url: "https://github.com/keepassxreboot/keepassxc",
      commit: "a".repeat(40),
      build_expr: "nixpkgs#keepassxc",
      build_expr_source: "nixpkgs",
      flake_lock_rev: "b".repeat(40),
    },
    buildEnv: {
      nix_version: "2.24.0",
      system: "x86_64-linux",
      sandbox: "hermetic",
      builder_hosts: ["builder-a", "builder-b"],
    },
    output: {
      store_path: "/nix/store/MOCK-abc123-keepassxc-2.7.x",
      nar_hash: "sha256:MOCK0000000000000000000000000000000000000000000000000000000000",
      shipped_artifact_hash: "sha256:MOCK0000000000000000000000000000000000000000000000000000000000",
    },
    result: { rebuild_match: true, shipped_match: true, verdict: "PASS", diagnostic: null, ...resultOverrides },
    run: { timestamp: "2026-07-13T00:00:00Z", run_by: "postern-ci@builder-a", verifier_version: "repro-verifier@0.0.0" },
  });
}

function signAs(kp, id, record = baseRecord()) {
  return signRecord(record, { builderId: id, builderPrivKeyB64: kp.privateKey, builderPubKeyB64: kp.publicKey });
}

test("1. record signed by a TRUSTED builder, verdict PASS -> signature valid, builder trusted, per-record ATTESTED-eligible (quorum decided separately)", () => {
  const record = signAs(trustedKp, TRUSTED_BUILDER_ID);

  const verdict = verifyBuildRecord({ record, trustStore });
  assert.equal(verdict.signatureValid, true);
  assert.equal(verdict.builderTrusted, true);
  assert.equal(verdict.badge, BADGE.ATTESTED);
});

test("1a. DEPOT FINDING H1: a SINGLE record — however valid, trusted, and PASS — is NOT enough on its own to earn the client-facing ATTESTED badge", () => {
  const record = signAs(trustedKp, TRUSTED_BUILDER_ID);
  const decision = decideAttestedBadge({ tier: "attestable-nix", records: [record], trustStore });
  assert.equal(decision.badge, BADGE.STRIPPED, "one signer, no matter how trusted, is not a two-builder quorum");
  assert.match(decision.reason, /distinct trusted builders? required|2 distinct/i);
});

test("1b. DEPOT FINDING H1 fix: TWO records signed by TWO DISTINCT pinned trusted builders -> ATTESTED", () => {
  const recordA = signAs(trustedKp, TRUSTED_BUILDER_ID);
  const recordB = signAs(trustedKp2, TRUSTED_BUILDER_ID_2, baseRecord()); // independent build, independent signer

  const quorum = verifyTwoBuilderQuorum({ records: [recordA, recordB], trustStore });
  assert.equal(quorum.ok, true);
  assert.equal(quorum.distinctBuilderCount, 2);

  const decision = decideAttestedBadge({ tier: "attestable-nix", records: [recordA, recordB], trustStore });
  assert.equal(decision.badge, BADGE.ATTESTED, "two distinct trusted builders each independently signing a valid PASS record satisfies the quorum");
});

test("1c. DEPOT FINDING H1 (the exact finding): TWO records that COLLAPSE to a SINGLE builder identity/key -> NOT attested", () => {
  // Same builder signs twice — e.g. a compromised/dishonest single CI signer
  // submitting two "independent-looking" records, or the same record replayed.
  const recordA = signAs(trustedKp, TRUSTED_BUILDER_ID);
  const recordB = signAs(trustedKp, TRUSTED_BUILDER_ID, baseRecord()); // same key, freshly re-signed — still one signer

  const quorum = verifyTwoBuilderQuorum({ records: [recordA, recordB], trustStore });
  assert.equal(quorum.ok, false);
  assert.equal(quorum.distinctBuilderCount, 1, "two records, but only ONE distinct trusted builder key among them");
  assert.match(quorum.reason, /1 distinct pinned trusted builder/);

  const decision = decideAttestedBadge({ tier: "attestable-nix", records: [recordA, recordB], trustStore });
  assert.equal(decision.badge, BADGE.STRIPPED, "two records collapsing to one signer must never earn ATTESTED (Depot finding H1)");

  // The literal duplicate case (byte-identical record submitted twice) must
  // collapse the same way.
  const dup = verifyTwoBuilderQuorum({ records: [recordA, recordA], trustStore });
  assert.equal(dup.ok, false);
  assert.equal(dup.distinctBuilderCount, 1);
});

test("1d. DEPOT FINDING H1: one TRUSTED + one UNTRUSTED record -> still NOT attested (only 1 distinct trusted builder)", () => {
  const trustedRecord = signAs(trustedKp, TRUSTED_BUILDER_ID);
  const untrustedRecord = signAs(attackerKp, "attacker-self-hosted-builder", baseRecord()); // never pinned

  const quorum = verifyTwoBuilderQuorum({ records: [trustedRecord, untrustedRecord], trustStore });
  assert.equal(quorum.ok, false);
  assert.equal(quorum.distinctBuilderCount, 1, "the untrusted record never qualifies, so only the one trusted record counts");
  assert.equal(quorum.qualifyingCount, 1);

  const decision = decideAttestedBadge({ tier: "attestable-nix", records: [trustedRecord, untrustedRecord], trustStore });
  assert.equal(decision.badge, BADGE.STRIPPED, "an untrusted second 'builder' buys nothing toward quorum");
});

test("2. RED-TEAM #2: repo forges a PASS record, self-signs with an UNTRUSTED builder-identity reusing the TRUSTED id string -> badge STRIPPED despite a self-consistent signature and tier:attestable-nix", () => {
  // Attacker controls a repo, wants ATTESTED without ever running a real
  // build. They generate their own keypair, claim `builder_identity.id` as
  // the WELL-KNOWN trusted id (id-squatting), and sign a hand-crafted PASS
  // record with their own key. The signature verifies (against the
  // attacker's own embedded key) — but it must NOT match the pinned key the
  // client trusts for that id.
  const forged = signAs(attackerKp, TRUSTED_BUILDER_ID);

  const verdict = verifyBuildRecord({ record: forged, trustStore });
  assert.equal(verdict.signatureValid, true, "the forged signature is internally self-consistent (attacker signed with their own matching key)...");
  assert.equal(verdict.builderTrusted, false, "...but the embedded pubkey does not match the pinned key for that id — id-squatting caught");
  assert.equal(verdict.badge, BADGE.STRIPPED);

  const decision = decideAttestedBadge({ tier: "attestable-nix", records: [forged], trustStore });
  assert.equal(decision.badge, BADGE.STRIPPED, "tier:attestable-nix string alone must never be enough to earn ATTESTED");
});

test("2b. RED-TEAM #2 variant: forged record uses its own unknown/self builder id (no id-squatting attempted) -> also STRIPPED", () => {
  const forged = signAs(attackerKp, "attacker-self-hosted-builder");
  const verdict = verifyBuildRecord({ record: forged, trustStore });
  assert.equal(verdict.signatureValid, true);
  assert.equal(verdict.builderTrusted, false);
  assert.equal(verdict.badge, BADGE.STRIPPED);

  const decision = decideAttestedBadge({ tier: "attestable-nix", records: [forged], trustStore });
  assert.equal(decision.badge, BADGE.STRIPPED);
  assert.equal(isTrustedBuilder(trustStore, forged.builder_identity), false);
});

test("3. nondeterminism FAIL, even from a trusted, correctly-signed builder -> badge never ATTESTED", () => {
  const record = signAs(trustedKp, TRUSTED_BUILDER_ID, baseRecord({ rebuild_match: false, shipped_match: null, verdict: "FAIL_NONDETERMINISM", diagnostic: "builder A/B store paths differ" }));

  const verdict = verifyBuildRecord({ record, trustStore });
  assert.equal(verdict.signatureValid, true);
  assert.equal(verdict.builderTrusted, true);
  assert.equal(verdict.badge, BADGE.STRIPPED);
  assert.match(verdict.reason, /FAIL_NONDETERMINISM/);
});

test("4. mutate -> divergence FAIL -> badge stripped even though the rebuild is internally reproducible", () => {
  const record = signAs(
    trustedKp,
    TRUSTED_BUILDER_ID,
    baseRecord({ rebuild_match: true, shipped_match: false, verdict: "FAIL_DIVERGENCE", diagnostic: "rebuild does not match the shipped artifact" })
  );

  const verdict = verifyBuildRecord({ record, trustStore });
  assert.equal(verdict.signatureValid, true);
  assert.equal(verdict.builderTrusted, true);
  assert.equal(verdict.badge, BADGE.STRIPPED);
  assert.match(verdict.reason, /FAIL_DIVERGENCE/);
});

test("5. tampered signature bytes (single bit flip on an otherwise legitimate, trusted record) -> signature invalid, badge stripped", () => {
  const record = signAs(trustedKp, TRUSTED_BUILDER_ID);
  const sigBytes = Buffer.from(record.signature.signature_b64, "base64");
  sigBytes[0] ^= 0xff;
  const tampered = { ...record, signature: { ...record.signature, signature_b64: sigBytes.toString("base64") } };

  const verdict = verifyBuildRecord({ record: tampered, trustStore });
  assert.equal(verdict.signatureValid, false);
  assert.equal(verdict.builderTrusted, false);
  assert.equal(verdict.badge, BADGE.STRIPPED);
});

test("5b. tampered record body (mutate a claimed field, keep the original signature) -> signature invalid, badge stripped", () => {
  const record = signAs(trustedKp, TRUSTED_BUILDER_ID);
  const tampered = { ...record, result: { ...record.result, verdict: "PASS", shipped_match: true, rebuild_match: true, diagnostic: "INJECTED" } };

  const verdict = verifyBuildRecord({ record: tampered, trustStore });
  assert.equal(verdict.signatureValid, false, "canonical bytes changed once the record body was mutated post-signing — original signature no longer verifies");
  assert.equal(verdict.badge, BADGE.STRIPPED);
});

test("6. tier gate: even TWO fully valid, trusted, PASS records (distinct builders) cannot earn ATTESTED on a non-attestable-nix tier", () => {
  const recordA = signAs(trustedKp, TRUSTED_BUILDER_ID);
  const recordB = signAs(trustedKp2, TRUSTED_BUILDER_ID_2, baseRecord());
  const decision = decideAttestedBadge({ tier: "pmos-overlay", records: [recordA, recordB], trustStore });
  assert.equal(decision.badge, BADGE.STRIPPED);
});

test("7. missing/malformed record -> STRIPPED, never throws", () => {
  assert.equal(verifyBuildRecord({ record: null, trustStore }).badge, BADGE.STRIPPED);
  assert.equal(verifyBuildRecord({ record: {}, trustStore }).badge, BADGE.STRIPPED);
  assert.equal(verifyBuildRecord({ record: { builder_identity: {}, signature: {} }, trustStore }).badge, BADGE.STRIPPED);
  assert.doesNotThrow(() => decideAttestedBadge({ tier: "attestable-nix", records: undefined, trustStore }));
  assert.equal(decideAttestedBadge({ tier: "attestable-nix", records: undefined, trustStore }).badge, BADGE.STRIPPED);
  assert.equal(decideAttestedBadge({ tier: "attestable-nix", records: [null, {}, { builder_identity: {}, signature: {} }], trustStore }).badge, BADGE.STRIPPED);
});

test("8. ADVERSARIAL-REVIEW FIX (CRITICAL, record/entry binding): a genuine, trusted, PASS record for one app/version is REPLAYED onto a different app -> STRIPPED, not ATTESTED", () => {
  // baseRecord() above is built with appId: "keepassxc". A trusted builder
  // signs it for real — no forged signature anywhere. The attack: a
  // dishonest (or compromised) repo attaches this SAME, validly-signed
  // record to a completely different app's catalog entry.
  const record = signAs(trustedKp, TRUSTED_BUILDER_ID);

  // Sanity: checked against its OWN app_id/version, it is honored.
  const ownVerdict = verifyBuildRecord({ record, trustStore, appId: "keepassxc", version: record.version });
  assert.equal(ownVerdict.badge, BADGE.ATTESTED, "sanity: the record legitimately earns ATTESTED for the app/version it was actually built for");

  // Attack: same record, but the catalog entry being evaluated is a DIFFERENT app.
  // The shared canonical decision core (reproducible-build-record.mjs's
  // decideBadge()) checks app/version binding BEFORE spending a signature
  // verification on a record that can never be honored anyway — so a
  // misbound record is rejected via `bindingValid: false`, not by first
  // reporting `signatureValid: true` and then separately failing binding.
  // Either order rejects the replay; this is the shared core's order.
  const replayedVerdict = verifyBuildRecord({ record, trustStore, appId: "totally-different-app", version: record.version });
  assert.equal(replayedVerdict.bindingValid, false, "the record fails the app_id binding check — a replay, not a forgery");
  assert.equal(replayedVerdict.badge, BADGE.STRIPPED, "a record signed for app 'keepassxc' must never earn ATTESTED when replayed onto a different app");
  assert.match(replayedVerdict.reason, /record\.app_id "keepassxc" does not match this catalog entry's id "totally-different-app"/);

  const decision = decideAttestedBadge({ tier: "attestable-nix", records: [record], trustStore, appId: "totally-different-app", version: record.version });
  assert.equal(decision.badge, BADGE.STRIPPED, "decideAttestedBadge must also reject the replay, not just verifyBuildRecord");
});

test("8b. ADVERSARIAL-REVIEW FIX: a genuine, trusted, PASS record is replayed onto a DIFFERENT VERSION of the SAME app -> STRIPPED", () => {
  const record = signAs(trustedKp, TRUSTED_BUILDER_ID); // built for version "2.7.x@aaa...a"

  const replayedVerdict = verifyBuildRecord({ record, trustStore, appId: "keepassxc", version: "9.9.9-not-the-signed-version" });
  assert.equal(replayedVerdict.badge, BADGE.STRIPPED);
  assert.match(replayedVerdict.reason, /does not match this version entry's version/);

  const decision = decideAttestedBadge({ tier: "attestable-nix", records: [record], trustStore, appId: "keepassxc", version: "9.9.9-not-the-signed-version" });
  assert.equal(decision.badge, BADGE.STRIPPED);
});

test("8c. omitting appId/version (no entry to bind to) preserves old behavior — no binding check performed", () => {
  const record = signAs(trustedKp, TRUSTED_BUILDER_ID);
  const verdict = verifyBuildRecord({ record, trustStore }); // no appId/version passed
  assert.equal(verdict.badge, BADGE.ATTESTED, "callers with no surrounding entry (e.g. standalone CLI inspection) are unaffected");
});
