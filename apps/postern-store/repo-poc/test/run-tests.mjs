// Real, executable proof that the postern.repo/v1 format + client verifier
// (docs/store-fdroid/A-repo-client.md) actually works: sign, verify, detect
// tampering, detect a wrong pinned key, detect a rollback, and strip
// self-declared dishonest claims client-side. Run with:
//   node --test test/
import { test } from "node:test";
import assert from "node:assert/strict";

import { generateKeypair } from "../lib/keys.mjs";
import { buildSignedIndex, GOOD_ARTIFACT_BYTES, SWAPPED_ARTIFACT_BYTES } from "../lib/build-index.mjs";
import { verifyRepoIndex, TRUST } from "../lib/verify.mjs";

const repoKp = generateKeypair();
const TIMESTAMP = 1_800_000_000;

function buildValid() {
  return buildSignedIndex({ privateKeyB64: repoKp.privateKey, publicKeyB64: repoKp.publicKey, timestamp: TIMESTAMP });
}

test("1. valid index + correct pinned key -> VERIFIED, adopted, honesty invariants enforced, checksums checked", () => {
  const { indexBytes, sigBytes } = buildValid();

  const result = verifyRepoIndex({
    indexBytes,
    sigBytes,
    pinnedPubKeyB64: repoKp.publicKey,
    artifacts: {
      "vault-mirror": GOOD_ARTIFACT_BYTES, // matches the claimed checksum
      "courier-mirror": SWAPPED_ARTIFACT_BYTES, // does NOT match the claimed checksum
    },
  });

  assert.equal(result.state, TRUST.VERIFIED);
  assert.equal(result.adopted, true);
  assert.equal(result.apps.length, 5);

  // --- honesty invariant 1: proprietary can never be hosted_by_us:true ---
  const proprietary = result.apps.find((a) => a.id === "some-proprietary-app");
  assert.equal(proprietary.dist.hostedByUs, false, "proprietary app must be de-hosted");
  assert.equal(proprietary.dist.model, "link", "proprietary app must be coerced to link");
  assert.equal(proprietary.dist.checksum, null, "checksum must be nulled once de-hosted");
  assert.ok(
    result.strippedByApp["some-proprietary-app"].some((s) => s.includes("proprietary")),
    "strip reason must be recorded"
  );

  // --- honesty invariant 2: attestable survives ONLY on tier:attestable-nix ---
  const laundered = result.apps.find((a) => a.id === "laundered-attestable-tool");
  assert.equal(laundered.tier, "pmos-overlay");
  assert.ok(!laundered.security.includes("attestable"), "attestable tag must be stripped on a non-Nix tier");
  assert.ok(laundered.security.includes("post-quantum"), "unrelated, honest security tags must survive");
  assert.ok(
    result.strippedByApp["laundered-attestable-tool"].some((s) => s.includes("attestable claimed on tier:pmos-overlay")),
    "strip reason must name the false tier claim"
  );

  // --- a LEGITIMATE attestable-nix entry must NOT be stripped (no over-stripping) ---
  const vault = result.apps.find((a) => a.id === "vault-mirror");
  assert.ok(vault.security.includes("attestable"), "attestable-nix tier entries keep the badge");
  assert.equal(result.strippedByApp["vault-mirror"], undefined);

  // --- §1.4 per-package checksum verification ---
  const vaultCk = result.checksumResults.find((c) => c.id === "vault-mirror");
  assert.equal(vaultCk.status, "match");
  const courierCk = result.checksumResults.find((c) => c.id === "courier-mirror");
  assert.equal(courierCk.status, "mismatch", "a swapped artifact must be caught even though the index itself verified");
});

test("2. tampered index (bit-flipped bytes, original .sig kept) -> TAMPERED, previously-cached stands", () => {
  const { indexBytes, sigBytes } = buildValid();

  // Mutate one byte of the exact served bytes after signing — e.g. flip a
  // character inside a JSON string value, simulating a MITM/compromised-host edit.
  const tampered = Buffer.from(indexBytes);
  const needle = Buffer.from('"Example Journalist Kit"');
  const at = tampered.indexOf(needle);
  assert.ok(at >= 0, "fixture must contain the string we intend to tamper");
  tampered[at + 1] = "X".charCodeAt(0); // "Example..." -> "XXample..."

  const result = verifyRepoIndex({ indexBytes: tampered, sigBytes, pinnedPubKeyB64: repoKp.publicKey });

  assert.equal(result.state, TRUST.TAMPERED);
  assert.equal(result.adopted, false);
  assert.equal(result.apps.length, 0, "a tampered fetch must never be adopted or parsed into apps");
});

test("3a. correctly-signed index verified against the WRONG pinned key -> TAMPERED (not a separate 'wrong key' state)", () => {
  const { indexBytes, sigBytes } = buildValid();
  const attackerOrUnrelatedKp = generateKeypair();

  const result = verifyRepoIndex({ indexBytes, sigBytes, pinnedPubKeyB64: attackerOrUnrelatedKp.publicKey });

  // See the header comment in lib/verify.mjs: per A-repo-client.md §3.2's
  // trust-state table, verifying against a key that did not produce the
  // signature is mechanically indistinguishable from a tampered payload —
  // both fail crypto.subtle.verify()/nodeVerify(). There is no separate
  // "WRONG_KEY" state in the design; this IS what "wrong key" resolves to.
  assert.equal(result.state, TRUST.TAMPERED);
  assert.equal(result.adopted, false);
});

test("3b. genuine UNVERIFIABLE — engine cannot check Ed25519 at all (honest 'can't verify here')", () => {
  const { indexBytes, sigBytes } = buildValid();

  const result = verifyRepoIndex({
    indexBytes,
    sigBytes,
    pinnedPubKeyB64: repoKp.publicKey,
    engineHasEd25519: false, // simulates ed25519Available() === false
  });

  assert.equal(result.state, TRUST.UNVERIFIABLE);
  assert.equal(result.adopted, false);
});

test("4. anti-rollback: valid signature + valid new key, but repo.timestamp is OLDER than last-adopted -> rejected, not adopted", () => {
  const older = buildSignedIndex({ privateKeyB64: repoKp.privateKey, publicKeyB64: repoKp.publicKey, timestamp: TIMESTAMP - 1000 });

  const result = verifyRepoIndex({
    indexBytes: older.indexBytes,
    sigBytes: older.sigBytes,
    pinnedPubKeyB64: repoKp.publicKey,
    previousTimestamp: TIMESTAMP, // client already adopted a newer index for this key
  });

  assert.equal(result.state, TRUST.VERIFIED, "the signature itself is still valid...");
  assert.equal(result.adopted, false, "...but a stale timestamp must never be adopted (anti-rollback, §1.3)");
  assert.equal(result.rollback, true);
});

test("5. missing signature file -> UNSIGNED, never a fake VERIFIED", () => {
  const { indexBytes } = buildValid();
  const result = verifyRepoIndex({ indexBytes, sigBytes: null, pinnedPubKeyB64: repoKp.publicKey });
  assert.equal(result.state, TRUST.UNSIGNED);
  assert.equal(result.adopted, false);
});

test("6. no key pinned yet (TOFU candidate, nothing to compare against) -> UNSIGNED", () => {
  const { indexBytes, sigBytes } = buildValid();
  const result = verifyRepoIndex({ indexBytes, sigBytes, pinnedPubKeyB64: null });
  assert.equal(result.state, TRUST.UNSIGNED);
});
