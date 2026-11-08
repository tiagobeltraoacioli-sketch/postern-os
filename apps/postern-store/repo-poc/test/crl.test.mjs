// Real, executable proof that the Depot revocations.json CRL (lib/crl.mjs,
// ported from enterprise/licensing/src/crl.ts) actually works: sign a CRL,
// revoke an app -> client hides it; anti-rollback; tampered CRL rejected;
// absent CRL -> best-effort + disclosed. Run with:
//   node --test test/crl.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";

import { generateKeypair } from "../lib/keys.mjs";
import {
  buildCrl,
  verifyCrl,
  pickNewerCrl,
  crlFreshness,
  isIdRevoked,
  isVersionRevoked,
  checkAppRevocation,
  applyCrlToApps,
  resolveCrl,
  CRL_STATE,
  versionKey,
} from "../lib/crl.mjs";

const repoKp = generateKeypair();
const KID = "test-repo-kid";
const NOW = new Date(1_800_000_000 * 1000);
const REPO_ID = "com.example.journalist-kit";

function buildValidCrl(overrides = {}) {
  return buildCrl(repoKp.privateKey, {
    repoId: REPO_ID,
    kid: KID,
    version: 1,
    revokedIds: ["courier-mirror"],
    revokedVersions: ["vault-mirror@13"],
    now: NOW,
    ...overrides,
  });
}

const SHELF = [
  { id: "organic-maps" },
  { id: "vault-mirror", versionCode: 14 },
  { id: "vault-mirror-old", versionCode: 13 }, // distinct id on purpose, see versionKey test below
  { id: "courier-mirror" },
  { id: "laundered-attestable-tool" },
];

test("1. sign a CRL, revoke an app -> client hides it (applyCrlToApps pulls it off the shelf)", () => {
  const crl = buildValidCrl();
  const verdict = verifyCrl(repoKp.publicKey, crl);
  assert.equal(verdict.ok, true, "a freshly-built CRL must verify against its own signer's public key");

  const { apps, removed } = applyCrlToApps(SHELF, crl);

  assert.ok(!apps.some((a) => a.id === "courier-mirror"), "whole-app revoked id must be removed from the shelf");
  assert.ok(apps.some((a) => a.id === "organic-maps"), "non-revoked apps must remain");
  assert.ok(apps.some((a) => a.id === "laundered-attestable-tool"), "non-revoked apps must remain");
  assert.equal(apps.length, SHELF.length - 1);

  assert.equal(removed.length, 1);
  assert.equal(removed[0].id, "courier-mirror");
  assert.match(removed[0].reason, /whole-app revocation/);

  // Direct predicates, independent of applyCrlToApps, exercised too.
  assert.equal(isIdRevoked(crl, "courier-mirror"), true);
  assert.equal(isIdRevoked(crl, "organic-maps"), false);
  assert.equal(checkAppRevocation(crl, "courier-mirror").revoked, true);
});

test("1b. single-VERSION revocation only pulls that version, not the whole app id", () => {
  const crl = buildValidCrl();
  // "vault-mirror" at versionCode 14 is NOT the revoked version (13 is).
  const shelf = [
    { id: "vault-mirror", versionCode: 14 },
    { id: "vault-mirror", versionCode: 13 }, // same id, the revoked version
  ];
  const { apps, removed } = applyCrlToApps(shelf, crl);
  assert.equal(apps.length, 1);
  assert.equal(apps[0].versionCode, 14, "the non-revoked version of the same app id must survive");
  assert.equal(removed.length, 1);
  assert.equal(removed[0].versionCode, 13);
  assert.match(removed[0].reason, /single-version revocation/);

  assert.equal(isVersionRevoked(crl, "vault-mirror", 13), true);
  assert.equal(isVersionRevoked(crl, "vault-mirror", 14), false);
  assert.equal(versionKey("vault-mirror", 13), "vault-mirror@13");
});

test("1c. an entry with no versionCode field is only checked against whole-id revocation (forward-compat)", () => {
  const crl = buildValidCrl();
  const shelf = [{ id: "vault-mirror" }]; // no versionCode at all
  const { apps, removed } = applyCrlToApps(shelf, crl);
  assert.equal(apps.length, 1, "id itself is not on revoked_ids, and there's no version to check -> survives");
  assert.equal(removed.length, 0);
});

test("2. tampered CRL (bit-flipped payload field, signature unchanged) -> verifyCrl rejects it", () => {
  const crl = buildValidCrl();
  const tampered = {
    payload: { ...crl.payload, revoked_ids: [] }, // attacker tries to un-revoke by editing the payload
    sig: crl.sig, // keeps the ORIGINAL signature, now over the wrong bytes
  };
  const verdict = verifyCrl(repoKp.publicKey, tampered);
  assert.equal(verdict.ok, false);
  assert.equal(verdict.reason, "bad-crl-signature");
});

test("2b. tampered fetch end-to-end via resolveCrl -> TAMPERED, previously-cached CRL stands", () => {
  const cached = buildValidCrl({ version: 1 });
  const attackerCrl = { payload: { ...cached.payload, version: 2, revoked_ids: [] }, sig: cached.sig };
  const fetchedBytes = Buffer.from(JSON.stringify(attackerCrl), "utf8");

  const result = resolveCrl({ fetchedBytes, pinnedPubKeyB64: repoKp.publicKey, repoId: REPO_ID, cachedCrl: cached, now: NOW });

  assert.equal(result.state, CRL_STATE.TAMPERED);
  assert.equal(result.crl, cached, "rejected fetch must fall back to the previously-cached, verified CRL");
  assert.match(result.disclosure, /does NOT verify/);
});

test("2c. malformed JSON in the fetch -> treated as tampered, never adopted", () => {
  const cached = buildValidCrl({ version: 1 });
  const result = resolveCrl({
    fetchedBytes: Buffer.from("{not valid json", "utf8"),
    pinnedPubKeyB64: repoKp.publicKey, repoId: REPO_ID,
    cachedCrl: cached,
    now: NOW,
  });
  assert.equal(result.state, CRL_STATE.TAMPERED);
  assert.equal(result.crl, cached);
});

test("3a. anti-rollback: an OLDER but validly-signed CRL is not adopted over a newer cached one (pickNewerCrl)", () => {
  const newer = buildValidCrl({ version: 5, revokedIds: ["courier-mirror"] });
  const older = buildValidCrl({ version: 2, revokedIds: [] }); // attacker replays an old, still-validly-signed CRL that un-revokes everything

  assert.equal(pickNewerCrl(newer, older), newer, "pickNewerCrl must keep the higher version regardless of argument order semantics");
  assert.equal(pickNewerCrl(older, newer), newer);
});

test("3b. anti-rollback end-to-end via resolveCrl: stale (older-version) fetched CRL -> ROLLBACK_REJECTED, cached CRL kept, not adopted", () => {
  const cached = buildValidCrl({ version: 5, revokedIds: ["courier-mirror"] });
  const staleReplay = buildValidCrl({ version: 2, revokedIds: [] }); // validly signed, but an OLDER version
  const fetchedBytes = Buffer.from(JSON.stringify(staleReplay), "utf8");

  const result = resolveCrl({ fetchedBytes, pinnedPubKeyB64: repoKp.publicKey, repoId: REPO_ID, cachedCrl: cached, now: NOW });

  assert.equal(result.state, CRL_STATE.ROLLBACK_REJECTED);
  assert.equal(result.crl, cached, "must keep serving the newer cached CRL, not the rolled-back one");
  assert.equal(result.crl.payload.version, 5);
  // Prove the rollback attempt's payload really would have un-revoked, and that it did NOT take effect:
  const { apps } = applyCrlToApps([{ id: "courier-mirror" }], result.crl);
  assert.equal(apps.length, 0, "courier-mirror must STILL be revoked — the rollback attempt must not have been adopted");
});

test("4. a fresh, newer fetched CRL IS adopted over an older cached one", () => {
  const cached = buildValidCrl({ version: 1, revokedIds: [] });
  const fresh = buildValidCrl({ version: 2, revokedIds: ["courier-mirror"] });
  const fetchedBytes = Buffer.from(JSON.stringify(fresh), "utf8");

  const result = resolveCrl({ fetchedBytes, pinnedPubKeyB64: repoKp.publicKey, repoId: REPO_ID, cachedCrl: cached, now: NOW });

  assert.equal(result.state, CRL_STATE.ADOPTED);
  assert.equal(result.crl.payload.version, 2);
  assert.match(result.disclosure, /adopted/);
});

test("4b. ADVERSARIAL-REVIEW FIX: same-version republish with a WEAKER (emptier) revocation list is NOT adopted (version-tie)", () => {
  // A repo (or anyone who still holds the signing key) re-signs the SAME
  // version number with fewer revocations than what's cached — e.g. trying
  // to quietly "forgive" a revoked entry without bumping version. Ties must
  // never be treated as newer.
  const cached = buildValidCrl({ version: 3, revokedIds: ["courier-mirror"] });
  const sameVersionWeaker = buildValidCrl({ version: 3, revokedIds: [] }); // same version, empty revocations
  const fetchedBytes = Buffer.from(JSON.stringify(sameVersionWeaker), "utf8");

  const result = resolveCrl({ fetchedBytes, pinnedPubKeyB64: repoKp.publicKey, repoId: REPO_ID, cachedCrl: cached, now: NOW });

  assert.equal(result.state, CRL_STATE.ROLLBACK_REJECTED, "a same-version republish must not be adopted just because it isn't literally older");
  assert.equal(result.crl, cached, "the cached CRL (with the real revocation) must stand");
  assert.match(result.disclosure, /SAME version/);

  const { apps } = applyCrlToApps([{ id: "courier-mirror" }], result.crl);
  assert.equal(apps.length, 0, "courier-mirror must STILL be revoked — the weaker same-version CRL must not have taken effect");
});

test("4c. pickNewerCrl itself: a tie (equal version) keeps the CACHED CRL, never the freshly-fetched one", () => {
  const a = buildValidCrl({ version: 4, revokedIds: ["courier-mirror"] });
  const b = buildValidCrl({ version: 4, revokedIds: [] }); // same version, different (weaker) content
  assert.equal(pickNewerCrl(a, b), a, "cached must win a tie");
  assert.equal(pickNewerCrl(b, a), b, "still: first-arg (cached) wins a tie, second-arg (fetched) never does");
});

test("4d. ADVERSARIAL-REVIEW FIX: a repo_id-bound CRL replayed onto a DIFFERENT repo (shared operator key) is rejected, not adopted", () => {
  // PoC: two repos share one operator key. A network attacker takes repo A's
  // genuinely-signed CRL (here, one with NO revocations) and serves it back
  // as repo B's revocations.json. The Ed25519 signature checks out fine
  // (same key) — the attack is a cross-repo REPLAY, not a forged signature.
  // Without the repo_id check this would ADOPT, silently suppressing repo
  // B's real revocations, and its version would become the new anti-rollback
  // floor for repo B — permanently locking out repo B's genuine CRL.
  const repoACrl = buildCrl(repoKp.privateKey, {
    repoId: "repo-a.example",
    kid: KID,
    version: 99, // deliberately high, so if adopted it would ALSO poison anti-rollback for repo B
    revokedIds: [], // empty — this is what "silently suppresses repo B's revocations" looks like
    now: NOW,
  });
  const fetchedBytes = Buffer.from(JSON.stringify(repoACrl), "utf8");

  const repoBCachedCrl = buildCrl(repoKp.privateKey, {
    repoId: "repo-b.example",
    kid: KID,
    version: 1,
    revokedIds: ["courier-mirror"],
    now: NOW,
  });

  const result = resolveCrl({
    fetchedBytes,
    pinnedPubKeyB64: repoKp.publicKey, // SAME shared key for both repos
    repoId: "repo-b.example", // resolving for repo B
    cachedCrl: repoBCachedCrl,
    now: NOW,
  });

  assert.equal(result.state, CRL_STATE.TAMPERED, "a CRL signed for a different repo_id must be rejected outright, not adopted");
  assert.equal(result.crl, repoBCachedCrl, "repo B's own cached CRL must stand — never silently swapped for repo A's replayed CRL");
  assert.match(result.disclosure, /repo-id-mismatch|does NOT verify/);

  // Prove repo B's real revocation is still enforced (was NOT suppressed):
  const { apps } = applyCrlToApps([{ id: "courier-mirror" }], result.crl);
  assert.equal(apps.length, 0, "repo B's courier-mirror revocation must still be enforced after the cross-repo replay attempt");

  // And a genuine, higher-version repo-B CRL must STILL be adoptable afterwards
  // (the replay attempt must not have poisoned repo B's anti-rollback floor).
  const repoBRealUpdate = buildCrl(repoKp.privateKey, {
    repoId: "repo-b.example",
    kid: KID,
    version: 2,
    revokedIds: ["courier-mirror", "laundered-attestable-tool"],
    now: NOW,
  });
  const secondResult = resolveCrl({
    fetchedBytes: Buffer.from(JSON.stringify(repoBRealUpdate), "utf8"),
    pinnedPubKeyB64: repoKp.publicKey,
    repoId: "repo-b.example",
    cachedCrl: result.crl,
    now: NOW,
  });
  assert.equal(secondResult.state, CRL_STATE.ADOPTED, "repo B's genuine higher-version CRL must still adopt cleanly after the rejected replay");
  assert.equal(secondResult.crl.payload.version, 2);
});

test("4e. verifyCrl directly: repo_id mismatch is rejected even with a perfectly valid signature", () => {
  const crl = buildValidCrl(); // signed for REPO_ID
  const verdict = verifyCrl(repoKp.publicKey, crl, "some-other-repo-id");
  assert.equal(verdict.ok, false);
  assert.match(verdict.reason, /repo-id-mismatch/);

  // Omitting expectedRepoId (3rd arg) preserves old callers that don't yet bind — no check performed.
  const noBindVerdict = verifyCrl(repoKp.publicKey, crl);
  assert.equal(noBindVerdict.ok, true);
});

test("5. absent CRL (fetch failed, no cache either) -> NO_CRL, best-effort, apps unfiltered, disclosed honestly", () => {
  const result = resolveCrl({ fetchedBytes: null, pinnedPubKeyB64: repoKp.publicKey, repoId: REPO_ID, cachedCrl: null, now: NOW });

  assert.equal(result.state, CRL_STATE.NO_CRL);
  assert.equal(result.crl, null);
  assert.match(result.disclosure, /WITHOUT revocation filtering/);
  assert.match(result.disclosure, /network attacker/i, "the disclosure must honestly name the suppression risk, not just say 'unknown'");

  // applyCrlToApps must be a no-op when there's genuinely nothing to check against.
  const { apps, removed } = applyCrlToApps(SHELF, result.crl);
  assert.equal(apps.length, SHELF.length);
  assert.equal(removed.length, 0);
});

test("5b. absent fetch but a cached CRL exists and is still fresh -> USING_CACHE, revocations from the cache still apply", () => {
  const cached = buildValidCrl({ version: 1, revokedIds: ["courier-mirror"] });
  const result = resolveCrl({ fetchedBytes: null, pinnedPubKeyB64: repoKp.publicKey, repoId: REPO_ID, cachedCrl: cached, now: NOW });

  assert.equal(result.state, CRL_STATE.USING_CACHE);
  assert.equal(result.crl, cached);
  assert.equal(result.freshness.fresh, true);
  assert.match(result.disclosure, /selectively blocks only this fetch/);

  const { apps } = applyCrlToApps([{ id: "courier-mirror" }, { id: "organic-maps" }], result.crl);
  assert.deepEqual(apps.map((a) => a.id), ["organic-maps"], "cached revocation must still be enforced while offline");
});

test("5c. absent fetch, cached CRL has gone STALE (past next_update + max_stale_secs) -> honest degrade, still discloses which CRL it's holding", () => {
  const issuedAt = 1_800_000_000;
  const stale = buildCrl(repoKp.privateKey, {
    repoId: "r",
    kid: KID,
    version: 1,
    revokedIds: ["courier-mirror"],
    nextUpdateSecs: 3600, // next_update = issuedAt + 1h
    maxStaleSecs: 3600, // hard deadline = issuedAt + 2h
    now: new Date(issuedAt * 1000),
  });
  const wayLater = new Date((issuedAt + 3 * 3600) * 1000); // 3h later, past the 2h hard deadline

  const result = resolveCrl({ fetchedBytes: null, pinnedPubKeyB64: repoKp.publicKey, repoId: REPO_ID, cachedCrl: stale, now: wayLater });

  assert.equal(result.state, CRL_STATE.USING_CACHE);
  assert.equal(result.freshness.stale, true);
  assert.match(result.disclosure, /can no longer be trusted/);
});

test("6. crlFreshness: fresh / ageing / stale boundaries", () => {
  const issuedAt = 1_800_000_000;
  const crl = buildCrl(repoKp.privateKey, {
    repoId: "r",
    kid: KID,
    version: 1,
    nextUpdateSecs: 1000, // next_update = issuedAt + 1000
    maxStaleSecs: 500, // hard deadline = issuedAt + 1500
    now: new Date(issuedAt * 1000),
  });

  const fresh = crlFreshness(crl, new Date((issuedAt + 500) * 1000));
  assert.equal(fresh.fresh, true);
  assert.equal(fresh.ageing, false);
  assert.equal(fresh.stale, false);

  const ageing = crlFreshness(crl, new Date((issuedAt + 1200) * 1000));
  assert.equal(ageing.fresh, false);
  assert.equal(ageing.ageing, true);
  assert.equal(ageing.stale, false);

  const stale = crlFreshness(crl, new Date((issuedAt + 1600) * 1000));
  assert.equal(stale.fresh, false);
  assert.equal(stale.ageing, false);
  assert.equal(stale.stale, true);
});

test("7. malformed / structurally-invalid CRLs are rejected by verifyCrl, never crash", () => {
  assert.equal(verifyCrl(repoKp.publicKey, null).ok, false);
  assert.equal(verifyCrl(repoKp.publicKey, undefined).ok, false);
  assert.equal(verifyCrl(repoKp.publicKey, {}).ok, false);
  assert.equal(verifyCrl(repoKp.publicKey, { payload: { v: 1, typ: "depot-crl" }, sig: "" }).ok, false);
  assert.equal(
    verifyCrl(repoKp.publicKey, { payload: { v: 2, typ: "depot-crl", revoked_ids: [], revoked_versions: [], version: 1 }, sig: "AA==" }).ok,
    false,
    "wrong v must be rejected"
  );
  assert.equal(
    verifyCrl(repoKp.publicKey, { payload: { v: 1, typ: "not-a-crl", revoked_ids: [], revoked_versions: [], version: 1 }, sig: "AA==" }).ok,
    false,
    "wrong typ must be rejected"
  );
});

test("8. verifyCrl rejects a correctly-formed, correctly-signed CRL checked against an unrelated key", () => {
  const crl = buildValidCrl();
  const attackerKp = generateKeypair();
  const verdict = verifyCrl(attackerKp.publicKey, crl);
  assert.equal(verdict.ok, false);
  assert.equal(verdict.reason, "bad-crl-signature");
});

test("10. resolveCrl fails closed (throws) if called without repoId, rather than silently skipping the repo_id check", () => {
  const cached = buildValidCrl({ version: 1 });
  assert.throws(() => resolveCrl({ fetchedBytes: null, pinnedPubKeyB64: repoKp.publicKey, cachedCrl: cached, now: NOW }));
});

test("9. buildCrl de-duplicates and sorts revoked lists so signed bytes are stable", () => {
  const a = buildCrl(repoKp.privateKey, {
    repoId: "r",
    kid: KID,
    version: 1,
    revokedIds: ["b", "a", "a", "c"],
    revokedVersions: [],
    now: NOW,
  });
  assert.deepEqual(a.payload.revoked_ids, ["a", "b", "c"]);
});
