// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Postern Labs and Postern community contributors
//
// Depot revocations.json — a signed, versioned Certificate Revocation List
// (CRL) for the postern.repo/v1 self-hostable repo format
// (docs/store-fdroid/01-architecture.md). PORTED from
// enterprise/licensing/src/crl.ts, same logic (monotonic version,
// freshness/soft-offline window, fail-closed-on-signal, never-throws), same
// canonical-JSON-over-payload signing shape (SignedToken<T> = {payload, sig}
// per enterprise/licensing/src/types.ts) — adapted from "revoked license
// serials / org keys" to "revoked app ids / app versions."
//
// STATUS: reference prototype, UNAUDITED, pre-production. HOST-testable only
// (Node, no browser build here) — see test/crl.test.mjs.
//
// WHY revocations.json is signed THIS way, not index.json's way
// ---------------------------------------------------------------
// index.json (lib/verify.mjs, lib/build-index.mjs) is signed DETACHED: raw
// Ed25519 bytes over the file's exact served bytes, in a sibling
// index.json.sig file — "sign the file, don't canonicalize it" (SIGNING.md).
// revocations.json is the OTHER case docs/store-fdroid explicitly carries
// over from crl.ts instead: the signature travels INSIDE the JSON, as a
// base64 string next to a `payload` object, and what's signed is
// canonicalJson(payload) (sorted keys), not the served bytes of the whole
// file. This is deliberate, not an inconsistency (see lib/encoding.mjs's own
// header comment) — a CRL is republished frequently and independently of the
// index, so its own self-contained envelope (matching crl.ts's `Crl` type)
// is the more natural fit than a second detached-.sig sibling file.
//
// THE HONEST GAP — READ THIS BEFORE WIRING A CLIENT TO revocations.json
// -----------------------------------------------------------------------
// crl.ts's own header states plainly: "a missing/absent CRL means 'no
// revocation info' — best-effort, disclosed." That posture is FINE for
// licensing (an unrevoked license that should have been revoked degrades a
// paid feature, not a security boundary) but it means something sharper
// here: **a network attacker who can selectively block/drop the
// revocations.json request (without touching index.json or the app
// artifacts at all) suppresses every revocation for that repo, silently,
// for as long as the client's cached CRL (if any) stays inside its
// max_stale_secs grace window — and after that window, degrades to "no
// revocation info" again, NOT to "block everything."**
//
// This is not a bug to patch away in this module — it is the honest ceiling
// of "revocation over a CRL a client fetches opportunistically," the same
// ceiling `docs/store-fdroid/03-honesty-license.md` §3e already names for
// this whole stack ("No revocation list, anywhere in this stack... Nothing
// in this design should be worded to suggest a compromised key/app can be
// instantly and automatically neutralized for every already-pinned
// client."). Fixing this for real needs a positive-freshness-proof protocol
// (e.g. short-lived signed "I checked and there is nothing new" receipts, or
// TUF's timestamp/snapshot roles) — out of scope for this module. What THIS
// module does, honestly:
//   - `max_stale_secs` bounds how long a suppressed fetch can hide a
//     revocation using a CACHED CRL before the client is told to stop
//     trusting it (`crlFreshness` -> `stale: true`).
//   - `resolveCrl()` NEVER silently claims a fetch succeeded when it didn't;
//     every return carries a `disclosure` string a UI is expected to surface,
//     not bury.
//   - There is NO way, in this module, to distinguish "revocations.json was
//     never published" from "revocations.json was blocked by a network
//     attacker" — both look identical to a client (a failed/absent fetch).
//     Do not build a UI that implies otherwise.

import { canonicalJson, utf8 } from "./encoding.mjs";
import { ed25519SignRaw, ed25519VerifyRaw } from "./keys.mjs";

/** Sensible defaults for the freshness window (disclosed, tunable). Same values as crl.ts. */
export const CRL_DEFAULT_NEXT_UPDATE_SECS = 24 * 3600; // publish daily
export const CRL_DEFAULT_MAX_STALE_SECS = 14 * 24 * 3600; // 14-day soft-offline grace

function nowSec(now) {
  return Math.floor(now.getTime() / 1000);
}

function b64(bytes) {
  return Buffer.from(bytes).toString("base64");
}

function unb64(s) {
  return Buffer.from(s, "base64");
}

/** A revoked-version key: scoped to an app id, never a bare version number alone. */
export function versionKey(appId, versionCode) {
  return `${appId}@${versionCode}`;
}

/**
 * Repo-operator side: sign a CRL over a set of revoked app ids (whole-app,
 * every version pulled off the shelf) and revoked (id, versionCode) pairs
 * (single-version pulled, other versions of the same app stay listed).
 *
 * @param {string} repoPrivateKeyB64 the repo's own Ed25519 private key (same
 *   keypair used for index.json.sig — the repo operator revokes their own
 *   repo's listings; there is no separate "vendor" authority here, unlike
 *   crl.ts's licensing CRL which is vendor-signed over org-issued tokens).
 * @param {object} opts
 * @param {string} opts.repoId stable id of the repo this CRL applies to.
 * @param {string} opts.kid key id of the signing key (keys.mjs `keyId()`).
 * @param {number} opts.version monotonic; MUST be greater than any previously-published version.
 * @param {readonly string[]} [opts.revokedIds] app ids revoked entirely.
 * @param {readonly string[]} [opts.revokedVersions] `versionKey(id, versionCode)` strings.
 * @param {number} [opts.nextUpdateSecs]
 * @param {number} [opts.maxStaleSecs]
 * @param {Date} [opts.now]
 */
export function buildCrl(repoPrivateKeyB64, opts) {
  const now = opts.now ?? new Date();
  const issued_at = nowSec(now);
  const nextUpdate = opts.nextUpdateSecs ?? CRL_DEFAULT_NEXT_UPDATE_SECS;
  const maxStale = opts.maxStaleSecs ?? CRL_DEFAULT_MAX_STALE_SECS;
  // De-duplicate + sort so the signed bytes are stable for a given input set
  // (unchanged rationale from crl.ts).
  const revoked_ids = [...new Set(opts.revokedIds ?? [])].sort();
  const revoked_versions = [...new Set(opts.revokedVersions ?? [])].sort();

  const payload = {
    v: 1,
    typ: "depot-crl",
    repo_id: opts.repoId,
    kid: opts.kid,
    version: opts.version,
    issued_at,
    next_update: issued_at + nextUpdate,
    max_stale_secs: maxStale,
    revoked_ids,
    revoked_versions,
  };
  const sigBytes = ed25519SignRaw(repoPrivateKeyB64, utf8(canonicalJson(payload)));
  return { payload, sig: b64(sigBytes) };
}

/**
 * Verify a CRL's signature and structure against the repo's PUBLIC key. Does
 * NOT check freshness (see `crlFreshness`) or anti-rollback (see
 * `pickNewerCrl`) — a structurally-valid, signature-valid but stale or
 * rolled-back CRL is still authentic; those are separate, disclosed policy
 * decisions layered on top, exactly as crl.ts documents.
 *
 * ADVERSARIAL-REVIEW FIX (repo_id binding): a valid Ed25519 signature over
 * `payload` only proves the holder of `repoPublicKeyB64` signed THIS payload
 * — it never proves the payload was meant for THIS repo. If two repos happen
 * to share an operator key (or one operator runs several repos off one key),
 * a network attacker can take repo A's genuinely-signed CRL (e.g. an empty,
 * nothing-revoked one) and serve it back as repo B's revocations.json. The
 * signature verifies fine — the attack is a REPLAY across repos, not a
 * forgery. `expectedRepoId`, when supplied, closes this: the CRL's own
 * `payload.repo_id` MUST match, or the CRL is rejected outright, regardless
 * of how valid its signature is.
 *
 * @param {string} repoPublicKeyB64
 * @param {object} crl
 * @param {string} [expectedRepoId] - the repo this CRL is being checked FOR; when given, `payload.repo_id` must match exactly
 */
export function verifyCrl(repoPublicKeyB64, crl, expectedRepoId) {
  const p = crl?.payload;
  if (!p || p.v !== 1 || p.typ !== "depot-crl") return { ok: false, reason: "malformed-crl" };
  if (!Array.isArray(p.revoked_ids) || !Array.isArray(p.revoked_versions)) {
    return { ok: false, reason: "malformed-crl-lists" };
  }
  if (typeof p.version !== "number" || p.version < 0) return { ok: false, reason: "bad-crl-version" };
  if (expectedRepoId != null && p.repo_id !== expectedRepoId) {
    return {
      ok: false,
      reason: `repo-id-mismatch: this CRL is signed for repo_id "${p.repo_id ?? "(missing)"}", not the expected "${expectedRepoId}" — a CRL cannot be replayed from one repo onto another, even when both share a signing key`,
    };
  }
  if (typeof crl.sig !== "string" || crl.sig.length === 0) return { ok: false, reason: "missing-signature" };

  let sigBytes;
  try {
    sigBytes = unb64(crl.sig);
  } catch {
    return { ok: false, reason: "bad-signature-encoding" };
  }
  if (!ed25519VerifyRaw(repoPublicKeyB64, utf8(canonicalJson(p)), sigBytes)) {
    return { ok: false, reason: "bad-crl-signature" };
  }
  return { ok: true };
}

/**
 * Pick the CRL to trust between a freshly-fetched one and a cached one,
 * enforcing monotonic `version` (anti-rollback). Both must already be
 * signature-verified — this function does not verify, only compares.
 *
 * ADVERSARIAL-REVIEW FIX (version-tie): this used to adopt the fetched CRL on
 * a TIE (`fetched.version >= cached.version`). A same-version republish is
 * not evidence of anything newer — a repo operator (or anyone who ever held
 * the signing key) can re-sign the SAME version number with a weaker/emptier
 * revocation list, and under `>=` that silently "un-revokes" entries the
 * cached CRL was still correctly enforcing. `version` is defined as
 * monotonically increasing for a REASON: adopting requires STRICTLY greater,
 * never equal. A tie keeps the cached CRL.
 */
export function pickNewerCrl(cached, fetched) {
  if (!cached) return fetched;
  if (!fetched) return cached;
  return fetched.payload.version > cached.payload.version ? fetched : cached;
}

/** Compute the soft-offline freshness of a cached CRL. Ported verbatim from crl.ts's `crlFreshness`. */
export function crlFreshness(crl, now = new Date()) {
  const t = nowSec(now);
  const p = crl.payload;
  const hardDeadline = p.next_update + p.max_stale_secs;
  const ageDays = Math.max(0, Math.floor((t - p.issued_at) / 86_400));
  if (t <= p.next_update) {
    return { fresh: true, ageing: false, stale: false, ageDays, note: "CRL is within its update window" };
  }
  if (t <= hardDeadline) {
    return {
      fresh: false,
      ageing: true,
      stale: false,
      ageDays,
      note: "CRL is past its update window but inside the soft-offline grace; fetch a fresher CRL soon",
    };
  }
  return {
    fresh: false,
    ageing: false,
    stale: true,
    ageDays,
    note: "CRL is older than the freshness window; revocation can no longer be trusted here — apps from this repo degrade to 'unrevocation-checked' until a fresher CRL is fetched",
  };
}

/** Is a whole app id on the CRL (every version pulled off the shelf)? */
export function isIdRevoked(crl, appId) {
  return !!appId && crl.payload.revoked_ids.includes(appId);
}

/** Is a specific (appId, versionCode) pair on the CRL? */
export function isVersionRevoked(crl, appId, versionCode) {
  if (!appId || versionCode === null || versionCode === undefined) return false;
  return crl.payload.revoked_versions.includes(versionKey(appId, versionCode));
}

/** Combined predicate: is this app (optionally at this version) revoked, and why? */
export function checkAppRevocation(crl, appId, versionCode) {
  if (isIdRevoked(crl, appId)) {
    return { revoked: true, reason: `app '${appId}' is revoked (whole-app revocation, every version)` };
  }
  if (versionCode !== null && versionCode !== undefined && isVersionRevoked(crl, appId, versionCode)) {
    return { revoked: true, reason: `app '${appId}' version '${versionCode}' is revoked (single-version revocation)` };
  }
  return { revoked: false };
}

/**
 * THE CLIENT-SIDE REVOCATION CHECK: pull a revoked app/version off the shelf.
 * Takes the (already index-signature-verified, already normalizeEntry'd)
 * apps list a repo offers and a trusted CRL, and returns the apps that
 * survive, plus a disclosed list of what was removed and why. Entries with
 * no `versionCode` field are only checked against whole-id revocation
 * (forward-compatible with today's repo-poc normalize.mjs, which does not
 * yet model per-version entries from 01-architecture.md's `versions[]`).
 *
 * If `crl` is null/undefined, NOTHING is filtered — this function never
 * fails closed on a missing CRL (that would contradict the "personal-free /
 * offline-first" posture crl.ts's own header insists on: absence of
 * revocation info is not itself grounds to hide an app). The caller
 * (`resolveCrl` below, or a real client) is responsible for deciding
 * whether/how to disclose that no CRL was available.
 */
export function applyCrlToApps(apps, crl) {
  if (!crl) return { apps: [...apps], removed: [] };
  const kept = [];
  const removed = [];
  for (const app of apps) {
    const versionCode = "versionCode" in app ? app.versionCode : undefined;
    const check = checkAppRevocation(crl, app.id, versionCode);
    if (check.revoked) {
      removed.push({ id: app.id, versionCode: versionCode ?? null, reason: check.reason });
    } else {
      kept.push(app);
    }
  }
  return { apps: kept, removed };
}

export const CRL_STATE = Object.freeze({
  /** Fetch failed / revocations.json absent, and no cached CRL exists either — nothing to filter with. */
  NO_CRL: "NO_CRL",
  /** Fetch failed / absent this time, but a previously-adopted CRL is still cached and used. */
  USING_CACHE: "USING_CACHE",
  /** A revocations.json was fetched but its signature does not verify against the pinned key. */
  TAMPERED: "TAMPERED",
  /** Fetched CRL verified but its version is older than the cached one — anti-rollback, not adopted. */
  ROLLBACK_REJECTED: "ROLLBACK_REJECTED",
  /** Fetched CRL verified and is new/current — adopted. */
  ADOPTED: "ADOPTED",
});

/**
 * Client-side orchestration: given a fetch attempt's raw result (bytes or
 * null on failure/absence — deliberately the SAME shape for both, per the
 * honest-gap note above), the repo's pinned public key, and whatever CRL
 * this client last adopted for this repo, decide which CRL (if any) to
 * trust going forward and produce a `disclosure` string a UI MUST surface.
 *
 * ADVERSARIAL-REVIEW FIX (repo_id binding): `opts.repoId` is now REQUIRED —
 * the repo this CRL is being resolved FOR. Without it, a network attacker
 * who can get one genuinely-signed CRL from ANY repo sharing the same
 * operator key (e.g. a repo-A CRL with empty revocation lists) can replay it
 * as repo-B's revocations.json: the signature checks out fine against the
 * shared key, so the old code would happily ADOPT it — silently suppressing
 * repo-B's real revocations, and (worse) anti-rollback would then treat that
 * forged CRL's version number as the new floor, permanently locking out
 * repo-B's genuine, higher-version CRL the next time it's fetched. Missing
 * `repoId` throws immediately (fail closed on misuse) rather than silently
 * skipping the check.
 *
 * @param {object} opts
 * @param {Buffer|Uint8Array|null} opts.fetchedBytes exact bytes of a fetched
 *   revocations.json, or null if the fetch failed OR the file does not
 *   exist OR (indistinguishably, by design) a network attacker blocked it.
 * @param {string} opts.pinnedPubKeyB64 this repo's pinned Ed25519 key.
 * @param {string} opts.repoId the repo this CRL is being resolved FOR — a fetched CRL's own `payload.repo_id` must match this exactly.
 * @param {object|null} [opts.cachedCrl] last-adopted verified CRL for this repo, or null.
 * @param {Date} [opts.now]
 */
export function resolveCrl(opts) {
  const { fetchedBytes, pinnedPubKeyB64, repoId, cachedCrl = null, now = new Date() } = opts;
  if (!repoId) {
    throw new Error("resolveCrl requires opts.repoId — a CRL must never be resolved without knowing which repo it's being checked for (repo_id binding fix)");
  }

  if (!fetchedBytes) {
    if (!cachedCrl) {
      return {
        state: CRL_STATE.NO_CRL,
        crl: null,
        freshness: null,
        disclosure:
          "No revocation list is available for this repo (never fetched successfully). Apps are shown WITHOUT revocation filtering — best-effort, disclosed. Note: this is indistinguishable from a network attacker deliberately blocking revocations.json; selective blocking of this one file defeats revocation for this repo until a fetch succeeds.",
      };
    }
    const freshness = crlFreshness(cachedCrl, now);
    return {
      state: CRL_STATE.USING_CACHE,
      crl: cachedCrl,
      freshness,
      disclosure: freshness.stale
        ? "Could not fetch a fresh revocation list, and the cached copy is now stale (past its disclosed max_stale window). Revocation can no longer be trusted for this repo — treat it as if no CRL is available until a fresher one is fetched. Note: an attacker able to keep blocking revocations.json indefinitely can keep this repo permanently in this degraded state, but cannot make it look ADOPTED again."
        : `Could not fetch a fresh revocation list this time; using the last verified copy (${freshness.note}). A network attacker who selectively blocks only this fetch (while letting everything else through) can suppress newly-added revocations until the cache goes stale or a fetch succeeds.`,
    };
  }

  let parsed;
  try {
    parsed = JSON.parse(Buffer.from(fetchedBytes).toString("utf8"));
  } catch {
    // Malformed JSON is treated the same as a bad signature: reject the
    // fetch, fall back to cache, never adopt garbage.
    return tamperedResult(cachedCrl, now, "Fetched revocations.json is not valid JSON — treated as tampered/corrupt, rejected.");
  }

  const verdict = verifyCrl(pinnedPubKeyB64, parsed, repoId);
  if (!verdict.ok) {
    return tamperedResult(
      cachedCrl,
      now,
      `Fetched revocations.json does NOT verify against this repo's pinned key/repo_id (${verdict.reason}) — rejected. Any previously-cached, verified CRL stands.`
    );
  }

  // ADVERSARIAL-REVIEW FIX (version-tie): check `chosen === cachedCrl`
  // directly rather than re-deriving "older" with `<` — pickNewerCrl() now
  // requires STRICTLY greater to prefer the fetched CRL, so `chosen ===
  // cachedCrl` alone already covers both "older" AND "same version"
  // (a same-version republish with a weaker/emptier revocation list must
  // never silently adopt just because it isn't literally "older").
  const chosen = pickNewerCrl(cachedCrl, parsed);
  if (cachedCrl && chosen === cachedCrl) {
    const freshness = crlFreshness(cachedCrl, now);
    const sameVersion = parsed.payload.version === cachedCrl.payload.version;
    return {
      state: CRL_STATE.ROLLBACK_REJECTED,
      crl: cachedCrl,
      freshness,
      disclosure: sameVersion
        ? `Fetched revocations.json is validly signed and carries the SAME version (${parsed.payload.version}) as the cached CRL, but its content may differ — a same-version republish is never treated as newer (ties do not adopt), so a network attacker (or a compromised-then-recovered key) cannot silently weaken revocations by re-signing the same version number with a shorter list. Continuing to use the cached CRL.`
        : `Fetched revocations.json is validly signed, but its version (${parsed.payload.version}) is OLDER than the cached CRL's version (${cachedCrl.payload.version}) — rejected as a rollback attempt (a network attacker cannot un-revoke by replaying an old, still-validly-signed CRL). Continuing to use the cached CRL.`,
    };
  }

  const freshness = crlFreshness(parsed, now);
  return {
    state: CRL_STATE.ADOPTED,
    crl: parsed,
    freshness,
    disclosure: `revocations.json verified for this repo's pinned key (version ${parsed.payload.version}) and adopted. ${freshness.note}.`,
  };
}

function tamperedResult(cachedCrl, now, disclosure) {
  const freshness = cachedCrl ? crlFreshness(cachedCrl, now) : null;
  return { state: CRL_STATE.TAMPERED, crl: cachedCrl, freshness, disclosure };
}
