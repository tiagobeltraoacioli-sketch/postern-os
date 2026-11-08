#!/usr/bin/env node
// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern CLOUD — HOSTED license-verification service (reference prototype).
//
// STATUS: design / reference prototype. UNAUDITED. Pre-production.
//
// WHAT THIS IS
// ------------
// The offline counterpart (enterprise/licensing/) verifies a license entirely
// on-device: vendor public key + master/sub tokens + the clock, no network. THAT
// IS THE RECOMMENDED PATH and it is strictly more private. This hosted service
// exists only for orgs that WANT a central check-in — e.g. a revocation list
// (revoke a leaked sub token before its exp) or a rough seat/activity view.
//
// HONEST PRIVACY POSTURE (see /v1/posture and README)
// ---------------------------------------------------
//   CAN see:  that a given master_pub / sub label checked in, when, from which
//             IP; whatever token you POST to /v1/verify (which is PUBLIC data —
//             tokens carry no secret). It can build a login-frequency picture.
//   CANNOT:   forge a token (it holds only the vendor PUBLIC key — no signing
//             key of any kind lives here), read any application data, or decrypt
//             anything. It cannot make an expired token valid or vice-versa.
//   The regression vs offline: offline verification reveals NOTHING to anyone.
//   A hosted check reveals the check happened. That is the whole trade, stated.
//
//   PERSONAL editions never touch this. It is BUSINESS opt-in only. There is no
//   phone-home for personal use anywhere in Postern.
//
// ENDPOINTS
//   GET  /healthz
//   GET  /v1/posture                 the structured privacy posture (this file)
//   GET  /v1/vendor-key              the vendor PUBLIC key this service verifies
//                                    against (so a client can confirm it matches
//                                    the key bundled in its app)
//   POST /v1/verify { master, sub? } run the SAME offline chain server-side; also
//                                    apply the revocation list. Honest echo of
//                                    what was observed.
//   GET  /v1/revocations             the raw server-side revocation working-set
//                                    (hashes + jti + master_pub). Public, unsigned.
//   POST /v1/revocations { ... }     admin-only (ADMIN_TOKEN): add a sub hash, a
//                                    token serial (jti), or a whole org master_pub
//                                    to the working-set before exp.
//   GET  /v1/crl                     the latest VENDOR-SIGNED, versioned CRL for
//                                    offline installs to fetch + cache (public).
//                                    Falls back to an honest UNSIGNED advisory copy
//                                    of the working-set if none has been published.
//   POST /v1/crl { payload, sig }    admin-only: publish a vendor-signed CRL. The
//                                    service VERIFIES it against the vendor PUBLIC
//                                    key and enforces monotonic `version` — it
//                                    never signs (no signing key lives here).
//
// ENV
//   PORT                 default 8801
//   VENDOR_PUBLIC_KEY    base64 raw Ed25519 vendor public key. MANDATORY — the
//                        service REFUSES TO START without it (fail-closed: no key
//                        ⇒ cannot verify ⇒ would fail-open on master tokens).
//   ADMIN_TOKEN          bearer required to POST revocations (required to revoke)
//   ALLOWED_ORIGIN       CORS origin. Default is DENY (localhost only); never "*".
//                        Set it explicitly to your client origin in production.
//   TRUST_PROXY          "1" to honor X-Forwarded-For (only behind your proxy)
//   RETAIN_CHECKINS      "1" to keep an in-memory check-in tally (default OFF —
//                        minimization default is to NOT build an activity log)

"use strict";

import {
  makeServer, sendJSON, readJSON, bearerToken, clientIP, logLine,
  createRateLimiter, verifyChain, sha256hex, timingSafeEqualStr,
  definePosture, runIfMain, requireVendorKey, resolveAllowedOrigin,
  verifySignedToken,
} from "./common.mjs";

const PORT = parseInt(process.env.PORT || "8801", 10);
const VENDOR_PUBLIC_KEY = (process.env.VENDOR_PUBLIC_KEY || "").trim();
const ADMIN_TOKEN = (process.env.ADMIN_TOKEN || "").trim();
const ORIGIN = resolveAllowedOrigin(process.env.ALLOWED_ORIGIN);
const ALLOWED_ORIGIN = ORIGIN.origin;
const TRUST_PROXY = process.env.TRUST_PROXY === "1";
const RETAIN_CHECKINS = process.env.RETAIN_CHECKINS === "1";
const MAX_BODY_BYTES = 256 * 1024;

export const POSTURE = definePosture({
  service: "postern-cloud-license",
  label: "Postern Cloud — hosted license verification",
  lessPrivateThan: "on-device offline verification (enterprise/licensing), which reveals a check to no one",
  canSee: [
    "That a specific master_pub (org) or sub label checked in, and when.",
    "The client IP and timestamp of each /v1/verify call (unless fronted by an anonymizing proxy).",
    "The full token you POST — tokens are PUBLIC data (no secret inside), so this is not a secret leak, but the org/user identity in them is now known to the operator.",
    "Aggregate activity: how often an org verifies, roughly implying login frequency.",
  ],
  cannotSee: [
    "Any signing key. Only the vendor PUBLIC key lives here; nothing is ever signed server-side.",
    "Application data, files, or messages of any kind.",
    "Message plaintext or any decryptable content — this service has no crypto beyond signature verification.",
  ],
  metadataExposed: [
    "Check-in metadata: which org/sub, when, from where. Offline verification exposes NONE of this.",
    "A revocation query reveals which client is asking about revocations, and when.",
  ],
  minimizations: [
    "No check-in log is kept by default (RETAIN_CHECKINS off) — verification is answered and forgotten.",
    "The verification math is identical to the on-device chain; the server adds no new authority, only the revocation list.",
    "The revocation list stores only a SHA-256 of each revoked token plus a coarse reason — never the org's private data.",
    "No cookies, no tracking identifiers, no analytics, no third-party calls.",
  ],
  promiseNotProof:
    "That we do not retain check-ins by default is a POLICY of this code, not an architectural guarantee — a hosted verifier that receives a request has, at that instant, seen it. For a guarantee, verify offline; the app already can.",
});

/* Revocation working-set. In-memory for the reference build; a real deployment
   swaps in a durable store. Public read; admin write.

   THREE ways to revoke, in ascending blast radius:
     - by sub HASH   (legacy: SHA-256 of the sub's signature) — the raw token is
       not retained;
     - by SERIAL     (jti: a token's 128-bit serial) — master OR sub (D4);
     - by MASTER_PUB (an org's master key) — kills every token under that org.

   This working-set is what an operator/ops builds. The SIGNED, versioned CRL
   that offline installs actually fetch is produced by the VENDOR (holding the
   private key — the site Function / CLI `crl-build`) and PUBLISHED here via
   POST /v1/crl. This service holds only the vendor PUBLIC key: it can VERIFY a
   CRL but never sign one. */
const revocations = new Map(); // hash -> { reason, at }
const revokedJti = new Map(); // jti -> { reason, at }
const revokedMasterPub = new Map(); // master_pub -> { reason, at }

/* The latest vendor-signed CRL published to this service ({ payload, sig }), or
   null. Served verbatim at GET /v1/crl. Monotonic `version` is enforced on
   publish so a stale CRL cannot be rolled back over a newer one. */
let publishedCrl = null;
/* Optional, OFF by default: a minimal check-in tally so an operator who opts in
   can see rough activity. Deliberately gated so the default is to keep nothing. */
const checkins = new Map(); // master_pub -> { count, last }

const verifyRate = createRateLimiter(120, 60_000); // 120 verifies / IP / minute

function tokenHash(token) {
  // Hash the canonical signature — stable, and never stores the token body.
  return sha256hex(String(token && token.sig || ""));
}

/** Is this verified chain revoked by the working-set or the published CRL? */
function revocationVerdict(master, sub) {
  const mp = master && master.payload;
  const sp = sub && sub.payload;
  // Whole-org kill first (largest blast radius).
  if (mp && mp.master_pub && revokedMasterPub.has(mp.master_pub)) {
    return { revoked: true, reason: "org master key is revoked (whole-org revocation)" };
  }
  if (mp && mp.jti && revokedJti.has(mp.jti)) {
    return { revoked: true, reason: "master token serial (jti) is revoked" };
  }
  if (sp && sp.jti && revokedJti.has(sp.jti)) {
    return { revoked: true, reason: "sub token serial (jti) is revoked" };
  }
  if (sub && revocations.has(tokenHash(sub))) {
    return { revoked: true, reason: "sub token is on the revocation list (by hash)" };
  }
  // Also honour a separately-published signed CRL, if one is loaded.
  if (publishedCrl && publishedCrl.payload) {
    const p = publishedCrl.payload;
    if (mp && p.revoked_master_pub && p.revoked_master_pub.includes(mp.master_pub)) {
      return { revoked: true, reason: "org master key is on the published CRL" };
    }
    const jtis = p.revoked_jti || [];
    if (mp && mp.jti && jtis.includes(mp.jti)) return { revoked: true, reason: "master jti is on the published CRL" };
    if (sp && sp.jti && jtis.includes(sp.jti)) return { revoked: true, reason: "sub jti is on the published CRL" };
  }
  return { revoked: false, reason: null };
}

function requireAdmin(req, res) {
  if (!ADMIN_TOKEN) {
    sendJSON(res, 501, { error: { type: "admin_unconfigured", message: "Revocation writes are disabled (ADMIN_TOKEN unset)." } }, ALLOWED_ORIGIN);
    return false;
  }
  const tok = bearerToken(req);
  if (!tok || !timingSafeEqualStr(tok, ADMIN_TOKEN)) {
    sendJSON(res, 401, { error: { type: "unauthorized", message: "Admin bearer token required." } }, ALLOWED_ORIGIN);
    return false;
  }
  return true;
}

async function handleVerify(req, res) {
  if (!VENDOR_PUBLIC_KEY) {
    return sendJSON(res, 503, { error: { type: "unconfigured", message: "VENDOR_PUBLIC_KEY is not set; the service cannot verify." } }, ALLOWED_ORIGIN);
  }
  if (!verifyRate.allow(clientIP(req, TRUST_PROXY))) {
    return sendJSON(res, 429, { error: { type: "rate_limited", message: "Too many verifications; slow down." } }, ALLOWED_ORIGIN);
  }
  let body;
  try { ({ json: body } = await readJSON(req, MAX_BODY_BYTES)); }
  catch (e) { return sendJSON(res, e.status || 400, { error: { type: "invalid_request", message: e.message } }, ALLOWED_ORIGIN); }

  const master = body.master || null;
  const sub = body.sub || null;
  const result = verifyChain(VENDOR_PUBLIC_KEY, master, sub, new Date());

  // Apply the revocation working-set (+ any published CRL) to an otherwise-valid
  // chain: by org master key, master serial, sub serial, or legacy sub hash.
  let revoked = false;
  let revokedReason = null;
  if (result.ok) {
    const r = revocationVerdict(master, sub);
    revoked = r.revoked;
    revokedReason = r.reason;
  }

  // Opt-in, minimized activity tally.
  if (RETAIN_CHECKINS && result.ok && master && master.payload) {
    const mp = master.payload.master_pub;
    const e = checkins.get(mp) || { count: 0, last: null };
    e.count += 1; e.last = new Date().toISOString();
    checkins.set(mp, e);
  }

  // Content-free log (never the token body).
  logLine("verify", result.ok ? result.level : "invalid", result.ok ? (result.expired ? "expired" : "in-window") : result.reason, revoked ? "REVOKED" : "");

  const state = !result.ok
    ? { state: "invalid", reason: result.reason }
    : revoked
    ? { state: "revoked", reason: revokedReason || "token is on the revocation list" }
    : result.expired
    ? { state: "expired", tier: result.tier, level: result.level, expiredAt: new Date(result.exp * 1000).toISOString() }
    : { state: result.tier === "corporate-master" ? "in-eval" : "valid", tier: result.tier, level: result.level, seats: result.seats, expiresAt: new Date(result.exp * 1000).toISOString() };

  return sendJSON(res, 200, {
    ...state,
    // Honest disclosure returned INLINE with every answer.
    disclosure: "This hosted check observed that this token was verified now. Offline verification (in-app) would reveal nothing to anyone and is the more private path.",
    verifiedAgainstVendorKeyFingerprint: sha256hex(VENDOR_PUBLIC_KEY).slice(0, 16),
  }, ALLOWED_ORIGIN);
}

async function handleAddRevocation(req, res) {
  if (!requireAdmin(req, res)) return;
  let body;
  try { ({ json: body } = await readJSON(req, MAX_BODY_BYTES)); }
  catch (e) { return sendJSON(res, e.status || 400, { error: { type: "invalid_request", message: e.message } }, ALLOWED_ORIGIN); }
  const at = new Date().toISOString();
  const reason = String(body.reason || "unspecified").slice(0, 200);
  const added = {};
  // Preferred: revoke by serial (jti) or by whole org master key (D4).
  if (body.jti) { revokedJti.set(String(body.jti), { reason, at }); added.jti = String(body.jti); }
  if (body.master_pub) { revokedMasterPub.set(String(body.master_pub), { reason, at }); added.master_pub = String(body.master_pub); }
  // Legacy / fallback: revoke a sub by (hash of its) signature.
  const hash = body.hash ? String(body.hash) : (body.sub ? tokenHash(body.sub) : null);
  if (hash) { revocations.set(hash, { reason, at }); added.hash = hash; }
  if (!added.jti && !added.master_pub && !added.hash) {
    return sendJSON(res, 400, { error: { type: "invalid_request", message: "Provide { jti }, { master_pub }, { sub } or { hash }." } }, ALLOWED_ORIGIN);
  }
  logLine("revoke", JSON.stringify(added).slice(0, 80));
  return sendJSON(res, 200, {
    ok: true, added,
    counts: { hashes: revocations.size, jti: revokedJti.size, master_pub: revokedMasterPub.size },
    note: "Added to the server working-set. Publish a VENDOR-SIGNED CRL (crl-build + POST /v1/crl) for offline installs to enforce this.",
  }, ALLOWED_ORIGIN);
}

function handleListRevocations(res) {
  return sendJSON(res, 200, {
    hashes: [...revocations.entries()].map(([hash, v]) => ({ hash, reason: v.reason, at: v.at })),
    jti: [...revokedJti.entries()].map(([jti, v]) => ({ jti, reason: v.reason, at: v.at })),
    master_pub: [...revokedMasterPub.entries()].map(([master_pub, v]) => ({ master_pub, reason: v.reason, at: v.at })),
    note: "Public, UNSIGNED working-set. Offline installs should fetch the SIGNED CRL at /v1/crl instead; this endpoint is the operator's staging view. A client that consults it reveals to the operator that it is checking.",
  }, ALLOWED_ORIGIN);
}

/** Public: the latest vendor-signed CRL for offline installs, + freshness. */
function handleGetCrl(res) {
  if (publishedCrl && publishedCrl.payload) {
    const p = publishedCrl.payload;
    const nowSec = Math.floor(Date.now() / 1000);
    const hardDeadline = (p.next_update || 0) + (p.max_stale_secs || 0);
    const freshness = nowSec <= (p.next_update || 0) ? "fresh" : (nowSec <= hardDeadline ? "ageing" : "stale");
    return sendJSON(res, 200, {
      crl: publishedCrl,
      freshness,
      note: "Vendor-signed, versioned CRL. Verify it against the vendor PUBLIC key you already trust, cache it, and prefer the higher `version`. Offline verification is preserved — the CRL only revokes, never grants.",
    }, ALLOWED_ORIGIN);
  }
  // No signed CRL published yet: return an HONEST unsigned advisory copy.
  return sendJSON(res, 200, {
    crl: null,
    unsigned_advisory: {
      revoked_jti: [...revokedJti.keys()],
      revoked_master_pub: [...revokedMasterPub.keys()],
    },
    note: "No vendor-signed CRL has been published to this service. The advisory set is UNSIGNED and MUST NOT be trusted for enforcement — publish a signed CRL via POST /v1/crl.",
  }, ALLOWED_ORIGIN);
}

/** Admin: publish a vendor-signed CRL. Verify + enforce monotonic version. */
async function handlePublishCrl(req, res) {
  if (!requireAdmin(req, res)) return;
  let body;
  try { ({ json: body } = await readJSON(req, MAX_BODY_BYTES)); }
  catch (e) { return sendJSON(res, e.status || 400, { error: { type: "invalid_request", message: e.message } }, ALLOWED_ORIGIN); }
  const crl = body && body.payload && body.sig ? body : (body && body.crl) || null;
  const p = crl && crl.payload;
  if (!p || p.v !== 1 || p.typ !== "crl") {
    return sendJSON(res, 400, { error: { type: "invalid_request", message: "Body must be a signed CRL { payload:{v:1,typ:'crl',...}, sig }." } }, ALLOWED_ORIGIN);
  }
  // The service holds only the vendor PUBLIC key: it can VERIFY, never sign.
  if (!verifySignedToken(VENDOR_PUBLIC_KEY, crl)) {
    return sendJSON(res, 400, { error: { type: "bad_signature", message: "CRL signature does not verify against the vendor public key." } }, ALLOWED_ORIGIN);
  }
  if (typeof p.version !== "number" || p.version < 0) {
    return sendJSON(res, 400, { error: { type: "invalid_request", message: "CRL version must be a non-negative number." } }, ALLOWED_ORIGIN);
  }
  if (publishedCrl && p.version <= publishedCrl.payload.version) {
    return sendJSON(res, 409, { error: { type: "stale_version", message: `Refusing rollback: version ${p.version} <= published ${publishedCrl.payload.version}.` } }, ALLOWED_ORIGIN);
  }
  publishedCrl = crl;
  logLine("crl-publish", `v${p.version}`, `jti=${(p.revoked_jti || []).length}`, `orgs=${(p.revoked_master_pub || []).length}`);
  return sendJSON(res, 200, { ok: true, version: p.version, revoked_jti: (p.revoked_jti || []).length, revoked_master_pub: (p.revoked_master_pub || []).length }, ALLOWED_ORIGIN);
}

async function route(req, res, url, key) {
  if (key === "GET /v1/vendor-key") {
    return sendJSON(res, 200, {
      vendor_public_key: VENDOR_PUBLIC_KEY || null,
      fingerprint: VENDOR_PUBLIC_KEY ? sha256hex(VENDOR_PUBLIC_KEY).slice(0, 16) : null,
      note: "Confirm this matches the vendor key bundled in your app. This service holds NO private key.",
    }, ALLOWED_ORIGIN), true;
  }
  if (key === "POST /v1/verify") { await handleVerify(req, res); return true; }
  if (key === "GET /v1/revocations") { handleListRevocations(res); return true; }
  if (key === "POST /v1/revocations") { await handleAddRevocation(req, res); return true; }
  if (key === "GET /v1/crl") { handleGetCrl(res); return true; }
  if (key === "POST /v1/crl") { await handlePublishCrl(req, res); return true; }
  return false;
}

export function createServer() {
  // SVC-1: fail-closed — refuse to start without a mandatory vendor public key.
  requireVendorKey(VENDOR_PUBLIC_KEY, "license-service");
  return makeServer({ allowedOrigin: ALLOWED_ORIGIN, posture: POSTURE, route });
}

/* Test hooks. */
export { revocations, revokedJti, revokedMasterPub, checkins, tokenHash, revocationVerdict, getPublishedCrl };
function getPublishedCrl() { return publishedCrl; }

runIfMain(import.meta.url, process.argv[1], () => {
  createServer().listen(PORT, () => {
    logLine(`postern-cloud license-verification listening on :${PORT}`);
    logLine(`  vendor key:    configured (MANDATORY — service refuses to start without it)`);
    logLine(`  admin writes:  ${ADMIN_TOKEN ? "enabled" : "disabled (ADMIN_TOKEN unset)"}`);
    logLine(`  check-in log:  ${RETAIN_CHECKINS ? "ON (opt-in activity tally)" : "off (nothing retained — recommended)"}`);
    logLine(`  CORS origin:   ${ALLOWED_ORIGIN}${ORIGIN.explicit ? "" : " (deny-by-default; set ALLOWED_ORIGIN for your client)"}`);
    if (ORIGIN.wildcard) logLine("  WARNING: ALLOWED_ORIGIN='*' was set explicitly; scope it to your client origin before deployment.");
    logLine("  REMEMBER: offline verification is strictly more private. This service is an opt-in convenience.");
  });
});
