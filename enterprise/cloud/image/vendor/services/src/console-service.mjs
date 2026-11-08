#!/usr/bin/env node
// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern CLOUD — HOSTED admin console backend (reference prototype).
//
// STATUS: design / reference prototype. UNAUDITED. Pre-production.
//
// WHAT THIS IS
// ------------
// The server side of the enterprise admin console. In the self-hosted model
// (enterprise/features/sub-access.mjs) the org keeps its MASTER PRIVATE KEY on
// its own machine and mints sub tokens locally — the key never leaves the org.
// A HOSTED console has to answer one uncomfortable question: where does the
// signing happen? This service supports BOTH, and defaults to the private one.
//
//   MODE A — CLIENT-SIGN  (default, recommended, "server never holds the key")
//     The admin's browser holds the org master private key. The server stores
//     only the ROSTER (labels, expiries, status) and the resulting SIGNED PUBLIC
//     token records the admin uploads after signing locally. The server NEVER
//     receives a private key. This is the more-private option and is presented
//     first-class — mirroring the tolmach-subscription rule: keep the private
//     path and never push users off it.
//
//   MODE B — DELEGATED-SIGN  (opt-in, disclosed regression)
//     The org uploads its master private key so the SERVER mints sub tokens.
//     Convenient (no browser crypto, central minting) but the operator now holds
//     the key that can mint unlimited subs for the org. This is a genuine
//     trust regression and the service says so on every response. Off unless
//     CONSOLE_SIGNING_MODE=delegated is set. Even then the key is held only in
//     memory for the request and never written to disk by this code.
//
// HONEST PRIVACY POSTURE (see /v1/posture and README)
//   CAN see:  org identity, the full roster (member labels), token metadata
//             (expiries, mint/revoke times) — this is the console's whole job.
//             In DELEGATED mode it also, necessarily, sees the master private
//             key in memory while minting.
//   CANNOT:   read application data or messages; in CLIENT-SIGN mode it never
//             sees the private key at all.
//   Regression vs self-host: a self-hosted console exposes the roster to no
//     third party. A hosted one exposes it to the operator. Disclosed.
//
// ENDPOINTS
//   GET  /healthz  /v1/posture
//   POST /v1/orgs { orgName, masterToken }     register an org workspace -> admin bearer
//   POST /v1/roster { label, expires }         add a pending roster entry (no token yet)
//   GET  /v1/roster                            list roster (labels/status/metadata)
//   POST /v1/roster/:id/token { signedToken }  CLIENT-SIGN: attach the token the
//                                              admin signed locally (public data)
//   POST /v1/roster/:id/mint { masterPrivateKey, subExp? }
//                                              DELEGATED only: server mints. Refused
//                                              unless CONSOLE_SIGNING_MODE=delegated.
//   POST /v1/roster/:id/revoke                 revoke a roster entry
//
// ENV
//   PORT                 default 8802
//   VENDOR_PUBLIC_KEY    base64 raw Ed25519 vendor pubkey. MANDATORY — the service
//                        REFUSES TO START without it. Without it, uploaded master
//                        tokens could not be verified and a FORGED workspace would
//                        be admitted (fail-open); the key makes registration
//                        fail-closed.
//   CONSOLE_SIGNING_MODE "client-sign" (default) | "delegated"
//   ALLOWED_ORIGIN       CORS origin. Default is DENY (localhost only); never "*".
//                        Set it explicitly in production.
//   TRUST_PROXY          "1" to honor X-Forwarded-For

"use strict";

import crypto from "node:crypto";
import {
  makeServer, sendJSON, readJSON, bearerToken, clientIP, logLine,
  createRateLimiter, verifyChain, verifySignedToken, canonicalJson, sha256hex,
  definePosture, runIfMain, requireVendorKey, resolveAllowedOrigin,
} from "./common.mjs";

const PORT = parseInt(process.env.PORT || "8802", 10);
const VENDOR_PUBLIC_KEY = (process.env.VENDOR_PUBLIC_KEY || "").trim();
const SIGNING_MODE = (process.env.CONSOLE_SIGNING_MODE || "client-sign").trim();
const DELEGATED = SIGNING_MODE === "delegated";
const ORIGIN = resolveAllowedOrigin(process.env.ALLOWED_ORIGIN);
const ALLOWED_ORIGIN = ORIGIN.origin;
const TRUST_PROXY = process.env.TRUST_PROXY === "1";
const MAX_BODY_BYTES = 256 * 1024;

export const POSTURE = definePosture({
  service: "postern-cloud-console",
  label: "Postern Cloud — hosted admin console backend",
  lessPrivateThan: "a self-hosted console where the roster and master key never leave the org",
  canSee: [
    "The org identity (name, the master token's public identity / DUNS if present).",
    "The full roster: every member label the admin adds.",
    "Token metadata: expiries, mint times, revocation times.",
    DELEGATED
      ? "IN DELEGATED MODE: the org master PRIVATE KEY, in memory, at mint time — the operator can mint unlimited subs for the org while it runs."
      : "In the default client-sign mode: NO private key ever — only signed public token records the admin uploads.",
  ],
  cannotSee: [
    "Application data, files, or messages.",
    "Any user's message plaintext (that belongs to the comms relay / E2EE, not here).",
    ...(DELEGATED ? [] : ["The org master private key — in client-sign mode signing happens in the admin's browser."]),
  ],
  metadataExposed: [
    "The roster and its churn (who was added/removed and when) are visible to the operator; a self-hosted console exposes this to no third party.",
    "Admin activity timing (when subs are minted/revoked).",
  ],
  minimizations: [
    "Default mode is client-sign: the server is a roster + public-token store, never a key holder.",
    "Uploaded master tokens are verified against the vendor public key so a forged workspace cannot be registered.",
    "Delegated signing is OFF unless explicitly enabled, and when on it holds the key only transiently in memory (never written to disk by this code).",
    "No message content, no analytics, no third-party calls.",
  ],
  promiseNotProof:
    DELEGATED
      ? "In delegated mode, 'we don't persist your key' is a policy of this code, not a proof. A compelled or malicious operator could log it. The client-sign mode removes the need to trust that promise — prefer it."
      : "Client-sign keeps the key in the browser by design, so there is little to promise here; the residual trust is that the operator serves you honest console JavaScript.",
});

/* In-memory stores (reference build). orgId -> { orgName, masterPub, adminTokenHash, roster: Map } */
const orgs = new Map();
const tokensToOrg = new Map(); // adminTokenHash -> orgId
const registerRate = createRateLimiter(20, 60_000);

function orgByToken(req) {
  const tok = bearerToken(req);
  if (!tok) return null;
  const orgId = tokensToOrg.get(sha256hex(tok));
  return orgId ? orgs.get(orgId) || null : null;
}

async function handleRegisterOrg(req, res) {
  if (!registerRate.allow(clientIP(req, TRUST_PROXY))) {
    return sendJSON(res, 429, { error: { type: "rate_limited", message: "Too many workspace registrations." } }, ALLOWED_ORIGIN);
  }
  let body;
  try { ({ json: body } = await readJSON(req, MAX_BODY_BYTES)); }
  catch (e) { return sendJSON(res, e.status || 400, { error: { type: "invalid_request", message: e.message } }, ALLOWED_ORIGIN); }

  const orgName = String(body.orgName || "").trim();
  const masterToken = body.masterToken || null;
  if (!orgName) return sendJSON(res, 400, { error: { type: "invalid_request", message: "orgName is required" } }, ALLOWED_ORIGIN);

  // SVC-1 (fail-closed): ALWAYS verify the uploaded master against the vendor key
  // so only a real corporate/business master can open a workspace (no forged
  // orgs). The vendor key is mandatory (createServer refuses to start without
  // it), so this verification is never skipped — previously a missing key
  // silently accepted unverified masters (fail-open).
  if (!VENDOR_PUBLIC_KEY) {
    return sendJSON(res, 503, { error: { type: "unconfigured", message: "VENDOR_PUBLIC_KEY is not set; cannot verify master tokens." } }, ALLOWED_ORIGIN);
  }
  const r = verifyChain(VENDOR_PUBLIC_KEY, masterToken, null, new Date());
  if (!r.ok) return sendJSON(res, 400, { error: { type: "bad_master", message: "master token did not verify against the vendor key: " + r.reason } }, ALLOWED_ORIGIN);
  if (r.expired) return sendJSON(res, 400, { error: { type: "master_expired", message: "master token has expired" } }, ALLOWED_ORIGIN);

  const orgId = "org_" + crypto.randomBytes(8).toString("hex");
  const adminToken = "pca_" + crypto.randomBytes(32).toString("hex"); // Postern Console Admin
  const masterPub = masterToken && masterToken.payload ? masterToken.payload.master_pub : null;
  orgs.set(orgId, {
    id: orgId,
    orgName,
    masterPub,
    masterExp: masterToken && masterToken.payload ? masterToken.payload.exp : null,
    roster: new Map(),
    createdAt: new Date().toISOString(),
  });
  tokensToOrg.set(sha256hex(adminToken), orgId);
  logLine("org register", orgId, "signing=" + SIGNING_MODE);
  return sendJSON(res, 200, {
    org_id: orgId,
    admin_token: adminToken,
    signing_mode: SIGNING_MODE,
    note: "Store the admin_token — kept only as a hash server-side. " +
      (DELEGATED
        ? "This workspace runs in DELEGATED signing: to mint, you upload the master private key and the SERVER signs. That means the operator sees your key at mint time — a trust regression. Prefer client-sign."
        : "This workspace runs in CLIENT-SIGN mode: keep your master private key in your browser, sign sub tokens locally, and upload only the signed token. The server never sees your key."),
  }, ALLOWED_ORIGIN);
}

async function handleAddRosterEntry(req, res, org) {
  let body;
  try { ({ json: body } = await readJSON(req, MAX_BODY_BYTES)); }
  catch (e) { return sendJSON(res, e.status || 400, { error: { type: "invalid_request", message: e.message } }, ALLOWED_ORIGIN); }
  const label = String(body.label || "").trim();
  if (!label) return sendJSON(res, 400, { error: { type: "invalid_request", message: "label is required" } }, ALLOWED_ORIGIN);

  // Default expiry to the master expiry; never allow beyond it.
  let expSec = typeof body.expires === "number" ? Math.floor(body.expires) : org.masterExp;
  if (org.masterExp && expSec && expSec > org.masterExp) {
    return sendJSON(res, 400, { error: { type: "sub_outlives_master", message: "expires may not exceed the master token expiry" } }, ALLOWED_ORIGIN);
  }
  const id = "sub_" + crypto.randomBytes(6).toString("hex");
  org.roster.set(id, {
    id, label, expires: expSec || null,
    token: null, signed: false, revoked: false,
    createdAt: new Date().toISOString(),
  });
  logLine("roster add", org.id, id);
  return sendJSON(res, 200, {
    id, label, expires: expSec || null, status: "pending-signature",
    toSign: {
      // The canonical claims the admin should sign LOCALLY with the org master
      // key (matching the licensing lib's sub payload shape).
      v: 1, typ: "sub", master_pub: org.masterPub, sub: label,
      iat: Math.floor(Date.now() / 1000), exp: expSec || null,
    },
    note: DELEGATED
      ? "Delegated mode: POST /v1/roster/" + id + "/mint with the master private key to have the server sign — discloses your key to the operator."
      : "Client-sign: sign `toSign` locally with your org master private key, then POST the { signedToken } to /v1/roster/" + id + "/token.",
  }, ALLOWED_ORIGIN);
}

async function handleAttachToken(req, res, org, id) {
  const rec = org.roster.get(id);
  if (!rec) return sendJSON(res, 404, { error: { type: "not_found", message: "unknown roster id" } }, ALLOWED_ORIGIN);
  let body;
  try { ({ json: body } = await readJSON(req, MAX_BODY_BYTES)); }
  catch (e) { return sendJSON(res, e.status || 400, { error: { type: "invalid_request", message: e.message } }, ALLOWED_ORIGIN); }
  const signedToken = body.signedToken || null;
  if (!signedToken || !signedToken.payload || !signedToken.sig) {
    return sendJSON(res, 400, { error: { type: "invalid_request", message: "signedToken { payload, sig } required" } }, ALLOWED_ORIGIN);
  }
  // Verify the uploaded sub token really was signed by THIS org's master key —
  // the server stores only PUBLIC data and refuses mismatched tokens.
  if (org.masterPub && !verifySignedToken(org.masterPub, signedToken)) {
    return sendJSON(res, 400, { error: { type: "bad_signature", message: "sub token is not validly signed by this org master key" } }, ALLOWED_ORIGIN);
  }
  if (signedToken.payload.sub !== rec.label) {
    return sendJSON(res, 400, { error: { type: "label_mismatch", message: "signed token label does not match roster entry" } }, ALLOWED_ORIGIN);
  }
  rec.token = signedToken;
  rec.signed = true;
  rec.expires = signedToken.payload.exp || rec.expires;
  logLine("roster attach (client-signed)", org.id, id);
  return sendJSON(res, 200, { id, status: "active", signed: true, note: "Stored the signed PUBLIC token. The server never saw your private key." }, ALLOWED_ORIGIN);
}

async function handleDelegatedMint(req, res, org, id) {
  if (!DELEGATED) {
    return sendJSON(res, 403, { error: { type: "delegated_disabled", message: "Server-side minting is disabled. This workspace is client-sign: sign locally and use /token. (Set CONSOLE_SIGNING_MODE=delegated to enable server minting — a disclosed trust regression.)" } }, ALLOWED_ORIGIN);
  }
  const rec = org.roster.get(id);
  if (!rec) return sendJSON(res, 404, { error: { type: "not_found", message: "unknown roster id" } }, ALLOWED_ORIGIN);
  let body;
  try { ({ json: body } = await readJSON(req, MAX_BODY_BYTES)); }
  catch (e) { return sendJSON(res, e.status || 400, { error: { type: "invalid_request", message: e.message } }, ALLOWED_ORIGIN); }
  const masterPrivateKey = String(body.masterPrivateKey || "").trim();
  if (!masterPrivateKey) return sendJSON(res, 400, { error: { type: "invalid_request", message: "masterPrivateKey required in delegated mode" } }, ALLOWED_ORIGIN);

  const exp = typeof body.subExp === "number" ? Math.floor(body.subExp) : (rec.expires || org.masterExp);
  const payload = { v: 1, typ: "sub", master_pub: org.masterPub, sub: rec.label, iat: Math.floor(Date.now() / 1000), exp };
  let sig;
  try {
    // Sign in memory, then drop the key. Same canonical bytes as the offline lib.
    sig = signWithRawKey(masterPrivateKey, canonicalJson(payload));
  } catch (e) {
    return sendJSON(res, 400, { error: { type: "bad_key", message: "could not sign with the provided master private key" } }, ALLOWED_ORIGIN);
  }
  rec.token = { payload, sig };
  rec.signed = true;
  rec.expires = exp;
  logLine("roster mint (DELEGATED — key seen in memory)", org.id, id);
  return sendJSON(res, 200, {
    id, status: "active", signed: true, token: rec.token,
    disclosure: "DELEGATED mint: the operator's process saw your master private key in memory to produce this signature. This code did not persist it, but that is a promise, not a proof. Client-sign avoids this entirely.",
  }, ALLOWED_ORIGIN);
}

function handleListRoster(res, org) {
  const now = Math.floor(Date.now() / 1000);
  const list = [...org.roster.values()].map((r) => ({
    id: r.id, label: r.label, expires: r.expires,
    signed: r.signed, revoked: r.revoked,
    status: r.revoked ? "revoked" : !r.signed ? "pending-signature" : (r.expires && r.expires <= now) ? "expired" : "active",
    createdAt: r.createdAt,
  }));
  return sendJSON(res, 200, { org: org.orgName, signing_mode: SIGNING_MODE, roster: list }, ALLOWED_ORIGIN);
}

function handleRevoke(res, org, id) {
  const rec = org.roster.get(id);
  if (!rec) return sendJSON(res, 404, { error: { type: "not_found", message: "unknown roster id" } }, ALLOWED_ORIGIN);
  rec.revoked = true;
  rec.expires = Math.floor(Date.now() / 1000);
  logLine("roster revoke", org.id, id);
  return sendJSON(res, 200, {
    id, status: "revoked",
    note: "Revoked in the console roster. Because app verification is OFFLINE, revocation before exp only bites if clients consult the license service's revocation list (POST the sub token's hash there). Otherwise the sub remains valid offline until its exp.",
  }, ALLOWED_ORIGIN);
}

/* Minimal raw-Ed25519 signer used ONLY in delegated mode. Mirrors the licensing
   library's PKCS#8 wrapping of a raw 32-byte seed. */
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
function signWithRawKey(rawPrivB64, message) {
  const raw = Buffer.from(rawPrivB64, "base64");
  if (raw.length !== 32) throw new Error("Ed25519 private seed must be 32 bytes");
  const der = Buffer.concat([ED25519_PKCS8_PREFIX, raw]);
  const keyObj = crypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  return crypto.sign(null, Buffer.from(message, "utf8"), keyObj).toString("base64");
}

async function route(req, res, url, key) {
  if (key === "POST /v1/orgs") { await handleRegisterOrg(req, res); return true; }

  // Everything below requires an org admin bearer.
  const org = orgByToken(req);
  if (!org) {
    sendJSON(res, 401, { error: { type: "unauthorized", message: "Register a workspace and use its admin token." } }, ALLOWED_ORIGIN);
    return true;
  }
  if (key === "GET /v1/roster") { handleListRoster(res, org); return true; }
  if (key === "POST /v1/roster") { await handleAddRosterEntry(req, res, org); return true; }

  const mToken = /^\/v1\/roster\/([^/]+)\/token$/.exec(url.pathname);
  if (req.method === "POST" && mToken) { await handleAttachToken(req, res, org, mToken[1]); return true; }
  const mMint = /^\/v1\/roster\/([^/]+)\/mint$/.exec(url.pathname);
  if (req.method === "POST" && mMint) { await handleDelegatedMint(req, res, org, mMint[1]); return true; }
  const mRev = /^\/v1\/roster\/([^/]+)\/revoke$/.exec(url.pathname);
  if (req.method === "POST" && mRev) { handleRevoke(res, org, mRev[1]); return true; }

  return false;
}

export function createServer() {
  // SVC-1: fail-closed — refuse to start without a mandatory vendor public key,
  // otherwise forged master tokens could register workspaces unverified.
  requireVendorKey(VENDOR_PUBLIC_KEY, "console-service");
  return makeServer({ allowedOrigin: ALLOWED_ORIGIN, posture: POSTURE, route });
}

export { orgs, tokensToOrg, signWithRawKey, DELEGATED };

runIfMain(import.meta.url, process.argv[1], () => {
  createServer().listen(PORT, () => {
    logLine(`postern-cloud console backend listening on :${PORT}`);
    logLine(`  signing mode:  ${SIGNING_MODE}${DELEGATED ? "  (DELEGATED — operator sees the master key at mint time; a disclosed regression)" : "  (client-sign — server never holds the key; recommended)"}`);
    logLine(`  vendor key:    configured (MANDATORY — uploaded masters are always verified; service refuses to start without it)`);
    logLine(`  CORS origin:   ${ALLOWED_ORIGIN}${ORIGIN.explicit ? "" : " (deny-by-default; set ALLOWED_ORIGIN for your console)"}`);
    if (ORIGIN.wildcard) logLine("  WARNING: ALLOWED_ORIGIN='*' was set explicitly; scope it to your console origin before deployment.");
  });
});
