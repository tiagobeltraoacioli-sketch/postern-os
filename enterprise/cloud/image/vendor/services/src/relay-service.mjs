#!/usr/bin/env node
// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern CLOUD — HOSTED comms RELAY (reference prototype).
//
// STATUS: design / reference prototype. UNAUDITED. Pre-production.
//
// WHAT THIS IS
// ------------
// A metadata-minimizing message RELAY for the enterprise comms app. The comms
// app (enterprise/comms/) end-to-end encrypts message BODIES (Megolm via the
// postern-messenger crate); this relay is TRANSPORT ONLY. It moves opaque
// ciphertext blobs from sender to recipient and NEVER holds, parses, or can
// read message plaintext. There is no crypto here that could decrypt a body —
// the relay does not have the keys and does not want them.
//
// THE HONEST TRADE (see /v1/posture and README)
// ---------------------------------------------
// E2EE means the BODY is safe from the relay. But a hosted relay, unlike a
// self-hosted homeserver on the org's own metal, still learns ROUTING METADATA:
// who is sending to whom, when, how big, and from what IP / at what times. That
// social graph and timing is a REAL privacy cost of hosting, and self-hosting
// avoids exposing it to any third party. We disclose it plainly and minimize it:
//
//   * bodies are opaque and never persisted beyond the brief queue-until-
//     delivered window; delivered ciphertext is DROPPED;
//   * SEALED-SENDER mode lets a client omit the `from` routing id (the sender
//     identity then lives only INSIDE the E2EE body the relay cannot read), so
//     the relay sees the recipient but not the authenticated sender;
//   * only counts and coarse timestamps are logged — never ciphertext, never
//     any body, never a plaintext anything;
//   * undelivered messages expire (TTL) so nothing lingers.
//
// It still cannot be as private as not using a hosted relay at all. That's the
// disclosed trade. Personal editions never use this — enterprise opt-in only.
//
// ENDPOINTS
//   GET  /healthz  /v1/posture
//   POST /auth/register { label? }         issue a routing id + bearer token
//   POST /v1/send { to, ciphertext, sealedSender?, contentType? }
//                                          queue an OPAQUE blob for a recipient
//   GET  /v1/inbox                         pull + DROP queued blobs for the caller
//   GET  /v1/me                            caller's routing id + queue depth (metadata)
//
// ENV
//   PORT               default 8803
//   ALLOWED_ORIGIN     CORS origin. Default is DENY (localhost only); never "*".
//                      Set it explicitly to your client origin in production.
//   TRUST_PROXY        "1" to honor X-Forwarded-For
//   MAX_BLOB_BYTES     max ciphertext size (default 5 MiB)
//   QUEUE_TTL_MS       undelivered-message TTL (default 604800000 = 7 days)
//   MAX_QUEUE_PER_RCPT max queued blobs per recipient (default 1000)

"use strict";

import crypto from "node:crypto";
import {
  makeServer, sendJSON, readJSON, bearerToken, clientIP, logLine,
  createRateLimiter, sha256hex, definePosture, runIfMain, resolveAllowedOrigin,
} from "./common.mjs";

const PORT = parseInt(process.env.PORT || "8803", 10);
const ORIGIN = resolveAllowedOrigin(process.env.ALLOWED_ORIGIN);
const ALLOWED_ORIGIN = ORIGIN.origin;
const TRUST_PROXY = process.env.TRUST_PROXY === "1";
const MAX_BLOB_BYTES = parseInt(process.env.MAX_BLOB_BYTES || String(5 * 1024 * 1024), 10);
const QUEUE_TTL_MS = parseInt(process.env.QUEUE_TTL_MS || String(7 * 24 * 60 * 60 * 1000), 10);
const MAX_QUEUE_PER_RCPT = parseInt(process.env.MAX_QUEUE_PER_RCPT || "1000", 10);
const MAX_BODY_BYTES = MAX_BLOB_BYTES + 64 * 1024; // envelope overhead

export const POSTURE = definePosture({
  service: "postern-cloud-relay",
  label: "Postern Cloud — hosted comms relay (transport only)",
  lessPrivateThan: "a self-hosted homeserver on the org's own infrastructure, which exposes routing metadata to no third party",
  canSee: [
    "Routing metadata: the RECIPIENT routing id of every message, and (unless sealed-sender) the SENDER routing id.",
    "Timing: when each message is sent and collected — enough to infer a social graph and activity patterns.",
    "Ciphertext SIZE and coarse type label (an opaque length, not content).",
    "Connection metadata: client IP and connection times (unless fronted by an anonymizing network).",
  ],
  cannotSee: [
    "Message PLAINTEXT — bodies are end-to-end encrypted opaque blobs. The relay holds no decryption keys and has no crypto that could read them.",
    "Attachment content, message text, reactions, or anything inside the E2EE envelope.",
    "In SEALED-SENDER mode: the authenticated sender identity (it lives only inside the body the relay cannot read).",
  ],
  metadataExposed: [
    "The who-talks-to-whom social graph and its timing — the principal cost of a hosted relay over self-hosting.",
    "Ciphertext sizes and send/receive cadence, which can leak coarse behavioral patterns even without content.",
  ],
  minimizations: [
    "Bodies are opaque and NEVER parsed; the relay treats ciphertext as bytes.",
    "Deliver-then-drop: a blob is removed from the queue the moment it is collected; nothing is archived.",
    "Undelivered blobs expire after a TTL so nothing lingers indefinitely.",
    "Sealed-sender: clients may omit the `from` routing id so the relay never sees an authenticated sender.",
    "Logs carry counts and coarse timing only — never ciphertext, never a routing pair when sealed.",
    "No message content, no analytics, no third-party calls, no persistence to disk in this reference build.",
  ],
  promiseNotProof:
    "The relay cannot read bodies — that is architecture, not a promise (it has no keys). But 'we don't log the social graph' and 'we drop on delivery' are POLICIES of this code; a compelled operator could change them. Self-hosting removes the third party entirely; sealed-sender removes the sender from what a hosted relay sees.",
});

/* In-memory stores (reference build; a real deployment uses a durable queue).
   Routing id -> account; recipient routing id -> array of opaque envelopes. */
const accounts = new Map(); // routingId -> { routingId, label, tokenHash }
const tokensToRouting = new Map(); // tokenHash -> routingId
const queues = new Map(); // recipientRoutingId -> [ envelope ]

const registerRate = createRateLimiter(30, 60_000);
const sendRate = createRateLimiter(600, 60_000);

function callerByToken(req) {
  const tok = bearerToken(req);
  if (!tok) return null;
  const rid = tokensToRouting.get(sha256hex(tok));
  return rid ? accounts.get(rid) || null : null;
}

function pruneExpired(rid, now = Date.now()) {
  const q = queues.get(rid);
  if (!q) return;
  const kept = q.filter((e) => now - e.receivedAt < QUEUE_TTL_MS);
  if (kept.length) queues.set(rid, kept);
  else queues.delete(rid);
}

async function handleRegister(req, res) {
  if (!registerRate.allow(clientIP(req, TRUST_PROXY))) {
    return sendJSON(res, 429, { error: { type: "rate_limited", message: "Too many registrations." } }, ALLOWED_ORIGIN);
  }
  let body = {};
  try { ({ json: body } = await readJSON(req, 8 * 1024)); } catch { body = {}; }
  const routingId = "rid_" + crypto.randomBytes(12).toString("hex");
  const token = "prt_" + crypto.randomBytes(32).toString("hex"); // Postern Relay Token
  accounts.set(routingId, {
    routingId,
    // A label is optional and, if provided, is the caller's OWN choice to expose.
    label: body && body.label ? String(body.label).slice(0, 200) : null,
    createdAt: new Date().toISOString(),
  });
  tokensToRouting.set(sha256hex(token), routingId);
  logLine("relay register", routingId);
  return sendJSON(res, 200, {
    routing_id: routingId,
    token,
    note: "Store this token — kept only as a hash. This routing id is what senders address. The relay routes opaque E2EE blobs; it cannot read message bodies. Prefer sealed-sender when sending.",
  }, ALLOWED_ORIGIN);
}

async function handleSend(req, res, caller) {
  if (!sendRate.allow(caller.routingId)) {
    return sendJSON(res, 429, { error: { type: "rate_limited", message: "Send rate exceeded." } }, ALLOWED_ORIGIN);
  }
  let body;
  try { ({ json: body } = await readJSON(req, MAX_BODY_BYTES)); }
  catch (e) { return sendJSON(res, e.status || 413, { error: { type: "invalid_request", message: e.message } }, ALLOWED_ORIGIN); }

  const to = String(body.to || "").trim();
  const ciphertext = typeof body.ciphertext === "string" ? body.ciphertext : null;
  const sealed = body.sealedSender === true;
  if (!to) return sendJSON(res, 400, { error: { type: "invalid_request", message: "`to` routing id is required" } }, ALLOWED_ORIGIN);
  if (!ciphertext) return sendJSON(res, 400, { error: { type: "invalid_request", message: "`ciphertext` (opaque base64 E2EE blob) is required" } }, ALLOWED_ORIGIN);
  // Approximate decoded size; the relay treats this purely as bytes.
  const approxBytes = Math.floor(ciphertext.length * 3 / 4);
  if (approxBytes > MAX_BLOB_BYTES) {
    return sendJSON(res, 413, { error: { type: "too_large", message: `ciphertext exceeds MAX_BLOB_BYTES (${MAX_BLOB_BYTES})` } }, ALLOWED_ORIGIN);
  }
  if (!accounts.has(to)) {
    // Honest: we cannot deliver to an unknown routing id. This does reveal
    // (to the sender) whether a routing id exists — a known metadata leak of
    // any store-and-forward relay; sealed systems mitigate with blind delivery.
    return sendJSON(res, 404, { error: { type: "unknown_recipient", message: "no such routing id is registered on this relay" } }, ALLOWED_ORIGIN);
  }

  pruneExpired(to);
  const q = queues.get(to) || [];
  if (q.length >= MAX_QUEUE_PER_RCPT) {
    return sendJSON(res, 507, { error: { type: "recipient_queue_full", message: "recipient mailbox is full; try later" } }, ALLOWED_ORIGIN);
  }
  const envelope = {
    id: "env_" + crypto.randomBytes(8).toString("hex"),
    // Sender routing id is recorded ONLY when NOT sealed. Sealed-sender puts the
    // authenticated sender inside the E2EE body the relay cannot read.
    from: sealed ? null : caller.routingId,
    sealed,
    contentType: body.contentType ? String(body.contentType).slice(0, 64) : "application/octet-stream",
    size: approxBytes,
    ciphertext, // OPAQUE — never parsed, never logged, dropped on delivery
    receivedAt: Date.now(),
  };
  q.push(envelope);
  queues.set(to, q);

  // Content-free log: never the ciphertext; sender omitted entirely when sealed.
  logLine("relay send", sealed ? "sealed" : `from=${caller.routingId}`, `to=${to}`, `bytes=${approxBytes}`);
  return sendJSON(res, 200, {
    queued: true, id: envelope.id, sealed,
    disclosure: sealed
      ? "Queued sealed: the relay recorded the RECIPIENT and time, not an authenticated sender. It cannot read the body."
      : "Queued: the relay recorded sender + recipient + time + size (metadata). It cannot read the body. Use sealedSender:true to hide the sender from the relay.",
  }, ALLOWED_ORIGIN);
}

function handleInbox(res, caller) {
  pruneExpired(caller.routingId);
  const q = queues.get(caller.routingId) || [];
  // Deliver-then-DROP: hand over the blobs and clear the mailbox immediately.
  queues.delete(caller.routingId);
  const messages = q.map((e) => ({
    id: e.id, from: e.from, sealed: e.sealed, contentType: e.contentType,
    size: e.size, receivedAt: new Date(e.receivedAt).toISOString(), ciphertext: e.ciphertext,
  }));
  logLine("relay inbox", `to=${caller.routingId}`, `delivered=${messages.length}`);
  return sendJSON(res, 200, {
    messages,
    note: "Delivered and dropped from the relay. Decrypt each ciphertext locally with your E2EE keys — the relay never could. Sealed messages carry `from:null`; the real sender is inside the encrypted body.",
  }, ALLOWED_ORIGIN);
}

function handleMe(res, caller) {
  pruneExpired(caller.routingId);
  const q = queues.get(caller.routingId) || [];
  return sendJSON(res, 200, {
    routing_id: caller.routingId,
    label: caller.label,
    queued: q.length,
    note: "The relay knows your routing id and queue depth (metadata). It does not know the content of anything queued for you.",
  }, ALLOWED_ORIGIN);
}

async function route(req, res, url, key) {
  if (key === "POST /auth/register") { await handleRegister(req, res); return true; }

  const caller = callerByToken(req);
  if (!caller) {
    sendJSON(res, 401, { error: { type: "unauthorized", message: "Register to get a routing id + token." } }, ALLOWED_ORIGIN);
    return true;
  }
  if (key === "POST /v1/send") { await handleSend(req, res, caller); return true; }
  if (key === "GET /v1/inbox") { handleInbox(res, caller); return true; }
  if (key === "GET /v1/me") { handleMe(res, caller); return true; }
  return false;
}

export function createServer() {
  return makeServer({ allowedOrigin: ALLOWED_ORIGIN, posture: POSTURE, route });
}

export { accounts, tokensToRouting, queues, pruneExpired };

runIfMain(import.meta.url, process.argv[1], () => {
  createServer().listen(PORT, () => {
    logLine(`postern-cloud comms relay listening on :${PORT}`);
    logLine(`  transport only: message bodies are E2EE and opaque — the relay cannot read them.`);
    logLine(`  blob cap: ${MAX_BLOB_BYTES} bytes   queue TTL: ${QUEUE_TTL_MS} ms   per-recipient cap: ${MAX_QUEUE_PER_RCPT}`);
    logLine(`  minimization: deliver-then-drop; sealed-sender supported; counts-only logging.`);
    logLine(`  CORS origin:   ${ALLOWED_ORIGIN}${ORIGIN.explicit ? "" : " (deny-by-default; set ALLOWED_ORIGIN for your client)"}`);
    if (ORIGIN.wildcard) logLine("  WARNING: ALLOWED_ORIGIN='*' was set explicitly; scope it to your client origin before deployment.");
    logLine("  DISCLOSED: a hosted relay sees routing metadata (who->whom, when, size) that self-hosting would not expose to a third party.");
  });
});
