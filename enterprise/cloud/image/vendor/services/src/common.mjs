// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern CLOUD hosted services — shared, framework-free plumbing.
//
// STATUS: design / reference prototype. UNAUDITED. Pre-production. Not a
// security product; do not rely on it for anything safety- or compliance-
// critical without an independent review and a real audit.
//
// WHAT LIVES HERE
// ---------------
//   1. The canonical Ed25519 + canonical-JSON verification format, re-derived
//      standalone from `enterprise/licensing/` (keys.ts + encoding.ts +
//      token.ts). We do NOT import that library — this directory is a
//      self-contained hosted counterpart. The FORMAT is mirrored so a token
//      signed by the offline library verifies here byte-for-byte. We only ever
//      hold PUBLIC keys here; nothing in the hosted services signs a master
//      token, and nothing here needs the vendor private key.
//   2. Zero-dependency HTTP plumbing (Node's http/crypto only), a fixed-window
//      rate limiter, and small helpers shared by the three services.
//   3. The honest PRIVACY POSTURE model. Every hosted service declares, in one
//      structured place, what it CAN and CANNOT see — and states plainly that a
//      hosted service is LESS private than self-hosting/offline. The rail: this
//      is "a promise, not a proof" (mirrored from apps/tolmach-subscription).
//
// HOUSE RAILS honored throughout this directory:
//   - Hosted = less private, and we DISCLOSE it, never bury it.
//   - The comms relay never sees message plaintext (E2EE bodies are opaque).
//   - Metadata is minimized AND disclosed; no telemetry beyond what is declared.
//   - These are BUSINESS/opt-in services. Personal editions are free forever
//     and never touch a hosted service — nothing here gates or phones home for
//     them.
//   - Adherence-by-design, not certified. Unaudited. The coin is not a security
//     and is never involved; billing (if any) is ordinary currency.

"use strict";

import http from "node:http";
import crypto from "node:crypto";
import path from "node:path";

/* ============================================================================
   1. CANONICAL FORMAT — Ed25519 detached signatures over canonical JSON.
   Mirrors enterprise/licensing/src/{encoding,keys,token}.ts exactly so tokens
   minted by the offline library verify here without modification.
   ========================================================================== */

// Fixed ASN.1/DER prefix that turns a raw 32-byte Ed25519 public key into SPKI
// DER that node:crypto accepts. (Same constant as the licensing library.)
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/** Deterministic JSON: keys sorted at every level, undefined dropped. */
export function canonicalJson(value) {
  return JSON.stringify(sortDeep(value));
}
function sortDeep(value) {
  if (Array.isArray(value)) return value.map(sortDeep);
  if (value && typeof value === "object") {
    const src = value;
    const out = {};
    for (const key of Object.keys(src).sort()) {
      if (src[key] === undefined) continue;
      out[key] = sortDeep(src[key]);
    }
    return out;
  }
  return value;
}

function publicKeyObject(rawPubB64) {
  const raw = Buffer.from(rawPubB64, "base64");
  if (raw.length !== 32) throw new Error("Ed25519 public key must be 32 bytes");
  const der = Buffer.concat([ED25519_SPKI_PREFIX, raw]);
  return crypto.createPublicKey({ key: der, format: "der", type: "spki" });
}

/** Verify a base64 detached signature over `message` (bytes) with a raw pubkey. */
export function ed25519Verify(rawPubB64, message, sigB64) {
  try {
    return crypto.verify(null, Buffer.from(message), publicKeyObject(rawPubB64), Buffer.from(sigB64, "base64"));
  } catch {
    return false;
  }
}

/** Verify a { payload, sig } signed token against a raw public key. */
export function verifySignedToken(pubB64, token) {
  if (!token || typeof token !== "object" || token.payload == null || typeof token.sig !== "string") return false;
  return ed25519Verify(pubB64, Buffer.from(canonicalJson(token.payload), "utf8"), token.sig);
}

/**
 * Offline verification chain, mirrored from the licensing library:
 *   verify(VENDOR_PUB, master) && (optional) verify(master.master_pub, sub)
 * `expired` is reported separately from `ok` so callers degrade gracefully — an
 * authentic-but-expired token is ok:true, expired:true, never a hard failure.
 *
 * NOTE: this is the SAME computation an app does locally and offline. Running it
 * on a server buys nothing cryptographically; the only thing a hosted verify
 * adds is convenience (and the metadata cost disclosed in the posture).
 */
export function verifyChain(vendorPublicKey, master, sub, now = new Date()) {
  const m = master && master.payload;
  if (!m || m.v !== 1 || m.typ !== "master") return { ok: false, reason: "malformed-master" };
  if (!verifySignedToken(vendorPublicKey, master)) return { ok: false, reason: "bad-master-signature" };
  if (m.tier === "corporate-master" && !/^[0-9]{9}$/.test(String(m.duns || ""))) {
    return { ok: false, reason: "bad-duns" };
  }
  const t = Math.floor(now.getTime() / 1000);
  const masterExpired = m.exp <= t;

  if (!sub) {
    return { ok: true, level: "master", tier: m.tier, seats: m.seats, duns: m.duns, exp: m.exp, expired: masterExpired };
  }
  const s = sub.payload;
  if (!s || s.v !== 1 || s.typ !== "sub") return { ok: false, reason: "malformed-sub" };
  if (s.master_pub !== m.master_pub) return { ok: false, reason: "sub-master-mismatch" };
  if (s.exp > m.exp) return { ok: false, reason: "sub-outlives-master" };
  if (!verifySignedToken(m.master_pub, sub)) return { ok: false, reason: "bad-sub-signature" };

  const effectiveExp = Math.min(s.exp, m.exp);
  return {
    ok: true,
    level: "sub",
    tier: m.tier,
    seats: m.seats,
    duns: m.duns,
    exp: effectiveExp,
    sub: s.sub,
    expired: masterExpired || effectiveExp <= t,
  };
}

/* ============================================================================
   2. HTTP plumbing + small utilities (zero deps).
   ========================================================================== */

export function sha256hex(s) {
  return crypto.createHash("sha256").update(s).digest("hex");
}

/** Constant-time string compare (avoids leaking token/HMAC prefixes via timing). */
export function timingSafeEqualStr(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

/* ----------------------------------------------------------------------------
   FAIL-CLOSED CONFIG GUARDS (SVC-1, SVC-2).
   A hosted verifier that starts WITHOUT a vendor key would fail OPEN — it would
   have no key to check master tokens against and would end up accepting the
   unverifiable. So the vendor key is MANDATORY: a service refuses to start
   without it. Likewise CORS must never default to "*" — the default is deny
   (localhost only) and a wildcard is allowed only when an operator sets it.
   -------------------------------------------------------------------------- */

/** Deny-by-default CORS origin used when ALLOWED_ORIGIN is not configured. */
export const DEFAULT_DENY_ORIGIN = "http://localhost";

/**
 * SVC-2: resolve the CORS origin fail-closed. An unset/blank ALLOWED_ORIGIN
 * NEVER becomes "*"; it falls back to localhost-only (deny cross-origin). A
 * wildcard is honored only when an operator EXPLICITLY sets ALLOWED_ORIGIN="*".
 * @returns {{origin:string, explicit:boolean, wildcard:boolean}}
 */
export function resolveAllowedOrigin(raw) {
  const v = (raw == null ? "" : String(raw)).trim();
  if (!v) return { origin: DEFAULT_DENY_ORIGIN, explicit: false, wildcard: false };
  return { origin: v, explicit: true, wildcard: v === "*" };
}

/**
 * SVC-1: assert a mandatory vendor public key. Returns the trimmed key or throws
 * a clear fail-closed error so the service REFUSES TO START rather than run in a
 * fail-open state where master tokens cannot be verified.
 */
export function requireVendorKey(rawKey, serviceName = "service") {
  const key = (rawKey == null ? "" : String(rawKey)).trim();
  if (!key) {
    throw new Error(
      `${serviceName}: VENDOR_PUBLIC_KEY is MANDATORY and was not set. ` +
        `Refusing to start (fail-closed): with no vendor key this service cannot verify master ` +
        `tokens and would accept the unverifiable (fail-open). Set VENDOR_PUBLIC_KEY to the ` +
        `base64 raw Ed25519 vendor public key.`,
    );
  }
  return key;
}

export function corsHeaders(allowedOrigin, extra = {}) {
  return {
    "access-control-allow-origin": allowedOrigin,
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-allow-headers": "content-type, authorization",
    ...extra,
  };
}

// SVC-2 (fail closed at the LAST hop too): the default here is DENY, never
// "*". A wildcard default silently defeated resolveAllowedOrigin's whole
// fail-closed design for any caller that omitted the argument — the operator
// configured deny-by-default, and one forgetful call site re-opened CORS to
// every origin. A wildcard now only ever reaches the wire when a caller
// passes one through explicitly (i.e. the operator set ALLOWED_ORIGIN="*").
export function sendJSON(res, status, obj, allowedOrigin = DEFAULT_DENY_ORIGIN, extraHeaders = {}) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    "content-type": "application/json",
    "cache-control": "no-store",
    ...corsHeaders(allowedOrigin, extraHeaders),
  });
  res.end(body);
}

export function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > limit) {
        reject(Object.assign(new Error("payload too large"), { status: 413 }));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

export async function readJSON(req, limit) {
  const buf = await readBody(req, limit);
  const text = buf.toString("utf8") || "{}";
  return { json: JSON.parse(text), bytes: buf.length };
}

export function bearerToken(req) {
  const h = req.headers["authorization"] || "";
  const m = /^Bearer\s+(.+)$/i.exec(String(h).trim());
  return m ? m[1].trim() : null;
}

/** Client IP for rate limiting. X-Forwarded-For only when trustProxy is set. */
export function clientIP(req, trustProxy = false) {
  if (trustProxy) {
    const xf = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim();
    if (xf) return xf;
  }
  return (req.socket && req.socket.remoteAddress) || "unknown";
}

/** Timestamped, CONTENT-FREE log line. Never pass request/response bodies here. */
export function logLine(...parts) {
  console.log(new Date().toISOString(), ...parts);
}

/**
 * Fixed-window rate limiter (zero deps, memory-bounded). `allow(key, now)`
 * returns true and counts the hit, or false when `limit` hits already landed in
 * the current window.
 */
export function createRateLimiter(limit, windowMs) {
  const hits = new Map();
  return {
    allow(key, now = Date.now()) {
      if (hits.size > 4096) {
        for (const [k, e] of hits) if (now >= e.resetAt) hits.delete(k);
      }
      const e = hits.get(key);
      if (!e || now >= e.resetAt) {
        hits.set(key, { count: 1, resetAt: now + windowMs });
        return true;
      }
      if (e.count >= limit) return false;
      e.count += 1;
      return true;
    },
  };
}

/** Start an http server only when the module is run directly (import-safe). */
export function runIfMain(importMetaUrl, argv1, start) {
  try {
    const asUrl = new URL("file://" + path.resolve(argv1)).href;
    if (argv1 && importMetaUrl === asUrl) start();
  } catch {
    /* ignore */
  }
}

/* ============================================================================
   3. PRIVACY POSTURE — the honest, structured "what we can and cannot see".
   Each hosted service declares one of these. The header rail, the /v1/posture
   endpoint, and the README all render from it, so no disclosure can silently
   drift from what the service technically does.
   ========================================================================== */

/**
 * @typedef {Object} Posture
 * @property {string} service            machine id
 * @property {string} label              human label
 * @property {string} lessPrivateThan    the more-private alternative this replaces
 * @property {string[]} canSee           what the hosted operator CAN observe (cleartext / metadata)
 * @property {string[]} cannotSee        what it structurally CANNOT observe
 * @property {string[]} metadataExposed  the METADATA a hosted deployment leaks that self-hosting does not
 * @property {string[]} minimizations    concrete steps taken to minimize what is seen/kept
 * @property {string} promiseNotProof    the honest "policy, not architecture" caveat
 */

/** Freeze + shallow-validate a posture so callers can trust its shape. */
export function definePosture(p) {
  for (const k of ["service", "label", "lessPrivateThan", "canSee", "cannotSee", "metadataExposed", "minimizations", "promiseNotProof"]) {
    if (p[k] == null) throw new Error(`posture "${p && p.service}": missing field ${k}`);
  }
  return Object.freeze({
    ...p,
    canSee: Object.freeze([...p.canSee]),
    cannotSee: Object.freeze([...p.cannotSee]),
    metadataExposed: Object.freeze([...p.metadataExposed]),
    minimizations: Object.freeze([...p.minimizations]),
  });
}

/** Plain-text rendering of a posture — suitable for a banner, log, or README. */
export function postureText(p) {
  const bullet = (s) => `  - ${s}`;
  return [
    `PRIVACY POSTURE — ${p.label}`,
    `  Hosted is LESS private than: ${p.lessPrivateThan}.`,
    "",
    "What this hosted service CAN see:",
    ...p.canSee.map(bullet),
    "",
    "What it CANNOT see:",
    ...p.cannotSee.map(bullet),
    "",
    "Metadata a hosted deployment exposes (that self-hosting does not):",
    ...p.metadataExposed.map(bullet),
    "",
    "Minimizations applied:",
    ...p.minimizations.map(bullet),
    "",
    `A promise, not a proof: ${p.promiseNotProof}`,
    "",
    "Status: design / reference prototype — UNAUDITED, pre-production, adherence-by-design (not certified).",
  ].join("\n");
}

/** Shared HTTP server bootstrap: OPTIONS + /healthz + /v1/posture, then route. */
export function makeServer({ allowedOrigin, posture, route }) {
  return http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://localhost");
    const key = req.method + " " + url.pathname;
    try {
      if (req.method === "OPTIONS") {
        res.writeHead(204, corsHeaders(allowedOrigin, { "access-control-max-age": "86400" }));
        return res.end();
      }
      if (key === "GET /healthz") {
        return sendJSON(res, 200, { ok: true, service: posture.service }, allowedOrigin);
      }
      if (key === "GET /v1/posture") {
        return sendJSON(res, 200, { posture, status: "reference-prototype/unaudited" }, allowedOrigin);
      }
      const handled = await route(req, res, url, key);
      if (!handled && !res.headersSent) {
        sendJSON(res, 404, { error: { type: "not_found", message: "not found" } }, allowedOrigin);
      }
    } catch (e) {
      // Never include request content in error logs.
      logLine("error", key, e && e.message);
      if (!res.headersSent) sendJSON(res, e && e.status ? e.status : 500, { error: { type: "internal", message: "internal error" } }, allowedOrigin);
      else {
        try { res.end(); } catch {}
      }
    }
  });
}
