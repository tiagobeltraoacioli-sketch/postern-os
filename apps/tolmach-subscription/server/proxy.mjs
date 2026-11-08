#!/usr/bin/env node
/* ============================================================================
   TOLMACH SUBSCRIPTION PROXY — metering reverse-proxy for the Claude API
   A Postern Labs reference implementation.

   License: MIT. Zero runtime dependencies — Node.js >= 18.17 (built-in fetch,
   node:crypto, node:http). Everything below is standard library.

   WHAT THIS IS
   ------------
   The Sovereign tier of Tolmach is a static page: browser -> api.anthropic.com
   with the USER's own key. No server, no extra parties. This proxy exists for
   the OTHER tier — Subscription — where end-users pay a flat monthly price and
   tokens are billed to the OPERATOR's Anthropic contract. That is impossible
   without a server: the operator's master key must never reach a browser, so
   a backend has to hold it, authenticate the subscriber, meter usage, enforce
   quotas, and forward the request.

   HONEST PRIVACY STATEMENT (read this before deploying)
   ------------------------------------------------------
   * This process necessarily SEES PLAINTEXT prompts and responses in memory —
     translations, meeting transcripts — because it must forward them.
     That is a real privacy regression versus the Sovereign tier, and no
     amount of policy changes the architecture.
   * What this implementation guarantees BY CODE is zero prompt persistence:
     request/response bodies are never written to disk, never logged, and are
     dropped as soon as the stream ends. Only token COUNTS, model ids, and
     timestamps are persisted per subscriber (that's the metering).
   * This is trust REDUCTION, not trust ELIMINATION. A malicious or compelled
     operator could modify this code to log. Users who need the stronger
     guarantee must use the Sovereign tier — keep both tiers available.
   * Anthropic processes subscription-tier prompts under the OPERATOR's
     agreement, not the end-user's.

   ENDPOINTS
   ---------
     GET  /healthz                     liveness
     POST /auth/register {email}       Identity. DEFAULT (reference): issues a
                                       token directly (labeled stub). With
                                       REQUIRE_EMAIL_VERIFICATION=1 (real path):
                                       sends a one-time code OUT OF BAND and
                                       issues NO token here. Rate-limited (per-IP
                                       + global + account cap) and non-enumerating.
     POST /auth/verify {email, code}   Real path only: exchange the emailed code
                                       for a bearer token. Rate-limited +
                                       attempt-capped (a code is a low-entropy
                                       secret); non-enumerating.
     GET  /v1/me                       subscriber profile + this month's usage
     POST /v1/messages                 authenticated metering proxy to
                                       https://api.anthropic.com/v1/messages
                                       (SSE streamed back byte-for-byte)
     POST /billing/checkout {tier}     create a Stripe Checkout session (test mode)
     POST /billing/portal              Stripe billing-portal session
     POST /billing/webhook             Stripe webhook (signature-verified):
                                       activates/deactivates + sets tier
     POST /billing/dev-activate {tier} DEV_MODE=1 only — activate without Stripe

   ENV VARS
   --------
     ANTHROPIC_API_KEY      operator's master key (required to proxy) — server-side only
     PORT                   default 8787
     DATA_DIR               default ./data (subscribers + usage JSON; NO prompt text)
     ALLOWED_ORIGIN         CORS origin of the client page (default *; set it!)
     PUBLIC_BASE_URL        where the client is served (Stripe redirect URLs)
     STRIPE_SECRET_KEY      sk_test_… (Stripe test mode; live wiring identical)
     STRIPE_WEBHOOK_SECRET  whsec_… from `stripe listen` or the dashboard
     STRIPE_PRICE_BASIC     price_… id of the Basic monthly price
     STRIPE_PRICE_PRO       price_… id of the Pro monthly price
     DEV_MODE               "1" enables /billing/dev-activate — but is IGNORED
                            (fail-closed) if any production signal is present
                            (NODE_ENV=production, https PUBLIC_BASE_URL, or an
                            https ALLOWED_ORIGIN). Impossible to enable in prod.
     NODE_ENV               "production" hardens DEV_MODE off + disables dev code echo
     REQUIRE_EMAIL_VERIFICATION  "1" = real identity: register sends a code,
                            /auth/verify issues the token (needs MAIL_COMMAND)
     MAIL_COMMAND           process that reads a JSON {to,subject,code,text}
                            envelope on stdin and delivers it (e.g. "sendmail -t")
     VERIFY_CODE_TTL_MS     verification-code lifetime (default 900000 = 15 min)
     VERIFY_MAX_ATTEMPTS    max wrong codes before a pending code is burned (5)
     MAX_SUBSCRIBERS        cap on total accounts (default 10000)
     REGISTER_PER_IP_LIMIT  /auth/register per-IP limit per window (default 5)
     REGISTER_GLOBAL_LIMIT  /auth/register global limit per window (default 100)
     REGISTER_WINDOW_MS     rate-limit window (default 3600000 = 1 h)
     TRUST_PROXY            "1" = trust X-Forwarded-For (only behind your own
                            reverse proxy)
   ============================================================================ */
"use strict";

import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";

/* ----------------------------- configuration ----------------------------- */

const PORT = parseInt(process.env.PORT || "8787", 10);
const DATA_DIR = process.env.DATA_DIR || path.join(process.cwd(), "data");
const ANTHROPIC_API_KEY = (process.env.ANTHROPIC_API_KEY || "").trim();
// ANTHROPIC_BASE_URL override exists for tests only; production leaves it unset.
const ANTHROPIC_URL = (process.env.ANTHROPIC_BASE_URL || "https://api.anthropic.com").replace(/\/+$/, "") + "/v1/messages";
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || "*";
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || "http://localhost:8787";
const STRIPE_SECRET_KEY = (process.env.STRIPE_SECRET_KEY || "").trim();
const STRIPE_WEBHOOK_SECRET = (process.env.STRIPE_WEBHOOK_SECRET || "").trim();
const STRIPE_PRICE_BASIC = (process.env.STRIPE_PRICE_BASIC || "").trim();
const STRIPE_PRICE_PRO = (process.env.STRIPE_PRICE_PRO || "").trim();
const NODE_ENV = (process.env.NODE_ENV || "development").trim();

/* ── DEV_MODE, made impossible to enable in production (fail-closed) ─────────
   `/billing/dev-activate` grants a paid tier with NO payment. That is a dev-only
   convenience and a foot-gun in production. Rather than trust the operator to
   never set DEV_MODE=1 on a real host, the flag is INERT the moment anything
   looks like production: the effective flag is `false`, the endpoint 404s, and
   the bypass simply does not exist. Setting DEV_MODE=1 in prod does nothing. */
const RAW_DEV_MODE = process.env.DEV_MODE === "1";
function devModeProdSignals() {
  const s = [];
  if (NODE_ENV === "production") s.push("NODE_ENV=production");
  if (/^https:\/\//i.test(PUBLIC_BASE_URL)) s.push("PUBLIC_BASE_URL is https (a real deployment URL)");
  if (ALLOWED_ORIGIN !== "*" && /^https:\/\//i.test(ALLOWED_ORIGIN)) s.push("ALLOWED_ORIGIN is a real https origin");
  return s;
}
const DEV_MODE_PROD_SIGNALS = devModeProdSignals();
const DEV_MODE = RAW_DEV_MODE && DEV_MODE_PROD_SIGNALS.length === 0;

/* ── Real identity (opt-in) ─────────────────────────────────────────────────
   The reference `/auth/register` issues a token to whoever types an email —
   fine for a demo, wrong for production (README + the endpoint say so). Set
   REQUIRE_EMAIL_VERIFICATION=1 to switch on the real path: register only sends a
   one-time code OUT OF BAND (via MAIL_COMMAND — a process that reads a JSON
   {to,subject,code,text} envelope on stdin, e.g. `sendmail -t` or an API shim),
   and the token is issued ONLY by /auth/verify after the code is presented. No
   token is ever handed out from register in this mode, closing the
   type-any-email-get-a-token hole. The Sovereign/BYOK tier is unaffected — it
   needs no account at all. */
const REQUIRE_EMAIL_VERIFICATION = process.env.REQUIRE_EMAIL_VERIFICATION === "1";
const MAIL_COMMAND = (process.env.MAIL_COMMAND || "").trim();
const VERIFY_CODE_TTL_MS = parseInt(process.env.VERIFY_CODE_TTL_MS || String(15 * 60 * 1000), 10);
const VERIFY_MAX_ATTEMPTS = parseInt(process.env.VERIFY_MAX_ATTEMPTS || "5", 10);

const MAX_BODY_BYTES = 1 * 1024 * 1024; // 1 MiB request cap
const MAX_CONCURRENT_PER_SUB = 4;

/* Registration abuse controls: /auth/register is unauthenticated, so it is
   rate-limited per client IP and globally, and the total number of accounts
   is capped (the JSON store is an in-memory object — unbounded accounts is a
   memory/disk DoS). Tune via env; defaults are deliberately conservative. */
const MAX_SUBSCRIBERS = parseInt(process.env.MAX_SUBSCRIBERS || "10000", 10);
const REGISTER_PER_IP_LIMIT = parseInt(process.env.REGISTER_PER_IP_LIMIT || "5", 10);       // per IP per window
const REGISTER_GLOBAL_LIMIT = parseInt(process.env.REGISTER_GLOBAL_LIMIT || "100", 10);     // all IPs per window
const REGISTER_WINDOW_MS = parseInt(process.env.REGISTER_WINDOW_MS || String(60 * 60 * 1000), 10);
/* Only trust X-Forwarded-For when an operator-controlled reverse proxy sets
   it; otherwise clients could spoof their way past the per-IP limit. */
const TRUST_PROXY = process.env.TRUST_PROXY === "1";

/* Input-token estimate used for quota reservations: ~3 bytes of request body
   per token. English averages ~4 bytes/token and CJK ~3 bytes/token, and the
   estimate runs over the whole JSON body (framing overhead included), so it
   over-counts in the common case — the conservative direction for admission
   control. Pathological tokenizations (dense emoji/rare code points) can
   still exceed it, which is why the README claims BOUNDED overspend, not
   zero. */
export const EST_BYTES_PER_TOKEN = 3;

/* Current Claude list prices, USD per MTok. Sonnet 5 has an introductory
   price through 2026-08-31 (UTC) — priced by request date.
   Cache pricing (if a client ever sends cache_control): writes 1.25x input,
   reads 0.1x input (5-minute TTL rates). */
export const PRICES = {
  "claude-haiku-4-5-20251001": { label: "Haiku 4.5", in: 1.0, out: 5.0 },
  "claude-haiku-4-5":          { label: "Haiku 4.5", in: 1.0, out: 5.0 },
  "claude-sonnet-5": {
    label: "Sonnet 5", in: 3.0, out: 15.0,
    intro: { untilExclusive: "2026-09-01", in: 2.0, out: 10.0 },
  },
  "claude-opus-4-8":           { label: "Opus 4.8", in: 5.0, out: 25.0 },
};
const CACHE_WRITE_MULT = 1.25;
const CACHE_READ_MULT = 0.10;

/* Tier model: meeting-minutes mode dominates cost (~$0.5–1.5 per meeting-hour
   on Sonnet 5; translation is pennies). budgetUSD is the OPERATOR's monthly
   upstream token spend allowed per subscriber — the hard quota. softWarnAt is
   the fraction at which responses carry a warning header (still served). */
export const TIERS = {
  basic: {
    label: "Basic",
    monthlyUSD: 9,
    budgetUSD: 6.0,           // ≈ 6–12 meeting-hours on Sonnet 5, or a lot of translating
    softWarnAt: 0.8,
    models: ["claude-haiku-4-5-20251001", "claude-haiku-4-5", "claude-sonnet-5"],
    maxTokensCap: 4096,
  },
  pro: {
    label: "Pro",
    monthlyUSD: 29,
    budgetUSD: 20.0,          // ≈ 20–40 meeting-hours on Sonnet 5; Opus allowed
    softWarnAt: 0.8,
    models: ["claude-haiku-4-5-20251001", "claude-haiku-4-5", "claude-sonnet-5", "claude-opus-4-8"],
    maxTokensCap: 8192,
  },
};

/* ------------------------------ cost math -------------------------------- */

export function priceFor(model, at = new Date()) {
  const p = PRICES[model];
  if (!p) return { label: model, in: 5.0, out: 25.0 }; // conservative fallback (Opus rates)
  if (p.intro && at.toISOString().slice(0, 10) < p.intro.untilExclusive) {
    return { label: p.label + " (intro)", in: p.intro.in, out: p.intro.out };
  }
  return p;
}

/** usage: { in, out, cacheWrite, cacheRead } (token counts) -> USD */
export function costUSD(model, usage, at = new Date()) {
  const p = priceFor(model, at);
  return (
    (usage.in || 0) / 1e6 * p.in +
    (usage.out || 0) / 1e6 * p.out +
    (usage.cacheWrite || 0) / 1e6 * p.in * CACHE_WRITE_MULT +
    (usage.cacheRead || 0) / 1e6 * p.in * CACHE_READ_MULT
  );
}

/**
 * Worst-case USD a request could cost upstream, computed BEFORE forwarding —
 * the amount the quota reservation debits. Input tokens are estimated from
 * the raw body size (bytes / EST_BYTES_PER_TOKEN — input was previously
 * UNCAPPED, which let a 1 MiB body burn ~$1.5+ per request past the budget
 * check); output at the tier's max_tokens cap (or the request's smaller
 * declared max_tokens). If the body mentions cache_control, the input
 * estimate is priced at the dearer cache-write rate.
 */
export function estimateRequestCostUSD(model, bodyBytes, maxTokens, hasCacheControl, at = new Date()) {
  const estIn = Math.ceil(bodyBytes / EST_BYTES_PER_TOKEN);
  const usage = hasCacheControl
    ? { in: 0, out: maxTokens, cacheWrite: estIn, cacheRead: 0 }
    : { in: estIn, out: maxTokens, cacheWrite: 0, cacheRead: 0 };
  return costUSD(model, usage, at);
}

/**
 * Fixed-window rate limiter (zero deps, memory-bounded). `allow(key, now)`
 * returns true and counts the hit, or false when `limit` hits already landed
 * in the current window. Expired entries are pruned opportunistically.
 */
export function createRateLimiter(limit, windowMs) {
  const hits = new Map(); // key -> { count, resetAt }
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

/* --------------------------- persistence (NO prompts) --------------------- */
/* Two JSON files under DATA_DIR. Neither ever contains prompt or response
   text — subscribers.json holds accounts (tokens stored as SHA-256 hashes),
   usage.json holds per-subscriber per-month token counters and cost.
   A real deployment should swap this for SQLite/Postgres; the shape is the
   contract. Writes are atomic (tmp + rename). Cosmetic state (new accounts,
   Stripe status) is debounced; quota-bearing state (reservations, settled
   usage) is flushed SYNCHRONOUSLY so a crash cannot erase incurred spend. */

const FILES = {
  subscribers: path.join(DATA_DIR, "subscribers.json"),
  usage: path.join(DATA_DIR, "usage.json"),
};

function loadJSON(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, "utf8")); } catch { return fallback; }
}
const db = {
  subscribers: loadJSON(FILES.subscribers, { subscribers: {}, tokens: {} }),
  usage: loadJSON(FILES.usage, {}),
};
// Pending email verifications (only used when REQUIRE_EMAIL_VERIFICATION=1).
// Keyed by SHA-256(email); holds the code HASH (never the code) + expiry. This
// lives in the subscribers file so a restart doesn't strand a just-sent code.
if (!db.subscribers.pending) db.subscribers.pending = {};
let saveTimer = null;
function scheduleSave() {
  if (saveTimer) return;
  saveTimer = setTimeout(() => { saveTimer = null; saveNow(); }, 250);
}
function saveNow() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  for (const [key, file] of Object.entries(FILES)) {
    const tmp = file + ".tmp";
    fs.writeFileSync(tmp, JSON.stringify(db[key === "subscribers" ? "subscribers" : "usage"], null, 2));
    fs.renameSync(tmp, file);
  }
}
process.on("exit", () => { try { if (saveTimer) saveNow(); } catch {} });

function sha256hex(s) { return crypto.createHash("sha256").update(s).digest("hex"); }
function monthKey(d = new Date()) { return d.toISOString().slice(0, 7); } // "YYYY-MM" (UTC)

function subscriberByToken(token) {
  if (!token) return null;
  const id = db.subscribers.tokens[sha256hex(token)];
  return id ? db.subscribers.subscribers[id] || null : null;
}
function subscriberByStripeCustomer(customerId) {
  return Object.values(db.subscribers.subscribers).find(s => s.stripeCustomerId === customerId) || null;
}
function monthUsage(subId, mk = monthKey()) {
  const bySub = db.usage[subId] || (db.usage[subId] = {});
  return bySub[mk] || (bySub[mk] = {
    in: 0, out: 0, cacheWrite: 0, cacheRead: 0, usd: 0, requests: 0, byModel: {},
    /* reservedUSD: worst-case cost of requests currently in flight, debited
       BEFORE forwarding and released when the request settles. Persisted so
       a crash mid-stream leaves the (conservative) estimate counted instead
       of erasing already-incurred upstream spend. Older usage.json files
       lack the field — read it with `|| 0`. */
    reservedUSD: 0,
  });
}

/* Reserve-then-settle quota accounting. Node's single thread makes each of
   these atomic as long as the caller does check + reserve in ONE synchronous
   block (no await between them) — that is what closes the old race where 4
   concurrent requests all passed the checked-before/recorded-after quota
   gate. Both sides persist SYNCHRONOUSLY: spend that has (or may have)
   already been incurred upstream must never sit only in a 250 ms debounce
   window a crash can erase. */
function reserveUsage(u, usd) {
  u.reservedUSD = (u.reservedUSD || 0) + usd;
  saveNow();
}
function releaseReservation(u, usd) {
  u.reservedUSD = Math.max(0, (u.reservedUSD || 0) - usd);
}
function recordUsage(subId, model, usage) {
  const u = monthUsage(subId);
  const usd = costUSD(model, usage);
  u.in += usage.in || 0;
  u.out += usage.out || 0;
  u.cacheWrite += usage.cacheWrite || 0;
  u.cacheRead += usage.cacheRead || 0;
  u.usd += usd;
  u.requests += 1;
  const bm = u.byModel[model] || (u.byModel[model] = { in: 0, out: 0, usd: 0, requests: 0 });
  bm.in += usage.in || 0;
  bm.out += usage.out || 0;
  bm.usd += usd;
  bm.requests += 1;
  scheduleSave();
  return usd;
}

/* ------------------------------ http plumbing ----------------------------- */

function corsHeaders(extra = {}) {
  return {
    "access-control-allow-origin": ALLOWED_ORIGIN,
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-allow-headers": "content-type, authorization, anthropic-version",
    "access-control-expose-headers":
      "x-tolmach-tier, x-tolmach-quota-used-usd, x-tolmach-quota-budget-usd, x-tolmach-quota-warning",
    ...extra,
  };
}
function sendJSON(res, status, obj, extraHeaders = {}) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store", ...corsHeaders(extraHeaders) });
  res.end(body);
}
function readBody(req, limit = MAX_BODY_BYTES) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > limit) { reject(Object.assign(new Error("payload too large"), { status: 413 })); req.destroy(); return; }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}
function bearerToken(req) {
  const h = req.headers["authorization"] || "";
  const m = /^Bearer\s+(.+)$/i.exec(h.trim());
  return m ? m[1].trim() : null;
}

/** Client IP for rate limiting. X-Forwarded-For only under TRUST_PROXY=1. */
function clientIP(req) {
  if (TRUST_PROXY) {
    const xf = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim();
    if (xf) return xf;
  }
  return req.socket?.remoteAddress || "unknown";
}

/* Log WITHOUT content: method, path, status, subscriber id, token counts only. */
function logLine(...parts) {
  console.log(new Date().toISOString(), ...parts);
}

/* -------------------------------- Stripe ---------------------------------- */
/* Raw REST calls (form-encoded) so we stay dependency-free. Test mode and
   live mode use the exact same code — only the sk_test_/sk_live_ key and the
   webhook secret differ. */

async function stripePOST(pathname, params) {
  if (!STRIPE_SECRET_KEY) throw Object.assign(new Error("Stripe is not configured on this proxy (STRIPE_SECRET_KEY unset)."), { status: 501 });
  const body = new URLSearchParams(params).toString();
  const res = await fetch("https://api.stripe.com" + pathname, {
    method: "POST",
    headers: {
      "authorization": "Bearer " + STRIPE_SECRET_KEY,
      "content-type": "application/x-www-form-urlencoded",
    },
    body,
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw Object.assign(new Error(json?.error?.message || "Stripe error"), { status: 502 });
  return json;
}

/** Verify `Stripe-Signature: t=...,v1=...` over the RAW payload. */
export function verifyStripeSignature(rawPayload, sigHeader, secret, toleranceSec = 300, nowMs = Date.now()) {
  if (!sigHeader || !secret) return false;
  const parts = Object.create(null);
  for (const kv of sigHeader.split(",")) {
    const i = kv.indexOf("=");
    if (i < 0) continue;
    const k = kv.slice(0, i).trim(), v = kv.slice(i + 1).trim();
    if (k === "t") parts.t = v;
    else if (k === "v1") (parts.v1 || (parts.v1 = [])).push(v);
  }
  if (!parts.t || !parts.v1) return false;
  const t = parseInt(parts.t, 10);
  if (!Number.isFinite(t) || Math.abs(nowMs / 1000 - t) > toleranceSec) return false;
  const expected = crypto.createHmac("sha256", secret).update(`${parts.t}.${rawPayload}`).digest("hex");
  return parts.v1.some((sig) => {
    try { return crypto.timingSafeEqual(Buffer.from(sig, "hex"), Buffer.from(expected, "hex")); }
    catch { return false; }
  });
}

function tierForPriceId(priceId) {
  if (priceId && priceId === STRIPE_PRICE_BASIC) return "basic";
  if (priceId && priceId === STRIPE_PRICE_PRO) return "pro";
  return null;
}

/* ------------------------------ SSE metering ------------------------------ */
/**
 * Incremental SSE usage extractor. Feed it decoded chunks of an Anthropic
 * /v1/messages event stream; it accumulates ONLY the usage numbers from
 * `message_start` and `message_delta` events. Event payload text is parsed
 * transiently and discarded — nothing else is retained (zero prompt logging).
 * Exported so tools/metering-check.mjs can unit-test the exact same code.
 */
export function createSSEMeter() {
  let buf = "";
  const usage = { in: 0, out: 0, cacheWrite: 0, cacheRead: 0 };
  function handleEvent(ev) {
    if (ev.type === "message_start" && ev.message && ev.message.usage) {
      const u = ev.message.usage;
      usage.in = u.input_tokens || 0;
      usage.cacheWrite = u.cache_creation_input_tokens || 0;
      usage.cacheRead = u.cache_read_input_tokens || 0;
    } else if (ev.type === "message_delta" && ev.usage) {
      if (typeof ev.usage.output_tokens === "number") usage.out = ev.usage.output_tokens;
      // some responses restate cumulative input tokens on the final delta
      if (typeof ev.usage.input_tokens === "number") usage.in = ev.usage.input_tokens;
    }
  }
  return {
    push(chunkText) {
      buf += chunkText;
      let sep;
      while ((sep = buf.indexOf("\n\n")) !== -1) {
        const block = buf.slice(0, sep);
        buf = buf.slice(sep + 2);
        for (const line of block.split("\n")) {
          if (!line.startsWith("data:")) continue;
          const payload = line.slice(5).trim();
          if (!payload || payload === "[DONE]") continue;
          try { handleEvent(JSON.parse(payload)); } catch { /* non-JSON keepalive */ }
        }
      }
    },
    usage() { return { ...usage } },
  };
}

/* ------------------------------- handlers --------------------------------- */

const inflight = new Map(); // subscriberId -> count
const registerPerIP = createRateLimiter(REGISTER_PER_IP_LIMIT, REGISTER_WINDOW_MS);
const registerGlobal = createRateLimiter(REGISTER_GLOBAL_LIMIT, REGISTER_WINDOW_MS);
// /auth/verify shares the same window; a code is a low-entropy secret so it must
// be brute-force-rate-limited independently of registration.
const verifyPerIP = createRateLimiter(REGISTER_PER_IP_LIMIT, REGISTER_WINDOW_MS);
const verifyGlobal = createRateLimiter(REGISTER_GLOBAL_LIMIT, REGISTER_WINDOW_MS);

/* Create-or-find the subscriber for `email` and mint a fresh 256-bit bearer
   token (stored only as a SHA-256 hash). Shared by the reference register stub
   and the real /auth/verify path. Returns { id, token } or null if the account
   cap is reached. */
function issueTokenForEmail(email) {
  if (Object.keys(db.subscribers.subscribers).length >= MAX_SUBSCRIBERS) return null;
  let sub = Object.values(db.subscribers.subscribers).find(s => s.email === email);
  if (!sub) {
    const id = "sub_" + crypto.randomBytes(9).toString("hex");
    sub = {
      id, email, tier: null, active: false,
      stripeCustomerId: null, stripeSubscriptionId: null,
      createdAt: new Date().toISOString(),
    };
    db.subscribers.subscribers[id] = sub;
  }
  const token = "dgm_" + crypto.randomBytes(32).toString("hex");
  db.subscribers.tokens[sha256hex(token)] = sub.id;
  scheduleSave();
  return { id: sub.id, token };
}

/* Deliver a verification code OUT OF BAND. Real delivery is a spawned
   MAIL_COMMAND that reads a JSON envelope on stdin; the operator supplies the
   actual transport (sendmail, an API shim, …) so this file keeps zero deps and
   never embeds a mail provider. Returns true if the code was handed to a
   transport. In a non-production host with no MAIL_COMMAND the code is logged to
   the SERVER console as a developer convenience (never in production). */
function sendVerificationEmail(email, code) {
  const envelope = JSON.stringify({
    to: email,
    subject: "Your Tolmach subscription verification code",
    code,
    text: `Your Tolmach verification code is ${code}. It expires in ${Math.round(VERIFY_CODE_TTL_MS / 60000)} minutes. If you did not request this, ignore this email.`,
  });
  if (MAIL_COMMAND) {
    try {
      const [cmd, ...args] = MAIL_COMMAND.split(/\s+/);
      const child = spawn(cmd, args, { stdio: ["pipe", "ignore", "ignore"] });
      child.on("error", (e) => logLine("mail-command error", e.message)); // never logs the code
      child.stdin.end(envelope);
      return true;
    } catch (e) {
      logLine("mail-command spawn failed", e.message);
      return false;
    }
  }
  if (NODE_ENV !== "production") {
    // Dev-only: no transport configured, so surface the code locally so a
    // developer can complete the flow. Refused in production (see caller).
    logLine("DEV verification code (configure MAIL_COMMAND for real delivery)", email, code);
    return true;
  }
  return false; // production with no transport: caller returns 501
}

async function handleRegister(req, res) {
  /* STUB IDENTITY PROVIDER. Real deployments replace this with actual auth
     (email verification, OIDC, passkeys). What is real here is the boundary:
     everything privileged requires a bearer token that maps to exactly one
     subscriber; tokens are 256-bit random and stored hashed.

     Abuse hardening (real, not stubbed):
     - rate-limited per IP and globally, plus a hard cap on total accounts —
       unauthenticated registration must not be a store-growth DoS;
     - the response is UNIFORM whether or not the email already has an
       account, so this endpoint cannot be used to enumerate subscriber
       emails. For an already-registered email a decoy token of identical
       shape is returned and NOT stored — it simply never authenticates.
       Full non-enumerability (including not handing live tokens to whoever
       types an address first) requires delivering tokens out-of-band via a
       verified channel — that is the real-IdP work the README already
       requires before production. */
  const ip = clientIP(req);
  if (!registerGlobal.allow("global") || !registerPerIP.allow(ip)) {
    return sendJSON(res, 429, { error: { type: "rate_limited", message: "Too many registration attempts. Try again later." } },
      { "retry-after": String(Math.ceil(REGISTER_WINDOW_MS / 1000)) });
  }
  let body;
  try { body = JSON.parse((await readBody(req)).toString("utf8") || "{}"); }
  catch { return sendJSON(res, 400, { error: { type: "invalid_request", message: "invalid JSON" } }); }
  const email = String(body.email || "").trim().toLowerCase();
  if (email.length > 254 || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    return sendJSON(res, 400, { error: { type: "invalid_request", message: "a valid email is required" } });
  }
  if (Object.keys(db.subscribers.subscribers).length >= MAX_SUBSCRIBERS) {
    return sendJSON(res, 503, { error: { type: "registration_closed", message: "Registration is temporarily closed (capacity)." } });
  }

  /* ── Real identity path: send an out-of-band code, issue NO token here ───── */
  if (REQUIRE_EMAIL_VERIFICATION) {
    // 6-digit code (uniformly random 000000–999999).
    const code = String(crypto.randomInt(0, 1_000_000)).padStart(6, "0");
    const delivered = sendVerificationEmail(email, code);
    if (!delivered) {
      return sendJSON(res, 501, { error: { type: "mail_unconfigured", message: "Email delivery is not configured on this proxy (set MAIL_COMMAND). Cannot verify identity." } });
    }
    // Store the code HASH (never the code), keyed by email hash, single latest.
    db.subscribers.pending[sha256hex(email)] = {
      email,
      codeHash: sha256hex(code),
      expiresAt: Date.now() + VERIFY_CODE_TTL_MS,
      attempts: 0,
    };
    scheduleSave();
    logLine("register (verify sent)", "email-hash", sha256hex(email).slice(0, 12));
    // UNIFORM response whether or not the email already has an account.
    return sendJSON(res, 200, {
      pending: true,
      note: `We sent a verification code to ${email}. Enter it at /auth/verify to receive your access token. No token is issued until the code is verified — and the Sovereign tier needs no account at all.`,
    });
  }

  /* ── Reference stub path (default; labeled) ─────────────────────────────── */
  const existing = Object.values(db.subscribers.subscribers).find(s => s.email === email);
  const id = "sub_" + crypto.randomBytes(9).toString("hex");
  const token = "dgm_" + crypto.randomBytes(32).toString("hex");
  const tokenHash = sha256hex(token); // computed on both paths (uniform timing)
  if (!existing) {
    db.subscribers.subscribers[id] = {
      id, email, tier: null, active: false,
      stripeCustomerId: null, stripeSubscriptionId: null,
      createdAt: new Date().toISOString(),
    };
    db.subscribers.tokens[tokenHash] = id;
    scheduleSave();
  }
  // Server-side log may distinguish (the operator owns this data); the HTTP
  // response must not.
  logLine("register", existing ? "existing-email (decoy issued)" : id);
  sendJSON(res, 200, {
    subscriber_id: id,
    token,
    note: "Store this token — it is shown once and kept only as a hash server-side. If this email was already registered, this token is NOT valid (this reference build has no token recovery; set REQUIRE_EMAIL_VERIFICATION=1 for the real out-of-band-verified path). No subscription is active yet; complete checkout to enable the proxy.",
  });
}

/* Exchange an out-of-band verification code for a bearer token. Only meaningful
   when REQUIRE_EMAIL_VERIFICATION=1. Rate-limited and attempt-capped: a code is
   a low-entropy secret. Non-enumerating: a wrong/expired code and an unknown
   email return the same shape. */
async function handleVerify(req, res) {
  const ip = clientIP(req);
  if (!verifyGlobal.allow("global") || !verifyPerIP.allow(ip)) {
    return sendJSON(res, 429, { error: { type: "rate_limited", message: "Too many verification attempts. Try again later." } },
      { "retry-after": String(Math.ceil(REGISTER_WINDOW_MS / 1000)) });
  }
  if (!REQUIRE_EMAIL_VERIFICATION) {
    return sendJSON(res, 404, { error: { type: "not_found", message: "Email verification is not enabled on this proxy." } });
  }
  let body;
  try { body = JSON.parse((await readBody(req)).toString("utf8") || "{}"); }
  catch { return sendJSON(res, 400, { error: { type: "invalid_request", message: "invalid JSON" } }); }
  const email = String(body.email || "").trim().toLowerCase();
  const code = String(body.code || "").trim();
  const fail = () => sendJSON(res, 400, { error: { type: "verification_failed", message: "That code is wrong or expired. Request a new one." } });
  if (!email || !code) return fail();

  const key = sha256hex(email);
  const pend = db.subscribers.pending[key];
  if (!pend) return fail();
  if (Date.now() > pend.expiresAt || pend.attempts >= VERIFY_MAX_ATTEMPTS) {
    delete db.subscribers.pending[key];
    scheduleSave();
    return fail();
  }
  pend.attempts += 1;
  scheduleSave();
  const ok = crypto.timingSafeEqual(
    Buffer.from(sha256hex(code), "hex"),
    Buffer.from(pend.codeHash, "hex"));
  if (!ok) return fail();

  // Verified: consume the pending record and mint the token.
  delete db.subscribers.pending[key];
  const issued = issueTokenForEmail(email);
  if (!issued) {
    scheduleSave();
    return sendJSON(res, 503, { error: { type: "registration_closed", message: "Registration is temporarily closed (capacity)." } });
  }
  logLine("verify ok", issued.id);
  sendJSON(res, 200, {
    subscriber_id: issued.id,
    token: issued.token,
    note: "Email verified. Store this token — it is shown once and kept only as a hash server-side. No subscription is active yet; complete checkout to enable the proxy.",
  });
}

function usageSummary(sub) {
  const tier = TIERS[sub.tier] || null;
  const u = monthUsage(sub.id);
  return {
    subscriber_id: sub.id,
    email: sub.email,
    tier: sub.tier,
    active: !!sub.active,
    month: monthKey(),
    usage: { input_tokens: u.in, output_tokens: u.out, cache_write_tokens: u.cacheWrite, cache_read_tokens: u.cacheRead, requests: u.requests, upstream_cost_usd: +u.usd.toFixed(6), reserved_in_flight_usd: +(u.reservedUSD || 0).toFixed(6) },
    quota: tier ? { budget_usd: tier.budgetUSD, used_fraction: +(u.usd / tier.budgetUSD).toFixed(4), models: tier.models } : null,
  };
}

async function handleMessages(req, res, sub) {
  if (!ANTHROPIC_API_KEY) {
    return sendJSON(res, 503, { error: { type: "proxy_unconfigured", message: "The proxy has no ANTHROPIC_API_KEY configured." } });
  }
  const tier = TIERS[sub.tier];
  if (!sub.active || !tier) {
    return sendJSON(res, 402, { error: { type: "subscription_inactive", message: "No active subscription. Subscribe (or renew) to use the shared-key tier — or switch to Sovereign mode with your own key." } });
  }

  // Cheap early quota rejection (settled + reserved spend). The
  // authoritative, race-free check happens below, AFTER the body is read, in
  // the same synchronous block that takes the reservation.
  if (spentPlusReserved(monthUsage(sub.id)) >= tier.budgetUSD) {
    return sendJSON(res, 402, quotaExceededBody(tier), quotaHeaders(sub, tier));
  }

  // concurrency cap
  const cur = inflight.get(sub.id) || 0;
  if (cur >= MAX_CONCURRENT_PER_SUB) {
    return sendJSON(res, 429, { error: { type: "too_many_concurrent", message: "Too many concurrent requests." } }, quotaHeaders(sub, tier));
  }

  let bodyBuf;
  try { bodyBuf = await readBody(req); }
  catch (e) { return sendJSON(res, e.status || 400, { error: { type: "invalid_request", message: e.message } }); }
  let body;
  try { body = JSON.parse(bodyBuf.toString("utf8")); }
  catch { return sendJSON(res, 400, { error: { type: "invalid_request", message: "invalid JSON body" } }); }

  // tier policy: model allowlist + max_tokens clamp
  const model = String(body.model || "");
  if (!tier.models.includes(model)) {
    return sendJSON(res, 400, {
      error: { type: "model_not_in_tier", message: `Model "${model}" is not included in the ${tier.label} tier. Allowed: ${tier.models.join(", ")}.` },
    }, quotaHeaders(sub, tier));
  }
  // Clamp output tokens to the tier cap (and default a missing/invalid
  // max_tokens to the cap) so the reservation below can price the worst case.
  body.max_tokens = Math.min(
    tier.maxTokensCap,
    typeof body.max_tokens === "number" && body.max_tokens > 0 ? Math.ceil(body.max_tokens) : tier.maxTokensCap,
  );

  /* ── Atomic quota check + reservation ─────────────────────────────────────
     Everything from here to `reserveUsage` is synchronous (no await), so no
     other request can interleave: concurrent requests can no longer race a
     checked-before/recorded-after gate. The reservation prices the WORST
     CASE — input estimated from the raw body size (input tokens were
     previously uncapped) and output at the clamped max_tokens — and a
     request that could push settled+reserved spend past the budget is
     refused up front. Actual usage replaces the estimate at settle time. */
  const u = monthUsage(sub.id);
  const estUSD = estimateRequestCostUSD(
    model, bodyBuf.length, body.max_tokens, bodyBuf.includes('"cache_control"'));
  if (spentPlusReserved(u) + estUSD > tier.budgetUSD) {
    return sendJSON(res, 402, quotaExceededBody(tier, estUSD, spentPlusReserved(u)), quotaHeaders(sub, tier));
  }
  reserveUsage(u, estUSD); // persisted synchronously — survives a crash
  inflight.set(sub.id, cur + 1);

  /* Settle exactly once per request: release the reservation (from the same
     month record it was taken on, even across a month rollover), record what
     the meter actually saw, and flush synchronously — incurred spend must
     never sit only in the save debounce when the stream is over. */
  let settled = false;
  const done = (usage) => {
    if (settled) return;
    settled = true;
    inflight.set(sub.id, Math.max(0, (inflight.get(sub.id) || 1) - 1));
    releaseReservation(u, estUSD);
    if (usage && (usage.in || usage.out || usage.cacheWrite || usage.cacheRead)) {
      const usd = recordUsage(sub.id, model, usage);
      // Metering log: counts only — NEVER prompt or response text.
      logLine("meter", sub.id, model, `in=${usage.in}`, `out=${usage.out}`, `cw=${usage.cacheWrite}`, `cr=${usage.cacheRead}`, `usd=${usd.toFixed(6)}`);
    }
    saveNow();
  };

  const controller = new AbortController();
  req.on("close", () => controller.abort());

  let upstream;
  try {
    upstream = await fetch(ANTHROPIC_URL, {
      method: "POST",
      signal: controller.signal,
      headers: {
        "content-type": "application/json",
        "x-api-key": ANTHROPIC_API_KEY, // the operator's key — never leaves this process
        "anthropic-version": String(req.headers["anthropic-version"] || "2023-06-01"),
      },
      body: JSON.stringify(body),
    });
  } catch (e) {
    done(null); // nothing reached the model — release the reservation
    if (e.name === "AbortError") { try { res.destroy(); } catch {} return; }
    return sendJSON(res, 502, { error: { type: "upstream_unreachable", message: "Could not reach api.anthropic.com." } });
  }

  if (!upstream.ok) {
    // Pass Anthropic's error through (status + JSON) without exposing the key.
    let errJson = null;
    try { errJson = await upstream.json(); } catch {}
    done(null);
    const headers = quotaHeaders(sub, tier);
    const retryAfter = upstream.headers.get("retry-after");
    if (retryAfter) headers["retry-after"] = retryAfter;
    return sendJSON(res, upstream.status, errJson || { error: { type: "upstream_error", message: "Upstream error." } }, headers);
  }

  const isSSE = (upstream.headers.get("content-type") || "").includes("text/event-stream");

  if (isSSE) {
    // Stream the SSE back BYTE-FOR-BYTE (the client's existing parser keeps
    // working) while a tee'd meter extracts usage from message_start/_delta.
    res.writeHead(200, {
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-store",
      "connection": "keep-alive",
      "x-accel-buffering": "no",
      ...corsHeaders(quotaHeaders(sub, tier)),
    });
    if (res.flushHeaders) res.flushHeaders();
    const meter = createSSEMeter();
    const decoder = new TextDecoder();
    try {
      for await (const chunk of upstream.body) {
        res.write(chunk);                                  // unchanged bytes to client
        meter.push(decoder.decode(chunk, { stream: true })); // counts only
      }
      meter.push(decoder.decode());
    } catch {
      // client or upstream dropped mid-stream — meter what was seen
    } finally {
      done(meter.usage());
      try { res.end(); } catch {}
    }
    return;
  }

  // Non-streaming request: buffer JSON, meter from response.usage, relay.
  let text = "";
  try { text = await upstream.text(); } catch {}
  let usage = { in: 0, out: 0, cacheWrite: 0, cacheRead: 0 };
  try {
    const j = JSON.parse(text);
    if (j && j.usage) {
      usage = {
        in: j.usage.input_tokens || 0,
        out: j.usage.output_tokens || 0,
        cacheWrite: j.usage.cache_creation_input_tokens || 0,
        cacheRead: j.usage.cache_read_input_tokens || 0,
      };
    }
  } catch {}
  done(usage);
  res.writeHead(upstream.status, { "content-type": "application/json", "cache-control": "no-store", ...corsHeaders(quotaHeaders(sub, tier)) });
  res.end(text);
}

/** Settled + in-flight-reserved spend — what quota admission is checked against. */
function spentPlusReserved(u) {
  return u.usd + (u.reservedUSD || 0);
}

function quotaExceededBody(tier, estUSD, spentUSD) {
  const detail = typeof estUSD === "number"
    ? ` This request's worst-case cost (~$${estUSD.toFixed(4)}, input estimated from request size + max_tokens) does not fit the remaining budget ($${Math.max(0, tier.budgetUSD - spentUSD).toFixed(4)} left, including in-flight requests).`
    : "";
  return {
    error: {
      type: "quota_exceeded",
      message: `Monthly ${tier.label} quota reached ($${tier.budgetUSD.toFixed(2)} of metered usage).${detail} Resets next month, or upgrade — or switch to Sovereign mode with your own key, which has no proxy quota.`,
    },
  };
}

function quotaHeaders(sub, tier) {
  const u = monthUsage(sub.id);
  const h = {
    "x-tolmach-tier": sub.tier || "none",
    "x-tolmach-quota-used-usd": u.usd.toFixed(6),
    "x-tolmach-quota-budget-usd": tier ? tier.budgetUSD.toFixed(2) : "0",
  };
  if (tier && u.usd >= tier.budgetUSD * tier.softWarnAt) {
    h["x-tolmach-quota-warning"] = Math.round((u.usd / tier.budgetUSD) * 100) + "% of monthly quota used";
  }
  return h;
}

async function handleCheckout(req, res, sub) {
  let body;
  try { body = JSON.parse((await readBody(req)).toString("utf8") || "{}"); }
  catch { return sendJSON(res, 400, { error: { type: "invalid_request", message: "invalid JSON" } }); }
  const tierName = body.tier === "pro" ? "pro" : "basic";
  const priceId = tierName === "pro" ? STRIPE_PRICE_PRO : STRIPE_PRICE_BASIC;
  if (!priceId) {
    return sendJSON(res, 501, { error: { type: "billing_unconfigured", message: `Stripe price id for the ${tierName} tier is not configured (STRIPE_PRICE_${tierName.toUpperCase()}).` } });
  }
  try {
    const session = await stripePOST("/v1/checkout/sessions", {
      "mode": "subscription",
      "client_reference_id": sub.id,
      "customer_email": sub.email,
      "line_items[0][price]": priceId,
      "line_items[0][quantity]": "1",
      "success_url": PUBLIC_BASE_URL + "/?checkout=success",
      "cancel_url": PUBLIC_BASE_URL + "/?checkout=cancelled",
    });
    sendJSON(res, 200, { url: session.url });
  } catch (e) {
    sendJSON(res, e.status || 502, { error: { type: "stripe_error", message: e.message } });
  }
}

async function handlePortal(req, res, sub) {
  if (!sub.stripeCustomerId) {
    return sendJSON(res, 400, { error: { type: "no_customer", message: "No Stripe customer yet — complete checkout first." } });
  }
  try {
    const session = await stripePOST("/v1/billing_portal/sessions", {
      "customer": sub.stripeCustomerId,
      "return_url": PUBLIC_BASE_URL + "/",
    });
    sendJSON(res, 200, { url: session.url });
  } catch (e) {
    sendJSON(res, e.status || 502, { error: { type: "stripe_error", message: e.message } });
  }
}

async function handleWebhook(req, res) {
  const raw = (await readBody(req)).toString("utf8");
  if (!verifyStripeSignature(raw, String(req.headers["stripe-signature"] || ""), STRIPE_WEBHOOK_SECRET)) {
    return sendJSON(res, 400, { error: { type: "bad_signature", message: "Stripe signature verification failed." } });
  }
  let event;
  try { event = JSON.parse(raw); } catch { return sendJSON(res, 400, { error: { type: "invalid_request", message: "invalid JSON" } }); }

  const obj = event?.data?.object || {};
  switch (event.type) {
    case "checkout.session.completed": {
      const sub = db.subscribers.subscribers[obj.client_reference_id];
      if (sub) {
        sub.stripeCustomerId = obj.customer || sub.stripeCustomerId;
        sub.stripeSubscriptionId = obj.subscription || sub.stripeSubscriptionId;
        sub.active = true;
        // Tier from the purchased price; fetch line items lazily is overkill —
        // subscription.updated (below) carries the price and confirms it.
        if (!sub.tier) sub.tier = "basic";
        scheduleSave();
        logLine("stripe checkout.completed", sub.id);
      }
      break;
    }
    case "customer.subscription.created":
    case "customer.subscription.updated": {
      const sub = subscriberByStripeCustomer(obj.customer);
      if (sub) {
        const priceId = obj?.items?.data?.[0]?.price?.id;
        const tier = tierForPriceId(priceId);
        if (tier) sub.tier = tier;
        sub.stripeSubscriptionId = obj.id;
        sub.active = obj.status === "active" || obj.status === "trialing";
        scheduleSave();
        logLine("stripe subscription." + obj.status, sub.id, "tier=" + sub.tier);
      }
      break;
    }
    case "customer.subscription.deleted": {
      const sub = subscriberByStripeCustomer(obj.customer);
      if (sub) {
        sub.active = false;
        scheduleSave();
        logLine("stripe subscription.deleted", sub.id);
      }
      break;
    }
    case "invoice.payment_failed": {
      const sub = subscriberByStripeCustomer(obj.customer);
      if (sub) { sub.active = false; scheduleSave(); logLine("stripe payment_failed", sub.id); }
      break;
    }
    default:
      break; // ignore everything else
  }
  sendJSON(res, 200, { received: true });
}

async function handleDevActivate(req, res, sub) {
  if (!DEV_MODE) return sendJSON(res, 404, { error: { type: "not_found", message: "not found" } });
  let body;
  try { body = JSON.parse((await readBody(req)).toString("utf8") || "{}"); } catch { body = {}; }
  const tierName = body.tier === "pro" ? "pro" : "basic";
  sub.tier = tierName;
  sub.active = true;
  scheduleSave();
  logLine("DEV activate", sub.id, tierName);
  sendJSON(res, 200, { ok: true, tier: tierName, note: "DEV_MODE activation — no payment occurred. Never enable DEV_MODE in production." });
}

/* --------------------------------- server --------------------------------- */

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://localhost");
  const route = req.method + " " + url.pathname;

  try {
    if (req.method === "OPTIONS") {
      res.writeHead(204, corsHeaders({ "access-control-max-age": "86400" }));
      return res.end();
    }
    if (route === "GET /healthz") {
      return sendJSON(res, 200, { ok: true, stripe: !!STRIPE_SECRET_KEY, upstream_key: !!ANTHROPIC_API_KEY, dev_mode: DEV_MODE });
    }
    if (route === "POST /auth/register") return await handleRegister(req, res);
    if (route === "POST /auth/verify") return await handleVerify(req, res);
    if (route === "POST /billing/webhook") return await handleWebhook(req, res);

    // everything below requires a subscriber token
    const sub = subscriberByToken(bearerToken(req));
    if (!sub) {
      return sendJSON(res, 401, { error: { type: "unauthorized", message: "Missing or invalid access token. Register / sign in first, or switch to Sovereign mode." } });
    }
    if (route === "GET /v1/me") return sendJSON(res, 200, usageSummary(sub));
    if (route === "POST /v1/messages") return await handleMessages(req, res, sub);
    if (route === "POST /billing/checkout") return await handleCheckout(req, res, sub);
    if (route === "POST /billing/portal") return await handlePortal(req, res, sub);
    if (route === "POST /billing/dev-activate") return await handleDevActivate(req, res, sub);

    sendJSON(res, 404, { error: { type: "not_found", message: "not found" } });
  } catch (e) {
    // Never include request content in error logs.
    logLine("error", route, e.message);
    if (!res.headersSent) sendJSON(res, 500, { error: { type: "internal", message: "internal error" } });
    else { try { res.end(); } catch {} }
  }
});

/* Only start listening when run directly (import-safe for tests). */
const runDirectly = process.argv[1] && import.meta.url === new URL("file://" + path.resolve(process.argv[1])).href;
if (runDirectly) {
  server.listen(PORT, () => {
    logLine(`tolmach-subscription proxy listening on :${PORT}`);
    if (ANTHROPIC_API_KEY && ALLOWED_ORIGIN === "*") {
      logLine("  WARNING: ALLOWED_ORIGIN is '*' while an upstream key is configured — any web origin can invoke this key-bearing proxy. Set ALLOWED_ORIGIN to the exact client origin before real deployment.");
    }
    logLine(`  upstream key: ${ANTHROPIC_API_KEY ? "configured" : "MISSING (proxy disabled)"}`);
    logLine(`  stripe:       ${STRIPE_SECRET_KEY ? "configured" : "not configured (checkout disabled)"}`);
    logLine(`  identity:     ${REQUIRE_EMAIL_VERIFICATION ? "email verification REQUIRED (real path: /auth/register sends a code, /auth/verify issues the token)" : "reference stub (/auth/register issues a token; set REQUIRE_EMAIL_VERIFICATION=1 for the real path)"}`);
    if (REQUIRE_EMAIL_VERIFICATION && !MAIL_COMMAND && NODE_ENV === "production") {
      logLine("  WARNING: REQUIRE_EMAIL_VERIFICATION=1 but MAIL_COMMAND is unset in production — registration will 501 until a mail transport is configured.");
    }
    logLine(`  dev mode:     ${DEV_MODE ? "ON — /billing/dev-activate enabled (LOCAL/DEV ONLY)" : "off"}`);
    if (RAW_DEV_MODE && !DEV_MODE) {
      logLine(`  DEV_MODE=1 IGNORED — production signals present [${DEV_MODE_PROD_SIGNALS.join("; ")}]; the no-payment billing bypass stays DISABLED (fail-closed).`);
    }
    logLine(`  data dir:     ${DATA_DIR} (token counts only — prompt text is never persisted)`);
  });
}

export { server };
