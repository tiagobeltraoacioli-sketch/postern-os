#!/usr/bin/env node
/* ============================================================================
   metering-check.mjs — logic check for the proxy's token accounting.
   Imports the REAL metering code from ../server/proxy.mjs (createSSEMeter,
   costUSD, priceFor, verifyStripeSignature) and checks it against
   hand-computed expectations. Run:  node tools/metering-check.mjs
   License: MIT.
   ============================================================================ */
import crypto from "node:crypto";
import {
  createSSEMeter, costUSD, priceFor, verifyStripeSignature,
  estimateRequestCostUSD, createRateLimiter, EST_BYTES_PER_TOKEN, TIERS,
} from "../server/proxy.mjs";

let failures = 0;
function check(name, got, want, eps = 0) {
  const ok = typeof want === "number" && eps > 0 ? Math.abs(got - want) <= eps : got === want;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}  got=${JSON.stringify(got)} want=${JSON.stringify(want)}`);
  if (!ok) failures++;
}

/* ---- 1. SSE usage extraction: a realistic Anthropic stream ---- */
const sse = [
  'event: message_start',
  'data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude-haiku-4-5-20251001","usage":{"input_tokens":2500,"output_tokens":1,"cache_creation_input_tokens":0,"cache_read_input_tokens":0}}}',
  '',
  'event: content_block_start',
  'data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}',
  '',
  'event: content_block_delta',
  'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hola"}}',
  '',
  'event: content_block_stop',
  'data: {"type":"content_block_stop","index":0}',
  '',
  'event: message_delta',
  'data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":1200}}',
  '',
  'event: message_stop',
  'data: {"type":"message_stop"}',
  '',
  '',
].join("\n");

// Feed in awkward chunk sizes to prove the incremental parser handles splits.
const meter = createSSEMeter();
for (let i = 0; i < sse.length; i += 7) meter.push(sse.slice(i, i + 7));
const u = meter.usage();
check("sse input_tokens", u.in, 2500);
check("sse output_tokens", u.out, 1200);
check("sse cache tokens", u.cacheWrite + u.cacheRead, 0);

/* ---- 2. Cost math vs hand computation ---- */
// Haiku 4.5 ($1 in / $5 out): 2500 in + 1200 out
//   = 2500/1e6*1 + 1200/1e6*5 = 0.0025 + 0.006 = $0.0085
check("haiku cost", costUSD("claude-haiku-4-5-20251001", u), 0.0085, 1e-12);

// Sonnet 5 INTRO ($2/$10, request dated before 2026-09-01): 2500 in + 1200 out
//   = 0.005 + 0.012 = $0.017
check("sonnet intro cost", costUSD("claude-sonnet-5", u, new Date("2026-07-09T12:00:00Z")), 0.017, 1e-12);

// Sonnet 5 LIST ($3/$15, request dated after intro window): = 0.0075 + 0.018 = $0.0255
check("sonnet list cost", costUSD("claude-sonnet-5", u, new Date("2026-09-01T00:00:00Z")), 0.0255, 1e-12);
check("sonnet intro boundary (Aug 31 still intro)",
  costUSD("claude-sonnet-5", u, new Date("2026-08-31T23:59:59Z")), 0.017, 1e-12);

// Opus 4.8 ($5/$25): = 0.0125 + 0.03 = $0.0425
check("opus cost", costUSD("claude-opus-4-8", u), 0.0425, 1e-12);

// Cache accounting: 1000 in + 500 out + 2000 cache-write + 8000 cache-read on Haiku
//   = 1000/1e6*1 + 500/1e6*5 + 2000/1e6*1*1.25 + 8000/1e6*1*0.1
//   = 0.001 + 0.0025 + 0.0025 + 0.0008 = $0.0068
check("cache-aware cost",
  costUSD("claude-haiku-4-5-20251001", { in: 1000, out: 500, cacheWrite: 2000, cacheRead: 8000 }),
  0.0068, 1e-12);

/* ---- 3. Meeting-hour model (the tier-sizing math from the README) ---- */
// One minutes update every 2 min => 30/hour; ~2500 in + ~1200 out each on
// Sonnet 5: intro 30*0.017 = $0.51/hr, list 30*0.0255 = $0.765/hr.
check("minutes $/hr sonnet intro", +(30 * costUSD("claude-sonnet-5", u, new Date("2026-07-09"))).toFixed(4), 0.51, 1e-9);
check("minutes $/hr sonnet list", +(30 * costUSD("claude-sonnet-5", u, new Date("2026-10-01"))).toFixed(4), 0.765, 1e-9);
// Heavy hour (minutes doc has grown, ~5000 in / 1600 out per update) at list:
//   per update = 5000/1e6*3 + 1600/1e6*15 = 0.015 + 0.024 = $0.039 → $1.17/hr
check("minutes $/hr sonnet heavy", +(30 * costUSD("claude-sonnet-5", { in: 5000, out: 1600 }, new Date("2026-10-01"))).toFixed(4), 1.17, 1e-9);

/* ---- 4. message_delta restating input_tokens wins ---- */
const meter2 = createSSEMeter();
meter2.push('data: {"type":"message_start","message":{"usage":{"input_tokens":100}}}\n\n');
meter2.push('data: {"type":"message_delta","usage":{"output_tokens":50,"input_tokens":140}}\n\n');
check("delta restated input wins", meter2.usage().in, 140);
check("delta output", meter2.usage().out, 50);

/* ---- 5. Stripe signature verification (v1 HMAC scheme) ---- */
const secret = "whsec_testsecret";
const payload = '{"id":"evt_1","type":"checkout.session.completed"}';
const t = Math.floor(Date.now() / 1000);
const good = crypto.createHmac("sha256", secret).update(`${t}.${payload}`).digest("hex");
check("stripe sig valid", verifyStripeSignature(payload, `t=${t},v1=${good}`, secret), true);
check("stripe sig tampered payload", verifyStripeSignature(payload + " ", `t=${t},v1=${good}`, secret), false);
check("stripe sig stale timestamp", verifyStripeSignature(payload, `t=${t - 3600},v1=${good}`, secret), false);

/* ---- 6. priceFor fallback is conservative (never undercharges) ---- */
const fb = priceFor("claude-unknown-model");
check("unknown model falls back to opus-rate input", fb.in, 5.0);
check("unknown model falls back to opus-rate output", fb.out, 25.0);

/* ---- 7. Pre-flight worst-case cost estimate (quota reservations) ---- */
// 300,000-byte body on Opus ($5/$25), max_tokens 8192 (Pro cap):
//   estIn = ceil(300000/3) = 100000 → 100000/1e6*5 = $0.50 in
//   out   = 8192/1e6*25 = $0.2048  → total $0.7048
check("estimate: opus 300kB body + 8192 out",
  estimateRequestCostUSD("claude-opus-4-8", 300000, 8192, false), 0.7048, 1e-12);
// The old attack shape: a full 1 MiB body. estIn = ceil(1048576/3) = 349526
//   → 349526/1e6*5 + 8192/1e6*25 = 1.74763 + 0.2048 = $1.95243 — far above
//   any plausible remaining-budget epsilon, so it is refused pre-flight.
check("estimate: 1MiB opus body prices ≈ $1.95",
  estimateRequestCostUSD("claude-opus-4-8", 1024 * 1024, 8192, false), 1.95243, 1e-5);
// cache_control present → input estimate priced at the 1.25x cache-write rate
check("estimate: cache_control bumps to write rate",
  estimateRequestCostUSD("claude-haiku-4-5", 3000, 1000, true),
  Math.ceil(3000 / EST_BYTES_PER_TOKEN) / 1e6 * 1.0 * 1.25 + 1000 / 1e6 * 5.0, 1e-12);
// The estimate must be conservative vs the metered cost of a typical request:
// a ~2500-input-token English request is ~10kB of JSON body → estimate ≥ actual.
check("estimate ≥ metered cost for a typical request",
  estimateRequestCostUSD("claude-sonnet-5", 10000, TIERS.basic.maxTokensCap, false) >=
    costUSD("claude-sonnet-5", u), true);

/* ---- 8. Registration rate limiter (fixed window) ---- */
const rl = createRateLimiter(3, 60_000);
const t0 = 1_000_000;
check("rate limit: 1st allowed", rl.allow("ip1", t0), true);
check("rate limit: 2nd allowed", rl.allow("ip1", t0 + 1), true);
check("rate limit: 3rd allowed", rl.allow("ip1", t0 + 2), true);
check("rate limit: 4th blocked", rl.allow("ip1", t0 + 3), false);
check("rate limit: other key unaffected", rl.allow("ip2", t0 + 3), true);
check("rate limit: window reset", rl.allow("ip1", t0 + 60_001), true);

console.log(failures === 0 ? "\nALL CHECKS PASSED" : `\n${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
