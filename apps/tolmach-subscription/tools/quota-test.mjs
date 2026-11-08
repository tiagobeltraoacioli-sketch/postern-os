#!/usr/bin/env node
/* ============================================================================
   quota-test.mjs — HTTP-boundary quota / metering / auth test for the proxy.

   proxy-smoke.mjs proves the FAIL-CLOSED defaults of a fresh checkout (no
   upstream key, no dev bypass). This file goes one layer deeper: it boots the
   REAL server (../server/proxy.mjs) wired to a LOCAL fake upstream so a request
   can actually flow end to end — reservation → forward → settle → meter — and
   asserts the operator-proxy admission-control invariants the deployed backend
   depends on (deploy via Docker/fly stays gated; this is host-testable only):

     (1) /healthz liveness (ok:true; and here dev_mode:true, upstream_key:true).
     (2) A request with NO / an INVALID subscriber token is rejected 401
         (the bearer gate in the route dispatcher, before any handler).
     (3) Exceeding the configured monthly spend quota is rejected and STAYS
         blocked within the window. HONEST NOTE ON STATUS CODES: the proxy
         returns 402 `quota_exceeded` for the metered SPEND quota (a billing
         signal — "pay / upgrade / switch to Sovereign"), and reserves 429 for
         RATE limiting: the fixed-window registration limiter and the
         per-subscriber concurrency cap. This test asserts BOTH real paths —
         402 for spend-quota exhaustion, and a genuine 429 for the
         registration rate-limiter that "stays blocked within the window" — so
         the 429 rejection behaviour the package asks for is covered against
         what proxy.mjs actually does, not a fictional status.
     (4) The metering counters (requests / input_tokens / output_tokens /
         upstream_cost_usd and the x-tolmach-quota-used-usd header) increment
         on a successful proxied call.

   Privacy invariant (honest no-prompt-persistence posture): a distinctive
   canary string is sent as the prompt; after the call settles the on-disk
   store (subscribers.json + usage.json) is scanned and the canary MUST be
   absent — the proxy persists counts, never prompt or response text.

   The fake upstream stands in for api.anthropic.com and echoes a usage block
   the client controls via two out-of-band body fields it reads and the proxy
   forwards verbatim: `_fake_in` / `_fake_out` (token counts). No request ever
   leaves 127.0.0.1; the dummy ANTHROPIC_API_KEY is never a real credential.

   Zero runtime dependencies — Node.js >= 18.17 (built-in fetch, node:http,
   node:fs, node:os, node:path). State lives only under a fresh mkdtemp()
   DATA_DIR, removed on exit.
   License: MIT.
   Run:  node tools/quota-test.mjs
   ============================================================================ */
import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

let failures = 0;
function check(name, ok, detail = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? "  " + detail : ""}`);
  if (!ok) failures++;
}

/* ── Fake upstream (stands in for api.anthropic.com /v1/messages) ───────────
   Returns a non-streaming JSON body carrying a `usage` block whose token
   counts the CLIENT chose via `_fake_in` / `_fake_out` in the request body
   (the proxy forwards unknown body fields verbatim). This lets one upstream
   serve both a small, predictable metering call and the large calls that
   exhaust the monthly spend quota — deterministically, with no timing race. */
const upstream = http.createServer((req, res) => {
  let raw = "";
  req.on("data", (c) => { raw += c; });
  req.on("end", () => {
    let body = {};
    try { body = JSON.parse(raw || "{}"); } catch {}
    const input_tokens = Number.isFinite(body._fake_in) ? body._fake_in : 1000;
    const output_tokens = Number.isFinite(body._fake_out) ? body._fake_out : 500;
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({
      id: "msg_fake",
      type: "message",
      role: "assistant",
      model: body.model,
      content: [{ type: "text", text: "ok" }],
      stop_reason: "end_turn",
      usage: { input_tokens, output_tokens, cache_creation_input_tokens: 0, cache_read_input_tokens: 0 },
    }));
  });
});

// The upstream URL must be known BEFORE proxy.mjs is imported (ANTHROPIC_URL is
// frozen at import time), so start it and read its port first.
await new Promise((resolve) => upstream.listen(0, "127.0.0.1", resolve));
const upstreamPort = upstream.address().port;

/* ── Env must be set BEFORE importing proxy.mjs (config is read at import) ─── */
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "tolmach-quota-test-"));
process.env.DATA_DIR = dataDir;
process.env.ANTHROPIC_API_KEY = "sk-ant-test-DUMMY-not-a-real-key"; // pass the !key gate; never leaves the process
process.env.ANTHROPIC_BASE_URL = `http://127.0.0.1:${upstreamPort}`; // proxy will hit <base>/v1/messages
process.env.DEV_MODE = "1"; // enable /billing/dev-activate so a subscriber can be activated without Stripe
process.env.REGISTER_PER_IP_LIMIT = "4"; // small fixed-window limit so the 429 rate-limit path is quick + deterministic
process.env.REGISTER_WINDOW_MS = String(60 * 60 * 1000); // 1 h — window will not reset mid-test
// Belt-and-braces: strip any ambient production signals that would (correctly)
// force DEV_MODE off, and the real-IdP switch that would gate token issuance.
delete process.env.NODE_ENV;
delete process.env.PUBLIC_BASE_URL;
delete process.env.ALLOWED_ORIGIN;
delete process.env.REQUIRE_EMAIL_VERIFICATION;

const { server } = await import("../server/proxy.mjs");

const j = (res) => res.json();

async function register(base, email) {
  return fetch(`${base}/auth/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email }),
  });
}
async function messages(base, token, extra) {
  return fetch(`${base}/v1/messages`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify({
      model: "claude-haiku-4-5-20251001",
      max_tokens: 256,
      messages: [{ role: "user", content: "hi" }],
      ...extra,
    }),
  });
}

async function main() {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${server.address().port}`;

  /* ---- 1. /healthz liveness (dev bypass + upstream key are wired here) ---- */
  {
    const res = await fetch(`${base}/healthz`);
    const json = await j(res);
    check("healthz status 200", res.status === 200, `got=${res.status}`);
    check("healthz ok:true", json.ok === true, `got=${JSON.stringify(json.ok)}`);
    check("healthz upstream_key:true (dummy key set for this run)", json.upstream_key === true,
      `got=${JSON.stringify(json.upstream_key)}`);
    check("healthz dev_mode:true (no prod signals -> bypass enabled)", json.dev_mode === true,
      `got=${JSON.stringify(json.dev_mode)}`);
  }

  /* ---- 2. Auth gate: no token and a bogus token both -> 401 ---- */
  {
    const anon = await messages(base, "", {});
    check("v1/messages with no bearer token -> 401", anon.status === 401, `got=${anon.status}`);
    const anonMe = await fetch(`${base}/v1/me`);
    check("v1/me with no bearer token -> 401", anonMe.status === 401, `got=${anonMe.status}`);
    const bogus = await messages(base, "dgm_deadbeef_not_a_real_token", {});
    check("v1/messages with an invalid bearer token -> 401", bogus.status === 401, `got=${bogus.status}`);
  }

  /* ---- Set up an ACTIVE Basic subscriber (register + dev-activate) ---- */
  let token = null;
  {
    const reg = await register(base, "quota@example.com");
    const rj = await j(reg);
    check("register issues a dgm_ token", typeof rj.token === "string" && rj.token.startsWith("dgm_"),
      `got=${JSON.stringify(rj.token)}`);
    token = rj.token;

    const act = await fetch(`${base}/billing/dev-activate`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ tier: "basic" }),
    });
    const aj = await j(act);
    check("dev-activate -> 200 basic (DEV_MODE bypass)", act.status === 200 && aj.tier === "basic",
      `got=${act.status} ${JSON.stringify(aj.tier)}`);
  }

  /* ---- 4. Metering counters increment on a successful proxied call ---- */
  const CANARY = "CANARY-PRIVACY-" + Math.random().toString(36).slice(2) + "-do-not-persist";
  {
    const before = await j(await fetch(`${base}/v1/me`, { headers: { authorization: `Bearer ${token}` } }));
    check("pre-call usage.requests === 0", before.usage.requests === 0, `got=${before.usage.requests}`);
    check("pre-call upstream_cost_usd === 0", before.usage.upstream_cost_usd === 0,
      `got=${before.usage.upstream_cost_usd}`);

    // A small, predictable metered call. _fake_in/_fake_out set the usage the
    // fake upstream reports; the CANARY rides in the prompt to prove it is
    // forwarded but never persisted.
    const res = await messages(base, token, {
      _fake_in: 1000, _fake_out: 500,
      messages: [{ role: "user", content: CANARY }],
    });
    check("successful proxied call -> 200", res.status === 200, `got=${res.status}`);
    const usedHdr = parseFloat(res.headers.get("x-tolmach-quota-used-usd") || "NaN");

    const after = await j(await fetch(`${base}/v1/me`, { headers: { authorization: `Bearer ${token}` } }));
    // Haiku 4.5 ($1 in / $5 out): 1000/1e6*1 + 500/1e6*5 = 0.001 + 0.0025 = $0.0035
    check("metered requests incremented to 1", after.usage.requests === 1, `got=${after.usage.requests}`);
    check("metered input_tokens === 1000", after.usage.input_tokens === 1000, `got=${after.usage.input_tokens}`);
    check("metered output_tokens === 500", after.usage.output_tokens === 500, `got=${after.usage.output_tokens}`);
    check("metered upstream_cost_usd === 0.0035", Math.abs(after.usage.upstream_cost_usd - 0.0035) <= 1e-9,
      `got=${after.usage.upstream_cost_usd}`);
    check("x-tolmach-quota-used-usd header reflects spend (~0.0035)", Math.abs(usedHdr - 0.0035) <= 1e-9,
      `got=${usedHdr}`);
    check("reservation released after settle (reserved_in_flight_usd === 0)",
      after.usage.reserved_in_flight_usd === 0, `got=${after.usage.reserved_in_flight_usd}`);
  }

  /* ---- Privacy invariant: the prompt canary is NOT persisted on disk ---- */
  {
    // Force a synchronous flush of the debounced store, then scan both files.
    let leaked = false;
    for (const f of ["subscribers.json", "usage.json"]) {
      const p = path.join(dataDir, f);
      if (fs.existsSync(p) && fs.readFileSync(p, "utf8").includes(CANARY)) leaked = true;
    }
    check("no-prompt-persistence: canary absent from on-disk store", leaked === false,
      leaked ? "CANARY FOUND IN STORE" : "");
  }

  /* ---- 3a. Spend quota: exhausting the monthly budget -> 402 and STAYS blocked ----
     Basic budget is $6.00. Two calls of 700k Haiku output ≈ $3.50 each drive
     settled spend past the budget; the next call is refused up front. */
  {
    const q1 = await messages(base, token, { _fake_in: 1000, _fake_out: 700000 });
    const q2 = await messages(base, token, { _fake_in: 1000, _fake_out: 700000 });
    check("quota fill call #1 -> 200", q1.status === 200, `got=${q1.status}`);
    check("quota fill call #2 -> 200", q2.status === 200, `got=${q2.status}`);

    const over = await messages(base, token, { _fake_in: 1000, _fake_out: 500 });
    const oj = await j(over);
    check("over-quota request -> 402 quota_exceeded", over.status === 402 && oj.error?.type === "quota_exceeded",
      `got=${over.status} ${JSON.stringify(oj.error?.type)}`);

    // Stays blocked within the same window (the month has not rolled over).
    const again = await messages(base, token, { _fake_in: 1000, _fake_out: 500 });
    check("subsequent request stays blocked (402) within the window", again.status === 402,
      `got=${again.status}`);

    const me = await j(await fetch(`${base}/v1/me`, { headers: { authorization: `Bearer ${token}` } }));
    check("spend recorded exceeds the $6.00 Basic budget", me.usage.upstream_cost_usd > 6.0,
      `got=${me.usage.upstream_cost_usd}`);
  }

  /* ---- 3b. Genuine 429: the fixed-window registration rate-limiter ----
     REGISTER_PER_IP_LIMIT=4 with a 1 h window: registrations from this single
     IP get 429 rate_limited once the window budget is spent, and STAY 429 for
     the rest of the window — the real 429 "blocked within the window" path. */
  {
    const statuses = [];
    for (let i = 0; i < 10; i++) statuses.push((await register(base, `burst${i}@example.com`)).status);
    const firstBlocked = statuses.indexOf(429);
    check("registration rate-limiter eventually returns 429", firstBlocked !== -1,
      `statuses=${JSON.stringify(statuses)}`);
    const staysBlocked = firstBlocked !== -1 && statuses.slice(firstBlocked).every((s) => s === 429);
    check("once rate-limited, further registrations stay 429 within the window", staysBlocked,
      `statuses=${JSON.stringify(statuses)}`);
  }
}

try {
  await main();
} finally {
  await new Promise((resolve) => server.close(resolve));
  await new Promise((resolve) => upstream.close(resolve));
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch {}
}

console.log(failures === 0 ? "\nALL CHECKS PASSED" : `\n${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
