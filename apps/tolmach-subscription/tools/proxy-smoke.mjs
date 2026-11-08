#!/usr/bin/env node
/* ============================================================================
   proxy-smoke.mjs — HTTP-boundary smoke test for the subscription proxy.
   metering-check.mjs only exercises the pure math (createSSEMeter, costUSD,
   etc.); this file boots the REAL server (../server/proxy.mjs) on an
   ephemeral port and drives it over real fetch() calls, asserting the
   fail-closed defaults a fresh checkout actually has:
     - no ANTHROPIC_API_KEY  -> healthz reports upstream_key:false and
       /v1/messages never has a path to api.anthropic.com in this run
     - REQUIRE_EMAIL_VERIFICATION unset -> /auth/register issues a token
       directly (the labeled reference-stub identity path)
     - a freshly registered subscriber is inactive / on no tier (free state)
     - no bearer token -> 401
     - DEV_MODE unset -> /billing/dev-activate 404s (the bypass does not
       exist at all, per proxy.mjs's fail-closed design)
   Zero runtime dependencies — Node.js >= 18.17 (built-in fetch, node:http
   via the imported server, node:fs, node:os, node:path). Writes state only
   under a fresh mkdtemp() DATA_DIR, removed on exit. Makes no network call
   to any host other than 127.0.0.1.
   License: MIT.
   Run:  node tools/proxy-smoke.mjs
   ============================================================================ */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

let failures = 0;
function check(name, ok, detail = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? "  " + detail : ""}`);
  if (!ok) failures++;
}

// DATA_DIR must exist BEFORE proxy.mjs is imported: the module reads/creates
// its JSON store at import time (loadJSON) from process.env.DATA_DIR.
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "tolmach-proxy-smoke-"));
process.env.DATA_DIR = dataDir;
// Belt-and-braces: guarantee the fail-closed preconditions this test asserts,
// regardless of what the ambient shell environment happens to have set.
delete process.env.ANTHROPIC_API_KEY;
delete process.env.REQUIRE_EMAIL_VERIFICATION;
delete process.env.DEV_MODE;
delete process.env.NODE_ENV;

// listen() is guarded by a `runDirectly` main-module check in proxy.mjs, so
// importing it here starts no server and makes no network call.
const { server } = await import("../server/proxy.mjs");

async function main() {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  const base = `http://127.0.0.1:${port}`;

  /* ---- 1. GET /healthz: no upstream key, ok:true ---- */
  {
    const res = await fetch(`${base}/healthz`);
    const json = await res.json();
    check("healthz status 200", res.status === 200, `got=${res.status}`);
    check("healthz ok:true", json.ok === true, `got=${JSON.stringify(json.ok)}`);
    check("healthz upstream_key:false (no ANTHROPIC_API_KEY set)", json.upstream_key === false,
      `got=${JSON.stringify(json.upstream_key)}`);
  }

  /* ---- 2. POST /auth/register: reference stub issues a dgm_ token ---- */
  let token = null;
  {
    const res = await fetch(`${base}/auth/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "smoke@example.com" }),
    });
    const json = await res.json();
    check("register status 200", res.status === 200, `got=${res.status}`);
    check("register returns a dgm_-prefixed token",
      typeof json.token === "string" && json.token.startsWith("dgm_"),
      `got=${JSON.stringify(json.token)}`);
    token = json.token;
  }

  /* ---- 3. GET /v1/me: freshly registered subscriber is inactive/free ---- */
  {
    const res = await fetch(`${base}/v1/me`, {
      headers: { authorization: `Bearer ${token}` },
    });
    const json = await res.json();
    check("v1/me status 200", res.status === 200, `got=${res.status}`);
    check("v1/me active:false (no subscription yet)", json.active === false,
      `got=${JSON.stringify(json.active)}`);
    check("v1/me tier:null (no tier assigned)", json.tier === null,
      `got=${JSON.stringify(json.tier)}`);
  }

  /* ---- 4. POST /v1/messages with no Authorization -> 401 ---- */
  {
    const res = await fetch(`${base}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "claude-haiku-4-5-20251001", max_tokens: 16, messages: [] }),
    });
    check("v1/messages with no Authorization -> 401", res.status === 401, `got=${res.status}`);
  }

  /* ---- 5. POST /billing/dev-activate with a valid token -> 404 (DEV_MODE off) ---- */
  {
    const res = await fetch(`${base}/billing/dev-activate`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ tier: "pro" }),
    });
    check("billing/dev-activate -> 404 (DEV_MODE off by default, fail-closed)",
      res.status === 404, `got=${res.status}`);
  }
}

try {
  await main();
} finally {
  await new Promise((resolve) => server.close(resolve));
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch {}
}

console.log(failures === 0 ? "\nALL CHECKS PASSED" : `\n${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
