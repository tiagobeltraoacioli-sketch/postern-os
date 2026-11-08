// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// GRAMOTA-KYC CSP hash-parity regression test — run with: node test-csp.mjs (Node >= 18)
//
// Modeled on apps/gramota/test-csp.mjs, adapted for gramota-kyc's shape:
// gramota-kyc/index.html hash-pins THREE inline <script> blocks in script-src
// (grm-core, grm-ocr, and the bootstrap block) rather than a single one, and
// deliberately keeps style-src 'unsafe-inline' (inline <style> + style="" attrs
// are not hash-pinned here). Before this test only xss-escape.test.mjs existed,
// so editing any inline <script> block would silently drift its sha256 pin and
// white-screen the app under CSP instead of failing loudly here.
//
// The load-bearing guarantees under test:
//   - script-src carries NO 'unsafe-inline' / 'unsafe-eval' — the only tokens
//     allowed are 'none' or sha256-* hashes (the browser-enforced surface);
//   - each declared script-src sha256 hash is byte-exact for one of the file's
//     actual inline <script> blocks (this is what a browser recomputes + checks);
//   - there are exactly as many inline <script> blocks as pinned hashes, so the
//     hashes cover 100% of the inline script surface — a second, unhashed
//     <script> would silently escape the CSP net;
//   - default-src is 'none' and connect-src is exactly 'self'.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const html = readFileSync(join(here, "index.html"), "utf8");

let passed = 0;
const t = (name, fn) => Promise.resolve().then(fn).then(() => { passed++; console.log("  ok — " + name); });

function cspDirectives() {
  const m = html.match(/Content-Security-Policy" content="([^"]+)"/);
  assert.ok(m, "a CSP meta tag must be present");
  const out = {};
  for (const part of m[1].split(";")) {
    const s = part.trim();
    if (!s) continue;
    const [name, ...rest] = s.split(/\s+/);
    out[name] = rest;
  }
  return out;
}

// Extract every REAL inline <script> block, in document order.
//
// A sequential scan (not a global regex over the whole file) is required here:
// gramota-kyc has a literal `<script id="grm-ocr">` reference inside a JS
// comment (in the bootstrap block). A naive /<script[^>]*>/g would count that
// comment text as a 4th opening tag and mis-slice the blocks. By always
// resuming the search AFTER each block's </script>, the comment reference is
// consumed as block content and never mistaken for a real opening tag.
function extractScriptBlocks() {
  const openRe = /<script(\s[^>]*)?>/g;
  const blocks = [];
  let pos = 0;
  for (;;) {
    openRe.lastIndex = pos;
    const open = openRe.exec(html);
    if (!open) break;
    const start = open.index + open[0].length;
    const close = html.indexOf("</script>", start);
    assert.notEqual(close, -1, "found an unterminated <script> block");
    blocks.push(html.slice(start, close));
    pos = close + "</script>".length;
  }
  return blocks;
}

function sriHash(content) {
  return "'sha256-" + createHash("sha256").update(content, "utf8").digest("base64") + "'";
}

// -------- script-src is hash-pinned, not 'unsafe-inline' --------------------
await t("script-src contains no unsafe-inline / unsafe-eval", () => {
  const csp = cspDirectives();
  assert.ok("script-src" in csp, "script-src must be present");
  for (const tok of csp["script-src"]) {
    assert.notEqual(tok, "'unsafe-inline'", "script-src must not allow unsafe-inline");
    assert.notEqual(tok, "'unsafe-eval'", "script-src must not allow unsafe-eval");
  }
});
await t("default-src is 'none' (deny-by-default baseline)", () => {
  const csp = cspDirectives();
  assert.deepEqual(csp["default-src"], ["'none'"]);
});
await t("connect-src is exactly 'self' — no third-party network reach", () => {
  const csp = cspDirectives();
  assert.deepEqual(csp["connect-src"], ["'self'"]);
});
await t("base-uri and form-action stay locked to 'none'", () => {
  const csp = cspDirectives();
  assert.deepEqual(csp["base-uri"], ["'none'"]);
  assert.deepEqual(csp["form-action"], ["'none'"]);
});

// -------- the three-way sha256 hash parity ----------------------------------
await t("script-src declares exactly THREE sha256 hashes", () => {
  const csp = cspDirectives();
  const hashes = csp["script-src"].filter((tok) => tok.startsWith("'sha256-"));
  assert.equal(hashes.length, 3, "expected exactly 3 pinned sha256 script hashes, found " + hashes.length);
  // and script-src carries nothing but sha256 hashes (no host/scheme sources).
  assert.equal(hashes.length, csp["script-src"].length,
    "script-src must contain ONLY sha256 hashes — found extra tokens: " + csp["script-src"].join(" "));
});
await t("there are exactly as many inline <script> blocks as pinned hashes", () => {
  const csp = cspDirectives();
  const hashes = csp["script-src"].filter((tok) => tok.startsWith("'sha256-"));
  const blocks = extractScriptBlocks();
  assert.equal(blocks.length, hashes.length,
    "inline <script> block count (" + blocks.length + ") must equal pinned hash count (" + hashes.length + ") — " +
    "an unhashed block would silently escape the CSP net");
});
await t("every inline <script> block's sha256 is declared in script-src (byte-exact)", () => {
  const csp = cspDirectives();
  const declared = new Set(csp["script-src"].filter((tok) => tok.startsWith("'sha256-")));
  const blocks = extractScriptBlocks();
  for (let i = 0; i < blocks.length; i++) {
    const actual = sriHash(blocks[i]);
    assert.ok(declared.has(actual),
      "inline <script> block #" + (i + 1) + " hashes to " + actual +
      " which is NOT pinned in script-src — recompute the CSP hash (see the CSP NOTE in index.html). " +
      "Declared: " + [...declared].join(" "));
  }
});
await t("every pinned script-src hash is backed by a real inline <script> block", () => {
  const csp = cspDirectives();
  const declared = csp["script-src"].filter((tok) => tok.startsWith("'sha256-"));
  const actual = new Set(extractScriptBlocks().map(sriHash));
  for (const h of declared) {
    assert.ok(actual.has(h),
      "pinned script hash " + h + " matches no inline <script> block — it is stale/dead. " +
      "Actual block hashes: " + [...actual].join(" "));
  }
});

console.log(`\ngramota-kyc csp hash-parity: ${passed} checks passed`);
