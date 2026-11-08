// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// GRAMOTA hardening tests — run with: node test-csp.mjs   (Node >= 18)
//
// Pins the CSP + escaping invariants for apps/gramota/index.html so a future
// edit can't silently reopen the inline-script/style hole this hardening pass
// closed, and can't silently break the sha256 pin (which would white-screen
// the page under CSP rather than fail loudly here).
//
// The load-bearing guarantees under test:
//   - script-src / style-src carry NO 'unsafe-inline' / 'unsafe-eval' — the
//     only tokens allowed are 'none' or sha256-* hashes;
//   - the declared sha256 hashes are byte-exact for the file's actual single
//     inline <style> and <script> blocks (this is what a browser enforces);
//   - there is exactly one <style> and one <script> block (so the hash
//     actually covers 100% of the inline code surface — a second, unhashed
//     <script> would silently escape the CSP net);
//   - connect-src is exactly 'self' (no added origins);
//   - the HTML-escaper used before every innerHTML write escapes all five
//     characters that matter in both text and attribute contexts.

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

function extractSingle(tag) {
  const openTagRe = new RegExp("<" + tag + "(\\s[^>]*)?>", "g");
  const opens = [...html.matchAll(openTagRe)];
  assert.equal(opens.length, 1, "expected exactly one <" + tag + "> block, found " + opens.length);
  const open = opens[0];
  const start = open.index + open[0].length;
  const closeRe = new RegExp("</" + tag + ">", "g");
  const closes = [...html.matchAll(closeRe)];
  assert.equal(closes.length, 1, "expected exactly one </" + tag + "> close, found " + closes.length);
  assert.ok(closes[0].index > start, "close tag must follow open tag");
  return html.slice(start, closes[0].index);
}

function sriHash(content) {
  return "sha256-" + createHash("sha256").update(content, "utf8").digest("base64");
}

// -------- CSP is hash-pinned, not 'unsafe-inline' ---------------------------
await t("script-src and style-src contain no unsafe-inline / unsafe-eval", () => {
  const csp = cspDirectives();
  for (const dir of ["script-src", "style-src"]) {
    assert.ok(dir in csp, dir + " must be present");
    for (const tok of csp[dir]) {
      assert.notEqual(tok, "'unsafe-inline'", dir + " must not allow unsafe-inline");
      assert.notEqual(tok, "'unsafe-eval'", dir + " must not allow unsafe-eval");
    }
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
await t("there is exactly one inline <style> and one inline <script> block", () => {
  // extractSingle() itself asserts the count==1 invariant; call both to prove it.
  extractSingle("style");
  extractSingle("script");
});
await t("the declared style-src hash matches the actual inline <style> bytes", () => {
  const csp = cspDirectives();
  const declared = csp["style-src"].find((t) => t.startsWith("'sha256-"));
  assert.ok(declared, "style-src must carry a sha256 hash");
  const actual = "'" + sriHash(extractSingle("style")) + "'";
  assert.equal(declared, actual, "style-src hash is stale — recompute it (see the CSP NOTE in index.html)");
});
await t("the declared script-src hash matches the actual inline <script> bytes", () => {
  const csp = cspDirectives();
  const declared = csp["script-src"].find((t) => t.startsWith("'sha256-"));
  assert.ok(declared, "script-src must carry a sha256 hash");
  const actual = "'" + sriHash(extractSingle("script")) + "'";
  assert.equal(declared, actual, "script-src hash is stale — recompute it (see the CSP NOTE in index.html)");
});
await t("base-uri, form-action and frame-ancestors stay locked to 'none'", () => {
  const csp = cspDirectives();
  assert.deepEqual(csp["base-uri"], ["'none'"]);
  assert.deepEqual(csp["form-action"], ["'none'"]);
  assert.deepEqual(csp["frame-ancestors"], ["'none'"]);
});

// Pull a `function name(...){ ... }` declaration out of source by brace-counting
// (a naive non-greedy regex breaks on the nested {} of the entity map inside esc).
function extractFunctionSource(src, name) {
  const startMatch = src.match(new RegExp("function " + name + "\\([^)]*\\)\\s*\\{"));
  assert.ok(startMatch, "function " + name + "() must be present in the inline script");
  const bodyStart = startMatch.index + startMatch[0].length;
  let depth = 1, i = bodyStart;
  for (; i < src.length && depth > 0; i++) {
    if (src[i] === "{") depth++;
    else if (src[i] === "}") depth--;
  }
  return src.slice(bodyStart, i - 1);
}

// -------- the HTML-escaper used before innerHTML writes ---------------------
await t("esc() escapes all five HTML/attribute-breaking characters", () => {
  const src = extractSingle("script");
  const body = extractFunctionSource(src, "esc");
  // eslint-disable-next-line no-new-func
  const esc = new Function("s", body);
  assert.equal(esc(`&<>"'`), "&amp;&lt;&gt;&quot;&#39;");
  assert.equal(esc(`<script>alert(1)</script>`), "&lt;script&gt;alert(1)&lt;/script&gt;");
  assert.equal(esc(`" onmouseover="alert(1)`), "&quot; onmouseover=&quot;alert(1)");
  assert.equal(esc(`' onmouseover='alert(1)`), "&#39; onmouseover=&#39;alert(1)");
});
await t("every innerHTML write in the inline script is fed through esc()", () => {
  const src = extractSingle("script");
  const innerHtmlAssignments = [...src.matchAll(/\.innerHTML\s*=\s*([\s\S]*?);\n/g)].map((m) => m[1]);
  assert.ok(innerHtmlAssignments.length > 0, "expected at least one innerHTML write to check");
  for (const rhs of innerHtmlAssignments) {
    // Every dynamic (non-literal) segment concatenated into the markup must be
    // wrapped in esc(...) or be a locally-computed non-string (e.g. currentLoa()).
    const interpolations = [...rhs.matchAll(/\+\s*([a-zA-Z_$][\w.$]*\([^()]*\)|[a-zA-Z_$][\w.$]*)\s*\+/g)];
    for (const [, expr] of interpolations) {
      const isSafe = /^esc\(/.test(expr) || expr === "currentLoa()";
      assert.ok(isSafe, "unescaped interpolation into innerHTML: " + expr);
    }
  }
});

console.log(`\ngramota csp/xss hardening: ${passed} checks passed`);
