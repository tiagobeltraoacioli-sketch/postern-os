// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Stored-XSS regression tests for the gramota-kyc UI — run with:
//   node --test apps/gramota-kyc/
//
// THE BUG THIS PINS: index.html interpolated server/D&B-derived strings
// (legalName, country, error, decision, loa, assurance, methods, ref, engine
// name) into innerHTML unescaped. A hostile upstream value such as
// '<img src=x onerror=...>' stored in the D&B record (or returned by a
// compromised /license/review) would execute in the victim's page — stored XSS.
//
// THE FIX THIS VERIFIES (both layers):
//   1. GRM.escapeHtml entity-escapes & < > " ' and every tainted value is
//      wrapped at the render sink (pill() escapes its text too).
//   2. The CSP <meta> pins the three inline scripts by sha256 hash instead of
//      script-src 'unsafe-inline', so an injected <script> would not execute
//      even if escaping were bypassed.
//
// Method: the REAL inline scripts are extracted from index.html and evaluated
// against a minimal DOM stub; the real click handlers are driven with hostile
// payloads shaped like the D&B fixture (fixtures/dnb/company-l1-hostile-xss.json,
// SYNTHETIC, mapped to the /license/review response shape exactly as
// functions/license/review.js maps organization.primaryName ->
// dnb.legalName and primaryAddress.addressCountry.isoAlpha2Code ->
// dnb.country). We then assert the strings assigned to innerHTML contain the
// entity-escaped payload and never a live tag. No real network calls anywhere.
//
// Honest scope: this exercises the string that WOULD be assigned to
// innerHTML — there is no real browser DOM/parser here, so it proves correct
// escaping, not full end-to-end browser behavior. UNAUDITED reference
// prototype; escaping + hashed CSP is defense-in-depth, not a security proof.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

const html = readFileSync(new URL("./index.html", import.meta.url), "utf8");
const hostileFixture = JSON.parse(
  readFileSync(new URL("./fixtures/dnb/company-l1-hostile-xss.json", import.meta.url), "utf8"),
);

// ---- extract the real inline scripts --------------------------------------
// HTML comments are stripped first so prose mentioning script tags can never
// be confused with a real block. NOTE: the CSP hashes cover the raw bytes of
// the REAL blocks; comment-stripping does not alter script bodies.
function scriptBlocks(src) {
  const out = [];
  const noComments = src.replace(/<!--[\s\S]*?-->/g, "");
  const re = /<script(?:\s+id="([^"]*)")?>([\s\S]*?)<\/script>/g;
  let m;
  while ((m = re.exec(noComments))) out.push({ id: m[1] || null, body: m[2] });
  return out;
}
const blocks = scriptBlocks(html);
const core = blocks.find((b) => b.id === "grm-core");
const ocr = blocks.find((b) => b.id === "grm-ocr");
const ui = blocks.find((b) => !b.id && b.body.includes("resolveBtn"));
assert.ok(core && ocr && ui, "all three inline scripts found");

// ---- minimal DOM stub (records innerHTML/textContent assignments) ----------
const els = new Map();
function el(id) {
  if (!els.has(id)) {
    els.set(id, {
      id, innerHTML: "", textContent: "", value: "", checked: false, disabled: false,
      files: [], style: {}, _handlers: {},
      classList: { add() {}, remove() {} },
      addEventListener(type, fn) { this._handlers[type] = fn; },
      fire(type) { return this._handlers[type] && this._handlers[type].call(this); },
    });
  }
  return els.get(id);
}
globalThis.window = globalThis;
globalThis.document = { getElementById: el };

// Evaluate the REAL scripts in order (core, ocr seam, UI wiring).
(0, eval)(core.body);
(0, eval)(ocr.body);
(0, eval)(ui.body);
const G = globalThis.GRM;
assert.ok(typeof G.escapeHtml === "function", "GRM.escapeHtml exported by grm-core");

const jsonResponse = (body, ok = true, status = 200) =>
  async () => ({ ok, status, json: async () => body });

// ---- 1. escapeHtml unit behavior -------------------------------------------
test("escapeHtml escapes all five metacharacters and fails closed on null", () => {
  assert.equal(G.escapeHtml('&<>"\''), "&amp;&lt;&gt;&quot;&#39;");
  assert.equal(G.escapeHtml('<img src=x onerror="alert(1)">'),
    "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;");
  assert.equal(G.escapeHtml(null), "");
  assert.equal(G.escapeHtml(undefined), "");
  assert.equal(G.escapeHtml(3), "3");            // numbers (e.g. loa) coerce safely
  assert.equal(G.escapeHtml("plain text"), "plain text"); // no-op on clean input
});

// ---- 2. D&B-derived entity render path (the ~line 323 sink) ----------------
test("hostile D&B legalName/country render entity-escaped in entityOut", async () => {
  // Map the hostile fixture to the /license/review resolve response shape the
  // same way functions/license/review.js does.
  const org = hostileFixture.organization;
  globalThis.fetch = jsonResponse({
    dnb: {
      verified: true,
      legalName: org.primaryName,
      country: org.primaryAddress.addressCountry.isoAlpha2Code,
    },
  });
  el("duns").value = "804735132";
  el("entityOut").innerHTML = "";
  await el("resolveBtn").fire("click");
  const out = el("entityOut").innerHTML;

  // No live tag from the payload survives…
  assert.ok(!/<img/i.test(out), "raw <img> must not reach innerHTML: " + out);
  assert.ok(!/<svg/i.test(out), "raw <svg> must not reach innerHTML: " + out);
  assert.ok(!/<script/i.test(out), "raw <script> must not reach innerHTML: " + out);
  // …and the payload is present as escaped TEXT (shown to the user, defused).
  assert.ok(out.includes("&lt;img src=x onerror=&quot;window.__xss_pwned=1&quot;&gt;"), out);
  assert.ok(out.includes("&lt;svg onload=alert(1)&gt;US"), out);
  assert.ok(out.includes("&amp;"), "ampersand in the name is escaped: " + out);
  assert.equal(globalThis.__xss_pwned, undefined);
});

// ---- 3. server error string render path ------------------------------------
test("hostile j.error on refused resolve renders escaped", async () => {
  globalThis.fetch = jsonResponse({ error: '"><img src=x onerror=alert(1)>' }, false, 400);
  el("duns").value = "804735132";
  el("entityOut").innerHTML = "";
  await el("resolveBtn").fire("click");
  const out = el("entityOut").innerHTML;
  assert.ok(!/<img/i.test(out), "raw <img> must not reach innerHTML: " + out);
  assert.ok(out.includes("&quot;&gt;&lt;img src=x onerror=alert(1)&gt;"), out);
});

test("thrown fetch error message renders escaped (network-error path)", async () => {
  globalThis.fetch = async () => { throw new Error('<img src=e onerror=alert(1)>'); };
  el("duns").value = "804735132";
  el("entityOut").innerHTML = "";
  await el("resolveBtn").fire("click");
  const out = el("entityOut").innerHTML;
  assert.ok(!/<img/i.test(out), "raw <img> must not reach innerHTML: " + out);
  assert.ok(out.includes("&lt;img src=e onerror=alert(1)&gt;"), out);
});

// ---- 4. verdict render path (decision/loa/assurance/methods/ref) -----------
test("hostile verdict fields (decision, loa, assurance, methods, ref) render escaped", async () => {
  globalThis.fetch = jsonResponse({
    loa: '<img src=l onerror=alert(1)>',
    decision: '<img src=d onerror=alert(1)>',
    assurance: '"><svg onload=alert(1)>',
    methods: ["<script>m()</script>", "dnb-entity"],
    ref: '</pre><script>window.__xss_pwned=2</script>',
  });
  el("duns").value = "804735132";
  el("verdictOut").innerHTML = "";
  await el("submitBtn").fire("click");
  const out = el("verdictOut").innerHTML;
  assert.ok(!/<img/i.test(out), "raw <img> must not reach innerHTML: " + out);
  assert.ok(!/<svg/i.test(out), "raw <svg> must not reach innerHTML: " + out);
  assert.ok(!/<script/i.test(out), "raw <script> must not reach innerHTML: " + out);
  assert.ok(out.includes("&lt;img src=d onerror=alert(1)&gt;"), "decision escaped: " + out);
  assert.ok(out.includes("&lt;img src=l onerror=alert(1)&gt;"), "loa escaped: " + out);
  assert.ok(out.includes("&quot;&gt;&lt;svg onload=alert(1)&gt;"), "assurance escaped: " + out);
  assert.ok(out.includes("&lt;script&gt;m()&lt;/script&gt;"), "methods escaped: " + out);
  // ref cannot close the surrounding <pre> and start a live script:
  assert.ok(out.includes("&lt;/pre&gt;&lt;script&gt;window.__xss_pwned=2&lt;/script&gt;"), "ref escaped: " + out);
  assert.equal(globalThis.__xss_pwned, undefined);
});

test("hostile j.error on refused verdict renders escaped", async () => {
  globalThis.fetch = jsonResponse({ error: "<script>window.__xss_pwned=3</script>" }, false, 403);
  el("duns").value = "804735132";
  el("verdictOut").innerHTML = "";
  await el("submitBtn").fire("click");
  const out = el("verdictOut").innerHTML;
  assert.ok(!/<script/i.test(out), "raw <script> must not reach innerHTML: " + out);
  assert.ok(out.includes("&lt;script&gt;window.__xss_pwned=3&lt;/script&gt;"), out);
});

// ---- 5. adapter-derived engine name path ------------------------------------
test("hostile OCR adapter/engine name renders escaped in ocrEngineNote", () => {
  // The engine name flows into innerHTML inside <code>…</code>; escape it too.
  assert.ok(
    ui.body.includes('esc(ra.engine)'),
    "index.html must escape ra.engine before innerHTML (found: " +
      (ui.body.match(/ocrEngineNote[^\n]*engine[^\n]*/g) || []).join(" | ") + ")",
  );
});

// ---- 6. every remaining innerHTML sink is static or escaped -----------------
// Remove every balanced esc(...) span; whatever tainted identifier remains in
// an innerHTML assignment afterwards is by definition NOT escape-wrapped.
function stripEscCalls(src) {
  let out = src, i;
  while ((i = out.indexOf("esc(")) >= 0) {
    let depth = 0, j = i + 3;
    for (; j < out.length; j++) {
      if (out[j] === "(") depth++;
      else if (out[j] === ")") { depth--; if (depth === 0) { j++; break; } }
    }
    out = out.slice(0, i) + '"ESCAPED"' + out.slice(j);
  }
  return out;
}
test("no unescaped tainted identifier is concatenated into an innerHTML assignment", () => {
  // Tainted identifiers that may carry server/D&B/exception strings. Any
  // appearance inside an innerHTML expression must be wrapped in esc(...).
  const assignments = ui.body.match(/\.innerHTML\s*=[^;]+;/g) || [];
  assert.ok(assignments.length >= 8, "innerHTML sinks found: " + assignments.length);
  const tainted = /\b(j\.error|j\.loa|j\.decision|j\.assurance|j\.ref|j\.methods|entity\.legalName|entity\.country|ra\.engine|ra\.text|JSON\.stringify)\b/;
  for (const a of assignments) {
    const bad = stripEscCalls(a).match(tainted);
    assert.ok(!bad, "unescaped tainted value in innerHTML sink: " + (bad && bad[0]) + " in: " + a);
  }
  // The catch-path exception object must not be concatenated raw either.
  assert.ok(!/innerHTML[^;]*\+\s*e\s*;/.test(stripEscCalls(ui.body)), "raw exception concatenated into innerHTML");
});

// ---- 7. CSP: inline scripts pinned by hash, no 'unsafe-inline' scripts ------
test("CSP meta pins the three inline scripts by sha256 hash (no script-src 'unsafe-inline')", () => {
  const meta = html.match(/http-equiv="Content-Security-Policy" content="([^"]*)"/);
  assert.ok(meta, "CSP meta tag present");
  const scriptSrc = meta[1].match(/script-src ([^;]*)/);
  assert.ok(scriptSrc, "script-src directive present");
  assert.ok(!scriptSrc[1].includes("'unsafe-inline'"), "script-src must not allow 'unsafe-inline'");
  for (const b of blocks) {
    const h = "sha256-" + createHash("sha256").update(b.body, "utf8").digest("base64");
    assert.ok(scriptSrc[1].includes("'" + h + "'"),
      "script-src is missing the hash of inline script " + (b.id || "(ui)") +
      " — recompute after editing inline scripts: '" + h + "'");
  }
  // and nothing extra is allowed to run:
  const allowed = (scriptSrc[1].match(/'sha256-[^']*'/g) || []).length;
  assert.equal(allowed, blocks.length, "exactly one hash per inline script");
});
