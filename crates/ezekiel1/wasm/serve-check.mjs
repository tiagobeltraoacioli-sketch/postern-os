#!/usr/bin/env node
// Prove the *exact* code path the shipping browser console uses.
//
// parity.mjs proves wasm==native via the `nodejs` bindings. This goes one step
// further: it loads the SAME wasm-bindgen `no-modules` glue the browser loads
// (pkg-inline/ezekiel1.js), initialises it from the raw ezekiel1.wasm bytes
// (initSync — the offline, fetch-less form of what the page does with
// connect-src 'self'), and asserts the resulting engine object returns
// crate-correct decisions for the fixtures. If this passes, the console's
// `window.EZ1` calls are the crate's decisions.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const die = (m) => { console.error("serve-check: " + m); process.exit(1); };

const gluePath = join(here, "pkg-inline", "ezekiel1.js");
const wasmPath = join(here, "pkg-inline", "ezekiel1_bg.wasm");
let glueText, wasmBytes;
try {
  glueText = readFileSync(gluePath, "utf8");
  wasmBytes = readFileSync(wasmPath);
} catch (e) {
  die("no-modules build missing (" + e.message + "). Run: bash crates/ezekiel1/wasm/build.sh");
}

// The glue is `let wasm_bindgen = (function(exports){…})`. Capture it exactly as
// a browser would after the <script> tag runs, then init synchronously.
// eslint-disable-next-line no-new-func
const wasm_bindgen = new Function(glueText + "\nreturn wasm_bindgen;")();
wasm_bindgen.initSync({ module: new Uint8Array(wasmBytes) });
const EZ1 = wasm_bindgen; // exactly what the console exposes as window.EZ1

const fx = JSON.parse(readFileSync(join(here, "fixtures.json"), "utf8"));
let checks = 0, fails = 0;
const bad = (m) => { fails++; console.error("  FAIL " + m); };

for (const c of fx.evaluate) {
  checks++;
  const out = EZ1.evaluate(fx.policies[c.policy], c.subject, c.resource, c.context, c.action, c.now);
  const o = JSON.parse(out);
  const got = o.ok === false ? "error" : o.decision;
  if (got !== c.expect) bad(`evaluate/${c.name}: expect ${c.expect} got ${got} (${out})`);
}
for (const c of fx.blp) {
  checks++;
  const got = c.fn === "read" ? EZ1.blp_may_read(c.subject_level, c.resource_level)
                              : EZ1.blp_may_write(c.subject_level, c.resource_level);
  if (got !== c.expect) bad(`blp/${c.name}: expect ${c.expect} got ${got}`);
}
for (const c of fx.wall) {
  checks++;
  const got = EZ1.wall_barred(JSON.stringify(c.classes), JSON.stringify(c.history), c.target);
  if (got !== c.expect) bad(`wall/${c.name}: expect ${c.expect} got ${got}`);
}

if (fails) die(`${fails}/${checks} case(s) wrong through the shipped glue.`);
console.log(`serve-check: PASS — ${checks} cases via the no-modules glue + initSync (browser path).`);
console.log(`serve-check: engine ${EZ1.engine_version()} initialised from ${wasmBytes.length} wasm bytes, no fetch.`);
