#!/usr/bin/env node
// WASM half of the parity proof.
//
// Loads the compiled Ezekiel 1 WASM module (wasm-bindgen `nodejs` target under
// pkg-node/), runs EVERY fixture in fixtures.json through it, and asserts the
// output is byte-identical to the native binary's (`cargo run --bin
// ezekiel1-parity`). Because both halves call the same Rust `api` module —
// one compiled to wasm32, one to the host — equality proves the browser
// console's verdicts ARE the crate's verdicts.
//
// Exit 0 = parity holds. Non-zero = a divergence (printed) or a missing build.
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createRequire } from "node:module";

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

function die(msg) { console.error("parity: " + msg); process.exit(1); }

// --- load the WASM module -------------------------------------------------
let wasm;
try {
  wasm = require(join(here, "pkg-node", "ezekiel1.js"));
} catch (e) {
  die(
    "WASM build not found under pkg-node/ (" + e.message + ").\n" +
    "Build it first:  bash crates/ezekiel1/wasm/build.sh"
  );
}

const fx = JSON.parse(readFileSync(join(here, "fixtures.json"), "utf8"));

// --- compute the WASM side ------------------------------------------------
const wasmOut = { evaluate: {}, blp: {}, wall: {} };
for (const c of fx.evaluate) {
  wasmOut.evaluate[c.name] = wasm.evaluate(
    fx.policies[c.policy], c.subject, c.resource, c.context, c.action, c.now
  );
}
for (const c of fx.blp) {
  wasmOut.blp[c.name] = (c.fn === "read")
    ? wasm.blp_may_read(c.subject_level, c.resource_level)
    : wasm.blp_may_write(c.subject_level, c.resource_level);
}
for (const c of fx.wall) {
  wasmOut.wall[c.name] = wasm.wall_barred(
    JSON.stringify(c.classes), JSON.stringify(c.history), c.target
  );
}

// --- compute the NATIVE side (spawn the Rust binary) ----------------------
let nativeRaw;
try {
  nativeRaw = execFileSync(
    "cargo",
    ["run", "-q", "-p", "ezekiel1", "--bin", "ezekiel1-parity", "--", join(here, "fixtures.json")],
    { cwd: join(here, "..", "..", ".."), encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] }
  );
} catch (e) {
  die("could not run the native ezekiel1-parity binary: " + e.message);
}
const nativeOut = JSON.parse(nativeRaw);

// --- diff -----------------------------------------------------------------
const diffs = [];
let checks = 0;
for (const kind of ["evaluate", "blp", "wall"]) {
  const names = new Set([...Object.keys(nativeOut[kind]), ...Object.keys(wasmOut[kind])]);
  for (const name of names) {
    checks++;
    const n = JSON.stringify(nativeOut[kind][name]);
    const w = JSON.stringify(wasmOut[kind][name]);
    if (n !== w) diffs.push(`  [${kind}/${name}] native=${n}  wasm=${w}`);
    else if (process.env.VERBOSE) console.log(`  ok  ${kind}/${name} = ${n}`);
  }
}

if (diffs.length) {
  console.error(`parity: FAIL — ${diffs.length}/${checks} case(s) diverge:`);
  console.error(diffs.join("\n"));
  process.exit(1);
}
console.log(`parity: PASS — ${checks} cases, WASM decision == native decision for every one.`);
console.log(`parity: engine version ${wasm.engine_version()} (wasm) vs crate (native).`);
