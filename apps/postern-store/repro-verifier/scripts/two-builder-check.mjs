#!/usr/bin/env node
// Runnable-on-a-Nix-box CLI for lib/two-builder-check.mjs.
//
// Usage:
//   node scripts/two-builder-check.mjs <flakeRef> [shippedStorePath] [--cwd-a=<dir>] [--cwd-b=<dir>]
//
// Example (POC-repro-and-agpl.md Part 1's minimal artifact, once a real
// flake.lock exists on a Nix-capable host):
//   node scripts/two-builder-check.mjs .#poc
//
// Exits 0 on PASS, 1 on any FAIL, 127 if this host has no Nix at all (never
// fabricates a result in that case — see lib/two-builder-check.mjs's header
// comment). This mirrors the honesty banner in
// docs/store-fdroid/POC-repro-and-agpl.md: this repo's discipline is to say
// "not run here" plainly rather than print a plausible-looking fake PASS.

import { checkNixAvailable, twoBuilderCheck } from "../lib/two-builder-check.mjs";

function parseArgs(argv) {
  const positional = [];
  const flags = {};
  for (const arg of argv) {
    const m = /^--(cwd-a|cwd-b)=(.*)$/.exec(arg);
    if (m) flags[m[1]] = m[2];
    else positional.push(arg);
  }
  return { positional, flags };
}

const { positional, flags } = parseArgs(process.argv.slice(2));
const [flakeRef, shippedPath] = positional;

if (!flakeRef) {
  console.error("usage: node scripts/two-builder-check.mjs <flakeRef> [shippedStorePath] [--cwd-a=<dir>] [--cwd-b=<dir>]");
  process.exit(2);
}

if (!checkNixAvailable()) {
  console.error(
    "nix not found on this host. This script is real and requires an actual Nix " +
      "installation to run (see docs/store-fdroid/POC-repro-and-agpl.md's honesty banner). " +
      "Nothing was fabricated — run this on a Nix-capable host."
  );
  process.exit(127);
}

let result;
try {
  result = twoBuilderCheck({
    flakeRef,
    shippedPath: shippedPath ?? null,
    cwdA: flags["cwd-a"],
    cwdB: flags["cwd-b"],
  });
} catch (err) {
  console.error(`two-builder check failed to run: ${err.message}`);
  process.exit(1);
}

console.log(JSON.stringify(result, null, 2));
process.exit(result.verdict === "PASS" ? 0 : 1);
