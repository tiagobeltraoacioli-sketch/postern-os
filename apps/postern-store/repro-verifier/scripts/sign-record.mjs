#!/usr/bin/env node
// Signs a `reproducible_build` record JSON (as produced by, e.g.,
// scripts/two-builder-check.mjs's output, reshaped into the record fields)
// with a builder's own key. Usage:
//   node scripts/sign-record.mjs <record.json> [builderKeyPath]
// Prints the signed record JSON to stdout.
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { signRecord } from "../lib/build-record.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const defaultKeyPath = join(here, "..", "fixtures", "builder-key.json");

const recordPath = process.argv[2];
const keyPath = process.argv[3] || defaultKeyPath;

if (!recordPath || !existsSync(recordPath)) {
  console.error("usage: node scripts/sign-record.mjs <record.json> [builderKeyPath]");
  process.exit(2);
}
if (!existsSync(keyPath)) {
  console.error(`No builder key at ${keyPath} — run scripts/gen-builder-keys.mjs first.`);
  process.exit(2);
}

const record = JSON.parse(readFileSync(recordPath, "utf8"));
const { id, publicKey, privateKey } = JSON.parse(readFileSync(keyPath, "utf8"));

const signed = signRecord(record, { builderId: id, builderPrivKeyB64: privateKey, builderPubKeyB64: publicKey });
console.log(JSON.stringify(signed, null, 2));
