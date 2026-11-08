#!/usr/bin/env node
// Verifies fixtures/dist/index.json against a pinned public key, exactly the
// way a Store client would after fetching a self-hosted repo's two files.
// Usage: node scripts/verify-cli.mjs [pinnedPubKeyB64]
// Defaults to the key in fixtures/repo-key.json (the "correct" key) if none given.
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { verifyRepoIndex, TRUST } from "../lib/verify.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const distDir = join(here, "..", "fixtures", "dist");
const keyPath = join(here, "..", "fixtures", "repo-key.json");

const indexPath = join(distDir, "index.json");
const sigPath = join(distDir, "index.json.sig");
if (!existsSync(indexPath) || !existsSync(sigPath)) {
  console.error("No fixtures/dist/index.json(.sig) — run scripts/gen-keys.mjs then scripts/build-index.mjs first.");
  process.exit(1);
}

let pinnedPubKeyB64 = process.argv[2];
if (!pinnedPubKeyB64) {
  if (!existsSync(keyPath)) {
    console.error("No pinned key given and no fixtures/repo-key.json to default to.");
    process.exit(1);
  }
  pinnedPubKeyB64 = JSON.parse(readFileSync(keyPath, "utf8")).publicKey;
}

const indexBytes = readFileSync(indexPath);
const sigBytes = readFileSync(sigPath);

const result = verifyRepoIndex({ indexBytes, sigBytes, pinnedPubKeyB64 });

console.log("state:  ", result.state);
console.log("reason: ", result.reason);
if (result.state === TRUST.VERIFIED) {
  console.log("adopted:", result.adopted);
  console.log("apps:", result.apps.length);
  console.log("stripped claims by app:", JSON.stringify(result.strippedByApp, null, 2));
  console.log("checksum results:", JSON.stringify(result.checksumResults, null, 2));
}
