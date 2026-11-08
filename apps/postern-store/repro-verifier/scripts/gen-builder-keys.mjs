#!/usr/bin/env node
// Generates a builder Ed25519 keypair and writes it to
// fixtures/builder-key.json (POC/dev only — the private half is never
// committed in a real deployment; mirrors repo-poc's scripts/gen-keys.mjs).
//
// Usage: node scripts/gen-builder-keys.mjs [builderId]
import { writeFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { generateKeypair, keyId } from "../lib/keys.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(here, "..", "fixtures");
mkdirSync(fixturesDir, { recursive: true });

const builderId = process.argv[2] || "postern-ci-builder-1";
const kp = generateKeypair();
const out = { id: builderId, publicKey: kp.publicKey, privateKey: kp.privateKey, fingerprint: keyId(kp.publicKey) };
writeFileSync(join(fixturesDir, "builder-key.json"), JSON.stringify(out, null, 2) + "\n");

console.log("Generated builder Ed25519 keypair -> fixtures/builder-key.json");
console.log("  id:                              ", builderId);
console.log("  publicKey (base64, 32 raw bytes):", kp.publicKey);
console.log("  fingerprint (keyId()):           ", out.fingerprint);
console.log("  To trust this builder, pin {id, pubkey_b64: publicKey} in the client's trust store.");
console.log("  (private key is dev/POC-only; never commit this file in a real deployment)");
