#!/usr/bin/env node
// Generates a repo Ed25519 keypair and writes it to fixtures/repo-key.json
// (POC/dev only — SIGNING.md's real-world rule is "the private half is never
// committed"; this script exists so a human can run the POC end-to-end on
// their own host, mirroring keys/postern-keygen.sh's role for the bundled
// catalog).
import { writeFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { generateKeypair, keyId } from "../lib/keys.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(here, "..", "fixtures");
mkdirSync(fixturesDir, { recursive: true });

const kp = generateKeypair();
const out = { publicKey: kp.publicKey, privateKey: kp.privateKey, keyId: keyId(kp.publicKey) };
writeFileSync(join(fixturesDir, "repo-key.json"), JSON.stringify(out, null, 2) + "\n");

console.log("Generated repo Ed25519 keypair -> fixtures/repo-key.json");
console.log("  publicKey (base64, 32 raw bytes):", kp.publicKey);
console.log("  keyId():                         ", out.keyId);
console.log("  (private key is dev/POC-only; never commit this file in a real repo)");
