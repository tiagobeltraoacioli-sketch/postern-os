#!/usr/bin/env node
// Verifies fixtures/dist/revocations.json against a pinned public key, and
// shows what it would pull off the shelf from fixtures/dist/index.json — the
// end-to-end shape a real Depot client goes through per repo.
// Usage: node scripts/verify-crl-cli.mjs [pinnedPubKeyB64]
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { resolveCrl, applyCrlToApps, CRL_STATE } from "../lib/crl.mjs";
import { verifyRepoIndex, TRUST } from "../lib/verify.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const distDir = join(here, "..", "fixtures", "dist");
const keyPath = join(here, "..", "fixtures", "repo-key.json");

const indexPath = join(distDir, "index.json");
const sigPath = join(distDir, "index.json.sig");
const crlPath = join(distDir, "revocations.json");

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

const indexResult = verifyRepoIndex({
  indexBytes: readFileSync(indexPath),
  sigBytes: readFileSync(sigPath),
  pinnedPubKeyB64,
});
console.log("index state:", indexResult.state, "adopted:", indexResult.adopted, "apps:", indexResult.apps.length);
if (indexResult.state !== TRUST.VERIFIED || !indexResult.adopted) {
  console.error("Index did not verify/adopt — nothing to apply a CRL to.");
  process.exit(1);
}

const fetchedBytes = existsSync(crlPath) ? readFileSync(crlPath) : null;
if (!fetchedBytes) {
  console.log("(no fixtures/dist/revocations.json found — run `node scripts/build-crl.mjs` to produce one; continuing to demonstrate the absent-CRL path)");
}

// fixtures/repo-key.json + scripts/build-crl.mjs both use this fixed repo_id
// for this POC's single sample repo.
const crlResult = resolveCrl({ fetchedBytes, pinnedPubKeyB64, repoId: "com.example.journalist-kit", cachedCrl: null });
console.log("\nCRL state:", crlResult.state);
console.log("disclosure:", crlResult.disclosure);
if (crlResult.freshness) console.log("freshness:", crlResult.freshness);

const { apps, removed } = applyCrlToApps(indexResult.apps, crlResult.crl);
console.log("\napps remaining on the shelf:", apps.map((a) => a.id));
console.log("apps pulled off the shelf:", removed);

if (crlResult.state === CRL_STATE.NO_CRL || crlResult.state === CRL_STATE.TAMPERED) {
  console.log("\n(honest reminder: this state means revocation is NOT being enforced for this repo right now — see lib/crl.mjs's header comment)");
}
