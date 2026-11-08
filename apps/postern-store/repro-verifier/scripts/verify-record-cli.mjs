#!/usr/bin/env node
// Verifies a SET of signed `reproducible_build` records against a trust-store
// file and a claimed catalog tier, printing the badge decision — exactly what
// a Store client would do before rendering ATTESTED. Usage:
//   node scripts/verify-record-cli.mjs <trust-store.json> <tier> <appId> <version> <record1.json> [record2.json ...]
// trust-store.json shape: [{ "id": "...", "pubkey_b64": "...", "label": "..." }]
// appId/version are the identity of the CATALOG ENTRY these records are being
// checked against (record/entry binding fix) — pass "-" for either ONLY when
// there is no surrounding entry to bind to (e.g. inspecting records in
// isolation); a real Store client always has an entry and MUST pass both.
//
// DEPOT FINDING H1: ATTESTED now requires at least two of the given records to
// each independently verify AND resolve to DISTINCT pinned trusted-builder
// keys (lib/verify-record.mjs's verifyTwoBuilderQuorum()) — one record, or
// several records that all trace back to the same signer, is never enough.
import { readFileSync, existsSync } from "node:fs";
import { decideAttestedBadge } from "../lib/verify-record.mjs";
import { makeTrustStore } from "../lib/builder-trust.mjs";

const [trustPath, tier = "attestable-nix", appIdArg, versionArg, ...recordPaths] = process.argv.slice(2);

if (!trustPath || !existsSync(trustPath) || recordPaths.length === 0 || recordPaths.some((p) => !existsSync(p))) {
  console.error("usage: node scripts/verify-record-cli.mjs <trust-store.json> <tier> <appId> <version> <record1.json> [record2.json ...]");
  console.error("       (pass appId/version as \"-\" only for standalone record inspection with no catalog entry to bind to)");
  process.exit(2);
}
const appId = appIdArg === "-" ? undefined : appIdArg;
const version = versionArg === "-" ? undefined : versionArg;
if (!appId || !version) {
  console.error("(no appId/version given — record/entry binding will NOT be checked; only safe for standalone record inspection, never for a real catalog entry)");
}

const records = recordPaths.map((p) => JSON.parse(readFileSync(p, "utf8")));
const trustEntries = JSON.parse(readFileSync(trustPath, "utf8"));
const trustStore = makeTrustStore(trustEntries);

const decision = decideAttestedBadge({ tier, records, trustStore, appId, version });
console.log("badge: ", decision.badge);
console.log("reason:", decision.reason);
if (decision.detail) {
  console.log("distinctBuilderCount:", decision.detail.distinctBuilderCount);
  console.log("qualifyingCount:     ", decision.detail.qualifyingCount);
  for (const { record, verdict } of decision.detail.perRecord ?? []) {
    console.log(`  record builder_identity=${record?.builder_identity?.id ?? "(missing)"} -> badge=${verdict.badge} (${verdict.reason})`);
  }
}
process.exit(decision.badge === "ATTESTED" ? 0 : 1);
