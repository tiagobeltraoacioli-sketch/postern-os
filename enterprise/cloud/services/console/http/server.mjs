#!/usr/bin/env node
// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern CLOUD — Consiglio CONSOLE HTTP SERVER entrypoint (reference prototype).
//
// STATUS: reference prototype. UNAUDITED. Pre-production. NO SECURITY CLAIMS.
// This DEMONSTRATES controls that ENABLE compliance — NOT compliance, NOT legal
// advice. Tamper-EVIDENT, not tamper-proof. Fiat only. LGPD/GDPR-minimal.
//
// Boots the durable Consiglio console HTTP service and listens. State is
// restored from (and persisted to) the durable store directory, so a restart
// keeps enrollments, live sessions, the sub registry, and the audit trail.
//
// ENV
//   PORT               listen port (default 8803)
//   CONSOLE_DATA_DIR   durable store directory (default ./console-data)
//   SESSION_TTL_SECS   session lifetime (default 3600)
//   MASTER_BUNDLE      path to a JSON master bundle to enable the seat/device
//                      verbs: { token, masterKey, expires, seats,
//                      masterPublicKey?, vendorPublicKey?, masterTokenObj? }.
//                      Omit to run auth-only. The master PRIVATE key is read into
//                      memory only; this code never writes it to disk.
//
// The wallet-login signature check is the REAL hybrid-PQ verifier
// (consiglio-verify). If that binary is not built the service still starts, but
// login FAILS CLOSED (never a stub) — build it with:
//   cargo build --release --features verifier-bin --bin consiglio-verify
//     (in crates/postern-consiglio-auth)

import http from "node:http";
import { readFileSync } from "node:fs";

import { createConsoleService } from "./service.mjs";
import { loadLicensingSigner } from "./licensing-signer.mjs";

async function main() {
  const port = parseInt(process.env.PORT || "8803", 10);
  const dataDir = process.env.CONSOLE_DATA_DIR || "./console-data";
  const sessionTtlSecs = parseInt(process.env.SESSION_TTL_SECS || "3600", 10);

  let master = null;
  let signer = null;
  if (process.env.MASTER_BUNDLE) {
    master = JSON.parse(readFileSync(process.env.MASTER_BUNDLE, "utf8"));
    signer = await loadLicensingSigner({
      masterPublicKey: master.masterPublicKey,
      vendorPublicKey: master.vendorPublicKey,
      masterTokenObj: master.masterTokenObj,
    });
  }

  const svc = await createConsoleService({ dataDir, sessionTtlSecs, master, signer });
  const server = http.createServer(svc.handler);

  server.listen(port, () => {
    console.log(`Consiglio console HTTP service listening on :${port}`);
    console.log(`  data dir: ${dataDir}`);
    console.log(`  seat/device host: ${master ? "wired" : "off (no MASTER_BUNDLE)"}`);
    console.log(`  signer: ${signer ? signer.label : "demo stand-in (unsigned subs) — build @postern/licensing for real"}`);
    console.log("  RAILS: UNAUDITED reference prototype; enables ≠ is compliance; tamper-evident not tamper-proof.");
  });

  for (const sig of ["SIGINT", "SIGTERM"]) {
    process.on(sig, () => {
      svc.close().finally(() => server.close(() => process.exit(0)));
    });
  }
}

main().catch((e) => {
  console.error("Consiglio console failed to start:", e);
  process.exit(1);
});
