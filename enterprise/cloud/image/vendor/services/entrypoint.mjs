#!/usr/bin/env node
// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// entrypoint.mjs — runtime dispatcher for the Postern Cloud (hosted) image.
//
// Selects exactly ONE hosted service to run via POSTERN_SERVICE (default:
// "license") and starts it on $PORT (default 8080). It does no I/O of its own
// beyond binding the port.
//
// RAILS honored here:
//   - No secrets are baked in. All config/secrets are RUNTIME-INJECTED via env
//     (see compose.yaml: read-only config mount / operator secrets manager).
//   - Fail-closed (SVC-1): the license and console services' createServer()
//     REFUSE to start without a mandatory VENDOR_PUBLIC_KEY. We surface that as a
//     non-zero exit rather than limping along fail-open.
//   - Telemetry off, egress controlled — inherited from the image env; this
//     process opens no outbound connections on its own.
//   - Hosted is LESS private than self-hosting/offline — disclosed on boot.
//   - Reference / UNAUDITED, not production-ready.
"use strict";

import { logLine } from "./src/common.mjs";

const SERVICE = (process.env.POSTERN_SERVICE || "license").trim().toLowerCase();
const PORT = parseInt(process.env.PORT || "8080", 10);

// The three hosted services this image can run. Each exports createServer() and
// serves GET /healthz + GET /v1/posture via the shared server bootstrap.
const MODULES = {
  license: "./src/license-service.mjs",
  console: "./src/console-service.mjs",
  relay: "./src/relay-service.mjs",
};

const modPath = MODULES[SERVICE];
if (!modPath) {
  console.error(
    `postern-cloud: unknown POSTERN_SERVICE="${SERVICE}" ` +
      `(expected one of: ${Object.keys(MODULES).join(", ")})`,
  );
  process.exit(2);
}

const mod = await import(modPath);

let server;
try {
  // license/console call requireVendorKey() here (SVC-1) — they throw, and we
  // exit non-zero, if VENDOR_PUBLIC_KEY is absent. Fail-closed, not fail-open.
  server = mod.createServer();
} catch (e) {
  console.error(`postern-cloud: refusing to start "${SERVICE}" service: ${e && e.message}`);
  process.exit(1);
}

server.listen(PORT, () => {
  logLine(`postern-cloud [${SERVICE}] listening on :${PORT}`);
  logLine(
    `  edition=${process.env.POSTERN_EDITION || "cloud"} ` +
      `telemetry=${process.env.POSTERN_TELEMETRY || "off"} ` +
      `egress=${process.env.POSTERN_EGRESS || "controlled"}`,
  );
  logLine("  hosted is LESS private than self-hosting/offline — disclosed.");
  logLine("  reference / UNAUDITED — not production-ready. The coin is not a security.");
});

// Clean PID-1 shutdown so `compose down` / SIGTERM stops the container promptly.
for (const sig of ["SIGTERM", "SIGINT"]) {
  process.on(sig, () => {
    logLine(`postern-cloud: ${sig} received, shutting down`);
    server.close(() => process.exit(0));
    // Safety net if connections linger.
    setTimeout(() => process.exit(0), 5000).unref();
  });
}
