// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Bloch Shield (Enterprise) — DLP layer public barrel.
//
// STATUS: design / reference prototype. UNAUDITED. Pre-production. NOT LEGAL
// ADVICE — see COMPLIANCE.md.
//
// The one entry point the container/access layer (enterprise/shield/container/,
// another dev's) imports from. Corporate-scope only; never personal surveillance.

export {
  CLASSES,
  PERSONAL,
  SILENT_BLOCK_REASON,
  dataClass,
  classify,
  emptySharingPolicy,
  mayShareWithThirdParty,
} from "./classification.mjs";

export { EgressTrail, ALLOWED_EVENTS } from "./audit-trail.mjs";
export { gateEgress } from "./egress-gate.mjs";
export { transparencyNotice, transparencyText } from "./transparency.mjs";
