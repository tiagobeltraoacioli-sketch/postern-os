// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern Enterprise — integration layer: SIBLING PUBLIC-EXPORT SURFACE.
//
// STATUS: design / reference prototype — unaudited, pre-production.
//
// This is the ONLY file that reaches into the sibling enterprise modules, and it
// does so exclusively through their PUBLIC exports (package `main` for the
// licensing lib; the published `.mjs` entry points for the rest). Nothing here
// edits or forks a sibling — the integration layer consumes them as-is and
// re-exports a single, tidy surface the adapters build on.
//
//   licensing         -> enterprise/licensing (package @postern/licensing, dist)
//   features          -> enterprise/features
//   comms (app)       -> enterprise/comms/app/src
//   comms (compliance)-> enterprise/comms/compliance
//   shield (container)-> enterprise/shield/container/src
//   shield (dlp)      -> enterprise/shield/dlp

// ── licensing lib (offline-verifiable master -> sub Ed25519 chain) ────────────
export {
  generateKeypair,
  ed25519Sign,
  ed25519Verify,
  issue,
  mintSub,
  mintSubUnderMaster,
  verifyChain,
  isValidDunsFormat,
  status,
  describeState,
  disclosureForMaster,
} from "../../licensing/dist/index.js";

// ── features (license gate + sub-access delegation + org policy) ──────────────
export {
  createLicenseGate,
  EDITION_NOTICE,
  CORPORATE_EVAL_DAYS,
  FREEMIUM_SEATS,
} from "../../features/license-hook.mjs";
export { createSubAccessManager } from "../../features/sub-access.mjs";
export {
  emptyPolicy,
  evaluatePolicy,
  ADDITIVE_STATEMENT,
} from "../../features/org-policy.mjs";

// ── comms app (Bloch org messenger — enterprise-only, fail-closed) ────────────
export { createCommsOrg, CommsRefused } from "../../comms/app/src/comms-core.mjs";
export {
  resolveLicense,
  commsAllowed,
  refusalReason,
} from "../../comms/app/src/license-bridge.mjs";
export {
  buildTransparency as buildCommsTransparency,
  transparencyBanner as commsTransparencyBanner,
  transparencyText as commsTransparencyText,
} from "../../comms/app/src/transparency.mjs";
export { resolveComplianceDisclosure } from "../../comms/app/src/compliance-hook.mjs";

// ── comms compliance (employer transparency notice, schema .../1) ─────────────
export { transparencyNotice as commsComplianceNotice } from "../../comms/compliance/transparency.mjs";

// ── shield container (BYOD work-container, grant-bound seal, access broker) ────
export { createAccessGrant, GrantRevoked } from "../../shield/container/src/grant-binding.mjs";
export {
  createShieldContainer,
  makeDemoSealEngine,
  ContainerWiped,
} from "../../shield/container/src/shield-container.mjs";
export { createAccessBroker, AccessRefused } from "../../shield/container/src/access-broker.mjs";
export { createConsiglioBridge } from "../../shield/container/src/consiglio-bridge.mjs";
export {
  buildTransparency as buildShieldTransparency,
  transparencyBanner as shieldTransparencyBanner,
  transparencyText as shieldTransparencyText,
  resolveDlpDisclosure,
} from "../../shield/container/src/transparency-hook.mjs";

// ── shield dlp (corporate-egress traceability transparency notice) ────────────
export { transparencyNotice as shieldDlpNotice } from "../../shield/dlp/transparency.mjs";
