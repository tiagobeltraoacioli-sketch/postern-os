// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Bloch — org internal messenger (Business/Enterprise edition ONLY).
// Transparency banner + honest privacy panel model.
//
// STATUS: design / reference prototype — unaudited, pre-production.
//
// This module assembles what an employee is TOLD, from three honest sources —
// it invents no policy of its own:
//
//   1. E2EE FACTS about the transport. Bloch rides the Postern Messenger E2EE
//      core (crates/postern-messenger): Matrix + vodozemac/Megolm. The tier
//      model and the exact badge strings are OWNED by that crate's
//      `SecurityTier`/`disclosure`; we mirror them here as a JS view and mark
//      the crate as the source of truth. We do NOT fork or reimplement crypto.
//   2. EMPLOYER-VISIBILITY WRINKLE from enterprise/features/privacy.mjs — the
//      one honest difference from a purely personal app.
//   3. The COMPLIANCE DISCLOSURE injected by the compliance layer
//      (compliance-hook.mjs). Policy text is owned there, not here.
//
// House rule, restated: never "100% private". Bloch is an EMPLOYER-RUN tool.

import { PRIVACY } from "../../../features/privacy.mjs";
import { resolveComplianceDisclosure } from "./compliance-hook.mjs";

// --- (1) E2EE facts, mirrored from crates/postern-messenger (source of truth) ---
// SecurityTier + disclosure copy live in that crate's lib.rs. Bloch is an
// INTERNAL messenger: every conversation is the internal tier; anything bridged/
// external is explicitly out of scope (it belongs to the Messenger's Bridges tab,
// never silently inside Bloch). Mirrored verbatim where the crate pins wording.
export const TIER = Object.freeze({
  // Mirror of postern_messenger::SecurityTier::InternalE2ee.badge()
  INTERNAL_E2EE_BADGE: "E2EE (Postern)",
  // Mirror of postern_messenger::SecurityTier::BridgedExternal.badge()
  BRIDGED_BADGE: "\u{26a0} Bridged — not E2EE",
});

/** Honest, non-overclaiming statement of what the E2EE core does and does NOT do. */
export const E2EE_FACTS = Object.freeze({
  source: "crates/postern-messenger (Matrix + vodozemac/Megolm, Apache-2.0; UNAUDITED here)",
  encrypted: [
    "Message BODIES in your Bloch channels and DMs are end-to-end encrypted with Megolm (via vodozemac).",
    "Your employer's server (homeserver) stores only ciphertext for message content — it cannot read the words.",
  ],
  notEncryptedOrVisible: [
    "METADATA is not hidden: the homeserver (and thus your org) can see that a conversation exists, " +
      "its members, and timestamps — who talks to whom and when.",
    "Megolm is CLASSICAL crypto (Curve25519), NOT post-quantum. Harvest-now-decrypt-later applies to " +
      "intercepted transport ciphertext.",
    "This build is a reference prototype: UNAUDITED, no persistence guarantees, no device verification (SAS) yet.",
  ],
});

/**
 * Build the full transparency model an employee sees. Combines E2EE facts,
 * the employer-visibility wrinkle, and the injected compliance disclosure.
 *
 * @param {object} [opts]
 * @param {object} [opts.injectedCompliance] window.PosternCommsCompliance (or double)
 * @param {object} [opts.gate] the resolved license gate (for org name / tier)
 */
export function buildTransparency(opts = {}) {
  const compliance = resolveComplianceDisclosure({ injected: opts.injectedCompliance });
  const gate = opts.gate || null;
  return Object.freeze({
    orgName: (gate && gate.orgName) || null,
    tier: (gate && gate.tier) || null,
    e2ee: E2EE_FACTS,
    // The honest employer wrinkle, straight from the enterprise privacy statement.
    employerVisibility: PRIVACY.employerVisibility,
    // What we refuse to claim — house style.
    refusals: [
      "Bloch is an EMPLOYER-RUN tool. We do NOT claim it is '100% private' from your employer.",
      ...PRIVACY.refusals,
    ],
    // Policy owned by the compliance layer (or the honest 'unknown' default).
    compliance,
    status: "Design / reference prototype — unaudited, pre-production. Adherence-by-design, not certified.",
  });
}

/**
 * The short, always-visible transparency BANNER string. It states, in one line,
 * what is E2EE and flags that retention/employer-visibility is governed by the
 * (injected) compliance disclosure — without hardcoding that policy.
 */
export function transparencyBanner(opts = {}) {
  const t = buildTransparency(opts);
  const who = t.orgName ? `${t.orgName}'s ` : "your employer's ";
  const policyClause = t.compliance.injected
    ? "Retention & employer-visibility for this deployment are disclosed in the panel."
    : "Retention & employer-visibility for this deployment are NOT disclosed in this build — ask your admin; do not assume nothing is retained.";
  return (
    `Bloch is ${who}internal messenger. Message BODIES are end-to-end encrypted (Megolm); ` +
    `METADATA (who/when/membership) is visible to the org. ${policyClause} Not a personal, employer-invisible app.`
  );
}

/** A compact plain-text rendering for logs / a text pane / the self-check. */
export function transparencyText(opts = {}) {
  const t = buildTransparency(opts);
  const bullet = (s) => `  • ${s}`;
  const lines = [
    "TRANSPARENCY — Bloch org messenger (Business edition, reference prototype)",
    "",
    "Banner:",
    "  " + transparencyBanner(opts),
    "",
    "End-to-end encrypted:",
    ...t.e2ee.encrypted.map(bullet),
    "",
    "NOT hidden / honest limits:",
    ...t.e2ee.notEncryptedOrVisible.map(bullet),
    "",
    "Employer visibility (the wrinkle a personal app does not have):",
    ...t.employerVisibility.map(bullet),
    "",
    `Compliance disclosure [source: ${t.compliance.source}]:`,
    bullet(t.compliance.summary),
    bullet("Retention: " + t.compliance.retention),
    ...t.compliance.employerVisible.map((s) => bullet("Employer can see: " + s)),
    ...t.compliance.notRetained.map((s) => bullet("Explicitly NOT retained: " + s)),
    "",
    "What we refuse to claim:",
    ...t.refusals.map(bullet),
    "",
    `Status: ${t.status}`,
  ];
  return lines.join("\n");
}

export default {
  TIER,
  E2EE_FACTS,
  buildTransparency,
  transparencyBanner,
  transparencyText,
};
