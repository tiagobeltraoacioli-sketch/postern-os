// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern Comms (Enterprise) — employee transparency text (the disclosure banner).
//
// STATUS: design / reference prototype. UNAUDITED. Pre-production. NOT LEGAL
// ADVICE — see COMPLIANCE.md. This is the honest, plain-language disclosure the
// app banner injects for every employee. Its ONE job: say exactly what the
// employer/admin CAN and CANNOT see, and on what lawful basis. No marketing, no
// "100% private", no burying the audit trail.
//
// It is generated FROM the data model so the words can never drift from what the
// system can technically do.

import { employerVisibilitySummary } from "./data-model.mjs";
import { retentionDisclosure } from "./retention.mjs";

/** Structured transparency notice (machine-readable) built from the data model. */
export function transparencyNotice({ orgName = "your employer", residency = "eu", retentionPolicy = null } = {}) {
  const vis = employerVisibilitySummary();
  return Object.freeze({
    schema: "postern.comms.transparency/1",
    heading: `About privacy on ${orgName}'s Postern Comms`,
    canSee: vis.canRead.map((d) => ({ what: d.label, why: d.why })),
    cannotSee: vis.cannotRead.map((d) => ({ what: d.label, why: d.why })),
    keyFacts: [
      "Your message content is end-to-end encrypted. Your employer and the operator hold only unreadable ciphertext — they cannot read what you write.",
      "Your employer CAN see routing metadata (who messaged whom, when, channel, size) because it is needed to deliver messages and prevent abuse. It is minimised and time-limited.",
      "There is a DISCLOSED audit trail of ADMIN actions (provisioning, policy changes, exports). It is employee-visible. There is NO covert monitoring, no content surveillance, no keystroke/screen logging.",
      "'Admin' is not 'access': an IT-admin role does not grant the ability to read your messages.",
      "You have data-subject rights (access, correction, deletion, portability, objection). Some — like exporting your encrypted message history — you exercise from your OWN client, because only your device can read that content.",
    ],
    lawfulBasis: [
      "Message routing metadata: legitimate interest (delivery, abuse-prevention).",
      "Directory identity: contract / legal obligation (employment record).",
      "Admin-audit trail: legal obligation / legitimate interest (accountability).",
      "Where a deployment relies on CONSENT, it must be freely given and revocable — note that in an employment context consent is often not 'freely given', so another basis usually applies.",
    ],
    residency,
    retention: retentionPolicy ? retentionDisclosure(retentionPolicy) : "See your org's published retention policy.",
    honestLimits: [
      "This is NOT a claim of '100% private' or 'unhackable' — no honest software claims that.",
      "This tooling is compliance-BY-DESIGN, not certified compliance. Your employer remains the data controller and is responsible for lawful use.",
      "Unaudited, pre-production reference software.",
    ],
    yourRights: {
      how: "Contact your org's DPO / privacy contact to exercise a right, or use in-client self-serve export for your encrypted history.",
      articles: "LGPD Art. 18; GDPR Arts. 15–22.",
    },
  });
}

/** A compact plain-text banner rendering for a text pane / log. */
export function transparencyText(opts = {}) {
  const n = transparencyNotice(opts);
  const L = [
    n.heading,
    "=".repeat(n.heading.length),
    "",
    "What your employer/operator CAN see:",
    ...n.canSee.map((d) => `  • ${d.what}  (basis: ${d.why})`),
    "",
    "What your employer/operator CANNOT see:",
    ...n.cannotSee.map((d) => `  • ${d.what}  (${d.why})`),
    "",
    "Key facts:",
    ...n.keyFacts.map((f) => `  • ${f}`),
    "",
    "Honest limits:",
    ...n.honestLimits.map((f) => `  • ${f}`),
    "",
    `Your rights: ${n.yourRights.how}`,
    `  (${n.yourRights.articles})`,
    "",
    `Data residency: ${n.residency}`,
  ];
  return L.join("\n");
}

export default { transparencyNotice, transparencyText };
