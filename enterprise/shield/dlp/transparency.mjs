// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Bloch Shield (Enterprise) — DLP employee transparency text (the container banner).
//
// STATUS: design / reference prototype. UNAUDITED. Pre-production. NOT LEGAL
// ADVICE — see COMPLIANCE.md. This is the honest, plain-language disclosure the
// container banner shows every employee. Its ONE job: say exactly WHAT is traced
// (corporate data sent to third parties) and WHAT IS NOT (anything personal), and
// on what lawful basis — no marketing, no "100% private", no buried surveillance.
//
// Generated FROM the classification model + the audit trail's allow-list so the
// words can never drift from what the system can technically do. If the trail
// only holds corporate-egress records, the banner can only truthfully say so.

import { CLASSES, PERSONAL } from "./classification.mjs";
import { ALLOWED_EVENTS } from "./audit-trail.mjs";

/** Structured transparency notice (machine-readable), built from the model. */
export function transparencyNotice({ orgName = "your employer", residency = "eu" } = {}) {
  return Object.freeze({
    schema: "bloch.shield.dlp.transparency/1",
    heading: `About what ${orgName}'s Bloch Shield traces on this device`,

    // Exactly what IS traced — derived from the trail's single allowed event.
    tracked: [
      {
        what: "Corporate data you send OUT to a third party",
        detail:
          "When data classified as CORPORATE (public, internal, confidential, or " +
          "restricted) leaves the work container to an outside party, one record is " +
          "kept: which work identity sent it, which class, which destination, when, " +
          "and whether policy allowed / warned / blocked it.",
        events: ALLOWED_EVENTS.slice(),
        classes: CLASSES.map((c) => c.id),
        basis: "legal-obligation / legitimate-interest (data-loss prevention, accountability)",
      },
    ],

    // Exactly what is NEVER traced — the red line, stated plainly.
    notTracked: [
      "Your PERSONAL activity — full stop. Not your personal apps, messages, " +
        "browsing, files, photos, location, keystrokes, screen, clipboard, camera, " +
        "or microphone.",
      "Anything you do OUTSIDE the corporate scope. If it is not corporate data " +
        "leaving to a third party, it is not in this trail — the system REFUSES to " +
        "record it (a personal-shaped record throws an error, it is not a setting).",
      "The CONTENT of the corporate data itself is not copied into the trail — " +
        "only that a piece of that class went to that destination.",
    ],

    keyFacts: [
      "This trace is CORPORATE-SCOPE ONLY. It exists to stop corporate data " +
        "loss, not to watch you. It protects you too: it is the proof that the " +
        "scope is limited to work data going outside.",
      "It is DISCLOSED and employee-visible: you can see every corporate-egress " +
        "record attributed to your work identity. There is no hidden second log.",
      "It is append-only and tamper-evident (a hash chain). That is for " +
        "integrity/accountability — it is not a claim of secrecy or of being " +
        "'unhackable'.",
      `${PERSONAL.label}: recognised by the system only so it can be LEFT ALONE.`,
    ],

    lawfulBasis: [
      "Corporate third-party egress records: legal-obligation / legitimate-interest " +
        "(preventing loss of the employer's own confidential data). LGPD Art. 7 X / " +
        "GDPR Art. 6(1)(f), balanced against your rights.",
      "On a BYOD (bring-your-own-device) deployment the corporate/personal split " +
        "is the whole point: only the corporate container is in scope. Your personal " +
        "partition is never processed.",
      "Where a deployment leans on CONSENT, note that in an employment context " +
        "consent is often NOT 'freely given' (LGPD Art. 8 / GDPR recital 43), so a " +
        "legitimate-interest or legal-obligation basis — with this disclosure — " +
        "usually applies instead. That is a decision for your employer's DPO, not " +
        "this tool.",
    ],

    residency,

    honestLimits: [
      "This is NOT a claim of '100% private', 'fully secure', or 'unhackable' — no " +
        "honest software claims that.",
      "This tooling is compliance-BY-DESIGN, not certified compliance. Your " +
        "employer remains the data controller and is responsible for lawful use.",
      "Unaudited, pre-production reference software.",
    ],

    yourRights: {
      how:
        "Contact your org's DPO / privacy contact to exercise a data-subject right, " +
        "or ask to see the corporate-egress records attributed to your work identity.",
      articles: "LGPD Art. 18; GDPR Arts. 15–22.",
    },
  });
}

/** Compact plain-text banner rendering, for a text pane / container banner. */
export function transparencyText(opts = {}) {
  const n = transparencyNotice(opts);
  const L = [
    n.heading,
    "=".repeat(n.heading.length),
    "",
    "WHAT IS TRACED (corporate data leaving to third parties):",
    ...n.tracked.map((t) => `  • ${t.what}\n      ${t.detail}  (basis: ${t.basis})`),
    "",
    "WHAT IS NEVER TRACED:",
    ...n.notTracked.map((s) => `  • ${s}`),
    "",
    "Key facts:",
    ...n.keyFacts.map((f) => `  • ${f}`),
    "",
    "Lawful basis (BYOD / LGPD / GDPR):",
    ...n.lawfulBasis.map((f) => `  • ${f}`),
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
