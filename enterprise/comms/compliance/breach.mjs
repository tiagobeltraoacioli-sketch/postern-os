// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern Comms (Enterprise) — breach-notification hook.
//
// STATUS: design / reference prototype. UNAUDITED. Pre-production. NOT LEGAL
// ADVICE — see COMPLIANCE.md. This does NOT decide whether a breach is
// notifiable — that is a legal + risk judgement for the controller/DPO. It
// STRUCTURES the facts, computes the honest clock, and produces a draft the DPO
// reviews and sends. It notifies nobody automatically.
//
// FRAMEWORKS
//   GDPR Art. 33: notify the supervisory authority "without undue delay and,
//     where feasible, not later than 72 HOURS" after becoming aware, unless the
//     breach is unlikely to result in a risk to rights & freedoms.
//   GDPR Art. 34: notify affected data subjects "without undue delay" when the
//     breach is likely to result in a HIGH risk.
//   LGPD Art. 48: notify the ANPD and affected subjects "within a reasonable
//     time" (ANPD guidance references a short window; treat 72h as the working
//     target, but the statutory text differs — legal review required).
//
// THE E2EE MITIGATION, STATED HONESTLY
//   If only CIPHERTEXT was exposed and keys were NOT, the risk to message CONTENT
//   is materially reduced — a factor Art. 34/34(3)(a) recognises. This module
//   surfaces that factor but never concludes "no notice needed": that is a legal
//   call. Metadata exposure can still be high-risk even when content is encrypted.

/** @typedef {"content-plaintext"|"content-ciphertext-only"|"metadata"|"directory"|"credentials"|"keys"} ExposedClass */

/**
 * Assemble a breach record + a notification DRAFT. Sends nothing.
 * @param {Object} b
 * @param {string} b.detectedAt         ISO — when the org became AWARE
 * @param {ExposedClass[]} b.exposed     which data classes were exposed
 * @param {number} b.affectedSubjects
 * @param {string} b.description
 * @param {string} [b.residency]         "eu"|"br"|"self-hosted" → which authority
 * @param {Date} [now]
 */
export function assessBreach(b, now = new Date()) {
  const detected = new Date(b.detectedAt);
  const deadline72h = new Date(detected.getTime() + 72 * 3_600_000);
  const hoursElapsed = (now.getTime() - detected.getTime()) / 3_600_000;
  const hoursRemaining = (deadline72h.getTime() - now.getTime()) / 3_600_000;

  const keysExposed = b.exposed.includes("keys");
  const plaintextExposed = b.exposed.includes("content-plaintext");
  const ciphertextOnly =
    b.exposed.includes("content-ciphertext-only") && !plaintextExposed && !keysExposed;

  const riskFactors = [];
  if (plaintextExposed) riskFactors.push("HIGH: message plaintext exposed.");
  if (keysExposed) riskFactors.push("HIGH: encryption keys exposed — ciphertext must be treated as readable.");
  if (ciphertextOnly)
    riskFactors.push(
      "MITIGATION: only ciphertext exposed and keys NOT exposed — content confidentiality is materially preserved (GDPR Art. 34(3)(a) factor). NOT a legal conclusion.",
    );
  if (b.exposed.includes("metadata"))
    riskFactors.push("Metadata exposed — can still be high-risk (who-talked-to-whom) even with content encrypted.");
  if (b.exposed.includes("directory")) riskFactors.push("Directory identity exposed — identity/contact data.");
  if (b.exposed.includes("credentials")) riskFactors.push("HIGH: credentials exposed — force reset.");

  const authority =
    b.residency === "br"
      ? "ANPD (Autoridade Nacional de Proteção de Dados, Brazil) — LGPD Art. 48"
      : b.residency === "self-hosted"
        ? "The controller's competent supervisory authority (customer-determined)"
        : "The lead EU supervisory authority (DPA) — GDPR Art. 33";

  return Object.freeze({
    schema: "postern.comms.breach/1",
    detectedAt: b.detectedAt,
    clock: {
      target: "72h working target (GDPR Art. 33; LGPD Art. 48 wording differs — legal review required)",
      deadline72h: deadline72h.toISOString(),
      hoursElapsed: Math.round(hoursElapsed * 10) / 10,
      hoursRemaining: Math.round(hoursRemaining * 10) / 10,
      overdue: hoursRemaining < 0,
    },
    riskFactors,
    ciphertextMitigationApplies: ciphertextOnly,
    authorityToNotify: authority,
    subjectNotificationLikelyRequired: plaintextExposed || keysExposed || b.exposed.includes("credentials"),
    draft: _draft(b, authority, deadline72h),
    disclaimer:
      "This is a STRUCTURED DRAFT, not a determination. Whether, when, and whom to notify is a legal decision for the controller/DPO. Nothing was sent automatically.",
    requiresLegalReview: true,
  });
}

function _draft(b, authority, deadline) {
  return [
    `TO: ${authority}`,
    `SUBJECT: Personal data breach notification (draft — DPO review required)`,
    "",
    `1. Nature of the breach: ${b.description}`,
    `2. Categories of data affected: ${b.exposed.join(", ")}`,
    `3. Approx. number of data subjects affected: ${b.affectedSubjects}`,
    `4. Awareness timestamp: ${b.detectedAt}`,
    `5. 72h working deadline: ${deadline.toISOString()}`,
    `6. Likely consequences: [DPO to complete — see risk factors].`,
    `7. Measures taken/proposed: [DPO to complete].`,
    `8. DPO / contact point: [org DPO contact].`,
    "",
    "NOTE: If exposure was ciphertext-only with keys intact, state that mitigation explicitly and its bearing on subject-notification risk (Art. 34(3)(a)).",
  ].join("\n");
}

export default { assessBreach };
