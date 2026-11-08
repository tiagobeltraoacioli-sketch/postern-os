// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern Comms (Enterprise) — data-subject rights engine.
//
// STATUS: design / reference prototype. UNAUDITED. Pre-production.
// NOT LEGAL ADVICE — see COMPLIANCE.md. Adherence-by-design is NOT certified
// compliance. This produces STRUCTURED, HONEST request-handling: it never claims
// to have produced data it cannot technically reach.
//
// COVERAGE
//   LGPD Art. 18 (confirmation, access, correction, anonymisation/blocking/
//     deletion, portability, information on sharing, revocation of consent,
//     objection) and GDPR Arts. 15–22 (access, rectification, erasure,
//     restriction, portability, objection, no solely-automated decisions).
//
// THE HONEST CORE
//   Every handler returns a `ServedResult` that separates:
//     served[]   — data classes actually fulfilled by the employer, and
//     refused[]  — data classes the employer CANNOT fulfil, with a plain reason
//                  (chiefly: E2EE content the employer cannot read) PLUS the
//                  self-serve path the employee CAN use themselves.
//   Refusing honestly is a feature, not a failure. Over-promising is the risk.

import {
  DATA_CLASSES,
  dataClass,
  classesEmployerCanServe,
  VISIBILITY,
} from "./data-model.mjs";

/** The rights this engine models, mapped to the governing articles. */
export const RIGHTS = Object.freeze({
  access: { lgpd: "Art. 18 II/III", gdpr: "Art. 15" },
  rectification: { lgpd: "Art. 18 III", gdpr: "Art. 16" },
  erasure: { lgpd: "Art. 18 IV/VI", gdpr: "Art. 17" }, // 'right to be forgotten'
  portability: { lgpd: "Art. 18 V", gdpr: "Art. 20" },
  objection: { lgpd: "Art. 18 §2 / Art. 21", gdpr: "Art. 21" },
  restriction: { lgpd: "Art. 18 IV (blocking)", gdpr: "Art. 18" },
  automatedDecision: { lgpd: "Art. 20", gdpr: "Art. 22" },
  consentRevocation: { lgpd: "Art. 8 §5 / Art. 18 IX", gdpr: "Art. 7(3)" },
});

/** Statutory-ish response deadlines (informational; jurisdictions vary — NOT legal advice). */
export const RESPONSE_WINDOWS = Object.freeze({
  // LGPD Art. 19: immediate (simplified) or 15 days (full declaration).
  lgpd_full_declaration_days: 15,
  // GDPR Art. 12(3): 1 month, extendable by 2 further months for complexity.
  gdpr_days: 30,
  gdpr_extension_days: 60,
});

/**
 * @typedef {Object} SubjectRequest
 * @property {string} requestId
 * @property {string} subjectId          the employee (data subject) id
 * @property {keyof RIGHTS} right
 * @property {string} [rectifyField]     for rectification: which directory field
 * @property {string} [rectifyValue]     for rectification: the corrected value
 * @property {string} requestedAt        ISO timestamp
 * @property {string} [verifiedIdentity] how the subject's identity was verified
 */

/**
 * @typedef {Object} ServedResult
 * @property {string} requestId
 * @property {keyof RIGHTS} right
 * @property {{lgpd:string,gdpr:string}} articles
 * @property {Array<{id:string,label:string,how:string}>} served
 * @property {Array<{id:string,label:string,reason:string,selfServe:string|null}>} refused
 * @property {string} dueBy              honest response-deadline note
 * @property {string[]} disclosures      plain-language honesty notes for the subject
 * @property {boolean} requiresLegalReview always true — this is not a legal determination
 */

function _articles(right) {
  const a = RIGHTS[right];
  if (!a) throw new Error(`unknown right: ${right}`);
  return a;
}

function _selfServeFor(dc) {
  if (dc.visibility === VISIBILITY.EMPLOYEE_ONLY_E2EE) {
    return (
      "Use your own client's 'Export my data' / local history feature: because " +
      "this is end-to-end encrypted, only YOUR device holds the keys to read it."
    );
  }
  return null;
}

function _dueBy(right) {
  if (right === "access" || right === "portability") {
    return `LGPD Art. 19: 15 days (full declaration). GDPR Art. 12(3): 1 month (+2 months if complex).`;
  }
  return `GDPR Art. 12(3): 1 month (+2 months if complex). LGPD: without undue delay. (Informational — not legal advice.)`;
}

/**
 * ACCESS (LGPD Art. 18 II/III, GDPR Art. 15) & the PRODUCE half of portability.
 * Returns what the employer can actually hand over vs. what only the subject can.
 * @param {SubjectRequest} req
 * @param {(dataClassId:string, subjectId:string)=>any} [fetcher] optional real reader
 * @returns {ServedResult}
 */
export function handleAccess(req, fetcher) {
  const { can, cannot } = classesEmployerCanServe("produce");
  const served = can.map((dc) => ({
    id: dc.id,
    label: dc.label,
    how: fetcher
      ? `Included: ${_describeFetch(fetcher, dc.id, req.subjectId)}`
      : "Employer holds this and includes it in the access package (attach real data via fetcher).",
  }));
  const refused = cannot.map((dc) => ({
    id: dc.id,
    label: dc.label,
    reason:
      dc.visibility === VISIBILITY.EMPLOYEE_ONLY_E2EE
        ? "End-to-end encrypted: the employer holds only ciphertext and cannot read plaintext to disclose it."
        : "Employer does not hold this in a producible form.",
    selfServe: _selfServeFor(dc),
  }));
  return _result(req, served, refused, [
    "This access package contains ONLY what the employer/operator actually holds.",
    "E2EE message content is not included because the employer cannot read it — this is the privacy design working, and you can export it yourself from your own client.",
  ]);
}

function _describeFetch(fetcher, id, subjectId) {
  try {
    const v = fetcher(id, subjectId);
    return v == null ? "no records" : `${Array.isArray(v) ? v.length + " records" : "record"}`;
  } catch {
    return "reader error (recorded honestly, not silently swallowed)";
  }
}

/**
 * RECTIFICATION (LGPD Art. 18 III, GDPR Art. 16).
 * @param {SubjectRequest} req
 * @param {(id:string, field:string, value:string, subjectId:string)=>void} [writer]
 * @returns {ServedResult}
 */
export function handleRectification(req, writer) {
  const { can, cannot } = classesEmployerCanServe("rectify");
  const served = [];
  const refused = [];
  for (const dc of can) {
    if (req.rectifyField && writer) {
      try {
        writer(dc.id, req.rectifyField, req.rectifyValue ?? "", req.subjectId);
        served.push({ id: dc.id, label: dc.label, how: `Corrected field '${req.rectifyField}'.` });
      } catch (e) {
        refused.push({ id: dc.id, label: dc.label, reason: `writer error: ${e.message}`, selfServe: null });
      }
    } else {
      served.push({
        id: dc.id,
        label: dc.label,
        how: "Correctable by the employer (supply rectifyField/rectifyValue + a writer to apply).",
      });
    }
  }
  for (const dc of cannot) {
    refused.push({
      id: dc.id,
      label: dc.label,
      reason:
        dc.visibility === VISIBILITY.EMPLOYEE_ONLY_E2EE
          ? "E2EE content: the employer cannot read it and therefore cannot correct it. You control the plaintext on your device."
          : dc.id.startsWith("message.metadata") || dc.id.startsWith("audit")
            ? "Factual event/audit records are append-only: they are annotated, not rewritten (integrity requirement)."
            : "Not rectifiable by the employer.",
      selfServe: _selfServeFor(dc),
    });
  }
  return _result(req, served, refused, [
    "Directory identity fields are the main thing rectification can fix.",
    "Event logs and the admin-audit trail are append-only for integrity: corrections are appended, never silently overwritten.",
  ]);
}

/**
 * ERASURE / right to be forgotten (LGPD Art. 18 IV/VI, GDPR Art. 17).
 * @param {SubjectRequest} req
 * @param {(id:string, subjectId:string)=>void} [eraser]
 * @returns {ServedResult}
 */
export function handleErasure(req, eraser) {
  const { can, cannot } = classesEmployerCanServe("erase");
  const served = can.map((dc) => {
    if (eraser) {
      try {
        eraser(dc.id, req.subjectId);
        return { id: dc.id, label: dc.label, how: "Deleted at source." };
      } catch (e) {
        return { id: dc.id, label: dc.label, how: `eraser error (recorded): ${e.message}` };
      }
    }
    return {
      id: dc.id,
      label: dc.label,
      how:
        dc.id === "message.content.e2ee"
          ? "Employer deletes the CIPHERTEXT blob (it never held plaintext)."
          : "Employer deletes this record (subject to any legal-hold / legal-obligation override).",
    };
  });
  const refused = cannot.map((dc) => ({
    id: dc.id,
    label: dc.label,
    reason:
      dc.id.startsWith("audit")
        ? "Admin-audit records are retained for the accountability window (legal-obligation / legitimate-interest) and are tamper-evident — erasing them would defeat their transparency purpose. Objection/restriction may apply instead."
        : "Not erasable by the employer.",
    selfServe: _selfServeFor(dc),
  }));
  return _result(req, served, refused, [
    "Erasure of E2EE content removes the ciphertext only — the employer never had the plaintext.",
    "Directory identity erasure MAY be overridden by an independent employment-record legal obligation; any such override must be documented (ROPA), not assumed.",
    "The disclosed admin-audit trail is retained for accountability and is NOT covertly erasable — this protects employees as much as the employer.",
  ]);
}

/**
 * PORTABILITY (LGPD Art. 18 V, GDPR Art. 20) — a structured export.
 * @param {SubjectRequest} req
 * @param {(dataClassId:string, subjectId:string)=>any} [fetcher]
 * @returns {ServedResult & {export:{format:string, schemaHint:string}}}
 */
export function handlePortability(req, fetcher) {
  const base = handleAccess({ ...req, right: "portability" }, fetcher);
  // `base` is a frozen ServedResult — extend it into a fresh frozen object rather
  // than mutating it (Object.assign on the frozen base throws; keep it immutable).
  return Object.freeze({
    ...base,
    export: {
      format: "application/json (machine-readable, structured; schemas/export.schema.json)",
      schemaHint:
        "Employer-served export = metadata + directory only. E2EE message CONTENT " +
        "must be exported by the employee from their own client (self-serve path).",
    },
  });
}

/**
 * OBJECTION (LGPD Art. 18 §2 / Art. 21, GDPR Art. 21) and
 * RESTRICTION/BLOCKING (LGPD Art. 18 IV, GDPR Art. 18).
 * These do not delete data; they FLAG a processing purpose to stop/limit.
 * @param {SubjectRequest} req
 * @param {(subjectId:string, mode:"object"|"restrict")=>void} [flagger]
 * @returns {ServedResult & {mode:string}}
 */
export function handleObjectionOrRestriction(req, flagger) {
  const mode = req.right === "restriction" ? "restrict" : "object";
  if (flagger) {
    try {
      flagger(req.subjectId, mode);
    } catch (e) {
      /* recorded in disclosures */
    }
  }
  const served = DATA_CLASSES.filter(
    (d) => d.visibility === VISIBILITY.OPERATOR_METADATA || d.visibility === VISIBILITY.ADMIN_CONFIG,
  ).map((dc) => ({
    id: dc.id,
    label: dc.label,
    how: mode === "restrict" ? "Processing restricted/blocked pending review." : "Objection recorded; processing paused where not overridden by a compelling legitimate ground.",
  }));
  const refused = DATA_CLASSES.filter((d) => d.id.startsWith("audit")).map((dc) => ({
    id: dc.id,
    label: dc.label,
    reason: "Accountability logging cannot be objected away — but note it records only disclosed admin acts, never message content.",
    selfServe: null,
  }));
  const out = _result(req, served, refused, [
    "Objection/restriction flags a purpose to stop or limit processing; it is not deletion.",
    "An objection may be overridden only by a compelling legitimate ground that the controller must document.",
  ]);
  // `out` is a frozen ServedResult — extend into a fresh frozen object (see handlePortability).
  return Object.freeze({ ...out, mode });
}

/**
 * Route any request to the right handler.
 * @param {SubjectRequest} req
 * @param {Object} [io] optional {fetcher, writer, eraser, flagger}
 */
export function handle(req, io = {}) {
  switch (req.right) {
    case "access":
      return handleAccess(req, io.fetcher);
    case "rectification":
      return handleRectification(req, io.writer);
    case "erasure":
      return handleErasure(req, io.eraser);
    case "portability":
      return handlePortability(req, io.fetcher);
    case "objection":
    case "restriction":
      return handleObjectionOrRestriction(req, io.flagger);
    case "consentRevocation":
      return _result(req, [], [], [
        "Consent revocation is honoured going forward; processing that relied on consent stops.",
        "Processing under a DIFFERENT lawful basis (e.g. legal obligation for employment records) is unaffected — which basis applied must be stated in the ROPA.",
      ]);
    case "automatedDecision":
      return _result(req, [], [], [
        "This comms app makes NO solely-automated decisions producing legal/significant effects about employees (LGPD Art. 20 / GDPR Art. 22).",
        "If a deployment adds any such processing, it MUST be disclosed here and offer human review.",
      ]);
    default:
      throw new Error(`unknown right: ${req.right}`);
  }
}

/** Build the common ServedResult envelope. */
function _result(req, served, refused, disclosures) {
  return Object.freeze({
    requestId: req.requestId,
    right: req.right,
    articles: _articles(req.right),
    served: Object.freeze(served),
    refused: Object.freeze(refused),
    dueBy: _dueBy(req.right),
    disclosures: Object.freeze([
      ...disclosures,
      "This is compliance-by-design tooling, NOT a legal determination. A DPO / legal review is required before acting.",
    ]),
    requiresLegalReview: true,
  });
}

export default {
  RIGHTS,
  RESPONSE_WINDOWS,
  handle,
  handleAccess,
  handleRectification,
  handleErasure,
  handlePortability,
  handleObjectionOrRestriction,
};
