// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern Comms (Enterprise) — compliance data model & E2EE visibility map.
//
// STATUS: design / reference prototype. UNAUDITED. Pre-production. NOT LEGAL
// ADVICE — see COMPLIANCE.md. This file is compliance-BY-DESIGN tooling, not a
// certification and not a substitute for legal review + a real audit.
//
// WHAT THIS IS
// ------------
// The compliance layer does NOT own the messaging app. The app lives in
// `enterprise/comms/app/` and is owned by another developer. This module is the
// *contract* between the two: a declared, honest catalogue of every DATA CLASS
// the app is expected to hold, and — for each — WHO can actually read it. The
// rights engine, retention engine, audit trail and transparency text all read
// from this single source of truth so that no disclosure can silently drift from
// what the system can technically do.
//
// The single most important honest fact encoded here:
//   E2EE MESSAGE CONTENT is opaque to the employer/admin/operator. What the
//   employer cannot read, the employer CANNOT produce, rectify, or export on an
//   employee's behalf. A data-subject access request served BY THE EMPLOYER can
//   only return what the employer actually holds. This is disclosed, not hidden.

/**
 * Visibility levels — who can technically read a data class in cleartext.
 * These describe *capability*, not *policy*. Policy (retention, access control)
 * is layered on top; capability is the floor the disclosures must never oversell.
 * @typedef {"employee-only-e2ee"|"operator-metadata"|"admin-config"|"shared"} Visibility
 */

/**
 * @typedef {Object} DataClass
 * @property {string} id                 stable machine id
 * @property {string} label              human label
 * @property {Visibility} visibility     who can read it in cleartext
 * @property {string} lawfulBasisHint    LGPD/GDPR lawful-basis hint (NOT legal advice)
 * @property {boolean} employerCanProduce can the EMPLOYER fulfil an access/export request for this?
 * @property {boolean} employerCanRectify can the EMPLOYER edit/correct it?
 * @property {boolean} employerCanErase   can the EMPLOYER delete it at source?
 * @property {string} residency          which residency bucket it lives in (see residency.config.json)
 * @property {string} notes              honest limits / caveats
 */

/** Visibility constants. */
export const VISIBILITY = Object.freeze({
  /** Encrypted end-to-end; only the participating employees hold keys. */
  EMPLOYEE_ONLY_E2EE: "employee-only-e2ee",
  /** Server-side metadata the operator/host necessarily processes to route. */
  OPERATOR_METADATA: "operator-metadata",
  /** Admin/org configuration and directory data the org authored. */
  ADMIN_CONFIG: "admin-config",
  /** Visible to both the employee and the operator by design (e.g. audit of admin acts). */
  SHARED: "shared",
});

/**
 * The declared data model of the comms app, from the compliance layer's point
 * of view. This is the honest inventory a ROPA and every DSAR is built on.
 *
 * NOTE ON HONESTY: `employerCanProduce/Rectify/Erase = false` for E2EE content is
 * not a limitation we are apologising for — it is the privacy property working as
 * intended. The transparency text says so plainly to every employee.
 *
 * @type {ReadonlyArray<DataClass>}
 */
export const DATA_CLASSES = Object.freeze([
  {
    id: "message.content.e2ee",
    label: "Message body & attachments (end-to-end encrypted)",
    visibility: VISIBILITY.EMPLOYEE_ONLY_E2EE,
    lawfulBasisHint: "employment-context / legitimate-interest (comms), consent where required",
    employerCanProduce: false,
    employerCanRectify: false,
    employerCanErase: false, // employer can delete CIPHERTEXT at rest; cannot read/alter plaintext
    residency: "message-store",
    notes:
      "Employer/operator holds only ciphertext. Cannot read, correct, or export " +
      "plaintext. A subject's own device/client CAN export their own history " +
      "(see rights engine `portability` self-serve path). Employer erasure deletes " +
      "the ciphertext blob only.",
  },
  {
    id: "message.metadata",
    label: "Message metadata (sender, recipient, channel, timestamp, size)",
    visibility: VISIBILITY.OPERATOR_METADATA,
    lawfulBasisHint: "legitimate-interest (delivery/routing/abuse-prevention)",
    employerCanProduce: true,
    employerCanRectify: false, // factual event records are not 'corrected', they are annotated
    employerCanErase: true,
    residency: "metadata-store",
    notes:
      "Necessary to route and deliver. Minimised: no message body, no read-receipt " +
      "content. Retention windows apply (see retention-policy.json). This is the " +
      "MAIN thing an employer-served access request can actually return.",
  },
  {
    id: "directory.identity",
    label: "Directory identity (name, work email, team, role, employee id)",
    visibility: VISIBILITY.ADMIN_CONFIG,
    lawfulBasisHint: "contract / legal-obligation (employment record)",
    employerCanProduce: true,
    employerCanRectify: true,
    employerCanErase: true, // subject to overriding employment-record legal retention
    residency: "directory-store",
    notes:
      "Authored by the org. Rectification is straightforward here. Erasure may be " +
      "overridden by an independent employment-record legal-obligation — that " +
      "override must be documented in the ROPA, not assumed.",
  },
  {
    id: "presence.status",
    label: "Presence & status (online/away, custom status text)",
    visibility: VISIBILITY.OPERATOR_METADATA,
    lawfulBasisHint: "legitimate-interest (collaboration)",
    employerCanProduce: true,
    employerCanRectify: true,
    employerCanErase: true,
    residency: "metadata-store",
    notes:
      "Ephemeral by default; minimisation default is NOT to log presence history. " +
      "If a deployment enables presence history it MUST be disclosed + retention-bound.",
  },
  {
    id: "audit.admin-action",
    label: "Admin-action audit record (provisioning, policy change, export, legal hold)",
    visibility: VISIBILITY.SHARED,
    lawfulBasisHint: "legal-obligation / legitimate-interest (accountability)",
    employerCanProduce: true,
    employerCanRectify: false, // append-only integrity — never rewritten
    employerCanErase: false, // tamper-evident; retained for the accountability window
    residency: "audit-store",
    notes:
      "DISCLOSED and employee-VISIBLE by design (see audit-trail.mjs). Records WHO " +
      "did WHICH admin act, never covert content surveillance. Append-only + " +
      "tamper-evident; not user-erasable because its purpose is accountability.",
  },
  {
    id: "device.managed-config",
    label: "Managed device/app configuration pushed by the org",
    visibility: VISIBILITY.ADMIN_CONFIG,
    lawfulBasisHint: "legitimate-interest (IT administration)",
    employerCanProduce: true,
    employerCanRectify: true,
    employerCanErase: true,
    residency: "directory-store",
    notes: "Additive org config only. Never reads personal-app data (org-policy rail).",
  },
]);

/** Index for O(1) lookup. */
const _byId = Object.freeze(
  Object.fromEntries(DATA_CLASSES.map((d) => [d.id, d])),
);

/** @param {string} id */
export function dataClass(id) {
  return _byId[id] || null;
}

/**
 * The employer-visibility summary the transparency banner is built from.
 * Returns a plain, honest partition: what the employer CAN and CANNOT read.
 */
export function employerVisibilitySummary() {
  const canRead = [];
  const cannotRead = [];
  for (const d of DATA_CLASSES) {
    if (d.visibility === VISIBILITY.EMPLOYEE_ONLY_E2EE) cannotRead.push(d);
    else canRead.push(d);
  }
  return Object.freeze({
    canRead: canRead.map((d) => ({ id: d.id, label: d.label, why: d.lawfulBasisHint })),
    cannotRead: cannotRead.map((d) => ({ id: d.id, label: d.label, why: "end-to-end encrypted" })),
  });
}

/**
 * Which data classes an EMPLOYER-served request can satisfy for a given right.
 * The rights engine uses this to refuse honestly rather than over-promise.
 * @param {"produce"|"rectify"|"erase"} action
 */
export function classesEmployerCanServe(action) {
  const key =
    action === "produce"
      ? "employerCanProduce"
      : action === "rectify"
        ? "employerCanRectify"
        : "employerCanErase";
  const can = DATA_CLASSES.filter((d) => d[key]);
  const cannot = DATA_CLASSES.filter((d) => !d[key]);
  return Object.freeze({ can, cannot });
}

export default {
  VISIBILITY,
  DATA_CLASSES,
  dataClass,
  employerVisibilitySummary,
  classesEmployerCanServe,
};
