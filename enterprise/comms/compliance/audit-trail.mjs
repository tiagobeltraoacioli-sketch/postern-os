// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern Comms (Enterprise) — lawful, DISCLOSED, employee-visible audit trail.
//
// STATUS: design / reference prototype. UNAUDITED. Pre-production. NOT LEGAL
// ADVICE — see COMPLIANCE.md.
//
// THE RAIL THAT NEVER BENDS: NO COVERT SURVEILLANCE.
//   This audit trail records ADMIN ACTIONS ONLY (provisioning, policy changes,
//   exports, legal holds, DSAR handling). It NEVER records message content, never
//   reads E2EE plaintext, never logs an employee's private activity. Every record
//   is employee-VISIBLE by design — an employee can see who did which admin act
//   affecting them. If it can't be shown to the employee, it doesn't get logged.
//
//   This is the honest inverse of covert monitoring: the audit trail exists to
//   hold ADMINS accountable, and it protects employees as much as the employer.
//
// It is append-only and tamper-evident via a simple hash chain (SHA-256 over the
// previous record's hash + the canonical record). This uses Node's built-in
// `crypto` only — no third-party dependency. Integrity != confidentiality: the
// chain proves records weren't altered, it is not a secrecy mechanism.

import { createHash } from "node:crypto";

/** The only event types this trail is allowed to record. Content events are absent BY DESIGN. */
export const ALLOWED_EVENTS = Object.freeze([
  "admin.provision-user",
  "admin.deprovision-user",
  "admin.policy-change",
  "admin.data-export", // e.g. serving a DSAR — logged so the subject can see it happened
  "admin.legal-hold-set",
  "admin.legal-hold-release",
  "admin.dsar-received",
  "admin.dsar-served",
  "admin.retention-run",
  "admin.residency-change",
  "admin.breach-declared",
]);

/** Events that are explicitly FORBIDDEN — attempting them throws. */
const FORBIDDEN_PATTERNS = [/message\.content/i, /read.?receipt/i, /keystroke/i, /screen/i, /location/i, /content\.read/i];

const GENESIS = "0".repeat(64);

function _canonical(rec) {
  // Stable key order for a deterministic hash.
  return JSON.stringify({
    seq: rec.seq,
    ts: rec.ts,
    actor: rec.actor,
    event: rec.event,
    subject: rec.subject ?? null,
    detail: rec.detail ?? null,
    prev: rec.prev,
  });
}

function _hash(rec) {
  return createHash("sha256").update(_canonical(rec)).digest("hex");
}

/**
 * A disclosed, append-only, tamper-evident admin-audit trail.
 * Construct with an existing chain (e.g. loaded from the app's store) or empty.
 */
export class AuditTrail {
  /** @param {Array<object>} [existing] */
  constructor(existing = []) {
    /** @type {Array<object>} */
    this.records = existing.slice();
  }

  /** @returns {string} hash of the last record, or GENESIS. */
  head() {
    return this.records.length ? this.records[this.records.length - 1].hash : GENESIS;
  }

  /**
   * Append a disclosed admin-action record. Throws on any forbidden/covert event.
   * @param {{actor:string, event:string, subject?:string, detail?:object}} e
   * @param {Date} [now]
   * @returns {object} the appended record
   */
  append(e, now = new Date()) {
    if (!ALLOWED_EVENTS.includes(e.event))
      throw new Error(`audit: event '${e.event}' is not in the allow-list — covert/unknown events are refused`);
    const blob = JSON.stringify(e.detail ?? {});
    for (const p of FORBIDDEN_PATTERNS)
      if (p.test(e.event) || p.test(blob))
        throw new Error(`audit: refused — record resembles content/surveillance (${p}); this trail is admin-acts only`);
    const rec = {
      seq: this.records.length,
      ts: now.toISOString(),
      actor: e.actor,
      event: e.event,
      subject: e.subject ?? null,
      detail: e.detail ?? null,
      prev: this.head(),
      employeeVisible: true, // always — no covert records
    };
    rec.hash = _hash(rec);
    this.records.push(rec);
    return rec;
  }

  /** Verify the whole chain is intact. @returns {{ok:boolean, brokenAt:number|null}} */
  verify() {
    let prev = GENESIS;
    for (const rec of this.records) {
      if (rec.prev !== prev) return { ok: false, brokenAt: rec.seq };
      const { hash, employeeVisible, ...core } = rec;
      if (_hash(core) !== hash) return { ok: false, brokenAt: rec.seq };
      prev = rec.hash;
    }
    return { ok: true, brokenAt: null };
  }

  /**
   * The employee-facing view: every admin act touching a given subject.
   * This is the transparency guarantee — the subject can always see it.
   * @param {string} subjectId
   */
  visibleTo(subjectId) {
    return this.records
      .filter((r) => r.subject === subjectId || r.event === "admin.policy-change" || r.event === "admin.residency-change")
      .map((r) => ({ ts: r.ts, actor: r.actor, event: r.event, detail: r.detail }));
  }
}

export default { AuditTrail, ALLOWED_EVENTS };
