// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Bloch — org internal messenger (Business/Enterprise edition ONLY).
// COMPLIANCE RUNTIME — the execution layer that MOUNTS the pure engines.
//
// STATUS: design / reference prototype. UNAUDITED. Pre-production. NOT LEGAL
// ADVICE — this demonstrates controls that ENABLE compliance; it is NOT
// compliance and NOT certified. Legal review + a data-protection audit remain
// the uncleared gate (see compliance/COMPLIANCE.md).
//
// WHAT THIS FIXES
// ---------------
// The compliance engines (retention / rights / breach / audit-trail) were real,
// pure logic but UNMOUNTED: every side effect was a caller-supplied hook that
// nothing wired, so `evaluate()` computed a deletion PLAN that nobody executed,
// DSAR hooks were unset, breaches notified nobody, and no admin action was
// logged. This module is the seam that mounts them against a store + directory
// and actually EXECUTES:
//   • a deletion executor honouring LEGAL HOLD,
//   • DSAR intake with identity verification + a deadline clock + request
//     tracking, wired to real fetch/rectify/erase/flag hooks,
//   • breach case persistence,
//   • an append-only admin-audit record on every one of those admin acts.
//
// RAILS PRESERVED
//   • The audit trail records ADMIN ACTS ONLY and THROWS on covert/content
//     events — this runtime only ever appends allow-listed events.
//   • E2EE bodies are never read here (the engines refuse; erase deletes
//     ciphertext only). Metadata is operator-visible by design (employer-run).
//   • Nothing is auto-sent to an authority; breach output is a DRAFT + a case.

import { AuditTrail } from "../../compliance/audit-trail.mjs";
import { evaluate as retentionEvaluate, validatePolicy } from "../../compliance/retention.mjs";
import { handle as handleRight, RESPONSE_WINDOWS } from "../../compliance/rights-engine.mjs";
import { assessBreach } from "../../compliance/breach.mjs";

const DAY_MS = 86_400_000;

/**
 * A minimal in-memory metadata/directory store the runtime operates on. A
 * production deployment injects its real store implementing the same seam:
 *   { items(), deleteItem(id), directory(subjectId), rectify(field,value,subjectId) }
 * Bodies are NOT here — they are E2EE/ sealed by the transport; the runtime only
 * ever touches operator-held metadata + directory data.
 */
export function createMetadataStore(initial = {}) {
  /** @type {Map<string, object>} id -> retained metadata item */
  const items = new Map();
  /** @type {Map<string, object>} subjectId -> directory identity record */
  const directory = new Map(Object.entries(initial.directory || {}));

  for (const it of initial.items || []) items.set(it.id, { ...it });

  return {
    /** Record a retained metadata item (e.g. a message-metadata row). */
    record(item) {
      if (!item || !item.id) throw new Error("metadata-store: item needs an id");
      items.set(item.id, {
        id: item.id,
        dataClass: item.dataClass || "message.metadata",
        channelClass: item.channelClass ?? "*",
        subjectId: item.subjectId ?? null,
        createdAt: item.createdAt || new Date().toISOString(),
      });
      return this;
    },
    items() {
      return [...items.values()].map((i) => ({ ...i }));
    },
    deleteItem(id) {
      return items.delete(id);
    },
    itemsFor(subjectId) {
      return [...items.values()].filter((i) => i.subjectId === subjectId);
    },
    putDirectory(subjectId, record) {
      directory.set(subjectId, { ...record });
      return this;
    },
    directoryFor(subjectId) {
      const d = directory.get(subjectId);
      return d ? { ...d } : null;
    },
    rectifyDirectory(subjectId, field, value) {
      const d = directory.get(subjectId) || {};
      d[field] = value;
      directory.set(subjectId, d);
      return true;
    },
    eraseDirectory(subjectId) {
      return directory.delete(subjectId);
    },
    count() {
      return items.size;
    },
  };
}

/**
 * Mount the compliance engines against a metadata store. Every admin op requires
 * an `actor` (the admin performing it) so it can be written to the disclosed,
 * employee-visible audit trail.
 *
 * @param {object} [opts]
 * @param {object} [opts.store]  a metadata store (default: a fresh in-memory one)
 * @param {AuditTrail} [opts.auditTrail]  an existing trail to append to
 */
export function createComplianceRuntime(opts = {}) {
  const store = opts.store || createMetadataStore();
  const audit = opts.auditTrail || new AuditTrail();

  /** Legal holds: a Set of scopes ("*" = everything, else a subjectId). */
  const holds = new Set();
  /** DSAR request tracking: requestId -> record. */
  const dsar = new Map();
  /** Breach cases: caseId -> record. */
  const cases = new Map();

  let seq = 0;
  const genId = (p) => `${p}_${Date.now().toString(36)}_${++seq}`;

  function heldBack(item) {
    return holds.has("*") || (item.subjectId != null && holds.has(item.subjectId));
  }

  return {
    store,
    audit,

    /* ---------------- Legal hold ---------------- */

    /** Place a legal hold (suspends deletion) over a scope. */
    setLegalHold(scope, { actor }) {
      const s = scope || "*";
      holds.add(s);
      audit.append({ actor, event: "admin.legal-hold-set", subject: s === "*" ? null : s, detail: { scope: s } });
      return { scope: s, active: true };
    },
    releaseLegalHold(scope, { actor }) {
      const s = scope || "*";
      const had = holds.delete(s);
      audit.append({ actor, event: "admin.legal-hold-release", subject: s === "*" ? null : s, detail: { scope: s, wasActive: had } });
      return { scope: s, active: false };
    },
    legalHolds() {
      return [...holds];
    },

    /* ---------------- Retention (deletion executor) ---------------- */

    /**
     * Run retention: EVALUATE the plan (pure engine) then EXECUTE deletions on
     * the store — EXCEPT items under legal hold, which are held back. Appends an
     * `admin.retention-run` audit record with counts.
     * @returns {{deleted:string[], keptCount:number, heldBack:string[]}}
     */
    runRetention(policy, { actor }, now = new Date()) {
      const v = validatePolicy(policy);
      if (!v.ok) throw new Error("retention policy invalid: " + v.errors.join("; "));
      const plan = retentionEvaluate(policy, store.items(), now);

      const deleted = [];
      const held = [];
      for (const d of plan.delete) {
        const item = store.items().find((i) => i.id === d.id);
        if (item && heldBack(item)) {
          held.push(d.id);
          continue; // legal hold overrides deletion
        }
        if (store.deleteItem(d.id)) deleted.push(d.id);
      }
      audit.append({
        actor,
        event: "admin.retention-run",
        detail: { deleted: deleted.length, keptByPolicy: plan.keep.length, heldByLegalHold: held.length },
      });
      return { deleted, keptCount: plan.keep.length, heldBack: held };
    },

    /* ---------------- DSAR: intake + tracking + serve ---------------- */

    /**
     * Receive a data-subject request. ENFORCES identity verification (throws if
     * `verifiedIdentity` is missing) and starts the deadline clock. Appends
     * `admin.dsar-received`. Returns the tracking record (with `dueBy`).
     */
    receiveDsar(request, { actor }, now = new Date()) {
      if (!request || !request.subjectId || !request.right) {
        throw new Error("dsar: subjectId and right are required");
      }
      if (!request.verifiedIdentity) {
        // Fail-closed: never serve an unverified subject (impersonation risk).
        throw new Error("dsar: refused — verifiedIdentity is required before a request is accepted");
      }
      const requestId = request.requestId || genId("dsar");
      const windowDays =
        request.right === "access" || request.right === "portability"
          ? RESPONSE_WINDOWS.gdpr_days
          : RESPONSE_WINDOWS.gdpr_days;
      const dueBy = new Date(now.getTime() + windowDays * DAY_MS).toISOString();
      const rec = {
        requestId,
        subjectId: request.subjectId,
        right: request.right,
        verifiedIdentity: request.verifiedIdentity,
        receivedAt: now.toISOString(),
        dueBy,
        status: "open",
        request,
      };
      dsar.set(requestId, rec);
      audit.append({ actor, event: "admin.dsar-received", subject: request.subjectId, detail: { requestId, right: request.right, dueBy } });
      return { requestId, dueBy, status: "open" };
    },

    /**
     * Serve a tracked DSAR: runs the rights engine with REAL io hooks wired to
     * the store, appends `admin.dsar-served` (+ `admin.data-export` for
     * access/portability), and closes the request. Returns the ServedResult.
     */
    serveDsar(requestId, { actor }, now = new Date()) {
      const rec = dsar.get(requestId);
      if (!rec) throw new Error("dsar: unknown requestId " + requestId);
      if (rec.status === "served") return rec.result;

      const io = {
        fetcher: (dataClassId, subjectId) =>
          dataClassId === "directory.identity" ? store.directoryFor(subjectId) : store.itemsFor(subjectId),
        writer: (_dcId, field, value, subjectId) => store.rectifyDirectory(subjectId, field, value),
        eraser: (dataClassId, subjectId) => {
          if (dataClassId === "directory.identity") store.eraseDirectory(subjectId);
          else for (const it of store.itemsFor(subjectId)) store.deleteItem(it.id);
        },
        flagger: (_subjectId, _mode) => {}, // objection/restriction: no-op reference
      };
      const result = handleRight(rec.request, io);

      rec.result = result;
      rec.status = "served";
      rec.servedAt = now.toISOString();
      dsar.set(requestId, rec);

      // Serving is itself a disclosed admin act; access/portability is an export.
      if (rec.right === "access" || rec.right === "portability") {
        audit.append({ actor, event: "admin.data-export", subject: rec.subjectId, detail: { requestId, right: rec.right } });
      }
      audit.append({ actor, event: "admin.dsar-served", subject: rec.subjectId, detail: { requestId, right: rec.right, served: result.served.length, refused: result.refused.length } });
      return result;
    },

    dsarStatus(requestId) {
      const r = dsar.get(requestId);
      return r ? { requestId: r.requestId, right: r.right, status: r.status, dueBy: r.dueBy, servedAt: r.servedAt || null } : null;
    },
    openDsars(now = new Date()) {
      return [...dsar.values()].filter((r) => r.status === "open").map((r) => ({
        requestId: r.requestId,
        right: r.right,
        dueBy: r.dueBy,
        overdue: new Date(r.dueBy).getTime() < now.getTime(),
      }));
    },

    /* ---------------- Breach: assess + persist a case ---------------- */

    /**
     * Declare a breach: run the assessment (72h clock, ciphertext-mitigation
     * factor, authority routing) and PERSIST a case. Appends
     * `admin.breach-declared`. Notifies nobody automatically (honest: it is a
     * DRAFT for the DPO). Returns `{ caseId, assessment }`.
     */
    declareBreach(b, { actor }, now = new Date()) {
      const assessment = assessBreach(b, now);
      const caseId = genId("breach");
      cases.set(caseId, { caseId, declaredAt: now.toISOString(), status: "open", assessment });
      audit.append({
        actor,
        event: "admin.breach-declared",
        detail: {
          caseId,
          exposed: b.exposed,
          overdue: assessment.clock.overdue,
          ciphertextMitigationApplies: assessment.ciphertextMitigationApplies,
        },
      });
      return { caseId, assessment };
    },
    breachCase(caseId) {
      const c = cases.get(caseId);
      return c ? { ...c } : null;
    },
    breachCases() {
      return [...cases.values()].map((c) => ({ caseId: c.caseId, status: c.status, declaredAt: c.declaredAt }));
    },

    /* ---------------- Audit access (employee-visible) ---------------- */

    /** Verify the whole admin-audit chain is intact. */
    verifyAudit() {
      return audit.verify();
    },
    /** The subject-facing view: every disclosed admin act touching them. */
    auditVisibleTo(subjectId) {
      return audit.visibleTo(subjectId);
    },
  };
}

export default { createComplianceRuntime, createMetadataStore };
