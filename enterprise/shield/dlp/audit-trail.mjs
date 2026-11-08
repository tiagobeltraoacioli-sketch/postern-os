// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Bloch Shield (Enterprise) — DLP third-party-sharing TRACEABILITY trail.
//
// STATUS: design / reference prototype. UNAUDITED. Pre-production. NOT LEGAL
// ADVICE — see COMPLIANCE.md.
//
// THE RAIL THAT NEVER BENDS: CORPORATE-EGRESS ONLY, DISCLOSED, NEVER PERSONAL.
//   This trail records ONE thing: when CORPORATE data left the container to a
//   THIRD PARTY, scoped by which sub-access identity did it (master/sub, see
//   enterprise/features/sub-access.mjs), which class, which destination, when,
//   and the gate verdict. That is the whole world of this trail.
//
//   It NEVER records the employee's personal activity — not their personal apps,
//   messages, browsing, files, location, keystrokes, or screen. Not because a
//   config forgot to enable it, but because such a record is REFUSED at append:
//   a personal-scoped or content-surveillance-shaped event throws. If it can't be
//   shown to the employee as "corporate data you sent out", it doesn't get logged.
//
//   Every record is employee-VISIBLE by design. The trail exists so the employee
//   AND the employer can both see exactly what corporate data crossed the line —
//   it protects the employee (proof it is scoped) as much as the employer.
//
// Append-only + tamper-evident via a SHA-256 hash chain (over the previous
// record's hash + the canonical record), the same pattern the Comms compliance
// trail and the ezekiel1 "rims full of eyes" trail use. Node built-in `crypto`
// only — no third-party dependency. Integrity != confidentiality: the chain
// proves records were not silently altered; it is not a secrecy mechanism, and
// (like ezekiel1's) it is tamper-EVIDENT, not tamper-PROOF.

import { createHash } from "node:crypto";

/**
 * The ONLY event type this trail records. There is exactly one, on purpose:
 * corporate data egressing to a third party. No "opened app", no "typed", no
 * "visited" — those do not exist in this vocabulary.
 */
export const ALLOWED_EVENTS = Object.freeze(["corporate.third-party-egress"]);

/**
 * Shapes that must NEVER appear in this trail. Attempting to append a record that
 * matches any of these throws — the engine cannot be quietly turned into a
 * personal-activity monitor.
 */
const FORBIDDEN_PATTERNS = [
  /keystroke/i,
  /screenshot|screen.?capture|screen.?record/i,
  /\blocation\b|\bgps\b/i,
  /personal/i,
  /browsing|browser.?history|url.?visited/i,
  /message\.content|read.?receipt|content\.read/i,
  /clipboard/i,
  /microphone|camera|webcam/i,
];

const GENESIS = "0".repeat(64);

/** Stable key order => deterministic hash. Corporate-egress fields only. */
function _canonical(rec) {
  return JSON.stringify({
    seq: rec.seq,
    ts: rec.ts,
    event: rec.event,
    masterId: rec.masterId,
    subAccessId: rec.subAccessId,
    class: rec.class,
    destination: rec.destination,
    verdict: rec.verdict,
    reason: rec.reason,
    prev: rec.prev,
  });
}

function _hash(rec) {
  return createHash("sha256").update(_canonical(rec)).digest("hex");
}

/**
 * A disclosed, append-only, tamper-evident trail of CORPORATE third-party egress,
 * scoped by master/sub identity.
 */
export class EgressTrail {
  /**
   * @param {Array<object>} [existing] a prior chain (e.g. loaded from the durable
   *        container store) — the trail is rebuilt from it and stays verifiable.
   * @param {object} [opts]
   * @param {(record:object)=>void} [opts.onAppend]  write-through sink: called with
   *        each newly-appended record so the container can PERSIST it durably
   *        (Postgres/KV/append-only file) instead of keeping the trail in memory.
   * @param {(head:string)=>string} [opts.signer]  optional signer over the chain
   *        head, so the durable trail is tamper-EVIDENT to an external verifier
   *        beyond the internal hash chain. Integrity != confidentiality.
   */
  constructor(existing = [], opts = {}) {
    /** @type {Array<object>} */
    this.records = existing.slice();
    this._onAppend = typeof opts.onAppend === "function" ? opts.onAppend : null;
    this._signer = typeof opts.signer === "function" ? opts.signer : null;
  }

  /** @returns {string} hash of the last record, or GENESIS. */
  head() {
    return this.records.length ? this.records[this.records.length - 1].hash : GENESIS;
  }

  /**
   * Record ONE corporate third-party egress. Throws on any personal-scope or
   * surveillance-shaped event, and on a non-corporate egress.
   *
   * @param {Object} e
   * @param {string} e.masterId       the corporate master identity (org) — NOT a personal id
   * @param {string} e.subAccessId    the sub-access token id that performed the egress (e.g. "sub-3")
   * @param {string} e.class          the corporate class id (public|internal|confidential|restricted)
   * @param {string} e.destination    the third-party destination id the data left to
   * @param {"allow"|"warn"|"block"} e.verdict  the gate verdict
   * @param {string} [e.reason]       why (the gate's reason)
   * @param {boolean} [e.corporate]   MUST be true (or omitted-and-implied); false is refused
   * @param {string} [e.event]        defaults to the sole allowed event
   * @param {Date} [now]
   * @returns {object} the appended record
   */
  append(e, now = new Date()) {
    const event = e.event || ALLOWED_EVENTS[0];
    if (!ALLOWED_EVENTS.includes(event))
      throw new Error(`dlp-trail: event '${event}' is not the corporate-egress event — nothing else may be logged here`);

    // The red line: only corporate data is ever recorded.
    if (e.corporate === false || e.class === "personal")
      throw new Error(
        "dlp-trail: refused — this trail records CORPORATE third-party egress only; personal-scope data is never traced",
      );

    // Surveillance-shape tripwire across every stringy field.
    const blob = JSON.stringify({
      event,
      class: e.class,
      destination: e.destination,
      reason: e.reason ?? "",
    });
    for (const p of FORBIDDEN_PATTERNS)
      if (p.test(blob))
        throw new Error(
          `dlp-trail: refused — record resembles personal/surveillance data (${p}); this trail is corporate egress only`,
        );

    if (!e.masterId) throw new Error("dlp-trail: masterId (corporate master identity) is required");
    if (!e.subAccessId) throw new Error("dlp-trail: subAccessId (which sub-access egressed) is required");

    const rec = {
      seq: this.records.length,
      ts: now.toISOString(),
      event,
      masterId: String(e.masterId),
      subAccessId: String(e.subAccessId),
      class: String(e.class),
      destination: String(e.destination),
      verdict: String(e.verdict),
      reason: e.reason ? String(e.reason) : "",
      prev: this.head(),
      corporate: true, // always — this trail cannot hold anything else
      employeeVisible: true, // always — no covert records
    };
    rec.hash = _hash(rec);
    this.records.push(rec);
    // Durable write-through: persist the record the moment it is committed, so a
    // crash cannot lose a corporate-egress event. Best-effort — a failing sink
    // must not silently drop the in-memory record (the caller decides recovery).
    if (this._onAppend) this._onAppend({ ...rec });
    return rec;
  }

  /**
   * The signed head of the durable trail, for external tamper-evidence. Returns
   * `{ head, sig }` when a signer was wired, else `{ head, sig:null }`. Signing
   * the head binds the whole chain (each record commits to the previous hash).
   */
  signedHead() {
    const head = this.head();
    return { head, sig: this._signer ? this._signer(head) : null };
  }

  /**
   * Verify the whole chain is intact.
   * @returns {{ok:boolean, brokenAt:number|null}}
   */
  verify() {
    let prev = GENESIS;
    for (const rec of this.records) {
      if (rec.prev !== prev) return { ok: false, brokenAt: rec.seq };
      const { hash, corporate, employeeVisible, ...core } = rec;
      if (_hash(core) !== hash) return { ok: false, brokenAt: rec.seq };
      prev = rec.hash;
    }
    return { ok: true, brokenAt: null };
  }

  /**
   * The employee-facing disclosure view: every corporate egress attributed to a
   * given sub-access identity. This IS the transparency guarantee — the employee
   * behind `subAccessId` can always see exactly what corporate data they sent to
   * third parties, and nothing about them beyond that exists in this trail.
   * @param {string} subAccessId
   */
  visibleTo(subAccessId) {
    return this.records
      .filter((r) => r.subAccessId === subAccessId)
      .map((r) => ({
        ts: r.ts,
        class: r.class,
        destination: r.destination,
        verdict: r.verdict,
        reason: r.reason,
      }));
  }

  /** Admin/compliance view for one corporate master (org), newest first. */
  forMaster(masterId) {
    return this.records
      .filter((r) => r.masterId === masterId)
      .slice()
      .reverse()
      .map((r) => ({ ...r }));
  }
}

export default { EgressTrail, ALLOWED_EVENTS };
