// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern CLOUD — Consiglio console AUDIT TRAIL (reference prototype).
//
// STATUS: reference prototype. UNAUDITED. Pre-production. NO SECURITY CLAIMS.
//
// WHAT THIS IS
// ------------
// A tamper-EVIDENT, hash-chained audit trail written on EVERY grantAccess /
// revokeAccess (and every dual-control commit). Each entry is
//   { seq, ts, act, detail, meta, prev, hash }
// where `hash = SHAKE-256( prev ‖ canonicalJSON(entry-without-hash) )`, chaining
// `prev` to the previous entry's hash. Editing or dropping any past entry breaks
// the chain from that point on — detectable by re-walking it (`verify()`).
//
// HONESTY. This mirrors the AUTHORITATIVE trail the Ezekiel1 Rust engine chains
// with SHAKE-256; this console-side chain is the operational, tamper-EVIDENT
// record — evident, NOT tamper-proof: "no software stops a human photographing a
// screen", and an operator who controls the store can rewrite the WHOLE chain.
// The guarantee is detection of PARTIAL edits, not prevention. SHAKE-256 here is
// real (node:crypto), matching the engine's primitive — not an FNV stand-in.

import crypto from "node:crypto";

const DOMAIN = "consiglio:audit:v1";
const HASH_BYTES = 32;

// Deterministic canonical JSON (keys sorted at every level) so the hashed bytes
// are stable regardless of key insertion order.
function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  const keys = Object.keys(value).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonical(value[k])).join(",") + "}";
}

function shake256Hex(input) {
  // Real SHAKE-256 (XOF) via node:crypto — the same primitive family the
  // Ezekiel1 engine chains the authoritative trail with.
  return crypto.createHash("shake256", { outputLength: HASH_BYTES }).update(input).digest("hex");
}

function hashEntry(prev, core) {
  return shake256Hex(DOMAIN + "\n" + (prev || "") + "\n" + canonical(core));
}

/**
 * Build a hash-chained audit trail.
 * @param {object} [opts]
 * @param {Array<object>} [opts.entries]  restore prior entries (from the store).
 * @param {(entries:Array<object>)=>void|Promise<void>} [opts.onChange]  called
 *        after every append with the full entry set, so the caller persists it.
 * @param {()=>Date|string|number} [opts.now]
 */
export function createAuditTrail(opts = {}) {
  const entries = Array.isArray(opts.entries) ? opts.entries.map((e) => ({ ...e })) : [];
  const onChange = typeof opts.onChange === "function" ? opts.onChange : null;
  const now = typeof opts.now === "function" ? opts.now : () => new Date();

  const head = () => (entries.length ? entries[entries.length - 1].hash : null);

  return {
    /**
     * Append an entry. `act` is the verb (e.g. "grant.enroll.propose"), `detail`
     * a short string, `meta` a structured object (no secrets). Returns the entry.
     */
    async append(act, detail, meta = {}) {
      const prev = head();
      const core = {
        seq: entries.length,
        ts: new Date(now()).toISOString(),
        act: String(act),
        detail: detail == null ? "" : String(detail),
        meta,
        prev,
      };
      const entry = { ...core, hash: hashEntry(prev, core) };
      entries.push(entry);
      if (onChange) await onChange(entries.map((e) => ({ ...e })));
      return { ...entry };
    },

    /** All entries, oldest first. */
    list() {
      return entries.map((e) => ({ ...e }));
    },

    head,
    length: () => entries.length,

    /**
     * Re-walk the chain and report whether it is intact. Returns
     * `{ ok:true, length }` or `{ ok:false, brokenAt }` at the first entry whose
     * recomputed hash or `prev` link does not match (tamper EVIDENCE).
     */
    verify() {
      let prev = null;
      for (let i = 0; i < entries.length; i++) {
        const e = entries[i];
        if (e.prev !== prev) return { ok: false, brokenAt: i, reason: "prev-link mismatch" };
        const { hash, ...core } = e;
        if (hashEntry(prev, core) !== hash) return { ok: false, brokenAt: i, reason: "hash mismatch" };
        prev = hash;
      }
      return { ok: true, length: entries.length };
    },
  };
}

export default { createAuditTrail };
