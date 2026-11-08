// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern CLOUD — Consiglio console DURABLE STORE (reference prototype).
//
// STATUS: reference prototype. UNAUDITED. Pre-production. NO SECURITY CLAIMS.
//
// WHAT THIS IS
// ------------
// A real, durable backend for the Consiglio HTTP service, injected over the
// SAME snapshot/restore seams the in-memory reference already exposes:
//   • console-auth  `snapshot()` / `{state}`  — enrollments, nonces, sessions,
//     pending dual-control changes.
//   • sub-access    `onChange(records)` / `{records}` — the sub/seat registry.
//   • audit trail   the tamper-EVIDENT hash chain (see audit.mjs).
// It writes JSON files under one directory, ATOMICALLY (temp + rename), so a
// crash mid-write can never leave a half-written store — a reader sees the old
// file or the new one, never a torn one. This is the "inject a real backend"
// half of durability; the crypto lives untouched in the crate + licensing lib.
//
// PRIVACY (LGPD/GDPR §9). Snapshots are pure data and carry NO secret key
// material — only PUBLIC wallet keys + metadata. A durable file is tamper-
// EVIDENT at best, NOT tamper-proof. This ENABLES compliance controls; it is
// NOT compliance and NOT legal advice.

import { promises as fs } from "node:fs";
import { join } from "node:path";

const AUTH_FILE = "auth-snapshot.json";
const SUBS_FILE = "sub-registry.json";
const AUDIT_FILE = "audit-trail.json";

/**
 * A durable, atomic, single-directory JSON store.
 * @param {string} dir  directory to hold the store files (created on demand).
 */
export function createFileStore(dir) {
  const path = (name) => join(dir, name);

  async function ensureDir() {
    await fs.mkdir(dir, { recursive: true });
  }

  async function readJson(name) {
    try {
      const bytes = await fs.readFile(path(name), "utf8");
      return JSON.parse(bytes);
    } catch (e) {
      if (e && e.code === "ENOENT") return null; // first boot — nothing persisted yet
      throw e;
    }
  }

  // Atomic write: serialize -> temp -> rename over target.
  async function writeJson(name, value) {
    await ensureDir();
    const tmp = path(name + ".tmp");
    await fs.writeFile(tmp, JSON.stringify(value), "utf8");
    await fs.rename(tmp, path(name));
  }

  return {
    dir,

    /** Restore the console-auth snapshot (or null on first boot). */
    loadAuth() {
      return readJson(AUTH_FILE);
    },
    /** Persist the console-auth snapshot durably (atomic). */
    saveAuth(snapshot) {
      return writeJson(AUTH_FILE, snapshot);
    },

    /** Restore the sub-access registry records (or null on first boot). */
    async loadSubs() {
      const v = await readJson(SUBS_FILE);
      return v && Array.isArray(v.records) ? v.records : null;
    },
    /** Persist the sub-access registry durably (atomic). */
    saveSubs(records) {
      return writeJson(SUBS_FILE, { schema: "postern.consiglio.sub-registry/1", records });
    },

    /** Restore the audit trail entries (or [] on first boot). */
    async loadAudit() {
      const v = await readJson(AUDIT_FILE);
      return v && Array.isArray(v.entries) ? v.entries : [];
    },
    /** Persist the audit trail durably (atomic). */
    saveAudit(entries) {
      return writeJson(AUDIT_FILE, { schema: "postern.consiglio.audit-trail/1", entries });
    },
  };
}

export default { createFileStore };
