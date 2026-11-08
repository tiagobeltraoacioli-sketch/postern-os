// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern Comms (Enterprise) — retention & data-minimization policy engine.
//
// STATUS: design / reference prototype. UNAUDITED. Pre-production. NOT LEGAL
// ADVICE — see COMPLIANCE.md.
//
// PRINCIPLES (LGPD Art. 6 / GDPR Art. 5)
//   • Purpose limitation + necessity (Art. 6 I/II, Art. 5(1)(b/c)).
//   • Storage limitation: keep only as long as the purpose needs (Art. 5(1)(e),
//     LGPD Art. 15/16).
//   • Data minimisation defaults: OFF-by-default for anything not strictly needed.
//
// THE E2EE-vs-RETENTION TENSION, RESOLVED OUT LOUD
//   A retention policy can only act on data the operator actually holds:
//     - E2EE message CONTENT: the operator holds CIPHERTEXT. A retention window
//       deletes the ciphertext blob; it never had the plaintext. The employee's
//       OWN device may keep its own local copy under its own (disclosed) policy.
//     - METADATA the operator must process to route: retention applies normally.
//   The policy object below states, per data class, WHAT is retained, BY WHOM,
//   and makes the E2EE carve-out explicit rather than pretending content is
//   centrally retained-and-readable.
//
// This module is pure: it EVALUATES a policy (what is due for deletion) and
// VALIDATES a policy file. It performs no deletion itself — the app's data layer
// (owned by another dev) is authoritative and calls in through documented hooks.

import { DATA_CLASSES, dataClass, VISIBILITY } from "./data-model.mjs";

const DAY_MS = 86_400_000;

/**
 * @typedef {Object} RetentionRule
 * @property {string} dataClass          id from data-model.mjs
 * @property {string} channelClass       "*" | a channel data-class label
 * @property {number|null} retainDays    null = "kept until purpose ends / legal hold"; 0 = do-not-retain
 * @property {"operator"|"employee-device"|"none"} retainedBy who physically holds it
 * @property {boolean} disclosed         MUST be true — undisclosed retention is a rail violation
 * @property {string} basis              why it's retained (purpose)
 */

/** Load-time validation of a retention policy object. Returns {ok, errors[]}. */
export function validatePolicy(policy) {
  const errors = [];
  if (!policy || typeof policy !== "object") return { ok: false, errors: ["policy is not an object"] };
  if (policy.schema !== "postern.comms.retention/1")
    errors.push(`unexpected schema: ${policy.schema}`);
  if (!Array.isArray(policy.rules)) {
    errors.push("policy.rules must be an array");
    return { ok: false, errors };
  }
  for (const [i, r] of policy.rules.entries()) {
    const dc = dataClass(r.dataClass);
    if (!dc) errors.push(`rules[${i}]: unknown dataClass '${r.dataClass}'`);
    if (r.retainDays !== null && (!Number.isFinite(r.retainDays) || r.retainDays < 0))
      errors.push(`rules[${i}]: retainDays must be null or a non-negative number`);
    if (!["operator", "employee-device", "none"].includes(r.retainedBy))
      errors.push(`rules[${i}]: retainedBy must be operator|employee-device|none`);
    if (r.disclosed !== true)
      errors.push(`rules[${i}]: disclosed MUST be true — covert retention violates the transparency rail`);
    // Honesty guard: operator cannot be said to 'retain readable' E2EE content.
    if (dc && dc.visibility === VISIBILITY.EMPLOYEE_ONLY_E2EE && r.retainedBy === "operator" && r.retainDays !== 0) {
      if (!/ciphertext/i.test(r.basis || ""))
        errors.push(
          `rules[${i}]: E2EE data retained by operator must state it is CIPHERTEXT-only in 'basis' (operator cannot read it)`,
        );
    }
  }
  return { ok: errors.length === 0, errors };
}

/**
 * Given a policy and a set of stored items, compute which are due for deletion.
 * Pure & side-effect-free — returns a plan the data layer executes.
 * @param {{rules:RetentionRule[]}} policy
 * @param {Array<{id:string, dataClass:string, channelClass?:string, createdAt:string}>} items
 * @param {Date} [now]
 * @returns {{delete:Array<{id:string,reason:string}>, keep:Array<{id:string,reason:string}>}}
 */
export function evaluate(policy, items, now = new Date()) {
  const del = [];
  const keep = [];
  for (const it of items) {
    const rule = _matchRule(policy, it);
    if (!rule) {
      keep.push({ id: it.id, reason: "no matching rule (default: keep, flag for review)" });
      continue;
    }
    if (rule.retainDays === null) {
      keep.push({ id: it.id, reason: `retained until purpose ends / legal basis: ${rule.basis}` });
      continue;
    }
    const ageMs = now.getTime() - new Date(it.createdAt).getTime();
    const limitMs = rule.retainDays * DAY_MS;
    if (rule.retainDays === 0 || ageMs > limitMs) {
      del.push({
        id: it.id,
        reason:
          rule.retainDays === 0
            ? `do-not-retain (minimisation default) — ${rule.retainedBy}`
            : `exceeded ${rule.retainDays}d window (${Math.floor(ageMs / DAY_MS)}d old) — ${rule.retainedBy}`,
      });
    } else {
      keep.push({ id: it.id, reason: `within ${rule.retainDays}d window` });
    }
  }
  return { delete: del, keep };
}

function _matchRule(policy, item) {
  const rules = policy.rules || [];
  // Prefer an exact channelClass match, then wildcard.
  return (
    rules.find((r) => r.dataClass === item.dataClass && r.channelClass === (item.channelClass ?? "*")) ||
    rules.find((r) => r.dataClass === item.dataClass && r.channelClass === "*") ||
    null
  );
}

/**
 * The minimisation defaults this layer recommends (all conservative / privacy-first).
 * A deployment may loosen these ONLY with disclosure + documented purpose.
 */
export const MINIMIZATION_DEFAULTS = Object.freeze({
  schema: "postern.comms.minimization/1",
  presenceHistory: false, // do not log presence over time by default
  readReceiptsLogged: false, // delivery works without persisting who-read-what
  ipAddressLogging: "abuse-window-only", // keep IPs only briefly for abuse prevention
  messageContentServerReadable: false, // E2EE — server never reads content
  typingIndicatorsPersisted: false,
  metadataForRoutingOnly: true, // metadata processed for delivery, minimised, retention-bound
});

/** Render a plain-language retention disclosure the transparency panel can show. */
export function retentionDisclosure(policy) {
  const lines = ["What is kept, for how long, and by whom (disclosed retention):", ""];
  for (const r of policy.rules || []) {
    const dc = dataClass(r.dataClass);
    const label = dc ? dc.label : r.dataClass;
    const dur = r.retainDays === null ? "until purpose ends / legal hold" : r.retainDays === 0 ? "not retained" : `${r.retainDays} days`;
    lines.push(`  • ${label} [${r.channelClass}] — ${dur}, held by ${r.retainedBy}. ${r.basis}`);
  }
  lines.push("");
  lines.push("E2EE message content is held by the operator only as unreadable ciphertext; your own device keeps its own local copy under its own disclosed policy.");
  return lines.join("\n");
}

export default { validatePolicy, evaluate, MINIMIZATION_DEFAULTS, retentionDisclosure };
