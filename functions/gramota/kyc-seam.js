// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Gramota — the IDENTITY KYC SEAM (interface only).
//
// STATUS: design / reference prototype, UNAUDITED, pre-production. Not legal advice.
//
// OWNERSHIP: the REAL implementation of identity KYC (on-device OCR of the
// authority + ID documents, officer/authority match, liveness/UBO) is owned by
// the KYC advisor (Dev-2). Gramota only CONSUMES this seam as an interface — it
// calls it, gates issuance on its decision, and shows the assurance honestly. It
// does NOT implement KYC and must never receive raw documents or identity PII.
//
// This file defines the contract and a HONEST DEFAULT NO-OP so the merged
// behavior is the fallback: when no KYC provider is configured, the seam returns
// `self-declared / pass` — i.e. today's exact posture (self-declared owner/manager
// attestation + D&B, with real identity KYC deferred to the 6-month renewal). The
// KYC advisor tightens this by INJECTION (a bound `kycGate` in env), never by fork.
//
// PRIVACY: the cleanest LGPD/GDPR posture is to MINIMIZE BY NOT RECEIVING. The seam
// returns only { decision, ref, assurance, checkedAt } — an opaque provider ref and
// a label of what was actually proven — never the underlying documents.

/**
 * @typedef {Object} ApplicantContext
 * @property {string} duns                 9-digit, already format-checked
 * @property {("owner"|"manager")} role
 * @property {Object} [dnb]                the dnbDecisionFrom() object (verified/legalName/country)
 * @property {string} [attestationStatement] the exact self-declared text
 * @property {Object} [applicant]          opaque to us — whatever the KYC advisor's UI collected
 *
 * @typedef {Object} KycResult
 * @property {("pass"|"pending"|"fail")} decision
 * @property {string} ref                  provider reference id (opaque, non-PII to us)
 * @property {("self-declared"|"document"|"liveness"|"ubo")} assurance  what was actually proven
 * @property {number} checkedAt            unix seconds
 */

/**
 * The pluggable KYC gate. The KYC advisor provides a real implementation and
 * binds it as `env.KYC_GATE` (a function) or via a module they own. Until then,
 * this default preserves the merged contract exactly.
 *
 * @param {Object} env                     Pages Fn environment (may carry a bound provider)
 * @param {ApplicantContext} ctx
 * @returns {Promise<KycResult>}
 */
export async function kycGate(env, ctx) {
  // Injection point: if the KYC advisor bound a real gate, defer to it wholesale.
  const injected = env && env.KYC_GATE;
  if (typeof injected === "function") {
    const r = await injected(env, ctx);
    return normalizeResult(r);
  }
  // Honest default: NOT a real identity check. Self-declared today; real KYC at
  // the 6-month renewal (renew.js). We never pretend a check happened that didn't.
  return {
    decision: "pass",
    ref: "kyc-not-configured",
    assurance: "self-declared",
    checkedAt: Math.floor(Date.now() / 1000),
  };
}

/** Fail-closed normalizer: an unrecognized/garbled provider result becomes a `fail`. */
export function normalizeResult(r) {
  const decision = r && (r.decision === "pass" || r.decision === "pending" || r.decision === "fail") ? r.decision : "fail";
  const assurance =
    r && ["self-declared", "document", "liveness", "ubo"].includes(r.assurance) ? r.assurance : "self-declared";
  return {
    decision,
    ref: r && r.ref ? String(r.ref) : "kyc-unknown",
    assurance,
    checkedAt: r && Number.isFinite(r.checkedAt) ? r.checkedAt : Math.floor(Date.now() / 1000),
  };
}

export default { kycGate, normalizeResult };
