// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Gramota — KYC handoff endpoint (thin route over the SEAM).
//
// STATUS: design / reference prototype, UNAUDITED, pre-production. Not legal advice.
//
// POST /gramota/kyc  → runs the KYC seam (kyc-seam.js) for an applicant context and
// returns { decision, ref, assurance, checkedAt }. Gramota's V3 handoff calls this
// BEFORE it POSTs to /license/master; it proceeds to issuance only on `pass`.
//
// This route implements NO KYC of its own (Dev-2 owns the real gate; see
// kyc-seam.js). It also RECEIVES NO documents — only a minimal, non-sensitive
// applicant context (DUNS, role, the D&B decision). Document PII stays on-device
// per CC-2; only the decision is retained/returned. No PII is persisted here.
//
// Fail-closed: a malformed body or a garbled provider result resolves to a `fail`
// (via normalizeResult). Nothing "passes on error".

import { kycGate } from "./kyc-seam.js";

function json(status, body) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "referrer-policy": "no-referrer",
    },
  });
}

export async function onRequestPost(context) {
  const { request, env } = context;
  let body;
  try { body = await request.json(); } catch { return json(400, { error: "invalid JSON body" }); }

  const duns = String(body.duns || "").replace(/\D/g, "");
  if (!/^\d{9}$/.test(duns)) {
    return json(400, { error: "a 9-digit DUNS is required for the KYC handoff" });
  }
  const role = body.role === "owner" ? "owner" : body.role === "manager" ? "manager" : null;
  if (!role) return json(400, { error: "role must be 'owner' or 'manager'" });

  // Minimal, non-document context. We deliberately do NOT accept document images
  // or identity fields here — those stay on-device (CC-2). The seam may collect
  // them behind its own boundary, never through this endpoint.
  const ctx = {
    duns,
    role,
    dnb: body.dnb && typeof body.dnb === "object" ? body.dnb : undefined,
    attestationStatement: body.attestationStatement ? String(body.attestationStatement).slice(0, 500) : undefined,
  };

  let result;
  try {
    result = await kycGate(env, ctx);
  } catch {
    // Fail-closed: a throwing provider is a hold, never a silent pass.
    result = { decision: "pending", ref: "kyc-error", assurance: "self-declared", checkedAt: Math.floor(Date.now() / 1000) };
  }

  return json(200, {
    ...result,
    notice:
      "Identity KYC seam. " +
      (result.ref === "kyc-not-configured"
        ? "No KYC provider is configured on this deployment — identity is SELF-DECLARED today and validated (KYC) at the 6-month renewal. "
        : "") +
      "Passing certifies IDENTITY, not software security. Documents stay on-device; only this decision is retained. This is a reference prototype — not compliance, not legal advice.",
  });
}

export function onRequestGet() {
  return json(200, {
    seam: "gramota/kyc",
    contract: "POST { duns, role, dnb? } -> { decision: pass|pending|fail, ref, assurance, checkedAt }",
    default: "self-declared/pass when unconfigured (merged behavior); real identity KYC owned by the KYC advisor (Dev-2).",
    privacy: "No documents accepted here; on-device OCR (CC-2) keeps document PII off every server. Only the decision is retained.",
  });
}
