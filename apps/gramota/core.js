// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Gramota — browser CORE (pure, DOM-free, network-free).
//
// STATUS: design / reference prototype, UNAUDITED, pre-production. Not legal advice.
// "Gramota" is a PROPOSED name, pending trademark clearance.
//
// This is the browser-side mirror of the CANONICAL server walker
// (functions/gramota/registrar.js). It carries the deterministic registration
// state machine, the client-side mirror of every server guard, the absorb
// (freemium → corporate) planner, and the PII redactor that walls PII off from any
// BYOK LLM. apps/gramota/test-core.mjs asserts this stays in byte-parity with
// registrar.js so the two can never silently drift.
//
// It holds NO crypto and NO signing key. It cannot mint a token; it only computes
// the next legal state and an `action` intent the server-side guards still enforce.

// ==========================================================================
// Transition table — MUST stay identical to registrar.STATES.
// ==========================================================================
export const STATES = Object.freeze({
  start: {
    prompt:
      "Welcome. I can set you up on Postern. Two honest paths: a free business freemium (up to 3 desktops, 2 years, no DUNS), or a corporate master (unlimited users, a 6-month evaluation, needs a DUNS number + owner/manager attestation + identity KYC). Which would you like? Personal editions are free forever — you don't need this at all for those.",
    collects: "tier",
    terminal: false,
  },
  duns: {
    prompt:
      "Your corporate master needs your company's 9-digit DUNS number. We verify it against Dun & Bradstreet when available (a DUNS that doesn't resolve is refused), otherwise accept it by format and flag it for review at renewal. We store only the DUNS + issue/expiry + your declared role + the D&B decision — no marketing data, no tracking.",
    collects: "duns",
    terminal: false,
  },
  role: {
    prompt:
      "Are you the owner of the company that holds this DUNS number, or an authorized manager?",
    collects: "role",
    terminal: false,
  },
  attestation: {
    prompt:
      "One required step you must confirm yourself — I can explain it but I cannot tick it for you: you declare you are the owner or an authorized manager of the DUNS holder, with authority to accept these terms, and you understand that at the 6-month renewal Postern Labs validates this (KYC of the contracting company), so a DUNS used inappropriately will not renew. Tick the attestation box to continue.",
    collects: "attestation",
    terminal: false,
  },
  kyc: {
    prompt:
      "Now the identity KYC step. This is a separate, sealed handoff — I never see your documents; I only receive back a pass / pending / fail decision. Passing certifies identity, not software security. If no KYC provider is configured, identity is self-declared today and validated at the 6-month renewal.",
    collects: "kyc",
    terminal: false,
  },
  issue_corporate: {
    prompt:
      "All gates cleared on my side. I'll now ask the server to issue your vendor-signed corporate master. The server runs the authoritative D&B check; a DUNS that does not resolve is still refused here. You'll receive a bundle including master_private_key_pkcs8 — keep it SECRET, it mints your sub-accounts and we never store it.",
    collects: null,
    terminal: false,
  },
  issue_freemium: {
    prompt:
      "I'll ask the server to issue your free business-freemium master (3 desktops, 2 years). No DUNS, no KYC. You'll receive a bundle with a private key to keep secret.",
    collects: null,
    terminal: false,
  },
  issued_corporate: {
    prompt:
      "Corporate master issued. Save the bundle and keep the private key secret. Next: enrol devices and mint sub-accounts in Consiglio — seats are unlimited. If you have 3 freemium desktops, I can help you promote them onto this license.",
    collects: null,
    terminal: true,
  },
  issued_freemium: {
    prompt:
      "Freemium master issued (3 desktops, 2 years). Save the bundle and keep the private key secret. When you want unlimited seats, come back and choose the corporate master.",
    collects: null,
    terminal: true,
  },
  pending_kyc: {
    prompt:
      "Your KYC is in review. You stay on freemium until it clears — no charge, nothing locked. Return any time to check.",
    collects: null,
    terminal: true,
  },
  refused: {
    prompt:
      "I can't issue a corporate master on this path — either the DUNS did not resolve at Dun & Bradstreet, or the identity check did not pass. Your freemium is untouched. You can retry or contact support.",
    collects: null,
    terminal: true,
  },
});

// ==========================================================================
// Deterministic parsers (the PII-safe path).
// ==========================================================================
export function normalizeDuns(text) {
  const digits = String(text == null ? "" : text).replace(/\D/g, "");
  return /^\d{9}$/.test(digits) ? digits : null;
}

export function parseRole(text) {
  const s = String(text == null ? "" : text).toLowerCase();
  if (/\b(owner|founder|proprietor|ceo|principal|i own|i run the company|my company)\b/.test(s)) return "owner";
  if (/\b(manager|authori[sz]ed|director|officer|admin|on behalf)\b/.test(s)) return "manager";
  return null;
}

export function parseTier(text) {
  const s = String(text == null ? "" : text).toLowerCase();
  if (/\b(freemium|3 desktops|three desktops|free|no duns|just.*(me|myself)|small)\b/.test(s)) return "business-freemium";
  if (/\b(corporate|unlimited|master|company|business|enterprise|duns)\b/.test(s)) return "corporate-master";
  return null;
}

// ==========================================================================
// PII redaction — the wall consent cannot open.
// ==========================================================================
export function redactPII(text, known = {}) {
  let out = String(text == null ? "" : text);
  out = out.replace(/\d[\d\s.\-]{4,}\d/g, "[DUNS]");
  const names = [];
  if (known && known.legalName) names.push(known.legalName);
  if (known && Array.isArray(known.names)) for (const n of known.names) names.push(n);
  for (const n of names) {
    const t = String(n || "").trim();
    if (t.length >= 2) out = out.split(t).join("[NAME]");
  }
  return out;
}

export function assertNoPII(text, known = {}) {
  const s = String(text == null ? "" : text);
  if (/\d[\d\s.\-]{4,}\d/.test(s)) throw new Error("redaction failed: a DUNS-shaped value would reach the model");
  const names = [];
  if (known && known.legalName) names.push(known.legalName);
  if (known && Array.isArray(known.names)) for (const n of known.names) names.push(n);
  for (const n of names) {
    const t = String(n || "").trim();
    if (t.length >= 2 && s.includes(t)) throw new Error("redaction failed: a known name would reach the model");
  }
  return true;
}

// ==========================================================================
// The walker — MUST behave identically to registrar.stepRegistrar.
// ==========================================================================
export function newSession() {
  return { state: "start", collected: {} };
}

export function stepRegistrar(session, input = {}) {
  const s = session && STATES[session.state] ? session.state : "start";
  const collected = Object.assign({}, (session && session.collected) || {});
  const done = (state, extra) =>
    Object.assign(
      { state, collected, prompt: STATES[state].prompt, error: null, action: null, terminal: !!STATES[state].terminal },
      extra || {},
    );
  const stay = (error) => done(s, { error: error || null });

  switch (s) {
    case "start": {
      const tier = input.tier || parseTier(input.text);
      if (tier === "business-freemium") { collected.tier = tier; return done("issue_freemium"); }
      if (tier === "corporate-master") { collected.tier = tier; return done("duns"); }
      return stay("Please choose a path: business freemium (free, 3 desktops) or corporate master (unlimited, needs a DUNS).");
    }
    case "duns": {
      const duns = input.duns ? normalizeDuns(input.duns) : normalizeDuns(input.text);
      if (!duns) return stay("That isn't a 9-digit DUNS number. Please enter exactly 9 digits.");
      if (input.dnb === "not-found") { collected.duns = duns; return done("refused"); }
      collected.duns = duns;
      return done("role");
    }
    case "role": {
      const role = input.role || parseRole(input.text);
      if (role !== "owner" && role !== "manager") {
        return stay("Please say whether you are the owner or an authorized manager of the DUNS holder.");
      }
      collected.role = role;
      return done("attestation");
    }
    case "attestation": {
      if (input.attestation !== true) {
        return stay("You must tick the attestation checkbox yourself. I can explain it, but I cannot accept it on your behalf.");
      }
      collected.attestation = true;
      return done("kyc");
    }
    case "kyc": {
      const decision = input.kyc;
      if (decision === "pass") { collected.kyc = "pass"; return done("issue_corporate"); }
      if (decision === "pending") { collected.kyc = "pending"; return done("pending_kyc"); }
      if (decision === "fail") { collected.kyc = "fail"; return done("refused"); }
      if (decision === undefined) { collected.kyc = "self-declared"; return done("issue_corporate"); }
      return stay("Waiting on the identity check result.");
    }
    case "issue_freemium":
      return done("issue_freemium", { action: { type: "issue", body: { tier: "business-freemium" } } });
    case "issue_corporate":
      return done("issue_corporate", {
        action: {
          type: "issue",
          body: {
            tier: "corporate-master",
            duns: collected.duns,
            role: collected.role,
            attestation: collected.attestation === true,
          },
        },
      });
    case "issued_corporate":
    case "issued_freemium":
    case "pending_kyc":
    case "refused":
    default:
      return done(s);
  }
}

export function applyIssuance(session, ok, tier) {
  const collected = Object.assign({}, (session && session.collected) || {});
  if (!ok) return { state: "refused", collected, prompt: STATES.refused.prompt, error: null, action: null, terminal: true };
  const state = tier === "corporate-master" ? "issued_corporate" : "issued_freemium";
  return { state, collected, prompt: STATES[state].prompt, error: null, action: null, terminal: true };
}

// ==========================================================================
// Form validators — the CLIENT mirror of master.js's server guards. These are
// UX only; the server (functions/license/master.js) remains authoritative.
// ==========================================================================
export function validateDuns(raw) {
  const duns = String(raw == null ? "" : raw).replace(/\D/g, "");
  return { ok: /^\d{9}$/.test(duns), value: duns };
}

/** Mirror of master.js onRequestPost corporate guards. Returns {ok, error?, body?}. */
export function validateCorporate({ duns, role, attestation }) {
  const d = validateDuns(duns);
  if (!d.ok) return { ok: false, error: "a valid 9-digit DUNS number is required for a corporate master license" };
  const r = role === "owner" ? "owner" : role === "manager" ? "manager" : null;
  if (!r) return { ok: false, error: "declare your role: 'owner' or an authorized 'manager' of the company that holds this DUNS number" };
  if (attestation !== true) {
    return { ok: false, error: "you must attest that you are the owner or an authorized manager of the company that holds this DUNS number" };
  }
  return { ok: true, body: { tier: "corporate-master", duns: d.value, role: r, attestation: true } };
}

// ==========================================================================
// Absorb planner — "promote, don't strand" (Flow-Design §2). Pure planning only;
// the actual mint happens in Consiglio under the org master key.
// ==========================================================================
/**
 * @param {Array<{label:string}>} freemiumDevices  the ≤3 freemium sub records
 * @param {("revoke"|"let-expire")} retire          how to retire the freemium master
 * @returns {{ mint:Array<{label:string}>, retire:string, seatCost:number, notes:string[] }}
 */
export function planAbsorb(freemiumDevices, retire = "revoke") {
  const devices = Array.isArray(freemiumDevices) ? freemiumDevices.filter((d) => d && d.label) : [];
  const capped = devices.slice(0, 3); // freemium can only have held 3
  return {
    mint: capped.map((d) => ({ label: String(d.label) })),
    retire: retire === "let-expire" ? "let-expire" : "revoke",
    seatCost: 0, // corporate seat cap is unlimited — re-minting costs no seat
    notes: [
      "Corporate master mints a NEW keypair (a different master_pub), so freemium-era subs can't verify against it — each device is RE-MINTED, not migrated.",
      retire === "let-expire"
        ? "Freemium master left to expire on its own 24-month clock; during overlap a device may verify under either master (both belong to the same org)."
        : "Freemium master added to the CRL (best-effort, freshness-bound); already-installed corporate subs keep working. Offline grace still applies.",
      "No device is broken mid-flight: absorb only ADDS a corporate sub and (optionally) revokes the old master.",
    ],
  };
}

export default {
  STATES,
  newSession,
  stepRegistrar,
  applyIssuance,
  normalizeDuns,
  parseRole,
  parseTier,
  redactPII,
  assertNoPII,
  validateDuns,
  validateCorporate,
  planAbsorb,
};
