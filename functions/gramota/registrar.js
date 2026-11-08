// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Gramota — the registration bot's DETERMINISTIC state-machine walker.
//
// STATUS: design / reference prototype, UNAUDITED, pre-production. Not legal advice.
// "Gramota" is a PROPOSED name, pending trademark clearance.
//
// WHAT THIS IS
// ------------
// A pure, DOM-free, network-free walker over the SAME fail-closed upgrade state
// machine the Gramota forms use (Flow-Design §1): tier pick → DUNS → role →
// owner/manager attestation → KYC handoff → issue master → seat/device setup.
//
// It is a GUIDE, NEVER A GATE. This module holds NO signing key and cannot mint a
// token; every advance is expressed as an INTENT (`action`) that the real,
// server-side guards (`functions/license/master.js`, the KYC seam) still enforce.
// If the bot is bypassed or lied to, those functions still refuse — the client is
// a mirror, the server is the authority.
//
// NO LLM REQUIRED. The primary path is fully deterministic and on-device. An LLM,
// if ever wired, is BYOK / least-private and NEVER sees PII — the redactor below
// strips DUNS + names before any model call, and PII-bearing steps are parsed by
// the deterministic parsers here, not by a model.
//
// This module is CANONICAL. The Gramota app (apps/gramota/index.html) mirrors this
// logic in its <script id="grm-core"> block; apps/gramota/test-core.mjs asserts the
// two stay in parity so neither can silently drift.

// ---------------------------------------------------------------------------
// The transition table. Each state names its scripted prompt, the field it
// collects (if any), and whether it is terminal. Transitions are computed by
// stepRegistrar() below; the table is data so the client and server agree.
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// Deterministic parsers (the PII-safe path). These run on-device; their inputs
// NEVER go to any third-party model.
// ---------------------------------------------------------------------------

/** Extract a 9-digit DUNS from free text ("our D-U-N-S is 15 04 83 782" → "150483782"). */
export function normalizeDuns(text) {
  const digits = String(text == null ? "" : text).replace(/\D/g, "");
  return /^\d{9}$/.test(digits) ? digits : null;
}

/** Map free text to a role. Deterministic keyword map, no model. */
export function parseRole(text) {
  const s = String(text == null ? "" : text).toLowerCase();
  if (/\b(owner|founder|proprietor|ceo|principal|i own|i run the company|my company)\b/.test(s)) return "owner";
  if (/\b(manager|authori[sz]ed|director|officer|admin|on behalf)\b/.test(s)) return "manager";
  return null;
}

/** Map free text to a tier choice. Deterministic keyword map, no model. */
export function parseTier(text) {
  const s = String(text == null ? "" : text).toLowerCase();
  if (/\b(freemium|3 desktops|three desktops|free|no duns|just.*(me|myself)|small)\b/.test(s)) return "business-freemium";
  if (/\b(corporate|unlimited|master|company|business|enterprise|duns)\b/.test(s)) return "corporate-master";
  return null;
}

// ---------------------------------------------------------------------------
// PII redaction — the wall consent cannot open. Any text handed to a BYOK LLM
// passes through here first; DUNS runs and known collected names become
// placeholders. The default is a HARD no-egress for these fields.
// ---------------------------------------------------------------------------

/**
 * @param {string} text
 * @param {{duns?:string, legalName?:string, names?:string[]}} [known] collected PII to scrub verbatim
 * @returns {string} text safe to hand to a third-party model (placeholders only)
 */
export function redactPII(text, known = {}) {
  let out = String(text == null ? "" : text);
  // Any run of 6+ digits (covers DUNS with or without separators) → [DUNS].
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

/**
 * Assert that a payload bound for a third-party model carries NO PII. Fail-closed:
 * throws if a DUNS-shaped run or a known name survived. Callers MUST run this
 * immediately before any model call.
 */
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

// ---------------------------------------------------------------------------
// The walker. Pure: (session, input) -> next session + prompt + intent.
// Never mutates its arguments; never mints; never sets attestation itself.
// ---------------------------------------------------------------------------

/**
 * @typedef {Object} RegSession
 * @property {string} state          one of STATES
 * @property {Object} collected      { tier?, duns?, role?, attestation?, kyc? }
 *
 * @typedef {Object} RegInput
 * @property {string} [tier]         "business-freemium" | "corporate-master"
 * @property {string} [text]         free text for a deterministic parser
 * @property {string} [duns]         explicit DUNS
 * @property {string} [role]         "owner" | "manager"
 * @property {boolean} [attestation] MUST be a real human checkbox — the bot may not set it
 * @property {("pass"|"pending"|"fail")} [kyc]  the KYC seam's returned decision
 * @property {("verified"|"not-found"|"unavailable")} [dnb] optional pre-flight D&B hint (server is authoritative)
 *
 * @typedef {Object} RegResult
 * @property {string} state
 * @property {Object} collected
 * @property {string} prompt
 * @property {string|null} error
 * @property {(null|{type:string,body?:Object})} action  server intent (never a token; never a key)
 * @property {boolean} terminal
 */

export function newSession() {
  return { state: "start", collected: {} };
}

/**
 * Advance the machine one step. Fail-closed by construction.
 * @param {RegSession} session
 * @param {RegInput} input
 * @returns {RegResult}
 */
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
      // Optional client-side pre-flight hint. The server re-checks; a not-found
      // hint refuses here too so the bot can never talk past it.
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
      // HARD gate: attestation must be an explicit human boolean. The bot may
      // explain but may NEVER tick it, self-attest, or infer it from chat.
      if (input.attestation !== true) {
        return stay("You must tick the attestation checkbox yourself. I can explain it, but I cannot accept it on your behalf.");
      }
      collected.attestation = true;
      return done("kyc");
    }

    case "kyc": {
      // The KYC seam owns the decision (Dev-2). The bot only routes it.
      const decision = input.kyc;
      if (decision === "pass") { collected.kyc = "pass"; return done("issue_corporate"); }
      if (decision === "pending") { collected.kyc = "pending"; return done("pending_kyc"); }
      if (decision === "fail") { collected.kyc = "fail"; return done("refused"); }
      // Default (seam not configured) is self-declared/pass — matches merged behavior.
      if (decision === undefined) { collected.kyc = "self-declared"; return done("issue_corporate"); }
      return stay("Waiting on the identity check result.");
    }

    case "issue_freemium":
      // INTENT only — the bot holds no key and cannot mint. The server issues.
      return done("issue_freemium", {
        action: { type: "issue", body: { tier: "business-freemium" } },
      });

    case "issue_corporate":
      return done("issue_corporate", {
        action: {
          type: "issue",
          body: {
            tier: "corporate-master",
            duns: collected.duns,
            role: collected.role,
            attestation: collected.attestation === true, // never fabricated
          },
        },
      });

    // Terminal states just re-emit their prompt.
    case "issued_corporate":
    case "issued_freemium":
    case "pending_kyc":
    case "refused":
    default:
      return done(s);
  }
}

/**
 * Record the SERVER's issuance outcome into the session. Only the server can move
 * us into an "issued_*" state — the bot cannot fabricate a token, so it cannot
 * fabricate this transition either. `ok` reflects the real HTTP result.
 */
export function applyIssuance(session, ok, tier) {
  const collected = Object.assign({}, (session && session.collected) || {});
  if (!ok) return { state: "refused", collected, prompt: STATES.refused.prompt, error: null, action: null, terminal: true };
  const state = tier === "corporate-master" ? "issued_corporate" : "issued_freemium";
  return { state, collected, prompt: STATES[state].prompt, error: null, action: null, terminal: true };
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
};
