// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Gramota — registration bot orchestration endpoint (server-authoritative walker).
//
// STATUS: design / reference prototype, UNAUDITED, pre-production. Not legal advice.
//
// POST /gramota/bot  → advances the deterministic state machine one step, server
// side, using the CANONICAL walker (registrar.js). This is a fail-closed MIRROR of
// the client walker: even if the client is tampered with, the server recomputes
// the next legal state and the resulting `action` intent. It NEVER mints a token
// (it holds no signing key), NEVER ticks attestation, and NEVER lets the bot talk
// past a D&B not-found or a KYC fail.
//
// STATELESS + PII-MINIMAL: the session is passed in by the client each turn and is
// NOT stored server-side. No DUNS, name, or transcript is persisted here. There is
// NO LLM in this path — any LLM assist is client-side BYOK and only ever sees
// redacted placeholders (see registrar.redactPII / assertNoPII).
//
// GET /gramota/bot   → the transition table (prompts) for the client to render.

import { STATES, newSession, stepRegistrar, applyIssuance } from "./registrar.js";

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

/** Accept only the known, non-sensitive session shape; drop anything else. */
function sanitizeSession(s) {
  if (!s || typeof s !== "object" || !STATES[s.state]) return newSession();
  const c = (s.collected && typeof s.collected === "object") ? s.collected : {};
  return {
    state: s.state,
    collected: {
      tier: c.tier === "corporate-master" || c.tier === "business-freemium" ? c.tier : undefined,
      duns: typeof c.duns === "string" && /^\d{9}$/.test(c.duns) ? c.duns : undefined,
      role: c.role === "owner" || c.role === "manager" ? c.role : undefined,
      attestation: c.attestation === true ? true : undefined,
      kyc: typeof c.kyc === "string" ? c.kyc : undefined,
    },
  };
}

export async function onRequestPost(context) {
  const { request } = context;
  let body;
  try { body = await request.json(); } catch { return json(400, { error: "invalid JSON body" }); }

  const session = sanitizeSession(body.session);
  const input = (body.input && typeof body.input === "object") ? body.input : {};

  // The client reports a real HTTP issuance outcome; only that can move us into an
  // "issued_*" state. The bot cannot fabricate a token, so it cannot fabricate this.
  if (body.issuanceResult && typeof body.issuanceResult === "object") {
    const r = applyIssuance(session, body.issuanceResult.ok === true, session.collected.tier);
    return json(200, { ...r, notice: BOT_NOTICE });
  }

  // Never trust a client-asserted attestation flag beyond a strict boolean, and
  // never accept a client-asserted KYC pass unless it names a decision the seam
  // returned (the client got it from /gramota/kyc, which is authoritative).
  const safeInput = {
    tier: input.tier === "corporate-master" || input.tier === "business-freemium" ? input.tier : undefined,
    text: typeof input.text === "string" ? input.text.slice(0, 2000) : undefined,
    duns: typeof input.duns === "string" ? input.duns : undefined,
    role: input.role === "owner" || input.role === "manager" ? input.role : undefined,
    attestation: input.attestation === true, // explicit human boolean only
    kyc: ["pass", "pending", "fail"].includes(input.kyc) ? input.kyc : undefined,
    dnb: ["verified", "not-found", "unavailable"].includes(input.dnb) ? input.dnb : undefined,
  };

  const result = stepRegistrar(session, safeInput);
  return json(200, { ...result, notice: BOT_NOTICE });
}

export function onRequestGet() {
  const table = Object.fromEntries(
    Object.entries(STATES).map(([k, v]) => [k, { prompt: v.prompt, collects: v.collects, terminal: v.terminal }]),
  );
  return json(200, { states: table, notice: BOT_NOTICE });
}

const BOT_NOTICE =
  "Deterministic registration walker — a GUIDE, never a gate. Holds no signing key; cannot mint a token, cannot tick attestation, cannot pass a D&B not-found or a KYC fail. No PII is stored here and no LLM is in this path. Reference prototype, UNAUDITED — not compliance, not legal advice.";
