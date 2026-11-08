// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern SHIELD — Consiglio challenge/response bridge (Business/Enterprise ONLY).
//
// STATUS: design / reference prototype — unaudited, pre-production.
//
// WHAT THIS IS
// ------------
// A stable INTERFACE where the real wallet-as-login challenge/response plugs in.
// The protocol and ALL cryptography are owned by crates/postern-consiglio-auth
// (server issues a random challenge; the wallet signs a domain-separated
// transcript with its hybrid Falcon-1024 ‖ ML-DSA-65 key; the server verifies the
// signature against the enrolled pubkey — control of the key IS the login). This
// module contains NO cryptography and does NOT import that crate. It only defines
// the shape the access broker calls, and enforces the ENTERPRISE business rule:
// the responder must present a valid SUB-token under the org master.
//
// If no real verifier is injected, it stays HONEST: it returns an unauthenticated
// result and never pretends a signature was checked.
//
// The injected interface (provided by a real Consiglio binding — FFI/WASM):
//
//   issueChallenge({orgId, employeeId}) -> { orgId, employeeId, nonce, issuedAt, expiresAt }
//   verifyResponse(challenge, response) -> { ok:boolean, employeeId?, role?, reason? }
//
// where `response` carries { orgId, employeeId, nonce, publicKey, signature } —
// exactly the postern-consiglio-auth Response shape.

/** Domain tag, mirrored from postern_consiglio_auth::LOGIN_DOMAIN (source of truth). */
export const LOGIN_DOMAIN = "consiglio:wallet-login:v1";
/** Mirror of DEFAULT_TTL_SECS — a login challenge is answered immediately. */
export const DEFAULT_TTL_SECS = 120;

/**
 * Wrap an injected Consiglio verifier (or a labelled unauthenticated stand-in).
 *
 * @param {object} [opts]
 * @param {(req:{orgId:string,employeeId:string})=>object} [opts.issueChallenge]
 * @param {(challenge:object, response:object)=>({ok:boolean,employeeId?:string,role?:string,reason?:string})} [opts.verifyResponse]
 * @param {()=>number} [opts.random] test-injectable nonce source
 */
export function createConsiglioBridge(opts = {}) {
  const issue = typeof opts.issueChallenge === "function" ? opts.issueChallenge : null;
  const verify = typeof opts.verifyResponse === "function" ? opts.verifyResponse : null;
  // Test-injectable byte source. Default is a real CSPRNG (WebCrypto global,
  // present in Node 18+ and browsers) — NOT Math.random. The nonce is no longer
  // a predictability weakness even when no real Consiglio server issued it.
  const randomBytes = typeof opts.randomBytes === "function" ? opts.randomBytes : cryptoRandomBytes;

  return {
    authenticatorWired: !!verify,

    /** Issue a login challenge for (orgId, employeeId). */
    issueChallenge(req, now) {
      const orgId = String((req && req.orgId) || "").trim();
      const employeeId = String((req && req.employeeId) || "").trim();
      if (!orgId || !employeeId) throw new Error("consiglio-bridge: orgId and employeeId are required");
      if (issue) return issue({ orgId, employeeId });
      // Local stand-in challenge: no real Consiglio SERVER issued it (demo:true),
      // but the nonce IS a 256-bit CSPRNG value — safe against replay/guessing.
      const issuedAt = Math.floor(new Date(now || Date.now()).getTime() / 1000);
      return {
        orgId,
        employeeId,
        nonce: nonceHex(randomBytes),
        issuedAt,
        expiresAt: issuedAt + DEFAULT_TTL_SECS,
        domain: LOGIN_DOMAIN,
        demo: !issue,
      };
    },

    /**
     * Verify a wallet response against a challenge. Delegates the SIGNATURE check
     * to the injected Consiglio verifier. Without one, returns an honest
     * unauthenticated result (never a fake "ok").
     */
    verifyResponse(challenge, response, now) {
      if (!challenge || !response) return { ok: false, reason: "missing challenge or response" };
      // Local, non-crypto sanity: nonce echo + not expired. The REAL check
      // (PQ signature over the transcript, enrolled-pubkey binding) is the
      // injected verifier's job.
      const nowSec = Math.floor(new Date(now || Date.now()).getTime() / 1000);
      if (challenge.expiresAt && nowSec > challenge.expiresAt) {
        return { ok: false, reason: "challenge expired" };
      }
      if (response.nonce !== challenge.nonce) {
        return { ok: false, reason: "nonce mismatch (possible replay or wrong challenge)" };
      }
      if (response.orgId !== challenge.orgId || response.employeeId !== challenge.employeeId) {
        return { ok: false, reason: "response identity does not match challenge" };
      }
      if (!verify) {
        return {
          ok: false,
          reason: "no Consiglio verifier wired — PQ signature was NOT checked (demo). Refusing to authenticate.",
          authenticated: false,
        };
      }
      let res = null;
      try {
        res = verify(challenge, response);
      } catch {
        res = null; // broken verifier fails closed
      }
      if (!res || res.ok !== true) {
        return { ok: false, reason: (res && res.reason) || "signature did not verify", authenticated: false };
      }
      return { ok: true, employeeId: res.employeeId || challenge.employeeId, role: res.role || null, authenticated: true };
    },
  };
}

/** Fill `n` bytes from the platform CSPRNG (WebCrypto). Fail-closed: throws if
 *  no CSPRNG is available rather than silently downgrading to Math.random. */
function cryptoRandomBytes(n) {
  const c = globalThis.crypto;
  if (!c || typeof c.getRandomValues !== "function") {
    throw new Error("consiglio-bridge: no CSPRNG available (WebCrypto missing) — refusing to issue a weak nonce");
  }
  return c.getRandomValues(new Uint8Array(n));
}

/** A 256-bit nonce as hex, from an injected byte source (CSPRNG by default). */
function nonceHex(randomBytes) {
  const b = randomBytes(32);
  let s = "";
  for (let i = 0; i < b.length; i++) s += (b[i] & 0xff).toString(16).padStart(2, "0");
  return s;
}

/**
 * Adapt a REAL Consiglio binding (the FFI/WASM over crates/postern-consiglio-auth,
 * owned by the console front) into the { issueChallenge, verifyResponse } shape
 * this bridge consumes. The binding does ALL cryptography (Falcon-1024 ‖ ML-DSA-65
 * over the domain-separated transcript); this adapter only marshals shapes and
 * stays fail-closed — a binding that throws or returns a non-ok verdict yields an
 * honest unauthenticated result, never a fake "ok".
 *
 * @param {object} binding
 * @param {(req:{orgId:string,employeeId:string})=>object} binding.issueChallenge
 * @param {(challenge:object,response:object)=>({ok:boolean,employeeId?:string,role?:string,reason?:string})} binding.verifyResponse
 */
export function createConsiglioVerifierAdapter(binding) {
  if (!binding || typeof binding.verifyResponse !== "function") {
    throw new Error("consiglio-bridge: a real binding with verifyResponse() is required");
  }
  return createConsiglioBridge({
    ...(typeof binding.issueChallenge === "function" ? { issueChallenge: binding.issueChallenge } : {}),
    verifyResponse: (challenge, response) => {
      try {
        const r = binding.verifyResponse(challenge, response);
        return r && r.ok === true ? r : { ok: false, reason: (r && r.reason) || "signature did not verify" };
      } catch (e) {
        return { ok: false, reason: "consiglio binding threw (fail-closed): " + (e && e.message ? e.message : "error") };
      }
    },
  });
}

export default { createConsiglioBridge, createConsiglioVerifierAdapter, LOGIN_DOMAIN, DEFAULT_TTL_SECS };
