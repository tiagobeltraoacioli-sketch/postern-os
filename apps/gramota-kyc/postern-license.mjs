// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern licensing — browser-side offline verifier + device sub-minter.
// Reference prototype / UNAUDITED. Demonstrates controls that ENABLE compliance;
// it is NOT compliance and not legal advice. Tamper-EVIDENT, not tamper-proof.
//
// This is the ONE canonical copy. The single-file apps (apps/ezekiel1,
// apps/postern-enterprise/console.html, apps/gramota) inline a byte-identical
// copy of the `makePosternLicense()` body under their strict CSP (no build step,
// so the served bytes == these bytes). Keep them in sync with this file.
//
// It reimplements — byte-for-byte — the canonical serialization + Ed25519 chain
// used by `functions/license/{master,status,renew}.js` and the licensing lib
// (`enterprise/licensing/src`), so a token minted/served there verifies here and
// vice-versa. It rolls NO crypto: every signature op is WebCrypto Ed25519
// (`crypto.subtle`, `{name:"Ed25519"}`), the same primitive both servers use.
//
// Root of trust: the vendor public key is the RAW 32-byte Ed25519 key, standard
// base64, hard-coded in all three Cloudflare functions. Verification is offline;
// nothing here reaches the network.

// The production vendor public key (raw 32-byte Ed25519, standard base64).
// Byte-identical to VENDOR_PUB_RAW_B64 in functions/license/*.js.
export const VENDOR_PUB_RAW_B64 = "iW52PuhJm0+JE+g5UhfrArJ7ONfuUjrm0C38NSwQGm0=";

// Factory so the exact same body can be inlined verbatim into a CSP-locked page.
// `subtle` defaults to the platform WebCrypto; pass one explicitly under Node.
export function makePosternLicense(subtle = (globalThis.crypto && globalThis.crypto.subtle)) {
  // ---- base64 (STANDARD, with padding — NOT base64url) ----
  const b64d = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const enc = (s) => new TextEncoder().encode(s);

  // ---- canonical JSON — byte-identical to the servers' canonical()/canonicalJson ----
  // Sort object keys at EVERY level; compact separators; arrays keep order; drop
  // keys whose value is `undefined` (servers never emit them). Sign/verify over
  // the UTF-8 bytes of this string; the signed object must NOT carry its own sig.
  function canonicalJson(v) {
    if (v === null) return "null";
    if (Array.isArray(v)) return "[" + v.map(canonicalJson).join(",") + "]";
    if (typeof v === "object") {
      const keys = Object.keys(v).filter((k) => v[k] !== undefined).sort();
      return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalJson(v[k])).join(",") + "}";
    }
    return JSON.stringify(v);
  }

  async function verifySig(pubRawB64, payloadObj, sigB64) {
    try {
      const key = await subtle.importKey("raw", b64d(pubRawB64), { name: "Ed25519" }, false, ["verify"]);
      return await subtle.verify({ name: "Ed25519" }, key, b64d(sigB64), enc(canonicalJson(payloadObj)));
    } catch (_e) {
      return false; // fail-closed: an unparseable key/sig is a rejection, never a pass
    }
  }

  async function signPayload(pkcs8B64, payloadObj) {
    const key = await subtle.importKey("pkcs8", b64d(pkcs8B64), { name: "Ed25519" }, false, ["sign"]);
    const sig = await subtle.sign({ name: "Ed25519" }, key, enc(canonicalJson(payloadObj)));
    return b64(sig);
  }

  function randHex(bytes) {
    const b = new Uint8Array(bytes);
    (globalThis.crypto || crypto).getRandomValues(b);
    return Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
  }

  // ---- verifyChain — mirrors enterprise/licensing/src/token.ts:verifyChain ----
  // Accepts the master bundle as served by /license/master
  // ({master_token, master_sig}) plus an optional sub token ({payload, sig}).
  // Fail-closed at every step. `now` is a Date for testability.
  async function verifyChain(vendorPubB64, masterToken, masterSig, sub, now = new Date()) {
    const m = masterToken;
    if (!m || m.v !== 1 || m.typ !== "master") return { ok: false, reason: "malformed-master" };
    if (!(await verifySig(vendorPubB64, m, masterSig))) return { ok: false, reason: "bad-master-signature" };
    if (m.tier === "corporate-master" && !/^\d{9}$/.test(String(m.duns == null ? "" : m.duns)))
      return { ok: false, reason: "bad-duns" };
    const nowSec = Math.floor(now.getTime() / 1000);
    const masterExpired = m.exp <= nowSec;
    if (!sub) {
      return {
        ok: true, level: "master", tier: m.tier, seats: m.seats, duns: m.duns,
        exp: m.exp, expired: masterExpired, master_pub: m.master_pub, masterJti: m.jti,
      };
    }
    const s = sub.payload || sub;
    const ssig = sub.sig;
    if (!s || s.v !== 1 || s.typ !== "sub") return { ok: false, reason: "malformed-sub" };
    if (s.master_pub !== m.master_pub) return { ok: false, reason: "sub-master-mismatch" };
    if (s.exp > m.exp) return { ok: false, reason: "sub-outlives-master" };
    if (!(await verifySig(m.master_pub, s, ssig))) return { ok: false, reason: "bad-sub-signature" };
    const exp = Math.min(s.exp, m.exp);
    return {
      ok: true, level: "sub", tier: m.tier, seats: m.seats, duns: m.duns, exp,
      expired: exp <= nowSec, master_pub: m.master_pub, masterJti: m.jti, subJti: s.jti, sub: s.sub,
    };
  }

  // ---- mintSub — sign a device/seat sub-token with the org master private key ----
  // Chains vendor -> master -> sub. exp is clamped to master.exp. Extra fields
  // (clearance, device) are absent-key-safe: they only affect the org's own
  // downstream gate, and the canonical sign/verify round-trips them intact.
  async function mintSub(pkcs8B64, masterToken, opts) {
    const now = Math.floor((opts.now ? opts.now.getTime() : Date.now()) / 1000);
    const cappedExp = Math.min(opts.exp || masterToken.exp, masterToken.exp);
    const payload = {
      v: 1,
      typ: "sub",
      master_pub: masterToken.master_pub,
      sub: opts.sub,
      iat: now,
      exp: cappedExp,
      jti: randHex(16),
      iss: masterToken.iss,
    };
    if (opts.clearance != null) payload.clearance = opts.clearance;
    if (opts.device) payload.device = opts.device;
    const sig = await signPayload(pkcs8B64, payload);
    return { payload, sig };
  }

  // Serialize a sub token for out-of-band delivery (device installs this string).
  function exportToken(subToken) {
    return JSON.stringify(subToken);
  }

  // Detached Ed25519 signature over an arbitrary policy object (signed-TOML seam).
  // The org signs its policy digest with the master key; a peer verifies with
  // master_pub. Real crypto — distinct from the non-crypto FNV trail display.
  async function signPolicy(pkcs8B64, policyObj) {
    return signPayload(pkcs8B64, policyObj);
  }
  async function verifyPolicy(masterPubB64, policyObj, sigB64) {
    return verifySig(masterPubB64, policyObj, sigB64);
  }

  return {
    VENDOR_PUB_RAW_B64,
    canonicalJson, verifySig, signPayload,
    verifyChain, mintSub, exportToken, signPolicy, verifyPolicy, randHex,
    b64, b64d,
  };
}
