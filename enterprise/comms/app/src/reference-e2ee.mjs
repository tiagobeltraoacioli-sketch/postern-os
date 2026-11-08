// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Bloch — org internal messenger (Business/Enterprise edition ONLY).
// Message-BODY transport seam + a clearly-labelled REFERENCE fallback.
//
// STATUS: design / reference prototype — UNAUDITED, pre-production. ADDITIVE.
//
// WHY THIS EXISTS
// ---------------
// The reference `comms-core.post()` stored `body: String(body)` — CLEARTEXT — in
// an in-memory array. That is the exact thing the honesty rails forbid claiming
// away. Bodies must ride an E2EE transport (crates/postern-messenger, Megolm),
// and until that call path exists we must NOT keep plaintext and must NOT claim
// body-E2EE. This module is that call path:
//
//   * A `bodyTransport` is `{ label, e2ee, transport, seal(convId,sender,pt),
//     open(convId,ct) }`. `seal` returns an OPAQUE envelope; `open` returns the
//     plaintext IF the caller holds the keys.
//   * A production deployment injects the REAL transport (Megolm), whose `open`
//     the employer/operator CANNOT call (only participant devices hold keys) —
//     that is body-E2EE, and it sets `e2ee:true`.
//   * When no real transport is wired, `createReferenceBodyTransport()` stands
//     in: it encrypts each body with the AUDITED postern-core AEAD (the COMMS-1
//     seal, reused — not rewritten) under a per-conversation key. This removes
//     the cleartext defect and lets the reference app run, but it is HONESTLY
//     `e2ee:false`: it is in-process envelope confidentiality, NOT the audited
//     end-to-end transport, and it does NOT make Bloch "fully private."
//
// The distinction is load-bearing and never blurred: `e2ee` is `true` ONLY for a
// real transport whose keys the operator cannot hold.

import { defaultSealer, generateStoreKey } from "../persistence/sealed-store.mjs";

const enc = new TextEncoder();
const dec = new TextDecoder();

/** Binding context for a conversation body envelope (fed to the AEAD as AAD). */
function bodyContext(convId) {
  return `bloch-comms/body/v1|${String(convId)}`;
}

/**
 * The REFERENCE body transport. Encrypts bodies with the audited postern-core
 * AEAD under a per-conversation symmetric key held in-process. Clearly labelled
 * `e2ee:false` — it is NOT the Megolm end-to-end transport and the process that
 * runs it CAN open the body (so it is not employer-blind). Use it only so the
 * reference app never stores cleartext; a real deployment injects Megolm.
 *
 * @param {object} [opts]
 * @param {object} [opts.sealer] a `{seal,open}` sealer (defaults to the audited
 *                               COMMS-1 in-process WASM seal).
 */
export function createReferenceBodyTransport(opts = {}) {
  const sealer = opts.sealer || defaultSealer;
  /** @type {Map<string, Uint8Array>} convId -> 32-byte conversation key */
  const keys = new Map();

  function keyFor(convId) {
    const id = String(convId);
    let k = keys.get(id);
    if (!k) {
      k = generateStoreKey();
      keys.set(id, k);
    }
    return k;
  }

  return {
    label:
      "REFERENCE body envelope (audited postern-core AEAD, per-conversation key, " +
      "in-process) — NOT the Megolm E2EE transport; body-E2EE-by-transport is not " +
      "yet wired, so this is e2ee:false and the running process can open the body",
    e2ee: false,
    transport: "reference-envelope",

    /**
     * Encrypt a body into an opaque envelope. Returns `{ ciphertext, e2ee,
     * transport, alg }` — never the plaintext.
     */
    async seal(convId, _sender, plaintext) {
      const pt = plaintext instanceof Uint8Array ? plaintext : enc.encode(String(plaintext ?? ""));
      const ciphertext = await sealer.seal(keyFor(convId), enc.encode(bodyContext(convId)), pt);
      return { ciphertext, e2ee: false, transport: "reference-envelope", alg: "postern-core-aead(ref)" };
    },

    /**
     * Decrypt an envelope back to plaintext (reference transport can, because it
     * holds the key in-process — a real E2EE transport's `open` would refuse for
     * the operator). Fail-closed: a wrong key/context/tamper throws.
     */
    async open(convId, ciphertext) {
      const pt = await sealer.open(keyFor(convId), enc.encode(bodyContext(convId)), ciphertext);
      return dec.decode(pt);
    },
  };
}

export default { createReferenceBodyTransport };
