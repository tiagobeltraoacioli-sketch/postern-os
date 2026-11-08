// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Bloch — org internal messenger (Business/Enterprise edition ONLY).
// Persistence: message/session storage SEALED AT REST, keyed locally.
//
// STATUS: design / reference prototype — UNAUDITED, pre-production. ADDITIVE.
//
// WHY THIS EXISTS
// ---------------
// The messenger transport (crates/postern-messenger, the `matrix` slice) runs
// today on the SDK's IN-MEMORY store: Megolm sessions and replay state do NOT
// survive a restart (see that crate's "Persistence" honest-limit note). This
// module is the app-layer answer: a local, sealed-at-rest store so a device's
// sessions + message envelopes survive a restart WITHOUT ever writing key
// material or ciphertext to disk in the clear.
//
// WHAT THIS IS / IS NOT
// ---------------------
//  - It stores OPAQUE records the app hands it: Megolm session material,
//    per-conversation metadata, and message ENVELOPES. Message BODIES stay
//    end-to-end encrypted by the transport (this module never decrypts them);
//    the at-rest seal here is an ADDITIONAL local-device protection on top.
//  - It is HONEST about the seal. The canonical Postern seal is
//    `postern_core::aead` — XChaCha20-Poly1305, versioned, key-committing,
//    context-bound (the exact construction crates/postern-vault seals with).
//    That seal is Rust. The DEFAULT here binds it IN-PROCESS via WASM
//    (`postern-seal-wasm.mjs` -> `seal-wasm/`, built from postern-core): the
//    32-byte store key never crosses a process boundary and the seal nonce is
//    drawn from the host CSPRNG. So sessions are sealed with the AUDITED
//    primitive, not a placeholder.
//  - LAST-RESORT FALLBACK, not the default: a REFERENCE WebCrypto AES-256-GCM
//    sealer (context as AAD, a version byte). It is deliberately NOT the audited
//    Postern seal (no key commitment) and is used ONLY when the real WASM
//    binding is not built (e.g. a browser with no artifact, or a machine with no
//    Rust/wasm toolchain), so the reference app and its self-check still run
//    standalone. It is clearly labelled and MUST NOT be shipped as "the seal".
//    Its 0x01 version byte differs from the real seal's 0x02, so a blob sealed
//    by one is rejected (fail-closed) by the other — never silently mis-opened.
//  - Metadata remains org-visible by design (see transparency.mjs). Sealing at
//    rest protects the LOCAL device's copy; it does not make Bloch "fully
//    private" — the homeserver still sees the social graph.
//
// KEYING: the 32-byte store key is LOCAL to the device (generate() below, or
// derived by the host from a device passphrase / OS keystore). It is never sent
// to the homeserver and never embedded in the sealed blob.

/** Reference wire-format version byte (NOT the Postern-seal v2 format). */
const REF_VERSION = 0x01;
const IV_LEN = 12; // AES-GCM nonce
const TAG_LEN = 16; // GCM tag (WebCrypto appends it to the ciphertext)

/** Default binding context — mirrors postern-vault's `VAULT_CONTEXT` idea. */
export const STORE_CONTEXT = "bloch-comms/persistence/v1";

/** Thrown when a sealed blob is corrupt, truncated, or fails authentication. */
export class SealError extends Error {
  constructor(message) {
    super(message);
    this.name = "SealError";
  }
}

function textBytes(s) {
  return new TextEncoder().encode(s);
}

function webcrypto() {
  const c = globalThis.crypto;
  if (!c || !c.subtle) {
    throw new SealError(
      "no WebCrypto available: inject a real sealer (the postern-core seal) via opts.sealer",
    );
  }
  return c;
}

/**
 * The default REFERENCE sealer: WebCrypto AES-256-GCM, context bound as AAD,
 * one leading version byte. Shape only mirrors the Postern seal; it is NOT the
 * audited construction. Both methods are async (real seals — WASM/HSM — are too).
 *
 * A `sealer` is any `{ seal(key,ctx,pt)->Promise<Uint8Array>, open(key,ctx,blob)->Promise<Uint8Array> }`.
 */
export const referenceSealer = Object.freeze({
  label:
    "LAST-RESORT FALLBACK (WebCrypto AES-256-GCM) — NOT the audited postern-core seal; " +
    "used only when the real in-process WASM seal is unavailable",
  async seal(key, context, plaintext) {
    const c = webcrypto();
    const k = await c.subtle.importKey("raw", key, "AES-GCM", false, ["encrypt"]);
    const iv = c.getRandomValues(new Uint8Array(IV_LEN));
    const ct = new Uint8Array(
      await c.subtle.encrypt({ name: "AES-GCM", iv, additionalData: context }, k, plaintext),
    );
    const out = new Uint8Array(1 + IV_LEN + ct.length);
    out[0] = REF_VERSION;
    out.set(iv, 1);
    out.set(ct, 1 + IV_LEN);
    return out;
  },
  async open(key, context, sealed) {
    if (!(sealed instanceof Uint8Array) || sealed.length < 1 + IV_LEN + TAG_LEN) {
      throw new SealError("sealed blob is truncated or not bytes");
    }
    if (sealed[0] !== REF_VERSION) {
      throw new SealError("unknown sealed-blob version — wrong sealer or corrupt data");
    }
    const c = webcrypto();
    const iv = sealed.subarray(1, 1 + IV_LEN);
    const ct = sealed.subarray(1 + IV_LEN);
    const k = await c.subtle.importKey("raw", key, "AES-GCM", false, ["decrypt"]);
    try {
      return new Uint8Array(
        await c.subtle.decrypt({ name: "AES-GCM", iv, additionalData: context }, k, ct),
      );
    } catch {
      // Fail-closed: wrong key, wrong context, or tampered data -> no plaintext.
      throw new SealError("open failed — wrong key, wrong context, or tampered data");
    }
  },
});

/**
 * The DEFAULT sealer: the REAL, audited postern-core seal (XChaCha20-Poly1305,
 * key-committing), bound IN-PROCESS via the WASM loader in
 * `./postern-seal-wasm.mjs`. It is lazy — the WASM is loaded on first seal/open
 * and cached — so the store constructor stays synchronous and browser-safe
 * (the Node-only loader is imported dynamically, never at module top level).
 *
 * If the real binding cannot be loaded (artifact not built / no toolchain), it
 * transparently falls back to the labelled `referenceSealer` (AES-256-GCM) so
 * the app + self-check still run standalone. This is a fallback, NOT a silent
 * downgrade of a real deployment: the seal versions differ (0x02 vs 0x01), so a
 * blob sealed by the real seal can never be mis-opened by the fallback — it
 * fails closed. Open always fails closed (wrong key/context/tamper -> throws).
 */
let _defaultBackend = null; // Promise<realSealer | null>; null => referenceSealer

/** Resolve (once, cached) the active default backend: the real WASM seal if it
 * loads, else the labelled reference sealer. Never resolves to plaintext. */
async function resolveDefaultBackend() {
  if (!_defaultBackend) {
    _defaultBackend = (async () => {
      try {
        const mod = await import("./postern-seal-wasm.mjs");
        return mod.loadRealSealer(); // throws if the artifact is missing
      } catch {
        // Fall back ONLY to the clearly-labelled reference seal (never to
        // plaintext): keeps the reference app runnable without the toolchain.
        return null;
      }
    })();
  }
  return (await _defaultBackend) || referenceSealer;
}

/**
 * Whether the DEFAULT store is sealing with the REAL audited seal (true) or the
 * labelled reference fallback (false). Async because the WASM loads lazily.
 * Useful for a deployment/self-check to assert it is on the real primitive.
 */
export async function defaultSealIsReal() {
  const backend = await resolveDefaultBackend();
  return backend.__real === true;
}

export const defaultSealer = Object.freeze({
  label:
    "DEFAULT: REAL postern-core seal (in-process WASM); AES-256-GCM reference " +
    "ONLY as a last-resort fallback when the WASM binding is unbuilt",

  async seal(key, context, plaintext) {
    return (await resolveDefaultBackend()).seal(key, context, plaintext);
  },
  async open(key, context, sealed) {
    try {
      return await (await resolveDefaultBackend()).open(key, context, sealed);
    } catch (e) {
      // Normalise any real-seal error into the store's SealError so callers
      // (and the self-check) see one fail-closed type regardless of backend.
      throw e instanceof SealError
        ? e
        : new SealError("open failed — wrong key, wrong context, or tampered data");
    }
  },
});

/** Generate a fresh 32-byte LOCAL store key. Keep it on-device; never upload it. */
export function generateStoreKey() {
  return webcrypto().getRandomValues(new Uint8Array(32));
}

function assertKey(key) {
  if (!(key instanceof Uint8Array) || key.length !== 32) {
    throw new SealError("store key must be a 32-byte Uint8Array (see generateStoreKey())");
  }
}

/**
 * A local, sealable message/session store. Modeled after postern-vault's
 * `Vault` (put/get + seal/open) so the persistence rail matches the rest of the
 * Postern suite. In-memory while open; `seal()` produces the at-rest blob.
 *
 * @param {object} [opts]
 * @param {object}  [opts.sealer]  a `{seal,open}` sealer (defaults to referenceSealer)
 * @param {string}  [opts.context] binding context string (defaults to STORE_CONTEXT)
 * @param {object}  [opts.state]   initial state (used by openSealedStore)
 */
export function createSealedStore(opts = {}) {
  const sealer = opts.sealer || defaultSealer;
  const context = textBytes(opts.context || STORE_CONTEXT);
  const contextLabel = opts.context || STORE_CONTEXT;

  // Persisted state. `sessions` and `devices` hold key/verification material
  // (sensitive -> the whole thing is sealed). `messages` holds ENVELOPES only
  // (bodies stay E2EE; we store what the app already treats as at-rest data).
  const state = {
    schema: "bloch-comms/persistence/v1",
    sessions: {}, // deviceId/sessionId -> opaque session record
    devices: {}, // deviceId -> { identityKey, trust } verification snapshot
    conversations: {}, // convId -> { id, type, members, tier }
    messages: [], // { convId, sender, at, tier, envelope }
  };
  if (opts.state && typeof opts.state === "object") {
    Object.assign(state, sanitizeState(opts.state));
  }

  return {
    contextLabel,
    sealerLabel: sealer.label || "(injected sealer)",

    /** Store (or replace) an opaque Megolm session record under an id. */
    putSession(id, record) {
      if (!id) throw new Error("sealed-store: a session id is required");
      state.sessions[String(id)] = record;
      return this;
    },
    getSession(id) {
      return state.sessions[String(id)];
    },
    sessionIds() {
      return Object.keys(state.sessions);
    },

    /** Snapshot a device's identity key + trust state (from verification/). */
    putDevice(deviceId, snapshot) {
      if (!deviceId) throw new Error("sealed-store: a device id is required");
      state.devices[String(deviceId)] = snapshot;
      return this;
    },
    getDevice(deviceId) {
      return state.devices[String(deviceId)];
    },

    /** Record conversation metadata (org-visible either way; persisted locally). */
    putConversation(conv) {
      if (!conv || !conv.id) throw new Error("sealed-store: conversation needs an id");
      state.conversations[String(conv.id)] = {
        id: conv.id,
        type: conv.type,
        members: conv.members,
        tier: conv.tier,
      };
      return this;
    },

    /**
     * Append a message ENVELOPE. `envelope` is the at-rest form (e.g. the
     * transport's Megolm ciphertext ref) — this module never sees plaintext.
     */
    appendMessage(convId, envelope) {
      if (!convId) throw new Error("sealed-store: a conversation id is required");
      state.messages.push({
        convId: String(convId),
        sender: envelope && envelope.sender,
        at: (envelope && envelope.at) || new Date().toISOString(),
        tier: envelope && envelope.tier,
        envelope: envelope && envelope.envelope,
      });
      return this;
    },
    messagesFor(convId) {
      return state.messages.filter((m) => m.convId === String(convId));
    },

    /** A read-only view of the current state (for the UI / debugging). */
    snapshot() {
      return JSON.parse(JSON.stringify(state));
    },

    /**
     * Seal the whole store at rest under a 32-byte LOCAL key. Async (the seal
     * primitive is). Output is the sealer's opaque blob — persist it as-is.
     */
    async seal(key) {
      assertKey(key);
      const plaintext = textBytes(JSON.stringify(state));
      return sealer.seal(key, context, plaintext);
    },
  };
}

/**
 * Open a previously sealed store. FAIL-CLOSED: a wrong key, wrong context, or
 * tampered blob throws SealError and yields NO store (never a partial/plaintext
 * fallback). This is how "sessions survive restart" — reopen with the local key.
 *
 * @param {Uint8Array} sealed
 * @param {Uint8Array} key      the 32-byte local key used to seal
 * @param {object} [opts]       { sealer, context } — must match how it was sealed
 */
export async function openSealedStore(sealed, key, opts = {}) {
  const sealer = opts.sealer || defaultSealer;
  const context = textBytes(opts.context || STORE_CONTEXT);
  assertKey(key);
  const plain = await sealer.open(key, context, sealed); // throws on any failure
  let parsed;
  try {
    parsed = JSON.parse(new TextDecoder().decode(plain));
  } catch {
    throw new SealError("sealed store opened but its contents are not valid — refusing");
  }
  return createSealedStore({ sealer, context: opts.context, state: parsed });
}

/** Keep only the known state fields (never trust arbitrary injected shapes). */
function sanitizeState(s) {
  return {
    sessions: (s.sessions && typeof s.sessions === "object") ? s.sessions : {},
    devices: (s.devices && typeof s.devices === "object") ? s.devices : {},
    conversations: (s.conversations && typeof s.conversations === "object") ? s.conversations : {},
    messages: Array.isArray(s.messages) ? s.messages : [],
  };
}

export default {
  STORE_CONTEXT,
  SealError,
  defaultSealer,
  defaultSealIsReal,
  referenceSealer,
  generateStoreKey,
  createSealedStore,
  openSealedStore,
};
