// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Bloch — org internal messenger (Business/Enterprise edition ONLY).
// Device verification: verify a peer device's E2EE IDENTITY KEY, fail-closed.
//
// STATUS: design / reference prototype — UNAUDITED, pre-production. ADDITIVE.
//
// WHY THIS EXISTS
// ---------------
// The transport (crates/postern-messenger) and transparency.mjs both state the
// honest gap: "no device verification (SAS) yet". A Megolm session is only as
// trustworthy as your confidence that the key you're talking to is really your
// coworker's device — without verification, a malicious/compromised homeserver
// could inject a device and you'd never know. This module closes that gap at the
// app layer: an INTERFACE + FLOW to verify a peer device's identity key
// out-of-band (fingerprint compare) or interactively (SAS emoji/decimal).
//
// FAIL-CLOSED, ALWAYS
// -------------------
//  - Every device starts UNVERIFIED. Unverified is a FLAG, never silent trust.
//  - `isTrusted()` is true ONLY for a device the user explicitly verified.
//  - A fingerprint/SAS MISMATCH -> BLOCKED (a possible MITM), never a shrug.
//  - An identity-key CHANGE on an already-verified device -> re-flagged
//    UNVERIFIED (TOFU break), never auto-re-trusted.
//  - `guardSend()` refuses (throws) toward a device that is not verified, so a
//    caller cannot "accidentally" send to an unverified peer.
//
// WHAT THIS IS / IS NOT
// ---------------------
// This models the verification STATE MACHINE and a REFERENCE short-authentication
// -string derivation. It does NOT implement the real Matrix key-verification
// protocol (m.key.verification.* / QR / cross-signing) and does NOT run an ECDH:
// the reference SAS below is a transcript hash over both identity-key
// fingerprints, mapped to the standard Matrix emoji table — enough to drive an
// honest UX and self-check, explicitly NOT the audited SAS. A real deployment
// binds vodozemac/matrix-sdk verification and passes the resulting decision in.

/** Trust states. UNVERIFIED is the fail-closed default; only VERIFIED trusts. */
export const Trust = Object.freeze({
  UNVERIFIED: "unverified",
  VERIFIED: "verified",
  BLOCKED: "blocked", // mismatch / suspected MITM — actively distrusted
});

/** Human-honest badges (never render an unverified device as safe). */
export function trustBadge(state) {
  switch (state) {
    case Trust.VERIFIED:
      return "✅ Verified device";
    case Trust.BLOCKED:
      return "⛔ Verification FAILED — do not trust this device";
    default:
      return "⚠ Unverified device — identity not confirmed";
  }
}

/** Thrown by guardSend() when a caller tries to send toward a non-verified device. */
export class UnverifiedDeviceError extends Error {
  constructor(deviceId, state) {
    super(
      `device "${deviceId}" is ${state} — refusing to send toward an unverified device ` +
        `(verify it out-of-band or via SAS first). Bloch fails closed.`,
    );
    this.name = "UnverifiedDeviceError";
    this.deviceId = deviceId;
    this.state = state;
  }
}

function normFingerprint(identityKey) {
  // Fingerprint = the device's public Ed25519 identity key, normalized for a
  // stable compare (strip spaces, uppercase). We treat the key string as opaque.
  if (identityKey == null) return "";
  return String(identityKey).replace(/\s+/g, "").toUpperCase();
}

async function sha256(bytes) {
  const c = globalThis.crypto;
  if (!c || !c.subtle) {
    throw new Error("device-verification: no WebCrypto for SAS derivation (inject a real verifier)");
  }
  return new Uint8Array(await c.subtle.digest("SHA-256", bytes));
}

// The 64-emoji Matrix SAS table (MSC1946 / spec) — used verbatim so the UX
// matches every other Matrix client. Reference derivation only (see header).
const SAS_EMOJI = [
  "🐶", "🐱", "🦁", "🐎", "🦄", "🐷", "🐘", "🐰", "🐼", "🐓", "🐧", "🐢",
  "🐟", "🐙", "🦋", "🌷", "🌳", "🌵", "🍄", "🌏", "🌙", "☁️", "🔥", "🍌",
  "🍎", "🍓", "🌽", "🍕", "🎂", "❤️", "😀", "🤖", "🎩", "👓", "🔧", "🎅",
  "👍", "☂️", "⌛", "⏰", "🎁", "💡", "📕", "✏️", "📎", "✂️", "🔒", "🔑",
  "🔨", "☎️", "🏁", "🚂", "🚲", "✈️", "🚀", "🏆", "⚽", "🎸", "🎺", "🔔",
  "⚓", "🎧", "📁", "📌",
];

/** Map raw SAS bytes -> 7 emoji indices (6 bits each), Matrix-style. */
function sasEmoji(bytes) {
  // 7 emoji * 6 bits = 42 bits -> need 6 bytes.
  let bits = 0n;
  for (let i = 0; i < 6; i++) bits = (bits << 8n) | BigInt(bytes[i] || 0);
  const out = [];
  for (let i = 0; i < 7; i++) {
    const shift = BigInt(42 - 6 * (i + 1));
    const idx = Number((bits >> shift) & 0x3fn);
    out.push({ index: idx, emoji: SAS_EMOJI[idx] });
  }
  return out;
}

/** Map raw SAS bytes -> three 4-digit decimals (13 bits each), Matrix-style. */
function sasDecimal(bytes) {
  let bits = 0n;
  for (let i = 0; i < 5; i++) bits = (bits << 8n) | BigInt(bytes[i] || 0);
  const d = [];
  for (let i = 0; i < 3; i++) {
    const shift = BigInt(40 - 13 * (i + 1));
    d.push(Number((bits >> shift) & 0x1fffn) + 1000);
  }
  return d;
}

/**
 * The device verification registry: the app's source of truth for which peer
 * devices are trusted. Fail-closed by construction.
 *
 * @param {object} [opts]
 * @param {(bytes:Uint8Array)=>Promise<Uint8Array>} [opts.digest] override the SAS digest
 */
export function createDeviceVerifier(opts = {}) {
  const digest = typeof opts.digest === "function" ? opts.digest : sha256;
  /** @type {Map<string,{deviceId:string,owner:string,fingerprint:string,state:string,verifiedAt:?string,method:?string}>} */
  const devices = new Map();

  function get(deviceId) {
    return devices.get(String(deviceId));
  }

  return {
    Trust,

    /**
     * Register (or re-observe) a peer device and its E2EE identity key. New
     * devices are UNVERIFIED. If a KNOWN device presents a DIFFERENT identity
     * key, that is a TOFU break: it is re-flagged UNVERIFIED (never auto-trusted).
     */
    observe(deviceId, identityKey, owner) {
      const id = String(deviceId);
      const fp = normFingerprint(identityKey);
      if (!id) throw new Error("device-verification: a device id is required");
      if (!fp) throw new Error("device-verification: an identity key is required");
      const prev = devices.get(id);
      if (prev && prev.fingerprint !== fp) {
        // Identity key changed under us — distrust until re-verified.
        prev.fingerprint = fp;
        prev.state = Trust.UNVERIFIED;
        prev.verifiedAt = null;
        prev.method = null;
        prev.keyChanged = true;
        return this.status(id);
      }
      if (!prev) {
        devices.set(id, {
          deviceId: id,
          owner: owner != null ? String(owner) : null,
          fingerprint: fp,
          state: Trust.UNVERIFIED,
          verifiedAt: null,
          method: null,
          keyChanged: false,
        });
      } else if (owner != null) {
        prev.owner = String(owner);
      }
      return this.status(id);
    },

    /** Current trust status of a device (fail-closed: unknown => UNVERIFIED). */
    status(deviceId) {
      const d = get(deviceId);
      if (!d) {
        return {
          deviceId: String(deviceId),
          known: false,
          state: Trust.UNVERIFIED,
          badge: trustBadge(Trust.UNVERIFIED),
          trusted: false,
        };
      }
      return {
        deviceId: d.deviceId,
        owner: d.owner,
        known: true,
        fingerprint: d.fingerprint,
        state: d.state,
        method: d.method,
        verifiedAt: d.verifiedAt,
        keyChanged: !!d.keyChanged,
        badge: trustBadge(d.state),
        trusted: d.state === Trust.VERIFIED,
      };
    },

    /** The one predicate callers must gate on. True ONLY for VERIFIED devices. */
    isTrusted(deviceId) {
      const d = get(deviceId);
      return !!d && d.state === Trust.VERIFIED;
    },

    /**
     * OUT-OF-BAND verification: the user reads the peer's fingerprint over a
     * trusted channel (in person, signed doc, phone) and enters/scans it.
     * VERIFIES only on an EXACT match; a mismatch -> BLOCKED (possible MITM).
     */
    verifyOutOfBand(deviceId, presentedFingerprint) {
      const d = get(deviceId);
      if (!d) throw new Error(`device-verification: unknown device "${deviceId}" — observe() it first`);
      const presented = normFingerprint(presentedFingerprint);
      if (!presented) throw new Error("device-verification: a fingerprint to compare is required");
      if (presented === d.fingerprint) {
        d.state = Trust.VERIFIED;
        d.method = "out-of-band";
        d.verifiedAt = new Date().toISOString();
        d.keyChanged = false;
      } else {
        d.state = Trust.BLOCKED;
        d.method = "out-of-band";
        d.verifiedAt = null;
      }
      return this.status(deviceId);
    },

    /**
     * Begin an interactive SAS. Returns the short authentication string (emoji +
     * decimal) BOTH sides compute from the two identity-key fingerprints and a
     * transcript salt. The users compare it OUT OF BAND, then call confirmSas().
     * Reference derivation only (see header) — not the audited m.key.verification.
     *
     * @param {string} deviceId    the peer device being verified
     * @param {string} myFingerprint  this device's own identity-key fingerprint
     * @param {string} [transcript]   a shared per-attempt salt (both sides use the same)
     */
    async beginSas(deviceId, myFingerprint, transcript = "bloch-sas/v1") {
      const d = get(deviceId);
      if (!d) throw new Error(`device-verification: unknown device "${deviceId}" — observe() it first`);
      const mine = normFingerprint(myFingerprint);
      if (!mine) throw new Error("device-verification: your own fingerprint is required for SAS");
      // Order-independent transcript so both sides derive the same SAS.
      const both = [mine, d.fingerprint].sort().join("|");
      const material = new TextEncoder().encode(`bloch-sas/v1|${transcript}|${both}`);
      const bytes = await digest(material);
      return Object.freeze({
        deviceId: d.deviceId,
        emoji: sasEmoji(bytes),
        decimal: sasDecimal(bytes),
        instruction:
          "Compare these with your coworker OVER A TRUSTED CHANNEL (in person / a call you both recognise). " +
          "Only confirm if they match EXACTLY on both devices.",
      });
    },

    /**
     * Finish a SAS. `matched` MUST be the users' explicit "yes, identical"
     * decision. true -> VERIFIED; false -> BLOCKED (fail-closed, treat a
     * non-match as a possible attack, not a retry-later).
     */
    confirmSas(deviceId, matched) {
      const d = get(deviceId);
      if (!d) throw new Error(`device-verification: unknown device "${deviceId}" — observe() it first`);
      if (matched === true) {
        d.state = Trust.VERIFIED;
        d.method = "sas";
        d.verifiedAt = new Date().toISOString();
        d.keyChanged = false;
      } else {
        d.state = Trust.BLOCKED;
        d.method = "sas";
        d.verifiedAt = null;
      }
      return this.status(deviceId);
    },

    /**
     * Fail-closed send guard. Throws UnverifiedDeviceError unless the device is
     * VERIFIED. Wrap outbound sends with this so an unverified/blocked device is
     * never silently trusted.
     */
    guardSend(deviceId) {
      if (!this.isTrusted(deviceId)) {
        const st = this.status(deviceId);
        throw new UnverifiedDeviceError(String(deviceId), st.state);
      }
      return true;
    },

    /** All known devices and their status (e.g. for a "device audit" panel). */
    list() {
      return [...devices.keys()].map((id) => this.status(id));
    },

    /** Devices that are NOT verified (what a security-review UI must surface). */
    unverified() {
      return this.list().filter((s) => s.state !== Trust.VERIFIED);
    },
  };
}

export default {
  Trust,
  trustBadge,
  UnverifiedDeviceError,
  createDeviceVerifier,
};
