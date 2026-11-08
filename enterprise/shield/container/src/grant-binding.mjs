// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern SHIELD — grant binding & consent gate (Business/Enterprise edition ONLY).
//
// STATUS: design / reference prototype — unaudited, pre-production.
//
// WHAT THIS IS
// ------------
// The one place the SHIELD container's "is this employee still employed here"
// question is answered, and the one place the container's at-rest key is BOUND to
// a LIVE access grant. It mirrors the consent semantics of the shared consent
// kernel (crates/postern-policy: Decision / Expiry / Revocation — fail-closed,
// RFC-3339 expiry required and strictly-future, revoke == never-given, re-checked
// at every boundary) as a JS view. It does NOT re-implement or fork that crate;
// where the crate pins wording (the enforcement caveat) we mirror it verbatim and
// name the crate as the source of truth.
//
// THE KEY-BINDING IDEA (containment by construction, not a kernel boundary)
// ------------------------------------------------------------------------
// Corporate data in the container is sealed at rest. The sealing key is NOT a
// standalone passphrase the employee keeps — it is DERIVED FROM material that is
// only released while the access grant is LIVE (unrevoked and unexpired). Model
// it as: wrappingKey = KDF(grantSecret). Revoke or expire the grant and this
// module refuses to release grantSecret, so the wrapping key cannot be re-derived
// and the sealed blob is unreadable — even before the on-disk bytes are wiped.
//
// SEAL-1 — THE grantSecret IS NEVER PERSISTED (design contract, HARD invariant)
// ----------------------------------------------------------------------------
// The `grantSecret` is memory-only. It is RELEASED BY THE BROKER PER SESSION
// (unwrapped from the live access grant) and lives ONLY in this process's RAM —
// it is NEVER written to disk, a keychain, a log, a cache, or any durable store,
// and it is NEVER embedded in a persisted container blob. The whole
// revoke ⇒ inert guarantee DEPENDS on this: if the secret were on disk, a
// de-provisioned employee (or a rooted OS) could re-derive the wrapping key and
// re-open sealed corporate data after revocation, and revoke() would no longer
// make anything unreadable. Consequences of the invariant, enforced here:
//   * revoke() and zeroize() wipe the in-memory secret immediately (SEAL-2).
//   * the grant object refuses serialization: toJSON() returns a REDACTED view,
//     so an accidental JSON.stringify(grant) → file/log cannot leak the secret.
//   * callers MUST inject grantSecret as in-memory bytes/string from the broker;
//     there is deliberately no "load secret from path" API in this module.
// A caller that persists the secret elsewhere breaks the contract; this module
// cannot stop that, but it never does it itself and documents it prominently
// (see README "The grantSecret is never persisted").
//
// HONEST LIMITS (restated wherever it matters)
// --------------------------------------------
//  * This is a USERLAND, in-process check — "integrity by construction", NOT an
//    OS sandbox or kernel boundary (the exact words postern-policy pins for
//    EnforcementMode::ByConstruction). A rooted / jailbroken phone, a debugger
//    attached to the process, or a RAM capture defeats it. We say so.
//  * Offline revocation is BEST-EFFORT and clock-based: a phone with no signal
//    only learns a grant was revoked when it can re-check, or when the local
//    clock passes the grant's hard expiry. A back-dated device clock can delay
//    the expiry check. This is why grants carry a required, short-ish expiry.

// The canonical enforcement caveat, mirrored VERBATIM from postern-policy's
// EnforcementMode::ByConstruction::honest_label() (crates/postern-policy/src/lib.rs).
// Source of truth is that crate; this is a JS mirror, not a second definition.
export const ENFORCEMENT_LABEL =
  "integrity by construction: a userland, in-process check, not an OS sandbox or kernel boundary";

/** Fail-closed decision, mirroring postern_policy::Decision. */
export const Decision = Object.freeze({
  allow() {
    return Object.freeze({ allow: true, reason: null });
  },
  deny(reason) {
    return Object.freeze({ allow: false, reason: String(reason || "policy is silent; fail-closed default is deny") });
  },
});

/**
 * Parse a REQUIRED, RFC-3339 expiry that must be strictly in the future at check
 * time (mirrors postern_policy::Expiry). Missing / unparseable / already-passed
 * are all fail-closed refusals — never a silent allow.
 *
 * @param {string} value RFC-3339 instant
 * @param {Date} now
 * @returns {{ok:true, at:Date} | {ok:false, error:string}}
 */
export function checkedExpiry(value, now) {
  if (value == null || String(value).trim() === "") {
    return { ok: false, error: "expiry is required but was missing or empty" };
  }
  const at = new Date(value);
  if (Number.isNaN(at.getTime())) {
    return { ok: false, error: `expiry ${JSON.stringify(String(value))} is not a valid RFC 3339 instant` };
  }
  // Inclusive: the instant of expiry itself counts as expired (strictly-future required).
  if (at.getTime() <= now.getTime()) {
    return { ok: false, error: `grant is expired: expires ${at.toISOString()} is not after now ${now.toISOString()}` };
  }
  return { ok: true, at };
}

/**
 * A live access grant for one employee's SHIELD container. It couples the
 * enterprise sub-token identity to the consent gate (revoke/expiry) AND holds the
 * secret material the container's at-rest key is derived from. Revocation is
 * MONOTONIC (once revoked, never un-revoked), matching postern_policy::Revocation.
 *
 * The grant NEVER carries anything about the personal side of the device. Its
 * scope is exactly one corporate container. Personal apps/data are out of scope
 * by construction — there is no field here that could name them.
 *
 * @param {object} spec
 * @param {string} spec.orgId          corporate org id (from the master token)
 * @param {string} spec.employeeId     the sub-token subject (Consiglio identity)
 * @param {string} spec.subToken       the enterprise SUB access token
 * @param {string} spec.expires        REQUIRED RFC-3339 grant expiry (<= master.exp upstream)
 * @param {Uint8Array|string} spec.grantSecret  key material released ONLY while live
 * @param {Date|string|number} [spec.now]
 */
export function createAccessGrant(spec = {}) {
  const orgId = String(spec.orgId || "").trim();
  const employeeId = String(spec.employeeId || "").trim();
  const subToken = String(spec.subToken || "").trim();
  if (!orgId || !employeeId || !subToken) {
    throw new Error("grant-binding: orgId, employeeId and subToken are all required");
  }
  const grantSecret = normalizeSecret(spec.grantSecret);
  if (!grantSecret || grantSecret.length < 16) {
    throw new Error("grant-binding: grantSecret must be at least 16 bytes of key material");
  }
  const clock = () => new Date(spec.now || Date.now());
  const expiresRaw = spec.expires;
  let revoked = false;
  let revokedReason = null;

  /** The consent gate: fold revoke + expiry into one fail-closed Decision. */
  function decide(atNow = clock()) {
    if (revoked) {
      return Decision.deny(revokedReason || "grant revoked: treated as never given");
    }
    const exp = checkedExpiry(expiresRaw, atNow);
    if (!exp.ok) {
      return Decision.deny(`grant expired: treated as never given (${exp.error})`);
    }
    return Decision.allow();
  }

  return {
    orgId,
    employeeId,
    scope: "corporate-container-only",
    get expires() {
      return expiresRaw;
    },
    isLive(atNow) {
      return decide(atNow).allow;
    },
    decide,
    isRevoked() {
      return revoked;
    },
    /** Monotonic local revocation (best-effort offline; server revocation is authoritative). */
    revoke(reason) {
      revoked = true;
      revokedReason = reason ? `grant revoked: ${reason}` : "grant revoked by admin/de-provisioning";
      // SEAL-2: ZEROIZE the released-only-while-live secret material NOW. Once
      // revoked the grant is inert forever (decide() denies; releaseKeyMaterial
      // throws), so the secret can never be legitimately released again — drop it
      // from memory immediately rather than waiting for GC. This is what makes
      // "revoke ⇒ inert" a real drop of key material, not just a boolean flag.
      if (grantSecret && typeof grantSecret.fill === "function") grantSecret.fill(0);
      return decide();
    },
    /** The sub-token, for the access broker's Consiglio challenge/response. */
    subTokenForBroker() {
      return subToken;
    },
    /**
     * Release the key material the container's at-rest key is derived from —
     * ONLY while the grant is live. Revoked/expired => throws, so the wrapping
     * key cannot be re-derived and sealed corporate data stays unreadable. This
     * is the "key bound to the live grant" invariant, enforced here.
     */
    releaseKeyMaterial(atNow = clock()) {
      const d = decide(atNow);
      if (!d.allow) {
        throw new GrantRevoked(d.reason);
      }
      // Return a copy so callers can zeroize their own without mutating ours.
      return Uint8Array.prototype.slice.call(grantSecret);
    },
    /** Best-effort wipe of the in-memory grant secret (not a RAM-capture defense). */
    zeroize() {
      if (grantSecret && typeof grantSecret.fill === "function") grantSecret.fill(0);
    },
    /**
     * SEAL-1 guard: the grant MUST NOT be serialized to disk or a log with its
     * secret. grantSecret lives in a closure (never an enumerable field), so a
     * plain JSON.stringify(grant) already cannot reach it — but we make the
     * memory-only invariant explicit by returning a REDACTED view here, so any
     * accidental serialization is self-documenting rather than a silent leak.
     */
    toJSON() {
      return {
        orgId,
        employeeId,
        scope: "corporate-container-only",
        expires: expiresRaw,
        revoked,
        grantSecret: "[REDACTED — memory-only, broker-released per session, never persisted (SEAL-1)]",
      };
    },
    enforcement: { mode: "by-construction", label: ENFORCEMENT_LABEL, osEnforced: false },
  };
}

export class GrantRevoked extends Error {
  constructor(reason) {
    super(reason || "access grant is revoked or expired");
    this.name = "GrantRevoked";
  }
}

function normalizeSecret(s) {
  if (s == null) return null;
  if (s instanceof Uint8Array) return Uint8Array.prototype.slice.call(s);
  if (typeof s === "string") {
    if (typeof Buffer !== "undefined") return new Uint8Array(Buffer.from(s, "utf8"));
    return new TextEncoder().encode(s);
  }
  if (Array.isArray(s)) return Uint8Array.from(s);
  return null;
}

export default { Decision, checkedExpiry, createAccessGrant, GrantRevoked, ENFORCEMENT_LABEL };
