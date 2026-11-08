// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern SHIELD — shielded work-container (Business/Enterprise edition ONLY).
//
// STATUS: design / reference prototype — unaudited, pre-production.
//
// WHAT THIS IS
// ------------
// A model of a SHIELDED WORK-CONTAINER that lives on a personal phone. Corporate
// data lives ONLY inside it, sealed at rest, strictly segregated from the personal
// OS, and its at-rest key is bound to a LIVE access grant (see grant-binding.mjs)
// so that revoking the employee's access renders the sealed data unreadable and
// triggers a self-wipe of the container's OWN corporate data.
//
// NO HARDCODED CRYPTO — the seal is the canonical Postern seal
// ------------------------------------------------------------
// At rest the container uses the Postern seal exactly as crates/postern-vault
// does: XChaCha20-Poly1305 (versioned, key-committing, context-bound) with the
// 32-byte wrapping key derived by Argon2id. This module does NOT implement that
// crypto and does NOT import it. It plugs into an injected `seal` engine:
//
//     seal(key32, plaintextBytes)  -> sealedBytes
//     open(key32, sealedBytes)     -> plaintextBytes   (throws on wrong key / tamper)
//     deriveKey(secretBytes, salt) -> key32            (Argon2id, per postern-vault)
//
// A real deployment wires postern-vault (via FFI/WASM) here. If no engine is
// injected, a CLEARLY-LABELLED, NON-CRYPTOGRAPHIC demo engine is used so the model
// is explorable — it never claims to protect anything. See makeDemoSealEngine().
//
// SEGREGATION & SCOPE (corporate-only, by construction)
// -----------------------------------------------------
// Every item stored is namespaced under the corporate container. Item names are
// validated to be corporate-scoped; there is deliberately NO API here that can
// read, name, enumerate, or touch the personal side of the device. The personal
// OS is out of scope by construction — this code cannot reach it.
//
// HONEST LIMITS
// -------------
//  * Containment is BY CONSTRUCTION (userland), NOT a kernel boundary. A rooted /
//    jailbroken phone, a debugger on this process, or a RAM capture defeats it.
//  * A "self-wipe" here overwrites and drops the sealed blob this container holds.
//    On a personal device we CANNOT guarantee a remote wipe (no signal, powered
//    off, or a hostile owner who copied the blob first). We say so plainly.

import { GrantRevoked } from "./grant-binding.mjs";

const CORP_SCOPE_PREFIX = "corp/";

/**
 * Create a shielded work-container bound to one live access grant.
 *
 * @param {object} opts
 * @param {ReturnType<import("./grant-binding.mjs").createAccessGrant>} opts.grant
 * @param {{seal:Function, open:Function, deriveKey:Function}} [opts.sealEngine]
 *        injected Postern seal (postern-vault); omitted => labelled demo engine.
 * @param {Uint8Array} [opts.salt] KDF salt stored alongside the sealed blob.
 * @param {(evt:object)=>void} [opts.audit] optional local audit sink (corporate-scope events only).
 */
export function createShieldContainer(opts = {}) {
  const grant = opts.grant;
  if (!grant || typeof grant.releaseKeyMaterial !== "function") {
    throw new Error("shield-container: a live access grant (grant-binding.createAccessGrant) is required");
  }
  const engine = opts.sealEngine || makeDemoSealEngine();
  assertEngine(engine);
  const salt = opts.salt instanceof Uint8Array ? opts.salt : defaultSalt(grant.orgId, grant.employeeId);
  const audit = typeof opts.audit === "function" ? opts.audit : () => {};
  const usingDemoEngine = !!engine.__demo;

  // In-memory plaintext working set for the corporate container (names -> bytes).
  // This is the decrypted, "container is open" state; it is dropped on lock/wipe.
  /** @type {Map<string, Uint8Array>} */
  let plain = new Map();
  // The sealed-at-rest blob (what would persist to the container's private store).
  let sealedBlob = null;
  let wiped = false;
  let open = false;

  function requireCorpName(name) {
    const n = String(name || "");
    if (!n || n.includes("..") || n.startsWith("/") || n.startsWith("~")) {
      throw new ScopeViolation(`item name ${JSON.stringify(n)} is not a valid corporate-scope name`);
    }
    // Force the corporate namespace. There is no way to address the personal side.
    return n.startsWith(CORP_SCOPE_PREFIX) ? n : CORP_SCOPE_PREFIX + n;
  }

  function wrappingKey(now) {
    // Bound to the LIVE grant: releaseKeyMaterial throws if revoked/expired, so
    // the key cannot be re-derived once the employee has been de-provisioned.
    const material = grant.releaseKeyMaterial(now); // GrantRevoked if not live
    try {
      return engine.deriveKey(material, salt);
    } finally {
      if (material && material.fill) material.fill(0);
    }
  }

  return {
    orgId: grant.orgId,
    employeeId: grant.employeeId,
    scope: "corporate-container-only",
    usingRealCrypto: !usingDemoEngine,
    enforcement: grant.enforcement,

    /** Is the container currently unsealed in memory? */
    isOpen() {
      return open && !wiped;
    },
    isWiped() {
      return wiped;
    },

    /**
     * Unseal the container into memory. Requires the grant to be LIVE; a revoked
     * or expired grant cannot derive the key, so this throws GrantRevoked and the
     * corporate data stays unreadable.
     */
    unlock(now) {
      if (wiped) throw new ContainerWiped();
      const key = wrappingKey(now); // throws GrantRevoked if de-provisioned
      try {
        plain = sealedBlob ? deserializeItems(engine.open(key, sealedBlob)) : new Map();
      } finally {
        if (key && key.fill) key.fill(0);
      }
      open = true;
      audit({ event: "container.unlock", orgId: grant.orgId, employeeId: grant.employeeId, at: nowIso(now) });
      return true;
    },

    /** Store a corporate item (must be unlocked & live). */
    put(name, bytes, now) {
      ensureOpen();
      const key = requireCorpName(name);
      plain.set(key, toBytes(bytes));
      audit({ event: "container.put", item: key, at: nowIso(now) });
      return key;
    },

    /** Read a corporate item. */
    get(name) {
      ensureOpen();
      const key = requireCorpName(name);
      const v = plain.get(key);
      return v ? Uint8Array.prototype.slice.call(v) : null;
    },

    /** Corporate item names only (never anything personal — there is nothing personal here). */
    names() {
      ensureOpen();
      return [...plain.keys()].sort();
    },

    /**
     * Seal the working set back to rest under a freshly derived, grant-bound key.
     * Requires the grant to be LIVE. Returns the sealed blob (opaque bytes).
     */
    seal(now) {
      ensureOpen();
      const key = wrappingKey(now);
      try {
        sealedBlob = engine.seal(key, serializeItems(plain));
      } finally {
        if (key && key.fill) key.fill(0);
      }
      audit({ event: "container.seal", bytes: sealedBlob.length, at: nowIso(now) });
      return Uint8Array.prototype.slice.call(sealedBlob);
    },

    /** The opaque sealed-at-rest blob, if any (unreadable without the live grant). */
    sealedAtRest() {
      return sealedBlob ? Uint8Array.prototype.slice.call(sealedBlob) : null;
    },

    /** Drop the in-memory plaintext but keep the sealed blob (screen lock analogue). */
    lock() {
      zeroizeMap(plain);
      plain = new Map();
      open = false;
      return true;
    },

    /**
     * DE-PROVISIONING = LEAVING. Self-wipe the container's OWN corporate data:
     * zeroize in-memory plaintext AND overwrite+drop the sealed-at-rest blob, then
     * mark the container permanently wiped. Idempotent.
     *
     * HONEST: this wipes what THIS container holds on THIS process/store. On a
     * personal device we cannot guarantee the bytes are gone everywhere (a copy
     * may have been exfiltrated by a rooted OS before revocation). Not a remote
     * "kill" guarantee.
     */
    selfWipe(reason, now) {
      zeroizeMap(plain);
      plain = new Map();
      if (sealedBlob) {
        sealedBlob.fill(0); // best-effort overwrite before drop
        sealedBlob = null;
      }
      open = false;
      wiped = true;
      const rec = {
        event: "container.self_wipe",
        orgId: grant.orgId,
        employeeId: grant.employeeId,
        reason: reason || "de-provisioned",
        scope: "corporate-container-only",
        personalUntouched: true,
        at: nowIso(now),
      };
      audit(rec);
      return Object.freeze(rec);
    },

    /**
     * Enforce the grant at an access boundary: if the grant is no longer live,
     * refuse AND self-wipe the corporate data. This is the "revoke => data gone"
     * path, re-checked at every boundary (not cached).
     */
    enforceOrWipe(now) {
      const d = grant.decide(now);
      if (!d.allow) {
        const wipe = this.isWiped() ? null : this.selfWipe(d.reason, now);
        return { allowed: false, reason: d.reason, wiped: wipe };
      }
      return { allowed: true, reason: null, wiped: null };
    },
  };

  function ensureOpen() {
    if (wiped) throw new ContainerWiped();
    if (!open) throw new Error("shield-container: container is locked; call unlock() with a live grant first");
  }
}

export class ScopeViolation extends Error {
  constructor(msg) {
    super(msg);
    this.name = "ScopeViolation";
  }
}
export class ContainerWiped extends Error {
  constructor() {
    super("shield-container: container has been self-wiped (de-provisioned)");
    this.name = "ContainerWiped";
  }
}
export { GrantRevoked };

// ── injected-engine contract ────────────────────────────────────────────────

function assertEngine(e) {
  for (const m of ["seal", "open", "deriveKey"]) {
    if (typeof e[m] !== "function") throw new Error(`shield-container: seal engine missing ${m}()`);
  }
}

/**
 * A NON-CRYPTOGRAPHIC demo engine so the container model is explorable without
 * wiring postern-vault. It XORs with a key-stretched pad and prepends a marker.
 * It is NOT encryption and provides NO confidentiality — it exists only to make
 * the seal/open/derive SHAPE runnable. Real deployments MUST inject postern-vault.
 */
export function makeDemoSealEngine() {
  const MARKER = "SHIELD-DEMO-UNSEALED-NOT-ENCRYPTED ";
  const markerBytes = new TextEncoder().encode(MARKER);
  return {
    __demo: true,
    deriveKey(secret, salt) {
      // A weak, DETERMINISTIC stretch — explicitly NOT Argon2id. Demo only.
      const s = toBytes(secret);
      const out = new Uint8Array(32);
      for (let i = 0; i < 32; i++) {
        let acc = (i * 131 + s.length * 17 + (salt ? salt.length : 0)) & 0xff;
        for (let j = 0; j < s.length; j++) acc = (acc + s[j] * (j + 1 + i)) & 0xff;
        out[i] = acc;
      }
      return out;
    },
    seal(key, plaintext) {
      const pt = toBytes(plaintext);
      const body = new Uint8Array(pt.length);
      for (let i = 0; i < pt.length; i++) body[i] = pt[i] ^ key[i % key.length];
      const out = new Uint8Array(markerBytes.length + body.length);
      out.set(markerBytes, 0);
      out.set(body, markerBytes.length);
      return out;
    },
    open(key, sealed) {
      const s = toBytes(sealed);
      for (let i = 0; i < markerBytes.length; i++) {
        if (s[i] !== markerBytes[i]) throw new Error("demo-open: wrong key or corrupt (marker mismatch)");
      }
      const body = s.subarray(markerBytes.length);
      const out = new Uint8Array(body.length);
      for (let i = 0; i < body.length; i++) out[i] = body[i] ^ key[i % key.length];
      return out;
    },
  };
}

// ── length-prefixed item serialization (mirrors postern-vault's format idea) ──

function serializeItems(map) {
  const enc = new TextEncoder();
  const parts = [];
  let size = 0;
  for (const [k, v] of map) {
    const kb = enc.encode(k);
    const vb = toBytes(v);
    parts.push([kb, vb]);
    size += 8 + kb.length + vb.length;
  }
  const out = new Uint8Array(size);
  const dv = new DataView(out.buffer);
  let off = 0;
  for (const [kb, vb] of parts) {
    dv.setUint32(off, kb.length, true);
    off += 4;
    out.set(kb, off);
    off += kb.length;
    dv.setUint32(off, vb.length, true);
    off += 4;
    out.set(vb, off);
    off += vb.length;
  }
  return out;
}

function deserializeItems(bytes) {
  const b = toBytes(bytes);
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const dec = new TextDecoder();
  const map = new Map();
  let i = 0;
  while (i < b.length) {
    if (i + 4 > b.length) throw new Error("container: corrupt sealed data");
    const kl = dv.getUint32(i, true);
    i += 4;
    if (i + kl > b.length) throw new Error("container: corrupt sealed data");
    const name = dec.decode(b.subarray(i, i + kl));
    i += kl;
    if (i + 4 > b.length) throw new Error("container: corrupt sealed data");
    const vl = dv.getUint32(i, true);
    i += 4;
    if (i + vl > b.length) throw new Error("container: corrupt sealed data");
    map.set(name, Uint8Array.prototype.slice.call(b.subarray(i, i + vl)));
    i += vl;
  }
  return map;
}

function toBytes(x) {
  if (x instanceof Uint8Array) return x;
  if (typeof x === "string") return new TextEncoder().encode(x);
  if (Array.isArray(x)) return Uint8Array.from(x);
  if (x && x.buffer) return new Uint8Array(x.buffer, x.byteOffset || 0, x.byteLength);
  throw new Error("container: expected bytes or string");
}

function zeroizeMap(map) {
  for (const v of map.values()) if (v && v.fill) v.fill(0);
}

function defaultSalt(orgId, employeeId) {
  return new TextEncoder().encode(`postern-shield/v1:${orgId}:${employeeId}`).subarray(0, 16);
}

function nowIso(now) {
  return new Date(now || Date.now()).toISOString();
}

export default { createShieldContainer, makeDemoSealEngine, ScopeViolation, ContainerWiped, GrantRevoked };
