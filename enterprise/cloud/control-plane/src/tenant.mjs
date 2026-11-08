// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern CLOUD control plane — tenant identity, keyed to a corporate master license.
//
// STATUS: design / reference prototype, unaudited, pre-production. No real
// infrastructure is provisioned by this code — see NOTICE and README.
//
// THE MODEL
// ---------
// A business TENANT of the managed-node service is exactly one corporate org
// holding a vendor-signed MASTER token (enterprise/licensing/). A tenant comes
// into existence ONLY from a master token that verifies OFFLINE against the
// licensing lib's public key. There is no self-service signup and no per-user
// account: the org's master token IS its identity and its access grant.
//
// This module implements NO cryptography and does NOT import the licensing lib.
// It plugs into the SAME injected `verify()` interface used by
// enterprise/features/license-hook.mjs, so tenant identity is derived from the
// exact same offline check that gates the Business edition. When no verifier is
// wired, a tenant CANNOT be admitted (fail-closed) — never faked "verified".
//
// TENANT ISOLATION KEY
// --------------------
// Each tenant carries a stable, opaque `tenantId` derived deterministically from
// its verified org identity (DUNS + org name). Every managed node, every status
// record, and every isolation scope is keyed to this id. Two different orgs can
// never collide onto one id, and one org's id can never address another's.

/**
 * The pluggable OFFLINE master-token verifier — same shape as
 * enterprise/features/license-hook.mjs :: MasterTokenVerifier.
 *
 * @typedef {(masterToken: string) => (
 *   { valid: boolean, orgName?: string, duns?: string, seats?: number|"unlimited", expires?: string }
 *   | null
 * )} MasterTokenVerifier
 */

/**
 * @typedef {object} Tenant
 * @property {string} tenantId    stable opaque isolation key (never an org secret)
 * @property {string} orgName
 * @property {string} duns
 * @property {"unlimited"|number} seats
 * @property {string|null} masterExpires  RFC-3339 date the master token expires
 * @property {boolean} verifiedOffline
 */

/**
 * Admit a business tenant from a corporate master token. Fail-closed: no
 * verifier, an invalid token, or a token missing a DUNS => no tenant.
 *
 * @param {object} opts
 * @param {string} opts.masterToken            the org's vendor-signed master token
 * @param {MasterTokenVerifier} [opts.verify]  injected offline verifier (licensing lib)
 * @param {Date|string|number} [opts.now]
 * @returns {{ ok: true, tenant: Tenant } | { ok: false, reason: string }}
 */
export function admitTenant(opts = {}) {
  const masterToken = opts.masterToken || null;
  const verify = typeof opts.verify === "function" ? opts.verify : null;
  const now = new Date(opts.now || Date.now());

  if (!masterToken) return fail("no master token supplied");
  if (!verify) return fail("no offline verifier wired — a tenant cannot be admitted (fail-closed)");

  let claims = null;
  try {
    claims = verify(masterToken);
  } catch {
    claims = null; // a broken verifier fails closed
  }
  if (!claims || claims.valid !== true) return fail("master token did not verify offline");

  const orgName = (claims.orgName || "").trim();
  const duns = (claims.duns || "").trim();
  // The managed service is corporate-only: identity REQUIRES a DUNS. Freemium
  // desktops (no DUNS) never become cloud tenants.
  if (!duns) return fail("master token carries no DUNS — the managed service is corporate-only");
  if (!orgName) return fail("master token carries no org name");

  const expires = claims.expires ? new Date(claims.expires) : null;
  if (expires && expires.getTime() <= now.getTime()) {
    return fail("master token has expired — tenant not admitted");
  }

  return {
    ok: true,
    tenant: Object.freeze({
      tenantId: deriveTenantId(orgName, duns),
      orgName,
      duns,
      seats: claims.seats || "unlimited",
      masterExpires: expires ? expires.toISOString().slice(0, 10) : null,
      verifiedOffline: true,
    }),
  };

  function fail(reason) {
    return { ok: false, reason };
  }
}

/**
 * Deterministic, opaque tenant id. NOT a secret and NOT reversible to the
 * master key — it is only an isolation label. Uses a small, dependency-free
 * FNV-1a hash over the canonical (duns|orgName) pair so the same org always maps
 * to the same id and two orgs never collide onto one.
 *
 * @param {string} orgName
 * @param {string} duns
 * @returns {string}
 */
export function deriveTenantId(orgName, duns) {
  const canonical = `${String(duns).trim()}|${String(orgName).trim().toLowerCase()}`;
  return "t-" + fnv1a64(canonical);
}

// 64-bit FNV-1a as two 32-bit halves (no BigInt dependency on platform quirks),
// rendered as 16 lowercase hex chars. Non-cryptographic — a label, not a MAC.
function fnv1a64(str) {
  // FNV offset basis / prime, split high/low 32 bits.
  let hi = 0xcbf29ce4 >>> 0;
  let lo = 0x84222325 >>> 0;
  const primeHi = 0x00000100;
  const primeLo = 0x000001b3;
  for (let i = 0; i < str.length; i++) {
    lo ^= str.charCodeAt(i) & 0xff;
    // 64-bit multiply of (hi:lo) by (primeHi:primeLo), keep low 64 bits.
    const a = mul32(lo, primeLo);
    const b = mul32(lo, primeHi);
    const c = mul32(hi, primeLo);
    const newLo = a.lo >>> 0;
    const carry = a.hi >>> 0;
    const newHi = (b.lo + c.lo + carry) >>> 0;
    lo = newLo >>> 0;
    hi = newHi >>> 0;
  }
  return hex32(hi) + hex32(lo);
}

function mul32(a, b) {
  const aHi = (a >>> 16) & 0xffff;
  const aLo = a & 0xffff;
  const bHi = (b >>> 16) & 0xffff;
  const bLo = b & 0xffff;
  const lo = aLo * bLo;
  const mid = (aLo * bHi + aHi * bLo) >>> 0;
  const hi = aHi * bHi + ((mid >>> 16) & 0xffff);
  const low = (lo + ((mid & 0xffff) << 16)) >>> 0;
  return { hi: hi >>> 0, lo: low >>> 0 };
}

function hex32(n) {
  return (n >>> 0).toString(16).padStart(8, "0");
}

export default { admitTenant, deriveTenantId };
