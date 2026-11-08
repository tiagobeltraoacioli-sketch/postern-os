// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern CLOUD control plane — bind the tenant lifecycle to the master license.
//
// STATUS: design / reference prototype, unaudited, pre-production.
//
// THE INVARIANT: revoke ⇒ deprovision.
// -------------------------------------
// A tenant's managed nodes exist ONLY while its corporate master token still
// verifies OFFLINE (enterprise/licensing/) and has not expired. The instant the
// master token is revoked, expires, or stops verifying, every node for that
// tenant is torn down and its isolation namespace is wiped. There is no grace
// path that keeps a node running past the license — the binding fails closed.
//
// This module owns NO crypto. It re-uses the SAME injected `verify()` the rest
// of the enterprise layer uses. `reconcile()` is meant to be called on a
// schedule by the operator (e.g. hourly) and on demand (e.g. an admin revoke).

import { admitTenant } from "./tenant.mjs";

/**
 * @param {object} opts
 * @param {ReturnType<import("./orchestrator.mjs").createOrchestrator>} opts.orchestrator
 * @param {import("./tenant.mjs").MasterTokenVerifier} [opts.verify] injected offline verifier
 * @param {Date|string|number} [opts.now]
 */
export function createLicenseBinding(opts = {}) {
  const orchestrator = opts.orchestrator;
  if (!orchestrator || typeof orchestrator.registerTenant !== "function") {
    throw new Error("license-binding: an orchestrator is required");
  }
  const verify = typeof opts.verify === "function" ? opts.verify : null;
  const nowOf = () => new Date(opts.now || Date.now());

  /**
   * Track, per tenant id, the master token we admitted it with, so reconcile()
   * can re-verify the SAME token later. The token is an org credential, not
   * personal data; we hold only what is needed to re-check the license.
   * @type {Map<string, { masterToken: string }>}
   */
  const bindings = new Map();

  return {
    verifierWired: !!verify,

    /**
     * Admit a tenant from its master token and bind it. Fail-closed via
     * tenant.admitTenant (no verifier / bad token / no DUNS ⇒ rejected).
     *
     * @param {string} masterToken
     * @returns {{ ok:true, tenant: import("./tenant.mjs").Tenant } | { ok:false, reason:string }}
     */
    admit(masterToken) {
      const res = admitTenant({ masterToken, verify, now: nowOf() });
      if (!res.ok) return res;
      orchestrator.registerTenant(res.tenant);
      bindings.set(res.tenant.tenantId, { masterToken });
      return res;
    },

    /**
     * Re-verify one tenant's master token. If it no longer verifies (revoked,
     * expired, or unverifiable), deprovision the tenant. revoke ⇒ deprovision.
     *
     * @param {string} tenantId
     */
    async reconcileTenant(tenantId) {
      const id = String(tenantId || "").trim();
      const binding = bindings.get(id);
      if (!binding) {
        return { tenantId: id, action: "unknown", detail: "no binding for tenant" };
      }
      const res = admitTenant({ masterToken: binding.masterToken, verify, now: nowOf() });
      if (res.ok && res.tenant.tenantId === id) {
        // Still valid — keep it active (re-register refreshes claims/expiry).
        orchestrator.registerTenant(res.tenant);
        return { tenantId: id, action: "kept", masterExpires: res.tenant.masterExpires };
      }
      // No longer valid: revoke ⇒ deprovision. Fail closed.
      let teardown = { deprovisioned: 0, wipedRecords: 0 };
      if (orchestrator.tenantActive(id)) {
        teardown = await orchestrator.deprovisionTenant(id, "master license " + (res.reason || "no longer valid"));
      }
      bindings.delete(id);
      return { tenantId: id, action: "deprovisioned", reason: res.reason || "revoked", ...teardown };
    },

    /**
     * Reconcile ALL bound tenants. Returns one result per tenant. Iterates a
     * snapshot so tenants dropped mid-loop don't disturb it.
     */
    async reconcile() {
      const results = [];
      for (const id of [...bindings.keys()]) {
        results.push(await this.reconcileTenant(id));
      }
      return results;
    },

    /** Explicit admin revoke: deprovision now, regardless of token state. */
    async revoke(tenantId, reason = "explicit admin revoke") {
      const id = String(tenantId || "").trim();
      let teardown = { deprovisioned: 0, wipedRecords: 0 };
      if (orchestrator.tenantActive(id)) {
        teardown = await orchestrator.deprovisionTenant(id, reason);
      }
      bindings.delete(id);
      return { tenantId: id, action: "deprovisioned", reason, ...teardown };
    },

    /** Bound tenant ids (ops metric). */
    boundTenants() {
      return [...bindings.keys()];
    },
  };
}

export default { createLicenseBinding };
