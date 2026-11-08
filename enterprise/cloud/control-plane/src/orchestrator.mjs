// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern CLOUD control plane — managed-node provisioning / deprovisioning.
//
// STATUS: design / reference prototype, unaudited, pre-production.
//
// **NO REAL INFRASTRUCTURE IS SPUN UP HERE.** This is the orchestration LOGIC
// and the interfaces an operator's real provisioner plugs into. `provision()`
// records intent and returns a node descriptor in a `pending`/`running` model
// state; it does not create a VM, container, or DNS record. The actual managed
// hosts are OPERATOR-RUN and wired in through an injected `driver` (see below).
// Absent a driver, every node is clearly flagged `simulated: true` and the
// health API reports it as such — never pretending a host exists.
//
// WHAT IT MODELS
// --------------
//   • One org == one TENANT, admitted from a verified master token (tenant.mjs).
//   • provision()   — request a managed Postern node for a tenant. Per-tenant,
//                     namespaced, and never visible to another tenant.
//   • deprovision() — tear a node down and wipe its record from the tenant scope.
//   • The tenant lifecycle is KEYED TO THE MASTER LICENSE: license-binding.mjs
//     calls deprovisionTenant() the moment the master token stops verifying
//     (revoked / expired) — revoke ⇒ deprovision.
//
// The optional operator driver interface (all methods may be async):
//   driver.create(tenantId, spec) -> { handle, endpoint? }
//   driver.destroy(tenantId, handle) -> void
//   driver.probe(tenantId, handle)  -> { reachable:boolean, detail?:string }
// This module never implements any of them; it only orchestrates around them.

import { createIsolationRegistry } from "./isolation.mjs";
import { assertStore } from "./store.mjs";

export class UnknownTenant extends Error {
  constructor(msg) {
    super(msg);
    this.name = "UnknownTenant";
  }
}
export class UnknownNode extends Error {
  constructor(msg) {
    super(msg);
    this.name = "UnknownNode";
  }
}

/** The lifecycle states a managed node record can hold. */
export const NODE_STATES = Object.freeze(["pending", "running", "deprovisioning", "deprovisioned", "failed"]);

/**
 * Create the control-plane orchestrator.
 *
 * @param {object} [opts]
 * @param {object} [opts.driver]  operator's real provisioner (create/destroy/probe). Optional.
 * @param {import("./store.mjs").ControlPlaneStore} [opts.store] injectable durable backend
 *   (default: volatile in-memory — disclosed as such in posture/health).
 * @param {Date|string|number} [opts.now]
 */
export function createOrchestrator(opts = {}) {
  const driver = opts.driver && typeof opts.driver === "object" ? opts.driver : null;
  // Harden the injected-driver seam: record which capabilities it actually
  // exposes, so posture/health can disclose it and callers never assume more.
  const driverCapabilities = driver
    ? {
        create: typeof driver.create === "function",
        destroy: typeof driver.destroy === "function",
        probe: typeof driver.probe === "function",
      }
    : null;
  const now = () => new Date(opts.now || Date.now());
  // The persistence seam: a validated injected store (durable) or the volatile
  // default. The isolation registry and the tenant registry share this backend.
  const store = opts.store ? assertStore(opts.store) : undefined;
  const isolation = createIsolationRegistry(store);
  const backend = isolation.store;

  /** Reserved (non-tenant) control namespace for the tenant registry. */
  const tenantKey = (id) => "__cp/tenants/" + id;

  /**
   * Per-tenant registry of admitted tenants and their node ids. Node RECORDS
   * live inside each tenant's isolation scope (never in a shared table), so a
   * node can only be reached through its owning tenant.
   * @type {Map<string, { tenant: import("./tenant.mjs").Tenant, active: boolean, nodeIds: Set<string> }>}
   */
  const tenants = new Map();
  let nodeSeq = 0;

  // ── Rehydrate from a durable store (a no-op on a fresh/volatile one) ────────
  // Restore admitted tenants and re-derive their node ownership from the scope,
  // so a restart backed by a durable store does not lose the fleet.
  for (const k of backend.keys()) {
    if (!k.startsWith("__cp/tenants/")) continue;
    const rec = backend.get(k);
    if (!rec || !rec.tenant || !rec.tenant.tenantId) continue;
    const id = rec.tenant.tenantId;
    const scope = isolation.scopeFor(id); // populate the scope cache
    const nodeIds = new Set();
    for (const nk of scope.keys()) {
      if (!nk.includes("/nodes/")) continue;
      const node = scope.get(nk.slice(scope.prefix.length));
      if (node && node.nodeId) {
        nodeIds.add(node.nodeId);
        const n = Number(String(node.nodeId).replace(/^node-/, ""));
        if (Number.isFinite(n) && n > nodeSeq) nodeSeq = n; // avoid id reuse
      }
    }
    tenants.set(id, { tenant: rec.tenant, active: rec.active === true, nodeIds });
  }

  function requireTenant(tenantId) {
    const rec = tenants.get(String(tenantId || "").trim());
    if (!rec) throw new UnknownTenant("orchestrator: tenant not registered: " + tenantId);
    return rec;
  }

  /** Write-through a tenant registry record to the (possibly durable) store. */
  function persistTenant(rec) {
    backend.set(tenantKey(rec.tenant.tenantId), { tenant: rec.tenant, active: rec.active });
  }

  const api = {
    driverWired: !!driver,
    driverCapabilities,
    persistence: { durable: backend.durable === true, kind: backend.kind || "memory" },

    /**
     * Register an admitted tenant (from tenant.admitTenant().tenant). Idempotent:
     * re-registering the same tenant refreshes its record and reactivates it.
     */
    registerTenant(tenant) {
      if (!tenant || !tenant.tenantId || tenant.verifiedOffline !== true) {
        throw new UnknownTenant("orchestrator: only an offline-verified tenant may be registered");
      }
      const existing = tenants.get(tenant.tenantId);
      if (existing) {
        existing.tenant = tenant;
        existing.active = true;
        persistTenant(existing);
        return { tenantId: tenant.tenantId, active: true, reactivated: true };
      }
      const rec = { tenant, active: true, nodeIds: new Set() };
      tenants.set(tenant.tenantId, rec);
      isolation.scopeFor(tenant.tenantId); // open its isolation namespace
      persistTenant(rec);
      return { tenantId: tenant.tenantId, active: true, reactivated: false };
    },

    /** Is a tenant registered and active (its master still valid)? */
    tenantActive(tenantId) {
      const rec = tenants.get(String(tenantId || "").trim());
      return !!(rec && rec.active);
    },

    /**
     * Provision a managed Postern node for a tenant. Records intent only — NO
     * real host is created unless an operator driver is wired. Refuses if the
     * tenant is not active (its master license must be live).
     *
     * @param {string} tenantId
     * @param {{ region?:string, role?:string, label?:string }} [spec]
     */
    async provision(tenantId, spec = {}) {
      const rec = requireTenant(tenantId);
      if (!rec.active) {
        throw new UnknownTenant("orchestrator: tenant is not active (master license not live) — refusing to provision");
      }
      const scope = isolation.scopeFor(tenantId);
      const nodeId = "node-" + ++nodeSeq;
      const ts = now().toISOString();

      let handle = null;
      let endpoint = null;
      let simulated = true;
      let state = "pending";
      let failure = null;

      if (driver && typeof driver.create === "function") {
        try {
          const res = await driver.create(tenantId, sanitizeSpec(spec));
          handle = (res && res.handle) || null;
          endpoint = (res && res.endpoint) || null;
          simulated = false;
          state = "running";
        } catch (e) {
          state = "failed";
          failure = String((e && e.message) || e);
        }
      }

      const node = {
        nodeId,
        tenantId,
        state,
        simulated,
        handle,
        endpoint,
        spec: sanitizeSpec(spec),
        failure,
        createdAt: ts,
        updatedAt: ts,
      };
      // Store INSIDE the tenant's isolation scope — never a shared table.
      scope.put("nodes/" + nodeId, node);
      rec.nodeIds.add(nodeId);
      return { ...node };
    },

    /**
     * Deprovision a single node. Tears down the real host if a driver is wired,
     * then wipes the record from the tenant's scope.
     */
    async deprovision(tenantId, nodeId) {
      const rec = requireTenant(tenantId);
      const scope = isolation.scopeFor(tenantId);
      const node = scope.get("nodes/" + nodeId);
      if (!node) throw new UnknownNode("orchestrator: unknown node " + nodeId + " for tenant " + tenantId);

      node.state = "deprovisioning";
      node.updatedAt = now().toISOString();
      scope.put("nodes/" + nodeId, node);

      if (driver && typeof driver.destroy === "function" && node.handle) {
        try {
          await driver.destroy(tenantId, node.handle);
        } catch (e) {
          // Record the failure but still drop our record — fail toward teardown.
          node.failure = "destroy: " + String((e && e.message) || e);
        }
      }

      scope.delete("nodes/" + nodeId);
      rec.nodeIds.delete(nodeId);
      return { nodeId, tenantId, state: "deprovisioned", at: now().toISOString() };
    },

    /**
     * Deprovision EVERY node for a tenant and deactivate it. This is the hook
     * license-binding.mjs calls on master-license revoke/expiry:
     * revoke ⇒ deprovision.
     *
     * @param {string} tenantId
     * @param {string} [reason]
     */
    async deprovisionTenant(tenantId, reason = "license no longer valid") {
      const rec = requireTenant(tenantId);
      const ids = [...rec.nodeIds];
      const results = [];
      for (const nodeId of ids) {
        results.push(await api.deprovision(tenantId, nodeId));
      }
      rec.active = false;
      persistTenant(rec); // durable stores record the tenant as inactive
      const wiped = isolation.drop(tenantId); // wipe & drop the whole namespace
      return { tenantId, deprovisioned: results.length, wipedRecords: wiped, reason, at: now().toISOString() };
    },

    /**
     * List a single tenant's nodes. Reads ONLY that tenant's isolation scope;
     * there is no cross-tenant listing.
     */
    listNodes(tenantId) {
      requireTenant(tenantId);
      const scope = isolation.scopeFor(tenantId);
      return scope
        .keys()
        .filter((k) => k.includes("/nodes/"))
        .map((k) => ({ ...scope.get(k.slice(scope.prefix.length)) }))
        .sort((a, b) => a.nodeId.localeCompare(b.nodeId));
    },

    /** Fetch one node (only through its owning tenant). */
    getNode(tenantId, nodeId) {
      requireTenant(tenantId);
      const scope = isolation.scopeFor(tenantId);
      const node = scope.get("nodes/" + nodeId);
      return node ? { ...node } : null;
    },

    /**
     * Probe a node's real host through the operator driver, if any. Returns an
     * honest result: `{ reachable, detail }`, or `simulated`/`no-driver` when
     * there is nothing real to probe. Never fabricates reachability.
     */
    async probeNode(tenantId, nodeId) {
      requireTenant(tenantId);
      const scope = isolation.scopeFor(tenantId);
      const node = scope.get("nodes/" + nodeId);
      if (!node) throw new UnknownNode("orchestrator: unknown node " + nodeId + " for tenant " + tenantId);
      if (node.simulated || !node.handle) {
        return { reachable: null, simulated: true, detail: "simulated — no real host (no operator driver wired)" };
      }
      if (!driver || typeof driver.probe !== "function") {
        return { reachable: null, simulated: false, detail: "no driver probe available" };
      }
      try {
        const r = await driver.probe(tenantId, node.handle);
        return { reachable: !!(r && r.reachable), simulated: false, detail: (r && r.detail) || (r && r.reachable ? "reachable" : "unreachable") };
      } catch (e) {
        return { reachable: false, simulated: false, detail: "probe error: " + String((e && e.message) || e) };
      }
    },

    /** Registered tenant ids (ops metric only — no tenant data). */
    tenantIds() {
      return [...tenants.keys()];
    },

    /** The isolation registry, for the health API and license binding. */
    isolation,

    _internal: { tenants },
  };

  return api;
}

/** Keep only known, string-shaped spec fields — never trust arbitrary input. */
function sanitizeSpec(spec) {
  const s = spec && typeof spec === "object" ? spec : {};
  const clip = (v) => (v == null ? undefined : String(v).slice(0, 128));
  const out = {};
  if (s.region != null) out.region = clip(s.region);
  if (s.role != null) out.role = clip(s.role);
  if (s.label != null) out.label = clip(s.label);
  return out;
}

export default { createOrchestrator, NODE_STATES, UnknownTenant, UnknownNode };
