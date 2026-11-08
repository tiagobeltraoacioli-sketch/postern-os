// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern CLOUD control plane — tenant isolation BY CONSTRUCTION.
//
// STATUS: design / reference prototype, unaudited, pre-production.
//
// WHAT THIS ENFORCES
// ------------------
// One org's data and managed nodes must NEVER be visible to another org. This
// module makes that structural rather than a runtime permission check: every
// resource name a tenant can create is forced into that tenant's own namespace
// (`<tenantId>/…`), and a tenant scope has NO code path that can name, list, or
// address a resource under a different tenant's prefix. Cross-tenant access is
// refused, not filtered — there is deliberately no query that spans tenants.
//
// THE HONEST LIMIT (stated, not hidden)
// -------------------------------------
// Isolation here is a userland, in-process construction — the same honest stance
// as `crates/postern-policy :: EnforcementMode::ByConstruction`. It assumes the
// control plane itself is honest and uncompromised. **A COMPROMISED CONTROL
// PLANE DEFEATS THIS**: an attacker who owns the orchestrator process can read
// any tenant's records regardless of these guards. This is not a kernel or
// hypervisor boundary and does not claim to be. The real product would pin
// per-tenant nodes to separate operator-run hosts; this code models the
// addressing/segregation logic, not that host separation.

import { createMemoryStore } from "./store.mjs";

export class CrossTenantAccess extends Error {
  constructor(msg) {
    super(msg);
    this.name = "CrossTenantAccess";
  }
}

/**
 * A single tenant's isolation scope. All keys are namespaced under the tenant
 * id; every accessor refuses a key that resolves outside the tenant's prefix.
 *
 * The scope is backed by an injectable key/value {@link module:store}. When no
 * store is supplied it gets a private in-memory one, so a standalone scope
 * behaves exactly as before; when a shared/durable store is injected (via the
 * registry) the scope reads and writes through it — and its reads are hard
 * prefix-filtered, so even a shared backend can never surface another tenant's
 * keys through this scope.
 *
 * @param {string} tenantId
 * @param {import("./store.mjs").ControlPlaneStore} [store]
 */
export function createTenantScope(tenantId, store) {
  const id = String(tenantId || "").trim();
  if (!id || !/^t-[0-9a-f]{16}$/.test(id)) {
    throw new CrossTenantAccess("isolation: a valid tenant id is required to open a scope");
  }
  const prefix = id + "/";
  const backend = store || createMemoryStore();

  /**
   * Force a caller-supplied resource name into this tenant's namespace and
   * refuse any attempt to escape it (absolute-looking, parent traversal, or an
   * explicit other-tenant prefix).
   */
  const namespaced = (name) => {
    const raw = String(name == null ? "" : name).trim();
    if (!raw) throw new CrossTenantAccess("isolation: an empty resource name is not addressable");
    // Refuse traversal / escape attempts outright.
    if (raw.includes("..") || raw.startsWith("/") || raw.includes("\0")) {
      throw new CrossTenantAccess(`isolation: refused escape-shaped name "${raw}"`);
    }
    // If a tenant-looking prefix is present, it MUST be this tenant's.
    if (/^t-[0-9a-f]{16}\//.test(raw) && !raw.startsWith(prefix)) {
      throw new CrossTenantAccess(`isolation: name "${raw}" addresses another tenant — refused`);
    }
    const key = raw.startsWith(prefix) ? raw : prefix + raw;
    // Belt and suspenders: the resolved key must live under this prefix.
    if (!key.startsWith(prefix)) {
      throw new CrossTenantAccess(`isolation: "${raw}" resolved outside tenant namespace`);
    }
    return key;
  };

  return {
    tenantId: id,
    prefix,

    /** Resolve (and validate) a name into its namespaced key without storing. */
    key: namespaced,

    put(name, value) {
      backend.set(namespaced(name), value);
      return this;
    },

    get(name) {
      return backend.get(namespaced(name));
    },

    has(name) {
      return backend.has(namespaced(name));
    },

    delete(name) {
      return backend.delete(namespaced(name));
    },

    /**
     * List ONLY this tenant's keys, prefix-filtered from the backend. There is
     * no cross-tenant listing API: a shared backend is filtered to this
     * tenant's prefix, so no other tenant's key is ever returned here.
     */
    keys() {
      return backend.keys().filter((k) => k.startsWith(prefix));
    },

    values() {
      return this.keys().map((k) => backend.get(k));
    },

    size() {
      return this.keys().length;
    },

    /** Wipe every resource this tenant owns (used on deprovision). */
    wipe() {
      const own = this.keys();
      for (const k of own) backend.delete(k);
      return own.length;
    },
  };
}

/**
 * A tiny registry of tenant scopes. Its ONLY job is to hand back the scope for a
 * given tenant id and to guarantee that scopes are never shared or merged across
 * tenants. It exposes no operation that reads across two tenants at once.
 */
export function createIsolationRegistry(store) {
  // One shared backend for every scope in this registry. Defaults to a volatile
  // in-memory store; an operator injects a durable one to survive restarts.
  const backend = store || createMemoryStore();
  /** @type {Map<string, ReturnType<typeof createTenantScope>>} */
  const scopes = new Map();

  return {
    /** The underlying key/value store (for the orchestrator's control records). */
    store: backend,

    /** Get-or-create the isolation scope for one tenant, over the shared store. */
    scopeFor(tenantId) {
      const id = String(tenantId || "").trim();
      let s = scopes.get(id);
      if (!s) {
        s = createTenantScope(id, backend);
        scopes.set(id, s);
      }
      return s;
    },

    /** How many tenants currently have a scope (an ops metric, not tenant data). */
    tenantCount() {
      return scopes.size;
    },

    /** Drop a tenant's scope entirely (wiping its resources first). */
    drop(tenantId) {
      const id = String(tenantId || "").trim();
      const s = scopes.get(id);
      if (!s) return 0;
      const wiped = s.wipe();
      scopes.delete(id);
      return wiped;
    },

    /**
     * The disclosed isolation stance, verbatim, for any UI/README that surfaces it.
     */
    isolationStatement() {
      return ISOLATION_STATEMENT;
    },
  };
}

export const ISOLATION_STATEMENT = [
  "Tenant isolation is BY CONSTRUCTION: every managed node and status record is",
  "keyed to the org's tenant id and there is no query, list, or name that spans",
  "two tenants. One org's data and nodes are never addressable by another.",
  "",
  "Honest limit: this is a userland, in-process boundary, not a kernel or",
  "hypervisor one. A COMPROMISED CONTROL PLANE DEFEATS IT — whoever owns the",
  "orchestrator process can read any tenant. Hosted managed nodes are therefore",
  "LESS PRIVATE than self-hosting your own Postern node. Unaudited reference",
  "prototype: no real hosts are provisioned by this code.",
].join("\n");

export default { createTenantScope, createIsolationRegistry, CrossTenantAccess, ISOLATION_STATEMENT };
