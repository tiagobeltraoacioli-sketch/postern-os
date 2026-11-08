// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern CLOUD control plane — an HONEST health / status API.
//
// STATUS: design / reference prototype, unaudited, pre-production.
//
// HONESTY RULES BAKED IN
// ----------------------
//  • It reports `simulated: true` for every node when no operator driver is
//    wired — it never fabricates "healthy" for a host that does not exist. When
//    a driver IS wired it reports the driver's own probe result and says so.
//  • Per-tenant status reads ONLY that tenant's isolation scope. There is no API
//    that returns another tenant's nodes, and the fleet summary exposes COUNTS
//    only — never one tenant's records to another caller.
//  • The only numbers it emits are the DISCLOSED operational metrics listed in
//    privacy.mjs (node counts, states, uptime of the control process). No
//    telemetry, no phone-home, nothing about what runs inside a node.

/**
 * @param {object} opts
 * @param {ReturnType<import("./orchestrator.mjs").createOrchestrator>} opts.orchestrator
 * @param {Date|string|number} [opts.startedAt] when the control process came up
 * @param {Date|string|number} [opts.now]
 */
export function createHealthApi(opts = {}) {
  const orchestrator = opts.orchestrator;
  if (!orchestrator || typeof orchestrator.listNodes !== "function") {
    throw new Error("health-api: an orchestrator is required");
  }
  const startedAt = new Date(opts.startedAt || Date.now());
  const nowOf = () => new Date(opts.now || Date.now());

  /**
   * Per-tenant status. Scoped: a caller must present the tenant id and only ever
   * receives THAT tenant's nodes. Optionally probes live hosts via the driver.
   *
   * @param {string} tenantId
   * @param {{ probe?: boolean }} [q]
   */
  async function tenantStatus(tenantId, q = {}) {
    const id = String(tenantId || "").trim();
    const active = orchestrator.tenantActive(id);
    let nodes = [];
    try {
      nodes = orchestrator.listNodes(id);
    } catch {
      // Unknown tenant: report honestly rather than throwing at the boundary.
      return Object.freeze({
        tenantId: id,
        known: false,
        active: false,
        nodes: [],
        summary: emptySummary(),
        note: "no such tenant, or its master license was revoked and it was deprovisioned",
        generatedAt: nowOf().toISOString(),
      });
    }

    const enriched = [];
    for (const n of nodes) {
      let reachable = null;
      let detail = n.simulated ? "simulated — no real host (no operator driver wired)" : null;
      if (q.probe) {
        const r = await orchestrator.probeNode(id, n.nodeId);
        reachable = r.reachable;
        detail = r.detail;
      }
      enriched.push({
        nodeId: n.nodeId,
        state: n.state,
        simulated: n.simulated,
        region: n.spec && n.spec.region ? n.spec.region : null,
        role: n.spec && n.spec.role ? n.spec.role : null,
        health: n.simulated ? "unknown-simulated" : reachable == null ? "not-probed" : reachable ? "reachable" : "unreachable",
        detail,
      });
    }

    return Object.freeze({
      tenantId: id,
      known: true,
      active,
      nodes: enriched,
      summary: summarize(enriched),
      note: active ? null : "tenant is inactive — master license not live",
      generatedAt: nowOf().toISOString(),
    });
  }

  /**
   * Fleet-wide health for the OPERATOR. Exposes tenant COUNTS and aggregate node
   * states only — never one tenant's records. Honest about simulation and about
   * the audited/production status.
   */
  function fleetHealth() {
    const tenantIds = orchestrator.tenantIds();
    let totalNodes = 0;
    let simulated = 0;
    const stateCounts = {};
    let activeTenants = 0;
    for (const id of tenantIds) {
      if (orchestrator.tenantActive(id)) activeTenants++;
      let nodes = [];
      try {
        nodes = orchestrator.listNodes(id);
      } catch {
        nodes = [];
      }
      for (const n of nodes) {
        totalNodes++;
        if (n.simulated) simulated++;
        stateCounts[n.state] = (stateCounts[n.state] || 0) + 1;
      }
    }
    return Object.freeze({
      service: "postern-cloud-control-plane",
      status: "reference-prototype",
      audited: false,
      production: false,
      driverWired: orchestrator.driverWired,
      persistence: orchestrator.persistence
        ? { durable: orchestrator.persistence.durable === true, kind: orchestrator.persistence.kind }
        : { durable: false, kind: "memory" },
      allNodesSimulated: totalNodes > 0 && simulated === totalNodes,
      tenants: tenantIds.length,
      activeTenants,
      isolatedNamespaces: orchestrator.isolation ? orchestrator.isolation.tenantCount() : tenantIds.length,
      nodes: totalNodes,
      simulatedNodes: simulated,
      nodeStates: stateCounts,
      uptimeSeconds: Math.max(0, Math.floor((nowOf().getTime() - startedAt.getTime()) / 1000)),
      disclosedMetricsOnly: true,
      telemetry: "none",
      hostedIsLessPrivate: true,
      generatedAt: nowOf().toISOString(),
    });
  }

  /** A tiny liveness probe of the control process itself. */
  function live() {
    return Object.freeze({ ok: true, service: "postern-cloud-control-plane", status: "reference-prototype", at: nowOf().toISOString() });
  }

  return { tenantStatus, fleetHealth, live };
}

function summarize(nodes) {
  const s = emptySummary();
  s.total = nodes.length;
  for (const n of nodes) {
    if (n.simulated) s.simulated++;
    s.byState[n.state] = (s.byState[n.state] || 0) + 1;
  }
  return s;
}

function emptySummary() {
  return { total: 0, simulated: 0, byState: {} };
}

export default { createHealthApi };
