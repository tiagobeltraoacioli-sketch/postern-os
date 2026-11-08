// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern CLOUD control plane — assembled entry point (reference prototype).
//
// STATUS: design / reference prototype, unaudited, pre-production. NO real
// infrastructure is provisioned by this code. See NOTICE and README.
//
// createControlPlane() wires the orchestrator, the license binding (revoke ⇒
// deprovision), the isolation registry, and the honest health API into one
// object. It implements NO cryptography and does NOT import enterprise/licensing;
// it plugs into the same injected offline `verify()` used across the enterprise
// layer, and into an optional operator-run `driver` for real hosts.

import { admitTenant, deriveTenantId } from "./tenant.mjs";
import { createOrchestrator, NODE_STATES } from "./orchestrator.mjs";
import { createLicenseBinding } from "./license-binding.mjs";
import { createHealthApi } from "./health-api.mjs";
import { createIsolationRegistry, ISOLATION_STATEMENT } from "./isolation.mjs";
import { CLOUD_PRIVACY, cloudPrivacyText } from "./privacy.mjs";
import { createMemoryStore, assertStore } from "./store.mjs";

/**
 * @param {object} [opts]
 * @param {import("./tenant.mjs").MasterTokenVerifier} [opts.verify] injected offline verifier
 * @param {object} [opts.driver]     optional operator-run provisioner (create/destroy/probe)
 * @param {import("./store.mjs").ControlPlaneStore} [opts.store] injectable durable backend
 *   (default: volatile in-memory — disclosed in posture()/fleetHealth())
 * @param {Date|string|number} [opts.now]
 * @param {Date|string|number} [opts.startedAt]
 */
export function createControlPlane(opts = {}) {
  const orchestrator = createOrchestrator({ driver: opts.driver, store: opts.store, now: opts.now });
  const license = createLicenseBinding({ orchestrator, verify: opts.verify, now: opts.now });
  const health = createHealthApi({ orchestrator, now: opts.now, startedAt: opts.startedAt });

  /**
   * A COMPUTED honesty manifest — reflects the plane's LIVE wiring (verifier,
   * driver, persistence durability), not a frozen constant. This is what keeps
   * the posture from lying as capabilities change: it says "promise, not proof",
   * discloses that a volatile store loses state on restart, and never claims a
   * cryptographic or attested property the managed path does not have.
   */
  function posture() {
    const p = orchestrator.persistence;
    return Object.freeze({
      schema: "postern.cloud.control-plane.posture/1",
      service: "postern-cloud-control-plane",
      label: "managed-node (hosted) — a promise, not a proof",
      status: "reference-prototype/unaudited",
      audited: false,
      production: false,
      promiseNotProof: true,
      cryptography: "none (this control plane implements NO cryptography; it plugs into an injected offline verifier)",
      verifierWired: license.verifierWired,
      driverWired: orchestrator.driverWired,
      driverCapabilities: orchestrator.driverCapabilities,
      persistence: Object.freeze({
        durable: p.durable,
        kind: p.kind,
        note: p.durable
          ? "records persist to an operator-injected store; as trustworthy as that operator"
          : "VOLATILE in-memory store — all tenant/node records are LOST on restart (wire an injected store for durability)",
      }),
      isolation: "by-construction (userland namespacing) — a compromised control plane defeats it; not a kernel/hypervisor boundary",
      hostedIsLessPrivate: true,
      lessPrivateThan: "self-hosting your own Postern node",
      canSee: [
        "the existence, count, lifecycle state, and region/role spec of each tenant's managed nodes",
        "provision/deprovision events keyed to the org's master license (operator audit trail)",
        "a tenant's DUNS-derived opaque tenant id (never the master token's secret)",
      ],
      cannotSee: [
        "anything inside a managed node's workload (no in-node telemetry, no phone-home)",
        "any personal-app data — there is no code path for personal data to reach this plane",
      ],
      metadataExposed: ["node counts", "node lifecycle states", "regions/roles", "control-process uptime"],
      minimizations: ["disclosed operational metrics only", "no telemetry", "no cross-tenant query exists", "corporate-only (DUNS-gated)"],
      generatedAt: new Date(opts.now || Date.now()).toISOString(),
    });
  }

  return {
    // High-level, license-keyed tenant lifecycle (the intended surface).
    admitTenant: (masterToken) => license.admit(masterToken),
    provision: (tenantId, spec) => orchestrator.provision(tenantId, spec),
    deprovision: (tenantId, nodeId) => orchestrator.deprovision(tenantId, nodeId),
    revoke: (tenantId, reason) => license.revoke(tenantId, reason),
    reconcile: () => license.reconcile(),
    reconcileTenant: (tenantId) => license.reconcileTenant(tenantId),

    // Scoped reads.
    listNodes: (tenantId) => orchestrator.listNodes(tenantId),
    tenantStatus: (tenantId, q) => health.tenantStatus(tenantId, q),
    fleetHealth: () => health.fleetHealth(),
    live: () => health.live(),

    // Disclosures.
    posture,
    isolationStatement: ISOLATION_STATEMENT,
    privacy: CLOUD_PRIVACY,
    privacyText: cloudPrivacyText(),

    // Sub-components, for advanced wiring / tests.
    orchestrator,
    license,
    health,
  };
}

export {
  admitTenant,
  deriveTenantId,
  createOrchestrator,
  createLicenseBinding,
  createHealthApi,
  createIsolationRegistry,
  createMemoryStore,
  assertStore,
  NODE_STATES,
  ISOLATION_STATEMENT,
  CLOUD_PRIVACY,
  cloudPrivacyText,
};

export default { createControlPlane };
