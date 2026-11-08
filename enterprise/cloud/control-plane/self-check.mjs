// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Smoke test / demo for the Postern CLOUD control plane. No test framework:
//   node enterprise/cloud/control-plane/self-check.mjs
// Exits non-zero on failure.

import { createControlPlane, admitTenant, deriveTenantId } from "./src/index.mjs";
import { createTenantScope, CrossTenantAccess, ISOLATION_STATEMENT } from "./src/isolation.mjs";
import { cloudPrivacyText, CLOUD_PRIVACY } from "./src/privacy.mjs";

let failures = 0;
const ok = (cond, msg) => {
  console.log(`${cond ? "  ok  " : " FAIL "} ${msg}`);
  if (!cond) failures++;
};
const threws = async (fn, Type) => {
  try {
    await fn();
    return false;
  } catch (e) {
    return Type ? e instanceof Type : true;
  }
};

const NOW = new Date("2026-07-12T00:00:00Z");
const MASTER_EXP = "2027-01-11";

// Two distinct corporate orgs, each with a master token that verifies OFFLINE.
const TOKENS = {
  "MASTER-acme": { valid: true, orgName: "Acme Ltda.", duns: "00-123-4567", seats: "unlimited", expires: MASTER_EXP },
  "MASTER-globex": { valid: true, orgName: "Globex Corp.", duns: "99-888-7777", seats: "unlimited", expires: MASTER_EXP },
};
// A mutable verifier so we can simulate a REVOKE mid-run.
const revoked = new Set();
const verify = (t) => (revoked.has(t) ? null : TOKENS[t] || null);

// ── 1. Tenant identity comes ONLY from an offline-verified master token ──────
ok(admitTenant({ masterToken: "MASTER-acme" }).ok === false, "no verifier wired => tenant NOT admitted (fail-closed)");
ok(admitTenant({ masterToken: "MASTER-bogus", verify, now: NOW }).ok === false, "unverifiable token => tenant NOT admitted");
ok(
  admitTenant({ masterToken: "X", verify: () => ({ valid: true, orgName: "No DUNS Inc." }), now: NOW }).ok === false,
  "verified token WITHOUT a DUNS => rejected (managed service is corporate-only)",
);
const acmeAdmit = admitTenant({ masterToken: "MASTER-acme", verify, now: NOW });
ok(acmeAdmit.ok === true && acmeAdmit.tenant.verifiedOffline === true, "verified master token => tenant admitted, flagged verifiedOffline");
ok(/^t-[0-9a-f]{16}$/.test(acmeAdmit.tenant.tenantId), "tenant id is a stable opaque isolation label");
ok(deriveTenantId("Acme Ltda.", "00-123-4567") === deriveTenantId("acme ltda.", "00-123-4567"), "tenant id is deterministic / case-insensitive on org name");
ok(deriveTenantId("Acme Ltda.", "00-123-4567") !== deriveTenantId("Globex Corp.", "99-888-7777"), "two different orgs never collide onto one tenant id");

// ── 2. Build a control plane; admit both orgs; provision managed nodes ───────
const cp = createControlPlane({ verify, now: NOW });
const acme = cp.admitTenant("MASTER-acme").tenant;
const globex = cp.admitTenant("MASTER-globex").tenant;
ok(acme.tenantId !== globex.tenantId, "two tenants registered under distinct ids");

const a1 = await cp.provision(acme.tenantId, { region: "sa-east-1", role: "validator", label: "acme-node-1" });
const a2 = await cp.provision(acme.tenantId, { region: "sa-east-1", role: "rpc", label: "acme-node-2" });
const g1 = await cp.provision(globex.tenantId, { region: "eu-west-1", role: "validator", label: "globex-node-1" });
ok(a1.simulated === true && a1.state === "pending", "no operator driver => node is SIMULATED, state pending (no real host)");
ok(cp.listNodes(acme.tenantId).length === 2, "Acme sees exactly its 2 nodes");
ok(cp.listNodes(globex.tenantId).length === 1, "Globex sees exactly its 1 node");

// ── 3. TENANT ISOLATION — one org's nodes are never visible to another ───────
const acmeNodeIds = new Set(cp.listNodes(acme.tenantId).map((n) => n.nodeId));
const globexNodeIds = new Set(cp.listNodes(globex.tenantId).map((n) => n.nodeId));
ok([...acmeNodeIds].every((id) => !globexNodeIds.has(id)), "no node id appears in both tenants' lists");
ok(cp.orchestrator.getNode(globex.tenantId, a1.nodeId) === null, "Globex cannot fetch Acme's node by id (cross-tenant read returns null)");

// Isolation scope refuses escape- and cross-tenant-shaped names by construction.
const scope = createTenantScope(acme.tenantId);
scope.put("nodes/x", { ok: true });
ok(scope.get("nodes/x").ok === true, "a tenant can read within its own namespace");
ok(await threws(() => scope.get("../secret"), CrossTenantAccess), "path-escape name is REFUSED");
ok(await threws(() => scope.get(globex.tenantId + "/nodes/x"), CrossTenantAccess), "an explicit OTHER-tenant prefix is REFUSED");
ok(await threws(() => createTenantScope("not-a-tenant-id"), CrossTenantAccess), "opening a scope requires a valid tenant id");

// ── 4. Honest health/status API ──────────────────────────────────────────────
const acmeStatus = await cp.tenantStatus(acme.tenantId);
ok(acmeStatus.known === true && acmeStatus.nodes.length === 2, "tenantStatus returns ONLY that tenant's nodes");
ok(acmeStatus.nodes.every((n) => n.simulated === true && n.health === "unknown-simulated"), "health is honest: simulated nodes report unknown-simulated, never 'healthy'");
const stranger = await cp.tenantStatus("t-0000000000000000");
ok(stranger.known === false && stranger.nodes.length === 0, "status for an unknown tenant is honest and empty (no leakage)");

const fleet = await cp.fleetHealth();
ok(fleet.status === "reference-prototype" && fleet.audited === false && fleet.production === false, "fleet health declares reference-prototype / unaudited / non-production");
ok(fleet.tenants === 2 && fleet.nodes === 3 && fleet.allNodesSimulated === true, "fleet exposes COUNTS only (2 tenants, 3 nodes, all simulated)");
ok(fleet.telemetry === "none" && fleet.disclosedMetricsOnly === true && fleet.hostedIsLessPrivate === true, "fleet health: no telemetry, disclosed metrics only, hosted-is-less-private flagged");
ok(!("orgName" in fleet) && !("duns" in fleet), "fleet health leaks no tenant identity to the operator dashboard");

// ── 5. Keyed to master license: REVOKE ⇒ DEPROVISION ─────────────────────────
// Simulate the vendor/admin revoking Acme's master token, then reconcile.
revoked.add("MASTER-acme");
const rec = await cp.reconcile();
const acmeRec = rec.find((r) => r.tenantId === acme.tenantId);
const globexRec = rec.find((r) => r.tenantId === globex.tenantId);
ok(acmeRec.action === "deprovisioned" && acmeRec.deprovisioned === 2, "revoked master => Acme's 2 nodes deprovisioned");
ok(globexRec.action === "kept", "Globex (still valid) is untouched by Acme's revoke — isolation holds through teardown");
ok(cp.orchestrator.tenantActive(acme.tenantId) === false, "Acme is now inactive");
ok(cp.orchestrator.tenantActive(globex.tenantId) === true, "Globex stays active");
ok(cp.listNodes(globex.tenantId).length === 1, "Globex still owns its node after Acme's teardown");
const acmeAfter = await cp.tenantStatus(acme.tenantId);
ok(acmeAfter.active === false && acmeAfter.nodes.length === 0, "deprovisioned tenant has no nodes and reports inactive");

// Provisioning against an inactive tenant is refused (fail-closed).
ok(await threws(() => cp.provision(acme.tenantId, { role: "rpc" })), "cannot provision for a tenant whose license was revoked");

// Explicit admin revoke of the still-valid tenant also tears down.
const g = await cp.revoke(globex.tenantId, "admin revoke");
ok(g.action === "deprovisioned" && g.deprovisioned === 1, "explicit admin revoke deprovisions Globex too");

// ── 6. Operator driver path (still no real infra here — a stub) ──────────────
const created = [];
const destroyed = [];
const driver = {
  async create(tenantId, spec) {
    created.push({ tenantId, spec });
    return { handle: "h-" + created.length, endpoint: "10.0.0." + created.length };
  },
  async destroy(tenantId, handle) {
    destroyed.push({ tenantId, handle });
  },
  async probe(_t, _h) {
    return { reachable: true, detail: "stub probe ok" };
  },
};
const cp2 = createControlPlane({ verify, driver, now: NOW });
const t2 = cp2.admitTenant("MASTER-globex").tenant;
const n2 = await cp2.provision(t2.tenantId, { region: "eu-west-1", role: "validator" });
ok(n2.simulated === false && n2.state === "running" && n2.handle === "h-1", "with an operator driver, provision() reports a real (stubbed) running node");
const st2 = await cp2.tenantStatus(t2.tenantId, { probe: true });
ok(st2.nodes[0].health === "reachable", "probed node reports driver's honest reachability");
await cp2.revoke(t2.tenantId);
ok(destroyed.length === 1, "revoke drives the operator driver's destroy() — real teardown path exercised");

// ── 7. Disclosures present and honest ────────────────────────────────────────
ok(/less private/i.test(cp.privacy.hostedIsLessPrivate), "privacy explicitly discloses hosted is LESS private than self-hosting");
ok(/COMPROMISED CONTROL PLANE DEFEATS IT/.test(ISOLATION_STATEMENT), "isolation statement admits a compromised control plane defeats it");
ok(/corporate-only|NEVER touch/i.test(cp.privacy.businessOnly), "privacy states personal data never touches the control plane");
ok(CLOUD_PRIVACY.noTelemetry === true && CLOUD_PRIVACY.noPhoneHome === true, "privacy: no telemetry, no phone-home");

// ── 8. Persistence seam — volatile by default, durable when injected ─────────
// A tiny fake "durable" store: a Map behind the injectable KV contract, marked
// durable so posture discloses it. Reused across two plane instances to
// simulate a process RESTART over the same backend.
function fakeDurableStore() {
  const disk = new Map();
  return {
    kind: "test-durable",
    durable: true,
    get: (k) => disk.get(k),
    set: (k, v) => {
      disk.set(k, v);
    },
    has: (k) => disk.has(k),
    delete: (k) => disk.delete(k),
    keys: () => [...disk.keys()],
  };
}

const durable = fakeDurableStore();
const cpA = createControlPlane({ verify, store: durable, now: NOW });
const tA = cpA.admitTenant("MASTER-globex").tenant;
await cpA.provision(tA.tenantId, { region: "eu-west-1", role: "validator", label: "durable-1" });
ok(cpA.listNodes(tA.tenantId).length === 1, "durable store: node provisioned and recorded");

// Restart: a brand-new control plane over the SAME store must rehydrate.
const cpB = createControlPlane({ verify, store: durable, now: NOW });
ok(cpB.orchestrator.tenantActive(tA.tenantId) === true, "durable store: tenant survives a control-plane restart");
ok(cpB.listNodes(tA.tenantId).length === 1, "durable store: node ownership survives a restart");
ok(cpB.orchestrator.getNode(tA.tenantId, "node-1") !== null, "durable store: the node record itself is restored");

// A shared durable store still isolates tenants by prefix (the new read path).
revoked.delete("MASTER-acme"); // section 5 revoked it; restore for a 2-org test
const store2 = fakeDurableStore();
const cpS = createControlPlane({ verify, store: store2, now: NOW });
const acmeS = cpS.admitTenant("MASTER-acme").tenant;
const globexS = cpS.admitTenant("MASTER-globex").tenant;
const sNodeA = await cpS.provision(acmeS.tenantId, { role: "rpc" });
await cpS.provision(globexS.tenantId, { role: "rpc" });
ok(
  cpS.listNodes(acmeS.tenantId).length === 1 && cpS.listNodes(globexS.tenantId).length === 1,
  "shared durable store: each tenant sees ONLY its own node (prefix isolation holds)",
);
ok(cpS.orchestrator.getNode(globexS.tenantId, sNodeA.nodeId) === null, "shared durable store: cross-tenant node read still returns null");

// A broken injected store is rejected LOUDLY at construction (fail-loud).
ok(await threws(() => createControlPlane({ verify, store: { get() {} } }), TypeError), "a store missing contract methods is rejected at construction");

// ── 9. Computed posture — reflects LIVE wiring, never a frozen lie ───────────
const postureDefault = cp.posture();
ok(postureDefault.persistence.durable === false, "posture: default store is disclosed as VOLATILE (lost on restart)");
ok(/VOLATILE/i.test(postureDefault.persistence.note), "posture: volatility is spelled out in the note");
ok(cpA.posture().persistence.durable === true, "posture: a wired durable store is disclosed as durable");
ok(/promise, not a proof/i.test(postureDefault.label), "posture: label states promise-not-proof");
ok(postureDefault.cryptography.startsWith("none"), "posture: states the control plane implements NO cryptography");
ok(postureDefault.promiseNotProof === true && postureDefault.audited === false, "posture: promise-not-proof, unaudited");
ok(postureDefault.hostedIsLessPrivate === true && /self-hosting/i.test(postureDefault.lessPrivateThan), "posture: hosted is less private than self-hosting");
ok(cp.fleetHealth().persistence.durable === false, "fleet health discloses volatile persistence by default");

// Driver-capability disclosure (hardening the injected-driver seam).
ok(cp.orchestrator.driverCapabilities === null, "no driver => driverCapabilities is null (honest)");
ok(
  cp2.orchestrator.driverCapabilities && cp2.orchestrator.driverCapabilities.create === true && cp2.orchestrator.driverCapabilities.probe === true,
  "a wired driver has its create/destroy/probe capabilities disclosed",
);

console.log("\n--- isolation statement ---\n" + ISOLATION_STATEMENT);
console.log("\n--- privacy ---\n" + cloudPrivacyText());

if (failures) {
  console.error(`\n${failures} check(s) failed`);
  process.exit(1);
}
console.log("\nAll checks passed.");
