<!--
SPDX-License-Identifier: MIT OR Apache-2.0
SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
-->

# Postern CLOUD — control plane (multi-tenant managed-node orchestration)

> **Honest status: design / reference prototype. Unaudited. Pre-production.**
> **No real infrastructure is provisioned by this code.** This is the
> orchestration *logic* and the *interfaces* an operator's real provisioner plugs
> into — the actual managed hosts are **operator-run**. Nothing here ships as-is.

A control-plane model that provisions and deprovisions **managed Postern nodes**
for a business **TENANT**, keyed to the org's **master license**, with strict
**tenant isolation** and an **honest health/status API**. It is framework-free,
dependency-free, offline, and implements **no cryptography**. It does **not**
import `enterprise/licensing/`; it plugs into the same injected offline
`verify()` used across the enterprise layer, and into an optional operator
`driver` for real hosts.

## The rails that never bend

- **Business/Enterprise only.** A managed node is provisioned only for a
  corporate tenant holding a **DUNS-backed master license**
  (`enterprise/licensing/`, `enterprise/features/`). **Personal Postern apps and
  personal data never touch this control plane** — there is deliberately no code
  path for it.
- **Hosted is _less private_ than self-hosting.** A managed node runs on
  infrastructure the org does not own, under a control plane the org does not
  run. That is a real privacy cost and we **disclose it up front**, here and in
  every user-facing surface (`src/privacy.mjs :: CLOUD_PRIVACY.hostedIsLessPrivate`).
  We never claim the managed service is "as private as" running your own node.
  **Self-hosting stays free.**
- **Tenant isolation is by construction — and a compromised control plane defeats
  it.** Isolation is in-process namespacing (`src/isolation.mjs`), not a kernel
  or hypervisor boundary. Whoever owns the orchestrator process can read any
  tenant. We say so plainly (`ISOLATION_STATEMENT`). The real product would pin
  per-tenant nodes to separate operator-run hosts; this code models the
  addressing/segregation logic, not that host separation.
- **Revoke ⇒ deprovision.** A tenant's nodes exist only while its master token
  verifies **offline**. Revoke, expiry, or an unverifiable token ⇒ the tenant's
  nodes are torn down and its namespace wiped, **fail-closed**
  (`src/license-binding.mjs`).
- **No telemetry** beyond the disclosed ops metrics (node counts, lifecycle
  state, provision/deprovision events, control-process uptime). No phone-home.
- **Never a coin.** Payment (after the evaluation) is **fiat**; pricing is still
  being structured. The Bloch-SIS-PoW coin is not a security and buys no
  software.

The community/free personal suite is never "Postern OS"; Postern OS is the
separate reproducible operating system product.

## Compliance & data residency (not legal advice)

- **Controller / processor.** When **Postern Labs operates the managed control
  plane**, the corporate **tenant is the data CONTROLLER** and **Postern Labs is
  a data PROCESSOR** — which **requires a DPA** (LGPD Arts. 39–40 / GDPR Art. 28).
  In **self-hosted** mode Postern Labs operates no plane and is not a processor.
  Full note: [`COMPLIANCE.md`](COMPLIANCE.md); spec `docs/specs/POSTERN-ENTERPRISE.md` §9.
- **Data residency.** A managed deployment declares its region in
  [`residency.config.json`](residency.config.json): **EU (GDPR)**, **BR (LGPD)**,
  or **self-hosted** (customer-controlled). Residency governs **where** tenant
  metadata and node-lifecycle records physically live; it is a **deployment
  config, not a legal opinion**. **Cross-border transfer of personal data is a
  legally gated act** (GDPR Arts. 44–49 / LGPD Arts. 33–36) and must be reviewed
  by counsel before it is enabled.
- **Hard gate.** Legal review + a real data-protection audit precede any
  production deployment. Nothing in this repository clears that gate.

## The model

```
corporate org  ──master token──▶  admitTenant()      (offline verify(), DUNS required)
                                        │  fail-closed: no verifier / bad token / no DUNS ⇒ no tenant
                                        ▼
                                 TENANT (opaque tenantId, isolation namespace)
                                        │
                 provision(spec) ──────▶│◀────── deprovision(nodeId)
                                        ▼
                          managed Postern node records  (in the tenant's scope ONLY)
                                        │
       reconcile() re-verifies the master token ── revoked/expired ──▶ deprovisionTenant() + wipe
```

- **Tenant identity** (`src/tenant.mjs`): a tenant exists only from a master
  token that verifies offline and carries a DUNS. The `tenantId` is a
  deterministic, opaque isolation label (non-cryptographic FNV-1a over
  `duns|orgName`), so the same org always maps to the same id and two orgs never
  collide.
- **Isolation** (`src/isolation.mjs`): every resource is namespaced under
  `<tenantId>/…`; escape-shaped and cross-tenant names are **refused**, not
  filtered. There is no query that spans two tenants.
- **Orchestrator** (`src/orchestrator.mjs`): `provision` / `deprovision` /
  `deprovisionTenant` / `listNodes`. Node records live **inside** the owning
  tenant's isolation scope. With no operator `driver`, every node is flagged
  `simulated: true` — no real host is created.
- **License binding** (`src/license-binding.mjs`): `admit` / `reconcile` /
  `revoke`. Enforces **revoke ⇒ deprovision**.
- **Health API** (`src/health-api.mjs`): honest per-tenant status (scoped) and a
  fleet summary that exposes **counts only** — never one tenant's records to
  another caller, and never a fabricated "healthy" for a simulated node.

## Files

| File | What |
|------|------|
| `src/tenant.mjs` | admit a tenant from an offline-verified master token; derive its opaque isolation id |
| `src/isolation.mjs` | by-construction tenant namespacing + `ISOLATION_STATEMENT` (honest limits) |
| `src/orchestrator.mjs` | provision / deprovision managed nodes per tenant (no real infra without a driver) |
| `src/license-binding.mjs` | bind tenant lifecycle to the master license — revoke ⇒ deprovision |
| `src/health-api.mjs` | honest health / status API (scoped per tenant; fleet counts only) |
| `src/privacy.mjs` | hosted-privacy disclosure (`CLOUD_PRIVACY`, `cloudPrivacyText()`) |
| `src/index.mjs` | `createControlPlane()` — assembled entry point |
| `self-check.mjs` | dependency-free smoke test / demo (`node self-check.mjs`) — 39 checks |
| `NOTICE`, `LICENSE-MIT`, `LICENSE-APACHE` | dual license |

## Run the checks

```sh
node enterprise/cloud/control-plane/self-check.mjs   # 39 checks, exits non-zero on failure
node --check enterprise/cloud/control-plane/src/*.mjs # syntax
```

## Wiring the real licensing lib and an operator driver

Inject the offline `verify()` (from `enterprise/licensing/`) and, optionally, the
operator's real provisioner. This module never reimplements either:

```js
import { createControlPlane } from "./src/index.mjs";

const cp = createControlPlane({
  verify: lib.verify,        // offline master-token verifier (licensing lib)
  driver: operatorDriver,    // OPTIONAL: create(tenantId,spec) / destroy(tenantId,handle) / probe(tenantId,handle)
});

const { tenant } = cp.admitTenant(masterToken);          // fail-closed if it doesn't verify
await cp.provision(tenant.tenantId, { region: "sa-east-1", role: "validator" });
await cp.reconcile();                                    // revoke ⇒ deprovision, on a schedule
const status = await cp.tenantStatus(tenant.tenantId);   // scoped, honest
const fleet  = cp.fleetHealth();                         // counts only, no tenant identity
```

The operator `driver` interface (all methods may be async):

```
driver.create(tenantId, spec)   -> { handle, endpoint? }
driver.destroy(tenantId, handle)-> void
driver.probe(tenantId, handle)  -> { reachable: boolean, detail?: string }
```

Absent a driver, `provision()` records intent only and every node is honestly
reported as `simulated`.
