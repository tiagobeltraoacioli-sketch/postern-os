<!--
SPDX-License-Identifier: MIT OR Apache-2.0
SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
-->

# Compliance note — control plane (data processor / DPA)

> **Not legal advice.** This is an honest engineering disclosure. A **legal
> review + a real data-protection audit are a HARD GATE** before any production
> deployment. Nothing here clears that gate. See
> `docs/specs/POSTERN-ENTERPRISE.md` **§9** (Compliance-ENABLING control map —
> "Processor / DPA controls", LGPD Arts. 39–40 / GDPR Art. 28).

## Controller vs. processor, stated plainly

When **Postern Labs operates the managed control plane** (provisioning,
deprovisioning, reconciling a tenant's managed nodes on infrastructure the tenant
does not run), then for the personal data processed on the tenant's behalf:

- the **corporate tenant is the DATA CONTROLLER** (it determines the purposes and
  means of processing its own workforce/business data), and
- **Postern Labs is a DATA PROCESSOR** acting on the controller's documented
  instructions.

A controller ⇄ processor relationship of this kind **requires a Data Processing
Agreement (DPA)** — **LGPD Arts. 39–40** (operador / obligations and instructions
of the controller) and **GDPR Art. 28** (processor bound by a contract, with the
Art. 28(3) clauses: scope, duration, sub-processors, security, assistance,
deletion/return, audit). The DPA is a **precondition**, not a nicety.

## Self-hosted mode changes the analysis

In the **self-hosted** deployment the control plane runs on the **customer's own
infrastructure**, Postern Labs operates no server, and there is **no processor
relationship with Postern Labs at all** — the customer is controller and (for its
own infra) its own processor. Self-hosting stays free and is the more-private
path; the managed plane is a disclosed convenience with the DPA obligation above.

## What this repository does and does not give you

- **Does:** enumerate the data flows and lifecycle (provision / deprovision /
  reconcile), keep tenant isolation by construction, and disclose that hosted is
  *less private* — the raw material a DPA annex and a records-of-processing entry
  are built from.
- **Does not:** draft or execute a DPA, approve sub-processors, or supply
  international-transfer clauses. Those are **counsel's call** (spec §9).
