<!--
SPDX-License-Identifier: MIT OR Apache-2.0
SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
-->

# Compliance note — cloud image (data processor / DPA)

> **Not legal advice.** This is an honest engineering disclosure. A **legal
> review + a real data-protection audit are a HARD GATE** before any production
> deployment. Nothing here clears that gate. See
> `docs/specs/POSTERN-ENTERPRISE.md` **§9** (Compliance-ENABLING control map —
> "Processor / DPA controls", LGPD Arts. 39–40 / GDPR Art. 28).

## Controller vs. processor, stated plainly

This directory builds the deployable **cloud image** (`Containerfile`,
`compose.yaml`, `cloud-image.nix`, `build-image.sh`) that runs the managed plane.
When **Postern Labs operates the plane built from this image** on behalf of a
corporate tenant, then for the personal data processed:

- the **corporate tenant is the DATA CONTROLLER**, and
- **Postern Labs is a DATA PROCESSOR** acting on the controller's documented
  instructions.

This relationship **requires a Data Processing Agreement (DPA)** — **LGPD
Arts. 39–40** and **GDPR Art. 28** (processor bound by contract; the Art. 28(3)
clauses on scope, duration, sub-processors, security, assistance,
deletion/return, and audit). The DPA is a **precondition** of operating a managed
deployment.

## Who runs the image decides who the processor is

- **Postern Labs runs it (managed):** Postern Labs is the processor → DPA
  required, as above. Any infrastructure sub-processor (host, storage, network)
  must be enumerated in the DPA's sub-processor annex.
- **The customer runs it (self-hosted / on-prem):** the customer is controller
  and its own operator; **Postern Labs operates no server and is not a
  processor.** This is the more-private path and stays free.

Drafting/executing the DPA, approving sub-processors, and international-transfer
clauses are **counsel's call** (spec §9). Data-residency options for a managed
deployment are declared in `enterprise/cloud/control-plane/residency.config.json`.
