<!--
SPDX-License-Identifier: MIT OR Apache-2.0
SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
-->

# Compliance note — hosted services (data processor / DPA)

> **Not legal advice.** This is an honest engineering disclosure. A **legal
> review + a real data-protection audit are a HARD GATE** before any production
> deployment. Nothing here clears that gate. See
> `docs/specs/POSTERN-ENTERPRISE.md` **§9** (Compliance-ENABLING control map —
> "Processor / DPA controls", LGPD Arts. 39–40 / GDPR Art. 28).

## Controller vs. processor, stated plainly

When **Postern Labs operates these hosted services** (the license-verification
service, the admin-console backend, and/or the comms relay) for a corporate
tenant, then for the personal data they touch:

- the **corporate tenant is the DATA CONTROLLER**, and
- **Postern Labs is a DATA PROCESSOR** acting on the controller's documented
  instructions.

This relationship **requires a Data Processing Agreement (DPA)** — **LGPD
Arts. 39–40** and **GDPR Art. 28** (processor bound by contract; Art. 28(3)
clauses on scope, duration, sub-processors, security, assistance,
deletion/return, and audit). The DPA is a **precondition** of running the managed
services.

## What each hosted service exposes to the processor (already disclosed)

The DPA annex must reflect what these services actually see — which each declares
honestly in its `GET /v1/posture` and in the README:

- **license-service** — check-in metadata (which org/sub, when, from what IP);
  holds only the vendor **public** key (no signing key, no application data).
- **console-service** — org identity, the roster, token metadata; in the
  *delegated* mode only, the master private key in memory at mint time (a
  disclosed trust regression — client-sign avoids it).
- **relay-service** — routing metadata (who→whom, when, size); **never** message
  plaintext (E2EE bodies are opaque — architecture, not a promise).

## Self-hosted / offline changes the analysis

The self-hosted and offline counterparts (`enterprise/licensing/`,
`enterprise/features/`, `enterprise/comms/`) put the customer in control of the
data and remove Postern Labs from the path — **no processor relationship with
Postern Labs**. Those paths are free and stay first-class; the hosted services
are a disclosed, *less-private* convenience carrying the DPA obligation above.

Drafting/executing the DPA, sub-processor approval, and international-transfer
clauses are **counsel's call** (spec §9).
