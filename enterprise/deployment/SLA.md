<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# SLA.md — the support model, stated honestly

Postern's Business/Enterprise revenue is **deployment help, signed/notarized
build channels, and priority/SLA support**. This document states that model
plainly. The paid thing is **work and assurance** — never the token, never your
data.

## What you are (and are not) buying

You **are** buying:

- A committed **response-time window** (time to a substantive human reply).
- Hands-on **deployment and operational help** for self-hosting.
- A verifiable **signed build channel** and verification tooling.

You are **not** buying:

- A promise that any specific bug is instantly solvable (a **response**
  commitment is not a **resolution** guarantee).
- Any claim that the software is **secure, audited, attested, or production-
  ready** — it is not.
- A **security** — the coin is not one, and it is never the billing instrument.
- **Reproduction** — packaging is reproducible-by-design, not reproduced.

## Editions & pricing

| Edition | Price | Support |
|---|---|---|
| **Personal / community** | **Free**, always; buildable from source (not "Postern OS") | Best-effort community |
| **Business** | **Free 6-month evaluation**, then a paid **fiat** licence | Business-hours SLA |
| **Enterprise** | Paid **fiat** licence | Priority SLA, partly 24×7 for sev1 |

Licences and support are billed in **fiat, not the coin**. Personal products
stay free.

## Response-time targets

Machine-readable source of truth: [`support/sla-policy.yaml`](support/sla-policy.yaml).
Targets are **time-to-first-substantive-response**, not resolution times.

| Severity | eval (free) | business (paid) | enterprise (paid) |
|---|---|---|---|
| **sev1** critical/outage | 1 business day | 4 business hours | 1 hour (24×7) |
| **sev2** major | 2 business days | 8 business hours | 4 business hours |
| **sev3** minor | 5 business days | 2 business days | 1 business day |
| **sev4** question | best effort | 5 business days | 3 business days |

Track any ticket against these targets with
[`support/sla-track.sh`](support/sla-track.sh).

## Privacy — "we sell work + assurance, not your data"

- **No telemetry, no analytics, no product-usage collection.** SLAs are backed
  by customer-opened **tickets only**, not surveillance.
- Support intake is **minimal-data**: an opaque `org_ref` for entitlement, an
  **optional** single reply handle, and what the customer chooses to write. See
  [`support/intake-schema.json`](support/intake-schema.json), which explicitly
  forbids IP addresses, device fingerprints, session capture, and extra PII.
- **Bounded retention** — no indefinite storage of support records.

## Honesty rails

- Nothing here is secure, audited, attested, or production-ready.
- Reproducible-by-design ≠ reproduced.
- A signature proves origin + integrity only, not source-correspondence.
- The coin is not a security and is never the billing instrument.
