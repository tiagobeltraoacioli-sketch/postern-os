<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Support intake & SLA tracking scaffold

A **lightweight, privacy-preserving** support-intake and SLA-tracking scaffold.
The stance is simple and honest: **we sell work and assurance, not your data.**

## Files

| File | Purpose |
|---|---|
| [`intake-schema.json`](intake-schema.json) | JSON Schema (draft-07) for a support ticket. Minimal-data by construction. |
| [`sla-policy.yaml`](sla-policy.yaml) | SLA **response**-time targets per tier/severity. |
| [`sla-track.sh`](sla-track.sh) | Reads a ticket, reports MET / AT_RISK / BREACHED vs. its target. |
| [`sample-ticket.json`](sample-ticket.json) | An example ticket that validates against the schema. |

## Privacy by construction — what we do NOT collect

The schema forbids (and the scaffold never captures): **telemetry, product
usage/analytics, IP addresses, device fingerprints, session/keystroke capture,
or any PII beyond a single reply handle the customer volunteers.** A ticket ties
to an SLA tier through an **opaque `org_ref`** (a licence id / short code), not a
person. `retention_days` is bounded — no indefinite retention. `sla-track.sh`
reads only the ticket file you hand it; it phones nowhere.

## Validate a ticket against the schema

```sh
# Structural sanity with jq (both files must be valid JSON):
jq empty intake-schema.json && jq empty sample-ticket.json

# Full schema validation (operator's choice of validator), e.g.:
#   python -m jsonschema -i sample-ticket.json intake-schema.json
#   npx ajv-cli validate -s intake-schema.json -d sample-ticket.json
```

## Track SLA status

```sh
./sla-track.sh sample-ticket.json
# override "now" for what-if checks:
./sla-track.sh sample-ticket.json --now 2026-07-14T10:00:00Z
```

Exit code: `0` MET, `1` AT_RISK, `2` BREACHED, `3` error. Targets are
**time-to-first-substantive-response**, not time-to-resolution.

> **Honest simplification:** `sla-track.sh` approximates "business hours/days"
> as elapsed **calendar** time (1 business hour ≈ 1h, 1 business day ≈ 8h). It
> is an order-of-magnitude signal, not a working-calendar engine. Its target
> table **mirrors** `sla-policy.yaml`; keep them in sync, or replace the table
> with a real YAML read + business-calendar math for production use. Nothing
> here is audited or production-ready.
