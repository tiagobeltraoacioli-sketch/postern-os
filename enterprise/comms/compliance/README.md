<!--
SPDX-License-Identifier: MIT OR Apache-2.0
SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
-->

# Postern Comms (Enterprise) — compliance & employee-privacy layer

> **Honest status: design / reference prototype. UNAUDITED. Pre-production.**
> **NOT legal advice. Adherence-by-design is NOT certified compliance.**
> **Legal review + a real data-protection audit are a HARD GATE before any
> deployment.** See [`COMPLIANCE.md`](./COMPLIANCE.md) for the full caveat and the
> LGPD/GDPR article mapping.

This is the **LGPD/GDPR compliance + employee-privacy layer** for the
enterprise-only internal communication app. It is **framework-free, dependency-
light** (Node built-ins only), and it does **not** touch the messaging app — the
app lives in `../app/` and is owned by another developer. This layer is a
**contract over the app's data model**: a policy/rights engine plus honest
disclosures.

## The rails (never bent)

- **Not legal advice.** I am not a lawyer. This is tooling + disclosures.
- **Adherence-by-design ≠ certified.** No certification is claimed or implied.
- **Honest employer visibility — no covert surveillance.** The audit trail is
  admin-actions-only and employee-visible; no content/keystroke/screen logging.
- **Minimize data.** Privacy-first minimization defaults; retention windows bound
  everything.
- **Not "fully private".** No "100% private"/"unhackable" claim anywhere. E2EE
  content is unreadable by the employer, but metadata exists and is disclosed.
- **Unaudited, pre-production.** The coin is **not a security**.

## Files

| File | What it is |
|------|-----------|
| `data-model.mjs` | Declared data classes + **E2EE visibility map** — the single source of truth every disclosure is built from. |
| `rights-engine.mjs` | Data-subject rights (LGPD Art. 18; GDPR Arts. 15–22) as request handlers that **refuse honestly** rather than over-promise. |
| `retention.mjs` | Retention & minimization engine (evaluate + validate); resolves the E2EE-vs-retention tension explicitly. |
| `retention-policy.json` | Reference retention policy (per data-class / channel-class windows). |
| `residency.config.json` | EU / BR / self-hosted residency options, documented. |
| `audit-trail.mjs` | Disclosed, employee-visible, append-only, tamper-evident admin-audit trail. |
| `transparency.mjs` | The employee disclosure the app banner injects (generated from the data model). |
| `breach.mjs` | Breach-notification hook (72h clock, ANPD/GDPR authority routing, DPO draft). |
| `ropa.template.json` | Records-of-processing template (GDPR Art. 30 / LGPD Art. 37). |
| `schemas/export.schema.json` | JSON Schema for a portability export package. |
| `self-check.mjs` | Dependency-free honesty-invariant checks + JSON validation. |
| `COMPLIANCE.md` | Full caveat + feature→article mapping. |

## Verify

```sh
node self-check.mjs        # 15/15 honesty-invariant checks + JSON validation
node --check *.mjs         # syntax
```

## Integration contract (for the app dev)

This layer never imports the app. It expects the app's data layer to call in
through documented, optional hooks:

- `rights-engine.mjs` handlers accept `{ fetcher, writer, eraser, flagger }` —
  the app supplies real readers/writers; without them the handlers return an
  honest *plan* (what could be served / must be refused).
- `retention.mjs :: evaluate()` returns a **deletion plan** the app's data layer
  executes; this layer deletes nothing itself.
- `audit-trail.mjs :: AuditTrail` can be constructed from an existing stored
  chain and appended to; the app persists it.

## License

Dual-licensed **MIT OR Apache-2.0** (`LICENSE-MIT`, `LICENSE-APACHE`).
