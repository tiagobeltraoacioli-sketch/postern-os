<!--
SPDX-License-Identifier: MIT OR Apache-2.0
SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
-->

# Bloch Shield — DLP layer (classification + third-party-sharing traceability)

**Enterprise edition only.** Design / reference prototype — **unaudited,
pre-production. Not legal advice** (see [`COMPLIANCE.md`](./COMPLIANCE.md)).

The data-loss-prevention layer for the enterprise **shield container**. It
classifies **corporate** data, gates it as it leaves the container to a **third
party**, and keeps a disclosed, tamper-evident trail of that corporate egress —
scoped by which master/sub identity did it.

> **The one rail that never bends: corporate scope only, never personal-side
> surveillance.** This layer classifies/gates/traces corporate data leaving to
> third parties. It never touches the employee's personal activity — a
> personal-scoped or surveillance-shaped record is *refused* (throws), not merely
> "off by default". Disclosed and employee-visible by design.

## Boundary

This directory (`enterprise/shield/dlp/`) is the DLP engine only. The
container/access surface lives in `enterprise/shield/container/` and is another
developer's. The DLP layer is a dependency-light library the container imports;
it *evaluates and records* intent and is **not** an OS/kernel sandbox — the
container is authoritative at the real egress boundary.

## Modules

- `classification.mjs` — corporate taxonomy (public / internal / confidential /
  restricted) + fail-closed `classify()` and `mayShareWithThirdParty()`.
- `egress-gate.mjs` — `gateEgress()`: classify → policy verdict (allow / warn /
  block) → trace (corporate only).
- `audit-trail.mjs` — `EgressTrail`: append-only, SHA-256 hash-chained,
  tamper-evident, master/sub-scoped, corporate-egress-only.
- `transparency.mjs` — the employee disclosure banner, generated from the model.
- `schemas/sharing-policy.schema.json` + `sharing-policy.example.json` — the
  org sharing policy shape and an example.
- `index.mjs` — the public barrel the container imports.

## Built on (referenced, not forked)

- `crates/postern-policy` — the fail-closed consent kernel (`Decision`, required
  future `Expiry`, `Revocation`). This layer mirrors its "silence is no" and
  "no-widening" semantics in JS.
- `apps/ezekiel1` — governance engine; its hash-chained "rims full of eyes"
  trail is the pattern the traceability trail follows.
- `enterprise/features/sub-access.mjs` — master/sub identity; egress is scoped by
  the sub-access token id.

## Run the smoke test

```
node enterprise/shield/dlp/self-check.mjs
```

No test framework; exits non-zero on failure.

## Honest limits

Adherence-by-design ≠ certified. Tamper-**evident**, not tamper-**proof**.
Unaudited. Not "fully secure/private". Not legal advice. The coin is not a
security. This is the enterprise-edition tooling, not "Postern OS".

Dual-licensed **MIT OR Apache-2.0** (see `LICENSE-MIT`, `LICENSE-APACHE`).
