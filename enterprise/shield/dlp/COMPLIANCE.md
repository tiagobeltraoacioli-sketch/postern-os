<!--
SPDX-License-Identifier: MIT OR Apache-2.0
SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
-->

# COMPLIANCE — Bloch Shield DLP layer (classification + third-party traceability)

> **LOUD CAVEAT, READ FIRST.**
> This document maps the DLP layer's design to LGPD and GDPR. It is
> **adherence-by-design, NOT certified compliance.** No third party has audited
> this code. It is a design / reference prototype, unaudited and pre-production.
> **I am not a lawyer and this is not legal advice.** A qualified
> privacy/employment lawyer and a real audit — for your jurisdiction, your
> deployment, and your data — are required before any production use. Your
> organisation is the **data controller** and remains solely responsible for
> lawful processing. Nothing here is a claim of "fully secure", "fully private",
> or "unhackable". The Postern coin is **not a security**.

## The one rail this whole layer is built around

**Corporate scope only. Never personal-side surveillance.**

The DLP layer classifies, gates, and traces **corporate data leaving the work
container to a third party** — and nothing else. The employee's personal
activity (personal apps, messages, browsing, files, location, keystrokes, screen,
clipboard, camera, microphone) is **out of scope by construction**:

- `classify()` recognises non-corporate origin and returns `PERSONAL`,
  `corporate:false` — it is not gated and not traced.
- The traceability trail (`audit-trail.mjs`) has exactly **one** allowed event,
  `corporate.third-party-egress`, and a forbidden-pattern tripwire that **throws**
  on any personal-scope or surveillance-shaped record. This is not a config
  toggle you can flip; crossing the line is an error.
- The employee transparency text states plainly what IS traced (corporate egress)
  and what is NEVER traced (anything personal).

This is the honest inverse of covert monitoring: the trail exists to account for
where the **employer's own** confidential data went, and it protects the employee
(as proof the scope is limited) as much as the employer.

## What the layer does

| Module | Responsibility |
| --- | --- |
| `classification.mjs` | Corporate sensitivity taxonomy (public / internal / confidential / restricted) + fail-closed `mayShareWithThirdParty()` sharing policy. Recognises `PERSONAL` only to refuse it. |
| `egress-gate.mjs` | The call the container makes when corporate data leaves: classify -> policy verdict (allow / warn / block) -> record (corporate only). |
| `audit-trail.mjs` | Append-only, SHA-256 hash-chained, tamper-evident trail of corporate third-party egress, scoped by master/sub identity. Disclosed + employee-visible. |
| `transparency.mjs` | The disclosure banner text, generated from the model so words cannot drift from behaviour. |

The layer builds ON the suite's shared kernels (it references, does not fork
them): the **postern-policy** consent kernel (`crates/postern-policy`, fail-closed
`Decision`, required future `Expiry`, `Revocation`), the **ezekiel1** governance
engine (`apps/ezekiel1`, no-widening lattice + hash-chained "rims full of eyes"
trail), and **sub-access** master/sub identity (`enterprise/features/sub-access.mjs`).

## LGPD (Lei Geral de Proteção de Dados, Lei 13.709/2018)

| LGPD provision | How the design engages it | Honest limit |
| --- | --- | --- |
| Art. 6 — principles (purpose, adequacy, necessity, transparency, security, accountability) | Single-purpose trail (corporate egress); data minimised (class + destination + identity + time, **not the content**); transparency text is mandatory; hash chain supports accountability. | Principles are a legal standard; a passing design is not a legal ruling. |
| Art. 7 X / Art. 10 — legitimate interest | Corporate-egress tracing is framed as the controller's legitimate interest in preventing loss of its **own** confidential data, balanced against the employee's rights and disclosed. | The Art. 10 §3 balancing test / DPIA is the controller's + DPO's job, not this tool's. |
| Art. 8 — consent must be free, informed, unambiguous | Transparency text is the "informed" input. The docs flag that employment-context consent is often **not free**, so legitimate-interest/legal-obligation usually applies. | Choosing the correct basis is a legal decision. |
| Art. 9 / Art. 18 — data-subject rights (access, correction, deletion, portability, info) | `visibleTo(subAccessId)` gives the employee their own egress records; the trail is disclosed, not covert. | Append-only records are not user-erasable (accountability purpose); that trade-off must be documented in the ROPA. |
| Art. 37 — record of processing (ROPA) | The classification model + trail schema are a machine-readable inventory a ROPA can cite. | A ROPA is a controller obligation; this is an input, not the ROPA. |
| Art. 39 — data processor obligations | `confidential` third-party grants require a **DPA on file**; `restricted` is un-shareable. | Whether a real DPA exists and is adequate is a contractual/legal fact this tool only records a flag for. |
| Art. 46/47 — security & good practice | Tamper-evident hash chain; minimisation; no telemetry. | Tamper-**evident**, not tamper-**proof**; integrity != confidentiality. Unaudited. |

## GDPR (Regulation (EU) 2016/679)

| GDPR provision | How the design engages it | Honest limit |
| --- | --- | --- |
| Art. 5 — principles (lawfulness, purpose limitation, minimisation, integrity) | Same single-purpose, minimised, integrity-chained design as above. | Art. 5(2) accountability is demonstrated, not certified. |
| Art. 6(1)(f) — legitimate interests | Preventing loss of the controller's confidential data, with the Art. 6(1)(f) balancing disclosed to the data subject. | The LIA (legitimate interests assessment) is the controller's. |
| Recital 43 / Art. 7 — consent in employment | Docs flag that employer↔employee power imbalance usually makes consent invalid; another basis + this disclosure is the norm. | Legal call for the DPO. |
| Arts. 12–14 — transparency / information | `transparency.mjs` is the Art. 13/14 notice content: what is processed, why, on what basis, and rights. | Delivery/UX and completeness for the specific deployment must be reviewed. |
| Arts. 15–22 — data-subject rights | `visibleTo()` = self-serve access to one's egress records; disclosure is the anti-covert guarantee. | Erasure of append-only accountability records may be lawfully refused; document it. |
| Art. 25 — data protection by design & by default | Corporate-only scope, minimisation, fail-closed default (block on silence) are by-design defaults. | "By design" is a design property; still requires the controller's DPIA. |
| Art. 28 — processors | `confidential` egress requires a DPA-on-file flag; `restricted` never leaves. | The Art. 28 contract itself is a legal document outside this tool. |
| Art. 32 — security of processing | Hash-chain integrity, minimisation, no telemetry / no phone-home. | Tamper-evident only; unaudited; not "fully secure". |
| Art. 35 — DPIA | This layer's model + schema feed a DPIA for BYOD monitoring, which is likely to be **required**. | The DPIA is the controller's obligation. |
| Ch. V — international transfers | Third-party destination is an explicit, gated concept; residency is carried in the disclosure. | Adequacy / SCCs for cross-border transfer are legal instruments outside this tool. |

## BYOD (bring-your-own-device) note

On BYOD, the corporate/personal split **is** the compliance boundary. This layer
only ever sees the corporate container's egress; the employee's personal
partition is never processed. That separation is the whole reason the design can
honestly claim it does not surveil the employee — but it depends on the container
(`enterprise/shield/container/`, another developer's) actually enforcing the
partition at the real boundary. This module evaluates and records intent; it is
**not** an OS/kernel/hardware sandbox (same honesty as ezekiel1's firmament and
Yagabona's "userland boundary, not a sandbox" caveat).

## What this is NOT

- **Not certified.** Adherence-by-design ≠ a compliance certificate.
- **Not legal advice.** Get a lawyer and a DPO. I am not a lawyer.
- **Not audited.** No third party has reviewed this code.
- **Not "fully secure / fully private / unhackable."** No honest software claims that.
- **Not surveillance.** It cannot record personal activity; attempts throw.
- **Not the Postern coin as a security.** The coin is not a security.
- This is the **community/enterprise edition tooling**, not "Postern OS".
