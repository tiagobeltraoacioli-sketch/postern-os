<!--
SPDX-License-Identifier: MIT OR Apache-2.0
SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
-->

# Postern Comms (Enterprise) — LGPD / GDPR compliance mapping

> ## Read this first (the loud caveat)
>
> **I am not a lawyer, and this is not legal advice.** This directory is
> **compliance-BY-DESIGN tooling and honest disclosures** — a policy/rights
> engine plus plain-language notices. It is **NOT** a certification, an
> attestation, or a guarantee of compliance.
>
> - **Adherence-by-design ≠ certified compliant.** Building to the shape of a
>   right does not prove a deployment satisfies it.
> - **Jurisdictions differ.** LGPD (Brazil) and GDPR (EU) are not identical, and
>   both are interpreted by authorities and courts. Other jurisdictions differ
>   again.
> - **The employer is the data controller** and remains responsible for lawful
>   use. Postern Labs is at most a processor (and in self-hosted mode, not even
>   that — it operates no server).
> - **Legal review + a real data-protection audit are a HARD GATE** before any
>   production deployment. Nothing here clears that gate.
> - This software is **unaudited, pre-production reference**. The coin is **not a
>   security**. No claim of "100% private" or "unhackable" is made anywhere.

## The one honesty that shapes everything

Message **content is end-to-end encrypted**. The employer and the operator hold
only **unreadable ciphertext**. Therefore:

- **What the employer cannot read, the employer cannot produce, correct, or
  export** on an employee's behalf. An employer-served access/portability request
  returns metadata + directory data — never message plaintext.
- The employee exercises content-level rights (export their own history) **from
  their own client**, because only their device holds the keys.

This is disclosed to every employee in plain language (`transparency.mjs`). It is
the privacy design working as intended — not a gap we hide.

## Feature → article mapping

### Data-subject rights (`rights-engine.mjs`)

| Right | LGPD | GDPR | Honest limit encoded |
|-------|------|------|----------------------|
| Confirmation & access | Art. 18 II/III | Art. 15 | E2EE content refused with a self-serve path; only employer-held data returned |
| Rectification / correction | Art. 18 III | Art. 16 | Directory identity correctable; event/audit logs are append-only (annotated, not rewritten) |
| Erasure / right to be forgotten | Art. 18 IV/VI | Art. 17 | Employer deletes ciphertext & metadata; directory erasure may be overridden by employment-record legal obligation (documented); audit trail retained for accountability |
| Portability / export | Art. 18 V | Art. 20 | Structured JSON (`schemas/export.schema.json`); employer scope = metadata + directory; content self-served |
| Objection | Art. 18 §2 / Art. 21 | Art. 21 | Flags a purpose to stop; may be overridden only by a documented compelling ground |
| Restriction / blocking | Art. 18 IV | Art. 18 | Flags a purpose to limit; does not delete |
| No solely-automated decisions | Art. 20 | Art. 22 | App makes none; any future addition must be disclosed + offer human review |
| Consent revocation | Art. 8 §5 / Art. 18 IX | Art. 7(3) | Honoured forward; processing on another basis unaffected (basis stated in ROPA) |

Response windows are surfaced (`RESPONSE_WINDOWS`): LGPD Art. 19 (15 days for a
full declaration); GDPR Art. 12(3) (1 month, +2 for complexity). Informational,
not legal advice.

### Retention & minimization (`retention.mjs`, `retention-policy.json`)

| Principle | LGPD | GDPR |
|-----------|------|------|
| Purpose limitation & necessity | Art. 6 I/II | Art. 5(1)(b), 5(1)(c) |
| Storage limitation (retention windows) | Arts. 15–16 | Art. 5(1)(e) |
| Data minimization defaults | Art. 6 III | Art. 5(1)(c) |

Configurable retention windows **per data-class and channel-class**. Minimization
defaults are privacy-first (presence history off, read-receipts not logged, IPs
abuse-window only). The **E2EE-vs-retention tension is resolved explicitly**: the
policy states, per class, *what* is retained, *by whom*, and forbids describing
operator-held E2EE content as anything but ciphertext (validation rejects it
otherwise). **Undisclosed (`disclosed:false`) retention is rejected at
validation** — covert retention violates the transparency rail.

### Data residency (`residency.config.json`)

EU / BR / self-hosted, declared as deployment options with the governing
regulation and the honest note that **cross-border transfer is a legally gated
act** (GDPR Arts. 44–49 / LGPD Arts. 33–36) requiring counsel. Residency is
config, not a legal opinion.

### Lawful, disclosed audit trail (`audit-trail.mjs`)

Records **admin actions only** — never message content, never covert monitoring.
GDPR accountability (Art. 5(2)) / LGPD Art. 6 X. Every record is **employee-
visible** (`visibleTo`), append-only, and **tamper-evident** via a SHA-256 hash
chain (Node built-in `crypto`; no dependency). Content/surveillance-shaped events
are refused at `append()`.

### Records of processing (`ropa.template.json`)

A fill-in **ROPA template** — GDPR Art. 30 / LGPD Art. 37 — for the controller to
complete and maintain. Bracketed fields are the controller/DPO's to fill.

### Breach notification (`breach.mjs`)

A **hook**, not an autopilot: structures the facts, computes the **72-hour**
working clock (GDPR Art. 33; LGPD Art. 48 — statutory wording differs), routes to
the right authority (EU DPA / ANPD / customer), surfaces the **ciphertext-only
mitigation** (Art. 34(3)(a) factor) **without concluding** notice is unnecessary,
and produces a DPO-reviewed draft. It notifies nobody automatically.

### Employee transparency (`transparency.mjs`)

The disclosure the app banner injects — generated **from the data model** so the
words cannot drift from the system's actual capability. States exactly what the
employer **can** and **cannot** see, the lawful basis for each, and honest limits
(including that employment-context consent is often not "freely given", so another
basis usually applies).

## What is verified vs. what is not

`self-check.mjs` (run `node self-check.mjs`) verifies the tooling's **honesty
invariants**: E2EE content is un-producible by the employer; access refuses it
with a self-serve path; audit trail refuses covert events and detects tampering;
retention rejects undisclosed/mis-described rules; transparency makes no absolute
claims; breach clock computes correctly. **15/15 pass.**

That is a check of *this tooling's internal consistency*. **It is not, and cannot
be, a check that a deployment is legally compliant.** That still requires the hard
gate: legal review + a real audit.
