<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- BUCKET D PMO — readiness scoring for the D&B DUNS/LoA item -->

# READINESS — D&B Direct+ DUNS verification / LoA item

## Score: **PARTIAL** (today) → target **PREP-READY-FOR-CREDS** after Dev D1 + Advisor D1 land

Not scoring this "blocked-needs-creds-only" yet, because there is real,
HOST-fixable work outstanding that has nothing to do with the missing
credentials. Scoring it honestly as PARTIAL until that work lands is the
point of this exercise.

### What's already true (read directly from the code, not inherited from prior docs)

- `verifyDunsWithDnB` (OAuth2 client-credentials + static-bearer fallback) and
  `dnbDecisionFrom` (response→token-field mapping) are implemented in all
  three of `functions/license/{master,renew,review}.js`, self-contained (no
  imports), matching the "copy verbatim to `bp-wt-site`" deploy pattern
  already used by the rest of the license spine.
- Fail-open-to-`format-only` on any D&B outage/misconfiguration, fail-closed
  (refuse issuance) on a confirmed D&B `not-found` — the core safety property
  is present in the code today.
- `computeLoa`/`kycGate` in `review.js` implement the documented LoA 0-3
  ladder with the important invariant intact: D&B entity verification alone
  never elevates LoA (entity-is-real ≠ person-has-authority).
- `apps/gramota-kyc/review-seam.test.mjs` already exists and passes today
  (verified: `node apps/gramota-kyc/review-seam.test.mjs` → **9/9 passed**,
  HOST-runnable, mock-only, no framework needed). It covers the PII tripwire,
  sanitization, `kycGate` parity/enforced/refuse paths, and persisted-verdict
  shape.
- No secrets are set anywhere in this repo (confirmed absent) — no risk of an
  accidental live call today.
- `scripts/check-trust-labels.sh` runs clean (critical:0) at present.

### What's outstanding (PARTIAL, not blocked-needs-creds-only)

| Gap | Blocked on creds? | Owner |
|---|---|---|
| **No request timeout** on either `fetch` call in any of the 3 `verifyDunsWithDnB` copies (Finding F2, PARTITION.md §4) | **No — HOST-fixable now.** | Dev D1 |
| `verifyDunsWithDnB` itself has **zero direct unit tests** — only reachable indirectly via `kycGate`'s happy/not-found paths today; the auth-failure, malformed-response, network-exception, and timeout branches are untested | **No — HOST-fixable now.** | Dev D1 |
| No representative D&B response **fixtures** exist yet (`apps/gramota-kyc/fixtures/dnb/`) | **No — HOST-fixable now.** | Dev D1 |
| Cross-file drift between the 3 duplicated `verifyDunsWithDnB` copies is unaudited | **No — HOST-fixable now.** | Dev D1 / Advisor D1 |
| `kyc-loa.mjs` (client) and `review.js`'s `computeLoa` (server) are not actually the same model, despite a comment claiming parity (Finding F1) | **No — HOST-fixable now (doc fix or reconcile).** | Dev D1 |
| Independent correctness + honesty audit not yet performed | **No — HOST-doable now.** | Advisor D1 |
| `review.js` is **not present in `bp-wt-site`** (the actual deploy target) | **No — but cross-repo, out of Bucket D's file ownership.** Flagged, not fixed here. | Site owner / Bucket C (deploy config) |
| Real D&B account/contract + `DNB_CLIENT_ID`/`DNB_CLIENT_SECRET` (or `DNB_BEARER`) | **YES — this is the actual external-credential gate.** | Operator (procurement) |
| Live-response mapping verification against a real payload | **YES — cannot happen without the account.** | Operator, post-creds, per RUNBOOK.md §3 |

### Why PARTIAL and not "blocked-needs-creds-only"

`docs/gap/enterprise-gaps.md` §1.2 already characterizes this item as "code
real, no creds/mapping-verify — SCAFFOLD." That's accurate for the happy-path
logic, but this PMO pass surfaced two things that characterization glossed
over: **no timeout handling** (a real fail-closed gap independent of
credentials) and **no direct/fixture-driven test coverage of the DNB client
itself** (the existing test suite covers the KYC gate around it, not the
client). Both are fixable entirely on this HOST, entirely with mocks, with
zero D&B access. Calling this "blocked-needs-creds-only" today would
overstate readiness — exactly the kind of claim this fleet's honesty rail
exists to catch.

### Path to PREP-READY-FOR-CREDS

1. Dev D1 lands: timeout fix (+ hunks to Bucket C for `master.js`/`renew.js`),
   `dnb-client.test.mjs` + fixtures, the F1 doc/parity fix — per PARTITION.md.
2. Advisor D1 audits and returns APPROVE or APPROVE-WITH-FOLLOW-UPS (a BLOCK
   sends it back to Dev D1, not to READINESS).
3. `scripts/check-trust-labels.sh` re-run, still critical:0.
4. At that point: **PREP-READY-FOR-CREDS** — the only remaining gate is
   genuinely external (D&B account/contract + secrets + the cross-repo
   `review.js` deploy), and RUNBOOK.md §3 is the exact, honest, mock-verified
   procedure the operator runs the moment those land. This bucket's PMO does
   not re-score to "done"/"closed" at any point — "closed" requires a live
   D&B response, which by this task's hard constraint never happens here.

### Explicit non-claims

- This document does not claim `verifyDunsWithDnB` is correct against the
  real D&B API — only that it is correct against synthetic, docs-derived
  fixtures, and that its failure modes are fail-closed by design.
- This document does not claim LoA elevation has ever occurred for a real
  requester.
- This document does not claim `review.js` is deployed or reachable in
  production today (it is not, per `docs/gap/enterprise-gaps.md` §4.2).
