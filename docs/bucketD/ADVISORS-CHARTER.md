<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- BUCKET D PMO — 1-advisor charter -->

# ADVISORS-CHARTER — Bucket D (1 advisor)

## Advisor D1 — DNB client correctness + honesty audit

**Reviews:** Dev D1's output only, after Dev D1 lands. Independent read —
Advisor D1 should re-derive findings rather than rubber-stamp PARTITION.md's
claims. Scope is `functions/license/review.js` (sole Bucket D file), the
proposed hunks to `functions/license/master.js`/`renew.js` (review the diff,
not the whole file — those files stay Bucket C's), `apps/gramota-kyc/kyc-loa.mjs`,
`apps/gramota-kyc/dnb-client.test.mjs`, `apps/gramota-kyc/fixtures/dnb/*.json`,
and this doc set.

### A. Correctness

1. **OAuth client-credentials handling.** Basic-auth header built as
   `"Basic " + btoa(clientId:clientSecret)` — correct RFC 6749 §4.4 shape?
   Confirm `content-type: application/x-www-form-urlencoded` and
   `grant_type=client_credentials` body are right for D&B's stated OAuth2
   implementation (check against the D&B Direct+ authentication docs
   referenced in RUNBOOK.md, not against memory). Confirm the static-bearer
   escape hatch (`DNB_BEARER`) can't be silently preferred over a
   misconfigured client-credentials pair in a way that masks a real config
   error.
2. **No credential leakage.** Confirm `DNB_CLIENT_SECRET`/`DNB_BEARER` never
   appear in a thrown error, a response body, a log line, or a test fixture
   file. Grep the whole Bucket D file set for the literal secret env var
   names being interpolated into anything user/response-facing.
3. **Error/timeout/fail-closed matrix.** This is the load-bearing check.
   Verify, by reading the code (not trusting PARTITION.md's description):
   - Every D&B-down/misconfigured/network-error path returns
     `status:"unavailable"` and the caller falls back to `format-only` —
     **never** a hard 5xx that blocks legitimate onboarding on a D&B outage.
   - The ONE path that must fail closed (refuse) is a *confirmed* D&B
     `not-found` — verify that a `404` and a `200`-with-empty-organization
     both correctly land on `not-found`, and that neither an auth failure
     nor a timeout is ever miscategorized as `not-found` (that would refuse
     a legitimate customer because of an unrelated network blip — a
     correctness bug with real business impact, not just a style nit).
   - **Confirm Dev D1 actually added the timeout fix (Finding F2 in
     PARTITION.md)** — if the shipped diff has no `AbortController`/timeout
     around either `fetchImpl` call, this is a BLOCKING finding, not a nit:
     the audit's own charter names "timeout" explicitly.
   - Confirm the timeout path is exercised by a real test (a stub that
     never resolves, asserted to still return within bound), not just
     claimed in a comment.
4. **DUNS→LoA mapping soundness.** Walk `computeLoa`'s rung logic against the
   documented table (LoA 0 self-declared / 1 +corp-domain / 2 +D&B-principal-
   or-OCR / 3 +liveness-or-IDV) line by line. Confirm: (a) D&B entity
   verification ALONE never lifts LoA above 0 (entity-is-real is not
   person-has-authority — re-verify this is still true after Dev D1's
   changes, it's the single most important fail-closed property in this
   bucket); (b) no combination of *client-supplied, unverified* fields can
   reach LoA 2/3 without the corroborating signal actually being checked
   server-side (i.e., `sanitizeClientVerdict` can't be bypassed to inject a
   trusted-looking field); (c) the server (`review.js`) verdict is what's
   bound into the signed token by reference, so client-side `kyc-loa.mjs`
   divergence (Finding F1) cannot itself inflate an issued license's LoA —
   confirm this belt-and-braces claim is actually true in `master.js`'s
   `resolveKyc`/`boundKycFrom`, not just asserted in a comment.
5. **Cross-file drift.** Diff the shipped `master.js`/`renew.js` hunks
   against `review.js`'s canonical copy. Any unexplained behavioral
   difference across the three `verifyDunsWithDnB` copies is a finding.
6. **Fixture fidelity.** Spot-check 2-3 fixture JSON shapes against the
   actual D&B Direct+ Data Blocks public API reference structure (field
   names, nesting — `organization.primaryName`,
   `organization.primaryAddress.addressCountry.isoAlpha2Code`). A fixture
   that's shaped wrong makes the whole "mapping is correct" claim
   unverified-by-proxy.

### B. Honesty

1. **No live-vs-mock confusion, anywhere.** Read every new/changed file's
   comments, test names, and this doc set for any phrase that could be
   misread as "we verified against the real API." Every fixture file MUST
   carry the synthetic-fixture disclaimer (PARTITION.md §"Owned files").
   Every test file name/header must say mock/fixture, not "integration test"
   or "live test" unqualified.
2. **`scripts/check-trust-labels.sh` stays critical:0.** Run it after Dev
   D1's changes land: `bash scripts/check-trust-labels.sh`. Note for the
   record (don't let this become a false sense of coverage): the script's
   `EX`/scan paths are `apps`, `crates`, `site`, `desktop`, `pmos-overlay`
   plus the specific `NONATTEST_PATHS`/`QUALIFIED_PATHS` lists — it does
   **not** scan `functions/license/*.js` directly for attestation-grade
   bleed. `apps/gramota-kyc/**` (fixtures, tests, `kyc-loa.mjs`) IS in scope
   of the WARN pass (`audited|secure|hardened|production-ready` on `apps/`).
   Advisor D1 must manually read `functions/license/review.js` (and the
   Bucket-C-owned hunks) for honesty since the mechanical gate doesn't cover
   that directory — do not treat "critical:0" as "review.js is clean," treat
   it as "the apps/ surface and the two absolute bans are clean."
3. **RUNBOOK.md / READINESS.md self-check.** Confirm neither document
   contains a sentence that could be read as "DUNS verification is live" or
   "we tested this against D&B." Every success-signal description must be
   phrased as "what to look for once creds are set," not "what we observed."
4. **The "code done, cred-gapped" claim itself.** Cross-check
   `docs/gap/enterprise-gaps.md` §1.2/§4.2's characterization ("code real,
   no creds/mapping-verify") against what Dev D1 actually shipped — if the
   timeout fix or the new fixture suite change that characterization
   (e.g. genuinely closes the "mapping-verify" gap via fixtures, or doesn't),
   say so plainly; don't let the gap doc go stale silently.

### C. Deliverable

A short written finding set (blocking / non-blocking / honesty), each with a
file:line citation, ending in one of: **APPROVE** (fixture-tested, fail-closed,
honestly labeled — ready to sit cred-gated), **APPROVE WITH FOLLOW-UPS**
(non-blocking gaps noted), or **BLOCK** (timeout missing, a fail-closed
property broken, or a live/mock honesty violation found). Advisor D1 does not
approve deploy or credential provisioning — those are explicitly out of this
bucket's rails.
