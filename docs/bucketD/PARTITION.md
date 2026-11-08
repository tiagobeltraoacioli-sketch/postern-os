<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- BUCKET D PMO — 1-dev partition for the DNB Direct+ client -->

# PARTITION — Bucket D (1 dev)

**Base:** `roadmap/fleet2-integrate` (LOCAL, read at `/Users/tiagoacioli/dev/bp-wt-fleet2`,
currently clean at `93b1ee9`). Dev D1 works IN `bloch-protocol` (this repo /
worktree), never in `bp-wt-fleet2` or any other worktree — those are read-only
reference for understanding the shipped shape of the code.

**Seam rule (per PMO mandate):** Bucket D owns the DNB/DUNS/LoA logic.
Bucket C owns CRL/master/deploy config. `functions/license/master.js` and
`functions/license/renew.js` are **Bucket C's files** — Bucket D does not
commit to them directly. Where Bucket D's D&B/LoA logic lives *inside* those
files (a byte-near-identical duplicate block in each — see §2), Dev D1
produces a **proposed hunk** and hands it to Bucket C to apply, exactly per
the fleet-wide "one file → one owner, everyone else hands a hunk" convention
(`docs/plan/ROADMAP-FLEET-MASTER-PLAN.md` §1).

---

## Dev D1 — the DNB Direct+ client

### Owned files (Dev D1 may edit directly)

| File | What's owned |
|---|---|
| `functions/license/review.js` | **Sole owner**, in full: `verifyDunsWithDnB` (OAuth token flow + DUNS lookup), `dnbDecisionFrom` (response→token-field mapping), `computeLoa`/`ocrValidated` (D&B response + client evidence → LoA 0-3), `kycGate` (fail-closed orchestration), `sanitizeClientVerdict`/`scanForPII` (input hygiene feeding the gate — edit only where it touches DNB/LoA fields; the PII tripwire itself is shared plumbing, coordinate any unrelated tripwire change out of this bucket's scope). |
| `apps/gramota-kyc/kyc-loa.mjs` | The on-device LoA ladder mirror. Dev D1 audits/keeps this in parity with `review.js`'s `computeLoa` (they are two independently-written models today — see Finding F1 below — reconciling or explicitly documenting the divergence is in scope). |
| `apps/gramota-kyc/dnb-client.test.mjs` **(new file)** | The fixture/mock test suite for the OAuth + lookup + mapping + fail-closed + LoA-gating matrix (§3). Does not duplicate `review-seam.test.mjs`'s existing coverage — extends it. |
| `apps/gramota-kyc/fixtures/dnb/*.json` **(new files)** | Representative D&B Direct+ response shapes, hand-authored from the public Direct+ API reference documentation (companyinfo_L1_v1 block + OAuth token response + error bodies). **Every fixture file MUST carry a header comment: `SYNTHETIC FIXTURE — shaped from D&B's public API reference docs; NOT a captured real response. Postern Labs holds no D&B account.`** |
| `docs/bucketD/**` | This PMO doc set — Dev D1 may append an implementation log/notes section but not rewrite the READINESS verdict (PMO territory). |

### Read-only / hand-a-hunk (Bucket C's files — do not commit directly)

| File | The Bucket-D-relevant block | Rule |
|---|---|---|
| `functions/license/master.js` | `verifyDunsWithDnB` (lines ~79-117) + `dnbDecisionFrom` (~120-136) | Byte-near-identical duplicate of `review.js`'s copy (formatted multi-line vs. `review.js`/`renew.js`'s compact style). Dev D1 diffs it for drift/correctness as part of the audit and, if a fix is needed (e.g. the timeout fix in §4), produces a single unified-diff hunk and hands it to Bucket C to apply. **Never edit this file directly.** |
| `functions/license/renew.js` | `verifyDunsWithDnB` (lines ~65-92) + `dnbDecisionFrom` (~93-98) | Same rule as above. |

### 3. The mock/fixture test suite (HOST-runnable, no live calls — mandatory shape)

Run pattern matches the existing convention exactly: plain ESM, custom
assert-based runner, invoked as `node apps/gramota-kyc/dnb-client.test.mjs`
(no framework, no `package.json` test script exists in this repo — same as
`review-seam.test.mjs`, verified runnable today: `node
apps/gramota-kyc/review-seam.test.mjs` → 9/9 passed).

**Already covered by the existing `apps/gramota-kyc/review-seam.test.mjs`**
(do not re-litigate, build on top of it):
- PII/image tripwire accept/reject.
- `sanitizeClientVerdict` field allowlisting.
- `kycGate` default-unconfigured parity (`pass`, `loa:0`, `enforced:false`).
- `kycGate` enforced + self-declared-only ⇒ `provisional`.
- `kycGate` refuses on D&B `not-found` (fail-closed).
- Verdict persisted under `kyc:<ref>` KV, PII-free.
- `computeLoa` two-point spot check.

**Net-new coverage `dnb-client.test.mjs` must add** (this is the actual gap —
today only the *happy path* and the *not-found* path of `verifyDunsWithDnB`
are reachable, indirectly, through `kycGate`'s stub; the function itself, and
`master.js`/`renew.js`'s copies, have zero direct tests):

1. **No creds configured** → `{status:"unavailable", reason:"dnb-not-configured"}`
   returned WITHOUT calling `fetchImpl` at all — assert with a fetch spy that
   throws if called, proving the short-circuit is real (this is the
   fail-closed-to-mock guarantee that makes the whole suite host-safe).
2. **Static `DNB_BEARER`** path skips the token exchange entirely (spy asserts
   `/v3/token` is never hit).
3. **OAuth token HTTP failure** (401/500 from `/v3/token`) →
   `dnb-auth-http-<code>`, `status:"unavailable"`.
4. **OAuth token response missing `access_token`/`accessToken`** →
   `dnb-auth-no-token`.
5. **Data lookup 404** → `status:"not-found"`, `reason:"dnb-duns-not-found"`.
6. **Data lookup non-404 error** (429, 500) → `status:"unavailable"`,
   `dnb-data-http-<code>`.
7. **Data lookup 200 but malformed body** (no `organization`, or
   `organization` with no `primaryName`) → `status:"not-found"`,
   `dnb-no-organization` — this is a fail-CLOSED choice worth a dedicated
   assertion (a malformed-but-200 response must not be silently treated as
   "unavailable/retry-later"; it refuses).
8. **Thrown/rejected fetch** (simulated network error) →
   `status:"unavailable"`, `dnb-network-error"` — never an unhandled
   rejection/crash.
9. **Successful mapping** — fixture-driven: feed each `fixtures/dnb/*.json`
   shape through `verifyDunsWithDnB`/`dnbDecisionFrom` and assert
   `legalName`/`country` extraction, including the edge case of a present
   `organization.primaryAddress` with no `addressCountry` (country → `""`,
   not a throw).
10. **Timeout / hang** (see Finding F2 below — this is a fix, not just a
    test): a `fetchImpl` that never resolves must not hang the Worker
    forever. Test with a controllable never-resolving stub + fake timers or a
    short real timeout; assert the call resolves to
    `status:"unavailable", reason:"dnb-timeout"` within the configured bound
    and that this is NOT confused with `not-found` (fail-open on timeout,
    same as any other outage — timeouts must never silently refuse a real
    customer's issuance).
11. **Cross-file parity** — a test that imports `verifyDunsWithDnB`/
    `dnbDecisionFrom` from all three files' exported forms (note: `master.js`
    exports them; confirm `renew.js` does or expose them for the test —
    if not exported, the test documents the byte-diff instead) and asserts
    identical behavior against the same fixture set. This is what catches
    "someone fixed the bug in one of the three copies and not the others."
12. **`computeLoa` full fail-closed matrix**: every rung (0/1/2/3) reachable
    only via its documented corroborating-signal combination; assert that
    OCR-match-without-liveness caps at 2, corp-domain-alone caps at 1,
    D&B-verified-alone-with-nothing-else stays at 0 (entity being real is not
    proof of the *person's* authority — this is the core design invariant,
    re-assert it explicitly as its own test, not just incidentally).
13. **`kycGate` × `KYC_MODE=enforce` full 2×2**: (D&B verified/not-configured)
    × (evidence sufficient/insufficient) → the four `decision` outcomes,
    including the refuse-on-not-found path already covered plus the
    previously-untested `unavailable` (D&B down, format-only fallback) +
    enforce + sufficient-evidence combination (must still be able to reach
    `pass` on format-only fallback + strong client evidence — outage must not
    become a hard denial of service for legitimate onboarding).

### 4. Concrete code-correctness fix in scope (not just tests)

**Finding F2 — no request timeout.** Neither `fetch` call in any of the three
`verifyDunsWithDnB` copies uses `AbortController`/a timeout. A slow or
hanging D&B response blocks the Worker request indefinitely (Cloudflare
Workers have their own platform-level CPU/wall-clock limits that will
eventually kill it, but the code has no *intentional* fail-closed timeout of
its own — it relies entirely on the platform, which is a latent gap the
"error/timeout/fail-closed" audit criterion in ADVISORS-CHARTER.md is
specifically checking for). Dev D1 adds an `AbortController` with a short,
documented timeout (e.g. 8s) around both the token and data `fetchImpl`
calls in `review.js` directly, and hands Bucket C the equivalent hunk for
`master.js`/`renew.js`. Map an abort to
`{status:"unavailable", reason:"dnb-timeout"}` — same fail-open-to-format-only
treatment as every other outage reason, never a hard failure.

**Finding F1 — LoA-model divergence.** `review.js`'s `computeLoa` (server,
inputs: `dnbVerified`/`corpDomain`/`ocr`/`principalMatch`/`idvPass`) and
`apps/gramota-kyc/kyc-loa.mjs`'s `makeKycLadder` (client, inputs:
`corpEmailProof`/`ocrMatch` against a `dnbRecord`/`idv`) are **not the same
function** — different rung triggers, different evidence shapes. The
`review.js` comment claims `kyc-loa.mjs` "mirrors the same normalizers on the
device," which is not literally true today. Dev D1 either (a) documents the
two as intentionally-different (server is authoritative and coarser; client
is a UI-facing preview) with the overclaiming comment corrected, or (b)
reconciles them. Recommend (a) — the server is the single source of truth by
design (verdict bound by reference so the client cannot inflate its LoA), so
an exactly-mirrored client ladder is not load-bearing; fix the comment,
don't force a refactor. Advisor D1 should confirm this call is sound.

### 5. What Dev D1 does NOT do

- No live D&B calls, ever, under any credential.
- No edits to `functions/license/status.js`, `enterprise/licensing/src/crl.ts`,
  or deploy config (Bucket C).
- No deploy of `review.js` to `bp-wt-site` (cross-repo, out of scope, flagged
  in RUNBOOK.md §4).
- No touching `bp-wt-fleet2` or any other worktree.
- No git commit (PMO rail) — Dev D1's actual code changes, when dispatched,
  land as a real commit in this repo per normal process; this PARTITION is
  the pre-dispatch plan.
