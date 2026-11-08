<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- BUCKET D PMO — D&B Direct+ DUNS verification / LoA elevation runbook -->

# RUNBOOK — D&B Direct+ DUNS verification → LoA elevation

**Owner:** Bucket D PMO · **Scope:** the ONE external-credential item —
Dun & Bradstreet Direct+ DUNS verification feeding LoA (Level of Assurance) >0
into the Gramota KYC / license-issuance seam.

**HARD HONESTY CONSTRAINT:** nothing in this repo has ever called the real D&B
API. Every code path, test, and fixture referenced below is
**mock/fixture-only**. This runbook documents what the OPERATOR must do with
real D&B credentials; it is not evidence that verification has occurred.

---

## 1. What "done" requires from D&B (product/entitlement)

The code (`functions/license/{master,renew,review}.js`) calls exactly two
D&B Direct+ endpoints:

| Call | Endpoint | Purpose |
|---|---|---|
| OAuth token | `POST https://plus.dnb.com/v3/token` (client-credentials grant) | Exchange `DNB_CLIENT_ID`/`DNB_CLIENT_SECRET` for a bearer token. |
| Entity lookup | `GET https://plus.dnb.com/v1/data/duns/{duns}?blockIDs=companyinfo_L1_v1` | Resolve a 9-digit DUNS to `organization.primaryName` + `organization.primaryAddress.addressCountry.isoAlpha2Code`. |

**Operator must procure:**
1. A **D&B Direct+ account/contract** (Dun & Bradstreet API Direct+ — this is a
   paid, contracted product; provisioning is external and can take weeks per
   `docs/gap/enterprise-gaps.md` §1.2).
2. Entitlement to the **`companyinfo_L1_v1` Data Block** (Company Information,
   Level 1) at minimum — this is the cheapest block that returns
   `primaryName` + `primaryAddress`. No other block is fetched by the current
   code; do not over-procure principals/officers blocks — the design (`review.js`
   header, §"CRITICAL PRIVACY RULE") deliberately does NOT fetch principal/officer
   PII by default (that would be third-party PII outside the person→entity
   binder's minimal-data mandate).
3. **API credentials** in one of two shapes the code already supports:
   - OAuth2 client-credentials: a `DNB_CLIENT_ID` + `DNB_CLIENT_SECRET` pair, or
   - A pre-issued static bearer: `DNB_BEARER` (skips the token exchange; useful
     for short-lived test tokens D&B may issue during trial/sandbox).

Nothing else is required for the current scope. Liveness/IDV (LoA-3 "full IDV
pass") is a **separate, not-yet-integrated external provider** — out of this
bucket's scope; do not conflate it with D&B Direct+.

## 2. Exact secrets to set

Deploy target is **`bp-wt-site`** (Cloudflare Pages project), NOT this repo —
`bloch-protocol`'s `functions/license/*.js` files are staged copies (see the
"DEPLOY TARGET" header comment in each file); they must be copied verbatim to
`bp-wt-site/functions/license/`. **`review.js` is currently ABSENT from
`bp-wt-site`** (`docs/gap/enterprise-gaps.md` §4.2) — deploying it is a
cross-repo action outside this repo and outside Bucket D's file ownership
(flagged, not performed here).

Set as **Cloudflare Pages secrets** on the `bp-wt-site` deployment (`wrangler
pages secret put <NAME>` or the dashboard):

| Secret | Required? | Effect |
|---|---|---|
| `DNB_CLIENT_ID` + `DNB_CLIENT_SECRET` | one of these two rows | OAuth2 client-credentials path. |
| `DNB_BEARER` | *or* this | Static bearer, skips token exchange. |
| `KYC_MODE=enforce` (or `GRAMOTA_KYC=enforce`) | to make LoA matter | Without it, `kycGate` always returns `decision:"pass"`, `loa:0`, `enforced:false` — today's self-declared parity, **no regression, no elevation**. This is the switch that turns D&B verification + LoA from "computed but advisory" into "gating." |
| `VENDOR_PRIV_PKCS8_B64` | already required for `master.js` (Bucket-C/deploy-config territory) | Unrelated to D&B but co-required for the full issuance path to complete. |

None of these are set anywhere in this repo (by design — they are operator
secrets, never committed). Unset today ⇒ every `verifyDunsWithDnB` call
short-circuits to `{status:"unavailable", reason:"dnb-not-configured"}` before
any network call is attempted.

## 3. End-to-end verification path, once creds are set

This is the sequence the operator runs against the **live** `bp-wt-site`
deployment after secrets are set and `review.js` is deployed. Every step below
is currently exercised ONLY against mocks in this repo's test suite (§ see
PARTITION.md D1) — this section is the "what to do when real creds land," not
a claim that it has been done.

1. **Entity resolve (no PII, sanity check the account works):**
   ```
   POST /license/review
   { "duns": "<a real 9-digit test DUNS>", "resolve": true }
   ```
   Success signal: HTTP 200 with `dnb.verified === true`, `dnb.source ===
   "dnb-direct-plus"`, and a non-empty `dnb.legalName`. A `dnb-not-configured`
   or `dnb-auth-http-*` reason in a 422/`unavailable` path means creds are
   still wrong/absent — the wiring falls back to `format-only`, not an error,
   by design (fail-open on outage, never a hard 5xx).

2. **Full KYC verdict (drives LoA):**
   ```
   POST /license/review
   { "duns": "<duns>", "role": "owner", "attestation": true,
     "kyc": { "ocr": { "onDevice": true, "match": true,
                        "fieldsMatched": ["legalName","country"], "liveness": false } } }
   ```
   Success signal: HTTP 200, `decision !== "refuse"`, `loa >= 1` (with
   `corpDomain` or matched OCR evidence supplied — LoA-0 self-declared-only
   never elevates), a `ref` is returned, and the verdict is persisted under KV
   key `kyc:<ref>`. `dnb.verified === true` confirms the LoA computation used a
   REAL D&B answer, not the `format-only` fallback.

3. **License issuance binds the verdict:**
   ```
   POST /license/master
   { "duns": "<duns>", "role": "owner", "attestation": true, "kyc_ref": "<ref from step 2>" }
   ```
   Success signal: HTTP 200 with an issued token whose `dnb.verified === true`
   and whose bound KYC block shows `loa >= 1` — **not** the parity default
   (`loa:0`, `dnb.source:"format-only"`). This is the observable proof that
   real D&B verification elevated LoA into the signed, offline-verifiable
   token.

4. **Fail-closed check (must also be run — a negative control):** repeat step 1
   with a DUNS known NOT to resolve (or a syntactically valid but unassigned
   9-digit number). Success signal: HTTP 422, `dnb.verified === false`,
   `reason: "dnb-duns-not-found"`, and (with `KYC_MODE=enforce`) any issuance
   attempt against that DUNS is refused, not silently downgraded.

**The one observable, unambiguous "it's real now" signal across all of the
above:** `dnb.source` flips from `"format-only"` to `"dnb-direct-plus"` AND
`dnb.verified` flips from `false`/absent to `true` on a known-good DUNS. Until
an operator reports that flip from a live deployment, every claim in this
repo about D&B verification is **"code correct against mocks; requires
operator D&B credentials to go live."** Label it that way everywhere.

## 4. What is explicitly OUT of scope here

- No real D&B API call is made anywhere in Bucket D's work product.
- Deploying `review.js` to `bp-wt-site` and setting the Pages secrets are
  operator/deploy actions, not code Bucket D writes or runs.
- LoA-3 (full IDV) needs a third external identity-verification provider —
  not D&B, not in scope.
- CRL/revocation, `master.js`/`renew.js` overall ownership, and deploy config
  belong to **Bucket C** — Bucket D touches only the D&B/DUNS/LoA logic seam
  inside those files (see PARTITION.md for the exact line-level split).
