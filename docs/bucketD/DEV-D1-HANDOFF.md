<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- BUCKET D — Dev D1 implementation log + Bucket C hand-off. Additive per
     PARTITION.md ("Dev D1 may append an implementation log/notes section but
     not rewrite the READINESS verdict"). -->

# Dev D1 implementation log + Bucket C hand-off

Branch: `bucketD/dnb-client`. Base: `roadmap/fleet2-integrate` @ `93b1ee9`.

## What landed (owned files)

- `functions/license/review.js` — F2 (request timeout) fixed directly; F1
  (LoA-model divergence) comment corrected + reconciliation added.
- `apps/gramota-kyc/kyc-loa.mjs` — F1 reconciliation: added `evidenceToLoa`
  (+ `ocrEvidenceValidated`), a structural mirror of `review.js`'s
  `computeLoa`/`ocrValidated`, plus a corrected header comment. The existing
  `selfDeclare`/`corpEmailProof`/`ocrMatch`/`idv`/`maxLoa` UI-preview ladder is
  UNCHANGED (its behavior is byte-compatible with the inline copy in
  `apps/gramota/index.html` and asserted by `self-check.mjs` /
  `inline-parity-check.mjs`, both out of Bucket D's file ownership — changing
  it would have required touching those out-of-scope files).
- `apps/gramota-kyc/dnb-client.test.mjs` (new) — the 13-point matrix +
  cross-file parity + F1 equivalence test. 36/36 passing.
- `apps/gramota-kyc/fixtures/dnb/*.json` (new, 8 files) — SYNTHETIC D&B
  Direct+ response shapes, each carrying a `_synthetic` header field.

## Finding F2 — request timeout (fixed in review.js; hunks below for Bucket C)

Root cause: neither `fetch` call in any of the three `verifyDunsWithDnB`
copies used `AbortController`. `review.js` now bounds both the token exchange
and the data lookup with an `AbortController` timeout (`env.DNB_TIMEOUT_MS`,
default 8000ms). An abort (or any error whose `name === "AbortError"` /
message matches `/abort/i`) maps to `{status:"unavailable",
reason:"dnb-timeout"}` — the SAME fail-open-to-format-only treatment as any
other D&B outage, never confused with `"not-found"`.

`master.js` and `renew.js` carry byte-near-identical duplicate copies of this
function (Bucket C's files — Dev D1 does not edit them directly, per
PARTITION.md §2). The equivalent fix, generated and **functionally verified**
against extracted copies of both files before hand-off (happy-path fixture +
a 30ms-timeout hanging-fetch check, both passed — see the verification
transcript at the bottom of this doc), is attached as unified diffs:

- `docs/bucketD/master.js.dnb-timeout.patch`
- `docs/bucketD/renew.js.dnb-timeout.patch`

Both were checked with `git apply --check` against this branch's current
`functions/license/{master,renew}.js` and applied cleanly (no rebase
conflicts as of `93b1ee9`). Apply with:

```
git apply docs/bucketD/master.js.dnb-timeout.patch
git apply docs/bucketD/renew.js.dnb-timeout.patch
```

**Cross-file audit note:** other than formatting (master.js's verbose
multi-line style vs. renew.js's/review.js's original compact style), no
behavioral drift was found between the three pre-existing copies — same
`DNB_AUTH_URL`/`DNB_DATA_URL`, same status/reason mapping, same fail-closed
`not-found` vs. fail-open `unavailable` split. `apps/gramota-kyc/dnb-client.
test.mjs`'s point-11 tests assert this equivalence on the non-timeout paths
(auth failure, malformed body, not-found, network error) across all three
copies directly (master.js's exports are imported; renew.js's are NOT
exported, so the test extracts and invokes its source directly via the same
brace-matching technique already used by `self-check.mjs` /
`inline-parity-check.mjs` in this repo — real coverage, not just a documented
byte-diff). The suite deliberately does NOT assert timeout-equivalence today,
since master.js/renew.js don't have the fix yet — that would be a false
green; re-run the suite after applying the hunks above to confirm parity end
to end.

## Finding F1 — LoA-model divergence

PARTITION.md §4 recommended (a) (comment-only fix, since the server verdict
is authoritative and bound by reference so the client ladder is never
load-bearing) but the dispatch instructions to Dev D1 required going further:
"genuinely one model (shared logic or a tested equivalence), not just a
comment claiming parity."

Constraint discovered during implementation: `review.js` is deliberately
self-contained (no imports — it is copied verbatim to a separate deploy
repo), so a literal shared import between it and `kyc-loa.mjs` is not
possible. Separately, `kyc-loa.mjs`'s existing `ocrMatch` (loa:2 on a full
OCR match with no corp-domain precondition) is byte-compatible with an
inlined copy in `apps/gramota/index.html` and is asserted verbatim by
`self-check.mjs` and `inline-parity-check.mjs` — both outside Bucket D's file
ownership. Changing `ocrMatch`'s gating to match the server's precondition
(corp-domain required before OCR can lift LoA to 2) would have broken those
out-of-scope files and tests.

Resolution actually shipped: additive, not a rewrite of the existing ladder.
`kyc-loa.mjs` now also exports `evidenceToLoa` (+ `ocrEvidenceValidated`), a
structural mirror of `review.js`'s `computeLoa`/`ocrValidated` — same
evidence field names, same branch order, same rung-gating invariants
(corp-domain required before OCR/principal-match can reach LoA 2; LoA 3 needs
OCR+liveness or a full IDV pass). `dnb-client.test.mjs`'s F1 section runs an
exhaustive matrix (>300 evidence combinations) through both `computeLoa` and
`evidenceToLoa` and asserts identical output — a real tested equivalence, not
a comment. If a future change to `review.js`'s `computeLoa` is not mirrored
into `kyc-loa.mjs`, that test fails.

Both files' header comments were corrected to state this honestly: the
UI-facing `selfDeclare/corpEmailProof/ocrMatch/idv` ladder is an
intentionally coarser, differently-shaped on-device PREVIEW (never
authoritative — the server recomputes and binds the real verdict by
reference), while `evidenceToLoa` is the genuine, tested-equivalent mirror.
Advisor D1 should confirm this hybrid resolution (correct the overclaim +
add a tested-equivalent function, rather than either pure option (a) or a
breaking rewrite under option (b)) is sound.

## Verification transcript (fixed master.js/renew.js copies, pre-hand-off)

```
master.fixed.js happy path: {"status":"verified","legalName":"Acme Widgets LLC","country":"US"}
master.fixed.js timeout path: {"status":"unavailable","reason":"dnb-timeout"} elapsed(ms)= 32
renew.fixed.js happy path: {"status":"verified","legalName":"Acme Widgets LLC","country":"US"}
renew.fixed.js timeout path: {"status":"unavailable","reason":"dnb-timeout"} elapsed(ms)= 31

ALL FIXED-COPY CHECKS PASSED
```

## Test results (HOST, this branch, this commit)

```
node apps/gramota-kyc/dnb-client.test.mjs   -> 36 passed
node apps/gramota-kyc/review-seam.test.mjs  -> 9 passed   (kept green, per rails)
node apps/gramota-kyc/self-check.mjs        -> 21 passed, 0 failed (unchanged, verified still green)
node apps/gramota-kyc/inline-parity-check.mjs -> 14 passed, 0 failed (unchanged, verified still green)
bash scripts/check-trust-labels.sh          -> critical: 0, warn: 1 (pre-existing, unrelated to Bucket D's files)
```

Every fixture in `apps/gramota-kyc/fixtures/dnb/*.json` carries a
`_synthetic` header field; the test loader (`fx()` in `dnb-client.test.mjs`)
asserts its presence on every load, failing the suite if a fixture is ever
added without the label.
