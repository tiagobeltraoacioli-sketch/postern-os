<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- BUCKET C PMO — 1-dev + 1-advisor charter -->

# DEV-ADVISOR-CHARTER — Bucket C (1 dev, 1 advisor)

Read `REMAINING.md` first — most of Bucket C is already done this session.
This charter is scoped to the small tail only. Rails for both roles: **no
deploy, no git commit, no setting secrets, no touching `bp-wt-fleet2` or any
other agent's worktree.**

## Dev C1 — code-side remainders (HOST-testable only, no secrets, no deploy)

**Scope:** `bp-wt-site/site/static/_redirects`; a new helper script (location
below); optionally closing any verify-hook gap found during the work. Nothing
else — do not touch the other buckets' uncommitted files in `bp-wt-site` (see
`REMAINING.md` §2; that working tree is shared and committing/staging it is
not this role's call).

### Task 1 — `/gramota` → `/apps/gramota/` redirect

Add to `bp-wt-site/site/static/_redirects` (currently clean — no uncommitted
changes, safe to edit in isolation), matching the file's existing `<source>
<destination> <status>` format:
```
/gramota    /apps/gramota/   301
```
Place it near the other single-path rules (`/pool`, `/pool.html`) at the
bottom of the file, not among the wildcard `www` rules at the top.

**HOST-testable verification (no deploy needed):** Cloudflare Pages
`_redirects` has no first-party local simulator in this repo, so the
practical host-test is: (a) confirm the line matches the documented Pages
`_redirects` grammar exactly (three whitespace-separated fields, valid status
code); (b) run `bash assemble-public.sh` locally and confirm
`public/_redirects` now contains the new line (the script does `cp -R
site/static/. public/`); (c) do NOT deploy to confirm it fires in production —
that's an operator step. State clearly in your handoff that live-fire
confirmation (`curl -I https://posternlabs.com/gramota` returning `301` to
`/apps/gramota/`) is deferred to the operator's next deploy.

### Task 2 — signed-CRL publish helper script (operator runs it; you do not)

`SIGNED-CRL-FLOW.md` §"Operator activation sequence" is currently five manual
`curl` steps. Wrap steps 3–5 (pull the signed CRL from Pages, POST it to Fly,
confirm) into a single script the operator can run once both secrets are set.
Suggested location: `enterprise/cloud/image/publish-crl.sh`, following the
existing pattern of `enterprise/cloud/image/smoke-test.sh` (bash, `set -euo
pipefail`, clear `die()`/`ok()` helpers, no embedded secrets — reads
`ADMIN_TOKEN` from the environment, never a literal). Sketch:
```bash
#!/usr/bin/env bash
# publish-crl.sh — pull the current vendor-signed CRL from the Pages site and
# publish it to the Fly hosted verifier. Needs $ADMIN_TOKEN (Fly) in the
# environment; never hardcode it. Optionally $SITE_HOST / $FLY_HOST overrides.
set -euo pipefail
SITE="${SITE_HOST:-https://posternlabs.com}"
FLY="${FLY_HOST:-https://postern-cloud-demo.fly.dev}"
: "${ADMIN_TOKEN:?set ADMIN_TOKEN in the environment first}"
crl_json=$(curl -sf "$SITE/license/status" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["crl"]))')
resp=$(curl -sf -X POST "$FLY/v1/crl" -H "authorization: Bearer $ADMIN_TOKEN" -H "content-type: application/json" --data-binary "$crl_json")
echo "$resp"
echo "$resp" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d.get("ok") is True, d; print(f"published v{d[\"version\"]}")'
```
Do not run this against production with a real `ADMIN_TOKEN` — you don't have
one (rails: no secrets). **HOST-testable verification:** run it against the
local synthetic-key server harness described in `SIGNED-CRL-FLOW.md`'s
"verified by EXECUTION" section (regenerate that scratch setup — export
`enterprise/cloud/image/vendor/services/src/license-service.mjs` and run it
locally with a test keypair and a test `ADMIN_TOKEN`), confirmed against a
locally-running fake "Pages" endpoint (a two-line Node http server that serves
a `crl-build`-produced signed CRL) — or, simpler, `--data-binary` a
`crl-build`-produced file directly and skip the `curl "$SITE/..."` leg in the
test, documenting that substitution. Either way: prove the script's Fly-side
`curl` call actually round-trips against the real (locally-run) handler code,
not just that the bash syntax parses.

### Task 3 — verify-hook gap check

While doing Task 2, if you find any place the code *should* re-verify a
signature or version and silently doesn't (e.g. a client that reads
`publishedCrl` without ever having called `verifySignedToken` on it — it
doesn't, checked this session, but re-check as you go), file it as a finding
rather than silently patching production-facing verification logic outside
this charter's scope. `functions/license/*.js` and
`enterprise/licensing/src/*.ts` are Bucket C-adjacent but shared with other
buckets (D owns DNB correctness in `review.js`); don't rewrite logic you don't
need to for Tasks 1–2.

### Handoff

A short note: what you changed (file:line), how you host-tested each item,
and an explicit list of what is deferred to the operator (deploy, secret
values, live-fire confirmation). No secrets in the handoff, no committed
changes — leave the working tree as diffs for the operator/PM to review and
commit.

---

## Advisor C1 — signed-CRL flow correctness + honesty audit

**Reviews:** `SIGNED-CRL-FLOW.md`, `OPERATOR-SECRETS-RUNBOOK.md`,
`REMAINING.md` (this bucket's own docs — re-derive, don't rubber-stamp), plus
Dev C1's diff once it lands (`site/static/_redirects`,
`enterprise/cloud/image/publish-crl.sh` or wherever Dev C1 places it).

### A. Correctness

1. **Re-run the live checks yourself**, don't trust this doc's pasted output:
   `curl https://posternlabs.com/license/status`, `curl -X POST
   https://posternlabs.com/license/status -d '{}'`,  `curl -X POST
   https://postern-cloud-demo.fly.dev/v1/crl -d '{}'`, `fly secrets list -a
   postern-cloud-demo`, `npx wrangler pages secret list --project-name
   posternlabs` (from `bp-wt-site`). Confirm the current state matches what's
   documented (secrets still unset, endpoints still return the documented
   401/501 shapes) — if the operator has since set either secret, the
   "currently" sections in both docs need updating, not left stale.
2. **Independently re-verify the keypair-consistency claim.** Don't just read
   that I did it — fetch `GET /v1/vendor-key` from Fly and `GET
   /license/status` from Pages yourself, confirm the fingerprint/`kid` match,
   and separately re-run (or re-derive) a signature check of the live CRL
   against the vendor public key `iW52PuhJm0+JE+g5UhfrArJ7ONfuUjrm0C38NSwQGm0=`
   (build `@postern/licensing` from `roadmap/fleet2-integrate` in your own
   scratch dir; do not modify any worktree). If it doesn't verify, this is a
   BLOCKING finding — the entire bucket's headline claim depends on it.
3. **Local-execution claim.** `SIGNED-CRL-FLOW.md` claims a standalone local
   run of `license-service.mjs` proved the publish path (auth/verify/anti-
   rollback/serve). Re-run it yourself against a fresh synthetic keypair (the
   file is zero-dependency; export it to your own scratch dir) rather than
   trusting the pasted transcript. Confirm each of the six assertions still
   holds, especially the 409 anti-rollback and 400 bad-signature cases — those
   are the two that would be easy to get subtly wrong (e.g. comparing
   `>=` instead of `>` on version, or verifying against the wrong payload).
4. **`_redirects` syntax.** Confirm Dev C1's line is valid Cloudflare Pages
   `_redirects` grammar (source/destination/status, no trailing splat
   mismatch) and doesn't shadow or get shadowed by an existing rule (order
   matters in `_redirects` — first match wins). Confirm it doesn't
   accidentally also catch `/gramota-something` (it shouldn't — exact-path
   rules don't prefix-match unless a `*` is present, but confirm rather than
   assume).
5. **Publish-helper script.** Confirm it never logs or echoes `ADMIN_TOKEN`,
   fails loudly (non-zero exit) on any `curl` failure (`-f` flag present) or a
   non-`ok:true` publish response, and that Dev C1's host-test actually
   exercised the real handler code (not just bash syntax-checked).

### B. Honesty

1. **No re-claimed work.** Read `REMAINING.md`'s "explicitly NOT a remaining
   item" section against the actual current state (§A.1 above) — confirm
   every item listed as already-done is still true, and that neither
   `OPERATOR-SECRETS-RUNBOOK.md` nor `SIGNED-CRL-FLOW.md` describes any of
   this session's *already-shipped* work (the `/v1/crl` 404 fix, `review.js`,
   `ezekiel1.wasm`, `gramota` publish, the keypair gate) as if it were newly
   done by Dev C1's tail work.
2. **No secret values anywhere.** Grep this bucket's docs and Dev C1's diff
   for anything that looks like a real token, key, or credential value (not
   just the literal env var names, which are expected and fine).
   `LICENSE_ADMIN_TOKEN`/`ADMIN_TOKEN`/`DNB_*` should appear only as names,
   `openssl rand -hex 32` placeholders, or `<...>` placeholders — never a
   concrete value.
3. **Operator-action vs code-ready labels.** Walk every table row in
   `REMAINING.md` and `OPERATOR-SECRETS-RUNBOOK.md` and confirm the
   code-ready/operator-action label is actually correct given what you
   re-verified in §A — e.g. if the redirect turns out to need a Pages rebuild
   step beyond what's described, that changes its label from "no deploy
   needed to write the change" and the doc should say so.
4. **Cross-bucket honesty on the working-tree commit item.** Confirm
   `REMAINING.md` §2's characterization of the shared `bp-wt-site` diff (file
   list, which lines are Bucket C's vs other buckets') is accurate as of your
   review — `git status`/`git diff --stat` yourself rather than trusting the
   pasted table, since other buckets may have landed more work since this was
   written.

### C. Deliverable

A short written finding set (blocking / non-blocking / honesty), each citing
the specific command you ran or file:line you read — not "the doc says X, so
X is true." Ends in one of: **APPROVE** (all live checks re-confirmed, no
re-claimed work, no code-incomplete surprises), **APPROVE WITH FOLLOW-UPS**
(non-blocking gaps noted, e.g. a doc going stale after the operator acts),
or **BLOCK** (the keypair claim fails independent re-verification, the local
publish-path execution doesn't reproduce, or a live/mock or done/pending
honesty violation is found). Advisor C1 does not approve deploy or credential
provisioning — those stay explicitly out of this bucket's rails.
