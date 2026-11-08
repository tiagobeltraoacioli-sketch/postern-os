<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- BUCKET C PMO — honest remaining-work list -->

# REMAINING — Bucket C

Read this alongside the dispatch summary: **most of Bucket C shipped this
session.** Live + verified already: `/v1/crl` 404→200 on `postern-cloud-demo`
(real `node:22` digest, merged to `main` via MR !19); Cloudflare Pages
`review.js` + refresh functions + `ezekiel1.wasm` (404 cured) + `gramota`
published; the keypair-consistency gate (Pages `VENDOR_PRIV_PKCS8_B64` ↔ Fly
`VENDOR_PUBLIC_KEY`) is real and I independently re-proved it live this pass
(see `SIGNED-CRL-FLOW.md`). None of that is re-claimed as new below — this
file is only the tail.

## 1. `/gramota` bare-URL redirect — CODE-READY

**Confirmed live, this session:** `https://posternlabs.com/gramota` returns
`200` with the **site homepage** (`<title>Postern Labs — privacy & security
products...`), not the Gramota app and not a redirect. The canonical location
`https://posternlabs.com/apps/gramota/` also returns `200`, correctly, with
`<title>Gramota — enterprise onboarding · Postern Labs</title>`. There is no
internal link to bare `/gramota` anywhere in `site/` or `apps/` (checked by
grep) — this is a clean-URL / external-reference gap, not a broken in-site
link, but it's a real gap: anyone who types or is told the short URL lands on
the wrong page with a `200`, so nothing downstream even notices to fall back.

**Fix (one line, verified against the file's existing format):**
`bp-wt-site/site/static/_redirects` is the tracked source
(`assemble-public.sh` does `cp -R site/static/. public/`, and `public/` itself
is gitignored/generated — confirmed via `.gitignore` and `git check-ignore
-v`). Add, in the same `<source> <destination> <status>` format as the
existing rules:
```
/gramota    /apps/gramota/   301
```
This file is currently **clean** (no uncommitted changes) — a safe, isolated
edit. Code-ready for Dev C1; no secret, no deploy needed to write the change
(deploy is a separate operator step, out of Dev C1's rails).

## 2. Committing the live bp-wt-site working-tree changes — OPERATOR ACTION, cross-bucket

**Not Bucket C's alone to commit.** `git status` in `bp-wt-site` right now
shows a large uncommitted diff spanning multiple buckets' work this session:
`apps/ezekiel1/index.html` (+539), `explorer/*.html`, `site/build.js`,
`site/index.html`/`products.html`/`downloads.html`/etc., re-encoded media
files, plus new untracked directories (`apps/gramota/`,
`apps/enterprise-ux-proto/`, `apps/mobile-wallet/`, `apps/_design-system/`,
`site/docs-src/`, `site/media-src/`). **Bucket C's own slice** of that diff is:

| File | State | Note |
|---|---|---|
| `functions/license/master.js` | modified, +67/-1 | uncommitted D&B/KYC-binding additions on top of already-committed base |
| `functions/license/renew.js` | modified, +54 | same |
| `functions/license/review.js` | new, untracked | byte-identical to the staged copy on `roadmap/fleet2-integrate` (`enterprise/licensing/site-functions/license/review.js`) — confirmed via diff, 0 lines differ |
| `functions/license/status.js` | **already committed** (`464f81c`) | not part of the pending commit — already landed, already live |

Because the working tree is shared across buckets, a commit here is a
cross-bucket, operator/PM-level call — Dev C1 should **not** unilaterally
`git add`/`git commit` files outside Bucket C's three license files, and
should not commit at all per this bucket's rails (no git commit). Flagging it
here so the PM can either commit the whole tree in one coordinated pass or ask
each bucket to stage only its own files.

## 3. Deploy-config polish — FYI, non-blocking

- `enterprise/cloud/image/fly.toml` sets `ALLOWED_ORIGIN = "*"` in the plain
  `[env]` block (not a secret), explicitly commented `# demo only: allow the
  public posture/health/crl endpoints to be read cross-origin`. The service
  itself logs a warning at boot when this is set
  (`license-service.mjs`: `if (ORIGIN.wildcard) logLine("WARNING:
  ALLOWED_ORIGIN='*' was set explicitly; scope it to your client origin
  before deployment.")`). This is disclosed and intentional for the current
  staging/demo posture, not a silent gap — noted here only so it's not
  forgotten if `postern-cloud-demo` is ever promoted past demo status. No
  action recommended right now; not part of this bucket's blocking tail.

## The genuine operator-secret tail (see `OPERATOR-SECRETS-RUNBOOK.md` for commands)

| Item | Code-ready? | Operator action needed? |
|---|---|---|
| `LICENSE_ADMIN_TOKEN` (Pages) | Yes — code path tested live (501 today, code proven correct) | Yes — set the secret |
| `ADMIN_TOKEN` (Fly) | Yes — locally executed against the real handler, all paths pass | Yes — set the secret |
| Publishing a signed CRL to Fly | Yes, end-to-end proven (see `SIGNED-CRL-FLOW.md`) | Yes — needs both secrets above, then one `curl`/script run |
| `KYC_MODE=enforce` | Yes, optional | Operator decision, not required |
| `DNB_CLIENT_ID`/`DNB_CLIENT_SECRET`/`DNB_BEARER` | Owned by Bucket D | Bucket D's runbook, not this one |
| `/gramota` redirect | Yes (§1 above) | No secret — just needs the one-line edit + normal deploy |
| Working-tree commit | N/A | Cross-bucket operator/PM call (§2 above) |

## What is explicitly NOT a remaining item (do not re-open)

- The `/v1/crl` 404→200 fix on `postern-cloud-demo` — live, MR !19, merged to
  `main`.
- The keypair-consistency gate — proven this session AND re-proven
  independently by me this pass (live curl + local execution, see
  `SIGNED-CRL-FLOW.md`).
- `review.js`, the refresh functions, `ezekiel1.wasm`, `gramota` publish —
  already live on the deployed site (confirmed: `/apps/gramota/` returns 200
  with the correct app).
- `functions/license/status.js` itself — already committed (`464f81c`),
  already live, already correctly signing CRLs today (proven live this pass).
