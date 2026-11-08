<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- BUCKET C PMO — operator secrets runbook (deploy + operator secrets) -->

# OPERATOR-SECRETS-RUNBOOK — Bucket C

**Status as of this session, verified live** (not claimed from memory — every
line below was checked with `wrangler pages secret list`, `fly secrets list`,
and live `curl` against `posternlabs.com` / `postern-cloud-demo.fly.dev` during
this pass):

| Secret | Platform / target | State |
|---|---|---|
| `VENDOR_PRIV_PKCS8_B64` | Cloudflare Pages, project `posternlabs` | **SET** (already was — not new this session) |
| `VENDOR_PUBLIC_KEY` | Fly, app `postern-cloud-demo` | **SET** (already was — not new this session) |
| `LICENSE_ADMIN_TOKEN` | Cloudflare Pages, project `posternlabs` | **UNSET** — operator action needed |
| `ADMIN_TOKEN` | Fly, app `postern-cloud-demo` | **UNSET** — operator action needed |
| `KYC_MODE` | Cloudflare Pages, project `posternlabs` | **UNSET** (optional; default = today's parity, no regression) |
| `DNB_CLIENT_ID` / `DNB_CLIENT_SECRET` / `DNB_BEARER` | Cloudflare Pages, project `posternlabs` | **UNSET** — owned by Bucket D, listed here only for completeness |

**Important naming correction to carry forward:** `LICENSE_ADMIN_TOKEN` and
`ADMIN_TOKEN` are **two different secrets on two different platforms**, gating
two different endpoints. `LICENSE_ADMIN_TOKEN` gates `POST /license/status` on
Cloudflare Pages. `ADMIN_TOKEN` gates `POST /v1/crl` (and `POST
/v1/revocations`) on the Fly hosted verifier. Setting one does **not** set or
affect the other. Both are required to complete the full sign → publish
pipeline (see `SIGNED-CRL-FLOW.md`).

I confirmed the vendor keypair match live, independently of the earlier
session's claim: `fly secrets list -a postern-cloud-demo` shows
`VENDOR_PUBLIC_KEY` deployed; `GET https://postern-cloud-demo.fly.dev/v1/vendor-key`
returns fingerprint `fab36e2acbe1810e`; `GET https://posternlabs.com/license/status`
returns a signed CRL with `kid: "fab36e2acbe1810e"` — same fingerprint,
computed two different ways on two different platforms. I then took that live
CRL and verified its signature with the official `@postern/licensing`
`crl-verify` CLI (built from `enterprise/licensing/src` on
`roadmap/fleet2-integrate`) against the known vendor public key
(`iW52PuhJm0+JE+g5UhfrArJ7ONfuUjrm0C38NSwQGm0=`) — result `{"ok":true}`. The
keypair-consistency claim holds.

---

## 1. `LICENSE_ADMIN_TOKEN` (Cloudflare Pages, project `posternlabs`)

**Unlocks:** `POST /license/status` — add a `jti` (token serial) and/or
`master_pub` (whole org) to the revoked set, persisted to KV (`env.LICENSES`
key `crl:state`), monotonic `version` bump on each real change.

**Currently (live, confirmed this session):**
```
$ curl -s -X POST https://posternlabs.com/license/status -d '{}' -H 'content-type: application/json'
{"error":"revocation writes are disabled (LICENSE_ADMIN_TOKEN unset)"}
```

**Set it:**
```bash
cd bp-wt-site   # source tree for the deployed "posternlabs" Pages project
npx wrangler pages secret put LICENSE_ADMIN_TOKEN --project-name posternlabs
# paste a strong random token when prompted; generate one with:
openssl rand -hex 32
```
Pages secrets apply to Functions at the next request — no rebuild/redeploy of
the site is required for this alone.

**Verify it worked:**
```bash
# a) the secret is now listed (name only — wrangler never prints values):
npx wrangler pages secret list --project-name posternlabs
#   expect LICENSE_ADMIN_TOKEN: Value Encrypted, alongside VENDOR_PRIV_PKCS8_B64

# b) unauthenticated POST now 401s instead of 501ing — proves it's configured:
curl -s -X POST https://posternlabs.com/license/status -d '{}' -H 'content-type: application/json'
#   expect {"error":"admin bearer token required"}

# c) publish a real revocation:
curl -s -X POST https://posternlabs.com/license/status \
  -H "authorization: Bearer <LICENSE_ADMIN_TOKEN>" \
  -H "content-type: application/json" \
  -d '{"jti":"<hex jti to revoke>","reason":"operator test revocation"}'
#   expect {"ok":true,"version":1,"added":{"jti":"..."},"counts":{...}}

# d) confirm GET now reflects it:
curl -s https://posternlabs.com/license/status | python3 -c "import json,sys; print(json.load(sys.stdin)['crl']['payload'])"
#   expect version:1, revoked_jti includes your jti
```
See `SIGNED-CRL-FLOW.md` for the full offline-verify command against this CRL.

---

## 2. `ADMIN_TOKEN` (Fly, app `postern-cloud-demo`) — not the same secret as #1

**Unlocks:** `POST /v1/crl` — publish a vendor-signed CRL to the hosted
verifier (this is the step that activates enforcement for anyone who checks in
against the hosted service). Also gates `POST /v1/revocations` (the unsigned
staging working-set).

**Currently (live, confirmed this session):**
```
$ curl -s -X POST https://postern-cloud-demo.fly.dev/v1/crl -d '{}' -H 'content-type: application/json'
{"error":{"type":"admin_unconfigured","message":"Revocation writes are disabled (ADMIN_TOKEN unset)."}}
```

**Set it:**
```bash
fly secrets set ADMIN_TOKEN="$(openssl rand -hex 32)" -a postern-cloud-demo
```
`fly secrets set` triggers an automatic machine restart with the new secret —
no separate `fly deploy` is needed (this is the same mechanism that already
applied `VENDOR_PUBLIC_KEY`, which shows as `Deployed`).

**Verify it worked:**
```bash
fly secrets list -a postern-cloud-demo
#   expect ADMIN_TOKEN alongside VENDOR_PUBLIC_KEY

curl -s -X POST https://postern-cloud-demo.fly.dev/v1/crl -d '{}' -H 'content-type: application/json'
#   expect 401 {"error":{"type":"unauthorized","message":"Admin bearer token required."}}
#   (was 501 admin_unconfigured before — now it demands the token instead)
```
Setting `ADMIN_TOKEN` alone does **not** publish a CRL — it only unlocks the
door. See `SIGNED-CRL-FLOW.md` step 3 for the actual publish command, which
needs a signed CRL body produced on the Pages side (secret #1) or via the
`postern-license crl-build` CLI.

---

## 3. `KYC_MODE=enforce` (optional, Cloudflare Pages, project `posternlabs`)

**Unlocks:** caps a self-declared LoA-0 owner/manager verdict at
`"provisional"` instead of `"pass"` in `/license/review`'s `kycGate`. **Default
(unset) = today's self-declared parity — issuance behaves exactly as before,
no regression.** This is a policy tightening, not a bug fix; treat it as a
deliberate operator decision, not something to flip reflexively.

**Set it:**
```bash
npx wrangler pages secret put KYC_MODE --project-name posternlabs
# value: enforce
```

**Verify it worked:**
```bash
curl -s -X POST https://posternlabs.com/license/review \
  -H 'content-type: application/json' \
  -d '{"duns":"<9-digit DUNS>","role":"owner","attestation":true}'
# unset:            {"decision":"pass", "enforced":false, "loa":0, ...}
# KYC_MODE=enforce, no corroborating signal (no ocr/domain/idv):
#                    {"decision":"provisional", "enforced":true, "loa":0, ...}
```

---

## 4. `DNB_CLIENT_ID` + `DNB_CLIENT_SECRET` (or `DNB_BEARER`) — hand-off to Bucket D

These gate real Dun & Bradstreet Direct+ verification in `master.js` /
`renew.js` / `review.js`. **Bucket C does not own D&B correctness** —
`docs/bucketD/RUNBOOK.md` and `docs/bucketD/ADVISORS-CHARTER.md` (D&B client
correctness, OAuth handling, timeout/fail-closed matrix, fixture fidelity) are
the authoritative source. Listed here only so this LoA/secrets table is
complete for the operator sitting down to configure everything at once:

```bash
npx wrangler pages secret put DNB_CLIENT_ID --project-name posternlabs
npx wrangler pages secret put DNB_CLIENT_SECRET --project-name posternlabs
# — or, instead of the client-credentials pair —
npx wrangler pages secret put DNB_BEARER --project-name posternlabs
```

Smoke check only (Bucket D verifies mapping correctness, not this doc):
```bash
curl -s -X POST https://posternlabs.com/license/master \
  -H 'content-type: application/json' \
  -d '{"tier":"corporate-master","duns":"<a real 9-digit DUNS>","role":"owner","attestation":true}'
# once creds are correctly configured: dnb.verified:true, dnb.source:"dnb-direct-plus"
```

---

## LoA table (person → entity KYC assurance, `/license/review` `kycGate`)

| LoA | Label | Requires | Under `KYC_MODE=enforce` |
|---|---|---|---|
| 0 | self-declared | attestation checkbox only (today's default path) | capped to `"provisional"` if nothing else is present |
| 1 | domain-verified | LoA-0 + corporate-domain proof | `"pass"` |
| 2 | higher-assurance | LoA-1 + (D&B principal match **or** on-device OCR field match) | `"pass"` |
| 3 | top-assurance | (on-device OCR match + liveness) **or** a full IDV pass | `"pass"` |

Fail-closed property (unaffected by whether `DNB_*` is configured): D&B entity
verification alone — "this DUNS is a real company" — **never** by itself lifts
LoA above 0. Entity-is-real is not person-has-authority. This is enforced in
`computeLoa()` (`functions/license/review.js`) and is Bucket D's to re-verify
in depth; Bucket C only confirms the gate exists and is wired into `master.js`
/ `renew.js` via `resolveKyc()` / `boundKycFrom()`.

## Rails observed while writing this runbook

No secret was set. No deploy was triggered. Every "currently" line above is a
live `curl`/`wrangler`/`fly` read run during this session, not a claim carried
over from memory. Command outputs quoted verbatim.
