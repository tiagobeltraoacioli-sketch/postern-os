<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- BUCKET C PMO — signed-CRL flow: code-completeness verification -->

# SIGNED-CRL-FLOW — Bucket C

Question this doc answers: is `LICENSE_ADMIN_TOKEN → sign CRL → publish to Fly
→ offline install enforces` **code-complete and correct**, such that the only
thing standing between "not active" and "active" is the operator setting two
secrets? Answer: **yes**, verified below by inspection *and* by execution
(live curl against production + a standalone local run of the real Fly service
code against synthetic test keys — not just reading the source and trusting
comments).

## The four hops

```
[1] Cloudflare Pages: POST /license/status          (functions/license/status.js)
      admin: LICENSE_ADMIN_TOKEN
      writes KV "crl:state" {version, revoked_jti[], revoked_master_pub[]}
        │
        ▼
[2] Cloudflare Pages: GET /license/status            (functions/license/status.js)
      needs: VENDOR_PRIV_PKCS8_B64 (already set — proven live, see below)
      signs KV state fresh on every GET -> { crl: {payload, sig}, freshness }
        │
        ▼
[3] Fly: POST /v1/crl                                (enterprise/cloud/image/vendor/services/src/license-service.mjs)
      admin: ADMIN_TOKEN  (different secret, different platform — see runbook)
      VERIFIES the CRL sig against VENDOR_PUBLIC_KEY (already set — proven live)
      enforces monotonic version (anti-rollback, 409 on stale)
      stores it in `publishedCrl`, served verbatim at GET /v1/crl
        │
        ▼
[4] Offline install / hosted /v1/verify / shipping browser console
      fetches the CRL, verifies its signature against the vendor PUBLIC key it
      already trusts, applies checkRevocation() — cross-implementation proven
      (below) against the real shipping console.html verifier.
```

## What is ALREADY live and working right now (not blocked on anything)

Hop [2] is **not** gated by any missing secret — `VENDOR_PRIV_PKCS8_B64` was
already configured on the Pages project before this session. I fetched the
live endpoint and independently re-verified the signature:

```
$ curl -s https://posternlabs.com/license/status
{
  "crl": {
    "payload": {
      "v": 1, "typ": "crl", "iss": "posternlabs.com",
      "kid": "fab36e2acbe1810e", "version": 0,
      "issued_at": 1783954207, "next_update": 1784040607,
      "max_stale_secs": 1209600, "revoked_jti": [], "revoked_master_pub": []
    },
    "sig": "/aBDAUmeqqLoJ7jF+G7FPrjcr3E/BoeQBiigqYXbif4C9f62PJZl2nSFVXm2gq7DMOSy5jdOg0HMen+u6rkXDA=="
  },
  "freshness": "fresh", ...
}
```

I then built the real `@postern/licensing` library from
`enterprise/licensing/src` on `roadmap/fleet2-integrate` (in a scratch
directory, no repo touched) and ran its own `crl-verify` CLI against this
live-fetched CRL and the known vendor public key:

```
$ node dist/cli.js crl-verify --vendor-pub vendor-pub.json --crl live-crl.json
{ "ok": true, "freshness": { "fresh": true, "ageing": false, "stale": false, ... } }
```

**This proves, right now, independent of anything claimed earlier**: the CRL
signing path is live, correct, and cryptographically sound. `version: 0` and
empty revoked lists simply mean nothing has ever been revoked yet — that's
honest and expected, not a bug.

Hop [4]'s client-side enforcement is proven by
`enterprise/licensing/console-crl-enforce.test.mjs`, which extracts the
**actual shipping** `makePosternLicense(...)` verifier out of
`apps/postern-enterprise/console.html` (the exact bytes the browser runs) and
drives it against CRLs signed by the library's `buildCrl()` — same canonical
bytes, same vendor key, real cross-implementation proof, not a mock. Read the
file for the full assertion list (no-CRL-passthrough, clean-CRL-passthrough,
revoked-jti-blocks, revoked-master_pub-blocks-whole-org, stale-CRL-degrades).

## What I additionally verified by EXECUTION (not just reading), this session

Hop [3] (`POST /v1/crl` on the Fly service) had no existing automated test in
this repo covering the publish path specifically (`self-check.mjs` in
`enterprise/cloud/image/vendor/services/` covers other things; it does not
touch CRL publish). Rather than certify "code-complete" from reading alone, I
exported `enterprise/cloud/image/vendor/services/src/license-service.mjs`
(zero runtime dependencies — no npm install needed beyond Node itself) to a
scratch directory and ran the **actual, unmodified** `createServer()` /
`route()` handler locally against a freshly-generated **synthetic test**
Ed25519 keypair (never touches production keys or secrets):

```
  ok   pre-publish: GET /v1/crl is honest unsigned advisory (matches live prod state)
  ok   POST /v1/crl without bearer -> 401 (admin configured, auth required)
  ok   POST /v1/crl with admin bearer publishes v1
  ok   GET /v1/crl now serves the published SIGNED CRL (offline installs would fetch this)
  ok   stale (lower-version) CRL publish is rejected 409 (anti-rollback)
  ok   CRL with mismatched signature is rejected 400 (never trusts an unverified CRL)

ALL OK — publish-to-Fly path is code-complete.
```

This directly exercises: admin-bearer gating (`requireAdmin`), CRL signature
verification against the vendor public key (`verifySignedToken`), monotonic
version enforcement (`p.version <= publishedCrl.payload.version` → 409), and
that `GET /v1/crl` switches from the honest `unsigned_advisory` shape to the
real signed CRL once one is published. Every one of these matched the code's
documented behavior exactly; no discrepancy found.

## Code-complete verdict, hop by hop

| Hop | Code-complete? | Evidence |
|---|---|---|
| [1] POST /license/status revoke-write | Yes | live 501 confirms the gate exists; code path reads cleanly (KV write + version bump) |
| [2] GET /license/status sign | Yes — **and already active in production today** | live curl + independent `crl-verify` re-signature-check, `ok:true` |
| [3] POST /v1/crl publish | Yes | local execution of the real handler: auth, verify, anti-rollback, serve — all pass |
| [4] Offline/console enforcement | Yes | `console-crl-enforce.test.mjs` cross-implementation proof against the shipping console.html bytes |

**Nothing code-incomplete was found in this flow.** The only gap between
"designed" and "active" is the two operator secrets in
`OPERATOR-SECRETS-RUNBOOK.md` §1–2. This is a genuine "operator secret" gap,
not a disguised code gap — I looked for one (a missing test, a TODO, a
mismatched canonical-JSON implementation between `status.js`'s inline
`canonical()` and the TS lib's `canonicalJson()`) and did not find one. The
inline `canonical()` in `status.js` is byte-identical algorithm to the lib's;
the live CRL it produced verified against the lib's own verifier, which is the
strongest evidence available that they agree.

## Operator activation sequence (ties the runbook to this flow)

```bash
# 1. Unlock revocation writes on Pages.
npx wrangler pages secret put LICENSE_ADMIN_TOKEN --project-name posternlabs

# 2. Unlock CRL publish on Fly.
fly secrets set ADMIN_TOKEN="$(openssl rand -hex 32)" -a postern-cloud-demo

# 3. (Optional, only when there's an actual serial/org to revoke) Add a revocation:
curl -s -X POST https://posternlabs.com/license/status \
  -H "authorization: Bearer <LICENSE_ADMIN_TOKEN>" -H "content-type: application/json" \
  -d '{"jti":"<jti>","reason":"..."}'

# 4. Pull the freshly-signed CRL and publish it to the Fly hosted verifier:
curl -s https://posternlabs.com/license/status | python3 -c "import json,sys; print(json.dumps(json.load(sys.stdin)['crl']))" > crl.json
curl -s -X POST https://postern-cloud-demo.fly.dev/v1/crl \
  -H "authorization: Bearer <ADMIN_TOKEN>" -H "content-type: application/json" \
  --data-binary @crl.json

# 5. Confirm:
curl -s https://postern-cloud-demo.fly.dev/v1/crl
#   crl is no longer null; payload.version matches what you just published
```

Steps 3–5 are exactly what Dev C1's publish helper script should wrap (see
`REMAINING.md` and the charter) — the operator should not have to hand-type
this every time a revocation is needed.
