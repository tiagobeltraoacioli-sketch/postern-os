<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Staged Cloudflare Pages functions (bp-wt-site)

**Status:** reference prototype, UNAUDITED, pre-production. Not compliance, not legal advice.

These three files are the site's license edge functions for the D4 (revocation/CRL)
and D5 (real D&B + KYC-at-renewal) work. They are **staged here** — inside the
owned `enterprise/licensing/` path — because the implementing agent was isolated
to the `bloch-protocol` worktree and could not write into the separate `bp-wt-site`
repository. They are **self-contained (no imports)**, exactly like the shipped
function, so they are drop-in.

## Deploy

Copy verbatim to the deploy target in the `bp-wt-site` repo:

| Staged file | Deploy target |
|---|---|
| `license/master.js` | `bp-wt-site/functions/license/master.js` (replaces existing) |
| `license/status.js` | `bp-wt-site/functions/license/status.js` (new) |
| `license/renew.js`  | `bp-wt-site/functions/license/renew.js`  (new) |
| `license/review.js` | `bp-wt-site/functions/license/review.js` (new — Gramota owner/manager KYC) |

## Environment / bindings

- `VENDOR_PRIV_PKCS8_B64` — vendor Ed25519 signing key (already used by `master.js`).
  Required by `status.js` (to sign the CRL) and `renew.js` (to re-mint).
- `VENDOR_PUB_RAW_B64` — hardcoded in each file (unchanged); the app-side verifier
  and the standalone hosted verifier trust the same key.
- `LICENSES` — the KV namespace. Now also stores `crl:state`
  (`{version, revoked_jti[], revoked_master_pub[]}`), `billing:<duns>` (fiat
  onboarding intent, never the coin), and `kyc:<ref>` (the authoritative Gramota
  person→entity verdict, ~1h TTL, bound into the token by reference by `master.js` /
  `renew.js` — a client cannot inflate its own LoA).
- `KYC_MODE` — optional. `"enforce"` caps a self-declared LoA-0 request at
  *provisional* in `review.js`'s `kycGate`. **Default (unset) = today's self-declared
  parity — no regression.** The person→entity binder lives in `review.js` +
  `apps/gramota-kyc/` (on-device OCR); document images / raw PII NEVER reach the
  server (a tripwire refuses them).
- `LICENSE_ADMIN_TOKEN` — bearer required to POST revocations to `status.js`.
- `DNB_CLIENT_ID` + `DNB_CLIENT_SECRET` **or** `DNB_BEARER` — Dun & Bradstreet
  Direct+ credentials. **Optional:** when absent, corporate issuance falls back to
  format-only, flagged for manual review (graceful — never a hard failure). When
  present, a DUNS that does not resolve to a real legal entity is **refused**.

## Contract note (canonical JSON stays stable)

The `canonical()` function is **unchanged**. The new token fields (`jti`, `kid`,
`iss`, `dnb`) are additive and always defined when present, so tokens issued
before this change still verify byte-identically. The CRL uses the same detached
Ed25519-over-canonical-JSON scheme; a CRL signed by `status.js` verifies with the
app-side `@postern/licensing` `verifyCrl()` (proven by the cross-implementation
self-check).

Rails: offline verification preserved (the CRL only revokes, never grants;
freshness is best-effort / soft-offline). Fiat billing only — the coin is never
billed and is not a security. Personal editions are free forever and are never
gated by any of this.
