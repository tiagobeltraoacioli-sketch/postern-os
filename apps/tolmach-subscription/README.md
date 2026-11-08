# Tolmach — Subscription / Metered-Billing Layer (reference implementation)

A working, honestly-labeled subscription tier for the Tolmach privacy app
(`apps/tolmach/`), letting end-users pay a flat monthly price while Claude
tokens are billed to the **operator's** Anthropic contract — **without touching
or degrading the existing bring-your-own-key "Sovereign" tier**, which remains
intact at `apps/tolmach/index.html` and remains first-class inside this build.

```
apps/tolmach-subscription/
├── README.md                  ← you are here
├── server/proxy.mjs           metering proxy — single-file Node.js, zero deps, MIT
├── client/index.html          Tolmach dual-tier build (Sovereign + Subscription modes)
├── tools/metering-check.mjs   standalone check of the token-accounting math
└── tools/proxy-smoke.mjs      HTTP-boundary smoke test against a real server.listen()
```

---

## The tradeoff, stated up front

To bill a subscription against the operator's contract, the master API key
**cannot** be in the browser. That forces a backend proxy into the request
path, and a proxy that forwards prompts necessarily **sees plaintext prompts
and responses in memory** — translations, meeting transcripts.

| | Sovereign (BYO key) | Subscription (proxy) |
|---|---|---|
| Network path | browser → `api.anthropic.com` | browser → **Postern proxy** → `api.anthropic.com` |
| Who holds the Anthropic key | the user, in their browser | the operator, server-side only |
| Who Anthropic contracts with | the user | **the operator** |
| Can Postern see prompt text | **no — no server exists** | **yes, in transit/memory** (not persisted, by code — but that's policy, not proof) |
| "No extra parties" claim | **holds** | **does not hold** — the proxy is an extra party |
| Payment | user pays Anthropic per token | user pays operator flat monthly (Stripe) |

The proxy is a **trust-reduction** design (zero prompt persistence, published
source, token-counts-only metering), not a trust-elimination one. The client's
Privacy panel, the composer footer, and the settings dialog all say so in
plain words; the Sovereign tier is presented as the recommended,
more-private option. **Never market the Subscription tier as equally
private, and never remove the Sovereign tier to push users onto it.**

## Architecture

```
SOVEREIGN TIER (unchanged from apps/tolmach — no server anywhere)

  browser (user's key, localStorage) ──── POST /v1/messages, SSE ────▶ api.anthropic.com


SUBSCRIPTION TIER

  browser ── Bearer dgm_… token ──▶ ┌─────────────────────────────┐          ┌──────────────────┐
      POST {proxy}/v1/messages     │  proxy.mjs (operator infra)  │          │ api.anthropic.com │
      (no Anthropic key here)      │  · authenticate subscriber   │──x-api-─▶│ (operator's key,  │
                                   │  · check tier + $ quota      │  key     │  operator's       │
  ◀── SSE streamed back UNCHANGED ─│  · forward body verbatim     │◀──SSE────│  contract)        │
      (same parser as Sovereign)   │  · tee-parse message_start / │          └──────────────────┘
                                   │    message_delta usage only  │
                                   │  · persist token COUNTS only │
                                   └──────────┬──────────────────┘
                                              │ activate / deactivate / set tier
  browser ──▶ Stripe Checkout (card → Stripe) │ (webhook, HMAC-verified)
                        └──────────── stripe.com ┘
```

**Stack choice:** a single-file Node.js (>= 18.17) service with **zero runtime
dependencies** — built-in `fetch`, `node:http`, `node:crypto`. Chosen over a
Cloudflare Worker so it runs anywhere (laptop, VPS, container) with nothing to
install; a Worker port is mechanical (same fetch-based upstream call, swap the
JSON-file store for KV/Durable Objects, HMAC via WebCrypto).

## How each piece works

### Auth (real boundary, stubbed identity)
`POST /auth/register {email}` issues a 256-bit random bearer token
(`dgm_…`), stored **only as a SHA-256 hash** server-side. Every privileged
endpoint requires `Authorization: Bearer` and maps the token to exactly one
subscriber. The *identity provider* part (email verification, recovery, OIDC/
passkeys) is deliberately stubbed and marked as such — the *boundary* is real.

Registration abuse controls (real, not stubbed):
- **Rate-limited**: per client IP (default 5/hour) and globally (default
  100/hour), plus a hard cap on total accounts (default 10,000) — an
  unauthenticated endpoint must not be a token-minting / store-growth DoS.
  Tunable via `REGISTER_PER_IP_LIMIT` / `REGISTER_GLOBAL_LIMIT` /
  `REGISTER_WINDOW_MS` / `MAX_SUBSCRIBERS`; set `TRUST_PROXY=1` only behind
  an operator-controlled reverse proxy so `X-Forwarded-For` is honored.
- **Non-enumerating**: the response is uniform whether or not the email
  already has an account (an already-registered email gets a decoy token of
  identical shape that is never stored and never authenticates), so the
  endpoint no longer confirms which emails have accounts. Residual limit,
  stated honestly: an attacker who *uses* a returned token can still infer
  existence (a decoy token never works) — closing that fully requires
  delivering tokens out-of-band via verified email/OIDC, which is exactly the
  real-IdP work required before production (below).

### Proxying + metering
`POST /v1/messages` parses the body only to enforce policy (model allowlist
per tier, `max_tokens` clamp), injects the operator key from
`ANTHROPIC_API_KEY`, forwards to `https://api.anthropic.com/v1/messages` with
`x-api-key` / `anthropic-version: 2023-06-01` / `content-type:
application/json`, and **streams the SSE back byte-for-byte** — the client's
existing parser is untouched. A tee'd incremental parser (`createSSEMeter`)
extracts only the `usage` fields from `message_start` (input + cache tokens)
and `message_delta` (output tokens; restated input wins) and discards
everything else. Non-streaming requests are metered from the response `usage`.
Cost is attributed per current list prices (below) and persisted per
subscriber per month — **token counts, model, timestamps; never words**.

### Quotas (reserve-then-settle)
Each tier carries a monthly **upstream-cost budget** (the operator's metered
Anthropic spend for that subscriber). At ≥ 80% every response carries an
`x-tolmach-quota-warning` header (soft warn — the client renders "quota N%
used" in amber); at 100% requests are rejected with `402 quota_exceeded`
(hard stop) with a message that names the way out: wait for the monthly
reset, upgrade, or switch to Sovereign mode. Plus a per-subscriber
concurrency cap (4) and a 1 MiB body cap.

Enforcement is **admission-controlled, not check-then-hope**: before a
request is forwarded, its worst-case cost is priced — input tokens estimated
from the raw body size (~3 bytes/token, deliberately conservative; input was
the previously-uncapped side), output at the tier's `max_tokens` cap, cache
writes at the dearer rate when `cache_control` appears — and that amount is
**reserved** against the budget in the same synchronous step as the check, so
concurrent requests cannot race past the cap. When the stream settles, the
reservation is released and the *actual* metered usage is recorded. Both the
reservation and the settlement are persisted **synchronously** (not on the
debounced save path): a crash mid-stream leaves the conservative estimate
counted for the month instead of erasing spend that already hit the
operator's Anthropic bill. Near the end of a budget this correctly refuses
requests whose worst case doesn't fit — the 402 says so and clients can retry
with a smaller `max_tokens`.

### Stripe (test mode; live wiring identical)
- `POST /billing/checkout {tier}` → creates a subscription-mode Checkout
  Session via raw Stripe REST (`client_reference_id` = subscriber id) and
  returns the hosted URL. Card data goes to Stripe, never to the proxy.
- `POST /billing/webhook` → verifies the `Stripe-Signature` header (v1 HMAC-
  SHA-256 over `t.payload`, timing-safe compare, 5-min tolerance), then:
  `checkout.session.completed` activates + links customer;
  `customer.subscription.created/updated` sets tier from the price id and
  active from status; `customer.subscription.deleted` / `invoice.payment_failed`
  deactivate.
- `POST /billing/portal` → Stripe billing-portal session for self-service
  cancel/upgrade.
- `DEV_MODE=1` adds `POST /billing/dev-activate` so the whole flow is testable
  without Stripe keys. Never enable in production.

### Client (dual-tier Tolmach)
`client/index.html` is the original app plus a **tier selector** in Settings
(Sovereign default and recommended). In Subscription mode `streamClaude()`
targets `{proxyUrl}/v1/messages` with the bearer token and no Anthropic key;
in Sovereign mode it is byte-identical to the original path. Settings gains
register / checkout / quota buttons — and a **verification-code field** that
appears automatically when the proxy runs in the real email-verification mode
(register returns `pending`, no token, until the emailed code is entered);
the Privacy ledger gains an explicit
subscription row and scopes the "no extra parties" claim to Sovereign only;
the composer footer and page footer state the active tier's privacy posture.
Only external destinations in the file: `api.anthropic.com` (Sovereign) and
the user-configured proxy URL (Subscription; Stripe is reached only via the
checkout URL the proxy returns, in a new tab).

**CSP `connect-src` (enforced allowlist).** The `<meta>` CSP in
`client/index.html` is the hard network boundary: the browser refuses any
fetch to an origin not listed there, regardless of what the Settings proxy-URL
field says. As shipped it allows:

- `https://api.anthropic.com` — Sovereign tier (the only origin that tier ever
  needs; do not add anything for Sovereign),
- `http://localhost:8787` and `http://127.0.0.1:8787` — the dev-default proxy
  (`DEFAULT_PROXY_URL`), so local Subscription-mode testing works out of the box,
- `https://proxy.invalid` — a **deploy-time placeholder** on a reserved TLD
  that can never match a real host.

**Operators MUST edit `connect-src` at deploy**: replace `https://proxy.invalid`
with the exact origin the proxy is served from (scheme + host + port, no path
— e.g. `https://tolmach-proxy.example.com`), and preferably drop the two
localhost entries from the production copy. If the real proxy origin is not in
`connect-src`, every Subscription-mode request is CSP-refused in the browser
before it leaves the page. Add only that one origin — the allowlist is the
privacy claim.

## Cost model & tiers

List prices used by the meter (USD / MTok; cache writes 1.25× input, reads 0.1×):

| Model | Input | Output | Note |
|---|---|---|---|
| Haiku 4.5 | $1 | $5 | default translation model |
| Sonnet 5 | $3 | $15 | **intro $2 / $10 through 2026-08-31** (meter is date-aware) |
| Opus 4.8 | $5 | $25 | Pro tier only |

**Meeting minutes dominate cost.** One update every ~2 min = 30/hr; a typical
update is ~2,500 input + ~1,200 output tokens on Sonnet 5 (the app default):

| Workload | $/meeting-hour |
|---|---|
| Minutes, Sonnet 5 intro | **$0.51** |
| Minutes, Sonnet 5 list | $0.77 |
| Minutes, Sonnet 5 list, heavy hour (grown doc: 5k in / 1.6k out per update) | $1.17 |
| Minutes, Opus 4.8 | ~$1.9–2.9 |
| Minutes, Haiku 4.5 | ~$0.17–0.40 |
| Live translation, Haiku 4.5 (dense hour, ~120 utterances w/ context) | ~$0.08 |

(These exact numbers are asserted in `tools/metering-check.mjs`.)

**Tiers** (edit `TIERS` in `proxy.mjs`):

| Tier | Price/mo | Upstream budget | ≈ meeting-hours (Sonnet 5) | Models | max_tokens cap |
|---|---|---|---|---|---|
| Basic | $9 | $6.00 | ~5–12 h | Haiku, Sonnet | 4,096 |
| Pro | $29 | $20.00 | ~17–39 h | + Opus 4.8 | 8,192 |

**Break-even math** (Stripe standard 2.9% + $0.30 per charge):

```
Basic:  $9.00 − ($9.00×0.029 + $0.30) = $8.44 net
        worst case (quota fully used): $8.44 − $6.00 = $2.44 margin (27%)
Pro:    $29.00 − ($29.00×0.029 + $0.30) = $27.86 net
        worst case: $27.86 − $20.00 = $7.86 margin (27%)
```

Typical subscribers use well under the cap, so realized margin is higher.
**What the quota actually guarantees:** requests are admitted only while
settled + reserved spend fits the budget, so a maxed-out subscriber's token
overspend is **bounded by the estimation slack of admitted requests** — not
by uncapped input or concurrency races (the pre-flight estimate of ~3
bytes/token over-counts typical text, and output is priced at the cap, so
the practical bound is ≈ $0: only a pathological tokenization that beats 3
bytes/token on an admitted request can exceed the budget, by the difference
only). This is a *bounded-overspend-within-margin* guarantee, not an
absolute "never"; the margin above absorbs it. Fixed costs (a small VPS
~$5–10/mo) are covered from
the second or third subscriber. Failure modes to watch: a Basic user running
daily Sonnet meetings hits the $6 cap in ~5 heavy hours — the soft-warn at
80% plus the 402 message steer them to Pro or Sovereign instead of
surprising them. If the Sonnet intro price lapses (after 2026-08-31), hours
per budget drop ~34%; the meter reprices automatically, revisit tier budgets.

## Running it

```sh
# 1. proxy (dev, no Stripe needed)
cd apps/tolmach-subscription
ANTHROPIC_API_KEY=sk-ant-… DEV_MODE=1 node server/proxy.mjs

# 2. client — any static server, e.g.
python3 -m http.server 8080 -d client
# open http://localhost:8080 → Settings → tier "Subscription"
# → enter email → "get token" → "Check quota" (after dev-activate below)

# 3. activate without Stripe (dev only)
curl -X POST http://localhost:8787/billing/dev-activate \
  -H "Authorization: Bearer dgm_…" -H "content-type: application/json" \
  -d '{"tier":"basic"}'
```

Or via the package scripts (zero deps, nothing to install):

```sh
npm start          # node server/proxy.mjs
npm run verify     # --check all three files + metering-check + proxy-smoke
```

Stripe test mode:

```sh
stripe listen --forward-to localhost:8787/billing/webhook   # prints whsec_…
STRIPE_SECRET_KEY=sk_test_… STRIPE_WEBHOOK_SECRET=whsec_… \
STRIPE_PRICE_BASIC=price_… STRIPE_PRICE_PRO=price_… \
ANTHROPIC_API_KEY=sk-ant-… node server/proxy.mjs
# checkout with test card 4242 4242 4242 4242
```

### Deploying the hosted backend (operator)

Deployment scaffolding ships alongside the proxy; it is **not** wired into
`assemble-public.sh` or CI — the operator stands this up, and only then
re-enables the (currently commented) tolmach-subscription publish block that
serves the client. Nothing here deploys itself.

| File | Purpose |
|---|---|
| `package.json` | zero-dependency Node package; `start` / `verify` / `test` / `smoke` scripts; `engines.node >= 18.17` |
| `Dockerfile` | `node:20-slim` service image (matches `community/postern-bot`); unprivileged, `/healthz` HEALTHCHECK, `DATA_DIR=/data` volume, `EXPOSE 8787`; **no secrets baked in** |
| `.dockerignore` | keeps the build context tiny and secret-free (excludes `data/`, `client/`, any `.env`) |
| `.env.example` | the full runtime env contract to copy into a secret store (never commit a filled copy) |
| `fly.toml` | Fly deploy target (`primary_region = gru`, matches the repo); stateful, volume-mounted `/data`, one warm machine; **secrets via `fly secrets set`** |

Container / Fly go-live is exactly the checklist below, with the mechanics
filled in:

```sh
# build + run locally (no key = fail-closed: /healthz up, /v1/messages disabled)
docker build -t tolmach-proxy apps/tolmach-subscription
docker run --rm -p 8787:8787 -v tolmach_data:/data \
  -e ANTHROPIC_API_KEY=sk-ant-… -e ALLOWED_ORIGIN=https://your-client.example \
  tolmach-proxy

# Fly (rename `app` in fly.toml first)
fly volumes create tolmach_data --region gru --size 1
fly secrets set ANTHROPIC_API_KEY=sk-ant-… \
  STRIPE_SECRET_KEY=sk_live_… STRIPE_WEBHOOK_SECRET=whsec_… \
  STRIPE_PRICE_BASIC=price_… STRIPE_PRICE_PRO=price_…
fly deploy -c apps/tolmach-subscription/fly.toml
```

### Env vars

| Var | Required | Purpose |
|---|---|---|
| `ANTHROPIC_API_KEY` | yes (to proxy) | operator's master key — server-side only, never sent to clients |
| `PORT` | no (8787) | listen port |
| `DATA_DIR` | no (`./data`) | JSON store: accounts + monthly token counts (**no prompt text, ever**) |
| `ALLOWED_ORIGIN` | prod: yes | CORS origin of the client page (default `*` — tighten it) |
| `PUBLIC_BASE_URL` | for Stripe | redirect target after checkout |
| `STRIPE_SECRET_KEY` | for billing | `sk_test_…` / `sk_live_…` (same code either way) |
| `STRIPE_WEBHOOK_SECRET` | for billing | `whsec_…` |
| `STRIPE_PRICE_BASIC` / `STRIPE_PRICE_PRO` | for billing | monthly price ids; also map webhook price → tier |
| `DEV_MODE` | never in prod | enables `/billing/dev-activate` |
| `ANTHROPIC_BASE_URL` | tests only | upstream override used by the smoke test |
| `MAX_SUBSCRIBERS` | no (10000) | hard cap on total accounts (JSON-store DoS bound) |
| `REGISTER_PER_IP_LIMIT` | no (5) | `/auth/register` attempts per IP per window |
| `REGISTER_GLOBAL_LIMIT` | no (100) | `/auth/register` attempts across all IPs per window |
| `REGISTER_WINDOW_MS` | no (3600000) | rate-limit window in ms |
| `TRUST_PROXY` | only behind a reverse proxy | `1` = trust `X-Forwarded-For` for the per-IP limit |

### What the lead must wire before production
1. **Real Stripe keys + prices** (create two recurring prices, set the four env
   vars, register the webhook endpoint in the dashboard). Code paths are live;
   only credentials are stubbed.
2. **Real identity**: a built-in **out-of-band email-verification** path already
   ships — set `REQUIRE_EMAIL_VERIFICATION=1` and point `MAIL_COMMAND` at your
   mail transport, and `/auth/register` then only sends a one-time code while
   `/auth/verify` issues the token (the client shows a code-entry field
   automatically when the proxy replies `pending`). That closes the
   type-any-email-get-a-token hole for go-live. OIDC / passkeys remain an
   optional stronger upgrade; the bearer-token boundary stays as-is either way.
3. **TLS + domain** (reverse-proxy with Caddy/nginx or a PaaS), set
   `ALLOWED_ORIGIN` to the exact client origin, `DEV_MODE` off.
4. **Client CSP**: in the deployed copy of `client/index.html`, replace the
   `https://proxy.invalid` placeholder in `connect-src` with the exact proxy
   origin from step 3 (and drop the `localhost`/`127.0.0.1` dev entries).
   The CSP is enforced by the browser — skip this and Subscription mode is
   dead on arrival even with correct settings. See "CSP `connect-src`" above.
5. **Store**: swap the JSON files for SQLite/Postgres at real scale (the
   `recordUsage`/`monthUsage` shapes are the contract).
6. Publish the proxy source and the zero-prompt-logging policy where
   subscribers can read them — the honesty is the product.

## Licenses (permissive only — Postern rule: no AGPL/GPL)

| Component | License | Notes |
|---|---|---|
| `server/proxy.mjs` | MIT (this repo) | zero runtime dependencies |
| `client/index.html` | MIT (this repo) | zero dependencies, derived from `apps/tolmach` |
| `tools/metering-check.mjs` | MIT (this repo) | zero dependencies |
| `tools/proxy-smoke.mjs` | MIT (this repo) | zero runtime dependencies |
| Node.js runtime | MIT (+ permissive third-party notices) | not distributed by us |
| Stripe integration | raw HTTPS REST — **no SDK vendored** | (stripe-node is MIT if ever adopted) |

No copyleft anywhere in the dependency chain because there is no dependency chain.

## Verification performed

- `node --check server/proxy.mjs` and `node --check tools/metering-check.mjs` — pass.
- `node tools/metering-check.mjs` — 29/29 checks pass: SSE usage extraction
  across arbitrary chunk splits, per-model cost math vs hand computation
  (incl. Sonnet intro-price date boundary and cache-token rates), the
  $/meeting-hour figures above, Stripe signature verify/reject cases, the
  pre-flight worst-case cost estimator (incl. the 1 MiB-body attack shape
  pricing at ≈ $1.95 and estimate ≥ metered cost on typical requests), and
  the registration rate limiter (allow/block/window-reset).
- `node tools/proxy-smoke.mjs` — automated HTTP-boundary smoke test: boots
  the real `server` from `proxy.mjs` on an ephemeral port (no `ANTHROPIC_API_KEY`,
  `DEV_MODE`, or `REQUIRE_EMAIL_VERIFICATION` set) and asserts over real
  `fetch()` calls that `/healthz` reports `upstream_key:false`, `/auth/register`
  issues a `dgm_`-prefixed token via the reference stub, a fresh subscriber is
  `active:false`/`tier:null` at `/v1/me`, `/v1/messages` 401s with no bearer
  token, and `/billing/dev-activate` 404s (the bypass literally does not exist
  with `DEV_MODE` off). State is written only under a `mkdtemp()` temp
  `DATA_DIR`, removed on exit; no request ever reaches `api.anthropic.com`.
- Manual end-to-end smoke test (proxy against a mock SSE upstream, `DEV_MODE=1`):
  register →
  duplicate email returns a **uniform 200** (no 409 enumeration; decoy token
  never authenticates, real token does) → 6th registration in the window
  **429** with `retry-after` → dev-activate → streamed SSE passed through →
  usage persisted **synchronously** before the response ends (reservation
  released to 0) → **no prompt text anywhere in `DATA_DIR`** → with $0.30 of
  budget left, a 200 kB Opus request is refused **402 pre-flight without
  reaching upstream** → 4 concurrent worst-case requests at
  budget-minus-epsilon: **exactly 1 admitted, 3 rejected** (the old
  checked-before/recorded-after race is closed).
- Client inline JS extracted and `node --check`ed — pass; external hosts in
  the HTML are exactly `api.anthropic.com` and the configurable proxy URL.
