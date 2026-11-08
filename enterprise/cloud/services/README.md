<!--
SPDX-License-Identifier: MIT OR Apache-2.0
SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
-->

# Postern CLOUD — hosted services (reference prototype)

The **server side** of the hosted enterprise offering: the counterparts to the
self-hosted / offline enterprise modules. Three standalone, framework-free
Node.js services (zero runtime dependencies, Node ≥ 18.17):

| Service | File | Self-hosted / offline counterpart it mirrors |
|---|---|---|
| Hosted **license verification** | `src/license-service.mjs` | `enterprise/licensing/` (offline, on-device chain) |
| Hosted **admin console** backend | `src/console-service.mjs` | `enterprise/features/sub-access.mjs` (local minting) |
| Hosted **comms RELAY** (transport only) | `src/relay-service.mjs` | `enterprise/comms/` (self-hosted homeserver + E2EE) |

Shared plumbing, the canonical Ed25519 verification format, and the honest
privacy-posture model live in `src/common.mjs`. A framework-free end-to-end
smoke test is `self-check.mjs`.

> **STATUS: design / reference prototype. UNAUDITED. Pre-production.** Not a
> security product; do not rely on it for anything safety- or compliance-
> critical without an independent review and a real audit. Adherence-by-design,
> **not certified**. This is the *community/reference* edition of these
> services — it is not "Postern OS", and it is never "BABA YAGA".

---

## The one thing to understand first: hosted is *less private*

Every self-hosted / offline Postern enterprise module was designed so that a
third party (an operator, a host, Postern Labs itself) learns **nothing**:

- License verification is **on-device and offline** — it reveals a check to no one.
- Sub-token minting happens with the org's **master key on the org's own machine**.
- Comms can run on a **homeserver the org controls**, exposing routing metadata
  to no outside party.

A *hosted* service, by definition, inserts an operator into the path. That is a
**real privacy regression**, and this directory's rule is to **disclose it on
every service, plainly**, the way `apps/tolmach-subscription` discloses its proxy:

> **A promise, not a proof.** Where a hosted service *chooses* not to keep
> something (no check-in log, no key persistence, drop-on-delivery), that is a
> **policy of this code**, not an architectural guarantee. A compelled or
> malicious operator could change the policy. Only architecture (the relay
> having **no keys**, so it *cannot* read bodies) is a guarantee. Prefer the
> self-hosted / offline path when you need the guarantee; these hosted services
> exist for orgs that accept the trade for convenience.

Each service exposes `GET /v1/posture` returning a structured, honest
`what-we-can / cannot / metadata-exposed / minimizations / promise-not-proof`
record. Those postures are the source of truth; this README summarizes them.

**Business opt-in only.** Personal editions of Postern are free forever and
**never** touch a hosted service — nothing here gates them and nothing phones
home for them. Billing, where it ever applies, is ordinary currency; the coin
is **not a security** and is never involved.

---

## 1. Hosted license verification — `src/license-service.mjs`

Runs the **exact same** offline verification chain (`vendor → master → sub`,
Ed25519 over canonical JSON) that the app already runs on-device — server-side.
Cryptographically this **adds nothing**; the only things a hosted verify buys are
(a) a **revocation list** to kill a leaked sub token before its `exp`, and (b) an
optional, off-by-default activity view.

| | |
|---|---|
| **Can see** | that a given org/sub checked in, when, from what IP; the (public) token you submit; aggregate activity ≈ login frequency |
| **Cannot see** | any signing key (it holds only the vendor **public** key — it can never forge a token), application data, or any decryptable content |
| **Metadata exposed vs offline** | offline reveals *nothing*; a hosted check reveals *that the check happened* |
| **Minimizations** | no check-in log by default; revocations store only a SHA-256 of the token; no cookies/analytics/third-party calls |

Endpoints: `GET /v1/vendor-key`, `POST /v1/verify {master, sub?}`,
`GET /v1/revocations`, `POST /v1/revocations` (admin). Because apps verify
**offline**, a revocation only bites if clients consult the list (or ship a
periodically-published CRL) — otherwise a sub stays valid offline until `exp`.

```sh
VENDOR_PUBLIC_KEY=<base64-ed25519-pub> ADMIN_TOKEN=<secret> \
  node src/license-service.mjs      # :8801
```

> **`VENDOR_PUBLIC_KEY` is MANDATORY (fail-closed, SVC-1).** Both the license and
> console services **refuse to start** without it. A hosted verifier with no
> vendor key cannot check master tokens and would end up accepting the
> unverifiable (fail-open) — so the absence is a hard refusal, not a warning.

## 2. Hosted admin console backend — `src/console-service.mjs`

The server behind the enterprise admin console: it holds the org **roster** and
the resulting **signed public token records**. The uncomfortable question a
hosted console must answer honestly is *where does signing happen?* — so it
supports two modes and **defaults to the private one**:

- **`client-sign` (default, recommended)** — the org master **private key stays
  in the admin's browser**. The server stores only labels/expiries and the
  signed **public** tokens the admin uploads after signing locally. **The server
  never receives a private key.**
- **`delegated` (opt-in, disclosed regression)** — the org uploads its master
  private key and the **server** mints. Convenient, but the operator now sees
  the key that can mint unlimited subs. Off unless `CONSOLE_SIGNING_MODE=delegated`;
  even then the key is held only transiently in memory and **every mint response
  discloses it was seen** ("a promise, not a proof").

Mirroring the `tolmach-subscription` rule: the more-private option is
first-class and the console **never pushes the org off it**.

| | |
|---|---|
| **Can see** | org identity, the full roster (member labels), token metadata; *in delegated mode only*, the master key in memory at mint time |
| **Cannot see** | application data or messages; *in client-sign mode*, the private key at all |
| **Metadata exposed vs self-host** | the roster and its churn — a self-hosted console exposes this to no third party |

Endpoints: `POST /v1/orgs`, `POST /v1/roster`, `POST /v1/roster/:id/token`
(client-sign), `POST /v1/roster/:id/mint` (delegated only), `GET /v1/roster`,
`POST /v1/roster/:id/revoke`. Uploaded masters are verified against the vendor
key so a forged workspace cannot be registered.

```sh
VENDOR_PUBLIC_KEY=<base64-ed25519-pub> node src/console-service.mjs   # :8802 (client-sign)
CONSOLE_SIGNING_MODE=delegated VENDOR_PUBLIC_KEY=<...> node src/console-service.mjs
```

## 3. Hosted comms RELAY — `src/relay-service.mjs`

**Transport only.** The comms app end-to-end encrypts message **bodies** (Megolm
via the `postern-messenger` crate); this relay moves **opaque ciphertext blobs**
from sender to recipient and **never holds, parses, or can read message
plaintext** — it has no keys and no crypto that could decrypt a body. That the
relay cannot read bodies is **architecture, not a promise**.

The honest cost of a *hosted* relay (vs a homeserver on the org's own metal) is
**routing metadata**: who sends to whom, when, how big, from what IP. That social
graph and timing is a real privacy regression and is disclosed. Minimizations:

- bodies are **opaque and never parsed**; treated as bytes;
- **deliver-then-drop** — a blob is removed the moment it is collected; nothing
  archived; undelivered blobs **expire (TTL)**;
- **sealed-sender** — a client may omit the `from` routing id, so the relay sees
  the recipient but **not an authenticated sender** (the sender lives inside the
  E2EE body it cannot read);
- **counts-only logging** — never ciphertext, never a routing pair when sealed.

| | |
|---|---|
| **Can see** | recipient routing id (+ sender unless sealed); send/collect timing; ciphertext size; connection IP/times |
| **Cannot see** | message **plaintext** (E2EE opaque), attachment content, or — in sealed mode — the sender identity |
| **Metadata exposed vs self-host** | the who-talks-to-whom social graph and its timing |

Endpoints: `POST /auth/register`, `POST /v1/send {to, ciphertext, sealedSender?}`,
`GET /v1/inbox` (pull + drop), `GET /v1/me`.

```sh
node src/relay-service.mjs        # :8803
```

---

## Running the self-check

No test framework — a single script spins each service up on an ephemeral port
and drives it over real HTTP:

```sh
node self-check.mjs        # or: npm run self-check
```

It exercises: offline-chain verify (master-only, master+sub, tampered, expired,
revoked), the client-sign vs delegated console flows (including refusal of
server-side minting in client-sign mode and rejection of forged/mis-signed
tokens), and the relay (opaque round-trip, deliver-then-drop, sealed-sender,
unknown-recipient, unauthorized). **40/40 checks pass**; `npm run check` also
runs `node --check` over every file.

## What a lead must wire before production

1. **Real identity** on each service's `register` boundary (OIDC / passkeys /
   verified email). The bearer-token *boundary* is real; the identity provider is
   stubbed and marked as such.
2. **Durable stores** — the in-memory maps (revocations, rosters, mailboxes) are
   the reference shape; swap for SQLite/Postgres/a durable queue at scale.
3. **TLS + a set `ALLOWED_ORIGIN`.** CORS is **deny-by-default** — an unset
   `ALLOWED_ORIGIN` falls back to `http://localhost` only, **never `*`** (SVC-2).
   Set it to your real client origin; a wildcard is honored only if you set it
   explicitly, and it warns on boot. `TRUST_PROXY=1` only behind an
   operator-controlled reverse proxy.
4. **A published CRL story** for the license service if offline apps are to honor
   revocations without a per-check round-trip (which itself is a metadata cost).
5. **Keep the private paths first-class** — never remove offline verification,
   never remove client-sign, never remove self-hosting, and never market a hosted
   service as *equally* private. The honesty is the product.

## Licenses (permissive only — Postern rule: no AGPL/GPL)

Dual-licensed **MIT OR Apache-2.0** (`LICENSE-MIT`, `LICENSE-APACHE`); every
source file carries an SPDX header. **Zero runtime dependencies** — there is no
dependency chain, so no copyleft anywhere in it.
