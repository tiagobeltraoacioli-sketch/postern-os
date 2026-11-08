<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- Copyright (c) Postern Labs and Postern community contributors -->

# Postern Licensing Model

This document states, honestly and in full, how licensing works for Postern.
It is the source of truth the software, the website issuer, and this library all
follow. If anything here reads as a dark pattern, it is a bug — please open an
issue.

## Principles (non-negotiable)

1. **Mobile is free forever; only Postern Desktop is freemium.** Personal
   apps on **mobile** — and the mobile OS itself — are **free forever**: no
   token, no clock, no nag. Mobile is the free adoption channel. The one
   personal edition that is freemium is **Postern Desktop** (the personal
   desktop suite), which **reserves the right to require a license in the
   future**: it starts with a **24-month (2-year) free window** per install —
   the adoption on-ramp — after which a **personal key** is required to keep
   receiving **updates and premium features**. The key gates
   features/updates, **never access to your own encrypted data**: decrypt,
   read, and export of your own vault/wallet/credentials/messages/backups —
   and safety actions like Panic Lock — **always work**, key or not, expired
   or not. Expiry fails **open** into a read-only grace mode; it never
   deletes, locks, or holds your data hostage. The free window's start and
   end are disclosed up front; there is no telemetry and no phone-home. The
   **free versions** (all personal mobile apps, and Postern Desktop during its
   free window) **may show contextual, non-tracking ads** — see Principle 2 —
   and the **paid Postern Desktop key removes ads** as part of what it buys.
   *(This narrows a promise we published — "personal editions stay free
   regardless," which still holds in full for mobile. Only the desktop suite
   changes. The change is announced loudly and done as fairly as we can:
   every desktop install gets 2 full years free, and existing desktop
   installs are grandfathered a full 2-year window from the changeover date —
   24 months of notice-and-grace we are choosing to give, not a pre-existing
   notice commitment being honored. See §5 of
   `docs/POSTERN-FREEMIUM-LICENSING.md`.)*
2. **No surveillance.** Verification is **100% local and offline**. There is
   **no telemetry, no phone-home, no license server, no per-user account, and
   no usage tracking** — not for enforcement, not for analytics. Nothing about
   how you use Postern is transmitted anywhere by this system. **Advertising,
   where shown in free versions, is held to the same rule:** it is
   **contextual and non-tracking only** — chosen from nothing but the current
   screen/content, with **no user profile, no advertising or device ID, no
   third-party ad SDK that phones home, no telemetry, and no data leaving the
   device**, always clearly labeled. **Surveillance, programmatic, behavioral,
   and tracking-based advertising are forbidden** — the only ad model
   consistent with Postern. Ads **never** appear in security-critical flows
   (Panic Lock, Vault decrypt/export, backup), and the paid Desktop key
   removes them. *(Not built yet: no ad system exists, no ad network is
   integrated, and no placements ship — this is the announced model only.)*
3. **Honest, up-front disclosure.** Any free window (its start and end) is
   stated plainly at first run. See `disclosureForMaster()`.
4. **Graceful expiry.** When a free window ends and no license is present, the
   app degrades to a clear notice ("a license is required for continued
   business use"). It **never deletes, locks, or holds your data hostage**.
5. **Paid in ordinary currency (fiat).** Any future paid license is billed in
   ordinary money. It is **not** priced in, paid in, or tied to BLCH or any
   token or coin. BLCH is not involved in licensing and is not a security.
6. **Not a security product.** This is a pre-production, **unaudited** scaffold.
   Do not rely on it for safety- or compliance-critical decisions without an
   independent review.

## The three tiers

| Tier | Who | Token? | Seats | Window | DUNS |
|------|-----|--------|-------|--------|------|
| **Personal mobile** | Individuals, mobile apps + mobile OS | **None** | n/a | Free **forever** — the free adoption channel | — |
| **Postern Desktop (personal freemium)** | Individuals, personal **desktop** suite | Personal key (after the window) | 1 | **24 months** (2 years) free, then a key for updates/premium — data always openable | none (`null`) |
| **Business freemium** | Small business trying Postern | Vendor-signed master | **3 desktops** | **24 months** (2 years) | none (`null`) |
| **Corporate master** | A company with a DUNS number | Vendor-signed master | **Unlimited** | **6 months** (free now, pricing TBD) | required (9 digits) |

The **6-month corporate window** is explicitly the period during which the
revenue/pricing model is being structured. It is disclosed as "free now,
pricing to be determined" — not a silent trap.

## Master → Sub hierarchy

A corporate customer receives **one master token** plus its **own master
keypair** (generated at issuance). The customer keeps the master **private** key
and uses it to **mint unlimited sub tokens** — one per user/label — entirely on
their side. Every user then verifies **offline** with only the vendor **public**
key that ships in the app.

```
VENDOR private key (server secret, site Pages Function)
      │  signs
      ▼
MASTER token  { v:1, typ:"master", tier, duns, seats, iat, exp, master_pub }
      │  master_pub = the ORG's master public key
      ▼
ORG master private key (held by the customer)
      │  signs
      ▼
SUB token     { v:1, typ:"sub", master_pub, sub, iat, exp≤master.exp }
```

At issuance the site:
1. generates the org's master keypair,
2. embeds `master_pub` in the master payload and signs it with the **vendor**
   private key,
3. returns to the org: the **vendor-signed master token** + the **org master
   private key** (over a secure channel; the site does not retain it).

## Canonical token format

All tokens are **compact canonical JSON** (keys sorted at every level) plus a
**detached Ed25519 signature** (standard base64). On the wire a signed token is:

```json
{ "payload": { ...canonical fields... }, "sig": "<base64 ed25519 signature>" }
```

The signature is computed over the **UTF-8 bytes of `canonicalJson(payload)`**
(keys sorted, `undefined` dropped). Signer and verifier both canonicalise, so
they agree on the exact signed bytes. Keys (`master_pub`, vendor public key) and
signatures are raw 32-byte / 64-byte values in **standard base64**.

### MASTER payload (signed by the VENDOR key)

```json
{
  "v": 1,
  "typ": "master",
  "tier": "corporate-master",           // or "business-freemium"
  "duns": "123456789",                  // 9 digits for corporate; null for freemium
  "seats": "unlimited",                 // or 3 for freemium
  "iat": 1783887646,                    // issued-at, unix seconds
  "exp": 1799785246,                    // expiry, unix seconds
  "master_pub": "VuIIU8Xi...E/U="       // base64 raw Ed25519 pubkey of the ORG master keypair
}
```

- `corporate-master`: `duns` required (9 digits), `seats` = `"unlimited"`,
  `exp` = `iat + 6 months`.
- `business-freemium`: `duns` = `null`, `seats` = `3`, `exp` = `iat + 24 months`.

### SUB payload (signed by the ORG MASTER key)

```json
{
  "v": 1,
  "typ": "sub",
  "master_pub": "VuIIU8Xi...E/U=",      // MUST equal the master token's master_pub
  "sub": "alice@acme",                  // user/label
  "iat": 1783887646,
  "exp": 1799785246                     // MUST be ≤ master.exp
}
```

## Offline verification chain

`verifyChain(vendorPub, master, sub?)` implements exactly:

```
ed25519_verify(VENDOR_PUB, canonicalJson(master.payload), master.sig)
  && master.exp > now
  → extract master.payload.master_pub
  → (if a sub is presented)
       ed25519_verify(master.master_pub, canonicalJson(sub.payload), sub.sig)
       && sub.exp > now
       && sub.exp ≤ master.exp
       && sub.master_pub == master.master_pub
```

`status()` then returns `{ tier, seats, state, duns?, level }` where `state` is:

- `personal-free` — a free-forever personal edition that ships no token
  (all mobile personal apps, the mobile OS, and the free-forever platform/dev
  components), or a Postern Desktop install inside its 2-year free window;
  after the desktop window with no key it maps to `expired` → grace mode
  (§ graceful expiry), never a lockout;
- `valid` — business-freemium, in window;
- `in-eval` — corporate-master, in its disclosed "free now" window
  (`in-eval-until` == `expiresAt`);
- `expired` — window closed; **graceful** notice, data untouched;
- `invalid` — the chain did not verify (bad signature, structural mismatch, …).

Authenticity and time are reported **separately**: an authentic-but-expired
token is never a hard failure — it maps to `expired`, so the app can show a
polite renewal notice instead of breaking.

## DUNS validation — honor system (documented TODO)

For now, a corporate `duns` is validated by **format only** (exactly 9 digits).
Real Dun & Bradstreet verification against the D&B registry is **not** performed
yet — it is an explicit, disclosed **TODO**. Corporate issuance currently
operates on the honor system. This is stated openly rather than implied.

## Web-deployable issuance

`issue()` and `mintSub()` are portable and reused verbatim server-side:

- The **site's Cloudflare Pages Function** holds the vendor **private** key as a
  server secret and calls `issue()` to mint master tokens.
- The org's **admin console** holds the org master **private** key and calls
  `mintSub()`.
- The shipped **desktop apps** carry only the vendor **public** key and call
  `verifyChain()` / `status()` — fully offline.

The reference implementation uses Node's `node:crypto`. On Cloudflare Workers,
enable `nodejs_compat` to reuse it unchanged, or port the three primitives
(`generateKeypair` / `ed25519Sign` / `ed25519Verify`) to WebCrypto
(`crypto.subtle` supports Ed25519) — the token **format** is identical either
way, and any language port (e.g. a future Rust crate) MUST produce byte-identical
canonical JSON so signatures cross-verify.

## What this system deliberately does NOT do

- It does not identify your machine, user, or install.
- It does not call home, ever.
- It does not expire into a locked or wiped state.
- It does not involve BLCH or any token; BLCH is not a security.
- It does not claim to be audited or secure.
