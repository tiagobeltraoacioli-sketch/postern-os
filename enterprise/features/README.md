<!--
SPDX-License-Identifier: MIT OR Apache-2.0
SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
-->

# Postern Business/Enterprise — features layer

> **Honest status: design / reference prototype. Unaudited. Pre-production.**
> Not a certified security product. Nothing here ships as-is. Labels below say
> what is *built* (pure JS logic, test-verified here) vs *designed* (the console UI).

This directory is the **additive** enterprise feature layer that sits on top of
the free personal Postern app suite. It is **framework-free, dependency-free,
offline**, and implements **no cryptography**. The real license verification and
signing live in another developer's library (`enterprise/licensing/`); this layer
does **not** import it — it plugs into documented `verify()` / `mintSub()` /
`verifyChain()` interfaces, and ships an honest, clearly-labelled demo stand-in so
the console is explorable without the real signer.

## The one rail that never bends

**The personal app suite is free and unrestricted, forever.** Enterprise policy
is strictly **additive** — it can only *add* org-managed capabilities (managed
config, SSO, audit export, fleet defaults). It can never disable a personal app,
read a person's personal-app data, or lock anyone out of their own device.
`org-policy.mjs :: assertAdditive()` enforces this and throws on any attempt to
smuggle an app-disable into policy. (See test #5 in `self-check.mjs`.)

## Access & licensing model

| Tier | Who | Seats | Window | Login / account |
|------|-----|-------|--------|-----------------|
| **Personal** | anyone | — | free forever | none — no login, no account, no tracking |
| **Business freemium** | any org | up to **3 desktops** | **2 years** free | none — no per-user login |
| **Corporate master** | company w/ **DUNS** | **unlimited** | **6-month** evaluation | none — offline master token, no per-user login |

- A corporate org mints **one vendor-signed master token** (+ its master private
  key) on posternlabs.com. Importing it unlocks unlimited users for the eval,
  **verified offline** against the licensing lib's public key.
- The master holder mints **sub tokens** (signed by the org's master key) for
  users/teams — unlimited subs, each with **`sub.exp ≤ master.exp`**. A sub-user
  installs their token; the app verifies the offline chain **vendor → master →
  sub**. No server, no per-user account, no telemetry.
- After the evaluation, a paid **fiat** license is required — for the enterprise
  features only, never for the personal apps or your data. Pricing is still being
  structured. **Never a coin; the coin is not a security and buys no software.**

## Files

| File | What |
|------|------|
| `app-catalog.json` | the personal suite + the additive enterprise features each app can opt into |
| `org-policy.mjs` | pure policy model: `emptyPolicy`, `evaluatePolicy`, `assertAdditive` (the additive boundary) |
| `license-hook.mjs` | licensing NOTICE + `createLicenseGate()` (freemium vs corporate-master); offline `verify()` plugs in |
| `sub-access.mjs` | `createSubAccessManager()` — mint / list / revoke / export subs; `mintSub()`/`verifyChain()` plug in; enforces `sub.exp ≤ master.exp` |
| `privacy.mjs` | honest privacy statement (machine-readable + `privacyText()`) |
| `self-check.mjs` | dependency-free smoke test / demo (`node self-check.mjs`) |
| `LICENSE-MIT`, `LICENSE-APACHE-2.0`, `NOTICE` | dual license |

The admin **console UI** that consumes this layer is
`apps/postern-enterprise/console.html` (self-contained HTML). The governance
console (`apps/postern-enterprise/index.html`, "Consiglio") links to it.

## Privacy (same standard as the personal apps)

The only possible network call is an operator's **own** optional Claude request.
**No telemetry, no phone-home.** Master/sub tokens verify **offline**. There is no
per-user account and no per-user login. The one honest wrinkle vs a purely
personal app: an org admin console keeps an **audit trail of admin actions** — and
says so, in the console. We do **not** claim "100% private" or "unhackable".

## Run the checks

```sh
node enterprise/features/self-check.mjs   # 19 checks, exits non-zero on failure
node --check enterprise/features/*.mjs     # syntax
```

## Plugging in the real licensing library

Inject the licensing lib's functions; do not modify this layer's code:

```js
import { createLicenseGate } from "./license-hook.mjs";
import { createSubAccessManager } from "./sub-access.mjs";

const gate = createLicenseGate({ masterToken, verify: lib.verify });          // offline
const mgr  = createSubAccessManager({ master, mintSub: lib.mintSub,           // Ed25519, from the lib
                                      verifyChain: lib.verifyChain });        // vendor→master→sub
```

In `console.html` the same hooks are read from `window.PosternLicense`
(`.verify`, `.mintSub`, `.verifyChain`); absent those, an **unsigned demo**
stand-in runs and is labelled as such in the UI.
