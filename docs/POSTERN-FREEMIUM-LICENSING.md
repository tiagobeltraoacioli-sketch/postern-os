<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- Copyright (c) Postern Labs and Postern community contributors -->

# Postern Labs — Freemium / Licensing Model

**Status:** DESIGN DOC / PLAN. Not a live billing system. Nothing here is deployed,
priced, or charging anyone. Everything Postern ships today is an **UNAUDITED
reference prototype** — this document describes how licensing *should* work when
there is a real product to license, not how it works now.

**Scope:** answers the founder's question — *"which apps start with a 2-year free
license and then need a key, which stay free, and which are business/enterprise-paid?"*

**Founder decision (settled):** **the personal apps ARE freemium.** Personal privacy
apps are **not** "free forever"; they get a **2-year free license → paid unlock key**.
The 2-year free period is the adoption on-ramp; after it, a key is required to keep
receiving updates and premium features. Business/enterprise stay paid as before. The
coin (BLCH) is still **never** monetized. The hard honesty rail is absolute: **the key
gates features/updates, never access to your own encrypted data.**

**Grounding:** built on what already exists in the repo:
`enterprise/licensing/LICENSING-MODEL.md` (the offline verify model + master→sub
hierarchy), `functions/license/master.js` (the DUNS-based master-license generator,
live at `/license/master`), `wrangler.toml` (the `LICENSES` KV that stores only
DUNS + dates), `packaging/` (TUF update channel + Falcon‖ML-DSA hybrid-signed
bundles), and the product catalog / status badges in `site/products.html`.

---

## 0. The decision, and its one consequence to manage

The strategic tension ("personal free for adoption" vs "2 years free then key") is
**resolved by the founder in favour of personal-freemium.** Personal apps get the
2-year-free-then-key model. This section states the model as decided and flags the one
consequence that must be handled honestly.

**The one thing to manage:** adopting personal-freemium **contradicts two things
Postern has already published** and therefore both must be updated in the same change:

1. `enterprise/licensing/LICENSING-MODEL.md`, Principle 1: *"Personal is free forever…
   no license token at all… no clock and no nag for personal users."*
2. The live site (`site/products.html`) tiers table: *"Personal — Individuals — **Free
   forever.** No login, no tracking, no telemetry, full privacy."*

For a brand whose entire pitch is honesty-by-construction, silently walking back a
published "Free forever" promise is the real risk — not the model itself. The
mitigation is to make the change **loudly and honestly**: a dated changelog entry, a
plain-language explanation ("we changed the personal model from free-forever to
2-years-free-then-key; here is exactly what that means for your data: nothing — your
vault always opens"), and the strongest possible fail-open guarantee (§4.2, §5). The
founder has accepted the adoption-slowdown risk of charging personal users; this doc's
job is to make sure it is done **without a single dark pattern.**

---

## 1. The model (decided) and the adoption trade-off (noted)

### 1.1 The tension — and its resolution

The founder's idea — *apps start with a 2-year free license, then buy a key to
unlock* — sat in tension with Postern's published stance that **personal products are
free for adoption** and revenue comes from corporate/enterprise + service lines. **That
tension is now decided: personal apps are freemium.** The 2-year free window *is* the
"free for adoption" — adoption happens during the on-ramp; the key monetizes continued
updates/premium use after it.

Mechanically this is a small change, because the "2 years free, then a key" shape
**already exists** in the repo — it is exactly the **Business freemium** tier
(`LICENSING-MODEL.md`: 3 desktops, **24 months (2 years)**, free, then a key). We are
extending that same 24-month clock + offline-key mechanism to a new **Personal
freemium** tier. Nothing new needs inventing; the verifier, the token format, and the
signing infra all carry over.

> Note: the string "Pro" in `site/build.js` is **"PinePhone Pro"** (hardware), not a
> price tier. There is no pre-existing "Pro" tier; "premium features" here means the
> post-2-year gated features of the Personal tier, not a separate SKU.

### 1.2 The trade-off, noted (decided, not re-litigated)

Charging personal users has a real cost the founder has accepted:

- **Adoption friction.** A privacy suite's moat is ubiquity; a key requirement after
  2 years slows the "everyone just installs it" flywheel versus a free-forever suite.
- **Trust optics.** Any gate on a *privacy* app invites "dark pattern" suspicion. The
  only defence is that the free tier is genuinely complete, the gate is genuinely just
  updates/premium features, and the user's data is **never** held hostage (§4.2).
- **Published-promise reversal.** Handled in §0 — must be done loudly and honestly.

These are noted, not objections. The model is decided. The rest of this doc makes it
**honest and non-hostile.**

### 1.3 The model in one line

*Personal apps = 2 years free (per-install on-ramp) → key to keep updates/premium
features; your own data always stays openable. Business = 2yr eval → key. Enterprise =
DUNS master license (unlimited seats). Services (hosted/SLA) = fiat. The coin is never
involved.*

---

## 2. Tier taxonomy

Five buckets. Every product lands in exactly one.

| Tier | Meaning | Key? | Clock |
|------|---------|------|-------|
| **Personal (2yr free → key)** | Personal privacy apps. Free on-ramp, then a key for continued updates/premium features. Data always openable. **The founder's decided freemium model.** | Personal key; gates **features/updates**, never data | **24 mo (2 yr)** per-install first-run, then key |
| **Free forever (platform / dev / participation)** | The platform, dev tooling, distribution infra, and node participation that must stay frictionless for the ecosystem to exist. Not an app you license. | **None** | None |
| **Business (eval → key/subscription)** | Small-team / commercial use. Vendor-signed master, no DUNS. | Vendor-signed master token | **24 mo (2 yr)**, then key |
| **Enterprise (DUNS master license)** | Company with a DUNS number. Unlimited seats from one master, split into sub-tokens locally. The primary revenue line. | Vendor-signed master + org sub-tokens | **6 mo** free eval (pricing TBD), then license |
| **Not-a-product** | The ownerless base, the worthless coin, and zero-value scaffolds. Never sold, never licensed. | N/A | N/A |

Tier values in the token: `personal` (NEW) / `business-freemium` / `corporate-master`.
The old `personal-free` (no token) state is retired for the freemium apps; it survives
only for the Free-forever platform/dev bucket, which genuinely ships no token.

---

## 3. Tier table — every product categorized ("quais?")

Legend: 🟢 Personal freemium (2yr→key) · ⚪ Free forever (platform/dev) · 🟠 Business · 🔴 Enterprise · ⚫ Not-a-product

### 3.1 Product cores (the verified Rust foundations, `crates/postern-*`)

| Product | Tier | One-line rationale |
|---------|------|--------------------|
| Postern Wallet | 🟢 Personal freemium | Flagship personal PQ wallet; 2yr free, then key for continued updates. Your keys/coins always remain accessible and exportable. |
| Postern Vault | 🟢 Personal freemium | Personal secrets vault; freemium. Decrypt/export of your own vault always works, key or not. |
| Postern Courier | 🟢 Personal freemium | Serverless P2P file drop; freemium personal utility. |
| Vestnik (personal messenger) | 🟢 Personal freemium | Personal E2EE messenger; freemium. (The *org-run* messaging build is 🔴 — see 3.4.) |
| Postern Seal Companion | 🟢 Personal freemium | Attestation verifier; freemium. Verifying already-installed apps must keep working in grace mode. |
| Panic Lock | 🟢 Personal freemium | Safety feature; freemium — but the panic/re-lock action itself must **always** fire, even expired (safety ≠ premium). |
| Postern Keys | 🟢 Personal freemium | Passkey/FIDO2 core; freemium. Existing credential decrypt/export always works. |
| Postern Hygiene | 🟢 Personal freemium | Metadata scrubbing; freemium personal privacy tool. |
| Postern Quarantine | 🟢 Personal freemium | Inbound-document safety (Hygiene's mirror); freemium. |
| Postern Tor | 🟢 Personal freemium | In-process Tor (Arti); freemium as bundled with the personal apps. |
| Postern Telephony | 🟢 Personal freemium | Carrier SMS/calls surface for OS Mobile; freemium personal app. |
| Postern Core | ⚪ Free forever | The one canonical seal (XChaCha20-Poly1305 + Argon2id); shared infra embedded in every app, not separately licensed. |
| Postern SDK | ⚪ Free forever | Build-on-Postern developer surface; public by policy — a licensed SDK would strangle the ecosystem. |
| postern-trail | ⚪ Free forever | Shared hash-chained audit trail; embedded infra, not sold separately. |
| postern-policy | ⚪ Free forever | Shared consent kernel; embedded infra, not sold separately. |

### 3.2 Reference front-ends (self-contained apps)

| Product | Tier | One-line rationale |
|---------|------|--------------------|
| Sotto | 🟢 Personal freemium | Personal voice assistant (BYO-Claude-key); freemium. |
| Vedetta | 🟢 Personal freemium | Personal markets lookout; freemium. |
| Tolmach | 🟢 Personal freemium | Personal interpreter / minutes taker. A `tolmach-subscription` branch already anticipates this; any *hosted* transcription is additionally a 🟠 service line. |
| Chiave | 🟢 Personal freemium | Wallet-as-login identity UX; freemium. |
| Sarto | 🟢 Personal freemium | Onboarding configurator; freemium. Note: onboarding must run even before/without a key so a new user can set up. |
| Yagabona | 🟢 Personal freemium | Personal scheduled-task daemon; its automation is a natural post-2yr premium feature. |
| Izbushka | 🟢 Personal freemium | The task portal into Yagabona; freemium companion. |
| Ezekiel 1 — Personal | 🟢 Personal freemium | Household parental controls; freemium. (Was "free for personal use"; now the on-ramp then key — update its in-product copy.) |
| Postern Wallet — mobile | 🟢 Personal freemium | Touch-first personal wallet face; freemium; moves no real funds. |
| Postern Store | ⚪ Free forever | App-discovery front-end over Depot; the storefront must be free so users can *find and install* the freemium apps. |

### 3.3 Android security shells / OS / platform

| Product | Tier | One-line rationale |
|---------|------|--------------------|
| Porog (Postern Container) | 🟢 Personal freemium | Personal hardened-workspace door; freemium personal security app. Enterprise *management* of it rides 🔴 Shield. (Concept scaffold today.) |
| NoporIS (dual-persona bridge) | 🟢 Personal freemium | Personal Google-Play-persona separation; freemium. (Concept scaffold today.) |
| Sloboda (Tor egress rail) | 🟢 Personal freemium | Personal "data leaves the sealed base" rail; freemium. |
| Kalinov Bridge (Encrypted Backup on Filecoin) | 🟢 Personal freemium | Client-side sealed personal backups; freemium — and **critical fail-open case: restoring/decrypting an existing backup must always work** even without a key. **Hosted** access is additionally a 🟠 convenience service line. Design/spec today. |
| Postern OS — Desktop | ⚪ Free forever | The daily-driver privacy OS *platform*. A Linux distro is the on-ramp itself; charging for the OS would gate the very ground the freemium apps run on. Keep the platform free; monetize the apps on it. |
| Postern OS — Mobile | ⚪ Free forever | Wallet-first phone OS platform; free for the same reason as Desktop. |
| Postern OS — Node appliance | ⚪ Free forever | Running a node is **participation in the ownerless base**, not a purchase; must stay free. |
| Postern Browser | ⚪ Free forever | Hardened browser shipped inside OS Desktop; part of the free platform. |
| Terem (OS portal v2) | ⚪ Free forever | Run foreign apps/OSes in VMs from the sealed base; a platform/virtualization capability of the OS. Default attested build ships zero GPL-linked code; QEMU/Wine paths opt-in/user-fetched. |
| Depot (update + app channel) | ⚪ Free forever | Self-hosted, F-Droid-style distribution infra (TUF + PQ signing + CRL). The distribution rail must be free; the *enterprise* signed/notarized build channel is 🔴 (see 3.4). |

> **Judgment call flagged for the founder:** the OS images, node appliance, SDK, Store,
> and Depot are placed in **Free forever (platform/dev)** rather than Personal freemium.
> Rationale: these are the *ground* the freemium apps stand on — gating the platform or
> the storefront would choke the on-ramp that makes the app keys valuable. If the
> founder instead wants the **OS itself** to be freemium too, move the three OS rows to
> 🟢; the mechanism is identical. SDK/Store/Depot/node should stay free regardless.

### 3.4 Business & enterprise editions (the revenue)

| Product | Tier | One-line rationale |
|---------|------|--------------------|
| **Business freemium bundle** | 🟠 Business (2yr → key) | Up to 3 desktops, 24 months, no DUNS, then a key. The commercial-use sibling of the personal freemium tier. |
| Ezekiel 1 — Business | 🟠 Business | Access-governance engine (Bell-LaPadula / Brewer-Nash / tenant isolation); commercial-use tool. |
| Consiglio (enterprise admin console) | 🟠 Business → 🔴 Enterprise | Mints/manages org sub-tokens + RBAC; the hinge between Business and Enterprise. |
| Gramota / Gramota-KYC | 🟠 Business | Org-level onboarding/diligence — **never user-KYC** (constitutional). A B2B compliance tool. |
| Vestnik — org/enterprise messaging | 🔴 Enterprise | Employer-run E2EE messaging with retention/DSAR/audit; bodies E2EE, metadata org-visible (disclosed). |
| **Corporate master license** | 🔴 Enterprise (DUNS) | DUNS company; **unlimited users** from one master token, split locally, offline-verified. 6-mo free eval, pricing TBD. The primary revenue engine. |
| Postern Shield (BYOD) | 🔴 Enterprise | Reach the corporate Linux system from a personal phone; leaving the container loses corporate-data access. Never surveils the personal side. |
| Postern DLP | 🔴 Enterprise | Data-loss-prevention controls for the corporate deployment. |
| Cloud edition (Chiostro hosted / managed node) | 🔴 Enterprise (service line) | Opt-in, **business-only** hosted option; sells convenience + ops, not privacy. Personal editions never move to the cloud. Fiat; running it makes Postern a data processor (DPA required). |
| Enterprise support / SLA / signed build channel | 🔴 Enterprise (service line) | The §9 revenue line: deployment tooling, notarized build channel, priority/SLA support. Sells work + assurance, never data, never the coin. |
| RWA (real-world-asset settlement) | 🔴 Enterprise (service line, gated) | Owned Layer-2 product; state only in the owned layer, roots anchor to the base. `LegalGate::NotObtained` is the only constructible value; legal review is a HARD gate. Not offered now. |
| BaaS (blockchain-as-a-service) | 🔴 Enterprise (service line, gated) | N isolated tenant kernels, one batch anchor per tx. Legal review is a HARD gate. Not offered now. |

### 3.5 Not-a-product (ownerless base / worthless coin / zero-value scaffolds)

| Item | Tier | One-line rationale |
|------|------|--------------------|
| Bloch base protocol / consensus | ⚫ Not-a-product | **Ownerless** — no owner, no authority, pure PoW. Cannot be licensed or sold by anyone. |
| BLCH coin | ⚫ Not-a-product | Worthless by design, **never sold**, not a security. Revenue never touches it. |
| FFG-BFT finality overlay | ⚫ Not-a-product | Protocol overlay anchored to the ownerless base; not a product to license. |
| Bloch L2 (EVM) / wBLCH / PosternDex | ⚫ Not-a-product | Unaudited zero-value scaffold; testnet; native gas is bridged BLCH (zero issuance, never sold). RWA/BaaS built **on** the L2 are the 🔴 service lines; the rail itself is not sold. |
| bloch-pool (reference mining pool) | ⚫ Not-a-product | Strictly optional reference software; "never touches Postern's revenue, never sells or lists the coin." |

---

## 4. The key mechanism (honest, privacy-preserving)

Reuse the machinery that already exists — do not invent a second system.

### 4.1 What a key is

An **offline-verifiable license blob**: canonical JSON payload + a detached signature,
verified locally by an **embedded vendor public key** shipped in the app. **No
phone-home, no license server, no account, no telemetry** — for enforcement or
analytics (`LICENSING-MODEL.md`, Principle 2).

Two signing layers already exist and each keeps its job:

1. **License tokens** (`enterprise/licensing/` + `functions/license/master.js`):
   Ed25519, master → sub hierarchy. The **vendor private key** (Cloudflare Pages
   secret `VENDOR_PRIV_PKCS8_B64`) signs a **master** token; the org's own master key
   mints **sub** tokens locally; apps verify offline with the vendor public key. For
   **personal** keys there is no org layer — the vendor signs a single personal token
   directly (no sub-hierarchy, no DUNS).
2. **Package / update signing** (`packaging/`): Falcon-1024 ‖ ML-DSA-87 **hybrid PQ**
   detached signatures over release manifests, distributed via a **TUF** channel
   (`postern-tuf`). This is the natural basis for the *signed-update entitlement* a
   key grants after the free window, and it future-proofs the license blob itself.

Recommended token shape (superset of today's payload, so the existing verifier extends
rather than gets replaced):

```json
{
  "v": 1,
  "typ": "personal",               // personal | master | sub
  "product": "postern-suite",      // NEW: which product/bundle this entitles
  "tier": "personal",              // personal | business-freemium | corporate-master
  "duns": null,                    // 9 digits for corporate; null for personal/business
  "seats": 1,                      // 1 personal / 3 business / "unlimited" corporate
  "holder_hash": "b64(SHA-256(salt || buyer-email))",  // NEW: privacy ref, NOT the email
  "iat": 1783887646,               // issued-at, unix seconds
  "exp": 1799785246,               // expiry (see §4.4 for the personal clock)
  "master_pub": "…"                // org master pubkey (master tokens only; absent for personal)
}
```

- `holder_hash` is a **salted hash**, never the raw identity — a buyer can prove a key
  is theirs and support can dedupe, without the token carrying PII. The `LICENSES` KV
  already stores "only DUNS + issue/expiry — no PII" (`wrangler.toml`); keep that
  discipline for personal keys too (store a salted hash + dates, never an email).
- For **PQ keys**, sign the same canonical bytes with the Falcon‖ML-DSA hybrid signer
  from `crates/postern-release` (AND-of-both legs; one corrupted leg rejects the pair).
  The token **format** is identical across Ed25519 and PQ; any port MUST produce
  byte-identical canonical JSON so signatures cross-verify.

### 4.2 Verification: fail **OPEN**, never lock the user out of their own data

The non-negotiable rail for a privacy suite — and the load-bearing promise that makes
personal-freemium honest. `verifyChain()` / `status()` already report **authenticity
and time separately**: an authentic-but-expired token maps to `expired`, not `invalid`.
Build the app on top of that:

```
status == personal (in window) → full app                        (in the 2yr on-ramp OR keyed)
status == valid                → full features                   (in-window Business)
status == in-eval              → full features + "free now, pricing TBD" (Corporate eval)
status == expired              → GRACE MODE:
                                   • decrypt · open · READ · EXPORT your data → ALWAYS WORK
                                   • Panic Lock / re-lock / safety actions    → ALWAYS WORK
                                   • create-new · premium features · signed updates → gated
                                   • polite renewal notice; data untouched
status == invalid / no token   → behave no worse than grace mode; never a lockout
```

Concretely, for **personal-freemium after 2 years with no key**: the app enters a
**read-only / grace mode**. You can still **decrypt, read, and export** every vault,
wallet, credential, message, and backup you already have. What the key gates is
*continued updates, new-item creation, and premium features* — **never access to your
own encrypted data**. A privacy app must never hold the user's data hostage. This is
already the documented intent ("It does not expire into a locked or wiped state" —
`LICENSING-MODEL.md`); personal-freemium makes it a hard, tested product requirement.

### 4.3 Issuance — how a buyer gets a key

**Personal:**
1. The app is a **free download**; the 2-year window starts at first run (§4.4), no
   purchase needed to begin.
2. To keep updates/premium features after (or before) expiry, the user buys a personal
   key on the site. A Pages Function calls `issue()` for `tier: "personal"`
   (`seats: 1`, `duns: null`), signs it with the vendor key, and returns the token.
   The site stores only a salted `holder_hash` + dates in `LICENSES` KV.
3. The user drops the token into the app; it verifies **offline** against the embedded
   vendor public key. Nothing phones home.

**Business / Corporate (unchanged from today):**
- **Business freemium:** no DUNS; `issue()` mints a master (`seats: 3`,
  `exp = iat + 24mo`) + the org's master **private** key over a secure channel; the
  site retains only dates, never the private key.
- **Corporate master:** 9-digit DUNS; `seats: "unlimited"`, `exp = iat + 6mo`. The org
  mints **sub** tokens locally via Consiglio. **Honest TODO:** DUNS is **format-checked
  only** today — real Dun & Bradstreet verification is not performed. A
  `license/crl-dnb-backend` branch + a reference **CRL/revocation endpoint** exist
  (merged, not yet deployed).

**Payment** is **ordinary fiat**, fully out of band from crypto. Never priced in, paid
in, or tied to BLCH (Principle 5). *No billing integration exists yet — this is the
plan.*

### 4.4 The 2-year clock

- **Personal freemium — per-install first-run clock.** A free download has no issuance
  event, so the 24-month window **starts at first run** on that install and is stored
  locally; the start and end are **disclosed at first run** (Principle 3;
  `disclosureForMaster()` already does up-front disclosure for tokens). A local clock
  is user-resettable — that is acceptable **only because expiry fails open to grace
  mode** (§4.2): "cheating the clock" just returns a read-only-plus-your-data state, so
  there is little to gain and nothing hostage. Once the user buys a key, the clock
  switches to the signed, tamper-evident **issued-at** `exp` in the token.
- **Business / Corporate — issued-at clock.** `exp` is baked into the signed token at
  issuance (`iat + 24mo` business / `iat + 6mo` corporate). Simple and tamper-evident
  because it is signed; matches today's model.

Either way: the window's **start and end are disclosed up front**, and expiry is
**graceful** — never a lockout.

---

## 5. Honest guardrails (the non-negotiables)

1. **Revenue never touches BLCH.** All licensing (personal keys, business, enterprise,
   services) is fiat, fully out of band from the coin. BLCH is worthless by design,
   never sold, not a security, never involved in licensing.
2. **The free window is a real product, not crippleware.** During the 2-year on-ramp
   the personal app is complete and private — no login, no telemetry, no nag. The key
   gates only *continued updates + premium features* after the window; it may never
   subtract from what the app did during the free window.
3. **A missing/expired key must NEVER brick access to your own data.** Decrypt, read,
   and export always work — for every app, in every state — and safety actions (Panic
   Lock, re-lock) always fire. The key gates features/updates, never your vault,
   wallet, credentials, messages, or backups. **Fail open, never closed.**
4. **No surveillance, ever.** Verification is 100% local/offline. No phone-home, no
   license server, no per-user account, no usage tracking — enforcement or analytics.
   Personal keys store only a salted hash + dates, never an email or PII.
5. **The published "Free forever" promise must be corrected honestly and loudly.**
   Updating personal from free-forever to freemium reverses a live promise in
   `LICENSING-MODEL.md` and `products.html`. Ship the change with a dated changelog, a
   plain-language "what this means for your data: nothing" note, and grandfathering
   consideration for existing installs (recommended: honour a full 2-year window from
   the changeover date for anyone who installed under "free forever").
6. **Everything is UNAUDITED reference-prototype today.** This is a *plan*, not a live
   billing system: no payment integration, DUNS format-checked only, CRL endpoint
   merged-not-deployed, dev keys only. Do not present any of this as production.
7. **Honesty by construction stays.** Every published status badge (built vs designed
   vs reference-prototype, "unaudited" on everything) stays. Pricing pages carry the
   same honesty the product pages do.

---

## 6. Open TODOs before any of this is real

- **Update the stance docs + site** to personal-freemium: `LICENSING-MODEL.md`
  Principle 1, the `products.html` tiers table, and add the `personal` tier + grace
  mode to the model. Do it loudly (changelog + plain-language note), per §5.5.
- **Fiat billing integration** — none exists; pick a fiat processor, keep it fully out
  of band from BLCH.
- **Personal key issuance path** — extend `functions/license/master.js` (or a sibling
  `functions/license/personal.js`) to mint `tier:"personal"` tokens; store only a
  salted hash + dates in `LICENSES` KV.
- **Grace-mode implementation + tests** in every personal app — assert decrypt/export
  and safety actions work with an expired/absent key (the hard fail-open guarantee).
- **Per-install first-run clock** with up-front disclosure for the personal free
  window.
- **Real DUNS/D&B verification** at issuance/renewal (today: format-check only).
- **Deploy the CRL/revocation endpoint** as a durable, server-signed store (today:
  in-memory reference, keyed by token-signature hash, not signed, not deployed).
- **Extend the token schema** with `product` + `holder_hash` and re-pin golden vectors
  so Ed25519 and Falcon‖ML-DSA ports cross-verify byte-for-byte.
- **Wire real update-channel entitlement** to the `packaging/` TUF channel (today:
  `createUpdaterArtifacts = false`; dev keys only; no live endpoint).
- **Legal review** (HARD gate) for Cloud edition (data-processor / DPA), RWA, BaaS, and
  any compliance claim (LGPD/GDPR are adherence-by-design, **not certified**).

---

*Design doc only. No billing code, no deployment. Unaudited, pre-production. The coin
is not a security; Postern's revenue never touches it.*
