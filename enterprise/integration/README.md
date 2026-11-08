<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs -->

# @postern/enterprise-integration

Reference integration that wires the four Postern **enterprise reference
prototypes** together **end-to-end** — without editing any of them.

> **Status: SCAFFOLD / reference prototype — UNAUDITED, pre-production.** Not a
> security product. Do not rely on it for safety- or compliance-critical
> decisions without an independent review.

It consumes each sibling module through its **public exports only** (see
[`src/siblings.mjs`](./src/siblings.mjs)) and adds the **adapters** and
**orchestration** the seams need. Nothing here forks or modifies a sibling.

```
posternlabs.com (vendor)                 provisionOrg()      [licensing.issue]
   │ signs a MASTER token (Ed25519, offline-verifiable)
   ▼
ORG ADMIN CONSOLE                        createEnterpriseConsole()
   │ ONE license gate  ── verifyChain() ──►  features.createLicenseGate
   │ sub-access manager ─ verifyChain()/mintSub ─► features.createSubAccessManager
   ▼
ONE SUB IDENTITY per person              mintIdentity()
   ├── Bloch roster membership   (comms.createCommsOrg — enterprise-only, fail-closed)
   └── SHIELD access grant       (shield.createShieldContainer + createAccessBroker)
```

## What the integration adds

| Piece | File | Bridges |
|-------|------|---------|
| **License adapters** | [`src/license-adapter.mjs`](./src/license-adapter.mjs) | licensing `verifyChain()` → the console gate, the comms sub-access `mintSub`/`verifyChain`, and the shield Consiglio sub-token challenge |
| **Disclosure adapter** | [`src/disclosure-adapter.mjs`](./src/disclosure-adapter.mjs) | `transparencyNotice()` (shield-dlp + comms-compliance schemas) → the flat `disclosure()` hook the container/app transparency panels render |
| **Shared identity flow** | [`src/identity.mjs`](./src/identity.mjs) | one master → sub identity that unlocks **both** comms and shield, and one `revokeIdentity()` that de-provisions **both** |
| **End-to-end wiring** | [`src/index.mjs`](./src/index.mjs) | `wireEnterprise({ orgName, duns })` assembles the whole suite behind one call |

## Run it

```bash
node --check src/*.mjs self-check.mjs      # syntax
node self-check.mjs                        # end-to-end flow against the REAL modules
```

The self-check proves the headline invariant:

> **install master → mint sub → sub unlocks comms + shield → revoke → both refuse.**

plus the fail-closed rails (a master presented against the wrong vendor key never
verifies and the enterprise-only messenger refuses to run; a tampered sub token
is rejected by the offline chain; garbage input fails closed to `null`).

## Rails (inherited from every module, never bent here)

- **Personal is free and never gated.** This layer only ever touches the
  enterprise apps; personal apps and personal data are out of scope by
  construction.
- **Offline verification.** Every authenticity decision routes to the licensing
  lib's `verifyChain()` — no telemetry, no phone-home.
- **Fail-closed everywhere.** A token that does not verify is **never** reported
  as "licensed". Bad signature / bad DUNS / expired / unparseable all collapse to
  a negative verdict.
- **Honest employer-visibility / BYOD disclosures preserved.** The transparency
  banners still say plainly what an employer can and cannot see; never "100%
  private".
- **The coin is not a security** and buys no software. Any paid license is fiat,
  pricing TBD. Adherence-by-design, **not** certified.

## Layout

```
integration/
├── package.json
├── README.md
├── LICENSE-MIT / LICENSE-APACHE   (dual-licensed, at your option)
├── self-check.mjs                 end-to-end harness (real modules)
└── src/
    ├── siblings.mjs               single public-export surface of the 4 modules
    ├── license-adapter.mjs        verifyChain() → console + comms + shield gates
    ├── disclosure-adapter.mjs     transparencyNotice() ↔ disclosure()
    ├── identity.mjs               master → sub → comms + shield; revoke both
    └── index.mjs                  public barrel + wireEnterprise()
```

## License

Dual-licensed under [MIT](./LICENSE-MIT) OR [Apache-2.0](./LICENSE-APACHE), at
your option.
