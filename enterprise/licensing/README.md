<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- Copyright (c) Postern Labs and Postern community contributors -->

# @postern/licensing

Privacy-preserving, **offline-verifiable** license/entitlement library for the
Postern **Business / Corporate** editions, with a **master → sub** hierarchy.

> **Personal editions of Postern are free forever and need no license at all.**
> This library never gates personal use. There is **no telemetry and no
> phone-home** — verification is 100% local. Any paid license is billed in
> **ordinary currency (fiat)**, never in BLCH or any token/coin. BLCH is not a
> security and is not involved in licensing.
>
> **Status: SCAFFOLD, pre-production, UNAUDITED.** Not a security product. Do
> not rely on it for safety- or compliance-critical decisions without an
> independent review.

Read [`LICENSING-MODEL.md`](./LICENSING-MODEL.md) for the full, honest model.

## Tiers at a glance

| Tier | Token | Seats | Window |
|------|-------|-------|--------|
| **Personal** | none | n/a | free **forever** |
| **Business freemium** | vendor-signed master | 3 desktops | 24 months |
| **Corporate master** | vendor-signed master (needs 9-digit DUNS) | unlimited | 6 months (free now, pricing TBD) |

## Install / build

Dependency-free at runtime (uses Node's built-in `node:crypto`). Node >= 18.

```bash
npm install      # dev deps: typescript + @types/node only
npm run build    # emit dist/
npm run typecheck
```

## Library API

```ts
import {
  issue, mintSubUnderMaster, verifyChain, status, describeState,
  generateKeypair, disclosureForMaster,
} from "@postern/licensing";

// --- VENDOR side (server secret; e.g. a Cloudflare Pages Function) ---
const vendor = generateKeypair();                       // keep vendor.privateKey SECRET
const issued = issue(vendor.privateKey, {               // reused verbatim server-side
  tier: "corporate-master",
  duns: "123456789",                                    // required for corporate
});
// -> issued.masterToken            (vendor-signed; ship to the org)
// -> issued.orgMasterPrivateKey    (return to the org; server MUST NOT retain)

// --- ORG admin console (holds the org master private key) ---
const sub = mintSubUnderMaster(
  issued.orgMasterPrivateKey, issued.masterToken, "alice@acme",
);

// --- SHIPPED APP (offline; ships only vendor.publicKey) ---
const state = status({
  vendorPublicKey: vendor.publicKey,
  master: issued.masterToken,
  sub,
});
console.log(describeState(state));
// Free corporate window (corporate-master, unlimited seats, sub for alice@acme,
// DUNS 123456789) — 184 day(s) left, until 2027-01-12T…Z. Free now, pricing TBD.

// Personal edition: free forever, no token needed.
status({ vendorPublicKey: vendor.publicKey, personal: true });
// -> { state: "personal-free", tier: "personal" }
```

`status()` returns one of: `personal-free`, `valid` (business-freemium in
window), `in-eval` (corporate-master in its disclosed window), `expired`
(graceful — data untouched), or `invalid`.

## CLI

```
postern-license keygen-vendor [--out <file>]
postern-license issue    --vendor-priv <key|file> --tier <corporate-master|business-freemium> [--duns <9-digit>] [--out <file>]
postern-license mint-sub --master-priv <key|file> --master <masterToken.json> --sub <label> [--exp <unix>] [--out <file>]
postern-license verify   --vendor-pub <key|file> --master <masterToken.json> [--sub <subToken.json>]
postern-license status   --vendor-pub <key|file> [--personal] [--master <f>] [--sub <f>] [--now <iso>]
postern-license disclose --master <masterToken.json>
```

Example end-to-end (using the bundled **dev sample** public key):

```bash
node dist/cli.js issue    --vendor-priv vendor.json --tier corporate-master --duns 123456789 --out master.json
node dist/cli.js mint-sub --master-priv master.json --master master.json --sub alice@acme --out sub.json
node dist/cli.js verify   --vendor-pub keys/dev-vendor.pub.json --master master.json --sub sub.json
node dist/cli.js status   --vendor-pub keys/dev-vendor.pub.json --master master.json --sub sub.json
```

## Serverless issuance (Cloudflare Pages Function)

The signer is portable. A Pages Function reuses `issue()` with the vendor
private key stored as a secret binding:

```ts
// functions/api/issue.ts  (illustrative)
import { issue } from "@postern/licensing";

export const onRequestPost: PagesFunction<{ VENDOR_PRIVATE_KEY: string }> =
  async ({ request, env }) => {
    const { tier, duns } = await request.json();
    const issued = issue(env.VENDOR_PRIVATE_KEY, { tier, duns });
    // return issued.masterToken + issued.orgMasterPrivateKey to the org;
    // DO NOT retain the org private key.
    return Response.json(issued);
  };
```

The reference uses `node:crypto`; on Workers enable `nodejs_compat`, or port the
three key primitives to WebCrypto (`crypto.subtle` supports Ed25519). The token
format is byte-identical either way.

## Keys in this repo

- `keys/dev-vendor.pub.json` — a **clearly-marked SAMPLE / DEV** vendor public
  key, used only by the CLI demo and docs. **It is not a production key.**
- **No private key is committed.** The vendor private key is a server secret;
  org master private keys live with each customer. `.gitignore` blocks
  `*.secret`, `production*`, and `*.pem`.

## Source layout

| File | Purpose |
|------|---------|
| `src/types.ts` | Canonical payload + entitlement-state types |
| `src/encoding.ts` | base64url + **canonical JSON** (sorted keys) |
| `src/keys.ts` | raw Ed25519 keygen / sign / verify (`node:crypto`) |
| `src/token.ts` | `issue()`, `mintSub()`, `verifyChain()`, DUNS format check |
| `src/eval.ts` | calendar-month math + honest first-run disclosure |
| `src/status.ts` | offline `status()` resolver + `describeState()` |
| `src/cli.ts` | `postern-license` CLI |
| `src/index.ts` | public entry point |

## License

Dual-licensed under [MIT](./LICENSE-MIT) OR [Apache-2.0](./LICENSE-APACHE), at
your option.
