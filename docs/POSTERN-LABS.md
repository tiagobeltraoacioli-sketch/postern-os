# Postern Labs (products) ⟂ Bloch-SIS-PoW (ownerless protocol)

Two things, deliberately separate and owned differently:

- **Bloch-SIS-PoW** — an **ownerless protocol**. No owner, no curator, no official
  website, no official explorer. It exposes **RPCs / APIs**, and that's it — like
  Bitcoin: the protocol is public infrastructure; third parties build tools on it
  (an explorer is like mempool.space, not "Bitcoin's explorer"). The author of
  this repo is **not the owner** of the protocol; a community may steward it later.
- **Postern Labs** — a **product company** (the BlackBerry model: sells privacy +
  security software). It **owns its products**, which are **totally rebranded away
  from "Bloch"**. All products — up to and including the wallet and the explorer —
  are Postern Labs.

```
┌────────────────────────  POSTERN LABS  (owned products, rebranded) ─────────────┐
│  privacy/security on permissive Linux, parameterizable, attestable — sold.       │
│  entry: a privacy/security CONTAINER on the Android you already own;              │
│  deeper: a full privacy OS (desktop + mobile); a wallet; an explorer; a TEE seal.│
└──────────────────────────────┬─────────────────────────────┬────────────────────┘
              (wallet/explorer)  │  consume the protocol       │  the OSes/container
                                 │  via RPC/API                │  are independent
┌──────────────────────────────▼─────────────────────────────▼────────────────────┐
│                  BLOCH-SIS-PoW  (ownerless protocol — RPC/API only)               │
│   SHAKE-256 hashcash PoW (Module-SIS gate) · Falcon‖ML-DSA · GhostDAG-Q ·         │
│   Coherence · the coin                                                             │
│   No owner. No curator. No official site or explorer. Just the protocol.          │
└───────────────────────────────────────────────────────────────────────────────────┘
```

## Bloch-SIS-PoW — the protocol (no owner, no site)

Public infrastructure. It ships as software + a documented **JSON-RPC / API**
surface (chain state, blocks, mempool, addresses, submit-tx, attestation, …).
There is **no official website, no official explorer, no foundation, no curator**,
and — for now — **no owner**. Tools that read it (explorers, dashboards) are
independent products, exactly as mempool.space is an independent product on top of
Bitcoin. If a community forms to steward the protocol, good; it is not steered by
Postern Labs and not by the author.

## Postern Labs — the products (owned, rebranded)

Postern Labs is the company. Its products are **rebranded — no "Bloch" in their
names** (that word belongs to the protocol, not to a product). They earn their
value as **security/privacy products** — you buy/use them for the protection, not
to mine or hold a token. Adoption is low-friction first: a **container on existing
Android**, then a full **privacy OS** for those who want to go all the way.

### Portfolio (names below are PROVISIONAL — Postern's branding decision)

| Product (provisional name) | What it is | Consumes the protocol? |
|---|---|---|
| **Postern Container** (Android) | hardened, isolated, attestable privacy workspace on the phone you already own — sensitive apps/data/comms sealed off. The entry product. **Design: `docs/specs/POSTERN-CONTAINER.md`.** | no |
| **Postern OS — Desktop** | daily-driver privacy Linux (reproducible, hardened, LUKS, private-by-default) — "personalized Linux" | no |
| **Postern OS — Mobile** | privacy phone Linux — **adds privacy/security to the device; does not reward the user** | no |
| **Postern Seal** (TEE/attestation) | the integrity proof: reproducible build + hardening + TEE attestation (`os_roothash` / SEV-SNP) — proves a device runs the *genuine* Postern build | no (bridges) |
| **Postern Wallet** | post-quantum hybrid wallet (Falcon‖ML-DSA), diversified addresses, on-device key vault | **yes** (RPC/API) |
| **Postern Explorer** | an explorer/dashboard product on the protocol's RPC/API — like mempool.space for BTC | **yes** (RPC/API) |

Differentiator vs GrapheneOS / RedHat / Ubuntu: **reproducible + remotely
attestable** — a Postern product can *prove* it's the genuine, unmodified build.

### App roadmap (on the OS + container)

Beyond the OS/wallet, the apps that fill it out — ordered, all-permissive, with
honest limits — live in **`docs/POSTERN-APPS-ROADMAP.md`**:

1. **Tor/VPN layer** (now) — Arti + boringtun; the container's dependency.
2. **Document & media hygiene** (next) — scrub metadata by default, prove/seal by
   opt-in; the most ethos-defining app (metadata is the leak nobody fixes).
3. **Matrix messenger** (next) — a fresh Apache client on `matrix-rust-sdk` +
   `vodozemac` (never fork AGPL Element); classical-E2EE + metadata limits stated.
4. **Postern Vault** (next) — a secrets manager reusing the wallet's TEE vault.
5. **Encrypted backup** (later); office editing = aggregate unmodified LibreOffice
   (MPL, flagged), **never fork Apache OpenOffice** (red security status).
6. **Matrix-federation interop + external Bridges tab** (design —
   `docs/specs/POSTERN-MESSAGING-INTEROP.md`) — the messenger joins the open
   Matrix network with Megolm E2EE preserved; Telegram/WhatsApp/Signal reach is
   transitive via an **opt-in, plaintext-disclosed** Bridges tab (bridge **NOT
   operated by Postern** — user-hosted mautrix). Caveat: bridged messages are
   readable by the bridge and the external service, and metadata leaks to it —
   the tab says so persistently; full federation is substantial Phase-1+ work.

## "Useful PoW" — precisely

- **As a business** — yes: the useful thing is the **security/privacy value sold to
  clients** (BlackBerry model). Real, monetizable.
- **As consensus** — no: Bloch-SIS-PoW's mining work stays *arbitrary-but-secure* —
  a post-quantum SHAKE-256 hashcash (cumulative work) with a Module-SIS structural
  gate. Making the mining computation "useful" is a research graveyard;
  we don't claim it.
- **The honest bridge**: attestation as **proof of useful privacy *service*** —
  Postern Seal proves a device runs the genuine product. A **product seal** needs no
  token; **optionally** the protocol could recognize genuine privacy infrastructure,
  but only bound to **unique hardware** (TEE/StrongBox/Secure Enclave) to resist
  Sybil, and it is an incentive/attestation layer, **not** the consensus PoW.

## Honesty

- Protocol: **ownerless, RPC/API-only**, **mainnet beta — a designation, not a
  security claim**: unaudited (third-party audit contracted, **not done**), very
  few nodes / low hashrate → **51%-attackable**; the **relaxed regime (k=4)
  currently applies** — work is trivially forgeable. The k=8 hardening was
  activated at block 213,000 but **reverted**: it multiplied mining difficulty
  ~4096x and the current solo / low hashrate could not find blocks, so the
  chain stalled. k=8 will **re-activate together with a matched difficulty
  reduction** (so block time stays ~30s); until then, no security is claimed.
  The coin is not a security and not an asset — no sale, no listing,
  no price; 17% founder premine disclosed.
- Products: today they are **foundations** (reproducible/hardened/attestable NixOS
  + Mobile NixOS profiles + the wallet). The full daily-driver OS + the Android
  container are **to build**. Product names here are **provisional** — Postern's
  call.
- Claims for the protocol and for the products are **separate** and each
  **audit-gated**.

## Follow-through once names are set

- Rebrand the product artifacts (the OS profiles, wallet, explorer, the deck/site)
  away from "Bloch".
- Keep the protocol repo (node/PoW/consensus/Coherence) free of product/site
  material; move products under a Postern Labs group as independent projects that
  consume the protocol via its RPC/API.
