# Postern Labs

> Privacy & security software, sold the honest way — the BlackBerry model, on permissive Linux.

**Postern Labs** builds owned, rebranded privacy/security **products** — a
reproducible phone & desktop OS, wallets, a secrets vault, post-quantum file
drop, a messenger, passkeys, metadata scrub, a panic lock, voice tools, and an
app store — on top of an **ownerless, post-quantum protocol** it does not own.

You pay Postern for protection, support, and provable integrity — **never for a
coin**. The base protocol is a neutral commons; the tools built on it have
owners, like Bitcoin and the apps built around it.

- **The protocol (ownerless):** Bloch-SIS-PoW — a post-quantum, pure-PoW BlockDAG
  L1. It lives in its own repository and is consumed here as a git dependency:
  `gitlab.com/blochsispow-group/BlochSISPoW-project`. No owner, no foundation,
  no official site — software + a documented RPC/API surface, and nothing more.
- **The products (this repo):** owned by Postern Labs, fully rebranded away from
  "Bloch", permissively licensed (MIT / Apache-2.0 / BSD — never GPL/AGPL
  embedded).

---

> ## ⚠️ Honest status — pre-mainnet, audit-gated, **not shipping**
> Everything here is **pre-production**. The Rust product **cores** are built and
> test-verified; the **UIs, OS images, and cloud/enterprise editions are designs
> and reference prototypes** (each labelled where it appears — *built* vs
> *designed*). The underlying protocol runs a **zero-security testnet** and is
> **unaudited**. Nothing is a certified security product yet.
>
> **The coin is not a security and not an asset.** No token sale, no listing
> effort, no market-making. Disclosed in full: a **17% founder premine**
> (10-year cliff, 40-year vest), structurally passive — the single fact a skeptic
> weighs against "ownerless", kept visible on purpose. See
> [`docs/EVOLUTION.md`](./docs/EVOLUTION.md).

---

## What's here

**Product crates** (`crates/postern-*`) — the verified Rust cores:

| Crate | What it is |
|---|---|
| `postern-core` | the one canonical seal — AEAD (XChaCha20-Poly1305) + Argon2id KDF |
| `postern-vault` | secrets/password vault, sealed at rest |
| `postern-courier` | serverless person-to-person file drop, **hybrid ML-KEM‖X25519** payload seal (Tor onion transport planned, not yet shipped) |
| `postern-messenger` | Megolm-based messaging core |
| `postern-seal-companion` | the attestation verifier — self-audit + peer-verify |
| `postern-panic` | the Panic Lock — instant re-lock, destroys nothing |
| `postern-keys` | passkey / FIDO2 credential core |
| `postern-hygiene` | document metadata scrub (OOXML/ODF/JPEG) |
| `postern-quarantine` | untrusted-file image path |
| `postern-tor` | in-process Tor (Arti) for the RPC-over-onion path |
| `postern-telephony` | carrier SMS/calls surface |
| `postern-sdk` | one UniFFI surface over the suite (Android/iOS/desktop) |

**Apps** (`apps/*`) — self-contained reference front-ends (bring-your-own Claude
key where an AI concierge is offered; every one carries an honest privacy panel
and never claims "100% private"):

- **Sotto** — privacy-first voice assistant · **Vedetta** — voice markets (holdings never leave the device)
- **Tolmach** — private interpreter + meeting minutes · **Postern Store** — say what you need, it parameterizes the search
- **Chiave** — sign-in with your wallet (no email, no account) · **Sarto** — onboarding configurator + transparent parental/corporate controls
- **Consiglio** — enterprise admin console (Chinese-Wall, dual-control escrow, LGPD/GDPR/CCPA-enabling controls)

**OS + platform** (`os/`, `docs/specs/`): the reproducible-by-design (inputs pin
pending) Postern OS (desktop & mobile), the **confidential-VM cloud edition** (SEV-SNP/TDX,
`POSTERN-CLOUD.md`), the **wallet-as-login identity** (`POSTERN-IDENTITY.md`), and
the **enterprise** identity/governance model (`POSTERN-ENTERPRISE.md`).

**Desktop / mobile:** a Tauri desktop app (`desktop/`), the mobile wallet core +
UniFFI (`mobile/`), and an explorer (`explorer/`).

## Principles

Owned products ⟂ ownerless protocol; permissive licenses only; every claim
audit-gated and made honestly; no covert surveillance; privacy by design. The
protocol's constitution (`PRINCIPLES.md`) lives in the Bloch repo; the product
ethos is in [`docs/POSTERN-LABS.md`](./docs/POSTERN-LABS.md).

## Build

Products consume the protocol as a git dependency. `cargo build --workspace`
builds the product crates (the three that need protocol crypto — seal-companion,
mobile core, desktop — pull `bloch` / `bloch-crypto` from the Bloch repo, pinned
in `Cargo.lock`). The web apps are single self-contained HTML files — open them
in a browser (Chrome for the voice features).

## License

MIT / Apache-2.0 (per crate). No copyleft is embedded anywhere in the products.
