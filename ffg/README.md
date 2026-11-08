# postern-ffg

**Postern FFG — permissioned-notary module (design scaffold).**

> ## ⚠️ SCAFFOLD — not a secure or deployed system
>
> This crate is a **conceptual design scaffold**. **Nothing here is built,
> audited, attested, secure, offered, or operational.** There is **no security
> claim anywhere** in it. It exists only to give the design in
> `Postern-FFG-RWA-Design.md` a compiling type skeleton. **Do not settle,
> custody, or rely on anything of value using this code.** This is not legal,
> financial, or investment advice, and not an offer or solicitation.

---

## What this is

A standalone Rust type scaffold for **Layer 2** of the Postern
stack: a **permissioned, Postern-OPERATED notary checkpoint** service that
*anchors to* the ownerless **Bloch-SIS-PoW** base.

- It **reads** the base — block headers/hashes, accumulated PoW work, the
  canonical tip as seen by Postern's own fully-validating nodes.
- It **anchors** its certificate hashes back onto the base as **ordinary
  transactions/commitments** — the way any user writes data to an ownerless
  chain.
- It does **not** fork, modify, or become a consensus dependency of the base. If
  the whole Postern signer set vanished, the base continues exactly as before,
  minus the notarizations.
- **RWA / settlement state lives ONLY in this owned layer.** The base has no
  knowledge of any RWA and stores none.

This crate is intentionally **standalone**: it defines its own light anchoring
interface and does **not** depend on any sibling framework crate — it only
mirrors the same read-tip / write-commitment anchoring *pattern*.

## The in-process reference pipeline

Beyond the types, the crate now contains a **working, in-process, deterministic
reference of the notary's shape** — over the in-memory mock base, with no
operator infrastructure of any kind. Per epoch, `notary::NotaryService`:

1. **Re-checks the base under everything already notarized** — if a header at
   an already-notarized height no longer matches, it emits an explicit
   `BaseReorgObserved` event. This event is the code-level proof of the
   crate's central honesty rail: a checkpoint — even a HardNotarized one — is
   *a Postern attestation, not settlement finality*. The service can only
   observe and report a base reorg; it cannot prevent or undo one.
2. **Reads** the mock base via the existing `BlochAnchorClient` seam
   (canonical tip, headers, accumulated work) and assembles a
   `PosternNotaryCheckpoint` over the heights since the last justified one.
3. **Collects signatures** from its in-process signer seats via the
   `CheckpointSigner` seam (the signing mirror of `MlDsa65Verifier`).
4. **Checks quorum** with `verify_quorum`. Below threshold: the justified
   streak resets and nothing is anchored — the **only** outcome an offline
   `--no-default-features` build can produce, because the offline stub signer
   emits junk and the offline stub verifier refuses to assert validity. A
   **default** build wires the real (UNAUDITED, pre-1.0) ML-DSA-65 primitives
   and reaches genuine quorum on 14 distinct signatures.
5. **Anchors** the certificate hash — SHAKE-256-32 of the canonical
   certificate encoding (`certificate::CheckpointCertificate`) — onto the base
   via `anchor_commitment`, as an **ordinary transaction commitment**.
6. **Promotes** the previous epoch's record to `HardNotarized` only on two
   consecutive justified epochs (exactly what the `ConfidenceLevel` docs
   promise). **HardNotarized promotion exists in code but confers nothing**:
   it is a local label on a Postern attestation about a forgeable base — never
   irreversibility, never settlement finality.

Independent re-verification is `follower::reverify_anchored_certificate`:
given an anchored receipt, the certificate bytes, and the operator set,
**anyone** can recompute `certificate_hash()` against the anchored commitment
and re-run `verify_quorum` with a verifier of their own choosing. There is
**no privileged reader**. Under `--no-default-features` even the follower can
never "confirm" a quorum, because the offline stub verifier refuses to assert
validity; a default build re-verifies with the real ML-DSA-65 primitive.

The certificate hash uses an **in-crate, UNAUDITED reimplementation of
SHAKE-256 (FIPS 202, Keccak-f[1600])** in `src/shake.rs` — written from
scratch so the crate pulls in no hashing crate (its only default dependency is
the ML-DSA-65 signature primitive; `--no-default-features` drops that too). It
is validated in-tree against official FIPS-202 / NIST SHA-3 example test
vectors, which demonstrates *functional* correctness on those inputs — **not**
security. It is reference-only: not constant-time-reviewed, not
side-channel-hardened, never audited.

### Blocked on infra / audit (honestly out of scope here)

This is a software-only reference; the following are **not** attempted and are
labeled exactly what they are:

- **Talking to a real Bloch node RPC** instead of `InMemoryAnchorClient` —
  blocked-on-infra. The `BlochAnchorClient` trait is the seam where a real
  client would plug in.
- **Real operator key custody** (HSMs, key ceremonies) and **any
  deployed/operated signer set** — blocked-on-infra. The
  `CheckpointSigner` / `MlDsa65Verifier` traits are the seams.
- **Independent audit** of the RustCrypto `ml-dsa` crate and of the in-crate
  SHAKE-256 reimplementation — blocked-on-audit. Until then, every crypto
  primitive in this crate must be treated as unaudited, because it is.

## The honest trust model — "trust Postern"

This is a **centralized, permissioned, Postern-operated** service. Name it in
exactly those words.

- It is **NOT** BFT, **NOT** decentralized, **NOT** trustless, **NOT**
  permissionless. Every seat in the operator set is run by **one organization
  (Postern)**. A `14-of-21` quorum is `14-of-21` facets of one actor; there is
  no honest minority to dissent, raise evidence, or fork away. If Postern is
  compromised, coerced, or errs, there is no trust-minimized recourse.
- **No economic security this phase.** Slashing/bonding against a self-operated
  set is self-referential (Postern slashing itself) and is dropped from every
  security claim. The `21`-seat / `14-of-21` threshold and era rotation are
  **operational-robustness / crash-fault** measures within one trust domain —
  not Byzantine fault tolerance.
- **Censorship, ordering power, and legal coercion are inherent** to a
  single-operator finalizer and cannot be mitigated within the model — only
  disclosed, and eventually decentralized away.
- Only a future **independent-operator set** (distinct entities, staff, infra,
  jurisdictions; live external slasher; genuine key custody) could ever earn the
  words "BFT" / "decentralized." None of that holds today.

## Finality primitive: ML-DSA-65 (post-quantum), not BLS

The operator finality signature is **ML-DSA-65 (FIPS 204)** — natively
post-quantum. DKG / threshold-BLS aggregation was **deliberately shelved this
phase** to stay Shor-safe (BLS12-381 is Shor-breakable) and because DKG's
trust-distribution property is moot when Postern is every participant. Each
operator emits an **individual** ML-DSA-65 signature (no aggregation), so a full
`14-21`-signature certificate is `~46-69 KB`.

The lattice verify goes through the `MlDsa65Verifier` trait. **By default** the
trait is filled with `RustCryptoMlDsa65Verifier`, a **real FIPS-204 verify** via
the **unaudited, pre-1.0 (`0.1.1`)** RustCrypto `ml-dsa` crate — so a plain
`cargo test` accepts genuine 14-of-21 signatures, reaches quorum, and rejects
any tampered or wrong-key signature. Under `--no-default-features` the trait
falls back to the `NonVerifyingStubVerifier`, which **verifies nothing** (checks
byte lengths, then refuses to assert validity), so an offline stub build never
reaches quorum — that fallback is intentional. A real deployment MUST supply a
FIPS-204-conformant, **independently-audited** implementation; the default
`ml-dsa` backing is real crypto but not that audited primitive.

Wiring in the real (`real-mldsa65`, ON by default) verify primitive is **NOT** a
claim that this system is secure, operational, audited, or deployed — it is
one unaudited primitive, not a security posture. Every rail in this README
(SCAFFOLD, unaudited, not deployed, no aggregation/DKG, centralized
"trust Postern," `k=4`-forgeable base, `QuorumReached` = a Postern
attestation and never settlement finality) still holds regardless of which
verifier is compiled in.

## Finality is only as strong as the base beneath it

The Bloch-SIS-PoW base is a **mainnet-beta**: `k=4` **trivially-forgeable**,
**`51%`-attackable**, and **unaudited**. A notary checkpoint over a forgeable
base provides **NO real settlement guarantee today** — the security ceiling is
`min(base security, Postern integrity)`, and the base term is ~zero right now.
Irreversibility here is a **Postern promise, not a protocol property**, revocable
by Postern or by anyone who forges the base beneath it.

## The coin (BLCH)

**BLCH is worthless and is not a security** — no sale, no listing, no price.
Nothing in this scaffold gives BLCH value or routes value into it. BLCH is the
**neutral native gas** of the ownerless base (a protocol fact — "like ETH" only
as a mechanic, never a Postern pitch). Paying base gas in BLCH to anchor a
checkpoint is **operational spend only** — paying for computation, not
monetization and not a value claim.

## RWA is a separate, regulated, legally-gated instrument (HARD GATE)

Tokenizing a real-world asset creates a **regulated financial instrument** in
most jurisdictions, and because Postern *operates* the settlement/finality layer
for others' assets, Postern is very likely a **regulated intermediary** (money
transmitter / MSB, trust/custodian, transfer agent, broker/ATS/clearing —
jurisdiction- and asset-dependent). **Independent qualified legal review of BOTH
the RWA-token classification and the operator-role licensing is a HARD GATE
before anything is built, demonstrated with a specific asset, or offered.**
"We only run the nodes" is not a safe harbor. An on-chain attestation proves only
what a signer asserted and that the network recorded it — **not** that the
underlying asset exists, is unencumbered, or is legally redeemable.

## RWA + BaaS reference state kernels (kernel / rwa / baas modules)

The RWA and BaaS roadmap rows are implemented here as **reference state
kernels** (spec: `docs/specs/POSTERN-FFG-RWA-BAAS-REFERENCE.md` — REFERENCE
SCAFFOLD, unaudited, nothing operational or offered):

- `kernel` — a generic deterministic state kernel: append-only op log, pure
  `apply(state, op) -> Result<state>`, chained commitment root
  `root = SHAKE-256(prev_root ‖ canonical op encoding)`. Replay determinism is
  the point; the chained root is **NOT a Merkle tree** and supports **no
  inclusion proofs** — no proof claims of any kind, and no data availability
  (the base stores 32 bytes, not the log).
- `rwa` — an asset-registry reference kernel (`RegisterAsset` / `Transfer` /
  `Redeem` / `Freeze`, invariants enforced in the pure `apply`). Every asset
  record carries a mandatory `legal_review: LegalGate` whose **only
  constructible value is `NotObtained`**, and there is **deliberately no
  offer/sell/list operation** — the HARD GATE above, encoded in the type
  system. Blocked-on-legal-review by construction.
- `baas` — a multi-tenant reference host: N isolated kernels keyed by tenant
  id (tenants share nothing); one batch anchor = SHAKE-256 over the sorted
  `(tenant_id, root)` pairs, written as **ONE ordinary base transaction**.
  Commitment-only — it deliberately does not duplicate the sibling
  `l2/bloch-l2-anchor` `L2V0` envelope wire format.

State lives **ONLY** in this owned layer; the base sees nothing but opaque
32-byte roots anchored as ordinary txs. An on-base commitment proves only "a
signer asserted this root", never that any asset exists or is redeemable. The
"Postern vanishes" test in `lib.rs` asserts in code that dropping the anchor
client leaves the mock base untouched — the kernels merely stop anchoring.
The SHAKE-256 is an in-crate implementation (`hash.rs`) that pulls in no
hashing crate, pinned to the NIST FIPS 202 vectors in tests and otherwise
**unaudited**.

## The base belongs to everyone

The Bloch-SIS-PoW base is an **ownerless, permissionless commons**. **Anyone may
build their own finality gadget, RWA rails, or apps on it — including
trust-minimized / decentralized alternatives** that do not share this instance's
single-trust-domain limitation. Postern owns **only its own instance**; it claims
no reserved namespace, no consensus privilege, and no exclusivity, and cannot
grant, withhold, or price "permission" to build on Bloch.

## Naming rails

- Never the trademarked mark **"BABA YAGA."** If a scheduler/orchestrator is
  referenced, use **Yagabona** / **Izbushka**.
- The community edition is **never** called **"Postern OS"** (that name refers to
  the Nix-built family only).
- Never describe this layer as "decentralized," "trustless," "permissionless,"
  "non-custodial-by-design," "ownerless," or "BFT."

## Layout

```
ffg/
├── Cargo.toml            # standalone; one default dep (ml-dsa); MIT OR Apache-2.0
├── README.md             # this file
├── LICENSE-MIT
├── LICENSE-APACHE
└── src/
    ├── lib.rs            # SCAFFOLD module docs + rails, re-exports, disclaimer
    ├── signature.rs      # ML-DSA-65 operator-signature interfaces: real verify by default
    │                     #   + CheckpointSigner (real signer default; offline stub emits junk)
    ├── operator.rs       # PermissionedOperatorSet + era rotation types
    ├── checkpoint.rs     # PosternNotaryCheckpoint (height range, anchor, sigs, confidence)
    ├── anchor.rs         # light BlochAnchorClient interface + in-memory scaffold
    │                     #   (incl. deterministic reorg simulation, a test aid)
    ├── shake.rs          # in-crate SHAKE-256 (FIPS 202): UNAUDITED reimplementation,
    │                     #   reference only; pulls in no hashing crate
    ├── certificate.rs    # canonical certificate encoding + SHAKE-256-32 certificate hash
    ├── notary.rs         # in-process reference pipeline: read → sign → quorum →
    │                     #   anchor → promote → observe reorgs (nothing operational)
    ├── follower.rs       # independent re-verification of anchored certificates
    │                     #   (no privileged reader)
    ├── hash.rs           # in-crate SHAKE-256, no hashing crate (unaudited; NIST-vector-pinned)
    ├── kernel.rs         # generic deterministic state kernel (chained root; NOT a Merkle tree)
    ├── rwa.rs            # RWA asset-registry reference kernel (LegalGate HARD GATE in the types)
    └── baas.rs           # multi-tenant reference host (N isolated kernels, ONE batch anchor)
```

## Build

```sh
cd ffg
cargo build      # default: real (unaudited, pre-1.0) ML-DSA-65 verify wired in
cargo test       # scaffold + real-crypto pipeline tests: 14-of-21 genuine
                 #   ML-DSA-65 signatures reach quorum; 13, tampered, or
                 #   wrong-key signatures do not

# offline fallback: zero-dependency stub scaffold (verifies nothing, so quorum
# is never reached — by design). Drops the ml-dsa dependency entirely.
cargo test --no-default-features
```

The default build has a **single dependency** (the UNAUDITED, pre-1.0 RustCrypto
`ml-dsa` crate; `--no-default-features` drops it for a zero-dep stub build) and
the crate is **not** wired into any workspace. It is a design scaffold with an
in-process reference pipeline — nothing operational, audited, or secure.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
