<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Postern Data ⇄ Filecoin — private user-backup data layer — design

**Status: DESIGN ONLY — SCAFFOLD / UNAUDITED. Nothing below exists as code. designed ≠ built ≠ booted.** A client-side-sealed, PQ-integrity-anchored backup path that lets a Postern base push its *own already-encrypted* user data to Filecoin through a **hosted** deal-making API (Storacha / Lighthouse — no self-run Lotus), records a SHAKE-256 manifest root, signs it with Bloch's PQ signature, and anchors that root to the ownerless Bloch base as an ordinary zero-value `DATA0` envelope. Confidentiality is the existing Postern seal (`crates/postern-core`, XChaCha20-Poly1305 v2, key-committing, Argon2id); integrity/authenticity is a PQ overlay that sits **on top of** Filecoin's non-PQ SHA-256 CIDs. Companion idiom: [`BLOCH-L2-EVM-DESIGN.md`](BLOCH-L2-EVM-DESIGN.md) §2 (the L2V0/TKV0 anchor rail this reuses).

> **The honesty gate (read first).** This layer touches four different trust domains and overclaiming any one of them is the exact failure this project forbids. (1) **Confidentiality** is real and client-side — the provider only ever sees ciphertext. (2) **Integrity/authenticity** is real, PQ, and third-party-verifiable — but it lives in *our* overlay, never in the Filecoin CID. (3) **Availability** is a **provider promise, the weakest link** — between upload and deal-sealing (hours-to-≈1 day) the only off-base copy is the provider's hot layer; a provider that vanishes in that window loses that copy. (4) **Ordering/existence** of the anchor **inherits the Bloch base in full: k=4, low-hashrate, 51%-attackable, unaudited** — an anchor can be reorged away, and any ordering claim is exactly that weak, no stronger. Nothing here may render the words **"secured"** or **"backed up"** as a completed state; the only permitted claims are the journaled evidence states of §7. Everything is testnet / zero-value / unaudited until the base clears its own security gates.

_Design synthesized from a 3-candidate fleet (MVP-smallest-path, content-addressed-chunked, robustness-first). The MVP-smallest-path candidate is the chosen spine; the chunked and robustness candidates are grafted as explicitly-later phases (§8) and as honesty-surface language (§6). Each subsystem below carries its trust caveats in bold, inline, per repo discipline._

---

## 1. Overview

**Shape.** A new **offline, zero-network** scaffold crate `crates/postern-backup-core` performs the entire trust-bearing pipeline — *seal → manifest → SHAKE-256 root → PQ sign → `DATA0` envelope → verify → restore* — with the single point where the untrusted world begins factored out behind **one trait, `StorageBackend`**. Every byte of trust-bearing logic is therefore deterministic, panic-free, and testable with no network, against an in-crate `DirBackend`/`MemBackend`. The live hosted-provider client (`LighthouseBackend`, later `StorachaBackend`) lives in a **separate crate `crates/postern-backup-net`** and is **structurally out of scope for the offline crate**: the core crate contains no network client, so it cannot claim anything was stored. That structural separation *is* the honesty gate, not a policy bolted on top.

**Chosen granularity: whole-file seal (MVP), chunking deferred.** Each source file is sealed whole with `postern_core::aead::seal_with_context` and uploaded as one opaque ciphertext blob. This buys the smallest honest end-to-end path: **no chunker, no FastCDC, no CAR/dag-pb builder, no UnixFS, no dedup index, no Merkle tree** in v0. Provider-side chunking of the ciphertext is *acceptable precisely because the Filecoin CID carries zero integrity weight* — a per-blob SHAKE-256 digest recorded in the manifest does the integrity work, and is re-checked after every fetch before the key-committing AEAD gives a second, keyed check. Content-defined chunking, single-vault dedup, per-chunk Merkle inclusion proofs, and partial restore are a designed-but-deferred **Phase 4** (§8), grafted from the chunked candidate; they change the manifest and add a Merkle tree but touch nothing in the seal/sign/anchor spine.

**What already exists in-repo** (nothing new invented): the seal + Argon2id KDF (`crates/postern-core`), the SHAKE-256/256 idiom (`crates/postern-trail/src/lib.rs:352`, `sha3 = "0.10"`), the PQ hybrid signer (chain wallet's ML-DSA-65‖Falcon-1024 suite `0x0001` via external `bloch-crypto` @ rev `dd8df35` + the `pqcrypto-internals` seeded-keygen patch), the anchor-envelope idiom (`l2/bloch-l2-anchor/src/envelope.rs`, `crates/bloch-tokens/src/{envelope,stream,indexer}.rs`), and the reorg-correct chain reader (`bloch-tokens` `BlockSource`/`Indexer`). This design is almost entirely *composition of proven parts + two new binary formats (manifest + package) + one new envelope magic (`DATA0`)*.

**Data flow (backup), fail-safe ordering.**

```
 sealed base (TRUSTED)                                   │  untrusted from here →
                                                         │
 source file ─► aead::seal_with_context ─► sealed blob ─►│─► backend.put() ─► content CID (LOCATOR ONLY)
      ▲            (whole file, v2)              │        │                          │
 passphrase ─► kdf::derive_key (Argon2id) ─────► └─► SHAKE-256/256(sealed) ──┐       │
      salt per backup-set, tier byte                                         ▼       ▼
                                                       manifest entry {path, len, cid, shake256}
                                                                             │
                                    manifest (PBM0, plaintext) ─► seal ─► package (PBP0):
                                    magic‖tier‖salt‖sealed_manifest‖pk‖sig │
                                            │                              └─► backend.put() ─► manifest_cid
                                            └─► manifest_root = SHAKE-256(PBP0 committed prefix)
                                                                             │
                          bloch_crypto::crypto::sign(sk, transcript) ◄───────┤
                                                                             ▼
                                DATA0 envelope (177 B) ─► zero-value TxOut ─► Bloch tx ─► anchored
                                                                             │
                        journal: Sealed → Uploaded → Anchored → DealObserved  (per backup-set)
```

Ordering is fail-safe and idempotently resumable from a journal (spool under `/persist/postern/backup`, `0700`): files first, package second, anchor **only after** the provider acks the package, deal-observation last. Everything is content-addressed, so any interrupted step resumes from the journal without re-sealing.

**Restore flow (disaster recovery from nothing but `(seed, passphrase)`).** seed → backup-signer pk → `namespace_id` → scan the Bloch chain for `DATA0` in that namespace, `link()`-validate, take the highest-sequence valid head on the canonical chain → `manifest_cid` → fetch PBP0 package → recompute `manifest_root`, compare to the anchor → verify `signer_commit` + hybrid sig (**any mismatch aborts loudly**) → salt/tier from the package header → derive key → open manifest → per entry `get(cid)` → check SHAKE-256 (key-independent PQ check) → `open_with_context` (keyed, key-committing check) → write plaintext. No local state is required for restore. Steps after the fetch are pure functions over bytes and are fully offline-testable against `DirBackend` with corrupted-byte, wrong-key, wrong-context, truncation, and swapped-blob negatives.

---

## 2. DATA0 anchor envelope — 177-byte fixed wire format

The envelope follows the L2V0/TKV0 idiom **verbatim**: it is the `script_pubkey` of a **zero-value output** of an ordinary Bloch transaction, an OFF-consensus reader convention. Node validation never constrains an *output* `script_pubkey`, so this is **zero consensus change**; a malformed envelope is an anchor-layer no-op and NEVER invalidates the carrying Bloch tx. The magic reads "DATA0" on the wire as `*b"DAT0"` (4-char) followed by the `0x00` version byte playing the "0" — the same 3-char+`0` shape as `TKV0`/`L2V0`.

All multi-byte integers little-endian. Fixed **177 bytes**:

```text
offset  size  field           meaning
0       4     magic  "DAT0"    (44 41 54 30)
4       1     version u8 = 0x00
5       32    namespace_id     SHAKE-256/256(b"postern-backup/ns/v1" ‖ enveloped_signer_pk)
                               — the publisher/vault filter (role of rollup_id); binds the whole
                                 anchor chain to one backup-signer public key.
37      8     sequence u64 LE  strictly increasing per namespace; 0 = genesis (role of batch_index).
45      32    prev_root        previous anchor's manifest_root; [0u8;32] at genesis (the chain link).
77      32    manifest_root    SHAKE-256/256 of the PBP0 package's committed prefix (§4). THE commitment.
109     32    signer_commit    SHA3-256(enveloped_signer_pk) — matches bloch-crypto's own address-derivation
                               family (it hashes the *enveloped* pk with SHA3-256), so a reader recomputes it
                               with the same primitive the chain uses.
141     36    manifest_cid     CIDv1 binary (0x01 ‖ codec varint ‖ 0x12 0x20 ‖ sha2-256 digest[32]) —
                               a LOCATOR ONLY, UNSIGNED, carries zero integrity weight (§4, §6).
177 = total
```

**Decode discipline (ported byte-for-byte from `l2/bloch-l2-anchor/src/envelope.rs`).** Strict: exact magic ⇒ else `BadMagic`; exact version ⇒ else `BadVersion(u8)`; exact length ⇒ else `Truncated` / `TrailingBytes`; bounds-checked `Cursor` with `checked_add`; typed `EnvelopeError`; **garbage never panics** (xorshift fuzz test). Zero-value rule inherited: a magic-prefixed output with `value != 0` ⇒ `EnvelopeError::NonZeroValue(u64)`, because the node's address indexer misreads a ≥20-byte `script_pubkey` as an address and any BLCH riding an envelope is stranded (TKV0 caveat E.1) — **never attach value to an anchor output.**

**Extraction: first-envelope-wins, no fall-through.** `extract_anchor(tx) -> Option<(usize, Envelope)>` takes the lowest-index output whose script starts with `DAT0`; if that candidate is malformed or non-zero-value, the tx carries **no** anchor — there is no scan past a bad candidate (matches `extract_anchor`/`extract_envelope`).

**Linkage: `link(prev, next)`** = `prev.namespace_id == next.namespace_id` ∧ `next.sequence == prev.sequence.checked_add(1)?` (`u64::MAX` has no successor) ∧ `next.prev_root == prev.manifest_root`. Linkage only — confirmation depth and PQ-signature verification are separate reader steps.

**Carrier tx** = ordinary Bloch tx: fee input + change output + one `TxOut { value: 0, script_pubkey: envelope.encode() }`. **No new tx machinery** — signing, fee-input selection, and broadcast delegate to the existing wallet / node JSON-RPC path. Anchoring is **permissionless**: any fee-payer can write `DATA0` bytes, so **a decoded envelope is only a *claim*.** It becomes trustworthy solely after the reader fetches the package, recomputes `manifest_root`, checks `signer_commit == SHA3-256(pk)`, and verifies the PQ signature. **The `manifest_cid` in the envelope is unsigned by deliberate design** (see the signature-circularity note in §4): a wrong or malicious CID simply fails the `manifest_root` recomputation, and because no integrity claim ever rests on the CID, that is safe.

**Reader plumbing** reuses `bloch-tokens` `BlockSource` (`getblockcount`−1 / `getblockhash(h)` / `getblockbyheight(h, verbose)`, node method-errors-inside-`result`) and the `Indexer` height→hash journal with fork-point rewind + forward replay, so two independent readers of the same selected chain reach byte-identical anchor state, reorg-correctly.

---

## 3. Where sealing happens, and the manifest/package formats

**Sealing happens on the sealed base, before any byte leaves it.** Backup origins are exactly the writable surfaces (`/persist/bloch`, `/persist/postern`, `/var/lib/bloch`, `$HOME` + wallet keystores) — never the dm-verity read-only root, which is reproducible from the flake and holds no user data. Filecoin/Storacha/Lighthouse only ever receive v2-seal ciphertext, matching the house precedent that the remote party holds ciphertext at rest (`os/cloud.nix` LUKS-to-provider). Egress crosses the boundary as ciphertext, over Tor (SOCKS 127.0.0.1:9050, held until bootstrapped), with recorded consent reusing the `apps/sloboda-gate` writer pattern — but all of that is Phase 5, networked, and out of the offline crate.

### 3.1 Manifest format (`PBM0`, plaintext — exists only inside the seal)

Fixed little-endian binary, house style (no JSON, no serde in the core path), strict bounds-checked decode:

```text
magic "PBM0" (4) ‖ version 0x00 (1)
backup_set_id  [32]      SHAKE-256/256(namespace_id ‖ sequence u64 LE) — redundancy check vs the anchor
sequence       u64 LE    must equal the anchor's sequence
created_unix   u64 LE    timestamp (INSIDE the seal → not leaked)
entry_count    u32 LE
entries[] (sorted ascending by path bytes — canonical ordering rule):
  path_len         u16 LE ‖ path (UTF-8, relative)   — filenames NEVER appear outside the seal
  file_len         u64 LE                            — plaintext length
  content_cid_len  u8 ‖ content_cid (CIDv1 bytes)    — provider-returned locator, LOCATOR ONLY
  shake256         [32]                              — SHAKE-256/256 of the SEALED blob bytes (the PQ integrity bit)
```

The per-entry `shake256` is what makes integrity PQ end-to-end: Filecoin CIDs are sha2-256/blake2b and are treated purely as retrieval handles. After any fetch, bytes are checked against `shake256` (key-independent, so a third party with no key can still verify the *anchor↔ciphertext* binding) and only then opened, where the key-committing AEAD gives the second, keyed check. **A future sha2-256 collision costs availability (mis-retrieval), never undetected substitution.**

### 3.2 Package format (`PBP0`, plaintext wrapper — this is the uploaded manifest object)

```text
offset  field
0       magic "PBP0" (4) ‖ version 0x00 (1)
5       kdf_tier u8          0x00 = default (Argon2id 64 MiB / t=3 / p=1), 0x01 = floor (19 MiB / t=2 / p=1)
6       salt [16]           NOT secret; must be recoverable for disaster restore
22      sealed_manifest_len u32 LE ‖ sealed_manifest    (aead v2 blob of PBM0)
...     ── manifest_root = SHAKE-256/256 over bytes [0 .. end of sealed_manifest] ──
        pk_len  u32 LE ‖ pk    (suite-enveloped bloch-crypto public key, suite 0x0001)
        sig_len u32 LE ‖ sig   (suite-enveloped hybrid signature, ≈ 4.6 KB)
```

`manifest_root` commits to the salt and tier *as well as* the sealed manifest ciphertext, so the signature (which commits to the root) transitively covers them. Because the sealed manifest contains every entry's `content_cid` and `shake256`, the single 32-byte `manifest_root` transitively commits to the entire backup-set's ciphertext (an idea sharpened from the chunked candidate's two-level commitment). Anyone holding `manifest_cid` + the anchor can fetch PBP0 and check the hash with **no keys**; only the key holder can open it and reach the file/entry table.

**Signature circularity, resolved deliberately.** The sig lives inside the package, and the package's CID lives inside the envelope, so the sig cannot sign the full envelope (it would have to sign a hash of itself). The signed transcript is therefore the envelope **minus the locator**:

```text
t   = b"postern-backup/anchor/v0" ‖ magic ‖ version ‖ namespace_id ‖ sequence
      ‖ prev_root ‖ manifest_root ‖ signer_commit
sig = bloch_crypto::crypto::sign(&sk, &t)?          // suite 0x0001, ML-DSA-65 ‖ Falcon-1024, AND-of-both
```

`manifest_cid` (offset 141..177 of the envelope) is excluded and unsigned by design: it is only a pointer, and a wrong pointer fails the `manifest_root` recomputation. Verification: `crypto::verify(&pk, &t, &sig) == true` **and** `signer_commit == SHA3-256(pk)`.

---

## 4. `StorageBackend` trait — the pluggable, offline-testable seam

This one trait is the entire boundary between the trusted, offline, testable world and the untrusted network. It ships in `postern-backup-core` with offline impls; the live impls live only in `postern-backup-net`.

```rust
pub trait StorageBackend {
    /// Upload opaque ciphertext. The returned CID is PROVIDER-REPORTED and treated as a
    /// LOCATOR; it carries no integrity weight. (Hardening option, Phase 4: ship a single
    /// raw-block CAR so the provider-visible CID equals a client-computed one — then this
    /// impl MUST return `Err(CidMismatch)` if the ack differs.)
    fn put(&mut self, bytes: &[u8]) -> Result<PutReceipt, BackendError>;

    /// Fetch by CID. The CALLER MUST verify SHAKE-256 against the manifest before use;
    /// backend bytes are untrusted.
    fn get(&mut self, cid: &[u8]) -> Result<Vec<u8>, BackendError>;

    /// Persistence probe — honest vocabulary only (§6).
    fn status(&mut self, cid: &[u8]) -> Result<PersistenceStatus, BackendError>;
}

pub struct PutReceipt {
    pub cid: Vec<u8>,
    pub size: u64,
    /// Storacha piece CID v2 (0x1011), captured at upload via `onShardStored` — MUST be persisted
    /// or persistence queries are lost until recovered via the indexing service. `None` for
    /// Lighthouse (content-CID-keyed). Journaled at put time, non-optionally.
    pub provider_ref: Option<Vec<u8>>,
    pub observed_unix: u64,
}

pub enum PersistenceStatus {
    Unknown,                       // provider unreachable / no record
    Acknowledged,                  // provider says it holds the bytes (HOT layer only — NOT a deal)
    DealActive(Vec<DealInfo>),     // on-chain deals reported
}
pub struct DealInfo { pub deal_id: Option<u64>, pub provider: String /* f0… */, pub end_epoch: Option<u64> }
```

Synchronous, blocking, `Vec<u8>` in/out — MVP blobs are whole files; streaming is a Phase 4 problem. The live crate wraps its async transport internally behind this sync trait.

**Offline impls (ship in the core crate, feature-free, exercise the whole suite + CLI):**
- **`DirBackend`** — stores blobs under a directory keyed by locally computed CIDv1-raw-sha2-256; `status` returns `Acknowledged`. This is also the real staging spool the live uploader later drains.
- **`MemBackend`** — in-memory `HashMap`, for unit tests.
- **`RecordingBackend`** (grafted from the chunked/robustness candidates) — scripted, fault-injecting: returns `CidMismatch`, truncated bytes, wrong bytes, and drop-before-deal, so the caller's mandatory post-fetch SHAKE re-check and the restore fail-closed paths are adversarially tested offline.

**Live impls (`postern-backup-net`, Phase 3–4, OUT of the offline honesty scope):**
- **`LighthouseBackend` — the MVP live impl**, chosen first because it is pure-Rust-reachable: `POST https://upload.lighthouse.storage/api/v0/add` (multipart, `Authorization: Bearer <key>`) → `{Hash: CID}`; `GET .../deal_status?cid=` + `.../get_proof?cid=` for `status` (map `dealId: null` → `Acknowledged`, populated deals → `DealActive`); `get` via gateway with a **mandatory post-fetch SHAKE check**. Everything keyed by content CID — no piece-CID bookkeeping. Its bearer key on the box grants upload/quota abuse, **not data access** (bytes are already ciphertext).
- **`StorachaBackend` — Phase 4.** Better auth model (UCAN agent key + scoped, expirable delegation — no shared bearer secret, delegable to end-user devices) but its SDK is JS, so it needs a Node sidecar / `@storacha/cli` bridge — exactly the moving part MVP-first defers. Its `filecoin.info(pieceCidV2)` maps onto `status`; the trait's `provider_ref` already carries the piece CID v2 that MUST be captured at `onShardStored`.

All net egress goes through the box's Tor SOCKS, held-until-bootstrapped, matching the sloboda rail. **The offline crate compiles, tests, and fuzzes with zero network capability — that is the structural honesty guarantee, not a runtime flag.**

---

## 5. Key custody

Two secrets, both memorizable / seed-recoverable, **neither ever leaving the base.**

**1. Content key (confidentiality).** `kdf::derive_key(passphrase, salt)` — Argon2id default tier (64 MiB, t=3, p=1), `Zeroizing<[u8;32]>`, derived per run, never persisted. One salt per backup-set generation via `kdf::generate_salt()`. The salt + a tier byte live in the **plaintext PBP0 header** (the salt is not secret and *must* be recoverable for disaster restore). Fixed contexts, never changed:
- files:    `b"postern-backup/file/v1"`
- manifest: `b"postern-backup/manifest/v1"`

**2. Signing key (PQ integrity/authenticity).** A dedicated backup signer derived from the wallet seed, so the *spend* key is never reused for data signing yet everything is recoverable from the seed alone:

```rust
let sk_seed = shake256_32(seed ‖ b"postern-backup/signer/v1");
let (pk, sk) = bloch_crypto::crypto::generate_keypair_from_seed(&sk_seed)?; // deterministic via the pqcrypto-internals patch
// suite 0x0001 = ML-DSA-65 ‖ Falcon-1024 (AND-of-both must verify)
```

Suite `0x0001` is chosen deliberately over the in-repo `postern-release` signer (ML-DSA-87 ‖ Falcon-1024): it is **the chain wallet's own format**, so `signer_commit == SHA3-256(enveloped pk)` equals the on-chain address derivation, `bloch_crypto::crypto::verify` is the single verifier, and the anchor is chain-addressable — which is exactly the founder's "Bloch crypto" ask (ML-DSA-65 / Falcon, anchored to the Bloch base). The cost is the external `bloch-crypto` git dep @ rev `dd8df35` + the mirrored `[patch.crates-io] pqcrypto-internals` pin — the same pin the five existing in-repo consumers already carry, gated behind a `sign`/`verify` feature so the envelope-codec module stays zero-dep and offline.

**Recovery reality, stated honestly.** The complete disaster-recovery input set is **`(wallet seed, passphrase)`** — both already the user's existing custody burden; this layer adds *zero* new secrets to remember. But: **passphrase + seed lost ⇒ everything on Filecoin is permanently useless ciphertext, by design.** v0 offers no escrow. An optional user-printed recovery capsule (a manifest chunk sealing the content material under an independent Argon2id leg, salt/tier in the public header — grafted from the chunked/robustness candidates) is a deliberate **Phase 4** product decision, not v0 scope, and must be labeled as widening the offline-grinding surface against weak passphrases.

---

## 6. Threat model + trust surface

**This section ships verbatim in the crate README.** Four trust domains, each stated at its true strength — this is the load-bearing honesty of the whole design.

| Property | Rests on (real) | Explicitly NOT trusted / NOT provided |
|---|---|---|
| **Confidentiality** | `postern-core` XChaCha20-Poly1305 v2 (key-committing, 256-bit ⇒ PQ-adequate) + Argon2id-derived key that never leaves the base. Provider, Filecoin SPs, gateways, Tor exits, and anyone with a CID see **ciphertext only**. | **Metadata is NOT hidden:** blob count, sealed sizes (plaintext_len + 73 per file), upload cadence, backup frequency, and the linkage of all blobs in one set via the package. The public anchor chain leaks `namespace_id`, `sequence`, and timing. Tor hides origin IP; sizes/cadence are not hidden. Passphrase strength bounds everything — Argon2id at 64 MiB is a brake, not a wall, against weak passphrases. |
| **Deletion** | — | **NOT provided.** Uploading publishes ciphertext to a public network effectively forever; a provider "remove" is unlisting only. The only real delete is **key destruction** (crypto-shredding). The design assumes ciphertext is public forever. |
| **Integrity / authenticity** | **PQ, end-to-end, owner- and third-party-verifiable.** Per-blob SHAKE-256/256 digests + `manifest_root` + ML-DSA-65‖Falcon-1024 hybrid signature. AEAD tags additionally authenticate to the key holder. | Filecoin's sha2-256/blake2b CIDs are **locators with zero integrity weight**; provider-returned bytes are always re-hashed. A Grover/collision break of sha2 costs availability (mis-retrieval), never undetected substitution. |
| **Availability / durability** | **The weakest link — a provider promise, not a proof.** Before deals seal (hours–≈1 day on Lighthouse; until a ~16–32 GB aggregate fills on Storacha) the only off-base copy is the provider's hot layer; provider disappearance in that window = data loss. After sealing, deal IDs + PoDSI are third-party-verifiable, but **retrievability** still depends on gateways/SPs honoring retrieval, and `end_epoch` renewal is a provider promise that must be monitored. | PoDSI proves *aggregate inclusion*, not N-of-M geographic replication — count distinct provider IDs. A bearer API key on the box grants upload/quota abuse, not data access. |
| **Ordering / existence (the anchor)** | The Bloch base, for tamper-evidence and sequencing of the anchor chain. The PQ signature stands on its own **regardless of chain health**; the chain only adds public timestamping/sequencing. | **Inherits the base in full: k=4, low-hashrate, 51%-attackable, unaudited.** Anchors can be reorged away; a majority attacker reorders/censors them; no finite confirmation depth is finality. The envelope is an off-consensus convention — any fee-payer can write `DATA0`, so an envelope is a **claim** until its PQ sig verifies. |
| **Supply chain** | `postern-core` (in-repo). | External `bloch-crypto` @ rev `dd8df35` + `pqcrypto-internals` patch (seeded keygen). The largest new dependency surface — Storacha's JS bridge — is isolated in `postern-backup-net`, **outside the offline crate**. |

**Vocabulary gates (non-negotiable, enforced in CLI/UI output).** The four journal states are the *only* permitted claims, each requiring its named evidence:
`sealed locally` → `uploaded (provider ack, CID …)` → `anchored (tx …, unconfirmed / confirmed-depth-N on a k=4 base)` → `deal observed (dealId …, endEpoch …)`.
The words **"secured"**, **"backed up"** (as a completed state), and **"permanent"** never appear. `postern-backup status` renders the journaled evidence chain, not adjectives. The anchor caveat prints verbatim: *"anchored to Bloch (k=4, 51%-attackable); anchor = ordering/tamper-evidence claim, not finality."* Crate headers carry **SCAFFOLD / UNAUDITED**; the offline crate makes no network claims because it contains no network client.

---

## 7. Phased build plan

Each phase is independently landable; the offline honesty boundary is preserved throughout because every trust-bearing part lands before any network client exists.

**Phase 0 — `crates/postern-backup-core` scaffold, envelope codec (offline, no deps).**
Stand up the crate with its own empty `[workspace]` (the `bloch-l2-anchor`/`bloch-tokens` pattern). Implement the `DATA0` envelope module by porting `l2/bloch-l2-anchor/src/envelope.rs` wholesale — mirror `Tx/TxIn/TxOut` from `bloch_crypto::core` @ `dd8df35` (copied, not imported), strict decode, `NonZeroValue`, `extract_anchor` first-wins, `link()`. Port the full L2V0 test suite: pinned byte offsets, round-trips, truncation-at-every-prefix, trailing bytes, xorshift-garbage-never-panics, first-wins (incl. malformed-then-valid), zero-value enforcement, link chain-of-three. **Exit:** `cargo test` green, zero deps, offline.

**Phase 1 — manifest + package codecs, seal seam (offline).**
`PBM0` and `PBP0` strict binary codecs (bounds-checked cursor, typed errors, canonical path ordering, decode-re-encode equality). Wire `postern_core::{aead, kdf}` for whole-file seal + the two fixed contexts. Compute `shake256` per blob (`sha3` idiom) and `manifest_root` over the PBP0 committed prefix. **Exit:** seal→manifest→package→root round-trips deterministically; corrupted-byte / wrong-key / wrong-context / truncation negatives pass.

**Phase 2 — `StorageBackend` trait + offline impls + CLI (offline, end-to-end).**
Trait + `DirBackend`/`MemBackend`/`RecordingBackend`. `sign`/`verify` behind a feature (external `bloch-crypto` + `pqcrypto-internals` pin) producing the suite-0x0001 signature over the transcript `t`. `postern-backup` binary: `seal`, `plan`, `verify`, `restore --from-dir` run **fully offline** against `DirBackend`; the journal (Sealed→Uploaded→Anchored→DealObserved) persists under a spool dir. Full offline restore round-trip incl. swapped-blob / bad-sig / bad-root adversarial negatives via `RecordingBackend`. **Exit:** a wiped-machine restore drill succeeds from `(seed, passphrase)` + a `DirBackend` spool, entirely offline.

**Phase 3 — `crates/postern-backup-net`, `LighthouseBackend`, anchor write/read (networked, testnet).**
Separate crate, blocking `reqwest` over Tor SOCKS. `LighthouseBackend` (`add` / `deal_status` / `get_proof`, mandatory post-fetch SHAKE). `push`/`status` CLI subcommands (feature `net`). Anchor writer builds the zero-value `TxOut` and delegates signing/fee/broadcast to the existing wallet / node JSON-RPC; anchor reader reuses `bloch-tokens` `BlockSource`/`Indexer` to scan `DATA0`, `link()`-validate, and report the latest sequence. First real testnet push; PoDSI verified; recovery drill from the live network. **Exit:** an anchored, deal-observed backup-set restored from nothing but `(seed, passphrase)` over the live network + Bloch testnet.

**Phase 4 — richness & robustness (grafted from the other candidates, all later).**
- **Storacha backend** (UCAN + Node sidecar) behind the same trait; `provider_ref` piece-CID-v2 capture.
- **Chunking + dedup + partial restore** (from the content-addressed candidate): FastCDC per file, single-raw-block CARs so CIDs are client-computed (`put` then enforces `CidMismatch`), a SHAKE-256 Merkle tree over the chunk table for per-chunk inclusion proofs and partial restore, keyed `chunk_hint` single-vault dedup. Changes the manifest, not the seal/sign/anchor spine.
- **Replication + monitor + re-deal** (from the robustness candidate): ≥2 independent hosted backends of identical CAR bytes (same CIDs ⇒ manifest/anchor unchanged); local spool as the durability root, deleted only when a deal is `Active` with PoDSI; a monitor daemon (systemd timer) polling `status`, watching `end_epoch`, re-`put`ting to a replacement on lapse; the deal/SP list retained for worst-case direct-SP retrieval.
- **Optional recovery capsule** (independent Argon2id leg), labeled as widening offline-grinding surface.

**Phase 5 — OS integration (`os/postern-backup.nix`, later, not a crate concern).**
Hardened systemd service + timer modeled on `os/bloch-node.nix` (`ProtectSystem=strict`, `RequiresMountsFor=/persist`, `ReadOnlyPaths` on sources, `ReadWritePaths` on the spool), Tor-only egress held until bootstrapped, consent gate reusing the `apps/sloboda-gate` writer pattern (fail-closed `Before=` the backup unit). Packaged like `os/seal-gate.nix` (`callPackage`, `cargoLock.outputHashes` fail-closed until filled on a Nix host).

---

## Scaffold crate — module / file plan

`crates/postern-backup-core` (new; own empty `[workspace]`; **offline, zero network**):

```
crates/postern-backup-core/
  Cargo.toml            # own [workspace]; deps: none by default.
                        #   feature "sign" → sha3 = "0.10", bloch-crypto (git dd8df35) + [patch] pqcrypto-internals,
                        #                     postern-core (path) for aead+kdf.
                        #   (envelope + codec modules stay dep-free; hashing/signing live behind the feature.)
  src/
    lib.rs              # crate docs: SCAFFOLD/UNAUDITED banner + the §6 trust surface verbatim; re-exports.
    envelope.rs         # DATA0 177-byte codec: Tx/TxIn/TxOut mirrors (copied from bloch_crypto::core@dd8df35),
                        #   encode/decode (strict, NonZeroValue), extract_anchor (first-wins), link(). Ported from
                        #   l2/bloch-l2-anchor/src/envelope.rs. ZERO deps.
    manifest.rs         # PBM0 strict binary codec (entries sorted by path, decode/re-encode equality).
    package.rs          # PBP0 strict binary codec + manifest_root (SHAKE over committed prefix) [feature sign].
    seal.rs             # whole-file seal/open seam over postern_core::{aead,kdf}; the two fixed contexts [feature sign].
    sign.rs             # transcript t builder + suite-0x0001 sign/verify + signer_commit (SHA3-256) [feature sign].
    backend.rs          # StorageBackend trait, PutReceipt, PersistenceStatus, DealInfo, BackendError.
    backend/
      dir.rs            # DirBackend (spool dir, CIDv1-raw-sha2-256 keyed).
      mem.rs            # MemBackend (HashMap).
      recording.rs      # RecordingBackend (fault injection: CidMismatch, truncation, wrong bytes).
    journal.rs          # append-only Sealed→Uploaded→Anchored→DealObserved evidence log; vocabulary-gated render.
    verify.rs           # reader: fetch→recompute manifest_root→signer_commit→verify sig→SHAKE per entry [feature sign].
    restore.rs          # pure restore over bytes: manifest open → per-entry get+SHAKE+open_with_context → write.
    scan.rs             # DATA0 chain scan over a BlockSource (mirrors bloch-tokens stream.rs); MockChain reorg tests.
    bin/
      postern-backup.rs # CLI: seal|plan|verify|restore (offline, DirBackend); push|status gated on net (Phase 3+).
  tests/
    vectors.rs          # golden byte-vectors for DATA0/PBM0/PBP0 (pinned offsets), the ported L2V0 suite,
                        #   and offline restore round-trip + adversarial negatives via RecordingBackend.
```

`crates/postern-backup-net` (new; Phase 3+; **explicitly out of the offline honesty scope**): `lighthouse.rs` (MVP live), later `storacha.rs` (Node/UCAN bridge), `tor.rs` (SOCKS transport held-until-bootstrapped), `anchor_writer.rs` (delegates to wallet/node RPC), `monitor.rs` (Phase 4 deal/endEpoch watch + re-deal).

**Key template files for the builder:** `/Users/tiagoacioli/dev/bloch-protocol/l2/bloch-l2-anchor/src/envelope.rs` (envelope + test suite), `/Users/tiagoacioli/dev/bloch-protocol/crates/bloch-tokens/src/{envelope,stream,indexer}.rs` (reader/reorg), `/Users/tiagoacioli/dev/bloch-protocol/crates/postern-core/src/lib.rs` (seal + KDF seam), `/Users/tiagoacioli/dev/bloch-protocol/crates/postern-trail/src/lib.rs:352` (SHAKE-256 idiom), `~/.cargo/git/checkouts/BlochSISPoW-project-8e92980e8e926ed6/dd8df35/crates/bloch-crypto/src/crypto/mod.rs` (chain PQ signer, suite 0x0001), `/Users/tiagoacioli/dev/bloch-protocol/os/bloch-node.nix` + `os/cloud.nix` + `apps/sloboda-gate` (Phase 5 service/consent patterns).
