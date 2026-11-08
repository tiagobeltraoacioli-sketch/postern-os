//! # bloch-data
//!
//! **SCAFFOLD, UNAUDITED, NOT A WORKING BACKUP SYSTEM.** Offline, zero-dep
//! skeleton for the Postern → Filecoin *user-backup* path. Spec:
//! `docs/specs/POSTERN-DATA-FILECOIN-DESIGN.md`. Companion idiom:
//! `l2/bloch-l2-anchor` (the L2V0/TKV0 anchor rail this reuses).
//!
//! Private user data is sealed **client-side** with the existing Postern seal
//! *before* it leaves the sealed base; Filecoin only ever sees ciphertext.
//! Integrity/authenticity is a post-quantum overlay — a SHAKE-256 manifest
//! root, signed with Bloch's ML-DSA-65‖Falcon-1024 hybrid, anchored to the
//! ownerless Bloch base as an ordinary zero-value `DATA0` envelope — that
//! sits **on top of** Filecoin's non-PQ sha2-256 CIDs.
//!
//! ## What this crate is — and is not
//!
//! This crate is the **offline, trust-bearing skeleton and the seams**, and
//! nothing else. It is `designed`, not `built`, and certainly not `booted`.
//!
//! * **The DEFAULT build is ZERO dependencies, ZERO network, ZERO live
//!   crypto.** With no features it does **not** hash content (the SHAKE-256
//!   manifest root is an opaque `[u8; 32]` *slot*), does **not** run the PQ
//!   signer (the ML-DSA/Falcon signature is an opaque `Vec<u8>` *slot*), does
//!   **not** encrypt (confidentiality is the Postern seal, reached only
//!   through the [`seal`] traits; the in-crate [`seal::MockSealer`] is a test
//!   fixture with **zero confidentiality**), and contains **no network
//!   client**. Two **opt-in, OFF-by-default, UNAUDITED** cargo features cross
//!   two of those slots into their real primitives (see [Optional
//!   features](#optional-features-live--hash)). (The one exception to "does not
//!   hash content" is the [`backend::DirBackend`] on-disk spool, which computes
//!   a `sha2-256` **content-address locator** — a filename, zero integrity
//!   weight — with a hand-rolled, zero-dependency sha2-256; that is Filecoin
//!   addressing, NOT the PQ integrity primitive, which stays an opaque slot.)
//!   `hash` compiles the real
//!   `SHAKE-256/256` `hash::Shake256Hasher` (the ONLY feature that pulls a
//!   dependency, `sha3`), and `live` compiles the real Lighthouse
//!   `live::LiveBackend` network client (still zero-dep — a hand-rolled
//!   HTTP/1.1 client that needs a local TLS-terminating proxy). The PQ signer
//!   and the Postern-seal adapter stay in a separate, later crate
//!   (`postern-backup-net`). The honesty gate is the explicit, labelled
//!   feature opt-in — NOT the impossibility of turning crypto on; enabling
//!   either feature still does not make this a working backup system.
//! * **ZERO consensus change; Bloch nodes never parse this.** The `DATA0`
//!   envelope rides the `script_pubkey` of a zero-value output of an
//!   already-valid Bloch transaction (the L2V0/TKV0 idiom). The chain neither
//!   knows nor cares; a malformed envelope is a layer no-op and never
//!   invalidates the carrying transaction.
//! * **Bloch stays ownerless.** Anchoring is permissionless — any fee-payer
//!   can write `DATA0` bytes — so a decoded envelope is only a **claim**. It
//!   becomes trustworthy solely after a reader fetches the manifest package,
//!   recomputes the SHAKE-256 root, and verifies the PQ signature. This crate
//!   does **none** of that verification.
//! * **Nothing here means "your files are backed up".** Sealing, uploading,
//!   deal-making, and monitoring are later phases. The base itself is `k=4`,
//!   low-hashrate, 51%-attackable, and unaudited; anything anchored inherits
//!   that in full.
//!
//! ## Layout
//!
//! [`anchor`] — REAL + TESTED: the fixed 177-byte `DATA0` anchor wire format
//! ([`anchor::AnchorEnvelope`]: `namespace_id`, `sequence`, `prev_root`,
//! `manifest_root`, `signer_commit`, `manifest_cid`) with strict
//! `encode`/`decode`, the typed [`anchor::EnvelopeError`], the unsigned-locator
//! [`anchor::AnchorEnvelope::signing_transcript`], zero-value extraction
//! ([`anchor::extract_anchor`], first-envelope-wins), and the pure
//! canonical-chain check [`anchor::link`]. Follows the L2V0/TKV0 discipline of
//! `l2/bloch-l2-anchor/src/envelope.rs`.
//!
//! [`manifest`] — REAL + TESTED: the strict PBM0 backup-manifest codec
//! ([`manifest::Manifest`], plaintext, lives only inside the seal) —
//! length-prefixed, bounds-checked, re-encodes byte-identically. Each
//! [`manifest::ManifestEntry`] carries the per-blob `shake256` PQ-integrity
//! digest (an opaque slot here). NO `manifest_root`/signature live here — they
//! belong to the [`package`] wrapper.
//!
//! [`package`] — REAL + TESTED: the strict PBP0 package codec
//! ([`package::Package`], the uploaded manifest object) wrapping the sealed
//! manifest + public salt/tier + the signer `pk` and `sig`.
//! [`package::Package::committed_prefix`] returns the exact bytes
//! `manifest_root = SHAKE-256(prefix)` is computed over (the hash lives
//! outside this crate).
//!
//! [`backend`] — SEAM + test double + REAL durable spool: the
//! [`backend::StorageBackend`] trait (`put_car` / `get` / `deal_status`), the
//! in-memory [`backend::MockBackend`] with one-shot fault injection, the
//! [`backend::RecordingBackend`] that replays a caller-scripted, ordered
//! queue of adversarial [`backend::Fault`]s (CidMismatch, truncated bytes,
//! wrong bytes, drop-before-deal) so restore fail-closed paths are tested
//! offline, [`backend::DirBackend`] — a REAL, durable, offline **on-disk spool**
//! that content-addresses each blob under its `CIDv1-raw-sha2-256` filename
//! (hand-rolled sha2-256 + multibase-base32, zero dependencies), survives a
//! fresh instance over the same dir, and fails closed (`NotFound` on a miss,
//! `CidMismatch` on on-disk corruption) — and [`backend::LiveBackend`], a
//! `todo!()` SCAFFOLD stub in the default build, replaced by the REAL Lighthouse
//! client (the `live` module) under `--features live`. The `sha2-256` CID
//! `DirBackend` computes is a **content-address locator** (zero integrity
//! weight); the crate still runs no PQ integrity/signing in the default build.
//!
//! [`seal`] — SEAM + test fixture: the [`seal::Sealer`] / [`seal::Opener`]
//! traits the real `postern-core` AEAD plugs into, and the
//! zero-confidentiality [`seal::MockSealer`] for offline failure-mode tests.
//! This crate NEVER re-implements crypto.
//!
//! [`hash`] — SEAM + test double: the [`hash::Hasher`] trait (the domain-tagged
//! `digest` primitive, with `manifest_root` over [`package::Package::committed_prefix`]
//! and the per-blob `blob_digest` derived from it) that the real `SHAKE-256/256`
//! plugs into, and the deterministic, ZERO-collision-resistance
//! [`hash::MockHasher`] (explicitly NOT SHAKE-256) for offline recompute/tamper
//! tests. Turns the opaque `manifest_root`/`shake256` slots into a seam. The
//! default build NEVER runs real hashing; `--features hash` compiles the real
//! `hash::Shake256Hasher` (`SHAKE-256/256` + `SHA3-256(pk)` `signer_commit`,
//! the crate's only dependency, `sha3`) into that seam — see [Optional
//! features](#optional-features-live--hash).
//!
//! [`journal`] — REAL + TESTED: the append-only backup-set evidence log
//! ([`journal::Journal`], `Sealed → Uploaded → Anchored → DealObserved`) whose
//! stage order is enforced (§7's fail-safe ordering) and whose
//! [`journal::Journal::render`] is **vocabulary-gated** — it emits ONLY the
//! four permitted evidence claims of §6, each with its named evidence and the
//! verbatim [`journal::ANCHOR_CAVEAT`], and NEVER the words "secured" /
//! "backed up" / "permanent" ([`journal::Journal::render_is_clean`] asserts
//! this). No crypto, no verification — roots/txids/CIDs are opaque bytes
//! recorded verbatim.
//!
//! [`scan`] — REAL + TESTED: the reorg-aware DATA0 chain reader
//! ([`scan::ChainScanner::scan`]) over the [`scan::BlockSource`] trait, with
//! the offline [`scan::MockChain`] test double. Mirrors
//! `l2/bloch-l2-anchor/src/{source,manager}.rs`'s journal + rewind-and-replay
//! discipline, retargeted to the DATA0 namespace/sequence field set: two
//! independent readers of the same selected chain reach byte-identical anchor
//! state, reorg-correctly. Derives an **unverified** anchor chain from bytes
//! only — no PQ-signature / manifest / finality check, no live node.
//!
//! [`verify`] — REAL + TESTED (partial, non-PQ legs only): two offline
//! anchor<->package binding checks. (1) The **root-binding**
//! ([`verify::bind_anchor_to_package`]) — recompute `manifest_root` through the
//! [`hash::Hasher`] seam over [`package::Package::committed_prefix`] and compare
//! it to [`anchor::AnchorEnvelope::manifest_root`], returning the typed
//! [`verify::VerifyError::RootMismatch`]. (2) The **signer-binding**
//! ([`verify::bind_signer_to_commit`]) — recompute
//! [`hash::Hasher::signer_commit`] over [`package::Package::pk`] and compare it
//! to [`anchor::AnchorEnvelope::signer_commit`], returning the typed
//! [`verify::VerifyError::SignerMismatch`]. Both are the OFFLINE HALF of §1's
//! "recompute, compare to the anchor". They establish NO authenticity: the
//! PQ-signature leg is **NOT** run, and the signer-binding uses the
//! ZERO-collision-resistance [`hash::MockHasher`], **NOT** the real
//! `signer_commit == SHA3-256(pk)` — the real SHA3-256 hash AND the PQ signature
//! are GATED behind `postern-backup-net` (real crypto), exactly like every
//! other slot in this crate.
//!
//! ## Optional features (`live` + `hash`)
//!
//! Both are **UNAUDITED**, **OFF by default**, and gated so the default build
//! stays zero-dependency and network-incapable. Enabling them makes the named
//! primitive real but does **not** produce a working backup system — sealing
//! (confidentiality) and the ML-DSA/Falcon PQ signer stay out of scope.
//!
//! * `hash` — compiles `hash::Shake256Hasher`, the real `SHAKE-256/256`
//!   integrity primitive (domain-tagged `manifest_root`/`blob_digest`) with a
//!   real `SHA3-256(pk)` [`hash::Hasher::signer_commit`] override, KAT-tested
//!   in `tests/hash_kat.rs`. This is the ONLY feature that pulls a crate
//!   dependency (`sha3`).
//! * `live` — compiles `live::LiveBackend`, the real Lighthouse
//!   hosted-provider client, re-exported as [`backend::LiveBackend`]. It adds
//!   **no** dependency (a hand-rolled HTTP/1.1 client over
//!   `std::net::TcpStream`), but TLS is **not** linked in-crate: reaching the
//!   real HTTPS Lighthouse hosts needs a local TLS-terminating proxy plus the
//!   `LIGHTHOUSE_*_URL` env overrides (`https://` targets are rejected with a
//!   typed error). Data is Postern-sealed before it reaches any backend, so the
//!   provider stores ciphertext only, and the returned CID is a locator with
//!   zero integrity weight. See the `live` module docs (present under
//!   `--features live`).
//!
//! Licensed under MIT OR Apache-2.0.

pub mod anchor;
pub mod backend;
/// REAL hosted-provider client (Lighthouse), gated behind the `live` feature.
///
/// Off by default: the default build has no network client at all (the
/// structural honesty gate). With `--features live` this module provides the
/// real [`live::LiveBackend`] — a zero-dependency, hand-rolled HTTP/1.1 client
/// over `std::net::TcpStream` — re-exported as [`backend::LiveBackend`]. Data
/// is Postern-SEALED before it is ever handed to a backend, so the provider
/// stores ciphertext only; the returned CID is a provider locator with zero
/// integrity weight (§4). Reference prototype, UNAUDITED.
#[cfg(feature = "live")]
pub mod live;
pub mod hash;
pub mod journal;
pub mod manifest;
pub mod package;
pub mod scan;
pub mod seal;
pub mod verify;

pub use anchor::{
    decode_anchor_output, extract_anchor, link, select_head, AnchorEnvelope, EnvelopeError,
    LinkError, Tx, TxIn, TxOut, CID_LEN, ENVELOPE_LEN, ENVELOPE_MAGIC, ENVELOPE_VERSION,
};
pub use backend::{
    BackendError, Cid, DealInfo, DealStatus, DirBackend, Fault, LiveBackend, MockBackend,
    RecordingBackend, StorageBackend,
};
pub use hash::{Hasher, MockHasher, DOMAIN_BLOB, DOMAIN_MANIFEST_ROOT, DOMAIN_SIGNER_COMMIT};
#[cfg(feature = "hash")]
pub use hash::Shake256Hasher;
pub use manifest::{
    Manifest, ManifestEntry, ManifestError, MANIFEST_HEADER_LEN, MANIFEST_MAGIC, MANIFEST_VERSION,
};
pub use journal::{
    AnchorDepth, Evidence, Journal, JournalError, JournalRecord, Stage, ANCHOR_CAVEAT,
    FORBIDDEN_CLAIMS,
};
pub use package::{
    Package, PackageError, PACKAGE_HEADER_LEN, PACKAGE_MAGIC, PACKAGE_VERSION, SALT_LEN,
    TIER_DEFAULT, TIER_FLOOR,
};
pub use scan::{
    AnchorStatus, Block, BlockHash, BlockSource, ChainScanner, MockChain, ScanError, ScanReport,
    SourceError, SourceTx, TrackedAnchor,
};
pub use seal::{MockSealer, Opener, SealError, Sealer};
pub use verify::{bind_anchor_to_package, bind_signer_to_commit, VerifyError};
