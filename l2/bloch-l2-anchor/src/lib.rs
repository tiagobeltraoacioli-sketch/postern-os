//! # bloch-l2-anchor
//!
//! **SCAFFOLD, UNAUDITED, NOT A WORKING L2.** Reference codec for the
//! **L2V0 COMMIT anchor envelope** — the *off-consensus* byte convention by
//! which the (designed, unbuilt) Bloch EVM L2 writes batch commitments to
//! the ownerless Bloch base as ordinary transactions. Spec:
//! `docs/specs/BLOCH-L2-EVM-DESIGN.md` (§1 "Interfaces / formats", §2
//! anchor layer), mirroring the TKV0 idiom from `crates/bloch-tokens`.
//!
//! ## What this crate is — and is not
//!
//! * **ZERO consensus change; Bloch nodes never parse this.** The envelope
//!   rides the `script_pubkey` of a zero-value output of an already-valid
//!   Bloch transaction. The chain neither knows nor cares about it; anchor
//!   state is derived entirely by *readers*. A malformed envelope is an
//!   anchor-layer no-op and never invalidates the carrying transaction.
//!   This is a reader convention, not a fork and not a new consensus rule.
//! * **Bloch stays ownerless.** Anyone can run an independent anchor reader
//!   over this convention and must derive the same anchor chain; no party
//!   (Postern included) is privileged at the base layer. The L2 *itself* is
//!   an owned, operated product — that ownership never leaks into Bloch.
//! * **Not a working L2, not a prover, not a verifier.** A decoded envelope
//!   is an unverified *claim*. This crate does not check SP1 proofs, DA
//!   availability, or Bloch confirmation depth. There is no sequencer, no
//!   bridge, no node here.
//! * **Scaffold — unaudited, pre-anything.** Do not rely on this code for
//!   value. See the design doc's reorg gate: Bloch today is k=4 forgeable
//!   and 51%-attackable, and an L2 inherits its L1's finality.
//!
//! ## Layout
//!
//! [`envelope`] — REAL + TESTED: the fixed 173-byte L2V0 COMMIT wire format
//! ([`envelope::AnchorEnvelope`]) with strict `encode`/`decode`, the typed
//! [`envelope::EnvelopeError`], zero-value extraction
//! ([`envelope::extract_anchor`], first-envelope-wins), and the pure
//! canonical-chain linkage check [`envelope::link`]. `tests/vectors.rs`
//! pins the wire layout with a hand-written golden vector, exactly as
//! `bloch-tokens/tests/vectors.rs` pins TKV0.
//!
//! [`source`] — REAL + TESTED (offline): the [`source::BlockSource`] read
//! trait (shaped on the node's `getblockcount`/`getblockhash`/
//! `getblockbyheight` RPC) and the deterministic [`source::MockChain`] stand
//! -in, mirroring `bloch-tokens`' `stream` module one-to-one. The default
//! build is zero-dependency and offline. Behind the OFF-by-default `http`
//! feature, [`source::HttpBlockSource`] is a REAL read-only JSON-RPC client
//! (`--features http`) that wires [`source::BlockSource`] to a live Bloch node
//! — hand-rolled on `std` only, so even with the feature on the crate pulls in
//! zero third-party dependencies. It is strictly READ
//! (`getblockcount`/`getblockhash`/`getblockbyheight`) and maps the node's
//! in-`result` method-error quirk (HTTP 200 with `{"result":{"error":…}}`) to
//! [`source::SourceError::HeightNotFound`]. It never writes to, restarts, or
//! reconfigures a node. Still SCAFFOLD/UNAUDITED: reading real blocks does not
//! make any decoded anchor a verified claim.
//!
//! [`manager`] — the reorg-aware anchor reader: [`manager::AnchorStatus`]
//! (`Pending` / `Anchored { depth }` / `Orphaned`),
//! [`manager::TrackedAnchor`], and [`manager::AnchorManager::sync`], which
//! replays any [`source::BlockSource`] over a per-height block-hash journal
//! and recovers from reorgs by rewind-and-replay — the same discipline
//! `bloch-tokens`' `indexer::Indexer` uses for TKV0, and equality-tested
//! against a fresh replay of the current chain. This derives an *unverified*
//! anchor chain from bytes only: still SCAFFOLD/UNAUDITED, still not a working
//! L2, no prover, no bridge, no live node.
//!
//! Licensed under MIT OR Apache-2.0.

pub mod envelope;
pub mod manager;
pub mod source;

pub use envelope::{
    decode_anchor_output, extract_anchor, link, AnchorEnvelope, EnvelopeError, LinkError, Tx,
    TxIn, TxOut, ENVELOPE_LEN, ENVELOPE_MAGIC, ENVELOPE_VERSION,
};
pub use manager::{AnchorManager, AnchorStatus, AnchorSyncReport, SyncError, TrackedAnchor};
pub use source::{Block, BlockHash, BlockSource, MockChain, SourceError, SourceTx};
#[cfg(feature = "http")]
pub use source::HttpBlockSource;
