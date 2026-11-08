//! # bloch-tokens
//!
//! Neutral reference implementation of the **Bloch token-envelope standard**
//! (TKV0): an *off-consensus* byte convention for issuing and transferring
//! tokens by embedding a small, strictly-validated payload ("envelope") in a
//! zero-value output of an ordinary Bloch transaction — plus the
//! deterministic state machine and reproducible indexer that read it back.
//!
//! ## What this crate is — and is not
//!
//! * **ZERO consensus change.** Nothing here touches the node, PoW, block or
//!   transaction validation. The chain neither knows nor cares about
//!   envelopes; token state is derived entirely by *readers* (indexers) that
//!   scan already-valid transactions via the documented read RPC (or a mock).
//!   This is a convention, not a fork and not a new consensus rule.
//! * **Bloch stays ownerless.** The standard is fully specified by this
//!   crate's byte layout and indexer rules; anyone can run an independent
//!   indexer and must arrive at the same token state. No party — Postern
//!   included — holds any privilege over it.
//! * **BLCH is untouched.** The base coin is never a token under this
//!   standard, and the standard adds no revenue, burn, or promoter mechanism
//!   of any kind to BLCH. It only lets issuers create *other* tokens.
//! * **Design scaffold — unaudited, pre-mainnet.** Do not rely on this code
//!   for value. A token's legal/securities status is its **issuer's**
//!   responsibility, not Bloch's (the Ethereum-neutrality posture).
//!
//! ## Layout
//!
//! [`envelope`] — the TKV0 wire format: [`envelope::TokenOp`] with strict
//! `encode`/`decode`, the typed [`envelope::EnvelopeError`], and
//! [`envelope::extract_envelope`] (first envelope wins; zero-value rule).
//!
//! [`chain`] — the minimal read model: [`chain::OutPoint`] and
//! [`chain::ChainTx`], the subset of the node's `Transaction` schema the
//! token layer reads.
//!
//! [`state`] — the deterministic state machine: [`state::TokenState`] (token
//! registry, colored-outpoint map, balances by script) with a pure
//! [`state::TokenState::apply_tx`] returning a total
//! [`state::ApplyOutcome`] — never an error, because the token layer cannot
//! invalidate a chain transaction by construction. All containers are
//! `BTreeMap`s: no observable output depends on hash-iteration order.
//!
//! [`stream`] — chain read access: [`stream::BlockSource`], shaped exactly
//! on the node's JSON-RPC methods (`getblockcount`, `getblockhash`,
//! `getblockbyheight` — see `docs/openapi.yaml` in the BlochSISPoW repo),
//! plus [`stream::MockChain`], an in-memory source that can be forced to
//! reorg. The DEFAULT build is zero-dependency and offline-buildable (no
//! tokio, no HTTP). The optional `rpc-client` feature adds
//! [`stream::rpc::RpcBlockSource`] — a real, read-only JSON-RPC
//! [`stream::BlockSource`] that drives the same indexer against a live node
//! (hand-rolled HTTP over std `TcpStream`; only `serde_json` is pulled in).
//!
//! [`indexer`] — the reproducible reference indexer:
//! [`indexer::Indexer::sync`] replays heights in order, keeps a per-height
//! block-hash journal + state snapshots, detects reorgs by hash mismatch and
//! rewinds-then-replays; after any reorg it converges to exactly the state
//! of a fresh replay of the new chain (asserted by equality in tests).
//!
//! The normative byte-layout tables and indexer rules live in `SPEC.md` next
//! to this crate; `tests/vectors.rs` pins the wire layout with hand-written
//! golden vectors.
//!
//! Licensed under MIT OR Apache-2.0.

pub mod chain;
pub mod envelope;
pub mod indexer;
pub mod state;
pub mod stream;

pub use chain::{ChainTx, OutPoint};
pub use envelope::{
    decode_envelope_output, extract_envelope, EnvelopeError, TokenOp, TxOut, ENVELOPE_MAGIC,
    ENVELOPE_VERSION, FLAG_MINT_CLOSED, MAX_ASSIGNMENTS, MAX_DECIMALS, MAX_NAME_LEN,
    MAX_SYMBOL_LEN,
};
pub use indexer::{Indexer, SyncReport};
pub use state::{
    ApplyOutcome, ColoredCoin, NoOpReason, TokenEffect, TokenId, TokenInfo, TokenState,
};
pub use stream::{Block, BlockHash, BlockSource, MockChain, SourceError};

/// Live JSON-RPC block source (optional `rpc-client` feature). Re-exported so
/// consumers can `use bloch_tokens::RpcBlockSource;` when the feature is on.
#[cfg(feature = "rpc-client")]
pub use stream::rpc::RpcBlockSource;
