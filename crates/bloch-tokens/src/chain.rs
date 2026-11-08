//! Minimal chain-read model: [`OutPoint`] + [`ChainTx`].
//!
//! The token standard is OFF-consensus: an indexer only ever **reads**
//! already-valid transactions from a node (via the documented RPC in a real
//! deployment). These types model exactly what that read path yields — txid,
//! spent outpoints, outputs — nothing more. The block/RPC shape (hashes,
//! heights, the `BlockSource` trait and the `MockChain` test double) lives
//! in [`crate::stream`].
//!
//! Nothing here validates, produces, or alters chain data: chain validity is
//! the node's job and is assumed. The token layer can therefore never
//! invalidate a chain transaction — it only derives an *interpretation* of
//! transactions the chain already accepted.

use crate::envelope::TxOut;

/// Reference to a transaction output: `(txid, vout)`.
///
/// `Ord` is derived (txid bytes, then vout) so indexer state held in
/// `BTreeMap`s serializes in one canonical order on every machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OutPoint {
    pub txid: [u8; 32],
    pub vout: u32,
}

/// A chain transaction as seen by a reader: its id, the outpoints it spends,
/// and the outputs it creates. (Named `ChainTx` to avoid clashing with the
/// signature-level [`crate::envelope::Tx`] mirror used by the wire layer.)
///
/// This is the subset of the node's `Transaction` schema (openapi.yaml) the
/// token layer reads: `txid`, `inputs[].{prev_txid, prev_index}` (as
/// [`OutPoint`]s), `outputs[].{value, script_pubkey}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainTx {
    pub txid: [u8; 32],
    pub inputs: Vec<OutPoint>,
    pub outputs: Vec<TxOut>,
}
