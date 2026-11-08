// SPDX-License-Identifier: MIT OR Apache-2.0
//! Honest stubs — the large integrations this scaffold deliberately does NOT
//! contain. Every function here panics with `todo!` and exists only so the
//! missing surface is named, typed, and impossible to mistake for working
//! code. Do not call any of these.

use crate::batch::Batch;
use crate::block::L2Block;
use crate::deposit::DepositTx;

/// SCAFFOLD: revm execution hookup. The real sequencer executes assembled
/// blocks through the shared `bloch-l2-evm` crate (unmodified revm pinned to
/// SpecId::CANCUN, §1) and produces receipts/state roots. Nothing in this
/// crate executes anything.
pub fn execute_block_revm(_block: &L2Block) -> ! {
    todo!("SCAFFOLD: revm execution belongs to the bloch-l2-evm crate (unbuilt)")
}

/// SCAFFOLD: the `eth_*` JSON-RPC server (§1 interface list: Reth's
/// implementations, unmodified). No RPC exists in this crate.
pub fn serve_eth_rpc() -> ! {
    todo!("SCAFFOLD: eth_* RPC server (Reth jsonrpsee stack) not implemented")
}

/// SCAFFOLD: anchor posting. Sealed [`Batch`]es are committed to Bloch as
/// `L2V0` BATCH envelopes by the sibling `bloch-l2-anchor` crate (see the
/// field-correspondence table in [`crate::batch`]); this crate never touches
/// the Bloch RPC.
pub fn post_anchor(_batch: &Batch) -> ! {
    todo!("SCAFFOLD: L2V0 anchor posting belongs to bloch-l2-anchor (disjoint crate)")
}

/// SCAFFOLD: DA publication (§4 Mode A on-Bloch chunks / Mode B mirror with
/// the bold withholding disclosure). Not implemented anywhere yet.
pub fn publish_da(_batch: &Batch) -> ! {
    todo!("SCAFFOLD: DA publication (Mode A chunks / Mode B mirror) not implemented")
}

/// SCAFFOLD: forced-inclusion `FORCE_TX` scanning (§4 op 0x04: envelopes K=24
/// deep MUST execute within W=240 Bloch blocks). Requires the Bloch replay
/// reader (bloch-tokens indexer pattern); the derived txs would be fed into
/// block assembly as mandatory entries, like deposits.
pub fn scan_force_txs() -> ! {
    todo!("SCAFFOLD: FORCE_TX scanning of the Bloch chain not implemented")
}

/// SCAFFOLD: deposit derivation from L1 (§5 `L2D0` envelope watcher at
/// confirmation depth K). Callers of [`crate::block::build_block`] currently
/// supply [`DepositTx`]s directly; the real derivation reads them from Bloch.
pub fn derive_deposits_from_l1() -> Vec<DepositTx> {
    todo!("SCAFFOLD: L2D0 deposit derivation (Bloch watcher) not implemented")
}

/// SCAFFOLD: zstd -19 batch compression with a trained dictionary (§4).
/// Until this exists, `Batch::batch_data_hash` commits to RAW canonical
/// bytes — the documented delta in [`crate::batch`].
pub fn compress_batch_zstd(_raw: &[u8]) -> ! {
    todo!("SCAFFOLD: zstd compression not implemented; batch hash is over raw bytes")
}
