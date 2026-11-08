// SPDX-License-Identifier: MIT OR Apache-2.0
//! Chain / sequencer parameters, verbatim from `BLOCH-L2-EVM-DESIGN.md`.
//!
//! SCAFFOLD values: several are spec *placeholders* (chain id pending
//! ethereum-lists registration; the basefee floor is an open question in §4's
//! mempool policy). Nothing here is final or audited.

/// Proposed testnet chain id (§1 — placeholder pending registration).
pub const CHAIN_ID_TESTNET: u64 = 700_771;

/// L2 block time (§1: 2-second L2 blocks).
pub const L2_BLOCK_TIME_SECS: u64 = 2;

/// Block gas limit (§1: Ethereum-mainnet parity, 30,000,000).
pub const L2_GAS_LIMIT: u64 = 30_000_000;

/// EIP-1559 elasticity multiplier (§1 ChainSpec: `elasticity: 2`).
pub const ELASTICITY_MULTIPLIER: u64 = 2;

/// EIP-1559 gas target = gas_limit / elasticity.
pub const GAS_TARGET: u64 = L2_GAS_LIMIT / ELASTICITY_MULTIPLIER;

/// EIP-1559 basefee change denominator (§1 ChainSpec: `denominator: 250`,
/// raised toward the OP-Stack range for stability at 2 s blocks).
pub const BASEFEE_CHANGE_DENOMINATOR: u128 = 250;

/// Initial basefee (§1 ChainSpec: `initial: 1 gwei`).
pub const INITIAL_BASEFEE_WEI: u128 = 1_000_000_000;

/// Minimum basefee floor. §4's published mempool policy names a "min base fee
/// floor" but the spec leaves its value open; SCAFFOLD placeholder = 1 gwei
/// (the initial basefee). Passed explicitly to [`crate::fees::next_basefee`]
/// so callers can retune it.
pub const MIN_BASEFEE_WEI: u128 = 1_000_000_000;

// ---- §4 published mempool policy ----

/// Max nonce gap ahead of the sender's next expected nonce ("nonce-gap ≤ 16").
pub const NONCE_GAP_MAX: u64 = 16;

/// Per-sender pending-transaction cap ("pending cap 64 txs/sender").
pub const SENDER_PENDING_CAP: usize = 64;

/// Replacement requires a ≥10% effective-tip bump; enforced here as ≥10% on
/// both fee caps (the geth/OP convention), since effective tip depends on a
/// basefee not known at admission time.
pub const REPLACEMENT_BUMP_PERCENT: u128 = 10;

/// Max raw transaction size ("tx ≤ 128 KiB").
pub const MAX_TX_BYTES: usize = 128 * 1024;

/// Priority-lane effective-tip threshold (§4: "priority lane (effective tip ≥
/// priority threshold)"). The spec does not fix the value; SCAFFOLD
/// placeholder = 1 gwei. Always passed explicitly to ordering functions.
pub const PRIORITY_LANE_TIP_THRESHOLD_WEI: u128 = 1_000_000_000;

// ---- §4 batcher bounds ----

/// Seal a batch when pending canonical bytes reach this bound (§4: 256 KiB —
/// spec measures *compressed* bytes; compression is stubbed here, see
/// `crate::batch`).
pub const BATCH_TARGET_BYTES: usize = 256 * 1024;

/// Seal a batch on this cadence regardless of size (§4: every 300 s).
pub const BATCH_CADENCE_SECS: u64 = 300;

/// Block-count bound per batch: one cadence window of 2 s blocks.
pub const BATCH_MAX_BLOCKS: usize = (BATCH_CADENCE_SECS / L2_BLOCK_TIME_SECS) as usize;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_params_match_spec_section_1_and_4() {
        assert_eq!(GAS_TARGET, 15_000_000);
        assert_eq!(BATCH_MAX_BLOCKS, 150);
        assert_eq!(BATCH_TARGET_BYTES, 262_144);
    }
}
