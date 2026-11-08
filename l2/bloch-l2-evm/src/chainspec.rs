// SPDX-License-Identifier: MIT OR Apache-2.0
//! Chain specification — the design's genesis knobs (BLOCH-L2-EVM-DESIGN §1).
//!
//! **SCAFFOLD, UNAUDITED, not a working L2.** These are the testnet /
//! zero-value parameters; chain id 700771 is a placeholder pending
//! ethereum-lists/chains registration.

use alloy_primitives::{address, Address, U256};
use revm::primitives::hardfork::SpecId;

/// OP-Stack-convention predeploy address for the sequencer fee vault
/// (priority fees land here; it is also the block's COINBASE, per the design:
/// "COINBASE returns the fee-vault address").
pub const SEQUENCER_FEE_VAULT: Address = address!("4200000000000000000000000000000000000011");

/// OP-Stack-convention predeploy address for the base-fee vault. The EIP-1559
/// basefee is routed here instead of being destroyed — bridged BLCH is
/// **never burned**, so the L1 escrow always balances and no party operates a
/// BLCH supply-reduction mechanism.
pub const BASE_FEE_VAULT: Address = address!("4200000000000000000000000000000000000019");

/// Genesis / consensus-parameter knobs for the Bloch EVM L2, mirroring
/// `docs/specs/BLOCH-L2-EVM-DESIGN.md` §1's ChainSpec.
///
/// The EVM itself is UNMODIFIED revm at a named hardfork ([`SpecId::CANCUN`]).
/// The only deltas from mainline Ethereum are the enumerated, legal,
/// non-semantic knobs below (chain id, fee routing, zero issuance).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainSpec {
    /// EIP-155 chain id. 700771 = proposed Bloch L2 **testnet** id
    /// (placeholder pending ethereum-lists/chains registration).
    pub chain_id: u64,
    /// The pinned revm hardfork. CANCUN at genesis; Prague only via a
    /// coordinated, height-gated upgrade (out of scope for this scaffold).
    pub spec_id: SpecId,
    /// Block gas limit — Ethereum-mainnet parity (30M) so any
    /// mainnet-deployable contract deploys.
    pub gas_limit: u64,
    /// Target L2 block time in seconds (informational for this scaffold; no
    /// consensus loop exists here).
    pub block_time_secs: u64,
    /// EIP-1559 elasticity multiplier (gas target = gas_limit / elasticity).
    pub base_fee_elasticity: u64,
    /// EIP-1559 base-fee max-change denominator (raised toward the OP-Stack
    /// range so the basefee is stable at 2s blocks — a chain-config value
    /// Ethereum itself varies per network, not an EVM change).
    pub base_fee_denominator: u64,
    /// Base fee of the genesis block, in wei per gas (1 gwei).
    pub initial_base_fee: u64,
    /// Block reward. **Always zero**: the L2 never issues — native balance
    /// enters only via deposit mints of bridged BLCH.
    pub block_reward: U256,
    /// Where the EIP-1559 basefee is routed (never burned).
    pub base_fee_vault: Address,
    /// Where priority fees are routed; also the block beneficiary /
    /// COINBASE.
    pub sequencer_fee_vault: Address,
}

impl ChainSpec {
    /// The testnet / zero-value parameter set from the design.
    pub fn testnet() -> Self {
        Self {
            chain_id: 700_771,
            spec_id: SpecId::CANCUN,
            gas_limit: 30_000_000,
            block_time_secs: 2,
            base_fee_elasticity: 2,
            base_fee_denominator: 250,
            initial_base_fee: 1_000_000_000, // 1 gwei
            block_reward: U256::ZERO,
            base_fee_vault: BASE_FEE_VAULT,
            sequencer_fee_vault: SEQUENCER_FEE_VAULT,
        }
    }

    /// The address the COINBASE opcode observes (the design routes it to the
    /// sequencer fee vault so priority fees land there via unmodified revm
    /// beneficiary payment).
    pub fn coinbase(&self) -> Address {
        self.sequencer_fee_vault
    }

    /// EIP-1559 gas target per block (`gas_limit / elasticity`).
    pub fn gas_target(&self) -> u64 {
        self.gas_limit / self.base_fee_elasticity
    }

    /// EIP-1559 next-base-fee computation with this chain's elasticity /
    /// denominator knobs. Pure integer math (u128 internally, no overflow for
    /// any realistic base fee), byte-identical to the Ethereum formula with
    /// retuned constants.
    pub fn next_base_fee(&self, parent_base_fee: u64, parent_gas_used: u64) -> u64 {
        let target = self.gas_target();
        if target == 0 {
            return parent_base_fee;
        }
        let parent = parent_base_fee as u128;
        let denom = self.base_fee_denominator as u128;
        match parent_gas_used.cmp(&target) {
            core::cmp::Ordering::Equal => parent_base_fee,
            core::cmp::Ordering::Greater => {
                let gas_delta = (parent_gas_used - target) as u128;
                let delta = core::cmp::max(1, parent * gas_delta / target as u128 / denom);
                u64::try_from(parent + delta).unwrap_or(u64::MAX)
            }
            core::cmp::Ordering::Less => {
                let gas_delta = (target - parent_gas_used) as u128;
                let delta = parent * gas_delta / target as u128 / denom;
                u64::try_from(parent - delta).unwrap_or(0)
            }
        }
    }
}

impl Default for ChainSpec {
    fn default() -> Self {
        Self::testnet()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testnet_knobs_match_design() {
        let spec = ChainSpec::testnet();
        assert_eq!(spec.chain_id, 700_771);
        assert_eq!(spec.spec_id, SpecId::CANCUN);
        assert_eq!(spec.gas_limit, 30_000_000);
        assert_eq!(spec.base_fee_elasticity, 2);
        assert_eq!(spec.base_fee_denominator, 250);
        assert_eq!(spec.initial_base_fee, 1_000_000_000);
        assert_eq!(spec.block_reward, U256::ZERO, "zero issuance, always");
        assert_eq!(spec.gas_target(), 15_000_000);
        assert_eq!(spec.coinbase(), SEQUENCER_FEE_VAULT);
        assert_ne!(spec.base_fee_vault, spec.sequencer_fee_vault);
    }

    #[test]
    fn base_fee_constant_at_target() {
        let spec = ChainSpec::testnet();
        let bf = spec.initial_base_fee;
        assert_eq!(spec.next_base_fee(bf, spec.gas_target()), bf);
    }

    #[test]
    fn base_fee_rises_on_full_block() {
        let spec = ChainSpec::testnet();
        let bf = 1_000_000_000u64;
        // full block: gas_used = gas_limit = 2 * target → delta = bf / denominator
        let next = spec.next_base_fee(bf, spec.gas_limit);
        assert_eq!(next, bf + bf / 250);
        assert!(next > bf);
    }

    #[test]
    fn base_fee_falls_on_empty_block() {
        let spec = ChainSpec::testnet();
        let bf = 1_000_000_000u64;
        // empty block: gas_used = 0 → delta = bf / denominator
        let next = spec.next_base_fee(bf, 0);
        assert_eq!(next, bf - bf / 250);
        assert!(next < bf);
    }

    #[test]
    fn base_fee_increase_is_at_least_one_wei() {
        let spec = ChainSpec::testnet();
        // tiny parent base fee: integer division would give 0; EIP-1559
        // clamps the increase to at least 1 wei.
        let next = spec.next_base_fee(1, spec.gas_limit);
        assert_eq!(next, 2);
    }
}
