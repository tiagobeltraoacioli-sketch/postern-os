// SPDX-License-Identifier: MIT OR Apache-2.0
//! EIP-1559 basefee update and effective-tip math (§1 of
//! `BLOCH-L2-EVM-DESIGN.md`).
//!
//! All arithmetic is plain `u128` — no U256 dependency. Overflow bounds,
//! documented: the only multiplication is `parent_basefee * gas_delta` where
//! `gas_delta ≤ gas_target ≤ 30_000_000 < 2^25`, so the math is exact for any
//! `parent_basefee < 2^103` wei (≈ 10^31 wei ≈ 10^13 ether **per gas** — far
//! beyond anything reachable from a 1-gwei genesis under a 1/250 max step).
//! Inputs beyond that bound panic with an explicit message rather than
//! silently wrapping.

use crate::params::{
    BASEFEE_CHANGE_DENOMINATOR, GAS_TARGET, MIN_BASEFEE_WEI,
};

/// EIP-1559 basefee update rule.
///
/// * `parent_gas_used == gas_target` → basefee unchanged.
/// * above target → increase by `parent_basefee * excess / gas_target /
///   denominator`, minimum step 1 wei (the EIP-1559 `max(.., 1)` rule).
/// * below target → decrease by the symmetric amount (no minimum step).
/// * the result is clamped to `floor` (§4's "min base fee floor"; pass 0 for
///   pure Ethereum semantics).
///
/// # Panics
/// If `gas_target == 0`, `denominator == 0`, or `parent_basefee * gas_delta`
/// overflows `u128` (see module docs for the documented bound).
pub fn next_basefee(
    parent_basefee: u128,
    parent_gas_used: u64,
    gas_target: u64,
    denominator: u128,
    floor: u128,
) -> u128 {
    assert!(gas_target > 0, "gas_target must be non-zero");
    assert!(denominator > 0, "denominator must be non-zero");

    let scaled = |gas_delta: u64| -> u128 {
        parent_basefee
            .checked_mul(gas_delta as u128)
            .expect("basefee overflow: parent_basefee * gas_delta exceeds u128 (documented bound: parent_basefee < 2^103)")
            / gas_target as u128
            / denominator
    };

    let next = if parent_gas_used == gas_target {
        parent_basefee
    } else if parent_gas_used > gas_target {
        let delta = scaled(parent_gas_used - gas_target).max(1);
        parent_basefee.saturating_add(delta)
    } else {
        let delta = scaled(gas_target - parent_gas_used);
        parent_basefee.saturating_sub(delta)
    };
    next.max(floor)
}

/// [`next_basefee`] with the §1 chain parameters (gas target 15M, denominator
/// 250) and the scaffold-placeholder floor from [`crate::params`].
pub fn next_basefee_default(parent_basefee: u128, parent_gas_used: u64) -> u128 {
    next_basefee(
        parent_basefee,
        parent_gas_used,
        GAS_TARGET,
        BASEFEE_CHANGE_DENOMINATOR,
        MIN_BASEFEE_WEI,
    )
}

/// EIP-1559 effective tip: `min(max_priority_fee, max_fee - basefee)`.
///
/// Returns `None` when `max_fee < basefee` — the transaction is not includable
/// at this basefee (it stays in the pool; it is never given a lane).
pub fn effective_tip(
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
    basefee: u128,
) -> Option<u128> {
    if max_fee_per_gas < basefee {
        None
    } else {
        Some(max_priority_fee_per_gas.min(max_fee_per_gas - basefee))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{GAS_TARGET, INITIAL_BASEFEE_WEI, L2_GAS_LIMIT, MIN_BASEFEE_WEI};

    #[test]
    fn at_target_is_unchanged() {
        assert_eq!(
            next_basefee(INITIAL_BASEFEE_WEI, GAS_TARGET, GAS_TARGET, 250, 0),
            INITIAL_BASEFEE_WEI
        );
    }

    #[test]
    fn full_block_from_genesis_params_section_1() {
        // §1: initial 1 gwei, gas limit 30M (target 15M), denominator 250.
        // Full 30M block: delta = 1e9 * 15M / 15M / 250 = 4_000_000 wei.
        let next = next_basefee_default(INITIAL_BASEFEE_WEI, L2_GAS_LIMIT);
        assert_eq!(next, 1_004_000_000);
    }

    #[test]
    fn empty_block_from_genesis_params_section_1() {
        // Empty block: delta = 1e9 / 250 = 4_000_000 wei down — but the
        // scaffold floor is 1 gwei, so the default clamps back to 1 gwei.
        assert_eq!(next_basefee_default(INITIAL_BASEFEE_WEI, 0), MIN_BASEFEE_WEI);
        // Without a floor the pure EIP-1559 result applies.
        assert_eq!(
            next_basefee(INITIAL_BASEFEE_WEI, 0, GAS_TARGET, 250, 0),
            996_000_000
        );
    }

    #[test]
    fn decrease_above_floor_is_not_clamped() {
        let two_gwei = 2_000_000_000u128;
        let next = next_basefee(two_gwei, 0, GAS_TARGET, 250, MIN_BASEFEE_WEI);
        assert_eq!(next, two_gwei - two_gwei / 250);
        assert!(next > MIN_BASEFEE_WEI);
    }

    #[test]
    fn increase_has_minimum_step_of_one_wei() {
        // Tiny basefee, barely above target: integer math gives 0, EIP-1559
        // mandates a minimum step of 1.
        let next = next_basefee(100, GAS_TARGET + 1, GAS_TARGET, 250, 0);
        assert_eq!(next, 101);
    }

    #[test]
    fn decrease_has_no_minimum_step() {
        // Barely below target with a tiny basefee: delta rounds to 0.
        let next = next_basefee(100, GAS_TARGET - 1, GAS_TARGET, 250, 0);
        assert_eq!(next, 100);
    }

    #[test]
    fn clamps_to_floor_when_decreasing_at_floor() {
        let next = next_basefee(MIN_BASEFEE_WEI, 0, GAS_TARGET, 250, MIN_BASEFEE_WEI);
        assert_eq!(next, MIN_BASEFEE_WEI);
    }

    #[test]
    fn max_single_step_is_bounded_by_denominator() {
        // With elasticity 2, gas_used ≤ 2 * target, so the per-block increase
        // is at most parent/250 (0.4%).
        let parent = 123_456_789_000u128;
        let up = next_basefee(parent, L2_GAS_LIMIT, GAS_TARGET, 250, 0);
        assert!(up - parent <= parent / 250 + 1);
        let down = next_basefee(parent, 0, GAS_TARGET, 250, 0);
        assert!(parent - down <= parent / 250);
    }

    #[test]
    fn effective_tip_semantics() {
        // Tip capped by max_fee - basefee.
        assert_eq!(effective_tip(120, 50, 100), Some(20));
        // Tip capped by max_priority_fee.
        assert_eq!(effective_tip(200, 5, 100), Some(5));
        // Not includable below basefee.
        assert_eq!(effective_tip(99, 5, 100), None);
        // Exactly at basefee: includable with zero tip.
        assert_eq!(effective_tip(100, 5, 100), Some(0));
    }
}
