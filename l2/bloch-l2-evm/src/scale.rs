// SPDX-License-Identifier: MIT OR Apache-2.0
//! Exact L1-sats ⇄ L2-wei scaling (BLOCH-L2-EVM-DESIGN §1 unit mapping).
//!
//! BLCH is u64 base units ("sats") with 8 decimals on L1; the L2 scales by
//! `10^10` so 1 BLCH = `10^18` wei-equivalent and MetaMask/ethers display
//! naturally. The bridge must enforce that the scaling is **exact** in both
//! directions — these helpers are that rule in code. Pure integer math.

use alloy_primitives::U256;

/// `10^10`: the exact multiplier from u64 L1 sats (8 decimals) to U256 L2 wei
/// (18 decimals).
pub const ATOM_SCALE: u64 = 10_000_000_000;

/// One BLCH in L1 sats (8 decimals).
pub const SATS_PER_BLCH: u64 = 100_000_000;

/// One BLCH in L2 wei (18 decimals).
pub const WEI_PER_BLCH: U256 = U256::from_limbs([1_000_000_000_000_000_000, 0, 0, 0]);

/// Error for an L2-wei amount that does not correspond exactly to a whole
/// number of L1 sats representable in u64.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScaleError {
    /// The wei amount is not a multiple of [`ATOM_SCALE`]; it cannot have
    /// come from (or return to) L1 sats exactly, and rounding is forbidden.
    NotAtomAligned,
    /// The sat amount exceeds `u64::MAX` and cannot exist on L1.
    SatsOverflow,
}

impl core::fmt::Display for ScaleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ScaleError::NotAtomAligned => {
                write!(f, "wei amount is not an exact multiple of ATOM_SCALE (10^10)")
            }
            ScaleError::SatsOverflow => write!(f, "sat amount does not fit in u64"),
        }
    }
}

impl std::error::Error for ScaleError {}

/// Exactly scale u64 L1 sats to U256 L2 wei (`sats * 10^10`).
///
/// Infallible and exact by construction: `u64::MAX * 10^10 < 2^98 ≪ 2^256`.
pub fn sats_to_wei(sats: u64) -> U256 {
    U256::from(sats) * U256::from(ATOM_SCALE)
}

/// Exactly scale U256 L2 wei back to u64 L1 sats.
///
/// Fails (never rounds) if `wei` is not a multiple of [`ATOM_SCALE`] or the
/// result does not fit in u64 — the bridge rule "the scaling is exact and
/// total L2 supply ≤ L1 escrow" depends on this being lossless.
pub fn wei_to_sats(wei: U256) -> Result<u64, ScaleError> {
    let scale = U256::from(ATOM_SCALE);
    let (quotient, remainder) = wei.div_rem(scale);
    if !remainder.is_zero() {
        return Err(ScaleError::NotAtomAligned);
    }
    u64::try_from(quotient).map_err(|_| ScaleError::SatsOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_blch_is_1e18_wei() {
        assert_eq!(sats_to_wei(SATS_PER_BLCH), WEI_PER_BLCH);
        assert_eq!(
            sats_to_wei(SATS_PER_BLCH),
            U256::from(10u64).pow(U256::from(18))
        );
    }

    #[test]
    fn roundtrip_is_exact() {
        for sats in [0u64, 1, 42, SATS_PER_BLCH, u64::MAX] {
            assert_eq!(wei_to_sats(sats_to_wei(sats)), Ok(sats));
        }
    }

    #[test]
    fn non_aligned_wei_is_rejected_not_rounded() {
        assert_eq!(wei_to_sats(U256::from(1)), Err(ScaleError::NotAtomAligned));
        assert_eq!(
            wei_to_sats(sats_to_wei(7) + U256::from(1)),
            Err(ScaleError::NotAtomAligned)
        );
    }

    #[test]
    fn oversized_wei_is_rejected() {
        let too_big = sats_to_wei(u64::MAX) + U256::from(ATOM_SCALE);
        assert_eq!(wei_to_sats(too_big), Err(ScaleError::SatsOverflow));
    }

    #[test]
    fn max_sats_never_overflows_u256() {
        // u64::MAX * 10^10 fits comfortably in U256; sanity-pin the value.
        let wei = sats_to_wei(u64::MAX);
        assert_eq!(wei / U256::from(ATOM_SCALE), U256::from(u64::MAX));
    }
}
