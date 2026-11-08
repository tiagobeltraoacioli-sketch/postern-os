// SPDX-License-Identifier: MIT OR Apache-2.0
//! `ATOM_SCALE` — the exact L1-atom ↔ L2-wei unit mapping (§1, §5).
//!
//! BLCH is a u64 of base units ("atoms") with 8 decimals on L1. The L2
//! scales by `10^(18-8) = 10^10` so `1 BLCH == 10^18` wei-equivalent and
//! MetaMask/ethers display naturally. The bridge MUST enforce that the
//! scaling is exact in both directions:
//!
//! * deposits: `mint = amount_atoms * ATOM_SCALE` — always exact (u64×10^10
//!   cannot overflow u128), never lossy;
//! * withdrawals: the predeploy's `withdraw()` REVERTS unless
//!   `msg.value % ATOM_SCALE == 0` (no dust loss, no rounding) — modelled
//!   here as [`wei_to_atoms`] returning a typed error on any remainder.
//!
//! SCAFFOLD: pure math only; nothing here moves value.

/// L1 BLCH decimals (atoms per BLCH = 10^8).
pub const BLOCH_DECIMALS: u32 = 8;
/// L2 native-token decimals (Ethereum convention).
pub const L2_DECIMALS: u32 = 18;
/// Wei per atom: `10^(18-8) = 10^10`.
pub const ATOM_SCALE: u128 = 10u128.pow(L2_DECIMALS - BLOCH_DECIMALS);

/// Exact atoms → wei. Cannot overflow: `u64::MAX * 10^10 < 2^128`.
pub fn atoms_to_wei(atoms: u64) -> u128 {
    atoms as u128 * ATOM_SCALE
}

/// Typed conversion failures for the wei → atoms direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtomConversionError {
    /// `wei % ATOM_SCALE != 0` — the withdraw() dust rule: rather than
    /// silently rounding (value loss), the conversion is refused.
    NotAtomAligned { remainder: u128 },
    /// The atom amount would exceed `u64::MAX` (cannot exist on L1).
    Overflow,
}

impl core::fmt::Display for AtomConversionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AtomConversionError::NotAtomAligned { remainder } => write!(
                f,
                "wei amount not atom-aligned (remainder {remainder} of {ATOM_SCALE})"
            ),
            AtomConversionError::Overflow => write!(f, "atom amount exceeds u64"),
        }
    }
}

impl std::error::Error for AtomConversionError {}

/// Exact wei → atoms. Errors on any remainder (the `withdraw()` rule) and
/// on amounts too large to exist as L1 atoms. Never rounds.
pub fn wei_to_atoms(wei: u128) -> Result<u64, AtomConversionError> {
    let remainder = wei % ATOM_SCALE;
    if remainder != 0 {
        return Err(AtomConversionError::NotAtomAligned { remainder });
    }
    u64::try_from(wei / ATOM_SCALE).map_err(|_| AtomConversionError::Overflow)
}

/// The pure predicate behind the predeploy rule
/// `withdraw() REVERTS unless msg.value % ATOM_SCALE == 0`.
pub fn is_withdrawable_wei(wei: u128) -> bool {
    wei % ATOM_SCALE == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scale_constant() {
        assert_eq!(ATOM_SCALE, 10_000_000_000);
        // 1 BLCH = 10^8 atoms = 10^18 wei
        assert_eq!(atoms_to_wei(100_000_000), 1_000_000_000_000_000_000);
    }

    #[test]
    fn round_trip_is_exact() {
        for atoms in [0u64, 1, 7, 100_000_000, 123_456_789, u64::MAX] {
            let wei = atoms_to_wei(atoms);
            assert_eq!(wei_to_atoms(wei), Ok(atoms), "atoms={atoms}");
        }
    }

    #[test]
    fn no_overflow_at_u64_max() {
        // u64::MAX * 10^10 must fit u128 (compile-time-ish sanity)
        let wei = atoms_to_wei(u64::MAX);
        assert_eq!(wei, u64::MAX as u128 * ATOM_SCALE);
        assert!(wei < u128::MAX);
    }

    #[test]
    fn withdraw_alignment_rule() {
        // exactly aligned: ok
        assert!(is_withdrawable_wei(0));
        assert!(is_withdrawable_wei(ATOM_SCALE));
        assert!(is_withdrawable_wei(42 * ATOM_SCALE));
        // any dust below one atom: refused, never rounded
        for dust in [1u128, 9, ATOM_SCALE - 1] {
            let wei = 42 * ATOM_SCALE + dust;
            assert!(!is_withdrawable_wei(wei));
            assert_eq!(
                wei_to_atoms(wei),
                Err(AtomConversionError::NotAtomAligned { remainder: dust })
            );
        }
    }

    #[test]
    fn overflow_is_refused() {
        let too_big = (u64::MAX as u128 + 1) * ATOM_SCALE;
        assert_eq!(wei_to_atoms(too_big), Err(AtomConversionError::Overflow));
        // the largest representable amount still converts
        assert_eq!(wei_to_atoms(u64::MAX as u128 * ATOM_SCALE), Ok(u64::MAX));
    }

    #[test]
    fn no_rounding_loss_invariant() {
        // For every aligned wei w: atoms_to_wei(wei_to_atoms(w)) == w.
        for k in [0u128, 1, 999, 1_000_000, u64::MAX as u128] {
            let wei = k * ATOM_SCALE;
            let atoms = wei_to_atoms(wei).unwrap();
            assert_eq!(atoms_to_wei(atoms), wei);
        }
    }
}
