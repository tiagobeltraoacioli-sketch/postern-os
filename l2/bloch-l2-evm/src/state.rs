// SPDX-License-Identifier: MIT OR Apache-2.0
//! L2 account/state layer over revm's `CacheDB`/`InMemoryDB`.
//!
//! **SCAFFOLD, UNAUDITED, not a working L2.** In-memory only: the real node
//! persists state behind a keccak-256 MPT (see [`crate::stateroot`], stubbed).
//!
//! Supply rule (BLOCH-L2-EVM-DESIGN §1): the native gas token is an L2
//! representation of **bridged BLCH** with **zero issuance** — balances enter
//! only via deposit mints (crediting exactly what was escrowed on L1, scaled
//! by [`crate::scale::ATOM_SCALE`]) and leave only via withdrawals (bridge
//! component, not this crate). Block reward is zero and fees are routed to
//! vaults, never burned, so `total native supply == total minted` holds
//! across execution.

use alloy_primitives::{Address, B256, U256};
use revm::database::{AccountState, CacheDB, DbAccount, InMemoryDB};
use revm::primitives::KECCAK_EMPTY;

use crate::scale::{sats_to_wei, ScaleError};

/// Where a deposit mint's value provably came from.
///
/// Deliberately a single-variant enum: **bridged BLCH is the only provenance
/// that can ever mint on this L2**. There is no admin mint, no reward mint,
/// no other asset. Adding a variant here would violate the design's zero-
/// issuance / not-a-security posture and must not happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepositProvenance {
    /// BLCH escrowed on the Bloch L1 (the deposit system-transaction's
    /// source, OP-style type-0x7E envelope in the full design).
    BridgedBlch {
        /// L1 escrow transaction id.
        l1_txid: [u8; 32],
        /// Output index of the escrow within that transaction.
        l1_vout: u32,
        /// Escrowed amount in L1 sats (u64, 8 decimals).
        l1_sats: u64,
    },
}

/// A deposit system-transaction's mint effect, applied at block start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DepositMint {
    /// L2 recipient credited with the minted wei.
    pub recipient: Address,
    /// Amount to credit, in L2 wei. MUST equal `sats_to_wei(l1_sats)` of the
    /// provenance exactly — enforced by [`L2State::deposit_mint`].
    pub mint_wei: U256,
    /// Where the value came from (bridged BLCH only).
    pub provenance: DepositProvenance,
}

/// Errors from applying a deposit mint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepositError {
    /// `mint_wei` is not exactly `l1_sats * ATOM_SCALE` — the bridge rule is
    /// exact scaling, never rounding, never minting more than escrowed.
    MintMismatch {
        /// The wei the deposit claimed.
        claimed_wei: U256,
        /// The wei the L1 escrow actually supports.
        escrowed_wei: U256,
    },
    /// The claimed wei does not correspond to a representable sat amount.
    Scale(ScaleError),
}

impl core::fmt::Display for DepositError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DepositError::MintMismatch {
                claimed_wei,
                escrowed_wei,
            } => write!(
                f,
                "deposit mint {claimed_wei} wei != escrowed {escrowed_wei} wei (exact 10^10 scaling required)"
            ),
            DepositError::Scale(e) => write!(f, "deposit scale error: {e}"),
        }
    }
}

impl std::error::Error for DepositError {}

/// Read-only view of one L2 account (standard Ethereum account model; the
/// storage root is part of the stubbed MPT layer, not this in-memory view).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L2Account {
    /// Native (bridged-BLCH) balance in wei.
    pub balance: U256,
    /// Transaction nonce.
    pub nonce: u64,
    /// keccak-256 of the account's code ([`KECCAK_EMPTY`] for EOAs).
    pub code_hash: B256,
}

/// The L2 execution state: revm's in-memory `CacheDB` plus the zero-issuance
/// supply ledger (total wei ever minted by deposits).
#[derive(Debug, Default)]
pub struct L2State {
    /// The underlying revm database the EVM executes against.
    pub db: InMemoryDB,
    total_minted_wei: U256,
}

impl L2State {
    /// Fresh, empty state (genesis alloc / predeploys are out of scope for
    /// this scaffold; see README).
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply one deposit mint: credit **exactly** `mint_wei` to the
    /// recipient, after checking it equals the escrowed L1 sats scaled by
    /// `ATOM_SCALE` exactly. This is the ONLY way native balance is created.
    pub fn deposit_mint(&mut self, deposit: &DepositMint) -> Result<(), DepositError> {
        let DepositProvenance::BridgedBlch { l1_sats, .. } = deposit.provenance;
        let escrowed_wei = sats_to_wei(l1_sats);
        if deposit.mint_wei != escrowed_wei {
            return Err(DepositError::MintMismatch {
                claimed_wei: deposit.mint_wei,
                escrowed_wei,
            });
        }
        credit_balance(&mut self.db, deposit.recipient, deposit.mint_wei);
        self.total_minted_wei = self
            .total_minted_wei
            .checked_add(deposit.mint_wei)
            .expect("total minted wei cannot overflow U256");
        Ok(())
    }

    /// Total wei ever minted by deposits (the L2's entire authorized supply;
    /// zero issuance means nothing else creates native balance).
    pub fn total_minted_wei(&self) -> U256 {
        self.total_minted_wei
    }

    /// Sum of every live account's native balance. With zero issuance,
    /// vault-routed (never burned) fees, and no withdrawals processed, this
    /// equals [`Self::total_minted_wei`] — asserted by the executor tests.
    pub fn total_native_wei(&self) -> U256 {
        self.db
            .cache
            .accounts
            .values()
            .filter(|acc| acc.account_state != AccountState::NotExisting)
            .fold(U256::ZERO, |sum, acc| {
                sum.checked_add(acc.info.balance)
                    .expect("summed balances cannot overflow U256")
            })
    }

    /// Read-only account view (`None` if the account does not exist).
    pub fn account(&self, address: &Address) -> Option<L2Account> {
        let acc: &DbAccount = self.db.cache.accounts.get(address)?;
        let info = acc.info()?;
        Some(L2Account {
            balance: info.balance,
            nonce: info.nonce,
            code_hash: if info.code_hash == B256::ZERO {
                KECCAK_EMPTY
            } else {
                info.code_hash
            },
        })
    }

    /// Native balance of `address` (zero if absent).
    pub fn balance_of(&self, address: &Address) -> U256 {
        self.account(address).map(|a| a.balance).unwrap_or(U256::ZERO)
    }

    /// Nonce of `address` (zero if absent).
    pub fn nonce_of(&self, address: &Address) -> u64 {
        self.account(address).map(|a| a.nonce).unwrap_or(0)
    }
}

/// Credit `amount_wei` to `address` in the raw database (deposit mints and
/// vault fee routing — protocol-level accounting outside EVM opcode
/// semantics, the OP-Stack precedent). Must only be called between
/// transactions / at block boundaries, never mid-execution.
pub(crate) fn credit_balance(db: &mut CacheDB<revm::database::EmptyDB>, address: Address, amount_wei: U256) {
    let account = db
        .load_account(address)
        .expect("EmptyDB-backed CacheDB is infallible");
    account.info.balance = account
        .info
        .balance
        .checked_add(amount_wei)
        .expect("balance cannot overflow U256");
    if account.account_state == AccountState::NotExisting {
        // Mirror CacheDB::insert_account_info: the account now exists.
        account.account_state = AccountState::None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    const ALICE: Address = address!("00000000000000000000000000000000000a11ce");
    const BOB: Address = address!("0000000000000000000000000000000000000b0b");

    fn blch_deposit(recipient: Address, l1_sats: u64) -> DepositMint {
        DepositMint {
            recipient,
            mint_wei: sats_to_wei(l1_sats),
            provenance: DepositProvenance::BridgedBlch {
                l1_txid: [0x42; 32],
                l1_vout: 0,
                l1_sats,
            },
        }
    }

    #[test]
    fn deposit_mints_exactly_and_supply_equals_sum_of_mints() {
        let mut state = L2State::new();
        // 1.5 BLCH to alice, 0.00000001 BLCH (1 sat) to bob.
        state.deposit_mint(&blch_deposit(ALICE, 150_000_000)).unwrap();
        state.deposit_mint(&blch_deposit(BOB, 1)).unwrap();
        // A second deposit to the same recipient accumulates.
        state.deposit_mint(&blch_deposit(ALICE, 50_000_000)).unwrap();

        assert_eq!(state.balance_of(&ALICE), sats_to_wei(200_000_000));
        assert_eq!(state.balance_of(&BOB), sats_to_wei(1));
        // Zero issuance: total supply == sum of mints, nothing else.
        assert_eq!(
            state.total_minted_wei(),
            sats_to_wei(200_000_000) + sats_to_wei(1)
        );
        assert_eq!(state.total_native_wei(), state.total_minted_wei());
        // Nonces untouched by mints.
        assert_eq!(state.nonce_of(&ALICE), 0);
    }

    #[test]
    fn inexact_mint_is_rejected() {
        let mut state = L2State::new();
        let mut bad = blch_deposit(ALICE, 100);
        bad.mint_wei += U256::from(1); // one wei more than escrowed
        let err = state.deposit_mint(&bad).unwrap_err();
        assert!(matches!(err, DepositError::MintMismatch { .. }));
        // Nothing was credited or counted.
        assert_eq!(state.balance_of(&ALICE), U256::ZERO);
        assert_eq!(state.total_minted_wei(), U256::ZERO);
        assert_eq!(state.total_native_wei(), U256::ZERO);
    }

    #[test]
    fn absent_account_reads_as_zero() {
        let state = L2State::new();
        assert_eq!(state.balance_of(&ALICE), U256::ZERO);
        assert_eq!(state.nonce_of(&ALICE), 0);
        assert!(state.account(&ALICE).is_none());
    }

    #[test]
    fn mint_must_match_provenance_escrow_not_an_arbitrary_claim() {
        // The escrowed wei is derived from the provenance's `l1_sats`, never
        // from the caller-supplied `mint_wei`. A deposit claiming 200 sats'
        // worth of wei but whose provenance escrowed only 100 sats is rejected,
        // and the error reports the provenance-derived escrow — not the claim.
        let mut state = L2State::new();
        let mint = DepositMint {
            recipient: ALICE,
            mint_wei: sats_to_wei(200),
            provenance: DepositProvenance::BridgedBlch {
                l1_txid: [0x11; 32],
                l1_vout: 3,
                l1_sats: 100,
            },
        };
        let err = state.deposit_mint(&mint).unwrap_err();
        assert_eq!(
            err,
            DepositError::MintMismatch {
                claimed_wei: sats_to_wei(200),
                escrowed_wei: sats_to_wei(100),
            }
        );
        // Nothing was credited or counted — a mismatched deposit is a no-op.
        assert_eq!(state.balance_of(&ALICE), U256::ZERO);
        assert_eq!(state.total_minted_wei(), U256::ZERO);
    }

    #[test]
    fn zero_sat_deposit_is_exact_and_mints_nothing() {
        // A zero-value bridged deposit is exact (0 == 0) and adds nothing to
        // supply — the scaling rule is lossless even at the zero boundary, and
        // bridged BLCH remains the only provenance.
        let mut state = L2State::new();
        state.deposit_mint(&blch_deposit(ALICE, 0)).unwrap();
        assert_eq!(state.balance_of(&ALICE), U256::ZERO);
        assert_eq!(state.total_minted_wei(), U256::ZERO);
        assert_eq!(state.total_native_wei(), state.total_minted_wei());
    }

    #[test]
    fn max_sat_deposit_scales_without_overflow() {
        // u64::MAX sats is the largest escrow L1 can represent; it mints the
        // exact wei with no overflow (u64::MAX * 10^10 fits far inside U256).
        let mut state = L2State::new();
        state.deposit_mint(&blch_deposit(ALICE, u64::MAX)).unwrap();
        assert_eq!(state.balance_of(&ALICE), sats_to_wei(u64::MAX));
        assert_eq!(state.total_minted_wei(), sats_to_wei(u64::MAX));
    }
}
