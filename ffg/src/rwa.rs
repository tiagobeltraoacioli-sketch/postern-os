// SPDX-License-Identifier: MIT OR Apache-2.0
//! An RWA asset-registry **reference state kernel** on the owned layer.
//!
//! # REFERENCE SCAFFOLD — not a secure or deployed system
//!
//! This module takes the RWA row of the Postern roadmap from "design" to a
//! **reference state kernel**: a deterministic asset registry built on
//! [`crate::kernel::StateKernel`], with balance/ownership invariants enforced
//! in the pure `apply`. **Nothing here is operational, offered, audited, or
//! backed by any real asset.** No asset exists behind any of these types. This
//! is not legal, financial, or investment advice, and not an offer or
//! solicitation of anything.
//!
//! ## Where state lives
//!
//! RWA state lives **ONLY in this owned layer**. The ownerless base never sees
//! an asset, a balance, or an op — per batch, the operator may anchor the
//! kernel's 32-byte chained root onto the base as an **ordinary transaction**
//! (see [`anchor_rwa_root`]). An on-base commitment proves only "a signer
//! asserted this root", never that any asset exists or is redeemable.
//!
//! ## The legal HARD GATE, encoded in the type system
//!
//! Every asset record carries a mandatory [`LegalGate`] field whose **only
//! constructible value in this reference is [`LegalGate::NotObtained`]**, and
//! there is **deliberately no `Offer` / `Sell` / `List` operation** in
//! [`RwaOp`]. That encodes the HARD GATE from `ffg/README.md` §"RWA is a
//! separate, regulated, legally-gated instrument": independent qualified legal
//! review of BOTH the RWA-token classification and the operator-role licensing
//! must happen **before anything is built with a specific asset, demonstrated,
//! or offered** — and no code can satisfy that gate. This module stays
//! `blocked-on-legal-review` by construction.

use std::collections::BTreeMap;

use crate::anchor::{AnchorCommitment, AnchorError, AnchorReceipt, BlochAnchorClient};
use crate::kernel::{KernelOp, StateKernel};

/// A 32-byte account identifier on the owned layer (opaque in this reference).
pub type AccountId = [u8; 32];

/// A 32-byte asset identifier on the owned layer (opaque in this reference).
pub type AssetId = [u8; 32];

/// The legal-review HARD GATE, encoded in the type system.
///
/// Independent qualified legal review of the RWA-token classification AND the
/// operator-role licensing is a **HARD GATE** that no code can satisfy — so
/// this reference deliberately makes [`LegalGate::NotObtained`] the **only
/// constructible value**. There is no `Obtained` variant to construct, no
/// bypass, and (see [`RwaOp`]) no offer/sell/list operation to reach for.
/// The type only encodes that the review **has not happened**; it can never
/// encode that it has. Status: `blocked-on-legal-review`.
///
/// ```
/// use postern_ffg::rwa::LegalGate;
/// // Exhaustive over the whole type with a single arm — there is nothing
/// // else to construct. This doc-test stops compiling if a second variant
/// // is ever added without revisiting the HARD GATE.
/// let gate = LegalGate::NotObtained;
/// match gate {
///     LegalGate::NotObtained => {}
/// }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LegalGate {
    /// Independent legal review has NOT been obtained. In this reference this
    /// is the only value that exists.
    NotObtained,
}

impl LegalGate {
    /// Canonical single-byte encoding (folded into the commitment root).
    fn canonical_byte(self) -> u8 {
        match self {
            LegalGate::NotObtained => 0x00,
        }
    }
}

/// One registered asset record on the owned layer.
///
/// A record is bookkeeping ONLY. It does not assert that any real-world asset
/// exists, is unencumbered, is in custody, or is legally redeemable — and the
/// mandatory [`AssetRecord::legal_review`] field says exactly that.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetRecord {
    /// The legal-review HARD GATE. Mandatory; only [`LegalGate::NotObtained`]
    /// is constructible in this reference.
    pub legal_review: LegalGate,
    /// The account that registered the asset (initial holder of the supply).
    pub issuer: AccountId,
    /// Remaining (un-redeemed) supply.
    pub total_supply: u64,
    /// Frozen assets reject all subsequent transfers and redeems.
    pub frozen: bool,
    /// Balances per account. Zero balances are removed, so equal holdings
    /// always encode to the equal map (canonical state).
    pub balances: BTreeMap<AccountId, u64>,
}

/// The RWA registry state: all assets, keyed by id. Lives ONLY in the owned
/// layer; the base never sees it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RwaState {
    /// Registered assets by id.
    pub assets: BTreeMap<AssetId, AssetRecord>,
}

/// Operations of the RWA reference kernel.
///
/// **Deliberately absent: any `Offer`, `Sell`, or `List` operation.** That is
/// the legal HARD GATE from `ffg/README.md` encoded in the type system — this
/// reference cannot express offering an asset to anyone, and adding such an
/// op without the independent legal review having actually happened would
/// violate the gate. See [`LegalGate`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RwaOp {
    /// Register a new asset id and mint its whole supply to the issuer. The
    /// mandatory `legal_review` field can only carry
    /// [`LegalGate::NotObtained`].
    RegisterAsset {
        /// New asset id (must not already exist).
        asset_id: AssetId,
        /// Registering account; receives the initial supply.
        issuer: AccountId,
        /// Initial supply (must be non-zero).
        supply: u64,
        /// The legal HARD GATE marker (only `NotObtained` exists).
        legal_review: LegalGate,
    },
    /// Move `amount` of an asset between owned-layer accounts.
    Transfer {
        /// Asset to move.
        asset_id: AssetId,
        /// Sender (must hold at least `amount`).
        from: AccountId,
        /// Recipient.
        to: AccountId,
        /// Non-zero amount.
        amount: u64,
    },
    /// Burn `amount` of the holder's balance (bookkeeping only — it does NOT
    /// assert any real-world redemption happened or could happen).
    Redeem {
        /// Asset to redeem against.
        asset_id: AssetId,
        /// Holder whose balance is burned.
        holder: AccountId,
        /// Non-zero amount.
        amount: u64,
    },
    /// Freeze an asset: all subsequent transfers and redeems are rejected.
    Freeze {
        /// Asset to freeze.
        asset_id: AssetId,
    },
}

/// Rejections from the RWA kernel's pure `apply`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RwaError {
    /// The asset id is already registered.
    AssetAlreadyRegistered(AssetId),
    /// The asset id is not registered.
    UnknownAsset(AssetId),
    /// Zero supply/amount ops are rejected (keeps the log meaningful).
    ZeroAmount,
    /// The sender/holder balance is insufficient.
    InsufficientBalance {
        /// Balance actually held.
        held: u64,
        /// Amount required by the op.
        required: u64,
    },
    /// The asset is frozen; transfers and redeems are rejected.
    AssetFrozen(AssetId),
    /// The asset is already frozen (double-freeze is rejected to keep the
    /// log canonical).
    AlreadyFrozen(AssetId),
    /// A balance would overflow `u64` (unreachable while supply is conserved,
    /// checked anyway).
    BalanceOverflow,
}

impl core::fmt::Display for RwaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RwaError::AssetAlreadyRegistered(_) => write!(f, "asset already registered"),
            RwaError::UnknownAsset(_) => write!(f, "unknown asset"),
            RwaError::ZeroAmount => write!(f, "zero amount rejected"),
            RwaError::InsufficientBalance { held, required } => {
                write!(f, "insufficient balance: held {held}, required {required}")
            }
            RwaError::AssetFrozen(_) => write!(f, "asset is frozen"),
            RwaError::AlreadyFrozen(_) => write!(f, "asset is already frozen"),
            RwaError::BalanceOverflow => write!(f, "balance overflow"),
        }
    }
}

impl std::error::Error for RwaError {}

impl KernelOp<RwaState> for RwaOp {
    type Error = RwaError;

    fn apply(&self, state: &RwaState) -> Result<RwaState, RwaError> {
        let mut next = state.clone();
        match self {
            RwaOp::RegisterAsset { asset_id, issuer, supply, legal_review } => {
                if next.assets.contains_key(asset_id) {
                    return Err(RwaError::AssetAlreadyRegistered(*asset_id));
                }
                if *supply == 0 {
                    return Err(RwaError::ZeroAmount);
                }
                let mut balances = BTreeMap::new();
                balances.insert(*issuer, *supply);
                next.assets.insert(
                    *asset_id,
                    AssetRecord {
                        legal_review: *legal_review,
                        issuer: *issuer,
                        total_supply: *supply,
                        frozen: false,
                        balances,
                    },
                );
            }
            RwaOp::Transfer { asset_id, from, to, amount } => {
                if *amount == 0 {
                    return Err(RwaError::ZeroAmount);
                }
                let record =
                    next.assets.get_mut(asset_id).ok_or(RwaError::UnknownAsset(*asset_id))?;
                if record.frozen {
                    return Err(RwaError::AssetFrozen(*asset_id));
                }
                let held = record.balances.get(from).copied().unwrap_or(0);
                if held < *amount {
                    return Err(RwaError::InsufficientBalance { held, required: *amount });
                }
                // Self-transfer is a no-op on balances but still a valid,
                // logged (root-advancing) op.
                if from != to {
                    let to_held = record.balances.get(to).copied().unwrap_or(0);
                    let to_next = to_held.checked_add(*amount).ok_or(RwaError::BalanceOverflow)?;
                    match held - *amount {
                        0 => {
                            record.balances.remove(from);
                        }
                        rest => {
                            record.balances.insert(*from, rest);
                        }
                    }
                    record.balances.insert(*to, to_next);
                }
            }
            RwaOp::Redeem { asset_id, holder, amount } => {
                if *amount == 0 {
                    return Err(RwaError::ZeroAmount);
                }
                let record =
                    next.assets.get_mut(asset_id).ok_or(RwaError::UnknownAsset(*asset_id))?;
                if record.frozen {
                    return Err(RwaError::AssetFrozen(*asset_id));
                }
                let held = record.balances.get(holder).copied().unwrap_or(0);
                if held < *amount {
                    return Err(RwaError::InsufficientBalance { held, required: *amount });
                }
                match held - *amount {
                    0 => {
                        record.balances.remove(holder);
                    }
                    rest => {
                        record.balances.insert(*holder, rest);
                    }
                }
                record.total_supply -= *amount;
            }
            RwaOp::Freeze { asset_id } => {
                let record =
                    next.assets.get_mut(asset_id).ok_or(RwaError::UnknownAsset(*asset_id))?;
                if record.frozen {
                    return Err(RwaError::AlreadyFrozen(*asset_id));
                }
                record.frozen = true;
            }
        }
        Ok(next)
    }

    /// Canonical encoding: a tag byte then fixed-width fields (u64 LE). No
    /// two distinct ops encode equal.
    fn canonical_bytes(&self) -> Vec<u8> {
        match self {
            RwaOp::RegisterAsset { asset_id, issuer, supply, legal_review } => {
                let mut out = Vec::with_capacity(1 + 32 + 32 + 8 + 1);
                out.push(0x01);
                out.extend_from_slice(asset_id);
                out.extend_from_slice(issuer);
                out.extend_from_slice(&supply.to_le_bytes());
                out.push(legal_review.canonical_byte());
                out
            }
            RwaOp::Transfer { asset_id, from, to, amount } => {
                let mut out = Vec::with_capacity(1 + 32 + 32 + 32 + 8);
                out.push(0x02);
                out.extend_from_slice(asset_id);
                out.extend_from_slice(from);
                out.extend_from_slice(to);
                out.extend_from_slice(&amount.to_le_bytes());
                out
            }
            RwaOp::Redeem { asset_id, holder, amount } => {
                let mut out = Vec::with_capacity(1 + 32 + 32 + 8);
                out.push(0x03);
                out.extend_from_slice(asset_id);
                out.extend_from_slice(holder);
                out.extend_from_slice(&amount.to_le_bytes());
                out
            }
            RwaOp::Freeze { asset_id } => {
                let mut out = Vec::with_capacity(1 + 32);
                out.push(0x04);
                out.extend_from_slice(asset_id);
                out
            }
        }
    }
}

/// The RWA reference kernel: [`StateKernel`] over [`RwaState`] / [`RwaOp`].
pub type RwaKernel = StateKernel<RwaState, RwaOp>;

/// Create an RWA reference kernel at genesis (empty registry).
pub fn new_rwa_kernel(kernel_id: &[u8]) -> RwaKernel {
    RwaKernel::new(kernel_id, RwaState::default())
}

/// Anchor the kernel's current root onto the base as ONE ordinary transaction
/// (one batch = one 32-byte commitment).
///
/// An on-base commitment proves only "a signer asserted this root", never
/// that any asset exists or is redeemable. It confers no base-consensus
/// privilege, no data availability (the base stores 32 bytes, not the log),
/// and no settlement guarantee — the base itself is a `k=4`-forgeable
/// mainnet-beta.
pub fn anchor_rwa_root(
    kernel: &RwaKernel,
    client: &mut dyn BlochAnchorClient,
) -> Result<AnchorReceipt, AnchorError> {
    client.anchor_commitment(AnchorCommitment(kernel.root()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anchor::InMemoryAnchorClient;
    use crate::checkpoint::BaseAnchorRef;

    fn id(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn registered_kernel() -> RwaKernel {
        let mut k = new_rwa_kernel(b"rwa-test");
        k.apply(RwaOp::RegisterAsset {
            asset_id: id(1),
            issuer: id(10),
            supply: 100,
            legal_review: LegalGate::NotObtained,
        })
        .unwrap();
        k
    }

    #[test]
    fn transfer_of_unregistered_asset_is_rejected() {
        let mut k = new_rwa_kernel(b"rwa-test");
        let err = k
            .apply(RwaOp::Transfer { asset_id: id(9), from: id(10), to: id(11), amount: 1 })
            .unwrap_err();
        assert_eq!(err, RwaError::UnknownAsset(id(9)));
    }

    #[test]
    fn over_balance_transfer_is_rejected() {
        let mut k = registered_kernel();
        let err = k
            .apply(RwaOp::Transfer { asset_id: id(1), from: id(10), to: id(11), amount: 101 })
            .unwrap_err();
        assert_eq!(err, RwaError::InsufficientBalance { held: 100, required: 101 });
        // And from an account holding nothing at all.
        let err = k
            .apply(RwaOp::Transfer { asset_id: id(1), from: id(12), to: id(11), amount: 1 })
            .unwrap_err();
        assert_eq!(err, RwaError::InsufficientBalance { held: 0, required: 1 });
    }

    #[test]
    fn double_redeem_is_rejected_and_supply_is_conserved() {
        let mut k = registered_kernel();
        k.apply(RwaOp::Redeem { asset_id: id(1), holder: id(10), amount: 100 }).unwrap();
        assert_eq!(k.state().assets[&id(1)].total_supply, 0);
        // The same redeem again: the balance is gone.
        let err = k
            .apply(RwaOp::Redeem { asset_id: id(1), holder: id(10), amount: 100 })
            .unwrap_err();
        assert_eq!(err, RwaError::InsufficientBalance { held: 0, required: 100 });
    }

    #[test]
    fn freeze_blocks_subsequent_transfers() {
        let mut k = registered_kernel();
        k.apply(RwaOp::Freeze { asset_id: id(1) }).unwrap();
        let err = k
            .apply(RwaOp::Transfer { asset_id: id(1), from: id(10), to: id(11), amount: 1 })
            .unwrap_err();
        assert_eq!(err, RwaError::AssetFrozen(id(1)));
        // Redeems are conservatively blocked too.
        let err =
            k.apply(RwaOp::Redeem { asset_id: id(1), holder: id(10), amount: 1 }).unwrap_err();
        assert_eq!(err, RwaError::AssetFrozen(id(1)));
    }

    #[test]
    fn double_register_and_zero_amounts_are_rejected() {
        let mut k = registered_kernel();
        let err = k
            .apply(RwaOp::RegisterAsset {
                asset_id: id(1),
                issuer: id(10),
                supply: 5,
                legal_review: LegalGate::NotObtained,
            })
            .unwrap_err();
        assert_eq!(err, RwaError::AssetAlreadyRegistered(id(1)));
        let err = k
            .apply(RwaOp::Transfer { asset_id: id(1), from: id(10), to: id(11), amount: 0 })
            .unwrap_err();
        assert_eq!(err, RwaError::ZeroAmount);
    }

    /// (c) The legal HARD GATE is impossible to bypass by construction:
    /// `LegalGate` has exactly one variant, so *every* constructible asset
    /// record carries `NotObtained`. The exhaustive single-arm match compiles
    /// only while that stays true (see also the doc-test on [`LegalGate`]).
    #[test]
    fn legal_gate_only_constructible_value_is_not_obtained() {
        let k = registered_kernel();
        let record = &k.state().assets[&id(1)];
        match record.legal_review {
            LegalGate::NotObtained => {}
        }
        assert_eq!(record.legal_review, LegalGate::NotObtained);
    }

    #[test]
    fn rwa_replay_is_deterministic_and_tamper_evident() {
        let ops = vec![
            RwaOp::RegisterAsset {
                asset_id: id(1),
                issuer: id(10),
                supply: 100,
                legal_review: LegalGate::NotObtained,
            },
            RwaOp::Transfer { asset_id: id(1), from: id(10), to: id(11), amount: 40 },
            RwaOp::Redeem { asset_id: id(1), holder: id(11), amount: 10 },
        ];
        let a = RwaKernel::replay(b"rwa-test", RwaState::default(), ops.clone()).unwrap();
        let b = RwaKernel::replay(b"rwa-test", RwaState::default(), ops.clone()).unwrap();
        assert_eq!(a.root(), b.root());
        let mut tampered = ops;
        tampered[1] = RwaOp::Transfer { asset_id: id(1), from: id(10), to: id(11), amount: 41 };
        let c = RwaKernel::replay(b"rwa-test", RwaState::default(), tampered).unwrap();
        assert_ne!(a.root(), c.root());
    }

    #[test]
    fn anchoring_a_batch_writes_one_ordinary_commitment() {
        let k = registered_kernel();
        let mut client = InMemoryAnchorClient::new();
        client.push_header(BaseAnchorRef {
            block_height: 100,
            block_hash: [7u8; 32],
            accumulated_work: 1000,
        });
        let receipt = anchor_rwa_root(&k, &mut client).unwrap();
        assert_eq!(receipt.commitment.0, k.root());
        assert_eq!(client.anchored().len(), 1);
    }
}
