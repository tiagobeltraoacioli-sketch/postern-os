// SPDX-License-Identifier: MIT OR Apache-2.0
//! # bloch-l2-bridge — SCAFFOLD, UNAUDITED, not a working L2.
//!
//! **The v1 L1 vault is CUSTODY, full stop — nothing here moves value.**
//!
//! Bridge *types* for the design-only Bloch EVM L2
//! (`docs/specs/BLOCH-L2-EVM-DESIGN.md` §5): the `L2D0` deposit envelope
//! codec, the `ATOM_SCALE` sats↔wei conversion, the withdrawal-message
//! leaf encoding, the keccak256 depth-32 incremental Merkle tree with
//! inclusion-proof verification, the `K(amount)` confirmation-depth
//! schedule, and a WBLCH / Uniswap-v2 deploy **harness config** (no
//! deploys, no chain interaction, no compilation).
//!
//! Honesty invariants, mirrored from the spec and non-negotiable:
//! * Bloch today is k=4, low-hashrate, 51%-attackable, unaudited. No finite
//!   confirmation depth is finality, and no `K` may be represented as such.
//! * The validity proof (elsewhere, unbuilt) proves state transitions about
//!   a *named* L1 view — never L1 canonicality.
//! * The L2 is an owned Postern product; only the anchoring rail is
//!   ownerless.
//! * Everything here is testnet / zero-value until the
//!   POSTERNDEX-BRIDGE-DESIGN §0 gates clear.

pub mod atoms;
pub mod envelope;
pub mod harness;
pub mod hex;
pub mod merkle;
pub mod status;
pub mod stubs;
pub mod withdrawal;

pub use atoms::{atoms_to_wei, wei_to_atoms, AtomConversionError, ATOM_SCALE};
pub use envelope::{extract_deposit_envelope, DecodeError, DepositEnvelope, TxOutput};
pub use merkle::{keccak256, verify_inclusion, IncrementalMerkleTree, TREE_DEPTH};
pub use status::{
    confirmation_depth, ConfirmationRequirement, DepositEvent, WithdrawalEvent, WithdrawalStatus,
};
pub use withdrawal::{WithdrawalInclusion, WithdrawalMessage, UNANCHORED_ROOT};
