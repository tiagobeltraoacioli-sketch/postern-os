//! The guest entry point: stateless re-execution of one batch.
//!
//! # PLACEHOLDER STF — read this first
//!
//! This is a deliberately **SIMPLIFIED account-map re-execution** so the
//! witness → STF → public-values → (mock) prove/verify pipeline can be
//! exercised end-to-end in tests. It is:
//!
//! * **NOT revm** — no EVM, no gas, no contracts, no receipts;
//! * **NOT MPT-verified** — the "state root" is a flat SHAKE-256 commitment
//!   over sorted account leaves, not Ethereum's keccak-256 MPT;
//! * **NOT Ethereum tx format** — a toy fixed 64-byte transfer, not RLP;
//! * **NOT a validity guarantee of anything** — it exists only to give the
//!   scaffold deterministic, testable state math.
//!
//! The production guest (design §3: MPT witness verification → deposit mints
//! → revm execution → withdrawal accumulation → new MPT root →
//! `sp1_zkvm::io::commit`) is `// SCAFFOLD:`-stubbed in [`crate::sp1_stub`].
//!
//! What IS faithful to the design here: the *shape* of the algorithm
//! (verify witness against `pre_state_root` → apply deposits → execute txs →
//! fold withdrawals → compute `new_state_root` → emit public values), the
//! determinism contract (integer-only, `BTreeMap` ordering), and the
//! public-values wiring.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::hash::{merkle_root, shake256_32, shake256_list, Hash32};
use crate::public_values::BatchPublicValues;
use crate::witness::{ExecutionWitness, MAX_ANCESTOR_HEADERS};

/// Domain for the simplified flat state commitment (NOT an MPT root).
pub const STATE_COMMITMENT_DOMAIN: &str = "bloch-l2/flat-state/v0";
/// Domain for the batch tx-list commitment (the DA blob commitment).
pub const TX_COMMITMENT_DOMAIN: &str = "bloch-l2/batch-txs/v0";
/// Domain for deposit merkle leaves.
pub const DEPOSIT_LEAF_DOMAIN: &str = "bloch-l2/deposit-leaf/v0";
/// Domain for withdrawal merkle leaves.
pub const WITHDRAWAL_LEAF_DOMAIN: &str = "bloch-l2/withdrawal-leaf/v0";

/// The L2ToL1MessagePasser predeploy address (OP-Stack-convention slot in the
/// design). In this placeholder, a transfer TO this address burns the value
/// on the L2 and appends a withdrawal message to `withdrawal_root`.
pub const WITHDRAWAL_PREDEPLOY: [u8; 20] = [
    0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x16,
];

/// Simplified account state: balance + nonce (no code, no storage — see the
/// module-level placeholder disclaimer).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Account {
    /// Balance in placeholder wei-like units.
    pub balance: u128,
    /// Transaction nonce.
    pub nonce: u64,
}

/// Deterministic account map — `BTreeMap` per the determinism contract.
pub type StateMap = BTreeMap<[u8; 20], Account>;

/// Byte length of one flat account leaf: addr(20) | balance u128 LE | nonce u64 LE.
pub const ACCOUNT_LEAF_LEN: usize = 44;

/// Byte length of one placeholder transaction:
/// from(20) | to(20) | value u128 LE (16) | nonce u64 LE (8).
pub const TX_LEN: usize = 64;

/// Toy transfer transaction — the placeholder STF's entire "EVM".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SimpleTx {
    /// Sender address (no signature — placeholder; the host is trusted here,
    /// which is exactly why this proves nothing).
    pub from: [u8; 20],
    /// Recipient; [`WITHDRAWAL_PREDEPLOY`] burns and records a withdrawal.
    pub to: [u8; 20],
    /// Transfer value.
    pub value: u128,
    /// Must equal the sender's current nonce.
    pub nonce: u64,
}

impl SimpleTx {
    /// Canonical fixed-width encoding ([`TX_LEN`] bytes).
    pub fn encode(&self) -> [u8; TX_LEN] {
        let mut out = [0u8; TX_LEN];
        out[0..20].copy_from_slice(&self.from);
        out[20..40].copy_from_slice(&self.to);
        out[40..56].copy_from_slice(&self.value.to_le_bytes());
        out[56..64].copy_from_slice(&self.nonce.to_le_bytes());
        out
    }

    /// Decode; `None` unless exactly [`TX_LEN`] bytes.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != TX_LEN {
            return None;
        }
        let mut from = [0u8; 20];
        from.copy_from_slice(&bytes[0..20]);
        let mut to = [0u8; 20];
        to.copy_from_slice(&bytes[20..40]);
        let mut v = [0u8; 16];
        v.copy_from_slice(&bytes[40..56]);
        let mut n = [0u8; 8];
        n.copy_from_slice(&bytes[56..64]);
        Some(Self {
            from,
            to,
            value: u128::from_le_bytes(v),
            nonce: u64::from_le_bytes(n),
        })
    }
}

/// Errors from the placeholder STF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StfError {
    /// More than [`MAX_ANCESTOR_HEADERS`] ancestor headers supplied.
    TooManyAncestors(usize),
    /// `state_witness[index]` is not a valid [`ACCOUNT_LEAF_LEN`]-byte leaf.
    BadStateLeaf {
        /// Index of the offending witness entry.
        index: usize,
    },
    /// Two witness leaves carry the same address.
    DuplicateAccount([u8; 20]),
    /// The reconstructed pre-state does not commit to `pre_state_root` —
    /// the stateless-execution analogue of an MPT witness failure.
    WitnessRootMismatch {
        /// Commitment computed from the supplied leaves.
        computed: Hash32,
        /// `pre_state_root` claimed by the witness.
        claimed: Hash32,
    },
    /// `txs[index]` is not a valid [`TX_LEN`]-byte placeholder tx.
    MalformedTx {
        /// Index of the offending tx.
        index: usize,
    },
    /// Tx sender has no account in the witness (stateless execution cannot
    /// invent balances).
    UnknownSender {
        /// Index of the offending tx.
        index: usize,
    },
    /// Tx nonce does not match the sender's current nonce.
    BadNonce {
        /// Index of the offending tx.
        index: usize,
        /// Nonce the sender's account expected.
        expected: u64,
        /// Nonce the tx carried.
        got: u64,
    },
    /// Sender balance is insufficient for the transfer value.
    InsufficientBalance {
        /// Index of the offending tx.
        index: usize,
    },
    /// A balance addition overflowed u128 (deposit or transfer credit).
    BalanceOverflow,
}

impl core::fmt::Display for StfError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooManyAncestors(n) => {
                write!(f, "{n} ancestor headers exceeds {MAX_ANCESTOR_HEADERS}")
            }
            Self::BadStateLeaf { index } => write!(f, "state witness leaf {index} malformed"),
            Self::DuplicateAccount(_) => write!(f, "duplicate account in state witness"),
            Self::WitnessRootMismatch { .. } => {
                write!(f, "state witness does not open against pre_state_root")
            }
            Self::MalformedTx { index } => write!(f, "tx {index} malformed"),
            Self::UnknownSender { index } => write!(f, "tx {index} sender not in witness"),
            Self::BadNonce { index, expected, got } => {
                write!(f, "tx {index} nonce {got}, expected {expected}")
            }
            Self::InsufficientBalance { index } => {
                write!(f, "tx {index} value exceeds sender balance")
            }
            Self::BalanceOverflow => write!(f, "balance addition overflowed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for StfError {}

/// Encode one flat account leaf (addr ‖ balance LE ‖ nonce LE).
pub fn encode_account_leaf(addr: &[u8; 20], acct: &Account) -> [u8; ACCOUNT_LEAF_LEN] {
    let mut out = [0u8; ACCOUNT_LEAF_LEN];
    out[0..20].copy_from_slice(addr);
    out[20..36].copy_from_slice(&acct.balance.to_le_bytes());
    out[36..44].copy_from_slice(&acct.nonce.to_le_bytes());
    out
}

/// Simplified state commitment: SHAKE-256 over the address-sorted account
/// leaves (`BTreeMap` iteration order is the sort). **NOT an MPT root** —
/// `eth_getProof` compatibility and keccak-MPT verification are SCAFFOLD
/// (see [`crate::sp1_stub`]).
pub fn state_commitment(state: &StateMap) -> Hash32 {
    let leaves: Vec<Vec<u8>> = state
        .iter()
        .map(|(addr, acct)| encode_account_leaf(addr, acct).to_vec())
        .collect();
    shake256_list(STATE_COMMITMENT_DOMAIN, &leaves)
}

/// The guest entry point: stateless re-execution of one batch.
///
/// **PLACEHOLDER STF** (module docs have the full disclaimer): flat account
/// map, toy transfers, no EVM, no signatures, no MPT. Algorithm shape per
/// design §3: (1) open witness against `pre_state_root`; (2) apply deposit
/// mints; (3) execute txs in order; (4) fold withdrawals; (5) commit the new
/// state; (6) emit [`BatchPublicValues`]. In the real guest, step (6) is
/// `sp1_zkvm::io::commit` and any divergence makes the FRI proof
/// unsatisfiable; here it just returns a struct — nothing is proven.
pub fn stf(witness: ExecutionWitness) -> Result<BatchPublicValues, StfError> {
    if witness.ancestor_headers.len() > MAX_ANCESTOR_HEADERS {
        return Err(StfError::TooManyAncestors(witness.ancestor_headers.len()));
    }

    // (1) Reconstruct pre-state from the witness and check it opens against
    // pre_state_root. (Real design: keccak MPT proof verification.)
    let mut state: StateMap = BTreeMap::new();
    for (index, leaf) in witness.state_witness.iter().enumerate() {
        if leaf.len() != ACCOUNT_LEAF_LEN {
            return Err(StfError::BadStateLeaf { index });
        }
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&leaf[0..20]);
        let mut bal = [0u8; 16];
        bal.copy_from_slice(&leaf[20..36]);
        let mut nonce = [0u8; 8];
        nonce.copy_from_slice(&leaf[36..44]);
        let acct = Account {
            balance: u128::from_le_bytes(bal),
            nonce: u64::from_le_bytes(nonce),
        };
        if state.insert(addr, acct).is_some() {
            return Err(StfError::DuplicateAccount(addr));
        }
    }
    let computed = state_commitment(&state);
    if computed != witness.pre_state_root {
        return Err(StfError::WitnessRootMismatch {
            computed,
            claimed: witness.pre_state_root,
        });
    }

    // (2) Apply deposit mints (design: type-0x7E system txs at block start).
    let mut deposit_leaves: Vec<Hash32> = Vec::with_capacity(witness.deposits.len());
    for dep in &witness.deposits {
        let entry = state.entry(dep.recipient).or_default();
        entry.balance = entry
            .balance
            .checked_add(dep.amount)
            .ok_or(StfError::BalanceOverflow)?;
        deposit_leaves.push(shake256_32(DEPOSIT_LEAF_DOMAIN, &dep.encode()));
    }

    // (3)+(4) Execute txs in order, folding withdrawals.
    let mut withdrawal_leaves: Vec<Hash32> = Vec::new();
    for (index, raw) in witness.txs.iter().enumerate() {
        let tx = SimpleTx::decode(raw).ok_or(StfError::MalformedTx { index })?;
        let sender = state
            .get_mut(&tx.from)
            .ok_or(StfError::UnknownSender { index })?;
        if sender.nonce != tx.nonce {
            return Err(StfError::BadNonce {
                index,
                expected: sender.nonce,
                got: tx.nonce,
            });
        }
        if sender.balance < tx.value {
            return Err(StfError::InsufficientBalance { index });
        }
        sender.balance -= tx.value;
        sender.nonce += 1;
        if tx.to == WITHDRAWAL_PREDEPLOY {
            // Burn on L2, record the L2→L1 message (design: SMT of the
            // L2ToL1MessagePasser storage; here: simplified merkle leaf).
            let mut msg = [0u8; 44];
            msg[0..20].copy_from_slice(&tx.from);
            msg[20..36].copy_from_slice(&tx.value.to_le_bytes());
            msg[36..44].copy_from_slice(&tx.nonce.to_le_bytes());
            withdrawal_leaves.push(shake256_32(WITHDRAWAL_LEAF_DOMAIN, &msg));
        } else {
            let recipient = state.entry(tx.to).or_default();
            recipient.balance = recipient
                .balance
                .checked_add(tx.value)
                .ok_or(StfError::BalanceOverflow)?;
        }
    }

    // (5)+(6) Commit the post-state and emit the public values.
    Ok(BatchPublicValues {
        l2_chain_id: witness.context.l2_chain_id,
        batch_index: witness.context.batch_index,
        prev_batch_hash: witness.context.prev_batch_hash,
        prev_state_root: witness.pre_state_root,
        new_state_root: state_commitment(&state),
        batch_tx_commitment: shake256_list(TX_COMMITMENT_DOMAIN, &witness.txs),
        deposit_root: merkle_root(&deposit_leaves),
        l1_origin_hash: witness.context.l1_origin_hash,
        l1_origin_height: witness.context.l1_origin_height,
        withdrawal_root: merkle_root(&withdrawal_leaves),
        timestamp: witness.context.timestamp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::witness::{AncestorHeader, BatchContext, DepositEvent};
    use alloc::vec;

    pub(crate) const ALICE: [u8; 20] = [0xA1; 20];
    pub(crate) const BOB: [u8; 20] = [0xB0; 20];

    pub(crate) fn genesis_state() -> StateMap {
        let mut s = StateMap::new();
        s.insert(ALICE, Account { balance: 1_000, nonce: 0 });
        s
    }

    pub(crate) fn witness_for(state: &StateMap, txs: Vec<Vec<u8>>) -> ExecutionWitness {
        ExecutionWitness {
            context: BatchContext {
                l2_chain_id: 700_771,
                batch_index: 1,
                prev_batch_hash: [0; 32],
                l1_origin_hash: [0xF0; 32],
                l1_origin_height: 500,
                timestamp: 1_000,
            },
            pre_state_root: state_commitment(state),
            txs,
            state_witness: state
                .iter()
                .map(|(a, ac)| encode_account_leaf(a, ac).to_vec())
                .collect(),
            bytecodes: vec![],
            ancestor_headers: vec![],
            deposits: vec![],
        }
    }

    #[test]
    fn simple_transfer_moves_balance_and_changes_root() {
        let state = genesis_state();
        let tx = SimpleTx { from: ALICE, to: BOB, value: 250, nonce: 0 };
        let w = witness_for(&state, vec![tx.encode().to_vec()]);
        let pre_root = w.pre_state_root;
        let pv = stf(w).unwrap();
        assert_eq!(pv.prev_state_root, pre_root);
        assert_ne!(pv.new_state_root, pre_root);
        // Independently recompute the expected post-state.
        let mut post = StateMap::new();
        post.insert(ALICE, Account { balance: 750, nonce: 1 });
        post.insert(BOB, Account { balance: 250, nonce: 0 });
        assert_eq!(pv.new_state_root, state_commitment(&post));
        assert_eq!(pv.withdrawal_root, [0u8; 32]); // no withdrawals
        assert_eq!(pv.deposit_root, [0u8; 32]); // no deposits
    }

    #[test]
    fn deposit_mints_balance() {
        let state = genesis_state();
        let mut w = witness_for(&state, vec![]);
        w.deposits = vec![DepositEvent {
            source_hash: [7; 32],
            recipient: BOB,
            amount: 500,
        }];
        let pv = stf(w).unwrap();
        let mut post = genesis_state();
        post.insert(BOB, Account { balance: 500, nonce: 0 });
        assert_eq!(pv.new_state_root, state_commitment(&post));
        assert_ne!(pv.deposit_root, [0u8; 32]);
    }

    #[test]
    fn withdrawal_burns_and_sets_root() {
        let state = genesis_state();
        let tx = SimpleTx { from: ALICE, to: WITHDRAWAL_PREDEPLOY, value: 100, nonce: 0 };
        let w = witness_for(&state, vec![tx.encode().to_vec()]);
        let pv = stf(w).unwrap();
        let mut post = StateMap::new();
        post.insert(ALICE, Account { balance: 900, nonce: 1 });
        // Value burned: WITHDRAWAL_PREDEPLOY gains no account balance.
        assert_eq!(pv.new_state_root, state_commitment(&post));
        assert_ne!(pv.withdrawal_root, [0u8; 32]);
    }

    #[test]
    fn witness_root_mismatch_rejected() {
        let state = genesis_state();
        let mut w = witness_for(&state, vec![]);
        w.pre_state_root[0] ^= 1;
        assert!(matches!(stf(w), Err(StfError::WitnessRootMismatch { .. })));
    }

    #[test]
    fn bad_nonce_and_insufficient_balance_rejected() {
        let state = genesis_state();
        let bad_nonce = SimpleTx { from: ALICE, to: BOB, value: 1, nonce: 5 };
        let w = witness_for(&state, vec![bad_nonce.encode().to_vec()]);
        assert!(matches!(
            stf(w),
            Err(StfError::BadNonce { index: 0, expected: 0, got: 5 })
        ));

        let too_much = SimpleTx { from: ALICE, to: BOB, value: 1_001, nonce: 0 };
        let w = witness_for(&state, vec![too_much.encode().to_vec()]);
        assert_eq!(stf(w), Err(StfError::InsufficientBalance { index: 0 }));
    }

    #[test]
    fn unknown_sender_malformed_tx_duplicate_leaf_rejected() {
        let state = genesis_state();
        let ghost = SimpleTx { from: BOB, to: ALICE, value: 1, nonce: 0 };
        let w = witness_for(&state, vec![ghost.encode().to_vec()]);
        assert_eq!(stf(w), Err(StfError::UnknownSender { index: 0 }));

        let w = witness_for(&state, vec![vec![1, 2, 3]]);
        assert_eq!(stf(w), Err(StfError::MalformedTx { index: 0 }));

        let mut w = witness_for(&state, vec![]);
        let dup = w.state_witness[0].clone();
        w.state_witness.push(dup);
        assert_eq!(stf(w), Err(StfError::DuplicateAccount(ALICE)));
    }

    #[test]
    fn stf_is_deterministic() {
        let state = genesis_state();
        let tx = SimpleTx { from: ALICE, to: BOB, value: 5, nonce: 0 };
        let w1 = witness_for(&state, vec![tx.encode().to_vec()]);
        let w2 = w1.clone();
        assert_eq!(stf(w1).unwrap(), stf(w2).unwrap());
    }

    #[test]
    fn tx_encode_decode_round_trip() {
        let tx = SimpleTx { from: ALICE, to: BOB, value: u128::MAX, nonce: u64::MAX };
        assert_eq!(SimpleTx::decode(&tx.encode()), Some(tx));
        assert_eq!(SimpleTx::decode(&[0u8; TX_LEN - 1]), None);
        assert_eq!(SimpleTx::decode(&[0u8; TX_LEN + 1]), None);
    }

    #[test]
    fn tx_encoding_layout() {
        // Fixed 64-byte layout: from(20) ‖ to(20) ‖ value LE(16) ‖ nonce LE(8).
        let tx = SimpleTx { from: [0x11; 20], to: [0x22; 20], value: 0x0A0B, nonce: 0x0C0D };
        let enc = tx.encode();
        assert_eq!(enc.len(), TX_LEN);
        assert_eq!(&enc[0..20], &[0x11; 20]);
        assert_eq!(&enc[20..40], &[0x22; 20]);
        assert_eq!(&enc[40..56], &tx.value.to_le_bytes());
        assert_eq!(&enc[56..64], &tx.nonce.to_le_bytes());
    }

    #[test]
    fn account_leaf_encoding_layout() {
        // Fixed 44-byte flat leaf: addr(20) ‖ balance LE(16) ‖ nonce LE(8).
        let acct = Account { balance: 0x0102_0304, nonce: 0x0506 };
        let leaf = encode_account_leaf(&ALICE, &acct);
        assert_eq!(leaf.len(), ACCOUNT_LEAF_LEN);
        assert_eq!(&leaf[0..20], &ALICE);
        assert_eq!(&leaf[20..36], &acct.balance.to_le_bytes());
        assert_eq!(&leaf[36..44], &acct.nonce.to_le_bytes());
    }

    #[test]
    fn multiple_txs_same_sender_apply_in_nonce_order() {
        let state = genesis_state(); // Alice 1000, nonce 0
        let t0 = SimpleTx { from: ALICE, to: BOB, value: 100, nonce: 0 };
        let t1 = SimpleTx { from: ALICE, to: BOB, value: 200, nonce: 1 };
        let w = witness_for(&state, vec![t0.encode().to_vec(), t1.encode().to_vec()]);
        let pv = stf(w).unwrap();
        let mut post = StateMap::new();
        post.insert(ALICE, Account { balance: 700, nonce: 2 });
        post.insert(BOB, Account { balance: 300, nonce: 0 });
        assert_eq!(pv.new_state_root, state_commitment(&post));
    }

    #[test]
    fn second_tx_with_stale_nonce_is_rejected() {
        let state = genesis_state();
        let t0 = SimpleTx { from: ALICE, to: BOB, value: 1, nonce: 0 };
        // Nonce should now be 1; replaying nonce 0 must fail on the second tx.
        let t1_stale = SimpleTx { from: ALICE, to: BOB, value: 1, nonce: 0 };
        let w = witness_for(&state, vec![t0.encode().to_vec(), t1_stale.encode().to_vec()]);
        assert_eq!(
            stf(w),
            Err(StfError::BadNonce { index: 1, expected: 1, got: 0 })
        );
    }

    #[test]
    fn deposits_credit_before_txs_execute() {
        // Deposits are applied at batch start (design step order), so the
        // recipient can spend the topped-up balance within the same batch.
        let state = genesis_state(); // Alice 1000
        let mut w = witness_for(
            &state,
            vec![SimpleTx { from: ALICE, to: BOB, value: 1_200, nonce: 0 }.encode().to_vec()],
        );
        w.deposits = vec![DepositEvent { source_hash: [7; 32], recipient: ALICE, amount: 500 }];
        let pv = stf(w).unwrap();
        let mut post = StateMap::new();
        post.insert(ALICE, Account { balance: 300, nonce: 1 }); // 1000 + 500 - 1200
        post.insert(BOB, Account { balance: 1_200, nonce: 0 });
        assert_eq!(pv.new_state_root, state_commitment(&post));
        assert_ne!(pv.deposit_root, [0u8; 32]);
    }

    #[test]
    fn self_transfer_conserves_balance_and_bumps_nonce() {
        // to == from exercises the sender/recipient aliasing: the value leaves
        // and returns to the same account, so only the nonce changes.
        let state = genesis_state();
        let tx = SimpleTx { from: ALICE, to: ALICE, value: 250, nonce: 0 };
        let w = witness_for(&state, vec![tx.encode().to_vec()]);
        let pv = stf(w).unwrap();
        let mut post = StateMap::new();
        post.insert(ALICE, Account { balance: 1_000, nonce: 1 });
        assert_eq!(pv.new_state_root, state_commitment(&post));
    }

    #[test]
    fn zero_value_transfer_materializes_recipient_and_bumps_nonce() {
        // A zero-value transfer still bumps the sender nonce and (unlike
        // Ethereum's EIP-161) materializes the recipient as a zero account in
        // this placeholder flat-state model — pinned so any change is noticed.
        let state = genesis_state();
        let tx = SimpleTx { from: ALICE, to: BOB, value: 0, nonce: 0 };
        let w = witness_for(&state, vec![tx.encode().to_vec()]);
        let pv = stf(w).unwrap();
        let mut post = StateMap::new();
        post.insert(ALICE, Account { balance: 1_000, nonce: 1 });
        post.insert(BOB, Account { balance: 0, nonce: 0 });
        assert_eq!(pv.new_state_root, state_commitment(&post));
    }

    #[test]
    fn deposit_balance_overflow_is_rejected() {
        let state = genesis_state();
        let mut w = witness_for(&state, vec![]);
        w.deposits = vec![
            DepositEvent { source_hash: [1; 32], recipient: BOB, amount: u128::MAX },
            DepositEvent { source_hash: [2; 32], recipient: BOB, amount: 1 },
        ];
        assert_eq!(stf(w), Err(StfError::BalanceOverflow));
    }

    #[test]
    fn transfer_credit_overflow_is_rejected() {
        let mut state = StateMap::new();
        state.insert(ALICE, Account { balance: 1_000, nonce: 0 });
        state.insert(BOB, Account { balance: u128::MAX, nonce: 0 });
        let tx = SimpleTx { from: ALICE, to: BOB, value: 1, nonce: 0 };
        let w = witness_for(&state, vec![tx.encode().to_vec()]);
        assert_eq!(stf(w), Err(StfError::BalanceOverflow));
    }

    #[test]
    fn stf_rejects_too_many_ancestors() {
        // Built directly (not via decode), so the STF's own guard fires even
        // when the witness codec's limit is bypassed.
        let state = genesis_state();
        let mut w = witness_for(&state, vec![]);
        w.ancestor_headers = (0..=MAX_ANCESTOR_HEADERS as u64)
            .map(|height| AncestorHeader { height, hash: [0; 32] })
            .collect();
        assert_eq!(w.ancestor_headers.len(), MAX_ANCESTOR_HEADERS + 1);
        assert_eq!(stf(w), Err(StfError::TooManyAncestors(MAX_ANCESTOR_HEADERS + 1)));
    }

    #[test]
    fn state_commitment_is_order_independent_and_deterministic() {
        // The flat state commitment is a set commitment: equal account sets
        // hash equally regardless of insertion order, and differ on any change.
        let mut a = StateMap::new();
        a.insert(ALICE, Account { balance: 5, nonce: 1 });
        a.insert(BOB, Account { balance: 7, nonce: 0 });
        let mut b = StateMap::new();
        b.insert(BOB, Account { balance: 7, nonce: 0 });
        b.insert(ALICE, Account { balance: 5, nonce: 1 });
        assert_eq!(state_commitment(&a), state_commitment(&b));
        let mut c = a.clone();
        c.insert(ALICE, Account { balance: 6, nonce: 1 });
        assert_ne!(state_commitment(&a), state_commitment(&c));
    }
}
