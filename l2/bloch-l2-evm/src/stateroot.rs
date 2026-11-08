// SPDX-License-Identifier: MIT OR Apache-2.0
//! State-root commitment — keccak-256 hexary Merkle-Patricia trie.
//!
//! The design (BLOCH-L2-EVM-DESIGN §1) commits state as a **standard Ethereum
//! keccak-256 hexary Merkle-Patricia trie root** (account trie + per-account
//! storage tries) so `eth_getProof` and the Bloch-anchored root are
//! byte-compatible with Ethereum tooling. This module computes that root over
//! the scaffold's [`L2State`] via `alloy-trie`'s `HashBuilder` (the primitive
//! reth uses), with account and storage values RLP-encoded exactly as Ethereum
//! does.
//!
//! Correctness anchors (see the tests): an empty state hashes to the canonical
//! `EMPTY_ROOT_HASH`; an account with no storage carries an `EMPTY_ROOT_HASH`
//! storage root inside its RLP; the root is deterministic and insertion-order
//! independent; **empty accounts (EIP-161: nonce 0, balance 0, empty code) are
//! excluded** from the trie exactly as on Ethereum. Still **SCAFFOLD/UNAUDITED** —
//! this is the state-root primitive, not a node.

use alloy_primitives::{keccak256, B256, U256};
use alloy_rlp::{Encodable, Header};
use alloy_trie::{HashBuilder, Nibbles, EMPTY_ROOT_HASH};
use revm::database::AccountState;
use revm::primitives::KECCAK_EMPTY;

use crate::state::L2State;

/// RLP-encode one account as Ethereum does: a list `[nonce, balance,
/// storageRoot, codeHash]`. `nonce`/`balance` use minimal big-endian (RLP integer
/// form); the two roots are fixed 32-byte strings.
fn encode_account(nonce: u64, balance: U256, storage_root: B256, code_hash: B256, out: &mut Vec<u8>) {
    let payload_len =
        nonce.length() + balance.length() + storage_root.length() + code_hash.length();
    Header { list: true, payload_length: payload_len }.encode(out);
    nonce.encode(out);
    balance.encode(out);
    storage_root.encode(out);
    code_hash.encode(out);
}

/// Feed `(keccak-hashed key, rlp value)` leaves into a hexary MPT and return its
/// root. Leaves are sorted by hashed key (the order `HashBuilder` requires).
/// Empty input yields the canonical [`EMPTY_ROOT_HASH`].
fn trie_root(mut leaves: Vec<(B256, Vec<u8>)>) -> B256 {
    if leaves.is_empty() {
        return EMPTY_ROOT_HASH;
    }
    leaves.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    let mut hb = HashBuilder::default();
    for (hashed_key, value) in &leaves {
        hb.add_leaf(Nibbles::unpack(hashed_key), value);
    }
    hb.root()
}

/// The keccak-256 MPT storage root over one account's slots: key
/// `keccak256(slot)`, value `rlp(U256)` (leading zeros trimmed), **zero-valued
/// slots omitted** (Ethereum stores no zero slots). Empty storage →
/// [`EMPTY_ROOT_HASH`].
fn storage_root<'a>(slots: impl Iterator<Item = (&'a U256, &'a U256)>) -> B256 {
    let leaves: Vec<(B256, Vec<u8>)> = slots
        .filter(|(_, value)| !value.is_zero())
        .map(|(slot, value)| {
            let key = keccak256(slot.to_be_bytes::<32>());
            let mut buf = Vec::new();
            value.encode(&mut buf);
            (key, buf)
        })
        .collect();
    trie_root(leaves)
}

/// Compute the real keccak-256 MPT **state root** over the account and storage
/// tries of `state`.
///
/// Each existing, non-empty account contributes a leaf keyed by
/// `keccak256(address)` whose value is `rlp(nonce, balance, storageRoot,
/// codeHash)`, where `storageRoot` is that account's own storage-trie root.
/// Empty accounts (EIP-161) and non-existing accounts are excluded, matching
/// Ethereum's state trie.
pub fn compute_keccak_mpt_state_root(state: &L2State) -> B256 {
    let leaves: Vec<(B256, Vec<u8>)> = state
        .db
        .cache
        .accounts
        .iter()
        .filter(|(_, acc)| acc.account_state != AccountState::NotExisting)
        .filter_map(|(address, acc)| {
            let info = acc.info()?;
            let code_hash = if info.code_hash == B256::ZERO { KECCAK_EMPTY } else { info.code_hash };
            // EIP-161: an account with nonce 0, balance 0, and empty code is not
            // in the state trie.
            if info.nonce == 0 && info.balance.is_zero() && code_hash == KECCAK_EMPTY {
                return None;
            }
            let s_root = storage_root(acc.storage.iter());
            let mut value = Vec::new();
            encode_account(info.nonce, info.balance, s_root, code_hash, &mut value);
            Some((keccak256(address), value))
        })
        .collect();
    trie_root(leaves)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scale::sats_to_wei;
    use crate::state::{DepositMint, DepositProvenance, L2State};
    use alloy_primitives::{address, Address};

    fn deposit(state: &mut L2State, to: Address, sats: u64) {
        state
            .deposit_mint(&DepositMint {
                recipient: to,
                mint_wei: sats_to_wei(sats),
                provenance: DepositProvenance::BridgedBlch { l1_txid: [0u8; 32], l1_vout: 0, l1_sats: sats },
            })
            .expect("deposit");
    }

    #[test]
    fn empty_state_is_the_canonical_empty_root() {
        // The well-known Ethereum empty-trie root keccak256(rlp("")).
        assert_eq!(compute_keccak_mpt_state_root(&L2State::new()), EMPTY_ROOT_HASH);
    }

    #[test]
    fn empty_storage_root_is_the_canonical_empty_root() {
        let none: Vec<(U256, U256)> = vec![];
        assert_eq!(storage_root(none.iter().map(|(k, v)| (k, v))), EMPTY_ROOT_HASH);
    }

    #[test]
    fn one_funded_account_yields_a_nonempty_deterministic_root() {
        let mut a = L2State::new();
        deposit(&mut a, address!("00000000000000000000000000000000000000aa"), 5);
        let r1 = compute_keccak_mpt_state_root(&a);
        assert_ne!(r1, EMPTY_ROOT_HASH, "a funded account must change the root");
        assert_ne!(r1, B256::ZERO, "a real MPT root is never all-zeroes");
        assert_eq!(r1, compute_keccak_mpt_state_root(&a), "deterministic");
    }

    #[test]
    fn root_is_insertion_order_independent() {
        let x = address!("00000000000000000000000000000000000000aa");
        let y = address!("00000000000000000000000000000000000000bb");
        let mut a = L2State::new();
        deposit(&mut a, x, 3);
        deposit(&mut a, y, 7);
        let mut b = L2State::new();
        deposit(&mut b, y, 7);
        deposit(&mut b, x, 3);
        assert_eq!(
            compute_keccak_mpt_state_root(&a),
            compute_keccak_mpt_state_root(&b),
            "the state root is a set commitment — insertion order must not matter"
        );
    }

    #[test]
    fn different_balances_give_different_roots() {
        let who = address!("00000000000000000000000000000000000000aa");
        let mut a = L2State::new();
        deposit(&mut a, who, 1);
        let mut b = L2State::new();
        deposit(&mut b, who, 2);
        assert_ne!(compute_keccak_mpt_state_root(&a), compute_keccak_mpt_state_root(&b));
    }

    #[test]
    fn eip161_empty_account_is_excluded_but_nonempty_is_included() {
        use revm::state::AccountInfo;
        let who = address!("00000000000000000000000000000000000000aa");

        // An account that EXISTS in the DB (account_state = None, not
        // NotExisting) but is empty per EIP-161 (nonce 0, balance 0, empty
        // code) must NOT appear in the state trie: the root stays the
        // canonical empty root even though the account is present in the cache.
        let mut empty = L2State::new();
        empty.db.insert_account_info(who, AccountInfo::default());
        assert!(
            empty.db.cache.accounts.contains_key(&who),
            "the empty account is present in the DB cache"
        );
        assert_eq!(
            compute_keccak_mpt_state_root(&empty),
            EMPTY_ROOT_HASH,
            "an EIP-161 empty account must be excluded from the state trie"
        );

        // Nonce alone (nonce 1, balance 0, empty code) makes the account
        // non-empty, so it IS in the trie and moves the root.
        let mut with_nonce = L2State::new();
        with_nonce
            .db
            .insert_account_info(who, AccountInfo { nonce: 1, ..Default::default() });
        assert_ne!(
            compute_keccak_mpt_state_root(&with_nonce),
            EMPTY_ROOT_HASH,
            "a nonce-1 account is not EIP-161-empty and belongs in the trie"
        );

        // Balance alone likewise makes it non-empty.
        let mut with_balance = L2State::new();
        with_balance.db.insert_account_info(
            who,
            AccountInfo { balance: U256::from(1u64), ..Default::default() },
        );
        assert_ne!(
            compute_keccak_mpt_state_root(&with_balance),
            EMPTY_ROOT_HASH,
            "a positive-balance account is not EIP-161-empty and belongs in the trie"
        );
    }

    #[test]
    fn eip161_empty_accounts_are_invisible_to_the_root() {
        use revm::state::AccountInfo;
        let funded = address!("00000000000000000000000000000000000000aa");
        let ghost = address!("00000000000000000000000000000000000000bb");

        let mut only_funded = L2State::new();
        deposit(&mut only_funded, funded, 9);

        let mut with_ghost = L2State::new();
        deposit(&mut with_ghost, funded, 9);
        // A touched-but-empty account alongside the funded one.
        with_ghost.db.insert_account_info(ghost, AccountInfo::default());

        assert_eq!(
            compute_keccak_mpt_state_root(&only_funded),
            compute_keccak_mpt_state_root(&with_ghost),
            "EIP-161 empty accounts do not perturb the state root"
        );
    }
}
