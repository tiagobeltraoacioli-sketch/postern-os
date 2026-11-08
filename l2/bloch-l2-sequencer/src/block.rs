// SPDX-License-Identifier: MIT OR Apache-2.0
//! Block assembly: the ordering rule only.
//!
//! §5's derivation rule makes deposits MANDATORY: once derived from a
//! K-confirmed L1 escrow, a deposit executes FIRST in a block (OP-Stack
//! deposit-tx pattern) and the sequencer cannot drop it. User transactions
//! follow in the mempool's two-lane FIFO inclusion order, greedily under the
//! block gas limit.
//!
//! SCAFFOLD: no execution happens here — `revm` hookup, receipts, state roots
//! and real gas accounting are stubbed (see [`crate::stubs`]). "Gas" below is
//! the declared `gas_limit` of each tx, used only as a packing bound.

use std::collections::BTreeMap;

use crate::deposit::DepositTx;
use crate::mempool::{Mempool, TxSubmission};
use crate::params::L2_GAS_LIMIT;

/// A transaction slot in an assembled block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockTx {
    /// Type-0x7E system deposit — always at the front, never droppable.
    Deposit(DepositTx),
    /// Ordinary user transaction taken from the mempool.
    User(TxSubmission),
}

/// An assembled (UNEXECUTED) L2 block: ordering output only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct L2Block {
    pub number: u64,
    pub timestamp: u64,
    pub basefee: u128,
    pub gas_limit: u64,
    pub txs: Vec<BlockTx>,
}

impl L2Block {
    /// Number of leading deposit txs.
    pub fn deposit_count(&self) -> usize {
        self.txs
            .iter()
            .take_while(|t| matches!(t, BlockTx::Deposit(_)))
            .count()
    }
}

/// Assemble one block.
///
/// * `deposits` — the derived, K-confirmed deposit set for this block, in L1
///   derivation order. ALL of them are included, first, unconditionally
///   (§5: "executed first in the block, cannot be dropped by the sequencer
///   once anchored"). Their declared gas is reserved before any user tx.
/// * user txs come from `pool` in [`Mempool::inclusion_order`] order
///   (priority lane, then standard lane, FIFO within lane, nonce-eligible),
///   packed greedily: selection STOPS at the first tx that no longer fits the
///   remaining gas, rather than skipping it — skipping would break the FIFO
///   promise and same-sender nonce contiguity. Included txs are removed from
///   the pool; the rest stay pooled.
pub fn build_block(
    number: u64,
    timestamp: u64,
    basefee: u128,
    priority_tip_threshold: u128,
    deposits: Vec<DepositTx>,
    pool: &mut Mempool,
    account_nonces: &BTreeMap<[u8; 20], u64>,
) -> L2Block {
    let mut gas_reserved: u64 = 0;
    for d in &deposits {
        // Deposits are never dropped; their gas is reserved first. If the
        // derivation ever over-fills a block the assembly still includes them
        // (the real system sizes deposit gas at derivation time).
        gas_reserved = gas_reserved.saturating_add(d.gas_limit);
    }

    let order = pool.inclusion_order(basefee, priority_tip_threshold, account_nonces);
    let mut included: Vec<u64> = Vec::new();
    for &seq in &order {
        let e = pool
            .entries()
            .iter()
            .find(|e| e.arrival_seq == seq)
            .expect("inclusion_order returns live seqs");
        let next = gas_reserved.saturating_add(e.tx.gas_limit);
        if next > L2_GAS_LIMIT {
            break; // stop, don't skip: preserves FIFO + nonce contiguity
        }
        gas_reserved = next;
        included.push(seq);
    }
    let taken = pool.take(&included);

    let mut txs: Vec<BlockTx> = deposits.into_iter().map(BlockTx::Deposit).collect();
    txs.extend(taken.into_iter().map(|e| BlockTx::User(e.tx)));

    L2Block {
        number,
        timestamp,
        basefee,
        gas_limit: L2_GAS_LIMIT,
        txs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deposit::{DepositId, DepositTx};

    fn deposit(tag: u8, gas: u64) -> DepositTx {
        DepositTx::from_l1(
            &DepositId {
                l1_txid: [tag; 32],
                vout: 0,
            },
            &[0x99; 32],
            [tag; 20],
            [tag; 20],
            1_000,
            1_000,
            gas,
            vec![],
        )
    }

    fn user(sender_byte: u8, nonce: u64, tip: u128, gas: u64) -> TxSubmission {
        let mut hash = [0u8; 32];
        hash[0] = sender_byte;
        hash[1] = nonce as u8;
        TxSubmission {
            hash,
            sender: [sender_byte; 20],
            nonce,
            gas_limit: gas,
            max_fee_per_gas: 1_000,
            max_priority_fee_per_gas: tip,
            // Leading 0x02 = EIP-1559 envelope, clears the mempool type gate.
            raw: vec![0x02, sender_byte],
        }
    }

    const BASEFEE: u128 = 100;
    const THRESHOLD: u128 = 10;

    #[test]
    fn deposits_execute_first_in_derivation_order_then_lanes() {
        let mut pool = Mempool::new();
        pool.admit(user(1, 0, 1, 21_000), 0).unwrap(); // standard
        pool.admit(user(2, 0, 50, 21_000), 0).unwrap(); // priority
        let deposits = vec![deposit(0xd1, 21_000), deposit(0xd2, 21_000)];

        let block = build_block(
            7,
            1_000,
            BASEFEE,
            THRESHOLD,
            deposits.clone(),
            &mut pool,
            &BTreeMap::new(),
        );

        assert_eq!(block.txs.len(), 4);
        assert_eq!(block.deposit_count(), 2);
        // Deposits occupy the prefix, in derivation order.
        assert_eq!(block.txs[0], BlockTx::Deposit(deposits[0].clone()));
        assert_eq!(block.txs[1], BlockTx::Deposit(deposits[1].clone()));
        // Then the priority-lane user tx, then the standard-lane one.
        match (&block.txs[2], &block.txs[3]) {
            (BlockTx::User(a), BlockTx::User(b)) => {
                assert_eq!(a.sender, [2u8; 20], "priority lane first");
                assert_eq!(b.sender, [1u8; 20]);
            }
            other => panic!("expected user txs, got {other:?}"),
        }
        assert!(pool.is_empty());
    }

    #[test]
    fn deposits_cannot_be_dropped_even_with_no_user_capacity() {
        let mut pool = Mempool::new();
        // One giant user tx that fills the whole block.
        pool.admit(user(1, 0, 50, L2_GAS_LIMIT), 0).unwrap();
        let deposits = vec![deposit(0xd1, 1_000_000)];
        let block = build_block(
            1,
            2,
            BASEFEE,
            THRESHOLD,
            deposits,
            &mut pool,
            &BTreeMap::new(),
        );
        // Deposit is in; the user tx no longer fits and stays pooled.
        assert_eq!(block.deposit_count(), 1);
        assert_eq!(block.txs.len(), 1);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn gas_packing_stops_at_first_nonfitting_tx() {
        let mut pool = Mempool::new();
        // Same lane (all priority), FIFO: 20M, 15M (doesn't fit after 20M), 1M.
        pool.admit(user(1, 0, 50, 20_000_000), 0).unwrap();
        pool.admit(user(2, 0, 50, 15_000_000), 0).unwrap();
        pool.admit(user(3, 0, 50, 1_000_000), 0).unwrap();
        let block = build_block(
            1,
            2,
            BASEFEE,
            THRESHOLD,
            vec![],
            &mut pool,
            &BTreeMap::new(),
        );
        // Stops at sender 2 — sender 3 is NOT pulled forward past it (FIFO).
        assert_eq!(block.txs.len(), 1);
        match &block.txs[0] {
            BlockTx::User(t) => assert_eq!(t.sender, [1u8; 20]),
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn empty_everything_builds_empty_block() {
        let mut pool = Mempool::new();
        let block = build_block(
            0,
            0,
            BASEFEE,
            THRESHOLD,
            vec![],
            &mut pool,
            &BTreeMap::new(),
        );
        assert!(block.txs.is_empty());
        assert_eq!(block.gas_limit, L2_GAS_LIMIT);
    }
}
