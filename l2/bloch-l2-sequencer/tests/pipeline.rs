// SPDX-License-Identifier: MIT OR Apache-2.0
//! End-to-end ORDERING pipeline test (no execution, no network — SCAFFOLD):
//! admit user txs → derive-order blocks with mandatory-first deposits →
//! basefee updates per EIP-1559 → seal a batch → receipts reference the
//! promised FIFO positions.

use std::collections::BTreeMap;

use bloch_l2_sequencer::batch::BatchSealer;
use bloch_l2_sequencer::block::{build_block, BlockTx};
use bloch_l2_sequencer::deposit::{DepositId, DepositTx, ATOM_SCALE};
use bloch_l2_sequencer::fees::next_basefee_default;
use bloch_l2_sequencer::mempool::{AdmissionError, Mempool, TxSubmission};
use bloch_l2_sequencer::params::{
    BATCH_CADENCE_SECS, INITIAL_BASEFEE_WEI, PRIORITY_LANE_TIP_THRESHOLD_WEI,
};
use bloch_l2_sequencer::receipt::InclusionReceipt;

fn user(sender_byte: u8, nonce: u64, tip_gwei: u128) -> TxSubmission {
    let mut hash = [0u8; 32];
    hash[0] = sender_byte;
    hash[1] = nonce as u8;
    TxSubmission {
        hash,
        sender: [sender_byte; 20],
        nonce,
        gas_limit: 21_000,
        max_fee_per_gas: 10_000_000_000, // 10 gwei cap
        max_priority_fee_per_gas: tip_gwei * 1_000_000_000,
        // Leading 0x02 = EIP-1559 envelope, clears the mempool type gate.
        raw: vec![0x02, sender_byte, nonce as u8, 0xf0],
    }
}

#[test]
fn ordering_pipeline_end_to_end() {
    let mut pool = Mempool::new();
    let nonces: BTreeMap<[u8; 20], u64> = BTreeMap::new();

    // Six user txs: senders 1..3 standard (tip 0 gwei), 4..6 priority (2 gwei).
    let mut receipts = Vec::new();
    for (i, t) in [
        user(1, 0, 0),
        user(4, 0, 2),
        user(2, 0, 0),
        user(5, 0, 2),
        user(3, 0, 0),
        user(6, 0, 2),
    ]
    .into_iter()
    .enumerate()
    {
        let hash = t.hash;
        let seq = pool.admit(t, 0).unwrap();
        assert_eq!(seq, i as u64, "arrival seq mirrors admission order");
        receipts.push(InclusionReceipt::unsigned(hash, seq, 0, 1_000 + i as u64));
    }
    // Receipts are auditable bytes; signing is stubbed (empty sig).
    assert!(receipts.iter().all(|r| !r.is_signed()));
    assert!(receipts.iter().all(|r| !r.signing_payload().is_empty()));

    // Two K-confirmed deposits derived from L1.
    let deposits = vec![
        DepositTx::from_l1(
            &DepositId { l1_txid: [0xd1; 32], vout: 0 },
            &[0x0b; 32],
            [0xd1; 20],
            [0xd1; 20],
            7 * ATOM_SCALE,
            7 * ATOM_SCALE,
            21_000,
            vec![],
        ),
        DepositTx::from_l1(
            &DepositId { l1_txid: [0xd2; 32], vout: 1 },
            &[0x0b; 32],
            [0xd2; 20],
            [0xd2; 20],
            ATOM_SCALE,
            ATOM_SCALE,
            21_000,
            vec![],
        ),
    ];

    // Block 0 at the §1 genesis basefee.
    let block0 = build_block(
        0,
        1_000,
        INITIAL_BASEFEE_WEI,
        PRIORITY_LANE_TIP_THRESHOLD_WEI,
        deposits.clone(),
        &mut pool,
        &nonces,
    );

    // Placement: 2 deposits first (derivation order), then priority lane
    // FIFO (senders 4,5,6), then standard lane FIFO (senders 1,2,3).
    assert_eq!(block0.txs.len(), 8);
    assert_eq!(block0.deposit_count(), 2);
    let senders: Vec<u8> = block0.txs[2..]
        .iter()
        .map(|t| match t {
            BlockTx::User(u) => u.sender[0],
            BlockTx::Deposit(_) => panic!("deposit after user tx"),
        })
        .collect();
    assert_eq!(senders, vec![4, 5, 6, 1, 2, 3]);
    assert!(pool.is_empty());

    // EIP-1559 step: 8 * 21_000 gas used is far below target → basefee would
    // fall, but the scaffold floor (1 gwei = initial) clamps it.
    let gas_used = 8 * 21_000u64;
    let next = next_basefee_default(INITIAL_BASEFEE_WEI, gas_used);
    assert_eq!(next, INITIAL_BASEFEE_WEI);

    // Seal by cadence.
    let mut sealer = BatchSealer::new();
    assert!(sealer.push_block(&block0, 1_000).is_none());
    let (batch, _) = sealer
        .tick(1_000 + BATCH_CADENCE_SECS)
        .expect("cadence seal");
    assert_eq!(batch.batch_index, 0);
    assert_eq!(batch.l2_block_first, 0);
    assert_eq!(batch.l2_block_last, 0);
    assert_eq!(batch.tx_count, 8);
    // The batch commits to bytes that CONTAIN the canonical 0x7E deposits —
    // deposits cannot be dropped from the DA payload either.
    let d0 = deposits[0].encode();
    assert!(
        batch
            .tx_list
            .windows(d0.len())
            .any(|w| w == d0.as_slice()),
        "sealed batch must contain the canonical deposit bytes"
    );
    // §4 DA payload: batch_data_hash commits to the zstd-compressed bytes,
    // and that payload decompresses back to the canonical tx_list.
    assert_eq!(
        bloch_l2_sequencer::batch::decompress_batch(&batch.compressed)
            .expect("valid zstd frame"),
        batch.tx_list
    );
    assert_eq!(
        batch.batch_data_hash,
        bloch_l2_sequencer::hash::sha3_256(&batch.compressed)
    );
}

#[test]
fn blob_tx_is_rejected_at_the_sequencer_boundary() {
    // §1 enumerated delta: type-3 (EIP-4844) blob txs are rejected at the
    // sequencer, exactly as on OP-Stack L2s. The rejection happens at intake —
    // a blob tx never reaches ordering, block assembly, or a batch.
    let mut pool = Mempool::new();
    let mut blob = user(1, 0, 2);
    blob.raw = vec![0x03, 0xde, 0xad]; // EIP-4844 type byte
    assert_eq!(
        pool.admit(blob, 0).unwrap_err(),
        AdmissionError::BlobTxRejected
    );
    assert!(pool.is_empty(), "blob tx never enters the mempool");

    // A normal EIP-1559 tx from the same sender is admitted and orders as usual.
    let ok = user(1, 0, 2);
    pool.admit(ok, 0).unwrap();
    let order = pool.inclusion_order(
        INITIAL_BASEFEE_WEI,
        PRIORITY_LANE_TIP_THRESHOLD_WEI,
        &BTreeMap::new(),
    );
    assert_eq!(order, vec![0]);
}
