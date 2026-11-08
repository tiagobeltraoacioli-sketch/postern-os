//! End-to-end pipeline test for the SCAFFOLD:
//! host builds witness → serialize → (pretend to ship to guest) → deserialize
//! → placeholder STF → public values → mock bind → mock verify → chain the
//! next batch via `prev_batch_hash`.
//!
//! Reminder: nothing here is a zk proof. The MockProver binds bytes by hash
//! and has zero soundness; this test exercises PLUMBING only.

use bloch_l2_prover::stf::{
    encode_account_leaf, state_commitment, Account, SimpleTx, StateMap, WITHDRAWAL_PREDEPLOY,
};
use bloch_l2_prover::{
    stf, AncestorHeader, BatchContext, DepositEvent, ExecutionWitness, MockProver,
    MockVerifyError,
};

const CHAIN_ID: u64 = 700_771;
const ALICE: [u8; 20] = [0xA1; 20];
const BOB: [u8; 20] = [0xB0; 20];

fn witness(
    batch_index: u64,
    prev_batch_hash: [u8; 32],
    state: &StateMap,
    txs: Vec<Vec<u8>>,
    deposits: Vec<DepositEvent>,
) -> ExecutionWitness {
    ExecutionWitness {
        context: BatchContext {
            l2_chain_id: CHAIN_ID,
            batch_index,
            prev_batch_hash,
            l1_origin_hash: [0xF0; 32],
            l1_origin_height: 1_000 + batch_index,
            timestamp: 1_760_000_000 + batch_index * 2,
        },
        pre_state_root: state_commitment(state),
        txs,
        state_witness: state
            .iter()
            .map(|(a, ac)| encode_account_leaf(a, ac).to_vec())
            .collect(),
        bytecodes: vec![],
        ancestor_headers: vec![AncestorHeader { height: 0, hash: [0xEE; 32] }],
        deposits,
    }
}

#[test]
fn two_batch_pipeline_with_chain_link() {
    let prover = MockProver;

    // Genesis: Alice funded by a bridge deposit in batch 0.
    let genesis = StateMap::new();
    let w0 = witness(
        0,
        [0u8; 32],
        &genesis,
        vec![],
        vec![DepositEvent { source_hash: [1; 32], recipient: ALICE, amount: 1_000 }],
    );

    // Ship the witness as bytes (host → guest boundary).
    let w0 = ExecutionWitness::decode(&w0.encode()).expect("witness round-trip");
    let (proof0, pv0) = prover.prove(w0).expect("batch 0 proves");
    prover.verify(&proof0, &pv0).expect("batch 0 verifies");
    assert_eq!(pv0.batch_index, 0);
    assert_ne!(pv0.deposit_root, [0u8; 32]);

    // Post-state after batch 0, recomputed independently by the "host".
    let mut state1 = StateMap::new();
    state1.insert(ALICE, Account { balance: 1_000, nonce: 0 });
    assert_eq!(pv0.new_state_root, state_commitment(&state1));

    // Batch 1: transfer + withdrawal, chained via prev_batch_hash.
    let t1 = SimpleTx { from: ALICE, to: BOB, value: 300, nonce: 0 };
    let t2 = SimpleTx { from: ALICE, to: WITHDRAWAL_PREDEPLOY, value: 200, nonce: 1 };
    let w1 = witness(
        1,
        pv0.commitment(), // the SHAKE-256 chain link from the design
        &state1,
        vec![t1.encode().to_vec(), t2.encode().to_vec()],
        vec![],
    );
    let w1 = ExecutionWitness::decode(&w1.encode()).expect("witness round-trip");
    let (proof1, pv1) = prover.prove(w1).expect("batch 1 proves");
    prover.verify(&proof1, &pv1).expect("batch 1 verifies");

    // Chain-link and continuity checks the real l2-verifier would make.
    assert_eq!(pv1.prev_batch_hash, pv0.commitment());
    assert_eq!(pv1.prev_state_root, pv0.new_state_root);
    assert_eq!(pv1.batch_index, pv0.batch_index + 1);
    assert_ne!(pv1.withdrawal_root, [0u8; 32]);

    // Expected final state: Alice 1000-300-200 = 500 (nonce 2), Bob 300;
    // the 200 was burned into the withdrawal root.
    let mut state2 = StateMap::new();
    state2.insert(ALICE, Account { balance: 500, nonce: 2 });
    state2.insert(BOB, Account { balance: 300, nonce: 0 });
    assert_eq!(pv1.new_state_root, state_commitment(&state2));

    // Public values survive their own wire format.
    let pv1_bytes = pv1.encode();
    let pv1_back = bloch_l2_prover::BatchPublicValues::decode(&pv1_bytes).unwrap();
    assert_eq!(pv1, pv1_back);

    // Tamper detection (a hash check, NOT fraud detection): a verifier handed
    // different publics rejects the binding.
    let mut tampered = pv1;
    tampered.new_state_root[0] ^= 0xFF;
    assert_eq!(
        prover.verify(&proof1, &tampered),
        Err(MockVerifyError::BindingMismatch)
    );
}

#[test]
fn invalid_batch_cannot_be_mock_proven() {
    // Mirrors (without any cryptographic force) the design property that an
    // invalid batch is unprovable: an overspend fails the STF, so prove()
    // yields no proof at all.
    let mut state = StateMap::new();
    state.insert(ALICE, Account { balance: 10, nonce: 0 });
    let overspend = SimpleTx { from: ALICE, to: BOB, value: 11, nonce: 0 };
    let w = witness(5, [0; 32], &state, vec![overspend.encode().to_vec()], vec![]);
    assert!(MockProver.prove(w).is_err());
}

#[test]
fn determinism_equal_witness_bytes_equal_publics() {
    let mut state = StateMap::new();
    state.insert(ALICE, Account { balance: 42, nonce: 0 });
    let tx = SimpleTx { from: ALICE, to: BOB, value: 1, nonce: 0 };
    let w = witness(2, [3; 32], &state, vec![tx.encode().to_vec()], vec![]);
    let bytes = w.encode();
    let a = stf(ExecutionWitness::decode(&bytes).unwrap()).unwrap();
    let b = stf(ExecutionWitness::decode(&bytes).unwrap()).unwrap();
    assert_eq!(a, b);
    assert_eq!(a.commitment(), b.commitment());
}
