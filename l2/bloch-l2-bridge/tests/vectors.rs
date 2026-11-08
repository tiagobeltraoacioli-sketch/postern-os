// SPDX-License-Identifier: MIT OR Apache-2.0
//! Golden vectors + cross-module end-to-end shape tests (mirroring the
//! bloch-tokens vectors.rs discipline: byte layouts are pinned here so any
//! silent format drift fails CI).

use bloch_l2_bridge::atoms::{atoms_to_wei, wei_to_atoms, ATOM_SCALE};
use bloch_l2_bridge::envelope::{extract_deposit_envelope, DepositEnvelope, TxOutput};
use bloch_l2_bridge::hex;
use bloch_l2_bridge::merkle::{
    verify_inclusion, zero_hashes, IncrementalMerkleTree, ReferenceTree, TREE_DEPTH,
};
use bloch_l2_bridge::status::{
    confirmation_depth, ConfirmationRequirement, WithdrawalEvent, WithdrawalStatus, ATOMS_PER_BLCH,
};
use bloch_l2_bridge::withdrawal::{WithdrawalInclusion, WithdrawalMessage, UNANCHORED_ROOT};

/// The normative L2D0 golden vector, written out byte-for-byte.
#[test]
fn l2d0_golden_vector_is_pinned() {
    let envelope = DepositEnvelope {
        l2_chain_id: 700_771,
        l2_recipient: hex::decode_array::<20>("00112233445566778899aabbccddeeff00112233").unwrap(),
    };
    // magic | version | op | chain_id LE | recipient — exactly 34 bytes
    let golden = "4c3244300001" .to_string() + "63b10a0000000000" + "00112233445566778899aabbccddeeff00112233";
    let encoded = envelope.encode();
    assert_eq!(encoded.len(), 34);
    assert_eq!(hex::encode(&encoded), golden);
    assert_eq!(DepositEnvelope::decode(&encoded).unwrap(), envelope);
}

/// Full deposit-side pipeline on pure data: tx outputs -> envelope
/// extraction -> K schedule -> exact mint arithmetic.
#[test]
fn deposit_pipeline_end_to_end() {
    let envelope = DepositEnvelope {
        l2_chain_id: 700_771,
        l2_recipient: [0x42; 20],
    };
    let deposit_atoms: u64 = 25 * ATOMS_PER_BLCH; // 25 BLCH to the vault
    let outputs = vec![
        // vault payment (script here is opaque to this layer)
        TxOutput {
            value: deposit_atoms,
            script_pubkey: vec![0xab; 20],
        },
        // the envelope, zero-value
        TxOutput {
            value: 0,
            script_pubkey: envelope.encode().to_vec(),
        },
    ];

    let (vout, decoded) = extract_deposit_envelope(&outputs).expect("envelope present");
    assert_eq!(vout, 1);
    assert_eq!(decoded, envelope);

    // 25 BLCH sits in the 96-confirmation tier
    assert_eq!(
        confirmation_depth(deposit_atoms),
        ConfirmationRequirement::Automatic { depth: 96 }
    );

    // mint = amount * ATOM_SCALE, exact, round-trippable
    let mint_wei = atoms_to_wei(deposit_atoms);
    assert_eq!(mint_wei, 25_000_000_000_000_000_000); // 25e18
    assert_eq!(wei_to_atoms(mint_wei), Ok(deposit_atoms));
}

/// Full withdrawal-side pipeline on pure data: message -> aligned burn ->
/// leaf -> tree -> proof -> verify.
#[test]
fn withdrawal_pipeline_end_to_end() {
    // user burns 3 BLCH worth of native gas token
    let burn_wei: u128 = 3 * 100_000_000 * ATOM_SCALE;
    let amount_atoms = wei_to_atoms(burn_wei).expect("aligned");
    assert_eq!(amount_atoms, 3 * ATOMS_PER_BLCH);
    // a mis-aligned burn is refused (the withdraw() revert rule)
    assert!(wei_to_atoms(burn_wei + 1).is_err());

    let msg = WithdrawalMessage {
        nonce: 0,
        l2_sender: [0xa1; 20],
        l1_recipient: [0xb2; 20],
        amount_atoms,
        epoch_number: 9,
    };

    let mut tree = IncrementalMerkleTree::new();
    let mut reference = ReferenceTree::new();
    // some prior withdrawals
    for n in 0..3u64 {
        let other = WithdrawalMessage {
            nonce: n + 100,
            ..msg
        };
        tree.insert(other.leaf()).unwrap();
        reference.push(other.leaf());
    }
    let index = tree.insert(msg.leaf()).unwrap();
    reference.push(msg.leaf());
    assert_eq!(index, 3);

    let root = tree.root();
    assert_eq!(root, reference.root());

    let branch = reference.proof(index).unwrap();
    assert!(verify_inclusion(&msg.leaf(), index, &branch, &root));

    // a tampered amount does not verify against the same root
    let forged = WithdrawalMessage {
        amount_atoms: amount_atoms + 1,
        ..msg
    };
    assert!(!verify_inclusion(&forged.leaf(), index, &branch, &root));
}

/// Cross-module lifecycle: anchor a withdrawal root, walk the status state
/// machine to `ReleaseEligible`, and confirm the message-level inclusion
/// check accepts under the real root but refuses the all-zero (unanchored)
/// root. Pure data; nothing here moves value.
#[test]
fn withdrawal_lifecycle_and_inclusion_end_to_end() {
    let msg = WithdrawalMessage {
        nonce: 0,
        l2_sender: [0xa1; 20],
        l1_recipient: [0xb2; 20],
        amount_atoms: 3 * ATOMS_PER_BLCH,
        epoch_number: 9,
    };
    let mut tree = IncrementalMerkleTree::new();
    let mut reference = ReferenceTree::new();
    let index = tree.insert(msg.leaf()).unwrap();
    reference.push(msg.leaf());
    let root = tree.root();
    let branch = reference.proof(index).unwrap();

    // Before any anchor is observed, the root is the unanchored sentinel:
    // the inclusion check refuses it outright (distinct from NotIncluded).
    assert_eq!(
        msg.verify_inclusion(index, &branch, &UNANCHORED_ROOT),
        WithdrawalInclusion::UnanchoredRoot
    );

    // Drive the status machine: Queued -> Provable -> ReleaseEligible.
    let s = WithdrawalStatus::Queued;
    let s = s.step(WithdrawalEvent::AnchorObserved {
        commit_txid: [0xcc; 32],
        depth: 1,
    });
    let s = s.step(WithdrawalEvent::AnchorDeepened { depth: 24 });
    assert!(matches!(s, WithdrawalStatus::Provable { depth: 24, .. }));
    let s = s.step(WithdrawalEvent::ReleaseAuthorized);
    assert_eq!(s, WithdrawalStatus::ReleaseEligible);

    // Now the message verifies under the real anchored root...
    assert!(msg.verify_inclusion(index, &branch, &root).is_included());
    // ...but a fork observation still halts on a deep reorg (safety wins).
    assert_eq!(
        s.step(WithdrawalEvent::DeepReorg),
        WithdrawalStatus::Halted
    );
}

/// Depth-32 zero cascade: pin the empty root through the externally-known
/// keccak zero-pair constant (level 1), then the full cascade.
#[test]
fn empty_root_zero_cascade_pinned() {
    let z = zero_hashes();
    assert_eq!(z[0], [0u8; 32]);
    assert_eq!(
        hex::encode(&z[1]),
        "ad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5"
    );
    assert_eq!(IncrementalMerkleTree::new().root(), z[TREE_DEPTH]);
}
