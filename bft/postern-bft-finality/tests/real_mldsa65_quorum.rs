// SPDX-License-Identifier: MIT OR Apache-2.0
//! End-to-end weighted `> 2/3` finality driven by **real ML-DSA-65 (FIPS 204)**
//! signatures, exercising the [`CheckpointVerifier`] seam with the actual
//! RustCrypto `ml-dsa` primitive instead of the mock/stub.
//!
//! # SCAFFOLD / UNAUDITED — not a security claim
//!
//! `real-mldsa65` is ON by default, so this file runs on a plain `cargo test`
//! (no `--features` flag); only `--no-default-features` compiles it to nothing
//! (`#![cfg(...)]` below), falling back to the accept-nothing
//! `RejectingStubVerifier`. A green run here demonstrates that the crate's
//! weighted-quorum arithmetic is correctly plumbed through a genuine FIPS-204
//! verify — it is **not** a claim that this crate is secure, audited,
//! operational, or deployed. The `ml-dsa` crate is pre-1.0 (`0.1.1`) and
//! UNAUDITED; the committee is hashrate-weighted (only as decentralized as the
//! hashrate); the Bloch base beneath any checkpoint is still k-forgeable today,
//! so a reached quorum is not settlement finality.
#![cfg(feature = "real-mldsa65")]

use postern_bft_finality::{
    verify_finalized, Checkpoint, FinalityOutcome, RotationMeta, RustCryptoMlDsa65Signer,
    RustCryptoMlDsa65Verifier, Validator, ValidatorId, ValidatorSet, Vote,
};

/// 21 committee seats. The first 14 ("signers") carry weight 5, the last 7
/// carry weight 4:  total_weight = 14*5 + 7*4 = 98.
///
/// This is deliberately a **weighted**, not count-based, committee: 14 of 21
/// seats is exactly 2/3 by *count* (which would FAIL the strict `> 2/3` rule),
/// but the 14 signers hold 70 of 98 weight = 71.4% > 2/3, so they finalize —
/// and dropping any one signer (13 seats, weight 65 < 2/3 of 98 = 65.33) falls
/// back below quorum. That boundary is the whole point of the test.
const N_SEATS: usize = 21;
const N_SIGNERS: usize = 14;
const SIGNER_WEIGHT: u64 = 5;
const NON_SIGNER_WEIGHT: u64 = 4;

/// Deterministic per-seat ML-DSA-65 signer (test-only seed; never do this for a
/// real key).
fn seat_signer(seat: usize) -> RustCryptoMlDsa65Signer {
    RustCryptoMlDsa65Signer::from_seed([(seat as u8) + 1; 32])
}

/// Build the 21-seat hashrate-weighted committee with REAL ML-DSA-65 public
/// keys, returning the set alongside the signers so the test can co-sign.
fn build_committee() -> (ValidatorSet, Vec<RustCryptoMlDsa65Signer>) {
    let mut validators = Vec::with_capacity(N_SEATS);
    let mut signers = Vec::with_capacity(N_SEATS);
    for seat in 0..N_SEATS {
        let signer = seat_signer(seat);
        let mut id = [0u8; 32];
        id[0] = (seat as u8) + 1;
        id[1] = 0xBF;
        let mut coinbase = [0u8; 20];
        coinbase[0] = (seat as u8) + 1;
        coinbase[1] = 0xBF;
        let weight = if seat < N_SIGNERS { SIGNER_WEIGHT } else { NON_SIGNER_WEIGHT };
        validators.push(Validator {
            id: ValidatorId(id),
            coinbase_addr: coinbase,
            pubkey: signer.public_key_bytes(), // genuine 1952-byte ML-DSA-65 key
            weight,
        });
        signers.push(signer);
    }
    let set = ValidatorSet::new(
        validators,
        RotationMeta { epoch: 7, window_blocks: 2016, min_share: 1 },
    )
    .expect("21 distinct real-key seats form a valid weighted committee");
    (set, signers)
}

fn checkpoint(set: &ValidatorSet) -> Checkpoint {
    Checkpoint {
        committee_epoch: set.epoch(),
        finalized_height: 404_242,
        finalized_block_hash: [0xA1; 32],
        prev_checkpoint_hash: [0x00; 32],
        committee_commitment: [0xC0; 32],
        total_weight: set.total_weight(),
    }
}

/// Produce a GENUINE ML-DSA-65 vote for `seat` over the checkpoint payload.
fn genuine_vote(signers: &[RustCryptoMlDsa65Signer], seat: usize, message: &[u8]) -> Vote {
    let sig = signers[seat].sign(message).expect("deterministic ML-DSA-65 sign succeeds");
    assert_eq!(sig.len(), 3309, "ML-DSA-65 signature is 3309 bytes (FIPS 204)");
    Vote { validator_index: seat as u32, sig }
}

// ── 14-of-21 genuine ML-DSA-65 signatures reach a weighted > 2/3 quorum ──────

#[test]
fn fourteen_of_twenty_one_real_mldsa65_signatures_finalize() {
    let (set, signers) = build_committee();
    assert_eq!(set.size(), 21);
    assert_eq!(set.total_weight(), 98);

    let c = checkpoint(&set);
    let message = c.canonical_signing_payload();

    // Seats 0..14 each contribute a real ML-DSA-65 signature over the payload.
    let votes: Vec<Vote> = (0..N_SIGNERS).map(|s| genuine_vote(&signers, s, &message)).collect();

    // Verified through the REAL FIPS-204 primitive (not the mock/stub).
    let outcome = verify_finalized(&c, &votes, &set, &RustCryptoMlDsa65Verifier);
    assert_eq!(
        outcome,
        FinalityOutcome::Finalized { covered_weight: 70, total_weight: 98 },
        "14 signers holding 70/98 weight (> 2/3) must finalize"
    );
    assert!(outcome.is_finalized());
}

// ── a sub-quorum (13 of the 14 signers) does NOT finalize ────────────────────

#[test]
fn sub_quorum_of_thirteen_real_signatures_is_not_finalized() {
    let (set, signers) = build_committee();
    let c = checkpoint(&set);
    let message = c.canonical_signing_payload();

    // Drop one signer: 13 genuine signatures cover 65/98 weight.
    // 65*3 = 195 !> 196 = 98*2, so the strict > 2/3 rule is NOT met.
    let votes: Vec<Vote> =
        (0..(N_SIGNERS - 1)).map(|s| genuine_vote(&signers, s, &message)).collect();

    let outcome = verify_finalized(&c, &votes, &set, &RustCryptoMlDsa65Verifier);
    assert_eq!(
        outcome,
        FinalityOutcome::NotFinalized { covered_weight: 65, total_weight: 98 },
        "13 signers holding 65/98 weight (< 2/3) must NOT finalize"
    );
    assert!(!outcome.is_finalized());
}

// ── real verify actually rejects a tampered signature (no free weight) ───────

#[test]
fn tampered_real_signature_adds_no_weight() {
    let (set, signers) = build_committee();
    let c = checkpoint(&set);
    let message = c.canonical_signing_payload();

    // 13 genuine signatures (65 weight) plus one TAMPERED signature for the
    // 14th seat: if the flipped signature counted, weight would hit 70 and
    // finalize. A real FIPS-204 verify rejects it, so it stays at 65.
    let mut votes: Vec<Vote> =
        (0..(N_SIGNERS - 1)).map(|s| genuine_vote(&signers, s, &message)).collect();

    let mut tampered = signers[N_SIGNERS - 1].sign(&message).unwrap();
    tampered[0] ^= 0x01; // flip one bit
    votes.push(Vote { validator_index: (N_SIGNERS - 1) as u32, sig: tampered });

    let outcome = verify_finalized(&c, &votes, &set, &RustCryptoMlDsa65Verifier);
    assert_eq!(
        outcome,
        FinalityOutcome::NotFinalized { covered_weight: 65, total_weight: 98 },
        "a bit-flipped ML-DSA-65 signature must not verify or add weight"
    );
}

// ── a genuine signature presented under the WRONG seat is rejected ───────────

#[test]
fn signature_under_wrong_seat_is_rejected() {
    let (set, signers) = build_committee();
    let c = checkpoint(&set);
    let message = c.canonical_signing_payload();

    // 13 genuine signers (65 weight). Then seat 0's genuine signature is
    // resubmitted under seat 13's index: verify() checks seat 13's key over the
    // message, seat 0's signature fails against it => no weight added.
    let mut votes: Vec<Vote> =
        (0..(N_SIGNERS - 1)).map(|s| genuine_vote(&signers, s, &message)).collect();

    let seat0_sig = signers[0].sign(&message).unwrap();
    votes.push(Vote { validator_index: (N_SIGNERS - 1) as u32, sig: seat0_sig });

    let outcome = verify_finalized(&c, &votes, &set, &RustCryptoMlDsa65Verifier);
    assert_eq!(
        outcome,
        FinalityOutcome::NotFinalized { covered_weight: 65, total_weight: 98 },
        "seat 0's real signature must not verify under seat 13's key"
    );
}

// ── even genuine 14-of-21 signatures reach no quorum under the offline stub ──

#[test]
fn offline_stub_reaches_no_quorum_even_with_real_signatures() {
    use postern_bft_finality::RejectingStubVerifier;

    let (set, signers) = build_committee();
    let c = checkpoint(&set);
    let message = c.canonical_signing_payload();
    let votes: Vec<Vote> = (0..N_SIGNERS).map(|s| genuine_vote(&signers, s, &message)).collect();

    // The `--no-default-features` offline verifier asserts nothing: real
    // signatures or not, it never reaches quorum. (A default `cargo test` uses
    // the real `RustCryptoMlDsa65Verifier`, exercised by the tests above.)
    let outcome = verify_finalized(&c, &votes, &set, &RejectingStubVerifier);
    assert_eq!(
        outcome,
        FinalityOutcome::NotFinalized { covered_weight: 0, total_weight: 98 }
    );
    assert!(!outcome.is_finalized());
}
