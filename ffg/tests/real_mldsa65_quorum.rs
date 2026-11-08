// SPDX-License-Identifier: MIT OR Apache-2.0
//! Integration test: the design's real **14-of-21 ML-DSA-65 (FIPS 204)**
//! quorum, exercised end-to-end over ONE [`PosternNotaryCheckpoint`] with
//! genuine RustCrypto `ml-dsa` signatures.
//!
//! # PLUMBING-CORRECT-AGAINST-REAL-CRYPTO ONLY — not a security/finality claim
//!
//! `real-mldsa65` is ON by default, so this test runs on a plain `cargo test`
//! (no `--features` flag). Only `--no-default-features` compiles the whole file
//! to nothing (`#![cfg(...)]` below), falling back to the accept-nothing stub
//! verifier (the offline posture, where quorum is never reached).
//!
//! What a green run here proves, and ALL it proves: the
//! [`PosternNotaryCheckpoint::verify_quorum`] counting plumbing is correct
//! against **real** ML-DSA-65 signatures — 14 distinct genuine operator
//! signatures over the canonical payload reach `QuorumReached`, and 13 do not.
//! It is emphatically **NOT** a security, finality, or settlement claim:
//!
//! - The RustCrypto `ml-dsa` crate is **UNAUDITED, pre-1.0 (0.1.1)**.
//! - The committee is **one trust domain** — 14-of-21 facets of a single
//!   actor (Postern), **NOT** BFT, **NOT** decentralized, **NOT** trustless.
//!   There is no honest minority to dissent.
//! - There is **no signature aggregation / no DKG** — each seat verifies on an
//!   individual signature (design decision this phase).
//! - The Bloch-SIS-PoW base any such checkpoint would anchor to is still
//!   `k=4`, **trivially forgeable**, and `51%`-attackable today.
//!
//! `QuorumReached` is a Postern attestation about a forgeable base, never
//! settlement finality. Seed-derived keys below are **test-only**; real
//! operator seeds must come from a CSPRNG in real custody (blocked-on-infra).

#![cfg(feature = "real-mldsa65")]

use postern_ffg::checkpoint::{
    BaseAnchorRef, ConfidenceLevel, HeightRange, OperatorSignature, PosternNotaryCheckpoint,
    QuorumOutcome,
};
use postern_ffg::operator::{
    Era, Operator, OperatorIdentity, PermissionedOperatorSet, COMMITTEE_SIZE, QUORUM_THRESHOLD,
};
use postern_ffg::signature::{
    CheckpointSigner, MlDsa65Signature, RustCryptoMlDsa65Signer, RustCryptoMlDsa65Verifier,
};

/// One permissioned seat: a real seed-derived ML-DSA-65 signer plus the
/// matching operator record. Test-only key handling (fixed seed) — never a
/// pattern for real custody.
struct Seat {
    operator: Operator,
    signer: RustCryptoMlDsa65Signer,
}

/// Build seat number `i` (1-based). The UID is `[i, 0, 0, ...]` and the key is
/// derived from the `[i; 32]` seed, so every seat is distinct.
fn seat(i: u8) -> Seat {
    assert!(i >= 1, "seat index must be >= 1 (all-zero UID is rejected at admission)");
    let signer = RustCryptoMlDsa65Signer::from_seed([i; 32]);
    let mut uid = [0u8; 32];
    uid[0] = i;
    let operator = Operator {
        identity: OperatorIdentity {
            uid,
            jurisdiction: *b"US",
            client_version: "scaffold-integration".to_string(),
            registered_at_block: 1,
        },
        public_key: signer.public_key(),
    };
    Seat { operator, signer }
}

/// The design's committee: exactly [`COMMITTEE_SIZE`] (21) real seats.
fn committee() -> Vec<Seat> {
    (1..=COMMITTEE_SIZE as u8).map(seat).collect()
}

/// One fixed checkpoint that every signer in a run signs the canonical payload
/// of. Signatures start empty; each test fills them in.
fn base_checkpoint() -> PosternNotaryCheckpoint {
    PosternNotaryCheckpoint {
        height_range: HeightRange::new(1_000, 1_023).unwrap(),
        base_anchor: BaseAnchorRef {
            block_height: 1_023,
            block_hash: [0xABu8; 32],
            accumulated_work: 123_456,
        },
        era: Era::genesis(),
        confidence: ConfidenceLevel::HardNotarized,
        signatures: Vec::new(),
    }
}

/// Real ML-DSA-65 signature by `seat` over `payload`, wrapped as an
/// [`OperatorSignature`] tagged with that seat's UID.
fn sign_seat(seat: &Seat, payload: &[u8]) -> OperatorSignature {
    let sig: MlDsa65Signature = seat.signer.sign(payload).expect("real deterministic sign succeeds");
    OperatorSignature {
        operator_uid: seat.operator.identity.uid,
        signature: sig,
    }
}

/// Sanity: the design constants are what this test asserts against.
#[test]
fn design_constants_are_14_of_21() {
    assert_eq!(COMMITTEE_SIZE, 21);
    assert_eq!(QUORUM_THRESHOLD, 14);
}

/// 14 distinct real ML-DSA-65 signatures over ONE checkpoint reach quorum.
#[test]
fn fourteen_real_signatures_reach_quorum() {
    let committee = committee();
    let set = PermissionedOperatorSet::with_default_parameters(
        committee.iter().map(|s| s.operator.clone()).collect(),
    )
    .expect("21 valid distinct operators form the default 14-of-21 set");
    assert_eq!(set.size(), 21);
    assert_eq!(set.threshold(), 14);

    let mut checkpoint = base_checkpoint();
    let payload = checkpoint.canonical_signing_payload();

    // The first 14 distinct seats each produce a genuine signature over the
    // one canonical payload.
    checkpoint.signatures = committee
        .iter()
        .take(QUORUM_THRESHOLD)
        .map(|s| sign_seat(s, &payload))
        .collect();
    assert_eq!(checkpoint.signatures.len(), 14);

    let outcome = checkpoint.verify_quorum(&set, &RustCryptoMlDsa65Verifier);
    assert_eq!(
        outcome,
        QuorumOutcome::QuorumReached { valid: 14, threshold: 14 },
        "14 distinct real ML-DSA-65 signatures must clear the 14-of-21 threshold"
    );
}

/// 13 distinct real ML-DSA-65 signatures over the same checkpoint fall one
/// short of the 14-of-21 threshold.
#[test]
fn thirteen_real_signatures_below_threshold() {
    let committee = committee();
    let set = PermissionedOperatorSet::with_default_parameters(
        committee.iter().map(|s| s.operator.clone()).collect(),
    )
    .expect("21 valid distinct operators form the default 14-of-21 set");

    let mut checkpoint = base_checkpoint();
    let payload = checkpoint.canonical_signing_payload();

    checkpoint.signatures = committee
        .iter()
        .take(QUORUM_THRESHOLD - 1)
        .map(|s| sign_seat(s, &payload))
        .collect();
    assert_eq!(checkpoint.signatures.len(), 13);

    let outcome = checkpoint.verify_quorum(&set, &RustCryptoMlDsa65Verifier);
    assert_eq!(
        outcome,
        QuorumOutcome::BelowThreshold { valid: 13, threshold: 14 },
        "13 distinct real ML-DSA-65 signatures must fall one short of 14-of-21"
    );
}

/// The exact quorum boundary in one run over a single checkpoint: 13 real
/// signatures are below threshold, and adding the 14th distinct real signature
/// flips the same checkpoint to `QuorumReached`.
#[test]
fn quorum_boundary_flips_at_the_fourteenth_signature() {
    let committee = committee();
    let set = PermissionedOperatorSet::with_default_parameters(
        committee.iter().map(|s| s.operator.clone()).collect(),
    )
    .expect("21 valid distinct operators form the default 14-of-21 set");

    let mut checkpoint = base_checkpoint();
    let payload = checkpoint.canonical_signing_payload();

    // 13 genuine signatures -> below threshold.
    checkpoint.signatures = committee
        .iter()
        .take(13)
        .map(|s| sign_seat(s, &payload))
        .collect();
    assert_eq!(
        checkpoint.verify_quorum(&set, &RustCryptoMlDsa65Verifier),
        QuorumOutcome::BelowThreshold { valid: 13, threshold: 14 }
    );

    // Add the 14th distinct genuine signature -> the same checkpoint now
    // reaches quorum.
    checkpoint.signatures.push(sign_seat(&committee[13], &payload));
    assert_eq!(checkpoint.signatures.len(), 14);
    assert_eq!(
        checkpoint.verify_quorum(&set, &RustCryptoMlDsa65Verifier),
        QuorumOutcome::QuorumReached { valid: 14, threshold: 14 }
    );
}

/// Duplicate UIDs are counted once: 14 signature entries that collapse to only
/// 13 DISTINCT operators do NOT reach the 14-of-21 quorum, even though every
/// signature is a genuine real ML-DSA-65 signature. Guards the "one seat, one
/// counted vote" rail against a padded-count false quorum.
#[test]
fn duplicate_operator_does_not_inflate_quorum() {
    let committee = committee();
    let set = PermissionedOperatorSet::with_default_parameters(
        committee.iter().map(|s| s.operator.clone()).collect(),
    )
    .expect("21 valid distinct operators form the default 14-of-21 set");

    let mut checkpoint = base_checkpoint();
    let payload = checkpoint.canonical_signing_payload();

    // 13 distinct genuine signatures ...
    let mut sigs: Vec<OperatorSignature> = committee
        .iter()
        .take(13)
        .map(|s| sign_seat(s, &payload))
        .collect();
    // ... plus a genuine SECOND signature from seat 0 (a duplicate UID). This
    // is 14 signature entries but only 13 distinct operators.
    sigs.push(sign_seat(&committee[0], &payload));
    assert_eq!(sigs.len(), 14);
    checkpoint.signatures = sigs;

    let outcome = checkpoint.verify_quorum(&set, &RustCryptoMlDsa65Verifier);
    assert_eq!(
        outcome,
        QuorumOutcome::BelowThreshold { valid: 13, threshold: 14 },
        "duplicate UIDs must be counted once — 14 entries / 13 distinct = below quorum"
    );
}
