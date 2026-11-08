// SPDX-License-Identifier: MIT OR Apache-2.0
//! The independent-reader ("follower") check: anyone holding an anchored
//! receipt, the certificate bytes, and the operator set can re-verify a
//! notarization from scratch. **There is no privileged reader.**
//!
//! # SCAFFOLD — not a secure or deployed system
//!
//! This module is the crate's "anyone can re-check" seam:
//!
//! 1. Recompute the certificate hash from the certificate bytes and compare
//!    it to the commitment in the base receipt.
//! 2. Re-run the quorum check against the published operator set with a
//!    verifier of the *reader's own choosing*.
//!
//! Honesty rails, unchanged:
//!
//! - A successful re-verification proves only that **these bytes were
//!   committed to on the base and carry a quorum of Postern-operated
//!   signatures**. It is a re-checked *Postern attestation* — it does not
//!   make the notarization decentralized, trustless, or final, and it says
//!   nothing about whether the base has since reorged beneath it (readers
//!   should also compare `checkpoint.base_anchor` against their own view of
//!   the base — the same check [`crate::notary::NotaryService`] performs).
//! - Under **`--no-default-features`** the only available verifier is the stub,
//!   which refuses to assert validity — so an offline-stub follower can never
//!   "confirm" anything either. (A default build re-verifies with real
//!   ML-DSA-65, still an UNAUDITED pre-1.0 primitive — not a security claim.)
//! - The receipt itself comes from whatever base client the reader trusts;
//!   with the in-memory mock it proves nothing about any real chain
//!   (talking to a real Bloch node RPC is blocked-on-infra).

use crate::anchor::AnchorCommitment;
use crate::anchor::AnchorReceipt;
use crate::certificate::CheckpointCertificate;
use crate::checkpoint::QuorumOutcome;
use crate::operator::PermissionedOperatorSet;
use crate::signature::MlDsa65Verifier;

/// Why an independent re-verification rejected an anchored certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FollowerError {
    /// The recomputed certificate hash does not equal the anchored
    /// commitment: the certificate bytes are not what was committed to.
    CommitmentMismatch {
        /// The commitment carried by the base receipt.
        anchored: AnchorCommitment,
        /// SHAKE-256-32 recomputed over the presented certificate bytes.
        recomputed: AnchorCommitment,
    },
    /// The certificate's signatures do not reproduce a quorum against the
    /// operator set (tampered/missing signatures, or a stub verifier that
    /// refuses to assert validity — the default-build case).
    QuorumNotReproduced {
        /// How many signatures verified.
        valid: usize,
        /// The threshold that was not met.
        threshold: usize,
    },
}

impl core::fmt::Display for FollowerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FollowerError::CommitmentMismatch { .. } => {
                write!(f, "certificate bytes do not hash to the anchored commitment")
            }
            FollowerError::QuorumNotReproduced { valid, threshold } => {
                write!(f, "quorum not reproduced: {valid} valid of {threshold} required")
            }
        }
    }
}

impl std::error::Error for FollowerError {}

/// Independently re-verify one anchored certificate: recompute
/// `certificate_hash()` against the receipt's commitment, then re-run
/// [`verify_quorum`](crate::checkpoint::PosternNotaryCheckpoint::verify_quorum)
/// against `operator_set` with the caller's own `verifier`.
///
/// Anyone can call this with public data — no privileged reader exists. A
/// success is a re-checked **Postern attestation, never settlement finality**
/// (see the module docs for everything a success does *not* mean).
pub fn reverify_anchored_certificate<V: MlDsa65Verifier>(
    receipt: &AnchorReceipt,
    certificate: &CheckpointCertificate,
    operator_set: &PermissionedOperatorSet,
    verifier: &V,
) -> Result<QuorumOutcome, FollowerError> {
    let recomputed = certificate.certificate_hash();
    if recomputed != receipt.commitment {
        return Err(FollowerError::CommitmentMismatch {
            anchored: receipt.commitment,
            recomputed,
        });
    }
    match certificate.checkpoint.verify_quorum(operator_set, verifier) {
        outcome @ QuorumOutcome::QuorumReached { .. } => Ok(outcome),
        QuorumOutcome::BelowThreshold { valid, threshold } => {
            Err(FollowerError::QuorumNotReproduced { valid, threshold })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::{
        BaseAnchorRef, ConfidenceLevel, HeightRange, OperatorSignature, PosternNotaryCheckpoint,
    };
    use crate::operator::{Era, Operator, OperatorIdentity};
    use crate::signature::{
        MlDsa65PublicKey, MlDsa65Signature, NonVerifyingStubVerifier, ML_DSA_65_PUBLIC_KEY_LEN,
        ML_DSA_65_SIGNATURE_LEN,
    };

    fn operator(seed: u8) -> Operator {
        let mut uid = [0u8; 32];
        uid[0] = seed;
        Operator {
            identity: OperatorIdentity {
                uid,
                jurisdiction: *b"US",
                client_version: "scaffold-0".into(),
                registered_at_block: 1,
            },
            public_key: MlDsa65PublicKey::from_bytes(vec![seed; ML_DSA_65_PUBLIC_KEY_LEN]).unwrap(),
        }
    }

    fn stub_certificate() -> CheckpointCertificate {
        let mut uid = [0u8; 32];
        uid[0] = 1;
        CheckpointCertificate::new(PosternNotaryCheckpoint {
            height_range: HeightRange::new(100, 105).unwrap(),
            base_anchor: BaseAnchorRef {
                block_height: 105,
                block_hash: [1u8; 32],
                accumulated_work: 42,
            },
            era: Era::genesis(),
            confidence: ConfidenceLevel::SoftJustified,
            signatures: vec![OperatorSignature {
                operator_uid: uid,
                signature: MlDsa65Signature::from_bytes(vec![1u8; ML_DSA_65_SIGNATURE_LEN]).unwrap(),
            }],
        })
    }

    fn receipt_for(commitment: AnchorCommitment) -> AnchorReceipt {
        AnchorReceipt { base_txid: [0u8; 32], anchored_at_height: 105, commitment }
    }

    #[test]
    fn commitment_mismatch_is_rejected_before_any_quorum_check() {
        let cert = stub_certificate();
        let set = PermissionedOperatorSet::new((1..=3).map(operator).collect(), 2).unwrap();
        let wrong = receipt_for(AnchorCommitment([0xFF; 32]));
        assert!(matches!(
            reverify_anchored_certificate(&wrong, &cert, &set, &NonVerifyingStubVerifier),
            Err(FollowerError::CommitmentMismatch { .. })
        ));
    }

    /// The offline-stub (`--no-default-features`) face of the invariant: even
    /// with a hash-matching receipt, a stub-verifier follower can never confirm
    /// a quorum — it refuses to assert validity, by design. (A default build
    /// re-verifies with real ML-DSA-65.)
    #[test]
    fn offline_stub_follower_never_confirms_a_quorum() {
        let cert = stub_certificate();
        let set = PermissionedOperatorSet::new((1..=3).map(operator).collect(), 2).unwrap();
        let receipt = receipt_for(cert.certificate_hash());
        assert_eq!(
            reverify_anchored_certificate(&receipt, &cert, &set, &NonVerifyingStubVerifier),
            Err(FollowerError::QuorumNotReproduced { valid: 0, threshold: 2 })
        );
    }
}
