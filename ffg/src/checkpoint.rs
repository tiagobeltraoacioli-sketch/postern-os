// SPDX-License-Identifier: MIT OR Apache-2.0
//! The Postern notary checkpoint: a height range over the base, the base-anchor
//! reference it notarizes, the set of individual ML-DSA-65 operator signatures,
//! and a confidence level.
//!
//! # SCAFFOLD — not a secure or deployed system
//!
//! A [`PosternNotaryCheckpoint`] is an **advisory notarization** that a quorum
//! of Postern-operated signers *observed* a base checkpoint as canonical. It is
//! **not** a base-consensus object and grants **no** real settlement guarantee
//! (design `§1.3`, `§3.5`):
//!
//! > **Finality is only as strong as the base beneath it.** The Bloch-SIS-PoW
//! > base is a mainnet-beta — `k=4` trivially-forgeable and `51%`-attackable —
//! > so a "finalized" checkpoint can be reorged/forged beneath it. Irreversibility
//! > here is a **Postern promise**, not a protocol property, revocable by Postern
//! > or by anyone who forges the base. Do not settle anything of value on it.

use crate::operator::{Era, PermissionedOperatorSet};
use crate::signature::{MlDsa65Signature, MlDsa65Verifier, SignatureError};

/// A reference to a point on the ownerless Bloch-SIS-PoW base that a checkpoint
/// notarizes (design `§1.2`). This is the only real weight a checkpoint has —
/// and today that weight is near-zero because the base is forgeable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaseAnchorRef {
    /// Base block height of the checkpoint.
    pub block_height: u64,
    /// Base block hash at that height (SHAKE-256 hashcash header hash).
    pub block_hash: [u8; 32],
    /// Accumulated PoW work up to the checkpoint. This is *hashcash cumulative
    /// work, not lattice hardness* (design `§0.2`) — and on a `k=4` base it is
    /// trivially forgeable.
    pub accumulated_work: u128,
}

/// An inclusive base height range `[start, end]` that a checkpoint covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeightRange {
    /// First base height (inclusive).
    pub start: u64,
    /// Last base height (inclusive).
    pub end: u64,
}

impl HeightRange {
    /// Construct a range, requiring `start <= end`.
    pub fn new(start: u64, end: u64) -> Result<Self, CheckpointError> {
        if start > end {
            return Err(CheckpointError::InvalidHeightRange { start, end });
        }
        Ok(Self { start, end })
    }
}

/// Confidence level a checkpoint asserts **about a base checkpoint** — NOT a
/// settlement-finality guarantee (design `§3.4`).
///
/// The design forbids shipping "HardFinalized" / the RPC `finalized` alias for
/// external RWA use until the base is hardened (design `§3.4`, safety review
/// `H1.2`). Variants are named as *Postern attestations*, and every one carries
/// the "base is forgeable; this is a Postern attestation" caveat.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfidenceLevel {
    /// The base checkpoint was seen but not yet quorum-attested.
    Observed,
    /// **Soft (justified):** one epoch attested by a `14-of-21` quorum
    /// (`~15 min`). A Postern attestation, not settlement finality.
    SoftJustified,
    /// **Hard (notarized):** two consecutive justified epochs, Casper-style
    /// (`~30 min`). Still a Postern attestation about a forgeable base — NOT
    /// irreversible, NOT "HardFinalized" for external RWA use.
    HardNotarized,
}

impl ConfidenceLevel {
    /// A short honest caveat suitable to attach wherever this level is shown.
    pub fn honest_caveat(&self) -> &'static str {
        "No finality guarantee; the base is forgeable (k=4 / 51%-attackable, \
         unaudited); this is a Postern attestation, not settlement finality."
    }
}

/// One operator's individual ML-DSA-65 signature over the checkpoint payload.
///
/// No aggregation (design `§3.2`): a full cert carries `14-21` of these,
/// `~46-69 KB` total — the price of post-quantum finality without aggregation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperatorSignature {
    /// UID of the signing operator (must be a member of the operator set).
    pub operator_uid: [u8; 32],
    /// The individual ML-DSA-65 signature over the canonical payload.
    pub signature: MlDsa65Signature,
}

/// A permissioned, Postern-operated notary checkpoint (design `§3.5`).
///
/// SCAFFOLD: an advisory notarization object. It asserts only that a quorum of
/// **Postern-operated** signers attests that a base checkpoint, backed by some
/// accumulated PoW work, was seen as canonical in some era. It does not assert
/// the base cannot reorg, nor that Postern cannot be coerced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PosternNotaryCheckpoint {
    /// Base height range this checkpoint covers.
    pub height_range: HeightRange,
    /// The base-anchor reference being notarized.
    pub base_anchor: BaseAnchorRef,
    /// Era in which the checkpoint was produced.
    pub era: Era,
    /// Confidence level asserted about the base checkpoint.
    pub confidence: ConfidenceLevel,
    /// The set of individual ML-DSA-65 operator signatures.
    pub signatures: Vec<OperatorSignature>,
}

impl PosternNotaryCheckpoint {
    /// Deterministically encode the canonical payload that operators sign.
    ///
    /// SCAFFOLD: a simple length-prefixed, big-endian concatenation. It is
    /// **not** a domain-separated, versioned, audited wire format — a real
    /// deployment needs one. Signatures themselves are excluded (they sign this).
    pub fn canonical_signing_payload(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"POSTERN-FFG-NOTARY-CHECKPOINT-v0-SCAFFOLD");
        out.extend_from_slice(&self.height_range.start.to_be_bytes());
        out.extend_from_slice(&self.height_range.end.to_be_bytes());
        out.extend_from_slice(&self.base_anchor.block_height.to_be_bytes());
        out.extend_from_slice(&self.base_anchor.block_hash);
        out.extend_from_slice(&self.base_anchor.accumulated_work.to_be_bytes());
        out.extend_from_slice(&self.era.number.to_be_bytes());
        out.extend_from_slice(&self.era.first_epoch.to_be_bytes());
        out.extend_from_slice(&(self.confidence as u8).to_be_bytes());
        out
    }

    /// Count how many signatures verify against members of `set` using the
    /// supplied ML-DSA-65 verifier, then compare to the set threshold.
    ///
    /// # SCAFFOLD — not a secure or deployed system
    ///
    /// With the shipped [`NonVerifyingStubVerifier`](crate::signature::NonVerifyingStubVerifier)
    /// **every signature "fails"**, so this returns
    /// [`QuorumOutcome::BelowThreshold`] with `valid == 0`. That is by design:
    /// the scaffold refuses to assert validity without a real, audited verifier.
    /// Even with a real verifier a positive outcome is a *Postern attestation*,
    /// never settlement finality (see the module docs and `confidence`).
    pub fn verify_quorum<V: MlDsa65Verifier>(
        &self,
        set: &PermissionedOperatorSet,
        verifier: &V,
    ) -> QuorumOutcome {
        let payload = self.canonical_signing_payload();
        let mut valid = 0usize;
        let mut seen_uids: Vec<[u8; 32]> = Vec::new();

        for opsig in &self.signatures {
            // Ignore duplicate UIDs — one seat, one counted vote.
            if seen_uids.contains(&opsig.operator_uid) {
                continue;
            }
            if let Some(op) = set.operator_by_uid(&opsig.operator_uid) {
                if verifier
                    .verify(&op.public_key, &payload, &opsig.signature)
                    .is_ok()
                {
                    valid += 1;
                    seen_uids.push(opsig.operator_uid);
                }
            }
        }

        if valid >= set.threshold() {
            QuorumOutcome::QuorumReached {
                valid,
                threshold: set.threshold(),
            }
        } else {
            QuorumOutcome::BelowThreshold {
                valid,
                threshold: set.threshold(),
            }
        }
    }
}

/// Result of a quorum check.
///
/// A `QuorumReached` outcome is a **Postern attestation about a forgeable
/// base**, never a settlement-finality guarantee.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuorumOutcome {
    /// At least `threshold` distinct operator signatures verified.
    QuorumReached { valid: usize, threshold: usize },
    /// Fewer than `threshold` verified (the scaffold-stub case is always here).
    BelowThreshold { valid: usize, threshold: usize },
}

/// Errors from checkpoint construction / validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointError {
    /// `start > end` in a height range.
    InvalidHeightRange { start: u64, end: u64 },
    /// A signature-layer error surfaced during checkpoint handling.
    Signature(SignatureError),
}

impl From<SignatureError> for CheckpointError {
    fn from(e: SignatureError) -> Self {
        CheckpointError::Signature(e)
    }
}

impl core::fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CheckpointError::InvalidHeightRange { start, end } => {
                write!(f, "invalid height range: start {start} > end {end}")
            }
            CheckpointError::Signature(e) => write!(f, "signature error: {e}"),
        }
    }
}

impl std::error::Error for CheckpointError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operator::{Era, Operator, OperatorIdentity, PermissionedOperatorSet};
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

    fn checkpoint(uids: &[u8]) -> PosternNotaryCheckpoint {
        PosternNotaryCheckpoint {
            height_range: HeightRange::new(100, 105).unwrap(),
            base_anchor: BaseAnchorRef {
                block_height: 105,
                block_hash: [1u8; 32],
                accumulated_work: 42,
            },
            era: Era::genesis(),
            confidence: ConfidenceLevel::HardNotarized,
            signatures: uids
                .iter()
                .map(|&s| {
                    let mut uid = [0u8; 32];
                    uid[0] = s;
                    OperatorSignature {
                        operator_uid: uid,
                        signature: MlDsa65Signature::from_bytes(vec![s; ML_DSA_65_SIGNATURE_LEN])
                            .unwrap(),
                    }
                })
                .collect(),
        }
    }

    #[test]
    fn height_range_rejects_inverted() {
        assert!(matches!(
            HeightRange::new(10, 5),
            Err(CheckpointError::InvalidHeightRange { .. })
        ));
    }

    #[test]
    fn payload_is_deterministic() {
        let c = checkpoint(&[1, 2, 3]);
        assert_eq!(c.canonical_signing_payload(), c.canonical_signing_payload());
    }

    #[test]
    fn stub_verifier_never_reaches_quorum() {
        let set = PermissionedOperatorSet::new((1..=3).map(operator).collect(), 2).unwrap();
        let c = checkpoint(&[1, 2, 3]);
        let outcome = c.verify_quorum(&set, &NonVerifyingStubVerifier);
        // The stub asserts nothing -> zero valid -> below threshold, by design.
        assert_eq!(outcome, QuorumOutcome::BelowThreshold { valid: 0, threshold: 2 });
    }
}

/// Host tests proving [`PosternNotaryCheckpoint::verify_quorum`]'s counting
/// semantics against **real** ML-DSA-65 (FIPS 204) signatures. These run on a
/// default `cargo test` (`real-mldsa65` is ON by default); only
/// `--no-default-features` compiles them out. A `QuorumReached` here is still
/// only proof the quorum-counting *plumbing* is correct against real crypto —
/// see the crate/module docs: it is not, and never becomes, a
/// settlement-finality guarantee, and the committee is still one trust
/// domain ("trust Postern"), not BFT.
///
/// The stub tests in the sibling `mod tests` above are untouched by this
/// module and keep asserting nothing on every `cargo test` run.
#[cfg(all(test, feature = "real-mldsa65"))]
mod real_mldsa65_tests {
    use super::*;
    use crate::operator::{Operator, OperatorIdentity};
    use crate::signature::{MlDsa65PublicKey, RustCryptoMlDsa65Verifier};
    use ml_dsa::{ExpandedSigningKey, MlDsa65, Seed};

    /// Deterministic keypair for seed byte `i` (test-only; real seeds must
    /// come from a CSPRNG).
    fn seeded_keypair(i: u8) -> ExpandedSigningKey<MlDsa65> {
        let seed: Seed = [i; 32].into();
        ExpandedSigningKey::<MlDsa65>::from_seed(&seed)
    }

    fn real_operator(i: u8) -> (Operator, ExpandedSigningKey<MlDsa65>) {
        let esk = seeded_keypair(i);
        let mut uid = [0u8; 32];
        uid[0] = i;
        let op = Operator {
            identity: OperatorIdentity {
                uid,
                jurisdiction: *b"US",
                client_version: "scaffold-0".into(),
                registered_at_block: 1,
            },
            public_key: MlDsa65PublicKey::from_bytes(esk.verifying_key().encode().to_vec()).unwrap(),
        };
        (op, esk)
    }

    fn real_checkpoint() -> PosternNotaryCheckpoint {
        PosternNotaryCheckpoint {
            height_range: HeightRange::new(100, 105).unwrap(),
            base_anchor: BaseAnchorRef {
                block_height: 105,
                block_hash: [1u8; 32],
                accumulated_work: 42,
            },
            era: Era::genesis(),
            confidence: ConfidenceLevel::HardNotarized,
            signatures: Vec::new(),
        }
    }

    fn signed_by(esk: &ExpandedSigningKey<MlDsa65>, uid: [u8; 32], payload: &[u8]) -> OperatorSignature {
        let sig = esk
            .sign_deterministic(payload, b"")
            .expect("deterministic sign succeeds");
        OperatorSignature {
            operator_uid: uid,
            signature: MlDsa65Signature::from_bytes(sig.encode().to_vec()).unwrap(),
        }
    }

    /// N=3, threshold=2 permissioned set, all three operators sign with real
    /// keys -> full quorum, all three verify.
    #[test]
    fn real_quorum_reached_when_all_sign() {
        let (op1, esk1) = real_operator(1);
        let (op2, esk2) = real_operator(2);
        let (op3, esk3) = real_operator(3);
        let set = PermissionedOperatorSet::new(vec![op1.clone(), op2.clone(), op3.clone()], 2).unwrap();

        let mut c = real_checkpoint();
        let payload = c.canonical_signing_payload();
        c.signatures = vec![
            signed_by(&esk1, op1.identity.uid, &payload),
            signed_by(&esk2, op2.identity.uid, &payload),
            signed_by(&esk3, op3.identity.uid, &payload),
        ];

        let outcome = c.verify_quorum(&set, &RustCryptoMlDsa65Verifier);
        assert_eq!(outcome, QuorumOutcome::QuorumReached { valid: 3, threshold: 2 });
    }

    /// Tampering a single byte of one signature drops it from `valid`, but
    /// the remaining two genuine signatures still clear the threshold.
    #[test]
    fn real_quorum_reached_with_one_tampered_signature() {
        let (op1, esk1) = real_operator(1);
        let (op2, esk2) = real_operator(2);
        let (op3, esk3) = real_operator(3);
        let set = PermissionedOperatorSet::new(vec![op1.clone(), op2.clone(), op3.clone()], 2).unwrap();

        let mut c = real_checkpoint();
        let payload = c.canonical_signing_payload();
        let mut tampered_sig = signed_by(&esk3, op3.identity.uid, &payload);
        let mut bytes = tampered_sig.signature.as_bytes().to_vec();
        bytes[0] ^= 0x01;
        tampered_sig.signature = MlDsa65Signature::from_bytes(bytes).unwrap();

        c.signatures = vec![
            signed_by(&esk1, op1.identity.uid, &payload),
            signed_by(&esk2, op2.identity.uid, &payload),
            tampered_sig,
        ];

        let outcome = c.verify_quorum(&set, &RustCryptoMlDsa65Verifier);
        assert_eq!(outcome, QuorumOutcome::QuorumReached { valid: 2, threshold: 2 });
    }

    /// Tampering two of the three signatures drops the checkpoint below the
    /// `threshold=2` quorum.
    #[test]
    fn real_quorum_below_threshold_with_two_tampered_signatures() {
        let (op1, esk1) = real_operator(1);
        let (op2, esk2) = real_operator(2);
        let (op3, esk3) = real_operator(3);
        let set = PermissionedOperatorSet::new(vec![op1.clone(), op2.clone(), op3.clone()], 2).unwrap();

        let mut c = real_checkpoint();
        let payload = c.canonical_signing_payload();

        let tamper = |esk: &ExpandedSigningKey<MlDsa65>, uid: [u8; 32]| -> OperatorSignature {
            let mut opsig = signed_by(esk, uid, &payload);
            let mut bytes = opsig.signature.as_bytes().to_vec();
            bytes[0] ^= 0x01;
            opsig.signature = MlDsa65Signature::from_bytes(bytes).unwrap();
            opsig
        };

        c.signatures = vec![
            tamper(&esk1, op1.identity.uid),
            tamper(&esk2, op2.identity.uid),
            signed_by(&esk3, op3.identity.uid, &payload),
        ];

        let outcome = c.verify_quorum(&set, &RustCryptoMlDsa65Verifier);
        assert_eq!(outcome, QuorumOutcome::BelowThreshold { valid: 1, threshold: 2 });
    }

    /// A genuine, real signature from a key that is NOT a member of the
    /// operator set must not be counted toward quorum, even though it is
    /// otherwise cryptographically valid over the same payload.
    #[test]
    fn real_signature_from_key_outside_set_does_not_count() {
        let (op1, esk1) = real_operator(1);
        let (op2, esk2) = real_operator(2);
        // Set only contains operators 1 and 2 with threshold 2.
        let set = PermissionedOperatorSet::new(vec![op1.clone(), op2.clone()], 2).unwrap();

        // A third, real keypair that is NOT admitted into `set`.
        let outsider_esk = seeded_keypair(9);
        let mut outsider_uid = [0u8; 32];
        outsider_uid[0] = 9;

        let mut c = real_checkpoint();
        let payload = c.canonical_signing_payload();
        c.signatures = vec![
            signed_by(&esk1, op1.identity.uid, &payload),
            signed_by(&outsider_esk, outsider_uid, &payload),
        ];

        // Only operator 1's signature counts (operator 2 never signed, and
        // the outsider isn't a set member) -> below the threshold of 2.
        let outcome = c.verify_quorum(&set, &RustCryptoMlDsa65Verifier);
        assert_eq!(outcome, QuorumOutcome::BelowThreshold { valid: 1, threshold: 2 });

        let _ = esk2; // kept for symmetry with the other tests; not signed here.
    }
}
