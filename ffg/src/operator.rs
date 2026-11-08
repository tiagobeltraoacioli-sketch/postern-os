// SPDX-License-Identifier: MIT OR Apache-2.0
//! The **permissioned, Postern-operated** operator set and its era rotation.
//!
//! # SCAFFOLD — not a secure or deployed system
//!
//! # Trust model: this is NOT BFT, NOT decentralized, NOT trustless
//!
//! Every operator in a [`PermissionedOperatorSet`] is run by **one
//! organization (Postern)**. The `21`-seat / `14-of-21` threshold, the era
//! rotation, and any internal `m-of-n` custody are **operational-robustness /
//! crash-fault** measures **within a single trust domain** — they do **not**
//! deliver Byzantine fault tolerance across mutually-distrusting parties
//! (design `§2`, safety review `§0`). There is exactly one actor whose failure
//! or coercion breaks everything. The honest label is **"permissioned,
//! Postern-operated notary."** Never "BFT," "decentralized," or "trustless."
//!
//! Slashing/bonding are intentionally absent: against a self-operated set they
//! are self-referential and provide **no economic security** this phase
//! (design `§3.6`). The rotation-trigger enum below records *operational*
//! eviction reasons only, not an economic deterrent.

use crate::signature::MlDsa65PublicKey;

/// Retained operational-robustness committee size (design `§3.1`, ADR-001/002).
/// This is NOT a decentralization or Byzantine-tolerance parameter.
pub const COMMITTEE_SIZE: usize = 21;

/// Retained quorum threshold `14-of-21` (design `§3.1`). Operational only —
/// all seats trace to Postern, so a quorum is never adversarial-independent.
pub const QUORUM_THRESHOLD: usize = 14;

/// Epochs per era (`~24 h` rotation design point, ADR-005 / design `§3.3`).
pub const EPOCHS_PER_ERA: u64 = 24;

/// The sentinel jurisdiction that is rejected at admission (design `§3.7`).
pub const UNSPECIFIED_JURISDICTION: [u8; 2] = [b'?', b'?'];

/// Canonical operator identity (design `§3.7`, ADR-035).
///
/// While all operators are Postern (one trust domain) the self-declared `uid`
/// is TOFU-Sybil-able but irrelevant; these fields matter operationally and
/// become anti-fragmentation invariants only if independent third-party
/// operators are ever admitted (a future, not-yet phase).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperatorIdentity {
    /// 32-byte unique id. All-zero is rejected at admission.
    pub uid: [u8; 32],
    /// ISO-3166-1 alpha-2 jurisdiction. `UNSPECIFIED` (`??`) is rejected.
    pub jurisdiction: [u8; 2],
    /// Self-reported client version string.
    pub client_version: String,
    /// Base-chain height at which this operator was registered (metadata only).
    pub registered_at_block: u64,
}

impl OperatorIdentity {
    /// Admission check (design `§3.7`): reject zero-uid and `UNSPECIFIED`
    /// jurisdiction. SCAFFOLD: this is a metadata gate only, not a Sybil or
    /// identity-proof mechanism.
    pub fn validate_for_admission(&self) -> Result<(), OperatorSetError> {
        if self.uid == [0u8; 32] {
            return Err(OperatorSetError::ZeroUid);
        }
        if self.jurisdiction == UNSPECIFIED_JURISDICTION {
            return Err(OperatorSetError::UnspecifiedJurisdiction);
        }
        Ok(())
    }
}

/// A single permissioned, Postern-operated signer seat.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Operator {
    /// Operator identity metadata.
    pub identity: OperatorIdentity,
    /// The operator's ML-DSA-65 finality public key (design `§3.2`).
    pub public_key: MlDsa65PublicKey,
}

/// The permissioned, Postern-operated operator set for a given era.
///
/// SCAFFOLD: membership is a curated list Postern controls — an operational
/// seat-assignment across Postern's own nodes, **not** an open election
/// (design `§3.3`). It is centralized by design.
#[derive(Clone, Debug)]
pub struct PermissionedOperatorSet {
    operators: Vec<Operator>,
    threshold: usize,
}

impl PermissionedOperatorSet {
    /// Build a set with an explicit quorum threshold, validating every
    /// operator for admission and rejecting duplicate UIDs / duplicate keys.
    ///
    /// SCAFFOLD: no proof of independent control is (or can be) enforced — all
    /// seats are one trust domain.
    pub fn new(operators: Vec<Operator>, threshold: usize) -> Result<Self, OperatorSetError> {
        if operators.is_empty() {
            return Err(OperatorSetError::EmptySet);
        }
        if threshold == 0 || threshold > operators.len() {
            return Err(OperatorSetError::InvalidThreshold {
                threshold,
                size: operators.len(),
            });
        }
        for (i, op) in operators.iter().enumerate() {
            op.identity.validate_for_admission()?;
            for other in operators.iter().skip(i + 1) {
                if op.identity.uid == other.identity.uid {
                    return Err(OperatorSetError::DuplicateUid);
                }
                // Anti-fragmentation: a pubkey belongs to at most one identity.
                if op.public_key == other.public_key {
                    return Err(OperatorSetError::DuplicatePublicKey);
                }
            }
        }
        Ok(Self { operators, threshold })
    }

    /// Convenience constructor using the design's `14-of-21` operational
    /// parameters ([`QUORUM_THRESHOLD`]). Requires exactly [`COMMITTEE_SIZE`]
    /// operators.
    pub fn with_default_parameters(operators: Vec<Operator>) -> Result<Self, OperatorSetError> {
        if operators.len() != COMMITTEE_SIZE {
            return Err(OperatorSetError::InvalidThreshold {
                threshold: QUORUM_THRESHOLD,
                size: operators.len(),
            });
        }
        Self::new(operators, QUORUM_THRESHOLD)
    }

    /// The operators in the set.
    pub fn operators(&self) -> &[Operator] {
        &self.operators
    }

    /// The quorum threshold (operational parameter, not a security guarantee).
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Number of seats.
    pub fn size(&self) -> usize {
        self.operators.len()
    }

    /// Look up an operator by UID.
    pub fn operator_by_uid(&self, uid: &[u8; 32]) -> Option<&Operator> {
        self.operators.iter().find(|o| &o.identity.uid == uid)
    }
}

/// Why an operator seat rotates or is evicted (design `§3.3`).
///
/// These are **operational** eviction reasons within one trust domain, NOT an
/// economic-security deterrent (there is none this phase — design `§3.6`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RotationTrigger {
    /// The operator equivocated (signed conflicting checkpoints).
    Equivocation,
    /// The operator was inactive above the design's `>40%` threshold.
    Inactivity,
    /// The operator voluntarily exited its seat.
    VoluntaryExit,
    /// Ordinary end-of-era scheduled rotation.
    ScheduledEndOfEra,
}

/// An era: a rotation window over the operator set (design `§3.3`, ADR-005).
///
/// SCAFFOLD: era math is deliberately **integer-only** (no floats in
/// consensus-critical paths, design `§3.3`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Era {
    /// Monotonic era number.
    pub number: u64,
    /// First epoch index covered by this era (inclusive).
    pub first_epoch: u64,
    /// Number of epochs per era (defaults to [`EPOCHS_PER_ERA`]).
    pub epochs_per_era: u64,
}

impl Era {
    /// Construct the genesis era (era `0`) starting at epoch `0`.
    pub fn genesis() -> Self {
        Self {
            number: 0,
            first_epoch: 0,
            epochs_per_era: EPOCHS_PER_ERA,
        }
    }

    /// Last epoch index covered by this era (inclusive). Integer-only.
    pub fn last_epoch(&self) -> u64 {
        // saturating to avoid overflow panics in the scaffold
        self.first_epoch
            .saturating_add(self.epochs_per_era.saturating_sub(1))
    }

    /// Whether an epoch index falls inside this era.
    pub fn contains_epoch(&self, epoch: u64) -> bool {
        epoch >= self.first_epoch && epoch <= self.last_epoch()
    }

    /// The next era immediately following this one.
    pub fn next(&self) -> Era {
        Era {
            number: self.number.saturating_add(1),
            first_epoch: self.last_epoch().saturating_add(1),
            epochs_per_era: self.epochs_per_era,
        }
    }
}

/// A recorded rotation event (audit trail for operational accountability).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotationEvent {
    /// Era in which the rotation took effect.
    pub era: u64,
    /// UID of the affected operator seat.
    pub operator_uid: [u8; 32],
    /// Why the seat rotated.
    pub trigger: RotationTrigger,
}

/// Errors from operator-set construction / admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperatorSetError {
    /// Operator set was empty.
    EmptySet,
    /// Threshold was zero or exceeded the set size.
    InvalidThreshold { threshold: usize, size: usize },
    /// An operator declared an all-zero UID.
    ZeroUid,
    /// An operator declared the `UNSPECIFIED` jurisdiction.
    UnspecifiedJurisdiction,
    /// Two operators shared a UID.
    DuplicateUid,
    /// Two operators shared an ML-DSA-65 public key.
    DuplicatePublicKey,
}

impl core::fmt::Display for OperatorSetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            OperatorSetError::EmptySet => write!(f, "operator set is empty"),
            OperatorSetError::InvalidThreshold { threshold, size } => {
                write!(f, "invalid threshold {threshold} for set of size {size}")
            }
            OperatorSetError::ZeroUid => write!(f, "operator uid is all-zero (rejected at admission)"),
            OperatorSetError::UnspecifiedJurisdiction => {
                write!(f, "operator jurisdiction is UNSPECIFIED (rejected at admission)")
            }
            OperatorSetError::DuplicateUid => write!(f, "duplicate operator uid in set"),
            OperatorSetError::DuplicatePublicKey => write!(f, "duplicate operator public key in set"),
        }
    }
}

impl std::error::Error for OperatorSetError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::{MlDsa65PublicKey, ML_DSA_65_PUBLIC_KEY_LEN};

    fn key(seed: u8) -> MlDsa65PublicKey {
        MlDsa65PublicKey::from_bytes(vec![seed; ML_DSA_65_PUBLIC_KEY_LEN]).unwrap()
    }

    fn operator(seed: u8) -> Operator {
        let mut uid = [0u8; 32];
        uid[0] = seed.max(1);
        Operator {
            identity: OperatorIdentity {
                uid,
                jurisdiction: *b"US",
                client_version: "scaffold-0".to_string(),
                registered_at_block: 1,
            },
            public_key: key(seed.max(1)),
        }
    }

    #[test]
    fn zero_uid_and_unspecified_jurisdiction_are_rejected() {
        let mut bad = operator(1);
        bad.identity.uid = [0u8; 32];
        assert_eq!(bad.identity.validate_for_admission(), Err(OperatorSetError::ZeroUid));

        let mut bad2 = operator(1);
        bad2.identity.jurisdiction = UNSPECIFIED_JURISDICTION;
        assert_eq!(
            bad2.identity.validate_for_admission(),
            Err(OperatorSetError::UnspecifiedJurisdiction)
        );
    }

    #[test]
    fn set_rejects_duplicate_uid() {
        let a = operator(5);
        let b = operator(5); // same seed => same uid + key
        assert!(matches!(
            PermissionedOperatorSet::new(vec![a, b], 1),
            Err(OperatorSetError::DuplicateUid) | Err(OperatorSetError::DuplicatePublicKey)
        ));
    }

    #[test]
    fn era_math_is_integer_and_contiguous() {
        let g = Era::genesis();
        assert_eq!(g.first_epoch, 0);
        assert_eq!(g.last_epoch(), EPOCHS_PER_ERA - 1);
        let n = g.next();
        assert_eq!(n.first_epoch, EPOCHS_PER_ERA);
        assert!(n.contains_epoch(EPOCHS_PER_ERA));
        assert!(!g.contains_epoch(EPOCHS_PER_ERA));
    }

    #[test]
    fn valid_set_builds() {
        let ops: Vec<Operator> = (1..=3).map(operator).collect();
        let set = PermissionedOperatorSet::new(ops, 2).unwrap();
        assert_eq!(set.size(), 3);
        assert_eq!(set.threshold(), 2);
    }
}
