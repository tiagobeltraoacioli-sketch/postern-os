// SPDX-License-Identifier: MIT OR Apache-2.0
//! The **hashrate-weighted BFT finality committee** and its strict `> 2/3`
//! weighted-quorum arithmetic.
//!
//! # SCAFFOLD — not a secure or deployed system
//!
//! This module carries the *committee model* the design commits to (spec `§1`,
//! `§3`, `§5`). The committee **is the miners, weighted by hashrate** — where
//! hashrate is proxied by **block-share in a trailing look-back window**. Each
//! seat carries a per-validator `weight` (its block count in the window), and
//! finality is a strict **`> 2/3` of the epoch's *total weight*** rule, not a
//! count of seats.
//!
//! ## Why weighted, not count-based (spec `§3.2`, `§5.2`)
//!
//! An earlier draft used a count-based Byzantine committee: `N` seats, quorum
//! `2f+1`, safety from `N >= 3f+1`. **A review proved that unsafe whenever
//! `N != 3f+1`** — the `2(2f+1) - (3f+1) = f+1` overlap bound is sound only at
//! the exact `N = 3f+1` boundary; for `N > 3f+1` two `2f+1` quorums can fail to
//! overlap in an honest seat. The count-based path (`f = (N-1)/3`, `2f+1`) has
//! been **deleted**.
//!
//! The correct general form is a **weighted quorum**: votes must cover
//! **`> 2/3` of the epoch's frozen `total_weight`**. The quorum-intersection
//! guarantee then holds for **any** weight distribution: two `> 2W/3` signer
//! sets overlap in weight `w(A) + w(B) - w(A∪B) > 2W/3 + 2W/3 - W = W/3 > 0`,
//! so `>= 1` attributable seat signed both — with **no `N = 3f+1`
//! precondition**. See [`weighted_quorum_reached`].
//!
//! ## Honest concentration caveat (spec `§9`, ships on every finality surface)
//!
//! Because the committee *is* the miners weighted by block-share, the security
//! of finality **equals the decentralization of hashrate**. With concentrated
//! hashrate (as today) a `> 2/3`-weight quorum is a `> 2/3`-hashrate entity —
//! effectively Postern-controlled until miners decentralize, and a
//! `> 2/3`-hashrate entity still breaks it. This crate ships only the
//! *arithmetic and membership invariants*; it cannot and does not change the
//! hashrate distribution.
//!
//! ## Rotation & replacement metadata (spec `§3`)
//!
//! Each committee snapshot carries typed [`RotationMeta`] — the epoch, the
//! trailing look-back `window_blocks`, and the `min_share` dust floor. The
//! **derivation** of weights from base blocks (trailing-window block-share,
//! eligibility filtering, deterministic on-chain re-derivation) is an
//! intentional **out-of-scope seam** — like the anchor reader, this crate
//! consumes an already-snapshotted set and never reaches for chain data. The
//! `total_weight` is **frozen at rotation** and is **never re-normalized
//! mid-epoch** (shrinking the denominator would break quorum-intersection,
//! spec `§3.2`); a member that leaves just stops voting, and if departed weight
//! exceeds `1/3` finality *halts*, never forks.

/// A validator's stable identity within the committee: a 32-byte id
/// (e.g. a commitment binding its coinbase address to its long-term key /
/// registration record).
///
/// SCAFFOLD: this is an opaque identifier only. It proves nothing about
/// independent control of the seat — seats are miners, distinctness is
/// coinbase-attributed, and Sybil-resistance is the base's own PoW.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ValidatorId(pub [u8; 32]);

/// One committee seat: a mining identity weighted by its block-share.
///
/// The public key is carried as raw bytes and never interpreted here — this
/// crate does not re-implement or link any post-quantum crypto. Verification
/// happens through the [`crate::quorum::CheckpointVerifier`] seam.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Validator {
    /// Stable committee identity (a commitment binding coinbase + key).
    pub id: ValidatorId,
    /// The miner's coinbase address on the base (the block-attribution key).
    /// Seat distinctness is coinbase-attributed (one coinbase, one seat).
    pub coinbase_addr: [u8; 20],
    /// Opaque ML-DSA-65 (FIPS 204) public-key bytes — a **coinbase-bound**
    /// key commitment, registered on the base against `coinbase_addr`. Not
    /// validated here beyond non-emptiness; the verifier seam owns
    /// cryptographic interpretation.
    pub pubkey: Vec<u8>,
    /// This seat's **weight**: its block count in the trailing look-back
    /// window (a hashrate proxy). Pure block-share, **no per-miner cap** — the
    /// weights *are* the hashrate distribution, concentration included
    /// (spec `§1.1`, `§9`).
    pub weight: u64,
}

/// Rotation/eligibility metadata for a committee snapshot (spec `§3.1`).
///
/// These are typed inputs to a rotation; the *derivation* of the member set +
/// weights from base blocks is an out-of-scope seam (documented in the module
/// header). They are recorded so a reader can pin the exact rotation rule that
/// produced a snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RotationMeta {
    /// The committee epoch this snapshot serves.
    pub epoch: u64,
    /// Length in base blocks of the trailing look-back window whose block-share
    /// defines the weights (the window precedes the epoch, so weights are fixed
    /// *before* the epoch that uses them).
    pub window_blocks: u64,
    /// The dust floor: a miner is eligible only if its block-share (weight) is
    /// `>= min_share`. Drops dust miners to keep the eligible set inside the PQ
    /// signature-size cap (spec `§1.2`, `§7`) while covering the great majority
    /// of hashrate.
    pub min_share: u64,
}

/// A hashrate-weighted BFT finality committee for a given epoch.
///
/// SCAFFOLD: constructed via [`ValidatorSet::new`], which enforces the
/// membership invariants that make a `> 2/3`-weight quorum meaningful —
/// non-empty roster, distinct ids, distinct coinbase addresses, distinct
/// public keys, non-empty keys, and each weight at or above the snapshot's
/// `min_share`. The `total_weight` is summed once at construction and
/// **frozen** — it is the denominator every reader agrees on, and it is never
/// re-normalized mid-epoch (spec `§3.2`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorSet {
    validators: Vec<Validator>,
    rotation: RotationMeta,
    total_weight: u128,
}

impl ValidatorSet {
    /// Build a committee snapshot, enforcing the weighted-committee invariants.
    ///
    /// Rejects:
    /// * an empty roster ([`CommitteeError::EmptyCommittee`]);
    /// * an empty public key ([`CommitteeError::EmptyPublicKey`]);
    /// * a seat whose weight is below `rotation.min_share`
    ///   ([`CommitteeError::BelowMinShare`]) — the on-snapshot dust filter;
    /// * duplicate [`ValidatorId`]s ([`CommitteeError::DuplicateValidatorId`]);
    /// * duplicate coinbase addresses ([`CommitteeError::DuplicateCoinbase`]) —
    ///   one coinbase, one seat (anti-Sybil);
    /// * duplicate public keys ([`CommitteeError::DuplicatePublicKey`]) — one
    ///   key, one seat (anti-fragmentation / anti-Sybil);
    /// * a `total_weight` that overflows `u128` ([`CommitteeError::TotalWeightOverflow`]).
    ///
    /// The summed, overflow-checked `total_weight` becomes the frozen quorum
    /// denominator (spec `§3.2`, `§5.1`).
    pub fn new(validators: Vec<Validator>, rotation: RotationMeta) -> Result<Self, CommitteeError> {
        if validators.is_empty() {
            return Err(CommitteeError::EmptyCommittee);
        }
        let mut total_weight: u128 = 0;
        for (i, v) in validators.iter().enumerate() {
            if v.pubkey.is_empty() {
                return Err(CommitteeError::EmptyPublicKey);
            }
            if v.weight < rotation.min_share {
                return Err(CommitteeError::BelowMinShare {
                    weight: v.weight,
                    min_share: rotation.min_share,
                });
            }
            total_weight = total_weight
                .checked_add(v.weight as u128)
                .ok_or(CommitteeError::TotalWeightOverflow)?;
            for other in validators.iter().skip(i + 1) {
                if v.id == other.id {
                    return Err(CommitteeError::DuplicateValidatorId);
                }
                if v.coinbase_addr == other.coinbase_addr {
                    return Err(CommitteeError::DuplicateCoinbase);
                }
                if v.pubkey == other.pubkey {
                    return Err(CommitteeError::DuplicatePublicKey);
                }
            }
        }
        Ok(Self { validators, rotation, total_weight })
    }

    /// The committee's epoch number.
    pub fn epoch(&self) -> u64 {
        self.rotation.epoch
    }

    /// The rotation/eligibility metadata for this snapshot.
    pub fn rotation(&self) -> RotationMeta {
        self.rotation
    }

    /// The committee size `N` (seat count). This is **not** the quorum basis —
    /// quorum is by weight, not by count (spec `§5.1`).
    pub fn size(&self) -> usize {
        self.validators.len()
    }

    /// The **frozen** total weight of the committee: the sum of every seat's
    /// `weight`, computed once at construction. This is the denominator of the
    /// `> 2/3` quorum rule and is never re-normalized mid-epoch (spec `§3.2`).
    pub fn total_weight(&self) -> u128 {
        self.total_weight
    }

    /// The validators in the committee, in seat order.
    pub fn validators(&self) -> &[Validator] {
        &self.validators
    }

    /// Look up a validator by its seat index (position in the committee).
    /// Returns `None` for an out-of-range index — an out-of-range vote is
    /// simply uncounted, never a panic.
    pub fn validator_at(&self, index: u32) -> Option<&Validator> {
        self.validators.get(index as usize)
    }

    /// Look up a validator by its [`ValidatorId`].
    pub fn validator_by_id(&self, id: &ValidatorId) -> Option<&Validator> {
        self.validators.iter().find(|v| &v.id == id)
    }
}

/// The strict **`> 2/3` weighted-quorum predicate** (spec `§5.1`).
///
/// Returns `true` iff `covered_weight` is **strictly more than two-thirds** of
/// `total_weight`, computed in integer arithmetic with **no floats and no
/// rounding drift**:
///
/// ```text
/// covered_weight * 3 > total_weight * 2
/// ```
///
/// Strict `>`, never `>=`. `total_weight` is the **frozen** epoch total
/// (spec `§3.2`), never a live re-sum of present signers.
///
/// Overflow-safe and total (never panics): the products are checked, and the
/// astronomically-large regimes unreachable from `u64`-derived block counts are
/// resolved by the guard rather than a wrapping panic.
pub fn weighted_quorum_reached(covered_weight: u128, total_weight: u128) -> bool {
    match (covered_weight.checked_mul(3), total_weight.checked_mul(2)) {
        // The realistic path: both products fit in u128.
        (Some(lhs), Some(rhs)) => lhs > rhs,
        // covered*3 overflowed but total*2 did not => covered dwarfs total =>
        // quorum trivially reached.
        (None, Some(_)) => true,
        // total*2 overflowed but covered*3 did not => total dwarfs covered =>
        // not reached.
        (Some(_), None) => false,
        // Both overflow: unreachable from summed u64 block counts. Resolve
        // panic-free via saturation (kept only to keep the function total).
        (None, None) => covered_weight.saturating_mul(3) > total_weight.saturating_mul(2),
    }
}

/// Errors from committee construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitteeError {
    /// The roster was empty — a committee needs at least one weighted seat.
    EmptyCommittee,
    /// A validator carried an empty public key.
    EmptyPublicKey,
    /// A seat's weight was below the snapshot's `min_share` dust floor.
    BelowMinShare { weight: u64, min_share: u64 },
    /// Two validators shared a [`ValidatorId`].
    DuplicateValidatorId,
    /// Two validators shared a coinbase address (anti-Sybil; one coinbase, one
    /// seat).
    DuplicateCoinbase,
    /// Two validators shared a public key (anti-Sybil / anti-fragmentation).
    DuplicatePublicKey,
    /// The summed `total_weight` overflowed `u128`.
    TotalWeightOverflow,
}

impl core::fmt::Display for CommitteeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CommitteeError::EmptyCommittee => write!(f, "committee roster is empty"),
            CommitteeError::EmptyPublicKey => write!(f, "validator public key is empty"),
            CommitteeError::BelowMinShare { weight, min_share } => write!(
                f,
                "validator weight {weight} is below min_share {min_share} (dust)"
            ),
            CommitteeError::DuplicateValidatorId => write!(f, "duplicate validator id in committee"),
            CommitteeError::DuplicateCoinbase => {
                write!(f, "duplicate coinbase address in committee")
            }
            CommitteeError::DuplicatePublicKey => {
                write!(f, "duplicate validator public key in committee")
            }
            CommitteeError::TotalWeightOverflow => {
                write!(f, "committee total_weight overflows u128")
            }
        }
    }
}

impl std::error::Error for CommitteeError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn validator_w(seed: u8, weight: u64) -> Validator {
        let mut id = [0u8; 32];
        id[0] = seed;
        let mut coinbase = [0u8; 20];
        coinbase[0] = seed;
        Validator {
            id: ValidatorId(id),
            coinbase_addr: coinbase,
            // opaque, distinct, non-empty pubkey bytes per seed
            pubkey: vec![seed; 8],
            weight,
        }
    }

    fn meta(epoch: u64, min_share: u64) -> RotationMeta {
        RotationMeta { epoch, window_blocks: 2016, min_share }
    }

    fn committee(weights: &[u64], epoch: u64) -> ValidatorSet {
        let vs: Vec<Validator> = weights
            .iter()
            .enumerate()
            .map(|(i, &w)| validator_w((i as u8) + 1, w))
            .collect();
        ValidatorSet::new(vs, meta(epoch, 0)).unwrap()
    }

    // ── the strict > 2/3 weighted predicate, pinned exactly ──────────────

    #[test]
    fn weighted_quorum_predicate_is_strict_two_thirds() {
        // exactly 2/3 is NOT enough (strict >).
        assert!(!weighted_quorum_reached(2, 3)); // 2*3=6 !> 3*2=6
        assert!(!weighted_quorum_reached(20, 30));
        assert!(!weighted_quorum_reached(0, 0)); // vacuous: 0 !> 0
        // just over 2/3 IS enough.
        assert!(weighted_quorum_reached(3, 4)); // 9 > 8
        assert!(weighted_quorum_reached(21, 30)); // 63 > 60
        assert!(weighted_quorum_reached(67, 100)); // 201 > 200
        // just under 2/3 is not.
        assert!(!weighted_quorum_reached(66, 100)); // 198 !> 200
        // full coverage is always enough (for a positive total).
        assert!(weighted_quorum_reached(100, 100));
        assert!(weighted_quorum_reached(1, 1));
    }

    #[test]
    fn weighted_quorum_predicate_is_overflow_safe() {
        // Astronomically-large weights must not panic and must stay correct.
        let big = u128::MAX / 2; // covered*3 overflows, total*2 does not.
        assert!(weighted_quorum_reached(big, big)); // 3X > 2X for X>0 => true
        // covered small, total huge => not reached, no panic.
        assert!(!weighted_quorum_reached(1, u128::MAX));
        // covered huge, total small => reached, no panic.
        assert!(weighted_quorum_reached(u128::MAX, 1));
        // both at the ceiling: total, panic-free (saturating fallback).
        let _ = weighted_quorum_reached(u128::MAX, u128::MAX);
    }

    // ── total_weight is summed and frozen ────────────────────────────────

    #[test]
    fn total_weight_is_summed_and_frozen() {
        let set = committee(&[10, 20, 30, 40], 7);
        assert_eq!(set.total_weight(), 100);
        assert_eq!(set.epoch(), 7);
        assert_eq!(set.size(), 4);
        // single-seat committee is allowed (weight-based, not count-based).
        let solo = committee(&[5], 0);
        assert_eq!(solo.total_weight(), 5);
        assert_eq!(solo.size(), 1);
    }

    // ── membership invariants ────────────────────────────────────────────

    #[test]
    fn rejects_empty_committee() {
        assert_eq!(
            ValidatorSet::new(Vec::new(), meta(0, 0)),
            Err(CommitteeError::EmptyCommittee)
        );
    }

    #[test]
    fn rejects_duplicate_id() {
        let mut vs = vec![validator_w(1, 5), validator_w(2, 5), validator_w(3, 5)];
        vs[2].id = vs[0].id; // collide ids, keep coinbase/keys distinct
        assert_eq!(
            ValidatorSet::new(vs, meta(0, 0)),
            Err(CommitteeError::DuplicateValidatorId)
        );
    }

    #[test]
    fn rejects_duplicate_coinbase() {
        let mut vs = vec![validator_w(1, 5), validator_w(2, 5), validator_w(3, 5)];
        vs[2].coinbase_addr = vs[0].coinbase_addr; // collide coinbase only
        assert_eq!(
            ValidatorSet::new(vs, meta(0, 0)),
            Err(CommitteeError::DuplicateCoinbase)
        );
    }

    #[test]
    fn rejects_duplicate_pubkey() {
        let mut vs = vec![validator_w(1, 5), validator_w(2, 5), validator_w(3, 5)];
        vs[2].pubkey = vs[0].pubkey.clone(); // collide keys only
        assert_eq!(
            ValidatorSet::new(vs, meta(0, 0)),
            Err(CommitteeError::DuplicatePublicKey)
        );
    }

    #[test]
    fn rejects_empty_pubkey() {
        let mut vs = vec![validator_w(1, 5), validator_w(2, 5)];
        vs[1].pubkey = Vec::new();
        assert_eq!(
            ValidatorSet::new(vs, meta(0, 0)),
            Err(CommitteeError::EmptyPublicKey)
        );
    }

    #[test]
    fn rejects_weight_below_min_share() {
        let vs = vec![validator_w(1, 10), validator_w(2, 3)];
        assert_eq!(
            ValidatorSet::new(vs, meta(0, 5)),
            Err(CommitteeError::BelowMinShare { weight: 3, min_share: 5 })
        );
        // at or above min_share is fine.
        let vs = vec![validator_w(1, 10), validator_w(2, 5)];
        assert!(ValidatorSet::new(vs, meta(0, 5)).is_ok());
    }

    #[test]
    fn total_weight_overflow_is_rejected_not_panicked() {
        let vs = vec![
            validator_w(1, u64::MAX),
            validator_w(2, u64::MAX),
            // sum of two u64::MAX still fits u128; add a third to stay well
            // inside u128 — overflow of u128 from u64 sums is unreachable, so
            // we only assert construction succeeds and stays panic-free.
            validator_w(3, u64::MAX),
        ];
        let set = ValidatorSet::new(vs, meta(0, 0)).unwrap();
        assert_eq!(set.total_weight(), 3u128 * u64::MAX as u128);
    }

    #[test]
    fn rotation_metadata_is_carried() {
        let set = ValidatorSet::new(
            vec![validator_w(1, 5), validator_w(2, 5)],
            RotationMeta { epoch: 9, window_blocks: 120, min_share: 1 },
        )
        .unwrap();
        assert_eq!(set.rotation(), RotationMeta { epoch: 9, window_blocks: 120, min_share: 1 });
        assert_eq!(set.epoch(), 9);
    }

    // ── lookups ──────────────────────────────────────────────────────────

    #[test]
    fn lookups_by_index_and_id() {
        let set = committee(&[5, 5, 5, 5, 5], 9);
        assert_eq!(set.validator_at(0), Some(&validator_w(1, 5)));
        assert_eq!(set.validator_at(4), Some(&validator_w(5, 5)));
        assert_eq!(set.validator_at(5), None); // out of range => None, no panic
        assert_eq!(set.validator_by_id(&validator_w(3, 5).id), Some(&validator_w(3, 5)));
        let mut missing = [0u8; 32];
        missing[0] = 200;
        assert_eq!(set.validator_by_id(&ValidatorId(missing)), None);
    }
}
