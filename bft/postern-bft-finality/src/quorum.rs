// SPDX-License-Identifier: MIT OR Apache-2.0
//! Weighted BFT finality: do the votes of **distinct, valid** committee seats
//! cover **`> 2/3` of the epoch's frozen `total_weight`**?
//!
//! # SCAFFOLD — not a secure or deployed system
//!
//! This module carries the one deterministic finality primitive of the design
//! (spec `§5`): sum the **weights** of the *distinct* committee seats that have
//! contributed a *cryptographically valid* signature over a checkpoint's
//! canonical signing payload, and test that sum against the strict `> 2/3`
//! weighted threshold ([`crate::committee::weighted_quorum_reached`]).
//!
//! ## Why weighted, not count-based
//!
//! The retired count design finalized on `2f+1` *distinct seats* and derived
//! safety from `N = 3f+1`; a review proved that unsafe for `N != 3f+1`. This
//! module instead sums per-seat **weight** and compares to `> 2/3` of the
//! frozen `total_weight`. The quorum-intersection guarantee then holds for
//! **any** weight distribution (spec `§5.2`): two `> 2W/3` signer sets overlap
//! in weight `> W/3`, so `>= 1` attributable seat signed both. There is no
//! `N = 3f+1` precondition.
//!
//! ## The verify seam — real ML-DSA-65 is wired in BY DEFAULT
//!
//! Signature bytes are carried opaquely; this crate never re-implements
//! post-quantum crypto. Verification goes through the [`CheckpointVerifier`]
//! trait — the single seam. By **default** the seam is filled by
//! [`RustCryptoMlDsa65Verifier`], a **real FIPS-204 verify** backed by the
//! (still UNAUDITED, pre-1.0) RustCrypto `ml-dsa` crate: a default `cargo test`
//! finalizes a genuine `> 2/3` quorum and rejects any tampered ML-DSA-65
//! signature, with no `--features` flag. Two non-crypto seam impls remain for
//! offline/scripted use — [`MockVerifier`] (a scripted accept/reject oracle for
//! deterministic tests) and [`RejectingStubVerifier`] (accepts nothing, the
//! `--no-default-features` offline posture). A real deployment still supplies a
//! FIPS-204-conformant, **independently-audited** verifier (e.g. the repo's
//! wired `bloch_crypto::crypto::verify`); the default `ml-dsa` backing here is
//! real crypto but is **not** that audited primitive, so a reached quorum is
//! never a claim of production security.
//!
//! ## What a reached quorum does and does not mean (spec `§5`, `§8`, `§9`)
//!
//! * **Accountable safety.** Two conflicting checkpoints each covering `> 2/3`
//!   of the weight overlap in seats holding `> 1/3` of the weight, so a safety
//!   violation attributes equivocation to `>= 1` attributable seat whose two
//!   ML-DSA signatures are self-authenticating evidence. Detection is
//!   third-party verifiable; v1 has **no slashing** (reputation + exclusion at
//!   next rotation only).
//! * **Honest liveness.** Finality halts if seats holding `> 1/3` of the frozen
//!   weight go offline/depart — a deliberate, disclosed liveness/safety trade
//!   (spec `§3.2`, `§6`). It never forks.
//! * **Hashrate-concentration caveat (spec `§9`).** The committee *is* the
//!   miners weighted by block-share, so a `> 2/3`-weight quorum *is* a
//!   `> 2/3`-hashrate entity — finality is only as decentralized as the
//!   hashrate. Today concentrated ⇒ effectively Postern-controlled.
//! * **Capped by the base.** A finalized checkpoint cannot be reorged past
//!   *within the committee's view*, but overall security is
//!   `min(base security, committee security)`; today the base is
//!   `k`-forgeable, so this is not settlement finality (spec reorg gate).

use crate::checkpoint::{Checkpoint, Vote};
use crate::committee::{weighted_quorum_reached, ValidatorSet};

/// The single ML-DSA-65 verification seam.
///
/// A real implementation returns `true` iff `signature` is a valid ML-DSA-65
/// (FIPS 204) signature by `public_key` over `message`. It must be **total**
/// (never panic) — a bad signature is `false`, not a crash — matching the
/// repo's wired `bloch_crypto::crypto::verify(pk, msg, sig) -> bool`.
///
/// SCAFFOLD: the only implementations shipped in this crate are [`MockVerifier`]
/// and [`RejectingStubVerifier`].
pub trait CheckpointVerifier {
    /// Verify one signature. Returns `true` only on a valid signature; total,
    /// never panics.
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool;
}

/// Outcome of a weighted finality check against a committee.
///
/// Both variants carry the **`covered_weight`** (summed weight of the distinct
/// valid signers) and the frozen **`total_weight`** so the caller sees the exact
/// numerator and denominator of the `> 2/3` test.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinalityOutcome {
    /// Distinct valid signers covered `> 2/3` of `total_weight`: the checkpoint
    /// is finalized *by this committee* (subject to the base cap — never
    /// settlement finality on a forgeable base).
    Finalized { covered_weight: u128, total_weight: u128 },
    /// Distinct valid signers covered `<= 2/3` of `total_weight`: not finalized.
    NotFinalized { covered_weight: u128, total_weight: u128 },
    /// The FFG-BFT overlay is **inactive** at this checkpoint's
    /// `finalized_height` (`finalized_height < activation_height`), so the
    /// checkpoint was rejected **without even summing weights** — the overlay is
    /// provably inert below [`crate::FFG_ACTIVATION_HEIGHT`]. Only produced by
    /// the activation-gated entry point [`verify_finalized_gated`]; the ungated
    /// [`verify_finalized`] never returns this. Never `is_finalized`.
    Inert { finalized_height: u64, activation_height: u64 },
}

impl FinalityOutcome {
    /// Whether the checkpoint reached its committee's `> 2/3` weighted quorum.
    /// Always `false` for [`FinalityOutcome::Inert`] (a pre-activation height can
    /// never be finalized by this overlay).
    pub fn is_finalized(&self) -> bool {
        matches!(self, FinalityOutcome::Finalized { .. })
    }

    /// Whether the outcome is [`FinalityOutcome::Inert`] — the overlay was
    /// inactive at the checkpoint's height (below
    /// [`crate::FFG_ACTIVATION_HEIGHT`]) and no weights were even summed.
    pub fn is_inert(&self) -> bool {
        matches!(self, FinalityOutcome::Inert { .. })
    }

    /// The summed weight of the distinct valid signers. `0` for an
    /// [`FinalityOutcome::Inert`] outcome (no weights are summed below
    /// activation).
    pub fn covered_weight(&self) -> u128 {
        match self {
            FinalityOutcome::Finalized { covered_weight, .. }
            | FinalityOutcome::NotFinalized { covered_weight, .. } => *covered_weight,
            FinalityOutcome::Inert { .. } => 0,
        }
    }

    /// The frozen epoch total weight (the `> 2/3` denominator). `0` for an
    /// [`FinalityOutcome::Inert`] outcome (the committee is never consulted below
    /// activation).
    pub fn total_weight(&self) -> u128 {
        match self {
            FinalityOutcome::Finalized { total_weight, .. }
            | FinalityOutcome::NotFinalized { total_weight, .. } => *total_weight,
            FinalityOutcome::Inert { .. } => 0,
        }
    }
}

/// Sum the **weights** of the distinct valid committee seats that signed
/// `checkpoint`, and decide finality against `set`'s frozen `total_weight` via
/// the strict `> 2/3` rule.
///
/// Counting rules (spec `§5.1`):
///
/// 1. **One seat, one counted vote.** A repeated `validator_index` is counted
///    at most once (first valid occurrence wins; later duplicates — including
///    duplicates of a seat's *own* valid vote — add no weight).
/// 2. **Must be a committee member.** A vote whose `validator_index` is out of
///    range for `set` is uncounted (never a panic).
/// 3. **Must cryptographically verify** against *that seat's* public key over
///    the checkpoint's [`Checkpoint::canonical_signing_payload`]. A signature
///    valid for a different signer, presented under the wrong seat, fails
///    verification and adds no weight.
///
/// Each distinct valid seat contributes **its own weight** (block-share) to
/// `covered_weight`. Finalized iff
/// [`weighted_quorum_reached`]`(covered_weight, total_weight)` — i.e.
/// `covered_weight * 3 > total_weight * 2` (u128, strict, overflow-safe).
pub fn verify_finalized<V: CheckpointVerifier>(
    checkpoint: &Checkpoint,
    votes: &[Vote],
    set: &ValidatorSet,
    verifier: &V,
) -> FinalityOutcome {
    let message = checkpoint.canonical_signing_payload();
    let total_weight = set.total_weight();

    // Denominator cross-check (fail closed): the frozen `total_weight` the
    // signers attested inside the signed payload MUST equal the committee's own
    // total, or we would decide a `> 2/3` quorum against a different denominator
    // than was actually signed. On a mismatch, no finality.
    if checkpoint.total_weight != total_weight {
        return FinalityOutcome::NotFinalized { covered_weight: 0, total_weight };
    }

    let mut covered_weight: u128 = 0;
    let mut seen: Vec<u32> = Vec::new();

    for vote in votes {
        // One seat, one counted vote.
        if seen.contains(&vote.validator_index) {
            continue;
        }
        // Must be a committee member (out-of-range index => uncounted).
        let Some(validator) = set.validator_at(vote.validator_index) else {
            continue;
        };
        // Must cryptographically verify against THIS seat's key.
        if verifier.verify(&validator.pubkey, &message, &vote.sig) {
            // A seat is counted the first time it verifies; its own weight is
            // added exactly once. (u64 -> u128 add cannot overflow within one
            // committee, whose total_weight already fit u128 at construction.)
            covered_weight = covered_weight.saturating_add(validator.weight as u128);
            seen.push(vote.validator_index);
        }
    }

    if weighted_quorum_reached(covered_weight, total_weight) {
        FinalityOutcome::Finalized { covered_weight, total_weight }
    } else {
        FinalityOutcome::NotFinalized { covered_weight, total_weight }
    }
}

/// **Activation-gated** finality: the checkpoint/certificate entry point a node
/// consults. It enforces [`crate::FFG_ACTIVATION_HEIGHT`] before any weight
/// summation, so the overlay is **provably inert below the activation height**.
///
/// * If [`crate::is_active`]`(checkpoint.finalized_height)` is `false`
///   (`finalized_height < `[`crate::FFG_ACTIVATION_HEIGHT`]), it short-circuits
///   to [`FinalityOutcome::Inert`] **without calling the verifier or summing any
///   weight** — no certificate can be accepted for a pre-activation height, no
///   matter how much genuine `> 2/3` quorum the votes carry.
/// * At **exactly** the activation height and above it delegates verbatim to
///   [`verify_finalized`]; acceptance begins at exactly block `1_000_000`.
///
/// This is the gate; [`FFG_ACTIVATION_HEIGHT`](crate::FFG_ACTIVATION_HEIGHT)
/// stays a bare const and the ungated [`verify_finalized`] keeps its pure,
/// height-agnostic weighted-quorum arithmetic (so the many codec/quorum tests
/// that operate at low scaffold heights are unaffected). A real node integration
/// routes checkpoint acceptance through **this** function.
pub fn verify_finalized_gated<V: CheckpointVerifier>(
    checkpoint: &Checkpoint,
    votes: &[Vote],
    set: &ValidatorSet,
    verifier: &V,
) -> FinalityOutcome {
    if !crate::is_active(checkpoint.finalized_height) {
        return FinalityOutcome::Inert {
            finalized_height: checkpoint.finalized_height,
            activation_height: crate::FFG_ACTIVATION_HEIGHT,
        };
    }
    verify_finalized(checkpoint, votes, set, verifier)
}

/// A scripted verify oracle for **offline tests only**.
///
/// # SCAFFOLD — performs no cryptography
///
/// [`MockVerifier`] holds a list of `(public_key, message, signature)` triples
/// registered via [`MockVerifier::accept`]; [`CheckpointVerifier::verify`]
/// returns `true` iff the exact triple was registered. This lets a test script
/// precisely which signatures are "genuine" — for a specific key over a
/// specific message — without any real crypto. It asserts nothing about real
/// signatures and must never be used for anything of value.
#[derive(Debug, Default, Clone)]
pub struct MockVerifier {
    accepted: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>,
}

impl MockVerifier {
    /// A mock that accepts nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a `(public_key, message, signature)` triple as valid.
    pub fn accept(&mut self, public_key: &[u8], message: &[u8], signature: &[u8]) {
        self.accepted
            .push((public_key.to_vec(), message.to_vec(), signature.to_vec()));
    }
}

impl CheckpointVerifier for MockVerifier {
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        self.accepted
            .iter()
            .any(|(p, m, s)| p == public_key && m == message && s == signature)
    }
}

/// A verifier that accepts **nothing** — the offline `--no-default-features`
/// posture (the default build now uses the real [`RustCryptoMlDsa65Verifier`]).
/// With this wired in, no checkpoint can ever reach quorum, so a crate-free /
/// network-free build makes no false security claim (mirrors the notary crate's
/// `NonVerifyingStubVerifier`).
#[derive(Debug, Default, Clone, Copy)]
pub struct RejectingStubVerifier;

impl CheckpointVerifier for RejectingStubVerifier {
    fn verify(&self, _public_key: &[u8], _message: &[u8], _signature: &[u8]) -> bool {
        false
    }
}

/// A **real** ML-DSA-65 (FIPS 204) implementation of the [`CheckpointVerifier`]
/// seam, backed by the RustCrypto `ml-dsa` crate. It is the **default** seam
/// impl (the `real-mldsa65` feature is ON by default); it is compiled out only
/// under `--no-default-features`.
///
/// # This is real cryptography — it is still not a security claim
///
/// Unlike [`RejectingStubVerifier`] (accepts nothing) and [`MockVerifier`] (a
/// scripted oracle), this performs a **real FIPS-204 verify**: it accepts a
/// genuine ML-DSA-65 signature by `public_key` over `message` and rejects
/// everything else. It is **total** — any malformed key/signature, wrong
/// length, or bad signature is `false`, never a panic — matching the seam's
/// contract and the repo's wired `bloch_crypto::crypto::verify(pk, msg, sig)
/// -> bool`.
///
/// Wiring this in changes **nothing** about the trust model or the security
/// posture of this crate:
///
/// * The `ml-dsa` crate is **UNAUDITED, pre-1.0 (`0.1.1`)** RustCrypto.
/// * There is still **no aggregation and no DKG** — ML-DSA has none (spec
///   `§7`); each seat is verified on an **individual** signature, one
///   [`verify`](CheckpointVerifier::verify) call at a time.
/// * Finality remains **hashrate-weighted**, so it is only as decentralized as
///   the (today concentrated) hashrate (spec `§9`).
/// * The Bloch base a checkpoint anchors to is still `k`-forgeable and
///   `51%`-attackable **today**, so overall security stays
///   `min(base, committee)` — a reached quorum here is **not** settlement
///   finality.
///
/// Default builds (`cargo test` / `cargo build` with no `--features`) wire in
/// this type as the real default verify posture. It, its impl, and the `ml-dsa`
/// dependency are compiled out of the artifact **only** under
/// `--no-default-features`, where [`RejectingStubVerifier`] (accepts nothing)
/// takes over as the offline, zero-dependency posture.
#[cfg(feature = "real-mldsa65")]
#[derive(Debug, Default, Clone, Copy)]
pub struct RustCryptoMlDsa65Verifier;

#[cfg(feature = "real-mldsa65")]
impl CheckpointVerifier for RustCryptoMlDsa65Verifier {
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        use ml_dsa::signature::Verifier as _;
        use ml_dsa::{
            EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature as InnerSignature, VerifyingKey,
        };

        // Total, never panics: every decode failure is a rejection (`false`).
        let Ok(encoded_vk) = EncodedVerifyingKey::<MlDsa65>::try_from(public_key) else {
            return false;
        };
        let vk = VerifyingKey::<MlDsa65>::decode(&encoded_vk);

        let Ok(encoded_sig) = EncodedSignature::<MlDsa65>::try_from(signature) else {
            return false;
        };
        let Some(sig) = InnerSignature::<MlDsa65>::decode(&encoded_sig) else {
            return false;
        };

        vk.verify(message, &sig).is_ok()
    }
}

/// A real ML-DSA-65 (FIPS 204) **deterministic** signer for the checkpoint
/// signing payload, backed by the RustCrypto `ml-dsa` crate. Compiled in by
/// **default** (the `real-mldsa65` feature is ON by default); dropped only under
/// `--no-default-features`.
///
/// It exists so this crate's own tests and downstream integration
/// harnesses can produce **genuine** ML-DSA-65 co-signatures that
/// [`RustCryptoMlDsa65Verifier`] accepts — without any test needing to depend
/// on `ml-dsa` directly. It emits raw signature/public-key **bytes**, matching
/// the crate's opaque-bytes seam ([`Vote::sig`](crate::checkpoint::Vote::sig)
/// and [`Validator::pubkey`](crate::committee::Validator::pubkey)).
///
/// # This is real cryptography — it is still not a security claim
///
/// Everything on [`RustCryptoMlDsa65Verifier`] applies unchanged: the `ml-dsa`
/// crate is **UNAUDITED, pre-1.0 (`0.1.1`)**; the model is still
/// hashrate-weighted; the base is still forgeable; nothing here is secure,
/// operational, audited, or deployed. Additionally:
///
/// - **Seed-derived keys are for deterministic tests ONLY.** Real operator
///   keys must be drawn from a CSPRNG and held in real custody (HSMs, key
///   ceremonies, coinbase-bound registration on the base) — that is
///   **out of scope / blocked-on-infra** here.
/// - This type is compiled in by default; only `--no-default-features` drops it.
#[cfg(feature = "real-mldsa65")]
pub struct RustCryptoMlDsa65Signer {
    esk: ml_dsa::ExpandedSigningKey<ml_dsa::MlDsa65>,
}

#[cfg(feature = "real-mldsa65")]
impl core::fmt::Debug for RustCryptoMlDsa65Signer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print key material, even scaffold test keys.
        write!(f, "RustCryptoMlDsa65Signer(<signing key redacted>)")
    }
}

#[cfg(feature = "real-mldsa65")]
impl RustCryptoMlDsa65Signer {
    /// Derive a keypair deterministically from a 32-byte seed.
    ///
    /// **Test-only key handling:** never derive a real committee key from a
    /// fixed or low-entropy seed; real seeds must come from a CSPRNG.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let seed: ml_dsa::Seed = seed.into();
        Self {
            esk: ml_dsa::ExpandedSigningKey::<ml_dsa::MlDsa65>::from_seed(&seed),
        }
    }

    /// The ML-DSA-65 public-key bytes matching this signer (FIPS-204 encoded).
    /// Use directly as a [`Validator::pubkey`](crate::committee::Validator::pubkey).
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.esk.verifying_key().encode().to_vec()
    }

    /// Deterministically sign `message`, returning the FIPS-204-encoded
    /// signature bytes. Use directly as a [`Vote::sig`](crate::checkpoint::Vote::sig).
    ///
    /// Returns `None` only if the underlying primitive fails (it does not for a
    /// well-formed message); callers treat that as "no signature", never a
    /// panic.
    pub fn sign(&self, message: &[u8]) -> Option<Vec<u8>> {
        self.esk
            .sign_deterministic(message, b"")
            .ok()
            .map(|sig| sig.encode().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::Checkpoint;
    use crate::committee::{RotationMeta, Validator, ValidatorId, ValidatorSet};

    fn validator_w(seed: u8, weight: u64) -> Validator {
        let mut id = [0u8; 32];
        id[0] = seed;
        let mut coinbase = [0u8; 20];
        coinbase[0] = seed;
        Validator {
            id: ValidatorId(id),
            coinbase_addr: coinbase,
            pubkey: vec![seed; 8],
            weight,
        }
    }

    /// Build a committee from an explicit weight list (seat `k` = seed `k+1`).
    fn committee(weights: &[u64], min_share: u64) -> ValidatorSet {
        let vs: Vec<Validator> = weights
            .iter()
            .enumerate()
            .map(|(i, &w)| validator_w((i as u8) + 1, w))
            .collect();
        ValidatorSet::new(vs, RotationMeta { epoch: 0, window_blocks: 2016, min_share }).unwrap()
    }

    fn checkpoint(set: &ValidatorSet) -> Checkpoint {
        Checkpoint {
            committee_epoch: 0,
            finalized_height: 100,
            finalized_block_hash: [1u8; 32],
            prev_checkpoint_hash: [0u8; 32],
            committee_commitment: [0x11; 32],
            total_weight: set.total_weight(),
        }
    }

    /// A "genuine" signature for a given seat: distinct per (seat, message) so
    /// the mock can bind validity to the right key.
    fn genuine_sig(seed: u8) -> Vec<u8> {
        vec![0x80 | seed; 3309]
    }

    /// Register genuine signatures for the given seats (1-indexed seeds) and
    /// return the votes.
    fn signed_votes(
        set: &ValidatorSet,
        c: &Checkpoint,
        verifier: &mut MockVerifier,
        seats: &[u8],
    ) -> Vec<Vote> {
        let message = c.canonical_signing_payload();
        let mut votes = Vec::new();
        for &seat in seats {
            let idx = (seat - 1) as u32; // seat `k` lives at index k-1
            let pubkey = &set.validator_at(idx).unwrap().pubkey;
            let sig = genuine_sig(seat);
            verifier.accept(pubkey, &message, &sig);
            votes.push(Vote { validator_index: idx, sig });
        }
        votes
    }

    // ── reached at exactly just-over-2/3 weight ──────────────────────────

    #[test]
    fn reached_just_over_two_thirds_weight() {
        // total = 100; seats [40, 30, 20, 10]. Signers {40,30} = 70 > 66.6 =>
        // finalized. (70*3 = 210 > 200 = 100*2.)
        let set = committee(&[40, 30, 20, 10], 0);
        assert_eq!(set.total_weight(), 100);
        let c = checkpoint(&set);
        let mut v = MockVerifier::new();
        let votes = signed_votes(&set, &c, &mut v, &[1, 2]); // 40 + 30 = 70
        assert_eq!(
            verify_finalized(&c, &votes, &set, &v),
            FinalityOutcome::Finalized { covered_weight: 70, total_weight: 100 }
        );
    }

    // ── just under 2/3 weight is not finalized ───────────────────────────

    #[test]
    fn just_under_two_thirds_weight_is_not_finalized() {
        // total = 3; a single seat of weight 2 is exactly 2/3 => NOT reached
        // (strict >). 2*3 = 6 !> 6 = 3*2.
        let set = committee(&[2, 1], 0);
        assert_eq!(set.total_weight(), 3);
        let c = checkpoint(&set);
        let mut v = MockVerifier::new();
        let votes = signed_votes(&set, &c, &mut v, &[1]); // weight 2 of 3
        assert_eq!(
            verify_finalized(&c, &votes, &set, &v),
            FinalityOutcome::NotFinalized { covered_weight: 2, total_weight: 3 }
        );

        // total = 100, signers cover 66 < 66.6 => not finalized.
        let set = committee(&[66, 34], 0);
        let c = checkpoint(&set);
        let mut v = MockVerifier::new();
        let votes = signed_votes(&set, &c, &mut v, &[1]); // 66 of 100
        assert_eq!(
            verify_finalized(&c, &votes, &set, &v),
            FinalityOutcome::NotFinalized { covered_weight: 66, total_weight: 100 }
        );
    }

    // ── duplicate-validator weight counted once ──────────────────────────

    #[test]
    fn duplicate_validator_weight_counts_once() {
        // total = 100; seats [50, 30, 20]. {50,30} = 80 > 66.6 => finalized.
        let set = committee(&[50, 30, 20], 0);
        let c = checkpoint(&set);
        let mut v = MockVerifier::new();
        let mut votes = signed_votes(&set, &c, &mut v, &[1, 2]); // 50 + 30
        // Duplicate seat 1's valid vote several times: must NOT inflate weight.
        let dup = votes[0].clone();
        votes.push(dup.clone());
        votes.push(dup);
        assert_eq!(
            verify_finalized(&c, &votes, &set, &v),
            FinalityOutcome::Finalized { covered_weight: 80, total_weight: 100 }
        );

        // With only the weight-50 seat genuine, spamming its duplicate cannot
        // manufacture the missing weight: 50 of 100 is not > 2/3.
        let mut v2 = MockVerifier::new();
        let mut votes2 = signed_votes(&set, &c, &mut v2, &[1]);
        votes2.push(votes2[0].clone());
        votes2.push(votes2[0].clone());
        assert_eq!(
            verify_finalized(&c, &votes2, &set, &v2),
            FinalityOutcome::NotFinalized { covered_weight: 50, total_weight: 100 }
        );
    }

    // ── wrong signer excluded ────────────────────────────────────────────

    #[test]
    fn wrong_signer_signature_is_excluded() {
        // total = 100; seats [40, 30, 20, 10]. Seats 1,2 genuine (70) would
        // finalize — but we make seat 2 fail and try to sneak seat 4's sig in
        // under seat 3, which must not verify => only 40 counts.
        let set = committee(&[40, 30, 20, 10], 0);
        let c = checkpoint(&set);
        let message = c.canonical_signing_payload();
        let mut v = MockVerifier::new();

        // Only seat 1 signs genuinely (weight 40).
        let mut votes = signed_votes(&set, &c, &mut v, &[1]);

        // Seat 3's slot carries a signature genuine for seat 4's key, NOT seat
        // 3's. verify() checks seat 3's key => fails, no weight added.
        let seat4_pubkey = &set.validator_at(3).unwrap().pubkey; // seat 4 at idx 3
        let seat4_sig = genuine_sig(4);
        v.accept(seat4_pubkey, &message, &seat4_sig); // valid ONLY for seat 4's key
        votes.push(Vote { validator_index: 2, sig: seat4_sig }); // presented under seat 3 (idx 2)

        assert_eq!(
            verify_finalized(&c, &votes, &set, &v),
            FinalityOutcome::NotFinalized { covered_weight: 40, total_weight: 100 }
        );
    }

    // ── zero-weight edge: a zero-weight signer adds nothing ───────────────

    #[test]
    fn zero_weight_seat_contributes_no_weight() {
        // min_share = 0 admits a zero-weight seat. total = 90; seats
        // [60, 30, 0]. Seat 1 (60) alone is exactly 2/3 => not reached; adding
        // the zero-weight seat 3 changes nothing; seat 2 (30) tips it over.
        let set = committee(&[60, 30, 0], 0);
        assert_eq!(set.total_weight(), 90);
        let c = checkpoint(&set);

        // Seat 1 + zero-weight seat 3: covered = 60, exactly 2/3, NOT finalized.
        let mut v = MockVerifier::new();
        let votes = signed_votes(&set, &c, &mut v, &[1, 3]);
        assert_eq!(
            verify_finalized(&c, &votes, &set, &v),
            FinalityOutcome::NotFinalized { covered_weight: 60, total_weight: 90 }
        );

        // Seat 1 + seat 2 (+ zero seat 3): covered = 90 > 60 => finalized, and
        // the zero-weight vote still adds nothing.
        let mut v2 = MockVerifier::new();
        let votes2 = signed_votes(&set, &c, &mut v2, &[1, 2, 3]);
        assert_eq!(
            verify_finalized(&c, &votes2, &set, &v2),
            FinalityOutcome::Finalized { covered_weight: 90, total_weight: 90 }
        );
    }

    // ── out-of-range seat index is uncounted, never a panic ──────────────

    #[test]
    fn out_of_range_validator_index_is_uncounted() {
        let set = committee(&[40, 30, 20], 0); // total 90, seats at idx 0..=2
        let c = checkpoint(&set);
        let mut v = MockVerifier::new();
        let mut votes = signed_votes(&set, &c, &mut v, &[1, 2]); // 70 of 90 => finalized
        // append a vote for a nonexistent seat 99, with arbitrary bytes.
        votes.push(Vote { validator_index: 99, sig: vec![0xFF; 10] });
        assert_eq!(
            verify_finalized(&c, &votes, &set, &v),
            FinalityOutcome::Finalized { covered_weight: 70, total_weight: 90 }
        );
    }

    // ── overflow-safe weight summation ───────────────────────────────────

    #[test]
    fn weight_summation_is_overflow_safe() {
        // Enormous per-seat weights: covered_weight and total_weight are u128,
        // and the > 2/3 test stays panic-free and correct.
        let set = committee(&[u64::MAX, u64::MAX, u64::MAX], 0);
        assert_eq!(set.total_weight(), 3u128 * u64::MAX as u128);
        let c = checkpoint(&set);
        let mut v = MockVerifier::new();
        // Two of three max-weight seats => 2/3 exactly => NOT finalized.
        let votes = signed_votes(&set, &c, &mut v, &[1, 2]);
        let outcome = verify_finalized(&c, &votes, &set, &v);
        assert!(!outcome.is_finalized());
        assert_eq!(outcome.covered_weight(), 2u128 * u64::MAX as u128);
        // All three => finalized, no panic.
        let mut v2 = MockVerifier::new();
        let votes2 = signed_votes(&set, &c, &mut v2, &[1, 2, 3]);
        assert!(verify_finalized(&c, &votes2, &set, &v2).is_finalized());
    }

    // ── the rejecting stub never reaches quorum ──────────────────────────

    #[test]
    fn rejecting_stub_never_reaches_quorum() {
        let set = committee(&[40, 30, 20, 10], 0);
        let c = checkpoint(&set);
        // Even with well-formed votes for every seat, the stub asserts nothing.
        let votes: Vec<Vote> = (0..4u32)
            .map(|idx| Vote { validator_index: idx, sig: vec![idx as u8; 3309] })
            .collect();
        let outcome = verify_finalized(&c, &votes, &set, &RejectingStubVerifier);
        assert_eq!(
            outcome,
            FinalityOutcome::NotFinalized { covered_weight: 0, total_weight: 100 }
        );
        assert!(!outcome.is_finalized());
    }

    // ── a signature over a DIFFERENT checkpoint does not count ───────────

    #[test]
    fn signature_over_other_checkpoint_is_rejected() {
        let set = committee(&[40, 30, 20, 10], 0);
        let c = checkpoint(&set);
        let mut other = c.clone();
        other.finalized_height = 999;

        let mut v = MockVerifier::new();
        // Seat 1 signs the real checkpoint `c` (weight 40).
        let mut votes = signed_votes(&set, &c, &mut v, &[1]);
        // Seat 2 signs `other` (wrong message) but submits it against `c`.
        let other_msg = other.canonical_signing_payload();
        let seat2_pubkey = &set.validator_at(1).unwrap().pubkey;
        let seat2_sig = genuine_sig(2);
        v.accept(seat2_pubkey, &other_msg, &seat2_sig); // valid only over `other`
        votes.push(Vote { validator_index: 1, sig: seat2_sig });

        // Against `c`'s payload only seat 1's 40 counts => below quorum.
        assert_eq!(
            verify_finalized(&c, &votes, &set, &v),
            FinalityOutcome::NotFinalized { covered_weight: 40, total_weight: 100 }
        );
    }

    // ── activation gate: overlay is inert below FFG_ACTIVATION_HEIGHT ─────

    /// Build a checkpoint at an explicit `finalized_height` for the given set.
    fn checkpoint_at(set: &ValidatorSet, finalized_height: u64) -> Checkpoint {
        Checkpoint {
            committee_epoch: 0,
            finalized_height,
            finalized_block_hash: [1u8; 32],
            prev_checkpoint_hash: [0u8; 32],
            committee_commitment: [0x11; 32],
            total_weight: set.total_weight(),
        }
    }

    #[test]
    fn gated_verify_is_inert_below_activation_height_even_with_genuine_quorum() {
        // A genuine > 2/3 quorum (weight 70 of 100) that WOULD finalize the
        // ungated primitive must NOT be accepted below FFG_ACTIVATION_HEIGHT.
        let set = committee(&[40, 30, 20, 10], 0);
        assert_eq!(set.total_weight(), 100);

        for h in [0u64, 1, 100, crate::FFG_ACTIVATION_HEIGHT - 1] {
            let c = checkpoint_at(&set, h);
            let mut v = MockVerifier::new();
            let votes = signed_votes(&set, &c, &mut v, &[1, 2]); // 70 of 100

            // The ungated primitive still finalizes (it is height-agnostic)...
            assert!(
                verify_finalized(&c, &votes, &set, &v).is_finalized(),
                "ungated primitive stays height-agnostic at h={h}"
            );
            // ...but the GATED entry point is provably inert.
            let gated = verify_finalized_gated(&c, &votes, &set, &v);
            assert_eq!(
                gated,
                FinalityOutcome::Inert {
                    finalized_height: h,
                    activation_height: crate::FFG_ACTIVATION_HEIGHT,
                },
                "gated verify must be Inert at pre-activation height {h}"
            );
            assert!(!gated.is_finalized());
            assert!(gated.is_inert());
            assert_eq!(gated.covered_weight(), 0, "no weight summed below activation");
        }
    }

    #[test]
    fn gated_verify_acceptance_begins_exactly_at_activation_height() {
        let set = committee(&[40, 30, 20, 10], 0);

        // Exactly at the activation height: the same genuine quorum finalizes.
        let c = checkpoint_at(&set, crate::FFG_ACTIVATION_HEIGHT);
        let mut v = MockVerifier::new();
        let votes = signed_votes(&set, &c, &mut v, &[1, 2]); // 70 of 100
        assert_eq!(
            verify_finalized_gated(&c, &votes, &set, &v),
            FinalityOutcome::Finalized { covered_weight: 70, total_weight: 100 },
            "acceptance must begin at exactly FFG_ACTIVATION_HEIGHT"
        );

        // Above the height it also delegates to the real quorum check: a
        // sub-quorum (weight 40) is NotFinalized, not spuriously Inert/Finalized.
        let c2 = checkpoint_at(&set, crate::FFG_ACTIVATION_HEIGHT + 500_000);
        let mut v2 = MockVerifier::new();
        let votes2 = signed_votes(&set, &c2, &mut v2, &[1]); // 40 of 100
        assert_eq!(
            verify_finalized_gated(&c2, &votes2, &set, &v2),
            FinalityOutcome::NotFinalized { covered_weight: 40, total_weight: 100 }
        );
    }

    // ── DEFAULT-build real ML-DSA-65: quorum finalizes, tamper is rejected ────
    //
    // This runs on a plain `cargo test` (the `real-mldsa65` feature is ON by
    // default) — no `--features` flag. It proves the seam's DEFAULT posture is a
    // genuine FIPS-204 verify: real signatures reach the weighted `> 2/3`
    // quorum, and a single-byte-mutated ML-DSA-65 signature is REJECTED (adds no
    // weight). UNAUDITED pre-1.0 `ml-dsa`; not a security/finality claim.
    #[cfg(feature = "real-mldsa65")]
    #[test]
    fn default_build_real_mldsa65_finalizes_and_rejects_tamper() {
        // seat k (0-based) has weight 40/30/20/10; signers 0,1 hold 70 of 100.
        let weights = [40u64, 30, 20, 10];
        let signers: Vec<RustCryptoMlDsa65Signer> = (0..weights.len())
            .map(|i| RustCryptoMlDsa65Signer::from_seed([(i as u8) + 1; 32]))
            .collect();
        let validators: Vec<Validator> = weights
            .iter()
            .enumerate()
            .map(|(i, &w)| {
                let mut id = [0u8; 32];
                id[0] = (i as u8) + 1;
                let mut coinbase = [0u8; 20];
                coinbase[0] = (i as u8) + 1;
                Validator {
                    id: ValidatorId(id),
                    coinbase_addr: coinbase,
                    pubkey: signers[i].public_key_bytes(), // genuine 1952-byte key
                    weight: w,
                }
            })
            .collect();
        let set = ValidatorSet::new(
            validators,
            RotationMeta { epoch: 0, window_blocks: 2016, min_share: 0 },
        )
        .unwrap();
        assert_eq!(set.total_weight(), 100);
        let c = checkpoint(&set);
        let message = c.canonical_signing_payload();

        // Genuine real ML-DSA-65 signatures from seats 0,1 (weight 70 > 2/3).
        let votes: Vec<Vote> = [0usize, 1]
            .iter()
            .map(|&s| Vote {
                validator_index: s as u32,
                sig: signers[s].sign(&message).unwrap(),
            })
            .collect();
        assert_eq!(
            verify_finalized(&c, &votes, &set, &RustCryptoMlDsa65Verifier),
            FinalityOutcome::Finalized { covered_weight: 70, total_weight: 100 },
            "genuine real ML-DSA-65 signatures must finalize on a DEFAULT cargo test"
        );

        // Flip a single byte of seat 1's signature: real verify must reject it,
        // so weight drops to 40 and the quorum is NOT reached.
        let mut tampered = votes.clone();
        tampered[1].sig[0] ^= 0x01;
        assert_eq!(
            verify_finalized(&c, &tampered, &set, &RustCryptoMlDsa65Verifier),
            FinalityOutcome::NotFinalized { covered_weight: 40, total_weight: 100 },
            "a single-byte-mutated ML-DSA-65 signature must be REJECTED by default"
        );
    }
}
