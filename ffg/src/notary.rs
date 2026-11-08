// SPDX-License-Identifier: MIT OR Apache-2.0
//! The in-process notary pipeline: per epoch, read the base, assemble a
//! checkpoint, collect operator signatures, check quorum, anchor the
//! certificate hash, and track SoftJustified → HardNotarized promotion.
//!
//! # SCAFFOLD — not a secure or deployed system
//!
//! [`NotaryService`] is a **reference of the notary's shape**, all in-process
//! and deterministic: it drives the existing trait seams
//! ([`BlochAnchorClient`], [`CheckpointSigner`], [`MlDsa65Verifier`]) end to
//! end against the in-memory mock base. **Nothing here is operational,
//! deployed, audited, or secure.** In particular:
//!
//! - **Trust model is still "trust Postern."** All signer seats are one trust
//!   domain; quorum here is operational robustness, never BFT. A
//!   `QuorumReached` outcome is a **Postern attestation, never finality**.
//! - **HardNotarized promotion exists in code but confers NOTHING.** Two
//!   consecutive justified epochs flip a label in this service's local
//!   records — exactly what [`ConfidenceLevel::HardNotarized`] documents. The
//!   base beneath it is `k=4` forgeable and `51%`-attackable; the
//!   [`NotaryEvent::BaseReorgObserved`] event below is the code-level proof
//!   that a checkpoint is *a Postern attestation, not settlement finality*.
//! - **The offline stub build can never reach quorum.** Under
//!   `--no-default-features`, with the
//!   [`NonSigningStubSigner`](crate::signature::NonSigningStubSigner) and
//!   [`NonVerifyingStubVerifier`](crate::signature::NonVerifyingStubVerifier),
//!   every epoch ends in [`NotaryEvent::QuorumNotReached`] — that invariant is
//!   asserted by this module's `offline_stub_pipeline_never_reaches_quorum`
//!   test. A **default** build wires the real (UNAUDITED, pre-1.0) ML-DSA-65
//!   primitives and reaches genuine quorum in `real_mldsa65_tests`.
//! - **Blocked-on-infra/audit (out of scope here):** talking to a real Bloch
//!   node RPC instead of the in-memory mock, real operator key custody/HSMs,
//!   any deployed or operated signer set, and independent audit of every
//!   crypto primitive involved. The trait seams above are where real
//!   implementations would plug in later.

use crate::anchor::{AnchorCommitment, AnchorError, AnchorReceipt, BlochAnchorClient};
use crate::certificate::CheckpointCertificate;
use crate::checkpoint::{
    CheckpointError, ConfidenceLevel, HeightRange, OperatorSignature, PosternNotaryCheckpoint,
    QuorumOutcome,
};
use crate::operator::{Era, PermissionedOperatorSet};
use crate::signature::{CheckpointSigner, MlDsa65Verifier, SignatureError};

/// One in-process signer seat: the operator UID it signs as, plus its signer.
///
/// SCAFFOLD: in a real deployment a "seat" is an operated machine with real
/// key custody (blocked-on-infra). Here it is a struct in a `Vec`.
#[derive(Debug)]
pub struct SignerSeat<S: CheckpointSigner> {
    /// UID of the operator this seat signs as (must be in the operator set).
    pub operator_uid: [u8; 32],
    /// The seat's signer implementation.
    pub signer: S,
}

/// A locally-recorded, anchored checkpoint certificate.
///
/// The `certificate` is byte-identical to what was hashed and anchored (it
/// records `confidence: SoftJustified`, the level the operators signed).
/// `confidence` below is the **service's local view**, which promotion may
/// later flip to [`ConfidenceLevel::HardNotarized`] — a local label only,
/// conferring nothing (see the module docs). The anchored bytes never change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotarizedRecord {
    /// Epoch index in which this certificate was produced.
    pub epoch: u64,
    /// The certificate whose hash was anchored.
    pub certificate: CheckpointCertificate,
    /// The base receipt for the anchored certificate hash.
    pub receipt: AnchorReceipt,
    /// The service's current local confidence label for this record.
    pub confidence: ConfidenceLevel,
}

/// Events emitted by one [`NotaryService::run_epoch`] pass.
///
/// Every variant is an *observation or attestation by Postern's own service*
/// about a forgeable base — none of them is, or ever becomes, a settlement
/// guarantee (see [`ConfidenceLevel::honest_caveat`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotaryEvent {
    /// A quorum of seats signed this epoch's checkpoint: it is **soft
    /// justified** — a Postern attestation, not settlement finality.
    SoftJustified {
        /// Epoch that was justified.
        epoch: u64,
        /// Base height range the checkpoint covers.
        height_range: HeightRange,
        /// SHAKE-256-32 hash of the certificate (the anchored commitment).
        certificate_hash: AnchorCommitment,
    },
    /// The certificate hash was written onto the base as an ordinary
    /// transaction commitment (no privilege, no reserved namespace).
    CertificateAnchored {
        /// Epoch whose certificate was anchored.
        epoch: u64,
        /// The base receipt.
        receipt: AnchorReceipt,
    },
    /// Two consecutive justified epochs: the earlier record's local label was
    /// promoted to [`ConfidenceLevel::HardNotarized`]. **This exists in code
    /// but confers nothing** — still a Postern attestation about a forgeable
    /// base, never irreversibility.
    HardNotarizedPromoted {
        /// Epoch of the record that was promoted.
        promoted_epoch: u64,
        /// The later epoch whose justification triggered the promotion.
        by_epoch: u64,
    },
    /// Fewer than `threshold` signatures verified this epoch. The justified
    /// streak resets; nothing is anchored. (Under `--no-default-features` this
    /// is the ONLY terminal outcome — the offline stubs never verify.)
    QuorumNotReached {
        /// Epoch that failed to justify.
        epoch: u64,
        /// How many signatures verified.
        valid: usize,
        /// The quorum threshold that was not met.
        threshold: usize,
    },
    /// The base's current header at an already-notarized height no longer
    /// matches what was notarized: **the base reorged beneath a checkpoint.**
    ///
    /// This event is the code-level proof of the crate's central honesty
    /// rail: a checkpoint — even a HardNotarized one — is *a Postern
    /// attestation, not settlement finality*. The service can only observe
    /// and report the reorg; it cannot prevent or undo it.
    BaseReorgObserved {
        /// Epoch of the notarized record that was contradicted.
        notarized_epoch: u64,
        /// The base height at which the mismatch was observed.
        base_height: u64,
        /// The block hash the notarized checkpoint attested to.
        notarized_hash: [u8; 32],
        /// The hash now observed at that height (`None`: the height itself
        /// vanished from the base view).
        observed_hash: Option<[u8; 32]>,
        /// The record's local confidence label at observation time — showing
        /// that even `HardNotarized` does not survive a base reorg.
        confidence: ConfidenceLevel,
    },
}

/// Errors from the notary pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotaryError {
    /// A seat's operator UID is not a member of the operator set.
    SeatNotInOperatorSet {
        /// The offending UID.
        uid: [u8; 32],
    },
    /// No signer seats were supplied.
    NoSeats,
    /// The base tip has not advanced past the next uncovered height, so
    /// there is nothing for a new checkpoint to cover.
    NoNewBaseBlocks {
        /// First height the next checkpoint would need to cover.
        next_start: u64,
        /// The observed base tip height.
        tip: u64,
    },
    /// An anchoring-client error surfaced during the epoch run.
    Anchor(AnchorError),
    /// A checkpoint-layer error surfaced during the epoch run.
    Checkpoint(CheckpointError),
    /// A signature-layer error surfaced while collecting signatures.
    Signature(SignatureError),
}

impl From<AnchorError> for NotaryError {
    fn from(e: AnchorError) -> Self {
        NotaryError::Anchor(e)
    }
}

impl From<CheckpointError> for NotaryError {
    fn from(e: CheckpointError) -> Self {
        NotaryError::Checkpoint(e)
    }
}

impl From<SignatureError> for NotaryError {
    fn from(e: SignatureError) -> Self {
        NotaryError::Signature(e)
    }
}

impl core::fmt::Display for NotaryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            NotaryError::SeatNotInOperatorSet { uid } => {
                write!(f, "signer seat uid {:02x?}.. is not in the operator set", &uid[..4])
            }
            NotaryError::NoSeats => write!(f, "no signer seats supplied"),
            NotaryError::NoNewBaseBlocks { next_start, tip } => {
                write!(f, "no new base blocks: next checkpoint starts at {next_start}, tip is {tip}")
            }
            NotaryError::Anchor(e) => write!(f, "anchor error: {e}"),
            NotaryError::Checkpoint(e) => write!(f, "checkpoint error: {e}"),
            NotaryError::Signature(e) => write!(f, "signature error: {e}"),
        }
    }
}

impl std::error::Error for NotaryError {}

/// The in-process reference notary service. See the module docs for every
/// rail; in one line: **this is the shape of the pipeline, not the pipeline.**
#[derive(Debug)]
pub struct NotaryService<S: CheckpointSigner, V: MlDsa65Verifier> {
    operator_set: PermissionedOperatorSet,
    seats: Vec<SignerSeat<S>>,
    verifier: V,
    era: Era,
    epoch: u64,
    next_start: u64,
    justified_streak: usize,
    records: Vec<NotarizedRecord>,
}

impl<S: CheckpointSigner, V: MlDsa65Verifier> NotaryService<S, V> {
    /// Build a service over an operator set, a set of in-process signer
    /// seats, a verifier, and the first base height to notarize from.
    ///
    /// Every seat's UID must belong to the operator set (a seat signing as a
    /// non-member could never count toward quorum anyway — reject early).
    pub fn new(
        operator_set: PermissionedOperatorSet,
        seats: Vec<SignerSeat<S>>,
        verifier: V,
        first_height: u64,
    ) -> Result<Self, NotaryError> {
        if seats.is_empty() {
            return Err(NotaryError::NoSeats);
        }
        for seat in &seats {
            if operator_set.operator_by_uid(&seat.operator_uid).is_none() {
                return Err(NotaryError::SeatNotInOperatorSet { uid: seat.operator_uid });
            }
        }
        Ok(Self {
            operator_set,
            seats,
            verifier,
            era: Era::genesis(),
            epoch: 0,
            next_start: first_height,
            justified_streak: 0,
            records: Vec::new(),
        })
    }

    /// Run one epoch of the pipeline against `client`:
    ///
    /// 1. **Reorg scan** — re-read the base header under every recorded
    ///    checkpoint; any hash mismatch (or vanished height) emits
    ///    [`NotaryEvent::BaseReorgObserved`].
    /// 2. **Read** the canonical tip and assemble a checkpoint over the
    ///    heights since the last justified one.
    /// 3. **Sign** — every in-process seat signs the canonical payload.
    /// 4. **Quorum** — [`PosternNotaryCheckpoint::verify_quorum`] with this
    ///    service's verifier. Below threshold: streak resets, nothing is
    ///    anchored, [`NotaryEvent::QuorumNotReached`]. (Under
    ///    `--no-default-features` every epoch lands here — the offline stubs
    ///    never verify; a default build verifies real ML-DSA-65.)
    /// 5. **Anchor** — on quorum, the certificate hash is written to the base
    ///    as an ordinary commitment and the record is stored SoftJustified.
    /// 6. **Promote** — on the second consecutive justified epoch, the
    ///    previous record's local label becomes HardNotarized (a label that
    ///    confers nothing — see the module docs).
    ///
    /// Deterministic: no RNG, no time — outputs depend only on the operator
    /// set, seats, verifier, and the client's state.
    pub fn run_epoch<C: BlochAnchorClient>(
        &mut self,
        client: &mut C,
    ) -> Result<Vec<NotaryEvent>, NotaryError> {
        let mut events = Vec::new();

        // (1) Reorg scan: honesty first — report contradictions of anything
        // already notarized before producing anything new.
        for record in &self.records {
            let anchor = &record.certificate.checkpoint.base_anchor;
            let observed = client.header_at(anchor.block_height);
            let observed_hash = match observed {
                Ok(header) if header.block_hash == anchor.block_hash => continue,
                Ok(header) => Some(header.block_hash),
                Err(AnchorError::UnknownHeight(_)) => None,
                Err(e) => return Err(e.into()),
            };
            events.push(NotaryEvent::BaseReorgObserved {
                notarized_epoch: record.epoch,
                base_height: anchor.block_height,
                notarized_hash: anchor.block_hash,
                observed_hash,
                confidence: record.confidence,
            });
        }

        // (2) Read the base and assemble the checkpoint for this epoch.
        let tip = client.canonical_tip()?;
        if tip.block_height < self.next_start {
            return Err(NotaryError::NoNewBaseBlocks {
                next_start: self.next_start,
                tip: tip.block_height,
            });
        }
        if !self.era.contains_epoch(self.epoch) {
            self.era = self.era.next();
        }
        // Operators sign the checkpoint *as* SoftJustified: the asserted
        // level is part of the signed payload, and the assertion only stands
        // if quorum is actually reached below — otherwise the object is
        // discarded and nothing is anchored.
        let mut checkpoint = PosternNotaryCheckpoint {
            height_range: HeightRange::new(self.next_start, tip.block_height)?,
            base_anchor: tip.clone(),
            era: self.era.clone(),
            confidence: ConfidenceLevel::SoftJustified,
            signatures: Vec::new(),
        };

        // (3) Collect one signature per in-process seat.
        let payload = checkpoint.canonical_signing_payload();
        for seat in &self.seats {
            checkpoint.signatures.push(OperatorSignature {
                operator_uid: seat.operator_uid,
                signature: seat.signer.sign(&payload)?,
            });
        }

        // (4) Quorum check via the configured verifier. With the real default
        //     ML-DSA-65 verifier a genuine quorum finalizes; with the offline
        //     stub verifier this never reaches quorum.
        let outcome = checkpoint.verify_quorum(&self.operator_set, &self.verifier);
        let epoch = self.epoch;
        self.epoch += 1;
        match outcome {
            QuorumOutcome::BelowThreshold { valid, threshold } => {
                self.justified_streak = 0;
                events.push(NotaryEvent::QuorumNotReached { epoch, valid, threshold });
                return Ok(events);
            }
            QuorumOutcome::QuorumReached { .. } => {}
        }

        // (5) Anchor the certificate hash as an ordinary base commitment.
        let certificate = CheckpointCertificate::new(checkpoint);
        let certificate_hash = certificate.certificate_hash();
        let receipt = client.anchor_commitment(certificate_hash)?;
        events.push(NotaryEvent::SoftJustified {
            epoch,
            height_range: certificate.checkpoint.height_range,
            certificate_hash,
        });
        events.push(NotaryEvent::CertificateAnchored { epoch, receipt: receipt.clone() });
        self.records.push(NotarizedRecord {
            epoch,
            certificate,
            receipt,
            confidence: ConfidenceLevel::SoftJustified,
        });
        self.next_start = tip.block_height + 1;
        self.justified_streak += 1;

        // (6) Casper-style promotion on two consecutive justified epochs —
        // a local label flip that confers nothing (module docs).
        if self.justified_streak >= 2 {
            let idx = self.records.len() - 2;
            if self.records[idx].confidence == ConfidenceLevel::SoftJustified {
                self.records[idx].confidence = ConfidenceLevel::HardNotarized;
                events.push(NotaryEvent::HardNotarizedPromoted {
                    promoted_epoch: self.records[idx].epoch,
                    by_epoch: epoch,
                });
            }
        }

        Ok(events)
    }

    /// All locally-recorded anchored certificates (scaffold introspection;
    /// an independent reader does not need this — see [`crate::follower`]).
    pub fn records(&self) -> &[NotarizedRecord] {
        &self.records
    }

    /// Current consecutive-justified-epoch count.
    pub fn justified_streak(&self) -> usize {
        self.justified_streak
    }

    /// The next epoch index this service will run.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The operator set this service verifies against.
    pub fn operator_set(&self) -> &PermissionedOperatorSet {
        &self.operator_set
    }

    /// Mutable access to the signer seats (scaffold introspection: lets
    /// deterministic tests simulate seat outages / an unjustified epoch —
    /// there is no runtime seat-management story here, that is
    /// blocked-on-infra).
    pub fn seats_mut(&mut self) -> &mut Vec<SignerSeat<S>> {
        &mut self.seats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anchor::InMemoryAnchorClient;
    use crate::checkpoint::BaseAnchorRef;
    use crate::operator::{Operator, OperatorIdentity};
    use crate::signature::{
        MlDsa65PublicKey, NonSigningStubSigner, NonVerifyingStubVerifier,
        ML_DSA_65_PUBLIC_KEY_LEN,
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

    fn stub_seat(seed: u8) -> SignerSeat<NonSigningStubSigner> {
        let mut uid = [0u8; 32];
        uid[0] = seed;
        SignerSeat { operator_uid: uid, signer: NonSigningStubSigner { fill: seed } }
    }

    fn header(h: u64) -> BaseAnchorRef {
        BaseAnchorRef {
            block_height: h,
            block_hash: [h as u8; 32],
            accumulated_work: h as u128 * 10,
        }
    }

    fn stub_service() -> NotaryService<NonSigningStubSigner, NonVerifyingStubVerifier> {
        let set = PermissionedOperatorSet::new((1..=3).map(operator).collect(), 2).unwrap();
        NotaryService::new(
            set,
            (1..=3).map(stub_seat).collect(),
            NonVerifyingStubVerifier,
            100,
        )
        .unwrap()
    }

    #[test]
    fn seats_must_belong_to_the_operator_set() {
        let set = PermissionedOperatorSet::new((1..=3).map(operator).collect(), 2).unwrap();
        let err = NotaryService::new(set.clone(), vec![stub_seat(9)], NonVerifyingStubVerifier, 0);
        assert!(matches!(err, Err(NotaryError::SeatNotInOperatorSet { .. })));

        let err = NotaryService::<NonSigningStubSigner, _>::new(
            set,
            Vec::new(),
            NonVerifyingStubVerifier,
            0,
        );
        assert!(matches!(err, Err(NotaryError::NoSeats)));
    }

    /// THE standing `--no-default-features` (offline-stub) invariant, asserted
    /// explicitly at the pipeline level: with the zero-dependency stub signer +
    /// stub verifier, quorum is NEVER reached — every epoch ends
    /// `QuorumNotReached` with `valid == 0`, nothing is ever anchored, no record
    /// is ever produced, and no confidence level is ever promoted. (A default
    /// build wires the real ML-DSA-65 primitives; see the `real_mldsa65_tests`
    /// pipeline test below for the genuine-quorum path.)
    #[test]
    fn offline_stub_pipeline_never_reaches_quorum() {
        let mut service = stub_service();
        let mut client = InMemoryAnchorClient::new();

        for h in 100..=112 {
            client.push_header(header(h));
        }
        for expected_epoch in 0..4u64 {
            // Keep the tip advancing so every epoch has heights to cover.
            client.push_header(header(113 + expected_epoch));
            let events = service.run_epoch(&mut client).unwrap();
            assert_eq!(
                events,
                vec![NotaryEvent::QuorumNotReached { epoch: expected_epoch, valid: 0, threshold: 2 }],
                "the stub primitives must never verify a signature"
            );
        }
        assert!(service.records().is_empty(), "nothing may ever be notarized by a stub build");
        assert!(client.anchored().is_empty(), "nothing may ever be anchored by a stub build");
        assert_eq!(service.justified_streak(), 0);
    }

    #[test]
    fn epoch_without_new_base_blocks_is_reported() {
        let mut service = stub_service();
        let mut client = InMemoryAnchorClient::new();
        client.push_header(header(99)); // below the service's first_height=100
        assert_eq!(
            service.run_epoch(&mut client),
            Err(NotaryError::NoNewBaseBlocks { next_start: 100, tip: 99 })
        );
    }
}

/// Deterministic end-to-end pipeline tests with **real** ML-DSA-65 signers
/// and verifier. These run on a default `cargo test` (`real-mldsa65` is ON by
/// default); only `--no-default-features` compiles them out.
///
/// A green run here proves the *plumbing* — sign, quorum-count, hash, anchor,
/// promote, observe-reorg, re-verify — against real (but UNAUDITED, pre-1.0)
/// crypto. It is not, and never becomes, a claim that anything is secure,
/// operational, audited, or deployed; the committee is still one trust domain
/// ("trust Postern") and the mock base is still a `Vec` of headers.
#[cfg(all(test, feature = "real-mldsa65"))]
mod real_mldsa65_tests {
    use super::*;
    use crate::anchor::InMemoryAnchorClient;
    use crate::checkpoint::BaseAnchorRef;
    use crate::follower::{reverify_anchored_certificate, FollowerError};
    use crate::operator::{Operator, OperatorIdentity};
    use crate::signature::{RustCryptoMlDsa65Signer, RustCryptoMlDsa65Verifier};

    fn uid(seed: u8) -> [u8; 32] {
        let mut uid = [0u8; 32];
        uid[0] = seed;
        uid
    }

    /// Deterministic real operator + matching signer seat for seed byte `i`
    /// (seeded keys are test-only; real custody is blocked-on-infra).
    fn real_operator_and_seat(i: u8) -> (Operator, SignerSeat<RustCryptoMlDsa65Signer>) {
        let signer = RustCryptoMlDsa65Signer::from_seed([i; 32]);
        let op = Operator {
            identity: OperatorIdentity {
                uid: uid(i),
                jurisdiction: *b"US",
                client_version: "scaffold-0".into(),
                registered_at_block: 1,
            },
            public_key: signer.public_key(),
        };
        (op, SignerSeat { operator_uid: uid(i), signer })
    }

    fn header(h: u64) -> BaseAnchorRef {
        BaseAnchorRef {
            block_height: h,
            block_hash: [h as u8; 32],
            accumulated_work: h as u128 * 10,
        }
    }

    /// 5 operators, threshold 3, but only 3 in-process signer seats: a
    /// 3-of-5 quorum, exactly at the threshold.
    fn service_3_of_5() -> NotaryService<RustCryptoMlDsa65Signer, RustCryptoMlDsa65Verifier> {
        let mut operators = Vec::new();
        let mut seats = Vec::new();
        for i in 1..=5u8 {
            let (op, seat) = real_operator_and_seat(i);
            operators.push(op);
            if i <= 3 {
                seats.push(seat);
            }
        }
        let set = PermissionedOperatorSet::new(operators, 3).unwrap();
        NotaryService::new(set, seats, RustCryptoMlDsa65Verifier, 100).unwrap()
    }

    fn client_with_headers(range: core::ops::RangeInclusive<u64>) -> InMemoryAnchorClient {
        let mut client = InMemoryAnchorClient::new();
        for h in range {
            client.push_header(header(h));
        }
        client
    }

    /// (b) A full epoch with 3-of-5 real signers: quorum reached, the
    /// certificate is soft-justified, its hash is anchored, and the receipt's
    /// commitment equals `certificate_hash()`.
    #[test]
    fn full_epoch_reaches_quorum_and_anchors_certificate_hash() {
        let mut service = service_3_of_5();
        let mut client = client_with_headers(100..=110);

        let events = service.run_epoch(&mut client).unwrap();
        assert_eq!(service.records().len(), 1);
        let record = &service.records()[0];
        let expected_hash = record.certificate.certificate_hash();

        assert_eq!(
            events[0],
            NotaryEvent::SoftJustified {
                epoch: 0,
                height_range: HeightRange::new(100, 110).unwrap(),
                certificate_hash: expected_hash,
            }
        );
        assert!(matches!(events[1], NotaryEvent::CertificateAnchored { epoch: 0, .. }));
        assert_eq!(events.len(), 2, "one justified epoch: no promotion, no reorg");

        // The receipt's commitment IS the certificate hash — no truncated
        // payload, no privileged data path, an ordinary base write.
        assert_eq!(record.receipt.commitment, expected_hash);
        assert_eq!(client.anchored().len(), 1);
        assert_eq!(client.anchored()[0].commitment, expected_hash);
        assert_eq!(record.confidence, ConfidenceLevel::SoftJustified);

        // The checkpoint carries exactly the 3 seat signatures and clears
        // the 3-of-5 threshold.
        assert_eq!(record.certificate.checkpoint.signatures.len(), 3);
        assert_eq!(
            record.certificate.checkpoint.verify_quorum(service.operator_set(), &RustCryptoMlDsa65Verifier),
            QuorumOutcome::QuorumReached { valid: 3, threshold: 3 }
        );
    }

    /// (c) Two consecutive justified epochs promote the earlier record to
    /// HardNotarized; a broken (unjustified) epoch resets the streak so the
    /// next justified epoch does NOT promote its (non-consecutive) predecessor.
    #[test]
    fn consecutive_justified_epochs_promote_and_a_broken_epoch_resets() {
        let mut service = service_3_of_5();
        let mut client = client_with_headers(100..=110);

        // Epoch 0: justified (streak 1, nothing to promote).
        let e0 = service.run_epoch(&mut client).unwrap();
        assert!(!e0.iter().any(|e| matches!(e, NotaryEvent::HardNotarizedPromoted { .. })));

        // Epoch 1: justified again -> epoch 0's record promotes.
        client.push_header(header(111));
        let e1 = service.run_epoch(&mut client).unwrap();
        assert!(e1.contains(&NotaryEvent::HardNotarizedPromoted { promoted_epoch: 0, by_epoch: 1 }));
        assert_eq!(service.records()[0].confidence, ConfidenceLevel::HardNotarized);
        assert_eq!(service.records()[1].confidence, ConfidenceLevel::SoftJustified);
        assert_eq!(service.justified_streak(), 2);

        // Epoch 2: BROKEN — simulate a seat outage (2 seats < threshold 3).
        // The streak resets and nothing is anchored.
        client.push_header(header(112));
        let lost_seat = service.seats_mut().pop().unwrap();
        let e2 = service.run_epoch(&mut client).unwrap();
        assert_eq!(
            e2,
            vec![NotaryEvent::QuorumNotReached { epoch: 2, valid: 2, threshold: 3 }]
        );
        assert_eq!(service.justified_streak(), 0);
        assert_eq!(service.records().len(), 2, "an unjustified epoch anchors nothing");

        // Epoch 3: seat restored, justified again — but the streak restarted,
        // so epoch 1's record must NOT be promoted by a non-consecutive epoch.
        service.seats_mut().push(lost_seat);
        client.push_header(header(113));
        let e3 = service.run_epoch(&mut client).unwrap();
        assert!(!e3.iter().any(|e| matches!(e, NotaryEvent::HardNotarizedPromoted { .. })));
        assert_eq!(service.records()[1].confidence, ConfidenceLevel::SoftJustified);
        assert_eq!(service.justified_streak(), 1);

        // Epoch 4: consecutive with epoch 3 -> epoch 3's record promotes now.
        client.push_header(header(114));
        let e4 = service.run_epoch(&mut client).unwrap();
        assert!(e4.contains(&NotaryEvent::HardNotarizedPromoted { promoted_epoch: 3, by_epoch: 4 }));
    }

    /// (d) A simulated base reorg BELOW a HardNotarized checkpoint yields
    /// `BaseReorgObserved` — the code-level proof that a checkpoint is a
    /// Postern attestation, not settlement finality.
    #[test]
    fn base_reorg_below_hard_notarized_checkpoint_is_observed_and_reported() {
        let mut service = service_3_of_5();
        let mut client = client_with_headers(100..=110);

        // Two justified epochs: epoch 0 (anchored at height 110) promotes to
        // HardNotarized.
        service.run_epoch(&mut client).unwrap();
        client.push_header(header(111));
        service.run_epoch(&mut client).unwrap();
        assert_eq!(service.records()[0].confidence, ConfidenceLevel::HardNotarized);

        // Deterministically reorg the base from height 108 — BELOW both
        // notarized checkpoints (heights 110 and 111): same heights, new
        // hashes, and a longer replacement chain.
        let reorged = |h: u64| BaseAnchorRef {
            block_height: h,
            block_hash: [0xEE; 32],
            accumulated_work: h as u128 * 10 + 1,
        };
        client.simulate_reorg_from(108, (108..=115).map(reorged).collect());

        // The next epoch pass observes and reports the contradiction of the
        // HardNotarized record (and of the SoftJustified one).
        let events = service.run_epoch(&mut client).unwrap();
        assert!(events.contains(&NotaryEvent::BaseReorgObserved {
            notarized_epoch: 0,
            base_height: 110,
            notarized_hash: [110u8; 32],
            observed_hash: Some([0xEE; 32]),
            confidence: ConfidenceLevel::HardNotarized,
        }));
        assert!(events.contains(&NotaryEvent::BaseReorgObserved {
            notarized_epoch: 1,
            base_height: 111,
            notarized_hash: [111u8; 32],
            observed_hash: Some([0xEE; 32]),
            confidence: ConfidenceLevel::SoftJustified,
        }));
    }

    /// (e) The independent follower re-verifies anchored certificates with no
    /// privileged access, and rejects both a tampered certificate byte (hash
    /// mismatch against the anchored commitment) and a tampered signature
    /// (quorum not reproduced).
    #[test]
    fn follower_reverifies_and_rejects_tampering() {
        let mut service = service_3_of_5();
        let mut client = client_with_headers(100..=110);
        service.run_epoch(&mut client).unwrap();
        let record = service.records()[0].clone();

        // Anyone with (receipt, certificate, operator set): re-verification
        // succeeds and reproduces the exact quorum.
        assert_eq!(
            reverify_anchored_certificate(
                &record.receipt,
                &record.certificate,
                service.operator_set(),
                &RustCryptoMlDsa65Verifier,
            ),
            Ok(QuorumOutcome::QuorumReached { valid: 3, threshold: 3 })
        );

        // Tampered certificate byte -> the recomputed hash no longer matches
        // the anchored commitment.
        let mut tampered_cert = record.certificate.clone();
        tampered_cert.checkpoint.base_anchor.accumulated_work += 1;
        assert!(matches!(
            reverify_anchored_certificate(
                &record.receipt,
                &tampered_cert,
                service.operator_set(),
                &RustCryptoMlDsa65Verifier,
            ),
            Err(FollowerError::CommitmentMismatch { .. })
        ));

        // Tampered signatures with a MATCHING anchored commitment (an
        // attacker anchoring their own forged certificate): the hash gate
        // passes, but the quorum gate rejects it — below threshold.
        let mut forged_cert = record.certificate.clone();
        let broken = forged_cert.checkpoint.signatures.len() - 1; // keep 2 of 3 valid < threshold 3
        let mut bytes = forged_cert.checkpoint.signatures[broken].signature.as_bytes().to_vec();
        bytes[0] ^= 0x01;
        forged_cert.checkpoint.signatures[broken].signature =
            crate::signature::MlDsa65Signature::from_bytes(bytes).unwrap();
        let forged_receipt = client.anchor_commitment(forged_cert.certificate_hash()).unwrap();
        assert_eq!(
            reverify_anchored_certificate(
                &forged_receipt,
                &forged_cert,
                service.operator_set(),
                &RustCryptoMlDsa65Verifier,
            ),
            Err(FollowerError::QuorumNotReproduced { valid: 2, threshold: 3 })
        );
    }
}
