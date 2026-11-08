// SPDX-License-Identifier: MIT OR Apache-2.0
//! The checkpoint **certificate**: a canonical, deterministic byte encoding of
//! a [`PosternNotaryCheckpoint`] together with its operator signatures, and its
//! SHAKE-256-32 hash — the 32-byte commitment that gets anchored onto the base.
//!
//! # SCAFFOLD — not a secure or deployed system
//!
//! A certificate is the *data object* the notary anchors: the checkpoint plus
//! the individual ML-DSA-65 operator signatures over it. Its hash
//! ([`CheckpointCertificate::certificate_hash`]) is written to the base as an
//! **ordinary transaction commitment** — no reserved namespace, no consensus
//! privilege. Anyone holding the certificate bytes and the operator set can
//! recompute the hash and re-run the quorum check (see [`crate::follower`]);
//! there is no privileged reader.
//!
//! Honesty rails (unchanged from the crate docs):
//!
//! - An anchored certificate is a **Postern attestation about a forgeable
//!   base** (`k=4` / `51%`-attackable, unaudited) — **never settlement
//!   finality**. Trust model is "trust Postern."
//! - The encoding below is a simple length-prefixed, big-endian concatenation.
//!   It is **not** a versioned, audited wire format — a real deployment needs
//!   one (blocked-on-audit).
//! - The hash is the in-crate, **unaudited** SHAKE-256 reimplementation
//!   ([`crate::shake`], reference only).

use crate::anchor::AnchorCommitment;
use crate::checkpoint::PosternNotaryCheckpoint;
use crate::shake::shake256_32;

/// Domain tag prefixed to every certificate encoding, so a certificate hash
/// can never collide with a raw signing-payload hash by construction.
pub const CERTIFICATE_DOMAIN_TAG: &[u8] = b"POSTERN-FFG-NOTARY-CERTIFICATE-v0-SCAFFOLD";

/// A notary checkpoint certificate: the checkpoint plus its operator
/// signatures, as one canonically-encodable object.
///
/// SCAFFOLD: an advisory data object only. Holding (or anchoring the hash of)
/// a certificate confers no settlement guarantee — see the module docs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointCertificate {
    /// The checkpoint, including its `signatures` vector.
    pub checkpoint: PosternNotaryCheckpoint,
}

impl CheckpointCertificate {
    /// Wrap a checkpoint (with whatever signatures it carries) as a
    /// certificate. No validation happens here — quorum validity is checked
    /// separately via [`PosternNotaryCheckpoint::verify_quorum`], and by any
    /// independent follower ([`crate::follower`]).
    pub fn new(checkpoint: PosternNotaryCheckpoint) -> Self {
        Self { checkpoint }
    }

    /// Canonical deterministic byte encoding of the certificate: the domain
    /// tag, the length-prefixed canonical signing payload, then the signature
    /// count and each `(operator_uid, signature)` pair in the checkpoint's
    /// stored order.
    ///
    /// SCAFFOLD: deterministic (no RNG, no time, no maps) but **not** a
    /// versioned, audited wire format — a real deployment needs one.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let payload = self.checkpoint.canonical_signing_payload();
        let mut out = Vec::new();
        out.extend_from_slice(CERTIFICATE_DOMAIN_TAG);
        out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        out.extend_from_slice(&payload);
        out.extend_from_slice(&(self.checkpoint.signatures.len() as u64).to_be_bytes());
        for opsig in &self.checkpoint.signatures {
            out.extend_from_slice(&opsig.operator_uid);
            let sig = opsig.signature.as_bytes();
            out.extend_from_slice(&(sig.len() as u64).to_be_bytes());
            out.extend_from_slice(sig);
        }
        out
    }

    /// The certificate hash: SHAKE-256-32 of [`canonical_bytes`]
    /// (via the in-crate, **unaudited** [`crate::shake`] reimplementation).
    /// This is the 32-byte commitment the notary anchors onto the base.
    ///
    /// A matching anchored commitment proves only that *these bytes* were
    /// committed to — it is a Postern attestation, never settlement finality.
    ///
    /// [`canonical_bytes`]: Self::canonical_bytes
    pub fn certificate_hash(&self) -> AnchorCommitment {
        AnchorCommitment(shake256_32(&self.canonical_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::{
        BaseAnchorRef, ConfidenceLevel, HeightRange, OperatorSignature, PosternNotaryCheckpoint,
    };
    use crate::operator::Era;
    use crate::signature::{MlDsa65Signature, ML_DSA_65_SIGNATURE_LEN};

    fn certificate(sig_seed: u8) -> CheckpointCertificate {
        let mut uid = [0u8; 32];
        uid[0] = sig_seed;
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
                signature: MlDsa65Signature::from_bytes(vec![sig_seed; ML_DSA_65_SIGNATURE_LEN])
                    .unwrap(),
            }],
        })
    }

    #[test]
    fn encoding_is_deterministic() {
        let c = certificate(1);
        assert_eq!(c.canonical_bytes(), c.canonical_bytes());
        assert_eq!(c.certificate_hash(), c.certificate_hash());
    }

    #[test]
    fn encoding_starts_with_domain_tag_and_covers_signatures() {
        let c = certificate(1);
        let bytes = c.canonical_bytes();
        assert!(bytes.starts_with(CERTIFICATE_DOMAIN_TAG));
        // The signature bytes must be inside the encoding (the certificate
        // commits to the signatures, not just the signed payload).
        assert!(bytes.len() > CERTIFICATE_DOMAIN_TAG.len() + ML_DSA_65_SIGNATURE_LEN);
    }

    #[test]
    fn hash_changes_when_any_field_changes() {
        let base = certificate(1);
        let h = base.certificate_hash();

        // Different signature bytes -> different hash.
        assert_ne!(h, certificate(2).certificate_hash());

        // Different checkpoint field -> different hash.
        let mut tampered = base.clone();
        tampered.checkpoint.base_anchor.accumulated_work += 1;
        assert_ne!(h, tampered.certificate_hash());

        // Different confidence -> different hash.
        let mut tampered2 = base.clone();
        tampered2.checkpoint.confidence = ConfidenceLevel::HardNotarized;
        assert_ne!(h, tampered2.certificate_hash());
    }
}
