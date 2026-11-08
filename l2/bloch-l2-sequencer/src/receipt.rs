// SPDX-License-Identifier: MIT OR Apache-2.0
//! Signed inclusion receipt (§4): "the sequencer returns a signed inclusion
//! receipt `{tx_hash, seq_no, soft_block, timestamp, sig}` for every accepted
//! tx, making its FIFO promise after-the-fact auditable against published
//! batches (detection, not prevention)".
//!
//! UNAUDITED, single disclosed operator. This crate carries a REAL
//! disclosed-sequencer-key signature over the deterministic signing payload
//! using **post-quantum ML-DSA-65 (FIPS 204)** — the SAME primitive the
//! `postern-bft-finality` (BFT) and `ffg` crates use, via the RustCrypto
//! `ml-dsa` crate. It sits behind the [`ReceiptSigScheme`] trait so the receipt
//! shape and the domain-separated payload are scheme-agnostic, but the ONLY
//! scheme shipped here is PQ ML-DSA-65 (NO BLS, NO classical curve): the whole
//! Bloch stack is post-quantum, so the sequencer's disclosed-operator receipt
//! signature is too.
//!
//! Trust model: there is exactly ONE operator and its verifying key is
//! disclosed/pinned out of band. A valid signature proves the receipt came
//! from that operator and that no field was altered after signing — it is
//! detection (auditable FIFO promise), NOT prevention of reordering, and NOT
//! finality. `soft_block` remains a 2 s pre-confirmation, not a settled block.
//!
//! The `ml-dsa` crate is **UNAUDITED, pre-1.0 (`0.1.1`)** RustCrypto; wiring a
//! real primitive does not make this crate secure, audited, operational, or
//! deployed. Seed-derived keys below are for deterministic tests / reproducible
//! offline key loading ONLY — real operator keys must come from a CSPRNG and be
//! held in real custody. `designed != built != booted`.

use core::fmt;

/// Domain separator prepended to the signing payload.
pub const RECEIPT_DOMAIN: &[u8; 16] = b"BLOCH-L2-RCPT-0\0";

/// A sequencer inclusion receipt. `sig` is empty until signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InclusionReceipt {
    pub tx_hash: [u8; 32],
    /// Pool arrival sequence number — the FIFO position being promised.
    pub seq_no: u64,
    /// The soft (2 s, pre-confirmation, NOT finality) block number.
    pub soft_block: u64,
    /// Sequencer receipt time, unix seconds (self-reported — §4: auditable
    /// after the fact, not preventable).
    pub timestamp: u64,
    /// Detached signature bytes over [`InclusionReceipt::signing_payload`].
    /// Empty until signed; scheme-specific length (3309 bytes for ML-DSA-65).
    pub sig: Vec<u8>,
}

impl InclusionReceipt {
    /// An unsigned receipt (empty `sig`).
    pub fn unsigned(tx_hash: [u8; 32], seq_no: u64, soft_block: u64, timestamp: u64) -> Self {
        Self {
            tx_hash,
            seq_no,
            soft_block,
            timestamp,
            sig: Vec::new(),
        }
    }

    /// The exact bytes a sequencer key must sign:
    /// `RECEIPT_DOMAIN ‖ tx_hash ‖ seq_no LE ‖ soft_block LE ‖ timestamp LE`.
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + 32 + 8 + 8 + 8);
        out.extend_from_slice(RECEIPT_DOMAIN);
        out.extend_from_slice(&self.tx_hash);
        out.extend_from_slice(&self.seq_no.to_le_bytes());
        out.extend_from_slice(&self.soft_block.to_le_bytes());
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        out
    }

    /// Attach raw signature bytes without checking them. Prefer
    /// [`InclusionReceipt::sign`], which computes them from the payload.
    pub fn with_signature(mut self, sig: Vec<u8>) -> Self {
        self.sig = sig;
        self
    }

    /// Sign this receipt with the operator's disclosed key, populating `sig`
    /// with a real signature over [`InclusionReceipt::signing_payload`].
    pub fn sign<S: ReceiptSigScheme>(mut self, key: &S::SigningKey) -> Self {
        self.sig = S::sign(key, &self.signing_payload());
        self
    }

    /// Verify `sig` against the operator's disclosed verifying key over the
    /// current payload. Returns `false` for an empty/short/forged signature OR
    /// if ANY field was mutated after signing (the payload no longer matches).
    pub fn verify<S: ReceiptSigScheme>(&self, key: &S::VerifyingKey) -> bool {
        if self.sig.is_empty() {
            return false;
        }
        S::verify(key, &self.signing_payload(), &self.sig)
    }

    pub fn is_signed(&self) -> bool {
        !self.sig.is_empty()
    }
}

/// A signature scheme usable for inclusion receipts. Object-safe-friendly split
/// of signing- and verifying-key types keeps the exact same receipt payload and
/// verification call site regardless of the concrete primitive. The only scheme
/// shipped is post-quantum [`MlDsa65Scheme`].
pub trait ReceiptSigScheme {
    /// Secret operator key material.
    type SigningKey;
    /// Public, disclosed operator key material.
    type VerifyingKey;
    /// Stable identifier for the scheme (goes in disclosures/logs).
    const SCHEME_ID: &'static str;

    /// Produce a detached signature over `msg`.
    fn sign(key: &Self::SigningKey, msg: &[u8]) -> Vec<u8>;
    /// Return `true` iff `sig` is a valid signature by `key` over `msg`.
    fn verify(key: &Self::VerifyingKey, msg: &[u8], sig: &[u8]) -> bool;
}

// --------------------------------------------------------------------------
// ML-DSA-65 scheme — the disclosed-operator scheme (post-quantum, FIPS 204).
// Same RustCrypto `ml-dsa` primitive as the BFT/FFG crates. NO BLS, NO curve.
// --------------------------------------------------------------------------

pub use mldsa::{MlDsa65Scheme, MlDsa65SigningKey, MlDsa65VerifyingKey};

mod mldsa {
    use super::ReceiptSigScheme;
    use ml_dsa::signature::Verifier as _;
    use ml_dsa::{
        EncodedSignature, EncodedVerifyingKey, ExpandedSigningKey, MlDsa65, Seed,
        Signature as InnerSignature, VerifyingKey,
    };

    /// The operator's secret sequencer key (expanded ML-DSA-65 signing key).
    #[derive(Clone)]
    pub struct MlDsa65SigningKey(ExpandedSigningKey<MlDsa65>);

    /// The operator's disclosed public sequencer key (pinned out of band),
    /// held as its canonical FIPS-204 encoded bytes (1952 bytes).
    #[derive(Clone, PartialEq, Eq)]
    pub struct MlDsa65VerifyingKey(Vec<u8>);

    impl MlDsa65SigningKey {
        /// Construct from a 32-byte seed. Deterministic: the same seed always
        /// yields the same operator identity (used for reproducible tests and
        /// for loading a key persisted as a raw seed).
        ///
        /// **Test/loader-only key handling:** a real operator key must be drawn
        /// from a CSPRNG and held in real custody — never a fixed seed.
        pub fn from_seed(seed: &[u8; 32]) -> Self {
            let seed: Seed = (*seed).into();
            Self(ExpandedSigningKey::<MlDsa65>::from_seed(&seed))
        }

        /// The matching disclosed verifying key to publish.
        pub fn verifying_key(&self) -> MlDsa65VerifyingKey {
            MlDsa65VerifyingKey(self.0.verifying_key().encode().to_vec())
        }
    }

    impl MlDsa65VerifyingKey {
        /// The FIPS-204 encoding (1952 bytes) an auditor pins.
        pub fn to_bytes(&self) -> Vec<u8> {
            self.0.clone()
        }

        /// Parse a disclosed key from its FIPS-204 bytes; rejects any input
        /// that is not a well-formed ML-DSA-65 verifying key (wrong length or
        /// non-decodable), returning `None` instead of panicking.
        pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
            let encoded = EncodedVerifyingKey::<MlDsa65>::try_from(bytes).ok()?;
            // Decode to confirm the bytes are a genuine, canonical key.
            let _vk = VerifyingKey::<MlDsa65>::decode(&encoded);
            Some(MlDsa65VerifyingKey(bytes.to_vec()))
        }
    }

    /// ML-DSA-65 (FIPS 204) over the receipt payload, deterministic signing
    /// (empty context string), backed by the RustCrypto `ml-dsa` crate.
    ///
    /// UNAUDITED integration of an UNAUDITED (pre-1.0) primitive. Post-quantum;
    /// no BLS, no classical curve — the same scheme the BFT/FFG overlays use.
    pub struct MlDsa65Scheme;

    impl ReceiptSigScheme for MlDsa65Scheme {
        type SigningKey = MlDsa65SigningKey;
        type VerifyingKey = MlDsa65VerifyingKey;
        const SCHEME_ID: &'static str = "ml-dsa-65";

        fn sign(key: &Self::SigningKey, msg: &[u8]) -> Vec<u8> {
            // Deterministic signing with an empty context string. Returns the
            // FIPS-204-encoded detached signature bytes. On the (unreachable
            // for a well-formed message) primitive failure, emit an empty sig,
            // which `verify` rejects — never panic.
            match key.0.sign_deterministic(msg, b"") {
                Ok(sig) => sig.encode().to_vec(),
                Err(_) => Vec::new(),
            }
        }

        fn verify(key: &Self::VerifyingKey, msg: &[u8], sig: &[u8]) -> bool {
            // Total, never panics: every decode failure is a rejection.
            let Ok(encoded_vk) = EncodedVerifyingKey::<MlDsa65>::try_from(key.0.as_slice()) else {
                return false;
            };
            let vk = VerifyingKey::<MlDsa65>::decode(&encoded_vk);

            let Ok(encoded_sig) = EncodedSignature::<MlDsa65>::try_from(sig) else {
                return false; // wrong length ⇒ reject
            };
            let Some(signature) = InnerSignature::<MlDsa65>::decode(&encoded_sig) else {
                return false;
            };

            vk.verify(msg, &signature).is_ok()
        }
    }
}

impl fmt::Debug for MlDsa65SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MlDsa65SigningKey(<secret>)")
    }
}

impl fmt::Debug for MlDsa65VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MlDsa65VerifyingKey(<ml-dsa-65 pubkey>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ML-DSA-65 FIPS-204 sizes (RustCrypto `ml-dsa` 0.1.1).
    const ML_DSA_65_SIG_LEN: usize = 3309;
    const ML_DSA_65_PK_LEN: usize = 1952;

    fn test_key() -> MlDsa65SigningKey {
        // Fixed seed ⇒ deterministic operator identity for reproducible tests.
        // (Never do this for a real operator key.)
        MlDsa65SigningKey::from_seed(&[7u8; 32])
    }

    #[test]
    fn signing_payload_is_deterministic_and_field_sensitive() {
        let r = InclusionReceipt::unsigned([9; 32], 42, 7, 1_700_000_000);
        let p = r.signing_payload();
        assert_eq!(p.len(), 16 + 32 + 8 + 8 + 8);
        assert_eq!(&p[..16], RECEIPT_DOMAIN);
        assert_eq!(p, r.signing_payload());

        let mut r2 = r.clone();
        r2.seq_no = 43;
        assert_ne!(p, r2.signing_payload());
        let mut r3 = r.clone();
        r3.soft_block = 8;
        assert_ne!(p, r3.signing_payload());
    }

    #[test]
    fn sign_verify_round_trip() {
        let sk = test_key();
        let vk = sk.verifying_key();

        let receipt =
            InclusionReceipt::unsigned([0xab; 32], 42, 7, 1_700_000_000).sign::<MlDsa65Scheme>(&sk);

        assert!(receipt.is_signed());
        assert_eq!(
            receipt.sig.len(),
            ML_DSA_65_SIG_LEN,
            "ML-DSA-65 signatures are 3309 bytes"
        );
        assert!(
            receipt.verify::<MlDsa65Scheme>(&vk),
            "freshly signed receipt must verify"
        );
    }

    #[test]
    fn tampering_any_field_is_rejected() {
        let sk = test_key();
        let vk = sk.verifying_key();
        let signed =
            InclusionReceipt::unsigned([0xab; 32], 42, 7, 1_700_000_000).sign::<MlDsa65Scheme>(&sk);
        assert!(signed.verify::<MlDsa65Scheme>(&vk));

        // Mutate each authenticated field in turn; every mutation invalidates.
        let mut t = signed.clone();
        t.tx_hash[0] ^= 0x01;
        assert!(!t.verify::<MlDsa65Scheme>(&vk), "tx_hash tamper must fail");

        let mut t = signed.clone();
        t.seq_no += 1;
        assert!(!t.verify::<MlDsa65Scheme>(&vk), "seq_no tamper must fail");

        let mut t = signed.clone();
        t.soft_block += 1;
        assert!(!t.verify::<MlDsa65Scheme>(&vk), "soft_block tamper must fail");

        let mut t = signed.clone();
        t.timestamp += 1;
        assert!(!t.verify::<MlDsa65Scheme>(&vk), "timestamp tamper must fail");

        // Mutating the signature itself is also rejected.
        let mut t = signed.clone();
        t.sig[0] ^= 0x01;
        assert!(!t.verify::<MlDsa65Scheme>(&vk), "sig tamper must fail");
    }

    #[test]
    fn wrong_operator_key_is_rejected() {
        let sk = test_key();
        let other = MlDsa65SigningKey::from_seed(&[8u8; 32]);
        let signed = InclusionReceipt::unsigned([1; 32], 0, 0, 0).sign::<MlDsa65Scheme>(&sk);
        // Correct operator verifies, a different operator does not.
        assert!(signed.verify::<MlDsa65Scheme>(&sk.verifying_key()));
        assert!(!signed.verify::<MlDsa65Scheme>(&other.verifying_key()));
    }

    #[test]
    fn unsigned_and_malformed_signatures_do_not_verify() {
        let sk = test_key();
        let vk = sk.verifying_key();

        let unsigned = InclusionReceipt::unsigned([1; 32], 0, 0, 0);
        assert!(!unsigned.is_signed());
        assert!(!unsigned.verify::<MlDsa65Scheme>(&vk), "empty sig must fail");

        // Wrong-length signature bytes are rejected, not panicked on.
        let bogus = InclusionReceipt::unsigned([1; 32], 0, 0, 0).with_signature(vec![0xde, 0xad]);
        assert!(!bogus.verify::<MlDsa65Scheme>(&vk));

        // A full-length-but-forged signature is also rejected.
        let forged = InclusionReceipt::unsigned([1; 32], 0, 0, 0)
            .with_signature(vec![0u8; ML_DSA_65_SIG_LEN]);
        assert!(!forged.verify::<MlDsa65Scheme>(&vk));
    }

    #[test]
    fn disclosed_key_round_trips_through_bytes() {
        let sk = test_key();
        let vk = sk.verifying_key();
        let bytes = vk.to_bytes();
        assert_eq!(
            bytes.len(),
            ML_DSA_65_PK_LEN,
            "ML-DSA-65 public keys are 1952 bytes"
        );
        let reparsed = MlDsa65VerifyingKey::from_bytes(&bytes).expect("canonical key");
        assert_eq!(vk, reparsed);
        assert_eq!(MlDsa65Scheme::SCHEME_ID, "ml-dsa-65");

        // A signature made under the original key verifies under the reparsed
        // (byte-round-tripped) disclosed key — proving the pinned bytes are the
        // real operator identity.
        let signed = InclusionReceipt::unsigned([0x5a; 32], 9, 3, 42).sign::<MlDsa65Scheme>(&sk);
        assert!(signed.verify::<MlDsa65Scheme>(&reparsed));

        // Garbage / wrong-length pubkey bytes are rejected.
        assert!(MlDsa65VerifyingKey::from_bytes(&[0u8; 10]).is_none());
    }

    #[test]
    fn signing_is_deterministic() {
        // Deterministic ML-DSA signing: the same key over the same payload
        // yields byte-identical signatures (reproducible receipts).
        let sk = test_key();
        let a = InclusionReceipt::unsigned([3; 32], 5, 2, 100).sign::<MlDsa65Scheme>(&sk);
        let b = InclusionReceipt::unsigned([3; 32], 5, 2, 100).sign::<MlDsa65Scheme>(&sk);
        assert_eq!(a.sig, b.sig, "deterministic signing must be reproducible");
    }
}
