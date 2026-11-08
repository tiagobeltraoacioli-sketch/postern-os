// SPDX-License-Identifier: MIT OR Apache-2.0
//! Operator finality-signature primitive: **ML-DSA-65 (FIPS 204)**.
//!
//! # SCAFFOLD — not a secure or deployed system
//!
//! This module defines the *interface* around the post-quantum operator
//! signature primitive the design commits to — **ML-DSA-65**, deliberately
//! **NOT BLS**. Per the design (`§3.2`, `§3.8`) BLS12-381 is Shor-breakable and
//! is therefore kept out of the finality path so the certificate is natively
//! post-quantum; DKG/threshold aggregation was shelved this phase (`§3.1`), so
//! each operator emits an **individual** ML-DSA-65 signature (no aggregation).
//!
//! The lattice verify goes through the [`MlDsa65Verifier`] trait, whose
//! **default** implementation is now [`RustCryptoMlDsa65Verifier`] — a **real
//! FIPS-204 verify** backed by the (UNAUDITED, pre-1.0) RustCrypto `ml-dsa`
//! crate, compiled in by default (`real-mldsa65` is ON by default). A default
//! `cargo test` therefore accepts genuine ML-DSA-65 signatures and rejects
//! tampered ones. The [`NonVerifyingStubVerifier`] (which verifies **NOTHING**)
//! remains as the `--no-default-features` offline posture for a crate-free
//! build. Real crypto here is **not** a security claim: a real deployment MUST
//! still supply a FIPS-204-conformant, **independently-audited** implementation.
//! Nothing here is secure.

/// ML-DSA-65 public-key length in bytes (FIPS 204). Design `§3.2`.
pub const ML_DSA_65_PUBLIC_KEY_LEN: usize = 1952;

/// ML-DSA-65 signature length in bytes (FIPS 204). Design `§3.2`.
///
/// Corrected to **3309** (was previously 3293, which is the round-3
/// Dilithium3 signature length, not FIPS 204 final ML-DSA-65). Empirically
/// confirmed against RustCrypto `ml-dsa` 0.1.1, which encodes
/// `vk = 1952` / `sig = 3309` bytes for the ML-DSA-65 parameter set.
pub const ML_DSA_65_SIGNATURE_LEN: usize = 3309;

/// An ML-DSA-65 public key (opaque bytes; length validated on construction).
///
/// SCAFFOLD: this is a byte container only — it performs no cryptographic
/// validation of key structure.
#[derive(Clone, PartialEq, Eq)]
pub struct MlDsa65PublicKey {
    bytes: Vec<u8>,
}

impl MlDsa65PublicKey {
    /// Wrap raw public-key bytes, checking only the expected FIPS-204 length.
    ///
    /// SCAFFOLD: length is the *only* check; key well-formedness is not verified.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, SignatureError> {
        if bytes.len() != ML_DSA_65_PUBLIC_KEY_LEN {
            return Err(SignatureError::BadPublicKeyLength {
                expected: ML_DSA_65_PUBLIC_KEY_LEN,
                got: bytes.len(),
            });
        }
        Ok(Self { bytes })
    }

    /// Borrow the raw key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl core::fmt::Debug for MlDsa65PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MlDsa65PublicKey({} bytes)", self.bytes.len())
    }
}

/// An individual ML-DSA-65 signature over a canonical checkpoint payload.
///
/// SCAFFOLD: byte container only; not validated cryptographically here.
#[derive(Clone, PartialEq, Eq)]
pub struct MlDsa65Signature {
    bytes: Vec<u8>,
}

impl MlDsa65Signature {
    /// Wrap raw signature bytes, checking only the expected FIPS-204 length.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, SignatureError> {
        if bytes.len() != ML_DSA_65_SIGNATURE_LEN {
            return Err(SignatureError::BadSignatureLength {
                expected: ML_DSA_65_SIGNATURE_LEN,
                got: bytes.len(),
            });
        }
        Ok(Self { bytes })
    }

    /// Borrow the raw signature bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl core::fmt::Debug for MlDsa65Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MlDsa65Signature({} bytes)", self.bytes.len())
    }
}

/// Errors from the signature-primitive layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureError {
    /// Public-key byte length did not match [`ML_DSA_65_PUBLIC_KEY_LEN`].
    BadPublicKeyLength { expected: usize, got: usize },
    /// Signature byte length did not match [`ML_DSA_65_SIGNATURE_LEN`].
    BadSignatureLength { expected: usize, got: usize },
    /// The verifier rejected the signature (or, for the stub, always).
    VerificationFailed,
    /// No real verifier is wired in — the stub refuses to assert validity.
    StubRefusesToAssertValidity,
}

impl core::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SignatureError::BadPublicKeyLength { expected, got } => {
                write!(f, "bad ML-DSA-65 public key length: expected {expected}, got {got}")
            }
            SignatureError::BadSignatureLength { expected, got } => {
                write!(f, "bad ML-DSA-65 signature length: expected {expected}, got {got}")
            }
            SignatureError::VerificationFailed => write!(f, "ML-DSA-65 signature verification failed"),
            SignatureError::StubRefusesToAssertValidity => write!(
                f,
                "no real ML-DSA-65 verifier wired in; the scaffold stub refuses to assert validity"
            ),
        }
    }
}

impl std::error::Error for SignatureError {}

/// The operator finality-signature verification interface (ML-DSA-65).
///
/// A real deployment supplies a FIPS-204-conformant, independently-audited
/// implementation. This trait is the single seam the rest of the crate uses so
/// that the post-quantum dependency can be kept out of the scaffold entirely.
///
/// SCAFFOLD: the only implementation shipped here ([`NonVerifyingStubVerifier`])
/// does not verify anything.
pub trait MlDsa65Verifier {
    /// Verify that `signature` is a valid ML-DSA-65 signature by `public_key`
    /// over `message`.
    ///
    /// Real implementations return `Ok(())` only on a cryptographically valid
    /// signature. The scaffold stub NEVER returns `Ok(())`.
    fn verify(
        &self,
        public_key: &MlDsa65PublicKey,
        message: &[u8],
        signature: &MlDsa65Signature,
    ) -> Result<(), SignatureError>;
}

/// A stub verifier that performs **no cryptography** and asserts **nothing**.
///
/// # SCAFFOLD — not a secure or deployed system
///
/// Its [`verify`](MlDsa65Verifier::verify) only checks byte lengths and then
/// returns [`SignatureError::StubRefusesToAssertValidity`]. It is the
/// `--no-default-features` offline posture, letting this scaffold compile with
/// no post-quantum crate; the **default** verifier is now the real
/// [`RustCryptoMlDsa65Verifier`]. Wiring this stub into anything that settles
/// value would be a security defect. Replace it (or the unaudited default) with
/// an independently-audited FIPS-204 implementation before any real use.
#[derive(Debug, Default, Clone, Copy)]
pub struct NonVerifyingStubVerifier;

impl MlDsa65Verifier for NonVerifyingStubVerifier {
    fn verify(
        &self,
        public_key: &MlDsa65PublicKey,
        _message: &[u8],
        signature: &MlDsa65Signature,
    ) -> Result<(), SignatureError> {
        // Length sanity only. Deliberately no cryptographic check.
        if public_key.as_bytes().len() != ML_DSA_65_PUBLIC_KEY_LEN {
            return Err(SignatureError::BadPublicKeyLength {
                expected: ML_DSA_65_PUBLIC_KEY_LEN,
                got: public_key.as_bytes().len(),
            });
        }
        if signature.as_bytes().len() != ML_DSA_65_SIGNATURE_LEN {
            return Err(SignatureError::BadSignatureLength {
                expected: ML_DSA_65_SIGNATURE_LEN,
                got: signature.as_bytes().len(),
            });
        }
        // The stub cannot and will not vouch for validity.
        Err(SignatureError::StubRefusesToAssertValidity)
    }
}

/// A real ML-DSA-65 (FIPS 204) verify primitive backed by the RustCrypto
/// `ml-dsa` crate. It is the **default** [`MlDsa65Verifier`] impl (the
/// `real-mldsa65` feature is ON by default); it is compiled out only under
/// `--no-default-features`.
///
/// # This is real cryptography — it is still not a security claim
///
/// This performs a **real FIPS-204 verify** — unlike
/// [`NonVerifyingStubVerifier`], it will actually reject invalid signatures
/// and accept valid ones. But it is wired through an **UNAUDITED, pre-1.0
/// (`0.1.1`) RustCrypto crate**, and its presence in this crate does **NOT**
/// make the system secure, audited, operational, or deployed.
///
/// The trust model this verifier plugs into is unchanged and is still
/// **"trust Postern"**: a centralized, permissioned, Postern-operated
/// checkpoint service — **NOT** BFT, **NOT** decentralized, **NOT**
/// trustless, **NOT** permissionless. There is **no signature aggregation
/// and no DKG/threshold scheme** — that was deliberately shelved this phase
/// (see the crate- and module-level docs); each operator emits and is
/// verified on an **individual** ML-DSA-65 signature, one call to
/// [`verify`](MlDsa65Verifier::verify) at a time. And the Bloch-SIS-PoW base
/// that any checkpoint built on this verifier would anchor to is still
/// `k=4`, **trivially forgeable**, and `51%`-attackable **today**.
/// Compiling this in changes none of that.
///
/// Default builds (`cargo test`, `cargo build` with no `--features`) wire in
/// this type as the real default verifier. It, its impl, and the `ml-dsa`
/// dependency are compiled out of the artifact **only** under
/// `--no-default-features`, where [`NonVerifyingStubVerifier`] (verifies
/// nothing) takes over as the offline, zero-dependency posture.
#[cfg(feature = "real-mldsa65")]
#[derive(Debug, Default, Clone, Copy)]
pub struct RustCryptoMlDsa65Verifier;

#[cfg(feature = "real-mldsa65")]
impl MlDsa65Verifier for RustCryptoMlDsa65Verifier {
    fn verify(
        &self,
        public_key: &MlDsa65PublicKey,
        message: &[u8],
        signature: &MlDsa65Signature,
    ) -> Result<(), SignatureError> {
        use ml_dsa::signature::Verifier as _;
        use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature as InnerSignature, VerifyingKey};

        let encoded_vk = EncodedVerifyingKey::<MlDsa65>::try_from(public_key.as_bytes())
            .map_err(|_| SignatureError::VerificationFailed)?;
        let vk = VerifyingKey::<MlDsa65>::decode(&encoded_vk);

        let encoded_sig = EncodedSignature::<MlDsa65>::try_from(signature.as_bytes())
            .map_err(|_| SignatureError::VerificationFailed)?;
        let sig =
            InnerSignature::<MlDsa65>::decode(&encoded_sig).ok_or(SignatureError::VerificationFailed)?;

        vk.verify(message, &sig)
            .map_err(|_| SignatureError::VerificationFailed)
    }
}

/// The operator checkpoint-**signing** interface (ML-DSA-65), mirroring the
/// [`MlDsa65Verifier`] split: the crate's logic is written against this seam.
/// The **default** build now provides the real [`RustCryptoMlDsa65Signer`]; the
/// [`NonSigningStubSigner`] (signs **nothing real**) is the
/// `--no-default-features` offline stand-in.
///
/// # SCAFFOLD — not a secure or deployed system
///
/// Real operator key custody (HSMs, key ceremonies, a deployed/operated signer
/// set) is **blocked-on-infra** and entirely out of scope here. Under
/// `--no-default-features` the only implementation is [`NonSigningStubSigner`],
/// which emits deterministic length-valid junk that **no verifier will ever
/// accept** — so an offline stub build reaches no quorum, by design.
pub trait CheckpointSigner {
    /// Produce an ML-DSA-65 signature over `message`.
    ///
    /// Real implementations sign with a held ML-DSA-65 key. The stub returns
    /// length-valid junk bytes that verify against nothing.
    fn sign(&self, message: &[u8]) -> Result<MlDsa65Signature, SignatureError>;
}

/// A stub signer that performs **no cryptography**: it emits deterministic,
/// length-valid junk bytes.
///
/// # SCAFFOLD — not a secure or deployed system
///
/// The output is `[fill; ML_DSA_65_SIGNATURE_LEN]` — a syntactically valid
/// signature container that is cryptographically meaningless. Combined with
/// the [`NonVerifyingStubVerifier`] (which refuses to assert validity) this
/// keeps the `--no-default-features` invariant: **an offline stub build can
/// NEVER reach quorum.** Deterministic by construction (no RNG, no time).
#[derive(Debug, Default, Clone, Copy)]
pub struct NonSigningStubSigner {
    /// Byte the junk signature is filled with (lets tests keep distinct
    /// per-seat outputs while staying deterministic).
    pub fill: u8,
}

impl CheckpointSigner for NonSigningStubSigner {
    fn sign(&self, _message: &[u8]) -> Result<MlDsa65Signature, SignatureError> {
        // Deliberately no cryptography: length-valid junk only.
        MlDsa65Signature::from_bytes(vec![self.fill; ML_DSA_65_SIGNATURE_LEN])
    }
}

/// A real ML-DSA-65 (FIPS 204) **deterministic** signer backed by the
/// RustCrypto `ml-dsa` crate. It is the **default** [`CheckpointSigner`] impl
/// (the `real-mldsa65` feature is ON by default); it is compiled out only under
/// `--no-default-features`. Reuses the seed-derived deterministic signing
/// exercised by this crate's tests.
///
/// # This is real cryptography — it is still not a security claim
///
/// Everything said on [`RustCryptoMlDsa65Verifier`] applies here unchanged:
/// the `ml-dsa` crate is **UNAUDITED, pre-1.0 (0.1.1)**; the trust model is
/// still "trust Postern"; the base is still forgeable; compiling this in
/// makes nothing secure, operational, audited, or deployed. Additionally:
///
/// - **Seed-derived keys are for deterministic tests ONLY.** Real operator
///   seeds must come from a CSPRNG and live in real key custody (HSMs, key
///   ceremonies) — that is **blocked-on-infra** and out of scope here.
/// - This type is compiled in by default; only `--no-default-features` drops it
///   in favor of [`NonSigningStubSigner`].
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
    /// **Test-only key handling:** never derive a real operator key from a
    /// fixed or low-entropy seed; real seeds must be drawn from a CSPRNG and
    /// held in real custody (blocked-on-infra).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let seed: ml_dsa::Seed = seed.into();
        Self {
            esk: ml_dsa::ExpandedSigningKey::<ml_dsa::MlDsa65>::from_seed(&seed),
        }
    }

    /// The ML-DSA-65 public key matching this signer's key.
    pub fn public_key(&self) -> MlDsa65PublicKey {
        MlDsa65PublicKey::from_bytes(self.esk.verifying_key().encode().to_vec())
            .expect("ml-dsa encodes ML-DSA-65 verifying keys at the FIPS-204 length")
    }
}

#[cfg(feature = "real-mldsa65")]
impl CheckpointSigner for RustCryptoMlDsa65Signer {
    fn sign(&self, message: &[u8]) -> Result<MlDsa65Signature, SignatureError> {
        let sig = self
            .esk
            .sign_deterministic(message, b"")
            .map_err(|_| SignatureError::VerificationFailed)?;
        MlDsa65Signature::from_bytes(sig.encode().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_key_length_is_enforced() {
        assert!(MlDsa65PublicKey::from_bytes(vec![0u8; ML_DSA_65_PUBLIC_KEY_LEN]).is_ok());
        assert!(matches!(
            MlDsa65PublicKey::from_bytes(vec![0u8; 10]),
            Err(SignatureError::BadPublicKeyLength { .. })
        ));
    }

    #[test]
    fn signature_length_is_enforced() {
        assert!(MlDsa65Signature::from_bytes(vec![0u8; ML_DSA_65_SIGNATURE_LEN]).is_ok());
        assert!(matches!(
            MlDsa65Signature::from_bytes(vec![0u8; 10]),
            Err(SignatureError::BadSignatureLength { .. })
        ));
    }

    #[test]
    fn stub_verifier_never_asserts_validity() {
        let pk = MlDsa65PublicKey::from_bytes(vec![7u8; ML_DSA_65_PUBLIC_KEY_LEN]).unwrap();
        let sig = MlDsa65Signature::from_bytes(vec![9u8; ML_DSA_65_SIGNATURE_LEN]).unwrap();
        let res = NonVerifyingStubVerifier.verify(&pk, b"anything", &sig);
        assert_eq!(res, Err(SignatureError::StubRefusesToAssertValidity));
    }

    #[test]
    fn stub_signer_emits_deterministic_length_valid_junk() {
        let signer = NonSigningStubSigner { fill: 5 };
        let a = signer.sign(b"payload").unwrap();
        let b = signer.sign(b"a completely different payload").unwrap();
        // Deterministic and message-independent: it is junk, not a signature.
        assert_eq!(a, b);
        assert_eq!(a.as_bytes().len(), ML_DSA_65_SIGNATURE_LEN);
        assert_eq!(a.as_bytes(), &vec![5u8; ML_DSA_65_SIGNATURE_LEN][..]);
    }

    #[test]
    fn stub_signer_output_is_never_accepted_by_the_stub_verifier() {
        // The default-build invariant, end to end at the primitive level:
        // stub-signed junk + stub verifier -> validity is NEVER asserted.
        let pk = MlDsa65PublicKey::from_bytes(vec![7u8; ML_DSA_65_PUBLIC_KEY_LEN]).unwrap();
        let sig = NonSigningStubSigner { fill: 3 }.sign(b"payload").unwrap();
        assert_eq!(
            NonVerifyingStubVerifier.verify(&pk, b"payload", &sig),
            Err(SignatureError::StubRefusesToAssertValidity)
        );
    }
}

/// Host tests running **real** ML-DSA-65 (FIPS 204) crypto through
/// [`RustCryptoMlDsa65Verifier`]. These run on a **default** `cargo test`
/// (the `real-mldsa65` feature is ON by default); only `--no-default-features`
/// compiles them out. See the crate-, module-, and type-level SCAFFOLD /
/// unaudited caveats — a green run here is not a security claim.
///
/// Every stub test above stays untouched: the stub still asserts nothing, on
/// any `cargo test` invocation.
#[cfg(all(test, feature = "real-mldsa65"))]
mod real_mldsa65_tests {
    use super::*;
    use ml_dsa::{ExpandedSigningKey, MlDsa65, Seed};

    /// Deterministic keypair for seed byte `i`: `ExpandedSigningKey` derived
    /// straight from a `[i; 32]` seed (test-only — never do this with a real
    /// key; real seeds must be drawn from a CSPRNG).
    fn seeded_keypair(i: u8) -> ExpandedSigningKey<MlDsa65> {
        let seed: Seed = [i; 32].into();
        ExpandedSigningKey::<MlDsa65>::from_seed(&seed)
    }

    fn wrapped_public_key(esk: &ExpandedSigningKey<MlDsa65>) -> MlDsa65PublicKey {
        MlDsa65PublicKey::from_bytes(esk.verifying_key().encode().to_vec()).unwrap()
    }

    #[test]
    fn real_verifier_accepts_genuine_signature() {
        let esk = seeded_keypair(1);
        let msg = b"postern-ffg real-mldsa65 host test payload";
        let sig = esk.sign_deterministic(msg, b"").expect("deterministic sign succeeds");

        let pk = wrapped_public_key(&esk);
        let wrapped_sig = MlDsa65Signature::from_bytes(sig.encode().to_vec()).unwrap();

        assert_eq!(RustCryptoMlDsa65Verifier.verify(&pk, msg, &wrapped_sig), Ok(()));
    }

    #[test]
    fn real_verifier_rejects_bit_flipped_signature() {
        let esk = seeded_keypair(2);
        let msg = b"postern-ffg real-mldsa65 host test payload";
        let sig = esk.sign_deterministic(msg, b"").expect("deterministic sign succeeds");

        let pk = wrapped_public_key(&esk);
        let mut tampered = sig.encode().to_vec();
        tampered[0] ^= 0x01;
        let wrapped_sig = MlDsa65Signature::from_bytes(tampered).unwrap();

        assert_eq!(
            RustCryptoMlDsa65Verifier.verify(&pk, msg, &wrapped_sig),
            Err(SignatureError::VerificationFailed)
        );
    }

    #[test]
    fn real_signer_round_trips_through_real_verifier() {
        // The CheckpointSigner seam with the real primitive: deterministic
        // seed -> deterministic signature -> accepted by the real verifier.
        let signer = RustCryptoMlDsa65Signer::from_seed([7u8; 32]);
        let msg = b"postern-ffg real-mldsa65 signer seam payload";
        let sig_a = signer.sign(msg).unwrap();
        let sig_b = signer.sign(msg).unwrap();
        assert_eq!(sig_a, sig_b, "deterministic signing must be reproducible");
        assert_eq!(
            RustCryptoMlDsa65Verifier.verify(&signer.public_key(), msg, &sig_a),
            Ok(())
        );
    }

    #[test]
    fn real_verifier_rejects_signature_from_foreign_key() {
        let esk = seeded_keypair(3);
        let foreign_esk = seeded_keypair(4);
        let msg = b"postern-ffg real-mldsa65 host test payload";
        let sig = esk.sign_deterministic(msg, b"").expect("deterministic sign succeeds");

        // Genuine signature, but verified against a DIFFERENT operator's key.
        let foreign_pk = wrapped_public_key(&foreign_esk);
        let wrapped_sig = MlDsa65Signature::from_bytes(sig.encode().to_vec()).unwrap();

        assert_eq!(
            RustCryptoMlDsa65Verifier.verify(&foreign_pk, msg, &wrapped_sig),
            Err(SignatureError::VerificationFailed)
        );
    }
}
