//! Detached HYBRID Falcon-1024 + ML-DSA-87 signature over a `SHA256SUMS`
//! manifest.
//!
//! # Hybrid = AND, not OR
//!
//! [`verify_manifest`] only returns `Ok(())` if **both** the Falcon-1024 leg
//! AND the ML-DSA-87 leg verify against the given transcript. A signature
//! with a valid Falcon leg and a corrupted/forged ML-DSA leg — or vice versa
//! — is REJECTED. This is deliberate: the two schemes rest on unrelated hard
//! problems (NTRU lattices for Falcon, Module-LWE/Module-SIS for ML-DSA), so
//! a break of one algorithm does not compromise the pair, but only if the
//! verifier enforces AND. An OR/either-leg check would silently downgrade the
//! hybrid to "as weak as the weaker of the two," so this crate never offers
//! that mode. See `tests/roundtrip.rs` for the fail-closed proof: corrupting
//! only one leg's bytes fails verification even though the other leg alone
//! would have verified fine.
//!
//! # Domain separation
//!
//! Both legs sign the SAME **transcript**, not the raw manifest bytes
//! directly:
//!
//! ```text
//! transcript = DOMAIN || SHA-256(SHA256SUMS)
//! DOMAIN     = b"postern-release/manifest-sig/v1"
//! ```
//!
//! Hashing the manifest first keeps the transcript a fixed 32 bytes
//! regardless of artifact-set size (both Falcon and ML-DSA sign arbitrary-
//! length messages fine, but a fixed-size, pre-hashed transcript is cheaper
//! to re-derive and log). The `DOMAIN` prefix is a context-separation tag:
//! it stops a signature produced for this exact purpose (a Postern release
//! `SHA256SUMS` manifest) from being replayable as a valid signature under a
//! DIFFERENT protocol that happens to also hash-and-sign 32-byte values with
//! the same two keys.
//!
//! # UNAUDITED — see the crate-level docs
//!
//! `ml-dsa` (pre-1.0, pure Rust, RustCrypto) and `pqcrypto-falcon` (wraps
//! unaudited PQClean C) are both UNAUDITED. A passing [`verify_manifest`]
//! proves origin + integrity of the manifest bytes under BOTH keys — it is
//! NOT an attestation, NOT a reproducibility proof, and NOT a security audit.
//! This signature COMPLEMENTS, and does not replace, the repo's existing
//! minisign (Ed25519) release signature.

use ml_dsa::signature::{Keypair as _, Signer as _, Verifier as _};
use ml_dsa::{
    EncodedSignature as MlDsaEncodedSignature, EncodedVerifyingKey as MlDsaEncodedVerifyingKey,
    Generate as _, MlDsa87, Signature as MlDsaSignature, SigningKey as MlDsaSigningKey,
    VerifyingKey as MlDsaVerifyingKey,
};
use pqcrypto_falcon::falcon1024;
use pqcrypto_traits::sign::{
    DetachedSignature as _, PublicKey as _, SecretKey as _,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

/// Domain-separation tag prefixed to the SHA-256 of the manifest before
/// either leg signs it. See the module docs for why.
pub const DOMAIN: &[u8] = b"postern-release/manifest-sig/v1";

/// Build the fixed 32-byte-domain + 32-byte-digest transcript both legs sign.
fn transcript(manifest_bytes: &[u8]) -> Vec<u8> {
    let digest = Sha256::digest(manifest_bytes);
    let mut t = Vec::with_capacity(DOMAIN.len() + digest.len());
    t.extend_from_slice(DOMAIN);
    t.extend_from_slice(&digest);
    t
}

/// Errors generating a hybrid key pair or a signature.
#[derive(Debug, Error)]
pub enum SignError {
    /// The ML-DSA-87 leg failed to produce a signature (the underlying
    /// deterministic scheme is effectively infallible for a well-formed key
    /// and message, but the `signature` crate's `Signer` trait is fallible by
    /// contract, so this is surfaced rather than unwrapped).
    #[error("ML-DSA-87 signing failed: {0}")]
    MlDsa(ml_dsa::signature::Error),
}

/// Errors loading key/signature bytes or verifying a hybrid signature.
#[derive(Debug, Error)]
pub enum VerifyError {
    /// The Falcon-1024 leg did not verify against the transcript.
    #[error("falcon-1024 leg failed to verify")]
    FalconFailed,
    /// The ML-DSA-87 leg did not verify against the transcript.
    #[error("ML-DSA-87 leg failed to verify")]
    MlDsaFailed,
    /// A key or signature byte string was the wrong length / malformed for
    /// its scheme.
    #[error("malformed {0}")]
    Malformed(&'static str),
}

/// A Falcon-1024 ‖ ML-DSA-87 public-key bundle — what a verifier needs.
///
/// Deliberately public keys only: this type is safe to publish alongside a
/// release (e.g. committed to the repo as `keys/dev-sample.falcon.pub` +
/// `keys/dev-sample.mldsa.pub`, mirroring the existing minisign
/// `keys/dev-sample.pub`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyBundle {
    /// Raw Falcon-1024 public key bytes.
    pub falcon_public: Vec<u8>,
    /// Encoded ML-DSA-87 verifying-key bytes.
    pub ml_dsa_public: Vec<u8>,
}

/// A Falcon-1024 ‖ ML-DSA-87 hybrid key pair.
///
/// **Operator-held.** [`KeyPair::generate`] draws fresh key material from the
/// ambient system CSPRNG in memory; this crate never embeds, generates into
/// the source tree, or commits a private key. Secret material is zeroized on
/// drop (Falcon secret-key bytes via `zeroize::Zeroizing`; the ML-DSA seed
/// the same way, and the expanded ML-DSA signing key itself carries
/// `ZeroizeOnDrop` because this crate enables `ml-dsa`'s `zeroize` feature).
pub struct KeyPair {
    falcon_public: Vec<u8>,
    falcon_secret: Zeroizing<Vec<u8>>,
    ml_dsa_public: Vec<u8>,
    /// The 32-byte ML-DSA-87 seed (`SigningKey::from_seed` is deterministic),
    /// which is cheaper to zeroize-and-store than the expanded key.
    ml_dsa_seed: Zeroizing<[u8; 32]>,
}

impl KeyPair {
    /// Generate a fresh hybrid key pair from the ambient system CSPRNG.
    ///
    /// This is an in-memory operation only — see the struct docs. The CLI's
    /// `keygen` subcommand is the only place this crate writes key bytes to
    /// disk, and only when an operator explicitly asks it to.
    #[must_use]
    pub fn generate() -> Self {
        let (falcon_pk, falcon_sk) = falcon1024::keypair();
        let ml_dsa_sk = MlDsaSigningKey::<MlDsa87>::generate();
        let ml_dsa_vk: MlDsaVerifyingKey<MlDsa87> = ml_dsa_sk.verifying_key();
        let seed: [u8; 32] = ml_dsa_sk.to_seed().into();

        KeyPair {
            falcon_public: falcon_pk.as_bytes().to_vec(),
            falcon_secret: Zeroizing::new(falcon_sk.as_bytes().to_vec()),
            ml_dsa_public: ml_dsa_vk.encode().as_slice().to_vec(),
            ml_dsa_seed: Zeroizing::new(seed),
        }
    }

    /// Reconstruct a key pair from raw key bytes (e.g. loaded from disk by
    /// the CLI). `ml_dsa_seed` is the 32-byte ML-DSA-87 seed, NOT the encoded
    /// expanded key.
    pub fn from_parts(
        falcon_public: Vec<u8>,
        falcon_secret: Vec<u8>,
        ml_dsa_seed: [u8; 32],
    ) -> Result<Self, VerifyError> {
        // Validate the Falcon public key decodes; the secret key is validated
        // lazily at sign time (pqcrypto's `SecretKey::from_bytes` is the only
        // place that check exists), but round-tripping the public key here
        // catches the common "wrong file" mistake early.
        let falcon_pk = falcon1024::PublicKey::from_bytes(&falcon_public)
            .map_err(|_| VerifyError::Malformed("falcon-1024 public key"))?;
        let ml_dsa_sk = MlDsaSigningKey::<MlDsa87>::from_seed(&ml_dsa_seed.into());
        let ml_dsa_vk: MlDsaVerifyingKey<MlDsa87> = ml_dsa_sk.verifying_key();

        Ok(KeyPair {
            falcon_public: falcon_pk.as_bytes().to_vec(),
            falcon_secret: Zeroizing::new(falcon_secret),
            ml_dsa_public: ml_dsa_vk.encode().as_slice().to_vec(),
            ml_dsa_seed: Zeroizing::new(ml_dsa_seed),
        })
    }

    /// The public half of this key pair — safe to publish.
    #[must_use]
    pub fn public_key(&self) -> PublicKeyBundle {
        PublicKeyBundle {
            falcon_public: self.falcon_public.clone(),
            ml_dsa_public: self.ml_dsa_public.clone(),
        }
    }

    /// Raw Falcon-1024 secret-key bytes. **Key material** — exists so a
    /// caller (e.g. the CLI's `keygen` subcommand) can persist it under a
    /// path the operator controls. This crate never does that persistence on
    /// its own initiative.
    #[must_use]
    pub fn falcon_secret_bytes(&self) -> Vec<u8> {
        self.falcon_secret.to_vec()
    }

    /// The 32-byte ML-DSA-87 seed. **Key material** — same caveat as
    /// [`KeyPair::falcon_secret_bytes`].
    #[must_use]
    pub fn ml_dsa_seed_bytes(&self) -> [u8; 32] {
        *self.ml_dsa_seed
    }
}

/// A detached hybrid signature: a Falcon-1024 leg and an ML-DSA-87 leg, both
/// computed over the same [`transcript`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridSignature {
    /// Raw detached Falcon-1024 signature bytes (variable length).
    pub falcon: Vec<u8>,
    /// Encoded ML-DSA-87 signature bytes (fixed length for the parameter
    /// set).
    pub ml_dsa: Vec<u8>,
}

impl HybridSignature {
    /// Serialize as `[falcon_len: u32 LE][falcon bytes][ml_dsa_len: u32 LE][ml_dsa bytes]`.
    ///
    /// This crate's own on-disk detached-signature format (e.g.
    /// `SHA256SUMS.pqsig`); it is deliberately simple (no external
    /// serialization dependency) rather than a claim of interoperability
    /// with any other hybrid-signature encoding.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + self.falcon.len() + self.ml_dsa.len());
        buf.extend_from_slice(&(self.falcon.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.falcon);
        buf.extend_from_slice(&(self.ml_dsa.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.ml_dsa);
        buf
    }

    /// Parse the format written by [`HybridSignature::to_bytes`].
    pub fn from_bytes(data: &[u8]) -> Result<Self, VerifyError> {
        let malformed = || VerifyError::Malformed("hybrid signature container");
        if data.len() < 4 {
            return Err(malformed());
        }
        let (len_bytes, rest) = data.split_at(4);
        let falcon_len = u32::from_le_bytes(len_bytes.try_into().unwrap()) as usize;
        if rest.len() < falcon_len + 4 {
            return Err(malformed());
        }
        let (falcon, rest) = rest.split_at(falcon_len);
        let (len_bytes, rest) = rest.split_at(4);
        let ml_dsa_len = u32::from_le_bytes(len_bytes.try_into().unwrap()) as usize;
        if rest.len() != ml_dsa_len {
            return Err(malformed());
        }
        Ok(HybridSignature {
            falcon: falcon.to_vec(),
            ml_dsa: rest.to_vec(),
        })
    }
}

/// Sign `manifest_bytes` (the exact `SHA256SUMS` contents from
/// [`crate::manifest::build_manifest`]) with BOTH legs of `key_pair`, over
/// the domain-separated [`transcript`].
///
/// # Errors
/// Returns [`SignError`] only if the underlying ML-DSA-87 `Signer`
/// implementation reports failure (Falcon's `detached_sign` in
/// `pqcrypto-falcon` is infallible by its own API).
pub fn sign_manifest(manifest_bytes: &[u8], key_pair: &KeyPair) -> Result<HybridSignature, SignError> {
    let t = transcript(manifest_bytes);

    let falcon_sk = falcon1024::SecretKey::from_bytes(&key_pair.falcon_secret)
        .expect("KeyPair only ever holds a Falcon-1024-sized secret key");
    let falcon_sig = falcon1024::detached_sign(&t, &falcon_sk);

    let ml_dsa_sk = MlDsaSigningKey::<MlDsa87>::from_seed(&(*key_pair.ml_dsa_seed).into());
    let ml_dsa_sig: MlDsaSignature<MlDsa87> = ml_dsa_sk
        .try_sign(&t)
        .map_err(SignError::MlDsa)?;

    Ok(HybridSignature {
        falcon: falcon_sig.as_bytes().to_vec(),
        ml_dsa: ml_dsa_sig.encode().as_slice().to_vec(),
    })
}

/// Verify a [`HybridSignature`] over `manifest_bytes` against `public_keys`.
///
/// Returns `Ok(())` **only if both legs verify** (true AND-of-both hybrid —
/// see the module docs). A corrupted/forged Falcon leg fails with
/// [`VerifyError::FalconFailed`] even if the ML-DSA leg is perfectly valid,
/// and vice versa with [`VerifyError::MlDsaFailed`].
pub fn verify_manifest(
    manifest_bytes: &[u8],
    signature: &HybridSignature,
    public_keys: &PublicKeyBundle,
) -> Result<(), VerifyError> {
    let t = transcript(manifest_bytes);

    // --- Falcon-1024 leg ---
    let falcon_pk = falcon1024::PublicKey::from_bytes(&public_keys.falcon_public)
        .map_err(|_| VerifyError::Malformed("falcon-1024 public key"))?;
    let falcon_sig = falcon1024::DetachedSignature::from_bytes(&signature.falcon)
        .map_err(|_| VerifyError::Malformed("falcon-1024 signature"))?;
    falcon1024::verify_detached_signature(&falcon_sig, &t, &falcon_pk)
        .map_err(|_| VerifyError::FalconFailed)?;

    // --- ML-DSA-87 leg ---
    let ml_dsa_vk_enc = MlDsaEncodedVerifyingKey::<MlDsa87>::try_from(public_keys.ml_dsa_public.as_slice())
        .map_err(|_| VerifyError::Malformed("ML-DSA-87 public key"))?;
    let ml_dsa_vk = MlDsaVerifyingKey::<MlDsa87>::decode(&ml_dsa_vk_enc);
    let ml_dsa_sig_enc = MlDsaEncodedSignature::<MlDsa87>::try_from(signature.ml_dsa.as_slice())
        .map_err(|_| VerifyError::Malformed("ML-DSA-87 signature"))?;
    let ml_dsa_sig = MlDsaSignature::<MlDsa87>::decode(&ml_dsa_sig_enc)
        .ok_or(VerifyError::Malformed("ML-DSA-87 signature"))?;
    ml_dsa_vk
        .verify(&t, &ml_dsa_sig)
        .map_err(|_| VerifyError::MlDsaFailed)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::build_manifest;

    fn sample_manifest(dir: &std::path::Path) -> Vec<u8> {
        std::fs::write(dir.join("artifact.bin"), b"release payload").unwrap();
        build_manifest(dir).unwrap()
    }

    #[test]
    fn roundtrip_passes() {
        let dir = tempfile::tempdir().unwrap();
        let manifest_bytes = sample_manifest(dir.path());

        let kp = KeyPair::generate();
        let sig = sign_manifest(&manifest_bytes, &kp).unwrap();
        verify_manifest(&manifest_bytes, &sig, &kp.public_key()).unwrap();
    }

    #[test]
    fn tampered_manifest_fails() {
        let dir = tempfile::tempdir().unwrap();
        let manifest_bytes = sample_manifest(dir.path());

        let kp = KeyPair::generate();
        let sig = sign_manifest(&manifest_bytes, &kp).unwrap();

        let mut tampered = manifest_bytes.clone();
        // Flip a single byte in the hex digest of the manifest.
        tampered[0] ^= 0x01;
        let err = verify_manifest(&tampered, &sig, &kp.public_key()).unwrap_err();
        assert!(matches!(err, VerifyError::FalconFailed | VerifyError::MlDsaFailed));
    }

    #[test]
    fn wrong_verifying_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let manifest_bytes = sample_manifest(dir.path());

        let kp = KeyPair::generate();
        let sig = sign_manifest(&manifest_bytes, &kp).unwrap();

        let other = KeyPair::generate();
        let err = verify_manifest(&manifest_bytes, &sig, &other.public_key()).unwrap_err();
        assert!(matches!(err, VerifyError::FalconFailed | VerifyError::MlDsaFailed));
    }

    #[test]
    fn corrupting_only_falcon_leg_fails_the_whole_hybrid() {
        let dir = tempfile::tempdir().unwrap();
        let manifest_bytes = sample_manifest(dir.path());

        let kp = KeyPair::generate();
        let mut sig = sign_manifest(&manifest_bytes, &kp).unwrap();

        // Sanity: the untouched signature verifies.
        verify_manifest(&manifest_bytes, &sig, &kp.public_key()).unwrap();

        // Corrupt ONLY the Falcon leg; ML-DSA leg is untouched and would, on
        // its own, still verify fine.
        let last = sig.falcon.len() - 1;
        sig.falcon[last] ^= 0xFF;

        let err = verify_manifest(&manifest_bytes, &sig, &kp.public_key()).unwrap_err();
        assert_eq!(err.to_string(), VerifyError::FalconFailed.to_string());
    }

    #[test]
    fn corrupting_only_ml_dsa_leg_fails_the_whole_hybrid() {
        let dir = tempfile::tempdir().unwrap();
        let manifest_bytes = sample_manifest(dir.path());

        let kp = KeyPair::generate();
        let mut sig = sign_manifest(&manifest_bytes, &kp).unwrap();

        // Sanity: the untouched signature verifies.
        verify_manifest(&manifest_bytes, &sig, &kp.public_key()).unwrap();

        // Corrupt ONLY the ML-DSA leg; Falcon leg is untouched and would, on
        // its own, still verify fine. Flip a byte within the leading
        // `c_tilde` challenge-hash portion of the encoded signature (rather
        // than, say, the trailing bit-packed hint) — c_tilde is an opaque
        // hash with no internal format constraints, so this is guaranteed to
        // still *decode* successfully and fail at the cryptographic
        // verification step, rather than at decode time (flipping a bit
        // inside the hint's packed format CAN make `Signature::decode`
        // itself reject the bytes as malformed — also a correct fail-closed
        // outcome, just a different `VerifyError` variant than this test
        // pins down).
        sig.ml_dsa[0] ^= 0xFF;

        let err = verify_manifest(&manifest_bytes, &sig, &kp.public_key()).unwrap_err();
        assert_eq!(err.to_string(), VerifyError::MlDsaFailed.to_string());
    }

    #[test]
    fn hybrid_signature_byte_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let manifest_bytes = sample_manifest(dir.path());
        let kp = KeyPair::generate();
        let sig = sign_manifest(&manifest_bytes, &kp).unwrap();

        let encoded = sig.to_bytes();
        let decoded = HybridSignature::from_bytes(&encoded).unwrap();
        assert_eq!(sig, decoded);
        verify_manifest(&manifest_bytes, &decoded, &kp.public_key()).unwrap();
    }

    #[test]
    fn key_pair_from_parts_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let manifest_bytes = sample_manifest(dir.path());

        let kp = KeyPair::generate();
        let falcon_public = kp.falcon_public.clone();
        let falcon_secret = kp.falcon_secret.to_vec();
        let seed = *kp.ml_dsa_seed;

        let reconstructed = KeyPair::from_parts(falcon_public, falcon_secret, seed).unwrap();
        assert_eq!(reconstructed.public_key(), kp.public_key());

        let sig = sign_manifest(&manifest_bytes, &reconstructed).unwrap();
        verify_manifest(&manifest_bytes, &sig, &kp.public_key()).unwrap();
    }
}
