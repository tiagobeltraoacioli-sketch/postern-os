//! The REAL hybrid post-quantum backup signer/verifier — ML-DSA-65 ‖
//! Falcon-1024 (suite `0x0001`) — that fills the DATA0/PBP0 authenticity leg
//! `bloch-data` deliberately leaves as opaque slots.
//!
//! Spec: `docs/specs/POSTERN-DATA-FILECOIN-DESIGN.md`, §1 ("verify the PQ
//! signature") and §3.2 (the PBP0 `pk`/`sig` slots + the DATA0
//! `signer_commit`). `bloch-data` is zero-dep and, by construction, "does not
//! sign" ([`bloch_data::package::Package::pk`]/`sig` are carried verbatim;
//! [`bloch_data::verify`] runs only the offline root/`signer_commit` *wiring*
//! legs under a mock hash). This module is where the seam is finally crossed
//! for real: it drives [`bloch_crypto::crypto::sign`] /
//! [`bloch_crypto::crypto::verify`] — the SAME hybrid signer the node, CLI and
//! mobile wallet use — over the exact byte string
//! [`AnchorEnvelope::signing_transcript`] defines.
//!
//! ## What is REAL here (UNAUDITED)
//!
//! * [`VaultSigner::sign_anchor`] produces a genuine ML-DSA-65 ‖ Falcon-1024
//!   hybrid signature (suite-enveloped, ≈ 4.6 KB) over the DATA0 anchor's
//!   transcript — the transcript commits to the SHAKE-256 `manifest_root` (the
//!   anchor's `new_root`), so the signature authenticates the whole backup.
//! * [`sign_backup`] stamps the vault public key into
//!   [`Package::pk`](bloch_data::package::Package::pk), computes the REAL
//!   SHAKE-256 `manifest_root` and the REAL `SHA3-256(pk)` `signer_commit`
//!   ([`Shake256Hasher`]), builds the DATA0 [`AnchorEnvelope`], signs it, and
//!   writes the signature into
//!   [`Package::sig`](bloch_data::package::Package::sig). After it returns the
//!   two slots `bloch-data` calls out as unsigned are filled with real bytes.
//! * [`verify_signed_backup`] is the full, fail-closed authenticity check: it
//!   recomputes the SHAKE-256 root over the package's committed prefix, ties
//!   `signer_commit` to `pk` via real `SHA3-256`, pins `pk` to the caller's
//!   known vault key, and verifies **both** lattice halves of the hybrid
//!   signature. A single tampered byte anywhere in the sealed manifest (the
//!   root leg), the anchored root, the public key, or either signature half
//!   flips it to reject.
//!
//! ## Honesty (still true)
//!
//! Authenticity is only ever *relative to a pinned vault public key*: anchoring
//! is permissionless, so an attacker can sign their own `(root, pk, sig)`
//! triple that is internally consistent. That is why [`verify_signed_backup`]
//! **requires** the expected vault `pk` — a restoring user knows their own key
//! out-of-band. UNAUDITED, and inherits the k=4, low-hashrate, unaudited Bloch
//! base in full. The live provider network path remains out of scope.

use bloch_crypto::crypto;
use bloch_data::anchor::{AnchorEnvelope, CID_LEN};
use bloch_data::package::Package;
use bloch_data::verify::{bind_anchor_to_package, bind_signer_to_commit, VerifyError};
use zeroize::Zeroizing;

use crate::Shake256Hasher;

/// A backup vault's hybrid signing identity: the suite-enveloped ML-DSA-65 ‖
/// Falcon-1024 secret key (self-zeroizing) and its matching public key.
///
/// The public key is exactly the bytes written into
/// [`Package::pk`](bloch_data::package::Package::pk); its `SHA3-256` is the
/// DATA0 anchor's `signer_commit`. Constructed either with a fresh random key
/// ([`VaultSigner::generate`]) or deterministically from a 32-byte-or-longer
/// seed ([`VaultSigner::from_seed`]) so the same vault key re-derives on a
/// fresh device.
#[derive(Clone)]
pub struct VaultSigner {
    /// Suite-enveloped hybrid secret key (`magic ‖ suite ‖ mldsa_sk ‖
    /// falcon_sk`). Wiped on drop.
    secret: Zeroizing<Vec<u8>>,
    /// Suite-enveloped hybrid public key (`magic ‖ suite ‖ mldsa_pk ‖
    /// falcon_pk`). Public; goes into the PBP0 package verbatim.
    public: Vec<u8>,
}

/// Failure producing a hybrid signature (the underlying [`crypto::CryptoError`]
/// rendered) or deriving a keypair from a seed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignError {
    /// [`bloch_crypto::crypto::sign`] rejected the secret key or message.
    Crypto(String),
    /// [`bloch_crypto::crypto::generate_keypair_from_seed`] rejected the seed
    /// (e.g. shorter than 32 bytes).
    Seed(String),
    /// [`Package::committed_prefix`](bloch_data::package::Package::committed_prefix)
    /// failed its length guard, so no `manifest_root` could be computed.
    Package(bloch_data::package::PackageError),
}

impl core::fmt::Display for SignError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Crypto(m) => write!(f, "postern-backup-net signer: signing failed: {m}"),
            Self::Seed(m) => write!(f, "postern-backup-net signer: bad seed: {m}"),
            Self::Package(e) => write!(f, "postern-backup-net signer: {e}"),
        }
    }
}

impl std::error::Error for SignError {}

impl VaultSigner {
    /// A fresh random hybrid vault key (OS RNG) — ML-DSA-65 ‖ Falcon-1024,
    /// suite `0x0001`.
    pub fn generate() -> Self {
        let (public, secret) = crypto::generate_keypair();
        Self { secret: Zeroizing::new(secret), public }
    }

    /// A deterministic hybrid vault key from `seed` (≥ 32 bytes; only the first
    /// 32 are used as the ChaCha20 keygen seed). The same seed re-derives the
    /// byte-identical keypair on any device — the disaster-restore property.
    pub fn from_seed(seed: &[u8]) -> Result<Self, SignError> {
        let (public, secret) =
            crypto::generate_keypair_from_seed(seed).map_err(|e| SignError::Seed(e.to_string()))?;
        Ok(Self { secret: Zeroizing::new(secret), public })
    }

    /// The suite-enveloped hybrid public key — the exact bytes stamped into
    /// [`Package::pk`](bloch_data::package::Package::pk).
    pub fn public_key(&self) -> &[u8] {
        &self.public
    }

    /// The DATA0 anchor's `signer_commit` for this vault: `SHA3-256(pk)`, the
    /// same address-family primitive the chain uses (via
    /// [`Shake256Hasher`]'s real `signer_commit` override).
    pub fn signer_commit(&self, hasher: &Shake256Hasher) -> [u8; 32] {
        use crate::Hasher;
        hasher.signer_commit(&self.public)
    }

    /// Sign an arbitrary message with the hybrid key. Both lattice halves sign;
    /// the returned signature is suite-enveloped (`magic ‖ suite ‖ mldsa_sig ‖
    /// falcon_sig`).
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignError> {
        crypto::sign(&self.secret, message).map_err(|e| SignError::Crypto(e.to_string()))
    }

    /// Sign the DATA0 anchor's canonical transcript
    /// ([`AnchorEnvelope::signing_transcript`] — domain ‖ magic ‖ version ‖
    /// namespace_id ‖ sequence ‖ prev_root ‖ manifest_root ‖ signer_commit).
    /// Because the transcript carries `manifest_root` (the SHAKE-256 `new_root`)
    /// and `signer_commit`, the signature authenticates the committed backup.
    pub fn sign_anchor(&self, anchor: &AnchorEnvelope) -> Result<Vec<u8>, SignError> {
        self.sign(&anchor.signing_transcript())
    }
}

/// Build and sign a DATA0 anchor for a PBP0 `package`, filling the package's
/// `pk`/`sig` slots in place — the whole authenticity leg in one call.
///
/// Steps (all real, UNAUDITED):
/// 1. stamp `signer.public_key()` into `package.pk` (it lives outside the
///    committed prefix, so this does not disturb the root);
/// 2. compute `manifest_root = SHAKE-256(DOMAIN_MANIFEST_ROOT ‖
///    package.committed_prefix())` via [`Shake256Hasher`] — the anchor's
///    `new_root`;
/// 3. compute `signer_commit = SHA3-256(package.pk)`;
/// 4. assemble the [`AnchorEnvelope`] (`manifest_cid` is a locator only, zero
///    integrity weight);
/// 5. hybrid-sign the anchor transcript and write it into `package.sig`.
///
/// Returns the signed [`AnchorEnvelope`] the vault would anchor on-chain. The
/// mutated `package` (now with real `pk`/`sig`) and this anchor verify together
/// under [`verify_signed_backup`].
#[allow(clippy::too_many_arguments)]
pub fn sign_backup(
    signer: &VaultSigner,
    hasher: &Shake256Hasher,
    namespace_id: [u8; 32],
    sequence: u64,
    prev_root: [u8; 32],
    manifest_cid: [u8; CID_LEN],
    package: &mut Package,
) -> Result<AnchorEnvelope, SignError> {
    use crate::Hasher;

    // (1) the vault pubkey is part of the package (outside the committed prefix).
    package.pk = signer.public_key().to_vec();
    // (2) the REAL SHAKE-256 manifest_root over the committed prefix.
    let manifest_root = hasher.manifest_root(package).map_err(SignError::Package)?;
    // (3) the REAL SHA3-256(pk) commitment.
    let signer_commit = hasher.signer_commit(&package.pk);
    // (4) the DATA0 anchor.
    let anchor = AnchorEnvelope {
        namespace_id,
        sequence,
        prev_root,
        manifest_root,
        signer_commit,
        manifest_cid,
    };
    // (5) the REAL hybrid signature over the anchor transcript.
    package.sig = signer.sign_anchor(&anchor)?;
    Ok(anchor)
}

/// Fail-closed reason a signed backup did not verify.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BackupVerifyError {
    /// The SHAKE-256 root recomputed from the fetched package does not equal
    /// the anchor's committed `manifest_root` (or the prefix could not be
    /// built). Carries the underlying [`VerifyError`].
    Root(VerifyError),
    /// `SHA3-256(package.pk)` does not equal the anchor's committed
    /// `signer_commit`. Carries the underlying [`VerifyError`].
    Signer(VerifyError),
    /// The fetched `package.pk` is not the pinned vault public key the caller
    /// expected — authenticity is only ever relative to a known key.
    UnexpectedSigner,
    /// The hybrid ML-DSA-65 ‖ Falcon-1024 signature did not verify against the
    /// vault pubkey over the anchor transcript. This is `false` if **either**
    /// lattice half fails (defence in depth), if the suite envelopes mismatch,
    /// or on any malformation — [`bloch_crypto::crypto::verify`] never panics.
    BadSignature,
}

impl core::fmt::Display for BackupVerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Root(e) => write!(f, "signed-backup verify: root leg: {e}"),
            Self::Signer(e) => write!(f, "signed-backup verify: signer_commit leg: {e}"),
            Self::UnexpectedSigner => write!(
                f,
                "signed-backup verify: package pk is not the pinned vault public key"
            ),
            Self::BadSignature => write!(
                f,
                "signed-backup verify: hybrid ML-DSA-65 ‖ Falcon-1024 signature rejected \
                 (both halves must verify)"
            ),
        }
    }
}

impl std::error::Error for BackupVerifyError {}

/// The full, fail-closed authenticity check for a DATA0 anchor + PBP0 package,
/// pinned to a **known** vault public key `expected_vault_pk`.
///
/// Runs four independent legs; ALL must pass:
/// 1. **root** — recompute `SHAKE-256(DOMAIN_MANIFEST_ROOT ‖ committed_prefix)`
///    and require it equals `anchor.manifest_root`
///    ([`bind_anchor_to_package`], real hasher);
/// 2. **signer_commit** — require `SHA3-256(package.pk) ==
///    anchor.signer_commit` ([`bind_signer_to_commit`], real hasher);
/// 3. **pin** — require `package.pk == expected_vault_pk` (authenticity is
///    relative to a key the verifier already trusts);
/// 4. **signature** — verify the hybrid ML-DSA-65 ‖ Falcon-1024 signature
///    ([`bloch_crypto::crypto::verify`]) over
///    [`AnchorEnvelope::signing_transcript`]; **both** lattice halves must
///    verify.
///
/// A one-byte tamper in the sealed manifest breaks leg 1; in `anchor.manifest_root`
/// breaks legs 1 and 4; in `package.pk` breaks legs 2, 3 and 4; in `package.sig`
/// or `anchor.signer_commit`/`sequence`/… breaks leg 4. Returns `Ok(())` only
/// when the fetched bytes are the genuine, vault-signed backup.
///
/// # Honesty
///
/// This establishes authenticity **only relative to `expected_vault_pk`**.
/// Anchoring is permissionless, so an attacker can mint an internally-consistent
/// `(root, pk, sig)` under a key they control — which is exactly why the pin
/// (leg 3) is mandatory. UNAUDITED.
pub fn verify_signed_backup(
    hasher: &Shake256Hasher,
    anchor: &AnchorEnvelope,
    package: &Package,
    expected_vault_pk: &[u8],
) -> Result<(), BackupVerifyError> {
    // (1) root leg — real SHAKE-256 over the committed prefix.
    bind_anchor_to_package(hasher, anchor, package).map_err(BackupVerifyError::Root)?;
    // (2) signer_commit leg — real SHA3-256(pk).
    bind_signer_to_commit(hasher, anchor, package).map_err(BackupVerifyError::Signer)?;
    // (3) pin the signer to the caller's known vault key.
    if package.pk != expected_vault_pk {
        return Err(BackupVerifyError::UnexpectedSigner);
    }
    // (4) the REAL hybrid signature over the anchor transcript — both halves.
    if !crypto::verify(&package.pk, &anchor.signing_transcript(), &package.sig) {
        return Err(BackupVerifyError::BadSignature);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloch_data::package::{SALT_LEN, TIER_DEFAULT};
    use crate::Hasher;

    fn base_package() -> Package {
        Package {
            kdf_tier: TIER_DEFAULT,
            salt: [0x11; SALT_LEN],
            sealed_manifest: (0u8..=200).collect(),
            pk: Vec::new(),
            sig: Vec::new(),
        }
    }

    // The hybrid suite-0x0001 signature layout, for half-targeted tamper tests:
    // 4-byte suite header ‖ ML-DSA-65 sig (3309) ‖ Falcon-1024 sig (remainder).
    const SUITE_HEADER_LEN: usize = 4;
    const MLDSA_SIG_LEN: usize = 3309;

    fn sign_fresh() -> (VaultSigner, Shake256Hasher, AnchorEnvelope, Package) {
        let signer = VaultSigner::generate();
        let hasher = Shake256Hasher::new();
        let mut pkg = base_package();
        let anchor = sign_backup(
            &signer,
            &hasher,
            [0x22; 32],
            7,
            [0u8; 32],
            [0x00; CID_LEN],
            &mut pkg,
        )
        .expect("sign");
        (signer, hasher, anchor, pkg)
    }

    #[test]
    fn honest_signed_backup_verifies() {
        let (signer, hasher, anchor, pkg) = sign_fresh();
        assert_eq!(
            verify_signed_backup(&hasher, &anchor, &pkg, signer.public_key()),
            Ok(())
        );
        // The signature is a real ≈4.6 KB hybrid envelope, not a slot.
        assert!(pkg.sig.len() > SUITE_HEADER_LEN + MLDSA_SIG_LEN);
        assert_eq!(pkg.pk, signer.public_key());
    }

    #[test]
    fn from_seed_is_deterministic() {
        let seed = [0x5Au8; 32];
        let a = VaultSigner::from_seed(&seed).unwrap();
        let b = VaultSigner::from_seed(&seed).unwrap();
        assert_eq!(a.public_key(), b.public_key());
        // A signature from one verifies under the other's (same) key.
        let msg = b"anchor transcript stand-in";
        let sig = a.sign(msg).unwrap();
        assert!(crypto::verify(b.public_key(), msg, &sig));
    }

    #[test]
    fn tampered_sealed_manifest_root_leg_rejects() {
        let (signer, hasher, anchor, mut pkg) = sign_fresh();
        pkg.sealed_manifest[0] ^= 0x01;
        assert!(matches!(
            verify_signed_backup(&hasher, &anchor, &pkg, signer.public_key()),
            Err(BackupVerifyError::Root(VerifyError::RootMismatch { .. }))
        ));
    }

    #[test]
    fn tampered_anchor_root_rejects() {
        let (signer, hasher, mut anchor, pkg) = sign_fresh();
        anchor.manifest_root[0] ^= 0x01;
        // Root leg catches it first (recomputed != anchored).
        assert!(matches!(
            verify_signed_backup(&hasher, &anchor, &pkg, signer.public_key()),
            Err(BackupVerifyError::Root(VerifyError::RootMismatch { .. }))
        ));
    }

    #[test]
    fn tampered_signature_rejects_and_is_fail_closed() {
        let (signer, hasher, anchor, mut pkg) = sign_fresh();
        // Flip one byte in the ML-DSA half of the signature body.
        pkg.sig[SUITE_HEADER_LEN + 10] ^= 0x01;
        assert_eq!(
            verify_signed_backup(&hasher, &anchor, &pkg, signer.public_key()),
            Err(BackupVerifyError::BadSignature)
        );
    }

    #[test]
    fn both_halves_are_required() {
        // Proves BOTH lattice halves are actually checked: tampering ONLY the
        // ML-DSA half rejects, and tampering ONLY the Falcon half rejects.
        let (signer, hasher, anchor, pkg) = sign_fresh();

        // ML-DSA half: byte just past the suite header.
        let mut mldsa_tampered = pkg.clone();
        mldsa_tampered.sig[SUITE_HEADER_LEN] ^= 0x01;
        assert_eq!(
            verify_signed_backup(&hasher, &anchor, &mldsa_tampered, signer.public_key()),
            Err(BackupVerifyError::BadSignature),
            "flipping the ML-DSA half must reject"
        );

        // Falcon half: a byte after the fixed ML-DSA signature length.
        let mut falcon_tampered = pkg.clone();
        let falcon_off = SUITE_HEADER_LEN + MLDSA_SIG_LEN + 5;
        assert!(falcon_off < falcon_tampered.sig.len(), "sig has a Falcon half");
        falcon_tampered.sig[falcon_off] ^= 0x01;
        assert_eq!(
            verify_signed_backup(&hasher, &anchor, &falcon_tampered, signer.public_key()),
            Err(BackupVerifyError::BadSignature),
            "flipping the Falcon half must reject"
        );
    }

    #[test]
    fn tampered_pk_rejects_on_signer_leg() {
        let (signer, hasher, anchor, mut pkg) = sign_fresh();
        pkg.pk[SUITE_HEADER_LEN + 3] ^= 0x01;
        // signer_commit = SHA3-256(pk) no longer matches ⇒ signer leg fails first.
        assert!(matches!(
            verify_signed_backup(&hasher, &anchor, &pkg, signer.public_key()),
            Err(BackupVerifyError::Signer(VerifyError::SignerMismatch { .. }))
        ));
    }

    #[test]
    fn wrong_pinned_vault_pk_rejects() {
        // Honest, internally-consistent anchor+package, but pinned to a
        // DIFFERENT vault key ⇒ UnexpectedSigner (the permissionless-anchor
        // caveat: authenticity is only relative to a known key).
        let (_signer, hasher, anchor, pkg) = sign_fresh();
        let other = VaultSigner::generate();
        assert_eq!(
            verify_signed_backup(&hasher, &anchor, &pkg, other.public_key()),
            Err(BackupVerifyError::UnexpectedSigner)
        );
    }

    #[test]
    fn attacker_resigned_backup_fails_the_pin() {
        // The permissionless-anchor attack, made concrete: an attacker re-seals
        // a tampered manifest, recomputes a fresh root + signer_commit under
        // THEIR OWN vault key, and produces a perfectly self-consistent
        // (root, pk, sig) triple. Legs 1/2/4 all pass — but the pin (leg 3) to
        // the genuine vault key rejects it.
        let (genuine, hasher, _anchor, _pkg) = sign_fresh();

        let attacker = VaultSigner::generate();
        let mut evil = base_package();
        evil.sealed_manifest = b"attacker-substituted sealed manifest".to_vec();
        let evil_anchor = sign_backup(
            &attacker,
            &hasher,
            [0x22; 32],
            7,
            [0u8; 32],
            [0x00; CID_LEN],
            &mut evil,
        )
        .expect("attacker signs their own");

        // Self-consistent under the attacker key...
        assert_eq!(
            verify_signed_backup(&hasher, &evil_anchor, &evil, attacker.public_key()),
            Ok(())
        );
        // ...but rejected when pinned to the genuine vault key.
        assert_eq!(
            verify_signed_backup(&hasher, &evil_anchor, &evil, genuine.public_key()),
            Err(BackupVerifyError::UnexpectedSigner)
        );
    }

    #[test]
    fn signer_commit_matches_shake256hasher() {
        let signer = VaultSigner::generate();
        let hasher = Shake256Hasher::new();
        assert_eq!(signer.signer_commit(&hasher), hasher.signer_commit(signer.public_key()));
    }

    #[test]
    fn sign_backup_does_not_disturb_the_root() {
        // pk/sig live outside the committed prefix, so the manifest_root the
        // anchor commits to is the pure SHAKE-256 of the prefix — unchanged by
        // stamping pk/sig.
        let signer = VaultSigner::generate();
        let hasher = Shake256Hasher::new();
        let mut pkg = base_package();
        let root_before = hasher.manifest_root(&pkg).unwrap();
        let anchor = sign_backup(
            &signer, &hasher, [0x22; 32], 1, [0u8; 32], [0x00; CID_LEN], &mut pkg,
        )
        .unwrap();
        assert_eq!(anchor.manifest_root, root_before);
    }
}
