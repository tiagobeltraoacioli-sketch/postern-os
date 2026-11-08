//! Postern Core — the shared crypto primitives every Postern product seals with.
//!
//! One canonical **AEAD seal** (XChaCha20-Poly1305, versioned + key-committing,
//! see [`aead`]) and one memory-hard **KDF** (Argon2id, see [`kdf`]), so the
//! Vault, the Courier, the Panic Lock and any future product cannot drift on
//! wire format, nonce length, or KDF choice. Extracting them here means there
//! is exactly ONE seal to audit — the "Postern seal".
//!
//! **Format history.** The v2 seal (`0x02 ‖ nonce ‖ commit ‖ ct`) is what
//! [`aead::seal`] produces today. The legacy pre-versioned format (bare
//! `nonce ‖ ct`, no version byte, no context binding, no key commitment) is
//! still *readable* by [`aead::open`] so blobs sealed before the version bump
//! open, but it is never written anymore. Legacy blobs do not get v2's
//! context binding or key commitment — re-seal them to upgrade.
//!
//! All RustCrypto (Apache-2.0 / MIT). No copyleft anywhere in the seal path.

pub mod aead {
    //! The canonical Postern AEAD seal — XChaCha20-Poly1305, **versioned,
    //! context-bound and key-committing**.
    //!
    //! ## Wire format (v2)
    //!
    //! ```text
    //! 0x02 ‖ nonce (24) ‖ commit (32) ‖ AEAD-ciphertext (plaintext + 16-byte tag)
    //! ```
    //!
    //! Per seal, subkeys are derived with HKDF-SHA-256 from the caller's
    //! 32-byte key, salted by the fresh random nonce and labeled with a
    //! domain string plus the caller's `context`:
    //!
    //! ```text
    //! enc_key = HKDF(salt = nonce, ikm = key, info = "postern-seal/v2/enc"    ‖ context)
    //! commit  = HKDF(salt = nonce, ikm = key, info = "postern-seal/v2/commit" ‖ context)
    //! ```
    //!
    //! - **Key commitment:** `commit` is stored in the header and checked
    //!   (constant-time) before decryption. A ciphertext that opens under two
    //!   different keys would need an HKDF-SHA-256 output collision, so
    //!   cross-key ciphertext substitution ("invisible salamander"-style
    //!   partitioning) is excluded. This is the same committing construction
    //!   the AWS Encryption SDK uses (derive-and-store a key-commitment string)
    //!   — chosen over bleeding-edge committing-AEAD modes because it is the
    //!   mature, deployed technique.
    //! - **Context binding / domain separation:** `context` (e.g.
    //!   `b"postern-vault/v1"`) enters both HKDF `info` strings *and* the AEAD
    //!   associated data, so a blob sealed for one product/purpose cannot be
    //!   opened as another even under the same 32-byte key.
    //! - **Versioning:** the leading version byte gives future format/KDF bumps
    //!   an in-band signal instead of downgrade-by-guessing.
    //!
    //! ## Legacy format (read-only)
    //!
    //! Pre-v2 blobs are bare `nonce ‖ ct` under the raw key: no version byte,
    //! no context binding, no key commitment. [`open`] / [`open_with_context`]
    //! still accept them (`context` is ignored on that path — legacy blobs
    //! were never bound to one), but nothing writes them anymore. A legacy
    //! blob whose random leading nonce byte happens to be `0x02` (probability
    //! 2⁻⁸) is first tried as v2 and then falls back to legacy; both paths are
    //! fully authenticated, so the fallback can fix a misparse but can never
    //! admit a forgery.
    use chacha20poly1305::aead::rand_core::RngCore;
    use chacha20poly1305::aead::{Aead, KeyInit, OsRng, Payload};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};
    use hkdf::Hkdf;
    use sha2::Sha256;
    use subtle::ConstantTimeEq;
    use zeroize::Zeroizing;

    /// XChaCha20-Poly1305 nonce length.
    pub const NONCE_LEN: usize = 24;
    /// Poly1305 authentication tag length.
    pub const TAG_LEN: usize = 16;
    /// Length of the stored key-commitment string (HKDF-SHA-256 output).
    pub const COMMIT_LEN: usize = 32;
    /// Version byte of the current (key-committing) wire format.
    pub const VERSION_V2: u8 = 0x02;

    const V2_HEADER_LEN: usize = 1 + NONCE_LEN + COMMIT_LEN;
    const V2_MIN_LEN: usize = V2_HEADER_LEN + TAG_LEN;
    const LEGACY_MIN_LEN: usize = NONCE_LEN + TAG_LEN;

    const ENC_LABEL: &[u8] = b"postern-seal/v2/enc";
    const COMMIT_LABEL: &[u8] = b"postern-seal/v2/commit";
    const AAD_LABEL: &[u8] = b"postern-seal/v2/aad";

    // Compile-time guarantee that the cipher's internal key copy is wiped on
    // drop (chacha20poly1305 impls ZeroizeOnDrop for ChaChaPoly1305). If a
    // dependency bump silently loses this, the build fails instead of leaking.
    const _: () = {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        let _ = assert_zeroize_on_drop::<XChaCha20Poly1305>;
    };

    #[derive(Debug, thiserror::Error)]
    pub enum SealError {
        #[error("seal failed")]
        Seal,
        #[error("open failed — wrong key, wrong context, or tampered data")]
        Open,
        #[error("corrupt sealed data")]
        Corrupt,
    }

    /// `enc_key` (zeroized on drop) and `commit` for one (key, nonce, context).
    fn derive_subkeys(
        key: &[u8; 32],
        nonce: &[u8],
        context: &[u8],
    ) -> (Zeroizing<[u8; 32]>, [u8; COMMIT_LEN]) {
        let hk = Hkdf::<Sha256>::new(Some(nonce), key);
        let mut enc_key = Zeroizing::new([0u8; 32]);
        let mut commit = [0u8; COMMIT_LEN];
        // Labels are distinct fixed prefixes and `context` is the entire
        // remainder, so each info string is injective in (label, context).
        hk.expand_multi_info(&[ENC_LABEL, context], enc_key.as_mut())
            .expect("32 bytes is a valid HKDF-SHA-256 output length");
        hk.expand_multi_info(&[COMMIT_LABEL, context], &mut commit)
            .expect("32 bytes is a valid HKDF-SHA-256 output length");
        (enc_key, commit)
    }

    /// AAD = version ‖ label ‖ len(context) as u64-le ‖ context (injective).
    fn build_aad(context: &[u8]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(1 + AAD_LABEL.len() + 8 + context.len());
        aad.push(VERSION_V2);
        aad.extend_from_slice(AAD_LABEL);
        aad.extend_from_slice(&(context.len() as u64).to_le_bytes());
        aad.extend_from_slice(context);
        aad
    }

    /// Seal `plaintext` under a 32-byte key, bound to a caller-chosen
    /// `context` (a short domain string such as `b"postern-vault/v1"` —
    /// see the module docs). Output is the v2 wire format
    /// `0x02 ‖ nonce ‖ commit ‖ ciphertext`; opening requires the same key
    /// AND the same context.
    ///
    /// The caller owns `plaintext`; this function keeps no copy after
    /// returning (the derived subkey and the cipher's internal key copy are
    /// both zeroized). If your plaintext is a secret, zeroize your buffer
    /// once this returns.
    pub fn seal_with_context(
        key: &[u8; 32],
        context: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, SealError> {
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let (enc_key, commit) = derive_subkeys(key, &nonce, context);
        let cipher = XChaCha20Poly1305::new(enc_key.as_ref().into());
        let aad = build_aad(context);
        let ct = cipher
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad: &aad })
            .map_err(|_| SealError::Seal)?;
        let mut out = Vec::with_capacity(V2_HEADER_LEN + ct.len());
        out.push(VERSION_V2);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&commit);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Open a blob sealed by [`seal_with_context`] under the same key and
    /// context. Also accepts legacy pre-v2 blobs (see module docs) — on that
    /// path `context` is ignored, because legacy blobs were never bound to one.
    pub fn open_with_context(
        key: &[u8; 32],
        context: &[u8],
        sealed: &[u8],
    ) -> Result<Vec<u8>, SealError> {
        if sealed.len() < LEGACY_MIN_LEN {
            // Shorter than any structurally valid blob in either format.
            return Err(SealError::Corrupt);
        }
        if sealed[0] == VERSION_V2 && sealed.len() >= V2_MIN_LEN {
            match open_v2(key, context, sealed) {
                Ok(pt) => Ok(pt),
                // 2⁻⁸ case: a legacy blob whose random nonce starts with 0x02.
                // Both formats are AEAD-authenticated, so trying the other can
                // fix a misparse but can never admit a forgery.
                Err(e) => open_legacy(key, sealed).map_err(|_| e),
            }
        } else {
            open_legacy(key, sealed)
        }
    }

    /// Seal `plaintext` under a 32-byte key with an **empty context**.
    /// Prefer [`seal_with_context`] with a product-specific context string;
    /// this remains for callers that manage domain separation themselves.
    /// Output is the v2 key-committing format.
    pub fn seal(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
        seal_with_context(key, b"", plaintext)
    }

    /// Open a blob sealed with [`seal`] (empty context). Also accepts legacy
    /// pre-v2 `nonce ‖ ct` blobs. Returns the plaintext, or an error on a
    /// wrong key / wrong context / tampered or truncated input.
    pub fn open(key: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>, SealError> {
        open_with_context(key, b"", sealed)
    }

    /// v2 path: check the key commitment (constant-time), then decrypt with
    /// the context-bound subkey and AAD. Caller has checked length + version.
    fn open_v2(key: &[u8; 32], context: &[u8], sealed: &[u8]) -> Result<Vec<u8>, SealError> {
        let nonce = &sealed[1..1 + NONCE_LEN];
        let stored_commit = &sealed[1 + NONCE_LEN..V2_HEADER_LEN];
        let ct = &sealed[V2_HEADER_LEN..];
        let (enc_key, commit) = derive_subkeys(key, nonce, context);
        if !bool::from(commit[..].ct_eq(stored_commit)) {
            return Err(SealError::Open);
        }
        let cipher = XChaCha20Poly1305::new(enc_key.as_ref().into());
        let aad = build_aad(context);
        cipher
            .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: &aad })
            .map_err(|_| SealError::Open)
    }

    /// Legacy pre-v2 path: bare `nonce ‖ ct` under the raw key. Read-only;
    /// nothing writes this format anymore.
    fn open_legacy(key: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>, SealError> {
        if sealed.len() < LEGACY_MIN_LEN {
            // Cannot even hold a nonce and a Poly1305 tag: structurally
            // invalid, not "wrong key".
            return Err(SealError::Corrupt);
        }
        let (nonce_bytes, ct) = sealed.split_at(NONCE_LEN);
        let cipher = XChaCha20Poly1305::new(key.into());
        let nonce = XNonce::from_slice(nonce_bytes);
        cipher.decrypt(nonce, ct).map_err(|_| SealError::Open)
    }

    /// Legacy-format seal, exposed **only for tests** of the compatibility
    /// path. Never use in products: no version byte, no context binding, no
    /// key commitment.
    #[cfg(test)]
    pub(crate) fn seal_legacy_for_tests(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
        use chacha20poly1305::aead::AeadCore;
        let cipher = XChaCha20Poly1305::new(key.into());
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ct = cipher.encrypt(&nonce, plaintext).unwrap();
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(nonce.as_slice());
        out.extend_from_slice(&ct);
        out
    }
}

pub mod seal {
    //! The canonical **device-attestation transcript** — the exact bytes a Postern
    //! device signs (with its hybrid Falcon‖ML-DSA key) to prove it runs the
    //! genuine, unmodified build, and that a verifier (`postern-seal-companion`)
    //! reconstructs to check the signature.
    //!
    //! Defined ONCE here so a producer and a verifier can never disagree on the
    //! bytes. Two hygiene properties the ad-hoc concatenation lacked:
    //!   1. **Domain separation** — a unique tag prefix, so an attestation
    //!      signature can never be replayed as some other Postern signature
    //!      (a wallet tx, a courier handshake, …) that happened to share a layout.
    //!   2. **Length-prefixed variable field** — the optional TEE `measurement`
    //!      sits between two fixed fields; length-prefixing it makes the encoding
    //!      injective (no `None`-vs-empty or field-shift ambiguity).
    //!
    //! This is INTEGRITY of the signed transcript, not secrecy. It is NOT
    //! interchangeable with the node's cloud-TEE `bloch::attestation` (a SEV-SNP/TDX
    //! quote whose trust root is the hardware, not a device signature) — the two are
    //! complementary attestation models, deliberately distinct.

    /// Domain-separation tag. Bump the version suffix on any transcript change.
    pub const ATTESTATION_DOMAIN: &[u8] = b"postern-seal/attestation/v1";

    /// The exact bytes an attestation signs / verifies:
    /// `DOMAIN ‖ os_roothash(32) ‖ len(measurement) as u32-le ‖ measurement ‖ nonce(32)`.
    /// `None` and `Some(&[])` measurement are treated identically (length 0).
    ///
    /// # Panics
    ///
    /// If `measurement` is 4 GiB or larger — the u32 length prefix would
    /// silently truncate and void the injectivity property above. The
    /// measurement is producer-side input (the device's own TEE measurement,
    /// never attacker-supplied bytes on the verify path, which rebuilds the
    /// transcript from parsed fields), so a hard panic beats a silent
    /// collision.
    pub fn attestation_transcript(
        os_roothash: &[u8; 32],
        measurement: Option<&[u8]>,
        nonce: &[u8; 32],
    ) -> Vec<u8> {
        let m = measurement.unwrap_or(&[]);
        let m_len = u32::try_from(m.len())
            .expect("measurement must be < 4 GiB: the u32 length prefix must not truncate");
        let mut b = Vec::with_capacity(ATTESTATION_DOMAIN.len() + 32 + 4 + m.len() + 32);
        b.extend_from_slice(ATTESTATION_DOMAIN);
        b.extend_from_slice(os_roothash);
        b.extend_from_slice(&m_len.to_le_bytes());
        b.extend_from_slice(m);
        b.extend_from_slice(nonce);
        b
    }
}

pub mod kdf {
    //! Memory-hard key derivation: Argon2id with EXPLICITLY-PINNED parameters,
    //! in two labeled tiers.
    //!
    //! The KDF parameters are part of the wire format: the same passphrase and
    //! salt derive a *different* key under different parameters. Which tier a
    //! blob used must be recorded alongside it (the salt already is). Blobs
    //! sealed before the tier split used the floor parameters — open those
    //! with [`derive_key_floor`], then re-seal under [`derive_key`].

    use argon2::{Algorithm, Argon2, Params, Version};
    use chacha20poly1305::aead::rand_core::RngCore;
    use chacha20poly1305::aead::OsRng;
    use zeroize::Zeroizing;

    /// Recommended salt length for [`generate_salt`] (RFC 9106 recommends 16 bytes).
    pub const SALT_LEN: usize = 16;

    #[derive(Debug, thiserror::Error)]
    pub enum KdfError {
        #[error("key derivation failed: {0}")]
        Argon2(String),
    }

    // ── default tier (v2): at-rest vault master keys ────────────────────────
    // RFC 9106's second recommended option is m = 64 MiB, t = 3, p = 4. We pin
    // m = 64 MiB, t = 3 and set p = 1: the pure-Rust `argon2` crate computes
    // lanes serially, so p = 4 would add no attacker cost here while
    // quartering the memory-hardness per lane. 64 MiB / t = 3 matches the
    // deployed norm for offline-attackable vaults (e.g. Bitwarden's Argon2id
    // default). Memory cost: each derivation touches 64 MiB.
    const M_COST: u32 = 65536; // KiB = 64 MiB
    const T_COST: u32 = 3;
    const P_COST: u32 = 1;

    // ── floor tier (legacy / constrained): OWASP interactive minimum ────────
    // These EQUAL the argon2 0.5 library defaults (m = 19 MiB, t = 2, p = 1),
    // pinned explicitly so a future `argon2` crate bump that changes its
    // defaults cannot silently re-derive a different key.
    const M_COST_FLOOR: u32 = 19456; // KiB = 19 MiB
    const T_COST_FLOOR: u32 = 2;
    const P_COST_FLOOR: u32 = 1;

    fn derive(
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
        passphrase: &[u8],
        salt: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, KdfError> {
        let params = Params::new(m_cost, t_cost, p_cost, None)
            .map_err(|e| KdfError::Argon2(e.to_string()))?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = Zeroizing::new([0u8; 32]);
        argon
            .hash_password_into(passphrase, salt, key.as_mut())
            .map_err(|e| KdfError::Argon2(e.to_string()))?;
        Ok(key)
    }

    /// Derive a 32-byte key from a passphrase with **Argon2id** at the
    /// **at-rest tier** (m = 64 MiB, t = 3, p = 1 — see the module docs for
    /// the RFC 9106 rationale). This is the default for anything a stolen
    /// blob can be brute-forced against offline (vault master keys).
    ///
    /// `salt` must be at least 8 bytes (use [`generate_salt`] for new secrets)
    /// and stored alongside the sealed data. The returned key wipes itself
    /// from RAM on drop ([`Zeroizing`]); it derefs to `[u8; 32]` wherever a
    /// raw key is expected — avoid copying it out of the wrapper.
    ///
    /// **Breaking (pre-release):** before the tier split this function used
    /// the floor parameters; keys for blobs sealed back then must be
    /// re-derived with [`derive_key_floor`].
    pub fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, KdfError> {
        derive(M_COST, T_COST, P_COST, passphrase, salt)
    }

    /// Derive a 32-byte key at the **floor tier** — the OWASP *interactive
    /// login* minimum (m = 19 MiB, t = 2, p = 1). Use ONLY on memory-
    /// constrained targets that cannot afford 64 MiB, or to open blobs sealed
    /// before the tier split. This tier is deliberately labeled as a floor:
    /// it is low for an offline-attackable at-rest secret.
    pub fn derive_key_floor(
        passphrase: &[u8],
        salt: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, KdfError> {
        derive(M_COST_FLOOR, T_COST_FLOOR, P_COST_FLOOR, passphrase, salt)
    }

    /// A fresh random 16-byte KDF salt from the OS CSPRNG. Store it alongside
    /// the sealed data (it is not secret); never reuse a hard-coded salt.
    pub fn generate_salt() -> [u8; SALT_LEN] {
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        salt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = [7u8; 32];
        let sealed = aead::seal(&key, b"a sensitive document").unwrap();
        // The plaintext never appears in the sealed blob.
        assert!(!sealed.windows(9).any(|w| w == b"sensitive"));
        assert_eq!(aead::open(&key, &sealed).unwrap(), b"a sensitive document");
    }

    #[test]
    fn sealed_blob_is_versioned() {
        let sealed = aead::seal(&[7u8; 32], b"x").unwrap();
        assert_eq!(sealed[0], aead::VERSION_V2);
        assert_eq!(
            sealed.len(),
            1 + aead::NONCE_LEN + aead::COMMIT_LEN + 1 + aead::TAG_LEN
        );
    }

    #[test]
    fn context_binding_is_enforced() {
        let key = [3u8; 32];
        let sealed = aead::seal_with_context(&key, b"postern-vault/v1", b"secret").unwrap();
        // Same key, same context → opens.
        assert_eq!(
            aead::open_with_context(&key, b"postern-vault/v1", &sealed).unwrap(),
            b"secret"
        );
        // Same key, different / missing context → refuses. This is the
        // cross-product blob-substitution defense.
        assert!(aead::open_with_context(&key, b"postern-telephony/v1", &sealed).is_err());
        assert!(aead::open(&key, &sealed).is_err());
    }

    #[test]
    fn commit_tamper_is_detected() {
        let key = [4u8; 32];
        let mut sealed = aead::seal(&key, b"v").unwrap();
        sealed[1 + aead::NONCE_LEN] ^= 0xFF; // flip a key-commitment byte
        assert!(aead::open(&key, &sealed).is_err());
    }

    #[test]
    fn wrong_key_fails_to_open() {
        let sealed = aead::seal(&[1u8; 32], b"top secret").unwrap();
        assert!(matches!(aead::open(&[2u8; 32], &sealed), Err(aead::SealError::Open)));
    }

    #[test]
    fn tamper_is_detected() {
        let mut sealed = aead::seal(&[9u8; 32], b"v").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF;
        assert!(aead::open(&[9u8; 32], &sealed).is_err());
    }

    #[test]
    fn truncated_is_corrupt_not_wrong_key() {
        // Too short for either format → Corrupt (not "wrong key"), so a UI
        // never prompts "wrong passphrase?" for a truncated file.
        assert!(matches!(aead::open(&[0u8; 32], b"short"), Err(aead::SealError::Corrupt)));
        // 24..39 bytes: nonce-sized but cannot hold a Poly1305 tag.
        let blob = [0u8; aead::NONCE_LEN + aead::TAG_LEN - 1];
        assert!(matches!(aead::open(&[0u8; 32], &blob), Err(aead::SealError::Corrupt)));
    }

    #[test]
    fn legacy_blobs_still_open() {
        let key = [5u8; 32];
        // Legacy format: bare nonce ‖ ct under the raw key, no version byte.
        // Loop enough that some blobs start with 0x02 (the v2 version byte),
        // exercising the try-v2-then-fall-back path.
        for i in 0..64u8 {
            let msg = [i; 5];
            let legacy = aead::seal_legacy_for_tests(&key, &msg);
            assert_eq!(aead::open(&key, &legacy).unwrap(), msg);
            // Legacy blobs predate context binding: any context opens them.
            assert_eq!(aead::open_with_context(&key, b"ctx", &legacy).unwrap(), msg);
        }
    }

    #[test]
    fn attestation_transcript_is_domain_separated_and_injective() {
        use seal::{attestation_transcript, ATTESTATION_DOMAIN};
        let rh = [1u8; 32];
        let n = [2u8; 32];
        // Domain tag is present at the front (cross-protocol separation).
        let t = attestation_transcript(&rh, None, &n);
        assert!(t.starts_with(ATTESTATION_DOMAIN));
        // None and Some(empty) agree; a real measurement changes the transcript.
        assert_eq!(t, attestation_transcript(&rh, Some(&[]), &n));
        assert_ne!(t, attestation_transcript(&rh, Some(&[0xAA]), &n));
        // Length-prefixing makes it injective: moving a byte from measurement into
        // the (fixed-length) nonce region cannot collide.
        let a = attestation_transcript(&rh, Some(&[0xAA, 0xBB]), &n);
        let b = attestation_transcript(&rh, Some(&[0xAA]), &n);
        assert_ne!(a, b);
    }

    #[test]
    fn argon2_key_is_deterministic_and_tiers_differ() {
        let k1 = kdf::derive_key(b"correct horse battery staple", b"postern-salt-16b").unwrap();
        let k2 = kdf::derive_key(b"correct horse battery staple", b"postern-salt-16b").unwrap();
        assert_eq!(*k1, *k2);
        assert_ne!(*k1, *kdf::derive_key(b"wrong passphrase", b"postern-salt-16b").unwrap());
        // The floor tier derives a DIFFERENT key: the parameters are part of
        // the wire format.
        let floor =
            kdf::derive_key_floor(b"correct horse battery staple", b"postern-salt-16b").unwrap();
        assert_ne!(*k1, *floor);
    }

    #[test]
    fn generate_salt_is_random_and_sized() {
        let a = kdf::generate_salt();
        let b = kdf::generate_salt();
        assert_eq!(a.len(), kdf::SALT_LEN);
        assert_ne!(a, b, "two fresh salts must not collide");
        assert!(kdf::derive_key_floor(b"pw", &a).is_ok(), "generated salt is a valid Argon2 salt");
    }
}

/// Additional host-testable edge cases for the Postern AEAD seal. These probe
/// boundary conditions and per-region tamper points that the primary `tests`
/// module leaves implicit: exact v2 byte layout, key-commitment on a
/// one-bit-off key, context injectivity (prefix contexts), the deterministic
/// legacy-fallback branch, and tamper inside the ciphertext *body* (as opposed
/// to the Poly1305 tag). All are additive and test-only; they exercise the
/// public API plus the crate-private `seal_legacy_for_tests` helper.
#[cfg(test)]
mod edge_cases {
    use super::aead;

    // v2 header geometry, recomputed here so a silent layout change trips a test.
    const V2_HEADER_LEN: usize = 1 + aead::NONCE_LEN + aead::COMMIT_LEN; // 57
    const V2_MIN_LEN: usize = V2_HEADER_LEN + aead::TAG_LEN; // 73
    const LEGACY_MIN_LEN: usize = aead::NONCE_LEN + aead::TAG_LEN; // 40

    // ── v2 seal format (0x02 ‖ nonce ‖ commit ‖ ct) round-trip ──────────────

    #[test]
    fn v2_roundtrip_empty_plaintext_has_exact_layout() {
        let key = [0x11u8; 32];
        let sealed = aead::seal(&key, b"").unwrap();
        // Empty plaintext still yields a full header + a 16-byte tag, nothing more.
        assert_eq!(sealed[0], aead::VERSION_V2);
        assert_eq!(sealed.len(), V2_HEADER_LEN + aead::TAG_LEN);
        assert_eq!(aead::open(&key, &sealed).unwrap(), b"");
    }

    #[test]
    fn v2_roundtrip_large_plaintext_ct_len_is_pt_plus_tag() {
        let key = [0x22u8; 32];
        let pt = vec![0xABu8; 8192];
        let sealed = aead::seal(&key, &pt).unwrap();
        // ciphertext region = plaintext length + one Poly1305 tag.
        assert_eq!(sealed.len(), V2_HEADER_LEN + pt.len() + aead::TAG_LEN);
        assert_eq!(aead::open(&key, &sealed).unwrap(), pt);
    }

    #[test]
    fn two_seals_of_same_input_differ_but_both_open() {
        // Fresh random nonce per seal ⇒ nonce, commit and ct all differ, yet
        // both round-trip. Proves the seal is non-deterministic (no nonce reuse).
        let key = [0x33u8; 32];
        let a = aead::seal_with_context(&key, b"ctx", b"same message").unwrap();
        let b = aead::seal_with_context(&key, b"ctx", b"same message").unwrap();
        assert_ne!(a, b, "two seals must not be byte-identical (fresh nonce)");
        assert_ne!(a[1..1 + aead::NONCE_LEN], b[1..1 + aead::NONCE_LEN], "nonces differ");
        assert_eq!(aead::open_with_context(&key, b"ctx", &a).unwrap(), b"same message");
        assert_eq!(aead::open_with_context(&key, b"ctx", &b).unwrap(), b"same message");
    }

    // ── key commitment rejects a wrong key ──────────────────────────────────

    #[test]
    fn one_bit_off_key_is_rejected_by_commitment() {
        let key = [0x44u8; 32];
        let sealed = aead::seal(&key, b"balance: 100").unwrap();
        let mut near = key;
        near[0] ^= 0x01; // single-bit difference
        // Wrong key ⇒ different derived commit ⇒ Open (constant-time reject).
        assert!(matches!(aead::open(&near, &sealed), Err(aead::SealError::Open)));
        // Two unrelated wrong keys likewise fail.
        assert!(matches!(aead::open(&[0u8; 32], &sealed), Err(aead::SealError::Open)));
        assert!(matches!(aead::open(&[0xFFu8; 32], &sealed), Err(aead::SealError::Open)));
    }

    // ── wrong-context AAD rejects (including prefix injectivity) ─────────────

    #[test]
    fn prefix_context_does_not_open() {
        // Length-prefixed AAD + context in HKDF info ⇒ b"ab" and b"a" are
        // fully distinct domains; a context that is a prefix of another must
        // not open the other's blob.
        let key = [0x55u8; 32];
        let sealed = aead::seal_with_context(&key, b"ab", b"m").unwrap();
        assert!(aead::open_with_context(&key, b"a", &sealed).is_err());
        assert!(aead::open_with_context(&key, b"abc", &sealed).is_err());
        // Empty vs non-empty context are also distinct (asymmetry both ways).
        let empty = aead::seal(&key, b"m").unwrap();
        assert!(aead::open_with_context(&key, b"a", &empty).is_err());
        let nonempty = aead::seal_with_context(&key, b"a", b"m").unwrap();
        assert!(aead::open(&key, &nonempty).is_err());
    }

    // ── legacy pre-versioned blob still opens (deterministic fallback) ───────

    #[test]
    fn legacy_blob_starting_with_0x02_deterministically_falls_back() {
        // Force the try-v2-then-fall-back branch: keep making legacy blobs
        // until one's random leading nonce byte is 0x02 (the v2 version byte),
        // then confirm it still opens via the legacy fallback.
        let key = [0x66u8; 32];
        // Plaintext ≥ 33 bytes so the legacy blob is ≥ V2_MIN_LEN and is
        // actually *tried as v2 first* (then falls back), rather than being
        // routed straight to legacy by the length gate.
        let msg = b"legacy secret long enough to reach v2 min length";
        assert!(aead::NONCE_LEN + msg.len() + aead::TAG_LEN >= V2_MIN_LEN);
        let mut hit = false;
        for _ in 0..100_000 {
            let legacy = aead::seal_legacy_for_tests(&key, msg);
            if legacy[0] == aead::VERSION_V2 {
                assert!(legacy.len() >= V2_MIN_LEN, "sanity: long enough to be tried as v2");
                assert_eq!(aead::open(&key, &legacy).unwrap(), msg);
                hit = true;
                break;
            }
        }
        assert!(hit, "expected at least one legacy blob with a 0x02 leading byte in 100k tries");
    }

    #[test]
    fn legacy_blob_with_wrong_key_is_open_not_corrupt() {
        // A structurally valid legacy blob under the wrong key is an auth
        // failure (Open), never Corrupt — the UI must say "wrong key", not
        // "truncated file".
        let legacy = aead::seal_legacy_for_tests(&[0x77u8; 32], b"m");
        assert!(matches!(aead::open(&[0x78u8; 32], &legacy), Err(aead::SealError::Open)));
    }

    #[test]
    fn short_0x02_blob_below_v2_min_is_handled_as_legacy() {
        // First byte 0x02 but too short to be v2 (len in [LEGACY_MIN_LEN,
        // V2_MIN_LEN)) ⇒ routed to the legacy path, which authenticates and
        // rejects it as Open (not a panic, not Corrupt).
        let blob = [0x02u8; V2_MIN_LEN - 1];
        assert!(blob.len() >= LEGACY_MIN_LEN && blob.len() < V2_MIN_LEN);
        assert!(matches!(aead::open(&[0u8; 32], &blob), Err(aead::SealError::Open)));
    }

    // ── tamper inside the ciphertext body (not the tag) ─────────────────────

    #[test]
    fn tamper_in_ciphertext_body_fails() {
        // Flip the FIRST ciphertext byte (encrypted plaintext[0]) — distinct
        // from the primary suite's tag-byte flip. AEAD integrity must catch it.
        let key = [0x88u8; 32];
        let sealed = aead::seal(&key, b"a sensitive document").unwrap();
        let mut t = sealed.clone();
        t[V2_HEADER_LEN] ^= 0xFF; // first byte of the ciphertext body
        assert!(matches!(aead::open(&key, &t), Err(aead::SealError::Open)));
    }

    #[test]
    fn tamper_in_nonce_region_fails() {
        // Flipping a nonce byte re-derives different subkeys ⇒ the stored
        // commit no longer matches ⇒ rejected before decryption.
        let key = [0x99u8; 32];
        let sealed = aead::seal(&key, b"m").unwrap();
        let mut t = sealed.clone();
        t[1] ^= 0xFF; // first nonce byte
        assert!(matches!(aead::open(&key, &t), Err(aead::SealError::Open)));
    }

    #[test]
    fn every_single_byte_flip_breaks_the_seal() {
        // Exhaustive single-byte-flip: no position in a v2 blob can be mutated
        // and still open. Covers version byte, nonce, commit, ct body and tag.
        let key = [0xA5u8; 32];
        let sealed = aead::seal_with_context(&key, b"postern-vault/v1", b"funds").unwrap();
        for i in 0..sealed.len() {
            let mut t = sealed.clone();
            t[i] ^= 0xFF;
            assert!(
                aead::open_with_context(&key, b"postern-vault/v1", &t).is_err(),
                "flipping byte {i} must break the seal"
            );
        }
    }
}
