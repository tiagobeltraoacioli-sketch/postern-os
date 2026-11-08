//! # postern-backup-net
//!
//! **UNAUDITED wiring crate — REAL confidentiality, not a complete backup
//! system.** This is the crate `bloch-data` (`data/postern-data`) repeatedly
//! defers its real crypto to: the place its zero-dependency seams get plugged
//! into genuine primitives. Spec:
//! `docs/specs/POSTERN-DATA-FILECOIN-DESIGN.md`, §5.
//!
//! ## What this crate ships today
//!
//! [`PosternSealer`] — a concrete implementation of
//! [`bloch_data::seal::Sealer`] and [`bloch_data::seal::Opener`] over the
//! **canonical Postern seal** in [`postern_core::aead`]: XChaCha20-Poly1305 v2,
//! **key-committing**, **context-bound**, with its 32-byte key derived by the
//! memory-hard **Argon2id** KDF in [`postern_core::kdf`]. It is a thin,
//! one-to-one pass-through: [`Sealer::seal`](bloch_data::seal::Sealer::seal)
//! calls [`postern_core::aead::seal_with_context`] and
//! [`Opener::open`](bloch_data::seal::Opener::open) calls
//! [`postern_core::aead::open_with_context`], mapping
//! [`postern_core::aead::SealError`] one-to-one onto
//! [`bloch_data::seal::SealError`].
//!
//! Unlike `bloch-data`'s in-crate [`bloch_data::seal::MockSealer`] — a **zero
//! confidentiality** test fixture that frames the plaintext verbatim behind a
//! magic and a toy checksum — [`PosternSealer`] genuinely **encrypts**: the
//! sealed blob is XChaCha20-Poly1305 ciphertext (indistinguishable from random)
//! and the plaintext never appears in it. That is the whole point of this
//! crate: to cross the confidentiality seam for real.
//!
//! ## The integrity leg is now REAL too (feature-wired)
//!
//! This crate enables `bloch-data`'s `hash` feature and re-exports its real
//! `SHAKE-256/256` adapter as [`Shake256Hasher`] (with the [`Hasher`] seam).
//! The end-to-end pipeline (`tests/pipeline.rs`) uses it to wire **genuine**
//! integrity through the whole path:
//! * the DATA0 anchor's `manifest_root` (its `new_root`) is
//!   `SHAKE-256/256(DOMAIN_MANIFEST_ROOT ‖ `[`Package::committed_prefix`](bloch_data::package::Package::committed_prefix)`)`,
//!   and a verifier **independently recomputes** it and asserts equality
//!   (`bloch_data::verify::bind_anchor_to_package` over the real hasher); and
//! * every [`bloch_data::manifest::ManifestEntry::shake256`] is the real
//!   `SHAKE-256/256(DOMAIN_BLOB ‖ sealed_blob)`, so a fetched blob is
//!   re-hashed key-independently and the digest checked **before** the
//!   key-committing AEAD ever runs — a single-byte-swapped blob is rejected by
//!   the digest gate first.
//!
//! ## The authenticity leg is now REAL too ([`signer`])
//!
//! This crate now drives the **REAL ML-DSA-65 ‖ Falcon-1024 hybrid signer**
//! from `bloch-crypto` (the SAME crate the node, CLI and mobile wallet use).
//! The [`signer`] module fills the two slots `bloch-data` deliberately leaves
//! opaque:
//! * [`signer::sign_backup`] stamps the vault public key into
//!   [`Package::pk`](bloch_data::package::Package::pk), builds the DATA0
//!   [`AnchorEnvelope`](bloch_data::anchor::AnchorEnvelope) with the REAL
//!   SHAKE-256 `manifest_root` (its `new_root`) and the REAL `SHA3-256(pk)`
//!   `signer_commit`, hybrid-signs the anchor transcript, and writes the
//!   signature into [`Package::sig`](bloch_data::package::Package::sig); and
//! * [`signer::verify_signed_backup`] independently recomputes the SHAKE-256
//!   root, ties `signer_commit` to `pk`, pins `pk` to the caller's known vault
//!   key, and verifies **both** lattice halves of the hybrid signature —
//!   fail-closed on a single tampered byte in the sealed manifest, root, pk, or
//!   either signature half.
//!
//! ## What is deliberately OUT OF SCOPE
//!
//! This crate does **not** ship a **live** Storacha/Lighthouse network client
//! (the end-to-end test lands on [`bloch_data::backend::DirBackend`], the real
//! *durable on-disk spool*, not a live provider). Authenticity is only ever
//! established **relative to a pinned vault public key**: anchoring is
//! permissionless, so [`signer::verify_signed_backup`] requires the expected
//! vault `pk` a restoring user knows out-of-band.
//!
//! So this crate proves **real client-side confidentiality, real SHAKE-256
//! integrity, AND a real hybrid-PQ signature end-to-end over the durable
//! spool**, and nothing about the live network path. `designed != built !=
//! booted`. It is UNAUDITED and inherits the k=4, low-hashrate,
//! 51%-attackable, unaudited Bloch base in full.
//!
//! ## Key handling
//!
//! The seal key is held in a [`zeroize::Zeroizing`] buffer and wiped on drop.
//! Two constructors:
//! * [`PosternSealer::from_key`] — wrap a raw 32-byte key you already hold;
//! * [`PosternSealer::from_passphrase`] — derive the key with Argon2id from a
//!   passphrase and the public per-backup-set salt at a given
//!   [`bloch_data::package`] KDF tier ([`bloch_data::package::TIER_DEFAULT`] /
//!   [`bloch_data::package::TIER_FLOOR`]). The salt and tier are exactly the
//!   public fields the PBP0 [`bloch_data::package::Package`] carries for
//!   disaster restore, so the same passphrase re-derives the same key on a
//!   fresh device.
//!
//! Licensed under MIT OR Apache-2.0.

use bloch_data::package::{TIER_DEFAULT, TIER_FLOOR};
use bloch_data::seal::{Opener, SealError, Sealer};
use postern_core::aead;
use postern_core::kdf;
use zeroize::Zeroizing;

/// The REAL post-quantum integrity primitives, re-exported from `bloch-data`'s
/// `hash` feature (which this crate enables): the [`Hasher`] seam and its
/// concrete `SHAKE-256/256` adapter [`Shake256Hasher`]. This is the integrity
/// leg the wiring crate is responsible for — used by the end-to-end pipeline to
/// compute the DATA0 anchor's real `manifest_root` and every ManifestEntry's
/// real per-blob `shake256`, and to re-hash a fetched blob before the AEAD open.
pub use bloch_data::hash::{Hasher, Shake256Hasher};

/// The REAL hybrid post-quantum backup signer/verifier (ML-DSA-65 ‖
/// Falcon-1024) that fills the DATA0/PBP0 authenticity leg — see [`signer`].
pub mod signer;

pub use signer::{sign_backup, verify_signed_backup, BackupVerifyError, SignError, VaultSigner};

/// The real Postern-seal adapter: [`Sealer`] / [`Opener`] over
/// [`postern_core::aead`] (XChaCha20-Poly1305 v2, key-committing,
/// context-bound) keyed by an Argon2id-derived 32-byte key.
///
/// See the [crate docs](crate) for scope and honesty. The key is held in a
/// self-zeroizing buffer; clone with care (the clone holds its own zeroizing
/// copy of the key).
#[derive(Clone)]
pub struct PosternSealer {
    key: Zeroizing<[u8; 32]>,
}

/// Failure building a [`PosternSealer`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdapterError {
    /// The KDF tier byte was neither [`TIER_DEFAULT`] nor [`TIER_FLOOR`].
    UnknownTier(u8),
    /// Argon2id key derivation failed (e.g. a too-short salt); message is the
    /// underlying KDF error, rendered.
    Kdf(String),
}

impl core::fmt::Display for AdapterError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownTier(t) => write!(f, "postern-backup-net: unknown kdf tier {t}"),
            Self::Kdf(m) => write!(f, "postern-backup-net: key derivation failed: {m}"),
        }
    }
}

impl std::error::Error for AdapterError {}

impl PosternSealer {
    /// Wrap a raw 32-byte key already in hand (e.g. one you derived elsewhere).
    /// The key is moved into a self-zeroizing buffer.
    pub fn from_key(key: [u8; 32]) -> Self {
        Self { key: Zeroizing::new(key) }
    }

    /// Wrap a key already held in a [`Zeroizing`] buffer without copying it out
    /// of the wrapper.
    pub fn from_zeroizing_key(key: Zeroizing<[u8; 32]>) -> Self {
        Self { key }
    }

    /// Derive the seal key with **Argon2id** from `passphrase` and the public
    /// `salt`, at the [`bloch_data::package`] KDF `tier`
    /// ([`TIER_DEFAULT`] = 64 MiB/t=3, [`TIER_FLOOR`] = 19 MiB/t=2).
    ///
    /// `salt` and `tier` are the public fields the PBP0
    /// [`bloch_data::package::Package`] stores for restore, so the same
    /// passphrase re-derives the same key on any device. Fails with
    /// [`AdapterError::UnknownTier`] on an unknown tier byte or
    /// [`AdapterError::Kdf`] if Argon2id rejects the inputs.
    pub fn from_passphrase(
        passphrase: &[u8],
        salt: &[u8],
        tier: u8,
    ) -> Result<Self, AdapterError> {
        let key = match tier {
            TIER_DEFAULT => kdf::derive_key(passphrase, salt),
            TIER_FLOOR => kdf::derive_key_floor(passphrase, salt),
            other => return Err(AdapterError::UnknownTier(other)),
        }
        .map_err(|e| AdapterError::Kdf(e.to_string()))?;
        Ok(Self { key })
    }
}

/// Map [`postern_core::aead::SealError`] one-to-one onto the
/// [`bloch_data::seal::SealError`] vocabulary the seams speak. The two enums
/// are deliberately parallel (`Seal` / `Open` / `Corrupt`), so this is exact.
fn map_seal_error(e: aead::SealError) -> SealError {
    match e {
        aead::SealError::Seal => SealError::Seal,
        aead::SealError::Open => SealError::Open,
        aead::SealError::Corrupt => SealError::Corrupt,
    }
}

impl Sealer for PosternSealer {
    fn seal(&self, context: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
        aead::seal_with_context(&self.key, context, plaintext).map_err(map_seal_error)
    }
}

impl Opener for PosternSealer {
    fn open(&self, context: &[u8], sealed: &[u8]) -> Result<Vec<u8>, SealError> {
        aead::open_with_context(&self.key, context, sealed).map_err(map_seal_error)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const CTX: &[u8] = b"postern-backup/blob/v1";

    fn sealer() -> PosternSealer {
        PosternSealer::from_key([0x42; 32])
    }

    #[test]
    fn seal_open_round_trip_various_sizes() {
        let s = sealer();
        for pt in [&b""[..], b"hello", &vec![0xABu8; 8192][..]] {
            let blob = s.seal(CTX, pt).expect("seal");
            assert_eq!(s.open(CTX, &blob).expect("open"), pt);
        }
    }

    #[test]
    fn sealed_blob_is_real_ciphertext_not_plaintext() {
        // The distinguishing property from MockSealer: a real seal ENCRYPTS.
        let s = sealer();
        let pt = b"the kalinov bridge carries a sensitive secret payload";
        let blob = s.seal(CTX, pt).expect("seal");
        // The v2 wire format starts with the version byte 0x02.
        assert_eq!(blob[0], aead::VERSION_V2);
        // The plaintext never appears verbatim anywhere in the sealed blob.
        assert!(
            !blob.windows(pt.len()).any(|w| w == pt),
            "plaintext must not appear in the sealed blob"
        );
        // And the blob is not the plaintext.
        assert_ne!(&blob[..], &pt[..]);
    }

    #[test]
    fn two_seals_of_same_input_differ_but_both_open() {
        // Fresh random nonce per seal ⇒ non-deterministic ciphertext.
        let s = sealer();
        let a = s.seal(CTX, b"same message").unwrap();
        let b = s.seal(CTX, b"same message").unwrap();
        assert_ne!(a, b, "fresh nonce ⇒ two seals differ");
        assert_eq!(s.open(CTX, &a).unwrap(), b"same message");
        assert_eq!(s.open(CTX, &b).unwrap(), b"same message");
    }

    #[test]
    fn wrong_key_fails_closed_open() {
        let sealed = sealer().seal(CTX, b"secret").unwrap();
        let mut other_key = [0x42; 32];
        other_key[0] = 0x43;
        let other = PosternSealer::from_key(other_key);
        assert_eq!(other.open(CTX, &sealed), Err(SealError::Open));
    }

    #[test]
    fn wrong_context_fails_closed_open() {
        let s = sealer();
        let sealed = s.seal(CTX, b"secret").unwrap();
        assert_eq!(s.open(b"postern-backup/other/v1", &sealed), Err(SealError::Open));
    }

    #[test]
    fn tampered_blob_fails_closed_open() {
        let s = sealer();
        let mut blob = s.seal(CTX, b"secret").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xFF;
        assert_eq!(s.open(CTX, &blob), Err(SealError::Open));
    }

    #[test]
    fn truncated_blob_is_corrupt() {
        let s = sealer();
        assert_eq!(s.open(CTX, b"short"), Err(SealError::Corrupt));
    }

    #[test]
    fn never_panics_on_random_ish_garbage() {
        let s = sealer();
        let mut state = 0x1234_5678_9ABC_DEF0u64;
        for len in 0..400usize {
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                buf.push(state as u8);
            }
            let _ = s.open(CTX, &buf); // must not panic on any input
        }
    }

    // ── Argon2id key derivation ──────────────────────────────────────────────

    #[test]
    fn from_passphrase_is_deterministic_and_round_trips() {
        let salt = [0x7E; 16];
        let a = PosternSealer::from_passphrase(b"correct horse battery staple", &salt, TIER_FLOOR)
            .expect("derive");
        let b = PosternSealer::from_passphrase(b"correct horse battery staple", &salt, TIER_FLOOR)
            .expect("derive");
        // Same passphrase+salt+tier ⇒ same key ⇒ each opens the other's blob.
        let blob = a.seal(CTX, b"restore me on a fresh device").unwrap();
        assert_eq!(b.open(CTX, &blob).unwrap(), b"restore me on a fresh device");
    }

    #[test]
    fn from_passphrase_wrong_passphrase_derives_a_different_key() {
        let salt = [0x7E; 16];
        let good =
            PosternSealer::from_passphrase(b"right passphrase", &salt, TIER_FLOOR).unwrap();
        let bad = PosternSealer::from_passphrase(b"wrong passphrase", &salt, TIER_FLOOR).unwrap();
        let blob = good.seal(CTX, b"secret").unwrap();
        assert_eq!(bad.open(CTX, &blob), Err(SealError::Open));
    }

    #[test]
    fn from_passphrase_tiers_derive_different_keys() {
        let salt = [0x7E; 16];
        let default =
            PosternSealer::from_passphrase(b"pw", &salt, TIER_DEFAULT).unwrap();
        let floor = PosternSealer::from_passphrase(b"pw", &salt, TIER_FLOOR).unwrap();
        // The KDF parameters are part of the wire format: a blob sealed under
        // the default tier does not open under a floor-tier key.
        let blob = default.seal(CTX, b"secret").unwrap();
        assert_eq!(floor.open(CTX, &blob), Err(SealError::Open));
    }

    #[test]
    fn from_passphrase_rejects_unknown_tier() {
        // PosternSealer holds key material, so it is deliberately not Debug /
        // PartialEq; match on the error rather than assert_eq! over the Result.
        let err = PosternSealer::from_passphrase(b"pw", &[0u8; 16], 0x02)
            .err()
            .expect("unknown tier must be rejected");
        assert_eq!(err, AdapterError::UnknownTier(0x02));
    }
}
