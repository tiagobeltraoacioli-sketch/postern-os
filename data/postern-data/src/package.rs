//! PBP0 backup package: strict little-endian binary codec.
//!
//! Spec: `docs/specs/POSTERN-DATA-FILECOIN-DESIGN.md`, §3.2 ("Package format
//! `PBP0`, plaintext wrapper — this is the uploaded manifest object"). The
//! package wraps the **sealed** PBM0 manifest ciphertext together with the
//! public salt/tier needed for disaster restore and the backup signer's
//! public key + hybrid signature. Wire layout (all multi-byte integers LE):
//!
//! ```text
//! offset  size                field
//! 0       4                   magic ASCII "PBP0"   (50 42 50 30)
//! 4       1                   version u8 = 0x00
//! 5       1                   kdf_tier u8          0x00 = default (Argon2id 64 MiB/t=3/p=1),
//!                                                  0x01 = floor (19 MiB/t=2/p=1)
//! 6       16                  salt [16]            NOT secret; MUST be recoverable for restore
//! 22      4                   sealed_manifest_len u32 LE
//! 26      sealed_manifest_len sealed_manifest      (aead v2 blob of the PBM0 manifest)
//! ── manifest_root = SHAKE-256/256 over bytes [0 .. end of sealed_manifest] ──
//! ...     4                   pk_len  u32 LE
//! ...     pk_len              pk                   (suite-enveloped bloch-crypto public key, suite 0x0001)
//! ...     4                   sig_len u32 LE
//! ...     sig_len             sig                  (suite-enveloped hybrid signature, ≈ 4.6 KB)
//! ```
//!
//! `manifest_root` (the DATA0 anchor's commitment) is the SHAKE-256/256 of the
//! **committed prefix** — bytes `[0 .. end of sealed_manifest]` — so it commits
//! to the salt and tier *as well as* the sealed manifest ciphertext, and
//! because the sealed manifest carries every entry's `content_cid` and
//! `shake256`, the single 32-byte root transitively commits to the whole
//! backup-set's ciphertext.
//!
//! HONESTY (see crate docs): this crate does **not** hash, seal, or sign. The
//! `sealed_manifest`, `pk`, and `sig` are opaque byte slots carried verbatim;
//! [`Package::committed_prefix`] returns the exact bytes a signer/verifier
//! hashes to obtain `manifest_root`, but the SHAKE-256 itself and the
//! ML-DSA-65‖Falcon-1024 sign/verify live behind the `postern-backup-net`
//! boundary, never here.

/// 4-byte magic prefix identifying a PBP0 backup package (`50 42 50 30`).
pub const PACKAGE_MAGIC: [u8; 4] = *b"PBP0";
/// Wire-format version this crate encodes and accepts (PBP0 draft).
pub const PACKAGE_VERSION: u8 = 0x00;
/// Public per-backup-set KDF salt length (bytes).
pub const SALT_LEN: usize = 16;
/// `kdf_tier` value: default Argon2id tier (64 MiB, t=3, p=1).
pub const TIER_DEFAULT: u8 = 0x00;
/// `kdf_tier` value: floor Argon2id tier (19 MiB, t=2, p=1).
pub const TIER_FLOOR: u8 = 0x01;
/// Fixed size of the package header up to and including `sealed_manifest_len`:
/// magic(4) + version(1) + kdf_tier(1) + salt(16) + sealed_manifest_len(4).
pub const PACKAGE_HEADER_LEN: usize = 26;

// ── Errors ────────────────────────────────────────────────────────────────────

/// Typed encode/decode failure. Decoding never panics; encoding fails only on
/// a field that cannot fit its length prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PackageError {
    /// Payload does not start with [`PACKAGE_MAGIC`].
    BadMagic,
    /// Magic matched but the version byte is not [`PACKAGE_VERSION`].
    BadVersion(u8),
    /// `kdf_tier` is neither [`TIER_DEFAULT`] nor [`TIER_FLOOR`].
    BadTier(u8),
    /// Payload ended before a required field was fully read.
    Truncated,
    /// Bytes remain after a complete, valid package.
    TrailingBytes,
    /// The sealed manifest is longer than `u32::MAX` (encode-side guard).
    SealedManifestTooLong(usize),
    /// The public key is longer than `u32::MAX` (encode-side guard).
    PkTooLong(usize),
    /// The signature is longer than `u32::MAX` (encode-side guard).
    SigTooLong(usize),
}

impl core::fmt::Display for PackageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadMagic => write!(f, "pbp0 package: bad magic"),
            Self::BadVersion(v) => write!(f, "pbp0 package: unsupported version {v}"),
            Self::BadTier(t) => write!(f, "pbp0 package: unknown kdf_tier {t}"),
            Self::Truncated => write!(f, "pbp0 package: truncated payload"),
            Self::TrailingBytes => write!(f, "pbp0 package: trailing bytes after payload"),
            Self::SealedManifestTooLong(n) => {
                write!(f, "pbp0 package: sealed_manifest too long ({n} > u32::MAX)")
            }
            Self::PkTooLong(n) => write!(f, "pbp0 package: pk too long ({n} > u32::MAX)"),
            Self::SigTooLong(n) => write!(f, "pbp0 package: sig too long ({n} > u32::MAX)"),
        }
    }
}

impl std::error::Error for PackageError {}

// ── Package ─────────────────────────────────────────────────────────────────

/// A decoded PBP0 backup package — the plaintext wrapper uploaded to the
/// provider. `sealed_manifest`, `pk`, and `sig` are opaque slots.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Package {
    /// Argon2id tier selector ([`TIER_DEFAULT`] / [`TIER_FLOOR`]); public.
    pub kdf_tier: u8,
    /// Per-backup-set KDF salt. NOT secret; MUST be recoverable for restore.
    pub salt: [u8; SALT_LEN],
    /// The sealed (AEAD v2) PBM0 manifest ciphertext. Opaque here.
    pub sealed_manifest: Vec<u8>,
    /// Suite-enveloped backup-signer public key (suite 0x0001). Opaque here.
    pub pk: Vec<u8>,
    /// Suite-enveloped ML-DSA-65‖Falcon-1024 hybrid signature over the anchor
    /// transcript (§3.2). Opaque here — this crate never verifies it.
    pub sig: Vec<u8>,
}

impl Package {
    /// Encode to the canonical wire form. Fails only when a field is too long
    /// to fit its length prefix (a caller-side invariant violation).
    pub fn encode(&self) -> Result<Vec<u8>, PackageError> {
        if self.sealed_manifest.len() > u32::MAX as usize {
            return Err(PackageError::SealedManifestTooLong(self.sealed_manifest.len()));
        }
        if self.pk.len() > u32::MAX as usize {
            return Err(PackageError::PkTooLong(self.pk.len()));
        }
        if self.sig.len() > u32::MAX as usize {
            return Err(PackageError::SigTooLong(self.sig.len()));
        }
        let mut out = Vec::with_capacity(PACKAGE_HEADER_LEN + self.sealed_manifest.len());
        out.extend_from_slice(&PACKAGE_MAGIC);
        out.push(PACKAGE_VERSION);
        out.push(self.kdf_tier);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&(self.sealed_manifest.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.sealed_manifest);
        out.extend_from_slice(&(self.pk.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.pk);
        out.extend_from_slice(&(self.sig.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.sig);
        Ok(out)
    }

    /// The committed prefix — bytes `[0 .. end of sealed_manifest]` — over
    /// which `manifest_root = SHAKE-256/256(prefix)` is computed (§3.2). Pure
    /// function of the package; the hash itself lives outside this crate, so
    /// this method keeps signer and verifier in byte-agreement. Fails with the
    /// same length guard as [`Package::encode`].
    pub fn committed_prefix(&self) -> Result<Vec<u8>, PackageError> {
        if self.sealed_manifest.len() > u32::MAX as usize {
            return Err(PackageError::SealedManifestTooLong(self.sealed_manifest.len()));
        }
        let mut out = Vec::with_capacity(PACKAGE_HEADER_LEN + self.sealed_manifest.len());
        out.extend_from_slice(&PACKAGE_MAGIC);
        out.push(PACKAGE_VERSION);
        out.push(self.kdf_tier);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&(self.sealed_manifest.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.sealed_manifest);
        Ok(out)
    }

    /// Strict decode. Rejects bad magic, bad version, unknown tier, truncation
    /// and trailing bytes — each with a typed [`PackageError`]. Never panics
    /// on any input (adversarial length prefixes fail bounds checks rather
    /// than pre-allocating).
    pub fn decode(bytes: &[u8]) -> Result<Package, PackageError> {
        let mut cur = Cursor::new(bytes);

        if cur.take(4)? != PACKAGE_MAGIC {
            return Err(PackageError::BadMagic);
        }
        let version = cur.take_u8()?;
        if version != PACKAGE_VERSION {
            return Err(PackageError::BadVersion(version));
        }
        let kdf_tier = cur.take_u8()?;
        if kdf_tier != TIER_DEFAULT && kdf_tier != TIER_FLOOR {
            return Err(PackageError::BadTier(kdf_tier));
        }
        let salt = cur.take_salt()?;
        let sealed_manifest_len = cur.take_u32_le()? as usize;
        let sealed_manifest = cur.take(sealed_manifest_len)?.to_vec();
        let pk_len = cur.take_u32_le()? as usize;
        let pk = cur.take(pk_len)?.to_vec();
        let sig_len = cur.take_u32_le()? as usize;
        let sig = cur.take(sig_len)?.to_vec();

        if !cur.is_exhausted() {
            return Err(PackageError::TrailingBytes);
        }
        Ok(Package { kdf_tier, salt, sealed_manifest, pk, sig })
    }
}

// ── Bounds-checked cursor (no unsafe, no deps, checked arithmetic) ────────────

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], PackageError> {
        let end = self.pos.checked_add(n).ok_or(PackageError::Truncated)?;
        if end > self.bytes.len() {
            return Err(PackageError::Truncated);
        }
        let s = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn take_u8(&mut self) -> Result<u8, PackageError> {
        Ok(self.take(1)?[0])
    }

    fn take_u32_le(&mut self) -> Result<u32, PackageError> {
        let mut b = [0u8; 4];
        b.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(b))
    }

    fn take_salt(&mut self) -> Result<[u8; SALT_LEN], PackageError> {
        let mut b = [0u8; SALT_LEN];
        b.copy_from_slice(self.take(SALT_LEN)?);
        Ok(b)
    }

    fn is_exhausted(&self) -> bool {
        self.pos == self.bytes.len()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Package {
        Package {
            kdf_tier: TIER_DEFAULT,
            salt: [0x11; SALT_LEN],
            sealed_manifest: vec![0x22; 40],
            pk: vec![0x33; 24],
            sig: vec![0x44; 128],
        }
    }

    #[test]
    fn header_offsets_are_pinned() {
        // Offsets transcribed from spec §3.2, not from encode().
        let p = Package {
            kdf_tier: TIER_FLOOR,
            salt: [0xA1; SALT_LEN],
            sealed_manifest: vec![0xBB; 3],
            pk: vec![0xCC; 2],
            sig: vec![0xDD; 1],
        };
        let b = p.encode().unwrap();
        assert_eq!(&b[0..4], b"PBP0");
        assert_eq!(&b[0..4], &[0x50, 0x42, 0x50, 0x30]);
        assert_eq!(b[4], 0x00); // version
        assert_eq!(b[5], 0x01); // kdf_tier = floor
        assert_eq!(&b[6..22], &[0xA1; SALT_LEN]); // salt
        assert_eq!(&b[22..26], &3u32.to_le_bytes()); // sealed_manifest_len
        assert_eq!(PACKAGE_HEADER_LEN, 26);
        assert_eq!(&b[26..29], &[0xBB; 3]); // sealed_manifest
        assert_eq!(&b[29..33], &2u32.to_le_bytes()); // pk_len
        assert_eq!(&b[33..35], &[0xCC; 2]); // pk
        assert_eq!(&b[35..39], &1u32.to_le_bytes()); // sig_len
        assert_eq!(&b[39..40], &[0xDD; 1]); // sig
        assert_eq!(b.len(), 40);
    }

    #[test]
    fn committed_prefix_is_encode_up_to_sealed_manifest() {
        let p = sample();
        let full = p.encode().unwrap();
        let prefix = p.committed_prefix().unwrap();
        // prefix == header + sealed_manifest == bytes [0 .. 26 + 40]
        assert_eq!(prefix.len(), PACKAGE_HEADER_LEN + p.sealed_manifest.len());
        assert_eq!(&full[..prefix.len()], &prefix[..]);
        // and it stops exactly before pk_len
        assert_eq!(&full[prefix.len()..prefix.len() + 4], &(p.pk.len() as u32).to_le_bytes());
    }

    #[test]
    fn round_trip_various() {
        for p in [
            Package { kdf_tier: TIER_DEFAULT, salt: [0; SALT_LEN], sealed_manifest: vec![], pk: vec![], sig: vec![] },
            sample(),
            Package {
                kdf_tier: TIER_FLOOR,
                salt: [0xFF; SALT_LEN],
                sealed_manifest: (0u8..=255).collect(),
                pk: vec![0x01; 1],
                sig: (0u8..200).collect(),
            },
        ] {
            let bytes = p.encode().unwrap();
            let decoded = Package::decode(&bytes).expect("valid package must decode");
            assert_eq!(decoded, p);
            assert_eq!(decoded.encode().unwrap(), bytes); // encode∘decode == identity
        }
    }

    #[test]
    fn rejects_bad_magic() {
        let mut b = sample().encode().unwrap();
        b[0] ^= 0xFF;
        assert_eq!(Package::decode(&b), Err(PackageError::BadMagic));
        assert_eq!(Package::decode(b"PBM0\x00"), Err(PackageError::BadMagic));
        assert_eq!(Package::decode(&[]), Err(PackageError::Truncated));
    }

    #[test]
    fn rejects_bad_version() {
        let mut b = sample().encode().unwrap();
        b[4] = 0x01;
        assert_eq!(Package::decode(&b), Err(PackageError::BadVersion(0x01)));
    }

    #[test]
    fn rejects_unknown_tier() {
        let mut b = sample().encode().unwrap();
        b[5] = 0x02;
        assert_eq!(Package::decode(&b), Err(PackageError::BadTier(0x02)));
        b[5] = 0xFF;
        assert_eq!(Package::decode(&b), Err(PackageError::BadTier(0xFF)));
    }

    #[test]
    fn rejects_truncation_at_every_prefix() {
        let full = sample().encode().unwrap();
        for cut in 0..full.len() {
            let err = Package::decode(&full[..cut])
                .expect_err("every strict prefix must fail");
            assert!(
                matches!(err, PackageError::Truncated | PackageError::BadMagic),
                "unexpected error at cut {cut}: {err:?}"
            );
        }
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut b = sample().encode().unwrap();
        b.push(0x00);
        assert_eq!(Package::decode(&b), Err(PackageError::TrailingBytes));
    }

    #[test]
    fn adversarial_length_prefix_does_not_panic_or_over_allocate() {
        // A huge sealed_manifest_len with no backing bytes must fail Truncated.
        let mut b = Vec::new();
        b.extend_from_slice(&PACKAGE_MAGIC);
        b.push(PACKAGE_VERSION);
        b.push(TIER_DEFAULT);
        b.extend_from_slice(&[0u8; SALT_LEN]);
        b.extend_from_slice(&u32::MAX.to_le_bytes()); // sealed_manifest_len = 4 billion
        assert_eq!(Package::decode(&b), Err(PackageError::Truncated));
    }

    #[test]
    fn never_panics_on_random_ish_garbage() {
        let mut state = 0x1234_5678_9ABC_DEF0u64;
        for len in 0..500usize {
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                buf.push(state as u8);
            }
            let _ = Package::decode(&buf); // must not panic
            let mut with_magic = Vec::with_capacity(len + 6);
            with_magic.extend_from_slice(&PACKAGE_MAGIC);
            with_magic.push(PACKAGE_VERSION);
            with_magic.push(TIER_DEFAULT);
            with_magic.extend_from_slice(&buf);
            let _ = Package::decode(&with_magic); // must not panic
        }
    }
}
