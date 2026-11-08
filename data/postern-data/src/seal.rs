//! `Sealer` / `Opener` — the confidentiality seam.
//!
//! Spec: `docs/specs/POSTERN-DATA-FILECOIN-DESIGN.md`, §5. Confidentiality is
//! the existing **Postern seal** (`crates/postern-core`: XChaCha20-Poly1305
//! v2, key-committing, context-bound, Argon2id-derived key). This crate does
//! **NOT** re-implement any of that — it only defines the boundary two traits
//! wide, so the real `postern-core` AEAD plugs in on one side and the backup
//! pipeline calls it on the other.
//!
//! The trait vocabulary mirrors `postern_core::aead::SealError` deliberately
//! (`Seal` / `Open` / `Corrupt`) so the real adapter is a thin pass-through:
//!
//! ```ignore
//! // in the (later) wiring crate, NOT here:
//! struct PosternSealer { key: Zeroizing<[u8; 32]> }
//! impl Sealer for PosternSealer {
//!     fn seal(&self, ctx: &[u8], pt: &[u8]) -> Result<Vec<u8>, SealError> {
//!         postern_core::aead::seal_with_context(&self.key, ctx, pt)
//!             .map_err(SealError::from_core)
//!     }
//! }
//! ```
//!
//! HONESTY (see crate docs): the only implementation in this crate is
//! [`MockSealer`], a **test fixture with ZERO confidentiality** — it does not
//! encrypt. It exists solely so the offline pipeline and its adversarial
//! tests (wrong key, wrong context, truncation, tamper) can run with no
//! crypto dependency. Never ship [`MockSealer`] on a real backup path; never
//! read its framing as a security property.

/// Failure vocabulary, mirroring `postern_core::aead::SealError` so a real
/// adapter maps one-to-one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealError {
    /// Sealing failed.
    Seal,
    /// Opening failed — wrong key, wrong context, or tampered data.
    Open,
    /// Structurally corrupt sealed data (too short / bad framing).
    Corrupt,
}

impl core::fmt::Display for SealError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Seal => write!(f, "seal failed"),
            Self::Open => write!(f, "open failed — wrong key, wrong context, or tampered data"),
            Self::Corrupt => write!(f, "corrupt sealed data"),
        }
    }
}

impl std::error::Error for SealError {}

/// Seals plaintext into a context-bound blob. Implemented for real by an
/// adapter over `postern_core::aead::seal_with_context`; the caller owns and
/// should zeroize its plaintext buffer afterwards.
pub trait Sealer {
    /// Seal `plaintext` bound to `context`. Opening requires the same key
    /// (held by the impl) AND the same `context`.
    fn seal(&self, context: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SealError>;
}

/// Opens a context-bound sealed blob. Implemented for real by an adapter over
/// `postern_core::aead::open_with_context`.
pub trait Opener {
    /// Open `sealed`, requiring the same `context` used to seal it.
    /// `Err(Open)` on wrong key / context / tamper, `Err(Corrupt)` if the
    /// input is structurally too short.
    fn open(&self, context: &[u8], sealed: &[u8]) -> Result<Vec<u8>, SealError>;
}

// ── MockSealer — test fixture, NOT crypto ─────────────────────────────────────

/// A reversible framing that stands in for the seal in offline tests.
///
/// **ZERO confidentiality: this does NOT encrypt.** It frames the plaintext
/// with a magic, a 1-byte key-commit (a fold of the 32-byte key), the bound
/// context, and a checksum, so tests can exercise the seam's *failure modes*
/// — wrong key ⇒ [`SealError::Open`], wrong context ⇒ [`SealError::Open`],
/// tampered bytes ⇒ [`SealError::Open`], truncation ⇒ [`SealError::Corrupt`]
/// — without pulling in real crypto. The key-commit and checksum are toy
/// 1- and 8-byte folds, NOT a MAC. Do not mistake any of this for security.
///
/// Wire framing (little-endian):
/// `MAGIC(8) ‖ key_commit(1) ‖ ctx_len u32 ‖ context ‖ checksum(8) ‖ plaintext`.
#[derive(Clone, Debug)]
pub struct MockSealer {
    key: [u8; 32],
}

const MOCK_MAGIC: [u8; 8] = *b"MOCKSEAL";
const MOCK_MIN_LEN: usize = 8 + 1 + 4 + 8; // magic + commit + ctx_len + checksum

impl MockSealer {
    /// A mock sealer bound to `key`. Two `MockSealer`s open each other's
    /// blobs iff their keys fold to the same commit byte (see the toy
    /// [`MockSealer::key_commit`]).
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Toy 1-byte key commitment: XOR-fold of the key bytes. NOT
    /// cryptographic — just enough for a wrong-key test to fail.
    fn key_commit(&self) -> u8 {
        self.key.iter().fold(0u8, |a, b| a ^ b)
    }

    /// Toy 8-byte checksum over the plaintext (wrapping byte sum, splayed).
    /// NOT a MAC — just enough for a tamper test to fail.
    fn checksum(plaintext: &[u8]) -> [u8; 8] {
        let mut acc = 0u64;
        for (i, b) in plaintext.iter().enumerate() {
            acc = acc.wrapping_add((*b as u64).wrapping_mul(i as u64 + 1));
        }
        acc.to_le_bytes()
    }
}

impl Sealer for MockSealer {
    fn seal(&self, context: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
        if context.len() > u32::MAX as usize {
            return Err(SealError::Seal);
        }
        let mut out =
            Vec::with_capacity(MOCK_MIN_LEN + context.len() + plaintext.len());
        out.extend_from_slice(&MOCK_MAGIC);
        out.push(self.key_commit());
        out.extend_from_slice(&(context.len() as u32).to_le_bytes());
        out.extend_from_slice(context);
        out.extend_from_slice(&Self::checksum(plaintext));
        out.extend_from_slice(plaintext);
        Ok(out)
    }
}

impl Opener for MockSealer {
    fn open(&self, context: &[u8], sealed: &[u8]) -> Result<Vec<u8>, SealError> {
        if sealed.len() < MOCK_MIN_LEN {
            return Err(SealError::Corrupt);
        }
        if sealed[..8] != MOCK_MAGIC {
            return Err(SealError::Corrupt);
        }
        // Wrong key ⇒ Open.
        if sealed[8] != self.key_commit() {
            return Err(SealError::Open);
        }
        let ctx_len = u32::from_le_bytes(sealed[9..13].try_into().unwrap()) as usize;
        let ctx_start: usize = 13;
        let ctx_end = ctx_start.checked_add(ctx_len).ok_or(SealError::Corrupt)?;
        let checksum_end = ctx_end.checked_add(8).ok_or(SealError::Corrupt)?;
        if checksum_end > sealed.len() {
            return Err(SealError::Corrupt);
        }
        // Wrong context ⇒ Open.
        if &sealed[ctx_start..ctx_end] != context {
            return Err(SealError::Open);
        }
        let stored_checksum: [u8; 8] = sealed[ctx_end..checksum_end].try_into().unwrap();
        let plaintext = &sealed[checksum_end..];
        // Tampered plaintext ⇒ Open.
        if Self::checksum(plaintext) != stored_checksum {
            return Err(SealError::Open);
        }
        Ok(plaintext.to_vec())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const CTX: &[u8] = b"postern-backup/mock/v1";

    fn sealer() -> MockSealer {
        MockSealer::new([0x42; 32])
    }

    #[test]
    fn seal_open_round_trip() {
        let s = sealer();
        for pt in [&b""[..], b"hello", &vec![0xABu8; 4096][..]] {
            let blob = s.seal(CTX, pt).unwrap();
            assert_eq!(s.open(CTX, &blob).unwrap(), pt);
        }
    }

    #[test]
    fn wrong_context_fails_open() {
        let s = sealer();
        let blob = s.seal(CTX, b"secret").unwrap();
        assert_eq!(s.open(b"other-context", &blob), Err(SealError::Open));
    }

    #[test]
    fn wrong_key_fails_open() {
        let sealed = sealer().seal(CTX, b"secret").unwrap();
        // A sealer whose key folds to a different commit must fail to open.
        let mut other_key = [0x42; 32];
        other_key[0] = 0x43; // flips the XOR fold
        let other = MockSealer::new(other_key);
        assert_eq!(other.open(CTX, &sealed), Err(SealError::Open));
    }

    #[test]
    fn tampered_plaintext_fails_open() {
        let s = sealer();
        let mut blob = s.seal(CTX, b"secret").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xFF; // flip a plaintext byte
        assert_eq!(s.open(CTX, &blob), Err(SealError::Open));
    }

    #[test]
    fn truncated_blob_is_corrupt() {
        let s = sealer();
        let blob = s.seal(CTX, b"secret").unwrap();
        for cut in 0..MOCK_MIN_LEN {
            assert_eq!(s.open(CTX, &blob[..cut]), Err(SealError::Corrupt));
        }
    }

    #[test]
    fn bad_magic_is_corrupt() {
        let s = sealer();
        let mut blob = s.seal(CTX, b"secret").unwrap();
        blob[0] ^= 0xFF;
        assert_eq!(s.open(CTX, &blob), Err(SealError::Corrupt));
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
}
