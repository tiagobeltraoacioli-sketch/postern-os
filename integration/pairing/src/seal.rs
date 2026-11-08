// SPDX-License-Identifier: MIT OR Apache-2.0
//! The canonical Postern **seal** for data at rest — reproduced locally.
//!
//! This is the SAME construction as `postern_core::aead::seal_with_context`
//! (the one canonical Postern seal), reproduced here rather than depended-on so
//! this crate stays standalone (it carries its own empty `[workspace]` and pulls
//! no in-tree path crates — see `Cargo.toml`). The wire format, labels, and
//! properties are byte-compatible in shape with postern-core v2:
//!
//! ```text
//! 0x02 ‖ nonce (24) ‖ commit (32) ‖ AEAD-ciphertext (plaintext + 16-byte tag)
//! ```
//!
//! Per seal, two subkeys are derived with HKDF-SHA-256 from the caller's 32-byte
//! key, salted by the fresh random nonce and labeled with a domain string plus
//! the caller's `context`:
//!
//! ```text
//! enc_key = HKDF(salt = nonce, ikm = key, info = "postern-pairing/seal/v2/enc"    ‖ context)
//! commit  = HKDF(salt = nonce, ikm = key, info = "postern-pairing/seal/v2/commit" ‖ context)
//! ```
//!
//! - **Key-committing.** `commit` is stored in the header and checked (constant
//!   time) before decrypting. Without it, XChaCha20-Poly1305 (like any plain
//!   AEAD) is not key-committing — a single ciphertext could be made to open
//!   under two different keys. Storing and checking a derived commitment excludes
//!   that (the same derive-and-store construction the AWS Encryption SDK uses).
//! - **Context-bound / domain-separated.** `context` (e.g. `b"postern-pairing/
//!   record/v1"`) feeds BOTH subkey derivations AND the AEAD AAD, so a blob
//!   sealed for one context can never open under another even with the right key.
//! - **Fail-closed.** A wrong key, a wrong context, a rolled-back nonce, or any
//!   tamper makes either the commitment check or the AEAD tag fail; [`open`]
//!   returns [`SealError::Open`] and NO plaintext. There is no legacy/downgrade
//!   path here (unlike postern-core, this crate never wrote a pre-v2 blob).
//!
//! ## Honest limits
//! - **Symmetric only, no PQ leg.** A sealed blob is protected by XChaCha20-
//!   Poly1305 under the caller's key. Symmetric AEAD is not the PQ weak point
//!   (Grover only halves the key), so there is no ML-KEM here — but the caller's
//!   **storage key** must itself be protected at rest (vault/Argon2id on desktop,
//!   StrongBox/Secure-Enclave-wrapped on mobile). This module does not derive or
//!   store that key; it only consumes 32 bytes.
//! - **Scaffold, unaudited.** Same rails as the rest of the crate.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

/// XChaCha20-Poly1305 nonce length.
pub const NONCE_LEN: usize = 24;
/// Poly1305 tag length.
pub const TAG_LEN: usize = 16;
/// Length of the stored key-commitment string (HKDF-SHA-256 output).
pub const COMMIT_LEN: usize = 32;
/// Version byte of the (only) key-committing wire format.
pub const VERSION_V2: u8 = 0x02;

const HEADER_LEN: usize = 1 + NONCE_LEN + COMMIT_LEN;
const MIN_LEN: usize = HEADER_LEN + TAG_LEN;

const ENC_LABEL: &[u8] = b"postern-pairing/seal/v2/enc";
const COMMIT_LABEL: &[u8] = b"postern-pairing/seal/v2/commit";
const AAD_LABEL: &[u8] = b"postern-pairing/seal/v2/aad";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SealError {
    #[error("seal failed")]
    Seal,
    #[error("open failed — wrong key, wrong context, or tampered data")]
    Open,
}

/// Constant-time byte comparison (no `subtle` dependency; the commitment is a
/// public value, but comparing it in constant time avoids a needless oracle).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Derive `(enc_key, commit)` for one `(key, nonce, context)`. The labels are
/// distinct fixed prefixes and `context` is the entire remainder, so each info
/// string is injective in `(label, context)`.
fn derive_subkeys(
    key: &[u8; 32],
    nonce: &[u8],
    context: &[u8],
) -> (Zeroizing<[u8; 32]>, [u8; COMMIT_LEN]) {
    let hk = Hkdf::<Sha256>::new(Some(nonce), key);
    let mut enc_key = Zeroizing::new([0u8; 32]);
    let mut commit = [0u8; COMMIT_LEN];
    hk.expand_multi_info(&[ENC_LABEL, context], enc_key.as_mut())
        .expect("hkdf expand of 32 bytes is infallible");
    hk.expand_multi_info(&[COMMIT_LABEL, context], &mut commit)
        .expect("hkdf expand of 32 bytes is infallible");
    (enc_key, commit)
}

/// AAD = `version ‖ label ‖ len(context) as u64-le ‖ context` (injective).
fn build_aad(context: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(1 + AAD_LABEL.len() + 8 + context.len());
    aad.push(VERSION_V2);
    aad.extend_from_slice(AAD_LABEL);
    aad.extend_from_slice(&(context.len() as u64).to_le_bytes());
    aad.extend_from_slice(context);
    aad
}

/// Seal `plaintext` under a 32-byte `key`, bound to `context`. Output is the
/// versioned, key-committing `0x02 ‖ nonce ‖ commit ‖ ct`; opening requires the
/// same key AND the same context.
pub fn seal(key: &[u8; 32], context: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let (enc_key, commit) = derive_subkeys(key, &nonce, context);

    let ek: &[u8; 32] = &enc_key;
    let cipher = XChaCha20Poly1305::new(ek.into());
    let aad = build_aad(context);
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad: &aad })
        .map_err(|_| SealError::Seal)?;

    let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
    out.push(VERSION_V2);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&commit);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a blob sealed by [`seal`] under the same key and context. Checks the key
/// commitment (constant time) before decrypting, then verifies the AEAD tag. Any
/// mismatch is fail-closed: [`SealError::Open`] and no plaintext. The returned
/// buffer is wiped from RAM on drop.
pub fn open(
    key: &[u8; 32],
    context: &[u8],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SealError> {
    if sealed.len() < MIN_LEN || sealed[0] != VERSION_V2 {
        return Err(SealError::Open);
    }
    let nonce = &sealed[1..1 + NONCE_LEN];
    let stored_commit = &sealed[1 + NONCE_LEN..HEADER_LEN];
    let ct = &sealed[HEADER_LEN..];

    let (enc_key, commit) = derive_subkeys(key, nonce, context);
    if !ct_eq(&commit, stored_commit) {
        return Err(SealError::Open);
    }

    let ek: &[u8; 32] = &enc_key;
    let cipher = XChaCha20Poly1305::new(ek.into());
    let aad = build_aad(context);
    let pt = cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: &aad })
        .map_err(|_| SealError::Open)?;
    Ok(Zeroizing::new(pt))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CTX: &[u8] = b"postern-pairing/test/v1";

    #[test]
    fn seal_open_roundtrip() {
        let key = [0x11u8; 32];
        let sealed = seal(&key, CTX, b"session-root-and-pins").unwrap();
        // The plaintext must not appear in the sealed blob.
        assert!(!sealed
            .windows(b"session-root".len())
            .any(|w| w == b"session-root"));
        let opened = open(&key, CTX, &sealed).unwrap();
        assert_eq!(&**opened, b"session-root-and-pins");
    }

    #[test]
    fn wrong_key_fails_closed() {
        let sealed = seal(&[1u8; 32], CTX, b"x").unwrap();
        assert_eq!(open(&[2u8; 32], CTX, &sealed).unwrap_err(), SealError::Open);
    }

    #[test]
    fn wrong_context_fails_closed() {
        let key = [7u8; 32];
        let sealed = seal(&key, CTX, b"x").unwrap();
        assert_eq!(
            open(&key, b"postern-pairing/other/v1", &sealed).unwrap_err(),
            SealError::Open
        );
    }

    #[test]
    fn tampered_blob_fails_closed() {
        let key = [9u8; 32];
        let mut sealed = seal(&key, CTX, b"amount:10").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF;
        assert_eq!(open(&key, CTX, &sealed).unwrap_err(), SealError::Open);
    }

    #[test]
    fn flipped_commitment_fails_before_decrypt() {
        let key = [3u8; 32];
        let mut sealed = seal(&key, CTX, b"x").unwrap();
        // Flip a commitment byte (offset 1 + NONCE_LEN).
        sealed[1 + NONCE_LEN] ^= 0x01;
        assert_eq!(open(&key, CTX, &sealed).unwrap_err(), SealError::Open);
    }

    #[test]
    fn truncated_blob_fails_closed() {
        let key = [4u8; 32];
        let sealed = seal(&key, CTX, b"x").unwrap();
        assert_eq!(open(&key, CTX, &sealed[..MIN_LEN - 1]).unwrap_err(), SealError::Open);
    }
}
