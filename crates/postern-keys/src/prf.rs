//! PRF evaluation — the WebAuthn `prf` extension / CTAP2 `hmac-secret` model.
//!
//! Real hardware authenticators keep a per-credential secret (`CredRandom`)
//! inside their security boundary and answer `hmac-secret` requests with
//! `HMAC-SHA-256(CredRandom, salt)`. The WebAuthn `prf` extension layers a
//! domain separation on top: the browser hashes each caller-supplied input as
//! `SHA-256("WebAuthn PRF" || 0x00 || input)` before it becomes the CTAP2
//! salt, so a web page can never make the authenticator MAC an arbitrary raw
//! salt. This module implements both halves in one step:
//!
//! ```text
//! prf_eval(input) = HMAC-SHA-256(seed, SHA-256("WebAuthn PRF" || 0x00 || input))
//! ```
//!
//! Honest limit: here the per-credential seed is a **userland secret** — it is
//! protected only by the Postern Vault seal at rest (and zeroized in RAM on
//! drop), not by any hardware boundary. A hardware `hmac-secret` authenticator
//! never lets `CredRandom` leave the secure element; this software one cannot
//! make that claim.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// The WebAuthn `prf` extension's domain-separation context string.
const PRF_CONTEXT: &[u8] = b"WebAuthn PRF";

/// Hash a caller-supplied PRF input into the CTAP2 `hmac-secret` salt:
/// `SHA-256("WebAuthn PRF" || 0x00 || input)`.
fn hash_input(input: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(PRF_CONTEXT);
    h.update([0x00u8]);
    h.update(input);
    h.finalize().into()
}

/// Evaluate the credential PRF: `HMAC-SHA-256(seed, hash_input(input))`.
///
/// Deterministic for a given (seed, input); distinct seeds and distinct
/// inputs give unrelated outputs. The returned array is caller-owned — if it
/// is used as key material, zeroize it when done.
pub(crate) fn eval(seed: &[u8; 32], input: &[u8]) -> [u8; 32] {
    let salt = hash_input(input);
    let mut mac =
        HmacSha256::new_from_slice(seed).expect("HMAC-SHA-256 accepts a 32-byte key");
    mac.update(&salt);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eval_is_deterministic_and_input_separated() {
        let seed = [7u8; 32];
        assert_eq!(eval(&seed, b"input"), eval(&seed, b"input"));
        assert_ne!(eval(&seed, b"input"), eval(&seed, b"other"));
        // A different seed must give an unrelated output for the same input.
        assert_ne!(eval(&seed, b"input"), eval(&[8u8; 32], b"input"));
    }

    #[test]
    fn eval_matches_the_spec_composition() {
        // eval == HMAC(seed, SHA-256("WebAuthn PRF" || 0x00 || input)),
        // computed here by hand so a refactor cannot silently drop the
        // domain-separated input hashing.
        let seed = [3u8; 32];
        let input = b"account-encryption";
        let mut h = Sha256::new();
        h.update(b"WebAuthn PRF");
        h.update([0u8]);
        h.update(input);
        let salt: [u8; 32] = h.finalize().into();
        let mut mac = HmacSha256::new_from_slice(&seed).unwrap();
        mac.update(&salt);
        let expected: [u8; 32] = mac.finalize().into_bytes().into();
        assert_eq!(eval(&seed, input), expected);
        // And the raw (unhashed) input must NOT be what gets MACed.
        let mut raw = HmacSha256::new_from_slice(&seed).unwrap();
        raw.update(input);
        let raw_mac: [u8; 32] = raw.finalize().into_bytes().into();
        assert_ne!(eval(&seed, input), raw_mac);
    }
}
