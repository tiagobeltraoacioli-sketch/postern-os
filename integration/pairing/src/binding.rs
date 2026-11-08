// SPDX-License-Identifier: MIT OR Apache-2.0
//! Channel binding — `report_data = SHA-256(nonce || pubkey)`.
//!
//! This is the same anti-MITM / anti-relay primitive as
//! `postern-seal-companion::binding`, reused here (not reinvented) as the
//! **out-of-band anchor** of the pairing ceremony. The desktop's ephemeral
//! hybrid public key and a fresh 32-byte nonce are bound together; the phone
//! pins that binding off the QR **before** the KEM runs, which collapses the
//! MITM window to zero — an attacker cannot inject a key the user already
//! scanned off the glass.
//!
//! All inputs are public values, so [`matches`] is an integrity comparison, not
//! a secret comparison; a plain equality is sound. The concatenation is
//! injective because the nonce length is fixed at 32 bytes.

use sha2::{Digest, Sha256};

/// Length of the pairing nonce (matches the SNP/TDX `report_data` digest half).
pub const NONCE_LEN: usize = 32;

/// Length of a channel binding.
pub const BINDING_LEN: usize = 32;

/// A fresh pairing nonce.
pub type Nonce = [u8; NONCE_LEN];

/// Compute the channel binding a genuine pairing must have anchored:
/// `SHA-256(nonce || anchor_pubkey)`.
///
/// The desktop computes this over its own ephemeral hybrid public key and puts
/// (nonce, pubkey) in the QR. The phone recomputes it from the scanned bytes
/// and pins the result before dialing.
pub fn channel_binding(nonce: &Nonce, anchor_pubkey: &[u8]) -> [u8; BINDING_LEN] {
    let mut h = Sha256::new();
    h.update(nonce);
    h.update(anchor_pubkey);
    let digest = h.finalize();
    let mut out = [0u8; BINDING_LEN];
    out.copy_from_slice(&digest);
    out
}

/// Verifier-side check: does `binding` equal the binding of `nonce` to
/// `anchor_pubkey`? Public-value equality (see module docs).
pub fn matches(binding: &[u8; BINDING_LEN], nonce: &Nonce, anchor_pubkey: &[u8]) -> bool {
    binding == &channel_binding(nonce, anchor_pubkey)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nonce() -> Nonce {
        core::array::from_fn(|i| i as u8)
    }

    #[test]
    fn binding_matches_itself() {
        let pk = [0x80u8; 64];
        let b = channel_binding(&nonce(), &pk);
        assert!(matches(&b, &nonce(), &pk));
    }

    #[test]
    fn stale_nonce_fails_binding() {
        let pk = [0x80u8; 64];
        let b = channel_binding(&[0xAA; NONCE_LEN], &pk);
        assert!(!matches(&b, &nonce(), &pk));
    }

    #[test]
    fn substituted_pubkey_fails_binding() {
        // MITM splice: same fresh nonce, attacker presents THEIR key.
        let b = channel_binding(&nonce(), &[0x11u8; 64]);
        assert!(!matches(&b, &nonce(), &[0x22u8; 64]));
    }

    #[test]
    fn distinct_inputs_distinct_bindings() {
        let pk = [0x80u8; 64];
        let a = channel_binding(&nonce(), &pk);
        let mut n2 = nonce();
        n2[31] ^= 1;
        assert_ne!(a, channel_binding(&n2, &pk));
    }
}
