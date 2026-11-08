// SPDX-License-Identifier: MIT OR Apache-2.0
//! Short Authentication String (SAS) — the mandatory human MITM tripwire.
//!
//! **This is NOT a PAKE and NOT a secret.** No real PAKE exists in the tree, so
//! a typed PIN is never treated as key entropy. The SAS is a **6-digit value
//! derived from the already-agreed session key**, shown on *both* screens for
//! the human to compare. Under an active MITM (A2) the two sides agree on
//! *different* session keys (the relay must re-encapsulate), so their SAS values
//! differ and the human aborts. It is a comparison, never typed-then-trusted.
//!
//! Derivation is a *separate* HKDF branch from the channel key so displaying the
//! SAS leaks nothing about the key that encrypts traffic:
//!
//! ```text
//! sas_bytes = HKDF-SHA-256(ikm = session_key, info = "postern-pairing/sas/v1")
//! digits    = (be_u32(sas_bytes[0..4]) mod 1_000_000), zero-padded to 6
//! ```
//!
//! Six digits is ~20 bits: a one-shot online MITM has a 1-in-1,000,000 chance of
//! guessing a colliding SAS, and there is no retry oracle (fail-closed, single
//! ceremony). It is a human-factors tripwire, not a cryptographic key.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::hybrid::SessionKey;

/// Number of decimal digits in the SAS.
pub const SAS_DIGITS: usize = 6;

const SAS_INFO: &[u8] = b"postern-pairing/sas/v1";
const SAS_MODULUS: u32 = 1_000_000; // 10^6

/// A short authentication string the human compares across both screens.
#[derive(Clone, PartialEq, Eq)]
pub struct Sas {
    value: u32, // 0..1_000_000
}

impl Sas {
    /// Derive the SAS from the agreed session key.
    pub fn derive(key: &SessionKey) -> Self {
        let hk = Hkdf::<Sha256>::new(None, key.as_ref());
        let mut out = [0u8; 4];
        // HKDF-Expand of 4 bytes never fails for a SHA-256 length.
        hk.expand(SAS_INFO, &mut out)
            .expect("HKDF expand of 4 bytes is infallible");
        let raw = u32::from_be_bytes(out);
        Sas { value: raw % SAS_MODULUS }
    }

    /// The zero-padded 6-digit display string (e.g. `"042731"`).
    pub fn digits(&self) -> String {
        format!("{:0width$}", self.value, width = SAS_DIGITS)
    }

    /// Constant-time-ish equality of two derived SAS values. (Both are derived
    /// from public-after-the-fact key material and are compared by a human in
    /// the real flow; this helper exists for programmatic confirmation paths.)
    pub fn matches(&self, other: &Sas) -> bool {
        self.value == other.value
    }
}

impl core::fmt::Debug for Sas {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Show the digits — they are meant to be displayed to the user anyway.
        write!(f, "Sas({})", self.digits())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    fn key(byte: u8) -> SessionKey {
        Zeroizing::new([byte; 32])
    }

    #[test]
    fn same_key_same_sas() {
        let a = Sas::derive(&key(1));
        let b = Sas::derive(&key(1));
        assert!(a.matches(&b));
        assert_eq!(a.digits(), b.digits());
    }

    #[test]
    fn different_key_different_sas_usually() {
        // Not a guarantee (20-bit space), but distinct keys should almost always
        // differ; check a handful.
        let base = Sas::derive(&key(0));
        let mut diffs = 0;
        for b in 1..=20u8 {
            if !base.matches(&Sas::derive(&key(b))) {
                diffs += 1;
            }
        }
        assert!(diffs >= 18, "expected almost all distinct, got {diffs}/20");
    }

    #[test]
    fn digits_are_six_wide_zero_padded() {
        let s = Sas::derive(&key(7));
        assert_eq!(s.digits().len(), SAS_DIGITS);
        assert!(s.digits().chars().all(|c| c.is_ascii_digit()));
    }
}
