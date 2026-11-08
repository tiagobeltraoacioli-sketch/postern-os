// SPDX-License-Identifier: MIT OR Apache-2.0

//! `WalletCoreSigner` — the REAL [`WalletSigner`] the phone runs.
//!
//! `postern-signer-protocol` defines the [`WalletSigner`] seam and ships a
//! deterministic [`ScaffoldSigner`](postern_signer_protocol::ScaffoldSigner) so
//! it can build/test without `bloch-crypto`. This is the production adapter that
//! **replaces** the scaffold: it forwards `sign_digest` to
//! [`bloch_mobile::WalletCore`], the byte-identical hybrid **Falcon‖ML-DSA**
//! signer (golden-tested against the node).
//!
//! ## Key/seed never leaves the device — structurally
//!
//! The [`WalletSigner`] trait yields only **public** outputs (public key, address,
//! signature). This adapter holds the `WalletCore` by value and exposes nothing
//! else: there is no accessor here that returns the seed or the secret key, and
//! the protocol's wire types have no field one could be placed in. `WalletCore`
//! zeroizes its secret + seed on `Drop`; the PQ secret is only in RAM during a
//! sign.
//!
//! ## Software keystore, not hardware (say it)
//!
//! Even here the PQ secret is decrypted into normal RAM to sign. On the
//! "Postern for postmarketOS — community edition" it is a pure software keystore
//! (no StrongBox/Secure Enclave). A rooted/malware phone reads the key from RAM
//! and can forge the approval UI — unmitigable here. **This is not a hardware
//! wallet.**

use bloch_mobile::WalletCore;
use postern_signer_protocol::{SignerError, WalletSigner};

/// The production [`WalletSigner`]: a thin, public-only adapter over
/// [`WalletCore`]. Construct from a mnemonic/seed, then hand it to a
/// [`postern_signer_protocol::PhoneApprover`] (directly or via
/// [`crate::MobileSigner`]).
pub struct WalletCoreSigner {
    inner: WalletCore,
}

impl WalletCoreSigner {
    /// Wrap an existing `WalletCore` (the phone's live wallet).
    pub fn new(inner: WalletCore) -> Self {
        WalletCoreSigner { inner }
    }

    /// Build from a BIP39 mnemonic. The phrase is the wallet's only backup —
    /// never log it; drop the foreign-side copy promptly.
    pub fn from_mnemonic(phrase: &str, testnet: bool) -> Result<Self, SignerError> {
        let inner = WalletCore::from_mnemonic(phrase, testnet)
            .map_err(SignerError::Backend)?;
        Ok(WalletCoreSigner { inner })
    }

    /// Build deterministically from raw seed bytes (>= 32) — used by tests and by
    /// a restore-from-seed path. Same seed → same address (golden invariant).
    pub fn from_seed_bytes(seed: &[u8], testnet: bool) -> Result<Self, SignerError> {
        let inner = WalletCore::from_seed_bytes(seed, testnet)
            .map_err(SignerError::Backend)?;
        Ok(WalletCoreSigner { inner })
    }
}

impl WalletSigner for WalletCoreSigner {
    fn public_key_hex(&self) -> String {
        self.inner.public_key_hex()
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        // `WalletCore` exposes the public key as hex; decode to raw bytes for the
        // Approval. This is PUBLIC material — the identity, not a secret.
        hex::decode(self.inner.public_key_hex()).unwrap_or_default()
    }

    fn address(&self) -> String {
        self.inner.address()
    }

    fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>, SignerError> {
        // WalletCore signs a hex message with the hybrid Falcon‖ML-DSA secret.
        // Feeding the 32-byte canonical digest yields a signature that verifies
        // via `bloch_crypto::crypto::verify(pubkey, digest, sig)` — exactly what a
        // consiglio server checks for a wallet-login (transcript == this digest).
        let sig_hex = self
            .inner
            .sign_hex(&hex::encode(digest))
            .map_err(SignerError::Backend)?;
        hex::decode(sig_hex).map_err(|e| SignerError::Backend(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapter_signs_a_digest_that_the_node_verifier_accepts() {
        let s = WalletCoreSigner::from_seed_bytes(&[9u8; 32], true).unwrap();
        let digest = [0x42u8; 32];
        let sig = s.sign_digest(&digest).unwrap();
        // The exact hybrid verifier the node/consiglio runs.
        assert!(bloch_crypto::crypto::verify(&s.public_key_bytes(), &digest, &sig));
    }

    #[test]
    fn public_outputs_only_and_address_is_bloch1t_on_testnet() {
        let s = WalletCoreSigner::from_seed_bytes(&[9u8; 32], true).unwrap();
        assert!(s.address().starts_with("bloch1t"));
        assert!(!s.public_key_hex().is_empty());
        assert!(!s.public_key_bytes().is_empty());
    }
}
