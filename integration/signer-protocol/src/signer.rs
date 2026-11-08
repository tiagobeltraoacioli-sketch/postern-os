// SPDX-License-Identifier: MIT OR Apache-2.0
//! The on-device signer surface — the frozen interface the phone's `WalletCore`
//! satisfies, plus a scaffold stand-in so this crate builds and tests standalone.
//!
//! HONEST LABEL: the real signer is `mobile/core`'s [`WalletCore`], which decrypts
//! the hybrid **Falcon‖ML-DSA** secret into normal RAM to sign and zeroizes it on
//! drop. Even there the PQ key is **in RAM at sign time** — this is *software
//! signing with hardware-assisted at-rest protection on the phone*, NOT a hardware
//! wallet. On the pmOS community edition it is pure software. A rooted/malware
//! endpoint (A5) reads the key from RAM and can forge the approval UI; nothing in
//! this protocol fixes that.

use crate::error::SignerError;
use crate::secret::{SecretKey, SeedPhrase};

/// The minimal signing surface this protocol needs from the wallet. Modelled on
/// `WalletCore::{public_key_hex, address, sign_hex}` — the phone implements this
/// over its real hybrid signer; the desktop never holds an implementation.
///
/// The trait yields only **public** outputs (a pubkey, an address, a signature).
/// It has no method that returns a seed or secret key — the denylist is baked
/// into the interface, not bolted on after.
pub trait WalletSigner {
    /// The wallet's hybrid PQ public key (the identity), hex-encoded. Public.
    fn public_key_hex(&self) -> String;

    /// Raw public-key bytes (public), for embedding in an [`crate::Approval`].
    fn public_key_bytes(&self) -> Vec<u8>;

    /// The `bloch1q…` address (public).
    fn address(&self) -> String;

    /// Sign a 32-byte digest with the hybrid Falcon‖ML-DSA secret and return the
    /// signature bytes. This is the ONLY thing that leaves the signer, and a
    /// signature is public. Mirrors `WalletCore::sign_hex` over a fixed digest.
    fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>, SignerError>;
}

/// A deterministic **scaffold** signer used by this crate's own build/tests so it
/// stands alone without `bloch-crypto`.
///
/// ⚠️ NOT REAL CRYPTOGRAPHY. It produces a SHA3-256 tag over `secret ‖ digest`
/// as a stand-in "signature". It exists solely to exercise the request/approve
/// wiring, the replay guard, WYSIWYS, and the denylist golden test without the
/// heavyweight PQ dependency. In production this type is replaced by a thin
/// adapter over `WalletCore`. The seed/secret it holds are wrapped in the
/// [`SeedPhrase`]/[`SecretKey`] denylist types, so they cannot leak onto the wire
/// even from the scaffold.
pub struct ScaffoldSigner {
    public_key: Vec<u8>,
    address: String,
    #[allow(dead_code)]
    seed: SeedPhrase,
    secret: SecretKey,
}

impl ScaffoldSigner {
    /// Build a deterministic scaffold signer from a known seed. The "public key"
    /// and "address" are deterministic functions of the seed — enough for the
    /// protocol wiring, byte-meaningless to consensus.
    pub fn from_seed(seed_bytes: &[u8]) -> Self {
        use sha3::{Digest, Sha3_256};
        // Deterministic pseudo-secret and pseudo-pubkey from the seed.
        let secret = {
            let mut h = Sha3_256::new();
            h.update(b"scaffold-secret");
            h.update(seed_bytes);
            h.finalize().to_vec()
        };
        let public_key = {
            let mut h = Sha3_256::new();
            h.update(b"scaffold-pubkey");
            h.update(&secret);
            h.finalize().to_vec()
        };
        let address = format!("bloch1q{}", hex::encode(&public_key[..10]));
        ScaffoldSigner {
            public_key,
            address,
            seed: SeedPhrase::new(seed_bytes.to_vec()),
            secret: SecretKey::new(secret),
        }
    }
}

impl WalletSigner for ScaffoldSigner {
    fn public_key_hex(&self) -> String {
        hex::encode(&self.public_key)
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    fn address(&self) -> String {
        self.address.clone()
    }

    fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>, SignerError> {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(b"scaffold-sig:v1");
        h.update(self.secret.expose()); // on-device borrow; never serialized
        h.update(digest);
        Ok(h.finalize().to_vec())
    }
}
