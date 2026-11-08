//! Courier product — post-quantum hybrid (ML-KEM-1024 ‖ X25519) sealed messaging.
//! UniFFI wrapper over `postern_courier`.
//!
//! The recipient keypair is an OPAQUE object handle, not a Record: a Record's
//! generated Kotlin `toString()`/Swift `description` would print the ML-KEM
//! secret key into logs. The secret leaves the handle only via the explicit,
//! documented [`Recipient::export_secret_key`]; the common decrypt path
//! ([`Recipient::open`]) never exports it at all.

use crate::PosternError;
use std::sync::Arc;
use zeroize::Zeroizing;

/// A courier recipient keypair behind an opaque handle. The public key is
/// shareable; the secret key stays inside the object (zeroized on release)
/// unless explicitly exported for backup.
#[derive(uniffi::Object)]
pub struct Recipient {
    public: Vec<u8>,
    secret: Zeroizing<Vec<u8>>,
}

#[uniffi::export]
impl Recipient {
    /// Generate a fresh ML-KEM-1024 recipient keypair.
    #[uniffi::constructor]
    pub fn generate() -> Arc<Recipient> {
        let r = postern_courier::generate_recipient();
        // The clones go straight into a zeroizing wrapper; the core `Recipient`
        // wipes its own copies on drop, so no un-scrubbed intermediate remains.
        Arc::new(Recipient {
            public: r.public.clone(),
            secret: Zeroizing::new(r.secret.clone()),
        })
    }

    /// Restore a recipient from previously exported key material (e.g. bytes
    /// kept in the vault). Lengths are validated when the keys are used.
    #[uniffi::constructor]
    pub fn from_keys(public: Vec<u8>, secret: Vec<u8>) -> Arc<Recipient> {
        Arc::new(Recipient { public, secret: Zeroizing::new(secret) })
    }

    /// The ML-KEM public key bytes (share with senders).
    pub fn public_key(&self) -> Vec<u8> {
        self.public.clone()
    }

    /// Open a sealed payload with this recipient's secret key → plaintext.
    /// The secret never crosses the FFI boundary on this path.
    pub fn open(&self, sealed: SealedPayload) -> Result<Vec<u8>, PosternError> {
        let payload = postern_courier::SealedPayload { kem_ct: sealed.kem_ct, body: sealed.body };
        postern_courier::open(&self.secret, &payload).map_err(|e| PosternError::from(e.to_string()))
    }

    /// EXPLICIT EXPORT of the ML-KEM secret key, for backup into the vault.
    ///
    /// SECURITY: treat the returned bytes as toxic — never log them; the
    /// foreign-side copy is GC-managed and cannot be zeroized, so store it
    /// (e.g. `Vault::put`) and drop every reference immediately. Prefer
    /// [`Recipient::open`], which decrypts without exporting the secret.
    pub fn export_secret_key(&self) -> Vec<u8> {
        self.secret.to_vec()
    }
}

/// A sealed message: the KEM-encapsulated key + the AEAD body. (Ciphertext
/// only — safe to cross as a Record.)
#[derive(uniffi::Record)]
pub struct SealedPayload {
    /// ML-KEM ciphertext (the encapsulated shared secret).
    pub kem_ct: Vec<u8>,
    /// `nonce ‖ AEAD-ciphertext`.
    pub body: Vec<u8>,
}

/// Generate a fresh ML-KEM recipient keypair (alias for [`Recipient::generate`]).
#[uniffi::export]
pub fn generate_recipient() -> Arc<Recipient> {
    Recipient::generate()
}

/// Seal `plaintext` to a recipient's public key.
#[uniffi::export]
pub fn courier_seal(recipient_public: Vec<u8>, plaintext: Vec<u8>) -> Result<SealedPayload, PosternError> {
    // Wipe the Rust-side plaintext copy once sealed.
    let plaintext = Zeroizing::new(plaintext);
    let p = postern_courier::seal(&recipient_public, &plaintext)
        .map_err(|e| PosternError::from(e.to_string()))?;
    Ok(SealedPayload { kem_ct: p.kem_ct, body: p.body })
}

/// Open a sealed payload with a raw recipient secret key (restore path — e.g.
/// bytes fetched back from the vault). Prefer [`Recipient::open`] when a
/// handle is alive; SECURITY: never log `recipient_secret`. The Rust-side copy
/// is wiped before returning.
#[uniffi::export]
pub fn courier_open(recipient_secret: Vec<u8>, sealed: SealedPayload) -> Result<Vec<u8>, PosternError> {
    let secret = Zeroizing::new(recipient_secret);
    let payload = postern_courier::SealedPayload { kem_ct: sealed.kem_ct, body: sealed.body };
    postern_courier::open(&secret, &payload).map_err(|e| PosternError::from(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_handle_roundtrip_without_exporting_secret() {
        let rcpt = Recipient::generate();
        let sealed = courier_seal(rcpt.public_key(), b"sealed for the handle".to_vec()).unwrap();
        assert_eq!(rcpt.open(sealed).unwrap(), b"sealed for the handle");
    }

    #[test]
    fn export_restore_and_raw_open_paths_agree() {
        let rcpt = Recipient::generate();
        let backup = rcpt.export_secret_key();

        let sealed = courier_seal(rcpt.public_key(), b"restore me".to_vec()).unwrap();
        let sealed2 = courier_seal(rcpt.public_key(), b"raw path".to_vec()).unwrap();

        let restored = Recipient::from_keys(rcpt.public_key(), backup.clone());
        assert_eq!(restored.open(sealed).unwrap(), b"restore me");
        assert_eq!(courier_open(backup, sealed2).unwrap(), b"raw path");
    }

    #[test]
    fn wrong_secret_cannot_open() {
        let rcpt = Recipient::generate();
        let other = Recipient::generate();
        let sealed = courier_seal(rcpt.public_key(), b"secret".to_vec()).unwrap();
        assert!(other.open(sealed).is_err());
    }
}
