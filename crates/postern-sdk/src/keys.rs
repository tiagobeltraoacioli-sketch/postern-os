//! Keys product — WebAuthn/FIDO-style P-256 credentials over `postern_keys`.
//! The credential is an `Arc<Object>` (it holds a private signing key); public
//! material and signatures cross as byte vectors.

use crate::{to_array, PosternError};
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

/// A P-256 (ES256) credential: an `rp_id`, a 16-byte credential id, and a
/// private signing key held inside the object.
#[derive(uniffi::Object)]
pub struct Credential {
    inner: postern_keys::Credential,
}

#[uniffi::export]
impl Credential {
    /// Restore a credential from its raw 32-byte private key + 16-byte id.
    /// SECURITY: never log `key_bytes`; the Rust-side copy is wiped before
    /// this returns.
    #[uniffi::constructor]
    pub fn from_key_bytes(
        rp_id: String,
        credential_id: Vec<u8>,
        key_bytes: Vec<u8>,
    ) -> Result<Arc<Credential>, PosternError> {
        let key_bytes = Zeroizing::new(key_bytes);
        let cid: [u8; 16] = to_array(&credential_id, "credential_id")?;
        let inner = postern_keys::Credential::from_key_bytes(&rp_id, cid, &key_bytes)
            .map_err(|e| PosternError::from(e.to_string()))?;
        Ok(Arc::new(Credential { inner }))
    }

    /// The relying-party id this credential is bound to.
    pub fn rp_id(&self) -> String {
        self.inner.rp_id.clone()
    }

    /// The 16-byte credential id.
    pub fn credential_id(&self) -> Vec<u8> {
        self.inner.credential_id.to_vec()
    }

    /// The SEC1-encoded public key.
    pub fn public_key(&self) -> Vec<u8> {
        self.inner.public_key()
    }

    /// Produce a WebAuthn assertion signature (DER) over the authenticator data
    /// and a 32-byte client-data hash.
    pub fn sign_assertion(
        &self,
        authenticator_data: Vec<u8>,
        client_data_hash: Vec<u8>,
    ) -> Result<Vec<u8>, PosternError> {
        let hash: [u8; 32] = to_array(&client_data_hash, "client_data_hash")?;
        Ok(self.inner.sign_assertion(&authenticator_data, &hash))
    }

    /// EXPLICIT EXPORT of the raw 32-byte private key, for backup into the
    /// vault (restore via [`Credential::from_key_bytes`]).
    ///
    /// SECURITY: the returned bytes land in GC-managed foreign memory that
    /// cannot be zeroized — never log them, store them (e.g. `Vault::put`) and
    /// drop every reference immediately. The Rust-side intermediate copy is
    /// wiped before this returns.
    pub fn to_key_bytes(&self) -> Vec<u8> {
        let mut raw = self.inner.to_key_bytes();
        let out = raw.to_vec();
        raw.zeroize();
        out
    }
}

/// Create a brand-new credential for `rp_id` (random key + id).
#[uniffi::export]
pub fn create_credential(rp_id: String) -> Arc<Credential> {
    Arc::new(Credential { inner: postern_keys::create_credential(&rp_id) })
}

/// Verify a WebAuthn assertion signature against a SEC1 public key.
///
/// CAUTION — two distinct "not verified" outcomes: a malformed input length
/// returns an error, a cryptographically invalid signature returns `Ok(false)`.
/// Callers MUST check the returned boolean; catching the error alone treats a
/// forged signature as success.
#[uniffi::export]
pub fn verify_assertion(
    public_key_sec1: Vec<u8>,
    authenticator_data: Vec<u8>,
    client_data_hash: Vec<u8>,
    signature_der: Vec<u8>,
) -> Result<bool, PosternError> {
    let hash: [u8; 32] = to_array(&client_data_hash, "client_data_hash")?;
    Ok(postern_keys::verify_assertion(
        &public_key_sec1,
        &authenticator_data,
        &hash,
        &signature_der,
    ))
}
