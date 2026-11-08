//! Vault product — a UniFFI wrapper over `postern_vault::Vault`.
//!
//! An in-memory, sealable secret store. Held behind a `Mutex` because the core's
//! `put`/`remove` mutate, while UniFFI objects expose `&self` methods. The
//! core's zeroizing `Drop` still runs when the foreign object is released.
//!
//! The 32-byte vault master key lives behind the OPAQUE [`VaultKey`] handle:
//! derived keys never cross the FFI into GC-managed memory (where they could
//! not be zeroized), and no Record/`toString()` can ever print them.

use crate::{lock_recover, to_array, PosternError};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

/// A 32-byte vault master key behind an opaque handle.
///
/// Deliberately an object, not bytes: the key material stays on the Rust side
/// (zeroized when the handle is released) instead of being copied into the
/// foreign GC heap, and stringifying the handle prints nothing. Derive it from
/// a passphrase with [`VaultKey::derive`], or wrap TEE-released bytes with
/// [`VaultKey::from_bytes`].
#[derive(uniffi::Object)]
pub struct VaultKey {
    inner: Zeroizing<[u8; 32]>,
}

impl VaultKey {
    /// Rust-side access for the sibling products (vault, panic).
    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.inner
    }
}

#[uniffi::export]
impl VaultKey {
    /// Derive the key from a passphrase + salt with Argon2id (parameters are
    /// pinned in `postern-core` — nothing attacker-writable selects them).
    /// `salt` must be at least 8 bytes. The passphrase's Rust-side copy is
    /// wiped before returning; the derived key never crosses the FFI.
    #[uniffi::constructor]
    pub fn derive(passphrase: Vec<u8>, salt: Vec<u8>) -> Result<Arc<VaultKey>, PosternError> {
        let passphrase = Zeroizing::new(passphrase);
        // postern-vault already returns the key in a `Zeroizing` wrapper; move
        // it straight into the handle (no bare-array copy).
        let key = postern_vault::derive_key(&passphrase, &salt)
            .map_err(|e| PosternError::from(e.to_string()))?;
        Ok(Arc::new(VaultKey { inner: key }))
    }

    /// Wrap externally provided 32-byte key material (e.g. released by the
    /// device TEE) in an opaque handle. The Rust-side copy of `key` is wiped.
    #[uniffi::constructor]
    pub fn from_bytes(key: Vec<u8>) -> Result<Arc<VaultKey>, PosternError> {
        let key = Zeroizing::new(key);
        let k: [u8; 32] = to_array(&key, "vault key")?;
        Ok(Arc::new(VaultKey { inner: Zeroizing::new(k) }))
    }

    /// EXPLICIT EXPORT of the raw key bytes — needed only to hand the key to a
    /// platform keystore/TEE for hardware wrapping.
    ///
    /// SECURITY: the returned bytes land in GC-managed foreign memory that
    /// cannot be zeroized. Never log them; hand them to the keystore and drop
    /// every reference immediately. For everything else, pass the handle
    /// itself — `Vault`/`PanicSession` accept it directly.
    pub fn export_key_bytes(&self) -> Vec<u8> {
        self.inner.to_vec()
    }
}

/// A sealable in-memory secret store (name → bytes).
#[derive(uniffi::Object)]
pub struct Vault {
    inner: Mutex<postern_vault::Vault>,
}

impl Vault {
    /// Rust-side wrap of a core vault (used by the sibling products).
    pub(crate) fn from_core(v: postern_vault::Vault) -> Arc<Vault> {
        Arc::new(Vault { inner: Mutex::new(v) })
    }

    /// Rust-side read access to the core vault (used by the sibling products).
    pub(crate) fn with_core<R>(&self, f: impl FnOnce(&postern_vault::Vault) -> R) -> R {
        f(&lock_recover(&self.inner))
    }
}

#[uniffi::export]
impl Vault {
    /// A new empty vault.
    #[uniffi::constructor]
    pub fn new() -> Arc<Vault> {
        Arc::new(Vault { inner: Mutex::new(postern_vault::Vault::new()) })
    }

    /// Open (decrypt) a previously sealed vault with its key handle.
    #[uniffi::constructor]
    pub fn open(sealed: Vec<u8>, key: Arc<VaultKey>) -> Result<Arc<Vault>, PosternError> {
        let v = postern_vault::Vault::open(&sealed, key.bytes())
            .map_err(|e| PosternError::from(e.to_string()))?;
        Ok(Arc::new(Vault { inner: Mutex::new(v) }))
    }

    /// Store (or overwrite) a secret under `name`. The Rust-side copy of
    /// `secret` is wiped after it is stored.
    pub fn put(&self, name: String, secret: Vec<u8>) {
        let secret = Zeroizing::new(secret);
        lock_recover(&self.inner).put(&name, &secret);
    }

    /// Fetch a secret by `name`, copied out across the FFI boundary.
    /// SECURITY: the copy lands in GC-managed foreign memory — never log it,
    /// and drop references as soon as the secret has been used.
    pub fn get(&self, name: String) -> Option<Vec<u8>> {
        lock_recover(&self.inner).get(&name).map(|s| s.to_vec())
    }

    /// Remove a secret. Returns whether it existed.
    pub fn remove(&self, name: String) -> bool {
        lock_recover(&self.inner).remove(&name)
    }

    /// The names of all stored secrets.
    pub fn names(&self) -> Vec<String> {
        lock_recover(&self.inner).names()
    }

    /// Seal (encrypt) the whole vault with its key handle → the versioned,
    /// key-committing Postern seal (`postern_core::aead`), bound to the
    /// vault context.
    pub fn seal(&self, key: Arc<VaultKey>) -> Result<Vec<u8>, PosternError> {
        lock_recover(&self.inner)
            .seal(key.bytes())
            .map_err(|e| PosternError::from(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_seal_open_roundtrip_via_handles() {
        let key = VaultKey::derive(b"correct horse battery staple".to_vec(), b"postern-salt-16b".to_vec())
            .unwrap();
        let v = Vault::new();
        v.put("email".into(), b"alice@example.com".to_vec());
        let sealed = v.seal(key.clone()).unwrap();

        let reopened = Vault::open(sealed, key).unwrap();
        assert_eq!(reopened.get("email".into()), Some(b"alice@example.com".to_vec()));
    }

    #[test]
    fn from_bytes_validates_length_and_exports_roundtrip() {
        assert!(VaultKey::from_bytes(vec![0u8; 31]).is_err());
        let key = VaultKey::from_bytes(vec![7u8; 32]).unwrap();
        assert_eq!(key.export_key_bytes(), vec![7u8; 32]);
    }

    #[test]
    fn wrong_key_fails_to_open() {
        let v = Vault::new();
        v.put("secret".into(), b"top secret".to_vec());
        let sealed = v.seal(VaultKey::from_bytes(vec![1u8; 32]).unwrap()).unwrap();
        assert!(Vault::open(sealed, VaultKey::from_bytes(vec![2u8; 32]).unwrap()).is_err());
    }

    #[test]
    fn poisoned_lock_recovers_instead_of_panicking() {
        let v = Vault::new();
        v.put("a".into(), b"1".to_vec());

        // Poison the mutex: panic while holding the guard.
        let poison = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = v.inner.lock().unwrap();
            panic!("simulated core panic while locked");
        }));
        assert!(poison.is_err());
        assert!(v.inner.is_poisoned());

        // Every FFI-reachable method must keep working instead of panicking.
        assert_eq!(v.get("a".into()), Some(b"1".to_vec()));
        v.put("b".into(), b"2".to_vec());
        assert_eq!(v.names(), vec!["a".to_string(), "b".to_string()]);
        assert!(v.remove("b".into()));
    }
}
