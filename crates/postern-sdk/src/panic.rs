//! Panic product — a panic-lockable secret session over `postern_panic`
//! (the Panic Lock).
//!
//! An unlocked session holds a live [`postern_vault::Vault`]; `panic()` seals it
//! (wiping the plaintext and key from RAM) and `unlock(key)` re-opens it. Held
//! behind a `Mutex` because `panic`/`unlock`/`put` mutate while UniFFI exposes
//! `&self` methods.
//!
//! HONEST LIMITS — what this is and is not:
//! - It IS an instant re-lock: one call and only at-rest ciphertext remains in
//!   memory. Nothing is destroyed, so it cannot be misused to destroy evidence,
//!   and the legitimate owner re-opens later with the key.
//! - It is NOT coercion-resistant and NOT deniable: the session itself has no
//!   decoy vault and no plausible-deniability mode. An adversary holding the
//!   device can see that a locked session exists and that the data is intact —
//!   it protects by DENIAL OF ACCESS only. Do not present it to users as more
//!   than that. For coercion threat models, store the sealed data in the
//!   deniable dual-slot container instead (`deniable_seal_with_decoy` /
//!   `deniable_open` in this SDK), which carries its own honest limits.

use crate::{lock_recover, PosternError};
use crate::vault::VaultKey;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

/// A panic-lockable secret session (denial-of-access re-lock; see the module
/// doc's honest-limits note — no decoy, no deniability). Starts unlocked with
/// an empty vault.
#[derive(uniffi::Object)]
pub struct PanicSession {
    inner: Mutex<postern_panic::PanicSession>,
}

#[uniffi::export]
impl PanicSession {
    /// Start a new UNLOCKED session (empty vault) guarded by the given key.
    /// Populate it with [`PanicSession::put`], then [`PanicSession::panic`] to
    /// re-lock instantly.
    #[uniffi::constructor]
    pub fn unlocked(key: Arc<VaultKey>) -> Arc<PanicSession> {
        let session = postern_panic::PanicSession::unlocked(postern_vault::Vault::new(), *key.bytes());
        Arc::new(PanicSession { inner: Mutex::new(session) })
    }

    /// Whether the session is currently locked (sealed).
    pub fn is_locked(&self) -> bool {
        lock_recover(&self.inner).is_locked()
    }

    /// PANIC — instantly re-lock: seal the vault to ciphertext and wipe the
    /// plaintext secrets + key from RAM. Nothing is destroyed; the owner
    /// re-opens later with the key. Idempotent. (Denial of access only — this
    /// does NOT provide deniability against an adversary who can inspect the
    /// device.) This path must never panic: lock poisoning is recovered, and
    /// errors return as `PosternError`.
    pub fn panic(&self) -> Result<(), PosternError> {
        lock_recover(&self.inner).panic().map_err(|e| PosternError::from(e.to_string()))
    }

    /// Re-open a locked session with its key handle. Wrong key → error, the
    /// session stays locked.
    pub fn unlock(&self, key: Arc<VaultKey>) -> Result<(), PosternError> {
        lock_recover(&self.inner)
            .unlock(*key.bytes())
            .map_err(|e| PosternError::from(e.to_string()))
    }

    /// Fetch a secret by name (None if locked or absent), copied across FFI.
    /// SECURITY: the copy lands in GC-managed foreign memory — never log it.
    pub fn get(&self, name: String) -> Option<Vec<u8>> {
        lock_recover(&self.inner).get(&name).map(|s| s.to_vec())
    }

    /// Store a secret. Returns false if the session is locked. The Rust-side
    /// copy of `secret` is wiped after it is stored.
    pub fn put(&self, name: String, secret: Vec<u8>) -> bool {
        let secret = Zeroizing::new(secret);
        lock_recover(&self.inner).put(&name, &secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Arc<VaultKey> {
        VaultKey::from_bytes(vec![5u8; 32]).unwrap()
    }

    #[test]
    fn panic_locks_and_key_handle_unlocks() {
        let s = PanicSession::unlocked(key());
        assert!(s.put("seed".into(), b"secret mnemonic".to_vec()));
        assert!(!s.is_locked());

        s.panic().unwrap();
        assert!(s.is_locked());
        assert_eq!(s.get("seed".into()), None);
        assert!(!s.put("x".into(), b"y".to_vec()), "no writes while locked");

        assert!(s.unlock(VaultKey::from_bytes(vec![9u8; 32]).unwrap()).is_err());
        s.unlock(key()).unwrap();
        assert_eq!(s.get("seed".into()), Some(b"secret mnemonic".to_vec()));
    }

    #[test]
    fn poisoned_lock_never_panics_the_panic_path() {
        let s = PanicSession::unlocked(key());
        assert!(s.put("seed".into(), b"secret".to_vec()));

        // Poison the mutex: panic while holding the guard.
        let poison = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = s.inner.lock().unwrap();
            panic!("simulated core panic while locked");
        }));
        assert!(poison.is_err());
        assert!(s.inner.is_poisoned());

        // The duress path MUST still work — a crash here would be the worst time.
        s.panic().unwrap();
        assert!(s.is_locked());
        s.unlock(key()).unwrap();
        assert_eq!(s.get("seed".into()), Some(b"secret".to_vec()));
    }
}
