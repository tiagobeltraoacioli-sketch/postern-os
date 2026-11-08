//! Deniable product — the plausible-deniability (hidden-volume) container over
//! `postern_panic::deniable`.
//!
//! This is the coercion-resistance piece that [`crate::panic::PanicSession`]
//! deliberately does NOT claim: a fixed-size dual-slot container in which a
//! **real vault + decoy vault** are byte-for-byte indistinguishable from a
//! single vault + random filler. Under coercion the user reveals the decoy
//! key; whether a hidden vault exists cannot be proven from the bytes.
//!
//! HONEST LIMITS (from the core module — repeat them in any product UI):
//! - Deniability holds for a SINGLE SNAPSHOT of the container bytes. An
//!   adversary diffing versions over time (cloud backups!) sees which slot
//!   changed.
//! - Environment leaks (timestamps, sync logs, UI state, shoulder-surfing) are
//!   out of scope — only the returned bytes are protected.
//! - It changes what can be *proven*, not what a violent adversary may *do*.
//! - A decoy-key holder who re-seals with [`deniable_seal_single`] destroys the
//!   hidden vault (required for undetectability); use [`deniable_reseal`] to
//!   update one vault while preserving the other slot.
//!
//! Real and decoy keys MUST be independently derived (different passphrases
//! AND different salts); identical keys are rejected.

use crate::vault::{Vault, VaultKey};
use crate::PosternError;
use std::sync::Arc;

fn err(e: postern_panic::deniable::DeniableError) -> PosternError {
    PosternError::from(e.to_string())
}

/// Seal a **real vault + decoy vault** into one fixed-size container.
/// See the module honest-limits before surfacing this in a product.
#[uniffi::export]
pub fn deniable_seal_with_decoy(
    real: Arc<Vault>,
    real_key: Arc<VaultKey>,
    decoy: Arc<Vault>,
    decoy_key: Arc<VaultKey>,
) -> Result<Vec<u8>, PosternError> {
    real.with_core(|r| {
        decoy.with_core(|d| {
            postern_panic::deniable::seal_with_decoy(r, real_key.bytes(), d, decoy_key.bytes())
                .map_err(err)
        })
    })
}

/// Seal a **single vault** into a container whose other slot is random filler —
/// the same shape as a dual container, so possession never implies a hidden
/// vault. WARNING: on a container that previously held a hidden vault this
/// discards it (that clobber-ability is what makes the hidden slot
/// undetectable); use [`deniable_reseal`] to update in place.
#[uniffi::export]
pub fn deniable_seal_single(vault: Arc<Vault>, key: Arc<VaultKey>) -> Result<Vec<u8>, PosternError> {
    vault.with_core(|v| postern_panic::deniable::seal_single(v, key.bytes()).map_err(err))
}

/// Open whichever vault `key` unlocks (both slots are always attempted —
/// uniform work). A wrong key and a nonexistent hidden vault fail identically.
#[uniffi::export]
pub fn deniable_open(container: Vec<u8>, key: Arc<VaultKey>) -> Result<Arc<Vault>, PosternError> {
    postern_panic::deniable::open(&container, key.bytes())
        .map(Vault::from_core)
        .map_err(err)
}

/// Re-seal an updated `vault` into the slot `key` opens, leaving the other
/// slot's bytes untouched (the other vault survives without its key being
/// present). NOTE: an adversary diffing container versions sees which slot
/// changed — the fundamental multi-snapshot trade-off.
#[uniffi::export]
pub fn deniable_reseal(
    container: Vec<u8>,
    key: Arc<VaultKey>,
    vault: Arc<Vault>,
) -> Result<Vec<u8>, PosternError> {
    vault.with_core(|v| postern_panic::deniable::reseal(&container, key.bytes(), v).map_err(err))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> Arc<VaultKey> {
        VaultKey::from_bytes(vec![b; 32]).unwrap()
    }

    fn vault_with(name: &str, secret: &[u8]) -> Arc<Vault> {
        let v = Vault::new();
        v.put(name.into(), secret.to_vec());
        v
    }

    #[test]
    fn dual_container_roundtrip_via_handles() {
        let real = vault_with("seed", b"the real mnemonic");
        let decoy = vault_with("seed", b"harmless decoy");
        let c = deniable_seal_with_decoy(real, key(1), decoy, key(2)).unwrap();

        let opened_real = deniable_open(c.clone(), key(1)).unwrap();
        assert_eq!(opened_real.get("seed".into()), Some(b"the real mnemonic".to_vec()));
        let opened_decoy = deniable_open(c.clone(), key(2)).unwrap();
        assert_eq!(opened_decoy.get("seed".into()), Some(b"harmless decoy".to_vec()));

        // Wrong key fails; single and dual containers share size/shape.
        assert!(deniable_open(c.clone(), key(9)).is_err());
        let single = deniable_seal_single(vault_with("a", b"b"), key(3)).unwrap();
        assert_eq!(c.len(), single.len());
    }

    #[test]
    fn identical_keys_rejected_and_reseal_preserves_hidden() {
        let real = vault_with("seed", b"real v1");
        let decoy = vault_with("note", b"decoy v1");
        assert!(deniable_seal_with_decoy(real.clone(), key(1), decoy.clone(), key(1)).is_err());

        let c1 = deniable_seal_with_decoy(real, key(1), decoy, key(2)).unwrap();
        let c2 = deniable_reseal(c1, key(2), vault_with("note", b"decoy v2")).unwrap();
        assert_eq!(deniable_open(c2.clone(), key(2)).unwrap().get("note".into()), Some(b"decoy v2".to_vec()));
        assert_eq!(deniable_open(c2, key(1)).unwrap().get("seed".into()), Some(b"real v1".to_vec()));
    }
}
