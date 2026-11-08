//! Postern Vault — a secrets / password vault (a Postern Labs product).
//!
//! Secrets live encrypted at rest with the canonical Postern seal
//! (**XChaCha20-Poly1305**, versioned + key-committing, context-bound to
//! `"postern-vault/v1"` — see `postern_core::aead`) under a 32-byte vault key.
//! Today that key comes from an **Argon2id** passphrase ([`derive_key`]) or is
//! supplied by the app.
//!
//! **What this crate does NOT do (yet):** TEE wrapping of the vault key
//! (StrongBox / Secure Enclave) and hybrid PQ wrapping (ML-KEM alongside the
//! wallet's Falcon‖ML-DSA stack) are *planned app-layer integrations* — no
//! code for either exists here. A sealed blob today is protected by Argon2id +
//! XChaCha20-Poly1305 only. (Symmetric crypto is not the PQ weak point —
//! Grover at best square-roots a 256-bit key — but do not mistake this for a
//! shipped PQ key-wrap.)
//!
//! All RustCrypto (Apache-2.0/MIT). No Bitwarden (GPL/AGPL), no KeePassXC (GPL).

use std::collections::BTreeMap;
use zeroize::{Zeroize, Zeroizing};

/// Feature-gated key-wrap abstraction: a [`keychain::KeyStore`] trait plus an
/// [`keychain::unwrap_or_derive`] helper that prefers a stored key and falls
/// back to [`derive_key`]. See the module docs for the "NOT a TEE" caveat.
#[cfg(feature = "keychain")]
pub mod keychain;

/// macOS login-Keychain-backed [`keychain::KeyStore`] (generic-password item,
/// service `"com.posternlabs.vault"`), gated on `keychain-macos`. Still an OS
/// software store, not a TEE — see the module docs for the same "NOT a TEE"
/// disclosure as `keychain.rs`.
#[cfg(all(target_os = "macos", feature = "keychain-macos"))]
pub mod keychain_macos;

/// Linux freedesktop Secret Service (D-Bus)-backed [`keychain::KeyStore`]
/// (collection item, service attribute `"com.posternlabs.vault"`), gated on
/// `keychain-linux`. Still an OS software store, not a TEE — see the module
/// docs for the same "NOT a TEE" disclosure as `keychain.rs`, plus a BLOCKED
/// note: no live D-Bus round-trip has been run against this module (authored
/// on macOS, which has no Secret Service provider).
#[cfg(all(target_os = "linux", feature = "keychain-linux"))]
pub mod keychain_linux;

/// RFC 6238 TOTP / RFC 4226 HOTP for 2FA entries (RustCrypto `hmac` +
/// `sha1`/`sha2`; SHA-1 is the RFC default, SHA-256/512 variants included;
/// base32 secret decoding; seeds in `Zeroizing` buffers). A TOTP seed stored
/// in the vault gets exactly the same at-rest protection as any other entry
/// — Argon2id + XChaCha20-Poly1305 — and nothing more; the crate-level "no
/// TEE code exists here" caveat applies unchanged.
pub mod totp;

/// Typed vault entries (Password / Note / TOTP): a tagged, length-prefixed
/// record stored as the *value* of a normal vault entry, riding through the
/// existing seal/open paths as opaque bytes. Malformed records are rejected
/// as [`VaultError::Corrupt`]; partial secrets are wiped on parse failures.
pub mod entry;

/// Context string binding vault blobs to this product/format (see
/// `postern_core::aead::seal_with_context`): a blob sealed by another Postern
/// product under the same 32-byte key can NOT be opened as a vault, and vice
/// versa.
pub const VAULT_CONTEXT: &[u8] = b"postern-vault/v1";

/// Generate a fresh random KDF salt (re-exported from `postern_core`).
pub use postern_core::kdf::generate_salt;

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("seal failed")]
    Seal,
    #[error("open failed — wrong key or corrupt vault")]
    Open,
    #[error("corrupt vault data")]
    Corrupt,
    #[error("entry too large — names and secrets must each be under 4 GiB")]
    TooLarge,
    #[error("key derivation failed: {0}")]
    Kdf(String),
    #[cfg(feature = "keychain")]
    #[error("key store failed: {0}")]
    KeyStore(String),
}

// The AEAD seal + Argon2id KDF live once in postern-core (the canonical Postern
// seal); map its errors onto the vault's own error surface.
impl From<postern_core::aead::SealError> for VaultError {
    fn from(e: postern_core::aead::SealError) -> Self {
        use postern_core::aead::SealError::*;
        match e {
            Seal => VaultError::Seal,
            Open => VaultError::Open,
            Corrupt => VaultError::Corrupt,
        }
    }
}
impl From<postern_core::kdf::KdfError> for VaultError {
    fn from(e: postern_core::kdf::KdfError) -> Self {
        VaultError::Kdf(e.to_string())
    }
}

/// The decrypted, in-memory vault. Secret **values** are wiped from RAM on
/// drop (and on `remove`/replace); entry **names** are not treated as secret
/// and are not wiped.
#[derive(Default)]
pub struct Vault {
    entries: BTreeMap<String, Vec<u8>>,
}

impl Vault {
    pub fn new() -> Self {
        Self::default()
    }

    /// Store (or replace) a named secret.
    pub fn put(&mut self, name: &str, secret: &[u8]) {
        if let Some(old) = self.entries.insert(name.to_string(), secret.to_vec()) {
            let mut old = old;
            old.zeroize();
        }
    }

    /// Fetch a secret by name.
    pub fn get(&self, name: &str) -> Option<&[u8]> {
        self.entries.get(name).map(|v| v.as_slice())
    }

    /// Remove a secret (wiped from RAM). Returns whether it existed.
    pub fn remove(&mut self, name: &str) -> bool {
        match self.entries.remove(name) {
            Some(mut v) => {
                v.zeroize();
                true
            }
            None => false,
        }
    }

    /// The names of the stored secrets (never the values).
    pub fn names(&self) -> Vec<String> {
        self.entries.keys().cloned().collect()
    }

    /// Encrypt the whole vault with a 32-byte key (from [`derive_key`] or the
    /// app). Output is the versioned, key-committing Postern seal bound to
    /// [`VAULT_CONTEXT`]. The plaintext serialization lives in a single
    /// exactly-sized buffer that is zeroized before returning — serializing
    /// never leaves secret fragments in reallocated-and-freed heap blocks.
    pub fn seal(&self, key: &[u8; 32]) -> Result<Vec<u8>, VaultError> {
        let plain = serialize(&self.entries)?; // Zeroizing: wiped on all paths
        Ok(postern_core::aead::seal_with_context(key, VAULT_CONTEXT, &plain)?)
    }

    /// Decrypt a sealed vault with the 32-byte key. Accepts current
    /// context-bound blobs and blobs sealed before the seal was versioned
    /// (see `postern_core::aead::open_with_context`). The decrypted buffer is
    /// zeroized on every path, including parse failures.
    pub fn open(sealed: &[u8], key: &[u8; 32]) -> Result<Vault, VaultError> {
        let plain =
            Zeroizing::new(postern_core::aead::open_with_context(key, VAULT_CONTEXT, sealed)?);
        let entries = deserialize(&plain)?;
        Ok(Vault { entries })
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        for (_, v) in self.entries.iter_mut() {
            v.zeroize();
        }
    }
}

/// Derive a 32-byte vault key from a passphrase with **Argon2id** at the
/// at-rest tier (64 MiB, t = 3 — see `postern_core::kdf::derive_key`). `salt`
/// must be at least 8 bytes ([`generate_salt`] gives a fresh 16-byte one) and
/// stored alongside the sealed vault. The key wipes itself on drop and derefs
/// to `[u8; 32]`.
///
/// **Breaking (pre-release):** vaults passphrase-sealed before the KDF tier
/// split used the floor parameters — re-derive those keys with
/// `postern_core::kdf::derive_key_floor`, then re-seal.
pub fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    Ok(postern_core::kdf::derive_key(passphrase, salt)?)
}

// ── length-prefixed serialization (no serde dep) ─────────────────────────────

/// Serialize into ONE exactly-sized zeroizing buffer. Pre-computing the size
/// matters for hygiene, not speed: growing a plain `Vec` reallocates, and the
/// freed half-filled blocks would keep un-wiped copies of earlier secrets.
fn serialize(entries: &BTreeMap<String, Vec<u8>>) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let mut size = 0usize;
    for (k, v) in entries {
        if u32::try_from(k.len()).is_err() || u32::try_from(v.len()).is_err() {
            return Err(VaultError::TooLarge); // u32 length prefix must not truncate
        }
        size = size
            .checked_add(8)
            .and_then(|s| s.checked_add(k.len()))
            .and_then(|s| s.checked_add(v.len()))
            .ok_or(VaultError::TooLarge)?;
    }
    let mut out = Zeroizing::new(Vec::with_capacity(size));
    for (k, v) in entries {
        out.extend_from_slice(&(k.len() as u32).to_le_bytes());
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(&(v.len() as u32).to_le_bytes());
        out.extend_from_slice(v);
    }
    debug_assert_eq!(out.len(), size, "size precomputation must be exact (no realloc)");
    Ok(out)
}

fn deserialize(data: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, VaultError> {
    let mut m = BTreeMap::new();
    match deserialize_into(data, &mut m) {
        Ok(()) => Ok(m),
        Err(e) => {
            // A parse failure midway leaves already-decrypted secrets in the
            // partial map; wipe the values before dropping it. (Names are
            // deliberately not treated as secret, matching `Vault`'s policy.)
            for v in m.values_mut() {
                v.zeroize();
            }
            Err(e)
        }
    }
}

fn deserialize_into(data: &[u8], m: &mut BTreeMap<String, Vec<u8>>) -> Result<(), VaultError> {
    // All offset arithmetic is checked: `klen`/`vlen` are u32 values from the
    // blob, and on a 32-bit target `i + klen` could wrap `usize` and slip past
    // an unchecked bounds test. (Defense-in-depth — this only ever runs on
    // AEAD-authenticated plaintext.)
    let mut i = 0usize;
    let read_len = |d: &[u8], i: usize| -> Option<usize> {
        let end = i.checked_add(4).filter(|e| *e <= d.len())?;
        Some(u32::from_le_bytes(d[i..end].try_into().unwrap()) as usize)
    };
    while i < data.len() {
        let klen = read_len(data, i).ok_or(VaultError::Corrupt)?;
        i += 4;
        let kend = i.checked_add(klen).filter(|e| *e <= data.len()).ok_or(VaultError::Corrupt)?;
        let name = String::from_utf8(data[i..kend].to_vec()).map_err(|_| VaultError::Corrupt)?;
        i = kend;
        let vlen = read_len(data, i).ok_or(VaultError::Corrupt)?;
        i += 4;
        let vend = i.checked_add(vlen).filter(|e| *e <= data.len()).ok_or(VaultError::Corrupt)?;
        m.insert(name, data[i..vend].to_vec());
        i = vend;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = [7u8; 32];
        let mut v = Vault::new();
        v.put("email", b"alice@example.com");
        v.put("ssh-key", b"-----BEGIN OPENSSH-----...");
        v.put("bloch-seed", b"twelve word mnemonic here");

        let sealed = v.seal(&key).unwrap();
        // The sealed blob does not contain the plaintext.
        assert!(!sealed.windows(17).any(|w| w == b"alice@example.com"), "plaintext must not appear in the sealed blob");

        let opened = Vault::open(&sealed, &key).unwrap();
        assert_eq!(opened.get("email"), Some(&b"alice@example.com"[..]));
        assert_eq!(opened.get("ssh-key"), Some(&b"-----BEGIN OPENSSH-----..."[..]));
        assert_eq!(opened.names(), vec!["bloch-seed", "email", "ssh-key"]);
    }

    #[test]
    fn vault_blobs_are_context_bound() {
        let key = [7u8; 32];
        let mut v = Vault::new();
        v.put("secret", b"top secret");
        let sealed = v.seal(&key).unwrap();
        // The same 32-byte key cannot open the blob outside the vault context:
        // cross-product blob substitution is refused at the seal layer.
        assert!(postern_core::aead::open(&key, &sealed).is_err());
        assert!(postern_core::aead::open_with_context(&key, b"postern-courier/v1", &sealed).is_err());
        // ...while the vault itself opens it fine.
        assert!(Vault::open(&sealed, &key).is_ok());
    }

    #[test]
    fn wrong_key_fails_to_open() {
        let mut v = Vault::new();
        v.put("secret", b"top secret");
        let sealed = v.seal(&[1u8; 32]).unwrap();
        assert!(matches!(Vault::open(&sealed, &[2u8; 32]), Err(VaultError::Open)));
    }

    #[test]
    fn truncated_blob_is_corrupt_not_wrong_key() {
        assert!(matches!(Vault::open(b"short", &[1u8; 32]), Err(VaultError::Corrupt)));
    }

    #[test]
    fn tamper_is_detected() {
        let mut v = Vault::new();
        v.put("k", b"v");
        let mut sealed = v.seal(&[9u8; 32]).unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF; // flip a ciphertext bit
        assert!(Vault::open(&sealed, &[9u8; 32]).is_err(), "AEAD must reject tampered data");
    }

    #[test]
    fn argon2_key_is_deterministic() {
        let k1 = derive_key(b"correct horse battery staple", b"postern-salt-16b").unwrap();
        let k2 = derive_key(b"correct horse battery staple", b"postern-salt-16b").unwrap();
        assert_eq!(*k1, *k2);
        let k3 = derive_key(b"wrong passphrase", b"postern-salt-16b").unwrap();
        assert_ne!(*k1, *k3);
    }

    #[test]
    fn generated_salt_works_end_to_end() {
        let salt = generate_salt();
        let key = derive_key(b"pw", &salt).unwrap();
        let mut v = Vault::new();
        v.put("a", b"b");
        let sealed = v.seal(&key).unwrap();
        assert_eq!(Vault::open(&sealed, &key).unwrap().get("a"), Some(&b"b"[..]));
    }

    #[test]
    fn remove_and_replace() {
        let mut v = Vault::new();
        v.put("a", b"1");
        v.put("a", b"2"); // replace
        assert_eq!(v.get("a"), Some(&b"2"[..]));
        assert!(v.remove("a"));
        assert!(!v.remove("a"));
        assert_eq!(v.get("a"), None);
    }

    #[test]
    fn corrupt_serialization_is_rejected() {
        // An authenticated-but-malformed payload must fail cleanly (Corrupt),
        // exercising the checked bounds + partial-map wipe path.
        let key = [3u8; 32];
        // klen = 8 but only 2 bytes follow.
        let bad = postern_core::aead::seal_with_context(
            &key,
            VAULT_CONTEXT,
            &[8, 0, 0, 0, b'a', b'b'],
        )
        .unwrap();
        assert!(matches!(Vault::open(&bad, &key), Err(VaultError::Corrupt)));
        // One good entry, then a truncated second entry: the good entry's
        // secret lands in the partial map and must be wiped on the error path.
        let mut payload = Vec::new();
        payload.extend_from_slice(&2u32.to_le_bytes());
        payload.extend_from_slice(b"ok");
        payload.extend_from_slice(&1u32.to_le_bytes());
        payload.extend_from_slice(b"s");
        payload.extend_from_slice(&[255, 255, 255, 255]); // klen = u32::MAX
        let bad2 = postern_core::aead::seal_with_context(&key, VAULT_CONTEXT, &payload).unwrap();
        assert!(matches!(Vault::open(&bad2, &key), Err(VaultError::Corrupt)));
    }
}
