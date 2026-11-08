//! Postern Keys — a passkey / FIDO2 authenticator core (a Postern Labs product).
//!
//! Identity/auth is the biggest unfilled gap in the daily-driver surface, and the
//! permissive-license field is empty (Bitwarden is GPL/AGPL, KeePassXC GPL-2).
//! This is the credential core: a WebAuthn **ES256** (P-256) keypair per relying
//! party, signing authentication assertions. The private key is exported only to
//! be **sealed in the Postern Vault** (`postern-vault`: Argon2id + XChaCha20-
//! Poly1305 at rest today; TEE wrapping of the vault key by StrongBox / Secure
//! Enclave is planned app-layer work, not shipped) — never stored in the clear.
//! Export as ONE bound record via [`Credential::to_vault_record`], not as loose
//! fields. Third "same vault engine, different UI" product; the full
//! CTAP2/WebAuthn protocol + browser/Android integration is the app layer
//! (build it on `passkey-rs`, 1Password, MIT/Apache).
//!
//! Honest limits: WebAuthn signatures are **classical** (ES256/P-256) — no PQ
//! passkeys until relying parties accept them (ecosystem reality); most sites
//! ignore authenticator attestation, so the Seal benefit is local/P2P, not "sites
//! trust you more"; a software authenticator is weaker than a hardware key unless
//! the key lives in the TEE — which is exactly why the private key goes to the vault.
//! Same honesty for the PRF extension ([`Credential::prf_eval`], the WebAuthn
//! `prf` / CTAP2 `hmac-secret` model): the per-credential PRF seed is a
//! **userland secret**, protected only by the vault seal at rest — a hardware
//! `hmac-secret` authenticator keeps its `CredRandom` inside the secure
//! element; this software one cannot.

mod prf;

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use zeroize::Zeroizing;

/// Vault record format version 2 (adds PRF seed + signature counter).
const VAULT_RECORD_V2: u8 = 0x02;

/// Sealed-export envelope version 1:
/// `0x01 ‖ salt(16, fresh random per export) ‖ sealed_blob`.
const EXPORT_V1: u8 = 0x01;

/// AEAD domain-separation context for sealed credential exports. Crate- and
/// purpose-specific, so a keys export can never be opened as a Postern Vault
/// blob (or any other Postern seal) and vice versa, even under the same
/// passphrase.
const KEYS_EXPORT_CONTEXT: &[u8] = b"postern-keys/credential-export/v1";

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("invalid private key bytes")]
    BadKey,
    #[error("invalid vault record")]
    BadRecord,
    /// The sealed-export envelope is structurally invalid: wrong version
    /// byte, truncated before the salt boundary, or a corrupt sealed blob.
    #[error("invalid sealed export blob")]
    BadExport,
    /// The passphrase seal failed to open (on import: wrong passphrase OR a
    /// tampered blob — **indistinguishable by design**, the AEAD rejects both
    /// identically) or, on export, the KDF/seal primitive itself failed
    /// (practically unreachable with the pinned parameters).
    #[error("sealed export crypto failure — on import: wrong passphrase or tampered blob (indistinguishable by design)")]
    Unseal,
}

/// A passkey credential: an ES256 keypair bound to one relying party.
///
/// The private key material is wiped from RAM when the credential is dropped:
/// `ecdsa::SigningKey` implements `ZeroizeOnDrop` (statically asserted below,
/// so a future `p256`/`ecdsa` bump that silently loses the guarantee fails to
/// compile instead of leaking).
pub struct Credential {
    /// The relying party (e.g. `"example.com"`).
    pub rp_id: String,
    /// A random credential handle the RP stores + echoes back.
    pub credential_id: [u8; 16],
    key: SigningKey,
    /// Per-credential 32-byte PRF seed (WebAuthn `prf` / CTAP2 `hmac-secret`
    /// `CredRandom`). `Zeroizing` wipes it from RAM on drop, matching the
    /// signing key's `ZeroizeOnDrop` discipline.
    prf_seed: Zeroizing<[u8; 32]>,
    /// Monotonic signature counter (see [`Credential::next_counter`]).
    counter: u32,
}

// Compile-time guarantee that the wrapped signing key zeroizes itself on drop.
// If this stops holding after a dependency bump, wrap the key manually.
const _: () = {
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    let _ = assert_zeroize_on_drop::<SigningKey>;
};

/// Create a fresh passkey credential for a relying party, including a fresh
/// per-credential PRF seed and a signature counter starting at 0.
pub fn create_credential(rp_id: &str) -> Credential {
    use rand_core::{OsRng, RngCore};
    let mut credential_id = [0u8; 16];
    OsRng.fill_bytes(&mut credential_id);
    let mut prf_seed = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(prf_seed.as_mut());
    Credential {
        rp_id: rp_id.to_string(),
        credential_id,
        key: SigningKey::random(&mut OsRng),
        prf_seed,
        counter: 0,
    }
}

impl Credential {
    /// The public key in SEC1 form — what the RP stores at registration.
    pub fn public_key(&self) -> Vec<u8> {
        self.key.verifying_key().to_sec1_bytes().to_vec()
    }

    /// Sign a WebAuthn authentication assertion over
    /// `authenticator_data ‖ SHA-256(client_data)`. Returns the DER signature.
    pub fn sign_assertion(&self, authenticator_data: &[u8], client_data_hash: &[u8; 32]) -> Vec<u8> {
        let signed = assertion_message(authenticator_data, client_data_hash);
        let sig: Signature = self.key.sign(&signed);
        sig.to_der().as_bytes().to_vec()
    }

    /// Evaluate the credential PRF (WebAuthn `prf` extension / CTAP2
    /// `hmac-secret`):
    /// `HMAC-SHA-256(prf_seed, SHA-256("WebAuthn PRF" || 0x00 || input))` —
    /// the extension's domain-separated input hashing, so callers pass the
    /// raw `eval` input, never a pre-hashed salt.
    ///
    /// Deterministic per (credential, input); distinct credentials and
    /// distinct inputs give unrelated outputs. Typical use: derive a stable
    /// per-site encryption key from a passkey. The returned 32 bytes are
    /// **caller-owned** — zeroize them when done if used as key material.
    ///
    /// Honest limit: the seed is a userland secret, protected only by the
    /// vault seal at rest — not by a hardware boundary like a real
    /// `hmac-secret` authenticator's `CredRandom`.
    pub fn prf_eval(&self, input: &[u8]) -> [u8; 32] {
        prf::eval(&self.prf_seed, input)
    }

    /// The current signature counter value (last value handed out by
    /// [`Credential::next_counter`]; 0 for a fresh credential).
    pub fn counter(&self) -> u32 {
        self.counter
    }

    /// Bump the monotonic signature counter and return the new value.
    ///
    /// Honest scope: this crate does **not** construct `authenticator_data`
    /// (that is app-layer work, e.g. on `passkey-rs`). The caller embeds the
    /// returned value in the big-endian counter field of the
    /// `authenticator_data` it passes to [`Credential::sign_assertion`], and
    /// persists the credential (re-seal the vault record) so the counter
    /// survives restarts. Saturates at `u32::MAX` rather than wrapping — a
    /// wrapped counter would look like a cloned authenticator to RPs.
    pub fn next_counter(&mut self) -> u32 {
        self.counter = self.counter.saturating_add(1);
        self.counter
    }

    /// Export the 32-byte private key **only to seal it in the Postern Vault**.
    /// It must never be persisted outside the vault.
    ///
    /// **Prefer [`Credential::to_vault_record`]** — it binds the key to its
    /// `rp_id` and `credential_id` in one record, so a bug (or a swap of
    /// loose vault entries) can never pair site A's key with site B's rp_id.
    ///
    /// The returned array is **caller-owned**: this crate cannot wipe it for
    /// you. Zeroize it (`zeroize::Zeroize`) as soon as it has been handed to
    /// the vault — `postern-vault` wipes its own copy after sealing.
    pub fn to_key_bytes(&self) -> [u8; 32] {
        self.key.to_bytes().into()
    }

    /// Reconstruct a credential from a vault-unsealed private key.
    ///
    /// **Prefer [`Credential::from_vault_record`]** — this constructor accepts
    /// any (rp_id, credential_id, key) combination and cannot detect a
    /// mispairing; it exists for callers that stored the fields loose. Loose
    /// fields also cannot carry the PRF seed or the signature counter: this
    /// constructor generates a **fresh** PRF seed (so [`Credential::prf_eval`]
    /// outputs will NOT match the original credential's) and resets the
    /// counter to 0 (which an RP may flag as a cloned authenticator). Only
    /// the vault record preserves both.
    ///
    /// `key_bytes` remains caller-owned — zeroize it after this returns.
    pub fn from_key_bytes(rp_id: &str, credential_id: [u8; 16], key_bytes: &[u8]) -> Result<Self, KeyError> {
        use rand_core::{OsRng, RngCore};
        let key = SigningKey::from_slice(key_bytes).map_err(|_| KeyError::BadKey)?;
        let mut prf_seed = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(prf_seed.as_mut());
        Ok(Self { rp_id: rp_id.to_string(), credential_id, key, prf_seed, counter: 0 })
    }

    /// Export the credential as ONE vault record that keeps the private key
    /// **bound to its identity** — versioned record v2:
    /// `0x02 ‖ len(rp_id) as u32-le ‖ rp_id ‖ credential_id(16) ‖ key(32) ‖ prf_seed(32) ‖ counter(u32-le)`.
    ///
    /// Store this single record as the vault entry (instead of loose values)
    /// so key, PRF seed and identity cannot be recombined; nothing outside
    /// the vault seal cryptographically prevents mixing loose fields. Re-seal
    /// the record after each [`Credential::next_counter`] bump so the counter
    /// survives restarts. The record contains the private key and PRF seed:
    /// the returned buffer zeroizes itself on drop, and must only ever be
    /// persisted inside the vault.
    pub fn to_vault_record(&self) -> Zeroizing<Vec<u8>> {
        let rp = self.rp_id.as_bytes();
        let rp_len = u32::try_from(rp.len()).expect("rp_id length must fit in u32");
        let mut rec = Zeroizing::new(Vec::with_capacity(1 + 4 + rp.len() + 16 + 32 + 32 + 4));
        rec.push(VAULT_RECORD_V2);
        rec.extend_from_slice(&rp_len.to_le_bytes());
        rec.extend_from_slice(rp);
        rec.extend_from_slice(&self.credential_id);
        rec.extend_from_slice(&self.key.to_bytes());
        rec.extend_from_slice(self.prf_seed.as_ref());
        rec.extend_from_slice(&self.counter.to_le_bytes());
        rec
    }

    /// Reconstruct a credential from a [`Credential::to_vault_record`] v2
    /// record. The rp_id, credential_id, key, PRF seed and counter travel
    /// together, so they cannot have been recombined from different
    /// credentials' loose entries. Anything malformed — wrong version byte,
    /// truncated, overlong, an rp length pointing past the end — is rejected
    /// as [`KeyError::BadRecord`].
    ///
    /// **Breaking (pre-release):** records exported before the v2 format
    /// (the unversioned `rp_len-first` layout without PRF seed or counter)
    /// are rejected — a version byte cannot be retrofitted unambiguously onto
    /// an unversioned layout. Rebuild the credential from its loose key via
    /// [`Credential::from_key_bytes`], then re-export with
    /// [`Credential::to_vault_record`] and re-seal.
    ///
    /// `record` remains caller-owned — zeroize it after this returns (it holds
    /// the private key and PRF seed).
    pub fn from_vault_record(record: &[u8]) -> Result<Self, KeyError> {
        if record.first() != Some(&VAULT_RECORD_V2) {
            return Err(KeyError::BadRecord);
        }
        let rp_len = record
            .get(1..5)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()) as usize)
            .ok_or(KeyError::BadRecord)?;
        // Checked arithmetic: rp_len is untrusted and could wrap usize on
        // 32-bit targets.
        let cred_start = 5usize.checked_add(rp_len).ok_or(KeyError::BadRecord)?;
        let key_start = cred_start.checked_add(16).ok_or(KeyError::BadRecord)?;
        let seed_start = key_start.checked_add(32).ok_or(KeyError::BadRecord)?;
        let counter_start = seed_start.checked_add(32).ok_or(KeyError::BadRecord)?;
        let end = counter_start.checked_add(4).ok_or(KeyError::BadRecord)?;
        if record.len() != end {
            return Err(KeyError::BadRecord);
        }
        let rp_id =
            std::str::from_utf8(&record[5..cred_start]).map_err(|_| KeyError::BadRecord)?;
        let credential_id: [u8; 16] =
            record[cred_start..key_start].try_into().map_err(|_| KeyError::BadRecord)?;
        let key =
            SigningKey::from_slice(&record[key_start..seed_start]).map_err(|_| KeyError::BadKey)?;
        let mut prf_seed = Zeroizing::new([0u8; 32]);
        prf_seed.copy_from_slice(&record[seed_start..counter_start]);
        let counter = u32::from_le_bytes(
            record[counter_start..end].try_into().map_err(|_| KeyError::BadRecord)?,
        );
        Ok(Self { rp_id: rp_id.to_string(), credential_id, key, prf_seed, counter })
    }

    /// Export the credential as a **passphrase-sealed, self-contained blob**
    /// a user can carry across devices and import with
    /// [`Credential::import_sealed`]. Versioned envelope v1:
    /// `0x01 ‖ salt(16, fresh random per export) ‖ sealed_blob`, where the
    /// sealed blob is the [`Credential::to_vault_record`] v2 record sealed by
    /// the canonical Postern seal (`postern-core`): **Argon2id** at the
    /// at-rest tier (64 MiB, t = 3) derives the key from `passphrase` + salt,
    /// and the versioned **key-committing XChaCha20-Poly1305** AEAD seals the
    /// record under a crate-specific context — so a keys export can never be
    /// opened as a vault blob or vice versa. Two exports of the same
    /// credential produce different bytes (fresh salt + nonce every time).
    ///
    /// Honest limits, same as the rest of this crate: this is Argon2id +
    /// XChaCha20-Poly1305 at rest **today**; TEE key-wrap (StrongBox / Secure
    /// Enclave) is planned app-layer work, NOT shipped. Everything here is
    /// **unaudited**, and a software authenticator is weaker than a hardware
    /// key. The blob contains the **private key and PRF seed** — its only
    /// protection is the passphrase's strength against offline brute force,
    /// so treat the blob itself as a secret: don't post it, don't leave it in
    /// cloud storage you don't trust, and delete stale copies. The returned
    /// buffer zeroizes itself on drop; the derived key and the intermediate
    /// plaintext record are zeroized on every path, including errors.
    /// `passphrase` remains caller-owned — zeroize it when done.
    pub fn export_sealed(&self, passphrase: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeyError> {
        let salt = postern_core::kdf::generate_salt();
        // Zeroizing<[u8; 32]> — wiped on drop, including the error paths below.
        let key =
            postern_core::kdf::derive_key(passphrase, &salt).map_err(|_| KeyError::Unseal)?;
        // Zeroizing<Vec<u8>> — the plaintext record (private key + PRF seed)
        // is wiped when this scope ends, sealed or not.
        let record = self.to_vault_record();
        let sealed = postern_core::aead::seal_with_context(&key, KEYS_EXPORT_CONTEXT, &record)
            .map_err(|_| KeyError::Unseal)?;
        let mut out = Zeroizing::new(Vec::with_capacity(1 + salt.len() + sealed.len()));
        out.push(EXPORT_V1);
        out.extend_from_slice(&salt);
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// Import a credential from a [`Credential::export_sealed`] blob.
    /// Preserves everything the vault record carries: rp_id, credential_id,
    /// the ES256 private key, the PRF seed (so [`Credential::prf_eval`]
    /// outputs match the original) and the signature counter.
    ///
    /// Errors — never panics on malformed input:
    /// - [`KeyError::BadExport`]: wrong version byte, truncated, or
    ///   structurally invalid envelope/sealed blob.
    /// - [`KeyError::Unseal`]: the AEAD refused to open — wrong passphrase OR
    ///   tampered ciphertext, **indistinguishable by design** (the seal
    ///   rejects both identically; an importer cannot tell "typo" from
    ///   "someone modified the blob").
    /// - [`KeyError::BadRecord`] / [`KeyError::BadKey`]: the seal opened but
    ///   the inner record is not a valid v2 vault record (should not happen
    ///   for blobs this crate produced).
    ///
    /// The derived key and the decrypted record are zeroized on every path,
    /// including errors. Same honesty as the export side: Argon2id +
    /// XChaCha20-Poly1305 at rest today, TEE key-wrap NOT shipped, unaudited,
    /// and the blob holds the private key + PRF seed — treat it as a secret.
    /// `blob` and `passphrase` remain caller-owned; the blob is a secret too,
    /// so zeroize your copy once imported.
    pub fn import_sealed(blob: &[u8], passphrase: &[u8]) -> Result<Credential, KeyError> {
        const SALT_END: usize = 1 + postern_core::kdf::SALT_LEN;
        if blob.len() <= SALT_END || blob[0] != EXPORT_V1 {
            return Err(KeyError::BadExport);
        }
        let salt = &blob[1..SALT_END];
        let sealed = &blob[SALT_END..];
        // Zeroizing — wiped on drop, including the error paths below.
        let key =
            postern_core::kdf::derive_key(passphrase, salt).map_err(|_| KeyError::Unseal)?;
        // Wrap the decrypted record (private key + PRF seed) immediately so
        // it is wiped whether from_vault_record succeeds or fails.
        let record = postern_core::aead::open_with_context(&key, KEYS_EXPORT_CONTEXT, sealed)
            .map(Zeroizing::new)
            .map_err(|e| match e {
                postern_core::aead::SealError::Corrupt => KeyError::BadExport,
                _ => KeyError::Unseal,
            })?;
        Credential::from_vault_record(&record)
    }
}

fn assertion_message(authenticator_data: &[u8], client_data_hash: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(authenticator_data.len() + 32);
    m.extend_from_slice(authenticator_data);
    m.extend_from_slice(client_data_hash);
    m
}

/// Verify a WebAuthn assertion signature with a credential's SEC1 public key —
/// what a relying party (or a Postern-to-Postern flow) runs.
pub fn verify_assertion(
    public_key_sec1: &[u8],
    authenticator_data: &[u8],
    client_data_hash: &[u8; 32],
    signature_der: &[u8],
) -> bool {
    let vk = match VerifyingKey::from_sec1_bytes(public_key_sec1) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let sig = match Signature::from_der(signature_der) {
        Ok(s) => s,
        Err(_) => return false,
    };
    vk.verify(&assertion_message(authenticator_data, client_data_hash), &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn client_hash(data: &[u8]) -> [u8; 32] {
        Sha256::digest(data).into()
    }

    #[test]
    fn assertion_signs_and_verifies() {
        let cred = create_credential("example.com");
        let pk = cred.public_key();
        let auth_data = b"authenticator-data-rpidhash-flags-counter";
        let ch = client_hash(br#"{"type":"webauthn.get","challenge":"abc"}"#);

        let sig = cred.sign_assertion(auth_data, &ch);
        assert!(verify_assertion(&pk, auth_data, &ch, &sig));

        // A different challenge (client data) must not verify against this signature.
        let ch2 = client_hash(br#"{"type":"webauthn.get","challenge":"xyz"}"#);
        assert!(!verify_assertion(&pk, auth_data, &ch2, &sig));
    }

    #[test]
    fn vault_key_roundtrip_reconstructs_the_credential() {
        let cred = create_credential("bank.example");
        let sealed_key = cred.to_key_bytes(); // this is what goes into the vault
        let auth_data = b"auth-data";
        let ch = client_hash(b"challenge");
        let sig = cred.sign_assertion(auth_data, &ch);

        // Rebuild from the (vault-unsealed) key and verify the SAME public key signs.
        let restored = Credential::from_key_bytes("bank.example", cred.credential_id, &sealed_key).unwrap();
        assert_eq!(restored.public_key(), cred.public_key());
        assert!(verify_assertion(&restored.public_key(), auth_data, &ch, &sig));
    }

    #[test]
    fn vault_record_binds_identity_to_key() {
        let cred = create_credential("bank.example");
        let rec = cred.to_vault_record();
        let restored = Credential::from_vault_record(&rec).unwrap();
        assert_eq!(restored.rp_id, "bank.example");
        assert_eq!(restored.credential_id, cred.credential_id);
        assert_eq!(restored.public_key(), cred.public_key());

        // Malformed records are rejected (never silently mis-split).
        assert!(Credential::from_vault_record(&[]).is_err());
        assert!(Credential::from_vault_record(&rec[..rec.len() - 1]).is_err());
        let mut long = rec.to_vec();
        long.push(0);
        assert!(Credential::from_vault_record(&long).is_err());
        // rp_len pointing past the end must fail cleanly.
        let mut bad = rec.to_vec();
        bad[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Credential::from_vault_record(&bad).is_err());
    }

    #[test]
    fn wrong_credential_cannot_impersonate() {
        let a = create_credential("site");
        let b = create_credential("site");
        let auth = b"ad";
        let ch = client_hash(b"c");
        let sig_a = a.sign_assertion(auth, &ch);
        // b's public key must NOT verify a's signature.
        assert!(!verify_assertion(&b.public_key(), auth, &ch, &sig_a));
        assert!(Credential::from_key_bytes("site", [0u8; 16], b"tooshort").is_err());
    }

    #[test]
    fn prf_is_deterministic_and_separated_per_credential_and_input() {
        let a = create_credential("example.com");
        let b = create_credential("example.com");
        // Deterministic for one credential + input.
        assert_eq!(a.prf_eval(b"salt-1"), a.prf_eval(b"salt-1"));
        // Distinct per input.
        assert_ne!(a.prf_eval(b"salt-1"), a.prf_eval(b"salt-2"));
        // Distinct per credential (fresh seed each create_credential).
        assert_ne!(a.prf_eval(b"salt-1"), b.prf_eval(b"salt-1"));
    }

    #[test]
    fn prf_survives_vault_record_v2_roundtrip() {
        let cred = create_credential("example.com");
        let before = cred.prf_eval(b"derive-my-site-key");
        let restored = Credential::from_vault_record(&cred.to_vault_record()).unwrap();
        assert_eq!(restored.prf_eval(b"derive-my-site-key"), before);
        // Loose-field reconstruction honestly does NOT preserve the PRF seed.
        let loose = Credential::from_key_bytes(
            &cred.rp_id,
            cred.credential_id,
            &cred.to_key_bytes(),
        )
        .unwrap();
        assert_ne!(loose.prf_eval(b"derive-my-site-key"), before);
    }

    #[test]
    fn counter_is_monotonic_and_survives_a_record_roundtrip() {
        let mut cred = create_credential("example.com");
        assert_eq!(cred.counter(), 0);
        assert_eq!(cred.next_counter(), 1);
        assert_eq!(cred.next_counter(), 2);
        assert_eq!(cred.next_counter(), 3);
        assert_eq!(cred.counter(), 3);

        let mut restored = Credential::from_vault_record(&cred.to_vault_record()).unwrap();
        assert_eq!(restored.counter(), 3);
        // Continues monotonically after the roundtrip — never restarts.
        assert_eq!(restored.next_counter(), 4);
    }

    #[test]
    fn malformed_v2_records_are_rejected() {
        let cred = create_credential("example.com");
        let rec = cred.to_vault_record();
        assert!(Credential::from_vault_record(&rec).is_ok());

        // Wrong version byte (includes the old unversioned v1 layout, whose
        // first byte was the rp_len low byte — pre-release break, re-seal).
        let mut wrong_version = rec.to_vec();
        wrong_version[0] = 0x01;
        assert!(Credential::from_vault_record(&wrong_version).is_err());

        // A genuine v1-layout record (rp_len-first, no version/seed/counter)
        // must be rejected, not mis-parsed.
        let rp = cred.rp_id.as_bytes();
        let mut v1 = Vec::new();
        v1.extend_from_slice(&(rp.len() as u32).to_le_bytes());
        v1.extend_from_slice(rp);
        v1.extend_from_slice(&cred.credential_id);
        v1.extend_from_slice(&cred.to_key_bytes());
        assert!(Credential::from_vault_record(&v1).is_err());

        // Truncated at every prefix length.
        for n in 0..rec.len() {
            assert!(Credential::from_vault_record(&rec[..n]).is_err(), "prefix {n} accepted");
        }
        // Overlong.
        let mut long = rec.to_vec();
        long.push(0);
        assert!(Credential::from_vault_record(&long).is_err());
        // rp_len pointing past the end (and near usize wrap) fails cleanly.
        let mut bad = rec.to_vec();
        bad[1..5].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Credential::from_vault_record(&bad).is_err());
    }

    // ── passphrase-sealed export/import ─────────────────────────────────────
    // Each derive_key call runs Argon2id at the at-rest tier (64 MiB, t = 3),
    // so these tests share exports where possible to keep the suite fast.

    #[test]
    fn sealed_export_roundtrip_preserves_everything() {
        let mut cred = create_credential("bank.example");
        cred.next_counter();
        cred.next_counter();
        cred.next_counter();
        let auth_data = b"auth-data";
        let ch = client_hash(b"challenge");
        let pre_export_sig = cred.sign_assertion(auth_data, &ch);
        let prf_before = cred.prf_eval(b"derive-my-site-key");

        let blob = cred.export_sealed(b"correct horse battery staple").unwrap();
        let restored =
            Credential::import_sealed(&blob, b"correct horse battery staple").unwrap();

        // Identity, key, counter and PRF seed all survive the round trip.
        assert_eq!(restored.rp_id, "bank.example");
        assert_eq!(restored.credential_id, cred.credential_id);
        assert_eq!(restored.public_key(), cred.public_key());
        assert_eq!(restored.counter(), 3);
        assert_eq!(restored.prf_eval(b"derive-my-site-key"), prf_before);
        // The pre-export signature verifies against the imported credential's
        // public key, and a fresh post-import signature verifies too.
        assert!(verify_assertion(&restored.public_key(), auth_data, &ch, &pre_export_sig));
        let post_import_sig = restored.sign_assertion(auth_data, &ch);
        assert!(verify_assertion(&cred.public_key(), auth_data, &ch, &post_import_sig));
    }

    #[test]
    fn sealed_export_rejects_wrong_passphrase_tamper_version_and_truncation() {
        let cred = create_credential("example.com");
        let blob = cred.export_sealed(b"right passphrase").unwrap();

        // (b) Wrong passphrase → Err, no panic. Indistinguishable from tamper
        // by design — both surface as Unseal.
        assert!(matches!(
            Credential::import_sealed(&blob, b"wrong passphrase"),
            Err(KeyError::Unseal)
        ));

        // (c) Tamper: flip one ciphertext byte (past the envelope header and
        // the seal's own header) → the AEAD refuses.
        let mut tampered = blob.to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(matches!(
            Credential::import_sealed(&tampered, b"right passphrase"),
            Err(KeyError::Unseal)
        ));

        // (d) Wrong version byte → structurally invalid, rejected before any
        // KDF work.
        let mut wrong_version = blob.to_vec();
        wrong_version[0] = 0x02;
        assert!(matches!(
            Credential::import_sealed(&wrong_version, b"right passphrase"),
            Err(KeyError::BadExport)
        ));

        // (e) Truncated at every prefix length up to (and including) the salt
        // boundary → Err, never a panic; all fail the structural check.
        for n in 0..=(1 + postern_core::kdf::SALT_LEN) {
            assert!(
                matches!(
                    Credential::import_sealed(&blob[..n], b"right passphrase"),
                    Err(KeyError::BadExport)
                ),
                "prefix {n} accepted"
            );
        }
        // Overlong blob (one byte appended) → the AEAD tag no longer matches.
        let mut long = blob.to_vec();
        long.push(0);
        assert!(Credential::import_sealed(&long, b"right passphrase").is_err());
    }

    #[test]
    fn sealed_exports_differ_per_export_but_import_identically() {
        // (f) Fresh salt (and nonce) per export: same credential + passphrase
        // must still yield different bytes, yet both import to the same key.
        let cred = create_credential("example.com");
        let a = cred.export_sealed(b"pw").unwrap();
        let b = cred.export_sealed(b"pw").unwrap();
        assert_ne!(a.as_slice(), b.as_slice());
        let ia = Credential::import_sealed(&a, b"pw").unwrap();
        let ib = Credential::import_sealed(&b, b"pw").unwrap();
        assert_eq!(ia.public_key(), cred.public_key());
        assert_eq!(ib.public_key(), cred.public_key());
    }
}
