//! Encrypted-at-rest local store for SMS threads + the call log.
//!
//! **Threat model (honest):** the carrier already saw every SMS in plaintext
//! and every call's metadata — encryption at rest does NOT undo that. What it
//! DOES protect: the *device copy* — a seized/lost/malware-probed phone yields
//! an AEAD blob, not your message history. Same posture as the rest of the
//! portfolio (postern-vault, Deadbolt's Panic Lock).
//!
//! **Engine:** the one canonical Postern seal from `postern-core` —
//! **XChaCha20-Poly1305** AEAD (`nonce ‖ ciphertext`, tamper-detected) with the
//! 32-byte store key coming from the device vault: TEE-wrapped where hardware
//! allows, else an **Argon2id** passphrase via [`derive_key`]. This is the same
//! AES-GCM-class AEAD pattern Dragoman uses in WebCrypto — one implementation,
//! shared repo-wide, so formats can't drift. No cloud, no sync, no backup
//! unless the user exports explicitly.
//!
//! The store is a simple record log (length-prefixed, no serde) — plenty for a
//! v1 message/call history; pagination/indexing is a later concern and is
//! listed in the spec's "not built yet" ledger.

use crate::types::{CallRecord, SmsMessage};
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("seal failed")]
    Seal,
    #[error("open failed — wrong key or corrupt store")]
    Open,
    #[error("corrupt store data")]
    Corrupt,
    #[error("key derivation failed: {0}")]
    Kdf(String),
}

impl From<postern_core::aead::SealError> for StoreError {
    fn from(e: postern_core::aead::SealError) -> Self {
        use postern_core::aead::SealError::*;
        match e {
            Seal => StoreError::Seal,
            Open => StoreError::Open,
            Corrupt => StoreError::Corrupt,
        }
    }
}

/// Anything that persists telephony history. `SealedTelephonyStore` is the
/// shipped implementation; the trait exists so the UI layer / tests can swap
/// in memory-only or device-specific backends.
pub trait TelephonyStore {
    fn add_sms(&mut self, msg: SmsMessage);
    fn add_call(&mut self, rec: CallRecord);
    fn sms_history(&self) -> &[SmsMessage];
    fn call_log(&self) -> &[CallRecord];
    /// Irreversibly drop all local history (the "panic" path — pairs with
    /// `postern-panic`'s lock-don't-wipe ethos: this wipes only *this app's*
    /// local cache, which the user owns outright).
    fn clear(&mut self);
}

/// The in-memory working set; encrypted to/from disk as one sealed blob.
#[derive(Default)]
pub struct SealedTelephonyStore {
    sms: Vec<SmsMessage>,
    calls: Vec<CallRecord>,
}

const TAG_SMS: u8 = 1;
const TAG_CALL: u8 = 2;

impl SealedTelephonyStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Encrypt the whole store under a 32-byte key. Output = `nonce ‖ AEAD
    /// ciphertext`; the plaintext serialization — including every per-record
    /// intermediate encode buffer — is zeroized before returning.
    pub fn seal(&self, key: &[u8; 32]) -> Result<Vec<u8>, StoreError> {
        let mut plain = Vec::new();
        for m in &self.sms {
            let mut rec = m.encode();
            plain.push(TAG_SMS);
            plain.extend_from_slice(&(rec.len() as u32).to_le_bytes());
            plain.extend_from_slice(&rec);
            rec.zeroize(); // wipe the per-record plaintext copy, not just `plain`
        }
        for c in &self.calls {
            let mut rec = c.encode();
            plain.push(TAG_CALL);
            plain.extend_from_slice(&(rec.len() as u32).to_le_bytes());
            plain.extend_from_slice(&rec);
            rec.zeroize();
        }
        let out = postern_core::aead::seal(key, &plain)?;
        plain.zeroize();
        Ok(out)
    }

    /// Decrypt a sealed store. Wrong key or any tampering ⇒ error (AEAD).
    pub fn open(sealed: &[u8], key: &[u8; 32]) -> Result<Self, StoreError> {
        let mut plain = postern_core::aead::open(key, sealed)?;
        let parsed = Self::parse(&plain);
        plain.zeroize();
        parsed
    }

    fn parse(plain: &[u8]) -> Result<Self, StoreError> {
        let mut store = Self::new();
        let mut i = 0usize;
        while i < plain.len() {
            if i + 5 > plain.len() {
                return Err(StoreError::Corrupt);
            }
            let tag = plain[i];
            let len = u32::from_le_bytes(plain[i + 1..i + 5].try_into().unwrap()) as usize;
            i += 5;
            if i + len > plain.len() {
                return Err(StoreError::Corrupt);
            }
            let rec = &plain[i..i + len];
            match tag {
                TAG_SMS => store.sms.push(SmsMessage::decode(rec).ok_or(StoreError::Corrupt)?),
                TAG_CALL => store.calls.push(CallRecord::decode(rec).ok_or(StoreError::Corrupt)?),
                _ => return Err(StoreError::Corrupt),
            }
            i += len;
        }
        Ok(store)
    }
}

impl TelephonyStore for SealedTelephonyStore {
    fn add_sms(&mut self, msg: SmsMessage) {
        self.sms.push(msg);
    }
    fn add_call(&mut self, rec: CallRecord) {
        self.calls.push(rec);
    }
    fn sms_history(&self) -> &[SmsMessage] {
        &self.sms
    }
    fn call_log(&self) -> &[CallRecord] {
        &self.calls
    }
    fn clear(&mut self) {
        // SmsMessage zeroizes number/body/timestamp on drop; CallRecord
        // zeroizes number/start/duration on drop.
        self.sms.clear();
        self.calls.clear();
    }
}

/// Derive the 32-byte store key from a passphrase with **Argon2id**
/// (memory-hard). On TEE-capable devices prefer a vault-wrapped random key;
/// this is the portable fallback. `salt` (≥ 8 bytes) is stored beside the blob.
/// The returned key is wrapped in [`Zeroizing`] so it is wiped from RAM on
/// drop; it derefs to `[u8; 32]` wherever a key is expected (`&key`).
pub fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, StoreError> {
    postern_core::kdf::derive_key(passphrase, salt).map_err(|e| StoreError::Kdf(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{CallOutcome, Direction, SmsState};

    fn sample() -> SealedTelephonyStore {
        let mut s = SealedTelephonyStore::new();
        s.add_sms(SmsMessage {
            number: "+15551234567".into(),
            body: "the sealed blob must never leak this".into(),
            direction: Direction::Incoming,
            state: SmsState::Received,
            timestamp: Some("2026-07-09T10:00:00+00:00".into()),
        });
        s.add_call(CallRecord {
            number: "+15559876543".into(),
            direction: Direction::Outgoing,
            outcome: CallOutcome::Completed,
            started_at: 1_780_000_000,
            duration_secs: 212,
        });
        s
    }

    #[test]
    fn seal_open_roundtrip() {
        let key = [42u8; 32];
        let sealed = sample().seal(&key).unwrap();
        let opened = SealedTelephonyStore::open(&sealed, &key).unwrap();
        assert_eq!(opened.sms_history().len(), 1);
        assert_eq!(opened.sms_history()[0].body, "the sealed blob must never leak this");
        assert_eq!(opened.call_log().len(), 1);
        assert_eq!(opened.call_log()[0].duration_secs, 212);
    }

    #[test]
    fn ciphertext_hides_message_body_and_number() {
        let sealed = sample().seal(&[7u8; 32]).unwrap();
        let needle = b"the sealed blob must never leak this";
        assert!(!sealed.windows(needle.len()).any(|w| w == needle));
        assert!(!sealed.windows(12).any(|w| w == b"+15551234567"));
    }

    #[test]
    fn wrong_key_and_tamper_are_rejected() {
        let sealed = sample().seal(&[1u8; 32]).unwrap();
        assert!(SealedTelephonyStore::open(&sealed, &[2u8; 32]).is_err());
        let mut bad = sealed.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0x80;
        assert!(SealedTelephonyStore::open(&bad, &[1u8; 32]).is_err());
    }

    #[test]
    fn argon2_key_derivation_is_deterministic() {
        let a = derive_key(b"passphrase", b"telephony-salt16").unwrap();
        let b = derive_key(b"passphrase", b"telephony-salt16").unwrap();
        assert_eq!(*a, *b);
        assert_ne!(*a, *derive_key(b"other", b"telephony-salt16").unwrap());
    }

    #[test]
    fn clear_empties_history() {
        let mut s = sample();
        s.clear();
        assert!(s.sms_history().is_empty());
        assert!(s.call_log().is_empty());
    }
}
