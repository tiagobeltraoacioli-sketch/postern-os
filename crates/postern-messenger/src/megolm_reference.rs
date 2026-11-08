//! LEGACY / REFERENCE — the original hand-rolled Megolm core. **Not the live
//! E2EE path.**
//!
//! Postern Messenger's live E2EE is owned by **matrix-rust-sdk** (this crate's
//! `matrix` feature, [`crate::matrix`]): the SDK runs Olm + Megolm via
//! `vodozemac` internally *and* does the part this module never had —
//! **Olm-encrypted per-device room-key distribution**, device tracking, and
//! session management. Decision record: docs/specs/POSTERN-MESSAGING-INTEROP.md
//! §10 Phase 1 ("one crypto stack").
//!
//! This module is kept as a **reference implementation** of the bare Megolm
//! ratchet (same `vodozemac` primitives the SDK uses) because it is small,
//! auditable, and its tests document ratchet behaviour — roundtrip, index
//! advance, replay rejection. It is NOT wired to any transport, it must NOT
//! be composed with the `matrix` module (double-encrypting Megolm inside
//! Megolm buys nothing and breaks interop with other Matrix clients), and no
//! new callers should adopt it.
//!
//! Honest limits of this reference core (unchanged):
//! - **Session-key distribution is NOT implemented here**: it exports/imports
//!   the base64 session key and moving it safely is the caller's problem.
//!   (The `matrix` module has no such gap — the SDK shares keys over Olm.)
//! - **Replay**: rejects a repeated `message_index` *within one [`Receiver`]*;
//!   callers must persist `(session_id, message_index)` for cross-restart
//!   protection.
//! - **Megolm is classical** (Curve25519), not post-quantum.

use std::collections::HashSet;

use vodozemac::megolm::{
    GroupSession, InboundGroupSession, MegolmMessage, SessionConfig, SessionKey,
};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum MsgError {
    #[error("bad session key: {0}")]
    SessionKey(String),
    #[error("bad message: {0}")]
    Message(String),
    #[error("decrypt failed: {0}")]
    Decrypt(String),
    #[error("replayed message (index {0} already seen) — a malicious homeserver may be re-delivering old ciphertext")]
    Replay(u32),
}

/// A sender's Megolm group session — encrypts a room's outgoing messages. The
/// session key must be shared out-of-band; this reference module provides NO
/// distribution channel (the live path, [`crate::matrix`], lets the SDK share
/// it Olm-encrypted per device). The ratchet moves forward so a leaked key
/// can't read past traffic.
pub struct Sender {
    inner: GroupSession,
}

impl Default for Sender {
    fn default() -> Self {
        Self::new()
    }
}

impl Sender {
    pub fn new() -> Self {
        // Megolm "version 1" is THE Matrix wire format (what every federated
        // client speaks); vodozemac 0.10 gates the non-interoperable v2
        // variant behind an experimental feature we do not enable.
        Self { inner: GroupSession::new(SessionConfig::version_1()) }
    }

    /// The current session key to distribute to recipients (base64).
    ///
    /// SECURITY: this key decrypts all room traffic from this ratchet point on
    /// — treat it like a password. It is returned in a [`Zeroizing`] wrapper so
    /// the buffer is wiped when dropped; don't copy it into long-lived plain
    /// `String`s, and only move it over an already-encrypted channel.
    pub fn session_key(&self) -> Zeroizing<String> {
        Zeroizing::new(self.inner.session_key().to_base64())
    }

    /// Encrypt a room message; returns the base64 Megolm ciphertext.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> String {
        self.inner.encrypt(plaintext).to_base64()
    }
}

/// A successfully decrypted Megolm message: the plaintext plus the ratchet
/// `message_index` used to detect replays. Callers MUST treat
/// `(session_id, message_index)` as a uniqueness key in persistent storage.
pub struct Decrypted {
    pub plaintext: Vec<u8>,
    /// The Megolm ratchet index of this message. Unique per session for an
    /// honest sender; a repeat means the homeserver replayed old ciphertext.
    pub message_index: u32,
}

/// A receiver's inbound Megolm session — decrypts a sender's room messages and
/// rejects replayed ones ([`MsgError::Replay`]).
pub struct Receiver {
    inner: InboundGroupSession,
    /// Message indices already decrypted by THIS receiver instance. In-memory
    /// only — apps must additionally persist `(session_id, message_index)` to
    /// keep replay protection across restarts.
    seen: HashSet<u32>,
}

impl Receiver {
    /// Build from a base64 session key received out-of-band from the sender.
    pub fn from_session_key(key_b64: &str) -> Result<Self, MsgError> {
        let key = SessionKey::from_base64(key_b64).map_err(|e| MsgError::SessionKey(e.to_string()))?;
        Ok(Self {
            inner: InboundGroupSession::new(&key, SessionConfig::version_1()),
            seen: HashSet::new(),
        })
    }

    /// The session id — pair it with [`Decrypted::message_index`] for the
    /// persistent replay-dedup key.
    pub fn session_id(&self) -> String {
        self.inner.session_id()
    }

    /// Decrypt a base64 Megolm ciphertext.
    ///
    /// Returns the plaintext AND the ratchet `message_index`; a
    /// `message_index` this receiver has already decrypted is rejected as
    /// [`MsgError::Replay`] (a malicious homeserver re-delivering old
    /// ciphertext — e.g. a stale "send funds" message — must not surface as
    /// fresh). The in-memory check covers this process's lifetime; persist
    /// `(session_id, message_index)` for cross-restart protection.
    pub fn decrypt(&mut self, ciphertext_b64: &str) -> Result<Decrypted, MsgError> {
        let msg = MegolmMessage::from_base64(ciphertext_b64).map_err(|e| MsgError::Message(e.to_string()))?;
        let out = self.inner.decrypt(&msg).map_err(|e| MsgError::Decrypt(e.to_string()))?;
        if !self.seen.insert(out.message_index) {
            return Err(MsgError::Replay(out.message_index));
        }
        Ok(Decrypted { plaintext: out.plaintext, message_index: out.message_index })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn megolm_roundtrip_encrypts_and_decrypts() {
        let mut sender = Sender::new();
        let key = sender.session_key();
        let ct = sender.encrypt(b"private message over Megolm");
        assert_ne!(ct.as_bytes(), b"private message over Megolm");

        let mut receiver = Receiver::from_session_key(&key).unwrap();
        let out = receiver.decrypt(&ct).unwrap();
        assert_eq!(out.plaintext, b"private message over Megolm");
        assert_eq!(out.message_index, 0);
    }

    #[test]
    fn message_index_advances_per_message() {
        let mut sender = Sender::new();
        let key = sender.session_key();
        let ct0 = sender.encrypt(b"first");
        let ct1 = sender.encrypt(b"second");
        let mut receiver = Receiver::from_session_key(&key).unwrap();
        assert_eq!(receiver.decrypt(&ct0).unwrap().message_index, 0);
        assert_eq!(receiver.decrypt(&ct1).unwrap().message_index, 1);
    }

    #[test]
    fn replayed_ciphertext_is_rejected() {
        let mut sender = Sender::new();
        let key = sender.session_key();
        let ct = sender.encrypt(b"send 1 BTC");
        let mut receiver = Receiver::from_session_key(&key).unwrap();
        receiver.decrypt(&ct).unwrap();
        // The homeserver re-delivers the same ciphertext: hard error, not a
        // second fresh-looking plaintext.
        match receiver.decrypt(&ct) {
            Err(MsgError::Replay(0)) => {}
            Err(e) => panic!("expected Replay(0), got error {e:?}"),
            Ok(_) => panic!("replayed ciphertext decrypted as fresh"),
        }
    }

    #[test]
    fn replay_of_older_index_is_rejected_after_later_messages() {
        let mut sender = Sender::new();
        let key = sender.session_key();
        let ct0 = sender.encrypt(b"old");
        let ct1 = sender.encrypt(b"new");
        let mut receiver = Receiver::from_session_key(&key).unwrap();
        receiver.decrypt(&ct0).unwrap();
        receiver.decrypt(&ct1).unwrap();
        assert!(matches!(receiver.decrypt(&ct0), Err(MsgError::Replay(0))));
    }

    #[test]
    fn wrong_session_key_cannot_decrypt() {
        let mut sender = Sender::new();
        let ct = sender.encrypt(b"secret");
        // A receiver built from a DIFFERENT session's key can't read it.
        let other = Sender::new();
        let mut wrong = Receiver::from_session_key(&other.session_key()).unwrap();
        assert!(wrong.decrypt(&ct).is_err());
    }

    #[test]
    fn malformed_inputs_error_not_panic() {
        assert!(Receiver::from_session_key("not-a-key").is_err());
        let mut r = Receiver::from_session_key(&Sender::new().session_key()).unwrap();
        assert!(r.decrypt("not-a-message").is_err());
    }
}
