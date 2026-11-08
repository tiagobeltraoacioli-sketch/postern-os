// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Postern Labs
//! The default Postern-native Megolm channel — pre-release, **UNAUDITED**.
//!
//! This is the crate's answer to *"Megolm E2EE via vodozemac, real by default"*:
//! a [`SecureChannel`] is a **persistent** Megolm messaging endpoint that works
//! in the **default build** (no cargo feature, no homeserver, no matrix-sdk). It
//! wires the vodozemac Megolm ratchet — the same primitives as
//! [`crate::megolm_reference`] — to two things that reference module never had:
//!
//! 1. a [`crate::transport`] seam, so messages actually move (in-process
//!    loopback by default, or over Tor via the `tor` feature), and
//! 2. a [`crate::store`] seam, so **sessions and replay state survive a
//!    restart, encrypted at rest** — closing the "in-memory only" gap.
//!
//! # Scope, stated honestly (do not overclaim)
//!
//! - **Content crypto is real Megolm** (vodozemac 0.10, version-1 wire format):
//!   forward-ratcheted group encryption, replay-rejecting on decrypt. This is
//!   **classical** Curve25519 — **not** post-quantum. Harvest-now-decrypt-later
//!   applies to captured [`Frame`](crate::transport::Frame) ciphertext.
//! - **Key distribution is OUT-OF-BAND here.** Unlike the `matrix` feature
//!   (where the SDK shares each Megolm room key Olm-encrypted per device), this
//!   native channel hands you [`SecureChannel::outbound_session_key`] and you
//!   move it to peers over an already-secure channel yourself, then they call
//!   [`SecureChannel::register_peer`]. This is the **same honest limit** the
//!   reference module documents — the native path trades the SDK's automatic
//!   Olm key distribution for a lean, homeserver-free, default build. Choose the
//!   `matrix` path when you want federated, SDK-managed key distribution.
//! - **Persistence is encrypted at rest** with a caller-supplied 32-byte
//!   [`PickleKey`] (from the PQ vault in a shipped build). See
//!   [`crate::store`] for the exact guarantee and the rollback caveat.
//!
//! # End to end (default build, no network)
//!
//! ```
//! use postern_messenger::channel::SecureChannel;
//! use postern_messenger::store::MemorySessionStore;
//! use postern_messenger::transport::{FrameTransport, LoopbackTransport};
//!
//! // Alice and Bob each own a persistent channel (32-byte at-rest key from the
//! // PQ vault in a shipped build; a literal here for the example).
//! let mut alice = SecureChannel::create(MemorySessionStore::new(), [7u8; 32]).unwrap();
//! let mut bob = SecureChannel::create(MemorySessionStore::new(), [9u8; 32]).unwrap();
//!
//! // Out-of-band: Alice shares her outbound session key; Bob registers it.
//! let akey = alice.outbound_session_key();
//! bob.register_peer(&akey).unwrap();
//!
//! // A loopback transport stands in for the network.
//! let (mut a_tx, mut b_rx) = LoopbackTransport::pair();
//! let frame = alice.encrypt(b"meet at the drop, 0200").unwrap();
//! a_tx.send_frame(&frame).unwrap();
//!
//! let got = b_rx.recv_frame().unwrap().unwrap();
//! let msg = bob.decrypt(&got).unwrap();
//! assert_eq!(msg.plaintext, b"meet at the drop, 0200");
//! ```

use std::collections::{HashMap, HashSet};

use vodozemac::megolm::{
    GroupSession, GroupSessionPickle, InboundGroupSession, InboundGroupSessionPickle, MegolmMessage,
    SessionConfig, SessionKey,
};
use zeroize::Zeroizing;

use crate::store::{PersistedInbound, PersistedState, PickleKey, SessionStore, StoreError};
use crate::transport::Frame;

/// Errors from a [`SecureChannel`].
#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    #[error("bad session key: {0}")]
    SessionKey(String),
    #[error("bad message: {0}")]
    Message(String),
    #[error("decrypt failed: {0}")]
    Decrypt(String),
    #[error(
        "replayed message (session {session}, index {index} already seen) — a hostile \
         transport may be re-delivering old ciphertext"
    )]
    Replay { session: String, index: u32 },
    #[error(
        "no registered session for frame session_id {0} — the sender's key was never \
         registered (call register_peer with their outbound_session_key first)"
    )]
    UnknownSession(String),
    #[error("persisted state is corrupt or was sealed with a different key: {0}")]
    Pickle(String),
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// A successfully decrypted message: plaintext plus the Megolm ratchet index
/// that produced it (unique per session for an honest sender).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decrypted {
    pub plaintext: Vec<u8>,
    /// The sending session's id — pair with `message_index` for the persistent
    /// replay-dedup key.
    pub session_id: String,
    /// The Megolm ratchet index of this message.
    pub message_index: u32,
}

struct Inbound {
    session: InboundGroupSession,
    seen: HashSet<u32>,
}

/// A persistent, Megolm-encrypted messaging endpoint. Owns **one outbound**
/// session (this identity's own ratchet, encrypting outgoing messages) and
/// **any number of inbound** sessions (one per peer whose key was registered).
/// Every mutation is flushed to the [`SessionStore`], encrypted at rest, so a
/// restart resumes exactly where it left off — including replay protection.
pub struct SecureChannel<S: SessionStore> {
    outbound: GroupSession,
    outbound_id: String,
    inbound: HashMap<String, Inbound>,
    store: S,
    pickle_key: PickleKey,
}

impl<S: SessionStore> SecureChannel<S> {
    /// Create a **fresh** endpoint (new outbound Megolm session) and persist it
    /// immediately. `pickle_key` encrypts all session material at rest.
    ///
    /// Use [`SecureChannel::open`] to reload an existing one, or
    /// [`SecureChannel::open_or_create`] to do the right thing automatically.
    pub fn create(store: S, pickle_key: [u8; 32]) -> Result<Self, ChannelError> {
        // Megolm "version 1" is THE Matrix-interoperable wire format; vodozemac
        // gates the non-interoperable v2 behind an experimental feature we
        // never enable — so a Frame here stays a normal Megolm message.
        let outbound = GroupSession::new(SessionConfig::version_1());
        let outbound_id = outbound.session_id();
        let mut me = Self {
            outbound,
            outbound_id,
            inbound: HashMap::new(),
            store,
            pickle_key: Zeroizing::new(pickle_key),
        };
        me.persist()?;
        Ok(me)
    }

    /// Reload a previously persisted endpoint from `store`, decrypting its
    /// sessions with `pickle_key`. Returns `Ok(None)` if the store is empty.
    /// A wrong key surfaces as [`ChannelError::Pickle`], never a silent
    /// mis-decrypt.
    pub fn open(store: S, pickle_key: [u8; 32]) -> Result<Option<Self>, ChannelError> {
        let Some(state) = store.load()? else { return Ok(None) };
        let key = Zeroizing::new(pickle_key);

        let outbound_pickle = GroupSessionPickle::from_encrypted(&state.outbound, &key)
            .map_err(|e| ChannelError::Pickle(e.to_string()))?;
        let outbound = GroupSession::from_pickle(outbound_pickle);
        let outbound_id = outbound.session_id();

        let mut inbound = HashMap::new();
        for (session_id, p) in state.inbound {
            let pickle = InboundGroupSessionPickle::from_encrypted(&p.session, &key)
                .map_err(|e| ChannelError::Pickle(e.to_string()))?;
            inbound.insert(
                session_id,
                Inbound {
                    session: InboundGroupSession::from_pickle(pickle),
                    seen: p.seen.into_iter().collect(),
                },
            );
        }

        Ok(Some(Self { outbound, outbound_id, inbound, store, pickle_key: key }))
    }

    /// Reload if the store has state, otherwise create fresh. The common entry
    /// point for an app that just wants "my channel, persisted."
    pub fn open_or_create(store: S, pickle_key: [u8; 32]) -> Result<Self, ChannelError> {
        // `open` consumes the store on the None path, so probe first.
        if store.load()?.is_some() {
            // Safe: we just saw Some.
            Ok(Self::open(store, pickle_key)?.expect("state present"))
        } else {
            Self::create(store, pickle_key)
        }
    }

    /// This endpoint's own Megolm session id (the `session_id` peers will see on
    /// the [`Frame`]s it sends).
    pub fn outbound_session_id(&self) -> &str {
        &self.outbound_id
    }

    /// The outbound session key to hand to peers **over an already-secure
    /// channel** so they can decrypt this endpoint's messages
    /// ([`SecureChannel::register_peer`] on their side).
    ///
    /// SECURITY: this key decrypts all of this endpoint's traffic from the
    /// current ratchet point on — treat it like a password. Returned in a
    /// [`Zeroizing`] wrapper; never copy it into a long-lived plain `String` and
    /// never move it over an unencrypted channel. Distribution is the caller's
    /// responsibility here (the honest out-of-band limit; the `matrix` path
    /// automates it over Olm).
    pub fn outbound_session_key(&self) -> Zeroizing<String> {
        Zeroizing::new(self.outbound.session_key().to_base64())
    }

    /// Register a peer's outbound session key (received out-of-band) so this
    /// endpoint can decrypt their [`Frame`]s. Idempotent per session id;
    /// re-registering the same key resets nothing already seen. Persists.
    /// Returns the peer's session id.
    pub fn register_peer(&mut self, session_key_b64: &str) -> Result<String, ChannelError> {
        let key = SessionKey::from_base64(session_key_b64)
            .map_err(|e| ChannelError::SessionKey(e.to_string()))?;
        let session = InboundGroupSession::new(&key, SessionConfig::version_1());
        let id = session.session_id();
        // Don't clobber an existing session's replay watermark.
        self.inbound
            .entry(id.clone())
            .or_insert_with(|| Inbound { session, seen: HashSet::new() });
        self.persist()?;
        Ok(id)
    }

    /// `true` iff a peer session with this id is registered.
    pub fn knows_session(&self, session_id: &str) -> bool {
        self.inbound.contains_key(session_id)
    }

    /// Encrypt `plaintext` with this endpoint's outbound Megolm session, advance
    /// the ratchet, **persist**, and return the [`Frame`] to hand to a
    /// transport. Persisting before returning means a crash right after a send
    /// cannot forget that the index was consumed.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Frame, ChannelError> {
        let ciphertext = self.outbound.encrypt(plaintext).to_base64();
        self.persist()?;
        Ok(Frame { session_id: self.outbound_id.clone(), ciphertext })
    }

    /// Decrypt a received [`Frame`] with the matching registered peer session,
    /// rejecting replays ([`ChannelError::Replay`]) and unknown senders
    /// ([`ChannelError::UnknownSession`]). Updated replay state is **persisted**
    /// before returning, so a replay stays rejected across a restart.
    pub fn decrypt(&mut self, frame: &Frame) -> Result<Decrypted, ChannelError> {
        let msg = MegolmMessage::from_base64(&frame.ciphertext)
            .map_err(|e| ChannelError::Message(e.to_string()))?;

        let inbound = self
            .inbound
            .get_mut(&frame.session_id)
            .ok_or_else(|| ChannelError::UnknownSession(frame.session_id.clone()))?;

        let out = inbound
            .session
            .decrypt(&msg)
            .map_err(|e| ChannelError::Decrypt(e.to_string()))?;

        if !inbound.seen.insert(out.message_index) {
            return Err(ChannelError::Replay {
                session: frame.session_id.clone(),
                index: out.message_index,
            });
        }

        self.persist()?;
        Ok(Decrypted {
            plaintext: out.plaintext,
            session_id: frame.session_id.clone(),
            message_index: out.message_index,
        })
    }

    /// Snapshot every session (encrypted at rest) and hand it to the store.
    fn persist(&mut self) -> Result<(), ChannelError> {
        let outbound = self.outbound.pickle().encrypt(&self.pickle_key);
        let inbound = self
            .inbound
            .iter()
            .map(|(id, inb)| {
                let mut seen: Vec<u32> = inb.seen.iter().copied().collect();
                seen.sort_unstable();
                (
                    id.clone(),
                    PersistedInbound { session: inb.session.pickle().encrypt(&self.pickle_key), seen },
                )
            })
            .collect();
        self.store.save(&PersistedState {
            version: PersistedState::VERSION,
            outbound,
            inbound,
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{FileSessionStore, MemorySessionStore};
    use crate::transport::{FrameTransport, LoopbackTransport};

    const K_A: [u8; 32] = [0x11; 32];
    const K_B: [u8; 32] = [0x22; 32];

    fn wired_pair() -> (SecureChannel<MemorySessionStore>, SecureChannel<MemorySessionStore>) {
        let alice = SecureChannel::create(MemorySessionStore::new(), K_A).unwrap();
        let mut bob = SecureChannel::create(MemorySessionStore::new(), K_B).unwrap();
        let akey = alice.outbound_session_key();
        bob.register_peer(&akey).unwrap();
        (alice, bob)
    }

    #[test]
    fn encrypt_decrypt_roundtrip_over_loopback() {
        let (mut alice, mut bob) = wired_pair();
        let (mut a_tx, mut b_rx) = LoopbackTransport::pair();

        let frame = alice.encrypt(b"the eagle lands at noon").unwrap();
        assert_ne!(frame.ciphertext.as_bytes(), b"the eagle lands at noon");
        a_tx.send_frame(&frame).unwrap();

        let got = b_rx.recv_frame().unwrap().unwrap();
        let msg = bob.decrypt(&got).unwrap();
        assert_eq!(msg.plaintext, b"the eagle lands at noon");
        assert_eq!(msg.message_index, 0);
        assert_eq!(msg.session_id, alice.outbound_session_id());
    }

    #[test]
    fn ratchet_index_advances_per_message() {
        let (mut alice, mut bob) = wired_pair();
        let f0 = alice.encrypt(b"first").unwrap();
        let f1 = alice.encrypt(b"second").unwrap();
        assert_eq!(bob.decrypt(&f0).unwrap().message_index, 0);
        assert_eq!(bob.decrypt(&f1).unwrap().message_index, 1);
    }

    #[test]
    fn replayed_frame_is_rejected() {
        let (mut alice, mut bob) = wired_pair();
        let frame = alice.encrypt(b"send 1 BTC").unwrap();
        bob.decrypt(&frame).unwrap();
        match bob.decrypt(&frame) {
            Err(ChannelError::Replay { index: 0, .. }) => {}
            other => panic!("expected Replay, got {other:?}"),
        }
    }

    #[test]
    fn frame_from_unregistered_sender_is_unknown_session() {
        let mut alice = SecureChannel::create(MemorySessionStore::new(), K_A).unwrap();
        let mut bob = SecureChannel::create(MemorySessionStore::new(), K_B).unwrap();
        // Bob never registered Alice's key.
        let frame = alice.encrypt(b"hi").unwrap();
        match bob.decrypt(&frame) {
            Err(ChannelError::UnknownSession(id)) => {
                assert_eq!(id, alice.outbound_session_id());
            }
            other => panic!("expected UnknownSession, got {other:?}"),
        }
    }

    #[test]
    fn malformed_inputs_error_not_panic() {
        let mut bob = SecureChannel::create(MemorySessionStore::new(), K_B).unwrap();
        assert!(bob.register_peer("not-a-key").is_err());
        let (alice_key, _) = {
            let a = SecureChannel::create(MemorySessionStore::new(), K_A).unwrap();
            (a.outbound_session_key(), a)
        };
        let sid = bob.register_peer(&alice_key).unwrap();
        let bad = Frame { session_id: sid, ciphertext: "not-a-message".into() };
        assert!(bob.decrypt(&bad).is_err());
    }

    // ---- persistence: the whole point of this module ----------------------

    #[test]
    fn outbound_ratchet_survives_reload_shared_memory_store() {
        // A shared MemorySessionStore models the same on-disk state reopened.
        let store = MemorySessionStore::new();
        let bob_key = {
            let mut alice = SecureChannel::create(store.clone(), K_A).unwrap();
            let _f0 = alice.encrypt(b"before restart").unwrap(); // advances + persists
            alice.outbound_session_key()
        }; // alice dropped — simulates process exit

        // Reopen from the same store: the ratchet position must be preserved,
        // so the NEXT message is index 1, not a fresh index 0.
        let mut alice2 = SecureChannel::open_or_create(store, K_A).unwrap();
        let f1 = alice2.encrypt(b"after restart").unwrap();

        let mut bob = SecureChannel::create(MemorySessionStore::new(), K_B).unwrap();
        bob.register_peer(&bob_key).unwrap();
        // Bob can decrypt the post-restart message and it is index 1.
        assert_eq!(bob.decrypt(&f1).unwrap().message_index, 1);
    }

    #[test]
    fn replay_protection_survives_restart_via_file_store() {
        let dir = std::env::temp_dir().join(format!("postern-msg-chan-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bob.json");
        let _ = std::fs::remove_file(&path);

        let mut alice = SecureChannel::create(MemorySessionStore::new(), K_A).unwrap();

        // Megolm order: share the key at the current ratchet index, THEN send —
        // so Bob's inbound session is anchored at index 0 and CAN re-derive the
        // index-0 key. That makes this a strict test of the persisted *seen-set*
        // (not merely the ratchet forgetting old keys) catching the replay.
        let frame;
        {
            let mut bob = SecureChannel::open_or_create(FileSessionStore::new(&path), K_B).unwrap();
            bob.register_peer(&alice.outbound_session_key()).unwrap();
            frame = alice.encrypt(b"withdraw everything").unwrap();
            assert_eq!(bob.decrypt(&frame).unwrap().message_index, 0);
        } // bob dropped — simulates process exit

        // Fresh Bob from the SAME file: the replayed frame must STILL be
        // rejected — replay watermark persisted, not lost on restart.
        let mut bob2 = SecureChannel::open_or_create(FileSessionStore::new(&path), K_B).unwrap();
        match bob2.decrypt(&frame) {
            Err(ChannelError::Replay { index: 0, .. }) => {}
            other => panic!("replay protection did not survive restart: {other:?}"),
        }
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn wrong_pickle_key_fails_to_reopen() {
        let store = MemorySessionStore::new();
        {
            let mut a = SecureChannel::create(store.clone(), K_A).unwrap();
            a.encrypt(b"x").unwrap();
        }
        // Reopening with the wrong at-rest key is a hard error, not a mis-read.
        match SecureChannel::open(store, K_B) {
            Err(ChannelError::Pickle(_)) => {}
            Err(e) => panic!("expected Pickle error on wrong key, got {e:?}"),
            Ok(_) => panic!("wrong at-rest key must not silently reopen the channel"),
        }
    }

    #[test]
    fn registered_peer_survives_reload() {
        let store = MemorySessionStore::new();
        let mut alice = SecureChannel::create(MemorySessionStore::new(), K_A).unwrap();
        let alice_id = alice.outbound_session_id().to_owned();
        {
            let mut bob = SecureChannel::create(store.clone(), K_B).unwrap();
            bob.register_peer(&alice.outbound_session_key()).unwrap();
            assert!(bob.knows_session(&alice_id));
        }
        // Reopened Bob still knows Alice without re-registering.
        let mut bob2 = SecureChannel::open_or_create(store, K_B).unwrap();
        assert!(bob2.knows_session(&alice_id));
        let frame = alice.encrypt(b"still linked").unwrap();
        assert_eq!(bob2.decrypt(&frame).unwrap().plaintext, b"still linked");
    }
}
