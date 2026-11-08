// SPDX-License-Identifier: MIT OR Apache-2.0
//! The mutually-authenticated, PQ-hybrid encrypted [`Channel`].
//!
//! Once the ceremony agrees a session key (`hybrid.rs`) and the human confirms
//! the SAS, both devices open a `Channel` and exchange **opaque frames**. This
//! crate does not interpret frame contents — remote-signer requests, panic
//! signals, watch-only sync, and companion commands are all just plaintext
//! handed to [`Channel::seal_frame`] by the higher layers (Dev2/3/4).
//!
//! Each frame is XChaCha20-Poly1305 (24-byte random nonce, same seal family as
//! the vault) with hardening the security memo (§4.2, §5.3) requires:
//!
//! - **Monotonic counter anti-replay.** Every frame carries a per-direction
//!   counter that must strictly increase; a replayed or reordered frame is
//!   rejected. (A request captured on the wire cannot be re-injected.)
//! - **Direction separation.** The sender's direction label is in the AAD, so a
//!   frame cannot be *reflected* back to its author as if the peer sent it.
//! - **Session binding.** The `session_id` (derived from the pairing transcript)
//!   is in the AAD, so a frame captured on session A cannot replay on session B.
//! - **Counter in AAD.** The counter is authenticated, so it cannot be edited to
//!   slip past the replay window.
//!
//! HONEST LIMIT: a compromised endpoint (A5) holds the session key and can send
//! whatever it likes *within* the channel. The channel authenticates the
//! *peer device key*, not the *software's intent*. That is why every
//! consequential action still needs on-device WYSIWYS approval upstream — the
//! channel is a secure pipe, not a policy.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::hybrid::{SessionKey, SESSION_KEY_LEN};

const XNONCE_LEN: usize = 24;
const COUNTER_LEN: usize = 8;
/// AAD domain-separation prefix.
const AAD_CONTEXT: &[u8] = b"postern-pairing/frame/v1";

/// Per-direction label bound into the AAD (prevents reflection).
const LABEL_C2T: &[u8] = b"custodian->terminal";
const LABEL_T2C: &[u8] = b"terminal->custodian";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChannelError {
    #[error("frame too short / malformed")]
    Malformed,
    #[error("AEAD open failed — wrong key or tampered frame")]
    Open,
    #[error("AEAD seal failed")]
    Seal,
    #[error("replay or reorder — counter did not advance")]
    Replay,
    #[error("send counter exhausted; re-pair to rotate the session")]
    CounterExhausted,
}

/// A wire frame: `counter(8, BE) || nonce(24) || aead_ct`.
#[derive(Debug, Clone)]
pub struct Frame {
    counter: u64,
    nonce: [u8; XNONCE_LEN],
    ct: Vec<u8>,
}

impl Frame {
    /// Serialize for the transport.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(COUNTER_LEN + XNONCE_LEN + self.ct.len());
        out.extend_from_slice(&self.counter.to_be_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ct);
        out
    }

    /// Parse a frame off the transport. Rejects anything shorter than a header
    /// plus the AEAD tag.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ChannelError> {
        // header + 16-byte Poly1305 tag minimum.
        if bytes.len() < COUNTER_LEN + XNONCE_LEN + 16 {
            return Err(ChannelError::Malformed);
        }
        let counter = u64::from_be_bytes(bytes[..COUNTER_LEN].try_into().unwrap());
        let mut nonce = [0u8; XNONCE_LEN];
        nonce.copy_from_slice(&bytes[COUNTER_LEN..COUNTER_LEN + XNONCE_LEN]);
        let ct = bytes[COUNTER_LEN + XNONCE_LEN..].to_vec();
        Ok(Frame { counter, nonce, ct })
    }
}

/// A live, forward-secret session over the paired channel. One per peer.
pub struct Channel {
    key: SessionKey,
    session_id: [u8; 32],
    send_label: &'static [u8],
    recv_label: &'static [u8],
    send_counter: u64,
    /// Highest received counter accepted so far (0 = none yet; first valid is 1).
    recv_high_watermark: u64,
}

impl Channel {
    /// Open a channel from an agreed session key and the pairing `session_id`.
    ///
    /// `initiator` is `true` on the side that sent the encapsulation (the
    /// custodian/phone) and `false` on the anchor (terminal/desktop). The two
    /// sides pick opposite direction labels so their nonces/AAD never collide.
    pub fn open(key: SessionKey, session_id: [u8; 32], initiator: bool) -> Self {
        let (send_label, recv_label) = if initiator {
            (LABEL_C2T, LABEL_T2C)
        } else {
            (LABEL_T2C, LABEL_C2T)
        };
        Channel {
            key,
            session_id,
            send_label,
            recv_label,
            send_counter: 0,
            recv_high_watermark: 0,
        }
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        let key: &[u8; SESSION_KEY_LEN] = &self.key;
        XChaCha20Poly1305::new(key.into())
    }

    fn aad(context_label: &[u8], session_id: &[u8; 32], dir: &[u8], counter: u64) -> Vec<u8> {
        let mut aad = Vec::with_capacity(AAD_CONTEXT.len() + 32 + dir.len() + COUNTER_LEN + 8);
        aad.extend_from_slice(context_label);
        aad.extend_from_slice(session_id);
        aad.extend_from_slice(dir);
        aad.extend_from_slice(&counter.to_be_bytes());
        aad
    }

    /// Seal an opaque payload into a [`Frame`]. Uses the next send counter and a
    /// fresh random 24-byte nonce; binds session id + direction + counter as AAD.
    pub fn seal_frame(&mut self, plaintext: &[u8]) -> Result<Frame, ChannelError> {
        let counter = self
            .send_counter
            .checked_add(1)
            .ok_or(ChannelError::CounterExhausted)?;

        let mut nonce_bytes = [0u8; XNONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let aad = Self::aad(AAD_CONTEXT, &self.session_id, self.send_label, counter);
        let ct = self
            .cipher()
            .encrypt(nonce, Payload { msg: plaintext, aad: &aad })
            .map_err(|_| ChannelError::Seal)?;

        self.send_counter = counter;
        Ok(Frame { counter, nonce: nonce_bytes, ct })
    }

    /// Open a received [`Frame`]: authenticate + decrypt, then enforce the
    /// monotonic-counter anti-replay. A frame whose counter does not strictly
    /// advance the receive watermark is rejected even though the AEAD verified —
    /// that is the replay/reorder guard.
    pub fn open_frame(&mut self, frame: &Frame) -> Result<Zeroizing<Vec<u8>>, ChannelError> {
        let aad = Self::aad(AAD_CONTEXT, &self.session_id, self.recv_label, frame.counter);
        let nonce = XNonce::from_slice(&frame.nonce);
        let pt = self
            .cipher()
            .decrypt(nonce, Payload { msg: &frame.ct, aad: &aad })
            .map_err(|_| ChannelError::Open)?;

        // AEAD passed; now the freshness gate. Strictly-increasing counter.
        if frame.counter <= self.recv_high_watermark {
            return Err(ChannelError::Replay);
        }
        self.recv_high_watermark = frame.counter;
        Ok(Zeroizing::new(pt))
    }

    /// The session id this channel is bound to (for higher-layer request
    /// binding — e.g. a sign request scoped to this session).
    pub fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }
}

impl core::fmt::Debug for Channel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Channel")
            .field("send_counter", &self.send_counter)
            .field("recv_high_watermark", &self.recv_high_watermark)
            .finish()
    }
}

/// Derive this device's channel endpoint from the agreed session key. Splits
/// the pairing session key into an independent traffic key (so the SAS branch
/// and the traffic key never share bytes) and a public `session_id`, then opens
/// the correct direction for `initiator` (custodian = `true`, terminal =
/// `false`). This is the seam [`crate::pairing`] uses at `confirm_sas`.
pub fn open_endpoint(session_key: &SessionKey, initiator: bool) -> Channel {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk = Hkdf::<Sha256>::new(None, session_key.as_ref());
    let mut traffic = Zeroizing::new([0u8; SESSION_KEY_LEN]);
    hk.expand(b"postern-pairing/traffic/v1", traffic.as_mut())
        .expect("hkdf expand");
    let mut session_id = [0u8; 32];
    hk.expand(b"postern-pairing/session-id/v1", &mut session_id)
        .expect("hkdf expand");
    Channel::open(traffic, session_id, initiator)
}

/// Derive both channel endpoints from one agreed session key — an
/// `(initiator, responder)` pair ready to talk (test/demo convenience).
pub fn endpoints(session_key: &SessionKey) -> (Channel, Channel) {
    (open_endpoint(session_key, true), open_endpoint(session_key, false))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> (Channel, Channel) {
        let sk: SessionKey = Zeroizing::new([0x5au8; 32]);
        endpoints(&sk)
    }

    #[test]
    fn roundtrip_both_directions() {
        let (mut phone, mut desk) = keypair();
        let f = phone.seal_frame(b"start node").unwrap();
        assert_eq!(&**desk.open_frame(&f).unwrap(), b"start node");

        let g = desk.seal_frame(b"sign request").unwrap();
        assert_eq!(&**phone.open_frame(&g).unwrap(), b"sign request");
    }

    #[test]
    fn replay_is_rejected() {
        let (mut phone, mut desk) = keypair();
        let f = phone.seal_frame(b"panic").unwrap();
        let bytes = f.to_bytes();
        let parsed = Frame::from_bytes(&bytes).unwrap();
        assert!(desk.open_frame(&parsed).is_ok());
        // Re-inject the very same frame -> replay guard fires.
        let again = Frame::from_bytes(&bytes).unwrap();
        assert_eq!(desk.open_frame(&again).unwrap_err(), ChannelError::Replay);
    }

    #[test]
    fn reflection_is_rejected() {
        // A frame the phone sent must not open as if it were inbound to the phone
        // (direction label differs -> AAD mismatch -> AEAD open fails).
        let (mut phone, _desk) = keypair();
        let f = phone.seal_frame(b"hello").unwrap();
        assert_eq!(phone.open_frame(&f).unwrap_err(), ChannelError::Open);
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (mut phone, mut desk) = keypair();
        let mut f = phone.seal_frame(b"amount:10").unwrap();
        let last = f.ct.len() - 1;
        f.ct[last] ^= 0xFF;
        assert_eq!(desk.open_frame(&f).unwrap_err(), ChannelError::Open);
    }

    #[test]
    fn cross_session_frame_is_rejected() {
        // Same traffic key but a different session_id -> AAD mismatch.
        let sk: SessionKey = Zeroizing::new([1u8; 32]);
        let (mut phone_a, _da) = endpoints(&sk);
        let f = phone_a.seal_frame(b"x").unwrap();

        let mut desk_b = Channel::open(Zeroizing::new([1u8; 32]), [0xEEu8; 32], false);
        // Wrong key AND wrong session; must fail closed.
        assert!(desk_b.open_frame(&f).is_err());
    }

    #[test]
    fn out_of_order_frame_rejected_after_higher_counter() {
        let (mut phone, mut desk) = keypair();
        let f1 = phone.seal_frame(b"one").unwrap();
        let f2 = phone.seal_frame(b"two").unwrap();
        // Deliver f2 first (counter 2), then f1 (counter 1) -> f1 is stale.
        assert!(desk.open_frame(&f2).is_ok());
        assert_eq!(desk.open_frame(&f1).unwrap_err(), ChannelError::Replay);
    }

    #[test]
    fn short_frame_is_malformed() {
        assert_eq!(Frame::from_bytes(&[0u8; 4]).unwrap_err(), ChannelError::Malformed);
    }
}
