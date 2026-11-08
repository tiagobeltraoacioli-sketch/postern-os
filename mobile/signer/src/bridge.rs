// SPDX-License-Identifier: MIT OR Apache-2.0

//! `PairedSignerChannel` — ride the signer protocol over the REAL paired session.
//!
//! `postern-signer-protocol` is written against its own [`Channel`] trait
//! (send/recv opaque frames) and does not care how they travel. `postern-pairing`
//! provides the real thing: a mutually-authenticated, PQ-hybrid
//! (ML-KEM-1024‖X25519), replay-guarded [`pairing::Channel`] that
//! [`seal_frame`](pairing::Channel::seal_frame)s / [`open_frame`](pairing::Channel::open_frame)s
//! plaintext, plus a [`pairing::Transport`] that carries the sealed bytes.
//!
//! This bridge composes the two: **seal → transport.send** on the way out,
//! **transport.recv → open** on the way in. So a [`SignRequest`] flows over the
//! encrypted channel and every rail of BOTH crates applies — the pairing
//! channel's AEAD + per-direction + monotonic-counter + session binding, AND the
//! protocol's fresh-nonce + counter + session-id replay guard on top.
//!
//! HONEST LIMIT (from both crates): a compromised endpoint (A5) holds the session
//! key and can send anything *within* the channel — which is exactly why every
//! consequential sign still needs on-device WYSIWYS approval upstream. The channel
//! is a secure pipe, not a policy.

use postern_pairing::channel::Frame;
use postern_pairing::{Channel as PairingChannel, Transport};
use postern_signer_protocol::channel::Channel as ProtocolChannel;

/// Errors the bridge can surface, mapped from either underlying crate.
#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    /// The pairing channel failed to seal/open (wrong key, tamper, replay).
    #[error("paired channel error: {0}")]
    Channel(postern_pairing::ChannelError),
    /// The transport failed to move bytes.
    #[error("transport error: {0}")]
    Transport(postern_pairing::TransportError),
}

/// Adapts a live [`pairing::Channel`] + [`pairing::Transport`] into a
/// [`signer_protocol::Channel`]. Give this to
/// [`PhoneApprover`](postern_signer_protocol::PhoneApprover) (phone side) or
/// [`DesktopRequester`](postern_signer_protocol::DesktopRequester) (terminal side).
pub struct PairedSignerChannel<T: Transport> {
    /// The forward-secret, replay-guarded crypto endpoint (seals/opens frames).
    secure: PairingChannel,
    /// The byte carrier (a LAN socket in production; loopback in tests).
    transport: T,
}

impl<T: Transport> PairedSignerChannel<T> {
    /// Compose a signer-protocol channel from a paired `secure` endpoint and its
    /// byte `transport`. Both come out of the §2 pairing ceremony.
    pub fn new(secure: PairingChannel, transport: T) -> Self {
        PairedSignerChannel { secure, transport }
    }

    /// The 16-byte protocol [`SessionId`](postern_signer_protocol::SessionId) to
    /// bind requests to, derived from the paired session's 32-byte id (first 16
    /// bytes). Deterministic on both ends, so the desktop and phone agree.
    pub fn protocol_session_id(&self) -> postern_signer_protocol::SessionId {
        let full = self.secure.session_id();
        let mut id = [0u8; 16];
        id.copy_from_slice(&full[..16]);
        id
    }
}

impl<T: Transport> ProtocolChannel for PairedSignerChannel<T> {
    type Error = BridgeError;

    fn send(&mut self, frame: &[u8]) -> Result<(), Self::Error> {
        // Seal the (public) protocol frame under the paired session key, then hand
        // the sealed bytes to the transport.
        let sealed = self.secure.seal_frame(frame).map_err(BridgeError::Channel)?;
        self.transport
            .send(&sealed.to_bytes())
            .map_err(BridgeError::Transport)
    }

    fn recv(&mut self) -> Result<Vec<u8>, Self::Error> {
        let bytes = self.transport.recv().map_err(BridgeError::Transport)?;
        let frame = Frame::from_bytes(&bytes).map_err(BridgeError::Channel)?;
        // `open_frame` verifies the AEAD AND enforces the monotonic-counter replay
        // guard; the returned plaintext zeroizes on drop, so copy it out.
        let pt = self.secure.open_frame(&frame).map_err(BridgeError::Channel)?;
        Ok(pt.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use postern_pairing::channel::endpoints;
    use postern_pairing::transport::LoopbackPair;
    use zeroize::Zeroizing;

    #[test]
    fn frames_round_trip_over_the_paired_channel() {
        // Two paired endpoints from one agreed session key.
        let key: postern_pairing::hybrid::SessionKey = Zeroizing::new([0x5au8; 32]);
        let (phone_secure, desk_secure) = endpoints(&key);
        let (phone_tx, desk_tx) = LoopbackPair::new();

        let mut phone = PairedSignerChannel::new(phone_secure, phone_tx);
        let mut desk = PairedSignerChannel::new(desk_secure, desk_tx);

        // A protocol frame sent by the phone opens (decrypts + replay-checks) on
        // the desktop end unchanged.
        phone.send(b"a-sign-approval-frame").unwrap();
        assert_eq!(desk.recv().unwrap(), b"a-sign-approval-frame");

        // Both ends derive the same 16-byte protocol session id.
        assert_eq!(phone.protocol_session_id(), desk.protocol_session_id());
    }
}
