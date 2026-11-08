// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Postern Labs
//! The transport seam for the default Megolm path — pre-release, **UNAUDITED**.
//!
//! A [`SecureChannel`](crate::channel::SecureChannel) turns a plaintext into a
//! [`Frame`] (a Megolm-encrypted envelope) and consumes `Frame`s to recover
//! plaintext. **How a `Frame` travels is deliberately separated from how it is
//! encrypted** — the channel never touches sockets, and a transport never
//! touches key material. That seam is this module:
//!
//! - [`Frame`] — the on-wire envelope: a Megolm session id + base64 ciphertext.
//!   It is already E2EE; a transport carries opaque bytes.
//! - [`encode_frame`] / [`FrameDecoder`] — a pure, length-prefixed wire codec
//!   (4-byte big-endian length + JSON), so any byte-stream transport frames
//!   messages unambiguously. Pure functions → fully offline-testable.
//! - [`FrameTransport`] — the trait a transport implements.
//! - [`LoopbackTransport`] — an in-process transport (two ends wired by a
//!   queue) used to prove the whole channel→transport→channel path end-to-end
//!   with no network.
//!
//! The networked transport — routing `Frame`s over **Tor** via `postern-tor` —
//! is [`crate::tor`], behind the off-by-default `tor` feature (arti is heavy;
//! every Tor path in this workspace is feature-gated the same way). It reuses
//! the [`encode_frame`]/[`FrameDecoder`] codec here, so the framing is tested
//! offline in the default build regardless of the feature.
//!
//! ## Honest crypto posture of a `Frame`
//!
//! A `Frame`'s ciphertext is **Megolm (vodozemac)** — **classical** Curve25519,
//! not post-quantum. A transport hides or exposes *metadata*, it does not change
//! that: Tor hides who-talks-to-whom at the network layer; the loopback hides
//! nothing (same process). Neither authenticates the *carrier* — a `Frame`'s
//! integrity/confidentiality is exactly Megolm's, end to end, no more.

use serde::{Deserialize, Serialize};

/// The on-wire envelope produced and consumed by
/// [`SecureChannel`](crate::channel::SecureChannel). Already end-to-end
/// encrypted: `ciphertext` is a base64 Megolm message and `session_id`
/// identifies the sender's Megolm session so the receiver picks the right
/// inbound ratchet. A transport treats both fields as opaque.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Frame {
    /// The sender's Megolm session id (matches an inbound session the receiver
    /// registered out-of-band). Not secret; it is a routing/lookup key.
    pub session_id: String,
    /// Base64 Megolm ciphertext.
    pub ciphertext: String,
}

/// Cap on a single frame's encoded length. A hostile peer must not be able to
/// prefix a multi-gigabyte length and make the decoder buffer forever. 1 MiB is
/// far above any real Megolm message; hitting it is an error, never a silent
/// truncation.
pub const MAX_FRAME_LEN: usize = 1024 * 1024;

/// Errors from the wire codec.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("frame encoding failed: {0}")]
    Encode(String),
    #[error("frame decoding failed: {0}")]
    Decode(String),
    #[error("frame length {0} exceeds the {MAX_FRAME_LEN}-byte cap")]
    TooLarge(usize),
}

/// Encode a [`Frame`] as a length-prefixed record: 4-byte big-endian JSON
/// length, then the JSON. Pure; the inverse is [`FrameDecoder`].
pub fn encode_frame(frame: &Frame) -> Result<Vec<u8>, WireError> {
    let json = serde_json::to_vec(frame).map_err(|e| WireError::Encode(e.to_string()))?;
    if json.len() > MAX_FRAME_LEN {
        return Err(WireError::TooLarge(json.len()));
    }
    let mut out = Vec::with_capacity(4 + json.len());
    out.extend_from_slice(&(json.len() as u32).to_be_bytes());
    out.extend_from_slice(&json);
    Ok(out)
}

/// A streaming decoder: feed it received bytes, pull out whole [`Frame`]s as
/// they complete. Handles partial reads and multiple frames per read — exactly
/// what a byte-stream transport (a Tor `DataStream`) needs. Pure state machine,
/// fully offline-testable.
#[derive(Default)]
pub struct FrameDecoder {
    buf: Vec<u8>,
}

impl FrameDecoder {
    /// A new, empty decoder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append received bytes to the internal buffer.
    pub fn feed(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// `true` iff no partially-read bytes are buffered — used to tell a clean
    /// stream end from a truncated-mid-frame one.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Pop the next complete [`Frame`] if one has fully arrived, else `None`
    /// (need more bytes). An over-cap length prefix is a hard [`WireError`],
    /// so a hostile peer cannot make the buffer grow without bound.
    pub fn next_frame(&mut self) -> Result<Option<Frame>, WireError> {
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;
        if len > MAX_FRAME_LEN {
            return Err(WireError::TooLarge(len));
        }
        if self.buf.len() < 4 + len {
            return Ok(None);
        }
        let json = self.buf[4..4 + len].to_vec();
        self.buf.drain(..4 + len);
        let frame: Frame =
            serde_json::from_slice(&json).map_err(|e| WireError::Decode(e.to_string()))?;
        Ok(Some(frame))
    }
}

/// A carrier for [`Frame`]s. Implementors move already-encrypted envelopes
/// between two channel endpoints; they never see key material or plaintext.
///
/// This trait is intentionally **synchronous** — it covers the in-process and
/// caller-driven cases. The async, networked Tor carrier ([`crate::tor`]) is a
/// separate async type by design (arti is async and heavy, and lives behind the
/// `tor` feature), but it moves the very same [`Frame`]s over the same codec.
pub trait FrameTransport {
    /// Transport-specific error.
    type Error: std::error::Error;
    /// Hand a frame to the transport for delivery to the peer.
    fn send_frame(&mut self, frame: &Frame) -> Result<(), Self::Error>;
    /// Take the next delivered frame, or `None` if none is ready.
    fn recv_frame(&mut self) -> Result<Option<Frame>, Self::Error>;
}

/// Never-constructed error for the infallible [`LoopbackTransport`].
#[derive(Debug, thiserror::Error)]
#[error("loopback transport error")]
pub enum LoopbackError {}

/// An in-process transport: a pair of ends, each sending into the other's
/// queue. No sockets, no serialization on the hot path — used to exercise the
/// full [`SecureChannel`](crate::channel::SecureChannel) round-trip (encrypt →
/// carry → decrypt, persistence and replay included) with zero network.
pub struct LoopbackTransport {
    outgoing: std::sync::mpsc::Sender<Frame>,
    incoming: std::sync::mpsc::Receiver<Frame>,
}

impl LoopbackTransport {
    /// Build two cross-wired ends: a frame sent on one arrives on the other.
    pub fn pair() -> (Self, Self) {
        let (tx_a, rx_b) = std::sync::mpsc::channel();
        let (tx_b, rx_a) = std::sync::mpsc::channel();
        (
            Self { outgoing: tx_a, incoming: rx_a },
            Self { outgoing: tx_b, incoming: rx_b },
        )
    }
}

impl FrameTransport for LoopbackTransport {
    type Error = LoopbackError;

    fn send_frame(&mut self, frame: &Frame) -> Result<(), Self::Error> {
        // The only failure is a dropped peer end; treat that as "delivered to
        // nowhere" rather than an error, matching a lossy real transport.
        let _ = self.outgoing.send(frame.clone());
        Ok(())
    }

    fn recv_frame(&mut self) -> Result<Option<Frame>, Self::Error> {
        Ok(self.incoming.try_recv().ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame() -> Frame {
        Frame { session_id: "abc".into(), ciphertext: "AwgAEiB...".into() }
    }

    #[test]
    fn codec_roundtrips_one_frame() {
        let bytes = encode_frame(&frame()).unwrap();
        let mut dec = FrameDecoder::new();
        dec.feed(&bytes);
        assert_eq!(dec.next_frame().unwrap(), Some(frame()));
        assert_eq!(dec.next_frame().unwrap(), None, "buffer drained");
    }

    #[test]
    fn decoder_handles_partial_and_multiple_frames() {
        let mut all = encode_frame(&frame()).unwrap();
        all.extend(encode_frame(&frame()).unwrap());

        let mut dec = FrameDecoder::new();
        // Feed byte-by-byte: partial reads must never yield a bogus frame.
        for (i, b) in all.iter().enumerate() {
            dec.feed(&[*b]);
            let got = dec.next_frame().unwrap();
            // Frames only complete on their final byte; before that, None.
            if got.is_some() {
                assert_eq!(got, Some(frame()));
                assert!(i >= 3, "cannot complete a frame before its length prefix");
            }
        }
        // Both frames must have come out.
        let mut dec2 = FrameDecoder::new();
        dec2.feed(&all);
        assert_eq!(dec2.next_frame().unwrap(), Some(frame()));
        assert_eq!(dec2.next_frame().unwrap(), Some(frame()));
        assert_eq!(dec2.next_frame().unwrap(), None);
    }

    #[test]
    fn oversized_length_prefix_is_rejected_not_buffered() {
        let mut dec = FrameDecoder::new();
        dec.feed(&(u32::MAX).to_be_bytes());
        match dec.next_frame() {
            Err(WireError::TooLarge(_)) => {}
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[test]
    fn loopback_delivers_frames_between_ends() {
        let (mut a, mut b) = LoopbackTransport::pair();
        assert_eq!(b.recv_frame().unwrap(), None, "nothing sent yet");
        a.send_frame(&frame()).unwrap();
        assert_eq!(b.recv_frame().unwrap(), Some(frame()));
        assert_eq!(b.recv_frame().unwrap(), None, "one frame, one delivery");
    }
}
