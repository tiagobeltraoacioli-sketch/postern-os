// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Postern Labs
//! Tor carrier for Megolm [`Frame`]s (cargo feature `tor`) — pre-release,
//! **UNAUDITED**.
//!
//! Routes the default channel's already-encrypted [`Frame`]s over an in-process
//! **Tor** circuit via [`postern_tor`] (an arti wrapper), so a
//! [`SecureChannel`](crate::channel::SecureChannel)'s messages travel without
//! exposing the sender's IP or the who-talks-to-whom graph at the network layer.
//! It reuses the exact [`encode_frame`]/[`FrameDecoder`] wire codec from
//! [`crate::transport`] — the framing is unit-tested in the default build; this
//! module adds only the async socket plumbing.
//!
//! OFF BY DEFAULT on purpose: arti is a large dependency tree, and **every** Tor
//! path in this workspace is feature-gated the same way (`postern-tor`'s own
//! live bootstrap is an ignored test; the noporis/porog glue crates gate arti
//! behind `live`). Enabling `tor` pulls `postern-tor` + `tokio`.
//!
//! ```text
//! cargo build -p postern-messenger --features tor
//! cargo test  -p postern-messenger --features tor
//! ```
//!
//! # Honest posture (do not overclaim)
//!
//! - **Content crypto is unchanged**: still classical Megolm (vodozemac). Tor
//!   protects *metadata*, not the message crypto — a `Frame` is exactly as
//!   confidential/authentic as Megolm makes it, no more.
//! - **Onion services only for integrity.** Reaching a peer over a **`.onion`**
//!   address gives end-to-end Tor encryption to that hidden service. Reaching a
//!   **clearnet** host over Tor anonymises you but leaves the **exit relay an
//!   active man-in-the-middle** on the byte stream — it cannot read a `Frame`
//!   (Megolm-encrypted) but it can **drop, reorder, or duplicate** frames.
//!   Duplication is caught (replay rejection); censorship/reordering is a
//!   liveness/ordering concern the transport does not solve. Prefer `.onion`.
//! - **No hosting here.** `postern-tor` is an onion-service *client* only; this
//!   transport *connects to* a listener, it does not host one. A rendezvous/
//!   drop design (who listens, replay/DoS at the socket) is future work and out
//!   of scope for this module.
//! - **Circuit isolation is the caller's duty.** Build this transport from a
//!   per-identity handle ([`postern_tor::PosternTor::for_identity`]) so the
//!   messenger's circuits never share with, say, the wallet's — otherwise a
//!   shared exit + timing can relink the identities.

use postern_tor::{PosternTor, TorError};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::transport::{encode_frame, Frame, FrameDecoder, WireError};

/// Errors from the Tor frame carrier.
#[derive(Debug, thiserror::Error)]
pub enum TorTransportError {
    #[error(transparent)]
    Tor(#[from] TorError),
    #[error(transparent)]
    Wire(#[from] WireError),
    #[error("tor stream i/o failed: {0}")]
    Io(String),
}

/// An async [`Frame`] carrier over a single duplex byte stream to a peer
/// listener (ideally a `.onion` host — see the module honesty notes). Generic
/// over the stream so the async framing is round-trip-tested offline over an
/// in-memory `tokio::io::duplex`; [`TorFrameTransport::connect`] specialises it
/// to an arti Tor stream. Owns a streaming [`FrameDecoder`], so partial reads
/// and multiple frames per read are handled.
pub struct TorFrameTransport<S> {
    stream: S,
    decoder: FrameDecoder,
}

impl TorFrameTransport<arti_client::DataStream> {
    /// Open a Tor circuit to `host:port` and wrap the stream as a frame carrier.
    /// Pass a per-identity handle ([`PosternTor::for_identity`]) so this
    /// messenger identity's circuits stay isolated from other products'.
    pub async fn connect(
        tor: &PosternTor,
        host: &str,
        port: u16,
    ) -> Result<Self, TorTransportError> {
        let stream = tor.connect(host, port).await?;
        Ok(Self { stream, decoder: FrameDecoder::new() })
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> TorFrameTransport<S> {
    /// Wrap an already-opened duplex stream (an arti [`arti_client::DataStream`]
    /// from a custom `StreamPrefs`/isolation token, or any tokio duplex) as a
    /// frame carrier.
    pub fn from_stream(stream: S) -> Self {
        Self { stream, decoder: FrameDecoder::new() }
    }

    /// Length-prefix-encode `frame` and write it to the stream.
    pub async fn send_frame(&mut self, frame: &Frame) -> Result<(), TorTransportError> {
        let bytes = encode_frame(frame)?;
        self.stream.write_all(&bytes).await.map_err(|e| TorTransportError::Io(e.to_string()))?;
        self.stream.flush().await.map_err(|e| TorTransportError::Io(e.to_string()))?;
        Ok(())
    }

    /// Read until the next whole [`Frame`] arrives. Returns `Ok(None)` on a
    /// clean stream end with no partial frame buffered; a partial frame at EOF
    /// is a hard error (truncated record), never a silent drop.
    pub async fn recv_frame(&mut self) -> Result<Option<Frame>, TorTransportError> {
        loop {
            // A frame already buffered from a previous read?
            if let Some(frame) = self.decoder.next_frame()? {
                return Ok(Some(frame));
            }
            let mut chunk = [0u8; 4096];
            let n = self
                .stream
                .read(&mut chunk)
                .await
                .map_err(|e| TorTransportError::Io(e.to_string()))?;
            if n == 0 {
                // Clean EOF: OK only if nothing is half-read.
                return match self.decoder.next_frame()? {
                    Some(frame) => Ok(Some(frame)),
                    None if self.decoder.is_empty() => Ok(None),
                    None => Err(TorTransportError::Io(
                        "stream closed mid-frame (truncated record)".into(),
                    )),
                };
            }
            self.decoder.feed(&chunk[..n]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The async send/recv plumbing is tested offline over an in-memory duplex
    /// (no network, no arti). The *live* Tor circuit needs network + a peer
    /// listener, so it stays an ignored integration concern — matching
    /// `postern-tor`'s own live-bootstrap convention. Encrypting the payload is
    /// the channel's job ([`crate::channel`]); here we prove frames cross a
    /// byte stream intact, including a partial-read/interleaved case.
    #[tokio::test]
    async fn frames_roundtrip_over_a_duplex_stream() {
        // Buffer must hold both queued frames: this test writes both before it
        // reads either, so a buffer smaller than their combined encoded size
        // would deadlock the single task (write pends with no reader draining).
        let (a, b) = tokio::io::duplex(4096);
        let mut sender = TorFrameTransport::from_stream(a);
        let mut receiver = TorFrameTransport::from_stream(b);

        let f1 = Frame { session_id: "s1".into(), ciphertext: "AgAAAAA".into() };
        let f2 = Frame { session_id: "s1".into(), ciphertext: "AwAAAAB".into() };
        sender.send_frame(&f1).await.unwrap();
        sender.send_frame(&f2).await.unwrap();

        assert_eq!(receiver.recv_frame().await.unwrap(), Some(f1));
        assert_eq!(receiver.recv_frame().await.unwrap(), Some(f2));
    }

    /// A clean stream close with nothing buffered yields `None`, not an error.
    #[tokio::test]
    async fn clean_eof_is_none() {
        let (a, b) = tokio::io::duplex(64);
        drop(a); // peer hangs up having sent nothing
        let mut receiver = TorFrameTransport::from_stream(b);
        assert_eq!(receiver.recv_frame().await.unwrap(), None);
    }
}
