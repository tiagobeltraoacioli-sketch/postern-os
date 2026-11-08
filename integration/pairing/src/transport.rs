// SPDX-License-Identifier: MIT OR Apache-2.0
//! The transport seam — LAN-first, but stubbed behind a trait so the crate
//! compiles and tests with **no sockets and no network**.
//!
//! Every candidate transport (LAN/mDNS today; Tor-onion and BLE explicitly OUT
//! of v1) is an **unauthenticated bearer channel** — it carries bytes and
//! provides *zero* authentication. That is the whole reason the QR-pin + SAS
//! ceremony exists. So this trait is deliberately dumb: send bytes, receive
//! bytes. All security lives in [`crate::channel`] and [`crate::pairing`] on top.
//!
//! - [`Transport`] — a reliable, ordered, framed byte pipe to one peer. A real
//!   impl wraps a TCP socket discovered over mDNS; the tests use
//!   [`LoopbackPair`], an in-process duplex, so nothing here needs a network.
//! - [`Discovery`] — the mDNS discovery seam. It advertises **minimally** ("a
//!   Postern wallet is here", a mDNS/`:port` hint) and browses for peers. This
//!   is a **metadata leak by construction** (the subnet learns you run this) and
//!   is **opt-in, off by default**. The v1 crate ships only a [`NullDiscovery`]
//!   that finds nothing — real mDNS is a Dev-layer plug-in.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TransportError {
    #[error("transport closed")]
    Closed,
    #[error("no message available")]
    WouldBlock,
    #[error("transport backend error: {0}")]
    Backend(String),
}

/// A reliable, ordered, message-framed byte pipe to exactly one peer.
///
/// Implementations MUST preserve message boundaries (each [`send`](Transport::send)
/// is one [`recv`](Transport::recv)) and ordering. They provide NO
/// confidentiality or authentication — that is the channel's job.
pub trait Transport {
    /// Send one framed message to the peer.
    fn send(&mut self, msg: &[u8]) -> Result<(), TransportError>;
    /// Receive the next framed message, or [`TransportError::WouldBlock`] if
    /// none is queued (this stub is non-blocking; a real impl may block).
    fn recv(&mut self) -> Result<Vec<u8>, TransportError>;
}

/// A minimal, opt-in mDNS-style discovery hint. No wallet address, no identity —
/// just enough to dial (§2.3: "minimal TXT, no wallet address, no identity").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerHint {
    /// e.g. `"192.168.1.20:47001"` — a LAN dial hint only.
    pub lan_hint: String,
    /// An opaque, rotating instance tag. NOT the wallet address, NOT the
    /// identity key. Just disambiguates two instances on the subnet.
    pub instance_tag: String,
}

/// The mDNS discovery seam. Off by default; a metadata leak when on (stated).
pub trait Discovery {
    /// Begin advertising this device on the LAN with a minimal hint. Opt-in.
    fn advertise(&mut self, hint: &PeerHint) -> Result<(), TransportError>;
    /// Browse for peers currently advertising. Returns a snapshot.
    fn browse(&mut self) -> Result<Vec<PeerHint>, TransportError>;
    /// Stop advertising (leave no standing broadcast).
    fn stop(&mut self) -> Result<(), TransportError>;
}

/// The shipped default discovery: finds nothing, advertises nothing. Real mDNS
/// is a Dev-layer plug-in; the scaffold stays offline and silent.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullDiscovery;

impl Discovery for NullDiscovery {
    fn advertise(&mut self, _hint: &PeerHint) -> Result<(), TransportError> {
        Ok(()) // no-op: the scaffold never actually broadcasts.
    }
    fn browse(&mut self) -> Result<Vec<PeerHint>, TransportError> {
        Ok(Vec::new())
    }
    fn stop(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// In-process loopback duplex (test / offline stand-in for a socket).
// ---------------------------------------------------------------------------

type Queue = Arc<Mutex<VecDeque<Vec<u8>>>>;

/// One end of an in-process, ordered, reliable duplex. Two endpoints share
/// crossed queues so a `send` on one is a `recv` on the other. Stands in for a
/// real LAN socket in tests and offline builds — no network involved.
pub struct LoopbackTransport {
    outbox: Queue,
    inbox: Queue,
}

impl Transport for LoopbackTransport {
    fn send(&mut self, msg: &[u8]) -> Result<(), TransportError> {
        self.outbox
            .lock()
            .map_err(|_| TransportError::Backend("poisoned".into()))?
            .push_back(msg.to_vec());
        Ok(())
    }

    fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
        self.inbox
            .lock()
            .map_err(|_| TransportError::Backend("poisoned".into()))?
            .pop_front()
            .ok_or(TransportError::WouldBlock)
    }
}

/// A connected pair of [`LoopbackTransport`]s.
pub struct LoopbackPair;

impl LoopbackPair {
    /// Create two crossed endpoints: `(a, b)` where `a.send` -> `b.recv`.
    pub fn new() -> (LoopbackTransport, LoopbackTransport) {
        let q_ab: Queue = Arc::new(Mutex::new(VecDeque::new()));
        let q_ba: Queue = Arc::new(Mutex::new(VecDeque::new()));
        let a = LoopbackTransport { outbox: q_ab.clone(), inbox: q_ba.clone() };
        let b = LoopbackTransport { outbox: q_ba, inbox: q_ab };
        (a, b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_carries_bytes_both_ways() {
        let (mut a, mut b) = LoopbackPair::new();
        a.send(b"ping").unwrap();
        assert_eq!(b.recv().unwrap(), b"ping");
        b.send(b"pong").unwrap();
        assert_eq!(a.recv().unwrap(), b"pong");
    }

    #[test]
    fn loopback_preserves_order_and_boundaries() {
        let (mut a, mut b) = LoopbackPair::new();
        a.send(b"one").unwrap();
        a.send(b"two").unwrap();
        assert_eq!(b.recv().unwrap(), b"one");
        assert_eq!(b.recv().unwrap(), b"two");
        assert_eq!(b.recv().unwrap_err(), TransportError::WouldBlock);
    }

    #[test]
    fn null_discovery_finds_nothing() {
        let mut d = NullDiscovery;
        d.advertise(&PeerHint { lan_hint: "x".into(), instance_tag: "y".into() }).unwrap();
        assert!(d.browse().unwrap().is_empty());
        d.stop().unwrap();
    }
}
