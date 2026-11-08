// SPDX-License-Identifier: MIT OR Apache-2.0
//! A **real** [`Transport`] over a LAN TCP socket.
//!
//! [`postern_pairing::transport::Transport`] is a *message*-framed pipe: each
//! `send` must arrive as exactly one `recv`. TCP is a byte stream, so this layer
//! re-frames with a 4-byte big-endian length prefix — the same idea the pairing
//! crate already uses internally, applied at the wire so we recover message
//! boundaries. The bytes inside each frame are the pairing crate's already-sealed
//! output: **this layer never inspects, parses, or decrypts them.**
//!
//! It is a **dumb pipe** (RAIL): the pairing crate owns every bit of crypto. All
//! this file does is move bounded, framed byte blobs between two LAN hosts and
//! close cleanly.
//!
//! Hardening the pipe still needs (a dumb pipe is not a naive one):
//! - **Bounded frame size.** A peer-declared length above [`DEFAULT_MAX_FRAME_LEN`]
//!   is rejected *before* allocating, so a hostile/confused peer cannot make us
//!   reserve gigabytes. (LAN-only does not mean trusted.)
//! - **Timeouts.** `recv` honours the socket read timeout and reports a quiet
//!   socket as [`TransportError::WouldBlock`] rather than blocking forever.
//! - **Clean close.** A peer that closes at a frame boundary surfaces as
//!   [`TransportError::Closed`]; a close *mid-frame* is a distinct backend error
//!   (a truncated frame is not a clean shutdown).
//!
//! LAN-ONLY: nothing here dials off-subnet on its own — the caller supplies the
//! address, which the discovery layer sourced from a link-local mDNS hint. No
//! relay, no cloud, no internet path is introduced by this transport.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::time::Duration;

use postern_pairing::transport::{Transport, TransportError};

/// The length-prefix width: `u32` big-endian, so one frame is at most 4 GiB on
/// the wire (further clamped by [`DEFAULT_MAX_FRAME_LEN`]).
const LEN_PREFIX: usize = 4;

/// Default hard cap on one frame's payload. Pairing frames are tiny (a KEM
/// ciphertext plus a small AEAD frame — low kilobytes), so 256 KiB is
/// comfortably generous while still refusing an absurd length outright.
pub const DEFAULT_MAX_FRAME_LEN: usize = 256 * 1024;

fn backend<E: std::fmt::Display>(e: E) -> TransportError {
    TransportError::Backend(e.to_string())
}

/// A framed TCP [`Transport`] to exactly one peer.
///
/// Construct it by dialing a discovered peer with [`TcpTransport::connect`], or
/// from an accepted inbound stream via [`TcpTransportListener::accept`].
pub struct TcpTransport {
    stream: TcpStream,
    max_frame_len: usize,
}

impl TcpTransport {
    /// Dial a LAN peer (typically a `host:port` taken straight from a
    /// [`postern_pairing::transport::PeerHint`]) and set sane default timeouts.
    pub fn connect<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        Self::from_stream(stream)
    }

    /// Dial with an explicit connect timeout (fail fast if the peer is gone).
    pub fn connect_timeout(
        addr: std::net::SocketAddr,
        timeout: Duration,
    ) -> io::Result<Self> {
        let stream = TcpStream::connect_timeout(&addr, timeout)?;
        Self::from_stream(stream)
    }

    /// Wrap an already-connected stream (e.g. one returned by `accept`). Disables
    /// Nagle (pairing messages are small and latency-sensitive) and installs the
    /// default max frame size.
    pub fn from_stream(stream: TcpStream) -> io::Result<Self> {
        stream.set_nodelay(true).ok(); // best-effort; not fatal if unsupported.
        Ok(TcpTransport { stream, max_frame_len: DEFAULT_MAX_FRAME_LEN })
    }

    /// Override the per-frame size cap (both send and recv enforce it).
    pub fn set_max_frame_len(&mut self, max: usize) {
        self.max_frame_len = max.max(1);
    }

    /// Set the read timeout. `None` blocks indefinitely; a timeout makes a quiet
    /// socket surface as [`TransportError::WouldBlock`] from `recv`.
    pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.stream.set_read_timeout(dur)
    }

    /// Set the write timeout (bounds a stalled `send`).
    pub fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.stream.set_write_timeout(dur)
    }

    /// The local socket address (useful in tests / for logging a dial hint).
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.stream.local_addr()
    }

    /// The connected peer's address.
    pub fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.stream.peer_addr()
    }

    /// Cleanly shut the connection in both directions. Idempotent-ish: a second
    /// call may error at the OS layer, which we swallow.
    pub fn close(&self) -> Result<(), TransportError> {
        self.stream
            .shutdown(std::net::Shutdown::Both)
            .or_else(|e| match e.kind() {
                io::ErrorKind::NotConnected => Ok(()),
                _ => Err(backend(e)),
            })
    }

    /// Read exactly `buf.len()` bytes, distinguishing the three failure shapes
    /// the transport contract cares about:
    /// - a timeout / would-block *before any byte* -> caller maps to `WouldBlock`
    /// - a clean EOF *before any byte*             -> caller maps to `Closed`
    /// - anything after partial progress           -> a hard `Backend` error
    ///
    /// `Ok(false)` means "nothing arrived yet, cleanly" (empty read window).
    fn read_full(&mut self, buf: &mut [u8]) -> Result<bool, TransportError> {
        let mut filled = 0usize;
        while filled < buf.len() {
            match self.stream.read(&mut buf[filled..]) {
                Ok(0) => {
                    // EOF. Clean only if it lands exactly on a boundary.
                    if filled == 0 {
                        return Ok(false); // peer closed at a frame boundary.
                    }
                    return Err(backend("peer closed mid-frame (truncated)"));
                }
                Ok(n) => filled += n,
                Err(e) => match e.kind() {
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
                        if filled == 0 {
                            return Err(TransportError::WouldBlock);
                        }
                        // A timeout partway through a frame: don't spin, don't
                        // half-deliver. Surface it so the caller can re-pair.
                        return Err(backend("read timed out mid-frame"));
                    }
                    io::ErrorKind::Interrupted => continue,
                    io::ErrorKind::UnexpectedEof => {
                        return Err(backend("unexpected eof mid-frame"));
                    }
                    _ => return Err(backend(e)),
                },
            }
        }
        Ok(true)
    }
}

impl Transport for TcpTransport {
    fn send(&mut self, msg: &[u8]) -> Result<(), TransportError> {
        if msg.len() > self.max_frame_len {
            return Err(backend(format!(
                "frame {} exceeds max {}",
                msg.len(),
                self.max_frame_len
            )));
        }
        let len = msg.len() as u32;
        // One writev-friendly buffer: prefix then body, then a single flush.
        let mut framed = Vec::with_capacity(LEN_PREFIX + msg.len());
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(msg);
        self.stream.write_all(&framed).map_err(|e| match e.kind() {
            io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset => {
                TransportError::Closed
            }
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
                TransportError::WouldBlock
            }
            _ => backend(e),
        })?;
        self.stream.flush().map_err(backend)
    }

    fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
        let mut hdr = [0u8; LEN_PREFIX];
        if !self.read_full(&mut hdr)? {
            return Err(TransportError::Closed); // clean EOF at boundary.
        }
        let len = u32::from_be_bytes(hdr) as usize;
        if len > self.max_frame_len {
            // Refuse the allocation; this is a protocol violation, not a close.
            return Err(backend(format!(
                "peer declared frame {} over max {}",
                len, self.max_frame_len
            )));
        }
        let mut body = vec![0u8; len];
        if !self.read_full(&mut body)? {
            // EOF right after a header but before the body is a truncation.
            return Err(backend("peer closed after length prefix (truncated)"));
        }
        Ok(body)
    }
}

/// A LAN listener that yields framed [`TcpTransport`]s. This is the desktop side
/// of the pairing dial: it binds a port (advertised over mDNS) and accepts the
/// phone's connection.
pub struct TcpTransportListener {
    listener: TcpListener,
    max_frame_len: usize,
}

impl TcpTransportListener {
    /// Bind a listening socket. Pass `0` as the port to let the OS choose, then
    /// read it back with [`local_addr`](Self::local_addr) to advertise it.
    pub fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        Ok(TcpTransportListener { listener, max_frame_len: DEFAULT_MAX_FRAME_LEN })
    }

    /// The bound address, including the OS-chosen port when `0` was requested.
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// Frame cap applied to every transport this listener accepts.
    pub fn set_max_frame_len(&mut self, max: usize) {
        self.max_frame_len = max.max(1);
    }

    /// Block for the next inbound peer and wrap it as a framed transport.
    pub fn accept(&self) -> io::Result<(TcpTransport, std::net::SocketAddr)> {
        let (stream, peer) = self.listener.accept()?;
        let mut t = TcpTransport::from_stream(stream)?;
        t.max_frame_len = self.max_frame_len;
        Ok((t, peer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::thread;

    fn loopback_listener() -> TcpTransportListener {
        TcpTransportListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap()
    }

    #[test]
    fn localhost_roundtrip_preserves_boundaries() {
        let listener = loopback_listener();
        let addr = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (mut t, _peer) = listener.accept().unwrap();
            // Echo three distinct messages back, preserving boundaries.
            for _ in 0..3 {
                let m = t.recv().unwrap();
                t.send(&m).unwrap();
            }
            t.close().unwrap();
        });

        let mut client = TcpTransport::connect(addr).unwrap();
        for msg in [b"one".as_slice(), b"two", b"a slightly longer third frame"] {
            client.send(msg).unwrap();
            assert_eq!(client.recv().unwrap(), msg);
        }
        server.join().unwrap();
    }

    #[test]
    fn empty_frame_roundtrips() {
        let listener = loopback_listener();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut t, _p) = listener.accept().unwrap();
            let m = t.recv().unwrap();
            t.send(&m).unwrap();
        });
        let mut client = TcpTransport::connect(addr).unwrap();
        client.send(b"").unwrap();
        assert_eq!(client.recv().unwrap(), b"");
        server.join().unwrap();
    }

    #[test]
    fn clean_close_surfaces_as_closed() {
        let listener = loopback_listener();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (t, _p) = listener.accept().unwrap();
            t.close().unwrap(); // shut immediately, at a boundary.
        });
        let mut client = TcpTransport::connect(addr).unwrap();
        // The peer closed with no frame -> a clean Closed, not garbage.
        assert_eq!(client.recv().unwrap_err(), TransportError::Closed);
        server.join().unwrap();
    }

    #[test]
    fn read_timeout_surfaces_as_wouldblock() {
        let listener = loopback_listener();
        let addr = listener.local_addr().unwrap();
        // Hold the connection open but send nothing.
        let server = thread::spawn(move || {
            let (t, _p) = listener.accept().unwrap();
            thread::sleep(Duration::from_millis(200));
            t.close().ok();
        });
        let mut client = TcpTransport::connect(addr).unwrap();
        client.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        assert_eq!(client.recv().unwrap_err(), TransportError::WouldBlock);
        server.join().unwrap();
    }

    #[test]
    fn oversize_send_is_refused_without_allocating_peer_side() {
        let listener = loopback_listener();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let _ = listener.accept();
        });
        let mut client = TcpTransport::connect(addr).unwrap();
        client.set_max_frame_len(16);
        let too_big = vec![0u8; 17];
        assert!(client.send(&too_big).is_err());
        server.join().unwrap();
    }

    #[test]
    fn oversize_declared_length_is_refused_on_recv() {
        // Server writes a raw, hand-rolled oversize length prefix; the framed
        // recv must refuse it rather than allocate.
        let listener = loopback_listener();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (stream, _p) = listener.listener.accept().unwrap();
            let mut raw = stream;
            // Declare a 100 MiB frame.
            let len: u32 = 100 * 1024 * 1024;
            raw.write_all(&len.to_be_bytes()).unwrap();
            raw.flush().ok();
            thread::sleep(Duration::from_millis(50));
        });
        let mut client = TcpTransport::connect(addr).unwrap();
        client.set_max_frame_len(1024);
        let err = client.recv().unwrap_err();
        assert!(matches!(err, TransportError::Backend(_)));
        server.join().unwrap();
    }

    #[test]
    fn connect_timeout_to_dead_addr_errors_fast() {
        // 203.0.113.0/24 (TEST-NET-3) is reserved and unroutable; a bounded
        // connect must return promptly rather than hang. (No packet leaves the
        // LAN in practice; this only asserts the timeout path compiles/works.)
        let dead = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 1), 9));
        let r = TcpTransport::connect_timeout(dead, Duration::from_millis(150));
        assert!(r.is_err());
    }
}
