// SPDX-License-Identifier: MIT OR Apache-2.0
//! The transport seam — Dev1's frozen [`Channel`] interface (defined locally so
//! this crate builds standalone) plus a hardened frame codec and an in-memory
//! loopback for tests.
//!
//! The real channel is the §2 paired, mutually-authenticated, **hybrid-PQ**
//! session (ML-KEM-1024‖X25519 via `postern-courier`, QR/SAS-anchored via
//! `postern-seal-companion`). This protocol rides *over* that channel and does not
//! re-implement it; it depends only on the ability to send/receive opaque frames.
//! Everything that crosses is public (signatures/approvals) — the channel's job is
//! confidentiality + integrity of already-non-secret bytes.

use std::collections::VecDeque;

use crate::error::ProtocolError;

/// Dev1's frozen transport interface: send and receive length-delimited frames.
/// A real implementation wraps the courier session socket; this crate is written
/// entirely against the trait.
pub trait Channel {
    /// The transport's own error type.
    type Error;

    /// Send one opaque frame.
    fn send(&mut self, frame: &[u8]) -> Result<(), Self::Error>;

    /// Receive the next opaque frame (blocking in a real transport; here a queue).
    fn recv(&mut self) -> Result<Vec<u8>, Self::Error>;
}

/// Magic prefix + hard size cap, in the spirit of `seal-companion`'s strict-magic,
/// no-alloc-before-length codec. A frame that lies about its size or magic is
/// rejected before allocation.
const FRAME_MAGIC: &[u8; 4] = b"PSG1";
/// 64 KiB is far above any request/approval; a value transfer or login is a few
/// hundred bytes.
pub const MAX_FRAME_LEN: usize = 64 * 1024;

/// Frame `body` as `MAGIC ‖ len(4, LE) ‖ body`.
pub fn frame(body: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    if body.len() > MAX_FRAME_LEN {
        return Err(ProtocolError::BadFrame(format!(
            "body {} exceeds cap {}",
            body.len(),
            MAX_FRAME_LEN
        )));
    }
    let mut out = Vec::with_capacity(8 + body.len());
    out.extend_from_slice(FRAME_MAGIC);
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

/// Parse a frame, checking magic and the length cap *before* trusting the body.
pub fn deframe(bytes: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    if bytes.len() < 8 {
        return Err(ProtocolError::BadFrame("short header".into()));
    }
    if &bytes[..4] != FRAME_MAGIC {
        return Err(ProtocolError::BadFrame("bad magic".into()));
    }
    let len = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
    if len > MAX_FRAME_LEN {
        return Err(ProtocolError::BadFrame("declared length over cap".into()));
    }
    if bytes.len() != 8 + len {
        return Err(ProtocolError::BadFrame("length mismatch".into()));
    }
    Ok(bytes[8..].to_vec())
}

/// One end of an in-memory, single-process loopback. NOT a transport — no crypto,
/// no authentication, no network. It exists only to exercise the protocol wiring
/// end to end in tests/demos.
///
/// [`loopback`] returns a `(desktop_end, phone_end)` pair: what one end sends, the
/// other receives.
pub struct LoopEnd {
    outbox: std::rc::Rc<std::cell::RefCell<VecDeque<Vec<u8>>>>,
    inbox: std::rc::Rc<std::cell::RefCell<VecDeque<Vec<u8>>>>,
}

/// Build a connected loopback pair `(desktop_end, phone_end)`.
pub fn loopback() -> (LoopEnd, LoopEnd) {
    use std::cell::RefCell;
    use std::rc::Rc;
    let a = Rc::new(RefCell::new(VecDeque::<Vec<u8>>::new())); // desktop→phone
    let b = Rc::new(RefCell::new(VecDeque::<Vec<u8>>::new())); // phone→desktop
    let desktop = LoopEnd { outbox: a.clone(), inbox: b.clone() };
    let phone = LoopEnd { outbox: b, inbox: a };
    (desktop, phone)
}

impl Channel for LoopEnd {
    type Error = ProtocolError;

    fn send(&mut self, frame: &[u8]) -> Result<(), Self::Error> {
        self.outbox.borrow_mut().push_back(frame.to_vec());
        Ok(())
    }

    fn recv(&mut self) -> Result<Vec<u8>, Self::Error> {
        self.inbox
            .borrow_mut()
            .pop_front()
            .ok_or_else(|| ProtocolError::BadFrame("no frame available".into()))
    }
}
