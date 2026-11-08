// SPDX-License-Identifier: MIT OR Apache-2.0
//! Session + freshness helpers.
//!
//! A [`SessionId`] is the paired-session anchor (§2 pairing produces it; this
//! crate consumes it as the replay/session-binding root). The desktop draws a
//! fresh nonce and a strictly-advancing counter per request; the phone verifies
//! both against a [`crate::ReplayGuard`] bound to the same session.

use crate::message::SessionId;

/// Fill a buffer with OS CSPRNG bytes. Panics only if the OS entropy source
/// fails, which is unrecoverable for a signing protocol (fail loud, not weak).
fn os_random(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("OS CSPRNG unavailable");
}

/// A fresh 16-byte session id (used at pairing time; here for tests/demos).
pub fn new_session_id() -> SessionId {
    let mut id = [0u8; 16];
    os_random(&mut id);
    id
}

/// A fresh 32-byte single-use request nonce.
pub fn fresh_nonce() -> [u8; 32] {
    let mut n = [0u8; 32];
    os_random(&mut n);
    n
}

/// The desktop's monotonic per-session request counter. Strictly increasing;
/// the phone rejects any request whose counter does not advance past the last it
/// approved on this session.
#[derive(Debug, Clone)]
pub struct RequestCounter {
    session_id: SessionId,
    next: u64,
}

impl RequestCounter {
    /// Start a counter for a paired session. First issued counter is 1 (0 is
    /// reserved as "no request seen yet" on the guard side).
    pub fn new(session_id: SessionId) -> Self {
        RequestCounter { session_id, next: 1 }
    }

    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Take the next counter value, advancing the monotonic source.
    pub fn advance(&mut self) -> u64 {
        let c = self.next;
        self.next += 1;
        c
    }
}
