// SPDX-License-Identifier: MIT OR Apache-2.0
//! Replay / forgery resistance — the phone-side guard.
//!
//! Security §4.2 / §3.4: every request is **single-use and freshness-bound** by
//! three independent checks, all of which must pass before the phone will even
//! render an approval:
//!
//! 1. **Session binding** — the request's `session_id` must equal the paired
//!    session this guard is bound to. A request captured on session A cannot be
//!    replayed on session B (mirrors `seal-companion`'s channel binding).
//! 2. **Monotonic counter** — the request's `counter` must strictly exceed the
//!    last counter approved on this session. Catches reorder/replay of an older
//!    request.
//! 3. **Fresh nonce** — the request's `req_nonce` must be one this guard has
//!    never consumed on this session. Belt-and-suspenders with the counter.
//!
//! Fail closed: any check failing is a decline, and the guard state only advances
//! when a request is *accepted*, so a rejected request never poisons the sequence.

use std::collections::HashSet;

use crate::error::ProtocolError;
use crate::message::{SessionId, SignRequest};

/// Per-session anti-replay state, held on the phone for one paired session.
#[derive(Debug, Clone)]
pub struct ReplayGuard {
    session_id: SessionId,
    last_counter: u64,
    seen_nonces: HashSet<[u8; 32]>,
}

impl ReplayGuard {
    /// A fresh guard for a paired session. `last_counter` starts at 0, so the
    /// first request (counter 1) is the minimum acceptable.
    pub fn new(session_id: SessionId) -> Self {
        ReplayGuard {
            session_id,
            last_counter: 0,
            seen_nonces: HashSet::new(),
        }
    }

    /// Restore a guard from a persisted anti-replay **watermark** (see
    /// [`crate::resume`]): the last accepted counter is carried across a restart
    /// so the monotonic gate cannot be rolled back. The per-session nonce set is
    /// intentionally NOT restored — it is belt-and-suspenders to the counter, and
    /// the recommended reconnect mints a fresh session id anyway (so a captured
    /// frame fails the session binding regardless). Only ever feed this a
    /// watermark that was itself authenticated at rest.
    pub fn restore(session_id: SessionId, last_counter: u64) -> Self {
        ReplayGuard {
            session_id,
            last_counter,
            seen_nonces: HashSet::new(),
        }
    }

    /// The session this guard is bound to.
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// The last accepted counter (0 = none yet).
    pub fn last_counter(&self) -> u64 {
        self.last_counter
    }

    /// Validate a request against all three checks **without** mutating state.
    /// Used by the approval flow before showing the prompt, so a bad request is
    /// declined before any human decision.
    pub fn check(&self, req: &SignRequest) -> Result<(), ProtocolError> {
        if req.session_id != self.session_id {
            return Err(ProtocolError::WrongSession);
        }
        if req.counter <= self.last_counter {
            return Err(ProtocolError::StaleCounter {
                got: req.counter,
                last: self.last_counter,
            });
        }
        if self.seen_nonces.contains(&req.req_nonce) {
            return Err(ProtocolError::ReplayedNonce);
        }
        Ok(())
    }

    /// Commit an accepted request: advance the counter and retire its nonce.
    /// Call this **only** after [`check`](ReplayGuard::check) passed *and* the
    /// human approved — so the sequence advances on genuine approvals, never on
    /// rejected or declined requests.
    pub fn commit(&mut self, req: &SignRequest) {
        self.last_counter = req.counter;
        self.seen_nonces.insert(req.req_nonce);
    }
}
