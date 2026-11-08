// SPDX-License-Identifier: MIT OR Apache-2.0
//! Typed, fail-closed errors. Silence and ambiguity are always a refusal — never
//! a silent approval (mirrors `postern-policy`'s shut-door default).

use thiserror::Error;

/// A signing failure on the phone (the key-holding device).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SignerError {
    /// The on-device signer could not produce a signature.
    #[error("signer failed: {0}")]
    Backend(String),
}

/// A protocol-layer refusal. Every variant is a *decline to sign* — the phone
/// defaults closed.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtocolError {
    /// The request's session id does not match the paired session this guard is
    /// bound to. A request captured on session A cannot replay on session B.
    #[error("out-of-session request: bound to a different paired session")]
    WrongSession,

    /// The request's monotonic counter did not strictly advance past the last
    /// one seen on this session (a replay or reorder).
    #[error("stale counter: {got} does not advance past last-seen {last}")]
    StaleCounter { got: u64, last: u64 },

    /// This request nonce has already been consumed on this session (replay).
    #[error("replayed nonce: this request was already approved on this session")]
    ReplayedNonce,

    /// The signed-bytes payload could not be decoded into a known intent, so
    /// WYSIWYS cannot show the user what they would be signing. Fail closed.
    #[error("undisplayable payload: {0}")]
    UndecodablePayload(String),

    /// The human declined the approval prompt.
    #[error("declined by user on the signing device")]
    Declined,

    /// A wire frame was malformed, too large, or carried the wrong magic.
    #[error("bad wire frame: {0}")]
    BadFrame(String),

    /// The on-device signer failed while producing the approval signature.
    #[error("signer error: {0}")]
    Signer(String),

    /// The transport (Dev1's `Channel`) reported an error on send/recv.
    #[error("transport error: {0}")]
    Transport(String),
}

impl From<SignerError> for ProtocolError {
    fn from(e: SignerError) -> Self {
        ProtocolError::Signer(e.to_string())
    }
}
