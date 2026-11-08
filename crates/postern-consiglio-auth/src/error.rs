//! Auth error type.

use thiserror::Error;

/// Why a wallet-login attempt was rejected. Deliberately non-specific to the
/// caller-facing surface in a real deployment (don't leak which check failed);
/// the variants exist so the scaffold + tests can assert precisely.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("no enrollment for {org_id}/{user_id}")]
    NotEnrolled { org_id: String, user_id: String },

    #[error("presented public key does not match the enrolled key")]
    WrongKey,

    #[error("challenge has expired")]
    Expired,

    #[error("nonce already used — replay rejected")]
    Replay,

    #[error("unknown or already-retired nonce")]
    UnknownNonce,

    #[error("post-quantum signature verification failed")]
    BadSignature,

    #[error("signing failed: {0}")]
    Sign(String),

    // --- Change-control (dual-control + Brewer–Nash SoD) ---
    /// The actor lacks the admin role required to propose/approve a change.
    #[error("not authorized: {who} — {why}")]
    NotAuthorized { who: String, why: String },

    /// The two-person rule was violated (e.g. self-approval).
    #[error("dual-control violation: {why}")]
    DualControl { why: String },

    /// The proposer/approver pair does not satisfy separation-of-duty.
    #[error("separation-of-duty violation: {why}")]
    SodViolation { why: String },

    /// No pending change with the given id.
    #[error("no pending change with id {0}")]
    UnknownChange(String),

    /// The pending change outlived the pending-change max age and was
    /// discarded at approve time (fail-closed) — it must be re-proposed.
    #[error("pending change {0} has exceeded its max age and was discarded — re-propose it")]
    ChangeExpired(String),

    // --- Access-time session enforcement (`AuthServer::authorize`) ---
    /// The presented session id cannot authorize anything: unknown, expired,
    /// revoked, or its owner is no longer enrolled (offboarded). Fail-closed —
    /// a real deployment should surface this as an opaque 401, not the `why`.
    #[error("session invalid: {why}")]
    SessionInvalid { why: String },
}
