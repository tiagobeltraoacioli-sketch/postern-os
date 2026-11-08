// SPDX-License-Identifier: MIT OR Apache-2.0
//! Typed, fail-closed errors. Every variant is a **refusal to cross** — silence
//! and ambiguity are always a decline, never a silent crossing (mirrors the
//! signer-protocol and `postern-policy` shut-door default).

use thiserror::Error;

use crate::persona::Persona;

/// Why the N-gate (or its reference stand-in) refused a crossing. Deny-by-default:
/// anything not an explicit, live, per-capability yes lands here.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DenyReason {
    /// The operator kill-switch is engaged — the span is cut; nothing crosses.
    #[error("kill-switch engaged: the bridge is cut")]
    KillSwitchEngaged,
    /// First-entry consent was never accepted for this session; the crossing
    /// disclosure has not been shown/agreed.
    #[error("consent not accepted for this session")]
    ConsentNotAccepted,
    /// This specific capability's bridge is off (the default). Only an explicit,
    /// disclosed toggle opens it.
    #[error("capability bridge is closed (deny-by-default)")]
    CapabilityClosed,
    /// A malformed/corrupt gate state collapsed to full-deny (`normalize()`).
    #[error("gate state malformed → collapsed to deny")]
    Malformed,
}

impl DenyReason {
    /// A stable, lower-snake machine key for logs / the audit ledger chain. Never
    /// localized, never reordered.
    pub fn key(&self) -> &'static str {
        match self {
            DenyReason::KillSwitchEngaged => "kill_switch",
            DenyReason::ConsentNotAccepted => "consent_not_accepted",
            DenyReason::CapabilityClosed => "capability_closed",
            DenyReason::Malformed => "gate_malformed",
        }
    }
}

/// A crossing-layer refusal or failure. Fail-closed throughout.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BridgeError {
    /// The crossing's session id does not match the paired session this endpoint
    /// is bound to — a crossing captured on session A cannot replay on session B.
    #[error("out-of-session crossing: bound to a different paired session")]
    WrongSession,

    /// The monotonic per-session counter did not strictly advance (replay/reorder).
    #[error("stale counter: {got} does not advance past last-seen {last}")]
    StaleCounter { got: u64, last: u64 },

    /// This crossing nonce was already consumed on this session (replay).
    #[error("replayed nonce: this crossing was already delivered on this session")]
    ReplayedNonce,

    /// The near side has no live grant for this capability — the user never opened
    /// (or has revoked/expired) this lane. Nothing crosses without a live grant.
    #[error("no live grant: this capability lane is not open on the sending side")]
    NotGranted,

    /// The N-gate consent decision denied this crossing (deny-by-default).
    #[error("gate denied the crossing: {0}")]
    GateDenied(DenyReason),

    /// The signed [`ConsentRecord`](crate::consent_record::ConsentRecord) layer
    /// refused this crossing — no live, correctly-signed, correctly-directed
    /// authorization (or it was revoked / expired / spent / kill-switched).
    #[error("consent record refused the crossing: {0}")]
    ConsentRefused(String),

    /// The opaque payload exceeds the scaffold crossing cap.
    #[error("payload too large: {len} exceeds cap {max}")]
    PayloadTooLarge { len: usize, max: usize },

    /// The crossing envelope was malformed / undecodable — undisplayable, so it
    /// will not cross (fail closed).
    #[error("malformed crossing envelope: {0}")]
    Malformed(String),

    /// The underlying pairing `Channel` refused the frame (AEAD open, replay,
    /// direction/session AAD mismatch, …).
    #[error("paired channel error: {0}")]
    Channel(String),

    /// The `Transport` bearer reported an error on send/recv.
    #[error("transport error: {0}")]
    Transport(String),

    /// The append-only audit trail could not record the event. Fail-closed: if the
    /// action cannot be logged durably, the crossing does not proceed.
    #[error("audit trail error: {0}")]
    Audit(String),

    /// The crossing's claimed `from_persona` does not match the receiving
    /// endpoint's derived origin (the receiver's own `from_persona`, set from the
    /// pairing/lane it was constructed for — never from this field). A crossing
    /// carries no trusted-prose origin: the label must equal the derived one or
    /// it is refused, fail-closed, before the per-crossing guard, the signed
    /// consent check, the gate, or the audit trail's `from` attribution ever see
    /// it — a compromised endpoint cannot mislabel its own world or poison
    /// attribution by simply claiming to be someone else.
    #[error("from_persona mismatch: claimed {claimed:?} but this endpoint's derived origin is {expected:?}")]
    FromPersonaMismatch { claimed: Persona, expected: Persona },
}
