// SPDX-License-Identifier: MIT OR Apache-2.0
//! The two worlds the span connects — and the honest label each carries.
//!
//! A "world" is not a new primitive; it is simply *which paired peer a frame
//! arrived on* (Composition-UX §2). The persona label is therefore **derived
//! from the pairing**, never from a field the requester controls — a compromised
//! far side cannot mislabel its own world.
//!
//! **This is enforcement-backed, not just a naming convention.**
//! [`crate::bridge::CrossingReceiver`] is constructed with its own
//! `from_persona` (the origin derived from the pairing/lane — e.g. the daemon's
//! `CrossingLane`'s `direction.from`), and every decoded
//! [`crate::crossing::CrossingRequest::from_persona`] — the field the *sender*
//! sets — is cross-checked against it in
//! [`CrossingReceiver::receive_crossing`](crate::bridge::CrossingReceiver::receive_crossing)
//! and
//! [`CrossingReceiver::receive_crossing_audited`](crate::bridge::CrossingReceiver::receive_crossing_audited),
//! fail-closed on mismatch ([`crate::error::BridgeError::FromPersonaMismatch`]),
//! before the claim can reach the direction-pinned consent check,
//! `GateConsent::decide`, or the durable audit trail's `from` attribution. A
//! compromised endpoint can *claim* whatever it wants in the wire field; only
//! the receiver's own derived origin is ever trusted.
//!
//! Rail (Mechanism-Design, carried verbatim): the **Google-Play persona is the
//! LESS-PRIVATE side by construction** — GMS phones home. Every surface that
//! names it says so; NoporIS delivers *separation + convenience, not privacy* on
//! that side.

use serde::{Deserialize, Serialize};

/// Which world a crossing endpoint is. Two, exactly — Android permits one managed
/// profile per user, so the folklore (two worlds, one guarded crossing) maps 1:1
/// onto the mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Persona {
    /// The business/clean, de-Googled, wallet-side world (== Porog's container).
    Clean,
    /// The Google-Play world: GMS enabled, phones home. **The less-private side.**
    GooglePlay,
}

impl Persona {
    /// A plain-language label for the crossing prompt / world badge.
    pub fn label(self) -> &'static str {
        match self {
            Persona::Clean => "clean · hardened side",
            Persona::GooglePlay => "Google-Play side — less private",
        }
    }

    /// True for the world that phones home to Google. Surface this wherever the
    /// persona appears — it is a fact, not decoration.
    pub fn is_less_private(self) -> bool {
        matches!(self, Persona::GooglePlay)
    }
}
