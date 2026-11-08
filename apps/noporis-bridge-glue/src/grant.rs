// SPDX-License-Identifier: MIT OR Apache-2.0
//! The near-side **live grant** — the lever the user throws to open one lane.
//!
//! This is the "nothing crosses without a live grant" half of the crossing.
//! It is modelled **exactly** on the tested `postern_signer_protocol::ApprovalGrant`
//! (time-boxed, revocable, per-peer, fail-closed `gate`), reproduced here rather
//! than depended-on because that grant's scope is `LoginTo { org }` — a login, not
//! a capability crossing. The semantics — and the honest label — are identical:
//!
//! - **Required expiry.** There is no constructor without one; a lane cannot be
//!   opened "forever". The value is surfaced so the user always sees when it lapses.
//! - **Monotonic revocation.** `revoke()` is one-way; there is no un-revoke.
//! - **Fail-closed gate.** Revoked OR expired OR wrong peer OR wrong capability OR
//!   wrong world all collapse to "never given".
//! - **No blanket "open all".** A grant is one `(peer, persona, capability)` lane.
//!
//! HONEST LABEL (unchanged from `postern-policy`): enforcement is a **userland,
//! in-process check, not an OS/kernel boundary** — a best-effort convenience, never
//! a security boundary. A rooted host defeats it.

use crate::capability::Capability;
use crate::persona::Persona;

/// A revocable, expiring permission to cross **one** capability lane, to **one**
/// named peer, serving **one** world.
#[derive(Debug, Clone)]
pub struct CapabilityGrant {
    peer_device: String,
    persona: Persona,
    capability: Capability,
    /// Absolute expiry, unix seconds. Required — a grant with no expiry cannot
    /// exist (no constructor without it).
    expires_at_unix: i64,
    revoked: bool,
}

impl CapabilityGrant {
    /// Open a lane valid until `expires_at_unix`. Callers derive the expiry from a
    /// short window (e.g. now + a few minutes); it is surfaced in the UI.
    pub fn new(
        peer_device: impl Into<String>,
        persona: Persona,
        capability: Capability,
        expires_at_unix: i64,
    ) -> Self {
        CapabilityGrant {
            peer_device: peer_device.into(),
            persona,
            capability,
            expires_at_unix,
            revoked: false,
        }
    }

    pub fn peer_device(&self) -> &str {
        &self.peer_device
    }

    pub fn persona(&self) -> Persona {
        self.persona
    }

    pub fn capability(&self) -> Capability {
        self.capability
    }

    pub fn expires_at_unix(&self) -> i64 {
        self.expires_at_unix
    }

    /// Revoke this lane. Monotonic — there is no un-revoke.
    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked
    }

    /// The gate: does this grant permit crossing `capability` to `peer_device` for
    /// `persona` at `now_unix`? Fail-closed — a revoked or expired grant, a
    /// different peer, a different world, or a different capability all return
    /// `false`, sending the crossing back to an explicit prompt.
    pub fn allows(
        &self,
        peer_device: &str,
        persona: Persona,
        capability: Capability,
        now_unix: i64,
    ) -> bool {
        !self.revoked
            && now_unix < self.expires_at_unix
            && self.peer_device == peer_device
            && self.persona == persona
            && self.capability == capability
    }
}
