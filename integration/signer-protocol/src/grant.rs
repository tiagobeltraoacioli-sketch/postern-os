// SPDX-License-Identifier: MIT OR Apache-2.0
//! Time-boxed, revocable approval grants — the anti-approval-fatigue lever.
//!
//! Design §3.3: after an explicit review the phone MAY grant a **time-boxed,
//! revocable** window in which *single-tap* actions (only) auto-approve — "this
//! laptop can log you in to ACME for 22 min · revoke". Silence defaults to deny;
//! there is **no blanket "approve all"** (that would be a remote-drain primitive
//! if the desktop is A5), and value-moving actions are **never** covered by a
//! grant — they always demand a fresh explicit review.
//!
//! This mirrors `crates/postern-policy` (the one shared consent kernel: required
//! expiry, monotonic revocation, fail-closed `gate`). It is reproduced locally
//! rather than depended-on so the crate builds standalone; the semantics — and
//! the honest label — are the same. Enforcement is a **userland, in-process
//! check, not an OS/kernel boundary** (`EnforcementMode::ByConstruction`), and a
//! best-effort convenience, never a security boundary.

/// What a grant permits. Deliberately narrow: only a specific single-tap scope,
/// never "everything".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantScope {
    /// Auto-approve *login* challenges for this org, from the named peer only.
    LoginTo { org: String },
}

/// A revocable, expiring grant. `gate` is fail-closed: revoked OR expired both
/// collapse to "never given".
#[derive(Debug, Clone)]
pub struct ApprovalGrant {
    peer_device: String,
    scope: GrantScope,
    /// Absolute expiry, unix seconds. Required — a grant with no expiry cannot
    /// exist (there is no constructor without it).
    expires_at_unix: i64,
    revoked: bool,
}

impl ApprovalGrant {
    /// Mint a grant valid until `expires_at_unix`. Callers derive the expiry from
    /// a short window (e.g. now + 22 min); the value is surfaced in the UI so the
    /// user always sees when it lapses.
    pub fn new(peer_device: impl Into<String>, scope: GrantScope, expires_at_unix: i64) -> Self {
        ApprovalGrant {
            peer_device: peer_device.into(),
            scope,
            expires_at_unix,
            revoked: false,
        }
    }

    pub fn peer_device(&self) -> &str {
        &self.peer_device
    }

    pub fn expires_at_unix(&self) -> i64 {
        self.expires_at_unix
    }

    /// Revoke. Monotonic — there is no un-revoke (the postern-policy semantics).
    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked
    }

    /// The gate: does this grant auto-approve a *login* to `org` from `peer` at
    /// `now_unix`? Fail-closed — a revoked or expired grant, a different peer, or a
    /// different org all return `false`, sending the request back to an explicit
    /// prompt. Never covers value transfers.
    pub fn allows_login(&self, peer_device: &str, org: &str, now_unix: i64) -> bool {
        if self.revoked || now_unix >= self.expires_at_unix {
            return false;
        }
        if self.peer_device != peer_device {
            return false;
        }
        match &self.scope {
            GrantScope::LoginTo { org: g } => g == org,
        }
    }
}
