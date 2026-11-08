//! Dual-control + Brewer–Nash separation-of-duty (SoD), ENFORCED at runtime.
//!
//! The reference scaffold *declared* SoD (`Role::sod_conflicts`) and *declared*
//! admin dual-control on enroll/offboard, but enforced neither. This module is
//! the enforcement point. Every privileged change (enroll a wallet, offboard a
//! user) is a **two-person rule**:
//!
//! 1. An **admin** ([`Role::is_admin`]) PROPOSES the change — it is staged as a
//!    [`PendingChange`], nothing is mutated yet.
//! 2. A **second, distinct** admin APPROVES it — and the approver's role must be
//!    the Brewer–Nash *separated* counterpart of the proposer's
//!    ([`Role::sod_separated_from`]). Concretely, one IT-admin **and** one
//!    compliance-officer must both sign off; two IT-admins (or two
//!    compliance-officers, or a self-approval) can never commit a change.
//!
//! This makes the declared wall real: the control action itself is separated
//! across the two duties, so neither side can act unilaterally.
//!
//! ## Session-bound control plane (the production path)
//!
//! [`AuthServer::propose_change_by_session`], [`AuthServer::approve_change_by_session`],
//! and [`AuthServer::reject_change_by_session`] resolve the ACTING identity
//! from the live session store — the session id must be unexpired and
//! unrevoked (expired entries are reaped, exactly like `authorize` step 1) —
//! and re-read the actor's role from the CURRENT enrollment server-side. No
//! caller-supplied [`User`] struct is trusted anywhere on this path, so a
//! revoked/expired session, an offboarded admin's still-held session id, or a
//! demoted admin's live session can neither propose, approve, nor reject.
//!
//! The `&User` forms below remain ONLY as bootstrap/test seams (they let a
//! deployment seed its first admins and let tests drive the gate without a PQ
//! login), mirroring the `enrollments_mut()` honesty note. They are NOT less
//! checked where it counts: approve and reject both read the actor's role from
//! the live enrollment store and ignore the role claimed in the request.
//! (`reject_change` used to trust `rejecter.role` — a never-enrolled caller
//! self-asserting an admin role could drop any pending change; that hole is
//! closed on BOTH paths.) `propose_change(&User, ..)` still trusts the claimed
//! role — it is the documented bootstrap seam; its staged change is backstopped
//! by approve-time proposer re-validation, and production proposals go through
//! `propose_change_by_session`.
//!
//! Further gates keep the pending queue itself honest (all fail-closed,
//! all covered by tests — this is still a reference prototype, UNAUDITED):
//!
//! - **Reject is admin-gated server-side**: [`AuthServer::reject_change`]
//!   reads the rejecter's role from the live enrollment store — an unenrolled
//!   or non-admin (or demoted) rejecter cannot silently drop another admin's
//!   proposal, whatever role their request claims.
//! - **Approver role read server-side**: [`AuthServer::approve_change`] looks
//!   the approver's role up in the live enrollment store at approval time and
//!   IGNORES the role claimed in the request — a demoted or never-enrolled
//!   caller cannot self-assert an admin role to pass the gate.
//! - **Proposer re-validated at approve**: an offboarded (or demoted, or
//!   wall-crossing rotated) admin's stale proposal is refused at approve time;
//!   offboarding additionally purges the departed admin's pending proposals.
//! - **Pending-change max age**: a proposal older than the server's
//!   pending-change TTL is refused and discarded at approve time and reaped by
//!   the periodic sweep.
//!
//! On commit, an **offboard** flows through
//! [`AuthServer::offboard_and_revoke`](crate::server::AuthServer::offboard_and_revoke)
//! so live sessions + pending challenges + the departed user's own pending
//! proposals are invalidated in the same step; an **enroll that rotates the
//! wallet key** revokes the user's live sessions and purges their outstanding
//! challenges, so a rotated-out key cannot keep an authenticated session alive.
//! (Honest limit: the direct `enrollments_mut().enroll(..)` bootstrap seam
//! bypasses dual-control by design and therefore also bypasses this rotation
//! revocation — production rotations must go through propose/approve.)
//!
//! Honesty: everything here is a **userland enforcement point, not a kernel
//! boundary** — an unaudited reference prototype. It demonstrates controls
//! that enable compliance; it is NOT compliance.

use chrono::Utc;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::enroll::Enrollment;
use crate::error::AuthError;
use crate::org::User;
use crate::server::AuthServer;

/// What a [`PendingChange`] will do once dual-control approves it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChangeKind {
    /// Enroll (or rotate) a wallet key for a user.
    Enroll(Enrollment),
    /// Offboard a user (remove enrollment + revoke sessions/challenges).
    Offboard { org_id: String, user_id: String },
}

impl ChangeKind {
    fn describe(&self) -> String {
        match self {
            ChangeKind::Enroll(e) => format!("enroll {}/{} as {}", e.org_id, e.user_id, e.role.id()),
            ChangeKind::Offboard { org_id, user_id } => format!("offboard {org_id}/{user_id}"),
        }
    }
}

/// A privileged change staged by one admin, awaiting a second, separated admin's
/// approval. Serializable so the pending queue survives a restart (durability).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingChange {
    /// Random 128-bit change id (hex).
    pub id: String,
    /// The change to apply on approval.
    pub kind: ChangeKind,
    /// The admin who proposed it (identity + role captured at propose time).
    pub proposer: User,
    /// Unix seconds when proposed.
    pub created_at: i64,
    /// Human description for the audit trail / console UI.
    pub summary: String,
}

impl AuthServer {
    /// Resolve the ACTING identity for a session-bound control action, exactly
    /// as [`AuthServer::authorize`] does for data access (steps 1–2):
    ///
    ///   1. the session id must be known and unexpired at `now` — an expired
    ///      entry is reaped, an unknown/revoked id is refused fail-closed;
    ///   2. the session's `(org, user)` must STILL be enrolled — an orphaned
    ///      session (owner offboarded out-of-band) is revoked here and refused;
    ///   3. the returned [`User`] is projected from the CURRENT enrollment
    ///      (live role + clearance), never from the login-time snapshot inside
    ///      the stored [`crate::server::Session`] and never from any
    ///      caller-supplied struct.
    fn control_actor_by_session(&mut self, session_id: &str, now: i64) -> Result<User, AuthError> {
        let session = match self.sessions.get(session_id) {
            None => {
                return Err(AuthError::SessionInvalid {
                    why: "unknown or revoked session id".into(),
                })
            }
            Some(s) if s.is_expired(now) => {
                self.sessions.remove(session_id);
                return Err(AuthError::SessionInvalid { why: "session expired".into() });
            }
            Some(s) => s.clone(),
        };
        let Some(enrollment) = self.enrollments.get(&session.org_id, &session.user.user_id) else {
            self.sessions.remove(session_id);
            return Err(AuthError::SessionInvalid {
                why: "user no longer enrolled — session revoked".into(),
            });
        };
        Ok(enrollment.user())
    }

    /// PROPOSE a privileged change through a live session (the production
    /// path). The acting identity is resolved from the session store and the
    /// proposer's role is the CURRENT enrolled role — a caller can neither
    /// claim a role nor act on a revoked/expired session or after being
    /// offboarded/demoted. The live role must be an admin ([`Role::is_admin`]).
    ///
    /// Nothing is mutated here — the change only takes effect on
    /// [`AuthServer::approve_change_by_session`] /
    /// [`AuthServer::approve_change`].
    pub fn propose_change_by_session(
        &mut self,
        session_id: &str,
        kind: ChangeKind,
        now: i64,
    ) -> Result<String, AuthError> {
        let actor = self.control_actor_by_session(session_id, now)?;
        self.propose_change_at(&actor, kind, now)
    }

    /// PROPOSE a privileged change. The proposer MUST be an admin
    /// ([`Role::is_admin`]); a business role cannot stage enroll/offboard.
    /// Returns the [`PendingChange`] id to hand to a second admin for approval.
    ///
    /// BOOTSTRAP/TEST SEAM (like [`AuthServer::enrollments_mut`]): this form
    /// trusts the role claimed in the caller-supplied [`User`]. It is safe to
    /// keep only because approve-time proposer re-validation refuses any
    /// staged change whose proposer is not a live, enrolled admin — production
    /// proposals go through [`AuthServer::propose_change_by_session`], which
    /// resolves the proposer server-side.
    ///
    /// Nothing is mutated here — the change only takes effect on
    /// [`AuthServer::approve_change`].
    pub fn propose_change(
        &mut self,
        proposer: &User,
        kind: ChangeKind,
    ) -> Result<String, AuthError> {
        self.propose_change_at(proposer, kind, Utc::now().timestamp())
    }

    fn propose_change_at(
        &mut self,
        proposer: &User,
        kind: ChangeKind,
        now: i64,
    ) -> Result<String, AuthError> {
        if !proposer.role.is_admin() {
            return Err(AuthError::NotAuthorized {
                who: proposer.user_id.clone(),
                why: "only an IT-admin or compliance-officer may propose enroll/offboard".into(),
            });
        }
        let id = new_change_id();
        let change = PendingChange {
            id: id.clone(),
            summary: kind.describe(),
            kind,
            proposer: proposer.clone(),
            created_at: now,
        };
        self.pending.insert(id.clone(), change);
        Ok(id)
    }

    /// Peek at a pending change without committing it.
    pub fn pending_change(&self, id: &str) -> Option<&PendingChange> {
        self.pending.get(id)
    }

    /// The ids of all changes currently awaiting approval.
    pub fn pending_change_ids(&self) -> Vec<String> {
        self.pending.keys().cloned().collect()
    }

    /// APPROVE and commit a pending change through a live session (the
    /// production path). The approving identity is resolved from the session
    /// store (unexpired, unrevoked, reaped like `authorize` step 1) and its
    /// role re-read from the CURRENT enrollment — every gate of
    /// [`AuthServer::approve_change`] (self-approval refusal, SoD-separated
    /// pair against LIVE roles, proposer re-validation, pending-change max
    /// age) holds identically on this path.
    pub fn approve_change_by_session(
        &mut self,
        session_id: &str,
        change_id: &str,
        now: i64,
    ) -> Result<CommitOutcome, AuthError> {
        let actor = self.control_actor_by_session(session_id, now)?;
        self.approve_change_at(change_id, &actor, now)
    }

    /// APPROVE and commit a pending change under the two-person rule. The
    /// approver must:
    ///   - be a **distinct user** from the proposer (no self-approval); and
    ///   - be an **admin** whose role is the Brewer–Nash *separated* counterpart
    ///     of the proposer's ([`Role::sod_separated_from`]) — i.e. one IT-admin
    ///     and one compliance-officer must BOTH sign off.
    ///
    /// The approver's role is **re-read from the server-side enrollment store
    /// at approval time**; the role claimed in the request (`approver.role`)
    /// is never trusted for authorization. An unenrolled or demoted approver
    /// is refused fail-closed, whatever their request claims.
    ///
    /// Two more fail-closed gates run at approve time:
    ///   - **max age**: a change older than the server's pending-change TTL
    ///     ([`crate::server::DEFAULT_PENDING_CHANGE_TTL_SECS`]) is refused AND
    ///     discarded ([`AuthError::ChangeExpired`]) — a stale proposal cannot
    ///     be committed months later;
    ///   - **proposer re-validation**: the proposer must STILL be enrolled and
    ///     their *current* enrolled role must still be an admin role separated
    ///     from the approver's — an offboarded (or demoted, or wall-crossing
    ///     rotated) admin's stale proposal cannot commit. (Offboarding also
    ///     purges the departed admin's pending proposals outright — see
    ///     [`AuthServer::offboard_and_revoke`]; this check is the backstop.)
    ///
    /// On success the change is applied (an offboard also revokes live
    /// sessions + challenges + the departed user's pending proposals via
    /// [`AuthServer::offboard_and_revoke`]) and the pending entry is removed.
    /// On any check failure other than expiry the change stays pending and the
    /// store is untouched (fail-closed).
    ///
    /// BOOTSTRAP/TEST SEAM caveat: only the approver's *identity* (org + user
    /// id) is taken from the caller-supplied [`User`]; the role is read
    /// server-side. Production approvals go through
    /// [`AuthServer::approve_change_by_session`], where the identity too is
    /// resolved from a live session.
    pub fn approve_change(
        &mut self,
        change_id: &str,
        approver: &User,
    ) -> Result<CommitOutcome, AuthError> {
        self.approve_change_at(change_id, approver, Utc::now().timestamp())
    }

    fn approve_change_at(
        &mut self,
        change_id: &str,
        approver: &User,
        now: i64,
    ) -> Result<CommitOutcome, AuthError> {
        let change = self
            .pending
            .get(change_id)
            .ok_or_else(|| AuthError::UnknownChange(change_id.to_string()))?
            .clone();

        // Max age: an expired proposal is refused AND reaped (fail-closed) —
        // approval after the pending-change TTL requires a fresh proposal.
        if now - change.created_at > self.pending_change_ttl_secs {
            self.pending.remove(change_id);
            return Err(AuthError::ChangeExpired(change_id.to_string()));
        }

        // Two-person rule: the approver must not be the proposer.
        if approver.org_id == change.proposer.org_id && approver.user_id == change.proposer.user_id
        {
            return Err(AuthError::DualControl {
                why: "self-approval is refused — a second, distinct admin must approve".into(),
            });
        }
        // The APPROVER's role is read from the server-side enrollment store at
        // approval time — the role claimed inside the request (`approver.role`)
        // is caller-supplied and is deliberately IGNORED for authorization.
        // (Before this fix a demoted/never-enrolled caller could self-assert
        // an admin role in the request and pass the gate.) Fail-closed: an
        // approver with no live enrollment cannot approve anything.
        let approver_role_now = match self.enrollments.get(&approver.org_id, &approver.user_id) {
            Some(e) => e.role,
            None => {
                return Err(AuthError::NotAuthorized {
                    who: approver.user_id.clone(),
                    why: "approver is not enrolled — role claims in the request are not trusted"
                        .into(),
                })
            }
        };
        // The approver's LIVE role must be an admin.
        if !approver_role_now.is_admin() {
            return Err(AuthError::NotAuthorized {
                who: approver.user_id.clone(),
                why: format!(
                    "approver's current enrolled role '{}' is not administrative — only an \
                     IT-admin or compliance-officer may approve a privileged change",
                    approver_role_now.id()
                ),
            });
        }
        // Brewer–Nash: proposer and approver must be a SEPARATED pair (one
        // IT-admin + one compliance-officer). This enforces the declared SoD on
        // the control action itself — against the approver's LIVE role.
        if !change.proposer.role.sod_separated_from(approver_role_now) {
            return Err(AuthError::SodViolation {
                why: format!(
                    "dual-control requires separated duties: proposer '{}' and approver '{}' \
                     must be one IT-admin AND one compliance-officer",
                    change.proposer.role.id(),
                    approver_role_now.id()
                ),
            });
        }
        // Re-validate the PROPOSER at approve time (fail-closed): the identity
        // captured at propose time is only as good as the proposer's CURRENT
        // standing. If they were offboarded in between, their stale proposal
        // must not commit; if their enrolled role changed, the two-person
        // separation must still hold for the role they hold NOW.
        let proposer_role_now = match self
            .enrollments
            .get(&change.proposer.org_id, &change.proposer.user_id)
        {
            Some(e) => e.role,
            None => {
                return Err(AuthError::NotAuthorized {
                    who: change.proposer.user_id.clone(),
                    why: "proposer is no longer enrolled — stale proposal refused (fail-closed)"
                        .into(),
                })
            }
        };
        if !proposer_role_now.is_admin() {
            return Err(AuthError::NotAuthorized {
                who: change.proposer.user_id.clone(),
                why: format!(
                    "proposer's current role '{}' is no longer administrative — stale proposal refused",
                    proposer_role_now.id()
                ),
            });
        }
        if !proposer_role_now.sod_separated_from(approver_role_now) {
            return Err(AuthError::SodViolation {
                why: format!(
                    "proposer's CURRENT role '{}' and approver '{}' are no longer a separated pair",
                    proposer_role_now.id(),
                    approver_role_now.id()
                ),
            });
        }

        // Passed the gate — commit.
        let outcome = match &change.kind {
            ChangeKind::Enroll(e) => {
                let previous = self.enrollments_mut().enroll(e.clone());
                // Rotation revocation: if this enroll REPLACED an enrollment
                // whose wallet key differs, every session and pending
                // challenge minted under the old key is invalidated NOW —
                // a rotated-out (possibly compromised) key must not keep an
                // authenticated session alive until its TTL. (Before this fix
                // pre-rotation sessions survived a key rotation untouched.)
                let mut sessions_revoked = 0;
                if let Some(prev) = &previous {
                    if prev.public_key != e.public_key {
                        sessions_revoked = self.revoke_sessions_for(&e.org_id, &e.user_id);
                        self.purge_challenges_for(&e.org_id, &e.user_id);
                    }
                }
                CommitOutcome {
                    change_id: change.id.clone(),
                    summary: change.summary.clone(),
                    applied: true,
                    rotated: previous.is_some(),
                    sessions_revoked,
                }
            }
            ChangeKind::Offboard { org_id, user_id } => {
                let sessions_before = self.live_session_count(Utc::now().timestamp());
                let removed = self.offboard_and_revoke(org_id, user_id);
                let sessions_after = self.live_session_count(Utc::now().timestamp());
                CommitOutcome {
                    change_id: change.id.clone(),
                    summary: change.summary.clone(),
                    applied: removed,
                    rotated: false,
                    sessions_revoked: sessions_before.saturating_sub(sessions_after),
                }
            }
        };

        self.pending.remove(change_id);
        Ok(outcome)
    }

    /// REJECT (discard) a pending change through a live session (the
    /// production path). The rejecting identity is resolved from the session
    /// store (unexpired, unrevoked, reaped like `authorize` step 1) and its
    /// role re-read from the CURRENT enrollment — see
    /// [`AuthServer::reject_change`] for the gate itself.
    pub fn reject_change_by_session(
        &mut self,
        session_id: &str,
        change_id: &str,
        now: i64,
    ) -> Result<bool, AuthError> {
        let actor = self.control_actor_by_session(session_id, now)?;
        self.reject_change(&actor, change_id)
    }

    /// REJECT (discard) a pending change without applying it. Rejection is
    /// itself a privileged control action: the rejecter's role is **read from
    /// the live enrollment store** and must be an admin ([`Role::is_admin`]),
    /// mirroring the approve gate — a business role (or anyone merely
    /// *claiming* an admin role in the request) must not be able to silently
    /// drop another admin's staged change. Either side of the wall may reject
    /// (killing a proposal needs one admin, committing one needs two).
    ///
    /// REGRESSION NOTE: this gate used to trust the caller-claimed
    /// `rejecter.role` — a never-enrolled caller self-asserting an admin role
    /// could drop any pending dual-control change. The role is now read
    /// server-side on BOTH this legacy path and the session-bound path; only
    /// the rejecter's *identity* comes from the caller here (bootstrap/test
    /// seam — production rejects go through
    /// [`AuthServer::reject_change_by_session`]).
    ///
    /// Returns `Ok(true)` if a pending change was removed, `Ok(false)` if no
    /// change with that id exists, and `Err(AuthError::NotAuthorized)` for an
    /// unenrolled or non-admin caller (fail-closed, the queue is untouched).
    pub fn reject_change(&mut self, rejecter: &User, change_id: &str) -> Result<bool, AuthError> {
        // The rejecter's role is read from the live enrollment store; the role
        // claimed in the request is never trusted for authorization.
        let rejecter_role_now = match self.enrollments.get(&rejecter.org_id, &rejecter.user_id) {
            Some(e) => e.role,
            None => {
                return Err(AuthError::NotAuthorized {
                    who: rejecter.user_id.clone(),
                    why: "rejecter is not enrolled — role claims in the request are not trusted"
                        .into(),
                })
            }
        };
        if !rejecter_role_now.is_admin() {
            return Err(AuthError::NotAuthorized {
                who: rejecter.user_id.clone(),
                why: format!(
                    "rejecter's current enrolled role '{}' is not administrative — only an \
                     IT-admin or compliance-officer may reject a pending change",
                    rejecter_role_now.id()
                ),
            });
        }
        Ok(self.pending.remove(change_id).is_some())
    }
}

/// The result of committing a dual-control change — enough for the audit trail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitOutcome {
    pub change_id: String,
    pub summary: String,
    /// True if the underlying mutation took effect (enroll always; offboard only
    /// if an enrollment existed to remove).
    pub applied: bool,
    /// True if an enroll replaced a prior enrollment (a key/role rotation).
    pub rotated: bool,
    /// How many live sessions the change revoked (offboard, or an enroll that
    /// rotated the wallet key — old-key sessions are invalidated on rotation).
    pub sessions_revoked: usize,
}

fn new_change_id() -> String {
    let mut b = [0u8; 16];
    rand::rng().fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enroll::{Enrollment, EnrollmentStore};
    use crate::error::AuthError;
    use crate::org::Role;
    use crate::server::Session;

    const NOW: i64 = 1_800_000_000;

    fn enrollment(user_id: &str, role: Role) -> Enrollment {
        Enrollment {
            org_id: "acme".into(),
            user_id: user_id.into(),
            role,
            clearance: 5,
            // Public key bytes only — these tests mint sessions directly and
            // never drive the PQ login (that is covered by the lib.rs e2e).
            public_key: vec![0xC0],
        }
    }

    fn server_with_admins() -> AuthServer {
        let mut store = EnrollmentStore::new();
        store.enroll(enrollment("ivan", Role::ItAdmin));
        store.enroll(enrollment("carol", Role::ComplianceOfficer));
        AuthServer::new(store)
    }

    /// Mint + store a session for an enrolled user directly (same shape
    /// `verify_response` mints), bypassing the heavyweight PQ login.
    fn mint_session(server: &mut AuthServer, user_id: &str, now: i64) -> Session {
        let e = server.enrollments.get("acme", user_id).unwrap().clone();
        let session = Session {
            id: format!("test-session-{user_id}-{now}"),
            org_id: e.org_id.clone(),
            user: e.user(),
            role: e.role,
            issued_at: now,
            expires_at: now + server.session_ttl_secs,
        };
        server.sessions.insert(session.id.clone(), session.clone());
        session
    }

    fn stage_enroll_dave() -> ChangeKind {
        ChangeKind::Enroll(enrollment("dave", Role::FinanceAnalyst))
    }

    #[test]
    fn session_bound_dual_control_proposes_approves_and_rejects() {
        let mut server = server_with_admins();
        let it = mint_session(&mut server, "ivan", NOW);
        let comp = mint_session(&mut server, "carol", NOW);

        // Propose via ivan's session; self-approval via the SAME session (and
        // any other session of the same user) is refused — two-person rule.
        let id = server
            .propose_change_by_session(&it.id, stage_enroll_dave(), NOW)
            .unwrap();
        assert!(matches!(
            server.approve_change_by_session(&it.id, &id, NOW),
            Err(AuthError::DualControl { .. })
        ));
        // The separated admin's session commits it.
        let outcome = server.approve_change_by_session(&comp.id, &id, NOW).unwrap();
        assert!(outcome.applied);
        assert!(server.enrollments.get("acme", "dave").is_some());

        // Reject via session: carol stages, ivan's session rejects it.
        let id2 = server
            .propose_change_by_session(
                &comp.id,
                ChangeKind::Offboard { org_id: "acme".into(), user_id: "dave".into() },
                NOW,
            )
            .unwrap();
        assert_eq!(server.reject_change_by_session(&it.id, &id2, NOW), Ok(true));
        assert!(server.pending_change(&id2).is_none());
        assert!(server.enrollments.get("acme", "dave").is_some(), "reject applied nothing");
    }

    #[test]
    fn revoked_or_expired_session_cannot_drive_the_control_plane() {
        let mut server = server_with_admins();

        // Revoked: the held id is refused for all three control verbs.
        let it = mint_session(&mut server, "ivan", NOW);
        let comp = mint_session(&mut server, "carol", NOW);
        let staged = server
            .propose_change_by_session(&comp.id, stage_enroll_dave(), NOW)
            .unwrap();
        assert!(server.revoke_session(&it.id));
        assert!(matches!(
            server.propose_change_by_session(&it.id, stage_enroll_dave(), NOW),
            Err(AuthError::SessionInvalid { .. })
        ));
        assert!(matches!(
            server.approve_change_by_session(&it.id, &staged, NOW),
            Err(AuthError::SessionInvalid { .. })
        ));
        assert!(matches!(
            server.reject_change_by_session(&it.id, &staged, NOW),
            Err(AuthError::SessionInvalid { .. })
        ));
        assert!(server.pending_change(&staged).is_some(), "queue untouched (fail-closed)");

        // Expired: refused AND reaped, exactly like `authorize` step 1.
        let it2 = mint_session(&mut server, "ivan", NOW);
        let after_expiry = it2.expires_at + 1;
        assert!(matches!(
            server.propose_change_by_session(&it2.id, stage_enroll_dave(), after_expiry),
            Err(AuthError::SessionInvalid { .. })
        ));
        assert!(!server.sessions.contains_key(&it2.id), "expired session was reaped");
        assert!(server.enrollments.get("acme", "dave").is_none(), "nothing was committed");
    }

    #[test]
    fn offboarded_admins_held_session_cannot_drive_the_control_plane() {
        // Raw enrollment drop (bypassing offboard_and_revoke) so the session
        // entry survives in the store: the control plane still refuses the
        // held id fail-closed and revokes the orphaned session.
        let mut server = server_with_admins();
        let it = mint_session(&mut server, "ivan", NOW);
        let comp = mint_session(&mut server, "carol", NOW);
        let staged = server
            .propose_change_by_session(&comp.id, stage_enroll_dave(), NOW)
            .unwrap();

        server.enrollments.offboard("acme", "ivan");
        assert!(server.sessions.contains_key(&it.id), "orphaned session survived the raw drop");
        assert!(matches!(
            server.approve_change_by_session(&it.id, &staged, NOW),
            Err(AuthError::SessionInvalid { .. })
        ));
        assert!(!server.sessions.contains_key(&it.id), "orphaned session revoked on use");
        assert!(matches!(
            server.propose_change_by_session(&it.id, stage_enroll_dave(), NOW),
            Err(AuthError::SessionInvalid { .. })
        ));
        assert!(matches!(
            server.reject_change_by_session(&it.id, &staged, NOW),
            Err(AuthError::SessionInvalid { .. })
        ));
        assert!(server.pending_change(&staged).is_some(), "queue untouched (fail-closed)");
        assert!(server.enrollments.get("acme", "dave").is_none(), "nothing was committed");
    }

    #[test]
    fn demoted_admins_live_session_is_refused_with_its_current_role() {
        // ivan is demoted to a business role AFTER his session was minted. The
        // session id is still live, but the acting role is re-read from the
        // CURRENT enrollment — the login-time admin snapshot never speaks.
        let mut server = server_with_admins();
        let it = mint_session(&mut server, "ivan", NOW);
        let comp = mint_session(&mut server, "carol", NOW);
        let staged = server
            .propose_change_by_session(&comp.id, stage_enroll_dave(), NOW)
            .unwrap();

        server.enrollments.enroll(enrollment("ivan", Role::Engineer)); // demotion
        assert!(matches!(
            server.propose_change_by_session(&it.id, stage_enroll_dave(), NOW),
            Err(AuthError::NotAuthorized { .. })
        ));
        assert!(matches!(
            server.approve_change_by_session(&it.id, &staged, NOW),
            Err(AuthError::NotAuthorized { .. })
        ));
        assert!(matches!(
            server.reject_change_by_session(&it.id, &staged, NOW),
            Err(AuthError::NotAuthorized { .. })
        ));
        assert!(server.pending_change(&staged).is_some(), "queue untouched (fail-closed)");
        assert!(server.enrollments.get("acme", "dave").is_none(), "nothing was committed");
    }
}
