//! The relying-party (server) side: issue challenges, verify responses with the
//! REAL PQ verifier, mint sessions, and guard against replay.
//!
//! `verify_response` is the heart of wallet-as-login. It does NOT contain any
//! cryptography of its own — the signature check is delegated to
//! [`bloch_crypto::crypto::verify`], the same hybrid Falcon ‖ ML-DSA verifier the
//! Bloch-SIS node runs on its consensus path. This crate deliberately does not
//! roll new crypto.
//!
//! ## Production hardening landed here (was MVP-stub in the reference)
//! - **Sessions**: a successful login mints a [`Session`] with a random 128-bit
//!   id and a TTL, tracked in the server's session store; expired sessions are
//!   rejected and swept. (Was: `Session{user, role}` with no id/TTL.)
//! - **Nonce TTL sweep**: issued nonces carry their expiry and the owning
//!   `(org,user)`; [`AuthServer::sweep`] drops expired/aged entries so the store
//!   is bounded, and offboarding can purge a user's live challenges.
//! - **Offboard invalidates live state**: [`AuthServer::offboard_and_revoke`]
//!   removes the enrollment AND revokes every live session, pending challenge,
//!   and staged dual-control proposal of that user — a departing employee's key
//!   is dead immediately and their stale proposals cannot later be committed.
//! - **Access gate enforced at runtime**: [`AuthServer::authorize`] gates a
//!   volume access by SESSION ID against live server state — session must be
//!   unexpired and unrevoked, the user must STILL be enrolled, and the
//!   RBAC+ABAC check runs against the CURRENT enrollment, never the
//!   login-time snapshot inside a held [`Session`]. (Was: callers applied
//!   `rbac_check(session.user, vol)` themselves — an honor system a revoked,
//!   offboarded, or downgraded user's stale `Session` copy would pass.)
//! - **Pending-change max age**: a staged dual-control change carries a TTL
//!   ([`DEFAULT_PENDING_CHANGE_TTL_SECS`], configurable via
//!   [`AuthServer::with_pending_change_ttl`]) — enforced fail-closed at approve
//!   time and reaped by [`AuthServer::sweep`].
//! - **Dynamic Brewer–Nash wall on data access**: the wall used to exist only
//!   on the control action (proposer/approver separation). [`AuthServer::authorize`]
//!   now also enforces it on the DATA path: the first dataset a user is
//!   granted in a [`Volume::coi_class`] binds them, and a later request for a
//!   competing dataset in the same class is denied fail-closed. The
//!   per-(org,user) binding history is bounded
//!   ([`MAX_COI_CLASS_BINDINGS_PER_USER`]), purged by
//!   [`AuthServer::offboard_and_revoke`], and persisted in the
//!   [`crate::persist`] snapshot so the wall survives a restart.
//!
//! Durability (persist the stores across a restart / behind Postgres-Redis) is
//! provided by the snapshot/restore seam in [`crate::persist`]; enrollment and
//! change-control mutations flow through the dual-control gate in
//! [`crate::control`], which enforces the declared Brewer–Nash separation.

use std::collections::HashMap;

use chrono::Utc;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::challenge::{Challenge, Response, DEFAULT_TTL_SECS};
use crate::control::PendingChange;
use crate::enroll::EnrollmentStore;
use crate::error::AuthError;
use crate::org::{rbac_check, AccessDecision, Role, User, Volume};

/// Default session lifetime, in seconds (1 hour). A session is a short-lived
/// bearer of an authenticated identity; re-authentication re-mints it. Kept
/// short so a leaked session id ages out quickly even without explicit revoke.
pub const DEFAULT_SESSION_TTL_SECS: i64 = 3600;

/// How long a *consumed* nonce is remembered after it is spent, so the replay
/// guard still bites a replayed-but-recent nonce. Two challenge lifetimes is
/// ample: past that the freshness (expiry) check already rejects the challenge.
pub const CONSUMED_RETENTION_SECS: i64 = DEFAULT_TTL_SECS * 2;

/// Default max age of a staged dual-control change, in seconds (72 hours).
/// A proposal the second admin has not approved within this window is stale:
/// the org context it was proposed under may no longer hold, so it is refused
/// at approve time (fail-closed) and reaped by [`AuthServer::sweep`] — a
/// months-old proposal can never be committed. Server config (like
/// `session_ttl_secs`), not persisted state: override with
/// [`AuthServer::with_pending_change_ttl`].
pub const DEFAULT_PENDING_CHANGE_TTL_SECS: i64 = 72 * 3600;

/// Maximum number of DISTINCT conflict-of-interest classes one `(org, user)`
/// principal may hold live wall bindings in. Keeps the wall history bounded
/// (it is persisted state); once a user is at capacity a request that would
/// bind a NEW class is denied fail-closed rather than growing the store —
/// clearing history is an offboarding (re-onboarding) event, by design.
pub const MAX_COI_CLASS_BINDINGS_PER_USER: usize = 64;

/// An authenticated session — what a successful login yields. Carries a random
/// id + TTL and is bound to the org/user/role so a caller can apply the RBAC
/// gate ([`crate::org::rbac_check`]) and later validate/revoke by id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    /// Random 128-bit session id (hex). The bearer token of this session.
    pub id: String,
    /// The org this session is scoped to.
    pub org_id: String,
    /// The authenticated user (identity + role + clearance).
    pub user: User,
    /// The user's role, mirrored for convenience.
    pub role: Role,
    /// Unix seconds when the session was minted.
    pub issued_at: i64,
    /// Unix seconds after which the session is stale and MUST be rejected.
    pub expires_at: i64,
}

impl Session {
    /// True once `now` (unix seconds) is past `expires_at`.
    pub fn is_expired(&self, now: i64) -> bool {
        now > self.expires_at
    }
}

/// A live, not-yet-consumed challenge nonce: bound to its owner so offboarding
/// can purge it, and carrying its expiry so the sweep can bound the store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedNonce {
    pub org_id: String,
    pub user_id: String,
    pub expires_at: i64,
}

/// The verifier. Owns the enrollment directory, the live/consumed nonce stores
/// (the replay guard), the session store, and the dual-control change queue.
///
/// All state is snapshot/restore-able via [`crate::persist`] so a real
/// deployment can back it with Postgres/Redis and survive a restart. The
/// anti-replay LOGIC (single-use nonce, retired on consumption) and the PQ
/// verification are real.
pub struct AuthServer {
    pub(crate) enrollments: EnrollmentStore,
    /// Nonces handed out and not yet consumed: nonce -> owner + expiry.
    pub(crate) issued: HashMap<[u8; 32], IssuedNonce>,
    /// Nonces already spent: nonce -> unix-seconds consumed. A second
    /// presentation is a replay until swept (after `CONSUMED_RETENTION_SECS`).
    pub(crate) consumed: HashMap<[u8; 32], i64>,
    /// Live sessions: id -> Session.
    pub(crate) sessions: HashMap<String, Session>,
    /// Pending dual-control changes: id -> PendingChange.
    pub(crate) pending: HashMap<String, PendingChange>,
    /// Session lifetime for newly minted sessions.
    pub(crate) session_ttl_secs: i64,
    /// Max age of a staged dual-control change before it is refused/reaped.
    pub(crate) pending_change_ttl_secs: i64,
    /// Dynamic Brewer–Nash wall history: `(org, user)` -> `coi_class` -> the
    /// dataset that user is bound to in that class (first granted access
    /// binds). Bounded per principal by [`MAX_COI_CLASS_BINDINGS_PER_USER`],
    /// purged on offboard, snapshot/restored via [`crate::persist`].
    pub(crate) coi_history: HashMap<(String, String), HashMap<String, String>>,
}

impl AuthServer {
    pub fn new(enrollments: EnrollmentStore) -> Self {
        Self {
            enrollments,
            issued: HashMap::new(),
            consumed: HashMap::new(),
            sessions: HashMap::new(),
            pending: HashMap::new(),
            session_ttl_secs: DEFAULT_SESSION_TTL_SECS,
            pending_change_ttl_secs: DEFAULT_PENDING_CHANGE_TTL_SECS,
            coi_history: HashMap::new(),
        }
    }

    /// Override the session TTL (seconds). Chainable.
    pub fn with_session_ttl(mut self, secs: i64) -> Self {
        self.session_ttl_secs = secs;
        self
    }

    /// Override the pending-change max age (seconds). Chainable. Server config,
    /// like the session TTL — not part of the persisted snapshot schema.
    pub fn with_pending_change_ttl(mut self, secs: i64) -> Self {
        self.pending_change_ttl_secs = secs;
        self
    }

    /// Read access to the enrollment directory.
    pub fn enrollments(&self) -> &EnrollmentStore {
        &self.enrollments
    }

    /// Mutable access to the enrollment directory.
    ///
    /// NOTE: direct mutation bypasses dual-control. Production enroll/offboard
    /// should go through [`AuthServer::propose_change`] +
    /// [`AuthServer::approve_change`] (dual-control + Brewer–Nash SoD). This
    /// accessor exists for bootstrap (seeding the first admins) and tests.
    pub fn enrollments_mut(&mut self) -> &mut EnrollmentStore {
        &mut self.enrollments
    }

    /// Issue a fresh challenge for `(org, user)`. The nonce is registered as
    /// live (with its owner + expiry) so exactly one matching response can later
    /// consume it, and so offboarding can purge it.
    pub fn issue_challenge(&mut self, org_id: &str, user_id: &str) -> Challenge {
        let mut nonce = [0u8; 32];
        rand::rng().fill_bytes(&mut nonce);

        let now = Utc::now().timestamp();
        let expires_at = now + DEFAULT_TTL_SECS;
        self.issued.insert(
            nonce,
            IssuedNonce {
                org_id: org_id.to_string(),
                user_id: user_id.to_string(),
                expires_at,
            },
        );

        Challenge {
            org_id: org_id.to_string(),
            user_id: user_id.to_string(),
            nonce,
            issued_at: now,
            expires_at,
        }
    }

    /// Verify a wallet's [`Response`] against the challenge it answers.
    ///
    /// Order of checks (fail closed at each step):
    ///   1. the user is enrolled;
    ///   2. the presented pubkey equals the enrolled pubkey (identity binding);
    ///   3. the challenge has not expired;
    ///   4. the nonce is live and not already consumed (replay guard);
    ///   5. the hybrid PQ signature verifies over the challenge transcript —
    ///      via the REAL `bloch_crypto::crypto::verify`.
    ///
    /// On success the nonce is retired (moved from `issued` → `consumed`) so it
    /// can never be replayed, a [`Session`] is minted with a random id + TTL and
    /// stored, and that session is returned.
    pub fn verify_response(
        &mut self,
        challenge: &Challenge,
        response: &Response,
    ) -> Result<Session, AuthError> {
        // (1) enrolled?
        let enrollment = self
            .enrollments
            .get(&response.org_id, &response.user_id)
            .ok_or_else(|| AuthError::NotEnrolled {
                org_id: response.org_id.clone(),
                user_id: response.user_id.clone(),
            })?
            .clone();

        // (2) identity binding: presented key must be the enrolled key.
        if response.public_key != enrollment.public_key {
            return Err(AuthError::WrongKey);
        }

        // (3) freshness.
        let now = Utc::now().timestamp();
        if challenge.is_expired(now) {
            return Err(AuthError::Expired);
        }

        // (4) replay guard. The nonce in the response must match the challenge,
        //     be live, and not already spent.
        if response.nonce != challenge.nonce {
            return Err(AuthError::UnknownNonce);
        }
        if self.consumed.contains_key(&challenge.nonce) {
            return Err(AuthError::Replay);
        }
        if !self.issued.contains_key(&challenge.nonce) {
            return Err(AuthError::UnknownNonce);
        }

        // (5) THE REAL PQ CHECK — hybrid Falcon ‖ ML-DSA, not our own crypto.
        let transcript = challenge.transcript();
        let ok = bloch_crypto::crypto::verify(
            &response.public_key,
            &transcript,
            &response.signature,
        );
        if !ok {
            // Do NOT retire the nonce on a bad signature — a failed attempt must
            // not burn the user's challenge.
            return Err(AuthError::BadSignature);
        }

        // Success: retire the nonce so it can never be presented again.
        self.issued.remove(&challenge.nonce);
        self.consumed.insert(challenge.nonce, now);

        // Mint + store a session with a random id and a TTL.
        let session = Session {
            id: new_session_id(),
            org_id: enrollment.org_id.clone(),
            user: enrollment.user(),
            role: enrollment.role,
            issued_at: now,
            expires_at: now + self.session_ttl_secs,
        };
        self.sessions.insert(session.id.clone(), session.clone());
        Ok(session)
    }

    /// Look up a live session by id, returning it only if it exists AND has not
    /// expired at `now`. Fail-closed: an expired or unknown id yields `None`.
    pub fn session(&self, id: &str, now: i64) -> Option<&Session> {
        self.sessions.get(id).filter(|s| !s.is_expired(now))
    }

    /// Validate + reap: like [`AuthServer::session`] but drops an expired session
    /// from the store as a side effect. Returns a clone of the live session.
    pub fn validate_session(&mut self, id: &str, now: i64) -> Option<Session> {
        match self.sessions.get(id) {
            Some(s) if s.is_expired(now) => {
                self.sessions.remove(id);
                None
            }
            Some(s) => Some(s.clone()),
            None => None,
        }
    }

    /// The ACCESS gate, enforced server-side at access time — replaces the
    /// caller honor-system of applying [`rbac_check`] to a held [`Session`]
    /// snapshot. A `Session` carries a login-time CLONE of the user; this
    /// method never trusts it. Fail-closed, in order:
    ///
    ///   1. the session id must be known and unexpired at `now` — an expired
    ///      entry is reaped (like [`AuthServer::validate_session`]) and a
    ///      revoked/unknown id is refused, so a kept copy of an old `Session`
    ///      struct is worthless once its id is dead;
    ///   2. the session's `(org, user)` must STILL be enrolled — an offboarded
    ///      user's surviving session (e.g. enrollment dropped directly,
    ///      bypassing [`AuthServer::offboard_and_revoke`]) is revoked here and
    ///      refused;
    ///   3. [`rbac_check`] is applied to the CURRENT enrollment's role +
    ///      clearance (via [`crate::enroll::Enrollment::user`]), never the
    ///      login-time snapshot — a role/clearance change since login takes
    ///      effect at the very next access;
    ///   4. the **dynamic Brewer–Nash wall**: if the volume carries a
    ///      [`Volume::coi_class`], the first GRANTED access binds this user to
    ///      that class's dataset ([`Volume::dataset_id`]); a later request for
    ///      a DIFFERENT dataset in the SAME class is denied with a reasoned
    ///      [`AccessDecision`] (fail-closed). Same-dataset re-access and
    ///      volumes in other classes (or with no class) are unaffected. A
    ///      denied request never binds. The history is bounded
    ///      ([`MAX_COI_CLASS_BINDINGS_PER_USER`]) — at capacity a NEW class
    ///      binding is denied rather than grown — is purged by
    ///      [`AuthServer::offboard_and_revoke`], and rides the
    ///      [`crate::persist`] snapshot so a restart cannot reset the wall.
    ///
    /// `Err` means "no valid session — nothing to decide"; `Ok(decision)` is
    /// the live RBAC+ABAC (+ wall) verdict (which may itself deny).
    ///
    /// Honesty: this is a userland enforcement point, not a kernel boundary;
    /// unaudited reference prototype. It gates what THIS server hands out —
    /// it cannot stop a caller who already holds the bytes.
    pub fn authorize(
        &mut self,
        session_id: &str,
        vol: &Volume,
        now: i64,
    ) -> Result<AccessDecision, AuthError> {
        // (1) session id must be live: unknown/revoked refused; expired reaped.
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

        // (2) the owner must STILL be enrolled — offboarded means dead now.
        let Some(enrollment) = self
            .enrollments
            .get(&session.org_id, &session.user.user_id)
        else {
            self.sessions.remove(session_id);
            return Err(AuthError::SessionInvalid {
                why: "user no longer enrolled — session revoked".into(),
            });
        };

        // (3) gate against the CURRENT enrollment, never the login snapshot.
        let decision = rbac_check(&enrollment.user(), vol);
        if !decision.ok {
            // RBAC/ABAC already denies — and a denied request must NOT bind
            // the user to this dataset in the wall history.
            return Ok(decision);
        }

        // (4) dynamic Brewer–Nash wall: first granted dataset in a class binds.
        if let Some(class) = &vol.coi_class {
            let principal = (session.org_id.clone(), session.user.user_id.clone());
            let dataset = vol.dataset_id().to_string();
            let bindings = self.coi_history.entry(principal).or_default();
            match bindings.get(class) {
                // Bound to a COMPETING dataset in this class — fail-closed.
                Some(bound) if *bound != dataset => {
                    return Ok(AccessDecision::deny(format!(
                        "Brewer–Nash conflict of interest: already bound to dataset \
                         '{bound}' in class '{class}' — access to competing dataset \
                         '{dataset}' denied"
                    )));
                }
                // Same dataset as the existing binding — allowed.
                Some(_) => {}
                // First granted access in this class: bind, bounded fail-closed.
                None => {
                    if bindings.len() >= MAX_COI_CLASS_BINDINGS_PER_USER {
                        return Ok(AccessDecision::deny(format!(
                            "conflict-of-interest history at capacity \
                             ({MAX_COI_CLASS_BINDINGS_PER_USER} classes) for this user — \
                             new binding in class '{class}' refused (fail-closed)"
                        )));
                    }
                    bindings.insert(class.clone(), dataset);
                }
            }
        }

        Ok(decision)
    }

    /// The dataset `(org, user)` is wall-bound to in `coi_class`, if any.
    /// Read-only observability for consoles/tests; binding happens only inside
    /// [`AuthServer::authorize`] on a granted access.
    pub fn coi_binding(&self, org_id: &str, user_id: &str, coi_class: &str) -> Option<&str> {
        self.coi_history
            .get(&(org_id.to_string(), user_id.to_string()))
            .and_then(|classes| classes.get(coi_class))
            .map(String::as_str)
    }

    /// Explicitly revoke a single session by id (e.g. logout).
    pub fn revoke_session(&mut self, id: &str) -> bool {
        self.sessions.remove(id).is_some()
    }

    /// Revoke every live session for `(org, user)`. Returns the count revoked.
    /// Used by offboarding so a departing user is logged out everywhere at once.
    pub fn revoke_sessions_for(&mut self, org_id: &str, user_id: &str) -> usize {
        let before = self.sessions.len();
        self.sessions
            .retain(|_, s| !(s.org_id == org_id && s.user.user_id == user_id));
        before - self.sessions.len()
    }

    /// Purge every live (issued, unconsumed) challenge for `(org, user)`.
    /// Returns the count purged.
    pub fn purge_challenges_for(&mut self, org_id: &str, user_id: &str) -> usize {
        let before = self.issued.len();
        self.issued
            .retain(|_, n| !(n.org_id == org_id && n.user_id == user_id));
        before - self.issued.len()
    }

    /// Purge every pending dual-control change PROPOSED BY `(org, user)`.
    /// Returns the count purged. Used by offboarding: an offboarded admin's
    /// staged proposals must not remain approvable after they leave.
    pub fn purge_pending_proposed_by(&mut self, org_id: &str, user_id: &str) -> usize {
        let before = self.pending.len();
        self.pending
            .retain(|_, c| !(c.proposer.org_id == org_id && c.proposer.user_id == user_id));
        before - self.pending.len()
    }

    /// Offboard a user: remove the enrollment AND immediately invalidate every
    /// live session, pending challenge, staged dual-control proposal, and
    /// Brewer–Nash wall binding of theirs. This is the production offboarding
    /// invariant — a removed key cannot log in, any open session is killed, a
    /// stale proposal of the departed admin cannot later be committed, and the
    /// wall history does not accumulate for principals who no longer exist (a
    /// RE-onboarded user starts with a clean conflict slate, which the org's
    /// onboarding diligence — not this crate — must vouch for). Returns whether
    /// an enrollment was actually removed.
    ///
    /// Direct offboarding bypasses dual-control; the guarded path is
    /// `propose_change(ChangeKind::Offboard{..})` + `approve_change(..)`.
    pub fn offboard_and_revoke(&mut self, org_id: &str, user_id: &str) -> bool {
        let removed = self.enrollments.offboard(org_id, user_id).is_some();
        self.revoke_sessions_for(org_id, user_id);
        self.purge_challenges_for(org_id, user_id);
        self.purge_pending_proposed_by(org_id, user_id);
        self.coi_history
            .remove(&(org_id.to_string(), user_id.to_string()));
        removed
    }

    /// Sweep expired/aged transient state: live nonces past their expiry,
    /// consumed nonces past the retention window, expired sessions, and
    /// pending dual-control changes past the pending-change max age. A
    /// long-running server should call this periodically (or a TTL store does it
    /// natively). Returns the total number of entries dropped.
    pub fn sweep(&mut self, now: i64) -> usize {
        let mut dropped = 0;

        let before = self.issued.len();
        self.issued.retain(|_, n| n.expires_at >= now);
        dropped += before - self.issued.len();

        let before = self.consumed.len();
        self.consumed
            .retain(|_, &mut ts| now - ts <= CONSUMED_RETENTION_SECS);
        dropped += before - self.consumed.len();

        let before = self.sessions.len();
        self.sessions.retain(|_, s| !s.is_expired(now));
        dropped += before - self.sessions.len();

        let pending_ttl = self.pending_change_ttl_secs;
        let before = self.pending.len();
        self.pending.retain(|_, c| now - c.created_at <= pending_ttl);
        dropped += before - self.pending.len();

        dropped
    }

    /// Number of live sessions (post any expiry, without sweeping).
    pub fn live_session_count(&self, now: i64) -> usize {
        self.sessions.values().filter(|s| !s.is_expired(now)).count()
    }
}

/// A fresh random 128-bit session id, hex-encoded.
fn new_session_id() -> String {
    let mut b = [0u8; 16];
    rand::rng().fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enroll::Enrollment;

    const NOW: i64 = 1_800_000_000;

    fn enrolled_server() -> AuthServer {
        let mut store = EnrollmentStore::new();
        store.enroll(Enrollment {
            org_id: "acme".into(),
            user_id: "alice".into(),
            role: Role::Engineer,
            clearance: 3,
            // Public key bytes only — these tests exercise the access gate,
            // never the PQ login path (that is covered by the lib.rs e2e tests).
            public_key: vec![0xA1],
        });
        AuthServer::new(store)
    }

    /// Mint + store a session for alice directly (same shape `verify_response`
    /// mints), bypassing the heavyweight PQ login so the gate tests are fast.
    fn mint_session(server: &mut AuthServer, now: i64) -> Session {
        let e = server.enrollments.get("acme", "alice").unwrap().clone();
        let session = Session {
            id: new_session_id(),
            org_id: e.org_id.clone(),
            user: e.user(),
            role: e.role,
            issued_at: now,
            expires_at: now + server.session_ttl_secs,
        };
        server.sessions.insert(session.id.clone(), session.clone());
        session
    }

    fn eng_vol(clearance: u8) -> Volume {
        Volume::new("repo", "engineering", clearance)
    }

    /// An engineering volume carrying a competing dataset in the
    /// `audit-clients` conflict-of-interest class.
    fn coi_vol(dataset: &str) -> Volume {
        Volume::new(format!("vol-{dataset}"), "engineering", 2).with_coi("audit-clients", dataset)
    }

    #[test]
    fn authorize_happy_path_allows() {
        let mut server = enrolled_server();
        let session = mint_session(&mut server, NOW);
        let decision = server.authorize(&session.id, &eng_vol(2), NOW).unwrap();
        assert!(decision.ok, "enrolled engineer with clearance 3 reads a floor-2 engineering volume");

        // The live verdict still denies out-of-family volumes — authorize is a
        // gate, not a rubber stamp.
        let fin = Volume::new("ledger", "finance", 2);
        assert!(!server.authorize(&session.id, &fin, NOW).unwrap().ok);
    }

    #[test]
    fn revoked_session_cannot_authorize() {
        let mut server = enrolled_server();
        let session = mint_session(&mut server, NOW);
        assert!(server.authorize(&session.id, &eng_vol(2), NOW).unwrap().ok);

        assert!(server.revoke_session(&session.id));
        // The caller still HOLDS the Session struct — rbac_check on the
        // snapshot would happily allow — but the server refuses the dead id.
        assert!(rbac_check(&session.user, &eng_vol(2)).ok, "stale snapshot would allow");
        assert!(matches!(
            server.authorize(&session.id, &eng_vol(2), NOW),
            Err(AuthError::SessionInvalid { .. })
        ));
    }

    #[test]
    fn offboarded_users_kept_session_copy_is_dead() {
        let mut server = enrolled_server();
        let session = mint_session(&mut server, NOW);
        let kept_copy = session.clone();

        // Full offboarding path: enrollment gone AND sessions revoked.
        assert!(server.offboard_and_revoke("acme", "alice"));
        assert!(matches!(
            server.authorize(&kept_copy.id, &eng_vol(2), NOW),
            Err(AuthError::SessionInvalid { .. })
        ));

        // Backstop: enrollment dropped DIRECTLY (bypassing offboard_and_revoke)
        // so the session entry survives in the store — authorize still refuses
        // and revokes that orphaned session as a side effect.
        let mut server2 = enrolled_server();
        let s2 = mint_session(&mut server2, NOW);
        server2.enrollments.offboard("acme", "alice");
        assert!(server2.sessions.contains_key(&s2.id), "orphaned session survived the raw offboard");
        assert!(matches!(
            server2.authorize(&s2.id, &eng_vol(2), NOW),
            Err(AuthError::SessionInvalid { .. })
        ));
        assert!(!server2.sessions.contains_key(&s2.id), "authorize revoked the orphaned session");
    }

    #[test]
    fn authorize_reflects_current_enrollment_not_the_login_snapshot() {
        let mut server = enrolled_server();
        let session = mint_session(&mut server, NOW);
        let vol = eng_vol(2);
        assert!(server.authorize(&session.id, &vol, NOW).unwrap().ok);

        // Clearance downgraded 3 -> 1 after login. The stale snapshot still
        // (wrongly) allows; the server-enforced gate denies — this delta IS
        // the enforcement gap being closed.
        server.enrollments.enroll(Enrollment {
            org_id: "acme".into(),
            user_id: "alice".into(),
            role: Role::Engineer,
            clearance: 1,
            public_key: vec![0xA1],
        });
        assert!(rbac_check(&session.user, &vol).ok, "stale snapshot wrongly allows");
        let decision = server.authorize(&session.id, &vol, NOW).unwrap();
        assert!(!decision.ok, "server-enforced gate applies the CURRENT clearance");
        assert!(decision.why.unwrap().contains("clearance"));

        // Role changed Engineer -> FinanceAnalyst: engineering now denied,
        // finance now allowed — again against the CURRENT enrollment.
        server.enrollments.enroll(Enrollment {
            org_id: "acme".into(),
            user_id: "alice".into(),
            role: Role::FinanceAnalyst,
            clearance: 3,
            public_key: vec![0xA1],
        });
        assert!(!server.authorize(&session.id, &vol, NOW).unwrap().ok);
        let fin = Volume::new("ledger", "finance", 2);
        assert!(server.authorize(&session.id, &fin, NOW).unwrap().ok);
    }

    #[test]
    fn expired_session_is_denied_and_reaped() {
        let mut server = enrolled_server();
        let session = mint_session(&mut server, NOW);
        let after_expiry = session.expires_at + 1;
        assert!(matches!(
            server.authorize(&session.id, &eng_vol(2), after_expiry),
            Err(AuthError::SessionInvalid { .. })
        ));
        assert!(!server.sessions.contains_key(&session.id), "expired session was reaped");
    }

    // ----- Dynamic Brewer–Nash wall on data access -----

    #[test]
    fn wall_binds_first_dataset_then_denies_competitors_in_the_same_class() {
        let mut server = enrolled_server();
        let session = mint_session(&mut server, NOW);

        // First granted access to client-a in 'audit-clients' binds alice.
        assert!(server.authorize(&session.id, &coi_vol("client-a"), NOW).unwrap().ok);
        assert_eq!(server.coi_binding("acme", "alice", "audit-clients"), Some("client-a"));

        // A COMPETING dataset in the SAME class is denied with a reason that
        // names the conflict — fail-closed, and the denial does not re-bind.
        let denied = server.authorize(&session.id, &coi_vol("client-b"), NOW).unwrap();
        assert!(!denied.ok);
        let why = denied.why.unwrap();
        assert!(why.contains("conflict of interest"), "reason names the conflict: {why}");
        assert!(why.contains("client-a") && why.contains("client-b"));
        assert_eq!(server.coi_binding("acme", "alice", "audit-clients"), Some("client-a"));

        // Same dataset: still allowed (re-access is not a conflict).
        assert!(server.authorize(&session.id, &coi_vol("client-a"), NOW).unwrap().ok);
        // A different CLASS: independent binding, allowed.
        let other_class =
            Volume::new("deals", "engineering", 2).with_coi("ma-deals", "client-b");
        assert!(server.authorize(&session.id, &other_class, NOW).unwrap().ok);
        // A volume with NO class is outside every wall.
        assert!(server.authorize(&session.id, &eng_vol(2), NOW).unwrap().ok);
    }

    #[test]
    fn wall_does_not_bind_on_an_rbac_denied_request() {
        // An engineer is NOT entitled to finance volumes: the RBAC denial must
        // come back untouched and must NOT bind the class — otherwise a denied
        // probe could lock a user out of the dataset they legitimately get later.
        let mut server = enrolled_server();
        let session = mint_session(&mut server, NOW);
        let fin_coi =
            Volume::new("ledger-a", "finance", 2).with_coi("audit-clients", "client-a");
        assert!(!server.authorize(&session.id, &fin_coi, NOW).unwrap().ok);
        assert_eq!(server.coi_binding("acme", "alice", "audit-clients"), None);

        // She can still bind client-b in that class on her first GRANTED access.
        assert!(server.authorize(&session.id, &coi_vol("client-b"), NOW).unwrap().ok);
        assert_eq!(server.coi_binding("acme", "alice", "audit-clients"), Some("client-b"));
    }

    #[test]
    fn wall_history_is_purged_on_offboard() {
        let mut server = enrolled_server();
        let session = mint_session(&mut server, NOW);
        assert!(server.authorize(&session.id, &coi_vol("client-a"), NOW).unwrap().ok);
        assert_eq!(server.coi_binding("acme", "alice", "audit-clients"), Some("client-a"));

        // Offboarding purges the wall history with everything else.
        assert!(server.offboard_and_revoke("acme", "alice"));
        assert_eq!(server.coi_binding("acme", "alice", "audit-clients"), None);

        // A RE-onboarded alice starts with a clean conflict slate (the org's
        // onboarding diligence owns that decision, not this crate) — her first
        // granted dataset may now be client-b.
        server.enrollments.enroll(Enrollment {
            org_id: "acme".into(),
            user_id: "alice".into(),
            role: Role::Engineer,
            clearance: 3,
            public_key: vec![0xA2],
        });
        let session2 = mint_session(&mut server, NOW);
        assert!(server.authorize(&session2.id, &coi_vol("client-b"), NOW).unwrap().ok);
        assert_eq!(server.coi_binding("acme", "alice", "audit-clients"), Some("client-b"));
    }

    #[test]
    fn wall_history_is_bounded_fail_closed() {
        let mut server = enrolled_server();
        let session = mint_session(&mut server, NOW);

        // Fill alice's history to the cap with distinct classes.
        for i in 0..MAX_COI_CLASS_BINDINGS_PER_USER {
            let vol = Volume::new(format!("vol-{i}"), "engineering", 2)
                .with_coi(format!("class-{i}"), "client-a");
            assert!(server.authorize(&session.id, &vol, NOW).unwrap().ok);
        }
        // A binding in a NEW class is refused fail-closed with a reason...
        let overflow = Volume::new("vol-overflow", "engineering", 2)
            .with_coi("class-overflow", "client-a");
        let denied = server.authorize(&session.id, &overflow, NOW).unwrap();
        assert!(!denied.ok);
        assert!(denied.why.unwrap().contains("capacity"));
        // ...while already-bound classes keep working.
        let bound = Volume::new("vol-0", "engineering", 2).with_coi("class-0", "client-a");
        assert!(server.authorize(&session.id, &bound, NOW).unwrap().ok);
    }
}
