//! # Postern Enterprise — wallet-as-login (Consiglio edition)
//!
//! Org authentication where the **Postern PQ wallet is the identity**. No
//! passwords, no shared secret: the server issues a random challenge, the wallet
//! signs it with its hybrid **Falcon-1024 ‖ ML-DSA-65** key, and the server
//! verifies that signature against the user's **enrolled** public key. Control
//! of the key *is* the login.
//!
//! ## The protocol (challenge / response)
//!
//! ```text
//!   enroll:   (org, user, role, clearance, wallet_pubkey)  ──▶  EnrollmentStore
//!
//!   login:    server ──issue_challenge──▶  Challenge{ org,user,nonce,exp }
//!             wallet ──sign transcript──▶  Response{ pubkey, signature, nonce }
//!             server ──verify_response──▶  Session{ user, role }   (or AuthError)
//!
//!   gate:     rbac_check(session.user, volume)             ──▶  allow / deny
//!             (pure helper over a login-time snapshot — the caller-applied form)
//!
//!             server ──authorize(session.id, volume, now)──▶  allow / deny
//!             (server-ENFORCED: revalidates the session id, re-reads the
//!              CURRENT enrollment at access time — revoke/offboard/downgrade
//!              take effect at the very next access, not the next login — and
//!              applies the DYNAMIC Brewer–Nash wall: the first dataset granted
//!              in a volume's conflict-of-interest class binds the user, and a
//!              competing dataset in the same class is then denied)
//!
//!   control:  server ──propose/approve/reject_change_by_session(session.id, ..)──▶
//!             (the dual-control plane, session-bound: the acting identity is
//!              resolved from the live session store and its role re-read from
//!              the CURRENT enrollment — no caller-supplied User is trusted)
//! ```
//!
//! The signed message is a domain-separated transcript
//! (`consiglio:wallet-login:v1` ‖ org ‖ user ‖ nonce ‖ issued_at), so a login
//! signature can never be replayed as a payment or across orgs.
//!
//! ## This reuses REAL post-quantum crypto — it does not roll its own
//!
//! [`server::AuthServer::verify_response`] delegates the signature check to
//! [`bloch_crypto::crypto::verify`] — the exact hybrid Falcon ‖ ML-DSA verifier
//! the Bloch-SIS node runs on its consensus path. The demo signer
//! ([`client::sign_challenge`]) delegates to `bloch_crypto::crypto::sign`. No
//! bespoke cryptography exists in this crate.
//!
//! ## Honesty — what is real vs still-stub (UNAUDITED reference prototype)
//!
//! Wallet-as-login is **novel and UNAUDITED**. This crate **demonstrates
//! controls that enable compliance; it is NOT compliance** and is not yet a
//! hardened IAM. But the governance controls the reference once merely
//! *declared* are now **runtime-enforced and tested** (`cargo test` green):
//! dual-control, Brewer–Nash separation-of-duty, sessions with
//! TTL/revoke, offboarding invalidation, pending-queue hygiene
//! (server-side admin-gated reject, proposer re-validated at approve,
//! pending-change max age), the access gate itself —
//! [`server::AuthServer::authorize`] enforces RBAC server-side against live
//! state instead of trusting the caller to apply [`rbac_check`] to a stale
//! [`server::Session`] snapshot — plus, as of this iteration, the **dynamic
//! Brewer–Nash wall on data access** (first granted dataset in a
//! conflict-of-interest class binds the user; competing datasets in the same
//! class are then denied, persisted across restarts, purged on offboard) and
//! the **session-bound control plane** (`propose/approve/reject_change_by_session`
//! resolve the acting admin from the live session store and re-read their role
//! from the current enrollment — no caller-supplied `User` struct is trusted).
//! All of it is userland enforcement, not a kernel boundary.
//!
//! | Concern                | Status                                                     |
//! |------------------------|------------------------------------------------------------|
//! | PQ signature verify    | **REAL** — `bloch_crypto::crypto::verify` (Falcon‖ML-DSA)   |
//! | Challenge transcript   | **REAL** — domain-separated SHA3-256                        |
//! | Anti-replay logic      | **REAL** — single-use nonce, retired on consumption        |
//! | Pubkey→user binding    | **REAL** — enrolled key must equal presented key           |
//! | RBAC role gate         | **REAL & server-enforced** — was caller-applied over a login-time `Session` snapshot; [`server::AuthServer::authorize`] now revalidates the session id AND the CURRENT enrollment (role + clearance) at access time, fail-closed. Still mirrors Consiglio `rbacCheck`; still a userland enforcement point, not a kernel boundary — unaudited reference prototype |
//! | Sessions (id+TTL)      | **REAL** — 128-bit id, TTL, `validate`/`revoke`, bounded sweep |
//! | Admin dual-control     | **REAL & session-bound** — two-person `propose`→`approve` gate; the production path (`*_change_by_session`) resolves the acting admin from the live session store and re-reads their role from the CURRENT enrollment — a revoked/expired session or an offboarded/demoted admin's held session id can neither propose, approve, nor reject. The `&User` forms remain as documented bootstrap/test seams |
//! | Brewer–Nash wall / SoD | **REAL, control + data** — approver must be the *separated* admin (`control`); AND `authorize` enforces the DYNAMIC wall on data access: first granted dataset in a `Volume::coi_class` binds the user, competing datasets in the same class are denied fail-closed (bounded history, purged on offboard, snapshot-persisted). Userland enforcement, not a kernel boundary |
//! | Offboard invalidation  | **REAL** — drops enrollment + revokes live sessions/challenges + purges wall history |
//! | Pending-queue hygiene  | **REAL** — reject role read server-side (was: trusted the CLAIMED role — a never-enrolled caller could drop any pending change; closed + regression-tested); proposer re-validated at approve; offboard purges the departed admin's proposals; pending-change max age enforced at approve + swept |
//! | Enrollment store       | in-memory `HashMap`; **durable** via `persist` snapshot/restore seam |
//! | Nonce store            | in-memory; **bounded** by TTL sweep + owner-scoped purge    |
//! | Key custody / signing  | *external* — lives in the wallet / `postern-wallet` CLI    |
//!
//! The in-memory maps are no longer dead-ends: the [`persist`] snapshot/restore
//! seam (proven round-tripping in the tests) is wired to two REAL durable
//! backends in [`store`] — [`store::FileSnapshotStore`] (atomic single-file) and
//! [`store::KvSnapshotStore`] (a KV-blob store over a pluggable
//! [`store::KvBackend`], the injection point for Cloudflare KV / Redis / an
//! object store). Both survive a process restart (`kv_store_round_trips_across_a_restart`,
//! `file_store_round_trips_across_a_restart`). This is real persistence, not a
//! claim; a cloud KV binding is an out-of-crate adapter over the same trait.
//!
//! Feature gates keep it additive: `server` (verifier + stores + dual-control),
//! `client-demo` (the thin signer). Both are on by default.

pub mod challenge;
pub mod enroll;
pub mod error;
pub mod org;

#[cfg(feature = "server")]
pub mod control;
#[cfg(feature = "server")]
pub mod persist;
#[cfg(feature = "server")]
pub mod server;
#[cfg(feature = "server")]
pub mod store;

#[cfg(feature = "client-demo")]
pub mod client;

// Re-exports for the common path.
pub use challenge::{Challenge, Response, LOGIN_DOMAIN};
pub use enroll::{Enrollment, EnrollmentStore};
pub use error::AuthError;
pub use org::{rbac_check, AccessDecision, Org, Role, User, Volume};

#[cfg(feature = "server")]
pub use control::{ChangeKind, CommitOutcome, PendingChange};
#[cfg(feature = "server")]
pub use persist::{schema_supported, CoiBinding, ServerSnapshot, SNAPSHOT_SCHEMA, SNAPSHOT_SCHEMA_V1};
#[cfg(feature = "server")]
pub use server::{AuthServer, IssuedNonce, Session};
#[cfg(feature = "server")]
pub use store::{
    FileSnapshotStore, FsKvBackend, KvBackend, KvSnapshotStore, MemSnapshotStore,
    PersistentAuthServer, SnapshotStore, StoreError,
};

#[cfg(all(test, feature = "server", feature = "client-demo"))]
mod tests {
    use super::*;

    /// End-to-end: enroll a wallet, log in with a real hybrid-PQ signature,
    /// and apply the role gate. Proves the flow uses the real PQ primitives.
    fn setup() -> (AuthServer, Vec<u8>, Vec<u8>) {
        // Real keypair from the real crypto surface (hybrid Falcon ‖ ML-DSA).
        let (pk, sk) = bloch_crypto::crypto::generate_keypair();
        let mut store = EnrollmentStore::new();
        store.enroll(Enrollment {
            org_id: "acme".into(),
            user_id: "alice".into(),
            role: Role::Engineer,
            clearance: 3,
            public_key: pk.clone(),
        });
        (AuthServer::new(store), pk, sk)
    }

    #[test]
    fn happy_path_login_then_role_gate() {
        let (mut server, pk, sk) = setup();
        let challenge = server.issue_challenge("acme", "alice");
        let response = client::sign_challenge(&challenge, &pk, &sk).unwrap();

        let session = server
            .verify_response(&challenge, &response)
            .expect("valid PQ signature should authenticate");
        assert_eq!(session.role, Role::Engineer);

        // Role gate: Engineer may read engineering, not finance.
        let eng = Volume::new("repo", "engineering", 2);
        let fin = Volume::new("ledger", "finance", 2);
        assert!(rbac_check(&session.user, &eng).ok);
        assert!(!rbac_check(&session.user, &fin).ok);
    }

    /// End-to-end enforcement delta: a REAL PQ login mints a session; the gate
    /// applied via `authorize` tracks live server state, while the old
    /// caller-applied `rbac_check`-on-a-snapshot form would keep allowing.
    #[test]
    fn authorize_gates_a_real_login_session_against_live_state() {
        let (mut server, pk, sk) = setup();
        let challenge = server.issue_challenge("acme", "alice");
        let response = client::sign_challenge(&challenge, &pk, &sk).unwrap();
        let session = server.verify_response(&challenge, &response).unwrap();

        let eng = Volume::new("repo", "engineering", 2);
        let now = session.issued_at;
        assert!(server.authorize(&session.id, &eng, now).unwrap().ok);

        // Offboard alice: the held Session struct still snapshot-allows, but
        // the server-enforced gate refuses her kept session id outright.
        assert!(server.offboard_and_revoke("acme", "alice"));
        assert!(rbac_check(&session.user, &eng).ok, "stale snapshot would still allow");
        assert!(matches!(
            server.authorize(&session.id, &eng, now),
            Err(AuthError::SessionInvalid { .. })
        ));
    }

    #[test]
    fn replay_is_rejected() {
        let (mut server, pk, sk) = setup();
        let challenge = server.issue_challenge("acme", "alice");
        let response = client::sign_challenge(&challenge, &pk, &sk).unwrap();

        assert!(server.verify_response(&challenge, &response).is_ok());
        // Same nonce again → replay.
        assert_eq!(
            server.verify_response(&challenge, &response),
            Err(AuthError::Replay)
        );
    }

    #[test]
    fn tampered_signature_fails_and_does_not_burn_nonce() {
        let (mut server, pk, sk) = setup();
        let challenge = server.issue_challenge("acme", "alice");
        let mut response = client::sign_challenge(&challenge, &pk, &sk).unwrap();
        // Flip a byte of the signature.
        response.signature[0] ^= 0xff;
        assert_eq!(
            server.verify_response(&challenge, &response),
            Err(AuthError::BadSignature)
        );
        // A good response on the SAME challenge still works (nonce not burned).
        let good = client::sign_challenge(&challenge, &pk, &sk).unwrap();
        assert!(server.verify_response(&challenge, &good).is_ok());
    }

    #[test]
    fn wrong_key_is_rejected() {
        let (mut server, _pk, _sk) = setup();
        let (other_pk, other_sk) = bloch_crypto::crypto::generate_keypair();
        let challenge = server.issue_challenge("acme", "alice");
        // A different wallet signs a valid signature — but it isn't the enrolled key.
        let response = client::sign_challenge(&challenge, &other_pk, &other_sk).unwrap();
        assert_eq!(
            server.verify_response(&challenge, &response),
            Err(AuthError::WrongKey)
        );
    }

    #[test]
    fn not_enrolled_is_rejected() {
        let (mut server, pk, sk) = setup();
        let challenge = server.issue_challenge("acme", "bob");
        let response = client::sign_challenge(&challenge, &pk, &sk).unwrap();
        assert!(matches!(
            server.verify_response(&challenge, &response),
            Err(AuthError::NotEnrolled { .. })
        ));
    }

    // ----- Sessions: id + TTL + validate + revoke -----

    #[test]
    fn login_mints_a_session_with_id_and_ttl() {
        let (mut server, pk, sk) = setup();
        let challenge = server.issue_challenge("acme", "alice");
        let response = client::sign_challenge(&challenge, &pk, &sk).unwrap();
        let session = server.verify_response(&challenge, &response).unwrap();

        assert_eq!(session.id.len(), 32, "128-bit hex session id");
        assert_eq!(session.org_id, "acme");
        assert!(session.expires_at > session.issued_at, "session has a TTL");

        // The session is retrievable by id while live, and gone once expired.
        assert!(server.session(&session.id, session.issued_at).is_some());
        assert!(
            server.session(&session.id, session.expires_at + 1).is_none(),
            "an expired session id is rejected (fail-closed)"
        );
        // validate_session reaps the expired entry.
        assert!(server.validate_session(&session.id, session.expires_at + 1).is_none());
        assert_eq!(server.live_session_count(session.issued_at), 0);
    }

    #[test]
    fn offboard_revokes_live_sessions_and_challenges() {
        let (mut server, pk, sk) = setup();
        let challenge = server.issue_challenge("acme", "alice");
        let response = client::sign_challenge(&challenge, &pk, &sk).unwrap();
        let session = server.verify_response(&challenge, &response).unwrap();
        // A second, unanswered challenge is now live.
        let _pending = server.issue_challenge("acme", "alice");

        assert!(server.session(&session.id, session.issued_at).is_some());
        let removed = server.offboard_and_revoke("acme", "alice");
        assert!(removed, "enrollment was removed");
        assert!(
            server.session(&session.id, session.issued_at).is_none(),
            "offboard kills live sessions immediately"
        );
        assert_eq!(server.purge_challenges_for("acme", "alice"), 0, "no live challenges remain");
        // The key can no longer log in.
        let ch2 = server.issue_challenge("acme", "alice");
        let resp2 = client::sign_challenge(&ch2, &pk, &sk).unwrap();
        assert!(matches!(
            server.verify_response(&ch2, &resp2),
            Err(AuthError::NotEnrolled { .. })
        ));
    }

    #[test]
    fn nonce_and_session_sweep_is_bounded() {
        let (mut server, _pk, _sk) = setup();
        let ch = server.issue_challenge("acme", "alice");
        // Well past every TTL: the issued nonce and any session should sweep out.
        let dropped = server.sweep(ch.expires_at + crate::server::CONSUMED_RETENTION_SECS + 10);
        assert!(dropped >= 1, "expired live nonce is swept");
    }

    // ----- Dual-control + Brewer–Nash SoD, ENFORCED -----

    fn admin(user_id: &str, role: Role) -> User {
        User { org_id: "acme".into(), user_id: user_id.into(), role, clearance: 5 }
    }

    /// Bootstrap-enroll an admin (the seeded-first-admins path — bypasses
    /// dual-control by design). Approve-time proposer re-validation requires
    /// the proposer to actually be enrolled, so tests seed their admins.
    fn enroll_admin(server: &mut AuthServer, user_id: &str, role: Role) {
        server.enrollments_mut().enroll(Enrollment {
            org_id: "acme".into(),
            user_id: user_id.into(),
            role,
            clearance: 5,
            // Public key material only; these tests never log the admin in.
            public_key: vec![0xAA],
        });
    }

    #[test]
    fn business_role_cannot_propose_a_change() {
        let (mut server, _pk, _sk) = setup();
        let eng = admin("eve", Role::Engineer);
        let (pk, _sk) = bloch_crypto::crypto::generate_keypair();
        let err = server.propose_change(
            &eng,
            ChangeKind::Enroll(Enrollment {
                org_id: "acme".into(), user_id: "carol".into(),
                role: Role::FinanceAnalyst, clearance: 2, public_key: pk,
            }),
        );
        assert!(matches!(err, Err(AuthError::NotAuthorized { .. })));
    }

    #[test]
    fn dual_control_requires_two_separated_admins() {
        let (mut server, _pk, _sk) = setup();
        enroll_admin(&mut server, "ivan", Role::ItAdmin);
        // Approvers are authorized against their LIVE enrolled role (the role
        // claimed in the request is ignored), so they must be enrolled too.
        enroll_admin(&mut server, "ian", Role::ItAdmin);
        enroll_admin(&mut server, "carol", Role::ComplianceOfficer);
        let it = admin("ivan", Role::ItAdmin);
        let it2 = admin("ian", Role::ItAdmin);
        let comp = admin("carol", Role::ComplianceOfficer);
        let (newpk, _sk) = bloch_crypto::crypto::generate_keypair();
        let enroll = ChangeKind::Enroll(Enrollment {
            org_id: "acme".into(), user_id: "dave".into(),
            role: Role::FinanceAnalyst, clearance: 2, public_key: newpk,
        });

        // Self-approval is refused.
        let id = server.propose_change(&it, enroll.clone()).unwrap();
        assert!(matches!(
            server.approve_change(&id, &it),
            Err(AuthError::DualControl { .. })
        ));
        // Two IT-admins (same side of the wall) cannot commit — SoD violation.
        assert!(matches!(
            server.approve_change(&id, &it2),
            Err(AuthError::SodViolation { .. })
        ));
        // The change is still pending and nothing was enrolled.
        assert!(server.enrollments().get("acme", "dave").is_none());
        assert!(server.pending_change(&id).is_some());

        // A separated admin (compliance-officer) commits it.
        let outcome = server.approve_change(&id, &comp).unwrap();
        assert!(outcome.applied);
        assert!(server.enrollments().get("acme", "dave").is_some());
        assert!(server.pending_change(&id).is_none(), "pending entry cleared on commit");
    }

    #[test]
    fn dual_control_offboard_revokes_sessions_on_commit() {
        let (mut server, pk, sk) = setup();
        // alice logs in (live session), then compliance proposes offboard, IT approves.
        let challenge = server.issue_challenge("acme", "alice");
        let response = client::sign_challenge(&challenge, &pk, &sk).unwrap();
        let session = server.verify_response(&challenge, &response).unwrap();

        enroll_admin(&mut server, "carol", Role::ComplianceOfficer);
        enroll_admin(&mut server, "ivan", Role::ItAdmin); // approver's live role is what counts
        let comp = admin("carol", Role::ComplianceOfficer);
        let it = admin("ivan", Role::ItAdmin);
        let id = server
            .propose_change(&comp, ChangeKind::Offboard { org_id: "acme".into(), user_id: "alice".into() })
            .unwrap();
        let outcome = server.approve_change(&id, &it).unwrap();
        assert!(outcome.applied);
        assert!(outcome.sessions_revoked >= 1, "offboard revoked the live session");
        assert!(server.session(&session.id, session.issued_at).is_none());
    }

    /// A staged change that enrolls "dave". The key is dummy public bytes —
    /// these tests exercise the control gate, never a login by dave.
    fn stage_enroll_dave() -> ChangeKind {
        ChangeKind::Enroll(Enrollment {
            org_id: "acme".into(),
            user_id: "dave".into(),
            role: Role::FinanceAnalyst,
            clearance: 2,
            public_key: vec![0xD4],
        })
    }

    #[test]
    fn business_role_cannot_reject_but_an_admin_can() {
        let (mut server, _pk, _sk) = setup();
        enroll_admin(&mut server, "ivan", Role::ItAdmin);
        let it = admin("ivan", Role::ItAdmin);
        let id = server.propose_change(&it, stage_enroll_dave()).unwrap();

        // A business role must not be able to silently drop an admin's staged
        // change — refused fail-closed, the queue is untouched. (eve's ENROLLED
        // role is engineer; the role in her request is irrelevant either way.)
        enroll_admin(&mut server, "eve", Role::Engineer);
        let eng = admin("eve", Role::Engineer);
        assert!(matches!(
            server.reject_change(&eng, &id),
            Err(AuthError::NotAuthorized { .. })
        ));
        assert!(server.pending_change(&id).is_some(), "change still pending after refused reject");

        // An ENROLLED admin (either side of the wall) may reject — the
        // rejecter's role is read from the live enrollment store, so carol
        // must actually be enrolled as a compliance-officer.
        enroll_admin(&mut server, "carol", Role::ComplianceOfficer);
        let comp = admin("carol", Role::ComplianceOfficer);
        assert_eq!(server.reject_change(&comp, &id), Ok(true));
        assert!(server.pending_change(&id).is_none(), "rejected change is gone");
        // Rejecting an unknown id is not an error, just a no-op.
        assert_eq!(server.reject_change(&comp, &id), Ok(false));
    }

    #[test]
    fn self_asserted_admin_without_enrollment_cannot_reject() {
        // REGRESSION (server-side rejecter role): reject_change used to trust
        // the role CLAIMED in the request (`rejecter.role.is_admin()`), so a
        // never-enrolled caller self-asserting an admin role could drop ANY
        // pending dual-control change. The rejecter's role is now read from
        // the live enrollment store — the ghost is refused fail-closed and
        // the pending queue is untouched.
        let (mut server, _pk, _sk) = setup();
        enroll_admin(&mut server, "ivan", Role::ItAdmin);
        let it = admin("ivan", Role::ItAdmin);
        let id = server.propose_change(&it, stage_enroll_dave()).unwrap();

        let ghost = admin("mallory", Role::ComplianceOfficer); // never enrolled
        assert!(matches!(
            server.reject_change(&ghost, &id),
            Err(AuthError::NotAuthorized { .. })
        ));
        assert!(server.pending_change(&id).is_some(), "queue untouched (fail-closed)");

        // A DEMOTED admin's claimed role is equally worthless.
        enroll_admin(&mut server, "carol", Role::Engineer); // enrolled, but not admin
        let claimed = admin("carol", Role::ComplianceOfficer);
        assert!(matches!(
            server.reject_change(&claimed, &id),
            Err(AuthError::NotAuthorized { .. })
        ));
        assert!(server.pending_change(&id).is_some(), "queue untouched (fail-closed)");
    }

    #[test]
    fn offboarded_proposer_stale_change_cannot_be_approved() {
        let (mut server, _pk, _sk) = setup();
        enroll_admin(&mut server, "ivan", Role::ItAdmin);
        enroll_admin(&mut server, "carol", Role::ComplianceOfficer); // live-role approver
        let it = admin("ivan", Role::ItAdmin);
        let comp = admin("carol", Role::ComplianceOfficer);
        let id = server.propose_change(&it, stage_enroll_dave()).unwrap();

        // ivan's enrollment is dropped directly (bypassing offboard_and_revoke,
        // so the pending entry survives): the approve-time proposer
        // re-validation is the backstop and refuses fail-closed.
        server.enrollments_mut().offboard("acme", "ivan");
        assert!(matches!(
            server.approve_change(&id, &comp),
            Err(AuthError::NotAuthorized { .. })
        ));
        assert!(server.enrollments().get("acme", "dave").is_none(), "nothing was committed");
    }

    #[test]
    fn offboard_purges_pending_changes_proposed_by_the_departed_admin() {
        let (mut server, _pk, _sk) = setup();
        enroll_admin(&mut server, "ivan", Role::ItAdmin);
        enroll_admin(&mut server, "carol", Role::ComplianceOfficer); // live-role approver
        let it = admin("ivan", Role::ItAdmin);
        let comp = admin("carol", Role::ComplianceOfficer);
        let id = server.propose_change(&it, stage_enroll_dave()).unwrap();

        // The full offboarding path purges the departed admin's proposals too.
        assert!(server.offboard_and_revoke("acme", "ivan"));
        assert!(server.pending_change(&id).is_none(), "proposal purged with its proposer");
        assert!(matches!(
            server.approve_change(&id, &comp),
            Err(AuthError::UnknownChange(_))
        ));
        assert!(server.enrollments().get("acme", "dave").is_none());
    }

    #[test]
    fn expired_pending_change_is_refused_and_swept() {
        // A pending-change TTL of -1 makes every proposal already past its max
        // age — a clock-free way to exercise the approve-time guard.
        let (server, _pk, _sk) = setup();
        let mut server = server.with_pending_change_ttl(-1);
        enroll_admin(&mut server, "ivan", Role::ItAdmin);
        enroll_admin(&mut server, "carol", Role::ComplianceOfficer); // live-role approver
        let it = admin("ivan", Role::ItAdmin);
        let comp = admin("carol", Role::ComplianceOfficer);
        let id = server.propose_change(&it, stage_enroll_dave()).unwrap();

        assert!(matches!(
            server.approve_change(&id, &comp),
            Err(AuthError::ChangeExpired(_))
        ));
        assert!(server.pending_change(&id).is_none(), "expired entry reaped at approve");
        assert!(server.enrollments().get("acme", "dave").is_none(), "nothing was committed");

        // The periodic sweep reaps an expired pending change as well.
        let (server2, _pk2, _sk2) = setup();
        let mut server2 = server2.with_pending_change_ttl(3600);
        enroll_admin(&mut server2, "ivan", Role::ItAdmin);
        let id2 = server2.propose_change(&it, stage_enroll_dave()).unwrap();
        let created = server2.pending_change(&id2).unwrap().created_at;
        assert!(server2.sweep(created + 3601) >= 1, "expired pending change is swept");
        assert!(server2.pending_change(&id2).is_none());
    }

    #[test]
    fn demoted_or_unenrolled_approver_is_rejected_despite_claimed_admin_role() {
        // REGRESSION (server-side approver role): approve_change used to
        // authorize against the role CLAIMED in the request (`approver.role`).
        // A demoted (or never-enrolled) caller could self-assert
        // "compliance-officer" and commit a privileged change. The approver's
        // role is now re-read from the live enrollment store at approval time.
        let (mut server, _pk, _sk) = setup();
        enroll_admin(&mut server, "ivan", Role::ItAdmin);
        enroll_admin(&mut server, "carol", Role::ComplianceOfficer);
        let it = admin("ivan", Role::ItAdmin);
        let id = server.propose_change(&it, stage_enroll_dave()).unwrap();

        // carol is DEMOTED server-side after the proposal is staged...
        enroll_admin(&mut server, "carol", Role::Engineer);
        // ...but her approval request still CLAIMS compliance-officer.
        let claimed = admin("carol", Role::ComplianceOfficer);
        assert!(matches!(
            server.approve_change(&id, &claimed),
            Err(AuthError::NotAuthorized { .. })
        ));
        assert!(server.enrollments().get("acme", "dave").is_none(), "nothing was committed");
        assert!(server.pending_change(&id).is_some(), "change stays pending (fail-closed)");

        // A never-enrolled caller claiming an admin role is refused too.
        let ghost = admin("mallory", Role::ComplianceOfficer);
        assert!(matches!(
            server.approve_change(&id, &ghost),
            Err(AuthError::NotAuthorized { .. })
        ));
        assert!(server.enrollments().get("acme", "dave").is_none());

        // Restoring carol's REAL role makes the same request pass — proving the
        // gate keys on the live enrollment, not the request claim.
        enroll_admin(&mut server, "carol", Role::ComplianceOfficer);
        let outcome = server.approve_change(&id, &claimed).unwrap();
        assert!(outcome.applied);
        assert!(server.enrollments().get("acme", "dave").is_some());
    }

    #[test]
    fn key_rotation_revokes_pre_rotation_sessions_and_challenges() {
        // REGRESSION (rotation revocation): rotating a user's wallet key via
        // dual-control used to leave sessions minted under the OLD key alive
        // until their TTL. A rotated-out (possibly compromised) key could keep
        // an authenticated session going. Rotation now revokes the user's live
        // sessions and purges their outstanding challenges.
        let (mut server, pk, sk) = setup();
        // alice logs in with the ORIGINAL key — a live pre-rotation session.
        let challenge = server.issue_challenge("acme", "alice");
        let response = client::sign_challenge(&challenge, &pk, &sk).unwrap();
        let session = server.verify_response(&challenge, &response).unwrap();
        assert!(server.session(&session.id, session.issued_at).is_some());
        // An unanswered pre-rotation challenge is also outstanding.
        let _pending_challenge = server.issue_challenge("acme", "alice");

        // Dual-control rotation of alice's key to a NEW wallet.
        enroll_admin(&mut server, "ivan", Role::ItAdmin);
        enroll_admin(&mut server, "carol", Role::ComplianceOfficer);
        let it = admin("ivan", Role::ItAdmin);
        let comp = admin("carol", Role::ComplianceOfficer);
        let (new_pk, new_sk) = bloch_crypto::crypto::generate_keypair();
        let id = server
            .propose_change(
                &it,
                ChangeKind::Enroll(Enrollment {
                    org_id: "acme".into(),
                    user_id: "alice".into(),
                    role: Role::Engineer,
                    clearance: 3,
                    public_key: new_pk.clone(),
                }),
            )
            .unwrap();
        let outcome = server.approve_change(&id, &comp).unwrap();
        assert!(outcome.applied && outcome.rotated, "this enroll replaced an enrollment");
        assert!(outcome.sessions_revoked >= 1, "rotation revoked the old-key session");

        // The pre-rotation session is dead NOW, not at TTL expiry.
        assert!(
            server.session(&session.id, session.issued_at).is_none(),
            "a session minted under the rotated-out key must not survive rotation"
        );
        // The outstanding pre-rotation challenge was purged.
        assert_eq!(server.purge_challenges_for("acme", "alice"), 0, "no stale challenges remain");

        // The OLD key can no longer log in; the NEW key can.
        let ch_old = server.issue_challenge("acme", "alice");
        let resp_old = client::sign_challenge(&ch_old, &pk, &sk).unwrap();
        assert_eq!(server.verify_response(&ch_old, &resp_old), Err(AuthError::WrongKey));
        let ch_new = server.issue_challenge("acme", "alice");
        let resp_new = client::sign_challenge(&ch_new, &new_pk, &new_sk).unwrap();
        assert!(server.verify_response(&ch_new, &resp_new).is_ok());
    }

    // ----- Durability: snapshot / restore -----

    #[test]
    fn snapshot_round_trips_state() {
        let (mut server, pk, sk) = setup();
        let challenge = server.issue_challenge("acme", "alice");
        let response = client::sign_challenge(&challenge, &pk, &sk).unwrap();
        let session = server.verify_response(&challenge, &response).unwrap();
        let _live = server.issue_challenge("acme", "alice");

        // Serialize -> JSON -> back (as a durable store would).
        let snap = server.snapshot();
        assert_eq!(snap.schema, SNAPSHOT_SCHEMA);
        let json = serde_json::to_string(&snap).unwrap();
        let restored_snap: ServerSnapshot = serde_json::from_str(&json).unwrap();
        let mut restored = AuthServer::restore(restored_snap);

        // The enrollment, the session, and the live challenge all survived.
        assert!(restored.enrollments().get("acme", "alice").is_some());
        assert!(restored.session(&session.id, session.issued_at).is_some());
        assert_eq!(restored.purge_challenges_for("acme", "alice"), 1);
    }

    // ----- Session-bound control plane, end-to-end over REAL PQ logins -----

    /// Two separated admins run the whole dual-control lifecycle — enroll a
    /// user, then offboard them — through SESSIONS ONLY: real PQ logins mint
    /// the sessions, and every propose/approve resolves the acting admin from
    /// the live session store (no caller-supplied `User` anywhere).
    #[test]
    fn session_bound_control_plane_commits_enroll_and_offboard_end_to_end() {
        let (mut server, _pk, _sk) = setup();
        let (it_pk, it_sk) = bloch_crypto::crypto::generate_keypair();
        let (co_pk, co_sk) = bloch_crypto::crypto::generate_keypair();
        // Bootstrap-seed the two first admins (the documented seam).
        server.enrollments_mut().enroll(Enrollment {
            org_id: "acme".into(), user_id: "ivan".into(),
            role: Role::ItAdmin, clearance: 5, public_key: it_pk.clone(),
        });
        server.enrollments_mut().enroll(Enrollment {
            org_id: "acme".into(), user_id: "carol".into(),
            role: Role::ComplianceOfficer, clearance: 5, public_key: co_pk.clone(),
        });

        // Both admins log in for real (hybrid Falcon ‖ ML-DSA signatures).
        let ch = server.issue_challenge("acme", "ivan");
        let it_session = server
            .verify_response(&ch, &client::sign_challenge(&ch, &it_pk, &it_sk).unwrap())
            .unwrap();
        let ch = server.issue_challenge("acme", "carol");
        let co_session = server
            .verify_response(&ch, &client::sign_challenge(&ch, &co_pk, &co_sk).unwrap())
            .unwrap();
        let now = co_session.issued_at;

        // ENROLL dave: proposed via ivan's session; self-approval via ivan's
        // own session is refused (the two-person rule holds through sessions).
        let id = server
            .propose_change_by_session(&it_session.id, stage_enroll_dave(), now)
            .unwrap();
        assert!(matches!(
            server.approve_change_by_session(&it_session.id, &id, now),
            Err(AuthError::DualControl { .. })
        ));
        let outcome = server.approve_change_by_session(&co_session.id, &id, now).unwrap();
        assert!(outcome.applied);
        assert!(server.enrollments().get("acme", "dave").is_some());

        // OFFBOARD dave: proposed via carol's session, approved via ivan's.
        let id = server
            .propose_change_by_session(
                &co_session.id,
                ChangeKind::Offboard { org_id: "acme".into(), user_id: "dave".into() },
                now,
            )
            .unwrap();
        let outcome = server.approve_change_by_session(&it_session.id, &id, now).unwrap();
        assert!(outcome.applied);
        assert!(server.enrollments().get("acme", "dave").is_none());

        // And an offboarded admin's still-held session id is dead for control:
        // offboard ivan; his live session can no longer propose anything.
        assert!(server.offboard_and_revoke("acme", "ivan"));
        assert!(matches!(
            server.propose_change_by_session(&it_session.id, stage_enroll_dave(), now),
            Err(AuthError::SessionInvalid { .. })
        ));
    }

    // ----- Dynamic Brewer–Nash wall: persistence round-trip -----

    /// The wall binding must survive snapshot→restore: alice (a real PQ login)
    /// is granted dataset A in class 'audit-clients'; after a restart she is
    /// still bound — competing dataset B stays denied, A stays allowed. A
    /// pre-wall `/1` snapshot restores with an EMPTY history (documented).
    #[test]
    fn dynamic_wall_binding_survives_snapshot_restore() {
        let (mut server, pk, sk) = setup();
        let challenge = server.issue_challenge("acme", "alice");
        let response = client::sign_challenge(&challenge, &pk, &sk).unwrap();
        let session = server.verify_response(&challenge, &response).unwrap();
        let now = session.issued_at;

        let vol_a = Volume::new("repo-a", "engineering", 2).with_coi("audit-clients", "client-a");
        let vol_b = Volume::new("repo-b", "engineering", 2).with_coi("audit-clients", "client-b");

        // First granted access binds alice to client-a; client-b is now a
        // conflict; the reason names it.
        assert!(server.authorize(&session.id, &vol_a, now).unwrap().ok);
        let denied = server.authorize(&session.id, &vol_b, now).unwrap();
        assert!(!denied.ok);
        assert!(denied.why.unwrap().contains("conflict of interest"));

        // Snapshot → JSON → restore (as a durable store would across a restart).
        let snap = server.snapshot();
        assert_eq!(snap.schema, SNAPSHOT_SCHEMA);
        let json = serde_json::to_string(&snap).unwrap();
        let restored_snap: ServerSnapshot = serde_json::from_str(&json).unwrap();
        let mut restored = AuthServer::restore(restored_snap);

        // The binding rode the snapshot: B still denied, A still allowed.
        assert_eq!(restored.coi_binding("acme", "alice", "audit-clients"), Some("client-a"));
        assert!(!restored.authorize(&session.id, &vol_b, now).unwrap().ok, "wall survived restart");
        assert!(restored.authorize(&session.id, &vol_a, now).unwrap().ok);

        // Back-compat: a pre-wall `/1` snapshot (no `coi_history` field at all)
        // still restores — with an empty wall history, never a misread one.
        let mut v1 = serde_json::to_value(&snap).unwrap();
        v1["schema"] = serde_json::Value::from(SNAPSHOT_SCHEMA_V1);
        v1.as_object_mut().unwrap().remove("coi_history");
        assert!(schema_supported(SNAPSHOT_SCHEMA_V1));
        let v1_snap: ServerSnapshot = serde_json::from_value(v1).unwrap();
        let restored_v1 = AuthServer::restore(v1_snap);
        assert_eq!(restored_v1.coi_binding("acme", "alice", "audit-clients"), None);
    }
}
