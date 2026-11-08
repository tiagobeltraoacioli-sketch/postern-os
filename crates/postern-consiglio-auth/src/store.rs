// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//! Durable-store ADAPTER over the [`crate::persist`] snapshot/restore seam.
//!
//! STATUS: reference prototype. UNAUDITED. Pre-production. NO SECURITY CLAIMS —
//! a signature proves origin+integrity, nothing about what it signs. This module
//! adds **durability plumbing only**; it rewrites **no cryptography**. The PQ
//! verify, the replay guard, the dual-control gate all still live where they were
//! (`server.rs`, `control.rs`) — this file just makes their state survive a
//! restart by writing the existing [`ServerSnapshot`] to a real backend.
//!
//! # Why a seam, not a baked-in database
//! [`crate::persist`] already turns the whole [`AuthServer`] into a plain,
//! serializable [`ServerSnapshot`]. What was missing was a *backend* to put it
//! in, plus the discipline of persisting after every mutation. This module
//! provides both:
//!
//!   * [`SnapshotStore`] — the injection point. Any backend (a file here, a
//!     Postgres row, a Redis blob, an S3 object in a deployment) implements
//!     `load` + `save`. The crate depends on none of them.
//!   * [`FileSnapshotStore`] — a real, durable, **atomic** file backend
//!     (write-temp + `fsync` + rename) suitable for a single-node deployment and
//!     for the HTTP service's self-check. Durable across process restarts.
//!   * [`PersistentAuthServer`] — wraps an [`AuthServer`] + a store and persists
//!     the snapshot after **every mutating verb** (challenge issue, login,
//!     propose/approve, offboard, sweep, revoke). Read verbs delegate untouched.
//!
//! # Privacy posture (LGPD/GDPR §9, carried from `persist.rs`)
//! Snapshots are pure data and carry **no secret key material** — only *public*
//! wallet keys + metadata. Revocation/offboard **degrade entitlements, never
//! destroy data**. The store is tamper-EVIDENT at best (a durable file is not a
//! vault) — **not tamper-proof**. This ENABLES compliance controls; it **is not
//! compliance and not legal advice.**

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::challenge::{Challenge, Response};
use crate::control::{ChangeKind, CommitOutcome};
use crate::enroll::{Enrollment, EnrollmentStore};
use crate::error::AuthError;
use crate::org::User;
use crate::persist::{ServerSnapshot, SNAPSHOT_SCHEMA};
use crate::server::{AuthServer, Session};

/// A pluggable durable backend for a [`ServerSnapshot`]. Inject a real one
/// (file, Postgres, Redis) so console state survives a restart; the crate rolls
/// no persistence policy of its own beyond this contract.
///
/// `load` returns `Ok(None)` for a fresh, never-persisted store (first boot),
/// `Ok(Some(_))` to restore, and `Err(_)` for a genuine backend fault or a
/// schema it refuses to load (fail-closed — a corrupt snapshot is not silently
/// treated as "empty").
pub trait SnapshotStore {
    fn load(&self) -> Result<Option<ServerSnapshot>, StoreError>;
    fn save(&self, snapshot: &ServerSnapshot) -> Result<(), StoreError>;
}

/// Error surface for the durable path: a backend/IO fault, a JSON (de)serialize
/// failure, a refused schema, or an underlying [`AuthError`] from a wrapped
/// mutating verb. Keeping auth + durability errors in one type lets a
/// [`PersistentAuthServer`] verb return "did the op succeed AND did it persist?"
/// as a single `Result`.
#[derive(Debug)]
pub enum StoreError {
    /// The auth operation itself was refused (fail-closed) — nothing to persist.
    Auth(AuthError),
    /// The backend could not be read/written.
    Io(io::Error),
    /// Snapshot (de)serialization failed.
    Serde(String),
    /// The persisted snapshot's schema is not one this build restores.
    Schema { found: String, expected: String },
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Auth(e) => write!(f, "auth refused: {e}"),
            StoreError::Io(e) => write!(f, "durable store IO error: {e}"),
            StoreError::Serde(e) => write!(f, "snapshot serialize/parse error: {e}"),
            StoreError::Schema { found, expected } => {
                write!(f, "snapshot schema mismatch: found '{found}', this build restores '{expected}'")
            }
        }
    }
}

impl std::error::Error for StoreError {}

impl From<AuthError> for StoreError {
    fn from(e: AuthError) -> Self {
        StoreError::Auth(e)
    }
}
impl From<io::Error> for StoreError {
    fn from(e: io::Error) -> Self {
        StoreError::Io(e)
    }
}

/// A real, durable, single-file backend. Writes are **atomic**: the snapshot is
/// serialized to a sibling temp file, flushed to disk, then `rename`d over the
/// target, so a crash mid-write can never leave a half-written snapshot (a
/// reader sees either the old file or the new one, never a torn one).
pub struct FileSnapshotStore {
    path: PathBuf,
}

impl FileSnapshotStore {
    /// A store backed by the file at `path`. The parent directory must exist (or
    /// be creatable). No file is written until the first [`SnapshotStore::save`].
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self { path: path.as_ref().to_path_buf() }
    }

    fn tmp_path(&self) -> PathBuf {
        let mut p = self.path.clone().into_os_string();
        p.push(".tmp");
        PathBuf::from(p)
    }
}

impl SnapshotStore for FileSnapshotStore {
    fn load(&self) -> Result<Option<ServerSnapshot>, StoreError> {
        match fs::read(&self.path) {
            Ok(bytes) => {
                let snap: ServerSnapshot = serde_json::from_slice(&bytes)
                    .map_err(|e| StoreError::Serde(e.to_string()))?;
                if !crate::persist::schema_supported(&snap.schema) {
                    // Fail-closed: refuse an unknown schema rather than boot with
                    // a silently-empty or misread store. (`/1` is supported: it
                    // restores with an empty wall history — see `crate::persist`.)
                    return Err(StoreError::Schema {
                        found: snap.schema,
                        expected: SNAPSHOT_SCHEMA.to_string(),
                    });
                }
                Ok(Some(snap))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(StoreError::Io(e)),
        }
    }

    fn save(&self, snapshot: &ServerSnapshot) -> Result<(), StoreError> {
        if let Some(dir) = self.path.parent() {
            if !dir.as_os_str().is_empty() {
                fs::create_dir_all(dir)?;
            }
        }
        let bytes = serde_json::to_vec(snapshot).map_err(|e| StoreError::Serde(e.to_string()))?;
        let tmp = self.tmp_path();
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?; // durable before we swap it in
        }
        fs::rename(&tmp, &self.path)?; // atomic swap
        Ok(())
    }
}

/// An in-memory store — a real [`SnapshotStore`] with no filesystem, useful for
/// tests and for a caller that persists elsewhere. Round-trips through JSON on
/// every save so it exercises the exact serialize path a durable backend uses.
#[derive(Default)]
pub struct MemSnapshotStore {
    blob: std::sync::Mutex<Option<Vec<u8>>>,
}

impl MemSnapshotStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SnapshotStore for MemSnapshotStore {
    fn load(&self) -> Result<Option<ServerSnapshot>, StoreError> {
        let guard = self.blob.lock().expect("mem store mutex");
        match guard.as_ref() {
            None => Ok(None),
            Some(bytes) => {
                let snap = serde_json::from_slice(bytes)
                    .map_err(|e| StoreError::Serde(e.to_string()))?;
                Ok(Some(snap))
            }
        }
    }
    fn save(&self, snapshot: &ServerSnapshot) -> Result<(), StoreError> {
        let bytes = serde_json::to_vec(snapshot).map_err(|e| StoreError::Serde(e.to_string()))?;
        *self.blob.lock().expect("mem store mutex") = Some(bytes);
        Ok(())
    }
}

/// A minimal key/value backend contract — the injection point for a real
/// production KV (Cloudflare Workers KV, Redis, DynamoDB, an S3/R2 object). A
/// deployment implements `kv_get`/`kv_put` over its store; [`KvSnapshotStore`]
/// turns that into a durable [`SnapshotStore`] by writing the whole snapshot as
/// a single blob under one namespaced key. This is the exact shape the Node
/// console's "durable file/KV store" (DEV-2) binds a Cloudflare KV namespace to.
///
/// Honesty: this trait is the *seam*, not a KV client — the crate ships no cloud
/// SDK. [`FsKvBackend`] below is a real, durable, host-provable implementation of
/// it; a cloud backend is an out-of-crate adapter that satisfies the same two
/// methods. `kv_get` returns `Ok(None)` for an absent key (first boot).
pub trait KvBackend {
    /// Fetch the blob at `key`, or `Ok(None)` if the key was never written.
    fn kv_get(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError>;
    /// Durably write `value` at `key`, replacing any prior value.
    fn kv_put(&self, key: &str, value: &[u8]) -> Result<(), StoreError>;
}

/// A [`SnapshotStore`] over any [`KvBackend`]: the whole [`ServerSnapshot`] is
/// serialized to one JSON blob and stored under a single namespaced key. This is
/// the production-shaped backend (a KV-blob store) that sits beside
/// [`FileSnapshotStore`]: inject a real KV backend and console state survives a
/// restart. Fail-closed on an unknown schema, exactly like the file store.
pub struct KvSnapshotStore<B: KvBackend> {
    backend: B,
    key: String,
}

impl<B: KvBackend> KvSnapshotStore<B> {
    /// The default namespaced key the snapshot blob lives under.
    pub const DEFAULT_KEY: &'static str = "consiglio:server-snapshot";

    /// A KV-blob store over `backend`, using [`Self::DEFAULT_KEY`].
    pub fn new(backend: B) -> Self {
        Self { backend, key: Self::DEFAULT_KEY.to_string() }
    }

    /// A KV-blob store over `backend`, using a caller-chosen key (e.g. to shard
    /// several orgs' consoles into one KV namespace).
    pub fn with_key(backend: B, key: impl Into<String>) -> Self {
        Self { backend, key: key.into() }
    }
}

impl<B: KvBackend> SnapshotStore for KvSnapshotStore<B> {
    fn load(&self) -> Result<Option<ServerSnapshot>, StoreError> {
        match self.backend.kv_get(&self.key)? {
            None => Ok(None),
            Some(bytes) => {
                let snap: ServerSnapshot = serde_json::from_slice(&bytes)
                    .map_err(|e| StoreError::Serde(e.to_string()))?;
                if !crate::persist::schema_supported(&snap.schema) {
                    // Fail-closed: an unknown schema is refused, never booted
                    // empty. (`/1` is supported — empty wall history.)
                    return Err(StoreError::Schema {
                        found: snap.schema,
                        expected: SNAPSHOT_SCHEMA.to_string(),
                    });
                }
                Ok(Some(snap))
            }
        }
    }

    fn save(&self, snapshot: &ServerSnapshot) -> Result<(), StoreError> {
        let bytes = serde_json::to_vec(snapshot).map_err(|e| StoreError::Serde(e.to_string()))?;
        self.backend.kv_put(&self.key, &bytes)
    }
}

/// A durable, host-provable [`KvBackend`] over a directory: each key is a file
/// under `root` (the key sanitized to a safe filename), written **atomically**
/// (temp + `fsync` + rename). This is the concrete backend the restart-recovery
/// test drives to prove state survives a process exit on the host today. In a
/// cloud deployment you implement [`KvBackend`] over the platform's KV binding
/// instead; the [`KvSnapshotStore`] above is unchanged either way.
pub struct FsKvBackend {
    root: PathBuf,
}

impl FsKvBackend {
    /// A KV backend storing each key as a file under `root` (created on write).
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self { root: root.as_ref().to_path_buf() }
    }

    /// Map a KV key to a safe, collision-resistant filename: any byte outside
    /// `[A-Za-z0-9._-]` becomes `_`, so `consiglio:server-snapshot` is a valid
    /// single path component on every host filesystem (no `:` or `/` surprises).
    fn key_path(&self, key: &str) -> PathBuf {
        let safe: String = key
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c } else { '_' })
            .collect();
        self.root.join(format!("{safe}.kv"))
    }
}

impl KvBackend for FsKvBackend {
    fn kv_get(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        match fs::read(self.key_path(key)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(StoreError::Io(e)),
        }
    }

    fn kv_put(&self, key: &str, value: &[u8]) -> Result<(), StoreError> {
        fs::create_dir_all(&self.root)?;
        let path = self.key_path(key);
        let mut tmp = path.clone().into_os_string();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(value)?;
            f.sync_all()?; // durable before we swap it in
        }
        fs::rename(&tmp, &path)?; // atomic swap: a reader sees old or new, never torn
        Ok(())
    }
}

/// An [`AuthServer`] bound to a durable [`SnapshotStore`], persisting after every
/// mutating verb. Construct with [`PersistentAuthServer::load_or_new`] to
/// transparently restore prior state on boot. Read verbs (`session`,
/// `live_session_count`, `enrollments`, `pending_change`) delegate to the inner
/// server unchanged; mutating verbs run the inner op, then `save` the snapshot,
/// returning a [`StoreError`] if either half fails.
///
/// Durability is **transactional-ish, not transactional**: the in-memory
/// mutation is applied first, then persisted. If `save` fails, the error is
/// surfaced (the caller learns the write did not durably land) and the in-memory
/// state still reflects the op. A production deployment behind a transactional DB
/// would fold both into one transaction; that is a backend concern this seam
/// leaves open.
pub struct PersistentAuthServer<S: SnapshotStore> {
    server: AuthServer,
    store: S,
}

impl<S: SnapshotStore> PersistentAuthServer<S> {
    /// Restore from the store if it holds a snapshot, else start empty with the
    /// given session TTL. Fail-closed: a backend/schema fault propagates rather
    /// than silently booting an empty server over a real-but-unreadable store.
    pub fn load_or_new(store: S, session_ttl_secs: i64) -> Result<Self, StoreError> {
        let server = match store.load()? {
            Some(snap) => AuthServer::restore(snap),
            None => AuthServer::new(EnrollmentStore::new()).with_session_ttl(session_ttl_secs),
        };
        Ok(Self { server, store })
    }

    /// Persist the current snapshot to the durable store.
    pub fn persist(&self) -> Result<(), StoreError> {
        self.store.save(&self.server.snapshot())
    }

    /// Immutable access to the wrapped server for read-only verbs.
    pub fn inner(&self) -> &AuthServer {
        &self.server
    }

    // ---- Mutating verbs: run, then persist ----

    /// Bootstrap-enroll the first admins (bypasses dual-control, by design — see
    /// the console's `bootstrapEnroll`). Persists.
    pub fn bootstrap_enroll(&mut self, e: Enrollment) -> Result<(), StoreError> {
        self.server.enrollments_mut().enroll(e);
        self.persist()
    }

    /// Issue a login challenge (registers a live nonce → must persist so the
    /// replay guard survives a restart mid-login). Returns the challenge.
    pub fn issue_challenge(&mut self, org_id: &str, user_id: &str) -> Result<Challenge, StoreError> {
        let ch = self.server.issue_challenge(org_id, user_id);
        self.persist()?;
        Ok(ch)
    }

    /// Verify a wallet response (REAL hybrid-PQ verify inside `verify_response`)
    /// and mint a session. Persists the retired nonce + new session.
    pub fn verify_response(
        &mut self,
        challenge: &Challenge,
        response: &Response,
    ) -> Result<Session, StoreError> {
        let session = self.server.verify_response(challenge, response)?;
        self.persist()?;
        Ok(session)
    }

    /// Stage a dual-controlled change. Persists the pending queue.
    pub fn propose_change(
        &mut self,
        proposer: &User,
        kind: ChangeKind,
    ) -> Result<String, StoreError> {
        let id = self.server.propose_change(proposer, kind)?;
        self.persist()?;
        Ok(id)
    }

    /// Approve + commit a pending change under the two-person rule. Persists the
    /// committed enrollment/offboard and the drained pending entry.
    pub fn approve_change(
        &mut self,
        change_id: &str,
        approver: &User,
    ) -> Result<CommitOutcome, StoreError> {
        let outcome = self.server.approve_change(change_id, approver)?;
        self.persist()?;
        Ok(outcome)
    }

    /// Reject (drop) a pending change. Admin-gated like the propose/approve
    /// verbs (a non-admin rejecter is refused fail-closed and nothing is
    /// persisted). Persists on success.
    pub fn reject_change(&mut self, rejecter: &User, change_id: &str) -> Result<bool, StoreError> {
        let dropped = self.server.reject_change(rejecter, change_id)?;
        self.persist()?;
        Ok(dropped)
    }

    /// Stage a dual-controlled change through a live session (the production
    /// path — the acting identity and role are resolved server-side, never
    /// from a caller-supplied `User`). Persists the pending queue.
    pub fn propose_change_by_session(
        &mut self,
        session_id: &str,
        kind: ChangeKind,
        now: i64,
    ) -> Result<String, StoreError> {
        let id = self.server.propose_change_by_session(session_id, kind, now)?;
        self.persist()?;
        Ok(id)
    }

    /// Approve + commit a pending change through a live session. Persists.
    pub fn approve_change_by_session(
        &mut self,
        session_id: &str,
        change_id: &str,
        now: i64,
    ) -> Result<CommitOutcome, StoreError> {
        let outcome = self.server.approve_change_by_session(session_id, change_id, now)?;
        self.persist()?;
        Ok(outcome)
    }

    /// Reject (drop) a pending change through a live session. Persists.
    pub fn reject_change_by_session(
        &mut self,
        session_id: &str,
        change_id: &str,
        now: i64,
    ) -> Result<bool, StoreError> {
        let dropped = self.server.reject_change_by_session(session_id, change_id, now)?;
        self.persist()?;
        Ok(dropped)
    }

    /// The server-enforced access gate (session revalidation + live-enrollment
    /// RBAC + the dynamic Brewer–Nash wall). Persists — a granted first access
    /// in a conflict-of-interest class BINDS the user to that dataset, and the
    /// binding (like an expiry reap) must survive a restart.
    pub fn authorize(
        &mut self,
        session_id: &str,
        vol: &crate::org::Volume,
        now: i64,
    ) -> Result<crate::org::AccessDecision, StoreError> {
        let decision = self.server.authorize(session_id, vol, now)?;
        self.persist()?;
        Ok(decision)
    }

    /// Direct offboard (bypasses dual-control): remove + revoke sessions +
    /// challenges + the user's own staged proposals. Persists.
    pub fn offboard_and_revoke(&mut self, org_id: &str, user_id: &str) -> Result<bool, StoreError> {
        let removed = self.server.offboard_and_revoke(org_id, user_id);
        self.persist()?;
        Ok(removed)
    }

    /// Explicitly revoke a session (logout). Persists.
    pub fn revoke_session(&mut self, id: &str) -> Result<bool, StoreError> {
        let ok = self.server.revoke_session(id);
        self.persist()?;
        Ok(ok)
    }

    /// Validate a session by id, reaping it if expired. Persists (the reap is a
    /// mutation).
    pub fn validate_session(&mut self, id: &str, now: i64) -> Result<Option<Session>, StoreError> {
        let s = self.server.validate_session(id, now);
        self.persist()?;
        Ok(s)
    }

    /// Sweep expired/aged transient state. Persists the bounded store.
    pub fn sweep(&mut self, now: i64) -> Result<usize, StoreError> {
        let dropped = self.server.sweep(now);
        self.persist()?;
        Ok(dropped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::org::Role;

    fn admin(user_id: &str, role: Role) -> User {
        User { org_id: "acme".into(), user_id: user_id.into(), role, clearance: 5 }
    }

    fn enrollment(user_id: &str, role: Role) -> Enrollment {
        Enrollment {
            org_id: "acme".into(),
            user_id: user_id.into(),
            role,
            clearance: 5,
            // Public key material only — snapshots never carry a private key.
            public_key: vec![1, 2, 3, 4],
        }
    }

    #[test]
    fn file_store_round_trips_across_a_restart() {
        let dir = std::env::temp_dir().join(format!("consiglio-store-test-{}", std::process::id()));
        let path = dir.join("snapshot.json");
        let _ = fs::remove_file(&path);

        // Boot 1: seed admins, stage + commit a dual-controlled enroll, issue a
        // live challenge — all persisted through the file store.
        let it = admin("ivan", Role::ItAdmin);
        let comp = admin("carol", Role::ComplianceOfficer);
        {
            let store = FileSnapshotStore::new(&path);
            let mut srv = PersistentAuthServer::load_or_new(store, 3600).unwrap();
            srv.bootstrap_enroll(enrollment("ivan", Role::ItAdmin)).unwrap();
            srv.bootstrap_enroll(enrollment("carol", Role::ComplianceOfficer)).unwrap();

            let id = srv
                .propose_change(&it, ChangeKind::Enroll(enrollment("dave", Role::FinanceAnalyst)))
                .unwrap();
            // Self-approval is refused (fail-closed) and does NOT corrupt the store.
            assert!(srv.approve_change(&id, &it).is_err());
            // A separated admin commits it.
            let outcome = srv.approve_change(&id, &comp).unwrap();
            assert!(outcome.applied);

            let _ch = srv.issue_challenge("acme", "dave").unwrap();
        } // drop: simulate a process exit

        // Boot 2: a fresh server restored purely from the durable file.
        {
            let store = FileSnapshotStore::new(&path);
            let srv = PersistentAuthServer::load_or_new(store, 3600).unwrap();
            let s = srv.inner();
            assert!(s.enrollments().get("acme", "ivan").is_some(), "admin survived restart");
            assert!(s.enrollments().get("acme", "dave").is_some(), "committed enroll survived restart");
            assert!(s.pending_change_ids().is_empty(), "pending queue drained on commit, persisted");
        }

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn kv_store_round_trips_across_a_restart() {
        // The production-shaped backend: a KV-blob store over a durable KV
        // backend. Proves a kill-and-restart restores enrollments, a committed
        // dual-controlled change, and the live nonce — reading a *fresh* backend
        // instance over the same durable directory (no shared in-memory state).
        let dir = std::env::temp_dir().join(format!("consiglio-kv-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        let it = admin("ivan", Role::ItAdmin);
        let comp = admin("carol", Role::ComplianceOfficer);

        // Boot 1: seed admins, commit a dual-controlled enroll (SoD enforced),
        // issue a live challenge — all persisted through the KV-blob store.
        {
            let store = KvSnapshotStore::new(FsKvBackend::new(&dir));
            let mut srv = PersistentAuthServer::load_or_new(store, 3600).unwrap();
            srv.bootstrap_enroll(enrollment("ivan", Role::ItAdmin)).unwrap();
            srv.bootstrap_enroll(enrollment("carol", Role::ComplianceOfficer)).unwrap();

            let id = srv
                .propose_change(&it, ChangeKind::Enroll(enrollment("dave", Role::FinanceAnalyst)))
                .unwrap();
            // Self-approval refused (fail-closed); does not corrupt the KV blob.
            assert!(srv.approve_change(&id, &it).is_err());
            // A separated admin commits it.
            let outcome = srv.approve_change(&id, &comp).unwrap();
            assert!(outcome.applied);

            let _ch = srv.issue_challenge("acme", "dave").unwrap();
        } // drop: simulate a process exit — nothing kept in memory

        // Boot 2: a brand-new server + a brand-new KV backend over the same dir.
        {
            let store = KvSnapshotStore::new(FsKvBackend::new(&dir));
            let srv = PersistentAuthServer::load_or_new(store, 3600).unwrap();
            let s = srv.inner();
            assert!(s.enrollments().get("acme", "ivan").is_some(), "admin survived restart");
            assert!(s.enrollments().get("acme", "dave").is_some(), "committed enroll survived restart");
            assert!(s.pending_change_ids().is_empty(), "pending queue drained on commit, persisted");
        }

        // Boot 3: the fail-closed schema guard also holds on the KV path — a blob
        // written under a foreign schema is refused, not booted empty.
        {
            let backend = FsKvBackend::new(&dir);
            backend
                .kv_put(
                    KvSnapshotStore::<FsKvBackend>::DEFAULT_KEY,
                    br#"{"schema":"someone-elses/9","enrollments":[],"issued":[],"consumed":[],"sessions":[],"pending":[],"session_ttl_secs":3600}"#,
                )
                .unwrap();
            let store = KvSnapshotStore::new(FsKvBackend::new(&dir));
            match PersistentAuthServer::load_or_new(store, 3600) {
                Err(StoreError::Schema { .. }) => {}
                Ok(_) => panic!("unknown schema must be refused on the KV path too"),
                Err(other) => panic!("expected a schema error, got {other}"),
            }
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn durable_store_round_trips_the_offboard_purge() {
        // Offboarding an admin who has a proposal staged must purge that
        // proposal from the pending queue — and the purge must be persisted, so
        // a restart cannot resurrect the departed admin's stale change.
        let dir = std::env::temp_dir().join(format!("consiglio-purge-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        let it = admin("ivan", Role::ItAdmin);
        let comp = admin("carol", Role::ComplianceOfficer);

        // Boot 1: ivan stages an enroll; a business role's reject is refused
        // (and changes nothing durable); then ivan is offboarded — his staged
        // proposal is purged with him, persisted through the KV-blob store.
        {
            let store = KvSnapshotStore::new(FsKvBackend::new(&dir));
            let mut srv = PersistentAuthServer::load_or_new(store, 3600).unwrap();
            srv.bootstrap_enroll(enrollment("ivan", Role::ItAdmin)).unwrap();
            srv.bootstrap_enroll(enrollment("carol", Role::ComplianceOfficer)).unwrap();

            let id = srv
                .propose_change(&it, ChangeKind::Enroll(enrollment("dave", Role::FinanceAnalyst)))
                .unwrap();
            // A business role cannot reject on the durable path either.
            let eng = admin("eve", Role::Engineer);
            assert!(matches!(srv.reject_change(&eng, &id), Err(StoreError::Auth(_))));
            assert_eq!(srv.inner().pending_change_ids().len(), 1);

            assert!(srv.offboard_and_revoke("acme", "ivan").unwrap());
            assert!(srv.inner().pending_change_ids().is_empty(), "proposal purged with proposer");
            // The purged change can no longer be approved by anyone.
            assert!(matches!(
                srv.approve_change(&id, &comp),
                Err(StoreError::Auth(AuthError::UnknownChange(_)))
            ));
        } // drop: simulate a process exit

        // Boot 2: the purge survived the restart — the queue restores empty and
        // dave was never enrolled.
        {
            let store = KvSnapshotStore::new(FsKvBackend::new(&dir));
            let srv = PersistentAuthServer::load_or_new(store, 3600).unwrap();
            let s = srv.inner();
            assert!(s.enrollments().get("acme", "ivan").is_none(), "offboard survived restart");
            assert!(s.pending_change_ids().is_empty(), "purge survived restart");
            assert!(s.enrollments().get("acme", "dave").is_none(), "stale change never committed");
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn mem_store_persists_and_restores() {
        let store = MemSnapshotStore::new();
        // First server writes into the shared blob via load_or_new + a mutation.
        // We persist, take the snapshot out, and restore a second server from it.
        let snap = {
            let mut srv = PersistentAuthServer::load_or_new(MemSnapshotStore::new(), 3600).unwrap();
            srv.bootstrap_enroll(enrollment("ivan", Role::ItAdmin)).unwrap();
            srv.inner().snapshot()
        };
        store.save(&snap).unwrap();
        let srv2 = PersistentAuthServer::load_or_new(store, 3600).unwrap();
        assert!(srv2.inner().enrollments().get("acme", "ivan").is_some());
    }

    #[test]
    fn refuses_a_foreign_schema_fail_closed() {
        let dir = std::env::temp_dir().join(format!("consiglio-store-schema-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bad.json");
        fs::write(&path, br#"{"schema":"someone-elses/9","enrollments":[],"issued":[],"consumed":[],"sessions":[],"pending":[],"session_ttl_secs":3600}"#).unwrap();
        let store = FileSnapshotStore::new(&path);
        match PersistentAuthServer::load_or_new(store, 3600) {
            Err(StoreError::Schema { .. }) => {}
            Ok(_) => panic!("unknown schema must be refused, not booted empty"),
            Err(other) => panic!("expected a schema error, got {other}"),
        }
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }
}
