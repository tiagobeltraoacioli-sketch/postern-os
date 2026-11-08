//! Durability seam: snapshot / restore the whole [`AuthServer`] state.
//!
//! The reference scaffold held enrollment, nonce, session, and pending-change
//! state in in-memory `HashMap`s with no persistence — a restart forgot every
//! enrollment and logged everyone out. Production wants these behind a durable
//! store (Postgres/Redis). Rather than bake a specific backend into this crate,
//! this module exposes a plain, serializable [`ServerSnapshot`]: a deployment
//! serializes it to whatever store it runs (a row, a Redis blob, a file) and
//! restores on boot.
//!
//! Snapshots are pure data — no secret key material lives here (the wallet holds
//! private keys; the server only ever stores *public* keys + metadata). Nonces
//! are hex-encoded so the snapshot is valid JSON (a `[u8;32]` map key is not).
//!
//! Schema `/2` added the dynamic Brewer–Nash wall history ([`CoiBinding`]) so
//! the wall survives a restart — a restart must not reset who is bound to
//! which dataset. `/1` snapshots are still restorable ([`schema_supported`])
//! and restore with an EMPTY wall history, which is honest: no binding can
//! predate the wall's existence.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::control::PendingChange;
use crate::enroll::{Enrollment, EnrollmentStore};
use crate::server::{AuthServer, IssuedNonce, Session};

/// One persisted dynamic-Brewer–Nash wall binding: `(org, user)` is bound to
/// `dataset` within conflict-of-interest class `coi_class` (the first dataset
/// they were granted in that class). See `AuthServer::authorize` step 4.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoiBinding {
    pub org_id: String,
    pub user_id: String,
    pub coi_class: String,
    pub dataset: String,
}

/// A serializable snapshot of all [`AuthServer`] state. Persist this and restore
/// it on boot to survive a restart. Schema-versioned so a future layout change
/// is detectable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSnapshot {
    /// Snapshot schema version — bump on any breaking layout change.
    pub schema: String,
    pub enrollments: Vec<Enrollment>,
    /// Live challenges: (nonce-hex, owner+expiry).
    pub issued: Vec<(String, IssuedNonce)>,
    /// Spent nonces: (nonce-hex, consumed-at unix-seconds).
    pub consumed: Vec<(String, i64)>,
    pub sessions: Vec<Session>,
    pub pending: Vec<PendingChange>,
    pub session_ttl_secs: i64,
    /// Dynamic Brewer–Nash wall bindings (schema `/2`). `#[serde(default)]`
    /// so a `/1` snapshot — written before the wall existed — still restores:
    /// it restores with an EMPTY wall history (documented, acceptable — no
    /// binding predates the wall), never with a misread one.
    #[serde(default)]
    pub coi_history: Vec<CoiBinding>,
}

/// The current snapshot schema tag. `/2` added the persisted dynamic
/// Brewer–Nash wall history (`coi_history`).
pub const SNAPSHOT_SCHEMA: &str = "postern.consiglio.server-snapshot/2";

/// The previous snapshot schema tag — still restorable ([`schema_supported`]):
/// a `/1` snapshot predates the wall and restores with an empty `coi_history`.
pub const SNAPSHOT_SCHEMA_V1: &str = "postern.consiglio.server-snapshot/1";

/// Whether this build can restore a snapshot written under `schema`. `/1` is
/// accepted (empty wall history); anything else is refused fail-closed by the
/// durable stores in [`crate::store`].
pub fn schema_supported(schema: &str) -> bool {
    schema == SNAPSHOT_SCHEMA || schema == SNAPSHOT_SCHEMA_V1
}

impl AuthServer {
    /// Capture the full server state as a serializable [`ServerSnapshot`].
    pub fn snapshot(&self) -> ServerSnapshot {
        ServerSnapshot {
            schema: SNAPSHOT_SCHEMA.to_string(),
            enrollments: self.enrollments().all(),
            issued: self
                .issued
                .iter()
                .map(|(n, v)| (hex32(n), v.clone()))
                .collect(),
            consumed: self.consumed.iter().map(|(n, ts)| (hex32(n), *ts)).collect(),
            sessions: self.sessions.values().cloned().collect(),
            pending: self.pending.values().cloned().collect(),
            session_ttl_secs: self.session_ttl_secs,
            coi_history: {
                let mut bindings = Vec::new();
                for ((org_id, user_id), classes) in &self.coi_history {
                    for (coi_class, dataset) in classes {
                        bindings.push(CoiBinding {
                            org_id: org_id.clone(),
                            user_id: user_id.clone(),
                            coi_class: coi_class.clone(),
                            dataset: dataset.clone(),
                        });
                    }
                }
                bindings
            },
        }
    }

    /// Rebuild an [`AuthServer`] from a previously captured [`ServerSnapshot`].
    /// Fail-closed on a bad nonce encoding: a malformed nonce is skipped rather
    /// than corrupting the replay guard.
    ///
    /// The pending-change max age is SERVER CONFIG, not persisted state (the
    /// snapshot schema is unchanged — `PendingChange.created_at` was already
    /// serialized): a restored server starts at the default
    /// ([`crate::server::DEFAULT_PENDING_CHANGE_TTL_SECS`]); override with
    /// [`AuthServer::with_pending_change_ttl`]. Restored pending changes are
    /// still aged against their persisted `created_at`, so a stale proposal
    /// cannot dodge the TTL by riding through a restart.
    pub fn restore(snap: ServerSnapshot) -> Self {
        let mut server = AuthServer::new(EnrollmentStore::from_enrollments(snap.enrollments))
            .with_session_ttl(snap.session_ttl_secs);

        for (n, v) in snap.issued {
            if let Some(nonce) = unhex32(&n) {
                server.issued.insert(nonce, v);
            }
        }
        for (n, ts) in snap.consumed {
            if let Some(nonce) = unhex32(&n) {
                server.consumed.insert(nonce, ts);
            }
        }
        let mut sessions = HashMap::new();
        for s in snap.sessions {
            sessions.insert(s.id.clone(), s);
        }
        server.sessions = sessions;
        let mut pending = HashMap::new();
        for c in snap.pending {
            pending.insert(c.id.clone(), c);
        }
        server.pending = pending;
        // Dynamic Brewer–Nash wall bindings — absent in a `/1` snapshot, which
        // restores with an empty (not misread) history.
        for b in snap.coi_history {
            server
                .coi_history
                .entry((b.org_id, b.user_id))
                .or_default()
                .insert(b.coi_class, b.dataset);
        }

        server
    }
}

fn hex32(n: &[u8; 32]) -> String {
    n.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}
