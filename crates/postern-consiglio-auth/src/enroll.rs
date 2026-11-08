//! Enrollment — bind a wallet public key to a `(org, user, role)`.
//!
//! Enrollment is the trust root of wallet-as-login: whoever proves control of
//! the enrolled key IS that user. In the console this is the "enrollment
//! ceremony"; here it is a simple in-memory directory keyed by `(org, user)`.
//!
//! MVP-stub: an in-memory `HashMap`, no persistence, no admin dual-control on
//! the write path (the console requires officer approval to enroll/offboard).
//! The pubkey→user binding itself is real and is what the verifier checks.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::org::{OrgId, Role, User, UserId};

/// One enrolled identity: the wallet pubkey that speaks for this user + its role.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Enrollment {
    pub org_id: OrgId,
    pub user_id: UserId,
    pub role: Role,
    pub clearance: u8,
    /// The hybrid PQ public key bound to this user (ML-DSA-65 ‖ Falcon-1024).
    pub public_key: Vec<u8>,
}

impl Enrollment {
    /// Project the org-model [`User`] out of this enrollment.
    pub fn user(&self) -> User {
        User {
            org_id: self.org_id.clone(),
            user_id: self.user_id.clone(),
            role: self.role,
            clearance: self.clearance,
        }
    }
}

/// In-memory enrollment directory, keyed by `(org_id, user_id)`.
#[derive(Debug, Default)]
pub struct EnrollmentStore {
    inner: HashMap<(OrgId, UserId), Enrollment>,
}

impl EnrollmentStore {
    pub fn new() -> Self {
        Self { inner: HashMap::new() }
    }

    /// Enroll (or re-enroll / rotate) a user's wallet key. Returns the previous
    /// enrollment if this replaced one (i.e. a key rotation).
    pub fn enroll(&mut self, e: Enrollment) -> Option<Enrollment> {
        self.inner.insert((e.org_id.clone(), e.user_id.clone()), e)
    }

    /// Look up the enrollment for a user, if any.
    pub fn get(&self, org_id: &str, user_id: &str) -> Option<&Enrollment> {
        self.inner.get(&(org_id.to_string(), user_id.to_string()))
    }

    /// Offboard: remove a user's enrollment. Returns it if present.
    pub fn offboard(&mut self, org_id: &str, user_id: &str) -> Option<Enrollment> {
        self.inner.remove(&(org_id.to_string(), user_id.to_string()))
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// All enrollments, for snapshotting to a durable store (see
    /// [`crate::persist`]). Order is unspecified.
    pub fn all(&self) -> Vec<Enrollment> {
        self.inner.values().cloned().collect()
    }

    /// Rebuild a store from a flat list of enrollments (restore path).
    pub fn from_enrollments<I: IntoIterator<Item = Enrollment>>(items: I) -> Self {
        let mut store = Self::new();
        for e in items {
            store.enroll(e);
        }
        store
    }
}
