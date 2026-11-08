//! Challenge / response wire types and the signed login transcript.
//!
//! The server issues a random [`Challenge`]; the wallet returns a [`Response`]
//! carrying its public key + a hybrid PQ signature over the challenge transcript.
//! The transcript is domain-separated so a signature captured for one purpose
//! (org login) can never be replayed as another (e.g. a payment).

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::org::{OrgId, UserId};

/// Domain-separation tag — bound into every login transcript. Bump the version
/// suffix on any breaking change to the transcript layout.
pub const LOGIN_DOMAIN: &[u8] = b"consiglio:wallet-login:v1";

/// Default challenge lifetime, in seconds. Short: a login challenge is meant to
/// be answered immediately by an interactive wallet.
pub const DEFAULT_TTL_SECS: i64 = 120;

/// A server-issued login challenge. The `nonce` is the replay-guarded value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    /// The org the login is against.
    pub org_id: OrgId,
    /// The user the login claims to be (verified by the enrolled pubkey).
    pub user_id: UserId,
    /// 32 bytes of CSPRNG — the single-use anti-replay nonce.
    pub nonce: [u8; 32],
    /// Unix seconds when issued.
    pub issued_at: i64,
    /// Unix seconds after which the challenge is stale and MUST be rejected.
    pub expires_at: i64,
}

impl Challenge {
    /// The exact bytes the wallet must sign: a domain-separated SHA3-256 over
    /// (tag ‖ org ‖ user ‖ nonce ‖ issued_at). Both sides derive this the same
    /// way; the raw signature never covers ambiguous concatenations.
    pub fn transcript(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(LOGIN_DOMAIN);
        h.update((self.org_id.len() as u64).to_le_bytes());
        h.update(self.org_id.as_bytes());
        h.update((self.user_id.len() as u64).to_le_bytes());
        h.update(self.user_id.as_bytes());
        h.update(self.nonce);
        h.update(self.issued_at.to_le_bytes());
        h.finalize().into()
    }

    /// True once `now` (unix seconds) is past `expires_at`.
    pub fn is_expired(&self, now: i64) -> bool {
        now > self.expires_at
    }
}

/// The wallet's answer to a [`Challenge`].
///
/// `public_key` is the wallet's hybrid PQ public key (ML-DSA-65 ‖ Falcon-1024
/// bytes, exactly as `bloch_crypto` lays them out). The verifier checks it
/// against the pubkey enrolled for `(org_id, user_id)` AND checks that the
/// `signature` verifies over the challenge transcript — both must hold.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub org_id: OrgId,
    pub user_id: UserId,
    /// The nonce echoed back, so the verifier can locate/retire it.
    pub nonce: [u8; 32],
    /// Hybrid PQ public key bytes (the identity).
    pub public_key: Vec<u8>,
    /// Hybrid PQ signature over `Challenge::transcript()`.
    pub signature: Vec<u8>,
}
