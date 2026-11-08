// SPDX-License-Identifier: MIT OR Apache-2.0
//! Reconnect / session-resume hardening for the phone-side anti-replay guard.
//!
//! The phone's [`ReplayGuard`] is what makes every sign request single-use
//! (session binding + monotonic counter + fresh nonce, all fail-closed —
//! [`crate::replay`]). Its state lives in RAM, so a phone restart resets it. This
//! module lets the phone **persist the anti-replay watermark** (the last accepted
//! counter, per session) so a restart cannot silently roll it back and re-open
//! the replay window for a resumed session.
//!
//! ## The reconnect model (consistent with `postern-pairing`)
//! The RECOMMENDED reconnect path is the one `postern-pairing::resume` implements:
//! every reconnect mints a **fresh session** (new session id, new channel key,
//! counters from zero). Under that model an old captured request fails the
//! session-binding check ([`crate::ProtocolError::WrongSession`]) outright, so
//! cross-restart replay is already impossible and no watermark is needed.
//!
//! This module is **defense-in-depth** for the case a deployment keeps a *stable*
//! `session_id` across a brief transport drop (rather than a full pairing-resume):
//! restoring the watermark keeps the monotonic counter from rewinding across the
//! restart. Use [`seal_watermark`] on a clean shutdown / periodically, and
//! [`open_watermark`] on startup to rebuild the guard with its counter intact.
//!
//! ## Authenticated, not encrypted — and why that is correct here
//! Unlike a `PairingRecord` (which holds the secret `session_root` and is sealed
//! for confidentiality), the watermark is **not secret** — it is a session id and
//! a counter. What it needs is **integrity + anti-rollback**, not secrecy. So it
//! is protected with a keyed MAC (SHA3-256, which is not length-extendable, so a
//! prefix key is a sound MAC), context-bound and fail-closed:
//!
//! ```text
//! blob = MAGIC ‖ format ‖ session_id(16) ‖ last_counter(8, LE) ‖ mac(32)
//! mac  = SHA3-256( len(key) ‖ key ‖ WATERMARK_CONTEXT ‖ MAGIC ‖ format
//!                  ‖ session_id ‖ last_counter )
//! ```
//!
//! A wrong `storage_key`, a tampered counter, or a swapped session id all make the
//! MAC check fail → [`ResumeError::Unauthenticated`] and NO guard. Using a MAC
//! (rather than an AEAD over non-secret data) also keeps this crate dependency-
//! light — it needs no cipher, only the `sha3` it already uses.
//!
//! ## Honest limits
//! - A rooted endpoint (A5) that can rewrite BOTH the blob and forge the MAC
//!   (i.e. holds `storage_key`) defeats this; it is anti-rollback against a
//!   passive/offline tamper, not against ring-0 on the phone.
//! - It does not persist the nonce set (unbounded); the counter is the primary
//!   gate and the fresh-session reconnect model covers the rest.
//! - Scaffold, unaudited. Software signing in RAM is not a hardware wallet. The
//!   coin (BLCH) is not a security.

use sha3::{Digest, Sha3_256};

use crate::message::SessionId;
use crate::replay::ReplayGuard;

/// Domain string binding a watermark blob to this purpose (and separating it from
/// any other use of the same `storage_key`).
pub const WATERMARK_CONTEXT: &[u8] = b"postern:signer-protocol:replay-watermark:v1";

const WM_MAGIC: &[u8; 4] = b"PSRW";
const WM_FORMAT: u8 = 1;
const MAC_LEN: usize = 32;
const SID_LEN: usize = 16;
/// Total watermark blob length: magic(4) ‖ format(1) ‖ sid(16) ‖ counter(8) ‖ mac(32).
const WM_LEN: usize = 4 + 1 + SID_LEN + 8 + MAC_LEN;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ResumeError {
    /// The blob is the wrong length or carries the wrong magic.
    #[error("watermark blob is malformed")]
    Malformed,
    /// The blob is a format this build does not understand.
    #[error("unsupported watermark format")]
    Version,
    /// The MAC did not verify: wrong key, or tampered / rolled-back state.
    /// Fail-closed — no guard is produced.
    #[error("watermark authentication failed — wrong key or tampered state (fail closed)")]
    Unauthenticated,
}

/// Constant-time tag comparison.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn mac(storage_key: &[u8], session_id: &SessionId, last_counter: u64) -> [u8; MAC_LEN] {
    let mut h = Sha3_256::new();
    // Length-prefix the key so (key ‖ rest) is unambiguous.
    h.update((storage_key.len() as u64).to_le_bytes());
    h.update(storage_key);
    h.update(WATERMARK_CONTEXT);
    h.update(WM_MAGIC);
    h.update([WM_FORMAT]);
    h.update(session_id);
    h.update(last_counter.to_le_bytes());
    h.finalize().into()
}

/// Serialise + authenticate a guard's anti-replay watermark for storage. The
/// returned bytes are safe to persist (they carry no secret); their integrity is
/// what matters. Call on a clean shutdown or periodically.
pub fn seal_watermark(guard: &ReplayGuard, storage_key: &[u8]) -> Vec<u8> {
    let sid = guard.session_id();
    let last_counter = guard.last_counter();
    let tag = mac(storage_key, &sid, last_counter);

    let mut out = Vec::with_capacity(WM_LEN);
    out.extend_from_slice(WM_MAGIC);
    out.push(WM_FORMAT);
    out.extend_from_slice(&sid);
    out.extend_from_slice(&last_counter.to_le_bytes());
    out.extend_from_slice(&tag);
    out
}

/// Verify + restore a guard from a persisted watermark. Fail-closed: a wrong key
/// or any tamper yields [`ResumeError::Unauthenticated`] and NO guard, so a caller
/// that cannot authenticate the watermark must start a fresh session rather than
/// trust a rewound counter.
pub fn open_watermark(blob: &[u8], storage_key: &[u8]) -> Result<ReplayGuard, ResumeError> {
    if blob.len() != WM_LEN {
        return Err(ResumeError::Malformed);
    }
    if &blob[..4] != WM_MAGIC {
        return Err(ResumeError::Malformed);
    }
    if blob[4] != WM_FORMAT {
        return Err(ResumeError::Version);
    }
    let mut sid: SessionId = [0u8; SID_LEN];
    sid.copy_from_slice(&blob[5..5 + SID_LEN]);
    let last_counter = u64::from_le_bytes(
        blob[5 + SID_LEN..5 + SID_LEN + 8]
            .try_into()
            .map_err(|_| ResumeError::Malformed)?,
    );
    let stored_tag = &blob[5 + SID_LEN + 8..];

    let expected = mac(storage_key, &sid, last_counter);
    if !ct_eq(stored_tag, &expected) {
        return Err(ResumeError::Unauthenticated);
    }
    Ok(ReplayGuard::restore(sid, last_counter))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::SignRequest;
    use crate::SignPayload;
    use crate::message::LoginChallenge;

    fn login() -> LoginChallenge {
        LoginChallenge {
            org: "acme".into(),
            user: "alice".into(),
            nonce: [1u8; 32],
            issued_at: 1_752_000_000,
        }
    }

    fn req(session: SessionId, counter: u64, nonce: u8) -> SignRequest {
        SignRequest {
            session_id: session,
            req_nonce: [nonce; 32],
            counter,
            payload: SignPayload::Login(login()).encode(),
        }
    }

    #[test]
    fn watermark_roundtrip_preserves_counter() {
        let key = b"device-storage-key";
        let session = [7u8; 16];
        let mut guard = ReplayGuard::new(session);
        // Accept up to counter 5.
        for c in 1..=5u64 {
            let r = req(session, c, c as u8);
            guard.check(&r).unwrap();
            guard.commit(&r);
        }
        let blob = seal_watermark(&guard, key);

        // "Restart": rebuild the guard from the blob.
        let restored = open_watermark(&blob, key).unwrap();
        assert_eq!(restored.last_counter(), 5);
        assert_eq!(restored.session_id(), session);

        // A replay of counter 5 (or lower) is still stale after the restart —
        // the watermark was NOT rolled back.
        let replay = req(session, 5, 0x99);
        assert!(matches!(
            restored.check(&replay),
            Err(crate::ProtocolError::StaleCounter { .. })
        ));
        // Counter 6 (genuine next) is accepted.
        assert!(restored.check(&req(session, 6, 0x06)).is_ok());
    }

    #[test]
    fn wrong_key_fails_closed() {
        let session = [3u8; 16];
        let guard = ReplayGuard::restore(session, 9);
        let blob = seal_watermark(&guard, b"key-A");
        assert_eq!(
            open_watermark(&blob, b"key-B").unwrap_err(),
            ResumeError::Unauthenticated
        );
    }

    #[test]
    fn tampered_counter_fails_closed() {
        let session = [4u8; 16];
        let guard = ReplayGuard::restore(session, 42);
        let mut blob = seal_watermark(&guard, b"key");
        // Flip a byte in the counter field (offset 5 + 16).
        blob[5 + SID_LEN] ^= 0xFF;
        assert_eq!(
            open_watermark(&blob, b"key").unwrap_err(),
            ResumeError::Unauthenticated
        );
    }

    #[test]
    fn malformed_blob_is_rejected() {
        assert_eq!(open_watermark(&[0u8; 4], b"key").unwrap_err(), ResumeError::Malformed);
        let mut blob = seal_watermark(&ReplayGuard::restore([0u8; 16], 1), b"key");
        blob[0] ^= 0xFF; // break magic
        assert_eq!(open_watermark(&blob, b"key").unwrap_err(), ResumeError::Malformed);
    }
}
