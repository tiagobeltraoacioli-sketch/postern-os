// SPDX-License-Identifier: MIT OR Apache-2.0
//! The crossing envelope, its session anchor, and the per-crossing replay guard.
//!
//! A crossing carries an **opaque capability payload** (a clipboard blob, a file,
//! a sensor sample) plus exactly the freshness metadata the tested consent model
//! demands: a paired [`SessionId`], a `fresh_nonce()`, and a monotonic `counter`.
//! Everything on the wire is PUBLIC metadata + the opaque payload — there is no
//! human-text field the requester controls (the persona label is derived from the
//! pairing, not carried here as trusted prose).

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use postern_signer_protocol::SessionId;

use crate::capability::Capability;
use crate::error::BridgeError;
use crate::persona::Persona;

/// Scaffold cap on a single crossing's payload. Well under the pairing channel's
/// budget; real file crossing would chunk (future work).
pub const MAX_CROSSING_BYTES: usize = 16 * 1024;

/// Derive the 16-byte crossing [`SessionId`] from the pairing transcript's 32-byte
/// `session_id` (`postern_pairing::Channel::session_id`). Domain-separated so it
/// never collides with any other use of the paired session, and deterministic so
/// **both personas derive the same anchor** without exchanging a new secret.
pub fn crossing_session_id(paired_session_id: &[u8; 32]) -> SessionId {
    let mut h = Sha256::new();
    h.update(b"noporis:bridge-crossing:session:v1");
    h.update(paired_session_id);
    let d = h.finalize();
    let mut sid = [0u8; 16];
    sid.copy_from_slice(&d[..16]);
    sid
}

/// DESKTOP-of-the-crossing: the sending persona → the receiving persona. Carries
/// the session binding, a fresh nonce, a monotonic counter, the capability, the
/// (derived) origin world, and the opaque bytes. No trusted prose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossingRequest {
    /// Binds this crossing to one paired session (replay isolation across sessions).
    pub session_id: SessionId,
    /// Fresh per-crossing nonce — single-use, rejected on replay.
    pub req_nonce: [u8; 32],
    /// Monotonic per-session counter — must strictly advance.
    pub counter: u64,
    /// Which of the five bridges this crossing uses.
    pub capability: Capability,
    /// The world this crossing CLAIMS to originate from. This is the sender's own
    /// assertion — not, by itself, authority. The receiving
    /// [`crate::bridge::CrossingReceiver`] cross-checks this claim against its own
    /// derived origin (set at construction from the pairing/lane, e.g. a
    /// `CrossingLane`'s `direction.from`) and refuses the crossing, fail-closed, on
    /// any mismatch — so a compromised sender cannot mislabel its own world.
    pub from_persona: Persona,
    /// The opaque capability payload, hex-encoded on the wire.
    #[serde(with = "hexbytes")]
    pub payload: Vec<u8>,
}

impl CrossingRequest {
    /// Serialize the envelope to bytes for [`postern_pairing::Channel::seal_frame`].
    pub fn encode(&self) -> Result<Vec<u8>, BridgeError> {
        serde_json::to_vec(self).map_err(|e| BridgeError::Malformed(e.to_string()))
    }

    /// Decode an envelope from an opened frame. Fail-closed: an undecodable
    /// envelope is undisplayable, so it will not cross.
    pub fn decode(bytes: &[u8]) -> Result<CrossingRequest, BridgeError> {
        serde_json::from_slice(bytes).map_err(|e| BridgeError::Malformed(e.to_string()))
    }
}

/// The delivered result on the receiving side: the capability, the origin world,
/// its consequence tier, and the crossed bytes (wiped from RAM on drop).
#[derive(Debug, Clone)]
pub struct CrossedPayload {
    pub capability: Capability,
    pub from_persona: Persona,
    pub tier: postern_signer_protocol::ConsequenceTier,
    /// The bytes that crossed. Zeroized on drop — a clipboard/sensor sample must
    /// not linger in RAM after the receiver consumes it.
    pub bytes: zeroize::Zeroizing<Vec<u8>>,
}

/// Per-session anti-replay state for crossings, held on the receiving persona.
///
/// This **mirrors** `postern_signer_protocol::ReplayGuard` (whose `check` is typed
/// to a `SignRequest`, so a crossing needs its own) with the identical three
/// independent, fail-closed checks: session binding, monotonic counter, fresh
/// nonce. State advances only on an ACCEPTED crossing, so a rejected one never
/// poisons the sequence.
#[derive(Debug, Clone)]
pub struct CrossingGuard {
    session_id: SessionId,
    last_counter: u64,
    seen_nonces: HashSet<[u8; 32]>,
}

impl CrossingGuard {
    pub fn new(session_id: SessionId) -> Self {
        CrossingGuard {
            session_id,
            last_counter: 0,
            seen_nonces: HashSet::new(),
        }
    }

    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub fn last_counter(&self) -> u64 {
        self.last_counter
    }

    /// Validate a crossing against all three checks **without** mutating state.
    pub fn check(&self, req: &CrossingRequest) -> Result<(), BridgeError> {
        if req.session_id != self.session_id {
            return Err(BridgeError::WrongSession);
        }
        if req.counter <= self.last_counter {
            return Err(BridgeError::StaleCounter {
                got: req.counter,
                last: self.last_counter,
            });
        }
        if self.seen_nonces.contains(&req.req_nonce) {
            return Err(BridgeError::ReplayedNonce);
        }
        Ok(())
    }

    /// Commit an ACCEPTED crossing: advance the counter and retire its nonce. Call
    /// only after [`check`](Self::check) passed AND the gate allowed the crossing.
    pub fn commit(&mut self, req: &CrossingRequest) {
        self.last_counter = req.counter;
        self.seen_nonces.insert(req.req_nonce);
    }
}

/// serde helper: encode `Vec<u8>` as a hex string on the wire (compact vs a JSON
/// number array; everything here is PUBLIC opaque payload).
mod hexbytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The **authoritative** payload-size ceiling. This is the correctness gate the
    /// Rust receiver enforces on the *opened* payload (see
    /// `CrossingSender::send_crossing` / the `PayloadTooLarge` guard). It is the
    /// single source of truth; every other size bound reconciles to it.
    ///
    /// Mirror of the Kotlin broker's coarse DoS ceiling on the *sealed frame*
    /// (`CrossingBearerPolicy.MAX_SEALED_FRAME_BYTES`, `android-bridge/persona/.../
    /// bridge/CrossingBearerPolicy.kt`). The sealed frame is strictly larger than its
    /// payload (PQ-hybrid handshake material, per-direction counter, session AAD,
    /// AEAD tag), so the bearer ceiling is the payload ceiling plus framing headroom.
    /// It is duplicated here **on purpose** so this test fails the moment the two
    /// sides could silently diverge — the Kotlin half is asserted in
    /// `CrossingBearerPolicyTest` (`[BOX]`-run), this Rust half runs in CI now.
    const KOTLIN_BEARER_CEILING_BYTES: usize = 64 * 1024;

    #[test]
    fn max_crossing_bytes_is_pinned() {
        // Exact pin: a change to the authoritative payload ceiling trips this test,
        // forcing whoever bumps it to consciously re-check the broker reconciliation
        // below (and the Kotlin `MAX_SEALED_FRAME_BYTES` on the far side).
        assert_eq!(
            MAX_CROSSING_BYTES,
            16 * 1024,
            "MAX_CROSSING_BYTES is the authoritative payload ceiling; changing it must be deliberate"
        );
    }

    #[test]
    fn broker_bearer_ceiling_is_never_below_the_payload_ceiling() {
        // The fail-closed size ordering the broker doc-comment asserts in prose
        // (CrossingBearerPolicy.kt:33–41), pinned as an executable invariant: the
        // coarse bearer ceiling must NEVER drop below the authoritative payload
        // ceiling, or a payload the receiver would accept could be refused at the
        // door (or, worse, the ceilings could be reordered by a careless edit).
        assert!(
            KOTLIN_BEARER_CEILING_BYTES >= MAX_CROSSING_BYTES,
            "bearer ceiling {KOTLIN_BEARER_CEILING_BYTES} must be >= payload ceiling {MAX_CROSSING_BYTES}"
        );
        // And strictly larger — the sealed frame carries framing overhead beyond the
        // payload, so equality would mean zero headroom (a silent divergence risk).
        assert!(
            KOTLIN_BEARER_CEILING_BYTES > MAX_CROSSING_BYTES,
            "the sealed frame is larger than its payload; the bearer ceiling needs headroom"
        );
        // Pin the mirrored Kotlin value too, so a change on EITHER side (this const
        // or the Kotlin `MAX_SEALED_FRAME_BYTES`) forces the other to be re-examined.
        assert_eq!(KOTLIN_BEARER_CEILING_BYTES, 64 * 1024);
    }

    fn req(session_id: SessionId, counter: u64, nonce: [u8; 32]) -> CrossingRequest {
        CrossingRequest {
            session_id,
            req_nonce: nonce,
            counter,
            capability: Capability::Clipboard,
            from_persona: Persona::GooglePlay,
            payload: b"x".to_vec(),
        }
    }

    #[test]
    fn guard_rejects_wrong_session_stale_counter_and_replayed_nonce() {
        let sid = crossing_session_id(&[1u8; 32]);
        let other = crossing_session_id(&[2u8; 32]);
        let mut guard = CrossingGuard::new(sid);

        // Wrong session — fail-closed, state untouched.
        assert_eq!(
            guard.check(&req(other, 1, [1u8; 32])),
            Err(BridgeError::WrongSession)
        );

        // First good crossing checks, then commit advances the sequence.
        let first = req(sid, 1, [1u8; 32]);
        assert!(guard.check(&first).is_ok());
        guard.commit(&first);
        assert_eq!(guard.last_counter(), 1);

        // A non-advancing counter is stale.
        assert!(matches!(
            guard.check(&req(sid, 1, [2u8; 32])),
            Err(BridgeError::StaleCounter { got: 1, last: 1 })
        ));

        // A retired nonce replayed (even with an advancing counter) is refused.
        assert_eq!(
            guard.check(&req(sid, 2, [1u8; 32])),
            Err(BridgeError::ReplayedNonce)
        );

        // A fresh nonce with an advancing counter passes.
        assert!(guard.check(&req(sid, 2, [9u8; 32])).is_ok());
    }

    #[test]
    fn a_rejected_crossing_never_advances_the_sequence() {
        // check() is pure; only commit() moves state. A refused crossing must leave
        // last_counter untouched so it cannot poison a later legitimate one.
        let sid = crossing_session_id(&[3u8; 32]);
        // `check()` is pure (takes `&self`); this guard is never mutated — a rejected
        // crossing must not advance state, which is exactly what we assert below.
        let guard = CrossingGuard::new(sid);
        let _ = guard.check(&req(other_session(), 5, [7u8; 32]));
        assert_eq!(guard.last_counter(), 0, "a failed check must not advance state");
        let good = req(sid, 1, [7u8; 32]);
        assert!(guard.check(&good).is_ok());
    }

    fn other_session() -> SessionId {
        crossing_session_id(&[99u8; 32])
    }

    #[test]
    fn crossing_session_id_is_deterministic_and_domain_separated() {
        // Both personas derive the same 16-byte anchor from the paired session id…
        let paired = [0x5Au8; 32];
        assert_eq!(crossing_session_id(&paired), crossing_session_id(&paired));
        // …and a different paired session yields a different anchor.
        assert_ne!(crossing_session_id(&paired), crossing_session_id(&[0x5Bu8; 32]));
    }
}
