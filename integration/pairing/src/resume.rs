// SPDX-License-Identifier: MIT OR Apache-2.0
//! Reconnect / session-resume — a **clean, fresh, forward-secret re-handshake**
//! authenticated by the persisted pairing (no repeated human SAS).
//!
//! ## The design decision (and why it is the safe one)
//! When a paired app restarts or the LAN link drops, the live channel is gone but
//! the [`PairingRecord`] (its pins + `session_root`) survives on disk (sealed —
//! [`crate::persist`]). Two ways to get talking again exist:
//!
//! 1. **Counter continuity** — persist the channel's send/recv counters and
//!    resume the *same* long-lived session key across the restart.
//! 2. **Clean re-handshake** — run a fresh ephemeral KEM on every reconnect,
//!    deriving a NEW session key + session id with counters reset to zero,
//!    authenticated by proving both sides know the shared `session_root`.
//!
//! **This crate implements (2), and refuses (1)**, because (1) is fragile in
//! exactly the way the anti-replay guards exist to prevent:
//! - reusing one session key across many restarts erodes the forward secrecy the
//!   ephemeral handshake bought (a later key-compromise reads more history);
//! - if the persisted counter is ever rolled back (a restored backup, a crash
//!   before the counter flush, a copied disk image), the monotonic-counter
//!   replay window **re-opens** — a captured frame replays.
//!
//! (2) sidesteps both: every reconnect is a brand-new session, so counters
//! legitimately start at zero and old frames fail the session-id AAD binding
//! (they were sealed under a different session). The `session_root` is the
//! pre-shared authenticator that lets us skip the human SAS: only the genuinely
//! paired devices hold it, so only they derive the matching resume key — an
//! active MITM without it derives a different key and the confirmation tag (and
//! then every frame) fails **closed**, which the caller must treat as "fall back
//! to a full re-pair with a fresh SAS".
//!
//! ## Shape
//! ```text
//! Offerer (either side)                       Responder (the peer)
//! --------------------                        --------------------
//! offer(&record) -------- ResumeOffer -------> accept(&record, &offer)
//!   fresh ephemeral hybrid keypair,             encapsulate -> es,
//!   fresh nonce                                 resume_key = KDF(session_root ‖ es),
//!                                               derive fresh Channel + confirm_tag
//!         <-------- ResumeAccept{kem_ct, tag} --
//! finish(&record, &accept):
//!   decapsulate -> es, resume_key = KDF(session_root ‖ es),
//!   CHECK confirm_tag (fail closed), derive fresh Channel
//! ```
//!
//! Both sides pick the channel direction from their persisted [`Role`]
//! (custodian = initiator), so the two endpoints always take opposite direction
//! labels regardless of who offered — see [`crate::channel`].
//!
//! ## Honest limits
//! - **A rooted endpoint (A5) defeats this too.** Whoever holds `session_root` in
//!   RAM can resume; resume authenticates the *paired device key material*, not
//!   that the software is honest. That is why consequential actions still need
//!   on-device WYSIWYS approval upstream.
//! - **Identity-key rotation is out of band.** If a peer's pinned identity key
//!   changed, [`PairingRecord::peer_matches`] must fail elsewhere and force a
//!   fresh SAS ceremony — resume does not silently re-pin.
//! - **Scaffold, unaudited.** Same rails as the rest of the crate.

use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::binding::{Nonce, NONCE_LEN};
use crate::channel::{self, Channel};
use crate::hybrid::{self, EphemeralKeypair, SessionKey};
use crate::record::{PairingRecord, Role};
use crate::PROTOCOL_VERSION;

/// HKDF label for the resume-key combiner. Distinct from the initial-pairing and
/// SAS labels so a resume key can never collide with a first-pairing key.
const RESUME_LABEL: &[u8] = b"postern-pairing/resume/v1";
/// HKDF label for the mutual confirmation tag.
const CONFIRM_LABEL: &[u8] = b"postern-pairing/resume/confirm/v1";
/// Length of the resume confirmation tag.
pub const CONFIRM_LEN: usize = 32;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ResumeError {
    /// The record is revoked — a revoked pairing cannot be resumed; re-pair.
    #[error("cannot resume a revoked pairing")]
    Revoked,
    /// The hybrid KEM step failed (bad offer / bad encapsulation).
    #[error("resume handshake failed: {0}")]
    Hybrid(#[from] hybrid::HybridError),
    /// The confirmation tag did not verify: the peer did not prove knowledge of
    /// the shared `session_root` (wrong record, or an active MITM). Fail-closed —
    /// the caller MUST fall back to a full re-pair with a fresh SAS.
    #[error("resume peer not authenticated (session_root mismatch / MITM) — re-pair with a fresh SAS")]
    Unauthenticated,
    /// A resume message was malformed on the wire.
    #[error("malformed resume message")]
    Malformed,
}

/// Which channel direction this device takes on resume, derived from its role so
/// the two endpoints always end up opposite. Custodian (phone) = initiator.
fn initiator_for(role: Role) -> bool {
    matches!(role, Role::Custodian)
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

/// Resume-key combiner: `HKDF-SHA-256(ikm = session_root ‖ es, info = label ‖
/// version ‖ nonce)`. `es` is the fresh ephemeral hybrid session secret; binding
/// `session_root` as pre-shared IKM is what authenticates the reconnect.
fn combine_resume(session_root: &[u8; 32], es: &SessionKey, nonce: &Nonce) -> SessionKey {
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(session_root);
    ikm[32..].copy_from_slice(&es[..]);

    let hk = Hkdf::<Sha256>::new(None, ikm.as_ref());
    let mut key: SessionKey = Zeroizing::new([0u8; 32]);
    hk.expand_multi_info(&[RESUME_LABEL, &[PROTOCOL_VERSION], nonce], key.as_mut())
        .expect("hkdf expand of 32 bytes is infallible");
    key
}

/// The mutual confirmation tag derived from the resume key (a separate HKDF
/// branch from the traffic key).
fn confirm_tag(resume_key: &SessionKey) -> [u8; CONFIRM_LEN] {
    let hk = Hkdf::<Sha256>::new(None, resume_key.as_ref());
    let mut tag = [0u8; CONFIRM_LEN];
    hk.expand(CONFIRM_LABEL, &mut tag)
        .expect("hkdf expand of 32 bytes is infallible");
    tag
}

/// Offerer -> responder: a fresh ephemeral anchor + nonce for this reconnect.
#[derive(Clone, Debug)]
pub struct ResumeOffer {
    pub version: u8,
    /// A fresh EPHEMERAL hybrid public key (forward secrecy for THIS reconnect).
    pub anchor_public: Vec<u8>,
    /// Fresh 32-byte reconnect nonce.
    pub nonce: Nonce,
}

/// Responder -> offerer: the encapsulation plus a tag proving the responder
/// derived the same resume key from the shared `session_root`.
#[derive(Clone, Debug)]
pub struct ResumeAccept {
    pub kem_ct: Vec<u8>,
    pub confirm_tag: [u8; CONFIRM_LEN],
}

/// Offerer-side state held between emitting the [`ResumeOffer`] and receiving the
/// [`ResumeAccept`].
pub struct ResumePending {
    keypair: EphemeralKeypair,
    nonce: Nonce,
    role: Role,
    session_root: Zeroizing<[u8; 32]>,
}

/// Reconnect entry points. Stateless namespace.
pub struct Resume;

impl Resume {
    /// Offerer side: begin a reconnect from a persisted, non-revoked record.
    /// Emits a [`ResumeOffer`] to send to the peer and a [`ResumePending`] to
    /// finish with.
    pub fn offer(record: &PairingRecord) -> Result<(ResumePending, ResumeOffer), ResumeError> {
        if record.is_revoked() {
            return Err(ResumeError::Revoked);
        }
        let keypair = EphemeralKeypair::generate();
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);

        let mut session_root = Zeroizing::new([0u8; 32]);
        session_root.copy_from_slice(&record.session_root[..]);

        let offer = ResumeOffer {
            version: PROTOCOL_VERSION,
            anchor_public: keypair.public.clone(),
            nonce,
        };
        let pending = ResumePending {
            keypair,
            nonce,
            role: record.role,
            session_root,
        };
        Ok((pending, offer))
    }

    /// Responder side: accept an offer, deriving a fresh forward-secret
    /// [`Channel`] bound to `session_root`. Returns the channel plus the
    /// [`ResumeAccept`] to send back. The channel is live immediately (its first
    /// sealed frame authenticates the peer even before the tag is checked at the
    /// offerer).
    pub fn accept(
        record: &PairingRecord,
        offer: &ResumeOffer,
    ) -> Result<(Channel, ResumeAccept), ResumeError> {
        if record.is_revoked() {
            return Err(ResumeError::Revoked);
        }
        if offer.version != PROTOCOL_VERSION {
            return Err(ResumeError::Malformed);
        }
        let (kem_ct, es) = hybrid::encapsulate_to(&offer.anchor_public, &offer.nonce)?;

        let mut session_root = Zeroizing::new([0u8; 32]);
        session_root.copy_from_slice(&record.session_root[..]);
        let resume_key = combine_resume(&session_root, &es, &offer.nonce);

        let channel = channel::open_endpoint(&resume_key, initiator_for(record.role));
        let accept = ResumeAccept {
            kem_ct,
            confirm_tag: confirm_tag(&resume_key),
        };
        Ok((channel, accept))
    }
}

impl ResumePending {
    /// Offerer side: finish the reconnect. Decapsulates, re-derives the resume
    /// key, and **verifies the confirmation tag** before handing back a live
    /// [`Channel`]. A tag mismatch is [`ResumeError::Unauthenticated`] — the peer
    /// could not prove it holds `session_root`; fail closed and re-pair.
    pub fn finish(self, accept: &ResumeAccept) -> Result<Channel, ResumeError> {
        let es = self.keypair.decapsulate(&accept.kem_ct, &self.nonce)?;
        let resume_key = combine_resume(&self.session_root, &es, &self.nonce);

        let expected = confirm_tag(&resume_key);
        if !ct_eq(&expected, &accept.confirm_tag) {
            return Err(ResumeError::Unauthenticated);
        }
        Ok(channel::open_endpoint(&resume_key, initiator_for(self.role)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::BINDING_LEN;
    use crate::hybrid::SESSION_KEY_LEN;

    fn paired_records() -> (PairingRecord, PairingRecord) {
        // Both devices share the same session_root (as they would after a real
        // ceremony) but hold opposite roles.
        let root = [0x77u8; SESSION_KEY_LEN];
        let phone = PairingRecord::new(
            Role::Custodian,
            "desk",
            vec![1, 2, 3],
            [0u8; BINDING_LEN],
            Zeroizing::new(root),
        );
        let desk = PairingRecord::new(
            Role::Terminal,
            "phone",
            vec![4, 5, 6],
            [0u8; BINDING_LEN],
            Zeroizing::new(root),
        );
        (phone, desk)
    }

    #[test]
    fn reconnect_yields_fresh_channels_that_talk() {
        let (phone_rec, desk_rec) = paired_records();

        // Phone offers, desktop accepts.
        let (pending, offer) = Resume::offer(&phone_rec).unwrap();
        let (mut desk_ch, accept) = Resume::accept(&desk_rec, &offer).unwrap();
        let mut phone_ch = pending.finish(&accept).unwrap();

        // Fresh session: counters start at zero, both directions work.
        let f = phone_ch.seal_frame(b"resumed: sign request").unwrap();
        assert_eq!(&**desk_ch.open_frame(&f).unwrap(), b"resumed: sign request");
        let g = desk_ch.seal_frame(b"resumed: approval").unwrap();
        assert_eq!(&**phone_ch.open_frame(&g).unwrap(), b"resumed: approval");
    }

    #[test]
    fn two_reconnects_derive_distinct_session_ids() {
        let (phone_rec, desk_rec) = paired_records();

        let (p1, o1) = Resume::offer(&phone_rec).unwrap();
        let (d1, a1) = Resume::accept(&desk_rec, &o1).unwrap();
        let c1 = p1.finish(&a1).unwrap();

        let (p2, o2) = Resume::offer(&phone_rec).unwrap();
        let (_d2, a2) = Resume::accept(&desk_rec, &o2).unwrap();
        let c2 = p2.finish(&a2).unwrap();

        // Fresh ephemeral each time -> different session ids (forward secrecy;
        // no cross-reconnect frame replay).
        assert_ne!(c1.session_id(), c2.session_id());
        let _ = d1;
    }

    #[test]
    fn wrong_session_root_fails_closed() {
        let (phone_rec, _desk_rec) = paired_records();
        // The "peer" holds a DIFFERENT session_root (not actually paired / MITM).
        let impostor = PairingRecord::new(
            Role::Terminal,
            "impostor",
            vec![9],
            [0u8; BINDING_LEN],
            Zeroizing::new([0xAAu8; SESSION_KEY_LEN]),
        );

        let (pending, offer) = Resume::offer(&phone_rec).unwrap();
        let (_ch, accept) = Resume::accept(&impostor, &offer).unwrap();
        // The offerer's tag check catches the mismatch -> fail closed.
        assert_eq!(pending.finish(&accept).unwrap_err(), ResumeError::Unauthenticated);
    }

    #[test]
    fn revoked_record_cannot_resume() {
        let (mut phone_rec, _d) = paired_records();
        phone_rec.revoke();
        assert!(matches!(Resume::offer(&phone_rec), Err(ResumeError::Revoked)));
    }

    #[test]
    fn tampered_confirm_tag_fails_closed() {
        let (phone_rec, desk_rec) = paired_records();
        let (pending, offer) = Resume::offer(&phone_rec).unwrap();
        let (_desk_ch, mut accept) = Resume::accept(&desk_rec, &offer).unwrap();
        accept.confirm_tag[0] ^= 0x01;
        assert_eq!(pending.finish(&accept).unwrap_err(), ResumeError::Unauthenticated);
    }
}
