// SPDX-License-Identifier: MIT OR Apache-2.0
//! # noporis-bridge-glue — the NoporIS "Kalinov crossing" DATA-CROSSING glue
//!
//! ## ⚠️ SCAFFOLD / reference-prototype — UNAUDITED. Certifies nothing.
//!
//! **Porog is the guarded *door*; NoporIS is the guarded *bridge*.** This crate is
//! the narrow net-new glue that carries an **approved crossing's payload** between
//! NoporIS's two personas — the clean/hardened world and the Google-Play world, on
//! **one** stock-Android handset — over the ALREADY-TESTED pairing channel's
//! consent model. It invents no crypto, no pairing, no signing, and no gate; it
//! **composes** the pieces the other devs shipped:
//!
//! ```text
//!  Persona A (sends)                                   Persona B (receives)
//!  ─────────────────                                   ────────────────────
//!  open_lane(cap, …)  ── a live CapabilityGrant ─┐
//!  send_crossing(cap, payload) ──────────────────┤
//!    fresh nonce + monotonic counter + session   │
//!    binding, SEALED into the pairing Channel     │
//!    (AEAD, per-dir counter, session AAD)  ───────┼──▶ receive_crossing()
//!                                                 │      open_frame (channel guard)
//!                                                 │      CrossingGuard (nonce/ctr/session)
//!                                                 │      GateConsent.decide(cap)  ← deny-by-default
//!                                                 │      Allow ⇒ deliver (zeroizing)
//!                                                 └──    Deny  ⇒ fail closed, nothing crosses
//! ```
//!
//! ### What it consumes (public APIs only — never edits their internals)
//! - [`postern_pairing`] — the PQ-hybrid (ML-KEM-1024‖X25519), SAS-anchored,
//!   mutually-authenticated `Channel` (`seal_frame`/`open_frame`, monotonic
//!   counter, session-id + direction in the AAD), the `Transport` bearer, and the
//!   `PairingRecord` peer pin / revoke.
//! - [`postern_signer_protocol`] — the consent-model PRIMITIVES: `SessionId`,
//!   `fresh_nonce()`, `RequestCounter`, and `ConsequenceTier`. The per-crossing
//!   replay guard here MIRRORS that crate's `ReplayGuard` (whose guard is typed to
//!   a `SignRequest`).
//! - The **N-gate consent decision** — Dev N-gate's `apps/noporis-gate/`
//!   deny-by-default authority — consumed through the [`consent::GateConsent`]
//!   seam. This crate never owns or edits that gate.
//!
//! ### Binding rails (carry these wherever the crossing appears — do not round off)
//! - **Reference-prototype, UNAUDITED.** Nothing here is built on hardware,
//!   attested, or deployed. Internal review is not an audit.
//! - **Nothing crosses without a live grant.** A crossing needs BOTH a live
//!   near-side [`grant::CapabilityGrant`] AND a live far-side gate `Allow`; both
//!   are fail-closed, time-boxed, revocable, per-capability, per-peer. There is no
//!   blanket "open all".
//! - **The Google-Play persona is the LESS-PRIVATE side by construction** — GMS
//!   phones home. The world label is DERIVED from the pairing, never from a field
//!   the requester controls; a compromised far side cannot mislabel its world.
//! - **The per-crossing gate is a userland, in-process check, NOT an OS/kernel
//!   boundary** (`EnforcementMode::ByConstruction`); only the managed-profile
//!   storage/process boundary is `KernelBoundary`, and that is not this crate. A
//!   **rooted/kernel-compromised host defeats every boundary here.**
//! - **This is an app on stock Android — NEVER "Postern OS."** The measured-boot
//!   path is Postern OS Mobile; NoporIS is not it. The guardian is **Yagabona**,
//!   never "Baba Yaga". The coin (BLCH) is not a security and buys no software.

#![forbid(unsafe_code)]

pub mod audit;
pub mod bridge;
pub mod capability;
pub mod consent;
pub mod consent_record;
pub mod crossing;
pub mod daemon;
pub mod error;
pub mod grant;
pub mod persona;
pub mod substrate;

pub use audit::{
    AuditEntry, AuditLedger, AuditTrail, CrossingDecision, CrossingEvent, CrossingOutcome,
    CrossingRecord, PayloadDigest,
};
pub use bridge::{CrossingReceiver, CrossingSender};
pub use capability::Capability;
pub use consent::{ConsentDecision, GateConsent, ReferenceGate};
pub use consent_record::{
    Authorized, ConsentAuthority, ConsentError, ConsentLedger, ConsentRecord, ConsentRequest,
    ConsentScope, Direction,
};
pub use crossing::{
    crossing_session_id, CrossedPayload, CrossingGuard, CrossingRequest, MAX_CROSSING_BYTES,
};
// The daemon core: the tick-driven state machine that composes the
// Orchestrator (persona-lifecycle reconcile) with CrossingReceiver +
// ConsentLedger (the signed, per-Direction crossing decision) into one
// running process. See `daemon`'s module doc for the full public surface
// F2's E2E loop drives.
pub use daemon::{CrossingLane, Daemon, DaemonConfig, DaemonReport, LaneErrors, LaneReport};
pub use error::{BridgeError, DenyReason};
pub use grant::CapabilityGrant;
pub use persona::Persona;
pub use substrate::{
    project_sloboda_bridge_state, project_sloboda_line, read_sloboda_bridge_state, write_atomic,
    DpcSeam, Enforcement, GateState, LaneDirections, LaneSet, Lifecycle, ManagedProfileSubstrate,
    Orchestrator,
    Reconciliation, SessionState, SlobodaCli, SlobodaSeam, StatePaths, Substrate, SubstrateError,
    SubstrateStatus, WaydroidSubstrate, WriterLock,
};
// The in-memory HOST substrate seams, behind the default `host-stub` feature.
// (`substrate::ConsentScope` is intentionally NOT re-exported at the root — it
// would clash with `consent_record::ConsentScope`; name it via the full path.)
#[cfg(feature = "host-stub")]
pub use substrate::{HostStubDpc, HostStubSloboda};

// Re-export the consumed consent-model vocabulary so downstreams need not also
// depend on the signer-protocol crate just to name a tier.
pub use postern_signer_protocol::{ConsequenceTier, SessionId};

#[cfg(test)]
mod tests {
    use super::*;
    use postern_pairing::channel::endpoints;
    use postern_pairing::hybrid::SessionKey;
    use postern_pairing::transport::{LoopbackPair, Transport};
    use zeroize::Zeroizing;

    /// Build a connected pair: two paired `Channel`s over one session key + a
    /// loopback bearer. Returns `(sender_channel, sender_tx, recv_channel, recv_tx,
    /// paired_session_id)`.
    fn wired() -> (
        postern_pairing::channel::Channel,
        postern_pairing::transport::LoopbackTransport,
        postern_pairing::channel::Channel,
        postern_pairing::transport::LoopbackTransport,
        [u8; 32],
    ) {
        let sk: SessionKey = Zeroizing::new([0x42u8; 32]);
        let (ch_a, ch_b) = endpoints(&sk);
        let sid = *ch_a.session_id();
        let (tx_a, tx_b) = LoopbackPair::new();
        (ch_a, tx_a, ch_b, tx_b, sid)
    }

    const NOW: i64 = 1_752_000_000;

    fn sender(sid: &[u8; 32]) -> CrossingSender {
        CrossingSender::new(sid, Persona::GooglePlay, "Tiago's Pixel · clean")
    }

    fn gate_allowing(cap: Capability) -> ReferenceGate {
        let mut g = ReferenceGate::new();
        g.accept_consent().open(cap);
        g
    }

    #[test]
    fn both_personas_derive_the_same_crossing_session_id() {
        let (_ca, _ta, _cb, _tb, sid) = wired();
        let s = CrossingSender::new(&sid, Persona::GooglePlay, "peer");
        let r = CrossingReceiver::new(&sid, Persona::GooglePlay, Persona::Clean, ReferenceGate::new());
        assert_eq!(s.session_id(), r.session_id());
    }

    #[test]
    fn happy_path_crosses_only_with_grant_and_gate_allow() {
        let (mut ca, mut ta, mut cb, mut tb, sid) = wired();
        let mut s = sender(&sid);
        let mut r = CrossingReceiver::new(&sid, Persona::GooglePlay, Persona::Clean, gate_allowing(Capability::Clipboard));

        // Near side opens the lane, then hands a clipboard blob across.
        s.open_lane(Capability::Clipboard, Persona::Clean, NOW + 600);
        let sent = s
            .send_crossing(&mut ca, &mut ta, Capability::Clipboard, Persona::Clean, b"hello world", NOW)
            .expect("send with live grant");
        assert_eq!(sent.capability, Capability::Clipboard);

        let got = r
            .receive_crossing(&mut cb, &mut tb, NOW)
            .expect("gate allows → delivered");
        assert_eq!(got.capability, Capability::Clipboard);
        assert_eq!(&*got.bytes, b"hello world");
        assert_eq!(got.from_persona, Persona::GooglePlay);
        assert_eq!(got.tier, ConsequenceTier::SingleTap);
    }

    #[test]
    fn no_grant_means_the_near_side_refuses_to_send() {
        let (mut ca, mut ta, _cb, _tb, sid) = wired();
        let mut s = sender(&sid);
        // No open_lane() call → no live grant.
        let err = s
            .send_crossing(&mut ca, &mut ta, Capability::Files, Persona::Clean, b"x", NOW)
            .unwrap_err();
        assert_eq!(err, BridgeError::NotGranted);
    }

    #[test]
    fn expired_grant_is_fail_closed() {
        let (mut ca, mut ta, _cb, _tb, sid) = wired();
        let mut s = sender(&sid);
        s.open_lane(Capability::Files, Persona::Clean, NOW); // expires exactly now
        let err = s
            .send_crossing(&mut ca, &mut ta, Capability::Files, Persona::Clean, b"x", NOW)
            .unwrap_err();
        assert_eq!(err, BridgeError::NotGranted);
    }

    #[test]
    fn revoked_lane_is_fail_closed() {
        let (mut ca, mut ta, _cb, _tb, sid) = wired();
        let mut s = sender(&sid);
        s.open_lane(Capability::Clipboard, Persona::Clean, NOW + 600);
        assert!(s.has_live_grant(Capability::Clipboard, Persona::Clean, NOW));
        s.revoke_lane(Capability::Clipboard);
        assert!(!s.has_live_grant(Capability::Clipboard, Persona::Clean, NOW));
        let err = s
            .send_crossing(&mut ca, &mut ta, Capability::Clipboard, Persona::Clean, b"x", NOW)
            .unwrap_err();
        assert_eq!(err, BridgeError::NotGranted);
    }

    #[test]
    fn gate_deny_by_default_stops_delivery_even_with_a_send() {
        let (mut ca, mut ta, mut cb, mut tb, sid) = wired();
        let mut s = sender(&sid);
        // Receiver gate: consent accepted but the capability lever is CLOSED.
        let mut gate = ReferenceGate::new();
        gate.accept_consent(); // clipboard stays closed (deny-by-default)
        let mut r = CrossingReceiver::new(&sid, Persona::GooglePlay, Persona::Clean, gate);

        s.open_lane(Capability::Clipboard, Persona::Clean, NOW + 600);
        s.send_crossing(&mut ca, &mut ta, Capability::Clipboard, Persona::Clean, b"secret", NOW)
            .expect("near side sends");

        let err = r.receive_crossing(&mut cb, &mut tb, NOW).unwrap_err();
        assert_eq!(err, BridgeError::GateDenied(DenyReason::CapabilityClosed));
    }

    #[test]
    fn kill_switch_cuts_the_span() {
        let (mut ca, mut ta, mut cb, mut tb, sid) = wired();
        let mut s = sender(&sid);
        let mut gate = gate_allowing(Capability::Location);
        gate.engage_kill_switch();
        let mut r = CrossingReceiver::new(&sid, Persona::GooglePlay, Persona::Clean, gate);

        s.open_lane(Capability::Location, Persona::Clean, NOW + 600);
        s.send_crossing(&mut ca, &mut ta, Capability::Location, Persona::Clean, b"gps", NOW)
            .expect("near side sends");
        let err = r.receive_crossing(&mut cb, &mut tb, NOW).unwrap_err();
        assert_eq!(err, BridgeError::GateDenied(DenyReason::KillSwitchEngaged));
    }

    #[test]
    fn consent_not_accepted_is_fail_closed() {
        let (mut ca, mut ta, mut cb, mut tb, sid) = wired();
        let mut s = sender(&sid);
        // Gate opened the lever but never accepted first-entry consent.
        let mut gate = ReferenceGate::new();
        gate.open(Capability::Mic);
        let mut r = CrossingReceiver::new(&sid, Persona::GooglePlay, Persona::Clean, gate);

        s.open_lane(Capability::Mic, Persona::Clean, NOW + 600);
        s.send_crossing(&mut ca, &mut ta, Capability::Mic, Persona::Clean, b"audio", NOW)
            .expect("near side sends");
        let err = r.receive_crossing(&mut cb, &mut tb, NOW).unwrap_err();
        assert_eq!(err, BridgeError::GateDenied(DenyReason::ConsentNotAccepted));
    }

    #[test]
    fn poisoned_gate_collapses_to_deny() {
        let (mut ca, mut ta, mut cb, mut tb, sid) = wired();
        let mut s = sender(&sid);
        let mut gate = gate_allowing(Capability::Camera);
        gate.poison();
        let mut r = CrossingReceiver::new(&sid, Persona::GooglePlay, Persona::Clean, gate);

        s.open_lane(Capability::Camera, Persona::Clean, NOW + 600);
        s.send_crossing(&mut ca, &mut ta, Capability::Camera, Persona::Clean, b"frame", NOW)
            .expect("near side sends");
        let err = r.receive_crossing(&mut cb, &mut tb, NOW).unwrap_err();
        assert_eq!(err, BridgeError::GateDenied(DenyReason::Malformed));
    }

    #[test]
    fn channel_layer_refuses_a_replayed_frame() {
        // Re-injecting the EXACT sealed bearer bytes is caught by the pairing
        // channel's own monotonic-counter guard, before the crossing layer.
        let (mut ca, mut ta, mut cb, mut tb, sid) = wired();
        let mut s = sender(&sid);
        let mut r =
            CrossingReceiver::new(&sid, Persona::GooglePlay, Persona::Clean, gate_allowing(Capability::Clipboard));

        s.open_lane(Capability::Clipboard, Persona::Clean, NOW + 600);
        s.send_crossing(&mut ca, &mut ta, Capability::Clipboard, Persona::Clean, b"once", NOW)
            .expect("send");

        // Grab the raw frame off the bearer, deliver it once, then replay it.
        let raw = tb.recv().expect("frame on the bearer");
        ta.send(&raw).unwrap();
        let got = r.receive_crossing(&mut cb, &mut tb, NOW).expect("first delivery");
        assert_eq!(&*got.bytes, b"once");

        ta.send(&raw).unwrap(); // replay the identical sealed frame
        let err = r.receive_crossing(&mut cb, &mut tb, NOW).unwrap_err();
        assert!(matches!(err, BridgeError::Channel(_)), "channel replay guard fires: {err:?}");
    }

    #[test]
    fn crossing_guard_refuses_a_resent_envelope() {
        // Belt-and-suspenders: a duplicate envelope (same nonce+counter) sealed as a
        // FRESH channel frame passes the channel guard but is caught by the
        // per-crossing CrossingGuard (its counter no longer advances).
        let (mut ca, mut ta, mut cb, mut tb, sid) = wired();
        let mut s = sender(&sid);
        let mut r =
            CrossingReceiver::new(&sid, Persona::GooglePlay, Persona::Clean, gate_allowing(Capability::Clipboard));

        s.open_lane(Capability::Clipboard, Persona::Clean, NOW + 600);
        let sent = s
            .send_crossing(&mut ca, &mut ta, Capability::Clipboard, Persona::Clean, b"once", NOW)
            .expect("send");
        let got = r.receive_crossing(&mut cb, &mut tb, NOW).expect("first delivery");
        assert_eq!(&*got.bytes, b"once");

        // Re-seal the SAME envelope on a new channel frame (channel counter advances
        // to 2, so `open_frame` accepts it), then deliver → crossing guard refuses.
        let frame = ca.seal_frame(&sent.encode().unwrap()).unwrap();
        ta.send(&frame.to_bytes()).unwrap();
        let err = r.receive_crossing(&mut cb, &mut tb, NOW).unwrap_err();
        assert!(
            matches!(err, BridgeError::StaleCounter { .. } | BridgeError::ReplayedNonce),
            "crossing replay guard fires: {err:?}"
        );
    }

    #[test]
    fn cross_session_crossing_is_refused() {
        // A crossing minted under one paired session must not verify under another.
        let sid_a = [1u8; 32];
        let sid_b = [2u8; 32];
        let guard_b = CrossingGuard::new(crossing_session_id(&sid_b));
        let req = CrossingRequest {
            session_id: crossing_session_id(&sid_a),
            req_nonce: [9u8; 32],
            counter: 1,
            capability: Capability::Files,
            from_persona: Persona::GooglePlay,
            payload: b"x".to_vec(),
        };
        assert_eq!(guard_b.check(&req), Err(BridgeError::WrongSession));
    }

    #[test]
    fn oversize_payload_is_refused() {
        let (mut ca, mut ta, _cb, _tb, sid) = wired();
        let mut s = sender(&sid);
        s.open_lane(Capability::Files, Persona::Clean, NOW + 600);
        let big = vec![0u8; MAX_CROSSING_BYTES + 1];
        let err = s
            .send_crossing(&mut ca, &mut ta, Capability::Files, Persona::Clean, &big, NOW)
            .unwrap_err();
        assert!(matches!(err, BridgeError::PayloadTooLarge { .. }));
    }

    #[test]
    fn envelope_round_trips_through_hex_wire_form() {
        let req = CrossingRequest {
            session_id: [7u8; 16],
            req_nonce: [3u8; 32],
            counter: 5,
            capability: Capability::Location,
            from_persona: Persona::Clean,
            payload: vec![0xde, 0xad, 0xbe, 0xef],
        };
        let bytes = req.encode().unwrap();
        let back = CrossingRequest::decode(&bytes).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn google_play_persona_is_labelled_less_private() {
        assert!(Persona::GooglePlay.is_less_private());
        assert!(!Persona::Clean.is_less_private());
        assert!(Persona::GooglePlay.label().contains("less private"));
    }

    #[test]
    fn delivered_crossing_is_audited_by_digest_never_bytes() {
        let (mut ca, mut ta, mut cb, mut tb, sid) = wired();
        let mut s = sender(&sid);
        let mut r =
            CrossingReceiver::new(&sid, Persona::GooglePlay, Persona::Clean, gate_allowing(Capability::Clipboard));

        s.open_lane(Capability::Clipboard, Persona::Clean, NOW + 600);
        s.send_crossing(&mut ca, &mut ta, Capability::Clipboard, Persona::Clean, b"hello world", NOW)
            .expect("send");
        let _ = r.receive_crossing(&mut cb, &mut tb, NOW).expect("delivered");

        // Near side logged a Sent; far side logged a Delivered — both by digest.
        assert_eq!(s.audit().len(), 1);
        assert_eq!(r.audit().len(), 1);
        let sent = &s.audit().entries()[0].record;
        let delivered = &r.audit().entries()[0].record;
        assert_eq!(sent.outcome, CrossingOutcome::Sent);
        assert_eq!(delivered.outcome, CrossingOutcome::Delivered);
        // Both recorded the SAME digest — attribution that the exact blob crossed.
        assert_eq!(sent.digest, delivered.digest);
        assert_eq!(delivered.digest.len, "hello world".len());
        assert_eq!(
            delivered.digest.hex(),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
        // The ledgers are hash-chained and internally consistent.
        assert!(s.audit().verify());
        assert!(r.audit().verify());
    }

    #[test]
    fn gate_denied_crossing_is_audited_with_the_reason() {
        let (mut ca, mut ta, mut cb, mut tb, sid) = wired();
        let mut s = sender(&sid);
        let mut gate = ReferenceGate::new();
        gate.accept_consent(); // clipboard lever stays closed → deny-by-default
        let mut r = CrossingReceiver::new(&sid, Persona::GooglePlay, Persona::Clean, gate);

        s.open_lane(Capability::Clipboard, Persona::Clean, NOW + 600);
        s.send_crossing(&mut ca, &mut ta, Capability::Clipboard, Persona::Clean, b"secret", NOW)
            .expect("near side sends");
        let _ = r.receive_crossing(&mut cb, &mut tb, NOW).unwrap_err();

        // The far side recorded the deny (by digest, never bytes) and did NOT deliver.
        assert_eq!(r.audit().len(), 1);
        let rec = &r.audit().entries()[0].record;
        assert_eq!(rec.outcome, CrossingOutcome::Denied(DenyReason::CapabilityClosed));
        assert!(!rec.crossed());
        assert_eq!(rec.digest.len, "secret".len());
        assert!(r.audit().verify());
    }

    #[test]
    fn sensor_capabilities_are_explicit_review_tier() {
        assert_eq!(Capability::Clipboard.tier(), ConsequenceTier::SingleTap);
        assert_eq!(Capability::Files.tier(), ConsequenceTier::SingleTap);
        assert_eq!(Capability::Mic.tier(), ConsequenceTier::ExplicitReview);
        assert_eq!(Capability::Camera.tier(), ConsequenceTier::ExplicitReview);
        assert_eq!(Capability::Location.tier(), ConsequenceTier::ExplicitReview);
    }
}
