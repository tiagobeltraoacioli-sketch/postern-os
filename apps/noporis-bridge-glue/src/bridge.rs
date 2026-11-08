// SPDX-License-Identifier: MIT OR Apache-2.0
//! The two crossing roles, driven over the tested pairing `Channel` + `Transport`.
//!
//! * [`CrossingSender`] — the persona that HANDS something across. It holds the
//!   near-side [`CapabilityGrant`]s (the levers the user threw), a monotonic
//!   [`RequestCounter`], and the origin world. It refuses to send a capability it
//!   has no live grant for (*nothing crosses without a live grant*), then seals the
//!   envelope into the paired channel and puts it on the bearer.
//!
//! * [`CrossingReceiver`] — the persona that RECEIVES. It opens the sealed frame
//!   (the pairing channel's AEAD + monotonic-counter + session/direction binding),
//!   runs the per-crossing [`CrossingGuard`] (session/counter/nonce, fail-closed),
//!   then asks the [`GateConsent`] authority (deny-by-default) whether this
//!   capability may cross to it *right now*. Only on `Allow` does it commit the
//!   guard and deliver the payload; every other path fails closed.
//!
//! Both consent checks compose (defense in depth): the near side won't send
//! without a live grant, and the far side won't deliver without a live gate yes.
//! The pairing channel authenticates the *peer device key*, not intent — so the
//! per-crossing gate is what makes the crossing explicit and per-capability.

use postern_pairing::channel::{Channel as PairedChannel, ChannelError, Frame};
use postern_pairing::transport::Transport;
use postern_signer_protocol::{fresh_nonce, RequestCounter, SessionId};

use crate::audit::{AuditLedger, AuditTrail, CrossingDecision};
use crate::capability::Capability;
use crate::consent::{ConsentDecision, GateConsent};
use crate::consent_record::ConsentLedger;
use crate::crossing::{
    crossing_session_id, CrossedPayload, CrossingGuard, CrossingRequest, MAX_CROSSING_BYTES,
};
use crate::error::BridgeError;
use crate::grant::CapabilityGrant;
use crate::persona::Persona;

fn tx<E: std::fmt::Display>(e: E) -> BridgeError {
    BridgeError::Transport(e.to_string())
}

fn chan(e: ChannelError) -> BridgeError {
    BridgeError::Channel(e.to_string())
}

fn audit_err(e: postern_trail::ChainError) -> BridgeError {
    BridgeError::Audit(e.to_string())
}

// ── Sending persona (hands a capability across) ───────────────────────────────

/// The near side of a crossing: holds the levers the user threw and a monotonic
/// counter for this paired session. Holds no key and no secret beyond the grants.
pub struct CrossingSender {
    session_id: SessionId,
    counter: RequestCounter,
    from_persona: Persona,
    peer_device: String,
    grants: Vec<CapabilityGrant>,
    /// Append-only, in-memory, hash-chained near-side ledger: what this persona
    /// handed onto the bearer (size + SHA-256 digest, NEVER bytes). Complements
    /// [`AuditTrail`] (the durable file-backed trail wired through
    /// [`send_crossing_audited`](Self::send_crossing_audited)); this one lives for
    /// the process's lifetime and needs no path. Attribution, not confidentiality.
    audit: AuditLedger,
}

impl CrossingSender {
    /// Bind a sender to a paired session (its 32-byte `session_id` from the pairing
    /// `Channel`), naming the origin world and the peer this lane serves.
    pub fn new(
        paired_session_id: &[u8; 32],
        from_persona: Persona,
        peer_device: impl Into<String>,
    ) -> Self {
        let session_id = crossing_session_id(paired_session_id);
        CrossingSender {
            session_id,
            counter: RequestCounter::new(session_id),
            from_persona,
            peer_device: peer_device.into(),
            grants: Vec::new(),
            audit: AuditLedger::new(),
        }
    }

    /// The 16-byte crossing session id both personas derive from the paired session.
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// The append-only, in-memory near-side audit ledger (what was handed onto the
    /// bearer: size + digest, never bytes). Hash-chained and independently
    /// [`verify`](crate::audit::AuditLedger::verify)able.
    pub fn audit(&self) -> &AuditLedger {
        &self.audit
    }

    /// Open a lane: throw the lever for one capability to the paired peer for a
    /// world, until `expires_at_unix`. Replaces any prior grant for that
    /// `(capability)` so re-opening refreshes the window.
    pub fn open_lane(&mut self, capability: Capability, persona: Persona, expires_at_unix: i64) {
        self.grants.retain(|g| g.capability() != capability);
        self.grants.push(CapabilityGrant::new(
            &self.peer_device,
            persona,
            capability,
            expires_at_unix,
        ));
    }

    /// Revoke a lane (soft, per-capability): "stop lending the clipboard". Monotonic
    /// — the grant is dropped.
    pub fn revoke_lane(&mut self, capability: Capability) {
        for g in self.grants.iter_mut() {
            if g.capability() == capability {
                g.revoke();
            }
        }
        self.grants.retain(|g| !g.is_revoked());
    }

    /// Is there a live grant for `capability` to this peer/world at `now_unix`?
    pub fn has_live_grant(&self, capability: Capability, persona: Persona, now_unix: i64) -> bool {
        self.grants
            .iter()
            .any(|g| g.allows(&self.peer_device, persona, capability, now_unix))
    }

    /// Hand a capability payload across. Fail-closed order:
    /// 1. cap the payload size;
    /// 2. require a **live grant** for this capability/world (else `NotGranted`);
    /// 3. build the envelope (fresh nonce + monotonic counter + session binding);
    /// 4. seal it into the paired channel and put the frame on the bearer.
    ///
    /// Returns the sent [`CrossingRequest`] (for matching/inspection). The peer's
    /// gate still independently decides delivery — this only opens the near side.
    pub fn send_crossing<T: Transport>(
        &mut self,
        channel: &mut PairedChannel,
        transport: &mut T,
        capability: Capability,
        to_persona: Persona,
        payload: &[u8],
        now_unix: i64,
    ) -> Result<CrossingRequest, BridgeError> {
        if payload.len() > MAX_CROSSING_BYTES {
            return Err(BridgeError::PayloadTooLarge {
                len: payload.len(),
                max: MAX_CROSSING_BYTES,
            });
        }
        if !self.has_live_grant(capability, to_persona, now_unix) {
            return Err(BridgeError::NotGranted);
        }

        let req = CrossingRequest {
            session_id: self.session_id,
            req_nonce: fresh_nonce(),
            counter: self.counter.advance(),
            capability,
            from_persona: self.from_persona,
            payload: payload.to_vec(),
        };

        let plaintext = req.encode()?;
        let frame = channel.seal_frame(&plaintext).map_err(chan)?;
        transport.send(&frame.to_bytes()).map_err(tx)?;

        // Attribution: record WHAT crossed onto the bearer (size + digest, never
        // bytes) in the in-memory ledger. The far gate still decides delivery —
        // this is the near side only.
        self.audit.append(CrossingDecision::sent(
            self.session_id,
            req.counter,
            capability,
            self.from_persona,
            to_persona,
            payload,
            now_unix,
        ));
        Ok(req)
    }

    /// [`send_crossing`](Self::send_crossing), plus an append to the audit trail
    /// recording the **sent** event (size + SHA-256 digest, never the bytes). The
    /// send happens first; only a successful send is logged.
    #[allow(clippy::too_many_arguments)]
    pub fn send_crossing_audited<T: Transport>(
        &mut self,
        channel: &mut PairedChannel,
        transport: &mut T,
        capability: Capability,
        to_persona: Persona,
        payload: &[u8],
        now_unix: i64,
        now_iso: &str,
        audit: &mut AuditTrail,
    ) -> Result<CrossingRequest, BridgeError> {
        let req = self.send_crossing(channel, transport, capability, to_persona, payload, now_unix)?;
        audit
            .record_sent(&req, to_persona, now_iso)
            .map_err(audit_err)?;
        Ok(req)
    }
}

// ── Receiving persona (delivers only on a live gate yes) ──────────────────────

/// The far side of a crossing: opens the sealed frame, runs the replay guard, then
/// consults the deny-by-default [`GateConsent`] authority before delivering.
pub struct CrossingReceiver<G: GateConsent> {
    guard: CrossingGuard,
    /// The world this receiver is bound to receive FROM — derived from the
    /// pairing/lane at construction (e.g. the daemon's `CrossingLane`'s
    /// `direction.from`), never from the crossing itself. Every decoded crossing's
    /// claimed [`CrossingRequest::from_persona`] is cross-checked against this
    /// field and refused, fail-closed, on any mismatch (see
    /// [`CrossingReceiver::receive_crossing`] /
    /// [`CrossingReceiver::receive_crossing_audited`]) — so a compromised far side
    /// cannot mislabel its own world.
    from_persona: Persona,
    to_persona: Persona,
    gate: G,
    /// Append-only, in-memory, hash-chained far-side ledger: the double-gate
    /// verdict on every decoded crossing (size + SHA-256 digest, NEVER bytes).
    /// Complements [`AuditTrail`] (the durable file-backed trail wired through
    /// [`receive_crossing_audited`](Self::receive_crossing_audited)).
    audit: AuditLedger,
}

impl<G: GateConsent> CrossingReceiver<G> {
    /// Bind a receiver to the same paired session, naming the world it receives
    /// FROM (derived from the pairing/lane — every crossing's claimed origin is
    /// checked against this, fail-closed, on mismatch), the world it serves, and
    /// the gate that authorizes crossings into it.
    pub fn new(paired_session_id: &[u8; 32], from_persona: Persona, to_persona: Persona, gate: G) -> Self {
        let session_id = crossing_session_id(paired_session_id);
        CrossingReceiver {
            guard: CrossingGuard::new(session_id),
            from_persona,
            to_persona,
            gate,
            audit: AuditLedger::new(),
        }
    }

    /// The world this receiver derives crossings FROM (its pinned origin — never
    /// the crossing's own claim).
    pub fn from_persona(&self) -> Persona {
        self.from_persona
    }

    /// The 16-byte crossing session id (matches the sender's).
    pub fn session_id(&self) -> SessionId {
        self.guard.session_id()
    }

    /// The append-only, in-memory far-side audit ledger (the double-gate verdict
    /// on every decoded crossing: size + digest, never bytes). Hash-chained and
    /// independently [`verify`](crate::audit::AuditLedger::verify)able.
    pub fn audit(&self) -> &AuditLedger {
        &self.audit
    }

    /// Mutable access to the gate (e.g. to flip a lever / kill-switch in a demo or
    /// when the gate is embedded). In production this is Dev N-gate's authority.
    pub fn gate_mut(&mut self) -> &mut G {
        &mut self.gate
    }

    /// Receive and (maybe) deliver one crossing. Fail-closed order:
    /// 1. pull the frame off the bearer and OPEN it through the paired channel
    ///    (AEAD + the channel's own monotonic-counter/session/direction guard);
    /// 2. decode the envelope (undecodable → won't cross);
    /// 3. re-check the OPENED payload against [`MAX_CROSSING_BYTES`] — the
    ///    sender's own cap is a courtesy on the way out, not a guarantee on the
    ///    way in;
    /// 4. cross-check the crossing's claimed `from_persona` against this
    ///    receiver's derived [`CrossingReceiver::from_persona`] — a claim that
    ///    disagrees with the pairing/lane is refused before it can reach
    ///    anything else (the guard's log, the gate, the audit trail);
    /// 5. run the per-crossing [`CrossingGuard`] (session/counter/nonce);
    /// 6. ask the [`GateConsent`] authority — deny-by-default — for THIS capability
    ///    into THIS world;
    /// 7. only on `Allow`, commit the guard and deliver the (zeroizing) payload.
    ///
    /// Any failure leaves the guard un-committed, so a refused crossing never
    /// advances the sequence.
    pub fn receive_crossing<T: Transport>(
        &mut self,
        channel: &mut PairedChannel,
        transport: &mut T,
        now_unix: i64,
    ) -> Result<CrossedPayload, BridgeError> {
        let bytes = transport.recv().map_err(tx)?;
        let frame = Frame::from_bytes(&bytes).map_err(chan)?;
        let plaintext = channel.open_frame(&frame).map_err(chan)?;

        let req = CrossingRequest::decode(&plaintext)?;

        // Re-check the payload cap on the OPENED payload. `CrossingSender::
        // send_crossing` already refuses to send an oversized payload, but that is
        // the near side's own courtesy check — a compromised/divergent peer can
        // seal an oversized frame directly, bypassing it entirely. A validly-sealed
        // frame is not a validly-sized one; re-checked here, fail-closed.
        if req.payload.len() > MAX_CROSSING_BYTES {
            let e = BridgeError::PayloadTooLarge {
                len: req.payload.len(),
                max: MAX_CROSSING_BYTES,
            };
            self.audit.append(CrossingDecision::rejected(
                req.session_id,
                req.counter,
                req.capability,
                req.from_persona,
                self.to_persona,
                &req.payload,
                rejected_kind(&e),
                now_unix,
            ));
            return Err(e);
        }

        // The persona label is DERIVED from the pairing/lane (`self.from_persona`),
        // never trusted from the crossing's own claim. Cross-check before the claim
        // can flow anywhere else (the guard's own log, the gate, the audit trail's
        // `from` attribution) — a compromised far side cannot mislabel its world.
        if req.from_persona != self.from_persona {
            let e = BridgeError::FromPersonaMismatch {
                claimed: req.from_persona,
                expected: self.from_persona,
            };
            self.audit.append(CrossingDecision::rejected(
                req.session_id,
                req.counter,
                req.capability,
                req.from_persona,
                self.to_persona,
                &req.payload,
                rejected_kind(&e),
                now_unix,
            ));
            return Err(e);
        }

        // Replay / freshness — all three checks, no state mutation yet. A rejected
        // crossing is DECODED (attributable), so it is logged by size+digest.
        if let Err(e) = self.guard.check(&req) {
            self.audit.append(CrossingDecision::rejected(
                req.session_id,
                req.counter,
                req.capability,
                req.from_persona,
                self.to_persona,
                &req.payload,
                rejected_kind(&e),
                now_unix,
            ));
            return Err(e);
        }

        // The guarded crossing: deny-by-default N-gate decision for this capability.
        match self.gate.decide(req.capability, req.from_persona, self.to_persona) {
            ConsentDecision::Allow => {}
            ConsentDecision::Deny(reason) => {
                self.audit.append(CrossingDecision::denied(
                    req.session_id,
                    req.counter,
                    req.capability,
                    req.from_persona,
                    self.to_persona,
                    &req.payload,
                    reason.clone(),
                    now_unix,
                ));
                return Err(BridgeError::GateDenied(reason));
            }
        }

        // Accepted by BOTH gates: log the delivery (size+digest, never bytes),
        // advance the sequence, and deliver.
        self.guard.commit(&req);
        self.audit.append(CrossingDecision::delivered(
            req.session_id,
            req.counter,
            req.capability,
            req.from_persona,
            self.to_persona,
            &req.payload,
            now_unix,
        ));
        Ok(CrossedPayload {
            capability: req.capability,
            from_persona: req.from_persona,
            tier: req.capability.tier(),
            bytes: zeroize::Zeroizing::new(req.payload),
        })
    }

    /// The full functional crossing: open + guard + **signed [`ConsentLedger`]**
    /// (the 5-step check) + deny-by-default gate, with every outcome recorded to
    /// the [`AuditTrail`]. Fail-closed order:
    /// 1. pull + OPEN the frame (AEAD): a single-byte tamper is caught here and
    ///    propagates as [`BridgeError::Channel`] — nothing is delivered or, since we
    ///    cannot trust an unopenable frame's fields, logged;
    /// 2. decode the envelope, re-check the OPENED payload against
    ///    [`MAX_CROSSING_BYTES`] (the sender's own cap is a courtesy on the way
    ///    out, not a guarantee on the way in), and cross-check the crossing's
    ///    claimed `from_persona` against this receiver's derived
    ///    [`CrossingReceiver::from_persona`] — refused before the claim can reach
    ///    the direction-pinned consent check, the gate, or the audit trail's
    ///    `from` attribution;
    /// 3. per-crossing [`CrossingGuard`] (session/counter/nonce);
    /// 4. the signed consent 5-step check via `consent.authorize(...)`; a refusal
    ///    is logged **denied** (with the honest reason) and returned;
    /// 5. the deny-by-default gate; a refusal is logged **denied** and returned;
    /// 6. on the double-yes: commit the guard, **spend** a single-use consent,
    ///    log **delivered**, and hand over the (zeroizing) payload.
    #[allow(clippy::too_many_arguments)]
    pub fn receive_crossing_audited<T: Transport>(
        &mut self,
        channel: &mut PairedChannel,
        transport: &mut T,
        consent: &mut ConsentLedger,
        audit: &mut AuditTrail,
        now_unix: i64,
        now_iso: &str,
    ) -> Result<CrossedPayload, BridgeError> {
        let bytes = transport.recv().map_err(tx)?;
        let frame = Frame::from_bytes(&bytes).map_err(chan)?;
        // A flipped ciphertext byte fails AEAD here — tamper caught before any state.
        let plaintext = channel.open_frame(&frame).map_err(chan)?;

        let req = CrossingRequest::decode(&plaintext)?;

        // Re-check the payload cap on the OPENED payload — see the identical guard
        // in `receive_crossing` for why: `CrossingSender::send_crossing`'s own cap
        // check is a courtesy on the way OUT, not a guarantee on the way IN. A
        // compromised/divergent peer's validly-sealed frame can still be oversized.
        if req.payload.len() > MAX_CROSSING_BYTES {
            return Err(BridgeError::PayloadTooLarge {
                len: req.payload.len(),
                max: MAX_CROSSING_BYTES,
            });
        }

        // The persona label is DERIVED from the pairing/lane (`self.from_persona`,
        // set from the daemon's `CrossingLane`'s `direction.from`), never trusted
        // from the crossing's own claim. Cross-check BEFORE the claim can reach the
        // direction-pinning consent check, `GateConsent::decide`, or the durable
        // audit trail's `from` attribution — a compromised far side cannot mislabel
        // its own world or poison attribution by simply claiming to be someone else.
        if req.from_persona != self.from_persona {
            return Err(BridgeError::FromPersonaMismatch {
                claimed: req.from_persona,
                expected: self.from_persona,
            });
        }

        self.guard.check(&req)?;

        // Signed consent: the 5-step fail-closed check (+ the four revocation paths).
        let granted = match consent.authorize(
            &self.session_id(),
            req.capability,
            req.from_persona,
            self.to_persona,
            now_unix,
        ) {
            Ok(g) => g,
            Err(e) => {
                audit
                    .record_denied(&req, self.to_persona, now_iso, e.to_string())
                    .map_err(audit_err)?;
                return Err(BridgeError::ConsentRefused(e.to_string()));
            }
        };

        // Deny-by-default N-gate decision (defense in depth alongside the consent).
        match self.gate.decide(req.capability, req.from_persona, self.to_persona) {
            ConsentDecision::Allow => {}
            ConsentDecision::Deny(reason) => {
                audit
                    .record_denied(&req, self.to_persona, now_iso, reason.to_string())
                    .map_err(audit_err)?;
                return Err(BridgeError::GateDenied(reason));
            }
        }

        // Double-yes: commit, spend a single-use consent, log, deliver.
        self.guard.commit(&req);
        consent.commit_use(granted);
        audit
            .record_delivered(&req, self.to_persona, now_iso)
            .map_err(audit_err)?;
        Ok(CrossedPayload {
            capability: req.capability,
            from_persona: req.from_persona,
            tier: req.capability.tier(),
            bytes: zeroize::Zeroizing::new(req.payload),
        })
    }
}

/// Map a per-crossing guard refusal to a stable machine kind for the in-memory
/// audit ledger.
fn rejected_kind(e: &BridgeError) -> &'static str {
    match e {
        BridgeError::WrongSession => "wrong_session",
        BridgeError::StaleCounter { .. } => "stale_counter",
        BridgeError::ReplayedNonce => "replayed_nonce",
        BridgeError::PayloadTooLarge { .. } => "oversize",
        BridgeError::FromPersonaMismatch { .. } => "from_persona_mismatch",
        _ => "rejected",
    }
}
