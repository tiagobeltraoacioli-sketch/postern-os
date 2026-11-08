// SPDX-License-Identifier: MIT OR Apache-2.0
//! The two roles, driven over Dev1's [`Channel`]:
//!
//! * [`DesktopRequester`] — the **terminal that holds NO key**. It builds a
//!   [`SignRequest`] with a fresh nonce + monotonic counter + session binding,
//!   sends it, and later matches the returned [`Approval`] to the request it made.
//! * [`PhoneApprover`] — the **custodian that holds the key**. It receives a
//!   request, runs the replay guard (fail-closed), decodes the payload, renders
//!   WYSIWYS, and — on a human (or grant-covered single-tap) approval — signs the
//!   canonical digest and returns only a signature.
//!
//! The desktop→phone direction carries the request; phone→desktop carries the
//! approval. The private key never crosses either way (structural, `crate::secret`).

use crate::channel::{deframe, frame, Channel};
use crate::error::ProtocolError;
use crate::grant::ApprovalGrant;
use crate::message::{Approval, LoginChallenge, SessionId, SignPayload, SignRequest};
use crate::replay::ReplayGuard;
use crate::session::{fresh_nonce, RequestCounter};
use crate::signer::WalletSigner;
use crate::wysiwys::{render, ConsequenceTier, Wysiwys};

/// Map any transport error into a `ProtocolError::Transport`.
fn tx<E: std::fmt::Display>(e: E) -> ProtocolError {
    ProtocolError::Transport(e.to_string())
}

// ── Desktop (requester, holds nothing) ────────────────────────────────────────

/// The desktop side. Holds a monotonic counter for one paired session and no key.
pub struct DesktopRequester {
    counter: RequestCounter,
}

/// A handle the desktop keeps to match the eventual [`Approval`] to the request it
/// sent (Design §3.2 step 5–6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentRequest {
    pub session_id: SessionId,
    pub req_nonce: [u8; 32],
    pub counter: u64,
    /// The digest the phone should have signed (desktop recomputes it from the
    /// payload it sent, so it can bind the returned signature to this request).
    pub expected_digest: [u8; 32],
}

impl DesktopRequester {
    pub fn new(session_id: SessionId) -> Self {
        DesktopRequester {
            counter: RequestCounter::new(session_id),
        }
    }

    /// Build and send a **wallet-login** sign request (the v1 flow). Returns the
    /// [`SentRequest`] to match the approval against.
    pub fn request_login<C: Channel>(
        &mut self,
        channel: &mut C,
        challenge: &LoginChallenge,
    ) -> Result<SentRequest, ProtocolError>
    where
        C::Error: std::fmt::Display,
    {
        self.request(channel, SignPayload::Login(challenge.clone()))
    }

    /// Build and send a request for an arbitrary payload (login today; transfer is
    /// the same shape for v2).
    pub fn request<C: Channel>(
        &mut self,
        channel: &mut C,
        payload: SignPayload,
    ) -> Result<SentRequest, ProtocolError>
    where
        C::Error: std::fmt::Display,
    {
        let session_id = self.counter.session_id();
        let req_nonce = fresh_nonce();
        let counter = self.counter.advance();
        let expected_digest = payload.signing_digest();
        let req = SignRequest {
            session_id,
            req_nonce,
            counter,
            payload: payload.encode(),
        };
        let bytes = serde_json::to_vec(&req).expect("SignRequest serializes");
        channel.send(&frame(&bytes)?).map_err(tx)?;
        Ok(SentRequest {
            session_id,
            req_nonce,
            counter,
            expected_digest,
        })
    }

    /// Receive and match the phone's [`Approval`]. Verifies it echoes the session,
    /// nonce, counter and signed digest of `sent`. Does **not** verify the PQ
    /// signature — that is the consiglio server's job (or `bloch_crypto::verify`);
    /// the desktop only relays a matched approval.
    pub fn recv_approval<C: Channel>(
        &mut self,
        channel: &mut C,
        sent: &SentRequest,
    ) -> Result<Approval, ProtocolError>
    where
        C::Error: std::fmt::Display,
    {
        let bytes = channel.recv().map_err(tx)?;
        let body = deframe(&bytes)?;
        let approval: Approval = serde_json::from_slice(&body)
            .map_err(|e| ProtocolError::BadFrame(format!("approval decode: {e}")))?;
        if approval.session_id != sent.session_id
            || approval.req_nonce != sent.req_nonce
            || approval.counter != sent.counter
            || approval.payload_digest != sent.expected_digest
        {
            return Err(ProtocolError::BadFrame(
                "approval does not match the request that was sent".into(),
            ));
        }
        Ok(approval)
    }
}

// ── Phone (custodian, holds the key) ──────────────────────────────────────────

/// A validated, decoded, human-displayable request awaiting the user's decision.
/// The replay checks have already passed; the WYSIWYS is rendered from the actual
/// signed bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    req: SignRequest,
    payload: SignPayload,
    pub wysiwys: Wysiwys,
}

impl Pending {
    pub fn payload(&self) -> &SignPayload {
        &self.payload
    }

    pub fn tier(&self) -> ConsequenceTier {
        self.wysiwys.tier
    }

    /// True for the single-tap tier (a login that cannot move funds).
    pub fn is_single_tap(&self) -> bool {
        self.wysiwys.tier == ConsequenceTier::SingleTap
    }
}

/// The phone side. Holds the signer, the per-session replay guard, the peer device
/// name (learned at §2 pairing, NOT from the request), and an optional revocable
/// grant for single-tap auto-approval.
pub struct PhoneApprover<S: WalletSigner> {
    signer: S,
    guard: ReplayGuard,
    peer_device: String,
    grant: Option<ApprovalGrant>,
}

impl<S: WalletSigner> PhoneApprover<S> {
    /// Bind a signer to a paired session, naming the counterpart device.
    pub fn new(signer: S, session_id: SessionId, peer_device: impl Into<String>) -> Self {
        PhoneApprover {
            signer,
            guard: ReplayGuard::new(session_id),
            peer_device: peer_device.into(),
            grant: None,
        }
    }

    /// Attach a time-boxed, revocable grant (minted after an explicit review).
    pub fn set_grant(&mut self, grant: ApprovalGrant) {
        self.grant = Some(grant);
    }

    /// Revoke any grant — "revoke this laptop". Monotonic.
    pub fn revoke_grant(&mut self) {
        if let Some(g) = self.grant.as_mut() {
            g.revoke();
        }
    }

    pub fn address(&self) -> String {
        self.signer.address()
    }

    /// Receive the next request and validate it **before** any human decision:
    /// replay guard (session/counter/nonce, fail-closed) then payload decode
    /// (undisplayable → fail-closed). Returns a [`Pending`] carrying the WYSIWYS.
    pub fn receive<C: Channel>(&mut self, channel: &mut C) -> Result<Pending, ProtocolError>
    where
        C::Error: std::fmt::Display,
    {
        let bytes = channel.recv().map_err(tx)?;
        let body = deframe(&bytes)?;
        let req: SignRequest = serde_json::from_slice(&body)
            .map_err(|e| ProtocolError::BadFrame(format!("request decode: {e}")))?;

        // Replay / forgery resistance — all three checks, no state mutation yet.
        self.guard.check(&req)?;

        // WYSIWYS: parse from the ACTUAL bytes to be signed, never desktop prose.
        let payload = SignPayload::decode(&req.payload)?;
        let wysiwys = render(&payload, &self.peer_device, req.session_id, &req.req_nonce);
        Ok(Pending {
            req,
            payload,
            wysiwys,
        })
    }

    /// Would an attached, live grant auto-approve this pending request without a
    /// prompt? Only ever true for a single-tap login covered by the grant; value
    /// transfers are never covered.
    pub fn covered_by_grant(&self, pending: &Pending, now_unix: i64) -> bool {
        let Some(grant) = self.grant.as_ref() else {
            return false;
        };
        match pending.payload() {
            SignPayload::Login(c) if pending.is_single_tap() => {
                grant.allows_login(&self.peer_device, &c.org, now_unix)
            }
            _ => false,
        }
    }

    /// Approve and sign. Signs the **canonical digest** of the decoded payload,
    /// commits the replay guard (advancing the counter, retiring the nonce), sends
    /// the [`Approval`], and returns it. Call only after the human confirmed (or
    /// [`covered_by_grant`](Self::covered_by_grant) returned true for a single-tap).
    pub fn approve<C: Channel>(
        &mut self,
        channel: &mut C,
        pending: Pending,
    ) -> Result<Approval, ProtocolError>
    where
        C::Error: std::fmt::Display,
    {
        let digest = pending.payload.signing_digest();
        let signature = self.signer.sign_digest(&digest)?;
        // Commit AFTER a successful sign, so a signer failure does not burn the
        // counter/nonce for a request that produced no approval.
        self.guard.commit(&pending.req);
        let approval = Approval {
            session_id: pending.req.session_id,
            req_nonce: pending.req.req_nonce,
            counter: pending.req.counter,
            signature,
            public_key: self.signer.public_key_bytes(),
            payload_digest: digest,
        };
        let bytes = serde_json::to_vec(&approval).expect("Approval serializes");
        channel.send(&frame(&bytes)?).map_err(tx)?;
        Ok(approval)
    }

    /// Decline: the human said no. Nothing is signed and the guard is **not**
    /// committed, so the request's nonce/counter never advance the sequence — a
    /// declined request is as if it never arrived. Fail closed.
    pub fn decline(&mut self, _pending: Pending) -> Result<(), ProtocolError> {
        Err(ProtocolError::Declined)
    }
}
