// SPDX-License-Identifier: MIT OR Apache-2.0

//! `MobileSigner` — the app-drivable phone-side orchestrator.
//!
//! Wraps [`PhoneApprover`](postern_signer_protocol::PhoneApprover) with the real
//! [`WalletCoreSigner`](crate::WalletCoreSigner) and turns the trait-driven
//! request/approve flow into a **frame-in → prompt → approve → frame-out** shape
//! the native app (or the UniFFI surface) can drive without owning a generic
//! channel:
//!
//! 1. [`receive_frame`](MobileSigner::receive_frame) — feed the raw request frame;
//!    the [`ReplayGuard`](postern_signer_protocol::ReplayGuard) validates it (fresh
//!    nonce + monotonic counter + session binding, fail-closed), the payload is
//!    decoded from the ACTUAL bytes, and a WYSIWYS [`Prompt`] comes back.
//! 2. Native UI shows the prompt; the user performs biometric/PIN → a
//!    [`PresenceProof`] bound to THIS request's nonce.
//! 3. [`approve`](MobileSigner::approve) — with that proof, sign and get the
//!    approval frame to send back. Or [`decline`](MobileSigner::decline).
//!
//! ## User presence per sign — no blanket auto-approve (structural)
//!
//! [`approve`](MobileSigner::approve) requires a [`PresenceProof`] whose bound
//! nonce equals the pending request's nonce — a proof cannot be reused for a
//! different or replayed request, and there is **no** "approve all" token. The
//! only prompt-free path is a live, revocable single-tap
//! [`ApprovalGrant`](postern_signer_protocol::ApprovalGrant)
//! ([`approve_single_tap_by_grant`](MobileSigner::approve_single_tap_by_grant)),
//! which the protocol crate refuses to let cover a value transfer.

use postern_signer_protocol::channel::{deframe, Channel as ProtocolChannel};
use postern_signer_protocol::{
    ApprovalGrant, ConsequenceTier, GrantScope, Pending, PhoneApprover, ProtocolError, SessionId,
    SignRequest,
};

use crate::signer::WalletCoreSigner;

/// How the user proved presence for THIS signature. Asserted by the native app
/// (which performs the biometric/PIN); this crate cannot verify hardware — say so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum PresenceMethod {
    /// A biometric check (fingerprint / face) performed by the OS.
    Biometric,
    /// A device PIN / passphrase check performed by the OS.
    DevicePin,
}

/// Proof that the user was present and approved a SPECIFIC request. Bound to the
/// request's nonce, so it can authorize only that one sign. Deliberately NOT
/// serializable and with no `Default` — there is no blanket/ambient approval.
#[derive(Debug, Clone)]
pub struct PresenceProof {
    req_nonce: [u8; 32],
    method: PresenceMethod,
}

impl PresenceProof {
    /// Mint a proof for `req_nonce` after the OS confirmed presence by `method`.
    /// The caller (native app) must pass the exact nonce of the request being
    /// approved — see [`Prompt::req_nonce`].
    pub fn granted(req_nonce: [u8; 32], method: PresenceMethod) -> Self {
        PresenceProof { req_nonce, method }
    }

    /// Which method was used (for audit/display).
    pub fn method(&self) -> PresenceMethod {
        self.method
    }

    fn matches(&self, req_nonce: &[u8; 32]) -> bool {
        &self.req_nonce == req_nonce
    }
}

/// The consequence tier of a pending request, mirrored for the app boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum Tier {
    /// Read-only, no key use — never signs.
    SilentReadOnly,
    /// Low-stakes login — cannot move funds.
    SingleTap,
    /// Irreversible / valuable — deliberate confirm required.
    ExplicitReview,
}

impl From<ConsequenceTier> for Tier {
    fn from(t: ConsequenceTier) -> Self {
        match t {
            ConsequenceTier::SilentReadOnly => Tier::SilentReadOnly,
            ConsequenceTier::SingleTap => Tier::SingleTap,
            ConsequenceTier::ExplicitReview => Tier::ExplicitReview,
        }
    }
}

/// The WYSIWYS approval card the app renders. Every field is derived from the
/// signed bytes + the session — never trusted requester prose.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct Prompt {
    /// The consequence tier.
    pub tier: Tier,
    /// The human sentence, parsed from the actual payload.
    pub sentence: String,
    /// True only for actions that can move funds — surfaced explicitly.
    pub can_move_funds: bool,
    /// The counterpart device this approval is bound to ("Approve for …"), learned
    /// at pairing, not from the request.
    pub peer_device: String,
    /// A short fragment shown on BOTH screens; if it doesn't match the desktop,
    /// decline.
    pub confirmation_fragment: String,
    /// The request nonce to bind a [`PresenceProof`] to (hex). The native app
    /// echoes this into [`PresenceProof::granted`].
    pub req_nonce_hex: String,
    /// The standing "not a hardware wallet" disclosure to render on the card.
    pub disclosure: String,
}

/// The standing signing-surface disclosure (Design §11.1) — shown on every card.
pub const NOT_A_HARDWARE_WALLET: &str =
    "Postern signs in software. Your phone protects the key at rest and attests \
     the app, but the signing key is handled in memory — this is NOT a hardware \
     wallet. A rooted/jailbroken or malware-infected phone can steal the key.";

/// Errors at the orchestrator boundary.
#[derive(Debug, thiserror::Error)]
pub enum MobileError {
    /// A protocol-layer refusal (replay, undecodable, transport, signer, decline).
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    /// There is no request awaiting a decision (call `receive_frame` first).
    #[error("no request is pending")]
    NoPending,
    /// The presence proof is for a different request nonce than the pending one.
    #[error("presence proof does not match the pending request (per-sign presence required)")]
    PresenceMismatch,
    /// The wallet could not be constructed.
    #[error("wallet error: {0}")]
    Wallet(String),
}

/// A single-frame, in-memory channel: the app hands us the request frame and we
/// capture the approval frame, so the app never has to own a generic `Channel`.
struct OneShot {
    inbox: Option<Vec<u8>>,
    outbox: Option<Vec<u8>>,
}

impl ProtocolChannel for OneShot {
    type Error = ProtocolError;

    fn send(&mut self, frame: &[u8]) -> Result<(), Self::Error> {
        self.outbox = Some(frame.to_vec());
        Ok(())
    }

    fn recv(&mut self) -> Result<Vec<u8>, Self::Error> {
        self.inbox
            .take()
            .ok_or_else(|| ProtocolError::BadFrame("no request frame provided".into()))
    }
}

/// The phone-side orchestrator. One per paired session.
pub struct MobileSigner {
    approver: PhoneApprover<WalletCoreSigner>,
    io: OneShot,
    pending: Option<Pending>,
    /// The nonce of the pending request, captured for per-sign presence binding.
    pending_nonce: Option<[u8; 32]>,
    /// The counterpart device name (learned at pairing). A grant must be minted
    /// for this exact peer so it matches the approver's WYSIWYS binding.
    peer_device: String,
}

impl MobileSigner {
    /// Bind a real wallet signer to a paired session, naming the counterpart.
    pub fn new(
        signer: WalletCoreSigner,
        session_id: SessionId,
        peer_device: impl Into<String>,
    ) -> Self {
        let peer_device = peer_device.into();
        MobileSigner {
            approver: PhoneApprover::new(signer, session_id, peer_device.clone()),
            io: OneShot { inbox: None, outbox: None },
            pending: None,
            pending_nonce: None,
            peer_device,
        }
    }

    /// Build the wallet from a BIP39 mnemonic and bind it. The phrase is the only
    /// backup — never log it.
    pub fn from_mnemonic(
        phrase: &str,
        testnet: bool,
        session_id: SessionId,
        peer_device: impl Into<String>,
    ) -> Result<Self, MobileError> {
        let signer =
            WalletCoreSigner::from_mnemonic(phrase, testnet).map_err(|e| MobileError::Wallet(e.to_string()))?;
        Ok(Self::new(signer, session_id, peer_device))
    }

    /// The wallet's `bloch1q…`/`bloch1t…` address (public).
    pub fn address(&self) -> String {
        self.approver.address()
    }

    /// Feed a raw request frame (as received off the paired channel). Runs the
    /// replay guard + payload decode + WYSIWYS render and returns the [`Prompt`].
    /// Any refusal (stale/replayed/out-of-session/undecodable) fails closed.
    pub fn receive_frame(&mut self, request_frame: &[u8]) -> Result<Prompt, MobileError> {
        // Capture the request nonce up front (public field) so a presence proof can
        // be bound to it — parsed from the same frame the approver will validate.
        let body = deframe(request_frame)?;
        let req: SignRequest = serde_json::from_slice(&body)
            .map_err(|e| ProtocolError::BadFrame(format!("request decode: {e}")))?;
        let req_nonce = req.req_nonce;

        self.io.inbox = Some(request_frame.to_vec());
        self.io.outbox = None;
        let pending = self.approver.receive(&mut self.io)?;
        let prompt = Prompt {
            tier: pending.tier().into(),
            sentence: pending.wysiwys.sentence.clone(),
            can_move_funds: pending.wysiwys.can_move_funds,
            peer_device: pending.wysiwys.peer_device.clone(),
            confirmation_fragment: pending.wysiwys.confirmation_fragment.clone(),
            req_nonce_hex: hex::encode(req_nonce),
            disclosure: NOT_A_HARDWARE_WALLET.to_string(),
        };
        self.pending = Some(pending);
        self.pending_nonce = Some(req_nonce);
        Ok(prompt)
    }

    /// Approve and sign the pending request. Requires a [`PresenceProof`] bound to
    /// the pending request's nonce (per-sign presence; no blanket auto-approve).
    /// Returns the approval frame to send back over the channel.
    pub fn approve(&mut self, presence: PresenceProof) -> Result<Vec<u8>, MobileError> {
        let nonce = self.pending_nonce.ok_or(MobileError::NoPending)?;
        if !presence.matches(&nonce) {
            return Err(MobileError::PresenceMismatch);
        }
        self.sign_pending()
    }

    /// Approve a SINGLE-TAP login without a prompt IF a live, un-revoked grant
    /// covers it (Design §3.3 "fewer prompts, safely"). Never covers a value
    /// transfer — the protocol grant refuses that. `now_unix` is the current time.
    pub fn approve_single_tap_by_grant(&mut self, now_unix: i64) -> Result<Vec<u8>, MobileError> {
        let pending = self.pending.as_ref().ok_or(MobileError::NoPending)?;
        if !self.approver.covered_by_grant(pending, now_unix) {
            return Err(MobileError::Protocol(ProtocolError::Declined));
        }
        self.sign_pending()
    }

    fn sign_pending(&mut self) -> Result<Vec<u8>, MobileError> {
        let pending = self.pending.take().ok_or(MobileError::NoPending)?;
        self.pending_nonce = None;
        self.approver.approve(&mut self.io, pending)?;
        self.io
            .outbox
            .take()
            .ok_or(MobileError::Protocol(ProtocolError::BadFrame(
                "approver produced no approval frame".into(),
            )))
    }

    /// Decline the pending request. Nothing is signed; the replay guard is NOT
    /// committed, so the declined request never advances the sequence.
    pub fn decline(&mut self) -> Result<(), MobileError> {
        let pending = self.pending.take().ok_or(MobileError::NoPending)?;
        self.pending_nonce = None;
        // `decline` always returns ProtocolError::Declined by design (fail-closed).
        match self.approver.decline(pending) {
            Err(ProtocolError::Declined) => Ok(()),
            Err(e) => Err(MobileError::Protocol(e)),
            Ok(()) => Ok(()),
        }
    }

    /// Attach a time-boxed, revocable single-tap login grant for `org`, valid
    /// until `expires_at_unix`. Reduces prompts for the reversible tier only.
    /// Minted for this session's peer device so it matches the approver's binding.
    pub fn set_login_grant(&mut self, org: impl Into<String>, expires_at_unix: i64) {
        let grant = ApprovalGrant::new(
            self.peer_device.clone(),
            GrantScope::LoginTo { org: org.into() },
            expires_at_unix,
        );
        self.approver.set_grant(grant);
    }

    /// Revoke any attached grant ("revoke this laptop"). Monotonic.
    pub fn revoke_grant(&mut self) {
        self.approver.revoke_grant();
    }
}
