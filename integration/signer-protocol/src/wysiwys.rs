// SPDX-License-Identifier: MIT OR Apache-2.0
//! WYSIWYS — "What You See Is What You Sign".
//!
//! Design §3.3 / §6, Security §4.3: the phone parses the approval from the
//! **actual bytes it is about to sign** and renders a plain-language sentence and
//! a **consequence tier** — never from any desktop-supplied text (there is no
//! such field on the wire). A compromised desktop can request a legitimate-looking
//! signature, but it cannot make the phone *narrate* a lie: the sentence is a pure
//! function of the decoded [`SignPayload`].
//!
//! The prompt is **bound to the counterpart device**: it names the peer and shows
//! a short confirmation fragment derived from the session + request nonce, which
//! also appears on the desktop — "an approval with no matching desktop action is
//! the tell to decline."

use sha3::{Digest, Sha3_256};

use crate::message::{SessionId, SignPayload};

/// The three consequence tiers (Design §3.3). Derived **structurally** from what
/// the action does, not from a global toggle or a desktop flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsequenceTier {
    /// Read-only, reversible, **no key use** — never prompts, never signs value.
    SilentReadOnly,
    /// A scoped, low-stakes signature that **cannot move funds** (wallet-login).
    /// One clear card, one tap.
    SingleTap,
    /// Irreversible / valuable (moves funds). Full decoded meaning + a deliberate
    /// confirm (biometric / slide, not a muscle-memory tap).
    ExplicitReview,
}

impl ConsequenceTier {
    /// The house one-liner for this tier.
    pub fn headline(self) -> &'static str {
        match self {
            ConsequenceTier::SilentReadOnly => "Read-only — no signature, no key use.",
            ConsequenceTier::SingleTap => "Low-stakes — this signature can't move funds.",
            ConsequenceTier::ExplicitReview => "Irreversible — review carefully before you confirm.",
        }
    }
}

/// The rendered approval the phone shows. All fields derive from the signed bytes
/// and the session — nothing here is trusted desktop prose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wysiwys {
    pub tier: ConsequenceTier,
    /// The human sentence, parsed from the actual payload.
    pub sentence: String,
    /// True only for actions that can move funds — surfaced explicitly.
    pub can_move_funds: bool,
    /// The counterpart device this approval is bound to ("Approve for …").
    pub peer_device: String,
    /// A short fragment shown on BOTH screens; if it doesn't match the desktop,
    /// decline. Derived from session ‖ req_nonce so a relay/overlay can't fake it.
    pub confirmation_fragment: String,
}

/// Render the WYSIWYS prompt from the decoded payload. Pure and deterministic.
pub fn render(
    payload: &SignPayload,
    peer_device: &str,
    session_id: SessionId,
    req_nonce: &[u8; 32],
) -> Wysiwys {
    let (tier, sentence, can_move_funds) = match payload {
        SignPayload::Login(c) => (
            ConsequenceTier::SingleTap,
            format!(
                "This signs a login challenge for \"{user}\" at \"{org}\". \
                 It proves you hold the wallet key — it can't move funds.",
                user = c.user,
                org = c.org,
            ),
            false,
        ),
        SignPayload::Transfer(t) => (
            ConsequenceTier::ExplicitReview,
            format!(
                "This moves {amount} coins to {to} (fee {fee}, {chain}). \
                 A signature spends irreversibly — this cannot be undone.",
                amount = t.amount,
                to = t.to_address,
                fee = t.fee,
                chain = match t.chain {
                    crate::message::Chain::Mainnet => "mainnet",
                    crate::message::Chain::Testnet => "testnet",
                },
            ),
            true,
        ),
    };

    Wysiwys {
        tier,
        sentence,
        can_move_funds,
        peer_device: peer_device.to_string(),
        confirmation_fragment: confirmation_fragment(session_id, req_nonce),
    }
}

/// A 6-hex-char fragment bound to (session ‖ nonce), shown on both screens.
pub fn confirmation_fragment(session_id: SessionId, req_nonce: &[u8; 32]) -> String {
    let mut h = Sha3_256::new();
    h.update(b"postern:approval-fragment:v1");
    h.update(session_id);
    h.update(req_nonce);
    let d = h.finalize();
    hex::encode(&d[..3]) // 6 hex chars — a human-comparable tell
}
