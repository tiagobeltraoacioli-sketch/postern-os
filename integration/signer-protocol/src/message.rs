// SPDX-License-Identifier: MIT OR Apache-2.0
//! Protocol wire types: the **SignRequest** the desktop sends and the
//! **Approval** the phone returns, plus the [`SignPayload`] that is decoded from
//! the ACTUAL bytes to be signed (WYSIWYS).
//!
//! Every type here is [`WireSafe`](crate::secret::WireSafe): it carries only
//! public data. There is no key field anywhere — the seed and secret key live in
//! the non-serializable [`crate::secret`] types and are structurally unable to
//! appear here.
//!
//! ### The signed digest is canonical, the transport encoding is not trusted
//! The bytes on the wire (`SignRequest::payload`) are a serde encoding of a
//! [`SignPayload`]. The phone **decodes** them and recomputes a
//! domain-separated SHA3-256 digest from the *decoded fields* — so what is signed
//! is a canonical function of meaning, independent of any desktop-chosen framing,
//! and the human sees exactly the fields that feed the digest.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::error::ProtocolError;
use crate::secret::{wire_safe, WireSafe};

/// A 16-byte paired-session identifier (the §2 pairing establishes it; here it is
/// the replay/session-binding anchor). Public.
pub type SessionId = [u8; 16];

/// Domain tag for the phone-as-signer request transcript. Bump the suffix on any
/// breaking layout change.
pub const SIGNER_DOMAIN: &[u8] = b"postern:signer-protocol:v1";

/// Domain tag for the wallet-login transcript — **byte-identical discipline** to
/// `postern-consiglio-auth`'s `consiglio:wallet-login:v1`, so a login approved
/// here verifies against the same enrolled key on the consiglio server.
pub const LOGIN_DOMAIN: &[u8] = b"consiglio:wallet-login:v1";

/// Which network a value transfer is bound to — folded into the transfer digest
/// so a mainnet request can never replay as testnet (Security §4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Chain {
    Mainnet,
    Testnet,
}

impl Chain {
    fn tag(self) -> &'static [u8] {
        match self {
            Chain::Mainnet => b"mainnet",
            Chain::Testnet => b"testnet",
        }
    }
}

/// A desktop wallet-login challenge (the consiglio-auth shape). The v1 flow.
/// **Cannot move funds** — the domain separator guarantees a signature over this
/// can only ever be a login.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginChallenge {
    pub org: String,
    pub user: String,
    /// 32-byte server nonce (the anti-replay value inside the login itself).
    pub nonce: [u8; 32],
    pub issued_at: i64,
}

impl LoginChallenge {
    /// The exact 32 bytes to sign: domain-separated SHA3-256 over
    /// (tag ‖ len(org) ‖ org ‖ len(user) ‖ user ‖ nonce ‖ issued_at). This mirrors
    /// `Challenge::transcript()` in `postern-consiglio-auth` field-for-field.
    pub fn signing_digest(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(LOGIN_DOMAIN);
        h.update((self.org.len() as u64).to_le_bytes());
        h.update(self.org.as_bytes());
        h.update((self.user.len() as u64).to_le_bytes());
        h.update(self.user.as_bytes());
        h.update(self.nonce);
        h.update(self.issued_at.to_le_bytes());
        h.finalize().into()
    }
}

/// A value transfer (v2 shape, same protocol path — included so v1's structure is
/// proven general). Moves funds → the highest consequence tier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferIntent {
    pub to_address: String,
    pub amount: u64,
    pub fee: u64,
    pub chain: Chain,
    pub nonce: [u8; 32],
}

impl TransferIntent {
    /// Domain-separated SHA3-256 over the transfer fields (chain-id folded in).
    pub fn signing_digest(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(SIGNER_DOMAIN);
        h.update(b"transfer:v1");
        h.update(self.chain.tag());
        h.update((self.to_address.len() as u64).to_le_bytes());
        h.update(self.to_address.as_bytes());
        h.update(self.amount.to_le_bytes());
        h.update(self.fee.to_le_bytes());
        h.update(self.nonce);
        h.finalize().into()
    }
}

/// The decoded meaning of the bytes to be signed. WYSIWYS renders from THIS —
/// parsed on the phone from `SignRequest::payload`, never from desktop-supplied
/// prose (there is no prose field on the wire).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignPayload {
    /// v1: a wallet-login challenge. Cannot move funds.
    Login(LoginChallenge),
    /// v2: a value transfer. Moves funds.
    Transfer(TransferIntent),
}

impl SignPayload {
    /// The canonical 32-byte digest the phone will actually sign.
    pub fn signing_digest(&self) -> [u8; 32] {
        match self {
            SignPayload::Login(c) => c.signing_digest(),
            SignPayload::Transfer(t) => t.signing_digest(),
        }
    }

    /// Encode for transport (the `SignRequest::payload` bytes). serde_json keeps
    /// it self-describing; the SIGNED digest is computed from the decoded fields,
    /// not from this encoding, so framing choice is not trust-bearing.
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("SignPayload is always serializable")
    }

    /// Decode on the phone. A payload that will not decode is undisplayable →
    /// fail closed (the phone cannot show what it would sign, so it won't sign).
    pub fn decode(bytes: &[u8]) -> Result<SignPayload, ProtocolError> {
        serde_json::from_slice(bytes)
            .map_err(|e| ProtocolError::UndecodablePayload(e.to_string()))
    }
}

/// DESKTOP → PHONE. A request to sign. The desktop holds **no key**; it sends the
/// session binding, a fresh request nonce, a monotonic counter, and the exact
/// payload bytes. There is deliberately **no human-text field**: the phone parses
/// the payload itself (WYSIWYS), so a compromised desktop cannot narrate a lie.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignRequest {
    /// Binds this request to one paired session (replay isolation across sessions).
    pub session_id: SessionId,
    /// Fresh per-request nonce — single-use, rejected on replay.
    pub req_nonce: [u8; 32],
    /// Monotonic per-session counter — must strictly advance.
    pub counter: u64,
    /// The ACTUAL bytes to be signed (an encoded [`SignPayload`]).
    pub payload: Vec<u8>,
}

/// PHONE → DESKTOP. The approval + signature. The **only** things that cross back
/// are public: a signature, the identity public key, and the digest that was
/// signed (so the desktop can bind the signature to the request it sent). No key
/// material — structurally impossible here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    pub session_id: SessionId,
    /// Echoes the request nonce so the desktop can match request↔approval.
    pub req_nonce: [u8; 32],
    pub counter: u64,
    /// Hybrid Falcon‖ML-DSA signature bytes (public).
    pub signature: Vec<u8>,
    /// The signer's public key / identity (public).
    pub public_key: Vec<u8>,
    /// The 32-byte digest that was signed (public; a hash, not a key).
    pub payload_digest: [u8; 32],
}

// Bless the wire surface. Secret types are absent by construction and cannot be
// added here (they have no `Serialize`).
wire_safe!(
    Chain,
    LoginChallenge,
    TransferIntent,
    SignPayload,
    SignRequest,
    Approval,
);

/// A `const` census evaluated at build time: every message must be `WireSafe`.
/// If a message loses the blessing (or a secret sneaks into one), the crate stops
/// compiling here. This is the compile-half of the structural denylist; the
/// runtime half is `tests/golden_denylist.rs`.
#[allow(dead_code)]
pub(crate) const _WIRE_CENSUS: () = {
    // These calls are const-evaluable no-ops whose ONLY effect is to require the
    // trait bound `T: WireSafe` at compile time.
    const fn census<T: WireSafe>() {}
    census::<Chain>();
    census::<LoginChallenge>();
    census::<TransferIntent>();
    census::<SignPayload>();
    census::<SignRequest>();
    census::<Approval>();
};
