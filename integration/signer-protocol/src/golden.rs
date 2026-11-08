// SPDX-License-Identifier: MIT OR Apache-2.0
//! # Byte-identity golden — the ONE pinned wire both ends check against
//!
//! The desktop terminal and the phone signer are two independent implementations
//! of the same flow, but there is exactly **one wire message shape**: the
//! [`SignRequest`](crate::SignRequest) / [`Approval`](crate::Approval) serde
//! encoding in this crate. This module is the *single* committed reference for
//! those bytes — a fixed input tuple and the exact hex the encoder must produce.
//!
//! Both ends pin against these same constants:
//! - the **desktop/protocol** side in `tests/golden_wire.rs` (this crate), and
//! - the **phone** side in `mobile/signer`'s `tests/golden_wire.rs`,
//!
//! which imports these very constants ([`postern_signer_protocol::golden`]). If
//! either implementation's bytes drift from the golden, its test goes red — so the
//! two ends are *provably* wire-identical, not merely round-trip self-consistent.
//!
//! Why a fixed nonce/counter: the live desktop path uses a fresh random nonce and a
//! monotonic counter, so live frames are non-deterministic by design. To pin the
//! **encoding** (the thing that must match across ends) we fix every input and
//! assert the exact output. This checks the wire *format*, not the runtime replay
//! values.
//!
//! Regenerating (only on a deliberate, reviewed wire change): construct
//! [`sign_request`] and print `hex::encode(serde_json::to_vec(&req))`; a breaking
//! layout change must also bump [`SIGNER_DOMAIN`](crate::SIGNER_DOMAIN) /
//! [`LOGIN_DOMAIN`](crate::LOGIN_DOMAIN) suffixes as documented there.

use crate::message::{LoginChallenge, SignPayload, SignRequest};

/// Pinned session id for the golden vector (fixed, not a live paired session).
pub const GOLDEN_SESSION_ID: [u8; 16] = [0x11; 16];
/// Pinned per-request nonce for the golden vector (fixed, not a live fresh nonce).
pub const GOLDEN_REQ_NONCE: [u8; 32] = [0x22; 32];
/// Pinned monotonic counter for the golden vector.
pub const GOLDEN_COUNTER: u64 = 1;
/// Pinned login org for the golden vector.
pub const GOLDEN_ORG: &str = "acme";
/// Pinned login user for the golden vector.
pub const GOLDEN_USER: &str = "alice";
/// Pinned login server-nonce for the golden vector.
pub const GOLDEN_LOGIN_NONCE: [u8; 32] = [0x33; 32];
/// Pinned login `issued_at` for the golden vector.
pub const GOLDEN_ISSUED_AT: i64 = 1_752_000_000;

/// The canonical login challenge behind the golden vectors.
pub fn login_challenge() -> LoginChallenge {
    LoginChallenge {
        org: GOLDEN_ORG.to_string(),
        user: GOLDEN_USER.to_string(),
        nonce: GOLDEN_LOGIN_NONCE,
        issued_at: GOLDEN_ISSUED_AT,
    }
}

/// The canonical [`SignPayload`] behind the golden vectors (a login).
pub fn sign_payload() -> SignPayload {
    SignPayload::Login(login_challenge())
}

/// The canonical on-wire [`SignRequest`] for the golden vectors — the exact
/// message the desktop composes and the phone decodes.
pub fn sign_request() -> SignRequest {
    SignRequest {
        session_id: GOLDEN_SESSION_ID,
        req_nonce: GOLDEN_REQ_NONCE,
        counter: GOLDEN_COUNTER,
        payload: sign_payload().encode(),
    }
}

/// The 32-byte SHA3-256 login signing digest, hex — byte-identical to what a
/// `postern-consiglio-auth` server verifies for this challenge.
pub const GOLDEN_LOGIN_DIGEST_HEX: &str =
    "300f26f1ae15b419283a17eeab6813d1768f0da76ae1e8106a0b99377c4315ef";

/// The inner `SignPayload` (login) serde-JSON encoding, hex — the exact bytes
/// carried in [`SignRequest::payload`].
pub const GOLDEN_PAYLOAD_BODY_HEX: &str = "7b224c6f67696e223a7b226f7267223a2261636d65222c2275736572223a22616c696365222c226e6f6e6365223a5b35312c35312c35312c35312c35312c35312c35312c35312c35312c35312c35312c35312c35312c35312c35312c35312c35312c35312c35312c35312c35312c35312c35312c35312c35312c35312c35312c35312c35312c35312c35312c35315d2c226973737565645f6174223a313735323030303030307d7d";

/// The full [`SignRequest`] serde-JSON body encoding, hex — the wire message
/// (pre-framing).
pub const GOLDEN_SIGNREQUEST_BODY_HEX: &str = "7b2273657373696f6e5f6964223a5b31372c31372c31372c31372c31372c31372c31372c31372c31372c31372c31372c31372c31372c31372c31372c31375d2c227265715f6e6f6e6365223a5b33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33345d2c22636f756e746572223a312c227061796c6f6164223a5b3132332c33342c37362c3131312c3130332c3130352c3131302c33342c35382c3132332c33342c3131312c3131342c3130332c33342c35382c33342c39372c39392c3130392c3130312c33342c34342c33342c3131372c3131352c3130312c3131342c33342c35382c33342c39372c3130382c3130352c39392c3130312c33342c34342c33342c3131302c3131312c3131302c39392c3130312c33342c35382c39312c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c39332c34342c33342c3130352c3131352c3131352c3131372c3130312c3130302c39352c39372c3131362c33342c35382c34392c35352c35332c35302c34382c34382c34382c34382c34382c34382c3132352c3132355d7d";

/// The framed [`SignRequest`] — `PSG1 ‖ len(LE32) ‖ body` (what [`crate::channel::frame`]
/// emits and the transport carries), hex.
pub const GOLDEN_SIGNREQUEST_FRAME_HEX: &str = "50534731dd0200007b2273657373696f6e5f6964223a5b31372c31372c31372c31372c31372c31372c31372c31372c31372c31372c31372c31372c31372c31372c31372c31375d2c227265715f6e6f6e6365223a5b33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33342c33345d2c22636f756e746572223a312c227061796c6f6164223a5b3132332c33342c37362c3131312c3130332c3130352c3131302c33342c35382c3132332c33342c3131312c3131342c3130332c33342c35382c33342c39372c39392c3130392c3130312c33342c34342c33342c3131372c3131352c3130312c3131342c33342c35382c33342c39372c3130382c3130352c39392c3130312c33342c34342c33342c3131302c3131312c3131302c39392c3130312c33342c35382c39312c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c34342c35332c34392c39332c34342c33342c3130352c3131352c3131352c3131372c3130312c3130302c39352c39372c3131362c33342c35382c34392c35352c35332c35302c34382c34382c34382c34382c34382c34382c3132352c3132355d7d";
