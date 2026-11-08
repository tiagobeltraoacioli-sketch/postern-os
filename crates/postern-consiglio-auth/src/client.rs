//! Client (wallet) side — thin, demo-only.
//!
//! In production the wallet holds the secret key and signs the login challenge;
//! that lives in `bloch-crypto`'s wallet (`wallet::cli` / the `postern-wallet`
//! CLI binary), NOT here. We do not duplicate key custody, keystores, or seed
//! handling.
//!
//! This module exposes exactly one helper — [`sign_challenge`] — over the SAME
//! primitive the wallet uses (`bloch_crypto::crypto::sign`), so the demo and the
//! integration test can complete an end-to-end login. It takes raw key bytes; a
//! real caller would instead hand the transcript to an unlocked `Wallet`.

use crate::challenge::{Challenge, Response};
use crate::error::AuthError;

/// Sign a challenge's transcript with a wallet's hybrid PQ secret key and
/// assemble the [`Response`]. Reuses `bloch_crypto::crypto::sign` (hybrid
/// Falcon ‖ ML-DSA) — the real signer, no new crypto.
pub fn sign_challenge(
    challenge: &Challenge,
    public_key: &[u8],
    secret_key: &[u8],
) -> Result<Response, AuthError> {
    let transcript = challenge.transcript();
    let signature = bloch_crypto::crypto::sign(secret_key, &transcript)
        .map_err(|e| AuthError::Sign(e.to_string()))?;
    Ok(Response {
        org_id: challenge.org_id.clone(),
        user_id: challenge.user_id.clone(),
        nonce: challenge.nonce,
        public_key: public_key.to_vec(),
        signature,
    })
}
