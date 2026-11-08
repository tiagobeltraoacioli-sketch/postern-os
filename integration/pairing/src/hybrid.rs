// SPDX-License-Identifier: MIT OR Apache-2.0
//! The PQ-hybrid session-key handshake: **ML-KEM-1024 (FIPS-203) || X25519**.
//!
//! This mirrors `postern-courier`'s X-Wing-style HKDF combiner exactly — the
//! key format, the canonicality check on the ML-KEM encapsulation key, the
//! contributory-DH refusal, and the transcript-bound derivation — but here the
//! goal is a **session key for a live channel**, not a one-shot sealed payload.
//!
//! Shape (one-pass KEM, authenticated out-of-band by the QR-pin + SAS):
//!
//! 1. The **desktop (terminal)** generates a fresh EPHEMERAL hybrid keypair and
//!    publishes its public key in the QR (the anchor). See [`EphemeralKeypair`].
//! 2. The **phone (custodian)** [`encapsulate_to`]s that pinned public key,
//!    producing a hybrid encapsulation (`kem_ct`) and a 32-byte session key.
//! 3. The desktop [`decapsulate`]s `kem_ct` with its ephemeral secret and
//!    derives the **same** session key.
//!
//! Both legs are combined so a break of *either* (an `ml-kem` bug, a lattice
//! surprise, or a quantum computer versus X25519) still leaves the session key
//! protected by the other. **ML-KEM here is pre-1.0/unaudited — the X25519 leg
//! is the hedge, not a PQ guarantee.**
//!
//! Because the transcript (protocol version, `H(kem_ct)`, `H(anchor_pubkey)`,
//! and the pairing nonce) is bound into HKDF, a MITM who re-encapsulates to the
//! phone derives a *different* session key -> a *different* SAS -> the human
//! comparison aborts. The QR-pin removes the reverse direction (the phone will
//! only encapsulate to the key it scanned off the glass).

use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Ciphertext, Encoded, EncodedSizeUser, KemCore, MlKem1024};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey as XPublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::binding::Nonce;
use crate::PROTOCOL_VERSION;

type EncapKey = <MlKem1024 as KemCore>::EncapsulationKey;
type DecapKey = <MlKem1024 as KemCore>::DecapsulationKey;

const MLKEM_EK_LEN: usize = 1568;
const MLKEM_DK_LEN: usize = 3168;
const MLKEM_CT_LEN: usize = 1568;
const X25519_LEN: usize = 32;

/// Hybrid public key length: ML-KEM-1024 ek || X25519 pk.
pub const PUBLIC_KEY_LEN: usize = MLKEM_EK_LEN + X25519_LEN;
/// Hybrid secret key length: ML-KEM-1024 dk || X25519 sk.
pub const SECRET_KEY_LEN: usize = MLKEM_DK_LEN + X25519_LEN;
/// Hybrid encapsulation length: ML-KEM-1024 ct || X25519 ephemeral pk.
pub const KEM_CT_LEN: usize = MLKEM_CT_LEN + X25519_LEN;
/// Derived session-key length.
pub const SESSION_KEY_LEN: usize = 32;

/// Domain-separation label for the pairing session-key combiner. Distinct from
/// courier's label so a courier payload key and a pairing session key can never
/// collide even under identical inputs.
const HKDF_LABEL: &[u8] = b"postern-pairing/session/hybrid";

/// A derived 32-byte session key, wiped from RAM on drop.
pub type SessionKey = Zeroizing<[u8; SESSION_KEY_LEN]>;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HybridError {
    #[error("bad anchor public key")]
    PublicKey,
    #[error("bad ephemeral secret key")]
    SecretKey,
    #[error("bad encapsulation")]
    KemCiphertext,
    #[error("shared secret wrong size")]
    SharedSecret,
    #[error("encapsulation failed")]
    Encapsulate,
}

/// A device's fresh EPHEMERAL hybrid keypair for one pairing. The secret is
/// wiped from RAM when the keypair drops — this is the forward-secrecy root.
pub struct EphemeralKeypair {
    pub public: Vec<u8>,
    secret: Vec<u8>,
}

impl Drop for EphemeralKeypair {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl EphemeralKeypair {
    /// Generate a fresh ephemeral ML-KEM-1024 || X25519 keypair from the OS
    /// CSPRNG. Never derived from the wallet seed.
    pub fn generate() -> Self {
        let (dk, ek) = MlKem1024::generate(&mut OsRng);
        let x_sk = StaticSecret::random_from_rng(OsRng);
        let x_pk = XPublicKey::from(&x_sk);

        let mut public = Vec::with_capacity(PUBLIC_KEY_LEN);
        public.extend_from_slice(&ek.as_bytes());
        public.extend_from_slice(x_pk.as_bytes());

        let mut sk_enc = dk.as_bytes();
        let mut secret = Vec::with_capacity(SECRET_KEY_LEN);
        secret.extend_from_slice(&sk_enc);
        secret.extend_from_slice(x_sk.as_bytes());
        sk_enc.zeroize();

        EphemeralKeypair { public, secret }
    }

    /// Terminal side: decapsulate the phone's `kem_ct` and derive the session
    /// key, binding the same transcript the phone bound.
    pub fn decapsulate(&self, kem_ct: &[u8], nonce: &Nonce) -> Result<SessionKey, HybridError> {
        decapsulate(&self.secret, kem_ct, nonce)
    }
}

/// Custodian side: encapsulate to the desktop's pinned ephemeral public key.
/// Returns the hybrid encapsulation to send over the transport, plus the
/// session key. The `anchor_public` MUST be the QR-pinned key.
pub fn encapsulate_to(
    anchor_public: &[u8],
    nonce: &Nonce,
) -> Result<(Vec<u8>, SessionKey), HybridError> {
    if anchor_public.len() != PUBLIC_KEY_LEN {
        return Err(HybridError::PublicKey);
    }
    let (ek_bytes, xpk_bytes) = anchor_public.split_at(MLKEM_EK_LEN);

    let enc: Encoded<EncapKey> = ek_bytes.try_into().map_err(|_| HybridError::PublicKey)?;
    let ek = EncapKey::from_bytes(&enc);
    // Enforce FIPS-203 §7.2 encapsulation-key canonicality (upstream ml-kem 0.2
    // skips it): re-encode and require a byte-exact round-trip.
    if ek.as_bytes().as_slice() != ek_bytes {
        return Err(HybridError::PublicKey);
    }
    let x_pk = XPublicKey::from(
        <[u8; X25519_LEN]>::try_from(xpk_bytes).map_err(|_| HybridError::PublicKey)?,
    );

    // PQ leg.
    let (ct_m, mut ss_m) = ek.encapsulate(&mut OsRng).map_err(|_| HybridError::Encapsulate)?;
    // Classical leg (ephemeral).
    let eph = EphemeralSecret::random_from_rng(OsRng);
    let epk = XPublicKey::from(&eph);
    let ss_x = eph.diffie_hellman(&x_pk);
    if !ss_x.was_contributory() {
        ss_m.zeroize();
        return Err(HybridError::PublicKey);
    }

    let mut kem_ct = Vec::with_capacity(KEM_CT_LEN);
    kem_ct.extend_from_slice(&ct_m);
    kem_ct.extend_from_slice(epk.as_bytes());

    let key = combine(ss_m.as_slice(), ss_x.as_bytes(), &kem_ct, anchor_public, nonce);
    ss_m.zeroize();
    let key = key?;
    Ok((kem_ct, key))
}

/// Terminal side: derive the session key from the ephemeral secret and the
/// received `kem_ct`. Rebuilds the anchor public key from the secret so the
/// transcript matches [`encapsulate_to`].
pub fn decapsulate(
    ephemeral_secret: &[u8],
    kem_ct: &[u8],
    nonce: &Nonce,
) -> Result<SessionKey, HybridError> {
    if ephemeral_secret.len() != SECRET_KEY_LEN {
        return Err(HybridError::SecretKey);
    }
    if kem_ct.len() != KEM_CT_LEN {
        return Err(HybridError::KemCiphertext);
    }
    let (dk_bytes, xsk_bytes) = ephemeral_secret.split_at(MLKEM_DK_LEN);

    let mut sk_enc: Encoded<DecapKey> =
        dk_bytes.try_into().map_err(|_| HybridError::SecretKey)?;
    let dk = DecapKey::from_bytes(&sk_enc);
    sk_enc.zeroize();

    let mut xs = <[u8; X25519_LEN]>::try_from(xsk_bytes).map_err(|_| HybridError::SecretKey)?;
    let x_sk = StaticSecret::from(xs);
    xs.zeroize();

    let (ct_m_bytes, epk_bytes) = kem_ct.split_at(MLKEM_CT_LEN);
    let ct: Ciphertext<MlKem1024> =
        ct_m_bytes.try_into().map_err(|_| HybridError::KemCiphertext)?;
    let epk = XPublicKey::from(
        <[u8; X25519_LEN]>::try_from(epk_bytes).map_err(|_| HybridError::KemCiphertext)?,
    );

    let ss_x = x_sk.diffie_hellman(&epk);
    if !ss_x.was_contributory() {
        return Err(HybridError::KemCiphertext);
    }

    let mut ss_m = dk.decapsulate(&ct).map_err(|_| HybridError::SharedSecret)?;

    // Rebuild the anchor public key (dk embeds ek; X25519 pk derives from sk).
    let mut anchor_public = Vec::with_capacity(PUBLIC_KEY_LEN);
    anchor_public.extend_from_slice(&dk.encapsulation_key().as_bytes());
    anchor_public.extend_from_slice(XPublicKey::from(&x_sk).as_bytes());

    let key = combine(ss_m.as_slice(), ss_x.as_bytes(), kem_ct, &anchor_public, nonce);
    ss_m.zeroize();
    key
}

/// X-Wing-style combiner: `HKDF-SHA-256(ikm = ss_MLKEM || ss_X25519, info =
/// label || version || H(kem_ct) || H(anchor_pubkey) || nonce)`. Never returns
/// a raw KEM output as the key; binds the full transcript so a mix-and-match or
/// a relayed encapsulation derives a different key.
fn combine(
    ss_mlkem: &[u8],
    ss_x25519: &[u8; 32],
    kem_ct: &[u8],
    anchor_public: &[u8],
    nonce: &Nonce,
) -> Result<SessionKey, HybridError> {
    if ss_mlkem.len() != 32 {
        return Err(HybridError::SharedSecret);
    }
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(ss_mlkem);
    ikm[32..].copy_from_slice(ss_x25519);

    let ct_hash = Sha256::digest(kem_ct);
    let pk_hash = Sha256::digest(anchor_public);

    let hk = Hkdf::<Sha256>::new(None, ikm.as_ref());
    let mut key: SessionKey = Zeroizing::new([0u8; SESSION_KEY_LEN]);
    hk.expand_multi_info(
        &[HKDF_LABEL, &[PROTOCOL_VERSION], &ct_hash, &pk_hash, nonce],
        key.as_mut(),
    )
    .map_err(|_| HybridError::SharedSecret)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nonce() -> Nonce {
        core::array::from_fn(|i| (i as u8).wrapping_mul(7))
    }

    #[test]
    fn handshake_agrees_on_session_key() {
        let desk = EphemeralKeypair::generate();
        assert_eq!(desk.public.len(), PUBLIC_KEY_LEN);
        let n = nonce();
        let (kem_ct, phone_key) = encapsulate_to(&desk.public, &n).unwrap();
        assert_eq!(kem_ct.len(), KEM_CT_LEN);
        let desk_key = desk.decapsulate(&kem_ct, &n).unwrap();
        assert_eq!(&*phone_key, &*desk_key);
    }

    #[test]
    fn different_nonce_diverges_key() {
        // A relayed handshake bound to a different nonce yields a different key
        // (the SAS tripwire).
        let desk = EphemeralKeypair::generate();
        let (kem_ct, phone_key) = encapsulate_to(&desk.public, &nonce()).unwrap();
        let mut n2 = nonce();
        n2[0] ^= 1;
        let desk_key = desk.decapsulate(&kem_ct, &n2).unwrap();
        assert_ne!(&*phone_key, &*desk_key);
    }

    #[test]
    fn tampered_encapsulation_diverges_key() {
        let desk = EphemeralKeypair::generate();
        let n = nonce();
        let (mut kem_ct, phone_key) = encapsulate_to(&desk.public, &n).unwrap();
        kem_ct[0] ^= 0x01; // flip a bit in the ML-KEM ct -> implicit rejection
        let desk_key = desk.decapsulate(&kem_ct, &n).unwrap();
        assert_ne!(&*phone_key, &*desk_key);
    }

    #[test]
    fn wrong_length_inputs_rejected() {
        let desk = EphemeralKeypair::generate();
        assert_eq!(
            encapsulate_to(&desk.public[..PUBLIC_KEY_LEN - 1], &nonce()).unwrap_err(),
            HybridError::PublicKey
        );
        assert_eq!(
            decapsulate(&[0u8; 3], &[0u8; KEM_CT_LEN], &nonce()).unwrap_err(),
            HybridError::SecretKey
        );
    }
}
