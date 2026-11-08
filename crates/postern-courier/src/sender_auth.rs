//! Opt-in PQ sender-authentication over the seal.
//!
//! `seal`/`open` (the crate root) hybrid-encrypt a payload to a recipient's
//! public key, but **anyone holding that public key can produce a valid
//! [`SealedPayload`]** — `open` succeeding proves the payload was encrypted
//! to the recipient, nothing about who sealed it. This module closes that
//! gap with an **ML-DSA-87** (FIPS-204) signature over a domain-separated
//! transcript of the sealed payload: [`sign_sealed`] produces a
//! [`SignedSealedPayload`] the recipient can [`verify_sealed`] against the
//! sender's ML-DSA verifying key (authenticated out-of-band, exactly like the
//! recipient's courier key — see [`sender_fingerprint`]).
//!
//! This is a **signature leg bolted onto the existing seal**, not a change to
//! it: [`sign_sealed`]/[`verify_sealed`] operate on an already-built
//! [`SealedPayload`] and never touch [`crate::seal`], [`crate::open`],
//! [`crate::combine`]-the-KDF, [`crate::WIRE_VERSION`], or
//! [`SealedPayload::to_bytes`]/[`SealedPayload::from_bytes`] — the unsigned
//! wire bytes this module wraps are byte-identical to the crate root's.
//!
//! The transcript binds — via SHA-256 hashes, never the raw bytes — the
//! sealed payload's KEM ciphertext, its AEAD body, and the recipient's
//! public key, plus a fresh 32-byte nonce and a Unix-seconds timestamp:
//! `label ‖ WIRE_VERSION ‖ SHA-256(kem_ct) ‖ SHA-256(body) ‖
//! SHA-256(recipient_public) ‖ nonce ‖ timestamp`. Binding the recipient key
//! stops a signed payload sealed for one recipient from being replayed as if
//! it were signed for another; binding the wire version stops a transcript
//! from meaning something different if the unsigned wire format ever moves;
//! the nonce and timestamp are carried alongside the signature in
//! [`SignedSealedPayload`] so a recipient can feed them to
//! [`crate::replay::ReplayGuard`] (which this module does not do itself —
//! see "Honest limits" below and [`crate::replay`]'s own module docs).
//!
//! HONEST LIMITS (do not soften; read before relying on this):
//! - **Opt-in and additive.** A bare [`SealedPayload`] from [`crate::seal`]
//!   still has no sender authentication at all — this module only helps once
//!   both sides use it. A recipient that only calls [`crate::open`] gets
//!   nothing from a sender who also calls [`sign_sealed`]; the recipient must
//!   call [`verify_sealed`] too.
//! - **The sender's verifying key is out-of-band-authenticated, same as the
//!   recipient's courier key.** [`verify_sealed`] proves the payload was
//!   signed by *whoever holds the matching signing key* — nothing more. If
//!   the recipient has not authenticated the sender's verifying key over a
//!   trusted channel first ([`sender_fingerprint`]), an active attacker can
//!   simply substitute their own keypair and sign as "the sender".
//! - **No replay protection by itself.** [`verify_sealed`] checks the
//!   signature and the transcript binding; it does **not** check whether the
//!   nonce or timestamp have been seen before, or whether the timestamp is
//!   recent. A verified [`SignedSealedPayload`] can be re-served verbatim and
//!   will verify again. Anti-replay is [`crate::replay::ReplayGuard`] — a
//!   caller wanting both must call `verify_sealed` **and**
//!   `ReplayGuard::check_and_record` (this module's [`SignedSealedPayload`]
//!   implements [`crate::replay::ReplayCheckable`] for exactly that).
//! - **`ml-dsa` is pre-1.0 and UNAUDITED** (RustCrypto's pure-Rust FIPS-204
//!   implementation) — the same maturity caveat as this crate's `ml-kem` leg,
//!   with no classical fallback signature scheme here (unlike the hybrid
//!   KEM's X25519 leg): a break in `ml-dsa` breaks sender authentication,
//!   though the seal's confidentiality (the hybrid KEM) is unaffected either
//!   way — `sign_sealed`/`verify_sealed` never touch the AEAD key or either
//!   KEM secret.
//! - **Availability, not confidentiality or integrity of the unsigned path.**
//!   Removing/skipping this module entirely still leaves `seal`/`open` as
//!   confidential and tamper-evident as documented at the crate root; this
//!   module only adds a *positive* sender claim, it is never required for the
//!   payload itself to be safe to decrypt.

use ml_dsa::{Generate, KeyInit, Keypair, MlDsa87, Seed, Signature, Signer, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

use crate::{replay::ReplayCheckable, CourierError, SealedPayload, WIRE_VERSION};

/// Domain-separation label for the sender-auth transcript. Distinct from
/// [`crate::HKDF_LABEL`] (a different primitive, a different purpose) and
/// versioned independently of [`crate::WIRE_VERSION`] (which is bound *into*
/// the transcript, not reused as this label's version).
const TRANSCRIPT_LABEL: &[u8] = b"postern-courier/sender-auth/v1";

/// Domain-separation label for [`sender_fingerprint`] — distinct from
/// [`crate::key_fingerprint`]'s label so a sender verifying-key fingerprint
/// and a recipient courier-key fingerprint can never collide even if the
/// underlying bytes ever coincided in length.
const FINGERPRINT_LABEL: &[u8] = b"postern-courier/sender-fingerprint/v1";

/// Per-transcript random nonce length (bytes).
const NONCE_LEN: usize = 32;
/// Unix-seconds timestamp encoding length (bytes) in the transcript and wire
/// format.
const TIMESTAMP_LEN: usize = 8;
/// FIPS-204 ML-DSA-87 fixed signature encoding length. A constant (not a
/// runtime `EncodedSignature::<MlDsa87>::default().len()` query) because the
/// wire format below needs it at a fixed offset; confirmed against the
/// RustCrypto `ml-dsa` crate's `MlDsa87` parameter set.
const SIGNATURE_LEN: usize = 4627;
/// FIPS-204 ML-DSA-87 verifying-key encoding length, for reference (parsing
/// below uses `VerifyingKey::new_from_slice`'s own length check rather than
/// this constant, so it is not itself relied on for correctness).
pub const SENDER_VERIFYING_KEY_LEN: usize = 2592;

/// Wire-format version for [`SignedSealedPayload::to_bytes`] — a fresh,
/// independent version byte from [`crate::WIRE_VERSION`] (the unsigned
/// [`SealedPayload`] wire format), so the two can never be confused with each
/// other at parse time. This is the FIRST byte of
/// [`SignedSealedPayload::to_bytes`].
pub const SENDER_AUTH_WIRE_VERSION: u8 = 1;

/// Fixed prefix length of [`SignedSealedPayload::to_bytes`] before the
/// embedded (unsigned) `SealedPayload::to_bytes()` tail: version byte ‖
/// nonce ‖ timestamp ‖ signature.
const HEADER_LEN: usize = 1 + NONCE_LEN + TIMESTAMP_LEN + SIGNATURE_LEN;

/// An ML-DSA-87 sender keypair for [`sign_sealed`]. Shaped like
/// [`crate::Recipient`] on purpose: `public` is shared out-of-band with
/// recipients and MUST be authenticated out-of-band (compare
/// [`sender_fingerprint`] readings, exactly like [`crate::key_fingerprint`]
/// for a recipient's courier key) before anyone trusts a signature made with
/// it; `secret` is wiped from RAM when the `SenderIdentity` is dropped.
///
/// Randomness note: keygen draws from the OS CSPRNG, but via `ml-dsa`'s own
/// `getrandom`-backed `Generate::generate()` rather than the
/// `rand_core::OsRng` symbol the rest of this crate uses for the hybrid
/// KEM/X25519 legs — RustCrypto's `ml-dsa` depends on a newer, incompatible
/// major version of `rand_core`/`crypto-common`, so the two RNG entry points
/// cannot share a type. Both ultimately read the same OS entropy source.
pub struct SenderIdentity {
    /// ML-DSA-87 verifying-key encoding (2592 bytes) — share this out-of-band.
    pub public: Vec<u8>,
    /// The ML-DSA-87 signing key's 32-byte seed. Wiped from RAM on drop.
    pub secret: Vec<u8>,
}

impl Drop for SenderIdentity {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Generate a fresh ML-DSA-87 sender identity. See [`SenderIdentity`] for the
/// randomness-source note and the out-of-band-authentication requirement.
pub fn generate_sender_identity() -> SenderIdentity {
    let signing_key = ml_dsa::SigningKey::<MlDsa87>::generate();
    let public = signing_key.verifying_key().encode().to_vec();

    // `to_seed()` returns an owned copy of the 32-byte seed (the underlying
    // `SigningKey` itself is `ZeroizeOnDrop` and wipes its own copy when it
    // drops here); scrub this transient copy after extracting it into
    // `secret`, matching the crate root's "scrub the transient encoded copy"
    // pattern in `generate_recipient`.
    let mut seed = signing_key.to_seed();
    let secret = seed.to_vec();
    seed.zeroize();

    SenderIdentity { public, secret }
}

/// A short, human-comparable fingerprint of a sender's ML-DSA verifying key,
/// for **out-of-band key authentication** — the same pattern as
/// [`crate::key_fingerprint`] (truncated SHA-256 under a domain-separation
/// tag, rendered as five hex groups), with its own label so a sender
/// fingerprint and a recipient fingerprint are never mistakable for each
/// other even if compared side by side.
pub fn sender_fingerprint(sender_verifying_key: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(FINGERPRINT_LABEL);
    h.update((sender_verifying_key.len() as u64).to_le_bytes());
    h.update(sender_verifying_key);
    let digest = h.finalize();
    digest[..10]
        .chunks(2)
        .map(|p| format!("{:02x}{:02x}", p[0], p[1]))
        .collect::<Vec<_>>()
        .join("-")
}

/// A [`SealedPayload`] plus an ML-DSA-87 signature over its
/// domain-separated transcript (see the module docs), and the nonce/
/// timestamp that transcript binds. [`verify_sealed`] is the only supported
/// way to check the signature; do not compare fields individually.
pub struct SignedSealedPayload {
    /// The sealed payload the signature covers. Identical
    /// `kem_ct`/`body` bytes to what [`crate::seal`] produced — this module
    /// never re-encrypts or re-derives anything.
    pub sealed: SealedPayload,
    /// The ML-DSA-87 signature bytes (fixed [`SIGNATURE_LEN`]).
    pub signature: Vec<u8>,
    /// The per-transcript random nonce.
    pub nonce: [u8; NONCE_LEN],
    /// Unix-seconds timestamp bound into the transcript.
    pub timestamp: u64,
}

impl ReplayCheckable for SignedSealedPayload {
    fn replay_nonce(&self) -> &[u8; 32] {
        &self.nonce
    }

    fn replay_timestamp_secs(&self) -> u64 {
        self.timestamp
    }
}

impl SignedSealedPayload {
    /// Serialize for the wire: `SENDER_AUTH_WIRE_VERSION ‖ nonce ‖
    /// timestamp (u64 big-endian) ‖ signature ‖ SealedPayload::to_bytes()`.
    /// The leading version byte is independent of (never confusable with)
    /// [`crate::WIRE_VERSION`]; the embedded tail is exactly what
    /// [`SealedPayload::to_bytes`] would produce standalone.
    pub fn to_bytes(&self) -> Vec<u8> {
        let sealed_wire = self.sealed.to_bytes();
        let mut out = Vec::with_capacity(HEADER_LEN + sealed_wire.len());
        out.push(SENDER_AUTH_WIRE_VERSION);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&sealed_wire);
        out
    }

    /// Parse a wire blob produced by [`SignedSealedPayload::to_bytes`].
    /// Rejects an unknown version byte and truncated input (including a
    /// truncated embedded `SealedPayload`, which
    /// [`SealedPayload::from_bytes`] itself rejects). This does **not**
    /// verify the signature — call [`verify_sealed`] for that.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CourierError> {
        match bytes.first() {
            None => return Err(CourierError::SenderSignature),
            Some(&SENDER_AUTH_WIRE_VERSION) => {}
            Some(_) => return Err(CourierError::Version),
        }
        if bytes.len() < HEADER_LEN {
            return Err(CourierError::SenderSignature);
        }

        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[1..1 + NONCE_LEN]);

        let ts_start = 1 + NONCE_LEN;
        let ts_bytes: [u8; TIMESTAMP_LEN] = bytes[ts_start..ts_start + TIMESTAMP_LEN]
            .try_into()
            .map_err(|_| CourierError::SenderSignature)?;
        let timestamp = u64::from_be_bytes(ts_bytes);

        let sig_start = ts_start + TIMESTAMP_LEN;
        let signature = bytes[sig_start..sig_start + SIGNATURE_LEN].to_vec();

        let sealed = SealedPayload::from_bytes(&bytes[sig_start + SIGNATURE_LEN..])?;

        Ok(Self { sealed, signature, nonce, timestamp })
    }
}

/// Build the domain-separated transcript [`sign_sealed`]/[`verify_sealed`]
/// sign/verify: `TRANSCRIPT_LABEL ‖ WIRE_VERSION ‖ SHA-256(kem_ct) ‖
/// SHA-256(body) ‖ SHA-256(recipient_public) ‖ nonce ‖ timestamp`. Hashing
/// `kem_ct`/`body`/`recipient_public` rather than including them raw keeps
/// the signed message a small fixed size regardless of payload size.
fn transcript(
    kem_ct: &[u8],
    body: &[u8],
    recipient_public: &[u8],
    nonce: &[u8; NONCE_LEN],
    timestamp: u64,
) -> Vec<u8> {
    let mut t = Vec::with_capacity(TRANSCRIPT_LABEL.len() + 1 + 32 * 3 + NONCE_LEN + TIMESTAMP_LEN);
    t.extend_from_slice(TRANSCRIPT_LABEL);
    t.push(WIRE_VERSION);
    t.extend_from_slice(&Sha256::digest(kem_ct));
    t.extend_from_slice(&Sha256::digest(body));
    t.extend_from_slice(&Sha256::digest(recipient_public));
    t.extend_from_slice(nonce);
    t.extend_from_slice(&timestamp.to_be_bytes());
    t
}

/// Sign a [`SealedPayload`] as `sender`, binding it (via the transcript — see
/// the module docs) to `recipient_public` so the signature cannot be
/// replayed as if it authenticated a seal to a different recipient. Draws a
/// fresh 32-byte nonce from the OS CSPRNG and the current wall-clock time for
/// the timestamp (`0` if the clock is unreadable, e.g. pre-1970 — this fails
/// **open** on freshness, which is why [`verify_sealed`] alone provides no
/// replay protection; pair it with [`crate::replay::ReplayGuard`] on the
/// recipient side).
///
/// Never touches [`crate::seal`]/[`crate::open`]/the AEAD key/either KEM
/// secret — this only reads `sealed`'s already-public `kem_ct`/`body` bytes
/// and signs their hashes.
pub fn sign_sealed(
    sender: &SenderIdentity,
    recipient_public: &[u8],
    sealed: &SealedPayload,
) -> SignedSealedPayload {
    let mut nonce = [0u8; NONCE_LEN];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut nonce);

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let msg = transcript(&sealed.kem_ct, &sealed.body, recipient_public, &nonce, timestamp);

    // Reconstruct the signing key from its stored seed for this one
    // signature, then let it drop (ZeroizeOnDrop wipes the expanded key and
    // its own seed copy; `sender.secret` — the source seed — is untouched
    // and is wiped only when the `SenderIdentity` itself drops).
    let seed = Seed::try_from(sender.secret.as_slice())
        .expect("SenderIdentity.secret is always a 32-byte ML-DSA-87 seed");
    let signing_key = ml_dsa::SigningKey::<MlDsa87>::from_seed(&seed);
    let signature = signing_key.sign(&msg).encode().to_vec();

    SignedSealedPayload {
        sealed: SealedPayload { kem_ct: sealed.kem_ct.clone(), body: sealed.body.clone() },
        signature,
        nonce,
        timestamp,
    }
}

/// Verify a [`SignedSealedPayload`] against `sender_verifying_key` and
/// `recipient_public`, returning the enclosed [`SealedPayload`] on success —
/// still open it with [`crate::open`] and the recipient's hybrid secret key
/// afterwards; a verified signature says who sealed it, not that decryption
/// will succeed for a *different* recipient key than the one bound into the
/// transcript.
///
/// Uses only `sender_verifying_key`, `recipient_public`, and `signed`'s own
/// fields (the wire bytes) — no ambient state, no clock, no replay check
/// (see the module docs and [`crate::replay::ReplayGuard`]).
///
/// Errors are deliberately coarse ([`CourierError::SenderKey`] for a
/// malformed verifying key, [`CourierError::SenderSignature`] for a
/// malformed or non-verifying signature) — never distinguishing *why* a
/// signature failed to an attacker.
pub fn verify_sealed<'a>(
    sender_verifying_key: &[u8],
    recipient_public: &[u8],
    signed: &'a SignedSealedPayload,
) -> Result<&'a SealedPayload, CourierError> {
    let vk = VerifyingKey::<MlDsa87>::new_from_slice(sender_verifying_key)
        .map_err(|_| CourierError::SenderKey)?;
    let sig = Signature::<MlDsa87>::try_from(signed.signature.as_slice())
        .map_err(|_| CourierError::SenderSignature)?;

    let msg = transcript(
        &signed.sealed.kem_ct,
        &signed.sealed.body,
        recipient_public,
        &signed.nonce,
        signed.timestamp,
    );

    vk.verify(&msg, &sig).map_err(|_| CourierError::SenderSignature)?;

    Ok(&signed.sealed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{generate_recipient, seal};

    #[test]
    fn sign_then_verify_roundtrips() {
        let sender = generate_sender_identity();
        let rcpt = generate_recipient();
        let sealed = seal(&rcpt.public, b"a signed drop").unwrap();

        let signed = sign_sealed(&sender, &rcpt.public, &sealed);
        let verified = verify_sealed(&sender.public, &rcpt.public, &signed).unwrap();

        assert_eq!(verified.kem_ct, sealed.kem_ct);
        assert_eq!(verified.body, sealed.body);
        // The signed payload still opens with the recipient's secret key —
        // sender-auth is additive, never a change to the sealed bytes.
        assert_eq!(crate::open(&rcpt.secret, verified).unwrap(), b"a signed drop");
    }

    #[test]
    fn wrong_sender_key_is_rejected() {
        let sender = generate_sender_identity();
        let impostor = generate_sender_identity();
        let rcpt = generate_recipient();
        let sealed = seal(&rcpt.public, b"secret").unwrap();

        let signed = sign_sealed(&sender, &rcpt.public, &sealed);
        assert!(matches!(
            verify_sealed(&impostor.public, &rcpt.public, &signed),
            Err(CourierError::SenderSignature)
        ));
    }

    #[test]
    fn wrong_recipient_binding_is_rejected() {
        // The signature was made binding `rcpt`'s public key; verifying
        // against a DIFFERENT recipient public key must fail even though the
        // sender key and signature bytes are otherwise valid.
        let sender = generate_sender_identity();
        let rcpt = generate_recipient();
        let other_rcpt = generate_recipient();
        let sealed = seal(&rcpt.public, b"secret").unwrap();

        let signed = sign_sealed(&sender, &rcpt.public, &sealed);
        assert!(matches!(
            verify_sealed(&sender.public, &other_rcpt.public, &signed),
            Err(CourierError::SenderSignature)
        ));
    }

    #[test]
    fn tampered_sealed_body_breaks_verification() {
        let sender = generate_sender_identity();
        let rcpt = generate_recipient();
        let sealed = seal(&rcpt.public, b"secret").unwrap();

        let mut signed = sign_sealed(&sender, &rcpt.public, &sealed);
        let last = signed.sealed.body.len() - 1;
        signed.sealed.body[last] ^= 0xFF;

        assert!(matches!(
            verify_sealed(&sender.public, &rcpt.public, &signed),
            Err(CourierError::SenderSignature)
        ));
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let sender = generate_sender_identity();
        let rcpt = generate_recipient();
        let sealed = seal(&rcpt.public, b"secret").unwrap();

        let mut signed = sign_sealed(&sender, &rcpt.public, &sealed);
        let last = signed.signature.len() - 1;
        signed.signature[last] ^= 0x01;

        assert!(matches!(
            verify_sealed(&sender.public, &rcpt.public, &signed),
            Err(CourierError::SenderSignature)
        ));
    }

    #[test]
    fn tampered_nonce_or_timestamp_breaks_verification() {
        let sender = generate_sender_identity();
        let rcpt = generate_recipient();
        let sealed = seal(&rcpt.public, b"secret").unwrap();

        let mut signed_nonce = sign_sealed(&sender, &rcpt.public, &sealed);
        signed_nonce.nonce[0] ^= 0x01;
        assert!(verify_sealed(&sender.public, &rcpt.public, &signed_nonce).is_err());

        let mut signed_ts = sign_sealed(&sender, &rcpt.public, &sealed);
        signed_ts.timestamp = signed_ts.timestamp.wrapping_add(1);
        assert!(verify_sealed(&sender.public, &rcpt.public, &signed_ts).is_err());
    }

    #[test]
    fn bad_length_verifying_key_is_rejected() {
        let sender = generate_sender_identity();
        let rcpt = generate_recipient();
        let sealed = seal(&rcpt.public, b"secret").unwrap();
        let signed = sign_sealed(&sender, &rcpt.public, &sealed);

        assert!(matches!(
            verify_sealed(&sender.public[..sender.public.len() - 1], &rcpt.public, &signed),
            Err(CourierError::SenderKey)
        ));
    }

    #[test]
    fn wire_roundtrip_and_version_check() {
        let sender = generate_sender_identity();
        let rcpt = generate_recipient();
        let sealed = seal(&rcpt.public, b"payload").unwrap();
        let signed = sign_sealed(&sender, &rcpt.public, &sealed);

        let wire = signed.to_bytes();
        assert_eq!(wire[0], SENDER_AUTH_WIRE_VERSION);

        let parsed = SignedSealedPayload::from_bytes(&wire).unwrap();
        assert_eq!(parsed.nonce, signed.nonce);
        assert_eq!(parsed.timestamp, signed.timestamp);
        assert_eq!(parsed.signature, signed.signature);
        assert_eq!(parsed.sealed.kem_ct, signed.sealed.kem_ct);
        assert_eq!(parsed.sealed.body, signed.sealed.body);

        let verified = verify_sealed(&sender.public, &rcpt.public, &parsed).unwrap();
        assert_eq!(crate::open(&rcpt.secret, verified).unwrap(), b"payload");

        // Unknown version byte is rejected up front.
        let mut bad = wire.clone();
        bad[0] = 99;
        assert!(matches!(SignedSealedPayload::from_bytes(&bad), Err(CourierError::Version)));
        // Truncated input (before the header even completes) is rejected.
        assert!(SignedSealedPayload::from_bytes(&wire[..HEADER_LEN - 1]).is_err());
        assert!(SignedSealedPayload::from_bytes(&[]).is_err());
        // Truncated embedded SealedPayload tail is rejected too (delegated
        // to `SealedPayload::from_bytes`, which itself requires at least a
        // full `kem_ct`) — cut into the middle of the embedded `kem_ct`.
        assert!(SignedSealedPayload::from_bytes(&wire[..HEADER_LEN + 4]).is_err());
    }

    #[test]
    fn unsigned_wire_bytes_are_untouched_by_this_module() {
        // The embedded SealedPayload tail inside a SignedSealedPayload's wire
        // bytes is byte-identical to what SealedPayload::to_bytes() produces
        // standalone — this module wraps the unsigned wire, it never changes it.
        let sender = generate_sender_identity();
        let rcpt = generate_recipient();
        let sealed = seal(&rcpt.public, b"payload").unwrap();
        let sealed_wire = sealed.to_bytes();

        let signed = sign_sealed(&sender, &rcpt.public, &sealed);
        let signed_wire = signed.to_bytes();

        assert_eq!(&signed_wire[HEADER_LEN..], sealed_wire.as_slice());
    }

    #[test]
    fn fingerprint_is_stable_and_distinguishing() {
        let a = generate_sender_identity();
        let b = generate_sender_identity();
        let fa = sender_fingerprint(&a.public);
        assert_eq!(fa, sender_fingerprint(&a.public));
        assert_ne!(fa, sender_fingerprint(&b.public));
        assert_eq!(fa.len(), 24);
        assert_eq!(fa.split('-').count(), 5);
        // Distinct label from the recipient-key fingerprint even though the
        // two key encodings are different lengths anyway (2592 vs 1600).
        assert_ne!(fa, crate::key_fingerprint(&a.public));
    }

    #[test]
    fn generated_identity_has_expected_key_shapes() {
        let ident = generate_sender_identity();
        assert_eq!(ident.public.len(), SENDER_VERIFYING_KEY_LEN);
        assert_eq!(ident.secret.len(), 32);
    }

    #[test]
    fn replay_checkable_exposes_nonce_and_timestamp() {
        let sender = generate_sender_identity();
        let rcpt = generate_recipient();
        let sealed = seal(&rcpt.public, b"secret").unwrap();
        let signed = sign_sealed(&sender, &rcpt.public, &sealed);

        assert_eq!(*ReplayCheckable::replay_nonce(&signed), signed.nonce);
        assert_eq!(ReplayCheckable::replay_timestamp_secs(&signed), signed.timestamp);

        // And it actually plugs into a ReplayGuard end-to-end.
        let mut guard = crate::replay::ReplayGuard::new(std::time::Duration::from_secs(600));
        assert!(guard.check_and_record_payload(&signed, signed.timestamp).is_ok());
        let err = guard.check_and_record_payload(&signed, signed.timestamp).unwrap_err();
        assert!(matches!(err, CourierError::ReplayNonceReused));
    }

    // --- additional adversarial coverage -----------------------------------
    // The tests above already cover: (1) sign→verify roundtrip
    // (`sign_then_verify_roundtrips`), (2) a flipped signature byte
    // (`tampered_signature_is_rejected`), (4) a different sender's verifying
    // key (`wrong_sender_key_is_rejected`), (5) a different recipient_public
    // (`wrong_recipient_binding_is_rejected`), (6) wire round-trip / unknown
    // version / truncated input (`wire_roundtrip_and_version_check`), and a
    // same-object-presented-twice replay check
    // (`replay_checkable_exposes_nonce_and_timestamp`). The tests below close
    // the remaining gaps: transcript binding specifically via `kem_ct`
    // mutation and a genuine cross-payload signature transplant (3), and an
    // end-to-end replay test that goes through the actual wire bytes
    // (`to_bytes`/`from_bytes`) twice, matching "the same signed wire blob
    // presented twice" literally (7).

    // (3) A mutated kem_ct field is rejected — transcript binding covers the
    // KEM ciphertext leg too, not just the AEAD body.
    #[test]
    fn tampered_kem_ct_breaks_verification() {
        let sender = generate_sender_identity();
        let rcpt = generate_recipient();
        let sealed = seal(&rcpt.public, b"secret").unwrap();

        let mut signed = sign_sealed(&sender, &rcpt.public, &sealed);
        signed.sealed.kem_ct[0] ^= 0x01;

        assert!(matches!(
            verify_sealed(&sender.public, &rcpt.public, &signed),
            Err(CourierError::SenderSignature)
        ));
    }

    // (3) A signature transplanted onto a DIFFERENT, independently-sealed
    // SealedPayload is rejected — proving the signature is bound to a
    // specific transcript, not just "a valid signature exists from this
    // sender over *something*".
    #[test]
    fn signature_transplanted_onto_different_sealed_payload_is_rejected() {
        let sender = generate_sender_identity();
        let rcpt = generate_recipient();

        let sealed_a = seal(&rcpt.public, b"payload A").unwrap();
        let sealed_b = seal(&rcpt.public, b"payload B - a completely different seal").unwrap();
        assert_ne!(sealed_a.kem_ct, sealed_b.kem_ct);

        let signed_a = sign_sealed(&sender, &rcpt.public, &sealed_a);

        // Lift signed_a's signature/nonce/timestamp onto sealed_b's bytes.
        let transplanted = SignedSealedPayload {
            sealed: SealedPayload { kem_ct: sealed_b.kem_ct.clone(), body: sealed_b.body.clone() },
            signature: signed_a.signature.clone(),
            nonce: signed_a.nonce,
            timestamp: signed_a.timestamp,
        };

        assert!(matches!(
            verify_sealed(&sender.public, &rcpt.public, &transplanted),
            Err(CourierError::SenderSignature)
        ));
    }

    // (7) End-to-end replay through the actual wire encoding: the SAME
    // `SignedSealedPayload::to_bytes()` blob is parsed and presented to a
    // `ReplayGuard` twice. The first verify+check passes; the second verify
    // still succeeds (the signature itself is unaffected by replay — it is
    // the guard's job to catch repetition), but the guard rejects it with
    // the replay error.
    #[test]
    fn same_signed_wire_blob_presented_twice_is_rejected_by_replay_guard() {
        let sender = generate_sender_identity();
        let rcpt = generate_recipient();
        let sealed = seal(&rcpt.public, b"one-shot drop over the wire").unwrap();
        let signed = sign_sealed(&sender, &rcpt.public, &sealed);
        let wire = signed.to_bytes();

        let mut guard = crate::replay::ReplayGuard::new(std::time::Duration::from_secs(600));

        // First presentation: parse the wire blob, verify, check the guard.
        let first = SignedSealedPayload::from_bytes(&wire).expect("parse #1");
        let first_sealed =
            verify_sealed(&sender.public, &rcpt.public, &first).expect("verify #1 must pass");
        assert_eq!(
            crate::open(&rcpt.secret, first_sealed).unwrap(),
            b"one-shot drop over the wire"
        );
        assert!(
            guard.check_and_record_payload(&first, first.timestamp).is_ok(),
            "first presentation must pass the replay guard"
        );

        // Second presentation of the EXACT SAME wire bytes (re-parsed fresh,
        // as a recipient receiving a replayed network message would see it).
        let second = SignedSealedPayload::from_bytes(&wire).expect("parse #2");
        assert!(
            verify_sealed(&sender.public, &rcpt.public, &second).is_ok(),
            "the signature is still cryptographically valid on replay — only the guard rejects it"
        );
        let err = guard
            .check_and_record_payload(&second, second.timestamp)
            .expect_err("second presentation of the same wire blob must be rejected as a replay");
        assert!(matches!(err, CourierError::ReplayNonceReused));
    }
}
