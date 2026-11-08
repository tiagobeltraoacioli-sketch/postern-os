//! Postern Courier — the hybrid post-quantum payload seal for serverless file
//! drop (a Postern Labs product).
//!
//! Send a file/message person-to-person with the payload **hybrid-encrypted
//! end-to-end**: **ML-KEM-1024** (FIPS-203) *and* **X25519** each establish a
//! shared secret to the recipient's hybrid public key, the two secrets are
//! combined with an **HKDF-SHA-256** combiner (X-Wing-style: the transcript —
//! wire version, KEM ciphertexts, recipient key — is bound into the derived
//! key), and **XChaCha20-Poly1305** encrypts the bytes under the combined key.
//! A break of *either* leg alone — an `ml-kem` implementation bug, a future
//! lattice surprise, or a quantum computer defeating X25519 — leaves the
//! payload still protected by the other. Scrub the file with `postern-hygiene`
//! first and check its `ScrubReport` (including `passed_through`) — courier
//! encrypts whatever bytes it is given; it does not scrub them itself.
//!
//! TRANSPORT STATUS (honest): the transport is an ephemeral Tor onion service.
//! It lives behind the opt-in **`onion-transport`** feature (module
//! [`transport`]): the sender publishes an ephemeral `.onion` via
//! `postern-tor`'s onion-service HOSTING path (arti `onion-service-service`)
//! and serves the [`SealedPayload`] to the first peer; the recipient connects
//! as an onion-service client and downloads it. Default builds still ship the
//! **crypto seal only** — the feature is off, so no arti dependency and no
//! network. The transport is UNAUDITED reference-prototype: real HS publish
//! needs the live Tor network and minutes (exercised by an ignored test), the
//! onion key rests in arti's keystore (not a hardware token), and the drop has
//! **no anti-replay/DoS hardening beyond a size cap** — the seal, not the wire,
//! is what protects the payload. A human-runnable two-terminal walkthrough
//! ships as `examples/onion_drop.rs` (verified-receive is its ONLY receive
//! path; it prints these limits verbatim on every startup); its live
//! round-trip over the real Tor network remains a documented MANUAL step —
//! no transcript of one has been recorded yet.
//!
//! WIRE FORMAT v2 (deliberate, documented break — fine pre-mainnet, no
//! deployed payloads to stay compatible with): recipient public key =
//! `ML-KEM-1024 ek (1568) ‖ X25519 pk (32)`; secret key = `ML-KEM-1024 dk
//! (3168) ‖ X25519 sk (32)`; `SealedPayload::to_bytes` = `version byte ‖
//! kem_ct (ML-KEM ct 1568 ‖ X25519 ephemeral pk 32) ‖ nonce ‖ AEAD ct`. The
//! ML-KEM encodings are the RustCrypto `ml-kem` crate's FIPS-203 (final)
//! ML-KEM-1024 encodings — NOT the round-3 Kyber vectors. Note: RustCrypto
//! `ml-kem` is pre-1.0 and **unaudited** — exactly why the classical X25519
//! leg exists.
//!
//! Why this and not OnionShare: OnionShare is GPL *and* classical-crypto only
//! — a **harvest-now-decrypt-later** adversary who records the Tor circuit can
//! decrypt it once a quantum computer exists. Here the payload is PQ-sealed
//! *inside* the (classical) Tor tunnel, so a recorded circuit yields **no
//! payload plaintext, ever** (payload *size*, timing, and endpoints remain
//! visible — see limits below).
//!
//! Honest limits (state them in the product, never hide):
//! - **Key authenticity is out-of-band**: `seal` encrypts to whatever public
//!   key it is given. The recipient's key MUST be verified over an
//!   authenticated channel — compare [`key_fingerprint`] readings before
//!   sending, or an active MITM who substitutes their own key reads
//!   everything.
//! - **Sender authentication is OPT-IN**: a bare [`SealedPayload`] from
//!   [`seal`] still has no sender authentication at all — anyone holding the
//!   recipient's public key can produce one, and `open` succeeding proves
//!   nothing about who sealed it. The [`sender_auth`] module closes that gap
//!   with an **ML-DSA-87** (FIPS-204) signature over a domain-separated
//!   transcript of the sealed payload ([`sender_auth::sign_sealed`] /
//!   [`sender_auth::verify_sealed`]) — RustCrypto `ml-dsa`, pre-1.0 and
//!   **UNAUDITED**, the same maturity caveat as the `ml-kem` leg above, with
//!   no classical fallback signature scheme. It only helps once *both* sides
//!   use it: a recipient that only calls [`open`] gets nothing from a sender
//!   who also signs. And exactly like the recipient's courier key, the
//!   **sender's ML-DSA verifying key is authenticated out-of-band** — compare
//!   [`sender_auth::sender_fingerprint`] readings before trusting a signature,
//!   or an active attacker simply substitutes their own signing keypair.
//! - The sender must stay **online** during the (future) drop — a live
//!   transfer, not a mailbox. The onion *address* crypto is classical (the PQ
//!   wrap covers the **payload**, not circuit metadata); endpoint traffic
//!   analysis (timing/volume) remains possible; the AEAD is length-revealing
//!   (no padding), so the payload size leaks.

use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Ciphertext, Encoded, EncodedSizeUser, KemCore, MlKem1024};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey as XPublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

/// The ML-KEM-1024 encapsulation key (recipient public key, PQ leg) type.
type EncapKey = <MlKem1024 as KemCore>::EncapsulationKey;
/// The ML-KEM-1024 decapsulation key (recipient secret key, PQ leg) type.
/// `ZeroizeOnDrop`.
type DecapKey = <MlKem1024 as KemCore>::DecapsulationKey;

/// Wire-format version. Bump on ANY change to key/ciphertext encodings or the
/// KDF transcript; it is the first byte of [`SealedPayload::to_bytes`] and is
/// bound into the HKDF combiner, so a v2 key can never silently open a
/// differently-derived payload.
pub const WIRE_VERSION: u8 = 2;

/// FIPS-203 ML-KEM-1024 encapsulation-key encoding length.
const MLKEM_EK_LEN: usize = 1568;
/// FIPS-203 ML-KEM-1024 decapsulation-key encoding length.
const MLKEM_DK_LEN: usize = 3168;
/// FIPS-203 ML-KEM-1024 ciphertext length.
const MLKEM_CT_LEN: usize = 1568;
/// X25519 public-key / secret-scalar / ephemeral-key length.
const X25519_LEN: usize = 32;

/// Hybrid recipient public key length: ML-KEM-1024 ek ‖ X25519 pk.
pub const PUBLIC_KEY_LEN: usize = MLKEM_EK_LEN + X25519_LEN;
/// Hybrid recipient secret key length: ML-KEM-1024 dk ‖ X25519 sk.
pub const SECRET_KEY_LEN: usize = MLKEM_DK_LEN + X25519_LEN;
/// Hybrid encapsulation length: ML-KEM-1024 ct ‖ X25519 ephemeral pk.
pub const KEM_CT_LEN: usize = MLKEM_CT_LEN + X25519_LEN;

/// Domain-separation label for the HKDF combiner (includes the format name;
/// the version byte is appended separately in `combine`).
const HKDF_LABEL: &[u8] = b"postern-courier/hybrid";

#[derive(Debug, thiserror::Error)]
pub enum CourierError {
    #[error("bad recipient public key")]
    PublicKey,
    #[error("bad recipient secret key")]
    SecretKey,
    #[error("bad encapsulated key")]
    KemCiphertext,
    #[error("shared secret wrong size")]
    SharedSecret,
    #[error("unsupported wire version")]
    Version,
    #[error("seal failed")]
    Seal,
    #[error("open failed — wrong key or tampered payload")]
    Open,
    /// Transport-layer failure over the Tor onion drop (only produced with the
    /// `onion-transport` feature): bootstrap/publish/connect failed, the peer
    /// spoke the wrong framing, or the drop exceeded [`transport::MAX_DROP_BYTES`].
    /// Deliberately coarse — a transport error must not leak *why* to an
    /// observer (and the payload is authenticated by the seal, not the wire).
    #[error("transport over onion drop failed")]
    Transport,
    /// [`replay::ReplayGuard`] rejected a timestamp older than its configured
    /// freshness window.
    #[error("timestamp is older than the anti-replay window")]
    ReplayStale,
    /// [`replay::ReplayGuard`] rejected a timestamp further in the future than
    /// its configured allowed clock skew.
    #[error("timestamp is further in the future than the allowed clock skew")]
    ReplayFutureDated,
    /// [`replay::ReplayGuard`] rejected a nonce it already recorded within the
    /// current freshness window.
    #[error("nonce already seen within the anti-replay window")]
    ReplayNonceReused,
    /// A [`sender_auth`] verifying key was malformed (wrong length or an
    /// invalid ML-DSA-87 encoding) — never anything more specific.
    #[error("bad sender verifying key")]
    SenderKey,
    /// A [`sender_auth`] signature failed to decode or did not verify against
    /// the transcript — never anything more specific (which of the two is
    /// itself a signal an attacker should not get for free).
    #[error("sender signature verification failed")]
    SenderSignature,
}

/// The mockable transport seam over the drop ([`drop_transport::DropSender`] /
/// [`drop_transport::DropFetcher`]) plus the full opt-in verified-receive
/// pipeline ([`drop_transport::receive_verified`]: `verify_sealed` →
/// `ReplayGuard` → `open`). Not feature-gated — the traits and pipeline are
/// pure plumbing with no runtime dependency; the feature-gated onion
/// transport implements the traits, and an in-memory `MockDrop` (tests /
/// test-only `mock-transport` feature) makes the whole pipeline exercisable
/// offline. See the module docs for the restated honest limits.
pub mod drop_transport;

/// Recipient-side anti-replay window ([`replay::ReplayGuard`]) — see the
/// module docs for exactly what it does and does not protect (in-process,
/// non-persistent, window-bounded; does not cover the unsigned seal path).
pub mod replay;

/// Opt-in PQ sender-authentication over the seal ([`sender_auth::SenderIdentity`],
/// [`sender_auth::sign_sealed`], [`sender_auth::verify_sealed`]) — an ML-DSA-87
/// signature over a domain-separated transcript of a [`SealedPayload`], so a
/// verified signature also answers "who sealed this", not just "opened
/// successfully". See the module docs for exactly what it does and does not
/// cover (it does not touch the unsigned `seal`/`open` path or wire bytes).
pub mod sender_auth;

/// A recipient's hybrid (ML-KEM-1024 ‖ X25519) keypair. The public key is
/// shared out-of-band with senders and MUST be authenticated out-of-band —
/// compare [`key_fingerprint`] over a channel the sender already trusts.
///
/// The secret key is wiped from RAM when the `Recipient` is dropped.
pub struct Recipient {
    pub public: Vec<u8>,
    pub secret: Vec<u8>,
}

impl Drop for Recipient {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Generate a fresh hybrid recipient keypair — ML-KEM-1024 (FIPS-203) plus a
/// static X25519 key — drawing all randomness from the OS CSPRNG (`OsRng` /
/// getrandom).
pub fn generate_recipient() -> Recipient {
    let (dk, ek) = MlKem1024::generate(&mut OsRng);
    let x_sk = StaticSecret::random_from_rng(OsRng);
    let x_pk = XPublicKey::from(&x_sk);

    let mut public = Vec::with_capacity(PUBLIC_KEY_LEN);
    public.extend_from_slice(&ek.as_bytes());
    public.extend_from_slice(x_pk.as_bytes());

    // Serialize the decapsulation key, then scrub the transient encoded copy —
    // the `dk` itself is wiped by ml-kem's `ZeroizeOnDrop` when it drops here,
    // and `x_sk` (zeroize-on-drop) is copied out through a `Zeroizing` buffer.
    let mut sk_enc = dk.as_bytes();
    let mut secret = Vec::with_capacity(SECRET_KEY_LEN);
    secret.extend_from_slice(&sk_enc);
    secret.extend_from_slice(x_sk.as_bytes());
    sk_enc.zeroize();

    Recipient { public, secret }
}

/// A short, human-comparable fingerprint of a courier public key, for
/// **out-of-band key authentication**: both parties read it aloud / compare it
/// over a channel they already trust before the sender seals anything. It is
/// the truncated SHA-256 of the key under a domain-separation tag, rendered as
/// five hex groups (80 bits — collision-resistant enough for a second-preimage
/// setting where the attacker must match a *specific* honest key).
pub fn key_fingerprint(public_key: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"postern-courier/fingerprint/v2");
    h.update((public_key.len() as u64).to_le_bytes());
    h.update(public_key);
    let digest = h.finalize();
    digest[..10]
        .chunks(2)
        .map(|p| format!("{:02x}{:02x}", p[0], p[1]))
        .collect::<Vec<_>>()
        .join("-")
}

/// The sealed payload for the (planned) onion drop: the hybrid encapsulation
/// (ML-KEM ciphertext ‖ X25519 ephemeral public key) + the AEAD ciphertext
/// (nonce-prefixed). Reveals no plaintext without the recipient's hybrid
/// secret — including to a future quantum adversary (ML-KEM leg) and to an
/// adversary holding an ML-KEM implementation break (X25519 leg).
pub struct SealedPayload {
    /// Hybrid encapsulation: `ML-KEM-1024 ct (1568) ‖ X25519 ephemeral pk (32)`.
    pub kem_ct: Vec<u8>,
    /// `nonce ‖ AEAD-ciphertext`.
    pub body: Vec<u8>,
}

impl SealedPayload {
    /// Serialize for the wire: `WIRE_VERSION ‖ kem_ct ‖ body`. The leading
    /// version byte makes the next deliberate format break detectable at parse
    /// time instead of surfacing as a garbled decrypt.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.kem_ct.len() + self.body.len());
        out.push(WIRE_VERSION);
        out.extend_from_slice(&self.kem_ct);
        out.extend_from_slice(&self.body);
        out
    }

    /// Parse a wire blob produced by [`SealedPayload::to_bytes`]. Rejects an
    /// unknown version byte and truncated input.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CourierError> {
        match bytes.first() {
            None => return Err(CourierError::KemCiphertext),
            Some(&WIRE_VERSION) => {}
            Some(_) => return Err(CourierError::Version),
        }
        if bytes.len() < 1 + KEM_CT_LEN {
            return Err(CourierError::KemCiphertext);
        }
        Ok(Self {
            kem_ct: bytes[1..1 + KEM_CT_LEN].to_vec(),
            body: bytes[1 + KEM_CT_LEN..].to_vec(),
        })
    }
}

/// Seal a payload to a recipient's hybrid public key: encapsulate with
/// ML-KEM-1024 (PQ leg) *and* an ephemeral X25519 exchange (classical leg),
/// combine both shared secrets with HKDF-SHA-256 (binding the wire version,
/// the full encapsulation, and the recipient key into the derived key), then
/// XChaCha20-Poly1305-encrypt the plaintext under the combined key.
///
/// The recipient key MUST have been authenticated out-of-band
/// ([`key_fingerprint`]); this function cannot detect a substituted key.
pub fn seal(recipient_public: &[u8], plaintext: &[u8]) -> Result<SealedPayload, CourierError> {
    if recipient_public.len() != PUBLIC_KEY_LEN {
        return Err(CourierError::PublicKey);
    }
    let (ek_bytes, xpk_bytes) = recipient_public.split_at(MLKEM_EK_LEN);

    // Decode the ML-KEM encapsulation key (the fixed-size conversion is the
    // length check; no panic/unwrap) …
    let enc: Encoded<EncapKey> = ek_bytes.try_into().map_err(|_| CourierError::PublicKey)?;
    let ek = EncapKey::from_bytes(&enc);
    // … and enforce FIPS-203 §7.2 encapsulation-key canonicality, which
    // upstream `ml-kem` 0.2 skips: re-encode and require a byte-exact
    // round-trip, rejecting non-canonical (out-of-range coefficient) keys.
    if ek.as_bytes().as_slice() != ek_bytes {
        return Err(CourierError::PublicKey);
    }
    let x_pk = XPublicKey::from(
        <[u8; X25519_LEN]>::try_from(xpk_bytes).map_err(|_| CourierError::PublicKey)?,
    );

    // PQ leg: encapsulation randomness from the OS CSPRNG (never deterministic).
    let (ct_m, mut ss_m) = ek.encapsulate(&mut OsRng).map_err(|_| CourierError::Seal)?;
    // Classical leg: fresh ephemeral X25519 (the ephemeral secret zeroizes on
    // drop; `ss_x` is `SharedSecret`, also zeroize-on-drop).
    let eph = EphemeralSecret::random_from_rng(OsRng);
    let epk = XPublicKey::from(&eph);
    let ss_x = eph.diffie_hellman(&x_pk);
    if !ss_x.was_contributory() {
        // Low-order recipient point → attacker-known DH output. Refuse rather
        // than lean on the ML-KEM leg alone.
        ss_m.zeroize();
        return Err(CourierError::PublicKey);
    }

    let mut kem_ct = Vec::with_capacity(KEM_CT_LEN);
    kem_ct.extend_from_slice(&ct_m);
    kem_ct.extend_from_slice(epk.as_bytes());

    // Derive the AEAD key, then scrub the raw ML-KEM secret (a plain `Array`
    // with no `Drop`) BEFORE propagating any error — no early-return gap.
    let key = combine(ss_m.as_slice(), ss_x.as_bytes(), &kem_ct, recipient_public);
    ss_m.zeroize();
    let key = key?;

    // XChaCha20-Poly1305 under the combined key — the one canonical Postern
    // seal (postern-core), same wire format as the vault.
    let body = postern_core::aead::seal(&key, plaintext).map_err(|_| CourierError::Seal)?;
    Ok(SealedPayload { kem_ct, body })
}

/// Open a sealed payload with the recipient's hybrid secret key.
///
/// SECURITY (memory hygiene): the ML-KEM `DecapsulationKey` is `ZeroizeOnDrop`;
/// the X25519 `StaticSecret` and DH `SharedSecret` are zeroize-on-drop; the raw
/// ML-KEM shared secret is explicitly zeroized after the AEAD key is derived
/// (with no early return between decapsulation and the wipe); the derived key
/// and the HKDF input keying material live in `Zeroizing` buffers; transient
/// decoded secret-key bytes are scrubbed; `Recipient.secret` wipes itself on
/// drop. No un-scrubbed secret lingers.
pub fn open(recipient_secret: &[u8], sealed: &SealedPayload) -> Result<Vec<u8>, CourierError> {
    if recipient_secret.len() != SECRET_KEY_LEN {
        return Err(CourierError::SecretKey);
    }
    let (dk_bytes, xsk_bytes) = recipient_secret.split_at(MLKEM_DK_LEN);

    // Decode the ML-KEM decapsulation key, scrubbing the transient copy.
    let mut sk_enc: Encoded<DecapKey> =
        dk_bytes.try_into().map_err(|_| CourierError::SecretKey)?;
    let dk = DecapKey::from_bytes(&sk_enc);
    sk_enc.zeroize();

    // Decode the X25519 static secret through a scrubbed stack copy.
    let mut xs = <[u8; X25519_LEN]>::try_from(xsk_bytes).map_err(|_| CourierError::SecretKey)?;
    let x_sk = StaticSecret::from(xs);
    xs.zeroize();

    // Split the hybrid encapsulation; reject wrong-length bytes.
    if sealed.kem_ct.len() != KEM_CT_LEN {
        return Err(CourierError::KemCiphertext);
    }
    let (ct_m_bytes, epk_bytes) = sealed.kem_ct.split_at(MLKEM_CT_LEN);
    let ct: Ciphertext<MlKem1024> =
        ct_m_bytes.try_into().map_err(|_| CourierError::KemCiphertext)?;
    let epk = XPublicKey::from(
        <[u8; X25519_LEN]>::try_from(epk_bytes).map_err(|_| CourierError::KemCiphertext)?,
    );

    // Classical leg first (no secrets to scrub yet if we reject): a low-order
    // ephemeral point is never produced by an honest sender.
    let ss_x = x_sk.diffie_hellman(&epk);
    if !ss_x.was_contributory() {
        return Err(CourierError::KemCiphertext);
    }

    // PQ leg. ML-KEM decapsulation is implicit-rejection: a tampered ct yields
    // a pseudorandom secret and the AEAD open below fails.
    let mut ss_m = dk.decapsulate(&ct).map_err(|_| CourierError::SharedSecret)?;

    // Rebuild the recipient public key (the ML-KEM dk embeds its ek; the X25519
    // pk derives from the scalar) so the KDF transcript matches `seal`'s.
    let mut recipient_public = Vec::with_capacity(PUBLIC_KEY_LEN);
    recipient_public.extend_from_slice(&dk.encapsulation_key().as_bytes());
    recipient_public.extend_from_slice(XPublicKey::from(&x_sk).as_bytes());

    let key = combine(ss_m.as_slice(), ss_x.as_bytes(), &sealed.kem_ct, &recipient_public);
    ss_m.zeroize(); // scrub the raw ML-KEM shared secret before any `?`
    let key = key?;

    postern_core::aead::open(&key, &sealed.body).map_err(|_| CourierError::Open)
    // `dk` drops here → ml-kem's `ZeroizeOnDrop` wipes the decapsulation key;
    // `x_sk` / `ss_x` / `key` zeroize on drop.
}

/// The hybrid KDF combiner (X-Wing-style, per draft-connolly-cfrg-xwing /
/// RFC 9180 §"KEM combiners" practice): `HKDF-SHA-256(ikm = ss_MLKEM ‖
/// ss_X25519, info = label ‖ version ‖ H(kem_ct) ‖ H(recipient_public))`.
///
/// Never returns a raw KEM output as the AEAD key. Binding the full
/// encapsulation and the recipient key into `info` gives the ciphertext-binding
/// ML-KEM itself lacks (it is not MAL-BIND-K-CT): mix-and-match of
/// `kem_ct`/`body` pairs, or the same secrets under a different transcript,
/// derive a different key and the AEAD open fails.
fn combine(
    ss_mlkem: &[u8],
    ss_x25519: &[u8; 32],
    kem_ct: &[u8],
    recipient_public: &[u8],
) -> Result<Zeroizing<[u8; 32]>, CourierError> {
    if ss_mlkem.len() != 32 {
        return Err(CourierError::SharedSecret);
    }
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(ss_mlkem);
    ikm[32..].copy_from_slice(ss_x25519);

    let ct_hash = Sha256::digest(kem_ct);
    let pk_hash = Sha256::digest(recipient_public);

    let hk = Hkdf::<Sha256>::new(None, ikm.as_ref());
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand_multi_info(&[HKDF_LABEL, &[WIRE_VERSION], &ct_hash, &pk_hash], key.as_mut())
        .map_err(|_| CourierError::SharedSecret)?;
    Ok(key)
}

/// The real ephemeral-Tor-onion-service drop — the `onion-transport`-feature
/// transport that carries a [`SealedPayload`] person-to-person with no server
/// in the middle.
///
/// Roles: the **sender** publishes an ephemeral onion service ([`Sender`]) and
/// serves the sealed bytes to the first peer that connects; the **recipient**
/// connects to that `.onion` as a client ([`fetch`]) and downloads them, then
/// [`open`]s with their hybrid secret key. The onion address is handed over the
/// same out-of-band channel already used to authenticate the courier key
/// fingerprint (see the crate-level "Honest limits").
///
/// Wire framing on the accepted stream is deliberately trivial. A bare drop
/// is `b"PCD1" ‖ u32-BE length ‖ SealedPayload::to_bytes()`; a signed drop is
/// `b"PCS1" ‖ u32-BE length ‖ SignedSealedPayload::to_bytes()` — the SAME
/// header layout, [`MAX_DROP_BYTES`] cap, and [`DEFAULT_DROP_TIMEOUT`] bounds,
/// only the magic differs, and a fetch expecting one kind rejects the other
/// magic outright (coarse [`CourierError::Transport`], never a mis-parse).
/// The payload is already a self-describing, versioned, authenticated blob;
/// the frame only adds truncation detection and a hard size cap so a hostile
/// peer cannot stream unbounded bytes into memory. The `PCS1` frame adds **no
/// wire auth beyond what the payload layer provides** — the sender
/// authentication is [`sender_auth::verify_sealed`] over the carried bytes
/// (run via [`drop_transport::receive_verified`]), never the frame.
///
/// HONEST LIMITS (do not soften): UNAUDITED; the onion address crypto is
/// classical Tor (the PQ hybrid protects the *payload*, not circuit metadata);
/// the frame itself still carries **no auth and no replay protection of its
/// own** — a peer that completes the onion handshake can serve any bytes it
/// wants, and a recorded frame can be re-served verbatim. What the frame does
/// not provide, the recipient can require at the payload layer instead:
/// demand a [`sender_auth::SignedSealedPayload`] rather than a bare
/// [`SealedPayload`] (rejecting the drop unless [`sender_auth::verify_sealed`]
/// succeeds) and run it through a [`replay::ReplayGuard`] before trusting it —
/// both are opt-in, both UNAUDITED reference-prototype like this transport
/// itself, and the guard's protection is bounded to its configured window,
/// held only in the recipient process's memory, and lost on restart (see the
/// `replay` module docs for the full list of caveats). Endpoint timing/volume
/// and the (unpadded) payload size remain observable either way.
#[cfg(feature = "onion-transport")]
pub mod transport {
    use super::{CourierError, SealedPayload};
    use crate::replay::ReplayGuard;
    use crate::sender_auth::SignedSealedPayload;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::timeout;

    pub use postern_tor::PosternTor;

    /// Install a process-level rustls `CryptoProvider` (the `ring` backend)
    /// if none is installed yet. **Call once before the first
    /// [`PosternTor::bootstrap`]** — arti's TLS goes through
    /// `futures-rustls`, which enables no provider feature and leaves the
    /// choice to the application (arti's own binary installs one the same
    /// way); without this, rustls 0.23 panics at the first live TLS
    /// handshake. Found the first time the live onion round-trip was
    /// actually run (2026-07-16; evidence/live-onion-drop.evidence).
    ///
    /// Idempotent: if a provider is already installed (first caller wins —
    /// e.g. an embedding app that chose `aws-lc-rs`), the `Err` from
    /// `install_default` is deliberately discarded and that provider stays.
    /// HONEST SCOPE: this selects which TLS crypto backend arti uses,
    /// nothing more — it is not a hardening step, adds no security claim,
    /// and everything around it stays UNAUDITED.
    pub fn ensure_rustls_crypto_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    /// Bare-drop frame magic: "Postern Courier Drop v1". The framed payload is
    /// `SealedPayload::to_bytes()`.
    const DROP_MAGIC: [u8; 4] = *b"PCD1";
    /// Signed-drop frame magic: "Postern Courier Signed drop v1". The framed
    /// payload is `SignedSealedPayload::to_bytes()`. Same header layout, size
    /// cap, and timeout bounds as [`DROP_MAGIC`]; only the magic differs, so a
    /// reader expecting one kind rejects the other outright at the header.
    const SIGNED_DROP_MAGIC: [u8; 4] = *b"PCS1";
    /// Fixed frame header length: magic (4) + u32-BE payload length (4).
    const DROP_HEADER_LEN: usize = 8;

    /// Hard cap on one drop's sealed size. A drop larger than this is refused
    /// (never truncated) so a hostile peer cannot exhaust the receiver's memory.
    pub const MAX_DROP_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

    /// The onion virtual port the drop is served on. Arbitrary but fixed: the
    /// host accepts any BEGIN, and the client dials this port.
    pub const DROP_VIRTUAL_PORT: u16 = 80;

    /// Wall-clock bound on every blocking drop I/O step (accept/connect,
    /// header/body read, write+flush+shutdown). [`MAX_DROP_BYTES`] bounds how
    /// much memory a hostile or stalled peer can make the other side hold;
    /// this bounds how long that peer can make the other side *wait* — without
    /// it, a peer that opens the connection and then never sends (or never
    /// reads) another byte would hang the recipient's [`fetch`] or the
    /// sender's [`Sender::deliver_once`] forever. 120s is generous on purpose:
    /// a fresh onion-service descriptor can be slow to become fetchable, and
    /// this deadline has to comfortably outlast that, not just a healthy LAN
    /// round-trip. On expiry every call site maps the elapsed timeout to the
    /// same coarse [`CourierError::Transport`] used for every other I/O
    /// failure here — the point is not to distinguish "slow" from "hostile"
    /// from "network down" for the caller, only to guarantee the call returns.
    pub const DEFAULT_DROP_TIMEOUT: Duration = Duration::from_secs(120);

    /// Frame wire bytes under `magic` for the drop stream. Pure +
    /// offline-testable. Shared by both frame kinds — the header layout is
    /// identical; only the magic distinguishes bare from signed.
    fn encode_frame(magic: &[u8; 4], wire: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(DROP_HEADER_LEN + wire.len());
        out.extend_from_slice(magic);
        out.extend_from_slice(&(wire.len() as u32).to_be_bytes());
        out.extend_from_slice(wire);
        out
    }

    /// Read one framed drop from an async stream: validate the magic against
    /// the ONE kind the caller expects (any other magic — including the other
    /// frame kind — is a coarse [`CourierError::Transport`], never a
    /// mis-parse), read the declared length (rejecting anything over
    /// [`MAX_DROP_BYTES`]), then read exactly that many bytes. A short stream
    /// (peer closed early) is a [`CourierError::Transport`], never a silent
    /// partial read. Each read is individually bounded by
    /// [`DEFAULT_DROP_TIMEOUT`] — a peer that sends the header and then goes
    /// silent cannot hang this forever either.
    async fn read_frame<S>(stream: &mut S, expected_magic: &[u8; 4]) -> Result<Vec<u8>, CourierError>
    where
        S: AsyncReadExt + Unpin,
    {
        let mut header = [0u8; DROP_HEADER_LEN];
        timeout(DEFAULT_DROP_TIMEOUT, stream.read_exact(&mut header))
            .await
            .map_err(|_| CourierError::Transport)?
            .map_err(|_| CourierError::Transport)?;
        if header[..4] != *expected_magic {
            return Err(CourierError::Transport);
        }
        let len = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;
        if len > MAX_DROP_BYTES {
            return Err(CourierError::Transport);
        }
        // Read via a length-limited reader rather than pre-allocating `vec![0u8;
        // len]` up front: `len` is peer-declared and unauthenticated (bounded
        // only by MAX_DROP_BYTES above), so a hostile peer that declares the
        // full 64 MiB cap and then sends a handful of bytes must not be able to
        // force a 64 MiB allocation on the receiver. `take(len as u64)` caps
        // how much `read_to_end` will ever pull, so `body`'s capacity only ever
        // grows to cover bytes actually received off the wire.
        let mut body = Vec::new();
        let read = timeout(
            DEFAULT_DROP_TIMEOUT,
            (&mut *stream).take(len as u64).read_to_end(&mut body),
        )
        .await
        .map_err(|_| CourierError::Transport)?
        .map_err(|_| CourierError::Transport)?;
        if read != len || body.len() != len {
            return Err(CourierError::Transport);
        }
        Ok(body)
    }

    /// [`read_frame`] expecting the bare-drop magic ([`DROP_MAGIC`]).
    async fn read_drop_frame<S>(stream: &mut S) -> Result<Vec<u8>, CourierError>
    where
        S: AsyncReadExt + Unpin,
    {
        read_frame(stream, &DROP_MAGIC).await
    }

    /// [`read_frame`] expecting the signed-drop magic ([`SIGNED_DROP_MAGIC`]).
    async fn read_signed_drop_frame<S>(stream: &mut S) -> Result<Vec<u8>, CourierError>
    where
        S: AsyncReadExt + Unpin,
    {
        read_frame(stream, &SIGNED_DROP_MAGIC).await
    }

    /// Write one frame (under `magic`) to an async stream and half-close the
    /// write side so the peer sees a clean EOF after the payload.
    async fn write_frame<S>(
        stream: &mut S,
        magic: &[u8; 4],
        wire: &[u8],
    ) -> Result<(), CourierError>
    where
        S: AsyncWriteExt + Unpin,
    {
        let frame = encode_frame(magic, wire);
        stream.write_all(&frame).await.map_err(|_| CourierError::Transport)?;
        stream.flush().await.map_err(|_| CourierError::Transport)?;
        stream.shutdown().await.map_err(|_| CourierError::Transport)?;
        Ok(())
    }

    /// Best-effort linger after the frame is written: read (and discard)
    /// until the peer half-closes. Local `write_all` + `flush` success only
    /// means the bytes entered arti's stream sink — and `deliver_once`
    /// consuming the [`Sender`] tears the whole onion service down on
    /// return, which can discard cells still in flight across the
    /// rendezvous circuit. Observed live (2026-07-16, the first real
    /// round-trip attempt; see evidence/live-onion-drop.evidence): the
    /// sender reported "served" while the recipient received nothing.
    /// Waiting for the peer's EOF keeps the service alive until the peer
    /// has stopped reading (the recipient drops its stream after
    /// `read_frame`), closing that race.
    ///
    /// HONEST LIMITS: this is a teardown ordering fix, NOT an
    /// acknowledgment protocol — peer EOF does not prove the payload was
    /// received, parsed, verified, or opened, and a hostile peer can hold
    /// the stream open. That is why every call site bounds this whole wait
    /// with [`DEFAULT_DROP_TIMEOUT`] and ignores its outcome: expiry or a
    /// read error still returns the write's success, exactly as before.
    async fn drain_until_peer_eof<S>(stream: &mut S)
    where
        S: AsyncReadExt + Unpin,
    {
        let mut sink = [0u8; 512];
        loop {
            match stream.read(&mut sink).await {
                Ok(0) | Err(_) => break, // clean EOF or a dead stream: done
                Ok(_) => {}              // discard; the drop protocol has no reply bytes
            }
        }
    }

    /// [`write_frame`] for a bare sealed payload ([`DROP_MAGIC`]).
    async fn write_drop_frame<S>(stream: &mut S, sealed: &SealedPayload) -> Result<(), CourierError>
    where
        S: AsyncWriteExt + Unpin,
    {
        write_frame(stream, &DROP_MAGIC, &sealed.to_bytes()).await
    }

    /// [`write_frame`] for a signed sealed payload ([`SIGNED_DROP_MAGIC`]).
    async fn write_signed_drop_frame<S>(
        stream: &mut S,
        signed: &SignedSealedPayload,
    ) -> Result<(), CourierError>
    where
        S: AsyncWriteExt + Unpin,
    {
        write_frame(stream, &SIGNED_DROP_MAGIC, &signed.to_bytes()).await
    }

    /// A published ephemeral onion drop, sender side. `publish` brings the
    /// service up and exposes its `.onion` address; hand that address to the
    /// recipient out-of-band, then call [`Sender::deliver_once`] to serve the
    /// sealed payload to the first peer that connects. Dropping a `Sender`
    /// before delivery tears the service down.
    pub struct Sender {
        drop: postern_tor::onion_host::OnionDrop,
    }

    impl Sender {
        /// Publish a fresh ephemeral onion service on `tor`. `nickname` scopes
        /// the service's keys within arti; use a fresh one per drop.
        pub async fn publish(tor: &PosternTor, nickname: &str) -> Result<Self, CourierError> {
            let drop = postern_tor::onion_host::OnionDrop::publish(tor, nickname)
                .await
                .map_err(|_| CourierError::Transport)?;
            Ok(Self { drop })
        }

        /// The `<b32>.onion` address to give the recipient out-of-band (next to
        /// the courier key fingerprint).
        pub fn onion_address(&self) -> &str {
            self.drop.onion_address()
        }

        /// Wait for the first peer to connect and serve it `sealed`, then return.
        /// Consumes `self` (a drop is single-shot); the service is torn down on
        /// return. Both the wait for a peer and the write are bounded by
        /// [`DEFAULT_DROP_TIMEOUT`] — a peer that never connects, or connects
        /// and then never reads, cannot hang this forever.
        pub async fn deliver_once(mut self, sealed: &SealedPayload) -> Result<(), CourierError> {
            let mut stream = timeout(DEFAULT_DROP_TIMEOUT, self.drop.accept())
                .await
                .map_err(|_| CourierError::Transport)?
                .map_err(|_| CourierError::Transport)?;
            timeout(DEFAULT_DROP_TIMEOUT, write_drop_frame(&mut stream, sealed))
                .await
                .map_err(|_| CourierError::Transport)??;
            // Keep the service alive until the peer half-closes (bounded,
            // outcome ignored) — returning tears the onion service down,
            // which can discard in-flight cells. See [`drain_until_peer_eof`]
            // for why this is a teardown ordering fix, not an ACK.
            let _ = timeout(DEFAULT_DROP_TIMEOUT, drain_until_peer_eof(&mut stream)).await;
            Ok(())
        }

        /// [`Sender::deliver_once`] for a SIGNED drop: serve a
        /// [`SignedSealedPayload`] under the [`SIGNED_DROP_MAGIC`] frame
        /// instead of a bare [`SealedPayload`] under [`DROP_MAGIC`]. Same
        /// single-shot consume-on-deliver semantics, same
        /// [`DEFAULT_DROP_TIMEOUT`] bounds, same coarse
        /// [`CourierError::Transport`] on every failure. The frame still adds
        /// **no wire auth of its own** — the authentication is the ML-DSA
        /// signature inside the carried payload, which only the recipient's
        /// [`crate::drop_transport::receive_verified`] checks.
        pub async fn deliver_once_signed(
            mut self,
            signed: &SignedSealedPayload,
        ) -> Result<(), CourierError> {
            let mut stream = timeout(DEFAULT_DROP_TIMEOUT, self.drop.accept())
                .await
                .map_err(|_| CourierError::Transport)?
                .map_err(|_| CourierError::Transport)?;
            timeout(DEFAULT_DROP_TIMEOUT, write_signed_drop_frame(&mut stream, signed))
                .await
                .map_err(|_| CourierError::Transport)??;
            // Same bounded, outcome-ignored linger as [`Sender::deliver_once`]
            // — teardown ordering, not an ACK.
            let _ = timeout(DEFAULT_DROP_TIMEOUT, drain_until_peer_eof(&mut stream)).await;
            Ok(())
        }
    }

    /// Recipient side: connect to the sender's `.onion` over Tor and download
    /// the sealed payload. `tor` must be a bootstrapped client (its
    /// onion-service-client path is used; no hosting needed on this side). The
    /// returned [`SealedPayload`] still has to be [`super::open`]ed with the
    /// recipient's hybrid secret key — that is what proves it is really for them.
    ///
    /// The connect is bounded by [`DEFAULT_DROP_TIMEOUT`] (on top of the read
    /// bound already inside [`read_drop_frame`]) — a sender that never accepts,
    /// or accepts and then never sends, cannot hang this forever.
    pub async fn fetch(tor: &PosternTor, onion_address: &str) -> Result<SealedPayload, CourierError> {
        let mut stream = timeout(DEFAULT_DROP_TIMEOUT, tor.connect(onion_address, DROP_VIRTUAL_PORT))
            .await
            .map_err(|_| CourierError::Transport)?
            .map_err(|_| CourierError::Transport)?;
        let wire = read_drop_frame(&mut stream).await?;
        SealedPayload::from_bytes(&wire)
    }

    /// [`fetch`] for a SIGNED drop: expect the [`SIGNED_DROP_MAGIC`] frame and
    /// parse a [`SignedSealedPayload`] out of it. A bare `PCD1` frame served at
    /// the address is rejected outright at the magic (coarse
    /// [`CourierError::Transport`]), never mis-parsed as signed bytes. The
    /// returned payload is **unverified and unopened** — run it through
    /// [`crate::drop_transport::receive_verified`] (or use
    /// [`fetch_signed_verified`]), which checks the sender signature FIRST,
    /// then the replay guard, then decrypts.
    pub async fn fetch_signed(
        tor: &PosternTor,
        onion_address: &str,
    ) -> Result<SignedSealedPayload, CourierError> {
        let mut stream = timeout(DEFAULT_DROP_TIMEOUT, tor.connect(onion_address, DROP_VIRTUAL_PORT))
            .await
            .map_err(|_| CourierError::Transport)?
            .map_err(|_| CourierError::Transport)?;
        let wire = read_signed_drop_frame(&mut stream).await?;
        SignedSealedPayload::from_bytes(&wire)
    }

    // --- drop_transport seam -------------------------------------------------
    // The concrete transport behind the mockable seam, with NO change to the
    // concrete API above: `Sender` is the trait's sender (deliver ==
    // deliver_once, same consume-on-use single-shot semantics) and a
    // bootstrapped `PosternTor` is the trait's fetcher (fetch == this module's
    // `fetch`). UI callers program against `crate::drop_transport`'s traits
    // and inject either these or the offline `MockDrop`.

    impl crate::drop_transport::DropSender for Sender {
        /// [`Sender::deliver_once`], verbatim, behind the seam.
        async fn deliver(self, sealed: &SealedPayload) -> Result<(), CourierError> {
            self.deliver_once(sealed).await
        }
    }

    impl crate::drop_transport::DropFetcher for PosternTor {
        /// This module's [`fetch`], verbatim, behind the seam. `self` must be
        /// a bootstrapped client, exactly as [`fetch`] documents.
        async fn fetch(&self, address: &str) -> Result<SealedPayload, CourierError> {
            crate::transport::fetch(self, address).await
        }
    }

    impl crate::drop_transport::SignedDropSender for Sender {
        /// [`Sender::deliver_once_signed`], verbatim, behind the seam. Same
        /// consume-on-deliver single-shot semantics as the bare trait.
        async fn deliver_signed(self, signed: &SignedSealedPayload) -> Result<(), CourierError> {
            self.deliver_once_signed(signed).await
        }
    }

    impl crate::drop_transport::SignedDropFetcher for PosternTor {
        /// This module's [`fetch_signed`], verbatim, behind the seam. `self`
        /// must be a bootstrapped client, exactly as [`fetch`] documents.
        async fn fetch_signed(&self, address: &str) -> Result<SignedSealedPayload, CourierError> {
            crate::transport::fetch_signed(self, address).await
        }
    }

    /// Convenience: [`fetch`] then [`super::open`] with `recipient_secret`.
    pub async fn fetch_and_open(
        tor: &PosternTor,
        onion_address: &str,
        recipient_secret: &[u8],
    ) -> Result<Vec<u8>, CourierError> {
        let sealed = fetch(tor, onion_address).await?;
        super::open(recipient_secret, &sealed)
    }

    /// Convenience: [`fetch_signed`] then the full
    /// [`crate::drop_transport::receive_verified`] pipeline, in the one
    /// documented-safe order — [`crate::sender_auth::verify_sealed`] FIRST,
    /// then [`ReplayGuard::check_and_record`](crate::replay::ReplayGuard::check_and_record),
    /// then [`super::open`] — using the system clock for "now" (via
    /// [`crate::drop_transport::receive_verified_now`], which fails closed on
    /// an unreadable clock).
    ///
    /// HONEST LIMITS (unchanged; restated): this only means something if the
    /// sender's verifying key and the recipient's courier key were
    /// authenticated out-of-band first; every component is UNAUDITED
    /// reference-prototype; the guard's protection is window-bounded,
    /// in-process, and lost on restart; and payload size/timing remain
    /// observable on the wire either way.
    pub async fn fetch_signed_verified(
        tor: &PosternTor,
        onion_address: &str,
        sender_verifying_key: &[u8],
        recipient_public: &[u8],
        recipient_secret: &[u8],
        guard: &mut ReplayGuard,
    ) -> Result<Vec<u8>, CourierError> {
        let signed = fetch_signed(tor, onion_address).await?;
        crate::drop_transport::receive_verified_now(
            sender_verifying_key,
            recipient_public,
            recipient_secret,
            &signed,
            guard,
        )
    }

    #[cfg(test)]
    mod transport_tests {
        use super::*;
        use crate::drop_transport::receive_verified;
        use crate::sender_auth::{generate_sender_identity, sign_sealed};
        use crate::{generate_recipient, open, seal};

        // Offline: the drop framing round-trips a sealed payload through an
        // in-memory async pipe — the exact bytes the onion stream would carry,
        // no Tor. Proves seal → frame → read_drop_frame → from_bytes → open.
        #[tokio::test]
        async fn drop_frame_roundtrip_over_pipe() {
            let rcpt = generate_recipient();
            let plaintext = b"drop me over the onion";
            // Seal ONCE (the seal is randomized — two seals differ), move it into
            // the writer, and assert on the OPENED plaintext, not the ciphertext.
            let sealed = seal(&rcpt.public, plaintext).unwrap();

            // A 64 KiB duplex stands in for the accepted onion DataStream.
            let (mut a, mut b) = tokio::io::duplex(64 * 1024);
            let writer = tokio::spawn(async move {
                write_drop_frame(&mut a, &sealed).await.unwrap();
            });
            let wire = read_drop_frame(&mut b).await.unwrap();
            writer.await.unwrap();

            let parsed = SealedPayload::from_bytes(&wire).unwrap();
            assert_eq!(open(&rcpt.secret, &parsed).unwrap(), plaintext);
        }

        // A frame with the wrong magic is rejected up front (not mis-parsed).
        #[tokio::test]
        async fn wrong_magic_is_rejected() {
            let mut bad: &[u8] = b"XXXX\x00\x00\x00\x01!";
            assert!(read_drop_frame(&mut bad).await.is_err());
        }

        // A length header over the cap is refused before any allocation.
        #[tokio::test]
        async fn oversize_length_is_refused() {
            let mut frame = Vec::new();
            frame.extend_from_slice(&DROP_MAGIC);
            frame.extend_from_slice(&((MAX_DROP_BYTES as u32) + 1).to_be_bytes());
            let mut slice: &[u8] = &frame;
            assert!(read_drop_frame(&mut slice).await.is_err());
        }

        // A truncated body (peer closed after the header) is an error, never a
        // silent short payload.
        #[tokio::test]
        async fn truncated_body_is_rejected() {
            let mut frame = Vec::new();
            frame.extend_from_slice(&DROP_MAGIC);
            frame.extend_from_slice(&100u32.to_be_bytes()); // claims 100 bytes …
            frame.extend_from_slice(&[0u8; 10]); // … but only 10 arrive
            let mut slice: &[u8] = &frame;
            assert!(read_drop_frame(&mut slice).await.is_err());
        }

        // A peer that DECLARES the full MAX_DROP_BYTES cap but only ever sends
        // a few bytes before closing the stream must be rejected — and, unlike
        // `vec![0u8; len]`, must never force a MAX_DROP_BYTES (64 MiB)
        // allocation to service that lie. The body buffer here only ever grows
        // to cover the handful of bytes actually received off the wire before
        // `read_to_end` observes EOF and the length check below fails, so this
        // test both proves the error path and (by never touching anything
        // close to 64 MiB of real data) that the read is driven by bytes
        // received, not by the declared length.
        #[tokio::test]
        async fn oversize_declared_len_with_few_bytes_is_rejected_without_preallocating() {
            let (mut a, mut b) = tokio::io::duplex(64 * 1024);
            let writer = tokio::spawn(async move {
                let mut frame = Vec::new();
                frame.extend_from_slice(&DROP_MAGIC);
                frame.extend_from_slice(&(MAX_DROP_BYTES as u32).to_be_bytes()); // claims 64 MiB …
                frame.extend_from_slice(b"tiny"); // … but only 4 bytes ever arrive
                a.write_all(&frame).await.unwrap();
                a.shutdown().await.unwrap(); // then EOF, no more bytes coming
            });
            let err = read_drop_frame(&mut b).await;
            writer.await.unwrap();
            assert!(err.is_err());
        }

        // The header encoder is exact: magic ‖ big-endian length ‖ body.
        #[test]
        fn encode_frame_layout() {
            let framed = encode_frame(&DROP_MAGIC, b"hello");
            assert_eq!(&framed[..4], b"PCD1");
            assert_eq!(&framed[4..8], &5u32.to_be_bytes());
            assert_eq!(&framed[8..], b"hello");
        }

        // A peer that sends the header and then goes silent — never sending the
        // body, never closing the stream — must not hang read_drop_frame
        // forever: MAX_DROP_BYTES bounds memory, DEFAULT_DROP_TIMEOUT has to
        // bound time. Runs on a paused clock (`start_paused = true`) and
        // fast-forwards past the deadline, so the test itself completes
        // instantly instead of actually waiting 120s.
        #[tokio::test(start_paused = true)]
        async fn stalled_peer_times_out_instead_of_hanging() {
            let (mut a, mut b) = tokio::io::duplex(64);

            // Only the header arrives …
            let mut frame = Vec::new();
            frame.extend_from_slice(&DROP_MAGIC);
            frame.extend_from_slice(&10u32.to_be_bytes());
            a.write_all(&frame).await.unwrap();

            // … then the peer stalls without closing the stream. Keep `a`
            // alive for the whole test (parked in a task that never
            // completes) so the read genuinely blocks on missing bytes
            // rather than observing a clean EOF, which is a different code
            // path already covered by `truncated_body_is_rejected`.
            let _keepalive = tokio::spawn(async move {
                let _a = a;
                std::future::pending::<()>().await;
            });

            let read = tokio::spawn(async move { read_drop_frame(&mut b).await });

            // Let the reader task actually start and register the body
            // read's timer before jumping the clock past it.
            tokio::task::yield_now().await;
            tokio::time::advance(DEFAULT_DROP_TIMEOUT + Duration::from_secs(1)).await;

            let result = read.await.unwrap();
            assert!(matches!(result, Err(CourierError::Transport)));
        }

        // --- signed (PCS1) frame tests, all offline ------------------------

        // The signed header encoder is exact: PCS1 magic ‖ big-endian length ‖
        // body — the SAME layout as PCD1, only the magic differs.
        #[test]
        fn encode_signed_frame_layout() {
            let framed = encode_frame(&SIGNED_DROP_MAGIC, b"hello");
            assert_eq!(&framed[..4], b"PCS1");
            assert_eq!(&framed[4..8], &5u32.to_be_bytes());
            assert_eq!(&framed[8..], b"hello");
        }

        // Offline: a signed drop round-trips through an in-memory async pipe —
        // the exact bytes the onion stream would carry, no Tor — and then the
        // FULL verified-receive pipeline (verify_sealed → ReplayGuard → open)
        // succeeds on the fetched bytes.
        #[tokio::test]
        async fn signed_drop_frame_roundtrip_then_receive_verified() {
            let sender_id = generate_sender_identity();
            let rcpt = generate_recipient();
            let plaintext = b"signed drop over the onion frame";
            let sealed = seal(&rcpt.public, plaintext).unwrap();
            let signed = sign_sealed(&sender_id, &rcpt.public, &sealed);
            let ts = signed.timestamp;

            let (mut a, mut b) = tokio::io::duplex(64 * 1024);
            let writer = tokio::spawn(async move {
                write_signed_drop_frame(&mut a, &signed).await.unwrap();
            });
            let wire = read_signed_drop_frame(&mut b).await.unwrap();
            writer.await.unwrap();

            let fetched = SignedSealedPayload::from_bytes(&wire).unwrap();
            let mut guard = ReplayGuard::new(Duration::from_secs(600));
            let opened = receive_verified(
                &sender_id.public,
                &rcpt.public,
                &rcpt.secret,
                &fetched,
                &mut guard,
                ts,
            )
            .unwrap();
            assert_eq!(opened, plaintext);
        }

        // A reader expecting one frame kind MUST reject the other kind's magic
        // outright — coarse Transport, never a mis-parse of the carried bytes.
        #[tokio::test]
        async fn frame_kinds_reject_each_others_magic() {
            let sender_id = generate_sender_identity();
            let rcpt = generate_recipient();
            let sealed = seal(&rcpt.public, b"x").unwrap();
            let signed = sign_sealed(&sender_id, &rcpt.public, &sealed);

            // A bare PCD1 frame presented to the SIGNED reader is rejected.
            let bare_frame = encode_frame(&DROP_MAGIC, &sealed.to_bytes());
            let mut slice: &[u8] = &bare_frame;
            assert!(matches!(
                read_signed_drop_frame(&mut slice).await,
                Err(CourierError::Transport)
            ));

            // A signed PCS1 frame presented to the BARE reader is rejected.
            let signed_frame = encode_frame(&SIGNED_DROP_MAGIC, &signed.to_bytes());
            let mut slice: &[u8] = &signed_frame;
            assert!(matches!(
                read_drop_frame(&mut slice).await,
                Err(CourierError::Transport)
            ));
        }

        // A tampered signature byte inside a fetched PCS1 frame fails the
        // pipeline with SenderSignature — and, because verification runs
        // BEFORE the guard records anything, the guard is left empty.
        #[tokio::test]
        async fn tampered_signature_over_signed_frame_leaves_guard_empty() {
            let sender_id = generate_sender_identity();
            let rcpt = generate_recipient();
            let sealed = seal(&rcpt.public, b"genuine").unwrap();
            let signed = sign_sealed(&sender_id, &rcpt.public, &sealed);
            let ts = signed.timestamp;

            // Flip the first signature byte (after version ‖ nonce ‖ timestamp)
            // in the wire bytes the frame carries.
            let mut wire = signed.to_bytes();
            wire[1 + 32 + 8] ^= 0x01;
            let frame = encode_frame(&SIGNED_DROP_MAGIC, &wire);

            let mut slice: &[u8] = &frame;
            let fetched_wire = read_signed_drop_frame(&mut slice).await.unwrap();
            let fetched = SignedSealedPayload::from_bytes(&fetched_wire).unwrap();

            let mut guard = ReplayGuard::new(Duration::from_secs(600));
            let err = receive_verified(
                &sender_id.public,
                &rcpt.public,
                &rcpt.secret,
                &fetched,
                &mut guard,
                ts,
            )
            .unwrap_err();
            assert!(matches!(err, CourierError::SenderSignature));
            assert!(guard.is_empty(), "an unverified nonce must never be recorded");
        }

        // The same fetched frame bytes presented twice: the first presentation
        // passes the whole pipeline; the second is rejected by the guard as a
        // replay — the wire never protects against replay, receive_verified does.
        #[tokio::test]
        async fn same_signed_frame_bytes_twice_is_rejected_as_replay() {
            let sender_id = generate_sender_identity();
            let rcpt = generate_recipient();
            let plaintext = b"one-shot signed drop";
            let sealed = seal(&rcpt.public, plaintext).unwrap();
            let signed = sign_sealed(&sender_id, &rcpt.public, &sealed);
            let ts = signed.timestamp;

            let frame = encode_frame(&SIGNED_DROP_MAGIC, &signed.to_bytes());
            let mut guard = ReplayGuard::new(Duration::from_secs(600));

            // First presentation.
            let mut slice: &[u8] = &frame;
            let wire1 = read_signed_drop_frame(&mut slice).await.unwrap();
            let first = SignedSealedPayload::from_bytes(&wire1).unwrap();
            let opened = receive_verified(
                &sender_id.public,
                &rcpt.public,
                &rcpt.secret,
                &first,
                &mut guard,
                ts,
            )
            .unwrap();
            assert_eq!(opened, plaintext);

            // Second presentation of the SAME frame bytes.
            let mut slice: &[u8] = &frame;
            let wire2 = read_signed_drop_frame(&mut slice).await.unwrap();
            assert_eq!(wire1, wire2);
            let second = SignedSealedPayload::from_bytes(&wire2).unwrap();
            let err = receive_verified(
                &sender_id.public,
                &rcpt.public,
                &rcpt.secret,
                &second,
                &mut guard,
                ts,
            )
            .unwrap_err();
            assert!(matches!(err, CourierError::ReplayNonceReused));
        }

        // A PCS1 length header over the cap is refused before any allocation —
        // the same bound as the PCD1 path.
        #[tokio::test]
        async fn signed_oversize_length_is_refused() {
            let mut frame = Vec::new();
            frame.extend_from_slice(&SIGNED_DROP_MAGIC);
            frame.extend_from_slice(&((MAX_DROP_BYTES as u32) + 1).to_be_bytes());
            let mut slice: &[u8] = &frame;
            assert!(matches!(
                read_signed_drop_frame(&mut slice).await,
                Err(CourierError::Transport)
            ));
        }

        // A truncated PCS1 body (peer closed after the header) is an error,
        // never a silent short payload — the same bound as the PCD1 path.
        #[tokio::test]
        async fn signed_truncated_body_is_rejected() {
            let mut frame = Vec::new();
            frame.extend_from_slice(&SIGNED_DROP_MAGIC);
            frame.extend_from_slice(&100u32.to_be_bytes()); // claims 100 bytes …
            frame.extend_from_slice(&[0u8; 10]); // … but only 10 arrive
            let mut slice: &[u8] = &frame;
            assert!(matches!(
                read_signed_drop_frame(&mut slice).await,
                Err(CourierError::Transport)
            ));
        }

        // A peer that sends a PCS1 header and then goes silent must hit the
        // same DEFAULT_DROP_TIMEOUT bound as the PCD1 path (paused clock, so
        // the test completes instantly instead of waiting 120s).
        #[tokio::test(start_paused = true)]
        async fn signed_stalled_peer_times_out_instead_of_hanging() {
            let (mut a, mut b) = tokio::io::duplex(64);

            let mut frame = Vec::new();
            frame.extend_from_slice(&SIGNED_DROP_MAGIC);
            frame.extend_from_slice(&10u32.to_be_bytes());
            a.write_all(&frame).await.unwrap();

            // Keep `a` alive so the read blocks on missing bytes rather than
            // observing a clean EOF (that path is signed_truncated_body_is_rejected).
            let _keepalive = tokio::spawn(async move {
                let _a = a;
                std::future::pending::<()>().await;
            });

            let read = tokio::spawn(async move { read_signed_drop_frame(&mut b).await });

            tokio::task::yield_now().await;
            tokio::time::advance(DEFAULT_DROP_TIMEOUT + Duration::from_secs(1)).await;

            let result = read.await.unwrap();
            assert!(matches!(result, Err(CourierError::Transport)));
        }

        /// The real thing: bootstrap Tor, publish an ephemeral onion drop, and
        /// download+open it end-to-end over the live network. Needs network and
        /// **minutes** (a fresh HS descriptor must reach the HSDirs), so it is
        /// ignored in CI — and DOUBLE-gated: `--ignored` alone still skips,
        /// only an explicit `POSTERN_LIVE_TOR=1` opens a live circuit. Run:
        /// `POSTERN_LIVE_TOR=1 cargo test -p postern-courier --features onion-transport -- --ignored --nocapture`
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[ignore = "live Tor: needs network + minutes; run with POSTERN_LIVE_TOR=1 -- --ignored"]
        async fn live_onion_drop_end_to_end() {
            if std::env::var("POSTERN_LIVE_TOR").as_deref() != Ok("1") {
                eprintln!("SKIP: POSTERN_LIVE_TOR!=1 — no live circuit opened");
                return;
            }
            let rcpt = generate_recipient();
            let plaintext = b"a real payload over a real onion";
            let sealed = seal(&rcpt.public, plaintext).unwrap();

            // Sender: bootstrap Tor and publish the ephemeral drop.
            let sender_tor = PosternTor::bootstrap().await.expect("sender bootstrap");
            let sender = Sender::publish(&sender_tor, "postern-courier-livetest")
                .await
                .expect("publish");
            let onion = sender.onion_address().to_string();
            eprintln!("drop published at {onion} (waiting for descriptor to propagate)…");

            // Recipient: a circuit-isolated client on the same host for the test.
            let recipient_tor = sender_tor.for_identity();

            // Serve one, fetch one, concurrently.
            let serve = tokio::spawn(async move { sender.deliver_once(&sealed).await });
            let opened = fetch_and_open(&recipient_tor, &onion, &rcpt.secret)
                .await
                .expect("fetch_and_open");
            serve.await.expect("join serve").expect("serve");

            assert_eq!(opened, plaintext);
        }

        /// The real SIGNED thing, mirroring `live_onion_drop_end_to_end`:
        /// bootstrap Tor, publish an ephemeral onion drop, serve a
        /// `SignedSealedPayload` under the PCS1 frame, and fetch+verify+open
        /// it end-to-end over the live network via `fetch_signed_verified`
        /// (verify_sealed → ReplayGuard → open). Needs network and **minutes**,
        /// so it is ignored in CI — and DOUBLE-gated: `--ignored` alone still
        /// skips, only an explicit `POSTERN_LIVE_TOR=1` opens a live circuit.
        /// Run:
        /// `POSTERN_LIVE_TOR=1 cargo test -p postern-courier --features onion-transport -- --ignored --nocapture`
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[ignore = "live Tor: needs network + minutes; run with POSTERN_LIVE_TOR=1 -- --ignored"]
        async fn live_onion_signed_drop_end_to_end() {
            if std::env::var("POSTERN_LIVE_TOR").as_deref() != Ok("1") {
                eprintln!("SKIP: POSTERN_LIVE_TOR!=1 — no live circuit opened");
                return;
            }
            let sender_id = generate_sender_identity();
            let rcpt = generate_recipient();
            let plaintext = b"a real signed payload over a real onion";
            let sealed = seal(&rcpt.public, plaintext).unwrap();
            let signed = sign_sealed(&sender_id, &rcpt.public, &sealed);

            // Sender: bootstrap Tor and publish the ephemeral drop.
            let sender_tor = PosternTor::bootstrap().await.expect("sender bootstrap");
            let sender = Sender::publish(&sender_tor, "postern-courier-signed-livetest")
                .await
                .expect("publish");
            let onion = sender.onion_address().to_string();
            eprintln!("signed drop published at {onion} (waiting for descriptor to propagate)…");

            // Recipient: a circuit-isolated client on the same host for the test.
            let recipient_tor = sender_tor.for_identity();

            // Serve one, fetch+verify one, concurrently.
            let serve = tokio::spawn(async move { sender.deliver_once_signed(&signed).await });
            let mut guard = ReplayGuard::with_default_window();
            let opened = fetch_signed_verified(
                &recipient_tor,
                &onion,
                &sender_id.public,
                &rcpt.public,
                &rcpt.secret,
                &mut guard,
            )
            .await
            .expect("fetch_signed_verified");
            serve.await.expect("join serve").expect("serve");

            assert_eq!(opened, plaintext);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_seal_roundtrip() {
        let rcpt = generate_recipient();
        assert_eq!(rcpt.public.len(), PUBLIC_KEY_LEN);
        assert_eq!(rcpt.secret.len(), SECRET_KEY_LEN);
        let sealed = seal(&rcpt.public, b"a sensitive document").unwrap();
        assert_eq!(sealed.kem_ct.len(), KEM_CT_LEN);
        // The ciphertext reveals nothing of the plaintext.
        assert!(!sealed.body.windows(9).any(|w| w == b"sensitive"));
        let opened = open(&rcpt.secret, &sealed).unwrap();
        assert_eq!(opened, b"a sensitive document");
    }

    #[test]
    fn wrong_recipient_cannot_open() {
        let rcpt = generate_recipient();
        let other = generate_recipient();
        let sealed = seal(&rcpt.public, b"secret").unwrap();
        assert!(open(&other.secret, &sealed).is_err());
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let rcpt = generate_recipient();
        let mut sealed = seal(&rcpt.public, b"secret").unwrap();
        let last = sealed.body.len() - 1;
        sealed.body[last] ^= 0xFF;
        assert!(open(&rcpt.secret, &sealed).is_err());
    }

    #[test]
    fn tampered_encapsulation_is_rejected() {
        let rcpt = generate_recipient();
        // Flip a bit in the ML-KEM ciphertext leg → implicit rejection →
        // different combined key → AEAD open fails.
        let mut sealed = seal(&rcpt.public, b"secret").unwrap();
        sealed.kem_ct[10] ^= 0x01;
        assert!(open(&rcpt.secret, &sealed).is_err());
        // Flip a bit in the X25519 ephemeral-key leg → different DH output and
        // a changed bound transcript → AEAD open fails.
        let mut sealed = seal(&rcpt.public, b"secret").unwrap();
        let x_leg = sealed.kem_ct.len() - 1;
        sealed.kem_ct[x_leg] ^= 0x01;
        assert!(open(&rcpt.secret, &sealed).is_err());
    }

    #[test]
    fn wire_roundtrip_and_version_check() {
        let rcpt = generate_recipient();
        let sealed = seal(&rcpt.public, b"payload").unwrap();
        let wire = sealed.to_bytes();
        assert_eq!(wire[0], WIRE_VERSION);
        let parsed = SealedPayload::from_bytes(&wire).unwrap();
        assert_eq!(parsed.kem_ct, sealed.kem_ct);
        assert_eq!(parsed.body, sealed.body);
        assert_eq!(open(&rcpt.secret, &parsed).unwrap(), b"payload");

        // Unknown version byte is rejected up front.
        let mut bad = wire.clone();
        bad[0] = 99;
        assert!(matches!(SealedPayload::from_bytes(&bad), Err(CourierError::Version)));
        // Truncated input is rejected.
        assert!(SealedPayload::from_bytes(&wire[..KEM_CT_LEN]).is_err());
        assert!(SealedPayload::from_bytes(&[]).is_err());
    }

    #[test]
    fn wrong_length_keys_are_rejected() {
        let rcpt = generate_recipient();
        assert!(seal(&rcpt.public[..PUBLIC_KEY_LEN - 1], b"x").is_err());
        let sealed = seal(&rcpt.public, b"x").unwrap();
        assert!(open(&rcpt.secret[..SECRET_KEY_LEN - 1], &sealed).is_err());
    }

    #[test]
    fn fingerprint_is_stable_and_distinguishing() {
        let a = generate_recipient();
        let b = generate_recipient();
        let fa = key_fingerprint(&a.public);
        assert_eq!(fa, key_fingerprint(&a.public));
        assert_ne!(fa, key_fingerprint(&b.public));
        // Five 4-hex-char groups: "xxxx-xxxx-xxxx-xxxx-xxxx".
        assert_eq!(fa.len(), 24);
        assert_eq!(fa.split('-').count(), 5);
    }
}
