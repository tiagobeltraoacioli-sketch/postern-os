//! A mockable transport seam over the Courier drop, plus the full opt-in
//! **verified-receive pipeline** ([`receive_verified`]).
//!
//! The concrete transport (the `onion-transport`-feature [`crate::transport`]
//! module) already carries a [`SealedPayload`] person-to-person over an
//! ephemeral Tor onion service — but `Sender::publish`/`deliver_once` and
//! `transport::fetch` are concrete functions tied to a live `PosternTor`. A
//! UI caller (the planned Tauri/mobile shells) that wants to exercise its
//! receive plumbing offline, or unit-test it at all, has no seam to inject a
//! fake transport into. This module is that seam:
//!
//! - [`DropSender`] / [`DropFetcher`]: async traits mirroring the concrete
//!   transport's **single-shot** semantics — `deliver` consumes the sender (a
//!   drop is served once, then the service is gone) and `fetch` downloads one
//!   sealed payload from an out-of-band-communicated address. The
//!   feature-gated onion `Sender` and `PosternTor` implement them in
//!   [`crate::transport`] without any change to their concrete API, so
//!   existing callers keep working unmodified. [`SignedDropSender`] /
//!   [`SignedDropFetcher`] are the same seam for the signed (`PCS1`) frame —
//!   see "Signed drops over this seam" below.
//! - [`MockDrop`]: an in-memory stored-bytes drop implementing both traits,
//!   available to this crate's tests and — via the **test-only**
//!   `mock-transport` feature — to downstream test builds. It moves no bytes
//!   anywhere; never enable that feature in a shipping build.
//! - [`receive_verified`] / [`receive_verified_now`]: the full verified-receive
//!   pipeline a recipient opts into on top of a fetched drop, in the one
//!   documented-safe order: [`crate::sender_auth::verify_sealed`] **first**,
//!   then [`ReplayGuard::check_and_record`], then [`crate::open`].
//!
//! Signed drops over this seam: the concrete onion transport now frames a
//! [`SignedSealedPayload`] too — a separate `PCS1` frame (same u32-BE length
//! header, same size cap, same timeout bounds as the bare `PCD1` frame; only
//! the magic differs, and a fetch expecting one kind rejects the other
//! outright) carrying [`SignedSealedPayload::to_bytes`], served by the onion
//! `Sender::deliver_once_signed` and fetched by `transport::fetch_signed` /
//! `transport::fetch_signed_verified`. [`SignedDropSender`] /
//! [`SignedDropFetcher`] are that path's seam — implemented by the onion
//! `Sender`/`PosternTor` under the feature and by [`MockDrop`] (via its
//! raw-bytes [`MockDrop::deliver_wire`] / [`MockDrop::fetch_wire`], which
//! remain available for hand-built wire bytes) offline. The `PCS1` frame adds
//! **no wire auth of its own** — the authentication is the payload-layer
//! signature it carries, checked by [`receive_verified`], never the frame.
//!
//! HONEST LIMITS (unchanged by this module; restated, never softened):
//! - Everything here — the seal, the sender-auth leg, the replay guard, the
//!   onion transport, and this seam — is **UNAUDITED reference-prototype**.
//! - The drop's wire frame still has **no auth and no replay protection of
//!   its own** (beyond the size cap in [`crate::transport`]): a peer that
//!   completes the transport handshake can serve any bytes it wants, and a
//!   recorded frame can be re-served verbatim. These traits add no wire
//!   hardening — they only make the existing plumbing injectable. What the
//!   frame does not provide, the recipient opts into at the payload layer:
//!   require a [`SignedSealedPayload`] and run [`receive_verified`].
//! - Payload **size and timing remain observable** to the transport and to a
//!   network observer either way — the AEAD is length-revealing (no padding),
//!   and a mock cannot change what the real wire leaks.
//! - [`ReplayGuard`]'s protection is bounded to its configured window, held
//!   only in the recipient process's memory, and lost on restart — see
//!   [`crate::replay`]'s module docs for the full list of caveats.
//! - A mock is **not** a transport-security claim: [`MockDrop`] exists so the
//!   pipeline's *logic* is testable offline, not as evidence the onion path
//!   is safe. The live path is exercised by the ignored end-to-end test in
//!   [`crate::transport`], which needs the real Tor network and minutes.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::replay::ReplayGuard;
use crate::sender_auth::{verify_sealed, SignedSealedPayload};
use crate::{CourierError, SealedPayload};

/// Sender side of the drop seam: serve one sealed payload to one recipient,
/// then be done. Mirrors the concrete onion `Sender::deliver_once` exactly:
/// `deliver` **consumes** the sender because a drop is single-shot — the
/// concrete implementation tears the ephemeral onion service down on return,
/// and the mock refuses a second deliver.
///
/// `async fn` in a public trait is deliberate (no boxed-future dependency, no
/// new runtime deps): the trait is **not dyn-compatible** — inject an
/// implementation via generics, not `dyn DropSender` — and the returned
/// future's `Send`-ness is whatever the implementation's I/O gives it (add
/// bounds at your own spawn sites if your runtime needs `Send`).
#[allow(async_fn_in_trait)]
pub trait DropSender {
    /// Serve `sealed` to the (single) recipient and tear the drop down.
    ///
    /// Errors with the same deliberately coarse [`CourierError::Transport`]
    /// the concrete transport uses — a transport error must not leak *why*
    /// (the payload is authenticated by the seal, never by the wire).
    async fn deliver(self, sealed: &SealedPayload) -> Result<(), CourierError>;
}

/// Recipient side of the drop seam: download one sealed payload from an
/// address handed over out-of-band (next to the courier key fingerprint —
/// see the crate-level "Honest limits"). Mirrors the concrete
/// `transport::fetch`: the returned [`SealedPayload`] still has to be
/// [`crate::open`]ed with the recipient's hybrid secret key — that, not the
/// fetch succeeding, is what proves the drop is really for them. A recipient
/// wanting sender authentication and anti-replay on top uses
/// [`receive_verified`] instead of a bare `open`.
///
/// Same dyn-compatibility / `Send` note as [`DropSender`].
#[allow(async_fn_in_trait)]
pub trait DropFetcher {
    /// Fetch the sealed payload served at `address`.
    async fn fetch(&self, address: &str) -> Result<SealedPayload, CourierError>;
}

/// Sender side of the SIGNED drop seam: serve one
/// [`SignedSealedPayload`] to one recipient, then be done. Mirrors the
/// concrete onion `Sender::deliver_once_signed` exactly: `deliver_signed`
/// **consumes** the sender because a drop is single-shot — the concrete
/// implementation tears the ephemeral onion service down on return, and the
/// mock refuses a second deliver.
///
/// Same `async fn`-in-trait note as [`DropSender`]: not dyn-compatible,
/// inject via generics, `Send`-ness follows the implementation's I/O.
#[allow(async_fn_in_trait)]
pub trait SignedDropSender {
    /// Serve `signed` to the (single) recipient and tear the drop down.
    ///
    /// Errors with the same deliberately coarse [`CourierError::Transport`]
    /// the concrete transport uses — a transport error must not leak *why*
    /// (the payload is authenticated by its signature + seal, never by the
    /// wire; the signed frame adds no wire auth of its own).
    async fn deliver_signed(self, signed: &SignedSealedPayload) -> Result<(), CourierError>;
}

/// Recipient side of the SIGNED drop seam: download one
/// [`SignedSealedPayload`] from an out-of-band-communicated address. Mirrors
/// the concrete `transport::fetch_signed`: the returned payload is
/// **unverified and unopened** — run it through [`receive_verified`]
/// (verify_sealed FIRST, then the replay guard, then open); the fetch
/// succeeding proves nothing about who signed it or whether it is fresh.
///
/// Same dyn-compatibility / `Send` note as [`DropSender`].
#[allow(async_fn_in_trait)]
pub trait SignedDropFetcher {
    /// Fetch the signed sealed payload served at `address`.
    async fn fetch_signed(&self, address: &str) -> Result<SignedSealedPayload, CourierError>;
}

/// The full opt-in verified-receive pipeline over a fetched signed drop, in
/// the one documented-safe order:
///
/// 1. [`crate::sender_auth::verify_sealed`] — **before** anything is recorded:
///    the [`ReplayGuard`] must only ever see nonces/timestamps whose binding
///    to a payload and sender has been verified (feeding it unverified values
///    gives no protection — see [`crate::replay`]'s honest limits — and would
///    let a forger's garbage pollute the guard's bounded state).
/// 2. [`ReplayGuard::check_and_record`] with `signed`'s verified nonce and
///    timestamp, as of `now_secs`.
/// 3. [`crate::open`] with the recipient's hybrid secret key.
///
/// `now_secs` is a parameter (matching [`ReplayGuard::check_and_record`]) so
/// the pipeline is deterministic and testable; [`receive_verified_now`] is the
/// system-clock convenience.
///
/// Deliberate consequence of the ordering: the guard records the nonce
/// **before** `open` runs, so a drop whose signature verifies but whose AEAD
/// open then fails (wrong recipient secret handed in) has still burned its
/// nonce for the window — re-presenting the same wire bytes inside the window
/// is rejected as a replay even with the right key. That is the safe failure
/// direction for a single-shot drop; a sender re-sends with a fresh signature
/// (fresh nonce) rather than the recipient retrying stale bytes.
///
/// HONEST LIMITS: this pipeline only means something if the sender's
/// verifying key AND the recipient's courier key were authenticated
/// out-of-band first ([`crate::sender_auth::sender_fingerprint`],
/// [`crate::key_fingerprint`]); every component of it is UNAUDITED
/// reference-prototype; and the guard's protection is window-bounded,
/// in-process, and lost on restart.
pub fn receive_verified(
    sender_verifying_key: &[u8],
    recipient_public: &[u8],
    recipient_secret: &[u8],
    signed: &SignedSealedPayload,
    guard: &mut ReplayGuard,
    now_secs: u64,
) -> Result<Vec<u8>, CourierError> {
    // 1. Sender authentication FIRST — nothing below runs, and nothing is
    //    recorded, for a payload that does not verify.
    let sealed = verify_sealed(sender_verifying_key, recipient_public, signed)?;
    // 2. Anti-replay on the now-verified (nonce, timestamp).
    guard.check_and_record_payload(signed, now_secs)?;
    // 3. Decrypt.
    crate::open(recipient_secret, sealed)
}

/// [`receive_verified`] using the system clock for `now`. A pre-1970 (or
/// otherwise unreadable) clock fails **closed** exactly like
/// [`ReplayGuard::check_and_record_now`]: `now_secs = 0` makes any real
/// timestamp read as future-dated rather than silently bypassing the check.
pub fn receive_verified_now(
    sender_verifying_key: &[u8],
    recipient_public: &[u8],
    recipient_secret: &[u8],
    signed: &SignedSealedPayload,
    guard: &mut ReplayGuard,
) -> Result<Vec<u8>, CourierError> {
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    receive_verified(
        sender_verifying_key,
        recipient_public,
        recipient_secret,
        signed,
        guard,
        now_secs,
    )
}

#[cfg(any(test, feature = "mock-transport"))]
mod mock {
    use super::{
        CourierError, DropFetcher, DropSender, SealedPayload, SignedDropFetcher,
        SignedDropSender, SignedSealedPayload,
    };
    use std::sync::{Arc, Mutex, PoisonError};

    /// The one address a [`MockDrop`] answers to. Deliberately not a
    /// plausible real onion address (v3 onion addresses are 56 base32 chars
    /// followed by ".onion"), so mock plumbing can never be mistaken for —
    /// or accidentally handed to — the real transport.
    pub const MOCK_DROP_ADDRESS: &str = "mock-drop.invalid";

    /// An in-memory, stored-bytes drop for **offline tests only** — it moves
    /// no bytes anywhere and is NOT a transport-security claim of any kind
    /// (see the module docs). Available to this crate's tests and, via the
    /// test-only `mock-transport` feature, to downstream test builds.
    ///
    /// Semantics, chosen to mirror the real drop's honest behavior:
    /// - `Clone` shares the same underlying slot (hand one clone to the
    ///   sending half of a test and keep one for fetching).
    /// - [`MockDrop::deliver_wire`] is single-shot like the onion
    ///   `Sender::deliver_once` — a second deliver into the same drop is a
    ///   [`CourierError::Transport`].
    /// - [`MockDrop::fetch_wire`] deliberately **re-serves the same recorded
    ///   bytes on every call** — modeling exactly the documented transport
    ///   limit that "a recorded frame can be re-served verbatim". That is
    ///   what makes the replay-guard pipeline testable against this mock:
    ///   the wire never protects against replay; [`super::receive_verified`]
    ///   does.
    /// - Fetching an address other than [`MOCK_DROP_ADDRESS`], or fetching
    ///   before anything was delivered, is a [`CourierError::Transport`] —
    ///   the same deliberately coarse error the real transport returns for
    ///   every failure.
    #[derive(Clone, Default)]
    pub struct MockDrop {
        slot: Arc<Mutex<Option<Vec<u8>>>>,
    }

    impl MockDrop {
        /// An empty drop. Clone it to share the slot between the test's
        /// sending and fetching halves.
        pub fn new() -> Self {
            Self::default()
        }

        /// The address to "hand over out-of-band" in a test — the mock
        /// counterpart of the onion `Sender::onion_address`.
        pub fn address(&self) -> &'static str {
            MOCK_DROP_ADDRESS
        }

        /// Store raw wire bytes in the drop (e.g. a
        /// [`crate::sender_auth::SignedSealedPayload::to_bytes`] blob, which
        /// the [`DropSender`]/[`DropFetcher`] `SealedPayload` seam cannot
        /// carry — see the module docs). Single-shot: a second deliver is
        /// refused.
        pub fn deliver_wire(&self, wire: Vec<u8>) -> Result<(), CourierError> {
            let mut slot = self.slot.lock().unwrap_or_else(PoisonError::into_inner);
            if slot.is_some() {
                return Err(CourierError::Transport);
            }
            *slot = Some(wire);
            Ok(())
        }

        /// Fetch the stored raw wire bytes. Re-serves the same bytes on every
        /// call on purpose — see the type docs.
        pub fn fetch_wire(&self, address: &str) -> Result<Vec<u8>, CourierError> {
            if address != MOCK_DROP_ADDRESS {
                return Err(CourierError::Transport);
            }
            self.slot
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
                .ok_or(CourierError::Transport)
        }
    }

    impl DropSender for MockDrop {
        async fn deliver(self, sealed: &SealedPayload) -> Result<(), CourierError> {
            self.deliver_wire(sealed.to_bytes())
        }
    }

    impl DropFetcher for MockDrop {
        async fn fetch(&self, address: &str) -> Result<SealedPayload, CourierError> {
            SealedPayload::from_bytes(&self.fetch_wire(address)?)
        }
    }

    impl SignedDropSender for MockDrop {
        /// [`MockDrop::deliver_wire`] of the signed wire bytes — the same
        /// single-shot slot the bare trait uses (a mock drop holds ONE payload
        /// of either kind, like the real single-shot onion drop).
        async fn deliver_signed(self, signed: &SignedSealedPayload) -> Result<(), CourierError> {
            self.deliver_wire(signed.to_bytes())
        }
    }

    impl SignedDropFetcher for MockDrop {
        /// [`MockDrop::fetch_wire`] then [`SignedSealedPayload::from_bytes`].
        /// Re-serves the same recorded bytes on every call on purpose (see the
        /// type docs) — which is exactly what makes the replay-guard leg of
        /// [`super::receive_verified`] testable against this mock.
        async fn fetch_signed(&self, address: &str) -> Result<SignedSealedPayload, CourierError> {
            SignedSealedPayload::from_bytes(&self.fetch_wire(address)?)
        }
    }
}

#[cfg(any(test, feature = "mock-transport"))]
pub use mock::{MockDrop, MOCK_DROP_ADDRESS};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sender_auth::{generate_sender_identity, sign_sealed};
    use crate::{generate_recipient, seal, KEM_CT_LEN};
    use std::time::Duration;

    /// Generic helpers standing in for a UI caller that only knows the
    /// traits — proving the seam really is injectable (the mock reaches the
    /// pipeline through the SAME generic surface the onion transport would).
    async fn send_via<S: DropSender>(
        sender: S,
        sealed: &SealedPayload,
    ) -> Result<(), CourierError> {
        sender.deliver(sealed).await
    }

    async fn fetch_via<F: DropFetcher>(
        fetcher: &F,
        address: &str,
    ) -> Result<SealedPayload, CourierError> {
        fetcher.fetch(address).await
    }

    async fn send_signed_via<S: SignedDropSender>(
        sender: S,
        signed: &SignedSealedPayload,
    ) -> Result<(), CourierError> {
        sender.deliver_signed(signed).await
    }

    async fn fetch_signed_via<F: SignedDropFetcher>(
        fetcher: &F,
        address: &str,
    ) -> Result<SignedSealedPayload, CourierError> {
        fetcher.fetch_signed(address).await
    }

    // seal -> mock deliver -> mock fetch -> open, entirely through the trait
    // seam, entirely offline.
    #[tokio::test]
    async fn seal_deliver_fetch_open_roundtrip_over_mock() {
        let rcpt = generate_recipient();
        let plaintext = b"drop me through the seam";
        let sealed = seal(&rcpt.public, plaintext).unwrap();

        let drop_slot = MockDrop::new();
        let address = drop_slot.address().to_string();

        send_via(drop_slot.clone(), &sealed).await.unwrap();
        let fetched = fetch_via(&drop_slot, &address).await.unwrap();

        assert_eq!(fetched.kem_ct, sealed.kem_ct);
        assert_eq!(fetched.body, sealed.body);
        assert_eq!(crate::open(&rcpt.secret, &fetched).unwrap(), plaintext);
    }

    // The mock mirrors the real drop's coarse failure surface: fetch before
    // deliver, a wrong address, and a second deliver are all Transport errors.
    #[tokio::test]
    async fn mock_failure_surface_is_coarse_transport_errors() {
        let rcpt = generate_recipient();
        let sealed = seal(&rcpt.public, b"x").unwrap();
        let drop_slot = MockDrop::new();

        // Empty drop.
        assert!(matches!(
            fetch_via(&drop_slot, MOCK_DROP_ADDRESS).await,
            Err(CourierError::Transport)
        ));

        send_via(drop_slot.clone(), &sealed).await.unwrap();

        // Wrong address.
        assert!(matches!(
            fetch_via(&drop_slot, "somewhere-else.invalid").await,
            Err(CourierError::Transport)
        ));

        // Second deliver into the same (single-shot) drop.
        let sealed2 = seal(&rcpt.public, b"y").unwrap();
        assert!(matches!(
            send_via(drop_slot.clone(), &sealed2).await,
            Err(CourierError::Transport)
        ));

        // The original payload is still fetchable and intact.
        let fetched = fetch_via(&drop_slot, MOCK_DROP_ADDRESS).await.unwrap();
        assert_eq!(crate::open(&rcpt.secret, &fetched).unwrap(), b"x");
    }

    // Sealed bytes tampered in transit parse fine as a frame but are
    // rejected at `open` — the seal, not the wire, protects the payload.
    #[tokio::test]
    async fn tampered_sealed_wire_is_rejected_at_open() {
        let rcpt = generate_recipient();
        let sealed = seal(&rcpt.public, b"integrity matters").unwrap();

        // A hostile drop serves an almost-right blob: one bit flipped inside
        // the AEAD body region (past version byte + kem_ct, so from_bytes
        // still parses — the tamper is only detectable cryptographically).
        let mut wire = sealed.to_bytes();
        let last = wire.len() - 1;
        assert!(last > KEM_CT_LEN, "flip lands in the AEAD body");
        wire[last] ^= 0x01;

        let drop_slot = MockDrop::new();
        drop_slot.deliver_wire(wire).unwrap();

        let fetched = fetch_via(&drop_slot, MOCK_DROP_ADDRESS).await.unwrap();
        assert!(matches!(
            crate::open(&rcpt.secret, &fetched),
            Err(CourierError::Open)
        ));
    }

    // The SIGNED trait seam end-to-end over the mock, entirely through the
    // generic surface a UI caller would use: sign -> deliver_signed ->
    // fetch_signed -> receive_verified. The mock re-serves the same bytes, so
    // a second fetch through the seam is rejected by the guard as a replay.
    #[tokio::test]
    async fn signed_seam_roundtrip_over_mock_then_replay_rejected() {
        let sender_id = generate_sender_identity();
        let rcpt = generate_recipient();
        let plaintext = b"signed drop through the seam";
        let sealed = seal(&rcpt.public, plaintext).unwrap();
        let signed = sign_sealed(&sender_id, &rcpt.public, &sealed);

        let drop_slot = MockDrop::new();
        let address = drop_slot.address().to_string();

        send_signed_via(drop_slot.clone(), &signed).await.unwrap();

        let mut guard = ReplayGuard::new(Duration::from_secs(600));

        let first = fetch_signed_via(&drop_slot, &address).await.unwrap();
        let opened = receive_verified(
            &sender_id.public,
            &rcpt.public,
            &rcpt.secret,
            &first,
            &mut guard,
            first.timestamp,
        )
        .unwrap();
        assert_eq!(opened, plaintext);

        // Second deliver into the same single-shot drop is refused (coarse).
        let sealed2 = seal(&rcpt.public, b"y").unwrap();
        let signed2 = sign_sealed(&sender_id, &rcpt.public, &sealed2);
        assert!(matches!(
            send_signed_via(drop_slot.clone(), &signed2).await,
            Err(CourierError::Transport)
        ));

        // The mock re-serves the recorded bytes; the guard, not the wire,
        // rejects the second presentation.
        let second = fetch_signed_via(&drop_slot, &address).await.unwrap();
        let err = receive_verified(
            &sender_id.public,
            &rcpt.public,
            &rcpt.secret,
            &second,
            &mut guard,
            second.timestamp,
        )
        .unwrap_err();
        assert!(matches!(err, CourierError::ReplayNonceReused));
    }

    // Fetching THROUGH THE SIGNED SEAM from a drop that holds bare
    // SealedPayload wire bytes fails at parse (the leading version bytes
    // differ by construction), and vice versa — the seams never mis-parse
    // each other's payload kind even without the onion frame's magic check.
    #[tokio::test]
    async fn signed_and_bare_seams_reject_each_others_payload_kind() {
        let sender_id = generate_sender_identity();
        let rcpt = generate_recipient();
        let sealed = seal(&rcpt.public, b"x").unwrap();
        let signed = sign_sealed(&sender_id, &rcpt.public, &sealed);

        // Bare bytes in the drop, fetched through the signed seam.
        let bare_drop = MockDrop::new();
        send_via(bare_drop.clone(), &sealed).await.unwrap();
        assert!(fetch_signed_via(&bare_drop, MOCK_DROP_ADDRESS).await.is_err());

        // Signed bytes in the drop, fetched through the bare seam.
        let signed_drop = MockDrop::new();
        send_signed_via(signed_drop.clone(), &signed).await.unwrap();
        assert!(fetch_via(&signed_drop, MOCK_DROP_ADDRESS).await.is_err());
    }

    // The full signed pipeline over the mock: SignedSealedPayload wire bytes
    // through the drop, then receive_verified (verify_sealed -> ReplayGuard
    // -> open). The mock re-serves the same recorded bytes — exactly the
    // documented "a recorded frame can be re-served verbatim" transport
    // limit — and the SECOND presentation is rejected by the guard, not by
    // the wire.
    #[tokio::test]
    async fn signed_pipeline_over_mock_passes_then_replay_is_rejected() {
        let sender_id = generate_sender_identity();
        let rcpt = generate_recipient();
        let plaintext = b"one-shot verified drop";
        let sealed = seal(&rcpt.public, plaintext).unwrap();
        let signed = sign_sealed(&sender_id, &rcpt.public, &sealed);

        let drop_slot = MockDrop::new();
        drop_slot.deliver_wire(signed.to_bytes()).unwrap();

        let mut guard = ReplayGuard::new(Duration::from_secs(600));

        // First presentation: fetch, parse, run the whole verified pipeline.
        let wire1 = drop_slot.fetch_wire(MOCK_DROP_ADDRESS).unwrap();
        let first = SignedSealedPayload::from_bytes(&wire1).unwrap();
        let opened = receive_verified(
            &sender_id.public,
            &rcpt.public,
            &rcpt.secret,
            &first,
            &mut guard,
            first.timestamp,
        )
        .unwrap();
        assert_eq!(opened, plaintext);

        // Second presentation: the mock replays the SAME recorded bytes.
        let wire2 = drop_slot.fetch_wire(MOCK_DROP_ADDRESS).unwrap();
        assert_eq!(wire1, wire2, "the mock re-serves the recorded frame verbatim");
        let second = SignedSealedPayload::from_bytes(&wire2).unwrap();
        let err = receive_verified(
            &sender_id.public,
            &rcpt.public,
            &rcpt.secret,
            &second,
            &mut guard,
            second.timestamp,
        )
        .unwrap_err();
        assert!(matches!(err, CourierError::ReplayNonceReused));
    }

    // Verify-before-record: a payload that FAILS sender verification must
    // not burn its nonce — the genuine drop still passes the guard afterward.
    #[tokio::test]
    async fn failed_verification_does_not_pollute_the_replay_guard() {
        let sender_id = generate_sender_identity();
        let rcpt = generate_recipient();
        let sealed = seal(&rcpt.public, b"genuine").unwrap();
        let signed = sign_sealed(&sender_id, &rcpt.public, &sealed);

        // A forger re-serves the drop with a flipped signature byte.
        let mut forged_wire = signed.to_bytes();
        let sig_byte = 1 + 32 + 8; // first signature byte (after version‖nonce‖timestamp)
        forged_wire[sig_byte] ^= 0x01;

        let mut guard = ReplayGuard::new(Duration::from_secs(600));

        let forged = SignedSealedPayload::from_bytes(&forged_wire).unwrap();
        let err = receive_verified(
            &sender_id.public,
            &rcpt.public,
            &rcpt.secret,
            &forged,
            &mut guard,
            forged.timestamp,
        )
        .unwrap_err();
        assert!(matches!(err, CourierError::SenderSignature));
        assert!(guard.is_empty(), "an unverified nonce must never be recorded");

        // The genuine drop (same nonce!) still passes the whole pipeline.
        let opened = receive_verified(
            &sender_id.public,
            &rcpt.public,
            &rcpt.secret,
            &signed,
            &mut guard,
            signed.timestamp,
        )
        .unwrap();
        assert_eq!(opened, b"genuine");
    }

    // Documented ordering consequence: a verified payload whose open fails
    // (wrong recipient secret) has still burned its nonce for the window.
    #[tokio::test]
    async fn verified_but_unopenable_drop_still_burns_its_nonce() {
        let sender_id = generate_sender_identity();
        let rcpt = generate_recipient();
        let wrong = generate_recipient();
        let sealed = seal(&rcpt.public, b"secret").unwrap();
        let signed = sign_sealed(&sender_id, &rcpt.public, &sealed);

        let mut guard = ReplayGuard::new(Duration::from_secs(600));

        // Signature verifies (right sender, right recipient binding), but the
        // wrong secret key is handed in → open fails AFTER the guard recorded.
        let err = receive_verified(
            &sender_id.public,
            &rcpt.public,
            &wrong.secret,
            &signed,
            &mut guard,
            signed.timestamp,
        )
        .unwrap_err();
        assert!(matches!(err, CourierError::Open));

        // Re-presenting the same bytes inside the window — even with the
        // RIGHT key now — is a replay. A sender re-sends with a fresh nonce.
        let err = receive_verified(
            &sender_id.public,
            &rcpt.public,
            &rcpt.secret,
            &signed,
            &mut guard,
            signed.timestamp,
        )
        .unwrap_err();
        assert!(matches!(err, CourierError::ReplayNonceReused));
    }

    // receive_verified_now works against a freshly-signed payload (its
    // timestamp is "now" by construction, well inside the default window).
    #[tokio::test]
    async fn receive_verified_now_accepts_a_fresh_drop() {
        let sender_id = generate_sender_identity();
        let rcpt = generate_recipient();
        let sealed = seal(&rcpt.public, b"fresh").unwrap();
        let signed = sign_sealed(&sender_id, &rcpt.public, &sealed);

        let mut guard = ReplayGuard::with_default_window();
        let opened = receive_verified_now(
            &sender_id.public,
            &rcpt.public,
            &rcpt.secret,
            &signed,
            &mut guard,
        )
        .unwrap();
        assert_eq!(opened, b"fresh");
    }
}
