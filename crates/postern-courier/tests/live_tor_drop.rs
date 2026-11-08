//! LIVE Arti onion-drop integration tests driven THROUGH the
//! `drop_transport::DropSender`/`DropFetcher` (and `Signed*`) trait seam —
//! the same generic surface a UI caller injects `MockDrop` into offline,
//! here bound to the REAL feature-gated onion transport. This is the one
//! thing the offline suite cannot prove: that the concrete `transport::Sender`
//! / `PosternTor` trait impls actually carry a drop over the live Tor network
//! when reached only via the generic seam.
//!
//! HONEST LIMITS (restated from the crate docs; never softened):
//! - Everything exercised here is an **UNAUDITED reference-prototype** — the
//!   hybrid seal, the sender-auth leg, the replay guard, the onion transport,
//!   and the seam itself.
//! - The onion address crypto is **classical Tor** — the PQ hybrid protects
//!   the *payload*, not circuit metadata.
//! - Payload **size and timing remain observable** to the transport and to a
//!   network observer (the AEAD is length-revealing; no padding).
//! - A passing run proves the **plumbing works end-to-end**. It is NOT an
//!   anonymity claim, NOT a security claim, and NOT evidence the onion path
//!   is safe.
//! - Needs the real Tor network and **minutes** (a fresh HS descriptor must
//!   reach the HSDirs); it never runs in CI.
//!
//! DOUBLE-gated so no blanket `cargo test -- --ignored` ever opens a live
//! circuit: `#[ignore]` AND a `POSTERN_LIVE_TOR=1` env check that returns
//! before any Tor call. Run explicitly:
//! `POSTERN_LIVE_TOR=1 cargo test -p postern-courier --features onion-transport --test live_tor_drop -- --ignored --nocapture`
#![cfg(feature = "onion-transport")]

use postern_courier::drop_transport::{
    receive_verified_now, DropFetcher, DropSender, SignedDropFetcher, SignedDropSender,
};
use postern_courier::replay::ReplayGuard;
use postern_courier::sender_auth::{generate_sender_identity, sign_sealed, SignedSealedPayload};
use postern_courier::transport::{ensure_rustls_crypto_provider, PosternTor, Sender};
use postern_courier::{generate_recipient, open, seal, CourierError, SealedPayload};

/// The double gate's second half: `#[ignore]` keeps these out of the default
/// run; this keeps them out of a blanket `-- --ignored` run too. Only an
/// explicit `POSTERN_LIVE_TOR=1` opens a live circuit.
fn live_tor_enabled() -> bool {
    std::env::var("POSTERN_LIVE_TOR").as_deref() == Ok("1")
}

/// Bounded rendezvous retries, mirroring `examples/onion_drop.rs`'s runbook:
/// a fresh HS descriptor takes minutes to reach the HSDirs, so ONE 120 s
/// accept/connect window per side is not enough (observed live 2026-07-16:
/// both tests published fine and then failed their single fetch window; see
/// evidence/live-onion-drop.evidence). Each side spends at most this many
/// attempts; the recipient pauses between fetches instead of hammering the
/// HSDirs. Retries change nothing about what a pass MEANS (plumbing, only).
const LIVE_ATTEMPTS: u32 = 5;
/// Pause between recipient fetch attempts (as in the example runbook).
const FETCH_RETRY_PAUSE: std::time::Duration = std::time::Duration::from_secs(20);

/// Fetch with bounded retries through the seam helper, for the live tests.
async fn fetch_via_with_retries<F: DropFetcher>(
    fetcher: &F,
    address: &str,
) -> Result<SealedPayload, CourierError> {
    let mut last = None;
    for attempt in 1..=LIVE_ATTEMPTS {
        match fetch_via(fetcher, address).await {
            Ok(p) => return Ok(p),
            Err(e) => {
                eprintln!(
                    "fetch attempt {attempt}/{LIVE_ATTEMPTS}: {e}; descriptor propagation \
                     takes minutes"
                );
                last = Some(e);
                if attempt < LIVE_ATTEMPTS {
                    tokio::time::sleep(FETCH_RETRY_PAUSE).await;
                }
            }
        }
    }
    Err(last.expect("LIVE_ATTEMPTS >= 1"))
}

/// [`fetch_via_with_retries`] for the signed seam.
async fn fetch_signed_via_with_retries<F: SignedDropFetcher>(
    fetcher: &F,
    address: &str,
) -> Result<SignedSealedPayload, CourierError> {
    let mut last = None;
    for attempt in 1..=LIVE_ATTEMPTS {
        match fetch_signed_via(fetcher, address).await {
            Ok(p) => return Ok(p),
            Err(e) => {
                eprintln!(
                    "signed fetch attempt {attempt}/{LIVE_ATTEMPTS}: {e}; descriptor \
                     propagation takes minutes"
                );
                last = Some(e);
                if attempt < LIVE_ATTEMPTS {
                    tokio::time::sleep(FETCH_RETRY_PAUSE).await;
                }
            }
        }
    }
    Err(last.expect("LIVE_ATTEMPTS >= 1"))
}

// Generic helpers standing in for a UI caller that only knows the traits —
// mirroring the `send_via`/`fetch_via` shape in `src/drop_transport.rs`'s
// tests, but bound here to the REAL Arti transport instead of `MockDrop`.
// This is the point of the file: the live path reached exclusively through
// the injectable seam, never through the concrete API directly.

async fn send_via<S: DropSender>(sender: S, sealed: &SealedPayload) -> Result<(), CourierError> {
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

/// Live: seal → `DropSender::deliver` (the real onion `Sender`) →
/// `DropFetcher::fetch` (a real bootstrapped `PosternTor`) → open, with the
/// transport reached ONLY through the generic seam. Proves plumbing, nothing
/// more (see the module docs' honest limits).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "live Tor: needs network + minutes; run with POSTERN_LIVE_TOR=1 -- --ignored"]
async fn live_onion_drop_via_seam() {
    if !live_tor_enabled() {
        eprintln!("SKIP: POSTERN_LIVE_TOR!=1 — no live circuit opened");
        return;
    }

    // Select arti's rustls crypto backend before the first handshake (see
    // the helper's docs — provider selection only, no gating change).
    ensure_rustls_crypto_provider();

    let rcpt = generate_recipient();
    let plaintext = b"a real payload through the seam over a real onion";
    let sealed = seal(&rcpt.public, plaintext).unwrap();

    // Sender: bootstrap Tor and publish the ephemeral drop (concrete setup —
    // the seam has no publish; the address is handed over out-of-band).
    let sender_tor = PosternTor::bootstrap().await.expect("sender bootstrap");
    let sender = Sender::publish(&sender_tor, "postern-courier-seam-livetest")
        .await
        .expect("publish");
    let onion = sender.onion_address().to_string();
    eprintln!("seam drop published at {onion} (waiting for descriptor to propagate)…");

    // Recipient: a circuit-isolated client on the same host for the test.
    let recipient_tor = sender_tor.for_identity();

    // Serve and fetch concurrently — both sides through the traits, both
    // with the bounded runbook-style retries (one 120 s window per side is
    // not enough while a fresh descriptor propagates; see LIVE_ATTEMPTS).
    let serve_tor = sender_tor.clone();
    let serve_onion = onion.clone();
    let serve = tokio::spawn(async move {
        let mut sender = Some(sender);
        let mut last = None;
        for attempt in 1..=LIVE_ATTEMPTS {
            let s = match sender.take() {
                Some(s) => s,
                // The single-shot deliver consumed the previous Sender:
                // re-publish under the same nickname. The address must hold —
                // the recipient side already got `onion`.
                None => match Sender::publish(&serve_tor, "postern-courier-seam-livetest").await
                {
                    Ok(s) => {
                        assert_eq!(
                            s.onion_address(),
                            serve_onion,
                            "re-publish under the same nickname must keep the address"
                        );
                        s
                    }
                    Err(e) => {
                        eprintln!(
                            "serve attempt {attempt}/{LIVE_ATTEMPTS}: re-publish failed \
                             ({e}); the old service may still be tearing down — retrying…"
                        );
                        last = Some(e);
                        tokio::time::sleep(FETCH_RETRY_PAUSE).await;
                        continue;
                    }
                },
            };
            match send_via(s, &sealed).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    eprintln!(
                        "serve attempt {attempt}/{LIVE_ATTEMPTS}: no peer yet ({e}); \
                         re-publishing and re-serving…"
                    );
                    last = Some(e);
                }
            }
        }
        Err(last.expect("LIVE_ATTEMPTS >= 1"))
    });
    let fetched = fetch_via_with_retries(&recipient_tor, &onion)
        .await
        .expect("fetch_via");
    serve.await.expect("join serve").expect("serve");

    let opened = open(&rcpt.secret, &fetched).expect("open");
    assert_eq!(opened, plaintext);
}

/// Live SIGNED seam, mirroring `live_onion_drop_via_seam`: sign_sealed →
/// `SignedDropSender::deliver_signed` → `SignedDropFetcher::fetch_signed` →
/// the full `receive_verified_now` pipeline (verify_sealed FIRST, then a
/// fresh default-window `ReplayGuard`, then open). Same honest limits, same
/// double gate.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "live Tor: needs network + minutes; run with POSTERN_LIVE_TOR=1 -- --ignored"]
async fn live_onion_signed_drop_via_seam() {
    if !live_tor_enabled() {
        eprintln!("SKIP: POSTERN_LIVE_TOR!=1 — no live circuit opened");
        return;
    }

    // Select arti's rustls crypto backend before the first handshake (see
    // the helper's docs — provider selection only, no gating change).
    ensure_rustls_crypto_provider();

    let sender_id = generate_sender_identity();
    let rcpt = generate_recipient();
    let plaintext = b"a real signed payload through the seam over a real onion";
    let sealed = seal(&rcpt.public, plaintext).unwrap();
    let signed = sign_sealed(&sender_id, &rcpt.public, &sealed);

    // Sender: bootstrap Tor and publish the ephemeral drop.
    let sender_tor = PosternTor::bootstrap().await.expect("sender bootstrap");
    let sender = Sender::publish(&sender_tor, "postern-courier-seam-signed-livetest")
        .await
        .expect("publish");
    let onion = sender.onion_address().to_string();
    eprintln!("signed seam drop published at {onion} (waiting for descriptor to propagate)…");

    // Recipient: a circuit-isolated client on the same host for the test.
    let recipient_tor = sender_tor.for_identity();

    // Serve and fetch+verify concurrently — both sides through the traits,
    // with the same bounded runbook-style retries as the bare-seam test.
    let serve_tor = sender_tor.clone();
    let serve_onion = onion.clone();
    let serve = tokio::spawn(async move {
        let mut sender = Some(sender);
        let mut last = None;
        for attempt in 1..=LIVE_ATTEMPTS {
            let s = match sender.take() {
                Some(s) => s,
                None => match Sender::publish(&serve_tor, "postern-courier-seam-signed-livetest")
                    .await
                {
                    Ok(s) => {
                        assert_eq!(
                            s.onion_address(),
                            serve_onion,
                            "re-publish under the same nickname must keep the address"
                        );
                        s
                    }
                    Err(e) => {
                        eprintln!(
                            "serve attempt {attempt}/{LIVE_ATTEMPTS}: re-publish failed \
                             ({e}); the old service may still be tearing down — retrying…"
                        );
                        last = Some(e);
                        tokio::time::sleep(FETCH_RETRY_PAUSE).await;
                        continue;
                    }
                },
            };
            match send_signed_via(s, &signed).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    eprintln!(
                        "serve attempt {attempt}/{LIVE_ATTEMPTS}: no peer yet ({e}); \
                         re-publishing and re-serving…"
                    );
                    last = Some(e);
                }
            }
        }
        Err(last.expect("LIVE_ATTEMPTS >= 1"))
    });
    let fetched = fetch_signed_via_with_retries(&recipient_tor, &onion)
        .await
        .expect("fetch_signed_via");
    serve.await.expect("join serve").expect("serve");

    let mut guard = ReplayGuard::with_default_window();
    let opened = receive_verified_now(
        &sender_id.public,
        &rcpt.public,
        &rcpt.secret,
        &fetched,
        &mut guard,
    )
    .expect("receive_verified_now");
    assert_eq!(opened, plaintext);
}
