//! LIVE integration tests: real E2EE (Megolm) round-trips between two Matrix
//! accounts, with Olm per-device room-key distribution done by the SDK.
//!
//! Both tests are `#[ignore]`d because they need a reachable homeserver and
//! network — neither is assumed in CI (blocked from CI by design). Nothing
//! here is mocked; when they run, they prove:
//!
//! 1. `e2ee_text_roundtrip_between_two_accounts` — the Phase-1 slice
//!    end-to-end (login → encrypted room → tier-gated send → sync →
//!    decrypted receive with `was_encrypted == true`).
//! 2. `session_restore_resumes_same_device_and_megolm_state` — the
//!    persistence slice: `login_password_persistent` into a sqlite store,
//!    snapshot via `session()`, one E2EE round-trip each way, drop the
//!    client ("process restart"), `restore()` from the `SavedSession` + the
//!    same store path, then assert the SAME `device_id` (no fresh device
//!    keys) and that a second E2EE round-trip still decrypts — including a
//!    Bob→Alice message on Bob's PRE-restart outbound Megolm session, which
//!    only decrypts if Alice's inbound Megolm session survived on disk.
//!
//! # HONEST STATUS — both tests HAVE now been run live (see the evidence file)
//!
//! Offline CI compiles this file (`cargo test -p postern-messenger
//! --features matrix` lists both tests as `ignored`) and proves NOTHING
//! beyond compilation. BUT both tests — including the session-restore
//! round-trip (test 2) — HAVE now been executed end-to-end against a live
//! throwaway Synapse (1.156.0) on localhost:8008 and transcribed VERBATIM in
//! `crates/postern-messenger/evidence/matrix-live-e2ee.evidence` (2026-07-18,
//! `test result: ok. 2 passed`; `was_encrypted=true` on every leg; the same
//! `device_id` before and after `restore()`). That evidence is a PLUMBING +
//! classical-Megolm-E2EE + sqlite-persistence proof ONLY — read its honest
//! ceiling (no Tor, no PQ transport, no verification, UNAUDITED). Re-running
//! it still requires the manual `-- --ignored` + env-var setup below; it is
//! never a CI gate. NOTE (from that run): run against a FRESH homeserver —
//! reusing accounts across runs accumulates stale devices with exhausted
//! one-time keys and stalls Megolm key-sharing (a harness-state footgun, not
//! a crate defect; documented in the evidence file).
//!
//! # How to run
//!
//! 1. Bring up a throwaway homeserver, e.g. Synapse:
//!
//!    ```text
//!    docker run --rm -v synapse-data:/data \
//!        -e SYNAPSE_SERVER_NAME=localhost -e SYNAPSE_REPORT_STATS=no \
//!        matrixdotorg/synapse:latest generate
//!    docker run --rm -v synapse-data:/data -p 8008:8008 \
//!        matrixdotorg/synapse:latest
//!    # in the running container, register the two accounts:
//!    #   register_new_matrix_user -u alice -p test-pass-a --no-admin \
//!    #       -c /data/homeserver.yaml http://localhost:8008
//!    #   register_new_matrix_user -u bob   -p test-pass-b --no-admin \
//!    #       -c /data/homeserver.yaml http://localhost:8008
//!    ```
//!
//!    (Synapse is AGPL — fine to RUN as a service for testing; we never link
//!    or fork it. Any homeserver works: continuwuity, conduwuit, …)
//!
//! 2. Point the test at it and run it:
//!
//!    ```text
//!    export POSTERN_MATRIX_TEST_HOMESERVER=http://localhost:8008
//!    export POSTERN_MATRIX_TEST_USER_A=alice POSTERN_MATRIX_TEST_PASS_A=test-pass-a
//!    export POSTERN_MATRIX_TEST_USER_B=bob   POSTERN_MATRIX_TEST_PASS_B=test-pass-b
//!    cargo test -p postern-messenger --features matrix --test matrix_live -- --ignored
//!    ```

#![cfg(feature = "matrix")]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use matrix_sdk::ruma::{OwnedEventId, RoomId};
use postern_messenger::SecurityTier;
use postern_messenger::matrix::{MatrixMessenger, ReceivedText};

fn env(name: &str) -> String {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("set {name} (see the header of tests/matrix_live.rs)"))
}

/// Sync `receiver` until `event_id` shows up in `inbox` (filled by an
/// `on_text_message` handler), or panic after 60s. The event only lands
/// after the SDK has serviced the to-device key share AND decrypted the
/// room event, so returning at all already implies a completed E2EE path.
async fn sync_until_received(
    receiver: &MatrixMessenger,
    inbox: &Arc<Mutex<Vec<ReceivedText>>>,
    event_id: &OwnedEventId,
    who: &str,
) -> ReceivedText {
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            receiver.sync_once().await.expect("sync while waiting for a message");
            let hit = inbox
                .lock()
                .unwrap()
                .iter()
                .find(|m| &m.event_id == event_id)
                .cloned();
            if let Some(m) = hit {
                return m;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{who} never received {event_id} within 60s"))
}

/// Alice creates the encrypted DM (via the crate's only room-creation path),
/// Bob accepts the invite, both sides settle membership.
async fn create_dm_and_join(alice: &MatrixMessenger, bob: &MatrixMessenger) -> matrix_sdk::ruma::OwnedRoomId {
    let bob_user = bob.user_id().expect("B logged in").to_owned();
    let room_id = alice.create_encrypted_dm(&bob_user).await.expect("create E2EE DM room");
    bob.sync_once().await.expect("sync B (invite)");
    let bob_room = bob.client().get_room(&room_id).expect("B sees the room");
    bob_room.join().await.expect("B joins");
    bob.sync_once().await.expect("sync B (joined)");
    alice.sync_once().await.expect("sync A (sees join)");
    room_id
}

/// Send `body` from `sender` and require `receiver` to get it back
/// **Megolm-encrypted** (plaintext delivery = hard failure).
async fn assert_e2ee_delivery(
    sender: &MatrixMessenger,
    receiver: &MatrixMessenger,
    inbox: &Arc<Mutex<Vec<ReceivedText>>>,
    room_id: &RoomId,
    body: &str,
    leg: &str,
) {
    let event_id = sender.send_text(room_id, body).await.expect("E2EE send");
    let msg = sync_until_received(receiver, inbox, &event_id, leg).await;
    assert_eq!(msg.body, body, "plaintext must round-trip intact ({leg})");
    assert_eq!(msg.room_id, room_id);
    assert!(
        msg.was_encrypted,
        "{leg}: the event MUST have arrived Megolm-encrypted (EncryptionInfo \
         present) — a plaintext delivery here is a hard failure"
    );
    assert_eq!(msg.tier, SecurityTier::InternalE2ee);
    // Evidence line (visible under --nocapture): make the Megolm decrypt
    // self-demonstrating in the transcript rather than only asserted.
    eprintln!(
        "EVIDENCE[{leg}]: delivered event {event} was_encrypted={enc} tier={tier:?} body={body:?}",
        event = msg.event_id,
        enc = msg.was_encrypted,
        tier = msg.tier,
    );
}

#[tokio::test]
#[ignore = "needs a live homeserver + network; see file header for setup"]
async fn e2ee_text_roundtrip_between_two_accounts() {
    let homeserver = env("POSTERN_MATRIX_TEST_HOMESERVER");

    // Two fresh devices (in-memory store: every run is a new device).
    let alice = MatrixMessenger::login_password(
        &homeserver,
        &env("POSTERN_MATRIX_TEST_USER_A"),
        &env("POSTERN_MATRIX_TEST_PASS_A"),
        "postern-live-test-a",
    )
    .await
    .expect("login A");
    let bob = MatrixMessenger::login_password(
        &homeserver,
        &env("POSTERN_MATRIX_TEST_USER_B"),
        &env("POSTERN_MATRIX_TEST_PASS_B"),
        "postern-live-test-b",
    )
    .await
    .expect("login B");
    let bob_user = bob.user_id().expect("B logged in").to_owned();

    // First sync uploads device keys / one-time keys for both devices.
    alice.sync_once().await.expect("initial sync A");
    bob.sync_once().await.expect("initial sync B");

    // Alice creates a PRIVATE, E2EE room and invites Bob — through the same
    // `create_encrypted_dm` production path the crate exposes (no separate
    // ad-hoc request built here; this is the exact `encrypted_dm_request`
    // shape proven offline in `crates/postern-messenger/src/matrix.rs`).
    let room_id = alice.create_encrypted_dm(&bob_user).await.expect("create E2EE DM room");

    // Bob sees the invite and joins.
    bob.sync_once().await.expect("sync B (invite)");
    let bob_room = bob.client().get_room(&room_id).expect("B sees the room");
    bob_room.join().await.expect("B joins");
    bob.sync_once().await.expect("sync B (joined)");
    alice.sync_once().await.expect("sync A (sees join)");

    // The room must classify as the INTERNAL tier for both sides.
    assert_eq!(alice.room_tier(&room_id).await.unwrap(), SecurityTier::InternalE2ee);
    assert_eq!(bob.room_tier(&room_id).await.unwrap(), SecurityTier::InternalE2ee);

    // Bob listens for decrypted messages.
    let received: Arc<Mutex<Vec<postern_messenger::matrix::ReceivedText>>> =
        Arc::new(Mutex::new(Vec::new()));
    let sink = received.clone();
    let _handle = bob.on_text_message(move |msg| sink.lock().unwrap().push(msg));

    // Alice sends through the tier-gated path. Under the hood the SDK queries
    // Bob's device keys, claims one-time keys, Olm-encrypts the Megolm room
    // key to Bob's device (m.room_key), and Megolm-encrypts the event.
    const BODY: &str = "postern phase-1 live slice: E2EE round-trip";
    let event_id = alice.send_text(&room_id, BODY).await.expect("E2EE send");

    // Bob syncs until the message lands (to-device key share + room event).
    let msg = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            bob.sync_once().await.expect("sync B (receive)");
            let hit = received
                .lock()
                .unwrap()
                .iter()
                .find(|m| m.event_id == event_id)
                .cloned();
            if let Some(m) = hit {
                return m;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .expect("Bob never received the message within 60s");

    assert_eq!(msg.body, BODY, "plaintext must round-trip intact");
    assert_eq!(msg.room_id, room_id);
    assert!(
        msg.was_encrypted,
        "the event MUST have arrived Megolm-encrypted (EncryptionInfo present) — \
         a plaintext delivery here is a hard failure"
    );
    assert_eq!(msg.tier, SecurityTier::InternalE2ee);
    eprintln!(
        "EVIDENCE[e2ee_roundtrip]: alice_device={a:?} bob_device={b:?} room={room} \
         event={event} was_encrypted={enc} tier={tier:?}",
        a = alice.device_id(),
        b = bob.device_id(),
        room = room_id,
        event = msg.event_id,
        enc = msg.was_encrypted,
        tier = msg.tier,
    );
}

/// Persistence + session-restore round-trip. See the file header (test 2 and
/// the HONEST STATUS section): this is the live proof that
/// `login_password_persistent` → `session()` → drop → `restore()` resumes
/// the SAME Matrix device with its Olm/Megolm state intact — UNPROVEN until
/// someone actually runs it against a homeserver.
#[tokio::test]
#[ignore = "needs a live homeserver + network; see file header for setup"]
async fn session_restore_resumes_same_device_and_megolm_state() {
    let homeserver = env("POSTERN_MATRIX_TEST_HOMESERVER");
    const STORE_PASSPHRASE: &str = "postern-live-test-store-passphrase";

    // Alice: PERSISTENT sqlite store in a tempdir that outlives the simulated
    // restart. Bob: plain in-memory login — his persistence is not under test.
    let store_dir = tempfile::TempDir::new().expect("tempdir for Alice's sqlite store");
    let alice = MatrixMessenger::login_password_persistent(
        &homeserver,
        &env("POSTERN_MATRIX_TEST_USER_A"),
        &env("POSTERN_MATRIX_TEST_PASS_A"),
        "postern-live-test-persist-a",
        store_dir.path(),
        STORE_PASSPHRASE,
    )
    .await
    .expect("persistent login A");
    let bob = MatrixMessenger::login_password(
        &homeserver,
        &env("POSTERN_MATRIX_TEST_USER_B"),
        &env("POSTERN_MATRIX_TEST_PASS_B"),
        "postern-live-test-persist-b",
    )
    .await
    .expect("login B");

    // Snapshot the session NOW — this is what a real app would persist
    // (encrypted at rest! see SavedSession's HONEST CAVEAT) and restore
    // after a process restart.
    let saved = alice.session().expect("logged in => session() must be Some");
    let original_device_id = saved.device_id.clone();
    assert_eq!(alice.device_id(), Some(original_device_id.as_ref()));

    // First sync uploads device keys / one-time keys for both devices.
    alice.sync_once().await.expect("initial sync A");
    bob.sync_once().await.expect("initial sync B");

    let room_id = create_dm_and_join(&alice, &bob).await;

    // Both sides listen for decrypted messages.
    let alice_inbox: Arc<Mutex<Vec<ReceivedText>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = alice_inbox.clone();
    let _alice_handle = alice.on_text_message(move |m| sink.lock().unwrap().push(m));
    let bob_inbox: Arc<Mutex<Vec<ReceivedText>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = bob_inbox.clone();
    let _bob_handle = bob.on_text_message(move |m| sink.lock().unwrap().push(m));

    // ---- E2EE round-trip 1, BEFORE the restart ----------------------------
    // A→B proves the encrypted path is up. B→A matters more for what follows:
    // it makes Bob establish an outbound Megolm session and Olm-share its key
    // with Alice's CURRENT device, so Alice's on-disk sqlite store now holds
    // the inbound Megolm session that the post-restart decryption depends on.
    assert_e2ee_delivery(
        &alice, &bob, &bob_inbox, &room_id,
        "persist test: A->B before restart",
        "pre-restart A->B",
    )
    .await;
    assert_e2ee_delivery(
        &bob, &alice, &alice_inbox, &room_id,
        "persist test: B->A before restart",
        "pre-restart B->A",
    )
    .await;

    // ---- "Process restart": drop the client, rebuild from SavedSession ----
    drop(alice);
    let alice = MatrixMessenger::restore(&homeserver, store_dir.path(), STORE_PASSPHRASE, saved)
        .await
        .expect("restore A from SavedSession + same sqlite store");

    // THE core persistence assertion: the SAME device came back. A fresh
    // device_id here would mean fresh device keys — i.e. the store silently
    // did nothing and every peer would have to re-verify Alice.
    assert_eq!(
        alice.device_id(),
        Some(original_device_id.as_ref()),
        "restore() must resume the SAME Matrix device (no fresh device keys)"
    );
    eprintln!(
        "EVIDENCE[session_restore]: original_device={orig} post_restore_device={now:?} same={same}",
        orig = original_device_id,
        now = alice.device_id(),
        same = alice.device_id() == Some(original_device_id.as_ref()),
    );

    // Fresh client object => re-register Alice's receive handler, then let
    // her catch up from the persisted sync token.
    let alice_inbox2: Arc<Mutex<Vec<ReceivedText>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = alice_inbox2.clone();
    let _alice_handle2 = alice.on_text_message(move |m| sink.lock().unwrap().push(m));
    alice.sync_once().await.expect("sync A (post-restore catch-up)");

    // ---- E2EE round-trip 2, AFTER the restart ------------------------------
    // B→A first, and it is the sharp edge: Bob keeps using the outbound
    // Megolm session he created BEFORE the restart, and — same device_id,
    // already shared — does not re-send the room key. Decrypting this message
    // therefore proves Alice's inbound Megolm session really survived on
    // disk, not that a fresh key share papered over a wiped store.
    assert_e2ee_delivery(
        &bob, &alice, &alice_inbox2, &room_id,
        "persist test: B->A after restart (pre-restart Megolm session)",
        "post-restart B->A",
    )
    .await;

    // And A→B: the restored client still sends through the tier-gated path.
    assert_e2ee_delivery(
        &alice, &bob, &bob_inbox, &room_id,
        "persist test: A->B after restart",
        "post-restart A->B",
    )
    .await;
}
