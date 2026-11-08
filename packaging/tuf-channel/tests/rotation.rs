// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Integration tests for root rotation (TUF spec 5.3.4) and the
// snapshot/timestamp refresh operation of the DEV-ONLY TUF scaffold:
//
//   1. Roll-forward: a client still pinned to 1.root.json accepts the
//      dual-signed 2.root.json and verify-target succeeds.
//   2. Fail closed: a 2.root.json carrying ONLY the new key's signature
//      (the old root never blessed it) is REJECTED by that client.
//   3. Refresh bumps snapshot/timestamp versions (targets.json preserved
//      BYTE-FOR-BYTE, pinning the doc claim) and verification still passes.
//   4. Two consecutive rotations chain 1 → 2 → 3 and still verify.
//   5. Crash recovery: a rotation interrupted between writing N+1.root.json
//      and swapping the key files self-heals on the next rotate_root run.
//   6. A stray staged key that no written root ever blessed is discarded and
//      rotation proceeds normally.
//   7. Refresh cannot rescue a repo whose timestamp already expired — the
//      whole load fails closed (the documented "dev repo rots" behaviour).
//
// Everything runs in tempdirs with freshly generated throwaway dev keys.
// HONESTY: this is a LOCAL exercise of the TUF rotation/refresh rules —
// NOT a key ceremony, NOT a custody plan, UNAUDITED, no live update
// endpoint exists, and nothing signed here may ever ship to a user.

use std::path::Path;

const FIXTURE_NAME: &str = "postern-app-0.0.0-dev.bin";
const FIXTURE_BYTES: &[u8] = b"postern dev bundle fixture - NOT a real artifact\n";

/// init + add one fixture target, so the repo has something to verify.
async fn init_with_fixture(repo_dir: &Path) {
    postern_tuf::init_repo(repo_dir).await.expect("init_repo");
    let fixture = repo_dir.join(FIXTURE_NAME);
    std::fs::write(&fixture, FIXTURE_BYTES).expect("write fixture");
    postern_tuf::add_target(repo_dir, &fixture)
        .await
        .expect("add_target");
}

/// The keyid the root role of `<version>.root.json` trusts (single-key dev
/// scaffold: exactly one).
fn root_keyid(repo_dir: &Path, version: u64) -> String {
    let path = repo_dir
        .join("metadata")
        .join(format!("{version}.root.json"));
    let value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("read root.json"))
            .expect("parse root.json");
    let keyids = value["signed"]["roles"]["root"]["keyids"]
        .as_array()
        .expect("root role keyids");
    assert_eq!(keyids.len(), 1, "dev scaffold has exactly one root keyid");
    keyids[0].as_str().expect("keyid string").to_string()
}

/// (1) Rotation roll-forward: the client's trust anchor stays 1.root.json
/// (that is what load_repo/verify_target pin), and it must walk forward to
/// the dual-signed 2.root.json and still verify the target.
#[tokio::test(flavor = "current_thread")]
async fn client_pinned_to_root_v1_rolls_forward_through_rotation() {
    let repo_dir = tempfile::tempdir().expect("tempdir");
    let out_dir = tempfile::tempdir().expect("tempdir");
    init_with_fixture(repo_dir.path()).await;

    let keyid_v1 = root_keyid(repo_dir.path(), 1);
    let rotation = postern_tuf::rotate_root(repo_dir.path())
        .await
        .expect("rotate_root");
    assert_eq!(rotation.new_version, 2);
    assert!(rotation.new_root_json.ends_with("2.root.json"));
    assert!(rotation.new_root_json.exists(), "2.root.json written");
    assert!(
        repo_dir.path().join("metadata").join("1.root.json").exists(),
        "1.root.json (the pinned trust anchor) must stay in place"
    );

    // Old key file retired under a `.retired` name; a fresh key installed.
    assert!(rotation.retired_key.exists(), "retired key file kept");
    assert!(rotation
        .retired_key
        .to_str()
        .expect("utf-8 path")
        .ends_with(".retired"));
    let live_key = repo_dir
        .path()
        .join("dev-keys-DO-NOT-SHIP")
        .join("root.pkcs8.der");
    assert!(live_key.exists(), "new root dev key installed");
    assert_ne!(
        std::fs::read(&live_key).expect("new key bytes"),
        std::fs::read(&rotation.retired_key).expect("old key bytes"),
        "rotation must actually change the root key"
    );

    // The root keyid really rotated, and 2.root.json carries BOTH signatures
    // (TUF spec 5.3.4 dual requirement).
    let keyid_v2 = root_keyid(repo_dir.path(), 2);
    assert_ne!(keyid_v1, keyid_v2, "root keyid must change");
    let v2: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&rotation.new_root_json).expect("read v2"))
            .expect("parse v2");
    let sig_keyids: Vec<&str> = v2["signatures"]
        .as_array()
        .expect("signatures")
        .iter()
        .map(|s| s["keyid"].as_str().expect("keyid"))
        .collect();
    assert_eq!(sig_keyids.len(), 2, "dual-signed: old + new root key");
    assert!(sig_keyids.contains(&keyid_v1.as_str()));
    assert!(sig_keyids.contains(&keyid_v2.as_str()));

    // Client pinned to 1.root.json rolls forward and the target verifies.
    let repo = postern_tuf::load_repo(repo_dir.path())
        .await
        .expect("load after rotation");
    assert_eq!(repo.root().signed.version.get(), 2, "trusted root is now v2");
    postern_tuf::verify_target(repo_dir.path(), FIXTURE_NAME, out_dir.path())
        .await
        .expect("verify-target must succeed after rotation");
}

/// (2) Unauthorized rotation fails closed: strip the OLD key's signature
/// from 2.root.json (leaving only the new key's), and the client pinned to
/// 1.root.json must reject it — spec 5.3.4 requires a threshold of the
/// TRUSTED root's keys, and the old root never blessed this new one.
#[tokio::test(flavor = "current_thread")]
async fn root_v2_signed_only_by_new_key_is_rejected() {
    let repo_dir = tempfile::tempdir().expect("tempdir");
    let out_dir = tempfile::tempdir().expect("tempdir");
    init_with_fixture(repo_dir.path()).await;

    let rotation = postern_tuf::rotate_root(repo_dir.path())
        .await
        .expect("rotate_root");

    // Sanity: the honest dual-signed rotation verifies.
    postern_tuf::verify_target(repo_dir.path(), FIXTURE_NAME, out_dir.path())
        .await
        .expect("verify before stripping the old signature");

    // Strip the old (v1-trusted) key's signature from 2.root.json.
    let old_keyid = root_keyid(repo_dir.path(), 1);
    let mut v2: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&rotation.new_root_json).expect("read v2"))
            .expect("parse v2");
    let sigs = v2["signatures"].as_array_mut().expect("signatures");
    let before = sigs.len();
    sigs.retain(|s| s["keyid"].as_str() != Some(old_keyid.as_str()));
    assert_eq!(before - sigs.len(), 1, "exactly the old-key sig removed");
    assert_eq!(sigs.len(), 1, "only the new key's signature remains");
    std::fs::write(
        &rotation.new_root_json,
        serde_json::to_vec_pretty(&v2).expect("serialize"),
    )
    .expect("write stripped 2.root.json");

    // The client pinned to 1.root.json MUST reject the update — fail closed.
    assert!(
        postern_tuf::load_repo(repo_dir.path()).await.is_err(),
        "root v2 without the old key's signature MUST be rejected"
    );
    assert!(
        postern_tuf::verify_target(repo_dir.path(), FIXTURE_NAME, out_dir.path())
            .await
            .is_err(),
        "verify-target MUST fail when the rotation is unauthorized"
    );
}

/// (3) Refresh bumps snapshot + timestamp versions, preserves targets.json
/// BYTE-FOR-BYTE (same version, same expiry, deterministic ed25519 signature
/// — the documented claim, pinned here so a `tough` upgrade that breaks it
/// fails a test), and the repository still verifies end to end.
#[tokio::test(flavor = "current_thread")]
async fn refresh_bumps_versions_and_still_verifies() {
    let repo_dir = tempfile::tempdir().expect("tempdir");
    let out_dir = tempfile::tempdir().expect("tempdir");
    init_with_fixture(repo_dir.path()).await;

    let before = postern_tuf::load_repo(repo_dir.path())
        .await
        .expect("load before refresh");
    let snapshot_before = before.snapshot().signed.version.get();
    let timestamp_before = before.timestamp().signed.version.get();
    let targets_before = before.targets().signed.version.get();
    drop(before);
    let targets_json = repo_dir.path().join("metadata").join("targets.json");
    let targets_bytes_before = std::fs::read(&targets_json).expect("read targets.json before");

    let (snapshot_after, timestamp_after) = postern_tuf::refresh(repo_dir.path())
        .await
        .expect("refresh");
    assert_eq!(snapshot_after, snapshot_before + 1, "snapshot bumped");
    assert_eq!(timestamp_after, timestamp_before + 1, "timestamp bumped");

    let after = postern_tuf::load_repo(repo_dir.path())
        .await
        .expect("load after refresh");
    assert_eq!(after.snapshot().signed.version.get(), snapshot_after);
    assert_eq!(after.timestamp().signed.version.get(), timestamp_after);
    assert_eq!(
        after.targets().signed.version.get(),
        targets_before,
        "refresh must not touch targets"
    );
    assert_eq!(
        std::fs::read(&targets_json).expect("read targets.json after"),
        targets_bytes_before,
        "refresh must preserve targets.json BYTE-FOR-BYTE"
    );

    postern_tuf::verify_target(repo_dir.path(), FIXTURE_NAME, out_dir.path())
        .await
        .expect("verify-target must succeed after refresh");
}

/// (4) Two consecutive rotations chain 1 → 2 → 3: the client pinned to
/// 1.root.json walks the whole chain, and refresh still works under the
/// twice-rotated root.
#[tokio::test(flavor = "current_thread")]
async fn two_rotations_chain_and_refresh_still_verifies() {
    let repo_dir = tempfile::tempdir().expect("tempdir");
    let out_dir = tempfile::tempdir().expect("tempdir");
    init_with_fixture(repo_dir.path()).await;

    let first = postern_tuf::rotate_root(repo_dir.path())
        .await
        .expect("first rotation");
    assert_eq!(first.new_version, 2);
    let second = postern_tuf::rotate_root(repo_dir.path())
        .await
        .expect("second rotation");
    assert_eq!(second.new_version, 3);
    assert_ne!(first.retired_key, second.retired_key);
    assert!(first.retired_key.exists() && second.retired_key.exists());

    let repo = postern_tuf::load_repo(repo_dir.path())
        .await
        .expect("load after two rotations");
    assert_eq!(repo.root().signed.version.get(), 3);
    drop(repo);

    postern_tuf::refresh(repo_dir.path())
        .await
        .expect("refresh under rotated root");
    postern_tuf::verify_target(repo_dir.path(), FIXTURE_NAME, out_dir.path())
        .await
        .expect("verify-target after two rotations + refresh");
}

/// (5) Crash recovery: reproduce the exact on-disk state of a rotation that
/// died AFTER writing 2.root.json but BEFORE swapping the key files (trusted
/// root is v2, old key still installed, incoming key still staged). The next
/// rotate_root must self-heal — finish the v2 key install, then perform the
/// requested rotation to v3 — with no manual key-file surgery.
#[tokio::test(flavor = "current_thread")]
async fn interrupted_rotation_key_swap_self_heals_on_next_rotate() {
    let repo_dir = tempfile::tempdir().expect("tempdir");
    let out_dir = tempfile::tempdir().expect("tempdir");
    init_with_fixture(repo_dir.path()).await;

    let first = postern_tuf::rotate_root(repo_dir.path())
        .await
        .expect("first rotation");
    assert_eq!(first.new_version, 2);

    // Undo the key swap to reconstruct the crash window: the new key goes
    // back to its staged name, the old (v1) key is reinstalled.
    let keys_dir = repo_dir.path().join(postern_tuf::DEV_KEYS_DIR);
    let live_key = keys_dir.join("root.pkcs8.der");
    let staged_key = keys_dir.join(postern_tuf::STAGED_ROOT_KEY);
    std::fs::rename(&live_key, &staged_key).expect("re-stage the incoming key");
    std::fs::rename(&first.retired_key, &live_key).expect("reinstall the outgoing key");

    // Without recovery this state is stuck: the trusted root is v2 but the
    // installed key is v1's, which the authorization guard rejects. The next
    // rotate_root must repair it and then rotate to v3.
    let second = postern_tuf::rotate_root(repo_dir.path())
        .await
        .expect("rotate_root must self-heal the interrupted swap");
    assert_eq!(second.new_version, 3);
    assert!(!staged_key.exists(), "staged key consumed by recovery");
    assert!(
        keys_dir.join("root.v1.pkcs8.der.retired").exists(),
        "stale v1 key retired by crash recovery"
    );
    assert!(
        keys_dir.join("root.v2.pkcs8.der.retired").exists(),
        "v2 key retired by the new rotation"
    );

    let repo = postern_tuf::load_repo(repo_dir.path())
        .await
        .expect("load after self-healed rotation");
    assert_eq!(repo.root().signed.version.get(), 3);
    drop(repo);
    postern_tuf::verify_target(repo_dir.path(), FIXTURE_NAME, out_dir.path())
        .await
        .expect("verify-target after self-healed rotation");
}

/// (6) A stray staged key that NO written root ever blessed (the crash
/// happened before the rotated root was written, or the file is junk from
/// elsewhere) is discarded and the requested rotation proceeds normally.
#[tokio::test(flavor = "current_thread")]
async fn stray_unblessed_staged_key_is_discarded() {
    let repo_dir = tempfile::tempdir().expect("tempdir");
    let out_dir = tempfile::tempdir().expect("tempdir");
    init_with_fixture(repo_dir.path()).await;

    // A perfectly valid ed25519 key that this repo's roots never authorized:
    // borrow the root dev key of a SECOND, unrelated dev repo.
    let other_repo = tempfile::tempdir().expect("tempdir");
    postern_tuf::init_repo(other_repo.path())
        .await
        .expect("init other repo");
    let staged_key = repo_dir
        .path()
        .join(postern_tuf::DEV_KEYS_DIR)
        .join(postern_tuf::STAGED_ROOT_KEY);
    std::fs::copy(
        other_repo
            .path()
            .join(postern_tuf::DEV_KEYS_DIR)
            .join("root.pkcs8.der"),
        &staged_key,
    )
    .expect("plant stray staged key");

    let rotation = postern_tuf::rotate_root(repo_dir.path())
        .await
        .expect("rotation must proceed past a never-blessed staged key");
    assert_eq!(rotation.new_version, 2);
    assert!(!staged_key.exists(), "stray staged key discarded");
    postern_tuf::verify_target(repo_dir.path(), FIXTURE_NAME, out_dir.path())
        .await
        .expect("verify-target after rotation");
}

/// (7) Refresh cannot rescue an already-expired repo: once timestamp lapses,
/// load_repo fails closed and refresh/verify error out. This pins the
/// documented behaviour that a quiet dev repo ROTS (recovery = re-init) —
/// refresh is anti-staleness maintenance, not resurrection.
#[tokio::test(flavor = "current_thread")]
async fn refresh_cannot_rescue_expired_metadata() {
    let repo_dir = tempfile::tempdir().expect("tempdir");
    let out_dir = tempfile::tempdir().expect("tempdir");
    init_with_fixture(repo_dir.path()).await;

    // Re-sign timestamp with an expiry one hour in the PAST, using the
    // repo's own dev keys — the legitimate signer producing stale metadata
    // (signatures stay valid; only the expiry lapses).
    let repo = postern_tuf::load_repo(repo_dir.path())
        .await
        .expect("load while still fresh");
    let targets_version = repo.targets().signed.version;
    let targets_expires = repo.targets().signed.expires;
    let snapshot_version = repo.snapshot().signed.version;
    let snapshot_expires = repo.snapshot().signed.expires;
    let next_timestamp = repo.timestamp().signed.version.get() + 1;
    let root_json = repo_dir.path().join("metadata").join("1.root.json");
    let mut editor = tough::editor::RepositoryEditor::from_repo(&root_json, repo)
        .await
        .expect("editor");
    let past = jiff::Timestamp::from_second(jiff::Timestamp::now().as_second() - 3600)
        .expect("past timestamp");
    editor
        .targets_version(targets_version)
        .expect("targets version")
        .targets_expires(targets_expires)
        .expect("targets expiry")
        .snapshot_version(snapshot_version)
        .snapshot_expires(snapshot_expires)
        .timestamp_version(std::num::NonZeroU64::new(next_timestamp).expect("nonzero"))
        .timestamp_expires(past);
    let keys_dir = repo_dir.path().join(postern_tuf::DEV_KEYS_DIR);
    let key_sources: Vec<Box<dyn tough::key_source::KeySource>> =
        ["root", "targets", "snapshot", "timestamp"]
            .iter()
            .map(|role| {
                Box::new(tough::key_source::LocalKeySource {
                    path: keys_dir.join(format!("{role}.pkcs8.der")),
                }) as Box<dyn tough::key_source::KeySource>
            })
            .collect();
    let signed = editor.sign(&key_sources).await.expect("sign stale metadata");
    signed
        .write(repo_dir.path().join("metadata"))
        .await
        .expect("write stale metadata");

    // Everything must now fail closed — including refresh itself.
    assert!(
        postern_tuf::load_repo(repo_dir.path()).await.is_err(),
        "expired timestamp must fail the load, closed"
    );
    assert!(
        postern_tuf::refresh(repo_dir.path()).await.is_err(),
        "refresh must NOT be able to rescue an expired repo"
    );
    assert!(
        postern_tuf::verify_target(repo_dir.path(), FIXTURE_NAME, out_dir.path())
            .await
            .is_err(),
        "verify-target must fail on an expired repo"
    );
}
