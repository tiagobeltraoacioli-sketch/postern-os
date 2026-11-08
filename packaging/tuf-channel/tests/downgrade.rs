// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Rollback / downgrade-protection tests for the DEV-ONLY TUF update-channel
// scaffold. `tests/rotation.rs` proves the roll-FORWARD + refresh rules; this
// file proves the fail-closed rules that stop a client being walked BACKWARD:
//
//   1. Rolled-back snapshot: replaying an OLDER, validly-signed snapshot.json
//      over the current one is rejected — the live timestamp attests a higher
//      snapshot version+hash, so the stale one no longer lines up.
//   2. Rolled-back timestamp: replaying an OLDER timestamp.json is rejected for
//      the mirror reason — it attests a snapshot version+hash the repo has
//      already moved past.
//   3. Expired channel metadata: a timestamp re-signed (with the repo's OWN
//      dev keys) to an expiry in the PAST is rejected — a lapsed channel is a
//      hard error, never a stale-but-trusted warning.
//   4. Wrong-key-signed metadata: a timestamp.json signed by a DIFFERENT repo's
//      dev key — one this root never authorized — is rejected.
//
// TUF has no cross-session memory here (load_repo re-bootstraps from root every
// call), so these exercise the INTRA-repo rollback bindings TUF pins on a
// single fail-closed load: timestamp -> snapshot -> targets version+hash, plus
// expiry and root-authorized signer checks.
//
// Everything runs in tempdirs with freshly generated throwaway dev keys.
// HONESTY: a LOCAL exercise of the TUF rollback/expiry rules — NOT a key
// ceremony, NOT a custody plan, UNAUDITED, no live update endpoint exists, and
// nothing signed here may ever ship to a user.

use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

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

/// Path of a metadata file inside a repo dir.
fn metadata(repo_dir: &Path, name: &str) -> PathBuf {
    repo_dir.join("metadata").join(name)
}

/// The `[root, targets, snapshot, timestamp]` dev-key sources for `keys_dir` —
/// the same fixed role order the crate's own `key_sources()` uses (mirrored
/// here because it is private). Used to re-sign metadata with the repo's OWN
/// keys for the expired-metadata case.
fn key_sources(keys_dir: &Path) -> Vec<Box<dyn tough::key_source::KeySource>> {
    ["root", "targets", "snapshot", "timestamp"]
        .iter()
        .map(|role| {
            Box::new(tough::key_source::LocalKeySource {
                path: keys_dir.join(format!("{role}.pkcs8.der")),
            }) as Box<dyn tough::key_source::KeySource>
        })
        .collect()
}

/// (1) Rolled-back snapshot: keep the current (refreshed) timestamp but restore
/// an OLDER snapshot.json underneath it. The timestamp attests the newer
/// snapshot's version+hash, so the stale snapshot is rejected — fail closed.
#[tokio::test(flavor = "current_thread")]
async fn rolled_back_snapshot_is_rejected() {
    let repo_dir = tempfile::tempdir().expect("tempdir");
    let out_dir = tempfile::tempdir().expect("tempdir");
    init_with_fixture(repo_dir.path()).await;

    // Snapshot the OLD (v2) snapshot.json before it is bumped.
    let snapshot_path = metadata(repo_dir.path(), "snapshot.json");
    let old_snapshot = std::fs::read(&snapshot_path).expect("read old snapshot.json");

    // Move the channel forward: snapshot + timestamp both bump to v3.
    postern_tuf::refresh(repo_dir.path()).await.expect("refresh");
    // Sanity: the forward state verifies.
    postern_tuf::verify_target(repo_dir.path(), FIXTURE_NAME, out_dir.path())
        .await
        .expect("verify before rollback");

    // Roll the snapshot BACK to v2 while the timestamp stays at v3.
    std::fs::write(&snapshot_path, &old_snapshot).expect("replay old snapshot.json");

    assert!(
        postern_tuf::load_repo(repo_dir.path()).await.is_err(),
        "a rolled-back snapshot MUST be rejected (fail closed)"
    );
    assert!(
        postern_tuf::verify_target(repo_dir.path(), FIXTURE_NAME, out_dir.path())
            .await
            .is_err(),
        "verify-target MUST fail against a rolled-back snapshot"
    );
}

/// (2) Rolled-back timestamp: restore an OLDER timestamp.json over the current
/// one. The stale timestamp attests a snapshot version+hash the repo has since
/// moved past, so it is rejected — fail closed.
#[tokio::test(flavor = "current_thread")]
async fn rolled_back_timestamp_is_rejected() {
    let repo_dir = tempfile::tempdir().expect("tempdir");
    let out_dir = tempfile::tempdir().expect("tempdir");
    init_with_fixture(repo_dir.path()).await;

    let timestamp_path = metadata(repo_dir.path(), "timestamp.json");
    let old_timestamp = std::fs::read(&timestamp_path).expect("read old timestamp.json");

    postern_tuf::refresh(repo_dir.path()).await.expect("refresh");
    postern_tuf::verify_target(repo_dir.path(), FIXTURE_NAME, out_dir.path())
        .await
        .expect("verify before rollback");

    // Replay the v2 timestamp on top of the v3 repo.
    std::fs::write(&timestamp_path, &old_timestamp).expect("replay old timestamp.json");

    assert!(
        postern_tuf::load_repo(repo_dir.path()).await.is_err(),
        "a rolled-back timestamp MUST be rejected (fail closed)"
    );
    assert!(
        postern_tuf::verify_target(repo_dir.path(), FIXTURE_NAME, out_dir.path())
            .await
            .is_err(),
        "verify-target MUST fail against a rolled-back timestamp"
    );
}

/// (3) Expired channel metadata: re-sign timestamp with the repo's OWN dev keys
/// but an expiry one hour in the PAST (signatures valid, only the clock lapses).
/// tough's Safe expiration enforcement must reject the whole load — a lapsed
/// channel is a hard error, not a stale-but-trusted warning.
#[tokio::test(flavor = "current_thread")]
async fn expired_channel_metadata_is_rejected() {
    let repo_dir = tempfile::tempdir().expect("tempdir");
    let out_dir = tempfile::tempdir().expect("tempdir");
    init_with_fixture(repo_dir.path()).await;

    let repo = postern_tuf::load_repo(repo_dir.path())
        .await
        .expect("load while still fresh");
    let targets_version = repo.targets().signed.version;
    let targets_expires = repo.targets().signed.expires;
    let snapshot_version = repo.snapshot().signed.version;
    let snapshot_expires = repo.snapshot().signed.expires;
    let next_timestamp = repo.timestamp().signed.version.get() + 1;

    let root_json = metadata(repo_dir.path(), "1.root.json");
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
        .timestamp_version(NonZeroU64::new(next_timestamp).expect("nonzero"))
        .timestamp_expires(past);
    let keys_dir = repo_dir.path().join(postern_tuf::DEV_KEYS_DIR);
    let signed = editor
        .sign(&key_sources(&keys_dir))
        .await
        .expect("sign stale metadata");
    signed
        .write(repo_dir.path().join("metadata"))
        .await
        .expect("write stale metadata");

    assert!(
        postern_tuf::load_repo(repo_dir.path()).await.is_err(),
        "expired timestamp MUST fail the load, closed"
    );
    assert!(
        postern_tuf::verify_target(repo_dir.path(), FIXTURE_NAME, out_dir.path())
            .await
            .is_err(),
        "verify-target MUST fail on an expired channel"
    );
}

/// (4) Wrong-key-signed metadata: overwrite this repo's timestamp.json with one
/// from a SECOND, independent dev repo — validly signed, but by a timestamp key
/// this root never authorized. tough must reject it on the signature check.
#[tokio::test(flavor = "current_thread")]
async fn wrong_key_signed_timestamp_is_rejected() {
    let repo_dir = tempfile::tempdir().expect("tempdir");
    let out_dir = tempfile::tempdir().expect("tempdir");
    init_with_fixture(repo_dir.path()).await;

    // Sanity: honest repo verifies.
    postern_tuf::verify_target(repo_dir.path(), FIXTURE_NAME, out_dir.path())
        .await
        .expect("verify honest repo");

    // A second, unrelated dev repo with its OWN freshly generated keys.
    let other_repo = tempfile::tempdir().expect("tempdir");
    postern_tuf::init_repo(other_repo.path())
        .await
        .expect("init other repo");

    // Its timestamp.json is validly signed — by a key our root does not trust.
    let foreign_timestamp =
        std::fs::read(metadata(other_repo.path(), "timestamp.json")).expect("read foreign ts");
    std::fs::write(metadata(repo_dir.path(), "timestamp.json"), &foreign_timestamp)
        .expect("plant wrong-key timestamp.json");

    assert!(
        postern_tuf::load_repo(repo_dir.path()).await.is_err(),
        "timestamp signed by an unauthorized key MUST be rejected (fail closed)"
    );
    assert!(
        postern_tuf::verify_target(repo_dir.path(), FIXTURE_NAME, out_dir.path())
            .await
            .is_err(),
        "verify-target MUST fail against wrong-key-signed metadata"
    );
}
