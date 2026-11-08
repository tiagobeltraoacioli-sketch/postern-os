// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Integration tests for the designed lapse-recovery rule (`recover`) of the
// DEV-ONLY TUF scaffold — the recovery/re-init story the roadmap demands:
//
//   1. Honest recovery: init → add-target → force-lapse snapshot/timestamp
//      (the same legit-keys/past-expiry manipulation tests/rotation.rs uses)
//      → refresh still FAILS (the refresh/recover boundary, asserted from
//      both sides: recover also refuses a still-fresh repo) → recover
//      succeeds → verify succeeds, with targets.json preserved byte-for-byte.
//   2. Fail closed: a tampered targets.json makes recover a hard error (its
//      signature no longer verifies against the trusted root's targets key).
//   3. Fail closed: a tampered (same-length) target artifact fails the
//      recorded-hash re-check before anything is re-signed.
//   4. Fail closed: a resized target artifact fails the recorded-length
//      re-check before anything is re-signed.
//   5. Fail closed: an EXPIRED root is a hard error directing the operator
//      to full re-init — recovery never resurrects trust it cannot re-derive
//      from still-valid root metadata.
//   6. Fail closed: a missing snapshot signing key is a hard error (key loss
//      means re-init, not improvisation).
//   7. Fail closed: a file under targets/ that targets.json never recorded
//      is a hard error (an unlisted artifact is what tampering looks like).
//
// Everything runs in tempdirs with freshly generated throwaway dev keys.
// HONESTY: this is a LOCAL exercise of the recovery RULE — NOT an operated
// channel, UNAUDITED, no live update endpoint exists, and nothing signed
// here may ever ship to a user.

use std::num::NonZeroU64;
use std::path::Path;

use tough::sign::Sign as _;

const FIXTURE_NAME: &str = "postern-app-0.0.0-dev.bin";
const FIXTURE_BYTES: &[u8] = b"postern dev bundle fixture - NOT a real artifact\n";

/// init + add one fixture target, so the repo has something to recover.
async fn init_with_fixture(repo_dir: &Path) {
    postern_tuf::init_repo(repo_dir).await.expect("init_repo");
    let fixture = repo_dir.join(FIXTURE_NAME);
    std::fs::write(&fixture, FIXTURE_BYTES).expect("write fixture");
    postern_tuf::add_target(repo_dir, &fixture)
        .await
        .expect("add_target");
}

fn key_sources(repo_dir: &Path) -> Vec<Box<dyn tough::key_source::KeySource>> {
    let keys_dir = repo_dir.join(postern_tuf::DEV_KEYS_DIR);
    ["root", "targets", "snapshot", "timestamp"]
        .iter()
        .map(|role| {
            Box::new(tough::key_source::LocalKeySource {
                path: keys_dir.join(format!("{role}.pkcs8.der")),
            }) as Box<dyn tough::key_source::KeySource>
        })
        .collect()
}

fn past_timestamp() -> jiff::Timestamp {
    jiff::Timestamp::from_second(jiff::Timestamp::now().as_second() - 3600)
        .expect("past timestamp")
}

/// Force the LAPSE recover exists for: re-sign snapshot + timestamp with
/// expiries one hour in the PAST, using the repo's own dev keys — the
/// legitimate signer going quiet (signatures stay valid; only the expiries
/// lapse). Same expiry-manipulation approach as tests/rotation.rs.
async fn force_lapse(repo_dir: &Path) {
    let repo = postern_tuf::load_repo(repo_dir)
        .await
        .expect("load while still fresh");
    let targets_version = repo.targets().signed.version;
    let targets_expires = repo.targets().signed.expires;
    let next_snapshot = repo.snapshot().signed.version.get() + 1;
    let next_timestamp = repo.timestamp().signed.version.get() + 1;
    let root_json = repo_dir.join("metadata").join("1.root.json");
    let mut editor = tough::editor::RepositoryEditor::from_repo(&root_json, repo)
        .await
        .expect("editor");
    editor
        .targets_version(targets_version)
        .expect("targets version")
        .targets_expires(targets_expires)
        .expect("targets expiry")
        .snapshot_version(NonZeroU64::new(next_snapshot).expect("nonzero"))
        .snapshot_expires(past_timestamp())
        .timestamp_version(NonZeroU64::new(next_timestamp).expect("nonzero"))
        .timestamp_expires(past_timestamp());
    let signed = editor
        .sign(&key_sources(repo_dir))
        .await
        .expect("sign lapsed metadata");
    signed
        .write(repo_dir.join("metadata"))
        .await
        .expect("write lapsed metadata");

    // Sanity: the repo is now genuinely lapsed — the fail-closed load rejects it.
    assert!(
        postern_tuf::load_repo(repo_dir).await.is_err(),
        "force_lapse must leave a repo the client rejects"
    );
}

/// (1) The honest recovery round trip, plus the refresh/recover boundary
/// asserted from BOTH sides.
#[tokio::test(flavor = "current_thread")]
async fn recover_rescues_lapsed_repo_and_verify_succeeds() {
    let repo_dir = tempfile::tempdir().expect("tempdir");
    let out_dir = tempfile::tempdir().expect("tempdir");
    init_with_fixture(repo_dir.path()).await;

    // Boundary, side 1: a repo that still verifies is NOT recover's job.
    assert!(
        postern_tuf::recover(repo_dir.path()).await.is_err(),
        "recover must refuse a repo that still verifies (that is refresh's job)"
    );

    force_lapse(repo_dir.path()).await;
    let targets_json = repo_dir.path().join("metadata").join("targets.json");
    let targets_bytes_before = std::fs::read(&targets_json).expect("targets.json before");

    // Boundary, side 2: refresh must still fail on the lapsed repo — the
    // documented fail-closed rule is kept, not blurred.
    assert!(
        postern_tuf::refresh(repo_dir.path()).await.is_err(),
        "refresh must NOT be able to rescue a lapsed repo"
    );

    let recovery = postern_tuf::recover(repo_dir.path())
        .await
        .expect("recover must rescue a lapsed repo with a still-valid root");
    assert_eq!(recovery.root_version, 1);
    assert_eq!(recovery.targets_checked, 1, "the one fixture was re-hashed");
    // init v1 → add_target v2 → force_lapse v3 → recover bumps past them.
    assert_eq!(recovery.snapshot_version, 4);
    assert_eq!(recovery.timestamp_version, 4);

    // The recovered repo verifies through the full fail-closed client path,
    // and recovery re-signed FRESHNESS only: targets.json is byte-identical.
    let repo = postern_tuf::load_repo(repo_dir.path())
        .await
        .expect("load after recover");
    assert_eq!(repo.snapshot().signed.version.get(), 4);
    assert_eq!(repo.timestamp().signed.version.get(), 4);
    drop(repo);
    assert_eq!(
        std::fs::read(&targets_json).expect("targets.json after"),
        targets_bytes_before,
        "recover must preserve targets.json BYTE-FOR-BYTE"
    );
    postern_tuf::verify_target(repo_dir.path(), FIXTURE_NAME, out_dir.path())
        .await
        .expect("verify-target must succeed after recover");

    // And a recovered repo is a fresh repo again: refresh works.
    postern_tuf::refresh(repo_dir.path())
        .await
        .expect("refresh must work again after recover");
}

/// (2) A tampered targets.json fails recover closed: its signature no longer
/// verifies against the trusted root's targets key, and recovery never
/// re-signs content it cannot re-verify.
#[tokio::test(flavor = "current_thread")]
async fn recover_fails_closed_on_tampered_targets_metadata() {
    let repo_dir = tempfile::tempdir().expect("tempdir");
    init_with_fixture(repo_dir.path()).await;
    force_lapse(repo_dir.path()).await;

    // Flip the artifact length recorded in targets.json — still valid JSON,
    // no longer what the targets key signed (same tamper as tests/roundtrip.rs).
    let targets_path = repo_dir.path().join("metadata").join("targets.json");
    let metadata = std::fs::read_to_string(&targets_path).expect("read targets.json");
    let honest_len = format!("\"length\": {}", FIXTURE_BYTES.len());
    assert!(metadata.contains(&honest_len), "test setup: length field");
    std::fs::write(&targets_path, metadata.replace(&honest_len, "\"length\": 999999"))
        .expect("write tampered targets.json");

    let err = postern_tuf::recover(repo_dir.path())
        .await
        .expect_err("recover MUST fail on a tampered targets.json");
    assert!(
        format!("{err:#}").contains("targets.json signature"),
        "error must name the failed targets signature check, got: {err:#}"
    );
}

/// (3) A tampered target artifact (same length, different bytes) fails the
/// recorded-hash re-check before anything is re-signed.
#[tokio::test(flavor = "current_thread")]
async fn recover_fails_closed_on_tampered_artifact() {
    let repo_dir = tempfile::tempdir().expect("tempdir");
    init_with_fixture(repo_dir.path()).await;
    force_lapse(repo_dir.path()).await;

    let served = repo_dir.path().join("targets").join(FIXTURE_NAME);
    let mut evil = FIXTURE_BYTES.to_vec();
    evil[0] ^= 0xFF;
    std::fs::write(&served, &evil).expect("write tampered artifact");

    let err = postern_tuf::recover(repo_dir.path())
        .await
        .expect_err("recover MUST fail on a tampered artifact");
    assert!(
        format!("{err:#}").contains("SHA-256 mismatch"),
        "error must name the hash mismatch, got: {err:#}"
    );
    // Nothing was re-signed: the repo still fails the client load.
    assert!(postern_tuf::load_repo(repo_dir.path()).await.is_err());
}

/// (4) A resized target artifact fails the recorded-length re-check.
#[tokio::test(flavor = "current_thread")]
async fn recover_fails_closed_on_resized_artifact() {
    let repo_dir = tempfile::tempdir().expect("tempdir");
    init_with_fixture(repo_dir.path()).await;
    force_lapse(repo_dir.path()).await;

    let served = repo_dir.path().join("targets").join(FIXTURE_NAME);
    let mut grown = FIXTURE_BYTES.to_vec();
    grown.push(b'!');
    std::fs::write(&served, &grown).expect("write resized artifact");

    let err = postern_tuf::recover(repo_dir.path())
        .await
        .expect_err("recover MUST fail on a resized artifact");
    assert!(
        format!("{err:#}").contains("length mismatch"),
        "error must name the length mismatch, got: {err:#}"
    );
}

/// (5) An EXPIRED root is a hard error directing the operator to full
/// re-init — recovery never resurrects trust it cannot re-derive from
/// still-valid root metadata. The root here is re-signed by its own
/// legitimate key with a past expiry (signature valid, trust lapsed).
#[tokio::test(flavor = "current_thread")]
async fn recover_fails_closed_on_expired_root_directing_to_reinit() {
    let repo_dir = tempfile::tempdir().expect("tempdir");
    init_with_fixture(repo_dir.path()).await;

    // Re-sign 1.root.json with an expiry in the PAST using the repo's own
    // root dev key: the canonical-JSON signature verifies, the trust lapsed.
    let root_path = repo_dir.path().join("metadata").join("1.root.json");
    let signed: tough::schema::Signed<tough::schema::Root> =
        serde_json::from_slice(&std::fs::read(&root_path).expect("read root")).expect("parse");
    let mut root = signed.signed;
    root.expires = past_timestamp();
    let mut canonical = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(
        &mut canonical,
        olpc_cjson::CanonicalFormatter::new(),
    );
    serde::Serialize::serialize(&root, &mut ser).expect("canonical json");
    let key_der = std::fs::read(
        repo_dir
            .path()
            .join(postern_tuf::DEV_KEYS_DIR)
            .join("root.pkcs8.der"),
    )
    .expect("root dev key");
    let key = tough::sign::parse_keypair(&key_der).expect("parse root key");
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let sig = key.sign(&canonical, &rng).await.expect("sign expired root");
    let keyid = key.tuf_key().key_id().expect("key id");
    let resigned = tough::schema::Signed {
        signed: root,
        signatures: vec![tough::schema::Signature {
            keyid,
            sig: sig.into(),
        }],
    };
    std::fs::write(&root_path, serde_json::to_vec_pretty(&resigned).expect("serialize"))
        .expect("write expired root");

    // The client load fails (expired root), and recover must NOT step in:
    // an expired root is exactly the trust recovery cannot re-derive.
    assert!(postern_tuf::load_repo(repo_dir.path()).await.is_err());
    let err = postern_tuf::recover(repo_dir.path())
        .await
        .expect_err("recover MUST refuse an expired root");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("EXPIRED") && msg.contains("re-init"),
        "error must direct the operator to full re-init, got: {msg}"
    );
}

/// (6) A missing signing key is a hard error: key loss means re-init, not
/// improvisation with whatever key happens to be around.
#[tokio::test(flavor = "current_thread")]
async fn recover_fails_closed_on_missing_signing_key() {
    let repo_dir = tempfile::tempdir().expect("tempdir");
    init_with_fixture(repo_dir.path()).await;
    force_lapse(repo_dir.path()).await;

    std::fs::remove_file(
        repo_dir
            .path()
            .join(postern_tuf::DEV_KEYS_DIR)
            .join("snapshot.pkcs8.der"),
    )
    .expect("remove snapshot key");

    let err = postern_tuf::recover(repo_dir.path())
        .await
        .expect_err("recover MUST fail without the snapshot signing key");
    assert!(
        format!("{err:#}").contains("re-init"),
        "error must point at re-init for key loss, got: {err:#}"
    );
}

/// (7) A file under targets/ that targets.json never recorded fails closed —
/// an unlisted artifact is what tampering looks like.
#[tokio::test(flavor = "current_thread")]
async fn recover_fails_closed_on_unlisted_file_in_targets() {
    let repo_dir = tempfile::tempdir().expect("tempdir");
    init_with_fixture(repo_dir.path()).await;
    force_lapse(repo_dir.path()).await;

    std::fs::write(
        repo_dir.path().join("targets").join("smuggled.bin"),
        b"not in targets.json",
    )
    .expect("plant unlisted file");

    let err = postern_tuf::recover(repo_dir.path())
        .await
        .expect_err("recover MUST fail on an unlisted file under targets/");
    assert!(
        format!("{err:#}").contains("not recorded in targets.json"),
        "error must name the unlisted file rule, got: {err:#}"
    );
}

/// (8) Fail closed on a ROLLBACK: targets.json swapped for an OLDER but still
/// validly signed version (lower version + different hash than the lapsed
/// snapshot recorded). Its signature verifies against the trusted root, so the
/// signature re-check (test 2) would pass it — but in TUF the snapshot IS the
/// anti-rollback link for targets, and recover re-signs FRESHNESS only, never
/// blesses swapped CONTENT. The cross-check against the snapshot's recorded meta
/// (length + sha256 + version) turns the rollback into a hard error.
#[tokio::test(flavor = "current_thread")]
async fn recover_fails_closed_on_rolled_back_targets() {
    let repo_dir = tempfile::tempdir().expect("tempdir");
    let repo = repo_dir.path();

    // init → capture the validly signed v1 targets.json (empty, pre-add_target).
    postern_tuf::init_repo(repo).await.expect("init_repo");
    let targets_path = repo.join("metadata").join("targets.json");
    let rolled_back = std::fs::read(&targets_path).expect("read v1 targets.json");

    // add a target → targets.json becomes v2 (higher version + different hash);
    // the snapshot now commits to v2. Then lapse snapshot/timestamp.
    let fixture = repo.join(FIXTURE_NAME);
    std::fs::write(&fixture, FIXTURE_BYTES).expect("write fixture");
    postern_tuf::add_target(repo, &fixture).await.expect("add_target");
    force_lapse(repo).await;

    // Attacker rolls targets.json back to the still-validly-signed v1 bytes and
    // drops the v2 artifact, so v1's empty list stays disk-consistent — the only
    // thing wrong is that it is NOT what the lapsed snapshot committed to.
    let current = std::fs::read(&targets_path).expect("read v2 targets.json");
    assert_ne!(current, rolled_back, "test setup: v1 and v2 targets must differ");
    std::fs::write(&targets_path, &rolled_back).expect("plant rolled-back targets.json");
    std::fs::remove_file(repo.join("targets").join(FIXTURE_NAME)).expect("drop v2 artifact");

    let err = postern_tuf::recover(repo)
        .await
        .expect_err("recover MUST fail closed on a rolled-back targets.json");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("rollback") && msg.contains("does not match the lapsed snapshot"),
        "error must name the anti-rollback failure, got: {msg}"
    );
    // Nothing was re-signed: the repo still fails the client load.
    assert!(postern_tuf::load_repo(repo).await.is_err());
}
