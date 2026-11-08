//! Tests for `postern_release::tuf` — the TUF update-channel CORE SCAFFOLD.
//!
//! **These tests exercise LOCAL logic only.** They prove the k-of-n
//! threshold arithmetic, expiry comparison, and R2 path-layout computation
//! behave correctly on data the test itself supplies. None of them contact
//! a network, generate or verify a cryptographic signature, or fetch any
//! TUF metadata from anywhere — see `src/tuf.rs`'s module docs for the full
//! "what this is NOT" list.
//!
//! The single `#[cfg(feature = "tuf-tough")]` test at the bottom is a
//! LINK-CHECK ONLY: it proves `tough`'s real metadata/loader types compile
//! and construct from this crate. It is not part of the default `cargo
//! test` run.

use postern_release::tuf::{
    ChannelLayout, RoleMetadata, RootMetadata, SnapshotMetadata, TargetFile, TargetsMetadata,
    ThresholdPolicy, TimestampMetadata, TufError, TufRole,
};
use std::collections::HashMap;

// ---------------------------------------------------------------------
// ThresholdPolicy: local k-of-n accounting
// ---------------------------------------------------------------------

/// Illustrative-only example keyids/threshold for a root role. NOT a real
/// Postern release-signing quorum — see `src/tuf.rs` module docs.
fn example_root_keyids() -> Vec<String> {
    (1..=7).map(|n| format!("root-key-{n}")).collect()
}

#[test]
fn tuf_threshold_policy_rejects_zero_threshold() {
    let err = ThresholdPolicy::new(TufRole::Root, example_root_keyids(), 0).unwrap_err();
    assert_eq!(
        err,
        TufError::InvalidThreshold {
            role: TufRole::Root,
            threshold: 0,
            keyid_count: 7,
        }
    );
}

#[test]
fn tuf_threshold_policy_rejects_threshold_above_keyid_count() {
    let err = ThresholdPolicy::new(TufRole::Root, example_root_keyids(), 8).unwrap_err();
    assert_eq!(
        err,
        TufError::InvalidThreshold {
            role: TufRole::Root,
            threshold: 8,
            keyid_count: 7,
        }
    );
}

#[test]
fn tuf_threshold_policy_deduplicates_keyids_before_bounds_check() {
    // 3 distinct keyids, one duplicated -> distinct count is 3, so a
    // threshold of 3 is valid and 4 is not.
    let keyids = vec![
        "k1".to_string(),
        "k2".to_string(),
        "k3".to_string(),
        "k1".to_string(),
    ];
    assert!(ThresholdPolicy::new(TufRole::Targets, keyids.clone(), 3).is_ok());
    let err = ThresholdPolicy::new(TufRole::Targets, keyids, 4).unwrap_err();
    assert_eq!(
        err,
        TufError::InvalidThreshold {
            role: TufRole::Targets,
            threshold: 4,
            keyid_count: 3,
        }
    );
}

/// The task's own illustrative 4-of-7 example: 4 distinct signer keyids out
/// of the 7 authorized keyids on the root role must be present.
#[test]
fn tuf_threshold_policy_4_of_7_satisfied_by_exactly_4_authorized_signers() {
    let policy = ThresholdPolicy::new(TufRole::Root, example_root_keyids(), 4).unwrap();
    assert_eq!(policy.threshold(), 4);
    assert_eq!(policy.keyids().len(), 7);

    let signers = ["root-key-1", "root-key-3", "root-key-5", "root-key-7"];
    assert!(policy.is_satisfied(signers));
}

#[test]
fn tuf_threshold_policy_4_of_7_not_satisfied_by_3_signers() {
    let policy = ThresholdPolicy::new(TufRole::Root, example_root_keyids(), 4).unwrap();
    let signers = ["root-key-1", "root-key-3", "root-key-5"];
    assert!(!policy.is_satisfied(signers));
}

#[test]
fn tuf_threshold_policy_duplicate_signer_keyids_count_once() {
    let policy = ThresholdPolicy::new(TufRole::Root, example_root_keyids(), 4).unwrap();
    // 4 entries, but only 3 distinct keyids -> not satisfied.
    let signers = ["root-key-1", "root-key-1", "root-key-3", "root-key-5"];
    assert!(!policy.is_satisfied(signers));
}

#[test]
fn tuf_threshold_policy_unauthorized_signer_keyids_never_count() {
    let policy = ThresholdPolicy::new(TufRole::Root, example_root_keyids(), 4).unwrap();
    // 4 "signers" but only 2 are actually authorized keyids on this policy
    // -> not satisfied. Proves this is set-membership accounting, not a
    // raw count of whatever the caller hands in.
    let signers = ["root-key-1", "root-key-2", "not-authorized-1", "not-authorized-2"];
    assert!(!policy.is_satisfied(signers));
}

// ---------------------------------------------------------------------
// RoleMetadata: local expiry comparison
// ---------------------------------------------------------------------

#[test]
fn tuf_role_metadata_rejects_zero_version() {
    let err = RoleMetadata::new(TufRole::Timestamp, 0, 1_700_000_000).unwrap_err();
    assert_eq!(err, TufError::ZeroVersion);
}

#[test]
fn tuf_role_metadata_not_expired_strictly_before_expiry() {
    let meta = RoleMetadata::new(TufRole::Timestamp, 1, 1_700_000_000).unwrap();
    assert!(!meta.is_expired_at(1_699_999_999));
}

#[test]
fn tuf_role_metadata_expired_at_exact_expiry_instant() {
    // TUF treats the expiry instant itself as already expired.
    let meta = RoleMetadata::new(TufRole::Timestamp, 1, 1_700_000_000).unwrap();
    assert!(meta.is_expired_at(1_700_000_000));
}

#[test]
fn tuf_role_metadata_expired_after_expiry() {
    let meta = RoleMetadata::new(TufRole::Timestamp, 1, 1_700_000_000).unwrap();
    assert!(meta.is_expired_at(1_700_000_001));
}

// ---------------------------------------------------------------------
// Typed role wrappers: role-mismatch guard + composition
// ---------------------------------------------------------------------

#[test]
fn tuf_root_metadata_rejects_non_root_common() {
    let common = RoleMetadata::new(TufRole::Targets, 1, 1_700_000_000).unwrap();
    let err = RootMetadata::new(common, HashMap::new()).unwrap_err();
    assert_eq!(
        err,
        TufError::RoleMismatch {
            expected: TufRole::Root,
            actual: TufRole::Targets,
        }
    );
}

#[test]
fn tuf_root_metadata_exposes_per_role_policy() {
    let common = RoleMetadata::new(TufRole::Root, 1, 1_700_000_000).unwrap();
    let mut policies = HashMap::new();
    policies.insert(
        TufRole::Targets,
        ThresholdPolicy::new(TufRole::Targets, vec!["t1".into(), "t2".into(), "t3".into()], 2)
            .unwrap(),
    );
    let root = RootMetadata::new(common, policies).unwrap();

    let targets_policy = root.policy_for(TufRole::Targets).unwrap();
    assert_eq!(targets_policy.threshold(), 2);
    assert!(root.policy_for(TufRole::Snapshot).is_none());
}

#[test]
fn tuf_targets_metadata_rejects_non_targets_common() {
    let common = RoleMetadata::new(TufRole::Root, 1, 1_700_000_000).unwrap();
    let err = TargetsMetadata::new(common, HashMap::new()).unwrap_err();
    assert_eq!(
        err,
        TufError::RoleMismatch {
            expected: TufRole::Targets,
            actual: TufRole::Root,
        }
    );
}

#[test]
fn tuf_targets_metadata_looks_up_target_by_relative_path() {
    let common = RoleMetadata::new(TufRole::Targets, 1, 1_700_000_000).unwrap();
    let mut targets = HashMap::new();
    targets.insert(
        "bloch-node".to_string(),
        TargetFile {
            sha256_hex: "a".repeat(64),
            length_bytes: 12345,
        },
    );
    let metadata = TargetsMetadata::new(common, targets).unwrap();

    let found = metadata.target("bloch-node").unwrap();
    assert_eq!(found.length_bytes, 12345);
    assert!(metadata.target("does-not-exist").is_none());
}

#[test]
fn tuf_snapshot_metadata_rejects_non_snapshot_common_and_zero_targets_version() {
    let wrong_role = RoleMetadata::new(TufRole::Root, 1, 1_700_000_000).unwrap();
    assert_eq!(
        SnapshotMetadata::new(wrong_role, 1).unwrap_err(),
        TufError::RoleMismatch {
            expected: TufRole::Snapshot,
            actual: TufRole::Root,
        }
    );

    let right_role = RoleMetadata::new(TufRole::Snapshot, 1, 1_700_000_000).unwrap();
    assert_eq!(
        SnapshotMetadata::new(right_role, 0).unwrap_err(),
        TufError::ZeroVersion
    );
}

#[test]
fn tuf_timestamp_metadata_pins_snapshot_version() {
    let common = RoleMetadata::new(TufRole::Timestamp, 5, 1_700_000_000).unwrap();
    let metadata = TimestampMetadata::new(common, 3).unwrap();
    assert_eq!(metadata.snapshot_version().get(), 3);
    assert_eq!(metadata.common().version().get(), 5);
}

// ---------------------------------------------------------------------
// ChannelLayout: R2 object-key convention
// ---------------------------------------------------------------------

#[test]
fn tuf_channel_layout_rejects_empty_channel() {
    assert_eq!(ChannelLayout::new("").unwrap_err(), TufError::EmptyChannel);
}

#[test]
fn tuf_channel_layout_rejects_unsafe_channel_names() {
    assert!(matches!(
        ChannelLayout::new("stable/beta").unwrap_err(),
        TufError::InvalidChannelName(_)
    ));
    assert!(matches!(
        ChannelLayout::new("has space").unwrap_err(),
        TufError::InvalidChannelName(_)
    ));
    assert!(matches!(
        ChannelLayout::new("../escape").unwrap_err(),
        TufError::InvalidChannelName(_)
    ));
}

#[test]
fn tuf_channel_layout_computes_metadata_and_targets_prefixes() {
    let layout = ChannelLayout::new("stable").unwrap();
    assert_eq!(layout.metadata_prefix(), "stable/metadata");
    assert_eq!(layout.targets_prefix(), "stable/targets");
}

#[test]
fn tuf_channel_layout_metadata_object_key_unversioned_and_versioned() {
    let layout = ChannelLayout::new("stable").unwrap();
    assert_eq!(
        layout.metadata_object_key(TufRole::Root, None),
        "stable/metadata/root.json"
    );
    assert_eq!(
        layout.metadata_object_key(TufRole::Root, Some(3)),
        "stable/metadata/3.root.json"
    );
    assert_eq!(
        layout.metadata_object_key(TufRole::Timestamp, None),
        "stable/metadata/timestamp.json"
    );
}

#[test]
fn tuf_channel_layout_target_object_key_happy_path() {
    let layout = ChannelLayout::new("beta").unwrap();
    assert_eq!(
        layout.target_object_key("bin/bloch-node").unwrap(),
        "beta/targets/bin/bloch-node"
    );
}

#[test]
fn tuf_channel_layout_target_object_key_rejects_traversal_and_absolute_paths() {
    let layout = ChannelLayout::new("beta").unwrap();
    assert!(matches!(
        layout.target_object_key("").unwrap_err(),
        TufError::UnsafeTargetPath(_)
    ));
    assert!(matches!(
        layout.target_object_key("/etc/passwd").unwrap_err(),
        TufError::UnsafeTargetPath(_)
    ));
    assert!(matches!(
        layout.target_object_key("../../etc/passwd").unwrap_err(),
        TufError::UnsafeTargetPath(_)
    ));
    assert!(matches!(
        layout.target_object_key("bin/../../../etc/passwd").unwrap_err(),
        TufError::UnsafeTargetPath(_)
    ));
    assert!(matches!(
        layout.target_object_key("bin//double-slash").unwrap_err(),
        TufError::UnsafeTargetPath(_)
    ));
}

// ---------------------------------------------------------------------
// `tuf-tough` feature: link-check ONLY, not part of the default build.
// ---------------------------------------------------------------------

/// Proves `tough`'s real metadata/loader types compile, link, and construct
/// from this crate — nothing more. No network I/O, no key-signing
/// ceremony, no `.load()` call. See `src/tuf.rs::tough_link`'s docs.
#[cfg(feature = "tuf-tough")]
#[test]
fn tuf_tough_types_link_and_construct_without_network_or_keys() {
    use postern_release::tuf::tough_link;

    let root = tough_link::construct_root_placeholder();
    assert_eq!(root.version.get(), 1);
    assert!(root.keys.is_empty());
    assert!(root.roles.is_empty());

    let targets = tough_link::construct_targets_placeholder();
    assert_eq!(targets.version.get(), 1);
    assert!(targets.targets.is_empty());

    let snapshot = tough_link::construct_snapshot_placeholder();
    assert_eq!(snapshot.version.get(), 1);

    let timestamp = tough_link::construct_timestamp_placeholder();
    assert_eq!(timestamp.version.get(), 1);

    // A dummy, never-`.load()`-ed loader against unreachable file:// URLs.
    let root_bytes = vec![b'{', b'}'];
    let loader = tough_link::construct_repository_loader_dummy(&root_bytes);
    // `RepositoryLoader` derives `Debug`; formatting it touches no I/O and
    // is enough to prove the value is real and the type linked.
    let debug_repr = format!("{loader:?}");
    assert!(debug_repr.contains("RepositoryLoader"));
}
