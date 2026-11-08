//! TUF (`tough`) update-channel — **CORE SCAFFOLD ONLY. THIS IS NOT A WORKING
//! UPDATE CHANNEL.**
//!
//! # What this module IS
//!
//! - Typed, LOCAL models of the four top-level TUF roles ([`TufRole::Root`],
//!   [`TufRole::Targets`], [`TufRole::Snapshot`], [`TufRole::Timestamp`]) —
//!   just enough shape ([`RoleMetadata`], [`RootMetadata`],
//!   [`TargetsMetadata`], [`SnapshotMetadata`], [`TimestampMetadata`]) to
//!   reason about versions, expiry, and k-of-n signer thresholds.
//! - A [`ChannelLayout`] descriptor for the R2 object-key convention this
//!   repo intends for a TUF update channel: `<channel>/metadata/...json` +
//!   `<channel>/targets/...` under a channel-name prefix.
//! - LOCAL, offline k-of-n threshold accounting ([`ThresholdPolicy`]) and
//!   expiry comparison ([`RoleMetadata::is_expired_at`]) — pure arithmetic
//!   over strings/integers the caller supplies. Nothing here parses or
//!   verifies a real signature.
//! - Optional, feature-gated (`tuf-tough`) [`tough_link`] submodule: proves
//!   `tough`'s own metadata/loader types compile and link against this
//!   crate, nothing more.
//!
//! # What this module is NOT (read before wiring anything to it)
//!
//! - **NOT online root rotation.** There is no code here that fetches,
//!   compares, or "rolls forward" a chain of `root.json` versions the way a
//!   real TUF client does when the trusted root goes stale.
//! - **NOT a key-signing ceremony.** [`ThresholdPolicy`] holds opaque
//!   [`KeyId`] strings (`String`), never key material, and never invokes any
//!   cryptographic signing or verification. "Satisfied" below means "at
//!   least `threshold` distinct authorized key IDs are present in the caller-
//!   supplied list," full stop — it is a LOCAL MODEL of the TUF threshold
//!   *shape*, not a proof that any signature was checked.
//! - **NOT online metadata fetch/refresh.** [`ChannelLayout`] only computes
//!   what an R2 object key *would* look like for a role/target under a
//!   channel prefix. It never makes an HTTP request, never talks to R2, and
//!   never reads `metadata_base_url`/`targets_base_url` from anywhere.
//! - **NOT delegation.** Delegated targets roles (TUF's `Delegations`, TAP 3)
//!   are entirely out of scope; [`TargetsMetadata`] only models the
//!   top-level targets role.
//! - **The k-of-n threshold is illustrative, not a production value.** Any
//!   example threshold used in this module's own tests (e.g. a 4-of-7 root
//!   policy) is a stand-in to exercise the arithmetic — it does NOT reflect
//!   a real Postern release-signing key ceremony, quorum size, or key
//!   custody plan. Standing up a real root-of-trust for Postern releases is
//!   a separate, unstarted effort with its own key-generation, custody, and
//!   rotation ceremony that this scaffold deliberately does not attempt.
//!
//! In short: this is the typed vocabulary a future, real TUF update channel
//! would be built out of, plus the R2 path convention it would use — not
//! that channel itself. Default `cargo test` in this crate exercises the
//! local logic above; it proves the arithmetic is correct, not that any
//! update channel works end to end (none exists yet).

use std::collections::{BTreeSet, HashMap};
use std::num::NonZeroU64;

use thiserror::Error;

/// One of the four top-level TUF roles this scaffold models.
///
/// Delegated targets roles (TAP 3) are deliberately not represented — see
/// the module-level "What this module is NOT" section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TufRole {
    /// The root role: delegates trust (which keys, and what threshold) to
    /// every other top-level role, including itself.
    Root,
    /// The targets role: which target files are trusted, and their hashes.
    Targets,
    /// The snapshot role: pins the version of the targets metadata (and, in
    /// a full TUF deployment, any delegated targets metadata).
    Snapshot,
    /// The timestamp role: pins the version of the snapshot metadata; the
    /// short-lived role meant to be re-signed often to bound staleness.
    Timestamp,
}

impl TufRole {
    /// All four top-level roles, in the conventional TUF chain-of-trust
    /// order: root, then (targets, snapshot, timestamp) which root vouches
    /// for.
    pub const ALL: [TufRole; 4] = [
        TufRole::Root,
        TufRole::Targets,
        TufRole::Snapshot,
        TufRole::Timestamp,
    ];

    /// The role's canonical lowercase name, matching the TUF spec's role
    /// name strings (`"root"`, `"targets"`, `"snapshot"`, `"timestamp"`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            TufRole::Root => "root",
            TufRole::Targets => "targets",
            TufRole::Snapshot => "snapshot",
            TufRole::Timestamp => "timestamp",
        }
    }

    /// The role's UNVERSIONED metadata filename under `metadata/`
    /// (`root.json`, `targets.json`, `snapshot.json`, `timestamp.json`).
    /// See [`ChannelLayout::metadata_object_key`] for the versioned form
    /// (`consistent_snapshot`-style: `<version>.<role>.json`).
    #[must_use]
    pub fn metadata_filename(self) -> String {
        format!("{}.json", self.as_str())
    }
}

/// An opaque, LOCAL identifier for a signing key: just a string (e.g. a hex
/// key ID). This module never holds, generates, or touches actual key
/// material — see the module-level "What this module is NOT" section.
pub type KeyId = String;

/// Errors constructing or validating this module's local TUF-shaped types.
/// None of these are cryptographic errors — this module never attempts a
/// cryptographic operation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TufError {
    /// A [`ThresholdPolicy`] was constructed with a threshold of 0, or a
    /// threshold greater than the number of distinct authorized key IDs
    /// supplied — either makes the policy impossible to ever satisfy.
    #[error(
        "invalid k-of-n threshold for {role:?}: threshold {threshold} with {keyid_count} authorized keyid(s) (threshold must be 1..={keyid_count})"
    )]
    InvalidThreshold {
        /// The role the policy was for.
        role: TufRole,
        /// The threshold (`k`) that was rejected.
        threshold: u64,
        /// The number of authorized key IDs (`n`) supplied.
        keyid_count: usize,
    },
    /// A [`RoleMetadata`] was constructed with `version == 0`. TUF requires
    /// role versions to be a positive integer (roles start at version 1).
    #[error("role version must be >= 1, got 0")]
    ZeroVersion,
    /// A [`RootMetadata`] was constructed from a [`RoleMetadata`] whose
    /// [`TufRole`] was not [`TufRole::Root`] (and similarly for the other
    /// three typed role wrappers).
    #[error("expected role metadata for {expected:?}, got {actual:?}")]
    RoleMismatch {
        /// The role the typed wrapper requires.
        expected: TufRole,
        /// The role actually present on the [`RoleMetadata`] passed in.
        actual: TufRole,
    },
    /// [`ChannelLayout::new`] was given an empty channel name.
    #[error("channel name must not be empty")]
    EmptyChannel,
    /// [`ChannelLayout::new`] was given a channel name that is unsafe to use
    /// as an R2 object-key path segment (contains `/`, whitespace, or a
    /// `..` traversal component).
    #[error("channel name {0:?} must be a single path segment (no '/', whitespace, or '..')")]
    InvalidChannelName(String),
    /// [`ChannelLayout::target_object_key`] was given a target path that is
    /// empty, absolute, or contains a `.`/`..` path-traversal component.
    #[error(
        "target path {0:?} is not a safe relative path (must be non-empty, relative, and free of '.'/'..' components)"
    )]
    UnsafeTargetPath(String),
}

/// LOCAL, offline k-of-n signer-threshold model for one TUF role.
///
/// This is the *shape* of a TUF role's `roles[role] = {keyids, threshold}`
/// entry from `root.json` — nothing more. [`ThresholdPolicy::is_satisfied`]
/// does set membership + counting over caller-supplied key ID strings. It
/// performs **no cryptographic signature verification whatsoever**: a
/// caller that hands it a list of key IDs it merely *claims* signed
/// something gets exactly the same answer as one that hands it key IDs it
/// cryptographically verified elsewhere. Driving this from real, verified
/// signatures is future work this scaffold does not attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThresholdPolicy {
    role: TufRole,
    keyids: Vec<KeyId>,
    threshold: u64,
}

impl ThresholdPolicy {
    /// Construct a threshold policy: `threshold` of the (deduplicated)
    /// `keyids` must be present for the role to be considered locally
    /// "satisfied". Fails if `threshold` is 0 or exceeds the number of
    /// distinct key IDs supplied.
    pub fn new(role: TufRole, keyids: Vec<KeyId>, threshold: u64) -> Result<Self, TufError> {
        let distinct_keyid_count = keyids.iter().collect::<BTreeSet<_>>().len();
        if threshold == 0 || threshold as usize > distinct_keyid_count {
            return Err(TufError::InvalidThreshold {
                role,
                threshold,
                keyid_count: distinct_keyid_count,
            });
        }
        Ok(Self {
            role,
            keyids,
            threshold,
        })
    }

    /// The role this policy governs.
    #[must_use]
    pub fn role(&self) -> TufRole {
        self.role
    }

    /// The authorized key IDs (`n` in "k-of-n").
    #[must_use]
    pub fn keyids(&self) -> &[KeyId] {
        &self.keyids
    }

    /// The required threshold (`k` in "k-of-n").
    #[must_use]
    pub fn threshold(&self) -> u64 {
        self.threshold
    }

    /// True iff `signer_keyids` contains at least `threshold` DISTINCT
    /// key IDs that are also present in this policy's authorized `keyids`.
    ///
    /// This is pure set arithmetic over strings — a key ID appearing in
    /// `signer_keyids` is treated as "signed", with no cryptographic check
    /// that it actually did. Duplicate entries in `signer_keyids` count
    /// once. Key IDs not in this policy's authorized set are ignored (an
    /// unauthorized "signer" can never push the count over threshold).
    #[must_use]
    pub fn is_satisfied<'a, I>(&self, signer_keyids: I) -> bool
    where
        I: IntoIterator<Item = &'a str>,
    {
        let authorized: BTreeSet<&str> = self.keyids.iter().map(String::as_str).collect();
        let distinct_valid_signers = signer_keyids
            .into_iter()
            .filter(|keyid| authorized.contains(keyid))
            .collect::<BTreeSet<&str>>()
            .len() as u64;
        distinct_valid_signers >= self.threshold
    }
}

/// Fields common to every TUF role's metadata: which role, what version,
/// and when it expires. LOCAL MODEL: `expires_unix` is a bare Unix-seconds
/// integer, and expiry is decided by comparing it to a `now_unix` the
/// caller supplies — there is no calendar/timezone handling, no clock
/// reading, and no online freshness check anywhere in this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoleMetadata {
    role: TufRole,
    version: NonZeroU64,
    expires_unix: u64,
}

impl RoleMetadata {
    /// Construct role metadata. Fails if `version` is 0 (TUF versions start
    /// at 1).
    pub fn new(role: TufRole, version: u64, expires_unix: u64) -> Result<Self, TufError> {
        let version = NonZeroU64::new(version).ok_or(TufError::ZeroVersion)?;
        Ok(Self {
            role,
            version,
            expires_unix,
        })
    }

    /// The role this metadata is for.
    #[must_use]
    pub fn role(&self) -> TufRole {
        self.role
    }

    /// The role's version number.
    #[must_use]
    pub fn version(&self) -> NonZeroU64 {
        self.version
    }

    /// The expiry instant, as Unix seconds.
    #[must_use]
    pub fn expires_unix(&self) -> u64 {
        self.expires_unix
    }

    /// True iff `now_unix` (Unix seconds, caller-supplied — this module
    /// never reads the system clock) is at or past `expires_unix`. TUF
    /// treats the expiry instant itself as already expired ("MUST NOT be
    /// trusted"), so this is `now_unix >= expires_unix`, not `>`.
    #[must_use]
    pub fn is_expired_at(&self, now_unix: u64) -> bool {
        now_unix >= self.expires_unix
    }
}

/// LOCAL model of a `root.json`: which [`ThresholdPolicy`] governs each of
/// the four top-level roles (including root's own self-referential entry).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootMetadata {
    common: RoleMetadata,
    role_policies: HashMap<TufRole, ThresholdPolicy>,
}

impl RootMetadata {
    /// Construct root metadata. Fails if `common.role()` is not
    /// [`TufRole::Root`].
    pub fn new(
        common: RoleMetadata,
        role_policies: HashMap<TufRole, ThresholdPolicy>,
    ) -> Result<Self, TufError> {
        if common.role() != TufRole::Root {
            return Err(TufError::RoleMismatch {
                expected: TufRole::Root,
                actual: common.role(),
            });
        }
        Ok(Self {
            common,
            role_policies,
        })
    }

    /// The common version/expiry fields.
    #[must_use]
    pub fn common(&self) -> &RoleMetadata {
        &self.common
    }

    /// The threshold policy this root declares for `role`, if any.
    #[must_use]
    pub fn policy_for(&self, role: TufRole) -> Option<&ThresholdPolicy> {
        self.role_policies.get(&role)
    }
}

/// A single target file entry: its relative path is the map key in
/// [`TargetsMetadata::targets`]; this struct holds the rest of a TUF
/// `TARGETS` entry (length + sha256), matching the manifest shape
/// [`crate::manifest`] already produces for the SAME purpose (this module
/// does not reuse that type directly, to keep the scaffold's TUF vocabulary
/// self-contained and not couple it to the hybrid-signature manifest
/// format).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetFile {
    /// Hex-encoded SHA-256 of the target file's bytes.
    pub sha256_hex: String,
    /// The target file's length in bytes.
    pub length_bytes: u64,
}

/// LOCAL model of a `targets.json`: the set of target files this channel
/// trusts, keyed by their relative path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetsMetadata {
    common: RoleMetadata,
    targets: HashMap<String, TargetFile>,
}

impl TargetsMetadata {
    /// Construct targets metadata. Fails if `common.role()` is not
    /// [`TufRole::Targets`].
    pub fn new(
        common: RoleMetadata,
        targets: HashMap<String, TargetFile>,
    ) -> Result<Self, TufError> {
        if common.role() != TufRole::Targets {
            return Err(TufError::RoleMismatch {
                expected: TufRole::Targets,
                actual: common.role(),
            });
        }
        Ok(Self { common, targets })
    }

    /// The common version/expiry fields.
    #[must_use]
    pub fn common(&self) -> &RoleMetadata {
        &self.common
    }

    /// Look up a target file by its relative path.
    #[must_use]
    pub fn target(&self, relative_path: &str) -> Option<&TargetFile> {
        self.targets.get(relative_path)
    }
}

/// LOCAL model of a `snapshot.json`: pins the trusted version of
/// `targets.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotMetadata {
    common: RoleMetadata,
    targets_version: NonZeroU64,
}

impl SnapshotMetadata {
    /// Construct snapshot metadata. Fails if `common.role()` is not
    /// [`TufRole::Snapshot`].
    pub fn new(common: RoleMetadata, targets_version: u64) -> Result<Self, TufError> {
        if common.role() != TufRole::Snapshot {
            return Err(TufError::RoleMismatch {
                expected: TufRole::Snapshot,
                actual: common.role(),
            });
        }
        let targets_version = NonZeroU64::new(targets_version).ok_or(TufError::ZeroVersion)?;
        Ok(Self {
            common,
            targets_version,
        })
    }

    /// The common version/expiry fields.
    #[must_use]
    pub fn common(&self) -> &RoleMetadata {
        &self.common
    }

    /// The pinned `targets.json` version.
    #[must_use]
    pub fn targets_version(&self) -> NonZeroU64 {
        self.targets_version
    }
}

/// LOCAL model of a `timestamp.json`: pins the trusted version of
/// `snapshot.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimestampMetadata {
    common: RoleMetadata,
    snapshot_version: NonZeroU64,
}

impl TimestampMetadata {
    /// Construct timestamp metadata. Fails if `common.role()` is not
    /// [`TufRole::Timestamp`].
    pub fn new(common: RoleMetadata, snapshot_version: u64) -> Result<Self, TufError> {
        if common.role() != TufRole::Timestamp {
            return Err(TufError::RoleMismatch {
                expected: TufRole::Timestamp,
                actual: common.role(),
            });
        }
        let snapshot_version = NonZeroU64::new(snapshot_version).ok_or(TufError::ZeroVersion)?;
        Ok(Self {
            common,
            snapshot_version,
        })
    }

    /// The common version/expiry fields.
    #[must_use]
    pub fn common(&self) -> &RoleMetadata {
        &self.common
    }

    /// The pinned `snapshot.json` version.
    #[must_use]
    pub fn snapshot_version(&self) -> NonZeroU64 {
        self.snapshot_version
    }
}

/// Describes the R2 object-key convention for ONE TUF update channel (e.g.
/// `"stable"`, `"beta"`): metadata lives under `<channel>/metadata/`,
/// targets under `<channel>/targets/`. This is a pure path-string
/// calculator — it never talks to R2, never lists a bucket, and never reads
/// or writes anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelLayout {
    channel: String,
}

impl ChannelLayout {
    /// Construct a layout for `channel`. Fails if `channel` is empty, or is
    /// unsafe as a single R2 object-key path segment (contains `/`,
    /// whitespace, or `..`).
    pub fn new(channel: impl Into<String>) -> Result<Self, TufError> {
        let channel = channel.into();
        if channel.is_empty() {
            return Err(TufError::EmptyChannel);
        }
        if channel.contains('/')
            || channel.chars().any(char::is_whitespace)
            || channel.contains("..")
        {
            return Err(TufError::InvalidChannelName(channel));
        }
        Ok(Self { channel })
    }

    /// The channel name this layout was constructed for.
    #[must_use]
    pub fn channel(&self) -> &str {
        &self.channel
    }

    /// The `metadata/` prefix for this channel, e.g. `"stable/metadata"`.
    #[must_use]
    pub fn metadata_prefix(&self) -> String {
        format!("{}/metadata", self.channel)
    }

    /// The `targets/` prefix for this channel, e.g. `"stable/targets"`.
    #[must_use]
    pub fn targets_prefix(&self) -> String {
        format!("{}/targets", self.channel)
    }

    /// The R2 object key for `role`'s metadata file under this channel.
    ///
    /// `version = None` gives the unversioned name TUF clients bootstrap
    /// from (e.g. `"stable/metadata/root.json"`); `version = Some(n)` gives
    /// the `consistent_snapshot`-style versioned name TUF's spec uses for
    /// immutable, cacheable historical copies (e.g.
    /// `"stable/metadata/3.root.json"`). This module does not decide
    /// whether a real channel would enable consistent snapshots — it just
    /// computes the key for either case.
    #[must_use]
    pub fn metadata_object_key(&self, role: TufRole, version: Option<u64>) -> String {
        match version {
            Some(v) => format!("{}/{v}.{}", self.metadata_prefix(), role.metadata_filename()),
            None => format!("{}/{}", self.metadata_prefix(), role.metadata_filename()),
        }
    }

    /// The R2 object key for a target file at `relative_target_path` under
    /// this channel's `targets/` prefix.
    ///
    /// Fails on an empty, absolute (leading `/`), or path-traversing
    /// (containing a `.`/`..` component) `relative_target_path` — the same
    /// class of path-safety check a real TUF client applies before writing
    /// a fetched target to disk, applied here at object-key-construction
    /// time instead.
    pub fn target_object_key(&self, relative_target_path: &str) -> Result<String, TufError> {
        let unsafe_path = || TufError::UnsafeTargetPath(relative_target_path.to_string());
        if relative_target_path.is_empty() || relative_target_path.starts_with('/') {
            return Err(unsafe_path());
        }
        for component in relative_target_path.split('/') {
            if component.is_empty() || component == "." || component == ".." {
                return Err(unsafe_path());
            }
        }
        Ok(format!("{}/{relative_target_path}", self.targets_prefix()))
    }
}

/// Reference-only, LINK-CHECK-only import of `tough`'s real TUF
/// metadata/loader types, gated behind the `tuf-tough` cargo feature.
///
/// **This submodule proves `tough`'s types compile and link against this
/// crate — it does not drive a TUF client.** Every function here:
/// - performs NO network I/O (nothing calls `tough::RepositoryLoader::load`,
///   the one method that would);
/// - performs NO key-signing ceremony (no key generation, no signing, no
///   signature verification);
/// - performs NO filesystem I/O beyond what constructing a plain struct in
///   memory requires (none).
///
/// If this module is compiled at all (i.e. `--features tuf-tough`), that is
/// the entire claim it makes: `tough`'s public types are usable from this
/// crate. The default build does not compile this module, and does not link
/// `tough`, at all.
#[cfg(feature = "tuf-tough")]
pub mod tough_link {
    use std::collections::HashMap;
    use std::num::NonZeroU64;

    /// Construct `tough::schema::Root` in memory, with empty key/role maps.
    /// Proves the type exists, is constructible from this crate, and that
    /// its version/expires fields line up with the types this module
    /// otherwise expects — nothing is signed, parsed from a file, or
    /// fetched.
    #[must_use]
    pub fn construct_root_placeholder() -> tough::schema::Root {
        tough::schema::Root {
            spec_version: "1.0.0".to_string(),
            consistent_snapshot: false,
            version: NonZeroU64::new(1).expect("1 is nonzero"),
            expires: jiff::Timestamp::UNIX_EPOCH,
            keys: HashMap::new(),
            roles: HashMap::new(),
            _extra: HashMap::new(),
        }
    }

    /// Construct `tough::schema::Targets` via its own `new()` constructor.
    #[must_use]
    pub fn construct_targets_placeholder() -> tough::schema::Targets {
        tough::schema::Targets::new(
            "1.0.0".to_string(),
            NonZeroU64::new(1).expect("1 is nonzero"),
            jiff::Timestamp::UNIX_EPOCH,
        )
    }

    /// Construct `tough::schema::Snapshot` via its own `new()` constructor.
    #[must_use]
    pub fn construct_snapshot_placeholder() -> tough::schema::Snapshot {
        tough::schema::Snapshot::new(
            "1.0.0".to_string(),
            NonZeroU64::new(1).expect("1 is nonzero"),
            jiff::Timestamp::UNIX_EPOCH,
        )
    }

    /// Construct `tough::schema::Timestamp` via its own `new()`
    /// constructor.
    #[must_use]
    pub fn construct_timestamp_placeholder() -> tough::schema::Timestamp {
        tough::schema::Timestamp::new(
            "1.0.0".to_string(),
            NonZeroU64::new(1).expect("1 is nonzero"),
            jiff::Timestamp::UNIX_EPOCH,
        )
    }

    /// Construct (but never `.load()`) a `tough::RepositoryLoader` builder
    /// against dummy, unreachable `file://` base URLs.
    ///
    /// `RepositoryLoader::new` performs no I/O by itself — it is a plain
    /// builder; only the async `.load()` method (never called here, and not
    /// even reachable without a `#[tokio::main]`/`tokio::runtime` this crate
    /// does not set up) would attempt to read a root file or contact a
    /// transport. This function proves the loader TYPE and its builder
    /// constructor link and typecheck from this crate; it does not load a
    /// repository.
    #[must_use]
    pub fn construct_repository_loader_dummy(root_json_bytes: &Vec<u8>) -> tough::RepositoryLoader<'_> {
        let metadata_base_url =
            url::Url::parse("file:///nonexistent/postern-release-tuf-scaffold/metadata/")
                .expect("static literal is a well-formed URL");
        let targets_base_url =
            url::Url::parse("file:///nonexistent/postern-release-tuf-scaffold/targets/")
                .expect("static literal is a well-formed URL");
        tough::RepositoryLoader::new(root_json_bytes, metadata_base_url, targets_base_url)
    }
}
