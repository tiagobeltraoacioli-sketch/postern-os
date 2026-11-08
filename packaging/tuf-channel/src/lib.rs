// SPDX-License-Identifier: MIT OR Apache-2.0
//
// postern-tuf — DEV/TESTING-ONLY scaffold of the Postern TUF update channel,
// built on `tough` (AWS Labs, MIT OR Apache-2.0).
//
// RAILS — read before touching:
//
//   * UNAUDITED, pre-mainnet, dev keys only. `init` generates ed25519 keys
//     into a directory literally named `dev-keys-DO-NOT-SHIP`. Nothing signed
//     by them may ever be shipped to a user.
//   * There is NO live update endpoint. Everything here produces LOCAL
//     metadata on disk. The desktop Tauri config keeps
//     `createUpdaterArtifacts = false` (enforced by desktop tests) until the
//     channel is real — this crate must not be used to argue otherwise.
//   * F-Droid is the MODEL for self-hosted, reproducible app distribution,
//     but F-Droid code is GPL/AGPL: model only, NO code. This crate's
//     dependency tree is permissive-only (MIT/Apache/ISC/Unlicense).
//   * Fail closed: `verify` uses tough's Safe expiration enforcement and
//     hash/length pinning — expired or tampered metadata is a hard error,
//     never a warning.
//
// What exists: init (root of trust + empty targets/snapshot/timestamp),
// add-target (hash+length an artifact, re-sign the metadata chain), verify
// (full TUF client load + target fetch + SHA-256 printout), rotate-root
// (TUF spec 5.3.4 dual-signed root vN+1 with a fresh dev key; staged-key
// ordering makes an interrupted rotation self-healing on the next run),
// refresh (bump + re-sign snapshot/timestamp — the anti-staleness operation;
// it can NOT rescue a repo whose metadata already expired — that fails
// closed), and recover (the designed lapse-recovery rule: for a repo whose
// snapshot/timestamp LAPSED but whose root chain is still within its own
// expiry and whose signing keys are present, re-verify targets.json against
// the trusted root and re-hash every artifact BEFORE re-signing fresh
// snapshot/timestamp; an expired ROOT is a hard error directing to full
// re-init). One target file end-to-end, single platform — a vertical slice,
// not the product.
//
// rotate-root honesty: it is a LOCAL exercise of the TUF 5.3.4 rotation rule
// with throwaway dev keys. It is NOT a key ceremony, NOT a custody plan, and
// nothing signed here may ever ship to a user. desktop keeps
// createUpdaterArtifacts=false and this command must never be cited as a
// reason to flip it.

use std::collections::HashMap;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::Ed25519KeyPair;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tough::editor::RepositoryEditor;
use tough::key_source::{KeySource, LocalKeySource};
use tough::schema::decoded::{Decoded, Hex};
use tough::schema::key::Key;
use tough::schema::{
    Hashes, Metafile, RoleKeys, RoleType, Root, Signature, Signed, Snapshot, Targets, Timestamp,
};
use tough::sign::{parse_keypair, Sign};
use tough::{
    ExpirationEnforcement, FilesystemTransport, Prefix, Repository, RepositoryLoader, TargetName,
};
use url::Url;

/// TUF specification version written into every metadata file.
pub const SPEC_VERSION: &str = "1.0.0";

/// The dev-key directory name. The name is the warning.
pub const DEV_KEYS_DIR: &str = "dev-keys-DO-NOT-SHIP";

/// File name (inside `dev-keys-DO-NOT-SHIP/`) where `rotate_root` stages the
/// incoming root key BEFORE the rotated root metadata is written, so an
/// interrupted rotation is always detectable and recoverable (see
/// [`rotate_root`]'s crash-safety note).
pub const STAGED_ROOT_KEY: &str = "root.pkcs8.der.staged";

/// Metadata subdirectory of a repo dir.
pub const METADATA_DIR: &str = "metadata";

/// Targets subdirectory of a repo dir.
pub const TARGETS_DIR: &str = "targets";

/// Sane DEV expiries (days). Short on purpose: a stale dev repo should rot
/// quickly rather than look trustworthy.
pub const ROOT_EXPIRY_DAYS: i64 = 365;
pub const TARGETS_EXPIRY_DAYS: i64 = 90;
pub const SNAPSHOT_EXPIRY_DAYS: i64 = 14;
pub const TIMESTAMP_EXPIRY_DAYS: i64 = 7;

const ROLES: [(&str, RoleType); 4] = [
    ("root", RoleType::Root),
    ("targets", RoleType::Targets),
    ("snapshot", RoleType::Snapshot),
    ("timestamp", RoleType::Timestamp),
];

const DEV_KEYS_README: &str = "\
# dev-keys-DO-NOT-SHIP

ed25519 PKCS#8 signing keys for a LOCAL, DEV/TESTING-ONLY TUF repository.

* These keys are generated on this machine for development and testing ONLY.
* The update channel is UNAUDITED. No live update endpoint exists.
* Nothing signed with these keys may ever be distributed to a user.
* If any file in this directory ever leaves your machine, treat the whole
  repository as compromised and re-run `postern-tuf init` from scratch.
* The desktop Tauri config keeps createUpdaterArtifacts=false until the real
  channel (real keys, real endpoint, audit) exists.
";

/// Filesystem layout of a local dev TUF repository.
#[derive(Debug, Clone)]
pub struct RepoPaths {
    pub repo_dir: PathBuf,
    pub metadata_dir: PathBuf,
    pub targets_dir: PathBuf,
    pub keys_dir: PathBuf,
}

impl RepoPaths {
    pub fn new(repo_dir: &Path) -> Self {
        RepoPaths {
            repo_dir: repo_dir.to_path_buf(),
            metadata_dir: repo_dir.join(METADATA_DIR),
            targets_dir: repo_dir.join(TARGETS_DIR),
            keys_dir: repo_dir.join(DEV_KEYS_DIR),
        }
    }

    /// The version-1 root — the trust anchor every other command starts from.
    pub fn root_json(&self) -> PathBuf {
        self.metadata_dir.join("1.root.json")
    }

    fn key_file(&self, role: &str) -> PathBuf {
        self.keys_dir.join(format!("{role}.pkcs8.der"))
    }

    fn staged_root_key(&self) -> PathBuf {
        self.keys_dir.join(STAGED_ROOT_KEY)
    }

    fn key_sources(&self) -> Vec<Box<dyn KeySource>> {
        ROLES
            .iter()
            .map(|(role, _)| {
                Box::new(LocalKeySource {
                    path: self.key_file(role),
                }) as Box<dyn KeySource>
            })
            .collect()
    }
}

/// `now + days`, as the `jiff::Timestamp` tough's schema expects.
fn expires_in_days(days: i64) -> Result<jiff::Timestamp> {
    jiff::Timestamp::from_second(jiff::Timestamp::now().as_second() + days * 86_400)
        .context("computing expiry timestamp")
}

/// Canonical-JSON bytes of a serializable value (olpc-cjson — the exact
/// formatter tough signs and verifies with).
fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut ser =
        serde_json::Serializer::with_formatter(&mut buf, olpc_cjson::CanonicalFormatter::new());
    value
        .serialize(&mut ser)
        .context("canonical JSON serialization")?;
    Ok(buf)
}

/// Initialize a brand-new local dev TUF repository under `repo_dir`:
/// generate one ed25519 dev key per top-level role, build + self-sign
/// root.json, and write signed (empty) targets/snapshot/timestamp metadata.
pub async fn init_repo(repo_dir: &Path) -> Result<RepoPaths> {
    let paths = RepoPaths::new(repo_dir);
    if paths.root_json().exists() {
        bail!(
            "refusing to overwrite existing repository at {}",
            paths.root_json().display()
        );
    }
    std::fs::create_dir_all(&paths.metadata_dir).context("creating metadata dir")?;
    std::fs::create_dir_all(&paths.targets_dir).context("creating targets dir")?;
    std::fs::create_dir_all(&paths.keys_dir).context("creating dev-keys dir")?;
    std::fs::write(paths.keys_dir.join("README.md"), DEV_KEYS_README)
        .context("writing dev-keys README")?;

    // 1. Generate one ed25519 dev key per role (PKCS#8 v2 DER — the format
    //    tough::sign::parse_keypair / LocalKeySource consume directly).
    let rng = SystemRandom::new();
    let mut keys: HashMap<Decoded<Hex>, Key> = HashMap::new();
    let mut roles: HashMap<RoleType, RoleKeys> = HashMap::new();
    for (role, role_type) in ROLES {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| anyhow::anyhow!("generating ed25519 key for role {role}"))?;
        let key_path = paths.key_file(role);
        std::fs::write(&key_path, pkcs8.as_ref())
            .with_context(|| format!("writing {}", key_path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("chmod 600 {}", key_path.display()))?;
        }
        let key_pair = parse_keypair(pkcs8.as_ref())
            .context("re-parsing freshly generated key with tough")?;
        let tuf_key = key_pair.tuf_key();
        let key_id = tuf_key.key_id().context("computing TUF key id")?;
        roles.insert(
            role_type,
            RoleKeys {
                keyids: vec![key_id.clone()],
                threshold: NonZeroU64::new(1).unwrap(),
                _extra: HashMap::new(),
            },
        );
        keys.insert(key_id, tuf_key);
    }

    // 2. Build root.json (version 1, consistent_snapshot=false so filenames
    //    stay human-readable) and self-sign it with the root dev key.
    let root = Root {
        spec_version: SPEC_VERSION.to_string(),
        consistent_snapshot: false,
        version: NonZeroU64::new(1).unwrap(),
        expires: expires_in_days(ROOT_EXPIRY_DAYS)?,
        keys,
        roles,
        _extra: HashMap::new(),
    };
    let root_key_der = std::fs::read(paths.key_file("root")).context("reading root dev key")?;
    let root_key = parse_keypair(&root_key_der).context("parsing root dev key")?;
    let root_key_id = root
        .key_id(&root_key)
        .context("root key id not present in root.json (bug)")?;
    let canonical = canonical_json(&root)?;
    let sig = root_key
        .sign(&canonical, &rng)
        .await
        .map_err(|e| anyhow::anyhow!("signing root.json: {e}"))?;
    let signed_root = Signed {
        signed: root,
        signatures: vec![Signature {
            keyid: root_key_id,
            sig: sig.into(),
        }],
    };
    let mut root_bytes =
        serde_json::to_vec_pretty(&signed_root).context("serializing root.json")?;
    root_bytes.push(b'\n');
    std::fs::write(paths.root_json(), &root_bytes).context("writing 1.root.json")?;

    // 3. Sign empty targets/snapshot/timestamp through tough's editor —
    //    the same code path add-target uses later.
    let mut editor = RepositoryEditor::new(paths.root_json())
        .await
        .context("opening repository editor on fresh root")?;
    set_versions_and_expiries(&mut editor, 1, 1, 1)?;
    let signed = editor
        .sign(&paths.key_sources())
        .await
        .context("signing initial metadata")?;
    signed
        .write(&paths.metadata_dir)
        .await
        .context("writing initial metadata")?;
    Ok(paths)
}

fn set_versions_and_expiries(
    editor: &mut RepositoryEditor,
    targets_version: u64,
    snapshot_version: u64,
    timestamp_version: u64,
) -> Result<()> {
    editor
        .targets_version(NonZeroU64::new(targets_version).context("targets version")?)
        .context("setting targets version")?
        .targets_expires(expires_in_days(TARGETS_EXPIRY_DAYS)?)
        .context("setting targets expiry")?
        .snapshot_version(NonZeroU64::new(snapshot_version).context("snapshot version")?)
        .snapshot_expires(expires_in_days(SNAPSHOT_EXPIRY_DAYS)?)
        .timestamp_version(NonZeroU64::new(timestamp_version).context("timestamp version")?)
        .timestamp_expires(expires_in_days(TIMESTAMP_EXPIRY_DAYS)?);
    Ok(())
}

/// Load the repository with tough's fail-closed client (Safe expiration
/// enforcement; hash/length pinning is inherent to TUF metadata).
pub async fn load_repo(repo_dir: &Path) -> Result<Repository> {
    let paths = RepoPaths::new(repo_dir);
    let root_bytes = std::fs::read(paths.root_json())
        .with_context(|| format!("reading {}", paths.root_json().display()))?;
    let metadata_dir = paths
        .metadata_dir
        .canonicalize()
        .context("canonicalizing metadata dir")?;
    let targets_dir = paths
        .targets_dir
        .canonicalize()
        .context("canonicalizing targets dir")?;
    let metadata_url = Url::from_directory_path(&metadata_dir)
        .map_err(|()| anyhow::anyhow!("metadata dir is not an absolute path"))?;
    let targets_url = Url::from_directory_path(&targets_dir)
        .map_err(|()| anyhow::anyhow!("targets dir is not an absolute path"))?;
    RepositoryLoader::new(&root_bytes, metadata_url, targets_url)
        .transport(FilesystemTransport)
        .expiration_enforcement(ExpirationEnforcement::Safe)
        .load()
        .await
        .context("TUF verification failed while loading repository (fail closed)")
}

/// Add one artifact to the repository: hash + length it, copy it into
/// targets/, and re-sign targets/snapshot/timestamp with bumped versions.
pub async fn add_target(repo_dir: &Path, file: &Path) -> Result<String> {
    let paths = RepoPaths::new(repo_dir);
    let file = file
        .canonicalize()
        .with_context(|| format!("artifact not found: {}", file.display()))?;
    let target_name = file
        .file_name()
        .and_then(|n| n.to_str())
        .context("artifact path has no valid UTF-8 file name")?
        .to_string();

    let repo = load_repo(repo_dir).await?;
    let next_targets = repo.targets().signed.version.get() + 1;
    let next_snapshot = repo.snapshot().signed.version.get() + 1;
    let next_timestamp = repo.timestamp().signed.version.get() + 1;

    let mut editor = RepositoryEditor::from_repo(paths.root_json(), repo)
        .await
        .context("opening repository editor")?;
    editor
        .add_target_path(&file)
        .await
        .context("hashing artifact into targets metadata")?;
    set_versions_and_expiries(&mut editor, next_targets, next_snapshot, next_timestamp)?;
    let signed = editor
        .sign(&paths.key_sources())
        .await
        .context("re-signing targets/snapshot/timestamp")?;
    signed
        .write(&paths.metadata_dir)
        .await
        .context("writing re-signed metadata")?;
    // consistent_snapshot=false, so the target is stored under its plain name.
    std::fs::copy(&file, paths.targets_dir.join(&target_name))
        .context("copying artifact into targets/")?;
    Ok(target_name)
}

/// Result of a `rotate_root` run.
#[derive(Debug)]
pub struct RootRotation {
    /// Version of the newly written root metadata (old version + 1).
    pub new_version: u64,
    /// Path of the freshly written `N+1.root.json`.
    pub new_root_json: PathBuf,
    /// Where the old root dev key file was retired to (`*.retired`).
    pub retired_key: PathBuf,
}

/// Rotate the root role key: generate a fresh ed25519 DEV key, build root
/// vN+1 (bumped version, new root keyid, all other role keys unchanged) and
/// sign its canonical-JSON bytes with BOTH the outgoing and the incoming root
/// key — the TUF spec 5.3.4 dual-signature requirement that lets a client
/// still pinned to `1.root.json` roll forward, and makes a new-key-only root
/// rejectable, fail closed.
///
/// Crash safety: the rotation is NOT atomic (it is several file operations),
/// but it is ordered to be recoverable. The incoming key is staged as
/// `dev-keys-DO-NOT-SHIP/root.pkcs8.der.staged` BEFORE `N+1.root.json` is
/// written; only after the rotated root is on disk is the old key file
/// retired and the staged key renamed into place. If the process dies in any
/// of those windows, the NEXT `rotate_root` run detects the staged key and
/// self-heals: a staged key the (rolled-forward) trusted root authorizes has
/// its interrupted install finished; a staged key no written root ever
/// blessed is discarded. No manual key-file surgery is needed — re-running
/// `rotate-root` both repairs the interrupted swap and performs the newly
/// requested rotation.
///
/// HONESTY: this is a LOCAL exercise of the TUF 5.3.4 rotation rule with
/// throwaway dev keys (dev-keys-DO-NOT-SHIP). It is NOT a key ceremony, NOT a
/// custody plan, and nothing signed here may ever ship to a user. The channel
/// is UNAUDITED and no live update endpoint exists.
pub async fn rotate_root(repo_dir: &Path) -> Result<RootRotation> {
    let paths = RepoPaths::new(repo_dir);

    // Only rotate a repository that verifies fail-closed today. This also
    // rolls the trusted root forward through any earlier rotations, so `N`
    // below is always the LATEST root version, not just 1.
    let repo = load_repo(repo_dir).await?;
    let old_root = repo.root().signed.clone();
    let old_version = old_root.version.get();
    let new_version = old_version
        .checked_add(1)
        .context("root version overflow")?;
    let new_root_json = paths.metadata_dir.join(format!("{new_version}.root.json"));
    if new_root_json.exists() {
        bail!(
            "refusing to overwrite existing {}",
            new_root_json.display()
        );
    }

    // If a previous rotation was interrupted between writing the rotated
    // root and swapping the key files, finish (or discard) that swap first —
    // see the crash-safety note in the doc comment.
    recover_staged_root_key(&paths, &old_root)?;

    // The on-disk root dev key must be exactly a key the current trusted
    // root authorizes — refuse to "rotate" with a key the metadata never
    // trusted (that would just manufacture an unverifiable root).
    let old_key_der =
        std::fs::read(paths.key_file("root")).context("reading current root dev key")?;
    let old_key = parse_keypair(&old_key_der).context("parsing current root dev key")?;
    let old_key_id = old_key
        .tuf_key()
        .key_id()
        .context("computing outgoing root key id")?;
    let root_role = old_root
        .roles
        .get(&RoleType::Root)
        .context("root role missing from trusted root.json")?;
    if !root_role.keyids.contains(&old_key_id) {
        bail!(
            "on-disk root dev key is not authorized by the trusted root metadata — refusing to rotate"
        );
    }

    // Fresh ed25519 DEV key for the incoming root (same PKCS#8 v2 DER format
    // as init; throwaway, dev-keys-DO-NOT-SHIP).
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|_| anyhow::anyhow!("generating replacement ed25519 root key"))?;
    let new_key = parse_keypair(pkcs8.as_ref()).context("re-parsing freshly generated key")?;
    let new_tuf_key = new_key.tuf_key();
    let new_key_id = new_tuf_key
        .key_id()
        .context("computing incoming root key id")?;

    // Stage the incoming key on disk BEFORE the rotated root exists, so a
    // crash in any later window leaves a state the next run can recover.
    let staged_key_path = paths.staged_root_key();
    std::fs::write(&staged_key_path, pkcs8.as_ref())
        .with_context(|| format!("staging {}", staged_key_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&staged_key_path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 600 {}", staged_key_path.display()))?;
    }

    // Root vN+1: bumped version, fresh expiry, root keyid swapped; the
    // targets/snapshot/timestamp role keys are deliberately UNCHANGED.
    let mut new_root = old_root;
    new_root.version = NonZeroU64::new(new_version).context("new root version")?;
    new_root.expires = expires_in_days(ROOT_EXPIRY_DAYS)?;
    new_root.keys.remove(&old_key_id);
    new_root.keys.insert(new_key_id.clone(), new_tuf_key);
    new_root
        .roles
        .get_mut(&RoleType::Root)
        .context("root role missing (bug)")?
        .keyids = vec![new_key_id.clone()];

    // TUF spec 5.3.4: version N+1 of root MUST be signed by a threshold of
    // keys from root vN AND a threshold of keys from root vN+1 — so sign the
    // canonical-JSON bytes with BOTH the outgoing and the incoming key.
    let canonical = canonical_json(&new_root)?;
    let old_sig = old_key
        .sign(&canonical, &rng)
        .await
        .map_err(|e| anyhow::anyhow!("signing root v{new_version} with outgoing key: {e}"))?;
    let new_sig = new_key
        .sign(&canonical, &rng)
        .await
        .map_err(|e| anyhow::anyhow!("signing root v{new_version} with incoming key: {e}"))?;
    let signed_root = Signed {
        signed: new_root,
        signatures: vec![
            Signature {
                keyid: old_key_id,
                sig: old_sig.into(),
            },
            Signature {
                keyid: new_key_id,
                sig: new_sig.into(),
            },
        ],
    };

    let mut root_bytes =
        serde_json::to_vec_pretty(&signed_root).context("serializing rotated root.json")?;
    root_bytes.push(b'\n');
    std::fs::write(&new_root_json, &root_bytes)
        .with_context(|| format!("writing {}", new_root_json.display()))?;

    // Retire the outgoing dev key file (kept, renamed — the name is the
    // warning) and install the staged incoming key where key_sources()
    // expects it. Renames only from here on: a crash between them is exactly
    // the state recover_staged_root_key() repairs on the next run.
    let retired_key = paths
        .keys_dir
        .join(format!("root.v{old_version}.pkcs8.der.retired"));
    std::fs::rename(paths.key_file("root"), &retired_key)
        .with_context(|| format!("retiring old root key to {}", retired_key.display()))?;
    std::fs::rename(&staged_key_path, paths.key_file("root"))
        .with_context(|| format!("installing {}", paths.key_file("root").display()))?;

    Ok(RootRotation {
        new_version,
        new_root_json,
        retired_key,
    })
}

/// Staged-key crash recovery for [`rotate_root`]. If a `root.pkcs8.der.staged`
/// file exists, a previous rotation was interrupted:
///
/// * staged key AUTHORIZED by the (rolled-forward) trusted root — the rotated
///   `N.root.json` was already written and clients already trust it, but the
///   key swap never finished: retire the stale installed key (if any) and
///   rename the staged key into place.
/// * staged key NOT authorized by any written root — the crash happened
///   before the rotated root was written, so the staged key never signed
///   anything any client trusts: discard it.
///
/// A staged file that does not even parse as a key is a hard error (fail
/// closed — inspect and remove it by hand).
fn recover_staged_root_key(paths: &RepoPaths, trusted_root: &Root) -> Result<()> {
    let staged = paths.staged_root_key();
    if !staged.exists() {
        return Ok(());
    }
    let staged_der = std::fs::read(&staged).context("reading staged root dev key")?;
    let staged_key = parse_keypair(&staged_der).context(
        "staged root key exists but does not parse — refusing to guess; inspect and remove it",
    )?;
    let staged_key_id = staged_key
        .tuf_key()
        .key_id()
        .context("computing staged root key id")?;
    let root_role = trusted_root
        .roles
        .get(&RoleType::Root)
        .context("root role missing from trusted root.json")?;
    if root_role.keyids.contains(&staged_key_id) {
        // Finish the interrupted install.
        let installed = paths.key_file("root");
        if installed.exists() {
            let prev_version = trusted_root.version.get().saturating_sub(1);
            let retired = paths
                .keys_dir
                .join(format!("root.v{prev_version}.pkcs8.der.retired"));
            if retired.exists() {
                bail!(
                    "cannot retire stale root key during crash recovery: {} already exists",
                    retired.display()
                );
            }
            std::fs::rename(&installed, &retired)
                .context("retiring stale root key during crash recovery")?;
        }
        std::fs::rename(&staged, paths.key_file("root"))
            .context("installing staged root key during crash recovery")?;
    } else {
        std::fs::remove_file(&staged).context("discarding unused staged root key")?;
    }
    Ok(())
}

/// Re-sign snapshot + timestamp with bumped versions and fresh (short, dev)
/// expiries — the anti-staleness operation a real channel would run on a
/// schedule so clients can tell "quiet" apart from "frozen". Targets metadata
/// is preserved byte-for-byte (same version, same expiry, same deterministic
/// ed25519 signature). Returns the new (snapshot, timestamp) versions.
///
/// Fail-closed corollary: refresh can only refresh a repository that still
/// verifies TODAY. Once snapshot/timestamp have already EXPIRED (7/14 dev
/// days), `load_repo` rejects the whole repo and refresh errors out — it
/// cannot rescue a lapsed repo, by design. That boundary is deliberate and
/// stays: the designed lapse-recovery path is [`recover`], which re-derives
/// trust from still-valid root metadata before re-signing anything (and an
/// expired ROOT is a hard error there — full re-init is the only path). A
/// real channel additionally needs a scheduler that runs refresh before
/// expiry; none exists here.
///
/// HONESTY: LOCAL metadata, dev keys only, UNAUDITED — no live update
/// endpoint exists, and no scheduler runs this. It exercises the operation,
/// it does not operate a channel.
pub async fn refresh(repo_dir: &Path) -> Result<(u64, u64)> {
    let paths = RepoPaths::new(repo_dir);
    let repo = load_repo(repo_dir).await?;
    let targets_version = repo.targets().signed.version;
    let targets_expires = repo.targets().signed.expires;
    let next_snapshot = repo.snapshot().signed.version.get() + 1;
    let next_timestamp = repo.timestamp().signed.version.get() + 1;

    let mut editor = RepositoryEditor::from_repo(paths.root_json(), repo)
        .await
        .context("opening repository editor")?;
    editor
        .targets_version(targets_version)
        .context("keeping targets version")?
        .targets_expires(targets_expires)
        .context("keeping targets expiry")?
        .snapshot_version(NonZeroU64::new(next_snapshot).context("snapshot version")?)
        .snapshot_expires(expires_in_days(SNAPSHOT_EXPIRY_DAYS)?)
        .timestamp_version(NonZeroU64::new(next_timestamp).context("timestamp version")?)
        .timestamp_expires(expires_in_days(TIMESTAMP_EXPIRY_DAYS)?);
    let signed = editor
        .sign(&paths.key_sources())
        .await
        .context("re-signing snapshot/timestamp")?;
    signed
        .write(&paths.metadata_dir)
        .await
        .context("writing refreshed metadata")?;
    Ok((next_snapshot, next_timestamp))
}

/// Result of a [`recover`] run.
#[derive(Debug)]
pub struct Recovery {
    /// Version of the trusted root the recovery re-derived trust from (the
    /// end of the verified 1.root.json → N.root.json rotation chain).
    pub root_version: u64,
    /// Version of the freshly re-signed snapshot metadata.
    pub snapshot_version: u64,
    /// Version of the freshly re-signed timestamp metadata.
    pub timestamp_version: u64,
    /// Number of target artifacts re-hashed against their recorded
    /// hash+length before anything was re-signed.
    pub targets_checked: usize,
}

/// Recover a repository whose snapshot/timestamp have LAPSED — the designed
/// recovery rule the roadmap demands ("a quiet dev repo rots by design; a
/// real channel needs an explicit recovery/re-init story").
///
/// Semantics, fail closed — recovery never resurrects trust it cannot
/// re-derive from still-valid root metadata:
///
/// 1. A repository that still verifies today is REFUSED — that is
///    [`refresh`]'s job (anti-staleness maintenance). The refresh/recover
///    boundary is asserted from both sides, not blurred.
/// 2. The trust anchor is re-derived by walking the root rotation chain from
///    the pinned `1.root.json` (every step must be authorized by the previous
///    root AND verify under its own keys — the same rule the client
///    enforces). An EXPIRED root is a hard error directing the operator to
///    full re-init: a new trust root that installed clients must re-pin
///    out-of-band, stated as the trust event it is.
/// 3. `targets.json`'s signature is re-verified against the trusted root's
///    targets key, and its own expiry must still hold — recovery re-signs
///    FRESHNESS (snapshot/timestamp), never CONTENT.
/// 4. Every target recorded in `targets.json` is re-read from `targets/` and
///    re-checked against its recorded hash+length, and every file under
///    `targets/` must be recorded — BEFORE anything is re-signed. Any
///    signature, hash, length, unlisted-file, or missing-file failure is a
///    hard error.
/// 5. The lapsed snapshot/timestamp signatures must still verify against the
///    trusted root (expiry is exactly what lapsed; unverifiable bytes give
///    nothing trustworthy to bump versions from), and the snapshot/timestamp
///    signing keys must be present on disk AND authorized by the trusted
///    root. A missing or unauthorized key is a hard error — key loss means
///    re-init, not improvisation.
/// 6. Only then are a fresh snapshot (pinning the EXACT on-disk
///    `targets.json` bytes, preserved byte-for-byte) and a fresh timestamp
///    (pinning the new snapshot bytes) signed with bumped versions and short
///    dev expiries. snapshot.json is written before timestamp.json; a crash
///    between the two writes leaves a repo that still fails closed (lapsed
///    timestamp) and is repaired by simply re-running `recover`.
///
/// HONESTY: dev keys (dev-keys-DO-NOT-SHIP), LOCAL repository, UNAUDITED —
/// this exercises the recovery RULE; it is not an operated channel. No live
/// update endpoint exists, and desktop keeps createUpdaterArtifacts=false.
pub async fn recover(repo_dir: &Path) -> Result<Recovery> {
    let paths = RepoPaths::new(repo_dir);

    // (1) Boundary with refresh: a repo that still loads fail-closed today
    // needs maintenance, not recovery.
    if load_repo(repo_dir).await.is_ok() {
        bail!(
            "repository still verifies today — nothing to recover; use `refresh` for \
             anti-staleness maintenance (recover is only for a repo whose snapshot/timestamp \
             already LAPSED)"
        );
    }

    // (2) Re-derive the trust anchor from the pinned 1.root.json.
    let trusted = trusted_root_chain(&paths)?;
    let root_version = trusted.signed.version.get();
    let now = jiff::Timestamp::now();
    if trusted.signed.expires <= now {
        bail!(
            "trusted root (v{root_version}) is itself EXPIRED — recovery refuses to resurrect \
             trust it cannot re-derive from still-valid root metadata (fail closed). The only \
             path is a full re-init: a NEW trust root that installed clients must re-pin \
             out-of-band. That is a trust event, not maintenance — see packaging/README.md \
             (recovery/re-init design)."
        );
    }

    // (3) targets.json: signature against the trusted root's targets key,
    // plus its own expiry.
    let targets_path = paths.metadata_dir.join("targets.json");
    let targets_bytes = std::fs::read(&targets_path)
        .with_context(|| format!("reading {}", targets_path.display()))?;
    let signed_targets: Signed<Targets> = serde_json::from_slice(&targets_bytes)
        .with_context(|| format!("parsing {}", targets_path.display()))?;
    trusted.signed.verify_role(&signed_targets).map_err(|e| {
        anyhow::anyhow!(
            "targets.json signature does not verify against the trusted root's targets key: {e} \
             (fail closed — recovery never re-signs content it cannot re-verify)"
        )
    })?;
    if signed_targets.signed.expires <= now {
        bail!(
            "targets metadata is itself expired — recovery only restores snapshot/timestamp \
             freshness and will not resurrect expired targets (fail closed); for this dev \
             scaffold the recovery is re-running init (and re-adding targets)"
        );
    }

    // (4) Re-hash every recorded artifact, and require every file under
    // targets/ to be recorded — BEFORE any re-signing.
    let mut targets_checked = 0usize;
    for (name, target) in &signed_targets.signed.targets {
        let artifact = paths.targets_dir.join(name.resolved());
        let bytes = std::fs::read(&artifact).with_context(|| {
            format!(
                "target '{}' is recorded in targets.json but missing from targets/ (fail closed)",
                name.raw()
            )
        })?;
        if bytes.len() as u64 != target.length {
            bail!(
                "target '{}' length mismatch: targets.json records {} bytes, targets/ has {} \
                 bytes (fail closed — refusing to re-sign a repo whose artifacts changed)",
                name.raw(),
                target.length,
                bytes.len()
            );
        }
        if Sha256::digest(&bytes).as_slice() != &target.hashes.sha256[..] {
            bail!(
                "target '{}' SHA-256 mismatch against the hash recorded in targets.json (fail \
                 closed — refusing to re-sign a repo whose artifacts changed)",
                name.raw()
            );
        }
        targets_checked += 1;
    }
    for entry in std::fs::read_dir(&paths.targets_dir).context("reading targets/")? {
        let entry = entry.context("reading targets/")?;
        let file_name = entry.file_name();
        let file_name = file_name
            .to_str()
            .context("non-UTF-8 file name in targets/ (fail closed)")?;
        if !signed_targets
            .signed
            .targets
            .keys()
            .any(|n| n.resolved() == file_name)
        {
            bail!(
                "file '{file_name}' exists under targets/ but is not recorded in targets.json \
                 (fail closed — an unlisted artifact is what tampering looks like)"
            );
        }
    }

    // (5) The lapsed snapshot/timestamp must still be the trusted root's own
    // (their signatures re-verified; only their expiry lapsed) — otherwise
    // there is nothing trustworthy to bump versions from.
    let old_snapshot: Signed<Snapshot> = read_signed_json(&paths.metadata_dir.join("snapshot.json"))?;
    trusted.signed.verify_role(&old_snapshot).map_err(|e| {
        anyhow::anyhow!(
            "lapsed snapshot.json signature does not verify against the trusted root: {e} \
             (fail closed — cannot re-derive; re-init)"
        )
    })?;
    let old_timestamp: Signed<Timestamp> =
        read_signed_json(&paths.metadata_dir.join("timestamp.json"))?;
    trusted.signed.verify_role(&old_timestamp).map_err(|e| {
        anyhow::anyhow!(
            "lapsed timestamp.json signature does not verify against the trusted root: {e} \
             (fail closed — cannot re-derive; re-init)"
        )
    })?;
    let snapshot_version = old_snapshot
        .signed
        .version
        .get()
        .checked_add(1)
        .context("snapshot version overflow")?;
    let timestamp_version = old_timestamp
        .signed
        .version
        .get()
        .checked_add(1)
        .context("timestamp version overflow")?;

    // Signing keys: present on disk AND authorized by the trusted root.
    let snapshot_key =
        load_authorized_role_key(&paths, &trusted.signed, "snapshot", RoleType::Snapshot)?;
    let timestamp_key =
        load_authorized_role_key(&paths, &trusted.signed, "timestamp", RoleType::Timestamp)?;

    // (5c) ANTI-ROLLBACK — the crux. Verifying the lapsed snapshot's signature
    // only proves the trusted root signed *some* snapshot; it does NOT prove the
    // on-disk targets.json is the one that snapshot committed to. An attacker
    // with the same repo write-access the fail-closed checks already assume could,
    // during the lapse, roll targets.json + its artifacts back to an OLDER but
    // still validly-signed, unexpired pair. In TUF the snapshot IS the
    // anti-rollback link for targets, so recover must re-verify that link before
    // re-signing freshness — otherwise it blesses a content rollback. Cross-check
    // length + sha256 + version against the snapshot's recorded meta; fail closed
    // on any drift (this is a swap/tamper, not a lapse).
    let recorded = old_snapshot.signed.meta.get("targets.json").ok_or_else(|| {
        anyhow::anyhow!(
            "lapsed snapshot.json records no targets.json meta — cannot anti-rollback \
             verify (fail closed; re-init)"
        )
    })?;
    let on_disk_sha = Sha256::digest(&targets_bytes).to_vec();
    let len_ok = recorded.length == Some(targets_bytes.len() as u64);
    let sha_ok = recorded
        .hashes
        .as_ref()
        .map(|h| h.sha256.as_ref() == on_disk_sha.as_slice())
        .unwrap_or(false);
    let ver_ok = recorded.version == signed_targets.signed.version;
    if !(len_ok && sha_ok && ver_ok) {
        anyhow::bail!(
            "on-disk targets.json does not match the lapsed snapshot's recorded meta \
             (length_ok={len_ok}, sha256_ok={sha_ok}, version_ok={ver_ok}) — this is a \
             rollback or tamper, not a lapse. Fail closed: recover re-signs FRESHNESS \
             only and never blesses swapped CONTENT. Investigate, then re-init."
        );
    }

    // (6) Only now re-sign freshness. Fresh snapshot pins the EXACT on-disk
    // targets.json bytes (preserved byte-for-byte, like refresh).
    let rng = SystemRandom::new();
    let mut snapshot = Snapshot::new(
        SPEC_VERSION.to_string(),
        NonZeroU64::new(snapshot_version).context("snapshot version")?,
        expires_in_days(SNAPSHOT_EXPIRY_DAYS)?,
    );
    snapshot.meta.insert(
        "targets.json".to_string(),
        Metafile {
            length: Some(targets_bytes.len() as u64),
            hashes: Some(Hashes {
                sha256: Sha256::digest(&targets_bytes).to_vec().into(),
                _extra: HashMap::new(),
            }),
            version: signed_targets.signed.version,
            _extra: HashMap::new(),
        },
    );
    let snapshot_bytes = sign_role(snapshot, &snapshot_key, &rng, "recovered snapshot.json").await?;
    std::fs::write(paths.metadata_dir.join("snapshot.json"), &snapshot_bytes)
        .context("writing recovered snapshot.json")?;

    // Fresh timestamp pins the new snapshot bytes.
    let mut timestamp = Timestamp::new(
        SPEC_VERSION.to_string(),
        NonZeroU64::new(timestamp_version).context("timestamp version")?,
        expires_in_days(TIMESTAMP_EXPIRY_DAYS)?,
    );
    timestamp.meta.insert(
        "snapshot.json".to_string(),
        Metafile {
            length: Some(snapshot_bytes.len() as u64),
            hashes: Some(Hashes {
                sha256: Sha256::digest(&snapshot_bytes).to_vec().into(),
                _extra: HashMap::new(),
            }),
            version: NonZeroU64::new(snapshot_version).context("snapshot version")?,
            _extra: HashMap::new(),
        },
    );
    let timestamp_bytes =
        sign_role(timestamp, &timestamp_key, &rng, "recovered timestamp.json").await?;
    std::fs::write(paths.metadata_dir.join("timestamp.json"), &timestamp_bytes)
        .context("writing recovered timestamp.json")?;

    Ok(Recovery {
        root_version,
        snapshot_version,
        timestamp_version,
        targets_checked,
    })
}

/// Walk the root rotation chain from the pinned `1.root.json` to the latest
/// `N.root.json`, enforcing at every step the same dual rule the client
/// enforces (TUF spec 5.3.4): the next root must be authorized by the
/// previous (trusted) root AND verify under its own keys, with the version
/// exactly incremented. Expiry is deliberately NOT checked here — the caller
/// decides what an expired root means ([`recover`] makes it a hard error).
fn trusted_root_chain(paths: &RepoPaths) -> Result<Signed<Root>> {
    let mut trusted: Signed<Root> = read_signed_json(&paths.root_json())?;
    trusted.signed.verify_role(&trusted).map_err(|e| {
        anyhow::anyhow!("pinned 1.root.json does not verify under its own keys: {e} (fail closed)")
    })?;
    loop {
        let next_version = trusted
            .signed
            .version
            .get()
            .checked_add(1)
            .context("root version overflow")?;
        let next_path = paths.metadata_dir.join(format!("{next_version}.root.json"));
        if !next_path.exists() {
            return Ok(trusted);
        }
        let next: Signed<Root> = read_signed_json(&next_path)?;
        trusted.signed.verify_role(&next).map_err(|e| {
            anyhow::anyhow!(
                "root rotation chain step {next_version} is not authorized by root v{}: {e} \
                 (fail closed)",
                trusted.signed.version
            )
        })?;
        next.signed.verify_role(&next).map_err(|e| {
            anyhow::anyhow!(
                "root v{next_version} does not verify under its own keys: {e} (fail closed)"
            )
        })?;
        if next.signed.version.get() != next_version {
            bail!(
                "{} claims version {} instead of {next_version} (fail closed)",
                next_path.display(),
                next.signed.version
            );
        }
        trusted = next;
    }
}

/// Read + parse one `Signed<T>` metadata file.
fn read_signed_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Signed<T>> {
    let bytes =
        std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))
}

/// Load one role's dev signing key from disk and require the trusted root to
/// authorize it. A missing, unparseable, or unauthorized key is a hard error.
fn load_authorized_role_key(
    paths: &RepoPaths,
    root: &Root,
    role: &str,
    role_type: RoleType,
) -> Result<impl Sign> {
    let key_path = paths.key_file(role);
    let der = std::fs::read(&key_path).with_context(|| {
        format!(
            "missing {role} signing key {} — recovery cannot re-sign without it (hard error); \
             if the key is lost, the only path is full re-init (a NEW trust root)",
            key_path.display()
        )
    })?;
    let key = parse_keypair(&der).with_context(|| format!("parsing {role} dev key"))?;
    let key_id = key
        .tuf_key()
        .key_id()
        .with_context(|| format!("computing {role} key id"))?;
    let role_keys = root
        .roles
        .get(&role_type)
        .with_context(|| format!("{role} role missing from trusted root.json"))?;
    if !role_keys.keyids.contains(&key_id) {
        bail!(
            "on-disk {role} dev key is not authorized by the trusted root metadata — refusing \
             to re-sign with it (fail closed)"
        );
    }
    Ok(key)
}

/// Canonical-JSON sign `role` with `key` and serialize the `Signed` wrapper
/// the same way tough's editor does (pretty JSON, no trailing newline) so the
/// hash recorded over these exact bytes stays consistent.
async fn sign_role<T: Serialize>(
    role: T,
    key: &impl Sign,
    rng: &SystemRandom,
    what: &str,
) -> Result<Vec<u8>> {
    let canonical = canonical_json(&role)?;
    let sig = key
        .sign(&canonical, rng)
        .await
        .map_err(|e| anyhow::anyhow!("signing {what}: {e}"))?;
    let keyid = key
        .tuf_key()
        .key_id()
        .with_context(|| format!("computing {what} key id"))?;
    let signed = Signed {
        signed: role,
        signatures: vec![Signature {
            keyid,
            sig: sig.into(),
        }],
    };
    serde_json::to_vec_pretty(&signed).with_context(|| format!("serializing {what}"))
}

/// Verify + fetch one target through the full TUF client path and return the
/// SHA-256 (hex) of the fetched bytes. Fails closed on expired metadata, bad
/// signatures, hash mismatches, or unknown targets.
pub async fn verify_target(repo_dir: &Path, target_name: &str, outdir: &Path) -> Result<String> {
    let repo = load_repo(repo_dir).await?;
    let name = TargetName::new(target_name).context("invalid target name")?;
    std::fs::create_dir_all(outdir).context("creating output dir")?;
    repo.save_target(&name, outdir, Prefix::None)
        .await
        .context("TUF target verification failed (fail closed)")?;
    let fetched = std::fs::read(outdir.join(target_name)).context("reading fetched target")?;
    Ok(hex::encode(Sha256::digest(&fetched)))
}
