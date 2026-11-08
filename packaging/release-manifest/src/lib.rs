// SPDX-License-Identifier: MIT OR Apache-2.0

//! `postern-release-manifest` — build a JSON release manifest
//! (`release-manifest.json`: name/size/SHA-256 per bundle artifact) and check
//! it, fail-closed, against the bundle directory it describes.
//!
//! # Division of labor (reuse, not duplication)
//!
//! This crate owns ONLY the manifest schema and the against-directory
//! re-check. The detached HYBRID Falcon-1024 + ML-DSA-87 signature over the
//! manifest bytes is `postern_release::sign` (crates/postern-release),
//! consumed unmodified as a path dependency — including its AND-of-both rule
//! (a signature with one valid leg and one corrupted leg is REJECTED) and its
//! domain-separated transcript. See that crate's docs for the cryptographic
//! honesty section.
//!
//! # Fail closed
//!
//! Every mismatch is a hard `Err`, never a warning:
//!
//! - an artifact listed in the manifest but missing from the directory;
//! - a size mismatch (`stat`) or SHA-256 mismatch (full re-hash);
//! - a file present in the directory but NOT listed in the manifest (an
//!   unlisted artifact is exactly what a tampered bundle looks like);
//! - an empty bundle directory (nothing to release is not a release);
//! - an unknown `schema_version` (a verifier must not guess at fields it
//!   does not understand).
//!
//! # HONESTY — what a passing check means
//!
//! Dev keys only, UNAUDITED, LOCAL metadata only. A manifest whose hybrid
//! signature verifies AND whose against-directory re-check passes proves
//! origin + integrity of the listed bytes under the two public keys — it is
//! NOT attestation, NOT a reproducibility proof, and NOT an audit. It
//! COMPLEMENTS, and does not replace, the repo's existing minisign(Ed25519)
//! release signature. The [`HONESTY_NOTE`] embedding this into every
//! manifest is part of the schema on purpose.

use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Current (and only) manifest schema version.
pub const SCHEMA_VERSION: u32 = 1;

/// The manifest's fixed filename.
pub const MANIFEST_NAME: &str = "release-manifest.json";

/// Detached hybrid-signature filename for a manifest at [`MANIFEST_NAME`]
/// (same `.pqsig` suffix convention as postern-release's `SHA256SUMS.pqsig`).
pub const SIGNATURE_NAME: &str = "release-manifest.json.pqsig";

/// The honesty note embedded verbatim in every manifest this crate builds.
/// It is a schema field, not decoration: a manifest that leaves the local
/// dev pipeline carries its own disclaimer.
pub const HONESTY_NOTE: &str = "DEV KEYS ONLY - UNAUDITED - LOCAL METADATA ONLY. Produced by the \
dev/testing bundle pipeline (packaging/build-signed-bundle.sh); no live update server exists and \
nothing signed with dev keys may ever ship to a user. The detached hybrid Falcon-1024+ML-DSA-87 \
signature over this manifest COMPLEMENTS, and does not replace, the repository's minisign \
(Ed25519) release signature, and proves origin+integrity of this manifest only - NOT attestation, \
NOT reproducibility, NOT an audit.";

/// One bundle artifact: base name, byte size, lowercase-hex SHA-256.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactEntry {
    /// Base file name within the bundle directory (flat — this pipeline's
    /// bundle dirs are one level deep, matching build-signed-bundle.sh).
    pub name: String,
    /// Size in bytes, as `stat` reports it.
    pub size: u64,
    /// Lowercase hex SHA-256 of the file contents.
    pub sha256: String,
}

/// The `release-manifest.json` document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseManifest {
    /// Must equal [`SCHEMA_VERSION`]; anything else fails closed on parse.
    pub schema_version: u32,
    /// RFC 3339 UTC timestamp of when `build` ran — or, when the
    /// `SOURCE_DATE_EPOCH` environment variable is set (the reproducible-
    /// builds convention), that instant instead, making two `build` runs
    /// over an identical bundle dir byte-identical. HONESTY: this makes the
    /// MANIFEST deterministic; it does NOT make the bundle artifacts it
    /// describes bit-reproducible.
    pub created_at: String,
    /// [`HONESTY_NOTE`], embedded verbatim.
    pub honesty: String,
    /// Sorted (byte order on `name`) list of bundle artifacts.
    pub artifacts: Vec<ArtifactEntry>,
}

/// Errors building, parsing, or re-checking a manifest. Every variant is a
/// hard failure — there are no warning-grade outcomes in this crate.
#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("bundle path is not a directory: {0:?}")]
    NotADirectory(PathBuf),
    #[error("bundle directory contains no artifact files (fail closed): {0:?}")]
    EmptyBundle(PathBuf),
    #[error("manifest lists no artifacts (fail closed)")]
    EmptyManifest,
    #[error("non UTF-8 file name in bundle dir: {0:?}")]
    NonUtf8(PathBuf),
    #[error("I/O error at {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("manifest JSON is malformed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported schema_version {found} (this verifier only understands {SCHEMA_VERSION}); refusing to guess (fail closed)")]
    SchemaVersion { found: u32 },
    #[error("artifact '{0}' is listed in the manifest but missing from the bundle dir (FAIL CLOSED)")]
    MissingArtifact(String),
    #[error("artifact '{name}' size mismatch: manifest says {expected} bytes, bundle dir has {actual} bytes (FAIL CLOSED)")]
    SizeMismatch {
        name: String,
        expected: u64,
        actual: u64,
    },
    #[error("artifact '{name}' sha256 mismatch: manifest says {expected}, bundle dir hashes to {actual} (FAIL CLOSED)")]
    Sha256Mismatch {
        name: String,
        expected: String,
        actual: String,
    },
    #[error("file '{0}' exists in the bundle dir but is NOT listed in the manifest (FAIL CLOSED: an unlisted artifact is what tampering looks like)")]
    UnlistedFile(String),
    #[error(
        "remote SHA256SUMS is UNSIGNED (no detached .pqsig supplied): refusing to merge or \
         re-sign it (FAIL CLOSED — re-signing unverified remote bytes would launder whatever a \
         bucket attacker put there under a fresh signature)"
    )]
    RemoteSumsUnsigned,
    #[error(
        "remote SHA256SUMS signature does not verify against the release public keys: {0} \
         (FAIL CLOSED — do not merge, do not re-sign)"
    )]
    RemoteSumsSignature(String),
    #[error("SHA256SUMS is not valid UTF-8 (fail closed)")]
    SumsNotUtf8,
    #[error("malformed SHA256SUMS line {line:?}: {detail} (fail closed)")]
    SumsLine { line: String, detail: String },
    #[error("SHA256SUMS lists file {0:?} more than once (fail closed)")]
    SumsDuplicate(String),
    #[error(
        "SOURCE_DATE_EPOCH is set but not a valid UTC epoch-seconds value ({detail}): {value:?} \
         (fail closed — a silently ignored SOURCE_DATE_EPOCH would fake determinism)"
    )]
    SourceDateEpoch { value: String, detail: String },
}

fn io_err(path: &Path, source: std::io::Error) -> ManifestError {
    ManifestError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// File names `build`/`check` skip inside the bundle dir: this tool's own
/// outputs (never hash your own manifest/signature) plus `SHA256SUMS` and its
/// signatures, so the artifact set stays identical to the one
/// build-signed-bundle.sh feeds `sha256sum` and the shell cross-check is 1:1.
fn is_skipped(name: &str) -> bool {
    name == MANIFEST_NAME
        || name == "SHA256SUMS"
        || (name.starts_with(MANIFEST_NAME) && name[MANIFEST_NAME.len()..].ends_with("sig"))
        || (name.starts_with("SHA256SUMS.") && name.ends_with("sig"))
}

/// Streaming SHA-256 of one file, returned as lowercase hex.
fn sha256_file(path: &Path) -> Result<String, ManifestError> {
    let mut file = fs::File::open(path).map_err(|e| io_err(path, e))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(|e| io_err(path, e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Walk `bundle_dir`'s regular files (flat, no recursion — matching
/// build-signed-bundle.sh's `find -maxdepth 1 -type f`), skipping this
/// tool's own outputs, sorted by name. Symlinks and subdirectories are
/// ignored, not followed.
fn list_artifacts(bundle_dir: &Path) -> Result<Vec<(String, PathBuf)>, ManifestError> {
    if !bundle_dir.is_dir() {
        return Err(ManifestError::NotADirectory(bundle_dir.to_path_buf()));
    }
    let mut names = Vec::new();
    for entry in fs::read_dir(bundle_dir).map_err(|e| io_err(bundle_dir, e))? {
        let entry = entry.map_err(|e| io_err(bundle_dir, e))?;
        // `DirEntry::file_type` does NOT follow symlinks: a symlink is never
        // treated as a regular file here, so a manifest can only ever
        // describe real local bytes.
        let ft = entry.file_type().map_err(|e| io_err(&entry.path(), e))?;
        if !ft.is_file() {
            continue;
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| ManifestError::NonUtf8(entry.path()))?;
        if is_skipped(&name) {
            continue;
        }
        names.push((name, entry.path()));
    }
    names.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(names)
}

/// The `created_at` stamp for a fresh manifest: `SOURCE_DATE_EPOCH` (the
/// reproducible-builds convention, seconds since the UTC epoch) when set —
/// so two `build` runs over an identical bundle dir are byte-identical —
/// otherwise the wall clock. A set-but-malformed `SOURCE_DATE_EPOCH` is a
/// hard error, never silently ignored: an operator who asked for a
/// deterministic build must not get a nondeterministic one that looks fine.
///
/// HONESTY — determinism scope: this pins the MANIFEST bytes only. The
/// bundle artifacts the manifest describes (.dmg, .deb, …) are NOT made (or
/// claimed) bit-reproducible by this; "reproducible where the platform
/// allows" starts and ends at the manifest/metadata layer here.
fn created_at() -> Result<String, ManifestError> {
    match std::env::var("SOURCE_DATE_EPOCH") {
        Ok(value) => {
            let seconds: i64 = value.trim().parse().map_err(|e| ManifestError::SourceDateEpoch {
                value: value.clone(),
                detail: format!("not an integer: {e}"),
            })?;
            let ts = jiff::Timestamp::from_second(seconds).map_err(|e| {
                ManifestError::SourceDateEpoch {
                    value: value.clone(),
                    detail: format!("out of range: {e}"),
                }
            })?;
            Ok(ts.to_string())
        }
        Err(std::env::VarError::NotPresent) => Ok(jiff::Timestamp::now().to_string()),
        Err(std::env::VarError::NotUnicode(_)) => Err(ManifestError::SourceDateEpoch {
            value: "<non-unicode>".to_string(),
            detail: "not valid unicode".to_string(),
        }),
    }
}

/// Build a [`ReleaseManifest`] over `bundle_dir` (see [`list_artifacts`] for
/// the walk rules). Fails closed on an empty artifact set. With
/// `SOURCE_DATE_EPOCH` set, the result is fully deterministic for a given
/// bundle dir (see [`created_at`] — manifest bytes only, NOT the artifacts).
pub fn build_manifest(bundle_dir: &Path) -> Result<ReleaseManifest, ManifestError> {
    let files = list_artifacts(bundle_dir)?;
    if files.is_empty() {
        return Err(ManifestError::EmptyBundle(bundle_dir.to_path_buf()));
    }
    let mut artifacts = Vec::with_capacity(files.len());
    for (name, path) in files {
        let meta = fs::metadata(&path).map_err(|e| io_err(&path, e))?;
        artifacts.push(ArtifactEntry {
            name,
            size: meta.len(),
            sha256: sha256_file(&path)?,
        });
    }
    Ok(ReleaseManifest {
        schema_version: SCHEMA_VERSION,
        created_at: created_at()?,
        honesty: HONESTY_NOTE.to_string(),
        artifacts,
    })
}

/// Serialize a manifest to the exact bytes that get signed: pretty-printed
/// JSON plus a trailing newline. `sign`/`verify` operate on these bytes
/// verbatim (the signature covers the file bytes, not a re-serialization).
pub fn to_json_bytes(manifest: &ReleaseManifest) -> Result<Vec<u8>, ManifestError> {
    let mut bytes = serde_json::to_vec_pretty(manifest)?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Parse manifest bytes, failing closed on malformed JSON or an unknown
/// [`SCHEMA_VERSION`].
pub fn from_json_bytes(bytes: &[u8]) -> Result<ReleaseManifest, ManifestError> {
    let manifest: ReleaseManifest = serde_json::from_slice(bytes)?;
    if manifest.schema_version != SCHEMA_VERSION {
        return Err(ManifestError::SchemaVersion {
            found: manifest.schema_version,
        });
    }
    Ok(manifest)
}

/// Re-stat and re-hash `bundle_dir` against `manifest`, failing closed
/// (hard error, never a warning) on ANY discrepancy: an empty manifest, a
/// listed-but-missing artifact, a size mismatch, a SHA-256 mismatch, or a
/// file in the directory that the manifest does not list.
pub fn check_against_dir(
    manifest: &ReleaseManifest,
    bundle_dir: &Path,
) -> Result<(), ManifestError> {
    if manifest.artifacts.is_empty() {
        return Err(ManifestError::EmptyManifest);
    }
    let on_disk = list_artifacts(bundle_dir)?;

    // Any on-disk file the manifest does not list is a hard failure.
    for (name, _) in &on_disk {
        if !manifest.artifacts.iter().any(|a| &a.name == name) {
            return Err(ManifestError::UnlistedFile(name.clone()));
        }
    }

    // Every listed artifact must exist with the exact size and hash.
    for entry in &manifest.artifacts {
        let Some((_, path)) = on_disk.iter().find(|(n, _)| n == &entry.name) else {
            return Err(ManifestError::MissingArtifact(entry.name.clone()));
        };
        let meta = fs::metadata(path).map_err(|e| io_err(path, e))?;
        if meta.len() != entry.size {
            return Err(ManifestError::SizeMismatch {
                name: entry.name.clone(),
                expected: entry.size,
                actual: meta.len(),
            });
        }
        let actual = sha256_file(path)?;
        if actual != entry.sha256 {
            return Err(ManifestError::Sha256Mismatch {
                name: entry.name.clone(),
                expected: entry.sha256.clone(),
                actual,
            });
        }
    }
    Ok(())
}

/* ── Verified SHA256SUMS merge (fail closed) ────────────────────────────────
   The publish pipeline shares ONE SHA256SUMS per prefix: publishing a new
   image fetches the remote SHA256SUMS, merges the fresh entry in, and
   re-signs the result. Re-signing bytes that were merely FETCHED is a
   supply-chain hole: if the bucket was tampered with, the pipeline would
   launder the attacker's lines under a brand-new valid signature. So the
   merge here is verify-FIRST and fail-closed: a remote SUMS with a missing
   or invalid hybrid signature is a hard error, never a warning.           */

/// One `sha256sum`-format line: lowercase-hex digest + file name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SumsEntry {
    /// Lowercase hex SHA-256 (64 chars).
    pub sha256: String,
    /// File name (a leading BSD `*` binary marker is stripped on parse).
    pub name: String,
}

/// Parse `SHA256SUMS` bytes into entries, failing closed on anything that is
/// not a well-formed `<64-hex>  <name>` line (blank lines are permitted) or
/// on a file listed twice.
pub fn parse_sha256sums(bytes: &[u8]) -> Result<Vec<SumsEntry>, ManifestError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ManifestError::SumsNotUtf8)?;
    let mut entries: Vec<SumsEntry> = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let bad = |detail: &str| ManifestError::SumsLine {
            line: line.to_string(),
            detail: detail.to_string(),
        };
        let (hash, rest) = line.split_once(' ').ok_or_else(|| bad("no space separator"))?;
        if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(bad("first field is not a 64-char hex SHA-256"));
        }
        if hash.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(bad("SHA-256 must be lowercase hex"));
        }
        // `sha256sum` writes two spaces (or ` *` for binary mode).
        let name = rest.strip_prefix(' ').or_else(|| rest.strip_prefix('*')).ok_or_else(
            || bad("expected `<sha256>  <name>` (two spaces, or ` *` binary marker)"),
        )?;
        if name.is_empty() {
            return Err(bad("empty file name"));
        }
        if entries.iter().any(|e| e.name == name) {
            return Err(ManifestError::SumsDuplicate(name.to_string()));
        }
        entries.push(SumsEntry { sha256: hash.to_string(), name: name.to_string() });
    }
    Ok(entries)
}

/// Render entries back to canonical `sha256sum` format: sorted by name (byte
/// order), `<sha256>  <name>\n` per entry.
pub fn render_sha256sums(entries: &[SumsEntry]) -> String {
    let mut sorted: Vec<&SumsEntry> = entries.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    let mut out = String::new();
    for e in sorted {
        out.push_str(&e.sha256);
        out.push_str("  ");
        out.push_str(&e.name);
        out.push('\n');
    }
    out
}

/// Verify-then-merge a fetched remote `SHA256SUMS` into freshly computed
/// local lines, **fail closed**:
///
/// - `remote_sums == None` is the bootstrap case (no remote SUMS exists yet):
///   the result is just the normalized local lines. A signature supplied
///   without remote bytes is rejected as inconsistent input.
/// - Remote bytes with **no** signature: [`ManifestError::RemoteSumsUnsigned`].
///   The merge NEVER proceeds on unverified remote content — re-signing it
///   would launder a tampered bucket object under a fresh signature.
/// - Remote bytes whose hybrid Falcon-1024+ML-DSA-87 signature (AND-of-both,
///   `postern_release::sign::verify_manifest`, reused unmodified) does not
///   verify over the **exact fetched bytes**:
///   [`ManifestError::RemoteSumsSignature`].
/// - Only after the signature verifies are the remote lines parsed and
///   merged. Local entries WIN on a name collision (the fresh build is the
///   source of truth for the artifact just produced); the union is returned
///   sorted, in canonical `sha256sum` format.
///
/// HONESTY: verifying the remote signature proves the fetched SUMS is one
/// this key previously signed — it does NOT make the merge an attestation,
/// and it cannot detect a *rollback* to an older validly-signed SUMS on its
/// own. Dev keys only, UNAUDITED; complements, does not replace, minisign.
pub fn merge_signed_sha256sums(
    local_sums: &str,
    remote_sums: Option<&[u8]>,
    remote_sig: Option<&[u8]>,
    public_keys: &postern_release::sign::PublicKeyBundle,
) -> Result<String, ManifestError> {
    let local = parse_sha256sums(local_sums.as_bytes())?;
    let remote = match (remote_sums, remote_sig) {
        (None, None) => Vec::new(),
        (None, Some(_)) => {
            return Err(ManifestError::RemoteSumsSignature(
                "a remote signature was supplied without remote SHA256SUMS bytes".to_string(),
            ))
        }
        (Some(_), None) => return Err(ManifestError::RemoteSumsUnsigned),
        (Some(sums), Some(sig)) => {
            let signature = postern_release::sign::HybridSignature::from_bytes(sig)
                .map_err(|e| ManifestError::RemoteSumsSignature(e.to_string()))?;
            postern_release::sign::verify_manifest(sums, &signature, public_keys)
                .map_err(|e| ManifestError::RemoteSumsSignature(e.to_string()))?;
            parse_sha256sums(sums)?
        }
    };

    // Union; the freshly built LOCAL entry wins any name collision.
    let mut merged: Vec<SumsEntry> = local;
    for r in remote {
        if !merged.iter().any(|e| e.name == r.name) {
            merged.push(r);
        }
    }
    Ok(render_sha256sums(&merged))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skip_list_covers_own_outputs_and_sha256sums() {
        assert!(is_skipped(MANIFEST_NAME));
        assert!(is_skipped(SIGNATURE_NAME));
        assert!(is_skipped("release-manifest.json.minisig"));
        assert!(is_skipped("SHA256SUMS"));
        assert!(is_skipped("SHA256SUMS.pqsig"));
        assert!(is_skipped("SHA256SUMS.minisig"));
        assert!(!is_skipped("postern-app-0.0.0-dev.bin"));
        assert!(!is_skipped("release-manifest.json.txt"));
    }

    #[test]
    fn manifest_is_sorted_and_versioned() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("b.bin"), b"bb").unwrap();
        fs::write(dir.path().join("a.bin"), b"a").unwrap();
        let m = build_manifest(dir.path()).unwrap();
        assert_eq!(m.schema_version, SCHEMA_VERSION);
        assert_eq!(m.honesty, HONESTY_NOTE);
        let names: Vec<_> = m.artifacts.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, ["a.bin", "b.bin"]);
        assert_eq!(m.artifacts[0].size, 1);
        assert_eq!(m.artifacts[1].size, 2);
        // created_at parses back as RFC 3339.
        m.created_at.parse::<jiff::Timestamp>().unwrap();
    }

    #[test]
    fn unknown_schema_version_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.bin"), b"a").unwrap();
        let mut m = build_manifest(dir.path()).unwrap();
        m.schema_version = 99;
        let bytes = to_json_bytes(&m).unwrap();
        assert!(matches!(
            from_json_bytes(&bytes).unwrap_err(),
            ManifestError::SchemaVersion { found: 99 }
        ));
    }
}
