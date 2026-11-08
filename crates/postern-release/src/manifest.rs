//! `SHA256SUMS` manifest builder.
//!
//! Mirrors the repo's existing OS/pmOS + enterprise-delivery convention (see
//! `enterprise/deployment/signing/sign-build.sh`, which this module is
//! deliberately byte-compatible with for the same artifact set):
//!
//! - one line per artifact file: `<sha256-hex>  <relative-path>\n` (the
//!   two-space separator is GNU coreutils `sha256sum` / BSD `shasum -a 256`
//!   text-mode output, and is what `sha256sum -c` / `shasum -a 256 -c`
//!   expect);
//! - paths are recorded **relative** to the artifacts directory root, with
//!   `/` separators, so the manifest is portable and `-c` works when run
//!   from that root;
//! - entries are sorted in `LC_ALL=C` byte order (Rust's default `&str`/`&[u8]`
//!   ordering already is byte order for the ASCII paths this convention
//!   uses, so a plain `.sort()` reproduces `LC_ALL=C sort` exactly);
//! - the manifest itself, and any detached signature file over it
//!   (`SHA256SUMS.minisig`, `SHA256SUMS.pqsig`, ... — anything matching
//!   `SHA256SUMS.*sig`), are excluded, so re-running the builder — or signing
//!   a directory that already has a previous manifest/signature sitting in
//!   it — never hashes its own output.

use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use thiserror::Error;

/// The manifest's fixed filename, matching the repo-wide convention.
pub const MANIFEST_NAME: &str = "SHA256SUMS";

/// Errors building a manifest.
#[derive(Debug, Error)]
pub enum ManifestError {
    /// The given path is not a directory (or does not exist).
    #[error("artifacts path is not a directory: {0:?}")]
    NotADirectory(PathBuf),
    /// The directory contains no hashable artifact files.
    #[error("no artifact files found under {0:?}")]
    Empty(PathBuf),
    /// A path under the artifacts directory is not valid UTF-8; the manifest
    /// format (and `shasum -c`) require text paths.
    #[error("non UTF-8 path under artifacts dir: {0:?}")]
    NonUtf8(PathBuf),
    /// An I/O error occurred while walking or reading an artifact.
    #[error("I/O error at {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

fn io_err(path: &Path, source: std::io::Error) -> ManifestError {
    ManifestError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// True for a filename the manifest must NEVER hash: the manifest itself
/// (`SHA256SUMS`), or a detached signature file over it — `SHA256SUMS.` followed
/// by anything, as long as the name ends in `sig` (covers `SHA256SUMS.minisig`,
/// this crate's own `SHA256SUMS.pqsig`, and any future `SHA256SUMS.*sig`
/// convention) — so signing/re-signing a directory never covers its own output.
pub fn is_excluded(file_name: &str) -> bool {
    file_name == MANIFEST_NAME
        || (file_name
            .strip_prefix(MANIFEST_NAME)
            .and_then(|rest| rest.strip_prefix('.'))
            .is_some_and(|rest| rest.ends_with("sig")))
}

/// Recursively collect every regular file under `dir`, skipping excluded
/// manifest/signature filenames. Symlinks are intentionally NOT followed (a
/// symlink is neither `is_dir()` nor `is_file()` under `DirEntry::file_type`,
/// which does not follow links) — a release artifacts directory should not
/// contain them, and silently walking outside the artifacts tree via a
/// symlink would be a worse default than skipping.
fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), ManifestError> {
    let entries = fs::read_dir(dir).map_err(|e| io_err(dir, e))?;
    for entry in entries {
        let entry = entry.map_err(|e| io_err(dir, e))?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|e| io_err(&path, e))?;
        if file_type.is_dir() {
            walk(&path, out)?;
        } else if file_type.is_file() {
            let file_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| ManifestError::NonUtf8(path.clone()))?;
            if is_excluded(file_name) {
                continue;
            }
            out.push(path);
        }
    }
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Infallible: writing to a String never fails.
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Build the `SHA256SUMS` manifest bytes for every regular file under
/// `artifacts_dir` (recursively), excluding the manifest and any detached
/// signature file over it (see [`is_excluded`]).
///
/// Returns exactly the bytes that must be hashed and hybrid-signed — the same
/// bytes [`write_manifest`] writes to `<artifacts_dir>/SHA256SUMS`, and the
/// same bytes [`crate::sign::sign_manifest`] / [`crate::sign::verify_manifest`]
/// operate over.
pub fn build_manifest(artifacts_dir: &Path) -> Result<Vec<u8>, ManifestError> {
    if !artifacts_dir.is_dir() {
        return Err(ManifestError::NotADirectory(artifacts_dir.to_path_buf()));
    }

    let mut files = Vec::new();
    walk(artifacts_dir, &mut files)?;

    let mut rel_paths: Vec<String> = files
        .iter()
        .map(|p| {
            let rel = p
                .strip_prefix(artifacts_dir)
                .expect("walked path is always under artifacts_dir");
            rel.components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/")
        })
        .collect();

    if rel_paths.is_empty() {
        return Err(ManifestError::Empty(artifacts_dir.to_path_buf()));
    }

    // `LC_ALL=C sort` orders by raw byte value; Rust's `str`/`String` `Ord` is
    // already byte-order for these ASCII relative paths, so a plain sort matches.
    rel_paths.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

    let mut manifest = Vec::new();
    for rel in &rel_paths {
        let full = artifacts_dir.join(rel);
        let bytes = fs::read(&full).map_err(|e| io_err(&full, e))?;
        let digest = Sha256::digest(&bytes);
        manifest.extend_from_slice(hex_lower(&digest).as_bytes());
        manifest.extend_from_slice(b"  ");
        manifest.extend_from_slice(rel.as_bytes());
        manifest.push(b'\n');
    }
    Ok(manifest)
}

/// Build the manifest (see [`build_manifest`]) and write it to
/// `<artifacts_dir>/SHA256SUMS`, returning the exact bytes written.
pub fn write_manifest(artifacts_dir: &Path) -> Result<Vec<u8>, ManifestError> {
    let bytes = build_manifest(artifacts_dir)?;
    let out = artifacts_dir.join(MANIFEST_NAME);
    fs::write(&out, &bytes).map_err(|e| io_err(&out, e))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write_file(dir: &Path, rel: &str, contents: &[u8]) {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, contents).unwrap();
    }

    #[test]
    fn is_excluded_matches_manifest_and_sig_files() {
        assert!(is_excluded("SHA256SUMS"));
        assert!(is_excluded("SHA256SUMS.minisig"));
        assert!(is_excluded("SHA256SUMS.pqsig"));
        assert!(is_excluded("SHA256SUMS.sig"));
        assert!(!is_excluded("SHA256SUMS.txt")); // does not end in "sig"
        assert!(!is_excluded("artifact.bin"));
        assert!(!is_excluded("notSHA256SUMS.sig")); // must start with the exact name
    }

    #[test]
    fn build_manifest_known_vector() {
        let dir = tempfile::tempdir().unwrap();
        write_file(dir.path(), "a.txt", b"hello");
        write_file(dir.path(), "sub/b.txt", b"world");

        let manifest = build_manifest(dir.path()).unwrap();
        let text = String::from_utf8(manifest).unwrap();

        // sha256("hello")
        let expect_a = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        // sha256("world")
        let expect_b = "486ea46224d1bb4fb680f34f7c9ad96a8f24ec88be73ea8e5a6c65260e9cb8a7";
        let expected = format!("{expect_a}  a.txt\n{expect_b}  sub/b.txt\n");
        assert_eq!(text, expected);
    }

    #[test]
    fn build_manifest_excludes_own_output_and_sig_files() {
        let dir = tempfile::tempdir().unwrap();
        write_file(dir.path(), "artifact.bin", b"payload");
        write_file(dir.path(), "SHA256SUMS", b"stale manifest, must not be hashed");
        write_file(dir.path(), "SHA256SUMS.minisig", b"stale sig, must not be hashed");
        write_file(dir.path(), "SHA256SUMS.pqsig", b"stale pq sig, must not be hashed");

        let manifest = build_manifest(dir.path()).unwrap();
        let text = String::from_utf8(manifest).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert!(text.ends_with("  artifact.bin\n"));
    }

    #[test]
    fn build_manifest_sorts_lc_all_c() {
        let dir = tempfile::tempdir().unwrap();
        // Uppercase sorts before lowercase under LC_ALL=C (byte order), which
        // is NOT how a locale-aware sort would order these. Deliberately
        // distinct words (not the same word in different case) so this does
        // not depend on the host filesystem being case-sensitive — macOS's
        // default APFS is case-insensitive-but-preserving, so "A.txt" and
        // "a.txt" would collide as the same directory entry there.
        write_file(dir.path(), "zebra.txt", b"1");
        write_file(dir.path(), "Banana.txt", b"2");
        write_file(dir.path(), "apple.txt", b"3");

        let manifest = build_manifest(dir.path()).unwrap();
        let text = String::from_utf8(manifest).unwrap();
        let names: Vec<&str> = text
            .lines()
            .map(|l| l.split_once("  ").unwrap().1)
            .collect();
        // 'B' (0x42) < 'a' (0x61) < 'z' (0x7A) in byte order, though a
        // locale-aware / case-insensitive sort would put "apple" first.
        assert_eq!(names, vec!["Banana.txt", "apple.txt", "zebra.txt"]);
    }

    #[test]
    fn build_manifest_empty_dir_errors() {
        let dir = tempfile::tempdir().unwrap();
        let err = build_manifest(dir.path()).unwrap_err();
        assert!(matches!(err, ManifestError::Empty(_)));
    }

    #[test]
    fn build_manifest_not_a_directory_errors() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("not-a-dir");
        fs::write(&file, b"x").unwrap();
        let err = build_manifest(&file).unwrap_err();
        assert!(matches!(err, ManifestError::NotADirectory(_)));
    }
}
