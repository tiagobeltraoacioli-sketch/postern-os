//! End-to-end **durable restore** integration test for [`DirBackend`].
//!
//! HONESTY (mirrors the crate's scope): `MockSealer` / `MockHasher` are
//! ZERO-crypto test doubles (no confidentiality, no collision resistance), and
//! the `sha2-256` CID `DirBackend` computes is a Filecoin **content-address
//! locator** with zero integrity weight — NOT the PQ overlay. What this test
//! proves for real is exactly the [`DirBackend`] durability / fail-closed
//! self-verify contract: the sealed package survives the backend being dropped
//! (a process restart), is served back byte-identical from a fresh instance
//! over the same dir with **no in-RAM index**, and a single flipped on-disk
//! byte makes `get()` fail closed with [`BackendError::CidMismatch`].
//!
//! It closes the gap that the offline pipeline tests in `tests/vectors.rs` only
//! ever exercise [`MockBackend`] (an in-RAM `HashMap`): here the *whole*
//! `scan → manifest → package → seal → put_car` pipeline lands on the REAL,
//! durable, on-disk [`DirBackend`], for both the per-file sealed blobs and the
//! sealed PBP0 manifest package. Fully offline, zero network.

use std::fs;
use std::path::{Path, PathBuf};

use bloch_data::backend::{BackendError, Cid, DirBackend, StorageBackend};
use bloch_data::hash::{Hasher, MockHasher};
use bloch_data::manifest::{Manifest, ManifestEntry};
use bloch_data::package::{Package, TIER_DEFAULT};
use bloch_data::seal::{MockSealer, Opener, Sealer};

// ── A zero-dependency self-removing scratch directory ─────────────────────────
//
// The crate keeps a zero-dependency default build, so (like the `DirBackend`
// unit tests) we hand-roll a `TempDir` rather than pull the `tempfile` crate.

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> TempDir {
        // A per-run-unique name from pid + a nanosecond clock read, so parallel
        // test binaries never collide on the same real filesystem path.
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "bloch-data-dir-restore-{tag}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create scratch dir");
        TempDir { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

// ── The pipeline ──────────────────────────────────────────────────────────────

/// The realistic backup "source tree": relative path → plaintext bytes. Chosen
/// to exercise an empty file, small binary content, and a payload larger than a
/// single page so the durable spool round-trips more than one write size.
fn source_tree() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("notes/empty.txt", Vec::new()),
        (
            "notes/hello.txt",
            b"the kalinov bridge \x00\x01\xff sealed".to_vec(),
        ),
        ("photos/big.bin", vec![0xABu8; 200_000]),
    ]
}

/// Materialize `tree` as real files under `root` and return the on-disk paths in
/// the same order (the "scan" input the pipeline reads back).
fn write_source_tree(root: &Path, tree: &[(&'static str, Vec<u8>)]) -> Vec<PathBuf> {
    tree.iter()
        .map(|(rel, bytes)| {
            let p = root.join(rel);
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent).expect("create source subdir");
            }
            fs::write(&p, bytes).expect("write source file");
            p
        })
        .collect()
}

/// Result of running the whole backup pipeline against a real [`DirBackend`].
struct Backup {
    /// CID of the uploaded sealed PBP0 package (the manifest object).
    package_cid: Cid,
    /// The exact package bytes we uploaded (for a byte-identity check on
    /// restore).
    package_bytes: Vec<u8>,
    /// The plaintext manifest we sealed (to compare after open+decode).
    manifest: Manifest,
    /// Per-file sealed-blob CIDs, in canonical manifest order.
    blob_cids: Vec<Cid>,
    /// Per-file sealed bytes we put, in canonical manifest order.
    sealed_blobs: Vec<Vec<u8>>,
}

/// scan → per-file seal+put → manifest → seal → package → put_car, all onto the
/// REAL on-disk [`DirBackend`] rooted at `spool`.
fn run_backup(spool: &Path, source_root: &Path, tree: &[(&'static str, Vec<u8>)]) -> Backup {
    let sealer = MockSealer::new([0x42; 32]);
    let hasher = MockHasher::new();
    let mut backend = DirBackend::open(spool).expect("open spool");

    let paths = write_source_tree(source_root, tree);

    // ── scan: read each source file, seal it, spool the ciphertext, and record
    //    a manifest entry (content_cid = the durable spool locator; shake256 =
    //    the PQ-integrity digest of the sealed bytes — a MockHasher slot here).
    let file_ctx: &[u8] = b"postern-backup/blob/v1";
    let mut entries = Vec::new();
    for ((rel, _), abs) in tree.iter().zip(&paths) {
        let plaintext = fs::read(abs).expect("read source file");
        let sealed = sealer.seal(file_ctx, &plaintext).expect("seal blob");
        let blob_cid = backend.put_car(&sealed).expect("spool sealed blob");
        entries.push(ManifestEntry {
            path: rel.as_bytes().to_vec(),
            file_len: plaintext.len() as u64,
            content_cid: blob_cid.as_bytes().to_vec(),
            shake256: hasher.blob_digest(&sealed),
        });
    }

    // ── manifest: assemble the plaintext PBM0 manifest and canonicalize it
    //    (strictly ascending by path bytes, the spec's canonical order).
    let mut manifest = Manifest {
        backup_set_id: [0x11; 32],
        sequence: 7,
        created_unix: 1_700_000_000,
        entries,
    };
    manifest
        .canonicalize()
        .expect("no duplicate paths ⇒ canonicalizes");
    assert!(manifest.is_canonical(), "manifest must be canonical");
    let manifest_bytes = manifest.encode().expect("encode manifest");

    // Recover per-file blob CIDs / sealed bytes in the manifest's canonical
    // order, so the restore-side asserts line up with `manifest.entries`.
    let mut blob_cids = Vec::new();
    let mut sealed_blobs = Vec::new();
    for entry in &manifest.entries {
        let cid = Cid(entry.content_cid.clone());
        let sealed = backend.get(&cid).expect("re-fetch sealed blob for order recovery");
        blob_cids.push(cid);
        sealed_blobs.push(sealed);
    }

    // ── seal + package: seal the manifest, wrap it in the PBP0 package (pk/sig
    //    are opaque slots this crate never computes).
    let manifest_ctx: &[u8] = b"postern-backup/manifest/v1";
    let sealed_manifest = sealer.seal(manifest_ctx, &manifest_bytes).expect("seal manifest");
    let package = Package {
        kdf_tier: TIER_DEFAULT,
        salt: [0x7E; 16],
        sealed_manifest,
        pk: vec![0x01; 8],  // slot, filled by the out-of-scope PQ signer
        sig: vec![0x02; 16], // slot, filled by the out-of-scope PQ signer
    };
    let package_bytes = package.encode().expect("encode package");

    // ── put_car: upload the sealed package to the durable spool, get a CIDv1.
    let package_cid = backend.put_car(&package_bytes).expect("spool package");

    Backup {
        package_cid,
        package_bytes,
        manifest,
        blob_cids,
        sealed_blobs,
    }
    // `backend` dropped here — the point of the next phase is that NOTHING
    // survives in RAM; the spool is entirely on disk.
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// The core acceptance: durable end-to-end restore across a simulated process
/// restart, plus fail-closed self-verify on on-disk tampering.
#[test]
fn durable_end_to_end_restore_survives_restart_and_fails_closed() {
    let dir = TempDir::new("core");
    let spool = dir.path().join("spool");
    let source = dir.path().join("src");
    let tree = source_tree();

    // Phase 1: run the whole pipeline. `run_backup` DROPS its `DirBackend`
    // before returning — simulating the process exiting after the upload.
    let backup = run_backup(&spool, &source, &tree);

    // The package CID is a real CIDv1-raw-sha2-256 (multibase-base32 'b'…),
    // and its file exists on disk under exactly that name.
    let pkg_filename = filename_of(&spool, &backup.package_cid);
    assert!(
        pkg_filename.starts_with('b'),
        "package CID must be a multibase-base32 CIDv1 filename, got {pkg_filename:?}"
    );
    assert!(
        spool.join(&pkg_filename).is_file(),
        "the uploaded package must be spooled under its CID filename"
    );

    // Phase 2: FRESH backend over the SAME dir — no shared RAM state. This is
    // the restart. Everything below reads only from disk.
    let mut restored = DirBackend::open(&spool).expect("reopen spool after restart");

    // 2a — durability: the sealed package comes back byte-identical.
    let fetched_pkg = restored
        .get(&backup.package_cid)
        .expect("get package after restart");
    assert_eq!(
        fetched_pkg, backup.package_bytes,
        "restored package bytes must be byte-identical (durable, no RAM index)"
    );

    // 2b — the restored package fully re-opens to the original manifest: decode
    //     the PBP0 wrapper, open the sealed PBM0 manifest, decode it, and every
    //     per-file sealed blob is itself served back byte-identical from the
    //     durable spool and re-hashes to the manifest's recorded PQ digest.
    let sealer = MockSealer::new([0x42; 32]);
    let hasher = MockHasher::new();
    let decoded_pkg = Package::decode(&fetched_pkg).expect("decode restored package");
    let opened = sealer
        .open(b"postern-backup/manifest/v1", &decoded_pkg.sealed_manifest)
        .expect("open sealed manifest");
    let decoded_manifest = Manifest::decode(&opened).expect("decode manifest");
    assert_eq!(
        decoded_manifest, backup.manifest,
        "restored manifest must equal the one we sealed"
    );

    for (entry, (orig_cid, orig_sealed)) in decoded_manifest
        .entries
        .iter()
        .zip(backup.blob_cids.iter().zip(&backup.sealed_blobs))
    {
        // The manifest's content_cid is the durable spool locator.
        let blob_cid = Cid(entry.content_cid.clone());
        assert_eq!(&blob_cid, orig_cid, "content_cid must be the spool locator");
        // The sealed blob is durable across the restart too, byte-identical.
        let fetched_blob = restored.get(&blob_cid).expect("get sealed blob after restart");
        assert_eq!(
            &fetched_blob, orig_sealed,
            "restored sealed blob must be byte-identical"
        );
        // And it re-hashes to the manifest's recorded PQ-integrity digest
        // (the §6 re-hash-before-use check — MockHasher stands in for SHAKE-256).
        assert_eq!(
            hasher.blob_digest(&fetched_blob),
            entry.shake256,
            "fetched blob must re-hash to the manifest's shake256 slot"
        );
        // The opened plaintext file round-trips out of the sealed blob.
        let plaintext = sealer
            .open(b"postern-backup/blob/v1", &fetched_blob)
            .expect("open sealed blob");
        assert_eq!(
            plaintext.len() as u64, entry.file_len,
            "opened plaintext length must match the manifest entry"
        );
    }

    // 2c — fail closed on an unknown but well-formed CID (never spooled).
    let never = compute_locator_via_put(b"a blob that was never part of this backup");
    assert_eq!(
        restored.get(&never),
        Err(BackendError::NotFound),
        "an unknown CID must fail closed with NotFound"
    );

    // Phase 3: FAIL-CLOSED SELF-VERIFY. Flip a single on-disk byte of the
    // spooled package and confirm a fresh get() rejects it with CidMismatch
    // (the filesystem analog of the hardened-CAR content-address check).
    flip_one_byte(&spool.join(&pkg_filename));
    let mut after_tamper = DirBackend::open(&spool).expect("reopen after tamper");
    assert_eq!(
        after_tamper.get(&backup.package_cid),
        Err(BackendError::CidMismatch),
        "a single flipped on-disk byte must fail closed with CidMismatch"
    );
}

/// The corruption is detected specifically on the byte that was flipped: with
/// the package left intact, restore still succeeds — proving the CidMismatch
/// above is the tamper, not a flaky reopen.
#[test]
fn intact_package_restores_but_flipped_blob_fails_closed() {
    let dir = TempDir::new("blob");
    let spool = dir.path().join("spool");
    let source = dir.path().join("src");
    let tree = source_tree();
    let backup = run_backup(&spool, &source, &tree);

    // A fresh backend restores the package fine (control).
    {
        let mut be = DirBackend::open(&spool).expect("reopen");
        assert_eq!(
            be.get(&backup.package_cid).expect("get package"),
            backup.package_bytes
        );
    }

    // Now tamper with the LARGEST per-file sealed blob (the >1-page payload) and
    // confirm its get() fails closed, while the package still restores.
    let (idx, _) = backup
        .sealed_blobs
        .iter()
        .enumerate()
        .max_by_key(|(_, b)| b.len())
        .expect("at least one blob");
    let blob_cid = &backup.blob_cids[idx];
    let blob_file = spool.join(filename_of(&spool, blob_cid));
    flip_one_byte(&blob_file);

    let mut be = DirBackend::open(&spool).expect("reopen after blob tamper");
    assert_eq!(
        be.get(blob_cid),
        Err(BackendError::CidMismatch),
        "flipped sealed blob must fail closed with CidMismatch"
    );
    // The package, untouched, still restores byte-identical.
    assert_eq!(
        be.get(&backup.package_cid).expect("package still intact"),
        backup.package_bytes
    );
}

// ── Small on-disk helpers ─────────────────────────────────────────────────────

/// The on-disk filename `DirBackend` uses for `cid`, recovered by locating the
/// unique spool file whose bytes hash to it. `DirBackend` names files by the
/// CID string but does not expose that mapping publicly, so we find the file by
/// content-address: the entry whose own `put_car` locator round-trips to `cid`.
fn filename_of(spool: &Path, cid: &Cid) -> String {
    for entry in fs::read_dir(spool).expect("read spool dir") {
        let entry = entry.expect("dir entry");
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue; // skip any leftover temp files / subdirs
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue; // in-flight temp file
        }
        let bytes = fs::read(entry.path()).expect("read spool file");
        if &compute_locator_via_put(&bytes) == cid {
            return name;
        }
    }
    panic!("no spool file addresses {cid:?}");
}

/// Compute the CIDv1 locator for `bytes` the same way `DirBackend` does, by
/// round-tripping through a throwaway spool: put the bytes into a scratch
/// backend and read back the locator it assigns. This avoids re-implementing
/// the CID codec in the test — it uses the backend's own addressing. The
/// scratch dir lives under the system temp dir (never inside a spool being
/// scanned) and is removed immediately.
fn compute_locator_via_put(bytes: &[u8]) -> Cid {
    let mut scratch = std::env::temp_dir();
    scratch.push(format!(
        "bloch-data-locator-probe-{}-{}",
        std::process::id(),
        next_probe_nonce()
    ));
    let mut be = DirBackend::open(&scratch).expect("open probe spool");
    let cid = be.put_car(bytes).expect("probe put");
    let _ = fs::remove_dir_all(&scratch);
    cid
}

/// Flip the first byte of a file in place (a minimal on-disk mutation).
fn flip_one_byte(path: &Path) {
    let mut bytes = fs::read(path).expect("read file to tamper");
    assert!(!bytes.is_empty(), "cannot flip a byte of an empty file");
    bytes[0] ^= 0xFF;
    fs::write(path, &bytes).expect("write tampered file");
}

/// A monotonic nonce so concurrent locator probes never collide on a dir name.
fn next_probe_nonce() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}
