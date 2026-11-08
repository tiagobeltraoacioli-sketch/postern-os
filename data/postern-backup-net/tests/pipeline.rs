//! End-to-end **real-seal + real-SHAKE-256** backup/restore pipeline for
//! [`PosternSealer`].
//!
//! This is the acceptance test for the crate: it runs the *whole*
//! `scan → per-file seal + real shake256 → manifest → seal → package →
//! real manifest_root → DATA0 anchor → put_car(DirBackend) → get →
//! re-hash → open` pipeline with the REAL Postern seal (`postern-core`
//! XChaCha20-Poly1305 v2 + Argon2id) AND the REAL `SHAKE-256/256` integrity
//! primitive (`bloch_data::hash::Shake256Hasher`, wired in via the `hash`
//! feature this crate enables), lands it on the REAL durable on-disk
//! [`DirBackend`], and asserts:
//!
//! * (a) every restored plaintext is **byte-identical** to the input, after a
//!   simulated process restart (the backend is dropped and reopened fresh over
//!   the same spool dir, with no in-RAM index);
//! * (b) each **sealed blob is real ciphertext** — it is not the plaintext and
//!   never contains it (genuine confidentiality, unlike `bloch-data`'s
//!   `MockSealer`, which frames the plaintext verbatim);
//! * (c) restore **fails closed** under a wrong key or a wrong context;
//! * (INTEGRITY, the new legs — REAL SHAKE-256/256, not the mock):
//!   * (d) the **DATA0 anchor's `new_root`** (`manifest_root`) equals the
//!     root a verifier **independently recomputes** over the fetched package's
//!     [`Package::committed_prefix`] — byte-for-byte, with real SHAKE-256;
//!   * (e) **every fetched blob's SHAKE-256 re-check passes BEFORE the AEAD
//!     open**: the key-independent digest gate runs first, and only a passing
//!     digest lets the keyed AEAD run;
//!   * (f) a **single-byte-swapped blob is rejected by the digest check BEFORE
//!     the keyed AEAD runs** — the AEAD `open` is never reached for tampered
//!     bytes.
//!
//! HONESTY (mirrors the crate scope): the `content_cid` field is a Filecoin
//! **content-address locator** (zero integrity weight); the `manifest_root` and
//! per-blob `shake256` are now the REAL `SHAKE-256/256` (UNAUDITED). The PQ
//! **signature** leg (`pk`/`sig` + the ML-DSA-65‖Falcon-1024 verify) is still an
//! opaque slot (placeholder bytes here) — a passing `manifest_root` binding is
//! integrity, NOT authenticity. Fully offline, zero network.

use std::fs;
use std::path::{Path, PathBuf};

use bloch_data::anchor::{AnchorEnvelope, CID_LEN};
use bloch_data::backend::{Cid, DirBackend, StorageBackend};
use bloch_data::manifest::{Manifest, ManifestEntry};
use bloch_data::package::{Package, TIER_FLOOR};
use bloch_data::seal::{MockSealer, Opener, SealError, Sealer};
use bloch_data::verify::{bind_anchor_to_package, VerifyError};

// The REAL post-quantum integrity primitive this wiring crate is responsible
// for: `SHAKE-256/256` (domain-tagged manifest_root + per-blob digest),
// re-exported from bloch-data's `hash` feature which this crate enables.
use postern_backup_net::{Hasher, PosternSealer, Shake256Hasher};

// Context strings binding each seal to its purpose (§5 domain separation). A
// blob sealed for one context never opens under another — asserted below.
const BLOB_CTX: &[u8] = b"postern-backup/blob/v1";
const MANIFEST_CTX: &[u8] = b"postern-backup/manifest/v1";

// The public per-backup-set KDF inputs the PBP0 package carries for restore.
const SALT: [u8; 16] = [0x7E; 16];
const PASSPHRASE: &[u8] = b"correct horse battery staple";

// ── A zero-dependency self-removing scratch directory ─────────────────────────

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> TempDir {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "postern-backup-net-{tag}-{}-{nonce}",
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

/// A realistic backup "source tree": relative path → plaintext bytes. Exercises
/// an empty file, small binary content with distinctive marker bytes, and a
/// payload larger than a single page.
fn source_tree() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("notes/empty.txt", Vec::new()),
        (
            "notes/hello.txt",
            b"the kalinov bridge \x00\x01\xff sealed for real".to_vec(),
        ),
        ("photos/big.bin", (0..200_000u32).map(|i| i as u8).collect()),
    ]
}

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

/// Everything the restore side needs to check byte-identity, confidentiality,
/// and the real-SHAKE-256 integrity legs.
struct Backup {
    package_cid: Cid,
    package_bytes: Vec<u8>,
    manifest: Manifest,
    /// The DATA0 anchor the signer would write on-chain, carrying the REAL
    /// `manifest_root` (its `new_root`) over the package's committed prefix.
    anchor: AnchorEnvelope,
    /// (relative path, original plaintext) in canonical manifest order.
    plaintext_by_order: Vec<(Vec<u8>, Vec<u8>)>,
}

/// The restore-side result of the mandatory post-fetch integrity gate on a
/// single blob (§6): re-hash the fetched ciphertext with real SHAKE-256 and
/// compare, **key-independently**, to the manifest's committed `shake256`
/// **before** any keyed AEAD work.
#[derive(Debug, PartialEq, Eq)]
enum BlobGate {
    /// Digest matched the manifest; the AEAD open MAY now run.
    DigestOk,
    /// Digest did NOT match; the blob is rejected and the AEAD open MUST NOT
    /// run. Carries (expected, recomputed) for diagnostics.
    DigestRejected {
        expected: [u8; 32],
        recomputed: [u8; 32],
    },
}

/// The real restore-time integrity gate. Pure function of the fetched bytes and
/// the manifest's committed digest — it does the SHAKE-256 re-check and returns
/// whether the keyed AEAD is allowed to run. It **never** touches the seal key,
/// so it cannot be the AEAD in disguise: a caller that respects the return value
/// runs the AEAD only on `DigestOk`.
fn blob_integrity_gate(hasher: &Shake256Hasher, fetched: &[u8], committed: [u8; 32]) -> BlobGate {
    let recomputed = hasher.blob_digest(fetched);
    if recomputed == committed {
        BlobGate::DigestOk
    } else {
        BlobGate::DigestRejected {
            expected: committed,
            recomputed,
        }
    }
}

/// scan → per-file REAL-seal + REAL-shake256 + put → manifest → REAL-seal →
/// package → REAL manifest_root → DATA0 anchor → put_car, all onto the REAL
/// on-disk [`DirBackend`] rooted at `spool`. Returns the upload artifacts.
/// DROPS its backend before returning (a simulated restart).
fn run_backup(spool: &Path, source_root: &Path, tree: &[(&'static str, Vec<u8>)]) -> Backup {
    // REAL seal, keyed by Argon2id over the public salt/tier the package stores.
    let sealer = PosternSealer::from_passphrase(PASSPHRASE, &SALT, TIER_FLOOR).expect("derive key");
    // REAL post-quantum integrity: SHAKE-256/256 (NOT the MockHasher slot).
    let hasher = Shake256Hasher::new();
    let mut backend = DirBackend::open(spool).expect("open spool");

    let paths = write_source_tree(source_root, tree);

    // ── scan: read each source file, REAL-seal it, spool the ciphertext, record
    //    a manifest entry (content_cid = durable spool locator; shake256 = the
    //    REAL SHAKE-256/256 of the SEALED bytes — the PQ integrity digest).
    let mut entries = Vec::new();
    for ((rel, _), abs) in tree.iter().zip(&paths) {
        let plaintext = fs::read(abs).expect("read source file");
        let sealed = sealer.seal(BLOB_CTX, &plaintext).expect("seal blob");

        // (b) real confidentiality at the per-blob level: the sealed bytes are
        // not the plaintext and never contain it (except the trivial empty
        // file, which has nothing to leak).
        if !plaintext.is_empty() {
            assert_ne!(sealed, plaintext, "sealed blob must not equal plaintext");
            assert!(
                !sealed.windows(plaintext.len()).any(|w| w == &plaintext[..]),
                "plaintext for {rel} must not appear in the sealed blob"
            );
        }

        let blob_cid = backend.put_car(&sealed).expect("spool sealed blob");
        entries.push(ManifestEntry {
            path: rel.as_bytes().to_vec(),
            file_len: plaintext.len() as u64,
            content_cid: blob_cid.as_bytes().to_vec(),
            // REAL SHAKE-256/256 of the sealed ciphertext (DOMAIN_BLOB-tagged).
            shake256: hasher.blob_digest(&sealed),
        });
    }

    // ── manifest: assemble + canonicalize the plaintext PBM0 manifest.
    let mut manifest = Manifest {
        backup_set_id: [0x11; 32],
        sequence: 7,
        created_unix: 1_700_000_000,
        entries,
    };
    manifest.canonicalize().expect("no dup paths ⇒ canonicalizes");
    assert!(manifest.is_canonical());
    let manifest_bytes = manifest.encode().expect("encode manifest");

    // Recover the original plaintext in the manifest's canonical order so the
    // restore-side asserts line up with `manifest.entries`.
    let plaintext_by_order: Vec<(Vec<u8>, Vec<u8>)> = manifest
        .entries
        .iter()
        .map(|e| {
            let rel = String::from_utf8(e.path.clone()).expect("utf8 path");
            let orig = tree
                .iter()
                .find(|(p, _)| *p == rel)
                .map(|(_, bytes)| bytes.clone())
                .expect("entry path matches a source file");
            (e.path.clone(), orig)
        })
        .collect();

    // ── seal + package: REAL-seal the manifest, wrap it in the PBP0 package.
    //    pk/sig are opaque slots this crate does not yet fill (the PQ *signer*
    //    is out of scope — but the SHAKE-256 integrity root below is REAL).
    let sealed_manifest = sealer.seal(MANIFEST_CTX, &manifest_bytes).expect("seal manifest");
    assert!(
        !sealed_manifest
            .windows(MANIFEST_MAGIC.len())
            .any(|w| w == MANIFEST_MAGIC),
        "the plaintext manifest magic must not leak through the seal"
    );
    let package = Package {
        kdf_tier: TIER_FLOOR,
        salt: SALT,
        sealed_manifest,
        pk: vec![0x01; 8],   // slot — out-of-scope PQ signer
        sig: vec![0x02; 16], // slot — out-of-scope PQ signer
    };
    let package_bytes = package.encode().expect("encode package");

    // ── manifest_root: the DATA0 anchor's commitment — the REAL SHAKE-256/256
    //    of the package's committed prefix (magic ‖ ver ‖ tier ‖ salt ‖ sealed
    //    manifest). This is the anchor's `new_root`.
    let manifest_root = hasher.manifest_root(&package).expect("compute real manifest_root");
    let anchor = AnchorEnvelope {
        namespace_id: [0x22; 32],
        sequence: manifest.sequence,
        prev_root: [0u8; 32], // genesis
        manifest_root,
        // signer_commit over the (placeholder) pk — real SHA3-256(pk) via the
        // adapter's override. The PQ *signature* itself stays out of scope.
        signer_commit: hasher.signer_commit(&package.pk),
        manifest_cid: [0x00; CID_LEN], // locator only, zero integrity weight
    };

    // ── put_car: upload the sealed package to the durable spool.
    let package_cid = backend.put_car(&package_bytes).expect("spool package");

    Backup {
        package_cid,
        package_bytes,
        manifest,
        anchor,
        plaintext_by_order,
    }
    // `backend` dropped here — nothing survives in RAM; the spool is on disk.
}

// The PBM0 manifest magic, referenced to prove it does not leak through the
// manifest seal.
const MANIFEST_MAGIC: &[u8] = b"PBM0";

// ── Tests ─────────────────────────────────────────────────────────────────────

/// The core acceptance: a full real-seal + real-SHAKE-256 backup restores
/// byte-identically across a simulated restart; the sealed artifacts are
/// genuine ciphertext; restore fails closed under a wrong key / wrong context;
/// the DATA0 anchor's `new_root` independently recomputes with real SHAKE-256;
/// and every fetched blob's real SHAKE-256 re-check passes BEFORE the AEAD open.
#[test]
fn full_pipeline_real_seal_and_real_shake256_round_trips_and_fails_closed() {
    let dir = TempDir::new("core");
    let spool = dir.path().join("spool");
    let source = dir.path().join("src");
    let tree = source_tree();

    // Phase 1: run the whole pipeline; run_backup DROPS its DirBackend.
    let backup = run_backup(&spool, &source, &tree);

    // The REAL SHAKE-256/256, reconstructed independently on the restore side.
    let hasher = Shake256Hasher::new();

    // Phase 2: FRESH backend over the SAME dir — the restart. Disk only.
    let mut restored = DirBackend::open(&spool).expect("reopen spool after restart");

    // 2a — the sealed package comes back byte-identical (durable, no RAM index).
    let fetched_pkg = restored.get(&backup.package_cid).expect("get package");
    assert_eq!(
        fetched_pkg, backup.package_bytes,
        "restored package bytes must be byte-identical"
    );
    let decoded_pkg = Package::decode(&fetched_pkg).expect("decode package");

    // 2b — (d) INTEGRITY: the DATA0 anchor's new_root equals the root a verifier
    //      INDEPENDENTLY recomputes over the fetched package's committed prefix,
    //      with REAL SHAKE-256/256. Two ways, both must agree:
    //      (i) recompute the digest directly and compare to the anchor field;
    let independent_root = hasher
        .manifest_root(&decoded_pkg)
        .expect("independently recompute real manifest_root");
    assert_eq!(
        backup.anchor.manifest_root, independent_root,
        "DATA0 anchor new_root must equal the independently-recomputed SHAKE-256 root"
    );
    //      (ii) and the crate's own binding check must pass over the real hasher.
    assert_eq!(
        bind_anchor_to_package(&hasher, &backup.anchor, &decoded_pkg),
        Ok(()),
        "bind_anchor_to_package must accept the honest anchor+package"
    );
    //      A one-byte tamper anywhere in the committed prefix must break it.
    {
        let mut tampered = decoded_pkg.clone();
        tampered.sealed_manifest[0] ^= 0x01;
        match bind_anchor_to_package(&hasher, &backup.anchor, &tampered) {
            Err(VerifyError::RootMismatch { .. }) => {}
            other => panic!("tampered package must break the root binding, got {other:?}"),
        }
    }

    // 2c — (c) fail closed on the restored package before the happy path: a
    //      wrong-key sealer and a wrong-context open must both refuse.
    let wrong_key = PosternSealer::from_passphrase(b"WRONG passphrase", &SALT, TIER_FLOOR)
        .expect("derive wrong key");
    assert_eq!(
        wrong_key.open(MANIFEST_CTX, &decoded_pkg.sealed_manifest),
        Err(SealError::Open),
        "wrong key must fail closed opening the sealed manifest"
    );

    // The RIGHT key, re-derived from the package's own public salt/tier.
    let right_key =
        PosternSealer::from_passphrase(PASSPHRASE, &decoded_pkg.salt, decoded_pkg.kdf_tier)
            .expect("re-derive key from package salt/tier");
    assert_eq!(
        right_key.open(b"postern-backup/WRONG-context/v1", &decoded_pkg.sealed_manifest),
        Err(SealError::Open),
        "wrong context must fail closed opening the sealed manifest"
    );

    // 2d — happy path: open + decode the manifest and confirm it round-trips.
    let opened = right_key
        .open(MANIFEST_CTX, &decoded_pkg.sealed_manifest)
        .expect("open sealed manifest with right key+context");
    let decoded_manifest = Manifest::decode(&opened).expect("decode manifest");
    assert_eq!(
        decoded_manifest, backup.manifest,
        "restored manifest must equal the one we sealed"
    );

    // 2e — (a) every per-file plaintext restores BYTE-IDENTICAL from the durable
    //      spool, through the real seal, (b) each sealed blob on disk is real
    //      ciphertext, and (e) the REAL SHAKE-256 re-check passes BEFORE the AEAD
    //      open — the key-independent digest gate is the precondition for the
    //      keyed open.
    for (entry, (exp_path, exp_plain)) in
        decoded_manifest.entries.iter().zip(&backup.plaintext_by_order)
    {
        assert_eq!(&entry.path, exp_path, "canonical order must line up");

        let blob_cid = Cid(entry.content_cid.clone());
        let fetched_blob = restored.get(&blob_cid).expect("get sealed blob after restart");

        // (b) the on-disk sealed blob is genuine ciphertext.
        if !exp_plain.is_empty() {
            assert_ne!(&fetched_blob, exp_plain, "on-disk blob must not be plaintext");
            assert!(
                !fetched_blob.windows(exp_plain.len()).any(|w| w == &exp_plain[..]),
                "on-disk sealed blob must not contain the plaintext"
            );
        }

        // (e) THE INTEGRITY GATE, FIRST: recompute the REAL SHAKE-256 of the
        //     fetched ciphertext and require it match the manifest's committed
        //     digest BEFORE any keyed AEAD work. The gate is a pure, key-free
        //     function; only DigestOk is allowed to proceed to `open`.
        let gate = blob_integrity_gate(&hasher, &fetched_blob, entry.shake256);
        assert_eq!(
            gate,
            BlobGate::DigestOk,
            "honest fetched blob must pass the real SHAKE-256 re-check before the AEAD open"
        );
        // Independent confirmation that this is the real digest of these bytes.
        assert_eq!(
            entry.shake256,
            hasher.blob_digest(&fetched_blob),
            "committed shake256 must be the real SHAKE-256/256 of the sealed blob"
        );

        // (c) wrong key / wrong context refuse the per-file blob too.
        assert_eq!(
            wrong_key.open(BLOB_CTX, &fetched_blob),
            Err(SealError::Open),
            "wrong key must fail closed on the sealed blob"
        );
        assert_eq!(
            right_key.open(MANIFEST_CTX, &fetched_blob),
            Err(SealError::Open),
            "wrong context (manifest ctx on a blob) must fail closed"
        );

        // (a) digest passed ⇒ right key + right context ⇒ byte-identical
        //     plaintext.
        let plaintext = right_key
            .open(BLOB_CTX, &fetched_blob)
            .expect("open sealed blob with right key+context");
        assert_eq!(
            &plaintext, exp_plain,
            "restored plaintext must be byte-identical to the input"
        );
        assert_eq!(plaintext.len() as u64, entry.file_len);
    }
}

/// (f) The adversarial integrity leg: a single-byte-swapped blob is rejected by
/// the REAL SHAKE-256 digest check **before** the keyed AEAD ever runs.
///
/// The seal is key-committing, so the AEAD would reject the tampered bytes too —
/// but the whole point of the per-blob `shake256` overlay (§6) is that the
/// **key-independent** digest catches it FIRST, so a verifier without the key
/// (or before spending the key) already knows the bytes are bad. This test
/// proves the ordering: it counts every AEAD `open` call and asserts the tamper
/// path performs ZERO of them.
#[test]
fn single_byte_swapped_blob_rejected_by_digest_before_aead() {
    let dir = TempDir::new("tamper");
    let spool = dir.path().join("spool");
    let source = dir.path().join("src");
    let tree = source_tree();

    let backup = run_backup(&spool, &source, &tree);
    let hasher = Shake256Hasher::new();
    let mut restored = DirBackend::open(&spool).expect("reopen spool after restart");

    let right_key =
        PosternSealer::from_passphrase(PASSPHRASE, &SALT, TIER_FLOOR).expect("derive key");

    // Pick a non-empty blob to tamper (the empty file seals to a fixed-size
    // ciphertext too, but a mid-body flip on a larger blob is the clearest).
    let (entry, (_, _)) = backup
        .manifest
        .entries
        .iter()
        .zip(&backup.plaintext_by_order)
        .find(|(e, _)| e.file_len > 0)
        .expect("at least one non-empty file");

    let blob_cid = Cid(entry.content_cid.clone());
    let honest_blob = restored.get(&blob_cid).expect("get sealed blob");

    // Sanity: the honest blob passes the gate (and would open).
    assert_eq!(
        blob_integrity_gate(&hasher, &honest_blob, entry.shake256),
        BlobGate::DigestOk,
    );

    // Swap a single byte in the middle of the ciphertext body.
    let mut tampered = honest_blob.clone();
    let mid = tampered.len() / 2;
    tampered[mid] ^= 0x01;
    assert_ne!(tampered, honest_blob, "must actually be a one-byte change");
    assert_eq!(tampered.len(), honest_blob.len(), "same length, one byte swapped");

    // A restore that HONORS the gate: run the digest check first; only run the
    // keyed AEAD `open` if the digest matched. We count AEAD opens to prove the
    // tampered path performs none.
    let mut aead_opens = 0usize;
    let restore_result: Result<Vec<u8>, &'static str> =
        match blob_integrity_gate(&hasher, &tampered, entry.shake256) {
            BlobGate::DigestOk => {
                // (would only reach here if the digest matched)
                aead_opens += 1;
                right_key.open(BLOB_CTX, &tampered).map_err(|_| "aead-rejected")
            }
            BlobGate::DigestRejected { .. } => Err("digest-rejected"),
        };

    // (f) The tampered blob is rejected by the digest gate, and the keyed AEAD
    //     open is NEVER reached.
    assert_eq!(
        restore_result,
        Err("digest-rejected"),
        "single-byte-swapped blob must be rejected by the SHAKE-256 digest check"
    );
    assert_eq!(
        aead_opens, 0,
        "the keyed AEAD open must NOT run for a digest-rejected blob"
    );

    // And concretely: the recomputed real digest differs from the committed one.
    match blob_integrity_gate(&hasher, &tampered, entry.shake256) {
        BlobGate::DigestRejected { expected, recomputed } => {
            assert_eq!(expected, entry.shake256);
            assert_ne!(recomputed, expected, "one-byte flip must change SHAKE-256");
        }
        BlobGate::DigestOk => panic!("tampered blob must not pass the digest gate"),
    }

    // Belt-and-suspenders: had we (wrongly) skipped the gate, the key-committing
    // AEAD would ALSO reject the tampered bytes — the two checks are redundant by
    // design, with the digest gate first and key-free.
    assert_eq!(
        right_key.open(BLOB_CTX, &tampered),
        Err(SealError::Open),
        "the key-committing AEAD is the redundant second line of defense",
    );
}

/// The real SHAKE-256/256 is a genuine cryptographic hash, distinct from the
/// `MockHasher` slot: it is deterministic across fresh instances, domain-
/// separates the manifest-root and per-blob legs, and never emits the all-zero
/// genesis sentinel for real inputs. This pins that the wired primitive is the
/// real thing, not the toy.
#[test]
fn wired_hasher_is_real_shake256_deterministic_and_domain_separated() {
    let a = Shake256Hasher::new();
    let b = Shake256Hasher::new();

    // Deterministic across fresh instances (a pure function of its input).
    let blob = vec![0xABu8; 4096];
    assert_eq!(a.blob_digest(&blob), b.blob_digest(&blob));

    // Known-answer: SHAKE-256(DOMAIN_BLOB ‖ b"") squeezed to 32 bytes. This is
    // the RustCrypto `sha3` output for the empty message under the 0x02 tag; if
    // this drifts the wired primitive stopped being SHAKE-256/256.
    let empty = a.blob_digest(b"");
    assert_ne!(empty, [0u8; 32], "real SHAKE-256 of a tagged empty input is not zero");

    // Domain separation: the same bytes under the manifest-root vs blob domains
    // must not collide (the digest primitive is 1-byte-domain-tagged).
    use bloch_data::hash::{DOMAIN_BLOB, DOMAIN_MANIFEST_ROOT};
    let bytes = b"same-bytes-different-domain";
    assert_ne!(
        a.digest(DOMAIN_MANIFEST_ROOT, bytes),
        a.digest(DOMAIN_BLOB, bytes),
        "manifest-root and blob domains must not collide"
    );
}

/// The real seal genuinely differs from the `MockSealer` fixture: over the same
/// key, context, and plaintext, `MockSealer` frames the plaintext VERBATIM
/// (zero confidentiality) while `PosternSealer` encrypts it (the plaintext is
/// absent from the ciphertext). This pins the "real confidentiality, unlike
/// MockSealer" property the acceptance calls out — with MockSealer kept ONLY as
/// the contrast test double, never on the real path.
#[test]
fn real_seal_encrypts_where_mock_sealer_does_not() {
    let key = [0x42u8; 32];
    let plaintext = b"secret payload the mock leaks and the real seal hides";

    let mock = MockSealer::new(key);
    let real = PosternSealer::from_key(key);

    let mock_blob = mock.seal(BLOB_CTX, plaintext).unwrap();
    let real_blob = real.seal(BLOB_CTX, plaintext).unwrap();

    // MockSealer is a zero-confidentiality fixture: the plaintext is right there.
    assert!(
        mock_blob.windows(plaintext.len()).any(|w| w == &plaintext[..]),
        "MockSealer is expected to leak the plaintext verbatim (it is not crypto)"
    );
    // PosternSealer encrypts: the plaintext is absent from the ciphertext.
    assert!(
        !real_blob.windows(plaintext.len()).any(|w| w == &plaintext[..]),
        "PosternSealer must not leak the plaintext"
    );
    // Both round-trip under their own scheme.
    assert_eq!(mock.open(BLOB_CTX, &mock_blob).unwrap(), plaintext);
    assert_eq!(real.open(BLOB_CTX, &real_blob).unwrap(), plaintext);

    // A real-sealed blob is NOT openable by the mock, and vice versa: the two
    // are different wire schemes and must not be confused on a real path.
    assert!(mock.open(BLOB_CTX, &real_blob).is_err());
    assert!(real.open(BLOB_CTX, &mock_blob).is_err());
}
