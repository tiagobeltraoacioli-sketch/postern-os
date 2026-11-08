//! End-to-end **real hybrid-PQ signed** backup acceptance test.
//!
//! This is the acceptance for the authenticity leg (the DATA0/PBP0 `pk`/`sig`
//! slots `bloch-data` leaves opaque). It runs the WHOLE real pipeline —
//! `scan → per-file REAL-seal + REAL-shake256 → manifest → REAL-seal →
//! package → REAL SHAKE-256 manifest_root → REAL ML-DSA-65 ‖ Falcon-1024 sign
//! → put_car(DirBackend)` — then, after a simulated process restart (drop +
//! reopen the on-disk spool), an INDEPENDENT verifier:
//!
//! * recomputes the `SHAKE-256/256` `manifest_root` over the fetched package's
//!   committed prefix and requires it equals the DATA0 anchor's `new_root`;
//! * ties `signer_commit` to `pk` via real `SHA3-256`;
//! * pins `pk` to the vault key it re-derives from the same seed; and
//! * verifies **BOTH** lattice halves of the hybrid signature over the anchor
//!   transcript ([`bloch_crypto::crypto::verify`], via
//!   [`postern_backup_net::verify_signed_backup`]).
//!
//! Then it proves fail-closed behaviour: a single tampered byte in the blob
//! (sealed manifest), the anchored root, the public key, or EITHER signature
//! half flips verify to reject. Fully offline, zero network — the signer is the
//! real `bloch-crypto` PQClean path, the spool is the real durable
//! [`bloch_data::backend::DirBackend`], no live provider.

use std::fs;
use std::path::{Path, PathBuf};

use bloch_data::anchor::{AnchorEnvelope, CID_LEN};
use bloch_data::backend::{Cid, DirBackend, StorageBackend};
use bloch_data::manifest::{Manifest, ManifestEntry};
use bloch_data::package::{Package, TIER_FLOOR};
use bloch_data::seal::Sealer;

use postern_backup_net::{
    sign_backup, verify_signed_backup, BackupVerifyError, Hasher, PosternSealer, Shake256Hasher,
    VaultSigner,
};

const BLOB_CTX: &[u8] = b"postern-backup/blob/v1";
const MANIFEST_CTX: &[u8] = b"postern-backup/manifest/v1";
const SALT: [u8; 16] = [0x7E; 16];
const PASSPHRASE: &[u8] = b"correct horse battery staple";
// The vault SIGNING seed (distinct from the SEAL passphrase): the same seed
// re-derives the byte-identical hybrid vault key on a fresh device.
const VAULT_SEED: [u8; 32] = [0x9Cu8; 32];

// Hybrid suite-0x0001 signature layout, for the half-targeted tamper legs:
// 4-byte suite header ‖ ML-DSA-65 sig (3309) ‖ Falcon-1024 sig (remainder).
const SUITE_HEADER_LEN: usize = 4;
const MLDSA_SIG_LEN: usize = 3309;

// ── zero-dependency self-removing scratch dir ────────────────────────────────

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
        path.push(format!("postern-signed-backup-{tag}-{}-{nonce}", std::process::id()));
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

// ── the signed backup produced by the write side ─────────────────────────────

struct SignedBackup {
    package_cid: Cid,
    package_bytes: Vec<u8>,
    /// The DATA0 anchor the vault would write on-chain, carrying the REAL
    /// SHAKE-256 `manifest_root` (`new_root`) and signed transcript.
    anchor: AnchorEnvelope,
}

fn source_tree() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("notes/empty.txt", Vec::new()),
        ("notes/hello.txt", b"the kalinov bridge \x00\x01\xff signed for real".to_vec()),
        ("photos/big.bin", (0..200_000u32).map(|i| i as u8).collect()),
    ]
}

/// scan → seal → manifest → seal → package → SIGN → put_car, all onto the real
/// on-disk spool. Fills the package's `pk`/`sig` with a REAL hybrid signature
/// and returns the signed DATA0 anchor. Drops its backend before returning.
fn run_signed_backup(spool: &Path, source_root: &Path, tree: &[(&'static str, Vec<u8>)]) -> SignedBackup {
    let sealer = PosternSealer::from_passphrase(PASSPHRASE, &SALT, TIER_FLOOR).expect("derive seal key");
    let hasher = Shake256Hasher::new();
    let signer = VaultSigner::from_seed(&VAULT_SEED).expect("derive vault signing key");
    let mut backend = DirBackend::open(spool).expect("open spool");

    // scan → per-file seal + real shake256 → spool.
    let mut entries = Vec::new();
    for (rel, bytes) in tree {
        let p = source_root.join(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).expect("create source subdir");
        }
        fs::write(&p, bytes).expect("write source file");

        let sealed = sealer.seal(BLOB_CTX, bytes).expect("seal blob");
        let blob_cid = backend.put_car(&sealed).expect("spool sealed blob");
        entries.push(ManifestEntry {
            path: rel.as_bytes().to_vec(),
            file_len: bytes.len() as u64,
            content_cid: blob_cid.as_bytes().to_vec(),
            shake256: hasher.blob_digest(&sealed),
        });
    }

    let mut manifest = Manifest {
        backup_set_id: [0x11; 32],
        sequence: 7,
        created_unix: 1_700_000_000,
        entries,
    };
    manifest.canonicalize().expect("no dup paths");
    let manifest_bytes = manifest.encode().expect("encode manifest");
    let sealed_manifest = sealer.seal(MANIFEST_CTX, &manifest_bytes).expect("seal manifest");

    // package with EMPTY pk/sig slots — sign_backup fills them for real.
    let mut package = Package {
        kdf_tier: TIER_FLOOR,
        salt: SALT,
        sealed_manifest,
        pk: Vec::new(),
        sig: Vec::new(),
    };

    // SIGN: stamp the vault pubkey, compute the real SHAKE-256 manifest_root +
    // real SHA3-256(pk) signer_commit, build the DATA0 anchor, hybrid-sign it.
    let anchor = sign_backup(
        &signer,
        &hasher,
        [0x22; 32],       // namespace_id
        manifest.sequence, // sequence
        [0u8; 32],        // prev_root (genesis)
        [0x00; CID_LEN],  // manifest_cid (locator only)
        &mut package,
    )
    .expect("sign backup");

    // The slots bloch-data leaves opaque are now filled with real bytes.
    assert_eq!(package.pk, signer.public_key(), "pk slot filled with the vault pubkey");
    assert!(
        package.sig.len() > SUITE_HEADER_LEN + MLDSA_SIG_LEN,
        "sig slot filled with a real ≈4.6 KB hybrid signature, not a placeholder"
    );

    let package_bytes = package.encode().expect("encode package");
    let package_cid = backend.put_car(&package_bytes).expect("spool package");

    SignedBackup { package_cid, package_bytes, anchor }
    // backend dropped here — the restart boundary.
}

// ── the acceptance ───────────────────────────────────────────────────────────

#[test]
fn signed_backup_verifies_independently_and_fails_closed_on_tamper() {
    let dir = TempDir::new("core");
    let spool = dir.path().join("spool");
    let source = dir.path().join("src");
    let tree = source_tree();

    // Write side: full pipeline + REAL hybrid signature; drops its backend.
    let backup = run_signed_backup(&spool, &source, &tree);

    // ── INDEPENDENT verify side ──────────────────────────────────────────────
    // Reconstruct the hasher from scratch and re-derive the pinned vault pubkey
    // from the same seed (the restore-side knows its own vault key).
    let hasher = Shake256Hasher::new();
    let vault_pk = VaultSigner::from_seed(&VAULT_SEED).unwrap().public_key().to_vec();

    // Restart: fresh backend over the same on-disk spool, no RAM index.
    let mut restored = DirBackend::open(&spool).expect("reopen spool after restart");
    let fetched = restored.get(&backup.package_cid).expect("get package");
    assert_eq!(fetched, backup.package_bytes, "package bytes durable across restart");
    let package = Package::decode(&fetched).expect("decode package");

    // (independent SHAKE-256 root recompute equals the anchor's new_root)
    let independent_root = hasher.manifest_root(&package).expect("recompute root");
    assert_eq!(
        backup.anchor.manifest_root, independent_root,
        "DATA0 anchor new_root must equal the independently-recomputed SHAKE-256 root"
    );

    // THE FULL AUTHENTICITY CHECK: root + signer_commit + pin + BOTH hybrid halves.
    assert_eq!(
        verify_signed_backup(&hasher, &backup.anchor, &package, &vault_pk),
        Ok(()),
        "honest signed backup must verify: SHAKE-256 root + hybrid ML-DSA ‖ Falcon signature"
    );

    // ── fail-closed: a single tampered byte in blob / root / pk / sig rejects ─

    // (blob) one byte in the sealed manifest → root leg mismatch.
    {
        let mut p = package.clone();
        p.sealed_manifest[0] ^= 0x01;
        assert!(
            matches!(
                verify_signed_backup(&hasher, &backup.anchor, &p, &vault_pk),
                Err(BackupVerifyError::Root(_))
            ),
            "one tampered sealed-manifest byte must be rejected by the root leg"
        );
    }

    // (root) one byte in the anchor's committed manifest_root → reject.
    {
        let mut a = backup.anchor.clone();
        a.manifest_root[0] ^= 0x01;
        assert!(
            verify_signed_backup(&hasher, &a, &package, &vault_pk).is_err(),
            "one tampered anchored-root byte must be rejected"
        );
    }

    // (pk) one byte in the public key → signer_commit leg mismatch.
    {
        let mut p = package.clone();
        p.pk[SUITE_HEADER_LEN + 7] ^= 0x01;
        assert!(
            matches!(
                verify_signed_backup(&hasher, &backup.anchor, &p, &vault_pk),
                Err(BackupVerifyError::Signer(_)) | Err(BackupVerifyError::UnexpectedSigner)
            ),
            "one tampered pk byte must be rejected"
        );
    }

    // (sig) one byte in the signature → hybrid signature rejected.
    {
        let mut p = package.clone();
        let last = p.sig.len() - 1;
        p.sig[last] ^= 0x01;
        assert_eq!(
            verify_signed_backup(&hasher, &backup.anchor, &p, &vault_pk),
            Err(BackupVerifyError::BadSignature),
            "one tampered signature byte must be rejected (fail-closed)"
        );
    }

    // (both halves are actually checked) tamper ONLY ML-DSA, then ONLY Falcon.
    {
        let mut p = package.clone();
        p.sig[SUITE_HEADER_LEN] ^= 0x01; // ML-DSA half
        assert_eq!(
            verify_signed_backup(&hasher, &backup.anchor, &p, &vault_pk),
            Err(BackupVerifyError::BadSignature),
            "tampering only the ML-DSA half must reject"
        );

        let mut q = package.clone();
        let falcon_off = SUITE_HEADER_LEN + MLDSA_SIG_LEN + 9;
        assert!(falcon_off < q.sig.len(), "signature has a Falcon half");
        q.sig[falcon_off] ^= 0x01; // Falcon half
        assert_eq!(
            verify_signed_backup(&hasher, &backup.anchor, &q, &vault_pk),
            Err(BackupVerifyError::BadSignature),
            "tampering only the Falcon half must reject"
        );
    }
}
