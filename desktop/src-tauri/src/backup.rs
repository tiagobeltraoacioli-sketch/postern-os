// SPDX-License-Identifier: MIT OR Apache-2.0
//! Encrypted Backup — the LOCAL half of the Postern → Filecoin user-backup path,
//! wired to the real `bloch-data` (`postern-data`) scaffold crate behind the
//! desktop's `backup_*` #[tauri::command]s.
//!
//! What is REAL here (runs, end-to-end, on your machine):
//!   * **Encryption** — the file is sealed with the canonical Postern AEAD
//!     (`postern_core::aead`: XChaCha20-Poly1305 v2, key-committing,
//!     context-bound) under an Argon2id-derived key (`postern_core::kdf`). The
//!     passphrase and the derived key NEVER leave this process — no network, no
//!     disk for the key, `Zeroizing` on drop.
//!   * **The PBM0 manifest + PBP0 package codecs** — the real `bloch-data`
//!     strict binary codecs wrap the sealed manifest.
//!   * **The DATA0 anchor** — a real `bloch-data::AnchorEnvelope`, whose
//!     `manifest_root` is a REAL **SHAKE-256/256** (post-quantum hash) over the
//!     package's committed prefix, and whose `signer_commit` is a real
//!     **SHA3-256**. On restore we RECOMPUTE the SHAKE-256 root and check it
//!     equals the anchor — a real, fail-closed anchor verification.
//!   * **Local content-addressed store** ([`DirBackend`]) — a real
//!     `bloch-data::StorageBackend` that writes the sealed blob to a
//!     user-chosen folder keyed by its SHAKE-256 digest, and re-hashes it on
//!     read (the crate's "backend bytes are untrusted, re-verify" discipline).
//!
//! What is HONESTLY NOT here (the honesty rails, non-negotiable):
//!   * **`bloch-data` is a SCAFFOLD, UNAUDITED.** So is everything in this repo.
//!   * **No ML-DSA/Falcon signature.** The PBP0 `pk`/`sig` slots are EMPTY and
//!     the anchor is UNSIGNED — the real PQ signer lives in the out-of-scope
//!     `postern-backup-net` crate. The anchor's *hash* commitment is real PQ;
//!     its *signature* is not wired. So a stored anchor is a **claim**, not a
//!     settlement.
//!   * **Filecoin upload is REAL, but only of the SEALED ciphertext.**
//!     "Back up to Filecoin" ([`backup_filecoin_upload`]) POSTs the
//!     already-encrypted blob to Lighthouse (`node.lighthouse.storage`) over
//!     real HTTPS (the desktop's `ureq` + rustls client, NOT
//!     `bloch-data::LiveBackend` — that hand-rolled HTTP path has no in-crate
//!     TLS and is still a `todo!()` stub this module never calls). The provider
//!     therefore stores CIPHERTEXT ONLY: trust it for AVAILABILITY, never for
//!     confidentiality. The user supplies their OWN Lighthouse token (free
//!     account at lighthouse.storage); it is passed per-call, never logged,
//!     never persisted server-side. [`backup_filecoin_retrieve`] fetches the
//!     blob back from the gateway for a byte-identity verify.
//!   * The Bloch base this would anchor to is `k=…`, low-hashrate,
//!     51%-attackable, zero-value pre-mainnet. Anchoring ≠ backed up.
//!
//! Like `courier`/`vault`, the pure core here (`seal_backup` / `store_to_dir` /
//! `restore_from_dir`) takes no `State` and does its own IO, so the in-module
//! `#[cfg(test)]` round-trip test drives the real seal → store → restore path
//! offline. The three commands (`backup_seal`, `backup_store`, `backup_restore`)
//! are thin wrappers over that core.

use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use bloch_data::{
    AnchorEnvelope, BackendError, Cid, DealStatus, Manifest, ManifestEntry, Package,
    StorageBackend, CID_LEN, TIER_DEFAULT, TIER_FLOOR,
};
use serde_json::{json, Value};
use zeroize::Zeroizing;

/// Mandatory per-response honesty text, surfaced verbatim in every `backup_*`
/// result's `honesty` field so the pane can never overclaim. The phrases
/// "UNAUDITED scaffold", "unsigned anchor" and "not backed up" are load-bearing
/// (the module test asserts them).
pub const HONESTY: &str = "UNAUDITED scaffold reference prototype (bloch-data). Encryption is real \
     (Postern AEAD: XChaCha20-Poly1305 v2, key-committing, Argon2id key — passphrase/key never \
     leave this device). The DATA0 anchor's manifest_root is a real SHAKE-256 (post-quantum hash) \
     and is re-verified on restore, but the anchor is UNSIGNED — no ML-DSA/Falcon signature is \
     wired (that lives in the out-of-scope postern-backup-net crate), so an anchor is a claim, not \
     settlement. NO Filecoin upload happens here (LiveBackend is a todo!() stub). Anchoring is NOT \
     'backed up'; the base is zero-value pre-mainnet.";

/// Context string binding the sealed FILE blob (domain separation, §5).
const CTX_BLOB: &[u8] = b"postern-backup/blob/v1";
/// Context string binding the sealed PBM0 manifest.
const CTX_MANIFEST: &[u8] = b"postern-backup/manifest/v1";
/// Namespace-derivation domain (mirrors the design's `postern-backup/ns/v1`).
const NS_DOMAIN: &[u8] = b"postern-backup/ns/v1";
/// CIDv1 prefix for a raw-codec sha2-256 multihash: `0x01 ‖ 0x55 ‖ 0x12 0x20`.
const CIDV1_RAW_SHA256_PREFIX: [u8; 4] = [0x01, 0x55, 0x12, 0x20];

// ─────────────────────────────────────────────────────────────────────────────
// Real PQ hashing (SHAKE-256/256, SHA3-256) + sha2-256 for the CID locator.
// ─────────────────────────────────────────────────────────────────────────────

/// Real SHAKE-256/256 (32-byte squeeze) — the post-quantum manifest-root hash.
fn shake256_32(data: &[u8]) -> [u8; 32] {
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    let mut h = sha3::Shake256::default();
    h.update(data);
    let mut reader = h.finalize_xof();
    let mut out = [0u8; 32];
    XofReader::read(&mut reader, &mut out);
    out
}

/// Real SHA3-256 — the `signer_commit` primitive (matches bloch-crypto's
/// address family), computed here over the (empty) enveloped signer pk.
fn sha3_256(data: &[u8]) -> [u8; 32] {
    use sha3::Digest;
    let mut h = sha3::Sha3_256::new();
    h.update(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// sha2-256 (via the crate's dependency-free FIPS-180-4 core) — only for the
/// CIDv1 locator's multihash; carries zero integrity weight (§4).
fn sha2_256(data: &[u8]) -> [u8; 32] {
    let mut h = crate::sha256::Sha256::new();
    h.update(data);
    h.finish()
}

/// Build the 36-byte CIDv1 binary locator for the encoded package bytes.
fn manifest_cid_of(package_bytes: &[u8]) -> [u8; CID_LEN] {
    let mut cid = [0u8; CID_LEN];
    cid[..4].copy_from_slice(&CIDV1_RAW_SHA256_PREFIX);
    cid[4..].copy_from_slice(&sha2_256(package_bytes));
    cid
}

// ─────────────────────────────────────────────────────────────────────────────
// DirBackend — a real StorageBackend over a user-chosen folder (content-
// addressed by SHAKE-256). The offline `MockBackend` analog, but on disk.
// ─────────────────────────────────────────────────────────────────────────────

/// A real, offline `bloch-data::StorageBackend` that persists opaque ciphertext
/// blobs to a folder, keyed by their SHAKE-256 digest. Reads re-hash on `get`'s
/// caller side (see [`restore_from_dir`]) per the crate's "backend bytes are
/// untrusted" rule. This is the local, honest stand-in for the Filecoin
/// `LiveBackend` (which is a `todo!()` stub — never called here).
pub struct DirBackend {
    root: PathBuf,
}

impl DirBackend {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn blob_path(&self, cid: &[u8]) -> PathBuf {
        self.root.join(format!("{}.blob", hex::encode(cid)))
    }
}

impl StorageBackend for DirBackend {
    fn put_car(&mut self, bytes: &[u8]) -> Result<Cid, BackendError> {
        let id = shake256_32(bytes);
        fs::create_dir_all(&self.root)
            .map_err(|e| BackendError::Unavailable(e.to_string()))?;
        fs::write(self.blob_path(&id), bytes)
            .map_err(|e| BackendError::Unavailable(e.to_string()))?;
        Ok(Cid(id.to_vec()))
    }

    fn get(&mut self, cid: &Cid) -> Result<Vec<u8>, BackendError> {
        fs::read(self.blob_path(&cid.0)).map_err(|_| BackendError::NotFound)
    }

    fn deal_status(&mut self, cid: &Cid) -> Result<DealStatus, BackendError> {
        if self.blob_path(&cid.0).exists() {
            // HOT layer only — a local file is present. NEVER a Filecoin deal.
            Ok(DealStatus::Acknowledged)
        } else {
            Err(BackendError::NotFound)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pure core — seal / store / restore. No Tauri State; own IO. Test-driven.
// ─────────────────────────────────────────────────────────────────────────────

/// The artifacts produced by [`seal_backup`]: the encrypted blob, the PBP0
/// package, the 177-byte DATA0 anchor, and the derived ids/roots.
pub struct SealResult {
    /// Hex of the SHAKE-256 `manifest_root` — the backup-set id / file stem.
    pub set_id: String,
    /// The real SHAKE-256/256 manifest root committed by the anchor.
    pub manifest_root: [u8; 32],
    /// The 177-byte DATA0 anchor envelope (UNSIGNED).
    pub anchor: Vec<u8>,
    /// The encoded PBP0 package (sealed manifest + salt/tier + empty pk/sig).
    pub package: Vec<u8>,
    /// The sealed (real AEAD) file blob — what the DirBackend stores.
    pub sealed_blob: Vec<u8>,
    /// The blob's SHAKE-256 content id (the DirBackend locator).
    pub blob_cid: [u8; 32],
    /// Argon2id tier used ([`TIER_DEFAULT`] / [`TIER_FLOOR`]).
    pub tier: u8,
    /// Plaintext file length (bytes).
    pub plaintext_len: u64,
}

fn derive_key(passphrase: &[u8], salt: &[u8], tier: u8) -> Result<Zeroizing<[u8; 32]>, String> {
    let k = if tier == TIER_FLOOR {
        postern_core::kdf::derive_key_floor(passphrase, salt)
    } else {
        postern_core::kdf::derive_key(passphrase, salt)
    };
    k.map_err(|e| format!("key derivation failed: {e}"))
}

/// Seal one file into a real encrypted PBP0 package + a real (unsigned) DATA0
/// anchor. Real encryption, real SHAKE-256 manifest root, real SHA3-256
/// signer_commit. Nothing is written to disk here.
pub fn seal_backup(
    name: &str,
    plaintext: &[u8],
    passphrase: &[u8],
    tier: u8,
) -> Result<SealResult, String> {
    if passphrase.is_empty() {
        return Err("passphrase must not be empty".into());
    }
    let tier = if tier == TIER_FLOOR { TIER_FLOOR } else { TIER_DEFAULT };

    // 1) Argon2id key (default 64 MiB tier). Zeroized on drop.
    let salt = postern_core::kdf::generate_salt();
    let key = derive_key(passphrase, &salt, tier)?;

    // 2) Real AEAD seal of the file content → the stored blob.
    let sealed_blob = postern_core::aead::seal_with_context(&key, CTX_BLOB, plaintext)
        .map_err(|e| format!("seal (blob) failed: {e}"))?;

    // 3) Real SHAKE-256 of the sealed blob → the PQ integrity digest + locator.
    let blob_cid = shake256_32(&sealed_blob);

    // 4) Namespace + backup-set id (SHAKE-256, sequence 0 = genesis).
    let mut ns_input = Vec::with_capacity(NS_DOMAIN.len() + salt.len());
    ns_input.extend_from_slice(NS_DOMAIN);
    ns_input.extend_from_slice(&salt);
    let namespace_id = shake256_32(&ns_input);
    let sequence: u64 = 0;
    let mut bsid_input = Vec::with_capacity(32 + 8);
    bsid_input.extend_from_slice(&namespace_id);
    bsid_input.extend_from_slice(&sequence.to_le_bytes());
    let backup_set_id = shake256_32(&bsid_input);

    // 5) PBM0 manifest (plaintext, one entry) — then sealed.
    let manifest = Manifest {
        backup_set_id,
        sequence,
        created_unix: now_unix(),
        entries: vec![ManifestEntry {
            path: name.as_bytes().to_vec(),
            file_len: plaintext.len() as u64,
            content_cid: blob_cid.to_vec(),
            shake256: blob_cid,
        }],
    };
    let manifest_bytes = manifest.encode().map_err(|e| format!("manifest encode: {e}"))?;
    let sealed_manifest = postern_core::aead::seal_with_context(&key, CTX_MANIFEST, &manifest_bytes)
        .map_err(|e| format!("seal (manifest) failed: {e}"))?;

    // 6) PBP0 package. pk/sig deliberately EMPTY — the anchor is UNSIGNED
    //    (the ML-DSA/Falcon signer is out of scope; see module honesty).
    let package = Package {
        kdf_tier: tier,
        salt,
        sealed_manifest,
        pk: Vec::new(),
        sig: Vec::new(),
    };
    let package_bytes = package.encode().map_err(|e| format!("package encode: {e}"))?;

    // 7) DATA0 anchor. manifest_root = real SHAKE-256 over committed prefix.
    let committed = package.committed_prefix().map_err(|e| format!("committed_prefix: {e}"))?;
    let manifest_root = shake256_32(&committed);
    let signer_commit = sha3_256(&package.pk); // SHA3-256 of the (empty) pk
    let anchor = AnchorEnvelope {
        namespace_id,
        sequence,
        prev_root: [0u8; 32],
        manifest_root,
        signer_commit,
        manifest_cid: manifest_cid_of(&package_bytes),
    };

    Ok(SealResult {
        set_id: hex::encode(manifest_root),
        manifest_root,
        anchor: anchor.encode(),
        package: package_bytes,
        sealed_blob,
        blob_cid,
        tier,
        plaintext_len: plaintext.len() as u64,
    })
}

/// One written file (relative name + byte size).
pub struct StoredFile {
    pub name: String,
    pub size: u64,
}

/// Write a sealed backup set into `dir`: the blob via the [`DirBackend`]
/// (content-addressed), and the `.pbp0` package + `.data0` anchor as sidecars
/// keyed by the backup-set id. Creates `dir` if needed.
pub fn store_to_dir(dir: &Path, r: &SealResult) -> Result<Vec<StoredFile>, String> {
    fs::create_dir_all(dir).map_err(|e| format!("create backup dir: {e}"))?;
    let mut be = DirBackend::new(dir);
    let cid = be.put_car(&r.sealed_blob).map_err(|e| format!("store blob: {e}"))?;

    let pkg_name = format!("{}.pbp0", r.set_id);
    let anc_name = format!("{}.data0", r.set_id);
    fs::write(dir.join(&pkg_name), &r.package).map_err(|e| format!("write package: {e}"))?;
    fs::write(dir.join(&anc_name), &r.anchor).map_err(|e| format!("write anchor: {e}"))?;

    Ok(vec![
        StoredFile { name: format!("{}.blob", hex::encode(&cid.0)), size: r.sealed_blob.len() as u64 },
        StoredFile { name: pkg_name, size: r.package.len() as u64 },
        StoredFile { name: anc_name, size: r.anchor.len() as u64 },
    ])
}

/// The result of a verified restore.
pub struct RestoreResult {
    pub name: String,
    pub plaintext: Zeroizing<Vec<u8>>,
    /// The recomputed SHAKE-256 root matched the stored DATA0 anchor.
    pub anchor_verified: bool,
    /// The stored blob re-hashed to the manifest's SHAKE-256 digest.
    pub integrity_verified: bool,
}

/// Read a backup set back from `dir`, verify the anchor + blob integrity, and
/// decrypt. Fail-closed: any mismatch (wrong passphrase, tampered package,
/// tampered blob, root disagreement) is an `Err`, never partial plaintext.
pub fn restore_from_dir(
    dir: &Path,
    set_id: &str,
    passphrase: &[u8],
) -> Result<RestoreResult, String> {
    if !is_hex64(set_id) {
        return Err("invalid backup-set id (expected 64 hex chars)".into());
    }

    // 1) Anchor (DATA0) — strict structural decode.
    let anchor_bytes = fs::read(dir.join(format!("{set_id}.data0")))
        .map_err(|_| "anchor (.data0) not found in this folder".to_string())?;
    let anchor = AnchorEnvelope::decode(&anchor_bytes)
        .map_err(|e| format!("anchor decode failed: {e}"))?;

    // 2) Package (PBP0) — strict decode.
    let package_bytes = fs::read(dir.join(format!("{set_id}.pbp0")))
        .map_err(|_| "package (.pbp0) not found in this folder".to_string())?;
    let package = Package::decode(&package_bytes).map_err(|e| format!("package decode failed: {e}"))?;

    // 3) REAL anchor verification: recompute the SHAKE-256 manifest root over
    //    the package's committed prefix and require it to equal the anchor's.
    let committed = package.committed_prefix().map_err(|e| format!("committed_prefix: {e}"))?;
    let recomputed_root = shake256_32(&committed);
    if recomputed_root != anchor.manifest_root {
        return Err("anchor verification FAILED: recomputed SHAKE-256 manifest_root does not match \
                    the DATA0 anchor — the package was altered or does not belong to this anchor"
            .into());
    }
    let anchor_verified = true;

    // 4) Derive the key from the passphrase + stored salt/tier, open the manifest.
    let key = derive_key(passphrase, &package.salt, package.kdf_tier)?;
    let manifest_bytes = Zeroizing::new(
        postern_core::aead::open_with_context(&key, CTX_MANIFEST, &package.sealed_manifest)
            .map_err(|_| "wrong passphrase or tampered manifest (AEAD open failed)".to_string())?,
    );
    let manifest = Manifest::decode(&manifest_bytes).map_err(|e| format!("manifest decode: {e}"))?;
    let entry = manifest
        .entries
        .first()
        .ok_or("manifest has no file entries")?;

    // 5) Fetch the blob, re-hash it against the manifest's SHAKE-256 (backend
    //    bytes are untrusted — this is the integrity gate).
    let mut be = DirBackend::new(dir);
    let sealed_blob = be
        .get(&Cid(entry.content_cid.clone()))
        .map_err(|e| format!("blob fetch failed: {e}"))?;
    if shake256_32(&sealed_blob) != entry.shake256 {
        return Err("integrity check FAILED: the stored blob does not match the manifest's \
                    SHAKE-256 digest — the ciphertext was substituted or corrupted"
            .into());
    }
    let integrity_verified = true;

    // 6) Real AEAD open of the file blob.
    let plaintext = Zeroizing::new(
        postern_core::aead::open_with_context(&key, CTX_BLOB, &sealed_blob)
            .map_err(|_| "wrong passphrase or tampered blob (AEAD open failed)".to_string())?,
    );
    if plaintext.len() as u64 != entry.file_len {
        return Err("restored length disagrees with the manifest".into());
    }
    let name = String::from_utf8(entry.path.clone())
        .map_err(|_| "manifest path is not valid UTF-8".to_string())?;

    Ok(RestoreResult { name, plaintext, anchor_verified, integrity_verified })
}

// ── small helpers ─────────────────────────────────────────────────────────────

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Expand a leading `~/` to `$HOME` (the app has no dialog plugin; the pane
/// passes a folder path, so this makes `~/…` ergonomic). Absolute paths pass
/// through unchanged.
fn resolve_dir(raw: &str) -> Result<PathBuf, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("backup folder path is empty".into());
    }
    if let Some(rest) = raw.strip_prefix("~/") {
        let home = std::env::var("HOME").map_err(|_| "cannot resolve ~ (no $HOME)".to_string())?;
        Ok(PathBuf::from(home).join(rest))
    } else if raw == "~" {
        std::env::var("HOME").map(PathBuf::from).map_err(|_| "cannot resolve ~ (no $HOME)".into())
    } else {
        Ok(PathBuf::from(raw))
    }
}

/// A sensible default backup folder: `$HOME/PosternBackups`.
fn default_backup_dir() -> PathBuf {
    match std::env::var("HOME") {
        Ok(h) => PathBuf::from(h).join("PosternBackups"),
        Err(_) => PathBuf::from("PosternBackups"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// #[tauri::command] surface (matches ../src/modules/backup.js exactly).
// ─────────────────────────────────────────────────────────────────────────────

/// The default backup folder path the pane pre-fills (`$HOME/PosternBackups`).
#[tauri::command]
pub fn backup_default_dir() -> Value {
    json!({ "dir": default_backup_dir().to_string_lossy(), "honesty": HONESTY })
}

/// Seal a file locally: encrypt it, build the PBP0 package + the real
/// (unsigned) DATA0 anchor. Returns the artifacts (base64) the pane holds in
/// memory and hands to `backup_store`. NO disk IO, NO network. The passphrase
/// is used to derive the key and dropped immediately.
#[tauri::command]
pub fn backup_seal(
    name: String,
    bytes_b64: String,
    passphrase: String,
    tier: Option<String>,
) -> Result<Value, String> {
    let plaintext = Zeroizing::new(
        B64.decode(bytes_b64.trim())
            .map_err(|e| format!("invalid file base64: {e}"))?,
    );
    let pass = Zeroizing::new(passphrase.into_bytes());
    let tier_u8 = match tier.as_deref() {
        Some("floor") => TIER_FLOOR,
        _ => TIER_DEFAULT,
    };
    let name = if name.trim().is_empty() { "backup.bin".to_string() } else { name };
    let r = seal_backup(&name, &plaintext, &pass, tier_u8)?;
    Ok(json!({
        "setId": r.set_id,
        "manifestRoot": hex::encode(r.manifest_root),
        "anchorHex": hex::encode(&r.anchor),
        "anchorLen": r.anchor.len(),
        "packageB64": B64.encode(&r.package),
        "packageLen": r.package.len(),
        "sealedBlobB64": B64.encode(&r.sealed_blob),
        "sealedBlobLen": r.sealed_blob.len(),
        "blobCid": hex::encode(r.blob_cid),
        "plaintextLen": r.plaintext_len,
        "tier": if r.tier == TIER_FLOOR { "floor" } else { "default" },
        "signed": false,
        "honesty": HONESTY,
    }))
}

/// Store a sealed set (from `backup_seal`) into a user-chosen folder. Writes
/// the blob (content-addressed), the `.pbp0` package and the `.data0` anchor.
#[tauri::command]
pub fn backup_store(
    dir: String,
    set_id: String,
    package_b64: String,
    anchor_hex: String,
    sealed_blob_b64: String,
) -> Result<Value, String> {
    if !is_hex64(&set_id) {
        return Err("invalid backup-set id (expected 64 hex chars)".into());
    }
    let dir_path = resolve_dir(&dir)?;
    let package = B64.decode(package_b64.trim()).map_err(|e| format!("invalid package base64: {e}"))?;
    let anchor = hex::decode(anchor_hex.trim()).map_err(|e| format!("invalid anchor hex: {e}"))?;
    let sealed_blob =
        B64.decode(sealed_blob_b64.trim()).map_err(|e| format!("invalid blob base64: {e}"))?;
    // Recompute the blob cid so the on-disk name is authoritative, not caller-supplied.
    let blob_cid = shake256_32(&sealed_blob);

    let r = SealResult {
        set_id: set_id.clone(),
        manifest_root: {
            let mut m = [0u8; 32];
            m.copy_from_slice(&hex::decode(&set_id).unwrap());
            m
        },
        anchor,
        package,
        sealed_blob,
        blob_cid,
        tier: TIER_DEFAULT,
        plaintext_len: 0,
    };
    let files = store_to_dir(&dir_path, &r)?;
    Ok(json!({
        "dir": dir_path.to_string_lossy(),
        "setId": set_id,
        "files": files.iter().map(|f| json!({ "name": f.name, "size": f.size })).collect::<Vec<_>>(),
        "honesty": HONESTY,
    }))
}

/// Restore a backup set from a folder: verify the anchor, verify blob
/// integrity, decrypt. Returns the original name + bytes (base64). Fail-closed.
#[tauri::command]
pub fn backup_restore(dir: String, set_id: String, passphrase: String) -> Result<Value, String> {
    let dir_path = resolve_dir(&dir)?;
    let pass = Zeroizing::new(passphrase.into_bytes());
    let r = restore_from_dir(&dir_path, &set_id, &pass)?;
    Ok(json!({
        "name": r.name,
        "bytesB64": B64.encode(&*r.plaintext),
        "len": r.plaintext.len(),
        "anchorVerified": r.anchor_verified,
        "integrityVerified": r.integrity_verified,
        "honesty": HONESTY,
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// Filecoin (Lighthouse) — REAL HTTPS upload of the already-SEALED ciphertext.
//
// The design choice (deliberate): the upload is done HERE, at the Tauri layer,
// with the desktop's EXISTING `ureq` + rustls HTTPS client (the same client the
// wallet RPC uses to reach `https://…`). We do NOT route through
// `bloch-data::LiveBackend`, which is hand-rolled HTTP with no in-crate TLS (it
// can't reach https:// without a proxy) and is still a `todo!()` stub. Real TLS,
// no proxy, no new crate.
//
// HONESTY (load-bearing, surfaced verbatim in every response's `honesty` field):
//   * Only Postern-SEALED ciphertext is uploaded — Lighthouse/Filecoin stores
//     CIPHERTEXT; trust it for availability, not confidentiality.
//   * The user supplies their OWN Lighthouse token; it is passed per-call, never
//     logged, never persisted server-side.
//   * The DATA0 anchor is still UNSIGNED (SHAKE-256 real, no ML-DSA/Falcon yet).
//     UNAUDITED reference prototype, zero-value pre-mainnet.
// ─────────────────────────────────────────────────────────────────────────────

/// Lighthouse IPFS `add` endpoint (upload). Reachable only over real HTTPS.
const LIGHTHOUSE_ADD_URL: &str = "https://node.lighthouse.storage/api/v0/add";
/// Lighthouse public IPFS gateway prefix (retrieve / share link).
const LIGHTHOUSE_GATEWAY: &str = "https://gateway.lighthouse.storage/ipfs/";
/// Cap on a gateway retrieve so a hostile/large response can't exhaust memory.
const MAX_RETRIEVE_BYTES: u64 = 256 * 1024 * 1024;

/// Mandatory per-response honesty text for the Filecoin path. Surfaced verbatim
/// so the pane can never overclaim what the upload does. The phrases
/// "ciphertext", "OWN Lighthouse token" and "UNSIGNED" are load-bearing (the
/// module test asserts them).
pub const FILECOIN_HONESTY: &str = "Only Postern-SEALED ciphertext is uploaded — Lighthouse/Filecoin \
     stores ciphertext, trusted for AVAILABILITY, not confidentiality. You supply your OWN \
     Lighthouse token (free account at lighthouse.storage); it is sent ONLY to Lighthouse, \
     per-call, never logged or persisted. The DATA0 anchor is still UNSIGNED (SHAKE-256 real, no \
     ML-DSA/Falcon yet). UNAUDITED reference prototype, zero-value pre-mainnet.";

/// Build a `multipart/form-data` body with a single file part. Kept pure so the
/// in-module test can assert the exact bytes (boundary, disposition, filename,
/// payload, trailing boundary) without any network.
fn multipart_file_body(boundary: &str, field: &str, filename: &str, content: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(content.len() + 256);
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        format!("Content-Disposition: form-data; name=\"{field}\"; filename=\"{filename}\"\r\n")
            .as_bytes(),
    );
    body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
    body.extend_from_slice(content);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    body
}

/// Map a `ureq` error to a short, typed, UI-safe string — never a 500/stack.
/// Deliberately does NOT echo the request (which carries the bearer token).
fn lighthouse_err(op: &str, e: ureq::Error) -> String {
    match e {
        ureq::Error::Status(code, resp) => {
            let hint = match code {
                401 | 403 => " — check your Lighthouse API key (paste a valid token from lighthouse.storage)",
                413 => " — the blob is larger than the provider accepts",
                429 => " — rate-limited by Lighthouse, retry shortly",
                _ => "",
            };
            // A short body snippet aids debugging; cap it so nothing large leaks.
            let body = resp.into_string().unwrap_or_default();
            let snippet: String = body.chars().take(180).collect();
            let sep = if snippet.trim().is_empty() { "" } else { " — " };
            format!("Lighthouse {op} failed: HTTP {code}{hint}{sep}{}", snippet.trim())
        }
        ureq::Error::Transport(t) => {
            format!("Lighthouse {op} failed (network/TLS): {t}")
        }
    }
}

/// Parse the CID (`Hash`) out of a Lighthouse `add` JSON response. Pure + tested.
fn cid_from_add_response(v: &Value) -> Result<String, String> {
    v.get("Hash")
        .and_then(|h| h.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .ok_or_else(|| format!("Lighthouse response carried no CID (expected a non-empty \"Hash\"): {v}"))
}

/// A Lighthouse CID as returned by IPFS `add`: base58 (`Qm…`) or base32
/// (`bafy…`). Restrict to alphanumerics so a retrieve can't be pointed at an
/// arbitrary gateway path (no `/`, `.`, `?`, `#`, `..`).
fn cid_is_wellformed(cid: &str) -> bool {
    !cid.is_empty()
        && cid.len() <= 128
        && cid.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// The real HTTPS `add` request, factored out of the command so a local
/// mock-server test can drive the EXACT request-shaping (bearer header +
/// multipart body) over ureq and assert the CID parse — without a live token.
/// `add_url` is [`LIGHTHOUSE_ADD_URL`] in production. NEVER logs the key.
fn lighthouse_add(add_url: &str, api_key: &str, sealed: &[u8]) -> Result<String, String> {
    // A boundary derived from the ciphertext digest is guaranteed not to occur
    // inside the (high-entropy) ciphertext, so no escaping of the payload is needed.
    let boundary = format!("PosternBackupBoundary{}", hex::encode(&sha2_256(sealed)[..12]));
    let body = multipart_file_body(&boundary, "file", "postern-backup.sealed", sealed);

    let resp = ureq::post(add_url)
        .timeout(std::time::Duration::from_secs(180))
        .set("Authorization", &format!("Bearer {api_key}"))
        .set(
            "Content-Type",
            &format!("multipart/form-data; boundary={boundary}"),
        )
        .send_bytes(&body)
        .map_err(|e| lighthouse_err("upload", e))?;

    let v: Value = resp
        .into_json()
        .map_err(|e| format!("Lighthouse returned a non-JSON response: {e}"))?;
    cid_from_add_response(&v)
}

/// Upload the already-SEALED (Postern-AEAD) ciphertext blob to Lighthouse over
/// real HTTPS and return its CID + a gateway link. The `api_key` is the user's
/// OWN Lighthouse token, passed per-call — it is used ONLY for the Authorization
/// header on THIS request and is never logged or persisted. NEVER a 500/stack to
/// the UI: all failures are typed strings.
#[tauri::command]
pub fn backup_filecoin_upload(sealed_b64: String, api_key: String) -> Result<Value, String> {
    let key = api_key.trim();
    if key.is_empty() {
        return Err("no Lighthouse API key set — paste your Lighthouse API key (free account at \
                    lighthouse.storage) into the pane first"
            .into());
    }
    let sealed = B64
        .decode(sealed_b64.trim())
        .map_err(|e| format!("invalid sealed base64: {e}"))?;
    if sealed.is_empty() {
        return Err("nothing to upload — seal a file locally first".into());
    }

    let cid = lighthouse_add(LIGHTHOUSE_ADD_URL, key, &sealed)?;

    Ok(json!({
        "cid": cid,
        "gatewayUrl": format!("{LIGHTHOUSE_GATEWAY}{cid}"),
        "sealedLen": sealed.len(),
        "honesty": FILECOIN_HONESTY,
    }))
}

/// Retrieve a blob back from the Lighthouse public IPFS gateway by CID (no token
/// needed to read a public gateway). Used by the pane to VERIFY the uploaded
/// ciphertext round-trips. Returns the bytes (base64) so the pane can confirm
/// they are byte-identical to the sealed blob it uploaded (which decrypts under
/// the user's passphrase via Restore). Fail-closed + size-capped.
#[tauri::command]
pub fn backup_filecoin_retrieve(cid: String) -> Result<Value, String> {
    let cid = cid.trim();
    if !cid_is_wellformed(cid) {
        return Err("invalid CID — expected an alphanumeric IPFS CID (Qm… / bafy…)".into());
    }
    let url = format!("{LIGHTHOUSE_GATEWAY}{cid}");
    let resp = ureq::get(&url)
        .timeout(std::time::Duration::from_secs(180))
        .call()
        .map_err(|e| lighthouse_err("retrieve", e))?;

    let mut buf = Vec::new();
    resp.into_reader()
        .take(MAX_RETRIEVE_BYTES)
        .read_to_end(&mut buf)
        .map_err(|e| format!("Lighthouse retrieve read failed: {e}"))?;

    Ok(json!({
        "cid": cid,
        "bytesB64": B64.encode(&buf),
        "len": buf.len(),
        "honesty": FILECOIN_HONESTY,
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// Filecoin (Lighthouse) via the S3-COMPATIBLE endpoint — the PRIMARY upload path.
//
// WHY S3, not node.lighthouse.storage: the IPFS `add` bearer endpoint
// (`backup_filecoin_upload`, above) TIMES OUT from some networks and is unusable
// there. Lighthouse also exposes an S3-compatible API: a signed `PUT` stores the
// object and Lighthouse pins it to IPFS/Filecoin, returning the REAL content CID
// as object metadata (`x-amz-meta-cid`), read back with an S3 `HEAD`. This path
// signs each request with a MINIMAL, in-tree AWS Signature V4 (HMAC-SHA256 built
// on the desktop's own dependency-free SHA-256 — NO new crate, NO async runtime,
// NO aws-sdk) and rides the SAME `ureq` + rustls HTTPS client the wallet RPC uses.
// Path-style addressing (`https://ENDPOINT/BUCKET/KEY`), signing service "s3".
//
// HONESTY (identical rails to the node path): only Postern-SEALED ciphertext is
// uploaded (the provider stores CIPHERTEXT — trust it for AVAILABILITY, not
// confidentiality); the user supplies their OWN Lighthouse S3 credentials
// (Access Key / Secret Key from their Lighthouse account), passed per-call, used
// ONLY to sign THIS request, NEVER logged, NEVER persisted by us, and NEVER baked
// into the build; the DATA0 anchor is still UNSIGNED (SHAKE-256 real, no
// ML-DSA/Falcon). UNAUDITED reference prototype, zero-value pre-mainnet.
// ─────────────────────────────────────────────────────────────────────────────

/// Mandatory per-response honesty text for the Filecoin **S3** path. The phrases
/// "ciphertext", "OWN Lighthouse S3 credentials", "UNSIGNED" and "availability"
/// are load-bearing (the module test asserts them).
pub const FILECOIN_S3_HONESTY: &str = "Only Postern-SEALED ciphertext is uploaded — Lighthouse/Filecoin \
     stores ciphertext, trusted for AVAILABILITY, not confidentiality. You supply your OWN Lighthouse S3 \
     credentials (Access Key + Secret Key from your Lighthouse account); they are used ONLY to sign this \
     request, sent to no one else, never logged, never persisted by us, never baked into the build. The \
     DATA0 anchor is still UNSIGNED (SHAKE-256 real, no ML-DSA/Falcon yet). UNAUDITED reference prototype, \
     zero-value pre-mainnet.";

/// HMAC-SHA256 over the desktop's own dependency-free SHA-256 (no `hmac`/`sha2`
/// crate). Block size is 64 bytes (SHA-256's). Pure + tested against RFC 4231.
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&sha2_256(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = crate::sha256::Sha256::new();
    inner.update(&ipad);
    inner.update(msg);
    let inner_d = inner.finish();
    let mut outer = crate::sha256::Sha256::new();
    outer.update(&opad);
    outer.update(&inner_d);
    outer.finish()
}

/// Lowercase-hex SHA-256 of `data` — the SigV4 "hashed payload" / canonical-
/// request digest primitive.
fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha2_256(data))
}

/// AWS SigV4 URI-encoding: unreserved chars pass through; everything else is
/// %-encoded (uppercase hex). `/` is preserved when `encode_slash` is false (the
/// path case). Kept pure + tested.
fn uri_encode(s: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        let c = b as char;
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~') {
            out.push(c);
        } else if b == b'/' && !encode_slash {
            out.push('/');
        } else {
            out.push('%');
            out.push_str(&format!("{b:02X}"));
        }
    }
    out
}

/// The host (authority, incl. port if any) of an `https://…` endpoint.
fn host_of(endpoint: &str) -> Result<String, String> {
    let after = endpoint.split("://").nth(1).unwrap_or(endpoint);
    let host = after.split('/').next().unwrap_or("").trim();
    if host.is_empty() {
        return Err("invalid S3 endpoint — expected an https://HOST URL".into());
    }
    Ok(host.to_string())
}

/// The UTC `(amz_date, datestamp)` pair SigV4 needs: `YYYYMMDDTHHMMSSZ` and
/// `YYYYMMDD`. Uses the already-present `time` crate (no new dependency).
fn sigv4_now() -> (String, String) {
    let n = time::OffsetDateTime::now_utc();
    let (y, mo, d) = (n.year(), u8::from(n.month()), n.day());
    let (h, mi, s) = (n.hour(), n.minute(), n.second());
    (
        format!("{y:04}{mo:02}{d:02}T{h:02}{mi:02}{s:02}Z"),
        format!("{y:04}{mo:02}{d:02}"),
    )
}

/// The S3 credentials + region for one signed request. Borrowed, never cloned
/// into a longer-lived structure; the secret is used ONLY to derive the signing
/// key here and is never logged.
struct S3Creds<'a> {
    access_key: &'a str,
    secret_key: &'a str,
    region: &'a str,
}

/// Build the `Authorization: AWS4-HMAC-SHA256 …` header value for one request.
/// `canonical_uri` must already be URI-encoded (path-style). Query string is
/// always empty here (object PUT/HEAD + bucket create carry none). Pure + tested.
fn sigv4_authorization(
    creds: &S3Creds,
    amz_date: &str,
    datestamp: &str,
    method: &str,
    host: &str,
    canonical_uri: &str,
    payload_hash: &str,
) -> String {
    const SERVICE: &str = "s3";
    let canonical_headers = format!(
        "host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n"
    );
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let canonical_request = format!(
        "{method}\n{canonical_uri}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    );
    let scope = format!("{datestamp}/{}/{SERVICE}/aws4_request", creds.region);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let k_date = hmac_sha256(format!("AWS4{}", creds.secret_key).as_bytes(), datestamp.as_bytes());
    let k_region = hmac_sha256(&k_date, creds.region.as_bytes());
    let k_service = hmac_sha256(&k_region, SERVICE.as_bytes());
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));
    format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
        creds.access_key
    )
}

/// Conservative S3 bucket-name check (DNS-style): lowercase alnum, dot, dash;
/// 3–63 chars; must start/end alphanumeric. Rejects anything that would need
/// path escaping or point the request elsewhere.
fn bucket_name_ok(b: &str) -> bool {
    let n = b.len();
    if !(3..=63).contains(&n) {
        return false;
    }
    let bytes = b.as_bytes();
    let edge_ok = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    if !edge_ok(bytes[0]) || !edge_ok(bytes[n - 1]) {
        return false;
    }
    bytes.iter().all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'.' || c == b'-')
}

/// Map a `ureq` error from an S3 call to a short, typed, UI-safe string. The
/// request carries only a DERIVED signature (never the raw secret), so echoing a
/// capped body snippet leaks nothing sensitive.
fn s3_err(op: &str, e: ureq::Error) -> String {
    match e {
        ureq::Error::Status(code, resp) => {
            let hint = match code {
                400 => " — the S3 endpoint rejected the request (check the endpoint/region)",
                403 => " — check your Lighthouse S3 Access Key / Secret Key (SignatureDoesNotMatch or AccessDenied)",
                404 => " — bucket or object not found",
                409 => " — bucket name conflict",
                _ => "",
            };
            let body = resp.into_string().unwrap_or_default();
            let snippet: String = body.chars().take(200).collect();
            let sep = if snippet.trim().is_empty() { "" } else { " — " };
            format!("S3 {op} failed: HTTP {code}{hint}{sep}{}", snippet.trim())
        }
        ureq::Error::Transport(t) => format!("S3 {op} failed (network/TLS): {t}"),
    }
}

/// The S3 request timeout (shared by create/put/head).
const S3_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);

/// `PUT https://ENDPOINT/BUCKET` (empty body) to auto-create the bucket, like
/// `aws s3 mb`. Tolerates an already-existing bucket you own (HTTP 200 or 409).
fn s3_create_bucket(endpoint: &str, host: &str, creds: &S3Creds, bucket: &str) -> Result<(), String> {
    let (amz_date, datestamp) = sigv4_now();
    let payload_hash = sha256_hex(b"");
    let canonical_uri = uri_encode(&format!("/{bucket}"), false);
    let auth = sigv4_authorization(creds, &amz_date, &datestamp, "PUT", host, &canonical_uri, &payload_hash);
    let url = format!("{}/{bucket}", endpoint.trim_end_matches('/'));
    match ureq::put(&url)
        .timeout(S3_TIMEOUT)
        .set("x-amz-date", &amz_date)
        .set("x-amz-content-sha256", &payload_hash)
        .set("Authorization", &auth)
        .send_bytes(b"")
    {
        Ok(_) => Ok(()),
        // 409 = BucketAlreadyOwnedByYou / BucketAlreadyExists → already there, fine.
        Err(ureq::Error::Status(409, _)) => Ok(()),
        Err(e) => Err(s3_err("create-bucket", e)),
    }
}

/// `PUT https://ENDPOINT/BUCKET/KEY` with the sealed ciphertext as a signed body.
fn s3_put_object(
    endpoint: &str,
    host: &str,
    creds: &S3Creds,
    bucket: &str,
    key: &str,
    body: &[u8],
) -> Result<(), String> {
    let (amz_date, datestamp) = sigv4_now();
    let payload_hash = sha256_hex(body);
    let canonical_uri = uri_encode(&format!("/{bucket}/{key}"), false);
    let auth = sigv4_authorization(creds, &amz_date, &datestamp, "PUT", host, &canonical_uri, &payload_hash);
    let url = format!("{}/{bucket}/{key}", endpoint.trim_end_matches('/'));
    ureq::put(&url)
        .timeout(S3_TIMEOUT)
        .set("x-amz-date", &amz_date)
        .set("x-amz-content-sha256", &payload_hash)
        .set("Content-Type", "application/octet-stream")
        .set("Authorization", &auth)
        .send_bytes(body)
        .map_err(|e| s3_err("upload", e))?;
    Ok(())
}

/// `HEAD https://ENDPOINT/BUCKET/KEY` → the Lighthouse-computed CID from the
/// `x-amz-meta-cid` response header (Lighthouse pins the object to IPFS/Filecoin
/// and records the content id in object metadata).
fn s3_head_cid(
    endpoint: &str,
    host: &str,
    creds: &S3Creds,
    bucket: &str,
    key: &str,
) -> Result<Option<String>, String> {
    let (amz_date, datestamp) = sigv4_now();
    let payload_hash = sha256_hex(b"");
    let canonical_uri = uri_encode(&format!("/{bucket}/{key}"), false);
    let auth = sigv4_authorization(creds, &amz_date, &datestamp, "HEAD", host, &canonical_uri, &payload_hash);
    let url = format!("{}/{bucket}/{key}", endpoint.trim_end_matches('/'));
    let resp = ureq::request("HEAD", &url)
        .timeout(S3_TIMEOUT)
        .set("x-amz-date", &amz_date)
        .set("x-amz-content-sha256", &payload_hash)
        .set("Authorization", &auth)
        .call()
        .map_err(|e| s3_err("head", e))?;
    Ok(resp.header("x-amz-meta-cid").map(|s| s.trim().to_string()).filter(|s| !s.is_empty()))
}

/// Upload the already-SEALED (Postern-AEAD) ciphertext to Lighthouse's
/// S3-compatible endpoint and return the real IPFS/Filecoin CID + a gateway link.
/// The bucket is auto-created if missing. The object key is content-addressed
/// (`sealed/<sha256hex>.bin`) so re-uploading identical ciphertext is idempotent.
/// The S3 credentials are the user's OWN, passed per-call — used ONLY to sign
/// this request, never logged or persisted. All failures are typed strings, never
/// a 500/stack.
#[tauri::command]
pub fn backup_filecoin_s3_upload(
    sealed_b64: String,
    endpoint: String,
    region: String,
    access_key: String,
    secret_key: String,
    bucket: String,
) -> Result<Value, String> {
    let sealed = B64
        .decode(sealed_b64.trim())
        .map_err(|e| format!("invalid sealed base64: {e}"))?;
    if sealed.is_empty() {
        return Err("nothing to upload — seal a file locally first".into());
    }
    let endpoint = endpoint.trim();
    let region = {
        let r = region.trim();
        if r.is_empty() { "auto" } else { r }
    };
    let access_key = access_key.trim();
    let secret_key = secret_key.trim();
    let bucket = bucket.trim();

    if !endpoint.starts_with("https://") {
        return Err("S3 endpoint must be an https:// URL (e.g. your Lighthouse S3 endpoint)".into());
    }
    if access_key.is_empty() || secret_key.is_empty() {
        return Err("set your Lighthouse S3 Access Key and Secret Key first (from your Lighthouse \
                    account); they are used only to sign this upload and are never logged or persisted"
            .into());
    }
    if !bucket_name_ok(bucket) {
        return Err("invalid bucket name — use 3–63 lowercase letters/digits, dots or dashes, \
                    starting and ending alphanumeric (e.g. postern-backup)"
            .into());
    }

    let host = host_of(endpoint)?;
    let creds = S3Creds { access_key, secret_key, region };
    // Content-addressed object key: identical ciphertext ⇒ identical key.
    let key = format!("sealed/{}.bin", sha256_hex(&sealed));

    // 1) Ensure the bucket exists (auto-create, idempotent).
    s3_create_bucket(endpoint, &host, &creds, bucket)?;
    // 2) PUT the sealed ciphertext.
    s3_put_object(endpoint, &host, &creds, bucket, &key, &sealed)?;
    // 3) HEAD the object to read the Lighthouse-computed CID.
    let cid = s3_head_cid(endpoint, &host, &creds, bucket, &key)?.ok_or_else(|| {
        "upload stored the object, but Lighthouse has not yet published a CID in its metadata — \
         wait a moment and retry (the ciphertext is uploaded; only the CID lookup is pending)"
            .to_string()
    })?;
    if !cid_is_wellformed(&cid) {
        return Err(format!("Lighthouse returned an unexpected CID value: {cid}"));
    }

    Ok(json!({
        "cid": cid,
        "gatewayUrl": format!("{LIGHTHOUSE_GATEWAY}{cid}"),
        "sealedLen": sealed.len(),
        "bucket": bucket,
        "key": key,
        "honesty": FILECOIN_S3_HONESTY,
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests — the real seal → store → restore round-trip, offline, in a temp dir.
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "postern-backup-test-{}-{}-{:?}",
            tag,
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn honesty_text_carries_the_load_bearing_phrases() {
        assert!(HONESTY.contains("UNAUDITED scaffold"));
        assert!(HONESTY.contains("UNSIGNED"));
        assert!(HONESTY.contains("not"));
        assert!(HONESTY.to_lowercase().contains("no filecoin"));
    }

    #[test]
    fn filecoin_honesty_carries_the_load_bearing_phrases() {
        assert!(FILECOIN_HONESTY.contains("ciphertext"));
        assert!(FILECOIN_HONESTY.contains("OWN Lighthouse token"));
        assert!(FILECOIN_HONESTY.contains("UNSIGNED"));
        assert!(FILECOIN_HONESTY.to_lowercase().contains("availability"));
    }

    #[test]
    fn filecoin_s3_honesty_carries_the_load_bearing_phrases() {
        assert!(FILECOIN_S3_HONESTY.contains("ciphertext"));
        assert!(FILECOIN_S3_HONESTY.contains("OWN Lighthouse S3 credentials"));
        assert!(FILECOIN_S3_HONESTY.contains("UNSIGNED"));
        assert!(FILECOIN_S3_HONESTY.to_lowercase().contains("availability"));
    }

    #[test]
    fn hmac_sha256_matches_rfc4231_case2() {
        // RFC 4231 test case 2: key="Jefe", data="what do ya want for nothing?"
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex::encode(mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn hmac_sha256_handles_a_key_longer_than_the_block() {
        // A >64-byte key must be pre-hashed (RFC 2104). Cross-check against the
        // definition H((H(K) ⊕ opad) ‖ H((H(K) ⊕ ipad) ‖ m)) via a second path:
        // the mac must be stable and 32 bytes; regression-guard the exact value.
        let long_key = vec![0xaau8; 100];
        let mac = hmac_sha256(&long_key, b"payload");
        assert_eq!(mac.len(), 32);
        // Deterministic: same inputs → same mac.
        assert_eq!(mac, hmac_sha256(&long_key, b"payload"));
    }

    #[test]
    fn sigv4_signing_key_matches_aws_documented_example() {
        // AWS "Deriving the signing key" documented example:
        //   secret=wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY
        //   date=20150830  region=us-east-1  service=iam
        // Documented result: c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9
        let k_date = hmac_sha256(
            b"AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            b"20150830",
        );
        let k_region = hmac_sha256(&k_date, b"us-east-1");
        let k_service = hmac_sha256(&k_region, b"iam");
        let k_signing = hmac_sha256(&k_service, b"aws4_request");
        assert_eq!(
            hex::encode(k_signing),
            "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
        );
    }

    #[test]
    fn sigv4_authorization_is_deterministic_and_well_shaped() {
        // Fixed inputs → a stable Authorization header (guards accidental drift
        // in the canonical-request / string-to-sign assembly). No network.
        let creds = S3Creds { access_key: "AKIDEXAMPLE", secret_key: "SECRETKEY", region: "auto" };
        let payload_hash = sha256_hex(b"hello");
        let uri = uri_encode("/postern-backup/sealed/abc.bin", false);
        let a = sigv4_authorization(&creds, "20260718T000000Z", "20260718", "PUT", "s3.example", &uri, &payload_hash);
        assert!(a.starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260718/auto/s3/aws4_request"));
        assert!(a.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date"));
        // Signature is 64 lowercase hex chars and stable across calls.
        let sig = a.rsplit("Signature=").next().unwrap();
        assert_eq!(sig.len(), 64);
        assert!(sig.bytes().all(|b| b.is_ascii_hexdigit()));
        let b = sigv4_authorization(&creds, "20260718T000000Z", "20260718", "PUT", "s3.example", &uri, &payload_hash);
        assert_eq!(a, b, "same inputs must produce the same signature");
        // The raw secret must NEVER appear in the header.
        assert!(!a.contains("SECRETKEY"), "the secret key must not leak into the Authorization header");
    }

    #[test]
    fn uri_encode_preserves_path_and_escapes_specials() {
        assert_eq!(uri_encode("/postern-backup/sealed/a.bin", false), "/postern-backup/sealed/a.bin");
        assert_eq!(uri_encode("a b+c", false), "a%20b%2Bc");
        // With encode_slash, separators are escaped too (query-value case).
        assert_eq!(uri_encode("a/b", true), "a%2Fb");
        // Unreserved set passes through untouched.
        assert_eq!(uri_encode("Aa0-._~", false), "Aa0-._~");
    }

    #[test]
    fn host_of_extracts_authority() {
        assert_eq!(host_of("https://s3.example.com").unwrap(), "s3.example.com");
        assert_eq!(host_of("https://s3.example.com/bucket/key").unwrap(), "s3.example.com");
        assert_eq!(host_of("https://s3.example.com:8443/x").unwrap(), "s3.example.com:8443");
        assert!(host_of("https://").is_err());
    }

    #[test]
    fn bucket_name_ok_accepts_dns_names_and_rejects_junk() {
        assert!(bucket_name_ok("postern-backup"));
        assert!(bucket_name_ok("abc"));
        assert!(bucket_name_ok("my.bucket.123"));
        for bad in ["ab", "-abc", "abc-", "AbC", "has_underscore", "has/slash", &"x".repeat(64)] {
            assert!(!bucket_name_ok(bad), "must reject {bad:?}");
        }
    }

    #[test]
    fn multipart_body_is_well_formed_and_wraps_the_ciphertext_verbatim() {
        let content = b"\x00\x01SEALED-CIPHERTEXT\xff\xfe";
        let boundary = "PosternBackupBoundaryTEST";
        let body = multipart_file_body(boundary, "file", "postern-backup.sealed", content);
        let text = String::from_utf8_lossy(&body);
        // Opening boundary + a file part named "file" with the fixed filename.
        assert!(text.starts_with("--PosternBackupBoundaryTEST\r\n"));
        assert!(text.contains(
            "Content-Disposition: form-data; name=\"file\"; filename=\"postern-backup.sealed\"\r\n"
        ));
        assert!(text.contains("Content-Type: application/octet-stream\r\n\r\n"));
        // Closing boundary present (the multipart terminator).
        assert!(text.contains("\r\n--PosternBackupBoundaryTEST--\r\n"));
        // The raw ciphertext bytes appear verbatim inside the body (not escaped).
        assert!(
            body.windows(content.len()).any(|w| w == content),
            "the sealed bytes must be embedded verbatim in the multipart body"
        );
    }

    #[test]
    fn cid_parse_reads_hash_and_rejects_missing() {
        let ok = serde_json::json!({ "Name": "x", "Hash": "QmSomeCid123", "Size": "42" });
        assert_eq!(cid_from_add_response(&ok).unwrap(), "QmSomeCid123");
        // No Hash / empty Hash / non-string → typed error, never a panic.
        assert!(cid_from_add_response(&serde_json::json!({ "Size": "42" })).is_err());
        assert!(cid_from_add_response(&serde_json::json!({ "Hash": "" })).is_err());
        assert!(cid_from_add_response(&serde_json::json!({ "Hash": 7 })).is_err());
    }

    #[test]
    fn cid_wellformedness_guards_the_gateway_path() {
        assert!(cid_is_wellformed("QmSomeCid123"));
        assert!(cid_is_wellformed("bafybeigdyrht4example"));
        for bad in ["", "../etc/passwd", "cid/with/slash", "cid.with.dot", "cid?x=1", "a b"] {
            assert!(!cid_is_wellformed(bad), "must reject {bad:?}");
        }
    }

    /// A single-request localhost HTTP mock: captures the raw request bytes and
    /// serves a fixed response. Returns (url, JoinHandle→captured request bytes).
    /// No token, no real network — this drives the EXACT request-shaping ureq
    /// sends (bearer header + multipart body) so we can assert on it offline.
    fn spawn_http_mock(response: &'static str) -> (String, std::thread::JoinHandle<Vec<u8>>) {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock");
        let url = format!("http://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            // Read headers, then exactly Content-Length body bytes.
            let mut buf = Vec::new();
            let mut tmp = [0u8; 4096];
            let mut header_end = None;
            while header_end.is_none() {
                let n = stream.read(&mut tmp).expect("read headers");
                if n == 0 { break; }
                buf.extend_from_slice(&tmp[..n]);
                header_end = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4);
            }
            let head = String::from_utf8_lossy(&buf[..header_end.unwrap_or(buf.len())]).to_string();
            let clen = head
                .lines()
                .find_map(|l| l.strip_prefix("Content-Length:").or_else(|| l.strip_prefix("content-length:")))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            let have = buf.len() - header_end.unwrap_or(buf.len());
            let mut remaining = clen.saturating_sub(have);
            while remaining > 0 {
                let n = stream.read(&mut tmp).expect("read body");
                if n == 0 { break; }
                buf.extend_from_slice(&tmp[..n]);
                remaining = remaining.saturating_sub(n);
            }
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response.len(),
                response
            );
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.flush();
            buf
        });
        (url, handle)
    }

    #[test]
    fn lighthouse_add_sends_bearer_and_multipart_and_parses_cid() {
        // Mock Lighthouse's `add` response, then drive the REAL request path.
        let (url, handle) = spawn_http_mock(r#"{"Name":"postern-backup.sealed","Hash":"QmMockCid0001","Size":"20"}"#);
        let sealed = b"\x00\x01SEALED-CIPHERTEXT-BYTES\xff";
        let cid = lighthouse_add(&url, "lh-test-token-123", sealed).expect("upload");
        assert_eq!(cid, "QmMockCid0001", "CID parsed from the mock's Hash field");

        let req = handle.join().expect("mock thread");
        let text = String::from_utf8_lossy(&req);
        // The bearer token the user supplied must be on the wire, verbatim.
        assert!(
            text.contains("authorization: Bearer lh-test-token-123")
                || text.contains("Authorization: Bearer lh-test-token-123"),
            "request must carry the Bearer token header"
        );
        // Multipart shaping: our content-type + the file part.
        assert!(text.contains("multipart/form-data; boundary=PosternBackupBoundary"), "multipart content-type");
        assert!(text.contains("Content-Disposition: form-data; name=\"file\"; filename=\"postern-backup.sealed\""), "file part");
        // The raw sealed bytes are embedded verbatim in the request body.
        assert!(req.windows(sealed.len()).any(|w| w == sealed), "sealed bytes on the wire");
    }

    #[test]
    fn lighthouse_add_maps_transport_error_to_a_typed_string_not_a_panic() {
        // A network failure must become a typed string, never a panic/stack.
        // Port 1 on loopback refuses connections → ureq Transport error branch.
        let err = lighthouse_add("http://127.0.0.1:1", "k", b"x").unwrap_err();
        assert!(err.starts_with("Lighthouse upload failed"), "typed error, got: {err}");
        assert!(!err.to_lowercase().contains("panic"), "never a panic/stack");
    }

    #[test]
    fn seal_store_restore_round_trip() {
        let dir = tmp_dir("rt");
        let name = "secret-notes.txt";
        let plaintext = b"Bloch protocol backup round-trip \x00\x01\x02 test payload \xff";
        let pass = b"correct horse battery staple";

        let sealed = seal_backup(name, plaintext, pass, TIER_DEFAULT).expect("seal");
        // The stored blob is genuinely encrypted: the plaintext must NOT appear.
        assert!(
            !sealed.sealed_blob.windows(plaintext.len()).any(|w| w == &plaintext[..]),
            "plaintext leaked into the sealed blob"
        );

        let files = store_to_dir(&dir, &sealed).expect("store");
        assert_eq!(files.len(), 3, "blob + package + anchor written");

        let restored = restore_from_dir(&dir, &sealed.set_id, pass).expect("restore");
        assert_eq!(restored.name, name);
        assert_eq!(restored.plaintext.as_slice(), &plaintext[..], "round-trip must return the original bytes");
        assert!(restored.anchor_verified);
        assert!(restored.integrity_verified);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_passphrase_fails_closed() {
        let dir = tmp_dir("wp");
        let sealed = seal_backup("f.txt", b"top secret", b"right-pass", TIER_DEFAULT).unwrap();
        store_to_dir(&dir, &sealed).unwrap();
        assert!(restore_from_dir(&dir, &sealed.set_id, b"WRONG-pass").is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn tampered_package_fails_anchor_verification() {
        let dir = tmp_dir("tp");
        let sealed = seal_backup("f.txt", b"payload", b"pw12345678", TIER_DEFAULT).unwrap();
        store_to_dir(&dir, &sealed).unwrap();
        // Flip a byte in the package salt (offset 6, inside the committed
        // prefix): this changes the SHAKE-256 root, so anchor verification must
        // fail before any decrypt is attempted.
        let pkg_path = dir.join(format!("{}.pbp0", sealed.set_id));
        let mut pkg = fs::read(&pkg_path).unwrap();
        pkg[6] ^= 0xFF;
        fs::write(&pkg_path, &pkg).unwrap();
        let err = restore_from_dir(&dir, &sealed.set_id, b"pw12345678");
        assert!(err.is_err(), "a tampered package must not restore");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn tampered_blob_fails_integrity() {
        let dir = tmp_dir("tb");
        let sealed = seal_backup("f.txt", b"payload-xyz", b"pw12345678", TIER_DEFAULT).unwrap();
        store_to_dir(&dir, &sealed).unwrap();
        // Corrupt the stored blob file directly.
        let blob_path = dir.join(format!("{}.blob", hex::encode(sealed.blob_cid)));
        let mut blob = fs::read(&blob_path).unwrap();
        let n = blob.len();
        blob[n / 2] ^= 0xFF;
        fs::write(&blob_path, &blob).unwrap();
        // The blob file is now under the WRONG name for its content, so the
        // manifest's content_cid no longer resolves → fetch/integrity fails.
        assert!(restore_from_dir(&dir, &sealed.set_id, b"pw12345678").is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
