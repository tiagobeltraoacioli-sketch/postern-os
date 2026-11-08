//! [`DirBackend`] — a durable **on-disk spool** (Phase 2).
//!
//! Each sealed blob is written to a single file whose name **is** its
//! `CIDv1-raw-sha2-256` string, under a spool directory. Because the name is
//! the content address, the store is:
//!
//! * **durable** — a fresh [`DirBackend`] over the same directory (after the
//!   old instance is dropped, or the process restarts) serves back
//!   byte-identical blobs; there is no in-RAM index to lose;
//! * **self-verifying** — [`get`](DirBackend::get) recomputes the CID of the
//!   bytes it reads and fails closed with [`BackendError::CidMismatch`] on any
//!   disagreement (on-disk corruption / tampering);
//! * **crash-safe on write** — blobs are written to a temp file in the same
//!   directory, `fsync`-ed, then atomically `rename`-d into place, so a reader
//!   never sees a half-written object.
//!
//! HONESTY: this is a **real, durable, offline** backend — but it is still part
//! of an UNAUDITED SCAFFOLD crate. The `sha2-256` CID it computes is a Filecoin
//! **content-address locator** (`0x55` raw leaf), the same locator the live
//! provider would report — it carries **zero integrity weight** for the
//! post-quantum trust story (that is the separate SHAKE-256 manifest overlay,
//! still an opaque slot in the default build). `DirBackend` proves *durability
//! and fail-closed self-verification of the local spool*, nothing about the
//! live network path or the PQ overlay.
//!
//! Zero dependencies, zero network: the `sha2-256` and multibase-base32
//! primitives below are hand-rolled in pure `std`, keeping the crate's
//! zero-dependency default build intact (no `sha2` / `multihash` / `cid` /
//! `data_encoding` crates). The CID string is `[b][a-z2-7]+` by construction,
//! so using it directly as a filename carries no path-traversal risk, and any
//! [`Cid`] that is not a well-formed CIDv1-raw-sha2-256 (e.g. a synthetic
//! [`MockBackend`](super::MockBackend) locator) maps to no file and fails
//! closed.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use super::{BackendError, Cid, DealStatus, StorageBackend};

// ── Content addressing (CIDv1 · raw · sha2-256 · multibase-base32-lower) ───────

/// CIDv1 version prefix (unsigned-varint `0x01`).
const CID_VERSION: u8 = 0x01;
/// Multicodec for `raw` binary leaf data (`0x55`). Sealed blobs are opaque
/// bytes, so we address them as raw leaves rather than dag-pb.
const CID_CODEC_RAW: u8 = 0x55;
/// Multihash function code for `sha2-256` (`0x12`).
const MULTIHASH_SHA2_256: u8 = 0x12;
/// SHA-256 digest length in bytes (`0x20` = 32).
const SHA2_256_LEN: u8 = 0x20;
/// Total length of a CIDv1-raw-sha2-256 in binary form: 4 prefix bytes + 32.
const CIDV1_LEN: usize = 4 + SHA2_256_LEN as usize;

/// The **binary** CIDv1 of `data`: `0x01 ‖ 0x55 ‖ 0x12 ‖ 0x20 ‖ sha2-256(data)`.
///
/// The returned [`Cid`] wraps these 36 bytes; its multibase-base32-lower string
/// form (the on-disk filename) is derived by [`cid_to_filename`].
fn compute_cid(data: &[u8]) -> Cid {
    let digest = sha256(data);
    let mut bytes = Vec::with_capacity(CIDV1_LEN);
    bytes.push(CID_VERSION);
    bytes.push(CID_CODEC_RAW);
    bytes.push(MULTIHASH_SHA2_256);
    bytes.push(SHA2_256_LEN);
    bytes.extend_from_slice(&digest);
    Cid(bytes)
}

/// Whether `bytes` are a well-formed CIDv1-raw-sha2-256 (the only shape this
/// backend can address). Guards both path-safety and fail-closed lookups.
fn is_cidv1_raw_sha256(bytes: &[u8]) -> bool {
    bytes.len() == CIDV1_LEN
        && bytes[0] == CID_VERSION
        && bytes[1] == CID_CODEC_RAW
        && bytes[2] == MULTIHASH_SHA2_256
        && bytes[3] == SHA2_256_LEN
}

/// The canonical multibase-base32-lower filename for `cid`, or `None` if `cid`
/// is not a well-formed CIDv1-raw-sha2-256 (so it addresses no file — a
/// synthetic locator can never escape the spool root).
fn cid_to_filename(cid: &Cid) -> Option<String> {
    if !is_cidv1_raw_sha256(cid.as_bytes()) {
        return None;
    }
    let mut s = String::with_capacity(1 + CIDV1_LEN * 8 / 5 + 1);
    s.push('b'); // multibase base32 prefix
    base32_lower_encode(cid.as_bytes(), &mut s);
    Some(s)
}

/// Validate an existing CID filename string and recover its binary [`Cid`].
/// Rejects anything that is not a multibase-`b` base32 CIDv1-raw-sha2-256 of the
/// exact expected shape (bad prefix, non-base32 symbol, non-canonical trailing
/// bits, wrong codec/length). Currently exercised only by the parse-rejection
/// test; the durable write path names files via [`cid_to_filename`].
#[cfg(test)]
fn parse_cid_filename(name: &str) -> Option<Cid> {
    let body = name.strip_prefix('b')?;
    if body.is_empty() {
        return None;
    }
    let raw = base32_lower_decode(body)?;
    if !is_cidv1_raw_sha256(&raw) {
        return None;
    }
    Some(Cid(raw))
}

/// RFC-4648 base32 (no padding) over the lowercase multibase alphabet
/// `abcdefghijklmnopqrstuvwxyz234567`, appended to `out`.
fn base32_lower_encode(data: &[u8], out: &mut String) {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut acc: u64 = 0;
    let mut nbits: u32 = 0;
    for &byte in data {
        acc = (acc << 8) | byte as u64;
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            out.push(ALPHABET[((acc >> nbits) & 0x1f) as usize] as char);
        }
    }
    if nbits > 0 {
        // Left-pad the final partial group with zero bits (no `=` padding).
        out.push(ALPHABET[((acc << (5 - nbits)) & 0x1f) as usize] as char);
    }
}

/// Inverse of [`base32_lower_encode`]. Strict: rejects any non-alphabet symbol
/// and any non-canonical (non-zero) trailing padding bits, so a garbage string
/// never round-trips to a valid CID. Used by [`parse_cid_filename`] (test-only).
#[cfg(test)]
fn base32_lower_decode(s: &str) -> Option<Vec<u8>> {
    let mut acc: u64 = 0;
    let mut nbits: u32 = 0;
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    for ch in s.bytes() {
        let val: u64 = match ch {
            b'a'..=b'z' => (ch - b'a') as u64,
            b'2'..=b'7' => (ch - b'2' + 26) as u64,
            _ => return None,
        };
        acc = (acc << 5) | val;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            out.push(((acc >> nbits) & 0xff) as u8);
        }
    }
    // A leftover full symbol (≥5 unused bits) is not canonical; and any
    // remaining bits must be zero padding.
    if nbits >= 5 || (nbits > 0 && (acc & ((1u64 << nbits) - 1)) != 0) {
        return None;
    }
    Some(out)
}

/// Pure-`std` SHA-256 (FIPS 180-4). Hand-rolled to keep the crate's default
/// build zero-dependency; validated against the known empty-blob CID vector in
/// the tests below.
fn sha256(data: &[u8]) -> [u8; 32] {
    #[rustfmt::skip]
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    // Pre-processing: append 0x80, zero-pad to 56 mod 64, then the 64-bit
    // big-endian message length in bits.
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    let mut w = [0u32; 64];
    for chunk in msg.chunks_exact(64) {
        for (i, wi) in w.iter_mut().take(16).enumerate() {
            *wi = u32::from_be_bytes([
                chunk[4 * i],
                chunk[4 * i + 1],
                chunk[4 * i + 2],
                chunk[4 * i + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

// ── DirBackend ─────────────────────────────────────────────────────────────────

/// A durable on-disk spool backend rooted at a single directory.
///
/// State lives entirely on disk: a fresh instance over the same directory sees
/// every blob a prior instance spooled. See the [module docs](self) for the
/// durability / self-verification / crash-safety contract and honesty scope.
#[derive(Debug)]
pub struct DirBackend {
    root: PathBuf,
}

impl DirBackend {
    /// Open (creating if necessary) a spool at `root`. Any blobs already
    /// present in `root` are immediately visible — that is the durability
    /// contract: state lives on disk, not in this struct.
    pub fn open<P: AsRef<Path>>(root: P) -> Result<DirBackend, BackendError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root).map_err(io_unavailable)?;
        Ok(DirBackend { root })
    }

    /// The spool directory this backend is rooted at.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Absolute path of the file that would hold `cid`, or `None` if `cid` is
    /// not a well-formed CIDv1-raw-sha2-256 (and so addresses no file).
    fn path_for(&self, cid: &Cid) -> Option<PathBuf> {
        cid_to_filename(cid).map(|name| self.root.join(name))
    }
}

impl StorageBackend for DirBackend {
    fn put_car(&mut self, bytes: &[u8]) -> Result<Cid, BackendError> {
        let cid = compute_cid(bytes);
        let filename =
            cid_to_filename(&cid).expect("compute_cid always yields a valid CIDv1 filename");
        let final_path = self.root.join(&filename);

        // Content-addressed ⇒ if the object is already spooled, its bytes are
        // identical by definition; skip the rewrite (idempotent put).
        if final_path.exists() {
            return Ok(cid);
        }

        // Write to a uniquely named temp file in the SAME directory (so the
        // rename is a same-filesystem atomic op), fsync it, then rename into
        // place. `.<cid>.tmp.<pid>.<nonce>` keeps concurrent writers from
        // clobbering each other's temp file.
        let tmp_name = format!(".{}.tmp.{}.{}", filename, std::process::id(), next_nonce());
        let tmp_path = self.root.join(tmp_name);

        // Scope the file handle so it is closed before the rename.
        {
            let mut f = fs::File::create(&tmp_path).map_err(io_unavailable)?;
            if let Err(e) = f.write_all(bytes).and_then(|()| f.sync_all()) {
                // Best-effort cleanup of the partial temp file.
                let _ = fs::remove_file(&tmp_path);
                return Err(io_unavailable(e));
            }
        }

        if let Err(e) = fs::rename(&tmp_path, &final_path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(io_unavailable(e));
        }

        // Best-effort durability of the new directory entry itself. A failure
        // here does not invalidate the (already fsync-ed, already renamed)
        // data, so it is not fatal.
        if let Ok(dir) = fs::File::open(&self.root) {
            let _ = dir.sync_all();
        }

        Ok(cid)
    }

    fn get(&mut self, cid: &Cid) -> Result<Vec<u8>, BackendError> {
        // An un-addressable CID (e.g. a synthetic MockBackend locator) names no
        // object: fail closed, never touch the filesystem with it.
        let Some(path) = self.path_for(cid) else {
            return Err(BackendError::NotFound);
        };
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            // Fail CLOSED: a missing file is an explicit NotFound, never an
            // empty-success. Any other I/O error surfaces as Unavailable.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(BackendError::NotFound);
            }
            Err(e) => return Err(io_unavailable(e)),
        };
        // Self-verify: the bytes must hash back to the CID we were asked for.
        // On-disk corruption / tampering surfaces as CidMismatch — the client
        // re-computed content address disagreeing with the stored locator, the
        // filesystem analog of §4's hardened-CAR check.
        if compute_cid(&bytes) != *cid {
            return Err(BackendError::CidMismatch);
        }
        Ok(bytes)
    }

    fn deal_status(&mut self, cid: &Cid) -> Result<DealStatus, BackendError> {
        // Honest vocabulary: a present spool file is `Acknowledged` (the local
        // hot layer holds the bytes) — NOT a Filecoin deal. Absent ⇒ `Unknown`.
        let present = self.path_for(cid).is_some_and(|p| p.is_file());
        Ok(if present {
            DealStatus::Acknowledged
        } else {
            DealStatus::Unknown
        })
    }
}

/// Map an underlying I/O failure to the honest transport-error variant.
fn io_unavailable(e: std::io::Error) -> BackendError {
    BackendError::Unavailable(format!("dir backend i/o: {e}"))
}

/// A monotonic per-process nonce so concurrent `put_car` calls for distinct
/// blobs never collide on the temp filename.
fn next_nonce() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// A dependency-free scratch directory that removes itself on drop (the
    /// crate keeps a zero-dependency default build, so no `tempfile` crate).
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> TempDir {
            let mut path = std::env::temp_dir();
            path.push(format!(
                "bloch-data-dirbackend-{}-{}",
                std::process::id(),
                next_nonce()
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

    /// The core acceptance test: durability across instances.
    ///
    /// Put blobs into a scratch dir, DROP the instance, construct a FRESH
    /// `DirBackend` over the same dir, and `get()` returns byte-identical
    /// bytes. `get()` of an unknown CID fails closed with `NotFound`.
    /// Fully offline, zero network.
    #[test]
    fn durable_across_instances_and_fails_closed_on_miss() {
        let dir = TempDir::new();
        let spool = dir.path().join("spool");

        // Blobs chosen to exercise empty, binary, and larger-than-one-page
        // payloads.
        let blobs: Vec<Vec<u8>> = vec![
            b"".to_vec(),
            b"the kalinov bridge sealed blob \x00\x01\xff".to_vec(),
            vec![0xABu8; 200_000],
        ];

        // --- instance #1: write, then drop ---
        let cids: Vec<Cid> = {
            let mut be = DirBackend::open(&spool).expect("open #1");
            let mut cids = Vec::new();
            for blob in &blobs {
                let cid = be.put_car(blob).expect("put_car");
                assert_eq!(be.deal_status(&cid).unwrap(), DealStatus::Acknowledged);
                cids.push(cid);
            }
            cids
            // `be` dropped here — no in-RAM state may survive.
        };

        // --- instance #2: fresh backend over the SAME dir ---
        let mut be2 = DirBackend::open(&spool).expect("open #2");
        for (cid, blob) in cids.iter().zip(&blobs) {
            let got = be2.get(cid).expect("get after reopen");
            assert_eq!(&got, blob, "bytes must be identical after reopen");
            assert_eq!(be2.deal_status(cid).unwrap(), DealStatus::Acknowledged);
        }

        // --- fail closed on an unknown (but well-formed) CID ---
        let unknown = compute_cid(b"this blob was never spooled");
        assert_eq!(
            be2.get(&unknown),
            Err(BackendError::NotFound),
            "unknown CID must fail closed with NotFound"
        );
        assert_eq!(be2.deal_status(&unknown).unwrap(), DealStatus::Unknown);
    }

    #[test]
    fn empty_blob_cid_matches_known_vector() {
        // The CIDv1-raw-sha2-256 of the empty blob is a well-known fixture; it
        // pins the hand-rolled sha2-256 + multibase-base32 against the canonical
        // Filecoin/IPFS value.
        let cid = compute_cid(b"");
        assert_eq!(
            cid_to_filename(&cid).unwrap(),
            "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"
        );
    }

    #[test]
    fn blob_is_stored_under_its_cid_filename() {
        let dir = TempDir::new();
        let mut be = DirBackend::open(dir.path()).expect("open");
        let cid = be.put_car(b"named by content").expect("put");
        // The on-disk file name IS the CID string.
        let name = cid_to_filename(&cid).expect("valid cid");
        assert!(name.starts_with('b'));
        assert!(dir.path().join(&name).is_file());
    }

    #[test]
    fn put_is_idempotent() {
        let dir = TempDir::new();
        let mut be = DirBackend::open(dir.path()).expect("open");
        let c1 = be.put_car(b"same bytes").expect("put 1");
        let c2 = be.put_car(b"same bytes").expect("put 2");
        assert_eq!(c1, c2);
        // Exactly one object file (temp files are cleaned up).
        let files: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
            .collect();
        assert_eq!(files.len(), 1);
    }

    #[test]
    fn get_detects_on_disk_corruption() {
        let dir = TempDir::new();
        let mut be = DirBackend::open(dir.path()).expect("open");
        let cid = be.put_car(b"trustworthy bytes").expect("put");
        // Tamper with the stored file behind the backend's back.
        let name = cid_to_filename(&cid).expect("valid cid");
        fs::write(dir.path().join(&name), b"tampered bytes").unwrap();
        assert_eq!(be.get(&cid), Err(BackendError::CidMismatch));
    }

    #[test]
    fn synthetic_cid_maps_to_no_file_and_fails_closed() {
        // A locator that is not a CIDv1-raw-sha2-256 (e.g. a MockBackend
        // synthetic CID) addresses no file: it must fail closed without ever
        // touching the filesystem — the path-traversal / fail-closed guard.
        let dir = TempDir::new();
        let mut be = DirBackend::open(dir.path()).expect("open");
        let bogus = Cid(b"mock-cid:\x00\x00\x00\x00\x00\x00\x00\x00".to_vec());
        assert!(cid_to_filename(&bogus).is_none());
        assert_eq!(be.get(&bogus), Err(BackendError::NotFound));
        assert_eq!(be.deal_status(&bogus).unwrap(), DealStatus::Unknown);
        // Also reject a would-be traversal string outright at parse time.
        assert!(cid_to_filename(&Cid(b"../../etc/passwd".to_vec())).is_none());
    }

    #[test]
    fn cid_filename_round_trips_and_parse_rejects_garbage() {
        // Valid CID round-trips through filename -> parse -> Cid.
        let cid = compute_cid(b"round trip");
        let name = cid_to_filename(&cid).expect("valid");
        assert_eq!(parse_cid_filename(&name), Some(cid));

        // Garbage strings are rejected: empty, bare prefix, wrong multibase,
        // non-base32 symbols, and a base32 string of the wrong CID shape.
        for bad in ["", "b", "zabc", "b!!!", "bnotacid", "babcdef"] {
            assert!(
                parse_cid_filename(bad).is_none(),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn cid_is_stable_and_content_addressed() {
        let a = compute_cid(b"kalinov");
        let b = compute_cid(b"kalinov");
        let c = compute_cid(b"kalinov!");
        assert_eq!(a, b);
        assert_ne!(a, c);
        // Canonical multibase-base32-lower filename shape.
        let name = cid_to_filename(&a).unwrap();
        assert!(name.starts_with('b'));
        assert!(name[1..]
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ('2'..='7').contains(&ch)));
    }
}
