//! PBM0 backup manifest: strict little-endian binary codec.
//!
//! Spec: `docs/specs/POSTERN-DATA-FILECOIN-DESIGN.md`, §3.1 ("Manifest
//! format `PBM0`, plaintext — exists only inside the seal"). House style — no
//! JSON, no serde, no external deps: a fixed-magic, length-prefixed,
//! bounds-checked binary format that decodes strictly (typed errors, never
//! panics) and re-encodes byte-identically.
//!
//! A manifest lists the sealed files of one backup-set generation. It is
//! **plaintext and lives only inside the seal** — filenames NEVER appear
//! outside it. The signature and `manifest_root` are NOT here: they live in
//! the separate PBP0 package wrapper (§3.2, [`crate::package`]). Wire layout
//! (all multi-byte integers little-endian):
//!
//! ```text
//! offset  size  field
//! 0       4     magic ASCII "PBM0"        (50 42 4D 30)
//! 4       1     version u8 = 0x00
//! 5       32    backup_set_id [u8; 32]    SHAKE-256/256(namespace_id ‖ sequence u64 LE) — a
//!                                         redundancy check vs the anchor; opaque here (not recomputed).
//! 37      8     sequence      u64 LE      must equal the DATA0 anchor's sequence.
//! 45      8     created_unix  u64 LE      timestamp — INSIDE the seal, so it is not leaked.
//! 53      4     entry_count   u32 LE      number of file entries that follow.
//! 57      ...   entries[entry_count], each (sorted ascending by path bytes — caller's canonical rule):
//!                 path_len         u16 LE  ‖ path  (UTF-8, relative) — filenames stay inside the seal
//!                 file_len         u64 LE                            — plaintext length
//!                 content_cid_len  u8      ‖ content_cid (CIDv1 bytes) — provider LOCATOR, zero integrity weight
//!                 shake256         [u8; 32]                          — SHAKE-256/256 of the SEALED blob (PQ integrity)
//! ```
//!
//! HONESTY (see crate docs): this zero-dep crate does **not** hash content and
//! does **not** sign. Each entry's `shake256` is carried verbatim — the real
//! SHAKE-256/256 of the sealed blob is computed by the wiring crate
//! (`postern-backup-net`), never here; likewise `content_cid` is a
//! provider-reported **locator only**, carrying no integrity weight. The
//! per-entry `shake256` is what makes integrity PQ end-to-end (§3.1, §6): a
//! fetched blob is re-hashed against it (key-independent) before the
//! key-committing AEAD gives the second, keyed check — a check that lives
//! outside this zero-dep crate. The authenticity leg over these bytes (the
//! ML-DSA-65‖Falcon-1024 signature that fills the PBP0 [`crate::package`]
//! `pk`/`sig` slots and the DATA0 `signer_commit`) is likewise **not** run
//! here — it is now REALLY wired in `postern-backup-net`
//! (`signer::{sign_backup, verify_signed_backup}`, over `bloch-crypto`),
//! structurally out of this crate's zero-dep honesty scope.

// ── Wire constants ────────────────────────────────────────────────────────────

/// 4-byte magic prefix identifying a PBM0 backup manifest (`50 42 4D 30`).
pub const MANIFEST_MAGIC: [u8; 4] = *b"PBM0";
/// Wire-format version this crate encodes and accepts (PBM0 draft).
pub const MANIFEST_VERSION: u8 = 0x00;
/// Fixed size of the manifest header before the entry list: magic(4) +
/// version(1) + backup_set_id(32) + sequence(8) + created_unix(8) +
/// entry_count(4) = 57.
pub const MANIFEST_HEADER_LEN: usize = 57;

// ── Errors ────────────────────────────────────────────────────────────────────

/// Typed encode/decode failure. Decoding never panics; encoding fails only on
/// a field that cannot fit its length prefix. Every malformed-input class maps
/// here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManifestError {
    /// Payload does not start with [`MANIFEST_MAGIC`].
    BadMagic,
    /// Magic matched but the version byte is not [`MANIFEST_VERSION`].
    BadVersion(u8),
    /// Payload ended before a required field was fully read.
    Truncated,
    /// Bytes remain after a complete, valid manifest.
    TrailingBytes,
    /// An entry `path` is longer than `u16::MAX` and cannot be length-prefixed
    /// (encode-side guard).
    PathTooLong(usize),
    /// An entry `content_cid` is longer than `u8::MAX` (255) and cannot be
    /// length-prefixed (encode-side guard — CIDv1 is well under 255 bytes).
    CidTooLong(usize),
    /// The entry count is larger than `u32::MAX` (encode-side guard).
    TooManyEntries(usize),
    /// Two entries share the exact same `path` bytes. The canonical rule is
    /// *strictly* ascending, distinct paths, so duplicates cannot be ordered —
    /// raised by [`Manifest::canonicalize`]; carries the offending path bytes.
    DuplicatePath(Vec<u8>),
}

impl core::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadMagic => write!(f, "pbm0 manifest: bad magic"),
            Self::BadVersion(v) => write!(f, "pbm0 manifest: unsupported version {v}"),
            Self::Truncated => write!(f, "pbm0 manifest: truncated payload"),
            Self::TrailingBytes => write!(f, "pbm0 manifest: trailing bytes after payload"),
            Self::PathTooLong(n) => write!(f, "pbm0 manifest: path too long ({n} > u16::MAX)"),
            Self::CidTooLong(n) => write!(f, "pbm0 manifest: content_cid too long ({n} > u8::MAX)"),
            Self::TooManyEntries(n) => {
                write!(f, "pbm0 manifest: too many entries ({n} > u32::MAX)")
            }
            Self::DuplicatePath(p) => {
                write!(f, "pbm0 manifest: duplicate entry path ({} bytes)", p.len())
            }
        }
    }
}

impl std::error::Error for ManifestError {}

// ── Types ─────────────────────────────────────────────────────────────────────

/// One sealed file of a backup-set: its in-seal path, plaintext length, the
/// provider locator for the sealed blob, and the PQ integrity digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestEntry {
    /// Relative UTF-8 path of the source file. Stays **inside the seal** —
    /// filenames never appear outside it. Carried as raw bytes here (this
    /// crate does not enforce UTF-8; the sealer supplies valid paths).
    pub path: Vec<u8>,
    /// Plaintext byte length of the source file.
    pub file_len: u64,
    /// Provider-reported content CID for the sealed blob. Opaque bytes,
    /// treated as a **locator only** — zero integrity weight (§3.1, §6).
    pub content_cid: Vec<u8>,
    /// SHAKE-256/256 of the **sealed** (ciphertext) blob bytes — **the PQ
    /// integrity bit**. Computed outside this crate; carried verbatim. A
    /// fetched blob is re-hashed against this before use (§6).
    pub shake256: [u8; 32],
}

/// A decoded PBM0 backup manifest for one backup-set generation. Plaintext;
/// exists only inside the seal. The signature and `manifest_root` are NOT
/// here — they live in the [`crate::package`] PBP0 wrapper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    /// `SHAKE-256/256(namespace_id ‖ sequence)` — a redundancy check against
    /// the anchor. Opaque 32 bytes here (this crate does not recompute it).
    pub backup_set_id: [u8; 32],
    /// Must equal the DATA0 anchor's `sequence`.
    pub sequence: u64,
    /// Creation timestamp (seconds). Inside the seal, so not leaked.
    pub created_unix: u64,
    /// File entries. The wire codec ([`Manifest::encode`]/[`Manifest::decode`])
    /// preserves and round-trips their order exactly and does **not** impose
    /// it. The spec's canonical rule — sorted strictly ascending by path bytes
    /// — is enforced explicitly via [`Manifest::canonicalize`] (to establish
    /// it) and [`Manifest::is_canonical`] (to assert it).
    pub entries: Vec<ManifestEntry>,
}

impl Manifest {
    /// Encode to the canonical wire form. Fails only when a field is too long
    /// to fit its length prefix (a caller-side invariant violation) — the
    /// happy path is always decodable by [`Manifest::decode`].
    pub fn encode(&self) -> Result<Vec<u8>, ManifestError> {
        if self.entries.len() > u32::MAX as usize {
            return Err(ManifestError::TooManyEntries(self.entries.len()));
        }
        for e in &self.entries {
            if e.path.len() > u16::MAX as usize {
                return Err(ManifestError::PathTooLong(e.path.len()));
            }
            if e.content_cid.len() > u8::MAX as usize {
                return Err(ManifestError::CidTooLong(e.content_cid.len()));
            }
        }

        let mut out = Vec::with_capacity(MANIFEST_HEADER_LEN);
        out.extend_from_slice(&MANIFEST_MAGIC);
        out.push(MANIFEST_VERSION);
        out.extend_from_slice(&self.backup_set_id);
        out.extend_from_slice(&self.sequence.to_le_bytes());
        out.extend_from_slice(&self.created_unix.to_le_bytes());
        out.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());
        for e in &self.entries {
            out.extend_from_slice(&(e.path.len() as u16).to_le_bytes());
            out.extend_from_slice(&e.path);
            out.extend_from_slice(&e.file_len.to_le_bytes());
            out.push(e.content_cid.len() as u8);
            out.extend_from_slice(&e.content_cid);
            out.extend_from_slice(&e.shake256);
        }
        Ok(out)
    }

    /// Strict decode. Rejects bad magic, bad version, truncation and trailing
    /// bytes — each with a typed [`ManifestError`]. Never panics on any
    /// input (adversarial length prefixes fail bounds checks rather than
    /// pre-allocating; see the xorshift-garbage test).
    pub fn decode(bytes: &[u8]) -> Result<Manifest, ManifestError> {
        let mut cur = Cursor::new(bytes);

        if cur.take(4)? != MANIFEST_MAGIC {
            return Err(ManifestError::BadMagic);
        }
        let version = cur.take_u8()?;
        if version != MANIFEST_VERSION {
            return Err(ManifestError::BadVersion(version));
        }
        let backup_set_id = cur.take_32()?;
        let sequence = cur.take_u64_le()?;
        let created_unix = cur.take_u64_le()?;
        let entry_count = cur.take_u32_le()?;

        // Do NOT pre-allocate from the untrusted count: push and let the
        // bounds-checked cursor fail fast if the buffer runs out. This keeps
        // a giant `entry_count` from triggering a huge allocation.
        let mut entries = Vec::new();
        for _ in 0..entry_count {
            let path_len = cur.take_u16_le()? as usize;
            let path = cur.take(path_len)?.to_vec();
            let file_len = cur.take_u64_le()?;
            let cid_len = cur.take_u8()? as usize;
            let content_cid = cur.take(cid_len)?.to_vec();
            let shake256 = cur.take_32()?;
            entries.push(ManifestEntry { path, file_len, content_cid, shake256 });
        }

        if !cur.is_exhausted() {
            return Err(ManifestError::TrailingBytes);
        }
        Ok(Manifest { backup_set_id, sequence, created_unix, entries })
    }

    /// Is the entry list in canonical order? — the spec's rule (§3.1): entries
    /// **sorted strictly ascending by raw `path` bytes**, which also forbids
    /// exact duplicate paths (a duplicate is not *strictly* greater than its
    /// predecessor). Compares `path` bytes lexicographically; the other entry
    /// fields are irrelevant to ordering. The empty and single-entry lists are
    /// trivially canonical.
    ///
    /// The wire codec ([`Self::encode`]/[`Self::decode`]) only *preserves*
    /// order — it neither imposes nor checks it — so this is the explicit
    /// predicate a caller uses to assert the invariant, paired with
    /// [`Self::canonicalize`] to establish it.
    pub fn is_canonical(&self) -> bool {
        self.entries.windows(2).all(|w| w[0].path < w[1].path)
    }

    /// Reorder `entries` into canonical order: sort **ascending by raw `path`
    /// bytes** and reject exact duplicate paths.
    ///
    /// On `Ok(())` the entries are strictly ascending by path and
    /// [`Self::is_canonical`] returns `true`. On the first exact-duplicate
    /// path found, returns [`ManifestError::DuplicatePath`] with those bytes
    /// and leaves `entries` sorted (the duplicates are then adjacent) — the
    /// caller must resolve the collision; this crate will not silently drop or
    /// merge an entry. Ordering is by path bytes only, so entries that differ
    /// solely in `file_len`/`content_cid`/`shake256` but share a `path` are a
    /// duplicate, never a valid pair.
    pub fn canonicalize(&mut self) -> Result<(), ManifestError> {
        // Stable sort keeps any pre-existing relative order of equal-path
        // entries, which makes the duplicate reported deterministic.
        self.entries.sort_by(|a, b| a.path.cmp(&b.path));
        for w in self.entries.windows(2) {
            if w[0].path == w[1].path {
                return Err(ManifestError::DuplicatePath(w[0].path.clone()));
            }
        }
        Ok(())
    }
}

// ── Bounds-checked cursor (no unsafe, no deps, checked arithmetic) ────────────

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ManifestError> {
        let end = self.pos.checked_add(n).ok_or(ManifestError::Truncated)?;
        if end > self.bytes.len() {
            return Err(ManifestError::Truncated);
        }
        let s = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn take_u8(&mut self) -> Result<u8, ManifestError> {
        Ok(self.take(1)?[0])
    }

    fn take_u16_le(&mut self) -> Result<u16, ManifestError> {
        let mut b = [0u8; 2];
        b.copy_from_slice(self.take(2)?);
        Ok(u16::from_le_bytes(b))
    }

    fn take_u32_le(&mut self) -> Result<u32, ManifestError> {
        let mut b = [0u8; 4];
        b.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(b))
    }

    fn take_u64_le(&mut self) -> Result<u64, ManifestError> {
        let mut b = [0u8; 8];
        b.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(b))
    }

    fn take_32(&mut self) -> Result<[u8; 32], ManifestError> {
        let mut b = [0u8; 32];
        b.copy_from_slice(self.take(32)?);
        Ok(b)
    }

    fn is_exhausted(&self) -> bool {
        self.pos == self.bytes.len()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &[u8], file_len: u64, cid: &[u8], shake: u8) -> ManifestEntry {
        ManifestEntry {
            path: path.to_vec(),
            file_len,
            content_cid: cid.to_vec(),
            shake256: [shake; 32],
        }
    }

    fn sample() -> Manifest {
        Manifest {
            backup_set_id: [0x11; 32],
            sequence: 7,
            created_unix: 1_700_000_000,
            entries: vec![
                entry(b"docs/a.txt", 12, b"\x01\x55\x12\x20aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 0xA0),
                entry(b"docs/b.txt", 4096, b"\x01\x55\x12\x20bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 0xB0),
            ],
        }
    }

    #[test]
    fn header_offsets_are_pinned() {
        // Offsets transcribed from the spec §3.1 byte table, not from encode().
        let m = Manifest {
            backup_set_id: [0xA1; 32],
            sequence: 0x0102_0304_0506_0708,
            created_unix: 0x1112_1314_1516_1718,
            entries: vec![],
        };
        let b = m.encode().unwrap();
        assert_eq!(&b[0..4], b"PBM0");
        assert_eq!(&b[0..4], &[0x50, 0x42, 0x4D, 0x30]);
        assert_eq!(b[4], 0x00); // version at 4
        assert_eq!(&b[5..37], &[0xA1; 32]); // backup_set_id at 5
        assert_eq!(&b[37..45], &0x0102_0304_0506_0708u64.to_le_bytes()); // sequence at 37
        assert_eq!(&b[45..53], &0x1112_1314_1516_1718u64.to_le_bytes()); // created_unix at 45
        assert_eq!(&b[53..57], &0u32.to_le_bytes()); // entry_count at 53
        assert_eq!(MANIFEST_HEADER_LEN, 57);
        assert_eq!(b.len(), 57); // no entries → header only
    }

    #[test]
    fn entry_layout_offsets_pinned() {
        // One entry, distinct field bytes, offsets transcribed from spec.
        let m = Manifest {
            backup_set_id: [0; 32],
            sequence: 0,
            created_unix: 0,
            entries: vec![entry(b"ab", 0x2233_4455_6677_8899, b"\x01\x55", 0xCC)],
        };
        let b = m.encode().unwrap();
        assert_eq!(&b[57..59], &2u16.to_le_bytes()); // path_len
        assert_eq!(&b[59..61], b"ab"); // path
        assert_eq!(&b[61..69], &0x2233_4455_6677_8899u64.to_le_bytes()); // file_len
        assert_eq!(b[69], 0x02); // content_cid_len
        assert_eq!(&b[70..72], b"\x01\x55"); // content_cid
        assert_eq!(&b[72..104], &[0xCC; 32]); // shake256
        assert_eq!(b.len(), 104);
    }

    #[test]
    fn round_trip_various() {
        for m in [
            Manifest { backup_set_id: [0; 32], sequence: 0, created_unix: 0, entries: vec![] },
            sample(),
            Manifest {
                backup_set_id: [0xFF; 32],
                sequence: u64::MAX,
                created_unix: u64::MAX,
                entries: vec![entry(b"", 0, b"", 0x00), entry(b"\x00", u64::MAX, b"\xff", 0xFF)],
            },
        ] {
            let bytes = m.encode().unwrap();
            let decoded = Manifest::decode(&bytes).expect("valid manifest must decode");
            assert_eq!(decoded, m);
            assert_eq!(decoded.encode().unwrap(), bytes); // encode∘decode == identity
        }
    }

    #[test]
    fn distinct_entry_fields_survive_round_trip() {
        // Distinct paths/lengths/cids/digests so a swapped-field bug cannot pass.
        let m = Manifest {
            backup_set_id: (0u8..32).collect::<Vec<_>>().try_into().unwrap(),
            sequence: 42,
            created_unix: 99,
            entries: vec![
                entry(b"zero", 1, b"cid-zero", 0x10),
                entry(b"one-longer", 2, b"cid-one-longer", 0x20),
                entry(b"c", 0x0102_0304_0506_0708, b"c", 0x30),
            ],
        };
        let bytes = m.encode().unwrap();
        assert_eq!(Manifest::decode(&bytes).unwrap(), m);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut b = sample().encode().unwrap();
        b[0] ^= 0xFF;
        assert_eq!(Manifest::decode(&b), Err(ManifestError::BadMagic));
        assert_eq!(Manifest::decode(b"DAT0\x00"), Err(ManifestError::BadMagic));
        assert_eq!(Manifest::decode(&[]), Err(ManifestError::Truncated));
    }

    #[test]
    fn rejects_bad_version() {
        let mut b = sample().encode().unwrap();
        b[4] = 0x01;
        assert_eq!(Manifest::decode(&b), Err(ManifestError::BadVersion(0x01)));
    }

    #[test]
    fn rejects_truncation_at_every_prefix() {
        let full = sample().encode().unwrap();
        for cut in 0..full.len() {
            let err = Manifest::decode(&full[..cut])
                .expect_err("every strict prefix must fail");
            assert!(
                matches!(err, ManifestError::Truncated | ManifestError::BadMagic),
                "unexpected error at cut {cut}: {err:?}"
            );
        }
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut b = sample().encode().unwrap();
        b.push(0x00);
        assert_eq!(Manifest::decode(&b), Err(ManifestError::TrailingBytes));
    }

    #[test]
    fn encode_rejects_overlong_cid() {
        let m = Manifest {
            backup_set_id: [0; 32],
            sequence: 0,
            created_unix: 0,
            entries: vec![entry(b"p", 0, &vec![0u8; u8::MAX as usize + 1], 0)],
        };
        assert_eq!(m.encode(), Err(ManifestError::CidTooLong(u8::MAX as usize + 1)));
    }

    #[test]
    fn encode_rejects_overlong_path() {
        let m = Manifest {
            backup_set_id: [0; 32],
            sequence: 0,
            created_unix: 0,
            entries: vec![entry(&vec![b'a'; u16::MAX as usize + 1], 0, b"c", 0)],
        };
        assert_eq!(m.encode(), Err(ManifestError::PathTooLong(u16::MAX as usize + 1)));
    }

    #[test]
    fn adversarial_entry_count_does_not_panic_or_over_allocate() {
        // A huge entry_count with no backing bytes must fail as Truncated,
        // never panic and never try to allocate billions of entries.
        let mut b = Vec::new();
        b.extend_from_slice(&MANIFEST_MAGIC);
        b.push(MANIFEST_VERSION);
        b.extend_from_slice(&[0u8; 32]); // backup_set_id
        b.extend_from_slice(&0u64.to_le_bytes()); // sequence
        b.extend_from_slice(&0u64.to_le_bytes()); // created_unix
        b.extend_from_slice(&u32::MAX.to_le_bytes()); // entry_count = 4 billion
        // no entries follow
        assert_eq!(Manifest::decode(&b), Err(ManifestError::Truncated));
    }

    #[test]
    fn never_panics_on_random_ish_garbage() {
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        for len in 0..500usize {
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                buf.push(state as u8);
            }
            let _ = Manifest::decode(&buf); // must not panic
            // Also splice a valid magic in front so decode gets past the
            // magic check into the length-prefixed body with garbage lengths.
            let mut with_magic = Vec::with_capacity(len + 5);
            with_magic.extend_from_slice(&MANIFEST_MAGIC);
            with_magic.push(MANIFEST_VERSION);
            with_magic.extend_from_slice(&buf);
            let _ = Manifest::decode(&with_magic); // must not panic
        }
    }

    // ── canonical ordering: is_canonical / canonicalize ──────────────────────

    fn manifest_with(paths: &[&[u8]]) -> Manifest {
        Manifest {
            backup_set_id: [0x22; 32],
            sequence: 1,
            created_unix: 2,
            entries: paths.iter().map(|p| entry(p, 0, b"c", 0)).collect(),
        }
    }

    #[test]
    fn is_canonical_true_for_strictly_ascending_distinct_paths() {
        // Empty and singleton are trivially canonical.
        assert!(manifest_with(&[]).is_canonical());
        assert!(manifest_with(&[b"only"]).is_canonical());
        // Strictly ascending by raw path bytes.
        assert!(manifest_with(&[b"a", b"b", b"c"]).is_canonical());
        assert!(manifest_with(&[b"docs/a.txt", b"docs/b.txt", b"docs/c.txt"]).is_canonical());
        // Byte order, not length order: a prefix sorts before its extension.
        assert!(manifest_with(&[b"a", b"ab", b"b"]).is_canonical());
        // Zero byte is the lowest; ordering is over raw bytes.
        assert!(manifest_with(&[b"", b"\x00", b"\x00\x00", b"\x01"]).is_canonical());
    }

    #[test]
    fn is_canonical_false_for_out_of_order_paths() {
        assert!(!manifest_with(&[b"b", b"a"]).is_canonical());
        assert!(!manifest_with(&[b"a", b"c", b"b"]).is_canonical());
        // Descending — mirrors the `distinct_entry_fields_survive_round_trip`
        // fixture (zero > one-longer > c by first byte) which the codec still
        // round-trips but which is NOT canonical.
        assert!(!manifest_with(&[b"zero", b"one-longer", b"c"]).is_canonical());
        // A prefix must come first: "ab" before "a" is out of order.
        assert!(!manifest_with(&[b"ab", b"a"]).is_canonical());
    }

    #[test]
    fn is_canonical_false_for_duplicate_paths() {
        // Exact duplicate adjacent — not strictly ascending.
        assert!(!manifest_with(&[b"a", b"a"]).is_canonical());
        assert!(!manifest_with(&[b"a", b"b", b"b", b"c"]).is_canonical());
        // Duplicate path even when other fields differ is still not canonical.
        let m = Manifest {
            backup_set_id: [0; 32],
            sequence: 0,
            created_unix: 0,
            entries: vec![entry(b"dup", 1, b"x", 0x11), entry(b"dup", 999, b"y", 0x22)],
        };
        assert!(!m.is_canonical());
    }

    #[test]
    fn canonicalize_sorts_out_of_order_entries() {
        let mut m = manifest_with(&[b"c", b"a", b"b"]);
        assert!(!m.is_canonical());
        m.canonicalize().expect("distinct paths must canonicalize");
        assert!(m.is_canonical());
        let ordered: Vec<&[u8]> = m.entries.iter().map(|e| e.path.as_slice()).collect();
        assert_eq!(ordered, vec![b"a".as_slice(), b"b", b"c"]);
    }

    #[test]
    fn canonicalize_is_idempotent_and_preserves_entry_fields() {
        // Sorting must move whole entries, not just paths: pair each path with
        // a distinct file_len/shake so a field-shearing bug would surface.
        let mut m = Manifest {
            backup_set_id: [0x33; 32],
            sequence: 5,
            created_unix: 6,
            entries: vec![
                entry(b"gamma", 30, b"cg", 0x30),
                entry(b"alpha", 10, b"ca", 0x10),
                entry(b"beta", 20, b"cb", 0x20),
            ],
        };
        m.canonicalize().unwrap();
        assert_eq!(
            m.entries,
            vec![
                entry(b"alpha", 10, b"ca", 0x10),
                entry(b"beta", 20, b"cb", 0x20),
                entry(b"gamma", 30, b"cg", 0x30),
            ]
        );
        // Idempotent: a second pass leaves an already-canonical list unchanged.
        let mut again = m.clone();
        again.canonicalize().unwrap();
        assert_eq!(again, m);
    }

    #[test]
    fn canonicalize_rejects_exact_duplicate_paths() {
        let mut m = Manifest {
            backup_set_id: [0; 32],
            sequence: 0,
            created_unix: 0,
            // Same path, different other fields — must be rejected, not merged.
            entries: vec![
                entry(b"b", 1, b"c1", 0x01),
                entry(b"a", 2, b"c2", 0x02),
                entry(b"b", 3, b"c3", 0x03),
            ],
        };
        assert_eq!(m.canonicalize(), Err(ManifestError::DuplicatePath(b"b".to_vec())));
        // The offending duplicates are adjacent after the (attempted) sort, and
        // no entry was dropped — the caller still owns all three.
        assert_eq!(m.entries.len(), 3);
    }

    #[test]
    fn canonicalize_output_round_trips_byte_identically() {
        // The canonical-ordering work must not disturb the codec: a
        // canonicalized manifest still encodes and decodes byte-for-byte.
        let mut m = manifest_with(&[b"z", b"m", b"a", b"q"]);
        m.canonicalize().unwrap();
        assert!(m.is_canonical());
        let bytes = m.encode().unwrap();
        let decoded = Manifest::decode(&bytes).expect("valid manifest must decode");
        assert_eq!(decoded, m);
        assert!(decoded.is_canonical());
        assert_eq!(decoded.encode().unwrap(), bytes); // encode∘decode == identity
    }

    #[test]
    fn duplicate_path_error_displays() {
        let e = ManifestError::DuplicatePath(b"abc".to_vec());
        assert_eq!(e.to_string(), "pbm0 manifest: duplicate entry path (3 bytes)");
    }
}
