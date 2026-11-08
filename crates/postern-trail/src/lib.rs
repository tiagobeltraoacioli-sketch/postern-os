//! # postern-trail — the one shared, append-only, hash-chained audit trail.
//!
//! One JSONL file. Every line is one [`Record`]; each record commits to the
//! previous record's hash, so history can be *extended* but never silently
//! rewritten. This is the single authoritative implementation of the mechanism
//! that `yagabona` (the "glowing skull") and `ezekiel1` (the "rims full of
//! eyes") both used to carry as near-identical copies. Extracting it here means
//! the two chains **cannot drift** into incompatible canonical forms.
//!
//! The trail is generic over an app-specific content payload `C` (any
//! `Serialize + Deserialize` type that serializes to a JSON **object**). The
//! crate owns the envelope (`v`, `prev_hash`, `hash`) and the hashing; the app
//! owns the content fields.
//!
//! # Canonical form (pinned)
//!
//! The hash is taken over a **canonical JSON** encoding of everything in the
//! record *except* `hash` itself. The canonical form is deterministic and
//! reproducible on any machine (RFC 8785 / JCS in spirit):
//!
//! * object keys sorted lexicographically (recursively), via a [`BTreeMap`] so
//!   the ordering is independent of any serde_json feature flag (e.g.
//!   `preserve_order`, which the workspace could enable elsewhere);
//! * compact separators — `,` and `:`, no insignificant whitespace;
//! * scalars in serde_json's compact form; **timestamps are strings** and
//!   content SHOULD avoid floats, so there is no numeric-format ambiguity;
//! * the reserved envelope keys `v` and `prev_hash` are folded into the same
//!   object and participate in the preimage; `hash` is **excluded** from its
//!   own preimage.
//!
//! ```text
//! preimage = canonical_json({ <content fields…>, prev_hash, v })   // no `hash`
//! hash     = SHAKE-256( prev_hash_bytes ‖ preimage_bytes )         // 32 bytes, hex
//! ```
//!
//! `prev_hash_bytes` are the UTF-8 bytes of the `prev_hash` *string* (it also
//! appears inside the canonical JSON — this double commitment is intentional and
//! matches the original two implementations). The first record's `prev_hash` is
//! the literal [`GENESIS`]. [`Trail::append`] assigns it; [`verify_chain`]
//! recomputes every hash and every link, so any tampered line is detected.
//!
//! # Schema version
//!
//! Every record carries a `v` field pinned to [`SCHEMA_VERSION`], and `v` is
//! part of the preimage. Both original specs mandated a version tag and both had
//! dropped it; pinning it here means a future canonical-format change is
//! detectable rather than silently hash-incompatible.
//!
//! # Durability
//!
//! Each append is written and then `fsync`ed before the call returns, so a
//! recorded action is on stable storage before the caller proceeds.
//!
//! # Honesty
//!
//! This is **tamper-evident, not tamper-proof.** The owner of the file can
//! rewrite the entire trail and recompute every hash; nothing here prevents
//! that. What it guarantees is that a *partial* edit — changing one line and
//! leaving the rest — is caught by [`verify_chain`]. **UNAUDITED draft.**

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

/// The genesis marker used as the very first `prev_hash`.
pub const GENESIS: &str = "genesis";

/// The pinned canonical-form / schema version. Part of every preimage.
pub const SCHEMA_VERSION: u32 = 1;

/// Envelope keys the crate owns. App content **must not** use these names.
pub const RESERVED_KEYS: [&str; 3] = ["v", "prev_hash", "hash"];

/// One finalized trail record (one JSONL line): the app content `C`, inlined,
/// plus the envelope fields. `hash` is derived from everything else (see the
/// crate docs); it is excluded from its own preimage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record<C> {
    /// Canonical-form / schema version, pinned to [`SCHEMA_VERSION`]. In the
    /// preimage, so a format change is hash-detectable.
    pub v: u32,
    /// App-specific content, inlined into the JSON object (flattened).
    #[serde(flatten)]
    pub content: C,
    /// Hash of the previous record (or [`GENESIS`] for the first).
    pub prev_hash: String,
    /// SHAKE-256 hash committing to this record and the chain before it.
    pub hash: String,
}

/// Errors from opening, appending to, or verifying a chain.
///
/// Implemented by hand (no `thiserror`) to keep this crate's dependency set to
/// exactly `sha3` / `serde` / `serde_json`.
#[derive(Debug)]
pub enum ChainError {
    /// Underlying filesystem error.
    Io(std::io::Error),
    /// A line could not be parsed as JSON.
    Json {
        /// 1-based line number (`0` when the line is not yet known).
        line: usize,
        /// The underlying serde_json error.
        source: serde_json::Error,
    },
    /// A line's recorded hash did not match the recomputed one.
    HashMismatch {
        line: usize,
        recorded: String,
        recomputed: String,
    },
    /// A line's `prev_hash` did not match the previous line's hash.
    BrokenLink {
        line: usize,
        expected: String,
        found: String,
    },
    /// The verified chain's head hash did not match an externally-pinned
    /// expected head — the trail was **truncated or rolled back** to an earlier
    /// (still internally-valid) state. Only [`verify_chain_to_head`] raises this;
    /// plain [`verify_chain`] cannot see a dropped tail.
    HeadMismatch {
        /// The head the caller pinned out-of-band after the last append.
        expected: String,
        /// The head actually found at the end of the chain.
        found: String,
    },
    /// The content type did not serialize to a JSON object.
    ContentNotObject,
    /// App content serialized to an object using one of the reserved envelope
    /// keys ([`RESERVED_KEYS`]: `v`, `prev_hash`, `hash`). Rejected fail-closed
    /// so content can never silently overwrite or collide with the envelope the
    /// hash commits to.
    ContentUsesReservedKey {
        /// The offending reserved key found in the content.
        key: String,
    },
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainError::Io(e) => write!(f, "trail I/O error: {e}"),
            ChainError::Json { line, source } => {
                write!(f, "malformed JSON on line {line}: {source}")
            }
            ChainError::HashMismatch {
                line,
                recorded,
                recomputed,
            } => write!(
                f,
                "hash mismatch on line {line}: recorded {recorded}, recomputed {recomputed}"
            ),
            ChainError::BrokenLink {
                line,
                expected,
                found,
            } => write!(
                f,
                "broken link on line {line}: prev_hash {found:?} does not match previous hash {expected:?}"
            ),
            ChainError::HeadMismatch { expected, found } => write!(
                f,
                "head mismatch: chain ends at {found:?} but pinned head is {expected:?} (truncated or rolled back)"
            ),
            ChainError::ContentNotObject => {
                write!(f, "trail content must serialize to a JSON object")
            }
            ChainError::ContentUsesReservedKey { key } => write!(
                f,
                "trail content uses reserved envelope key {key:?} (reserved: v, prev_hash, hash)"
            ),
        }
    }
}

impl std::error::Error for ChainError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ChainError::Io(e) => Some(e),
            ChainError::Json { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ChainError {
    fn from(e: std::io::Error) -> Self {
        ChainError::Io(e)
    }
}

/// An append-only, hash-chained trail writer bound to a file path, generic over
/// the app content type `C`.
#[derive(Debug)]
pub struct Trail<C> {
    path: PathBuf,
    last_hash: String,
    _content: PhantomData<fn() -> C>,
}

impl<C> Trail<C>
where
    C: Serialize + DeserializeOwned,
{
    /// Open (creating on first append) the trail at `path`. If the file already
    /// has records, the chain resumes from the last line's hash; otherwise the
    /// next append links to [`GENESIS`].
    pub fn open(path: impl AsRef<Path>) -> Result<Trail<C>, ChainError> {
        let path = path.as_ref().to_path_buf();
        let last_hash = match File::open(&path) {
            Ok(f) => {
                let mut last = GENESIS.to_string();
                for line in BufReader::new(f).lines() {
                    let line = line?;
                    if line.trim().is_empty() {
                        continue;
                    }
                    let record: Record<C> = serde_json::from_str(&line)
                        .map_err(|source| ChainError::Json { line: 0, source })?;
                    last = record.hash;
                }
                last
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => GENESIS.to_string(),
            Err(e) => return Err(e.into()),
        };
        Ok(Trail {
            path,
            last_hash,
            _content: PhantomData,
        })
    }

    /// The hash the next appended record will link to.
    pub fn head(&self) -> &str {
        &self.last_hash
    }

    /// Append `content` to the trail, computing its hash over the current head,
    /// then `fsync` before returning the finalized [`Record`].
    pub fn append(&mut self, content: C) -> Result<Record<C>, ChainError> {
        let prev_hash = self.last_hash.clone();
        let canon = canonical_preimage(&content, &prev_hash)?;
        let hash = chain_hash(&prev_hash, &canon);

        let record = Record {
            v: SCHEMA_VERSION,
            content,
            prev_hash,
            hash,
        };

        let line = serde_json::to_string(&record)
            .map_err(|source| ChainError::Json { line: 0, source })?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")?;
        file.flush()?;
        file.sync_all()?; // fsync: the record is durable before we proceed.

        self.last_hash = record.hash.clone();
        Ok(record)
    }
}

/// Build the canonical-JSON **preimage** for a record's content: the content
/// object with the envelope keys `v` and `prev_hash` folded in and `hash`
/// excluded, encoded in the pinned canonical form.
fn canonical_preimage<C: Serialize>(content: &C, prev_hash: &str) -> Result<String, ChainError> {
    let mut value =
        serde_json::to_value(content).map_err(|source| ChainError::Json { line: 0, source })?;
    let obj = value.as_object_mut().ok_or(ChainError::ContentNotObject)?;
    // Enforce the documented contract *before* folding the envelope in: content
    // must not carry a reserved key, or a `flatten`ed field would silently be
    // overwritten (v, prev_hash) or dropped (hash) here and desync the stored
    // line from its own preimage. Fail closed instead.
    for key in RESERVED_KEYS {
        if obj.contains_key(key) {
            return Err(ChainError::ContentUsesReservedKey {
                key: key.to_string(),
            });
        }
    }
    // Envelope fields that participate in the preimage.
    obj.insert("v".to_string(), Value::from(SCHEMA_VERSION));
    obj.insert("prev_hash".to_string(), Value::String(prev_hash.to_string()));
    // `hash` is EXCLUDED from its own preimage (defensive: content shouldn't set it).
    obj.remove("hash");
    Ok(to_canonical_json(&value))
}

/// Encode a [`Value`] in the pinned canonical form: recursively sorted object
/// keys (via [`BTreeMap`], feature-flag independent), compact separators.
fn to_canonical_json(value: &Value) -> String {
    let mut buf = String::new();
    write_canonical(&mut buf, value);
    buf
}

fn write_canonical(buf: &mut String, value: &Value) {
    match value {
        Value::Object(map) => {
            // BTreeMap gives a fixed, sorted key order regardless of whether the
            // `preserve_order` serde_json feature is enabled anywhere else.
            let sorted: BTreeMap<&String, &Value> = map.iter().collect();
            buf.push('{');
            for (i, (k, v)) in sorted.iter().enumerate() {
                if i > 0 {
                    buf.push(',');
                }
                write_json_string(buf, k);
                buf.push(':');
                write_canonical(buf, v);
            }
            buf.push('}');
        }
        Value::Array(arr) => {
            buf.push('[');
            for (i, v) in arr.iter().enumerate() {
                if i > 0 {
                    buf.push(',');
                }
                write_canonical(buf, v);
            }
            buf.push(']');
        }
        // Scalars: serde_json's compact encoding is already canonical.
        scalar => buf.push_str(&serde_json::to_string(scalar).expect("scalar serializes")),
    }
}

fn write_json_string(buf: &mut String, s: &str) {
    buf.push_str(&serde_json::to_string(s).expect("string serializes"));
}

/// `hash = SHAKE-256(prev_hash_bytes ‖ canonical_json_bytes)`, 32 bytes, hex.
fn chain_hash(prev_hash: &str, canonical_json: &str) -> String {
    let mut hasher = Shake256::default();
    hasher.update(prev_hash.as_bytes());
    hasher.update(canonical_json.as_bytes());
    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; 32];
    reader.read(&mut out);
    to_hex(&out)
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Recompute every hash and every link in the trail at `path`. Returns the
/// number of records verified, or the first [`ChainError`] found.
///
/// This is **content-type agnostic**: it reads each line as a generic JSON
/// object, strips `hash`, and canonicalizes the remainder — exactly the preimage
/// [`Trail::append`] built — so both crates share one verifier. A missing file is
/// treated as an empty (valid) chain of length 0.
pub fn verify_chain(path: impl AsRef<Path>) -> Result<usize, ChainError> {
    Ok(verify_chain_inner(path)?.0)
}

/// Verify the chain **and** require its final record's hash to equal
/// `expected_head`. This closes the gap [`verify_chain`] structurally cannot:
/// a chain whose tail has been **truncated** (or rolled back to an earlier
/// state) is itself a perfectly valid, internally-consistent shorter chain and
/// passes [`verify_chain`] silently. Pinning the head out-of-band — persist the
/// value of [`Trail::head`] after each append, e.g. to a separate store — turns
/// that silent truncation into [`ChainError::HeadMismatch`].
///
/// An empty (or missing) chain's head is [`GENESIS`]; pass that to assert the
/// trail is legitimately empty. Returns the number of records verified.
pub fn verify_chain_to_head(
    path: impl AsRef<Path>,
    expected_head: &str,
) -> Result<usize, ChainError> {
    let (count, head) = verify_chain_inner(path)?;
    if head != expected_head {
        return Err(ChainError::HeadMismatch {
            expected: expected_head.to_string(),
            found: head,
        });
    }
    Ok(count)
}

/// Shared verifier: recompute every hash and link, returning `(records_verified,
/// final_head)`. `final_head` is the last record's hash, or [`GENESIS`] for an
/// empty/missing chain.
fn verify_chain_inner(path: impl AsRef<Path>) -> Result<(usize, String), ChainError> {
    let file = match File::open(path.as_ref()) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((0, GENESIS.to_string())),
        Err(e) => return Err(e.into()),
    };

    let mut expected_prev = GENESIS.to_string();
    let mut count = 0usize;
    for (idx, line) in BufReader::new(file).lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let line_no = idx + 1;
        let mut value: Value = serde_json::from_str(&line)
            .map_err(|source| ChainError::Json { line: line_no, source })?;

        let (recorded, prev) = {
            let obj = value.as_object_mut().ok_or(ChainError::ContentNotObject)?;
            let recorded = obj
                .get("hash")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let prev = obj
                .get("prev_hash")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            obj.remove("hash"); // exclude the hash from its own preimage
            (recorded, prev)
        };

        if prev != expected_prev {
            return Err(ChainError::BrokenLink {
                line: line_no,
                expected: expected_prev,
                found: prev,
            });
        }

        let canon = to_canonical_json(&value);
        let recomputed = chain_hash(&prev, &canon);
        if recomputed != recorded {
            return Err(ChainError::HashMismatch {
                line: line_no,
                recorded,
                recomputed,
            });
        }

        expected_prev = recorded;
        count += 1;
    }
    // After the loop, `expected_prev` is the last record's hash — the head
    // (still GENESIS if the chain was empty).
    Ok((count, expected_prev))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in app content payload (strings + a string array, like the real
    /// yagabona/ezekiel1 content).
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct TestContent {
        ts: String,
        msg: String,
        tags: Vec<String>,
    }

    fn content(msg: &str) -> TestContent {
        TestContent {
            ts: "2026-07-11T02:30:00Z".to_string(),
            msg: msg.to_string(),
            tags: vec!["a".to_string(), "b".to_string()],
        }
    }

    #[test]
    fn canonical_json_is_byte_stable_sorted_and_includes_schema_version() {
        let canon = canonical_preimage(&content("hello"), GENESIS).unwrap();
        // Keys sorted lexicographically; compact separators; `v` present and the
        // per-record `hash` absent from its own preimage.
        assert_eq!(
            canon,
            r#"{"msg":"hello","prev_hash":"genesis","tags":["a","b"],"ts":"2026-07-11T02:30:00Z","v":1}"#
        );
        assert!(canon.contains(r#""v":1"#), "schema_version in the preimage");
        assert!(!canon.contains(r#""hash""#), "hash excluded from its preimage");
    }

    #[test]
    fn canonical_json_is_key_order_independent() {
        // Same logical object, keys inserted in two different orders, must encode
        // to identical canonical bytes.
        let mut a = serde_json::Map::new();
        a.insert("b".into(), Value::from(2));
        a.insert("a".into(), Value::from(1));
        a.insert("m".into(), Value::from(vec![3, 1, 2]));
        let mut b = serde_json::Map::new();
        b.insert("m".into(), Value::from(vec![3, 1, 2]));
        b.insert("a".into(), Value::from(1));
        b.insert("b".into(), Value::from(2));
        assert_eq!(
            to_canonical_json(&Value::Object(a)),
            to_canonical_json(&Value::Object(b))
        );
    }

    #[test]
    fn schema_version_participates_in_the_hash() {
        // Same content + prev_hash, different `v`, must yield a different hash —
        // proof the version tag is really in the preimage.
        let c = content("x");
        let mut value = serde_json::to_value(&c).unwrap();
        let obj = value.as_object_mut().unwrap();
        obj.insert("prev_hash".into(), Value::String(GENESIS.into()));
        obj.insert("v".into(), Value::from(SCHEMA_VERSION));
        let canon_v1 = to_canonical_json(&value);

        value.as_object_mut().unwrap().insert("v".into(), Value::from(SCHEMA_VERSION + 1));
        let canon_v2 = to_canonical_json(&value);

        assert_ne!(
            chain_hash(GENESIS, &canon_v1),
            chain_hash(GENESIS, &canon_v2)
        );
    }

    #[test]
    fn genesis_anchor_and_chain_links() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.jsonl");
        let mut trail: Trail<TestContent> = Trail::open(&path).unwrap();
        assert_eq!(trail.head(), GENESIS);

        let first = trail.append(content("one")).unwrap();
        assert_eq!(first.prev_hash, GENESIS);
        assert_eq!(first.hash.len(), 64); // 32 bytes -> 64 hex chars
        assert_eq!(first.v, SCHEMA_VERSION);

        let second = trail.append(content("two")).unwrap();
        assert_eq!(second.prev_hash, first.hash);
    }

    #[test]
    fn clean_chain_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.jsonl");
        let mut trail: Trail<TestContent> = Trail::open(&path).unwrap();
        for i in 0..3 {
            trail.append(content(&format!("m{i}"))).unwrap();
        }
        assert_eq!(verify_chain(&path).unwrap(), 3);
    }

    #[test]
    fn tampered_middle_line_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.jsonl");
        let mut trail: Trail<TestContent> = Trail::open(&path).unwrap();
        for i in 0..3 {
            trail.append(content(&format!("m{i}"))).unwrap();
        }

        // Rewrite the middle record's payload, leaving its hash untouched.
        let original = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = original.lines().map(str::to_string).collect();
        lines[1] = lines[1].replace(r#""msg":"m1""#, r#""msg":"HACKED""#);
        assert!(lines[1].contains("HACKED"), "tamper edit applied");
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let err = verify_chain(&path).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("hash mismatch") || msg.contains("broken link"),
            "expected tamper detection, got: {msg}"
        );
    }

    #[test]
    fn same_content_hashes_identically_across_independent_trails() {
        // The core guarantee of the extraction: two independent Trail instances
        // fed the SAME content from genesis produce the SAME hash bytes.
        let dir = tempfile::tempdir().unwrap();
        let mut a: Trail<TestContent> = Trail::open(dir.path().join("a.jsonl")).unwrap();
        let mut b: Trail<TestContent> = Trail::open(dir.path().join("b.jsonl")).unwrap();
        let ra = a.append(content("same")).unwrap();
        let rb = b.append(content("same")).unwrap();
        assert_eq!(ra.hash, rb.hash);
        assert_eq!(ra.prev_hash, GENESIS);
        assert_eq!(rb.prev_hash, GENESIS);
    }

    #[test]
    fn missing_file_is_an_empty_valid_chain() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(verify_chain(dir.path().join("nope.jsonl")).unwrap(), 0);
    }

    /// Content whose object carries a reserved envelope key.
    #[derive(Debug, Serialize, Deserialize)]
    struct ReservedContent {
        v: u32, // collides with the envelope's schema-version field
        msg: String,
    }

    #[test]
    fn content_using_a_reserved_key_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.jsonl");
        let mut trail: Trail<ReservedContent> = Trail::open(&path).unwrap();
        let err = trail
            .append(ReservedContent {
                v: 99,
                msg: "x".into(),
            })
            .unwrap_err();
        assert!(
            matches!(err, ChainError::ContentUsesReservedKey { ref key } if key == "v"),
            "expected reserved-key rejection, got: {err}"
        );
        // Fail-closed: nothing was written, the chain is still empty.
        assert_eq!(verify_chain(&path).unwrap(), 0);
    }

    #[test]
    fn verify_to_head_accepts_the_true_head_and_empty_genesis() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.jsonl");
        // Empty chain's head is GENESIS.
        assert_eq!(verify_chain_to_head(&path, GENESIS).unwrap(), 0);

        let mut trail: Trail<TestContent> = Trail::open(&path).unwrap();
        let mut head = GENESIS.to_string();
        for i in 0..3 {
            head = trail.append(content(&format!("m{i}"))).unwrap().hash;
        }
        // The pinned head (what Trail::head would report) verifies.
        assert_eq!(trail.head(), head);
        assert_eq!(verify_chain_to_head(&path, &head).unwrap(), 3);
    }

    #[test]
    fn truncated_tail_passes_plain_verify_but_head_check_catches_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.jsonl");
        let mut trail: Trail<TestContent> = Trail::open(&path).unwrap();
        let mut heads = vec![GENESIS.to_string()];
        for i in 0..4 {
            heads.push(trail.append(content(&format!("m{i}"))).unwrap().hash);
        }
        let true_head = heads.last().unwrap().clone();

        // Drop the last two lines: a still-valid, shorter chain.
        let original = std::fs::read_to_string(&path).unwrap();
        let kept: Vec<&str> = original.lines().take(2).collect();
        std::fs::write(&path, kept.join("\n") + "\n").unwrap();

        // Plain verify is fooled — the truncated chain is internally consistent.
        assert_eq!(
            verify_chain(&path).unwrap(),
            2,
            "truncated chain still verifies structurally"
        );
        // Pinning the real head catches the dropped tail.
        let err = verify_chain_to_head(&path, &true_head).unwrap_err();
        assert!(
            matches!(err, ChainError::HeadMismatch { .. }),
            "expected HeadMismatch on truncation, got: {err}"
        );
        assert!(err.to_string().contains("truncated or rolled back"));
    }
}
