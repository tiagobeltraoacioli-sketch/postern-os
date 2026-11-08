//! The office session: a document sealed at rest, opened into a **secured
//! plaintext scratch** for editing, with a **panic-lock eviction** that
//! collapses the plaintext window on demand.
//!
//! ## State machine
//!
//! ```text
//!            open(key) / create(key,initial)
//!   Locked  ───────────────────────────────▶  Unlocked { Zeroizing<key>, ScratchGuard }
//!     ▲                                              │
//!     └────────────────  panic()  ───────────────────┘
//!         (secure-delete scratch, zeroize+drop key)
//! ```
//!
//! - **Unlocked**: the 32-byte key is held in `Zeroizing<[u8; 32]>` and the
//!   plaintext lives in a [`ScratchGuard`]-owned file. **This is the
//!   plaintext-while-editing window** — labelled, minimized, never denied.
//! - **Locked**: no key, no scratch — only the at-rest ciphertext file remains.
//!
//! The at-rest file at `sealed_path` is **always v2 ciphertext** (leading byte
//! `0x02`, produced by [`postern_core::aead::seal_with_context`]); [`panic`]
//! never touches it, so a panic can never destroy or corrupt the document.
//!
//! [`panic`]: OfficeSession::panic

use std::fs;
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use postern_core::aead;
use zeroize::Zeroizing;

/// Context string binding office documents to this product/format (see
/// [`postern_core::aead::seal_with_context`]): a blob sealed by another Postern
/// product under the same 32-byte key can NOT be opened as an office document,
/// and vice versa.
pub const OFFICE_CONTEXT: &[u8] = b"postern-office/v1";

#[derive(Debug, thiserror::Error)]
pub enum OfficeError {
    /// The seal did not open — wrong key, wrong context, or a tampered /
    /// truncated at-rest file. (The underlying AEAD is fail-closed.)
    #[error("open failed — wrong key or corrupt document")]
    Open,
    /// Sealing the document failed. The at-rest file is left unchanged.
    #[error("seal failed")]
    Seal,
    /// A filesystem operation failed (staging, secure-delete, read-back, …).
    #[error("i/o error: {0}")]
    Io(String),
    /// The operation requires an unlocked session, but the session is locked.
    #[error("session is locked — reopen with the key")]
    Locked,
    /// The injected editor seam returned an error (mirrors the
    /// `String`-error shape of `postern_quarantine`'s converter seam).
    #[error("editor failed: {0}")]
    Editor(String),
}

impl From<io::Error> for OfficeError {
    fn from(e: io::Error) -> Self {
        OfficeError::Io(e.to_string())
    }
}

/// Monotonic per-process counter so two sessions opened in the same nanosecond
/// still get distinct scratch filenames.
static SCRATCH_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Owner of the on-disk **plaintext editing scratch**. This is the concrete
/// plaintext-while-editing window: while the guard is `active`, a plaintext
/// copy of the document exists on the filesystem in the clear.
///
/// **Honest limits of the secure-delete.** [`secure_delete`](ScratchGuard::secure_delete)
/// overwrites the file's bytes (three passes) and syncs before unlinking. On a
/// classic overwrite-in-place filesystem this reduces recoverability, but it is
/// **best-effort, not a guarantee**: on SSDs (wear-levelling / TRIM),
/// copy-on-write filesystems (APFS, Btrfs, ZFS), and journaled filesystems the
/// original bytes may persist in blocks the overwrite never reaches. The real
/// mitigation is to put `scratch_dir` on **tmpfs / a no-swap RAM-backed
/// directory** so the plaintext never hits stable storage at all; the overwrite
/// is defense-in-depth on top of that, not a substitute.
pub struct ScratchGuard {
    path: PathBuf,
    active: bool,
}

impl ScratchGuard {
    /// Materialize a fresh scratch file in `dir` holding `plaintext`. The file
    /// is created with `create_new` (never clobbers) and, on Unix, mode `0600`.
    fn materialize(dir: &Path, plaintext: &[u8]) -> io::Result<ScratchGuard> {
        fs::create_dir_all(dir)?;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let seq = SCRATCH_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = dir.join(format!(
            "postern-office-scratch-{}-{nanos}-{seq}",
            std::process::id()
        ));

        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&path)?;
        f.write_all(plaintext)?;
        f.sync_all()?;
        Ok(ScratchGuard { path, active: true })
    }

    /// Path of the scratch file (whether or not it currently exists).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether the scratch is still live (created, not yet secure-deleted).
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Read the current plaintext back out of the scratch.
    fn read(&self) -> io::Result<Vec<u8>> {
        fs::read(&self.path)
    }

    /// Replace the scratch contents (an in-place edit). Truncates then rewrites;
    /// the guaranteed collapse of the plaintext window is [`secure_delete`], not
    /// this rewrite.
    ///
    /// [`secure_delete`]: ScratchGuard::secure_delete
    fn overwrite(&self, plaintext: &[u8]) -> io::Result<()> {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&self.path)?;
        f.write_all(plaintext)?;
        f.sync_all()?;
        Ok(())
    }

    /// Secure-delete the scratch: overwrite its bytes (three passes:
    /// `0x00`, `0xFF`, `0x00`), sync each pass, then unlink. Idempotent — a
    /// second call after the first is a no-op. See the type docs for the honest
    /// best-effort caveat (SSD / CoW / journaled filesystems).
    pub fn secure_delete(&mut self) -> io::Result<()> {
        if !self.active {
            return Ok(());
        }
        // Mark inactive up-front so a later Drop never double-runs even if a
        // step below errors partway through.
        self.active = false;

        let len = match fs::metadata(&self.path) {
            Ok(m) => m.len(),
            // Already gone — nothing to scrub.
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };

        {
            let mut f = fs::OpenOptions::new().write(true).open(&self.path)?;
            for pass in [0x00u8, 0xFFu8, 0x00u8] {
                f.seek(SeekFrom::Start(0))?;
                let chunk = [pass; 8192];
                let mut remaining = len;
                while remaining > 0 {
                    let n = remaining.min(chunk.len() as u64) as usize;
                    f.write_all(&chunk[..n])?;
                    remaining -= n as u64;
                }
                f.flush()?;
                f.sync_all()?;
            }
        }
        fs::remove_file(&self.path)?;
        Ok(())
    }
}

impl Drop for ScratchGuard {
    fn drop(&mut self) {
        // Best-effort: no plaintext scratch should outlive the guard, even on an
        // early `?`/panic-unwind teardown path.
        let _ = self.secure_delete();
    }
}

/// Session state: either unlocked (key in RAM + plaintext scratch on disk) or
/// locked (only the at-rest ciphertext remains).
enum State {
    Unlocked {
        key: Zeroizing<[u8; 32]>,
        scratch: ScratchGuard,
    },
    Locked,
}

/// A single office document, sealed at rest, guarded by a panic-lock eviction.
///
/// Holds the 32-byte session key in `Zeroizing<[u8; 32]>` and the active
/// [`ScratchGuard`] while unlocked. See the module docs for the state machine
/// and the plaintext-while-editing honesty.
pub struct OfficeSession {
    /// The durable file — **always v2 ciphertext**. Never written by [`panic`].
    ///
    /// [`panic`]: OfficeSession::panic
    sealed_path: PathBuf,
    /// Where a plaintext scratch is materialized on open (put this on tmpfs).
    scratch_dir: PathBuf,
    state: State,
}

impl OfficeSession {
    /// Seal `initial` plaintext to a **new** at-rest file at `sealed_path`, then
    /// open it — leaving the session unlocked with a plaintext scratch. The
    /// caller's `key` copy is wiped before returning.
    pub fn create(
        sealed_path: impl Into<PathBuf>,
        scratch_dir: impl Into<PathBuf>,
        key: [u8; 32],
        initial: &[u8],
    ) -> Result<Self, OfficeError> {
        let sealed_path = sealed_path.into();
        let scratch_dir = scratch_dir.into();
        let mut key = Zeroizing::new(key);

        let sealed = aead::seal_with_context(&key, OFFICE_CONTEXT, initial)
            .map_err(|_| OfficeError::Seal)?;
        if let Some(parent) = sealed_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        fs::write(&sealed_path, &sealed)?;

        let scratch = ScratchGuard::materialize(&scratch_dir, initial)?;
        let session = OfficeSession {
            sealed_path,
            scratch_dir,
            state: State::Unlocked {
                key: std::mem::replace(&mut key, Zeroizing::new([0u8; 32])),
                scratch,
            },
        };
        Ok(session)
    }

    /// Open the at-rest ciphertext at `sealed_path` under `key`, decrypting it
    /// into a fresh plaintext scratch in `scratch_dir`. Wrong key / corrupt file
    /// → [`OfficeError::Open`] (nothing is written). The caller's `key` copy is
    /// wiped before returning on every path.
    pub fn open(
        sealed_path: impl Into<PathBuf>,
        scratch_dir: impl Into<PathBuf>,
        key: [u8; 32],
    ) -> Result<Self, OfficeError> {
        let mut session = OfficeSession {
            sealed_path: sealed_path.into(),
            scratch_dir: scratch_dir.into(),
            state: State::Locked,
        };
        session.unlock(key)?;
        Ok(session)
    }

    /// Reopen a **locked** session: read the at-rest ciphertext, open it under
    /// `key`, and materialize a new plaintext scratch. No-op if already
    /// unlocked. Wrong key → [`OfficeError::Open`], session stays locked. The
    /// caller's `key` copy is wiped on every path.
    ///
    /// This is what makes "a subsequent open requires the key again" true: after
    /// [`panic`](OfficeSession::panic) the key is gone, so nothing short of the
    /// real key re-materializes any plaintext.
    pub fn unlock(&mut self, key: [u8; 32]) -> Result<(), OfficeError> {
        let mut key = Zeroizing::new(key);
        if matches!(self.state, State::Unlocked { .. }) {
            return Ok(()); // key wiped on drop
        }

        let sealed = fs::read(&self.sealed_path)?;
        let plaintext = aead::open_with_context(&key, OFFICE_CONTEXT, &sealed)
            .map_err(|_| OfficeError::Open)?;
        // Keep the plaintext in a zeroizing buffer until it is on the scratch.
        let plaintext = Zeroizing::new(plaintext);

        let scratch = ScratchGuard::materialize(&self.scratch_dir, &plaintext)?;
        self.state = State::Unlocked {
            key: std::mem::replace(&mut key, Zeroizing::new([0u8; 32])),
            scratch,
        };
        Ok(())
    }

    /// Whether the session is currently locked. NOTE: this observability is
    /// exactly why the panic lock is **not deniable** — anyone holding the
    /// device can see a locked document exists (same caveat as `postern_panic`).
    pub fn is_locked(&self) -> bool {
        matches!(self.state, State::Locked)
    }

    /// The at-rest ciphertext path (always v2 ciphertext on disk).
    pub fn sealed_path(&self) -> &Path {
        &self.sealed_path
    }

    /// The active plaintext scratch path, or `None` while locked. Callers can
    /// hand this to the (injected) editor as the file to open.
    pub fn scratch_path(&self) -> Option<&Path> {
        match &self.state {
            State::Unlocked { scratch, .. } => Some(scratch.path()),
            State::Locked => None,
        }
    }

    /// Read the current plaintext out of the scratch (unlocked only). This is a
    /// convenience for tests and for callers driving the editor seam in-process;
    /// it exposes plaintext by construction (the editing window).
    pub fn read_plaintext(&self) -> Result<Vec<u8>, OfficeError> {
        match &self.state {
            State::Unlocked { scratch, .. } => Ok(scratch.read()?),
            State::Locked => Err(OfficeError::Locked),
        }
    }

    /// Run the **injected editor seam** over the current plaintext and persist
    /// the result.
    ///
    /// `editor` mirrors `postern_quarantine`'s converter seam exactly —
    /// `FnOnce(&[u8]) -> Result<Vec<u8>, String>` — so the real out-of-process
    /// `soffice` editor (`editor.rs`, feature `soffice-live`) and a `MockEditor`
    /// are drop-in interchangeable. The flow is: read scratch plaintext → hand
    /// it to `editor` → write the edited plaintext back to the scratch →
    /// **re-seal it to the at-rest file** so the durable ciphertext tracks the
    /// edit. The plaintext-while-editing window is open for exactly this call's
    /// duration plus however long the scratch then lives.
    pub fn edit<F>(&mut self, editor: F) -> Result<(), OfficeError>
    where
        F: FnOnce(&[u8]) -> Result<Vec<u8>, String>,
    {
        let (key, scratch) = match &mut self.state {
            State::Unlocked { key, scratch } => (key, scratch),
            State::Locked => return Err(OfficeError::Locked),
        };

        let current = scratch.read()?;
        let edited = Zeroizing::new(editor(&current).map_err(OfficeError::Editor)?);
        scratch.overwrite(&edited)?;

        // Re-seal the edit to the durable store so at rest stays current
        // ciphertext. Seal to a temp sibling then rename so a crash never leaves
        // a half-written at-rest file.
        let sealed = aead::seal_with_context(key, OFFICE_CONTEXT, &edited)
            .map_err(|_| OfficeError::Seal)?;
        write_atomic(&self.sealed_path, &sealed)?;
        Ok(())
    }

    /// **PANIC.** Collapse the plaintext window on demand:
    ///
    /// 1. **secure-delete the scratch** (overwrite passes + unlink), and
    /// 2. **drop + zeroize the key** (the `Zeroizing<[u8; 32]>` is wiped as the
    ///    `Unlocked` state is replaced), leaving the session `Locked`.
    ///
    /// The at-rest file is **never touched** — it stays v2 ciphertext, so panic
    /// destroys nothing. A subsequent [`unlock`](OfficeSession::unlock) /
    /// [`open`](OfficeSession::open) requires the real key again. Idempotent (a
    /// second panic is a no-op).
    ///
    /// **Labelled per `postern-panic`:** this is a **denial-of-access re-lock**,
    /// NOT a duress or deniable feature — [`is_locked`](OfficeSession::is_locked)
    /// is observable and there is no decoy.
    ///
    /// The key is evicted on **every** path: even if the secure-delete of the
    /// scratch hits an I/O error, the session still transitions to `Locked`
    /// (zeroizing the key) and the error is returned afterward.
    pub fn panic(&mut self) -> Result<(), OfficeError> {
        let delete_result = match &mut self.state {
            State::Unlocked { scratch, .. } => scratch.secure_delete(),
            State::Locked => return Ok(()),
        };
        // Always evict: replacing the Unlocked state drops the Zeroizing key
        // (wiped) and the (already-deleted) ScratchGuard.
        self.state = State::Locked;
        delete_result.map_err(|e| OfficeError::Io(e.to_string()))
    }
}

// The key lives in `Zeroizing<[u8; 32]>` (wiped on drop) and the scratch is
// owned by a `ScratchGuard` (secure-deleted on drop), so a plain session
// teardown covers both without a manual `Drop` on `OfficeSession`.

/// Write `bytes` to `path` via a temp sibling + rename, so a crash mid-write
/// never leaves a truncated at-rest ciphertext file.
fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp-postern-office");
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unique temp dir for one test, removed on drop.
    struct TmpDir(PathBuf);
    impl TmpDir {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let seq = SCRATCH_COUNTER.fetch_add(1, Ordering::Relaxed);
            let p = std::env::temp_dir().join(format!(
                "postern-office-test-{tag}-{}-{nanos}-{seq}",
                std::process::id()
            ));
            fs::create_dir_all(&p).unwrap();
            TmpDir(p)
        }
        fn join(&self, n: &str) -> PathBuf {
            self.0.join(n)
        }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    const KEY: [u8; 32] = [7u8; 32];
    const DOC: &[u8] = b"chancery draft: quarterly report, CONFIDENTIAL";

    fn is_v2_ciphertext(bytes: &[u8]) -> bool {
        // v2 wire format: 0x02 ‖ nonce(24) ‖ commit(32) ‖ ct(>=tag)
        !bytes.is_empty()
            && bytes[0] == postern_core::aead::VERSION_V2
            && bytes.len() >= 1 + 24 + 32 + 16
    }

    // ---- ACCEPTANCE: the full panic-lock eviction round-trip --------------
    #[test]
    fn panic_evicts_scratch_and_key_but_leaves_at_rest_ciphertext() {
        let dir = TmpDir::new("acceptance");
        let sealed = dir.join("doc.psx");
        let scratch_dir = dir.join("scratch");

        // 1. Session opens: plaintext scratch present.
        let mut s = OfficeSession::create(&sealed, &scratch_dir, KEY, DOC).unwrap();
        assert!(!s.is_locked());
        let scratch_path = s.scratch_path().unwrap().to_path_buf();
        assert!(scratch_path.exists(), "plaintext scratch must exist while unlocked");
        assert_eq!(
            fs::read(&scratch_path).unwrap(),
            DOC,
            "scratch holds the plaintext (the editing window)"
        );
        // At rest is ciphertext even before any panic.
        let sealed_before = fs::read(&sealed).unwrap();
        assert!(is_v2_ciphertext(&sealed_before), "at-rest file is v2 ciphertext");
        assert_ne!(sealed_before, DOC);

        // 2. panic(): secure-deletes scratch, drops/zeroizes key, is_locked==true.
        s.panic().unwrap();
        assert!(s.is_locked(), "panic re-locks (denial of access)");
        assert!(!scratch_path.exists(), "panic secure-deleted the plaintext scratch");
        assert!(s.scratch_path().is_none(), "no scratch reachable while locked");
        assert!(s.read_plaintext().is_err(), "no plaintext reachable while locked");

        // 3. The on-disk file is STILL v2 ciphertext, byte-identical (untouched).
        let sealed_after = fs::read(&sealed).unwrap();
        assert!(is_v2_ciphertext(&sealed_after), "still v2 ciphertext after panic");
        assert_eq!(sealed_before, sealed_after, "panic never touches the at-rest file");

        // 4. A subsequent open requires the key again.
        assert!(s.unlock([0u8; 32]).is_err(), "wrong key cannot reopen");
        assert!(s.is_locked(), "still locked after a bad key");
        s.unlock(KEY).unwrap();
        assert!(!s.is_locked());
        assert_eq!(
            fs::read(s.scratch_path().unwrap()).unwrap(),
            DOC,
            "correct key re-materializes the intact plaintext — nothing was destroyed"
        );
    }

    #[test]
    fn panic_is_idempotent() {
        let dir = TmpDir::new("idem");
        let mut s = OfficeSession::create(dir.join("d"), dir.join("s"), KEY, DOC).unwrap();
        s.panic().unwrap();
        s.panic().unwrap(); // no-op, no error
        assert!(s.is_locked());
    }

    #[test]
    fn open_from_disk_requires_the_key() {
        let dir = TmpDir::new("open");
        let sealed = dir.join("d");
        let scratch_dir = dir.join("s");
        // Seal a document, then drop the session entirely.
        {
            let s = OfficeSession::create(&sealed, &scratch_dir, KEY, DOC).unwrap();
            drop(s);
        }
        // Wrong key fails; right key opens.
        assert!(OfficeSession::open(&sealed, &scratch_dir, [9u8; 32]).is_err());
        let s = OfficeSession::open(&sealed, &scratch_dir, KEY).unwrap();
        assert_eq!(fs::read(s.scratch_path().unwrap()).unwrap(), DOC);
    }

    #[test]
    fn edit_reseals_at_rest_and_stays_ciphertext() {
        let dir = TmpDir::new("edit");
        let sealed = dir.join("d");
        let mut s =
            OfficeSession::create(&sealed, dir.join("s"), KEY, b"before").unwrap();

        // Injected mock editor (mirrors the soffice converter seam shape).
        s.edit(|plaintext| {
            let mut out = plaintext.to_vec();
            out.extend_from_slice(b" + edited");
            Ok(out)
        })
        .unwrap();

        // Scratch reflects the edit; at rest is re-sealed ciphertext (not plaintext).
        assert_eq!(fs::read(s.scratch_path().unwrap()).unwrap(), b"before + edited");
        let at_rest = fs::read(&sealed).unwrap();
        assert!(is_v2_ciphertext(&at_rest));
        assert!(
            !at_rest.windows(6).any(|w| w == b"before"),
            "no plaintext substring in the at-rest ciphertext"
        );

        // Reopen fresh and confirm the edit persisted through the seal.
        drop(s);
        let s2 = OfficeSession::open(&sealed, dir.join("s2"), KEY).unwrap();
        assert_eq!(fs::read(s2.scratch_path().unwrap()).unwrap(), b"before + edited");
    }

    #[test]
    fn edit_error_from_seam_propagates_and_does_not_change_at_rest() {
        let dir = TmpDir::new("editerr");
        let sealed = dir.join("d");
        let mut s = OfficeSession::create(&sealed, dir.join("s"), KEY, DOC).unwrap();
        let before = fs::read(&sealed).unwrap();

        let r = s.edit(|_| Err("mock editor crashed".to_string()));
        assert!(matches!(r, Err(OfficeError::Editor(_))));
        assert_eq!(fs::read(&sealed).unwrap(), before, "failed edit left at-rest untouched");
    }

    #[test]
    fn cannot_edit_or_read_while_locked() {
        let dir = TmpDir::new("locked");
        let mut s = OfficeSession::create(dir.join("d"), dir.join("s"), KEY, DOC).unwrap();
        s.panic().unwrap();
        assert!(matches!(s.read_plaintext(), Err(OfficeError::Locked)));
        assert!(matches!(
            s.edit(|p| Ok(p.to_vec())),
            Err(OfficeError::Locked)
        ));
    }

    #[test]
    fn scratch_guard_secure_delete_is_idempotent_and_removes_file() {
        let dir = TmpDir::new("guard");
        let mut g = ScratchGuard::materialize(&dir.0, b"plaintext window").unwrap();
        let p = g.path().to_path_buf();
        assert!(p.exists());
        assert!(g.is_active());
        g.secure_delete().unwrap();
        assert!(!p.exists(), "secure-delete unlinks the scratch");
        assert!(!g.is_active());
        g.secure_delete().unwrap(); // idempotent
    }

    #[test]
    fn dropping_unlocked_session_removes_scratch() {
        let dir = TmpDir::new("drop");
        let s = OfficeSession::create(dir.join("d"), dir.join("s"), KEY, DOC).unwrap();
        let p = s.scratch_path().unwrap().to_path_buf();
        assert!(p.exists());
        drop(s);
        assert!(!p.exists(), "ScratchGuard::drop secure-deletes the plaintext scratch");
    }
}
