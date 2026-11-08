//! The scoped filesystem boundary — the runtime check.
//!
//! [`ScopedFs`] wraps a [`Grant`] and refuses to open any path that is not
//! covered by the grant: reads only within `read_paths`, writes only within
//! `write_paths`, and never outside the workspace root. Every path is resolved
//! and checked *before* the file is opened.
//!
//! # Honest boundary note
//!
//! **This is a userland boundary, not an OS sandbox.** It is a defense-in-depth
//! check performed by this process against itself: it prevents *this* code from
//! opening files outside the grant by mistake. It does **not** stop a compromised
//! or malicious process from making raw syscalls, following a TOCTOU-raced
//! symlink, or otherwise going around the check.
//!
//! True enforcement — Linux **Landlock** / **seccomp-bpf**, or the **macOS
//! sandbox** — is the intended follow-up and is *not* implemented here. Treat
//! this as the honest userland layer beneath a kernel sandbox that does not yet
//! exist.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::path::{Component, Path, PathBuf};

use postern_policy::EnforcementMode;

use crate::threshold::Grant;

/// Errors from the scoped filesystem boundary.
#[derive(Debug, thiserror::Error)]
pub enum FsError {
    #[error("path {declared:?} contains a `..` traversal component")]
    Traversal { declared: String },

    #[error("path {declared:?} could not be resolved: {io}")]
    Unresolvable { declared: String, io: String },

    #[error("read denied: {resolved:?} is not within any granted read_path")]
    ReadDenied { resolved: String },

    #[error("write denied: {resolved:?} is not within any granted write_path")]
    WriteDenied { resolved: String },

    #[error("I/O error on {path:?}: {io}")]
    Io { path: String, io: String },
}

/// A filesystem accessor scoped to a [`Grant`]. Construct with [`ScopedFs::new`]
/// and use its methods instead of `std::fs` directly.
#[derive(Debug)]
pub struct ScopedFs<'g> {
    grant: &'g Grant,
    /// Resolved paths this accessor **actually opened** (read or write) —
    /// the honest input for the audit trail, as opposed to the grant's
    /// requested/granted path list. `BTreeSet` keeps it deterministic.
    touched: RefCell<BTreeSet<PathBuf>>,
}

impl<'g> ScopedFs<'g> {
    /// How this boundary is honestly enforced: [`EnforcementMode::ByConstruction`]
    /// — a userland, in-process check, **not** an OS sandbox. This is the shared
    /// consent-kernel type, so the caveat is one word across the workspace
    /// rather than prose that could drift into "sandboxed". See
    /// [`EnforcementMode::honest_label`] for the exact wording.
    pub const ENFORCEMENT: EnforcementMode = EnforcementMode::ByConstruction;

    /// Bind a scoped accessor to `grant`.
    pub fn new(grant: &'g Grant) -> ScopedFs<'g> {
        ScopedFs { grant, touched: RefCell::new(BTreeSet::new()) }
    }

    /// The resolved paths this accessor actually opened (read or write),
    /// sorted and deduplicated. This is what the audit trail records —
    /// recording the grant's whole `write_paths` list would OVERSTATE the
    /// run (claiming paths were touched that never were).
    pub fn touched_paths(&self) -> Vec<String> {
        self.touched
            .borrow()
            .iter()
            .map(|p| p.display().to_string())
            .collect()
    }

    fn note_touch(&self, resolved: &Path) {
        self.touched.borrow_mut().insert(resolved.to_path_buf());
    }

    /// How this boundary is enforced — see [`ScopedFs::ENFORCEMENT`]. Exposed so
    /// UIs and logs read the honest caveat from the shared type, never a
    /// hand-written sentence.
    pub fn enforcement_mode(&self) -> EnforcementMode {
        Self::ENFORCEMENT
    }

    /// Open a file for reading, only if it lies within a granted `read_path`.
    pub fn open_read(&self, path: impl AsRef<Path>) -> Result<File, FsError> {
        let resolved = self.resolve_read(path.as_ref())?;
        let file = File::open(&resolved).map_err(|e| FsError::Io {
            path: resolved.display().to_string(),
            io: e.to_string(),
        })?;
        self.note_touch(&resolved);
        Ok(file)
    }

    /// Read a whole file, only if it lies within a granted `read_path`.
    pub fn read(&self, path: impl AsRef<Path>) -> Result<Vec<u8>, FsError> {
        let resolved = self.resolve_read(path.as_ref())?;
        let bytes = std::fs::read(&resolved).map_err(|e| FsError::Io {
            path: resolved.display().to_string(),
            io: e.to_string(),
        })?;
        self.note_touch(&resolved);
        Ok(bytes)
    }

    /// Open a file for writing (create + truncate), only within a granted
    /// `write_path`.
    pub fn open_write(&self, path: impl AsRef<Path>) -> Result<File, FsError> {
        let resolved = self.resolve_write(path.as_ref())?;
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&resolved)
            .map_err(|e| FsError::Io {
                path: resolved.display().to_string(),
                io: e.to_string(),
            })?;
        self.note_touch(&resolved);
        Ok(file)
    }

    /// Write bytes to a file, only within a granted `write_path`.
    pub fn write(&self, path: impl AsRef<Path>, bytes: &[u8]) -> Result<(), FsError> {
        let resolved = self.resolve_write(path.as_ref())?;
        std::fs::write(&resolved, bytes).map_err(|e| FsError::Io {
            path: resolved.display().to_string(),
            io: e.to_string(),
        })?;
        self.note_touch(&resolved);
        Ok(())
    }

    /// Resolve `path` and confirm it is within a granted read root. Public so
    /// callers can pre-check without opening.
    pub fn resolve_read(&self, path: &Path) -> Result<PathBuf, FsError> {
        let resolved = self.resolve_in_workspace(path)?;
        if within_any(&resolved, &self.grant.read_paths) {
            Ok(resolved)
        } else {
            Err(FsError::ReadDenied {
                resolved: resolved.display().to_string(),
            })
        }
    }

    /// Resolve `path` and confirm it is within a granted write root.
    pub fn resolve_write(&self, path: &Path) -> Result<PathBuf, FsError> {
        let resolved = self.resolve_in_workspace(path)?;
        if within_any(&resolved, &self.grant.write_paths) {
            Ok(resolved)
        } else {
            Err(FsError::WriteDenied {
                resolved: resolved.display().to_string(),
            })
        }
    }

    fn resolve_in_workspace(&self, path: &Path) -> Result<PathBuf, FsError> {
        if path.components().any(|c| matches!(c, Component::ParentDir)) {
            return Err(FsError::Traversal {
                declared: path.display().to_string(),
            });
        }
        let joined = if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.grant.workspace_root.join(path)
        };
        let resolved = resolve_partial(&joined).map_err(|e| FsError::Unresolvable {
            declared: path.display().to_string(),
            io: e.to_string(),
        })?;
        // Defense in depth: even a granted-looking path must stay in-workspace.
        if !resolved.starts_with(&self.grant.workspace_root) {
            return Err(FsError::WriteDenied {
                resolved: resolved.display().to_string(),
            });
        }
        Ok(resolved)
    }
}

fn within_any(path: &Path, roots: &[PathBuf]) -> bool {
    roots.iter().any(|root| path.starts_with(root))
}

/// Same partial-canonicalization used by the threshold: resolve the existing
/// prefix (following symlinks) and re-append any not-yet-created tail.
fn resolve_partial(path: &Path) -> std::io::Result<PathBuf> {
    let mut tail: Vec<&OsStr> = Vec::new();
    let mut cur: &Path = path;
    loop {
        if cur.exists() {
            let mut base = cur.canonicalize()?;
            for name in tail.iter().rev() {
                base.push(name);
            }
            return Ok(base);
        }
        match (cur.parent(), cur.file_name()) {
            (Some(parent), Some(name)) => {
                tail.push(name);
                cur = parent;
            }
            _ => return path.canonicalize(),
        }
    }
}
