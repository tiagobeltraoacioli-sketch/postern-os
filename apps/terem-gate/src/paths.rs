// SPDX-License-Identifier: MIT OR Apache-2.0
//! **Red-team fix (a).** `sharedFolder.hostPath` disjointness against Terem's
//! own state/audit/`WINEPREFIX` directories.
//!
//! Sharing a host directory into the guest (SS2.1/SS3.1 of both design docs)
//! is only as closed as the boundary around it: if the shared directory
//! itself contains -- or is contained by -- Terem's own state dir, audit
//! trail, or `WINEPREFIX`, the guest gets a path to exactly the state a
//! sealed-box design promises it cannot reach (the `terem-gate` consent
//! records, the hash-chained audit trail, another app's Wine prefix). This
//! module makes that overlap **structurally unmintable**: [`TeremPaths::
//! check_disjoint`] is called from [`crate::consent_record::ConsentAuthority::
//! mint_shared_folder`] and a `SharedFolder` grant simply cannot be minted
//! over an overlapping path -- the caller never gets a `ConsentRecord` to
//! misuse in the first place. Fail-closed: on error, no record.

use std::path::{Component, Path, PathBuf};

use crate::error::TeremGateError;

/// The host paths `terem-gate` itself occupies. A `sharedFolder.hostPath`
/// must be disjoint from **every** one of these, in **either** direction:
///
/// - the candidate must not be *nested inside* a guarded path (sharing
///   `/var/lib/postern/terem-gate/state.json`'s parent directly), and
/// - a guarded path must not be *nested inside* the candidate (sharing
///   `/home/operator`, which happens to contain `~/.wine`, leaks the
///   `WINEPREFIX` exactly as thoroughly as sharing it directly, even though
///   the shared path itself is "just the home directory").
///
/// The second case is the one naive implementations miss -- a same-prefix or
/// child-of check alone only catches the first.
#[derive(Debug, Clone)]
pub struct TeremPaths {
    /// `/var/lib/postern/terem-gate/` -- the canonical consent state dir
    /// (`02-security-consent-privacy.md` SS7).
    pub state_dir: PathBuf,
    /// The hash-chained audit trail's directory (SS7's "local audit trail").
    pub audit_dir: PathBuf,
    /// App Mode's `WINEPREFIX`, when this guest is a Wine prefix rather than
    /// a full VM/container guest (SS2.2). `None` for Guest Mode.
    pub wineprefix: Option<PathBuf>,
}

impl TeremPaths {
    pub fn new(state_dir: impl Into<PathBuf>, audit_dir: impl Into<PathBuf>) -> Self {
        TeremPaths {
            state_dir: state_dir.into(),
            audit_dir: audit_dir.into(),
            wineprefix: None,
        }
    }

    pub fn with_wineprefix(mut self, wineprefix: impl Into<PathBuf>) -> Self {
        self.wineprefix = Some(wineprefix.into());
        self
    }

    fn guarded(&self) -> Vec<(&'static str, &Path)> {
        let mut v = vec![
            ("state_dir", self.state_dir.as_path()),
            ("audit_dir", self.audit_dir.as_path()),
        ];
        if let Some(w) = &self.wineprefix {
            v.push(("wineprefix", w.as_path()));
        }
        v
    }

    /// The disjointness check. Fail-closed: any overlap in either direction
    /// against any guarded path is `Err`. Prefers `std::fs::canonicalize`
    /// (resolves `..`/symlinks) when **both** paths exist on this host, since
    /// that is the strongest check available; falls back to pure lexical
    /// normalization (resolving `.`/`..` components without touching the
    /// filesystem) when either path does not yet exist -- which is the common
    /// case for a `hostPath` an operator is about to create, and is also what
    /// makes this check exercisable in a host test without a real
    /// filesystem tree.
    ///
    /// Honest limit, stated once and not softened: canonicalization at
    /// check-time does not defend a **TOCTOU symlink swap after this check
    /// returns** (the caller mounts a path, and something later replaces a
    /// component with a symlink into a guarded dir) -- that needs `openat`
    /// with `O_NOFOLLOW`/`O_PATH`-style hardening in the actual mount code,
    /// out of scope for this consent-layer check. This function answers "is
    /// the requested path disjoint right now," not "will it always stay so."
    pub fn check_disjoint(&self, candidate: &Path) -> Result<(), TeremGateError> {
        let candidate_norm = best_effort_resolve(candidate);
        for (name, guarded) in self.guarded() {
            let guarded_norm = best_effort_resolve(guarded);
            if overlaps(&candidate_norm, &guarded_norm) {
                return Err(TeremGateError::SharedFolderPathOverlap {
                    host_path: candidate.display().to_string(),
                    guarded: name,
                    guarded_path: guarded.display().to_string(),
                });
            }
        }
        Ok(())
    }
}

/// Canonicalize when possible (resolves symlinks + `..`); otherwise fall back
/// to a pure lexical normalization of `.`/`..` components. Never touches the
/// filesystem beyond the canonicalize attempt itself, and never panics on a
/// nonexistent path.
fn best_effort_resolve(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| lexical_normalize(p))
}

fn lexical_normalize(p: &Path) -> PathBuf {
    let mut out: Vec<Component> = Vec::new();
    for c in p.components() {
        match c {
            Component::ParentDir => {
                if matches!(out.last(), Some(Component::Normal(_))) {
                    out.pop();
                } else {
                    out.push(c);
                }
            }
            Component::CurDir => {}
            other => out.push(other),
        }
    }
    out.into_iter().collect()
}

/// True if `a` and `b` are equal, or one is an ancestor of the other --
/// checked on normalized **component** sequences, never raw string
/// prefixing (which would wrongly treat `/var/lib/postern-x` as inside
/// `/var/lib/postern`).
fn overlaps(a: &Path, b: &Path) -> bool {
    let ac: Vec<Component> = a.components().collect();
    let bc: Vec<Component> = b.components().collect();
    let n = ac.len().min(bc.len());
    ac[..n] == bc[..n]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths() -> TeremPaths {
        TeremPaths::new(
            "/var/lib/postern/terem-gate/state",
            "/var/lib/postern/terem-gate/audit",
        )
        .with_wineprefix("/home/operator/.wine-terem")
    }

    #[test]
    fn a_disjoint_path_is_accepted() {
        let p = paths();
        assert!(p.check_disjoint(Path::new("/home/operator/Shared")).is_ok());
    }

    #[test]
    fn the_exact_state_dir_is_rejected() {
        let p = paths();
        let err = p
            .check_disjoint(Path::new("/var/lib/postern/terem-gate/state"))
            .unwrap_err();
        assert!(matches!(
            err,
            TeremGateError::SharedFolderPathOverlap { guarded: "state_dir", .. }
        ));
    }

    #[test]
    fn a_subdirectory_of_the_audit_dir_is_rejected() {
        let p = paths();
        let err = p
            .check_disjoint(Path::new("/var/lib/postern/terem-gate/audit/2026"))
            .unwrap_err();
        assert!(matches!(
            err,
            TeremGateError::SharedFolderPathOverlap { guarded: "audit_dir", .. }
        ));
    }

    #[test]
    fn a_parent_directory_that_would_swallow_the_wineprefix_is_rejected() {
        // The naive check (candidate-inside-guarded only) would miss this:
        // `/home/operator` is not INSIDE `.wine-terem`, but sharing it hands
        // the guest the WINEPREFIX anyway because the WINEPREFIX is inside it.
        let p = paths();
        let err = p.check_disjoint(Path::new("/home/operator")).unwrap_err();
        assert!(matches!(
            err,
            TeremGateError::SharedFolderPathOverlap { guarded: "wineprefix", .. }
        ));
    }

    #[test]
    fn sharing_the_filesystem_root_is_rejected() {
        let p = paths();
        let err = p.check_disjoint(Path::new("/")).unwrap_err();
        assert!(matches!(err, TeremGateError::SharedFolderPathOverlap { .. }));
    }

    #[test]
    fn a_lookalike_sibling_prefix_is_not_a_false_positive() {
        // `/var/lib/postern/terem-gate/state-backups` shares a STRING prefix
        // with `.../state` but is a sibling directory, not an ancestor or
        // descendant -- component-wise comparison must not flag it.
        let p = paths();
        assert!(p
            .check_disjoint(Path::new("/var/lib/postern/terem-gate/state-backups"))
            .is_ok());
    }

    #[test]
    fn dot_dot_traversal_cannot_launder_an_overlap() {
        let p = paths();
        let err = p
            .check_disjoint(Path::new(
                "/var/lib/postern/terem-gate/audit/../../terem-gate/state",
            ))
            .unwrap_err();
        assert!(matches!(
            err,
            TeremGateError::SharedFolderPathOverlap { guarded: "state_dir", .. }
        ));
    }

    #[test]
    fn no_wineprefix_configured_means_that_check_is_simply_absent() {
        let p = TeremPaths::new(
            "/var/lib/postern/terem-gate/state",
            "/var/lib/postern/terem-gate/audit",
        );
        // Would have overlapped a wineprefix if one were configured; Guest
        // Mode has none, so this is legitimately disjoint.
        assert!(p.check_disjoint(Path::new("/home/operator/.wine-terem")).is_ok());
    }
}
