// SPDX-License-Identifier: MIT OR Apache-2.0
//
// DESIGN PREVIEW — written ≠ built ≠ booted. UNAUDITED. THIS MODULE SPAWNS
// NOTHING: it only resolves and vets paths; it never executes anything. The
// crate's one spawn path is `crate::spawn`, gated OFF by default. Product
// name "Terem" is proposed only, pending trademark clearance.

//! Pinned-name binary resolution for the two QEMU userspace tools Terem's
//! POC drives as external processes (`qemu-system-x86_64` via the opt-in
//! [`crate::spawn`] path; `qemu-img` in a later slice).
//!
//! This is a deliberate, near-literal reuse of the already-tested
//! `resolve_node_binary` shape in `desktop/src-tauri/src/main.rs`
//! (POC-SCOPE.md §3 step 1: "pattern reuse, not new design"), parameterized
//! over two pinned names instead of one:
//!
//! * a bare command name is accepted only if it is exactly the pinned name,
//!   and is then resolved against `$PATH` (never the CWD);
//! * a path is canonicalized (symlinks / `..` collapsed) and must point at
//!   an existing regular file whose file name is the pinned name;
//! * on Unix the file must have an execute bit set.
//!
//! This is a name + location + existence check, not a signature/hash check:
//! it closes the "run any binary/path" hole but does not attest that the
//! resolved binary is an authentic QEMU. QEMU itself (GPL-2.0) is never
//! bundled or linked — resolution targets whatever the operator installed
//! (LICENSE-DECISION.md §2's "bring your own" opt-in doctrine).

use std::path::PathBuf;

/// The pinned QEMU system-emulator binary name (POC-SCOPE.md §2.1).
pub const QEMU_SYSTEM_BIN_NAME: &str = "qemu-system-x86_64";

/// The pinned QEMU disk-image tool binary name (POC-SCOPE.md §2.1).
pub const QEMU_IMG_BIN_NAME: &str = "qemu-img";

/// Minimal `which`: first `$PATH` entry containing `name` as a file.
/// (Same helper shape as `desktop/src-tauri/src/main.rs`.)
fn which_on_path(name: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    std::env::split_paths(&paths)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

/// Resolve `binary` to a vetted absolute path whose file name is exactly
/// `pinned_name`, or reject it. Shared core for the two public resolvers.
fn resolve_pinned_binary(binary: &str, pinned_name: &str) -> Result<PathBuf, String> {
    let binary = binary.trim();
    if binary.is_empty() {
        return Err(format!("{pinned_name} binary path is empty"));
    }

    let candidate = if binary.chars().any(std::path::is_separator) {
        // An explicit path (relative or absolute).
        PathBuf::from(binary)
    } else {
        // A bare name: only the pinned binary name is allowed, resolved via
        // $PATH so a caller can't ask this to run e.g. `sh` off the PATH.
        if binary != pinned_name {
            return Err(format!(
                "refusing to run '{binary}': a bare command name must be '{pinned_name}'"
            ));
        }
        which_on_path(binary).ok_or_else(|| format!("'{binary}' not found on PATH"))?
    };

    // Collapse symlinks/`..` and confirm the target exists. canonicalize()
    // errors on a missing path, which also rejects typo'd or injected paths
    // up front.
    let real = candidate
        .canonicalize()
        .map_err(|e| format!("cannot resolve '{}': {e}", candidate.display()))?;

    // Pin the file name: wherever it lives, the program must be the pinned
    // binary.
    if real.file_name().and_then(|n| n.to_str()) != Some(pinned_name) {
        return Err(format!(
            "refusing to run '{}': expected an executable named '{pinned_name}'",
            real.display()
        ));
    }

    let meta =
        std::fs::metadata(&real).map_err(|e| format!("cannot stat '{}': {e}", real.display()))?;
    if !meta.is_file() {
        return Err(format!("binary '{}' is not a regular file", real.display()));
    }

    // On Unix, require an execute bit so we reject non-executable look-alikes.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o111 == 0 {
            return Err(format!("binary '{}' is not executable", real.display()));
        }
    }

    Ok(real)
}

/// Resolve the caller-supplied `binary` to a vetted absolute path to
/// `qemu-system-x86_64`, or reject it.
///
/// Resolution only — this function never spawns anything; the crate's one
/// spawn path is the separately-gated [`crate::spawn::spawn_plan`]. QEMU is
/// an external, operator-supplied, opt-in process (see
/// [`crate::config::TeremConfig::full_vm_qemu`]); it is never linked into
/// any Postern binary.
pub fn resolve_qemu_binary(binary: &str) -> Result<PathBuf, String> {
    resolve_pinned_binary(binary, QEMU_SYSTEM_BIN_NAME)
}

/// Resolve the caller-supplied `binary` to a vetted absolute path to
/// `qemu-img`, or reject it.
///
/// Resolution only — never spawns; see [`resolve_qemu_binary`]'s caveats,
/// which apply identically here.
pub fn resolve_qemu_img_binary(binary: &str) -> Result<PathBuf, String> {
    resolve_pinned_binary(binary, QEMU_IMG_BIN_NAME)
}

#[cfg(test)]
mod tests {
    //! The six-case set mirrors `resolve_node_binary`'s tests in
    //! `desktop/src-tauri/src/main.rs` (POC-SCOPE.md §3 step 1), run once
    //! per pinned binary via fake executables in a temp dir — no real QEMU
    //! is needed, present, or executed.

    use super::*;
    use std::path::Path;

    /// One row per public resolver: (resolver fn, pinned name, scratch tag).
    type ResolveCase = (fn(&str) -> Result<PathBuf, String>, &'static str, &'static str);

    fn cases() -> [ResolveCase; 2] {
        [
            (resolve_qemu_binary, QEMU_SYSTEM_BIN_NAME, "qemu-system"),
            (resolve_qemu_img_binary, QEMU_IMG_BIN_NAME, "qemu-img"),
        ]
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "terem-core-test-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[cfg(unix)]
    fn write_exec(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, b"#!/bin/sh\ntrue\n").unwrap();
        let mut perm = std::fs::metadata(path).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(path, perm).unwrap();
    }

    #[test]
    fn resolve_rejects_empty() {
        for (resolve, _, _) in cases() {
            assert!(resolve("   ").is_err());
            assert!(resolve("").is_err());
        }
    }

    #[test]
    fn resolve_rejects_bare_non_qemu_name() {
        // A bare command name is only ever accepted if it is exactly the
        // pinned name — never an arbitrary program off $PATH, and never the
        // OTHER qemu tool's name.
        for (resolve, _, _) in cases() {
            let err = resolve("sh").unwrap_err();
            assert!(err.contains("bare command name"), "unexpected error: {err}");
        }
        // Cross-pinning: each resolver refuses the other's bare name.
        assert!(resolve_qemu_binary(QEMU_IMG_BIN_NAME).is_err());
        assert!(resolve_qemu_img_binary(QEMU_SYSTEM_BIN_NAME).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn resolve_accepts_real_qemu_path() {
        for (resolve, pinned, tag) in cases() {
            let dir = scratch(&format!("ok-{tag}"));
            let bin = dir.join(pinned);
            write_exec(&bin);
            let resolved = resolve(bin.to_str().unwrap()).expect("should resolve");
            assert_eq!(resolved.file_name().and_then(|n| n.to_str()), Some(pinned));
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[cfg(unix)]
    #[test]
    fn resolve_rejects_wrong_file_name() {
        // A path pointing at a look-alike (wrong name) is refused even if it
        // is a real, executable file.
        for (resolve, pinned, tag) in cases() {
            let dir = scratch(&format!("wrongname-{tag}"));
            let bin = dir.join(format!("{pinned}x"));
            write_exec(&bin);
            assert!(resolve(bin.to_str().unwrap()).is_err());
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[cfg(unix)]
    #[test]
    fn resolve_rejects_non_executable() {
        // Correct name but no execute bit → rejected (not an executable).
        for (resolve, pinned, tag) in cases() {
            let dir = scratch(&format!("noexec-{tag}"));
            let bin = dir.join(pinned);
            std::fs::write(&bin, b"not executable").unwrap();
            let err = resolve(bin.to_str().unwrap()).unwrap_err();
            assert!(err.contains("not executable"), "unexpected error: {err}");
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn resolve_rejects_missing_path() {
        // canonicalize() fails on a non-existent path → rejected up front.
        for (resolve, pinned, _) in cases() {
            let missing = std::env::temp_dir()
                .join("terem-core-does-not-exist")
                .join(pinned);
            assert!(resolve(missing.to_str().unwrap()).is_err());
        }
    }
}
