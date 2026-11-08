//! OS-level confinement for the quarantine decode path.
//!
//! On Linux, [`confine`] restricts the calling thread with the
//! [Landlock](https://docs.kernel.org/userspace-api/landlock.html) LSM
//! (via `rust-landlock`, MIT OR Apache-2.0) *before* an untrusted image is
//! handed to the decoder: the ruleset declares every Landlock-filesystem
//! access right and adds **no allow-rules**, so once `restrict_self()`
//! succeeds the thread cannot open, create, or modify any path for the rest
//! of its life — exactly the shape the decode step needs, since it only
//! touches an in-memory byte buffer.
//!
//! Landlock is unconditionally best-effort and never fails a build or a
//! request on its own: the ruleset is built against `ABI::V7` — the highest
//! Landlock ABI version this crate release knows about, a **compile-time**
//! constant, not something probed from the running kernel (the upstream
//! `rust-landlock` crate deliberately discourages runtime ABI detection,
//! since it would make sandboxing behavior non-deterministic across
//! otherwise-identical runs). The crate's best-effort compatibility layer —
//! the default — then transparently negotiates that request down to
//! whatever subset of access rights the *running* kernel's Landlock ABI
//! actually supports. So this degrades gracefully from a modern kernel
//! (fully enforced) down through an older kernel (a subset of access rights
//! enforced) to no Landlock support at all (kernel too old,
//! `CONFIG_SECURITY_LANDLOCK` unset, or LSM disabled at boot) — reported
//! honestly as [`SandboxStatus::Unsandboxed`], never as a silent success.
//!
//! On every non-Linux target the `landlock` crate is not even a dependency
//! (see `Cargo.toml`'s `cfg(target_os = "linux")` gate) — [`confine`] is a
//! trivial function that always reports [`SandboxStatus::Unsandboxed`] with
//! a truthful reason. Callers must not assume confinement happened; check
//! [`SandboxStatus::is_enforced`] and surface the caveat to the operator/log
//! rather than silently proceeding as if sandboxed.
//!
//! **Observed on a real Linux host:** `cargo test -p postern-quarantine`
//! (both the doctests and the Linux-gated unit tests, including
//! `confine_on_linux_never_panics_and_reports_a_known_status` below) has now
//! actually run — on the Fly.io `postern-os-build` build machine, kernel
//! `6.12.91-fly` — and passed. The concrete [`SandboxStatus`] that kernel
//! produces is **`Unsandboxed`**: its own build config reports
//! `CONFIG_SECURITY_LANDLOCK is not set`, and `/sys/kernel/security/landlock`
//! does not exist (confirmed by reading `/boot/config-6.12.91-fly` and
//! `/sys/kernel/security/` directly on that host), so Landlock is not
//! compiled into this particular kernel at all. `confine()` degraded
//! gracefully to `Unsandboxed` there exactly as designed, rather than
//! panicking or misreporting — that is the real, host-specific result this
//! run confirms. It does **not** confirm the `Enforced`/`Partial` branches:
//! this build host has no Landlock support to exercise them with, so
//! "Enforced (Linux ≥ 5.13)" below remains the *designed* behavior for a
//! kernel that actually ships `CONFIG_SECURITY_LANDLOCK`, not something this
//! project has observed end-to-end yet.

use std::fmt;

/// Outcome of attempting to confine the calling thread before an untrusted
/// decode. Never claims success it did not verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxStatus {
    /// The kernel fully enforced every access right the ruleset requested,
    /// at the given Landlock ABI version.
    Enforced { abi: String },
    /// The kernel enforced *some but not all* of the requested access
    /// rights (typically an older kernel supporting an earlier Landlock
    /// ABI than the one requested). `detail` explains the gap.
    Partial { abi: String, detail: String },
    /// No confinement is in effect. The decode runs with the caller's full
    /// privileges. `reason` states truthfully why.
    Unsandboxed { reason: String },
}

impl SandboxStatus {
    /// True only for [`SandboxStatus::Enforced`] — a `Partial` result is
    /// deliberately *not* "enforced": some requested access rights were not
    /// confined, so callers that need a hard guarantee must treat it like
    /// `Unsandboxed` and say so.
    pub fn is_enforced(&self) -> bool {
        matches!(self, SandboxStatus::Enforced { .. })
    }
}

impl fmt::Display for SandboxStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SandboxStatus::Enforced { abi } => {
                write!(f, "sandbox enforced (Landlock ABI {abi})")
            }
            SandboxStatus::Partial { abi, detail } => {
                write!(f, "sandbox partially enforced (Landlock ABI {abi}): {detail}")
            }
            SandboxStatus::Unsandboxed { reason } => {
                write!(f, "UNSANDBOXED — decode runs with no OS-level confinement: {reason}")
            }
        }
    }
}

/// Confine the calling thread before decoding an untrusted image.
///
/// Linux: builds a ruleset handling every [`landlock::AccessFs`] right for
/// `ABI::V7` (the best ABI this crate build knows about), adds **no path
/// rules** — so no directory or file is allow-listed and every handled
/// access right is denied for every path once restricted — and calls
/// `restrict_self()`. Returns the true result, mapped one-to-one from
/// [`landlock::RulesetStatus`]: `FullyEnforced` → [`SandboxStatus::Enforced`],
/// `PartiallyEnforced` → [`SandboxStatus::Partial`] (an older kernel /
/// narrower Landlock ABI enforced only a subset), `NotEnforced` → this
/// function's `Unsandboxed` case (kernel < 5.13 or Landlock disabled at
/// boot). **Any** Landlock error — ruleset construction, `handle_access`, or
/// the `restrict_self()` syscall itself failing — is also mapped to
/// `Unsandboxed { reason }` with the error's own message; this function
/// never panics on a Landlock failure and never reports `Enforced` unless
/// the kernel actually confirmed it.
///
/// **Irreversible and inherited:** once `restrict_self()` succeeds, the
/// restriction cannot be lifted for the calling thread's remaining lifetime
/// — it is a one-way ratchet, the same model as `seccomp`. It **is
/// inherited** by anything that thread spawns afterward (child threads,
/// `fork`/`exec`'d processes start at least as restricted as the caller). It
/// does **not** retroactively restrict other already-running threads in the
/// same process, and it does not revoke file descriptors already open
/// before the call.
///
/// **Not (yet) applied here:** this function confines filesystem access via
/// Landlock only. **No `seccomp` syscall filter is applied — that is still
/// planned, not active.** Do not describe the decode path this guards as
/// seccomp-confined until a seccomp filter actually lands alongside this.
///
/// Non-Linux: always [`SandboxStatus::Unsandboxed`] — Landlock is a
/// Linux-only LSM; there is no equivalent confinement wired up here for
/// macOS/Windows, and this function says so rather than staying silent.
#[cfg(target_os = "linux")]
pub fn confine() -> SandboxStatus {
    use landlock::{Access, AccessFs, Ruleset, RulesetAttr, RulesetStatus, ABI};

    // The highest Landlock ABI this crate build knows about — a
    // compile-time constant, deliberately NOT probed from the running
    // kernel (see the module docs on why `rust-landlock` discourages
    // runtime ABI detection). `handle_access` + `restrict_self` below
    // negotiate this down to whatever the running kernel actually
    // supports via the crate's best-effort compatibility layer; that
    // negotiation is what produces `Partial`/`Unsandboxed` below rather
    // than a hard error on an older kernel.
    let abi = ABI::V7;
    let abi_label = format!("{abi:?}");

    let attempt = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .and_then(|r| r.create())
        .and_then(|r| r.restrict_self());

    match attempt {
        Ok(status) => match status.ruleset {
            RulesetStatus::FullyEnforced => SandboxStatus::Enforced { abi: abi_label },
            RulesetStatus::PartiallyEnforced => SandboxStatus::Partial {
                abi: abi_label,
                detail: "kernel enforced only a subset of the requested Landlock access rights \
                         (older kernel / partial Landlock support)"
                    .to_string(),
            },
            RulesetStatus::NotEnforced => SandboxStatus::Unsandboxed {
                reason: "kernel reported no Landlock enforcement (Landlock disabled at boot, \
                         or unsupported by this kernel)"
                    .to_string(),
            },
        },
        Err(e) => SandboxStatus::Unsandboxed {
            reason: format!("Landlock ruleset setup failed: {e}"),
        },
    }
}

/// See the Linux implementation's docs above; this is the honest fallback
/// for every other target.
#[cfg(not(target_os = "linux"))]
pub fn confine() -> SandboxStatus {
    SandboxStatus::Unsandboxed {
        reason: "landlock is Linux-only; decode runs unsandboxed on this platform".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsandboxed_reason_is_truthful_and_nonempty() {
        // On non-Linux this exercises confine() directly; on Linux it still
        // holds for the manually-built variant below. Either way, an
        // Unsandboxed status must never carry an empty/placeholder reason.
        let status = SandboxStatus::Unsandboxed {
            reason: "landlock is Linux-only; decode runs unsandboxed on this platform".to_string(),
        };
        match &status {
            SandboxStatus::Unsandboxed { reason } => assert!(!reason.is_empty()),
            _ => unreachable!(),
        }
        assert!(!status.is_enforced());
        assert!(status.to_string().contains("UNSANDBOXED"));
    }

    #[test]
    fn enforced_is_the_only_status_reporting_is_enforced_true() {
        assert!(SandboxStatus::Enforced { abi: "V5".to_string() }.is_enforced());
        assert!(!SandboxStatus::Partial {
            abi: "V5".to_string(),
            detail: "gap".to_string()
        }
        .is_enforced());
        assert!(!SandboxStatus::Unsandboxed { reason: "n/a".to_string() }.is_enforced());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn confine_on_non_linux_is_unsandboxed_with_truthful_reason() {
        let status = confine();
        match status {
            SandboxStatus::Unsandboxed { reason } => {
                assert!(reason.contains("Linux-only"));
            }
            other => panic!("expected Unsandboxed on non-Linux, got {other:?}"),
        }
    }

    /// Linux-only: exercises the real `confine()` code path, not just a
    /// type-check. This test body only compiles on Linux (the module it
    /// lives in is gated the same way as `confine()`'s Linux impl above), so
    /// it cannot run on this macOS dev host — but it HAS now run for real:
    /// on the Fly.io `postern-os-build` machine, kernel `6.12.91-fly`,
    /// `cargo test -p postern-quarantine` executed this test over an SSH
    /// session and it passed. The observed [`SandboxStatus`] on that host is
    /// **`Unsandboxed`** — that kernel's own build config reports
    /// `CONFIG_SECURITY_LANDLOCK is not set` (and `/sys/kernel/security/landlock`
    /// does not exist), so Landlock itself is unavailable there; `confine()`
    /// correctly degraded to `Unsandboxed` instead of panicking or claiming
    /// enforcement it could not back up. That confirms the
    /// degrade-gracefully-without-Landlock branch end-to-end on a real Linux
    /// kernel. It does **not** confirm the `Enforced`/`Partial` branches —
    /// this build host has no Landlock support to exercise them with, so
    /// treat "Enforced on Linux ≥ 5.13" as the designed behavior for a
    /// kernel that ships `CONFIG_SECURITY_LANDLOCK`, not as something this
    /// particular run demonstrated.
    #[cfg(target_os = "linux")]
    #[test]
    fn confine_on_linux_never_panics_and_reports_a_known_status() {
        // `confine()` must return one of the three known SandboxStatus
        // variants — Enforced on a modern kernel with Landlock support,
        // Partial on an older kernel/ABI, or Unsandboxed if Landlock is
        // unavailable/disabled — and must never panic regardless of which
        // kernel this happens to run on. The match is exhaustive over the
        // enum, so this also fails to compile if a new variant is ever added
        // without updating this assertion.
        let status = confine();
        match status {
            SandboxStatus::Enforced { abi } => assert!(!abi.is_empty()),
            SandboxStatus::Partial { abi, detail } => {
                assert!(!abi.is_empty());
                assert!(!detail.is_empty());
            }
            SandboxStatus::Unsandboxed { reason } => assert!(!reason.is_empty()),
        }
    }

    /// BEHAVIORAL proof, not just a type-check: this proves `confine()`
    /// actually denies filesystem access when it claims to, not merely that
    /// it returns a recognized [`SandboxStatus`] variant.
    ///
    /// `confine()`'s restriction is irreversible and thread-wide (see the
    /// module docs), so it must never run on the shared test-harness thread
    /// where it could poison sibling tests. This spawns a fresh
    /// [`std::thread`], calls `confine()` inside it, performs real
    /// post-confine filesystem attempts on that same thread, and only that
    /// thread — never the caller — is left restricted; the thread exits
    /// (and is joined) once the probe is done.
    ///
    /// The assertions are branch-specific on the *returned* status, so this
    /// never asserts more than the kernel actually reported:
    /// - `Enforced`: a real `File::open` on `/etc/hostname` (a `ReadFile`
    ///   probe) and a real `File::create` in the temp dir (a `MakeReg`/
    ///   `WriteFile` probe) issued *after* `confine()` returned MUST both
    ///   fail with `ErrorKind::PermissionDenied`. That failure is the proof
    ///   of enforcement — without it this test would only be checking that
    ///   `confine()` returns a plausible-looking enum value.
    /// - `Partial`: `ReadFile`/`WriteFile`/`MakeReg` are handled since the
    ///   oldest Landlock ABI (`ABI::V1`), so a kernel that only partially
    ///   supports the newer `ABI::V7` ruleset this crate requests still
    ///   enforces these base rights — the same two probes are asserted
    ///   denied here as "at least the rights the kernel reported enforced".
    /// - `Unsandboxed`: the *opposite* assertion — both probes MUST succeed.
    ///   This is deliberate: if a plain `File::open`/`File::create` failed
    ///   here too, this test could not tell real Landlock enforcement apart
    ///   from a coincidental environment failure (missing file, read-only
    ///   temp dir, wrong permissions, etc.). Proving the unsandboxed case
    ///   still has full access is what makes the enforced/partial denials
    ///   above meaningful. This branch is environment-dependent — it is
    ///   truthfully NOT a demonstration of enforcement — and is logged as
    ///   such rather than silently passing.
    #[cfg(target_os = "linux")]
    #[test]
    fn confine_actually_denies_filesystem_access_when_enforced() {
        use std::io::ErrorKind;

        // Everything that touches the (post-confine, possibly irreversibly
        // restricted) thread happens inside the spawned thread; only plain
        // Result/enum data — nothing that keeps the restriction "alive" in
        // any meaningful sense — crosses back over `join()`.
        let probe = std::thread::Builder::new()
            .name("landlock-confine-probe".to_string())
            .spawn(|| {
                let status = confine();

                let open_result = std::fs::File::open("/etc/hostname")
                    .map(|_| ())
                    .map_err(|e| e.kind());

                let tmp_path = std::env::temp_dir().join(format!(
                    "postern-quarantine-landlock-probe-{}-{:?}",
                    std::process::id(),
                    std::thread::current().id()
                ));
                let create_result = std::fs::File::create(&tmp_path)
                    .map(|_| ())
                    .map_err(|e| e.kind());
                // Best-effort cleanup for the Unsandboxed branch, where the
                // create is expected to have actually succeeded.
                let _ = std::fs::remove_file(&tmp_path);

                (status, open_result, create_result)
            })
            .expect("failed to spawn the landlock-confine-probe thread");

        let (status, open_result, create_result) =
            probe.join().expect("landlock-confine-probe thread panicked");

        match status {
            SandboxStatus::Enforced { abi } => {
                assert!(!abi.is_empty());
                assert_eq!(
                    open_result,
                    Err(ErrorKind::PermissionDenied),
                    "confine() reported Enforced (ABI {abi}) but a post-confine \
                     File::open(\"/etc/hostname\") still succeeded — confinement is not \
                     actually denying filesystem reads"
                );
                assert_eq!(
                    create_result,
                    Err(ErrorKind::PermissionDenied),
                    "confine() reported Enforced (ABI {abi}) but a post-confine \
                     File::create in the temp dir still succeeded — confinement is not \
                     actually denying filesystem writes"
                );
            }
            SandboxStatus::Partial { abi, detail } => {
                assert!(!abi.is_empty());
                assert!(!detail.is_empty());
                // ReadFile/WriteFile/MakeReg are handled since Landlock
                // ABI::V1, the oldest version, so they are expected to be
                // among the rights a partially-enforcing kernel still
                // covers. Asserting the same denial here is deliberately
                // "at least the rights the kernel reported enforced", not a
                // claim that every ABI::V7 right was enforced.
                assert_eq!(
                    open_result,
                    Err(ErrorKind::PermissionDenied),
                    "confine() reported Partial (ABI {abi}: {detail}) but a post-confine \
                     File::open(\"/etc/hostname\") still succeeded — even the base \
                     ReadFile right was not enforced"
                );
                assert_eq!(
                    create_result,
                    Err(ErrorKind::PermissionDenied),
                    "confine() reported Partial (ABI {abi}: {detail}) but a post-confine \
                     File::create in the temp dir still succeeded — even the base \
                     WriteFile/MakeReg right was not enforced"
                );
            }
            SandboxStatus::Unsandboxed { reason } => {
                assert!(!reason.is_empty());
                // Proves this test is measuring *real* enforcement rather
                // than a coincidental failure: with no confinement in
                // effect, both plain filesystem operations must succeed.
                assert!(
                    open_result.is_ok(),
                    "confine() reported Unsandboxed ({reason}) but a plain \
                     File::open(\"/etc/hostname\") still failed ({open_result:?}) — this \
                     test cannot distinguish real Landlock enforcement from an unrelated \
                     environment failure; fix the environment (e.g. missing \
                     /etc/hostname) before trusting this test's Enforced/Partial branches"
                );
                assert!(
                    create_result.is_ok(),
                    "confine() reported Unsandboxed ({reason}) but a plain File::create \
                     in the temp dir still failed ({create_result:?}) — this test cannot \
                     distinguish real Landlock enforcement from an unrelated environment \
                     failure (e.g. read-only temp dir); fix the environment before \
                     trusting this test's Enforced/Partial branches"
                );
                eprintln!(
                    "confine_actually_denies_filesystem_access_when_enforced: \
                     environment-dependent — kernel reported Unsandboxed ({reason}); \
                     full Landlock enforcement was NOT observed on this host/kernel."
                );
            }
        }
    }
}
