//! Operator-facing probe: exercise `postern_quarantine::sandbox::confine()`
//! end-to-end on the *actual* running host/kernel and print the truth.
//!
//! This is deliberately not a test: `cargo test` output is easy to skim past
//! or infer from a green checkmark, and Landlock's behavior is host/kernel
//! dependent (ABI negotiated at runtime, `securityfs` mount state, whether
//! the LSM is even in the active list at boot). An operator who needs to
//! know "did this actually sandbox on *this* box" should run this binary and
//! read the two lines it prints, rather than trust a passing test suite.
//!
//! `cargo run --example confine_probe` does three things, in order:
//!   1. Calls [`postern_quarantine::sandbox::confine`] and prints the
//!      resulting [`postern_quarantine::sandbox::SandboxStatus`] (via its
//!      existing `Display` impl) — this is the kernel's own report of what
//!      Landlock enforcement it actually applied, not an assumption.
//!   2. Attempts one filesystem read (`std::fs::File::open("/etc/hostname")`)
//!      *after* confinement and prints whether the OS denied it.
//!   3. Attempts one filesystem write (`std::fs::File::create` in the temp
//!      dir) *after* confinement and prints whether the OS denied it —
//!      reads and writes are separate Landlock access rights, so both are
//!      probed.
//!
//! On Linux, when the status is `Unsandboxed`, it additionally prints the
//! kernel's active LSM list (`/sys/kernel/security/lsm`) if readable, so the
//! operator can see at a glance whether `landlock` is even compiled in /
//! enabled on this host (the exact host requirement is a kernel ≥ 5.13 built
//! with `CONFIG_SECURITY_LANDLOCK=y` and `landlock` in the active LSM list —
//! see this crate's README).
//!
//! Both outcomes are printed as-observed. `SandboxStatus::Unsandboxed` is a
//! valid, honestly-reported outcome (e.g. Landlock not in the active LSM
//! list, `securityfs` not mounted) — it is not a failure of this probe, and
//! this probe does not exit non-zero on it. The point is observability, not
//! asserting a particular result.

use postern_quarantine::sandbox::{self, SandboxStatus};

fn main() {
    let status = sandbox::confine();
    println!("SandboxStatus: {status}");

    match &status {
        SandboxStatus::Enforced { .. } => {
            println!("confine() reports fully enforced — expecting the filesystem open below to be DENIED.");
        }
        SandboxStatus::Partial { .. } => {
            println!(
                "confine() reports partial enforcement — the filesystem open below may or may not be denied \
                 depending on which access rights the kernel actually confined."
            );
        }
        SandboxStatus::Unsandboxed { .. } => {
            println!(
                "confine() reports UNSANDBOXED — expecting the filesystem open below to SUCCEED \
                 (no OS-level confinement is in effect on this host/kernel)."
            );
            // On Linux, show the kernel's own active-LSM list so the operator
            // can see whether `landlock` is even available on this host. This
            // is read-only observability, printed as-is; if securityfs isn't
            // mounted/readable, say so instead of guessing.
            #[cfg(target_os = "linux")]
            match std::fs::read_to_string("/sys/kernel/security/lsm") {
                Ok(lsms) => {
                    let lsms = lsms.trim();
                    println!("  active LSM list (/sys/kernel/security/lsm): {lsms}");
                    if lsms.split(',').any(|l| l == "landlock") {
                        println!(
                            "  -> 'landlock' IS in the active LSM list, yet confine() still \
                             reported Unsandboxed — check the status reason above."
                        );
                    } else {
                        println!(
                            "  -> 'landlock' is NOT in the active LSM list: this kernel was \
                             built without CONFIG_SECURITY_LANDLOCK or booted without landlock \
                             in the lsm= list. Host requirement: Linux >= 5.13 with \
                             CONFIG_SECURITY_LANDLOCK=y and landlock in the active LSM list."
                        );
                    }
                }
                Err(e) => println!(
                    "  could not read /sys/kernel/security/lsm ({e}) — securityfs not \
                     mounted or not readable; cannot show the active LSM list."
                ),
            }
        }
    }

    // Deliberately after confine(): this is the true end-to-end check —
    // did the kernel actually deny the open, not just did confine() claim
    // success. /etc/hostname is chosen because it's near-universally
    // present and readable by any user on a Linux host, so a denial here
    // can only be attributed to the sandbox, not to normal permissions.
    let path = "/etc/hostname";
    match std::fs::File::open(path) {
        Ok(_) => {
            println!("post-confine open({path}) SUCCEEDED — filesystem access was NOT denied.");
        }
        Err(e) => {
            println!("post-confine open({path}) FAILED: {e}");
            // EACCES (permission denied) is Landlock's signature; report it
            // explicitly so the operator doesn't have to know the errno by
            // heart, but don't editorialize beyond what the OS reported.
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                println!("  -> denied with PermissionDenied — consistent with Landlock (or another LSM) blocking the open.");
            } else {
                println!(
                    "  -> denied, but NOT with PermissionDenied (kind: {:?}) — likely not Landlock (e.g. the path itself is missing on this host).",
                    e.kind()
                );
            }
        }
    }

    // Write probe: reads and writes are distinct Landlock access rights
    // (ReadFile vs WriteFile/MakeReg), so probe both. Same honesty rules:
    // print what the OS actually did, nothing more.
    let tmp_path = std::env::temp_dir().join(format!(
        "postern-quarantine-confine-probe-{}",
        std::process::id()
    ));
    match std::fs::File::create(&tmp_path) {
        Ok(_) => {
            println!(
                "post-confine create({}) SUCCEEDED — filesystem writes were NOT denied.",
                tmp_path.display()
            );
            let _ = std::fs::remove_file(&tmp_path);
        }
        Err(e) => {
            println!("post-confine create({}) FAILED: {e}", tmp_path.display());
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                println!("  -> denied with PermissionDenied — consistent with Landlock (or another LSM) blocking the write.");
            } else {
                println!(
                    "  -> denied, but NOT with PermissionDenied (kind: {:?}) — likely not Landlock (e.g. a read-only temp dir).",
                    e.kind()
                );
            }
        }
    }
}
