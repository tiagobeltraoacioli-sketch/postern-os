//! Out-of-process office→PDF converter adapter — the previously-missing
//! convert half of the office quarantine path.
//!
//! This module produces the `FnOnce(&[u8]) -> Result<Vec<u8>, String>`
//! closure that [`crate::office::quarantine_office`] takes as its `convert`
//! argument, by spawning **unmodified LibreOffice**
//! (`soffice --headless --convert-to pdf`) as an external process.
//!
//! ## License position (why this is spawn, not link)
//!
//! LibreOffice is **MPL-2.0** — tolerated in this repo *only* as unmodified
//! aggregation (see `deny.toml`). This adapter honours that line strictly:
//! LibreOffice is a **user-installed external binary**, invoked via
//! [`std::process::Command`]. It is never linked, never vendored, never
//! forked, and no LibreOffice code (or Dangerzone code — Dangerzone is
//! **AGPL**, concept reimplemented only) appears in this crate. If
//! LibreOffice is not installed, the adapter fails closed with a clear
//! error; it never falls back to passing untrusted bytes through.
//!
//! ## What this adapter enforces, all fail-closed
//!
//! - **Executable resolution is explicit**: a configured path, or discovery
//!   of `soffice` on an injectable search path (defaults to `PATH`). No
//!   executable found ⇒ `Err`, before the untrusted bytes touch anything.
//! - **Fresh, isolated LibreOffice profile per run**: every invocation gets
//!   its own throwaway `-env:UserInstallation=` temp directory, so runs
//!   cannot see each other's state, a poisoned profile cannot persist, and
//!   the operator's real LibreOffice profile is never read or written.
//! - **Wall-clock timeout with kill-on-expiry**: a converter that hangs (a
//!   classic decompression/parse-loop DoS) is killed and reported as `Err`.
//! - **Output-size cap**: the produced PDF's size is checked (via file
//!   metadata, *before* reading it into memory) against a configurable cap;
//!   an oversized output is rejected unread.
//! - **Output magic check**: output that does not start with `%PDF-` is
//!   rejected (defense in depth — [`crate::office::quarantine_office`]
//!   re-checks the same thing at the pipeline seam).
//! - On **every** error path the original untrusted bytes are discarded —
//!   never returned, never partially copied into an output.
//!
//! ## What this adapter does NOT do — do not claim otherwise
//!
//! - **No Landlock/seccomp/namespace containment around the subprocess.**
//!   The only containment is the wall-clock kill, the output-size cap, and
//!   the fail-closed checks above. LibreOffice parses the hostile bytes
//!   with the invoking user's full privileges; a converter exploit runs as
//!   that user. Sandboxing the converter subprocess (the Dangerzone-shaped
//!   design in the crate docs) **still does not exist in this crate**.
//! - **On macOS and Windows there is no OS-level sandbox at all** — same
//!   honest position as the image path's [`crate::sandbox`].
//! - **Kill-on-expiry signals the direct child only.** LibreOffice's
//!   launcher can re-spawn itself (e.g. `oosplash` → `soffice.bin`); a
//!   grandchild that detaches from the killed child may survive the kill.
//!   Process-group/session kill is not implemented. The *result* is still
//!   fail-closed (the call returns `Err` on expiry), but "killed" must not
//!   be read as "the whole converter process tree is guaranteed gone".
//! - **No sanitisation of the converter's output** beyond the `%PDF-` magic
//!   and size cap: the converted PDF is still *untrusted* and must go
//!   through [`crate::pdf::quarantine_pdf`]'s render-and-rebuild —
//!   [`crate::office::quarantine_office`] does exactly that. Never treat
//!   this adapter's output as the cleaned artifact.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Default wall-clock budget for one conversion. Office→PDF of a legitimate
/// document is seconds; two minutes is generous headroom for slow machines
/// and first-run profile creation, while still bounding a hang.
pub const DEFAULT_CONVERT_TIMEOUT: Duration = Duration::from_secs(120);

/// Configuration for the LibreOffice converter adapter. Every knob has a
/// safe default; tests override `executable`/`search_path` to drive the
/// adapter against a stub script instead of a real LibreOffice.
#[derive(Debug, Clone)]
pub struct SofficeConfig {
    /// Explicit path to the `soffice` executable. `None` ⇒ discover via
    /// [`find_soffice`] on `search_path`. (On macOS, LibreOffice's standard
    /// install location — `/Applications/LibreOffice.app/Contents/MacOS/
    /// soffice` — is usually *not* on `PATH`; pass it here explicitly.)
    pub executable: Option<PathBuf>,
    /// Search path for discovery when `executable` is `None`. `None` ⇒ the
    /// process's `PATH` environment variable. Injectable so tests never
    /// depend on (or accidentally invoke) a real host LibreOffice.
    pub search_path: Option<OsString>,
    /// Wall-clock budget; on expiry the child is killed and the conversion
    /// fails closed. Default: [`DEFAULT_CONVERT_TIMEOUT`].
    pub timeout: Duration,
    /// Cap on the produced PDF's byte size, checked via file metadata
    /// before the file is read. Default: [`crate::MAX_INPUT_BYTES`] — the
    /// converted PDF is re-checked against that same cap when it enters
    /// [`crate::pdf::quarantine_pdf`], so a larger value here would only be
    /// rejected later anyway.
    pub max_output_bytes: u64,
}

impl Default for SofficeConfig {
    fn default() -> Self {
        SofficeConfig {
            executable: None,
            search_path: None,
            timeout: DEFAULT_CONVERT_TIMEOUT,
            max_output_bytes: crate::MAX_INPUT_BYTES as u64,
        }
    }
}

/// Discover a `soffice` executable on a `PATH`-shaped search path (the
/// process's own `PATH` when `search_path` is `None`). Returns the first
/// directory entry containing a file named `soffice`; `None` if there is
/// none. Deliberately simple and deterministic — no version probing, no
/// guessing at platform-specific install locations (callers that know a
/// non-`PATH` location pass [`SofficeConfig::executable`] explicitly).
pub fn find_soffice(search_path: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    let path_var = match search_path {
        Some(p) => p.to_os_string(),
        None => std::env::var_os("PATH")?,
    };
    for dir in std::env::split_paths(&path_var) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        let candidate = dir.join("soffice");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Factory: build the `convert` closure [`crate::office::quarantine_office`]
/// takes, backed by [`soffice_convert`] with the given config. The existing
/// injected-closure seam is untouched — this is just a ready-made thing to
/// inject.
///
/// ```no_run
/// use postern_quarantine::adapters::{soffice_converter, SofficeConfig};
/// use postern_quarantine::office::quarantine_office;
///
/// let untrusted: Vec<u8> = std::fs::read("suspicious.docx").unwrap();
/// let result = quarantine_office(
///     &untrusted,
///     soffice_converter(SofficeConfig::default()),
///     |_pdf| Err("inject a renderer here (e.g. feature `render-hayro`)".into()),
/// );
/// # let _ = result;
/// ```
pub fn soffice_converter(
    config: SofficeConfig,
) -> impl FnOnce(&[u8]) -> Result<Vec<u8>, String> {
    move |input| soffice_convert(&config, input)
}

/// Temp working directory that is removed (best-effort) on drop, so every
/// exit path — including early `?` returns — cleans up the untrusted input
/// copy, the throwaway profile, and the converter output.
struct WorkDir(PathBuf);

impl Drop for WorkDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Monotonic per-process counter so two conversions in the same nanosecond
/// (or on a coarse clock) still get distinct working directories.
static WORKDIR_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Encode a filesystem path as a `file://` URL for `-env:UserInstallation=`.
/// Minimal percent-encoding: bytes outside the URL-safe set are `%XX`-encoded
/// (temp-dir paths are plain ASCII on the supported platforms, but a space or
/// non-ASCII byte must not silently corrupt the argument).
fn file_url(path: &Path) -> String {
    let mut url = String::from("file://");
    for &b in path.to_string_lossy().as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'/' | b'.' | b'_' | b'-' | b'~' => {
                url.push(b as char)
            }
            _ => url.push_str(&format!("%{b:02X}")),
        }
    }
    url
}

/// Convert untrusted office bytes to PDF bytes by spawning unmodified
/// LibreOffice out-of-process. See the module docs for the full honest list
/// of what is and is not enforced (fail-closed errors, fresh profile,
/// wall-clock kill, output cap — but **no** Landlock/seccomp around the
/// subprocess, and no sanitisation of the output beyond magic + size: the
/// returned PDF is still untrusted and must be render-rebuilt).
///
/// Returns the produced PDF bytes on success; a human-readable error string
/// (the shape [`crate::office::quarantine_office`]'s `convert` seam expects)
/// on every failure.
pub fn soffice_convert(config: &SofficeConfig, input: &[u8]) -> Result<Vec<u8>, String> {
    // Resolve the executable BEFORE touching the untrusted bytes.
    let soffice = match &config.executable {
        Some(p) => {
            if !p.is_file() {
                return Err(format!(
                    "configured soffice executable does not exist: {}",
                    p.display()
                ));
            }
            p.clone()
        }
        None => find_soffice(config.search_path.as_deref()).ok_or_else(|| {
            "no `soffice` executable found on the search path — install LibreOffice \
             or set SofficeConfig::executable explicitly (fail-closed: the untrusted \
             bytes were not passed anywhere)"
                .to_string()
        })?,
    };

    // Unique throwaway working directory: input copy + fresh profile + outdir.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = WORKDIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    let work = std::env::temp_dir().join(format!(
        "postern-quarantine-soffice-{}-{nanos}-{seq}",
        std::process::id()
    ));
    std::fs::create_dir(&work)
        .map_err(|e| format!("could not create converter working dir: {e}"))?;
    let work = WorkDir(work); // from here on, every exit path cleans up

    let profile_dir = work.0.join("profile");
    let out_dir = work.0.join("out");
    let input_path = work.0.join("input"); // extension-less: forces content-based
                                           // type detection; output becomes input.pdf
    std::fs::create_dir(&profile_dir)
        .and_then(|()| std::fs::create_dir(&out_dir))
        .and_then(|()| std::fs::write(&input_path, input))
        .map_err(|e| format!("could not stage converter working files: {e}"))?;

    let mut child = Command::new(&soffice)
        .arg(format!("-env:UserInstallation={}", file_url(&profile_dir)))
        .arg("--headless")
        .arg("--norestore")
        .arg("--convert-to")
        .arg("pdf")
        .arg("--outdir")
        .arg(&out_dir)
        .arg(&input_path)
        .stdin(Stdio::null())
        // Deliberately discarded rather than piped: an unread pipe filled by
        // a chatty/hostile child would deadlock the wait loop below.
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("could not spawn {}: {e}", soffice.display()))?;

    // Wall-clock wait with kill-on-expiry. (Caveat: kill() signals the direct
    // child only — see the module docs on grandchildren.)
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if start.elapsed() >= config.timeout {
                    let _ = child.kill();
                    let _ = child.wait(); // reap; ignore the post-kill status
                    return Err(format!(
                        "converter exceeded the {:?} wall-clock timeout and was killed \
                         (fail-closed; note: only the direct child is signalled)",
                        config.timeout
                    ));
                }
                std::thread::sleep(Duration::from_millis(15));
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("could not wait on the converter process: {e}"));
            }
        }
    };

    if !status.success() {
        return Err(format!(
            "converter exited unsuccessfully ({status}) — refusing to look for output"
        ));
    }

    let out_path = out_dir.join("input.pdf");
    let meta = std::fs::metadata(&out_path).map_err(|e| {
        format!(
            "converter exited successfully but produced no {} ({e})",
            out_path.display()
        )
    })?;
    // Size cap FIRST, from metadata — an oversized output is never read.
    if meta.len() > config.max_output_bytes {
        return Err(format!(
            "converter output is {} bytes (cap {}) — rejected unread",
            meta.len(),
            config.max_output_bytes
        ));
    }
    let bytes = std::fs::read(&out_path)
        .map_err(|e| format!("could not read the converter output: {e}"))?;
    if !bytes.starts_with(b"%PDF-") {
        return Err(
            "converter output does not start with the %PDF- magic — refusing to \
             return it"
                .to_string(),
        );
    }
    Ok(bytes)
    // `work` drops here (and on every earlier error return): best-effort
    // removal of the input copy, profile, and output.
}

// The stub-driven tests are Unix-only: they exercise the adapter against
// executable `#!/bin/sh` scripts, which need Unix exec semantics + mode
// bits. That gates the *tests*, not the adapter — the adapter code above is
// portable std. (This repo's runners are macOS/Linux; a Windows-native test
// double has simply not been written, honestly.)
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::office::quarantine_office;
    use crate::pdf::{rebuild_pdf_from_pages, PageRaster};
    use std::os::unix::fs::PermissionsExt;

    /// Per-test scratch dir (cleaned by the returned guard's Drop).
    fn scratch(tag: &str) -> WorkDir {
        let dir = std::env::temp_dir().join(format!(
            "postern-quarantine-adapter-test-{tag}-{}-{}",
            std::process::id(),
            WORKDIR_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        WorkDir(dir)
    }

    /// Write an executable stub script standing in for `soffice`.
    fn write_stub(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        // Every stub asserts the adapter's own contract: a fresh
        // -env:UserInstallation= profile argument must be present (exit 9
        // otherwise), and the --outdir value is parsed the way the real
        // soffice CLI would.
        let script = format!(
            "#!/bin/sh\n\
             case \"$*\" in *-env:UserInstallation=file://*) ;; *) exit 9 ;; esac\n\
             out=\"\"\n\
             prev=\"\"\n\
             for a in \"$@\"; do\n\
               [ \"$prev\" = \"--outdir\" ] && out=\"$a\"\n\
               prev=\"$a\"\n\
             done\n\
             [ -n \"$out\" ] || exit 8\n\
             {body}\n"
        );
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    /// A real, minimal, crate-built PDF (via the crate's own emitter) for
    /// the good-path stub to emit — so the "converter output" the adapter
    /// accepts is exactly the kind of PDF the rest of the pipeline handles.
    fn fixture_pdf() -> Vec<u8> {
        let n = (3 * 2 * 3) as usize;
        let rgb8: Vec<u8> = (0..n).map(|i| (i % 7) as u8).collect();
        rebuild_pdf_from_pages(&[PageRaster::new(3, 2, rgb8).unwrap()]).unwrap()
    }

    fn raster(width: u32, height: u32, seed: u8) -> PageRaster {
        let n = (width * height * 3) as usize;
        let rgb8: Vec<u8> = (0..n).map(|i| seed.wrapping_add((i % 7) as u8)).collect();
        PageRaster::new(width, height, rgb8).unwrap()
    }

    /// A tainted fake OOXML input (correct ZIP magic + payload markers) for
    /// the end-to-end test; the stub never actually parses it.
    fn tainted_ooxml_input() -> Vec<u8> {
        let mut v = crate::office::OOXML_ZIP_MAGIC.to_vec();
        v.extend_from_slice(b"vbaProject.bin EVIL_MACRO_MARKER");
        v
    }

    /// Generous timeout for the non-hang stubs: macOS scans a newly-written
    /// executable on its first exec (XProtect/Gatekeeper), which under a
    /// parallel test run can stall a trivial `#!/bin/sh` stub for seconds —
    /// these tests assert the adapter's behavior, not its speed, so the
    /// budget only needs to bound a genuine hang. The dedicated
    /// kill-on-expiry test below uses its own short budget and bounds
    /// elapsed time itself.
    const STUB_TIMEOUT: Duration = Duration::from_secs(60);

    fn config_for(stub: PathBuf) -> SofficeConfig {
        SofficeConfig {
            executable: Some(stub),
            timeout: STUB_TIMEOUT,
            ..SofficeConfig::default()
        }
    }

    #[test]
    fn good_stub_round_trips_a_crate_built_pdf() {
        let dir = scratch("good");
        let fixture_path = dir.0.join("fixture.pdf");
        let fixture = fixture_pdf();
        std::fs::write(&fixture_path, &fixture).unwrap();
        let stub = write_stub(
            &dir.0,
            "soffice",
            &format!("cp '{}' \"$out/input.pdf\"", fixture_path.display()),
        );

        let out = soffice_convert(&config_for(stub), b"fake office bytes").unwrap();
        assert_eq!(out, fixture, "adapter must return the converter's PDF verbatim");
        assert!(out.starts_with(b"%PDF-"));
        // …and it parses, with the fixture's page count.
        let doc = lopdf::Document::load_mem(&out).unwrap();
        assert_eq!(doc.get_pages().len(), 1);
    }

    #[test]
    fn every_run_gets_a_fresh_isolated_profile() {
        let dir = scratch("profile");
        let recorder = dir.0.join("recorded-args.txt");
        let fixture_path = dir.0.join("fixture.pdf");
        std::fs::write(&fixture_path, fixture_pdf()).unwrap();
        // The stub records its full argv (one line per run) before succeeding.
        let stub = write_stub(
            &dir.0,
            "soffice",
            &format!(
                "echo \"$@\" >> '{}'\ncp '{}' \"$out/input.pdf\"",
                recorder.display(),
                fixture_path.display()
            ),
        );

        let cfg = config_for(stub);
        soffice_convert(&cfg, b"run one").unwrap();
        soffice_convert(&cfg, b"run two").unwrap();

        let recorded = std::fs::read_to_string(&recorder).unwrap();
        let profiles: Vec<&str> = recorded
            .lines()
            .map(|line| {
                line.split_whitespace()
                    .find(|a| a.starts_with("-env:UserInstallation="))
                    .expect("every run must pass -env:UserInstallation=")
            })
            .collect();
        assert_eq!(profiles.len(), 2);
        assert_ne!(
            profiles[0], profiles[1],
            "two runs must never share a LibreOffice profile"
        );
        // Both runs must also have requested headless PDF conversion.
        for line in recorded.lines() {
            assert!(line.contains("--headless"));
            assert!(line.contains("--convert-to pdf"));
        }
    }

    #[test]
    fn garbage_output_is_rejected_fail_closed() {
        let dir = scratch("garbage");
        let stub = write_stub(
            &dir.0,
            "soffice",
            "printf 'not a pdf at all' > \"$out/input.pdf\"",
        );
        let err = soffice_convert(&config_for(stub), b"fake office bytes").unwrap_err();
        assert!(err.contains("%PDF-"), "error must name the magic check: {err}");
    }

    #[test]
    fn nonzero_exit_is_rejected_fail_closed() {
        let dir = scratch("exit");
        let stub = write_stub(&dir.0, "soffice", "exit 3");
        let err = soffice_convert(&config_for(stub), b"fake office bytes").unwrap_err();
        assert!(err.contains("unsuccessfully"), "error must name the exit status: {err}");
    }

    #[test]
    fn missing_output_after_zero_exit_is_rejected_fail_closed() {
        let dir = scratch("noout");
        let stub = write_stub(&dir.0, "soffice", "exit 0");
        let err = soffice_convert(&config_for(stub), b"fake office bytes").unwrap_err();
        assert!(err.contains("no"), "error must say no output was produced: {err}");
    }

    #[test]
    fn hang_past_the_timeout_is_killed_and_rejected() {
        let dir = scratch("hang");
        let stub = write_stub(&dir.0, "soffice", "sleep 30");
        let cfg = SofficeConfig {
            executable: Some(stub),
            timeout: Duration::from_millis(300),
            ..SofficeConfig::default()
        };
        let start = Instant::now();
        let err = soffice_convert(&cfg, b"fake office bytes").unwrap_err();
        assert!(err.contains("timeout"), "error must name the timeout: {err}");
        assert!(
            start.elapsed() < Duration::from_secs(25),
            "kill-on-expiry must not wait out the child's 30s sleep (a few seconds \
             of macOS first-exec scanning latency are tolerated; sleeping out the \
             full 30s is not)"
        );
    }

    #[test]
    fn oversized_output_is_rejected_unread() {
        let dir = scratch("oversize");
        // 8 KiB of zeros — over the 1 KiB cap below; content is irrelevant
        // because the size check (from metadata) fires before any read.
        let stub = write_stub(
            &dir.0,
            "soffice",
            "dd if=/dev/zero of=\"$out/input.pdf\" bs=1024 count=8 2>/dev/null",
        );
        let cfg = SofficeConfig {
            executable: Some(stub),
            timeout: STUB_TIMEOUT,
            max_output_bytes: 1024,
            ..SofficeConfig::default()
        };
        let err = soffice_convert(&cfg, b"fake office bytes").unwrap_err();
        assert!(err.contains("cap"), "error must name the size cap: {err}");
    }

    #[test]
    fn missing_executable_fails_closed_without_touching_the_input() {
        let cfg = SofficeConfig {
            executable: Some(PathBuf::from("/nonexistent/definitely/not/soffice")),
            ..SofficeConfig::default()
        };
        assert!(soffice_convert(&cfg, b"fake office bytes").is_err());

        // Discovery variant: an empty search path finds nothing.
        let empty_dir = scratch("empty");
        let cfg = SofficeConfig {
            executable: None,
            search_path: Some(empty_dir.0.clone().into_os_string()),
            ..SofficeConfig::default()
        };
        let err = soffice_convert(&cfg, b"fake office bytes").unwrap_err();
        assert!(err.contains("fail-closed"), "{err}");
    }

    #[test]
    fn discovery_finds_a_stub_on_the_injected_search_path() {
        let dir = scratch("discover");
        let fixture_path = dir.0.join("fixture.pdf");
        std::fs::write(&fixture_path, fixture_pdf()).unwrap();
        write_stub(
            &dir.0,
            "soffice",
            &format!("cp '{}' \"$out/input.pdf\"", fixture_path.display()),
        );

        let found = find_soffice(Some(dir.0.as_os_str())).expect("stub must be discovered");
        assert_eq!(found, dir.0.join("soffice"));

        // And the discovered path works end-to-end through the factory.
        let cfg = SofficeConfig {
            executable: None,
            search_path: Some(dir.0.clone().into_os_string()),
            timeout: STUB_TIMEOUT,
            ..SofficeConfig::default()
        };
        let out = soffice_converter(cfg)(b"fake office bytes").unwrap();
        assert!(out.starts_with(b"%PDF-"));
    }

    /// End-to-end through the REAL pipeline seam: the adapter closure is
    /// injected into `quarantine_office` exactly as a caller would, and the
    /// final artifact keeps the flat-PDF banned-token guarantees.
    #[test]
    fn adapter_through_quarantine_office_keeps_the_banned_token_guarantees() {
        let dir = scratch("e2e");
        let fixture_path = dir.0.join("fixture.pdf");
        std::fs::write(&fixture_path, fixture_pdf()).unwrap();
        let stub = write_stub(
            &dir.0,
            "soffice",
            &format!("cp '{}' \"$out/input.pdf\"", fixture_path.display()),
        );

        let input = tainted_ooxml_input();
        let out = quarantine_office(
            &input,
            soffice_converter(config_for(stub)),
            |pdf_bytes| {
                assert!(pdf_bytes.starts_with(b"%PDF-"));
                Ok(vec![raster(4, 3, 10), raster(2, 5, 90)])
            },
        )
        .unwrap();

        let doc = lopdf::Document::load_mem(&out).unwrap();
        assert_eq!(doc.get_pages().len(), 2);
        for forbidden in [
            b"/Info".as_slice(),
            b"/ID",
            b"/Metadata",
            b"/JavaScript",
            b"/OpenAction",
            b"/EmbeddedFiles",
            b"/Names",
            b"/AA",
        ] {
            assert!(
                !out.windows(forbidden.len()).any(|w| w == forbidden),
                "forbidden token {:?} found in the final artifact",
                String::from_utf8_lossy(forbidden)
            );
        }
        assert!(
            !out.windows(17).any(|w| w == b"EVIL_MACRO_MARKER"),
            "input payload leaked into the final artifact"
        );
    }

    /// ENVIRONMENT-GATED (`#[ignore]`), honestly labelled: drives the
    /// adapter against a REAL user-installed LibreOffice. Not run in CI or
    /// on hosts without one — run explicitly with
    /// `cargo test -p postern-quarantine -- --ignored` on a machine where
    /// `soffice` is on `PATH` (or edit the config below). This is the only
    /// test here that proves the real-tool glue (argument shape, output
    /// naming) rather than the adapter's own fail-closed logic.
    #[test]
    #[ignore = "requires a real LibreOffice install (external binary, environment-gated)"]
    fn live_real_soffice_converts_plain_text_to_pdf() {
        let cfg = SofficeConfig::default();
        assert!(
            cfg.executable.is_some() || find_soffice(None).is_some(),
            "no soffice on PATH — install LibreOffice or set SofficeConfig::executable"
        );
        // Plain text: LibreOffice content-detects it and prints it to PDF.
        // (The office *pipeline* would refuse non-office magic before the
        // converter — this drives the adapter directly, which is exactly
        // the glue this live test exists to prove.)
        let out = soffice_convert(&cfg, b"postern-quarantine live adapter test\n").unwrap();
        assert!(out.starts_with(b"%PDF-"));
    }
}
