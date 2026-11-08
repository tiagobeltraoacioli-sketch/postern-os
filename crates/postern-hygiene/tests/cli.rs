//! Integration test for the `postern-hygiene` binary CLI (`scrub <file>`).
//! Drives the actual built binary via `std::process::Command` — this is a
//! black-box test of the real executable, not the library.

use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::Command;

/// Path to the compiled `postern-hygiene` binary, provided by Cargo for
/// integration tests (`CARGO_BIN_EXE_<name>`).
fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_postern-hygiene"))
}

/// A fresh scratch directory for this test run, under the project's
/// `target/` (so it's cleaned by `cargo clean` and never touches the
/// original fixture even if a test goes wrong).
fn scratch_dir(name: &str) -> PathBuf {
    let mut dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    dir.push(format!("postern-hygiene-cli-{name}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Build a minimal OOXML (.docx-shaped) zip with a planted PII string in
/// `docProps/core.xml`, matching the shape `scrub_ooxml` expects.
fn build_ooxml_fixture(pii: &str) -> Vec<u8> {
    use std::io::Cursor;
    let mut buf = Vec::new();
    let mut w = zip::ZipWriter::new(Cursor::new(&mut buf));
    let o = zip::write::SimpleFileOptions::default();
    w.start_file("[Content_Types].xml", o).unwrap();
    w.write_all(b"<Types/>").unwrap();
    w.start_file("docProps/core.xml", o).unwrap();
    w.write_all(
        format!(
            r#"<cp:coreProperties><dc:creator>{pii}</dc:creator><dcterms:created>2020-01-01</dcterms:created></cp:coreProperties>"#
        )
        .as_bytes(),
    )
    .unwrap();
    w.start_file("docProps/app.xml", o).unwrap();
    w.write_all(format!("<Properties><Company>{pii} Corp</Company></Properties>").as_bytes())
        .unwrap();
    w.start_file("word/document.xml", o).unwrap();
    w.write_all(b"<w:document>the actual content survives</w:document>").unwrap();
    w.finish().unwrap();
    buf
}

#[test]
fn scrub_ooxml_fixture_strips_planted_pii_and_reports() {
    const PII: &str = "Alice Confidential Secret";

    let dir = scratch_dir("ooxml-ok");
    let input_path = dir.join("fixture.docx");
    let original_bytes = build_ooxml_fixture(PII);
    fs::write(&input_path, &original_bytes).unwrap();

    let output = Command::new(bin())
        .arg("scrub")
        .arg(&input_path)
        .output()
        .expect("failed to run postern-hygiene binary");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        output.status.success(),
        "expected exit 0 on a valid fixture; stdout={stdout}\nstderr={stderr}"
    );

    // Report contents: the detected Format and cleaned/passed_through lines.
    assert!(stdout.contains("format: OOXML/ODF"), "stdout should print the detected format: {stdout}");
    assert!(stdout.contains("cleaned"), "stdout should print cleaned entries: {stdout}");
    assert!(
        stderr.contains("passed_through"),
        "stderr should print the passed_through summary line: {stderr}"
    );

    // `.scrubbed` sibling exists and no longer contains the planted PII.
    // The output is a real (Deflated) zip package, so check both the raw
    // bytes (belt) AND the decompressed XML parts (suspenders) rather than
    // scanning compressed bytes as if they were plain text.
    let scrubbed_path = PathBuf::from(format!("{}.scrubbed", input_path.display()));
    assert!(scrubbed_path.exists(), "expected {scrubbed_path:?} to be created");
    let scrubbed_bytes = fs::read(&scrubbed_path).unwrap();
    assert!(
        !scrubbed_bytes.windows(PII.len()).any(|w| w == PII.as_bytes()),
        "planted PII must not survive the scrub (raw bytes)"
    );

    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(&scrubbed_bytes)).expect(".scrubbed output must be a valid zip");
    let mut core_xml = String::new();
    zip.by_name("docProps/core.xml").unwrap().read_to_string(&mut core_xml).unwrap();
    assert!(!core_xml.contains(PII), "planted PII must not survive in docProps/core.xml");

    // Content is preserved (a scrub isn't a shredder).
    let mut doc_xml = String::new();
    zip.by_name("word/document.xml").unwrap().read_to_string(&mut doc_xml).unwrap();
    assert!(doc_xml.contains("the actual content survives"), "document content must be preserved");

    // The ORIGINAL input file must be completely untouched.
    let input_after = fs::read(&input_path).unwrap();
    assert_eq!(input_after, original_bytes, "input file must never be overwritten");
    let mut orig_zip = zip::ZipArchive::new(std::io::Cursor::new(&input_after)).unwrap();
    let mut orig_core_xml = String::new();
    orig_zip.by_name("docProps/core.xml").unwrap().read_to_string(&mut orig_core_xml).unwrap();
    assert!(
        orig_core_xml.contains(PII),
        "sanity: original still has the PII (we scrubbed a copy, not the input)"
    );
}

#[test]
fn scrub_jpeg_fixture_strips_exif_pii() {
    // A JPEG whose APP1/EXIF payload carries a planted marker string.
    const PII: &str = "GPS-Owner-Bob";
    let mut jpeg: Vec<u8> = vec![0xFF, 0xD8]; // SOI
    let exif_payload = format!("Exif\0\0{PII}");
    let seg_len = (exif_payload.len() + 2) as u16; // includes the 2 length bytes
    jpeg.push(0xFF);
    jpeg.push(0xE1); // APP1
    jpeg.extend_from_slice(&seg_len.to_be_bytes());
    jpeg.extend_from_slice(exif_payload.as_bytes());
    jpeg.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x02]); // SOS, no payload
    jpeg.extend_from_slice(&[0x12, 0x34]); // fake entropy-coded scan
    jpeg.extend_from_slice(&[0xFF, 0xD9]); // EOI

    let dir = scratch_dir("jpeg-ok");
    let input_path = dir.join("fixture.jpg");
    fs::write(&input_path, &jpeg).unwrap();

    let output = Command::new(bin()).arg("scrub").arg(&input_path).output().unwrap();
    assert!(output.status.success(), "stderr={}", String::from_utf8_lossy(&output.stderr));
    assert!(String::from_utf8_lossy(&output.stdout).contains("format: JPEG"));

    let scrubbed_path = PathBuf::from(format!("{}.scrubbed", input_path.display()));
    let scrubbed_bytes = fs::read(&scrubbed_path).unwrap();
    assert!(
        !scrubbed_bytes.windows(PII.len()).any(|w| w == PII.as_bytes()),
        "planted EXIF PII must not survive the scrub"
    );

    let input_after = fs::read(&input_path).unwrap();
    assert_eq!(input_after, jpeg, "input file must never be overwritten");
}

#[test]
fn scrub_rejects_garbage_unknown_format_with_nonzero_exit() {
    let dir = scratch_dir("garbage");
    let input_path = dir.join("not-a-real-document.bin");
    let garbage = b"this is not zip, pdf, jpeg, or png data at all, just junk bytes 0123456789";
    fs::write(&input_path, garbage).unwrap();

    let output = Command::new(bin()).arg("scrub").arg(&input_path).output().unwrap();
    assert!(!output.status.success(), "garbage input must exit non-zero");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("error:"), "stderr should carry a clear error message: {stderr}");
    assert!(stderr.to_lowercase().contains("format"), "error should mention the format problem: {stderr}");

    // No `.scrubbed` sibling should be written on failure.
    let scrubbed_path = PathBuf::from(format!("{}.scrubbed", input_path.display()));
    assert!(!scrubbed_path.exists(), "no output should be written when the scrub fails");

    // Original garbage file is untouched.
    let input_after = fs::read(&input_path).unwrap();
    assert_eq!(input_after, garbage);
}

#[test]
fn missing_args_exit_nonzero_with_usage() {
    let output = Command::new(bin()).output().unwrap();
    assert!(!output.status.success(), "no args must exit non-zero");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("usage:"), "stderr should print usage: {stderr}");
}

#[test]
fn missing_file_arg_after_scrub_exits_nonzero() {
    let output = Command::new(bin()).arg("scrub").output().unwrap();
    assert!(!output.status.success(), "'scrub' with no file must exit non-zero");
}

#[test]
fn unknown_subcommand_exits_nonzero() {
    let output = Command::new(bin()).arg("not-a-real-subcommand").output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown subcommand"), "stderr={stderr}");
}

#[test]
fn nonexistent_input_file_exits_nonzero() {
    let dir = scratch_dir("nofile");
    let missing = dir.join("does-not-exist.docx");
    let output = Command::new(bin()).arg("scrub").arg(&missing).output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cannot read"), "stderr={stderr}");
}

// ── `check` (dry-run) ────────────────────────────────────────────────────────

/// Sorted file names currently in `dir` — used to prove `check` writes nothing.
fn dir_listing(dir: &PathBuf) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn check_on_pii_docx_exits_1_names_parts_and_writes_nothing() {
    const PII: &str = "Alice Confidential Secret";
    let dir = scratch_dir("check-dirty");
    let input_path = dir.join("dirty.docx");
    let original_bytes = build_ooxml_fixture(PII);
    fs::write(&input_path, &original_bytes).unwrap();
    let before = dir_listing(&dir);

    let output = Command::new(bin()).arg("check").arg(&input_path).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    assert_eq!(
        output.status.code(),
        Some(1),
        "a file that a scrub would change must exit 1; stdout={stdout}\nstderr={stderr}"
    );
    // The report must name the parts that would be cleaned.
    assert!(stdout.contains("docProps/core.xml"), "check must name core.xml: {stdout}");
    assert!(stdout.contains("docProps/app.xml"), "check must name app.xml: {stdout}");
    assert!(stdout.contains("format: OOXML/ODF"), "check must print the format: {stdout}");

    // Dry run: NO file created, input byte-identical.
    assert_eq!(dir_listing(&dir), before, "check must never create or remove files");
    assert_eq!(fs::read(&input_path).unwrap(), original_bytes, "check must never modify the input");
    let scrubbed_path = PathBuf::from(format!("{}.scrubbed", input_path.display()));
    assert!(!scrubbed_path.exists(), "check must not write a .scrubbed sibling");
}

#[test]
fn check_on_scrubbed_output_exits_0() {
    const PII: &str = "Alice Confidential Secret";
    let dir = scratch_dir("check-clean");
    let input_path = dir.join("dirty.docx");
    fs::write(&input_path, build_ooxml_fixture(PII)).unwrap();

    // First actually scrub it...
    let scrub_out = Command::new(bin()).arg("scrub").arg(&input_path).output().unwrap();
    assert!(scrub_out.status.success(), "stderr={}", String::from_utf8_lossy(&scrub_out.stderr));
    let scrubbed_path = PathBuf::from(format!("{}.scrubbed", input_path.display()));
    let scrubbed_bytes = fs::read(&scrubbed_path).unwrap();
    let before = dir_listing(&dir);

    // ...then `check` the scrubbed output: already clean -> exit 0.
    let output = Command::new(bin()).arg("check").arg(&scrubbed_path).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_eq!(
        output.status.code(),
        Some(0),
        "the output of `scrub` must check as clean (change-accurate report); stdout={stdout}\nstderr={stderr}"
    );
    assert!(stdout.contains("nothing to strip"), "clean report expected: {stdout}");
    assert!(stdout.contains("clean:"), "clean verdict line expected: {stdout}");

    // Still a dry run: nothing new on disk, checked file untouched.
    assert_eq!(dir_listing(&dir), before, "check must never create files");
    assert_eq!(fs::read(&scrubbed_path).unwrap(), scrubbed_bytes);
}

#[test]
fn check_on_garbage_exits_2_and_writes_nothing() {
    let dir = scratch_dir("check-garbage");
    let input_path = dir.join("junk.bin");
    let garbage = b"neither zip nor pdf nor jpeg nor png -- just junk bytes 9876543210";
    fs::write(&input_path, garbage).unwrap();
    let before = dir_listing(&dir);

    let output = Command::new(bin()).arg("check").arg(&input_path).output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "unknown format must be an error (exit 2), never 'clean' and never the dirty exit 1"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("error:"), "stderr should carry a clear error: {stderr}");

    assert_eq!(dir_listing(&dir), before, "check must never create files, even on error");
    assert_eq!(fs::read(&input_path).unwrap(), garbage);
}

#[test]
fn check_missing_file_arg_exits_nonzero_with_usage() {
    let output = Command::new(bin()).arg("check").output().unwrap();
    assert!(!output.status.success(), "'check' with no file must exit non-zero");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("usage:"), "stderr should print usage: {stderr}");
    assert!(stderr.contains("check <file>"), "usage should document the check subcommand: {stderr}");
}

#[test]
fn check_nonexistent_file_exits_2() {
    let dir = scratch_dir("check-nofile");
    let missing = dir.join("does-not-exist.docx");
    let output = Command::new(bin()).arg("check").arg(&missing).output().unwrap();
    assert_eq!(output.status.code(), Some(2), "unreadable file is an error, not clean/dirty");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cannot read"), "stderr={stderr}");
}

// ── `--json` report output ───────────────────────────────────────────────────
//
// Honest-report contract carried into JSON: `clean` is true iff BOTH
// `cleaned` and `passed_through` are empty. A non-empty `passed_through`
// means the output is NOT fully scrubbed (e.g. embedded EMF/GIF/TIFF media
// keeps its own metadata) and must force `clean: false`.

/// Run the binary with `args` (and optional stdin bytes), returning
/// (exit code, stdout bytes, stderr string).
fn run_bin(args: &[&str], stdin: Option<&[u8]>) -> (Option<i32>, Vec<u8>, String) {
    use std::process::Stdio;
    let mut cmd = Command::new(bin());
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    if let Some(bytes) = stdin {
        cmd.stdin(Stdio::piped());
        let mut child = cmd.spawn().expect("failed to spawn postern-hygiene");
        child.stdin.take().unwrap().write_all(bytes).unwrap();
        let out = child.wait_with_output().unwrap();
        (out.status.code(), out.stdout, String::from_utf8_lossy(&out.stderr).into_owned())
    } else {
        cmd.stdin(Stdio::null());
        let out = cmd.output().unwrap();
        (out.status.code(), out.stdout, String::from_utf8_lossy(&out.stderr).into_owned())
    }
}

#[test]
fn check_json_on_dirty_fixture_exits_1_with_parsable_nonempty_cleaned() {
    const PII: &str = "Alice Confidential Secret";
    let dir = scratch_dir("json-check-dirty");
    let input_path = dir.join("dirty.docx");
    fs::write(&input_path, build_ooxml_fixture(PII)).unwrap();
    let before = dir_listing(&dir);

    let (code, stdout, stderr) =
        run_bin(&["check", "--json", input_path.to_str().unwrap()], None);
    assert_eq!(code, Some(1), "dirty file must still exit 1 with --json; stderr={stderr}");

    // Exactly ONE JSON object on stdout, and it must actually parse.
    let stdout = String::from_utf8(stdout).expect("--json stdout must be UTF-8");
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("--json stdout must parse as one JSON object");
    assert_eq!(v["format"], "ooxml", "stable machine token, not the human label: {v}");
    let cleaned = v["cleaned"].as_array().expect("cleaned must be an array");
    assert!(!cleaned.is_empty(), "dirty fixture must report a non-empty cleaned list: {v}");
    assert!(
        cleaned.iter().any(|c| c.as_str().unwrap().contains("docProps/core.xml")),
        "cleaned must name core.xml: {v}"
    );
    assert!(v["passed_through"].is_array(), "passed_through must be an array: {v}");
    assert_eq!(v["clean"], false, "dirty file must report clean:false: {v}");
    assert!(v.get("out_path").is_none(), "check never writes, so no out_path: {v}");

    // Still a dry run.
    assert_eq!(dir_listing(&dir), before, "check --json must never create files");
}

#[test]
fn check_json_on_scrubbed_fixture_exits_0_with_clean_true() {
    const PII: &str = "Alice Confidential Secret";
    let dir = scratch_dir("json-check-clean");
    let input_path = dir.join("dirty.docx");
    fs::write(&input_path, build_ooxml_fixture(PII)).unwrap();

    let scrub_out = Command::new(bin()).arg("scrub").arg(&input_path).output().unwrap();
    assert!(scrub_out.status.success());
    let scrubbed_path = PathBuf::from(format!("{}.scrubbed", input_path.display()));

    let (code, stdout, stderr) =
        run_bin(&["check", "--json", scrubbed_path.to_str().unwrap()], None);
    assert_eq!(code, Some(0), "scrubbed output must check clean with --json; stderr={stderr}");

    let stdout = String::from_utf8(stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("must parse as JSON");
    assert_eq!(v["clean"], true, "already-scrubbed file must report clean:true: {v}");
    assert_eq!(v["cleaned"].as_array().unwrap().len(), 0, "nothing left to clean: {v}");
    assert_eq!(v["passed_through"].as_array().unwrap().len(), 0, "nothing passed through: {v}");
}

#[test]
fn scrub_json_on_file_reports_out_path() {
    const PII: &str = "Alice Confidential Secret";
    let dir = scratch_dir("json-scrub-file");
    let input_path = dir.join("dirty.docx");
    fs::write(&input_path, build_ooxml_fixture(PII)).unwrap();

    let (code, stdout, stderr) =
        run_bin(&["scrub", "--json", input_path.to_str().unwrap()], None);
    assert_eq!(code, Some(0), "scrub success keeps exit 0 with --json; stderr={stderr}");

    let stdout = String::from_utf8(stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("must parse as JSON");
    let out_path = v["out_path"].as_str().expect("scrub --json must report out_path");
    assert!(out_path.ends_with(".scrubbed"), "out_path={out_path}");
    assert!(PathBuf::from(out_path).exists(), "reported out_path must exist");
    assert!(!v["cleaned"].as_array().unwrap().is_empty(), "dirty input was cleaned: {v}");
    // JSON string escaping must round-trip the real filesystem path.
    assert_eq!(out_path, format!("{}.scrubbed", input_path.display()));
}

// ── stdin/stdout embed-hook mode (`scrub -` / `check -`) ────────────────────

#[test]
fn scrub_stdin_writes_scrubbed_bytes_to_stdout_that_recheck_clean() {
    const PII: &str = "Alice Confidential Secret";
    let fixture = build_ooxml_fixture(PII);

    let (code, stdout, stderr) = run_bin(&["scrub", "-"], Some(&fixture));
    assert_eq!(code, Some(0), "scrub - on a valid fixture must exit 0; stderr={stderr}");
    assert!(!stdout.is_empty(), "scrubbed bytes must land on stdout");
    assert!(
        !stdout.windows(PII.len()).any(|w| w == PII.as_bytes()),
        "planted PII must not survive the piped scrub"
    );
    // The whole report lives on stderr — stdout is document bytes ONLY.
    assert!(stderr.contains("format:"), "report must be on stderr: {stderr}");
    assert!(stderr.contains("passed_through"), "report must be on stderr: {stderr}");

    // stdout must be a valid document that re-checks as clean (also via stdin).
    let (recheck_code, _, recheck_err) = run_bin(&["check", "-"], Some(&stdout));
    assert_eq!(
        recheck_code,
        Some(0),
        "scrub - output must re-check clean; stderr={recheck_err}"
    );

    // Content survived the round-trip (a scrub isn't a shredder).
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(&stdout))
        .expect("scrub - stdout must be a valid zip");
    let mut doc_xml = String::new();
    zip.by_name("word/document.xml").unwrap().read_to_string(&mut doc_xml).unwrap();
    assert!(doc_xml.contains("the actual content survives"));
}

#[test]
fn scrub_stdin_json_puts_json_on_stderr_and_bytes_on_stdout() {
    const PII: &str = "Alice Confidential Secret";
    let fixture = build_ooxml_fixture(PII);

    let (code, stdout, stderr) = run_bin(&["scrub", "--json", "-"], Some(&fixture));
    assert_eq!(code, Some(0), "stderr={stderr}");
    // stdout carries the document, so the one JSON object goes to stderr.
    assert!(zip::ZipArchive::new(std::io::Cursor::new(&stdout)).is_ok(), "stdout must be the document");
    let v: serde_json::Value =
        serde_json::from_str(stderr.trim()).expect("scrub - --json must put one JSON object on stderr");
    assert_eq!(v["format"], "ooxml");
    assert_eq!(v["clean"], false, "dirty input was cleaned, so not already-clean: {v}");
    assert!(v.get("out_path").is_none(), "stdin mode writes no file, so no out_path: {v}");
}

#[test]
fn check_stdin_json_on_dirty_fixture_exits_1() {
    const PII: &str = "Alice Confidential Secret";
    let fixture = build_ooxml_fixture(PII);

    let (code, stdout, stderr) = run_bin(&["check", "--json", "-"], Some(&fixture));
    assert_eq!(code, Some(1), "dirty stdin document must exit 1; stderr={stderr}");
    let stdout = String::from_utf8(stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("must parse as JSON");
    assert_eq!(v["clean"], false);
    assert!(!v["cleaned"].as_array().unwrap().is_empty());
}

#[test]
fn malformed_stdin_exits_2_with_nothing_usable_on_stdout() {
    let garbage = b"neither zip nor pdf nor jpeg nor png -- piped junk 5551212";

    // scrub -: fail-closed, exit 2, and stdout must stay COMPLETELY empty —
    // an embedding pipeline must never receive partial/unscrubbed bytes.
    let (code, stdout, stderr) = run_bin(&["scrub", "-"], Some(garbage));
    assert_eq!(code, Some(2), "unparsable stdin is an error, never 'clean'; stderr={stderr}");
    assert!(stdout.is_empty(), "nothing usable may land on stdout on error");
    assert!(stderr.contains("error:"), "stderr should carry a clear error: {stderr}");

    // check - --json: same contract; no JSON object is emitted on the error path.
    let (code, stdout, stderr) = run_bin(&["check", "--json", "-"], Some(garbage));
    assert_eq!(code, Some(2));
    assert!(stdout.is_empty(), "no JSON on the error path — exit 2 means stdout is unusable");
    assert!(stderr.contains("error:"), "stderr={stderr}");
}

#[test]
fn human_output_without_json_is_unchanged_on_file_paths() {
    // Guard the byte-compatibility promise: the non---json file-mode report
    // keeps today's exact shape (format:/cleaned/passed_through/wrote lines).
    const PII: &str = "Alice Confidential Secret";
    let dir = scratch_dir("compat-human");
    let input_path = dir.join("dirty.docx");
    fs::write(&input_path, build_ooxml_fixture(PII)).unwrap();

    let output = Command::new(bin()).arg("scrub").arg(&input_path).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.starts_with("format: OOXML/ODF (zip package)\n"), "stdout={stdout}");
    assert!(stdout.contains("\ncleaned ("), "stdout={stdout}");
    assert!(stdout.contains("wrote "), "stdout={stdout}");
    assert!(stderr.starts_with("passed_through"), "stderr={stderr}");
}

// ── verifier-hardening round: argv edge cases + JSON format token ────────────

/// A non-UTF-8 argv element must be a clean `error:` + exit 2, never a panic
/// (`env::args()` panics; the binary uses `args_os` and converts explicitly).
#[cfg(unix)]
#[test]
fn non_utf8_argument_exits_2_with_error_not_panic() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    // 0x80 alone is invalid UTF-8 in any position.
    let bad = OsStr::from_bytes(b"scr\x80ub");
    let output = Command::new(bin()).arg(bad).arg("x").output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "non-UTF-8 argv must exit 2 (a panic gives 101 / signal): {output:?}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("error:"), "clean error line expected: {stderr}");
    assert!(stderr.contains("UTF-8"), "error should name the cause: {stderr}");
    assert!(
        !stderr.contains("panicked"),
        "must not be a panic backtrace: {stderr}"
    );
}

/// `-` is reserved for stdin, so a file literally named `-` is addressed as
/// `./-` (documented in usage). Prove the workaround actually works.
#[test]
fn file_literally_named_dash_is_reachable_as_dot_slash_dash() {
    const PII: &str = "Alice Confidential Secret";
    let dir = scratch_dir("dash-file");
    fs::write(dir.join("-"), build_ooxml_fixture(PII)).unwrap();

    // check ./- reads the FILE (exit 1: dirty), not stdin (empty stdin would
    // be exit 2 "unknown format").
    let output = Command::new(bin())
        .arg("check")
        .arg("./-")
        .current_dir(&dir)
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(1),
        "./- must address the file named '-' (dirty fixture => exit 1); stderr={stderr}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("docProps/core.xml"), "file report expected: {stdout}");

    // scrub ./- writes the ./-.scrubbed sibling like any other file path.
    let output = Command::new(bin())
        .arg("scrub")
        .arg("./-")
        .current_dir(&dir)
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "scrub ./- must succeed; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(dir.join("-.scrubbed").exists(), "expected ./-.scrubbed to be written");
}

/// Minimal ODF (.odt-shaped) zip: `mimetype` + a `meta.xml` carrying planted
/// authorship, matching the shape the library's ODF arm scrubs.
fn build_odf_fixture(pii: &str) -> Vec<u8> {
    use std::io::Cursor;
    let mut buf = Vec::new();
    let mut w = zip::ZipWriter::new(Cursor::new(&mut buf));
    let o = zip::write::SimpleFileOptions::default();
    w.start_file("mimetype", o).unwrap();
    w.write_all(b"application/vnd.oasis.opendocument.text").unwrap();
    w.start_file("meta.xml", o).unwrap();
    w.write_all(
        format!(
            r#"<office:document-meta><office:meta><dc:creator>{pii}</dc:creator><meta:generator>LibreOffice/7.6</meta:generator></office:meta></office:document-meta>"#
        )
        .as_bytes(),
    )
    .unwrap();
    w.start_file("content.xml", o).unwrap();
    w.write_all(br#"<office:body><text:p>odt body text</text:p></office:body>"#).unwrap();
    w.finish().unwrap();
    buf
}

/// Documented (not accidental) behavior: ODF input reports the JSON format
/// token "ooxml", because the library detects both zip-package families as
/// its single `Format::Ooxml` variant. This test pins the documented token so
/// a future library split to a real "odf" token is a conscious, test-visible
/// change.
#[test]
fn odf_input_reports_ooxml_format_token_in_json() {
    let fixture = build_odf_fixture("Alice Confidential Secret");
    let (code, stdout, stderr) = run_bin(&["check", "--json", "-"], Some(&fixture));
    assert_eq!(code, Some(1), "dirty ODF must exit 1; stderr={stderr}");
    let stdout = String::from_utf8(stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("must parse as JSON");
    assert_eq!(
        v["format"], "ooxml",
        "ODF reports the documented shared zip-package token: {v}"
    );
    assert!(
        v["cleaned"].as_array().unwrap().iter().any(|c| c.as_str().unwrap() == "meta.xml"),
        "ODF meta.xml must be reported cleaned: {v}"
    );
    assert_eq!(v["clean"], false);
}
