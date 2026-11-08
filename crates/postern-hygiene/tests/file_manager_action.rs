// SPDX-License-Identifier: MIT OR Apache-2.0
//! Acceptance test for the file-manager right-click "scrub" embed integration.
//!
//! The Nautilus script, the KDE/.desktop action, and the macOS Automator Quick
//! Action all call ONE piece of glue: `desktop/file-manager/postern-scrub.sh`,
//! which pipes each selected file through the shipping `postern-hygiene scrub -`
//! embed mode into a scrubbed sibling. This test scripts a real invocation of
//! that action on a real EXIF-tagged JPEG and an OOXML `.docx` carrying author
//! metadata, then asserts — via `postern-hygiene check --json` — that:
//!
//!   1. each ORIGINAL reports `"clean":false` (metadata present), and
//!   2. the action's SCRUBBED sibling reports `"clean":true` (metadata gone),
//!      and the original is never rewritten.
//!
//! Fully hermetic: fixtures are built in-process (the `zip` dev-dep for the
//! OOXML, hand-assembled bytes for the JPEG), and the binary under test is the
//! one Cargo built (`CARGO_BIN_EXE_postern-hygiene`). No python, no exiftool,
//! no installed action — it drives the checked-in script directly. Skips with a
//! clear message on a host without `/bin/sh` (i.e. Windows), where this shell
//! action does not apply.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_postern-hygiene"))
}

/// `desktop/file-manager/postern-scrub.sh`, resolved from the crate manifest.
fn action_script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../desktop/file-manager/postern-scrub.sh")
        .canonicalize()
        .expect("action script postern-scrub.sh should exist")
}

fn scratch(name: &str) -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    d.push(format!("fm-action-{name}"));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

/// A real EXIF-tagged JPEG: SOI + an APP1 `Exif\0\0` segment carrying
/// identifying text (Artist/GPS/Make) + EOI. `scrub_jpeg` drops every APP1.
fn exif_jpeg(marker_text: &str) -> Vec<u8> {
    let mut app1 = b"Exif\x00\x00".to_vec();
    app1.extend_from_slice(b"MM\x00*");
    app1.extend_from_slice(marker_text.as_bytes());
    let len = (app1.len() + 2) as u16;
    let mut jpg = vec![0xFF, 0xD8, 0xFF, 0xE1];
    jpg.extend_from_slice(&len.to_be_bytes());
    jpg.extend_from_slice(&app1);
    jpg.extend_from_slice(&[0xFF, 0xD9]); // EOI
    jpg
}

/// A minimal OOXML `.docx` with author metadata in `docProps/core.xml`.
fn docx_with_author(author: &str) -> Vec<u8> {
    use std::io::Cursor;
    let mut buf = Vec::new();
    {
        let mut w = zip::ZipWriter::new(Cursor::new(&mut buf));
        let o = zip::write::SimpleFileOptions::default();
        w.start_file("[Content_Types].xml", o).unwrap();
        w.write_all(b"<Types/>").unwrap();
        w.start_file("docProps/core.xml", o).unwrap();
        w.write_all(
            format!(
                r#"<cp:coreProperties xmlns:cp="x" xmlns:dc="y"><dc:creator>{author}</dc:creator><cp:lastModifiedBy>{author}</cp:lastModifiedBy></cp:coreProperties>"#
            )
            .as_bytes(),
        )
        .unwrap();
        w.start_file("word/document.xml", o).unwrap();
        w.write_all(b"<w:document>the body text survives</w:document>").unwrap();
        w.finish().unwrap();
    }
    buf
}

/// Run `postern-hygiene check --json -` on `path`; return (exit0, json_stdout).
/// Exit 0 == "already clean"; exit 1 == "would be scrubbed" (dirty).
fn check_json(path: &Path) -> (bool, String) {
    let input = fs::read(path).unwrap();
    let mut child = Command::new(bin())
        .args(["check", "--json", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn check");
    child.stdin.take().unwrap().write_all(&input).unwrap();
    let out = child.wait_with_output().unwrap();
    (out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned())
}

#[test]
fn file_manager_action_scrubs_selection_to_clean_siblings() {
    // Skip on hosts without a POSIX shell (Windows) — the action is a shell hook.
    if !Path::new("/bin/sh").exists() {
        eprintln!("skipping: no /bin/sh (shell file-manager action is Linux/macOS only)");
        return;
    }

    let dir = scratch("selection");
    let jpg = dir.join("vacation photo.jpg");
    let docx = dir.join("quarterly report.docx");
    fs::write(&jpg, exif_jpeg("Artist=Alice Secret;GPSLatitude=51.5074;Make=Leica")).unwrap();
    fs::write(&docx, docx_with_author("Alice Secret")).unwrap();

    // (1) Baseline: both originals must report dirty.
    let (jpg_clean0, j0) = check_json(&jpg);
    let (docx_clean0, d0) = check_json(&docx);
    assert!(!jpg_clean0, "JPEG original should be dirty, got: {j0}");
    assert!(!docx_clean0, "DOCX original should be dirty, got: {d0}");
    assert!(j0.contains("\"clean\":false"), "jpg json: {j0}");
    assert!(d0.contains("\"clean\":false"), "docx json: {d0}");

    // (2) Invoke the ACTUAL right-click action glue on the selection, with the
    //     Cargo-built binary injected exactly as the installer would record it.
    let status = Command::new("/bin/sh")
        .arg(action_script())
        .arg(&jpg)
        .arg(&docx)
        .env("POSTERN_HYGIENE_BIN", bin())
        .status()
        .expect("run postern-scrub.sh");
    assert!(status.success(), "action script exited non-zero: {status:?}");

    // (3) Scrubbed siblings exist and are CLEAN.
    let jpg_out = dir.join("vacation photo.scrubbed.jpg");
    let docx_out = dir.join("quarterly report.scrubbed.docx");
    assert!(jpg_out.exists(), "action did not create the scrubbed JPEG sibling");
    assert!(docx_out.exists(), "action did not create the scrubbed DOCX sibling");

    let (jpg_clean, j1) = check_json(&jpg_out);
    let (docx_clean, d1) = check_json(&docx_out);
    assert!(jpg_clean, "scrubbed JPEG should be clean (exit 0), json: {j1}");
    assert!(docx_clean, "scrubbed DOCX should be clean (exit 0), json: {d1}");
    assert!(j1.contains("\"clean\":true"), "scrubbed jpg json: {j1}");
    assert!(d1.contains("\"clean\":true"), "scrubbed docx json: {d1}");

    // (4) Originals untouched: they must STILL report dirty (read-only guarantee).
    assert!(!check_json(&jpg).0, "the action must not rewrite the original JPEG");
    assert!(!check_json(&docx).0, "the action must not rewrite the original DOCX");
}

#[test]
fn file_manager_action_fails_closed_and_writes_no_sibling_for_unknown_format() {
    if !Path::new("/bin/sh").exists() {
        eprintln!("skipping: no /bin/sh");
        return;
    }
    let dir = scratch("unknown");
    // Plain text: no scrubber -> `scrub -` exits 2 -> the action must delete the
    // partial sibling (fail closed), never leave an unscrubbed copy behind.
    let txt = dir.join("notes.txt");
    fs::write(&txt, b"not a supported document format at all").unwrap();

    let status = Command::new("/bin/sh")
        .arg(action_script())
        .arg(&txt)
        .env("POSTERN_HYGIENE_BIN", bin())
        .status()
        .expect("run postern-scrub.sh");
    assert!(!status.success(), "action should report failure for an unscrubable file");
    assert!(
        !dir.join("notes.scrubbed.txt").exists(),
        "fail-closed: no scrubbed sibling may be left for an unknown format"
    );
}
