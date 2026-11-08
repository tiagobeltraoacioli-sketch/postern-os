// SPDX-License-Identifier: MIT OR Apache-2.0
//! Integration tests for the `hygiene_scrub` command's pure core
//! (src/hygiene.rs → `bloch_desktop::hygiene::{scrub, scrub_b64}`), driven
//! through the library target the same way tests/terem_lifecycle.rs drives
//! terem — no live Tauri app needed, the command fn is a thin wrapper over
//! `scrub_b64`.
//!
//! What is pinned here:
//! - a minimal in-test DOCX (zip with docProps/core.xml author/lastModifiedBy)
//!   scrubs for real: `removed` names the leaked part, the cleaned bytes no
//!   longer carry the names, and re-scrubbing the cleaned file is a no-op
//!   (idempotent, change-accurate reporting);
//! - a minimal JPEG with an EXIF APP1 segment loses exactly that segment;
//! - unknown formats FAIL CLOSED (error, never a simulated `real: true`);
//! - the serialized wire shape is EXACTLY what desktop/src/modules/hygiene.js
//!   consumes: `{ kind, real, removed, cleanedB64, note }`.

use std::io::{Cursor, Read, Write};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use bloch_desktop::hygiene::{scrub, scrub_b64};

/// Minimal DOCX-shaped zip: content-types root + a core.xml leaking
/// author/lastModifiedBy + real document content that must survive.
fn build_docx() -> Vec<u8> {
    let mut buf = Vec::new();
    let mut w = zip::ZipWriter::new(Cursor::new(&mut buf));
    let o = zip::write::SimpleFileOptions::default();
    w.start_file("[Content_Types].xml", o).unwrap();
    w.write_all(b"<Types/>").unwrap();
    w.start_file("docProps/core.xml", o).unwrap();
    w.write_all(
        br#"<cp:coreProperties><dc:creator>Alice Secret</dc:creator><cp:lastModifiedBy>Bob Doe</cp:lastModifiedBy></cp:coreProperties>"#,
    )
    .unwrap();
    w.start_file("word/document.xml", o).unwrap();
    w.write_all(b"<w:document>the actual content</w:document>").unwrap();
    w.finish().unwrap();
    buf
}

/// Minimal JPEG: SOI + APP1 EXIF segment + SOS + fake scan + EOI (the same
/// shape postern-hygiene's own unit tests use).
fn build_jpeg_with_exif() -> Vec<u8> {
    vec![
        0xFF, 0xD8, // SOI
        0xFF, 0xE1, 0x00, 0x08, b'E', b'x', b'i', b'f', 0x00, 0x00, // APP1 EXIF
        0xFF, 0xDA, 0x00, 0x02, // SOS
        0x12, 0x34, // (fake) entropy-coded scan
        0xFF, 0xD9, // EOI
    ]
}

fn read_zip_entry(doc: &[u8], name: &str) -> Option<String> {
    let mut z = zip::ZipArchive::new(Cursor::new(doc)).ok()?;
    let mut f = z.by_name(name).ok()?;
    let mut s = String::new();
    f.read_to_string(&mut s).ok()?;
    Some(s)
}

#[test]
fn docx_scrub_is_real_names_leaks_and_is_idempotent() {
    let docx = build_docx();
    let rep = scrub("leaky.docx", &docx).expect("a well-formed docx must scrub");

    assert_eq!(rep.kind, "ooxml");
    assert!(rep.real, "the Rust core ran — this is a real scrub, not a preview");
    assert!(
        rep.removed.iter().any(|r| r.contains("docProps/core.xml")),
        "removed[] must name the part carrying author/lastModifiedBy, got {:?}",
        rep.removed
    );

    // The cleaned bytes must actually be clean (decode and look inside).
    let cleaned = B64.decode(&rep.cleaned_b64).expect("cleanedB64 must be valid base64");
    let core = read_zip_entry(&cleaned, "docProps/core.xml").expect("core.xml still present");
    assert!(!core.contains("Alice Secret"), "author must be gone from the cleaned file");
    assert!(!core.contains("Bob Doe"), "lastModifiedBy must be gone from the cleaned file");
    let body = read_zip_entry(&cleaned, "word/document.xml").expect("document part kept");
    assert!(body.contains("the actual content"), "document content must survive the scrub");

    // Idempotent + change-accurate: re-scrubbing the cleaned file removes nothing.
    let rep2 = scrub("leaky.clean.docx", &cleaned).expect("cleaned output must re-scrub");
    assert!(
        rep2.removed.is_empty(),
        "re-scrub must be a no-op (already clean), got {:?}",
        rep2.removed
    );

    // Honesty caveats ride on every result.
    assert!(rep.note.contains("UNAUDITED"), "note must keep the unaudited caveat");
    assert!(rep.note.contains("opt-in"), "note must keep the seal-is-opt-in/pending caveat");
    assert!(
        rep.note.contains("local") || rep.note.contains("offline"),
        "note must say the scrub is local"
    );
}

#[test]
fn jpeg_scrub_drops_exif_and_is_idempotent() {
    let jpeg = build_jpeg_with_exif();
    let rep = scrub("photo.jpg", &jpeg).expect("a well-formed jpeg must scrub");

    assert_eq!(rep.kind, "jpeg");
    assert!(rep.real);
    assert!(
        rep.removed.iter().any(|r| r.contains("APP1")),
        "removed[] must name the EXIF APP1 segment, got {:?}",
        rep.removed
    );

    let cleaned = B64.decode(&rep.cleaned_b64).unwrap();
    assert!(
        !cleaned.windows(4).any(|w| w == b"Exif"),
        "EXIF bytes must be gone from the cleaned jpeg"
    );

    // Idempotent: the cleaned jpeg re-scrubs to itself with nothing removed.
    let rep2 = scrub("photo.clean.jpg", &cleaned).expect("cleaned jpeg must re-scrub");
    assert!(rep2.removed.is_empty(), "re-scrub removed {:?}", rep2.removed);
    assert_eq!(B64.decode(&rep2.cleaned_b64).unwrap(), cleaned, "re-scrub is byte-stable");
}

#[test]
fn unknown_format_fails_closed() {
    // No real scrubber for this → an honest error, never a simulated report.
    let err = scrub("mystery.bin", b"\x00\x01\x02 not any known format").unwrap_err();
    assert!(
        err.contains("unrecognized") && err.to_lowercase().contains("fail closed"),
        "unexpected error text: {err}"
    );
    // A plain-zip-that-is-not-a-document is also not blessed: is_zip_doc
    // requires an OOXML/ODF root, so detect_format → None → fail closed.
    let mut buf = Vec::new();
    let mut w = zip::ZipWriter::new(Cursor::new(&mut buf));
    w.start_file("random.txt", zip::write::SimpleFileOptions::default()).unwrap();
    w.write_all(b"hello").unwrap();
    w.finish().unwrap();
    assert!(scrub("archive.zip", &buf).is_err(), "a non-document zip must not scrub");
}

#[test]
fn bad_base64_fails_closed_on_the_wire_path() {
    let err = scrub_b64("x.jpg", "!!!not-base64!!!").unwrap_err();
    assert!(err.contains("base64"), "unexpected error text: {err}");
}

#[test]
fn wire_shape_matches_hygiene_js_exactly() {
    // hygiene.js reads rep.kind / rep.real / rep.removed / rep.cleanedB64 /
    // rep.note — pin the serde camelCase mapping so the contract cannot
    // silently drift (`cleaned_b64` MUST serialize as `cleanedB64`).
    let rep = scrub_b64("photo.jpg", &B64.encode(build_jpeg_with_exif())).unwrap();
    let v = serde_json::to_value(&rep).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["kind", "real", "removed", "cleanedB64", "note"] {
        assert!(obj.contains_key(key), "missing wire key '{key}' in {obj:?}");
    }
    assert_eq!(obj.len(), 5, "no extra/renamed keys: {obj:?}");
    assert_eq!(obj["real"], serde_json::json!(true));
}
