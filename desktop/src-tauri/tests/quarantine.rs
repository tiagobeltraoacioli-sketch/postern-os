// SPDX-License-Identifier: MIT OR Apache-2.0
//! Integration tests for the `quarantine_rebuild` command's pure core
//! (src/quarantine.rs → `bloch_desktop::quarantine::{rebuild, rebuild_b64}`),
//! driven through the library target the same way tests/hygiene_scrub.rs
//! drives hygiene — no live Tauri app needed, the command fn is a thin
//! wrapper over `rebuild_b64`.
//!
//! The MIRROR of the hygiene test: hygiene proves what you SEND is scrubbed;
//! this proves what you RECEIVE is neutralised by a real pixel/render rebuild.
//! What is pinned here:
//! - an EXIF-tagged JPEG is rebuilt into a clean PNG (kind "image"): the output
//!   starts with the PNG magic, the EXIF bytes are gone, and the picture
//!   (dimensions) survives — through the REAL postern-quarantine image path;
//! - a HOSTILE PDF (JavaScript / OpenAction / EmbeddedFiles / Metadata / a
//!   planted payload marker) is rendered by the pure-Rust `hayro` adapter and
//!   rebuilt into a flat PDF (kind "pdf"): the output starts with `%PDF-`, none
//!   of the forbidden tokens or the payload survive — a real render+rebuild,
//!   not a simulated report;
//! - office documents and unknown magic FAIL CLOSED (error, never a simulated
//!   `real: true`);
//! - every successful result carries the honesty note verbatim, and the
//!   serialized wire shape is EXACTLY what desktop/src/modules/quarantine.js
//!   consumes: `{ kind, real, cleanedB64, sandbox, note }`.

use std::io::Cursor;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use bloch_desktop::quarantine::{rebuild, rebuild_b64, NOTE_HONESTY};
use image::{DynamicImage, ImageFormat, Rgb, RgbImage};

/// A real, decodable 3x2 JPEG with a malicious/EXIF APP1 segment spliced in
/// right after the SOI — the same shape the postern-quarantine crate's own
/// unit test uses. Unlike hygiene's fixture this must actually DECODE (the
/// image path re-encodes from pixels), so it is produced by a real encoder.
fn tainted_jpeg() -> Vec<u8> {
    let mut img = RgbImage::new(3, 2);
    for (i, px) in img.pixels_mut().enumerate() {
        *px = Rgb([(i * 40) as u8, 0, 255 - (i * 20) as u8]);
    }
    let mut jpeg = Vec::new();
    DynamicImage::ImageRgb8(img)
        .write_to(&mut Cursor::new(&mut jpeg), ImageFormat::Jpeg)
        .unwrap();
    // Splice an APP1 (EXIF) marker right after the SOI (0xFFD8).
    let mut tainted = vec![
        0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x08, b'E', b'x', b'i', b'f', 0x00, 0x00,
    ];
    tainted.extend_from_slice(&jpeg[2..]);
    tainted
}

/// Hand-emit a minimal but VALID (correct xref offsets) single-page PDF that
/// is also HOSTILE: its catalog carries `/OpenAction` + `/Names`, there is a
/// `/JavaScript` action object holding a planted `EVIL_PAYLOAD_MARKER`, an
/// `/EmbeddedFiles` name tree, and a `/Metadata` XMP stream. hayro parses the
/// page tree and renders the (empty) page; the flat rebuild must carry over
/// NONE of that machinery — only pixels.
fn hostile_pdf() -> Vec<u8> {
    let mut out: Vec<u8> = b"%PDF-1.7\n".to_vec();
    let mut offsets: Vec<usize> = Vec::new();
    let push = |out: &mut Vec<u8>, offsets: &mut Vec<usize>, id: usize, body: &str| {
        offsets.push(out.len());
        out.extend_from_slice(format!("{id} 0 obj\n{body}\nendobj\n").as_bytes());
    };

    // 1 = Catalog (hostile: OpenAction + Names), 2 = Pages, 3 = Page,
    // 4 = JavaScript action (payload), 5 = EmbeddedFiles names, 6 = Metadata.
    push(
        &mut out,
        &mut offsets,
        1,
        "<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R \
         /Names << /JavaScript 4 0 R /EmbeddedFiles 5 0 R >> /Metadata 6 0 R >>",
    );
    push(
        &mut out,
        &mut offsets,
        2,
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    );
    push(
        &mut out,
        &mut offsets,
        3,
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 8 6] >>",
    );
    push(
        &mut out,
        &mut offsets,
        4,
        "<< /S /JavaScript /JS (app.alert('EVIL_PAYLOAD_MARKER')) >>",
    );
    push(
        &mut out,
        &mut offsets,
        5,
        "<< /Names [(evil.exe) 3 0 R] >>",
    );
    // A tiny XMP-ish metadata stream (its bytes must not survive the rebuild).
    let xmp = "<?xpacket?><x:xmpmeta>EVIL_PAYLOAD_MARKER in metadata</x:xmpmeta>";
    push(
        &mut out,
        &mut offsets,
        6,
        &format!(
            "<< /Type /Metadata /Subtype /XML /Length {} >>\nstream\n{xmp}\nendstream",
            xmp.len()
        ),
    );

    let total = offsets.len();
    let xref = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", total + 1).as_bytes());
    for o in &offsets {
        out.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R /Info 6 0 R /ID [<41> <42>] >>\nstartxref\n{xref}\n%%EOF\n",
            total + 1
        )
        .as_bytes(),
    );
    out
}

#[test]
fn exif_jpeg_is_rebuilt_into_a_clean_png_keeping_the_picture() {
    let tainted = tainted_jpeg();
    assert!(
        tainted.windows(4).any(|w| w == b"Exif"),
        "sanity: the input carries EXIF"
    );

    let rep = rebuild("photo.jpg", &tainted).expect("a real jpeg must quarantine");
    assert_eq!(rep.kind, "image");
    assert!(rep.real, "the Rust core ran — this is a real rebuild, not a preview");

    let clean = B64.decode(&rep.cleaned_b64).expect("cleanedB64 must be valid base64");
    // Output is a PNG (format normalised from the pixels alone) …
    assert_eq!(
        &clean[..8],
        &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        "image route must emit a clean PNG"
    );
    // … with none of the injected metadata …
    assert!(
        !clean.windows(4).any(|w| w == b"Exif"),
        "EXIF must be gone from the rebuilt image"
    );
    // … and the picture (dimensions) preserved.
    let re = image::load_from_memory(&clean).expect("rebuilt PNG must decode");
    assert_eq!((re.width(), re.height()), (3, 2), "picture geometry survives");

    // The image route surfaces a real, non-empty SandboxStatus string (on this
    // macOS/Windows/CI host it is honestly "Unsandboxed …" — never faked).
    assert!(!rep.sandbox.is_empty(), "sandbox status must be reported, never swallowed");
    assert!(rep.note.contains("UNAUDITED"), "note keeps the unaudited caveat");
    assert!(
        rep.note.contains("IN-PROCESS") && rep.note.contains("NO OS-level containment"),
        "note must keep the honest in-process / no-OS-containment caveat: {}",
        rep.note
    );
}

#[test]
fn hostile_pdf_is_rendered_and_rebuilt_flat_dropping_every_payload() {
    let input = hostile_pdf();
    assert!(input.starts_with(b"%PDF-"), "sanity: fixture is a PDF");
    assert!(
        input.windows(19).any(|w| w == b"EVIL_PAYLOAD_MARKER"),
        "sanity: the payload is in the input"
    );

    let rep = rebuild("hostile.pdf", &input).expect("a parseable PDF must quarantine");
    assert_eq!(rep.kind, "pdf");
    assert!(rep.real);

    let clean = B64.decode(&rep.cleaned_b64).expect("cleanedB64 must be valid base64");
    // The rebuilt artifact is a flat PDF …
    assert!(clean.starts_with(b"%PDF-"), "pdf route must emit a %PDF- artifact");
    // … carrying NONE of the hostile machinery (byte-level: these tokens are
    // simply never emitted by the flat rebuild) …
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
            !clean.windows(forbidden.len()).any(|w| w == forbidden),
            "forbidden token {:?} survived the rebuild",
            String::from_utf8_lossy(forbidden)
        );
    }
    // … and the planted payload marker is gone (input bytes reach the output
    // only as pixels, and this document's page is blank).
    assert!(
        !clean.windows(19).any(|w| w == b"EVIL_PAYLOAD_MARKER"),
        "the planted payload leaked into the rebuilt PDF"
    );

    // PDF route has no OS containment from the crate — it says so, honestly,
    // rather than inventing a sandbox status.
    assert!(
        rep.sandbox.contains("no OS-level containment"),
        "pdf route must not pretend to a sandbox it does not provide: {}",
        rep.sandbox
    );
}

#[test]
fn office_and_unknown_magic_fail_closed() {
    // OOXML/ZIP magic → the office route, which is deliberately NOT wired in the
    // desktop (no LibreOffice spawn): it must error, never a simulated report.
    let ooxml = b"PK\x03\x04 not really a document but the magic matches";
    let err = rebuild("book.xlsx", ooxml).unwrap_err();
    assert!(
        err.to_lowercase().contains("office") && err.to_lowercase().contains("libreoffice"),
        "office input must fail closed with an actionable message, got: {err}"
    );

    // Unknown magic → rejected before any renderer runs.
    let err = rebuild("mystery.bin", b"\x00\x01\x02 not any known format").unwrap_err();
    assert!(
        err.contains("unrecognized") && err.to_lowercase().contains("fail closed"),
        "unknown input must fail closed, got: {err}"
    );

    // A corrupt-but-image-magic input still fails inside its route (no fake clean).
    let err = rebuild("broken.jpg", &[0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x00, 0x00]).unwrap_err();
    assert!(!err.is_empty(), "a corrupt jpeg must error, not return clean bytes");
}

#[test]
fn bad_base64_fails_closed_on_the_wire_path() {
    let err = rebuild_b64("x.pdf", "!!!not-base64!!!").unwrap_err();
    assert!(err.contains("base64"), "unexpected error text: {err}");
}

#[test]
fn wire_shape_matches_quarantine_js_exactly() {
    // quarantine.js reads rep.kind / rep.real / rep.cleanedB64 / rep.sandbox /
    // rep.note — pin the serde camelCase mapping so the contract cannot
    // silently drift (`cleaned_b64` MUST serialize as `cleanedB64`).
    let rep = rebuild_b64("photo.jpg", &B64.encode(tainted_jpeg())).unwrap();
    let v = serde_json::to_value(&rep).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["kind", "real", "cleanedB64", "sandbox", "note"] {
        assert!(obj.contains_key(key), "missing wire key '{key}' in {obj:?}");
    }
    assert_eq!(obj.len(), 5, "no extra/renamed keys: {obj:?}");
    assert_eq!(obj["real"], serde_json::json!(true));
    assert_eq!(obj["note"], serde_json::json!(NOTE_HONESTY));
}
