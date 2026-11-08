//! End-to-end tests for the **non-injected default pipeline**
//! ([`postern_quarantine::dispatch::default_pipeline`]) — the wiring that
//! pre-injects the shipped LibreOffice converter adapter and the shipped
//! `hayro` renderer so a caller needs no closures at all.
//!
//! The whole file is gated on the `render-hayro` feature, because
//! `default_pipeline` only exists when the renderer half is compiled in.
//! Run with: `cargo test -p postern-quarantine --features render-hayro`.
//!
//! ## What runs where — honestly labelled
//!
//! - The **PDF leg** ([`pdf_leg_through_the_default_pipeline_is_a_flat_pdf`])
//!   runs on **every** host, LibreOffice installed or not: the default
//!   pipeline routes a `%PDF-` input to the in-process `hayro` renderer and
//!   never touches the converter. This is the always-green proof that the
//!   non-injected wiring produces the same flat, metadata-free, text-layer-less
//!   PDF the injected path does.
//! - The **office leg** ([`office_leg_synthesized_docx_through_the_default_pipeline`])
//!   is `#[ignore]`-gated on a real `soffice` being present, because it drives
//!   **unmodified LibreOffice** out-of-process. It synthesizes a real,
//!   author-tagged `.docx` (a stored-entry ZIP with a `<dc:creator>` in
//!   `docProps/core.xml` and visible body text) and asserts the DEFAULT
//!   pipeline turns it into a flat PDF with **no `/Info`, `/Metadata`,
//!   `/Names`, `/OpenAction`** and **no recoverable text layer** — i.e. the
//!   author tag and the text both die in the pixel round-trip. Run it on a
//!   machine with LibreOffice via:
//!   `cargo test -p postern-quarantine --features render-hayro -- --ignored`.
#![cfg(feature = "render-hayro")]

use postern_quarantine::adapters::find_soffice;
use postern_quarantine::dispatch::{default_pipeline, SniffedKind};
use postern_quarantine::office::OfficeKind;
use postern_quarantine::pdf::{rebuild_pdf_from_pages, PageRaster};

/// Names a flat quarantine PDF must never carry (a subset of the crate's full
/// banned set — exactly the four the acceptance calls out, plus the rest for
/// good measure). Asserted on the raw output bytes.
const FORBIDDEN_TOKENS: &[&[u8]] = &[
    b"/Info",
    b"/Metadata",
    b"/Names",
    b"/OpenAction",
    b"/JavaScript",
    b"/EmbeddedFiles",
    b"/AA",
    b"/ID",
];

/// Assert a produced artifact is a flat, image-only quarantine PDF: parseable,
/// carrying none of the forbidden names, and with **no recoverable text
/// layer** (the flat rebuild draws one image per page and emits no text
/// operators, so `extract_text` yields nothing but whitespace).
fn assert_flat_pdf_no_text(bytes: &[u8], expect_pages: usize) {
    assert!(bytes.starts_with(b"%PDF-"), "output is not a PDF");

    for forbidden in FORBIDDEN_TOKENS {
        assert!(
            !bytes.windows(forbidden.len()).any(|w| &w == forbidden),
            "forbidden token {:?} found in the default-pipeline output",
            String::from_utf8_lossy(forbidden)
        );
    }

    let doc = lopdf::Document::load_mem(bytes).expect("output must be a parseable PDF");
    let page_numbers: Vec<u32> = doc.get_pages().keys().copied().collect();
    assert_eq!(page_numbers.len(), expect_pages, "unexpected page count");

    // No /Info, no /ID in the trailer — asserted through the parser too.
    assert!(doc.trailer.get(b"Info").is_err(), "trailer carries /Info");
    assert!(doc.trailer.get(b"ID").is_err(), "trailer carries /ID");

    // No text layer: a flat image-only PDF has no text-showing operators, so
    // extraction yields only whitespace. (Empty is the honest expectation;
    // we tolerate whitespace/newlines a serializer might introduce.)
    let text = doc
        .extract_text(&page_numbers)
        .expect("extract_text must not error on a flat PDF");
    assert!(
        text.trim().is_empty(),
        "flat quarantine PDF must have NO recoverable text layer, extracted: {text:?}"
    );

    // Defense in depth: the flat rebuild never emits font machinery either.
    assert!(
        !bytes.windows(5).any(|w| w == b"/Font"),
        "flat quarantine PDF must not carry any /Font resource"
    );
}

/// The PDF leg of the DEFAULT pipeline, on every host: a `%PDF-` input is
/// routed to the in-process `hayro` renderer with no caller closures and no
/// LibreOffice, and the result is a flat, text-layer-less PDF.
#[test]
fn pdf_leg_through_the_default_pipeline_is_a_flat_pdf() {
    // A valid input PDF built by the crate's own flat emitter (two pages).
    let input = rebuild_pdf_from_pages(&[
        PageRaster::new(6, 4, vec![120u8; 6 * 4 * 3]).unwrap(),
        PageRaster::new(3, 5, vec![30u8; 3 * 5 * 3]).unwrap(),
    ])
    .unwrap();

    let out = default_pipeline(&input).expect("PDF leg of the default pipeline must succeed");
    assert_eq!(out.kind, SniffedKind::Pdf);
    assert!(
        out.sandbox.is_none(),
        "PDF route must not claim a sandbox status this crate does not provide"
    );
    assert_flat_pdf_no_text(&out.bytes, 2);
}

// ---------------------------------------------------------------------------
// Minimal stored-entry ZIP writer — enough to synthesize a real OOXML .docx
// LibreOffice will open. No zip crate dependency: every entry is stored
// (method 0), so we only need a CRC-32.
// ---------------------------------------------------------------------------

/// IEEE CRC-32, bytewise. Only used to build a well-formed ZIP for the test.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// Build a ZIP archive from `(name, contents)` entries, all stored
/// (uncompressed). The first entry's bytes become the archive's first bytes,
/// so passing `[Content_Types].xml` first keeps the OPC package well-formed
/// and the ZIP local-file magic (`PK\x03\x04`) at offset 0 — which is exactly
/// what the office route sniffs.
fn build_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    let mut offsets = Vec::new();

    for (name, data) in entries {
        let name_bytes = name.as_bytes();
        let crc = crc32(data);
        let local_offset = out.len() as u32;
        offsets.push(local_offset);

        // Local file header.
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes()); // signature PK\x03\x04
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&0u16.to_le_bytes()); // method: stored
        out.extend_from_slice(&0u16.to_le_bytes()); // mod time
        out.extend_from_slice(&0u16.to_le_bytes()); // mod date
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes()); // compressed
        out.extend_from_slice(&(data.len() as u32).to_le_bytes()); // uncompressed
        out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra len
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(data);
    }

    for ((name, data), local_offset) in entries.iter().zip(offsets.iter()) {
        let name_bytes = name.as_bytes();
        let crc = crc32(data);
        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes()); // central dir signature
        central.extend_from_slice(&20u16.to_le_bytes()); // version made by
        central.extend_from_slice(&20u16.to_le_bytes()); // version needed
        central.extend_from_slice(&0u16.to_le_bytes()); // flags
        central.extend_from_slice(&0u16.to_le_bytes()); // method: stored
        central.extend_from_slice(&0u16.to_le_bytes()); // mod time
        central.extend_from_slice(&0u16.to_le_bytes()); // mod date
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes()); // compressed
        central.extend_from_slice(&(data.len() as u32).to_le_bytes()); // uncompressed
        central.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // extra len
        central.extend_from_slice(&0u16.to_le_bytes()); // comment len
        central.extend_from_slice(&0u16.to_le_bytes()); // disk number start
        central.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        central.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        central.extend_from_slice(&local_offset.to_le_bytes());
        central.extend_from_slice(name_bytes);
    }

    let central_offset = out.len() as u32;
    let central_size = central.len() as u32;
    out.extend_from_slice(&central);

    // End of central directory.
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // disk number
    out.extend_from_slice(&0u16.to_le_bytes()); // disk with cd
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes()); // entries this disk
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes()); // entries total
    out.extend_from_slice(&central_size.to_le_bytes());
    out.extend_from_slice(&central_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment len

    out
}

/// The author tag and visible text markers planted in the synthesized .docx —
/// both must be gone from the final flat PDF.
const AUTHOR_MARKER: &str = "SECRET_AUTHOR_MARKER_ZZZ";
const VISIBLE_TEXT_MARKER: &str = "UNIQUE_VISIBLE_BODY_TEXT_QZX";

/// Synthesize a real, minimal, **author-tagged** `.docx`: a valid OOXML
/// package whose `docProps/core.xml` carries a `<dc:creator>` (the author
/// tag) and whose body carries a distinctive run of visible text. LibreOffice
/// opens this and renders it; the quarantine must destroy both the author tag
/// (metadata) and the text layer (it becomes pixels).
fn synthesize_authored_docx() -> Vec<u8> {
    let content_types = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/></Types>"#;

    let rels = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/></Relationships>"#;

    let document = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>{VISIBLE_TEXT_MARKER}</w:t></w:r></w:p></w:body></w:document>"#
    );

    let core = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>{AUTHOR_MARKER}</dc:creator><cp:lastModifiedBy>{AUTHOR_MARKER}</cp:lastModifiedBy></cp:coreProperties>"#
    );

    build_zip(&[
        ("[Content_Types].xml", content_types),
        ("_rels/.rels", rels),
        ("word/document.xml", document.as_bytes()),
        ("docProps/core.xml", core.as_bytes()),
    ])
}

/// ENVIRONMENT-GATED (`#[ignore]`), honestly labelled: the office leg of the
/// DEFAULT pipeline, driving REAL unmodified LibreOffice out-of-process. Not
/// run in the default `cargo test`. Run it on a machine with `soffice` on
/// `PATH` (e.g. after `brew install --cask libreoffice`, exporting the app's
/// MacOS dir onto PATH, or with the executable set via `SofficeConfig`):
///
///   cargo test -p postern-quarantine --features render-hayro -- --ignored
///
/// It synthesizes an author-tagged `.docx`, runs it through
/// `default_pipeline` (no caller closures), and asserts the final artifact is
/// a flat PDF with no `/Info`, `/Metadata`, `/Names`, `/OpenAction`, no
/// recoverable text layer, and neither the author tag nor the visible body
/// text surviving anywhere in the bytes.
#[test]
#[ignore = "office leg: requires a real LibreOffice install (soffice on PATH) — environment-gated"]
fn office_leg_synthesized_docx_through_the_default_pipeline() {
    assert!(
        find_soffice(None).is_some(),
        "no `soffice` on PATH — install LibreOffice (brew install --cask libreoffice) \
         and put its MacOS dir on PATH, or run this test on a host that has it"
    );

    let docx = synthesize_authored_docx();
    // Sanity: the input really is an OOXML/ZIP carrying the author tag and text.
    assert_eq!(
        &docx[..4],
        &[0x50, 0x4B, 0x03, 0x04],
        "input must have ZIP magic"
    );
    assert!(
        docx.windows(AUTHOR_MARKER.len())
            .any(|w| w == AUTHOR_MARKER.as_bytes()),
        "sanity: author tag is present in the synthesized .docx"
    );

    let out = default_pipeline(&docx).expect("office leg of the default pipeline must succeed");
    assert_eq!(out.kind, SniffedKind::Office(OfficeKind::OoxmlZip));
    assert!(
        out.sandbox.is_none(),
        "office route must not claim a sandbox status this crate does not provide"
    );

    // The rendered page count is whatever LibreOffice + hayro produced; a
    // one-line doc is a single page, but assert >=1 rather than hard-coding.
    let doc = lopdf::Document::load_mem(&out.bytes).expect("output must parse");
    let pages = doc.get_pages().len();
    assert!(
        pages >= 1,
        "expected at least one rendered page, got {pages}"
    );
    assert_flat_pdf_no_text(&out.bytes, pages);

    // The author tag and the visible body text must BOTH be gone from the
    // final bytes — destroyed by the pixel round-trip.
    assert!(
        !out.bytes
            .windows(AUTHOR_MARKER.len())
            .any(|w| w == AUTHOR_MARKER.as_bytes()),
        "author tag leaked into the final quarantine PDF"
    );
    assert!(
        !out.bytes
            .windows(VISIBLE_TEXT_MARKER.len())
            .any(|w| w == VISIBLE_TEXT_MARKER.as_bytes()),
        "visible body text leaked as a text layer into the final quarantine PDF"
    );
}
