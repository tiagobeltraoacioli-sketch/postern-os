//! Integration test: a REAL multi-page PDF, carrying a live-content attack
//! payload (embedded JavaScript, an annotation `/AA` action, `/OpenAction`,
//! `/EmbeddedFiles`, `/Names`, `/Metadata`, and an `/Info` producer string),
//! is neutralised end-to-end by `quarantine_pdf(hayro_renderer())` and the
//! injected active content is proven not to survive the pixel round-trip.
//!
//! This file is compiled ONLY with `--features render-hayro` (the whole file
//! is `#![cfg(...)]`-gated, so a default `cargo test` compiles it to nothing).
//! Run it with:
//!
//! ```text
//! cargo test -p postern-quarantine --features render-hayro
//! ```
//!
//! Unlike the in-crate unit tests in `render_hayro.rs` (which round-trip the
//! crate's OWN flat emitter or hand-emit content-less pages), this exercises a
//! from-scratch multi-page PDF that a real viewer would render as two pages of
//! visible ink AND would treat as hostile — the point is that hayro rasterises
//! the ink while the hostile machinery is dropped on the floor, and the
//! hand-built rebuild carries none of it forward.
#![cfg(feature = "render-hayro")]

use postern_quarantine::pdf::quarantine_pdf;
use postern_quarantine::render_hayro::hayro_renderer;

/// Every distinctive payload marker planted in the attack fixture. NONE may
/// appear anywhere in the quarantined output bytes: the pixel round-trip is
/// the only channel from input to output, and none of these are ink.
const PAYLOAD_MARKERS: &[&[u8]] = &[
    b"EVIL_OPENACTION_MARKER",
    b"EVIL_ANNOT_AA_MARKER",
    b"EVIL_NAMED_JS_MARKER",
    b"EVIL_EMBEDDED_EXE_MARKER",
    b"EVIL_INFO_PRODUCER_MARKER",
    b"EVIL_XMP_METADATA_MARKER",
];

/// PDF structural names that carry active/interactive content. The flat
/// rebuild never emits any of them, so a raw byte scan of the output must find
/// none — a stronger check than a parser's structured view.
const FORBIDDEN_NAMES: &[&[u8]] = &[
    b"/JavaScript",
    b"/JS",
    b"/OpenAction",
    b"/AA",
    b"/EmbeddedFiles",
    b"/EmbeddedFile",
    b"/Names",
    b"/Annot",
    b"/Metadata",
    b"/Info",
    b"/Launch",
];

/// A page-1 MediaBox of 300x400 and a page-2 MediaBox of 260x340 — different
/// on purpose, so "every page rasterises to its own geometry" is a real
/// assertion, not a coincidence of equal-sized pages.
const P1_W: u32 = 300;
const P1_H: u32 = 400;
const P2_W: u32 = 260;
const P2_H: u32 = 340;

/// Hand-build a real, parseable, MULTI-PAGE PDF that:
/// - draws a solid black rectangle on each page (so a correct render produces
///   genuinely non-white pixels — proof the rasteriser drew ink, not a blank),
/// - and stuffs every active-content vector a hostile PDF would use:
///   `/OpenAction` JavaScript, a widget-annotation `/AA` JavaScript action,
///   a named-`/JavaScript` action, an `/EmbeddedFiles` attachment, an `/Info`
///   producer string, and an XMP `/Metadata` stream.
///
/// Object numbering (1-based, matches the refs in the bodies below):
///   1 Catalog  2 Pages  3 Page1  4 Content1  5 Page2  6 Content2
///   7 Annot(AA JS)  8 OpenAction JS  9 Names  10 Named JS  11 EmbeddedFile
///   12 Info  13 Metadata
fn attack_pdf() -> Vec<u8> {
    // Visible ink: fill a black rectangle well inside each MediaBox.
    let content1 = b"0 0 0 rg\n40 40 200 300 re\nf\n".to_vec();
    let content2 = b"0 0 0 rg\n30 30 180 260 re\nf\n".to_vec();

    // The EmbeddedFile and Metadata payloads (stream bodies).
    let exe = b"MZ\x90\x00 EVIL_EMBEDDED_EXE_MARKER not-a-real-binary".to_vec();
    let xmp = b"<?xpacket?><x:xmpmeta>EVIL_XMP_METADATA_MARKER</x:xmpmeta>".to_vec();

    let objs: Vec<Vec<u8>> = vec![
        // 1 Catalog: hangs every catalog-level attack vector off itself.
        b"<< /Type /Catalog /Pages 2 0 R /OpenAction 8 0 R /Names 9 0 R \
          /AA << /WC 8 0 R >> /Metadata 13 0 R >>"
            .to_vec(),
        // 2 Pages
        b"<< /Type /Pages /Kids [3 0 R 5 0 R] /Count 2 >>".to_vec(),
        // 3 Page 1 (carries a hostile widget annotation)
        format!(
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {P1_W} {P1_H}] \
             /Contents 4 0 R /Annots [7 0 R] >>"
        )
        .into_bytes(),
        // 4 Content stream for page 1
        stream_obj(b"", &content1),
        // 5 Page 2 (different MediaBox)
        format!(
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {P2_W} {P2_H}] \
             /Contents 6 0 R >>"
        )
        .into_bytes(),
        // 6 Content stream for page 2
        stream_obj(b"", &content2),
        // 7 Widget annotation with an /AA JavaScript action
        b"<< /Type /Annot /Subtype /Widget /Rect [10 10 90 40] \
          /AA << /D << /S /JavaScript /JS (app.alert\\('EVIL_ANNOT_AA_MARKER'\\)) >> >> >>"
            .to_vec(),
        // 8 /OpenAction JavaScript
        b"<< /S /JavaScript /JS (app.alert\\('EVIL_OPENACTION_MARKER'\\)) >>".to_vec(),
        // 9 /Names: a named-JavaScript tree AND an embedded-files tree
        b"<< /JavaScript << /Names [(boot) 10 0 R] >> \
          /EmbeddedFiles << /Names [(evil.exe) 11 0 R] >> >>"
            .to_vec(),
        // 10 The named JavaScript action
        b"<< /S /JavaScript /JS (app.alert\\('EVIL_NAMED_JS_MARKER'\\)) >>".to_vec(),
        // 11 The embedded-file stream (fake executable)
        stream_obj(b"/Type /EmbeddedFile /Subtype /application#2Foctet-stream", &exe),
        // 12 /Info producer/author metadata
        b"<< /Producer (EVIL_INFO_PRODUCER_MARKER) /Author (attacker) >>".to_vec(),
        // 13 XMP /Metadata stream
        stream_obj(b"/Type /Metadata /Subtype /XML", &xmp),
    ];

    assemble(&objs, "<< /Size 14 /Root 1 0 R /Info 12 0 R /ID [<4142> <4344>] >>")
}

/// Build a `<< dict /Length N >>\nstream\n...raw...\nendstream` object body.
fn stream_obj(dict_extra: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = b"<< ".to_vec();
    out.extend_from_slice(dict_extra);
    out.extend_from_slice(format!(" /Length {} >>\nstream\n", body.len()).as_bytes());
    out.extend_from_slice(body);
    out.extend_from_slice(b"\nendstream");
    out
}

/// Serialise 1-based object bodies into a valid classic-xref PDF with the
/// given trailer dictionary text.
fn assemble(objs: &[Vec<u8>], trailer: &str) -> Vec<u8> {
    let mut out = b"%PDF-1.7\n".to_vec();
    // Binary marker comment (conventional).
    out.extend_from_slice(&[b'%', 0xE2, 0xE3, 0xCF, 0xD3, b'\n']);

    let mut offsets = Vec::with_capacity(objs.len());
    for (i, body) in objs.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    }

    let xref_off = out.len();
    let size = objs.len() + 1;
    out.extend_from_slice(format!("xref\n0 {size}\n").as_bytes());
    out.extend_from_slice(b"0000000000 65535 f \n");
    for o in &offsets {
        out.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(format!("trailer\n{trailer}\nstartxref\n{xref_off}\n%%EOF\n").as_bytes());
    out
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// The core acceptance test: a real multi-page attack PDF goes through the
/// pure-Rust hayro renderer + flat rebuild, every page rasterises to visible
/// ink at its own geometry, the output re-parses as a flat PDF, and NONE of
/// the injected active content survives the pixel round-trip.
#[test]
fn multipage_attack_pdf_is_rebuilt_flat_and_active_content_does_not_survive() {
    let input = attack_pdf();

    // Sanity: the fixture really does carry each payload before quarantine —
    // otherwise the "did not survive" assertions would be vacuously true.
    for marker in PAYLOAD_MARKERS {
        assert!(
            contains(&input, marker),
            "fixture bug: payload {:?} is not even present in the input",
            String::from_utf8_lossy(marker)
        );
    }

    // --- (1) every page rasterises, via the real renderer, to its geometry ---
    // Drive the renderer directly first so we can assert page-level facts the
    // rebuilt PDF alone can't show (per-page dimensions + actual ink).
    let rasters = postern_quarantine::render_hayro::render_pdf_pages(&input)
        .expect("hayro must rasterise the multi-page PDF");
    assert_eq!(rasters.len(), 2, "both pages must rasterise");
    assert_eq!(
        (rasters[0].width, rasters[0].height),
        (P1_W, P1_H),
        "page 1 must rasterise to its own MediaBox geometry"
    );
    assert_eq!(
        (rasters[1].width, rasters[1].height),
        (P2_W, P2_H),
        "page 2 must rasterise to its own MediaBox geometry"
    );
    for (i, r) in rasters.iter().enumerate() {
        assert_eq!(
            r.rgb8.len(),
            (r.width * r.height * 3) as usize,
            "page {i} raster buffer size must match its geometry"
        );
        // Proof the rasteriser actually drew the black rectangle — a blank
        // (all-white) page would mean the content stream was NOT rendered,
        // which would make the round-trip meaningless.
        assert!(
            r.rgb8.iter().any(|&b| b < 64),
            "page {i} must contain the rendered black ink (found no dark pixels)"
        );
    }

    // --- full end-to-end quarantine through the injected hayro closure ---
    let out = quarantine_pdf(&input, hayro_renderer()).expect("quarantine must succeed");

    // --- (2) the output re-parses as a flat PDF with the right page count ---
    assert!(out.starts_with(b"%PDF-"), "output must be a PDF");
    let doc = lopdf::Document::load_mem(&out).expect("output must re-parse as a valid PDF");
    let pages = doc.get_pages();
    assert_eq!(pages.len(), 2, "rebuilt PDF must have exactly two pages");

    // Flat structure: the trailer carries no /Info and no /ID, and every page
    // is a pixel image with no interactive machinery.
    assert!(doc.trailer.get(b"Info").is_err(), "flat PDF trailer must have no /Info");
    assert!(doc.trailer.get(b"ID").is_err(), "flat PDF trailer must have no /ID");
    let catalog = doc.catalog().expect("catalog");
    for banned in [&b"OpenAction"[..], b"Names", b"AA", b"Metadata"] {
        assert!(
            catalog.get(banned).is_err(),
            "catalog must not carry /{}",
            String::from_utf8_lossy(banned)
        );
    }
    // Each page must have exactly one image XObject and no /Annots.
    let mut image_streams = 0usize;
    for (_num, page_id) in &pages {
        let page = doc.get_object(*page_id).and_then(|o| o.as_dict()).expect("page dict");
        assert!(page.get(b"Annots").is_err(), "rebuilt page must have no /Annots");
        let res = page.get(b"Resources").and_then(|o| o.as_dict()).expect("page resources");
        let xobjects = res.get(b"XObject").and_then(|o| o.as_dict()).expect("xobject dict");
        for (_k, v) in xobjects.iter() {
            let sid = v.as_reference().expect("xobject reference");
            let stream = doc.get_object(sid).and_then(|o| o.as_stream().cloned()).expect("image stream");
            let subtype = stream.dict.get(b"Subtype").and_then(|o| o.as_name()).unwrap_or(b"");
            assert_eq!(subtype, b"Image", "the only XObject per page must be an image");
            image_streams += 1;
        }
    }
    assert_eq!(image_streams, 2, "exactly one image per page");

    // --- (3) the injected active content did NOT survive the round-trip ---
    for marker in PAYLOAD_MARKERS {
        assert!(
            !contains(&out, marker),
            "payload {:?} SURVIVED the pixel round-trip into the rebuilt PDF",
            String::from_utf8_lossy(marker)
        );
    }
    for name in FORBIDDEN_NAMES {
        assert!(
            !contains(&out, name),
            "active-content name {:?} leaked into the rebuilt PDF",
            String::from_utf8_lossy(name)
        );
    }
}
