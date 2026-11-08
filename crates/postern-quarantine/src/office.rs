//! Office-document quarantine core — sniff, convert (injected), then reuse
//! the PDF path's flat rebuild. Pure Rust, no new runtime dependencies.
//!
//! ## What ships here, honestly
//!
//! - **A converter adapter now exists** — [`crate::adapters`] spawns
//!   **unmodified LibreOffice headless** (MPL, aggregation-only; external
//!   user-installed binary, never linked or forked) out-of-process, with a
//!   fresh throwaway profile per run, a wall-clock kill, an output-size
//!   cap, and fail-closed error mapping. The *convert* step here stays an
//!   **injected closure** — the seam is unchanged;
//!   [`crate::adapters::soffice_converter`] is a ready-made thing to
//!   inject, and this pipeline keeps being tested with fakes. Likewise the
//!   *render* step: injected closure, with
//!   `crate::render_hayro::hayro_renderer` shipping behind the default-OFF
//!   `render-hayro` feature (in-process pure Rust — see `render_hayro.rs`).
//! - **NO LANDLOCK/SECCOMP CONTAINMENT AROUND THE CONVERT OR RENDER.**
//!   Whatever the injected closures do with the untrusted bytes happens
//!   with the closures' own privileges. The shipped converter adapter's
//!   only bounds on the subprocess are the wall-clock kill, the output-size
//!   cap, and the fail-closed checks — LibreOffice still parses hostile
//!   bytes with the invoking user's full privileges, and on macOS/Windows
//!   nothing is sandboxed at all. The design calls for the converter and
//!   renderer to run under Landlock/seccomp (Dangerzone's concept —
//!   Dangerzone is **AGPL**, so reimplemented, no code taken); that
//!   containment still does not exist in this crate.
//! - **Everything that made the file "Office" is destroyed by design.**
//!   Macros, OLE objects, embedded files, revision history, author metadata,
//!   external references — none of it can survive, because the only thing
//!   that reaches the output is the rendered pixels of each page, rebuilt by
//!   [`crate::pdf::rebuild_pdf_from_pages`] into the same metadata-free flat
//!   PDF the PDF path emits (no `/Info`, no trailer `/ID`, no `/Metadata`,
//!   `/Names`, `/OpenAction`, `/JavaScript`, `/AA`, or `/EmbeddedFiles`).
//!   Editability and the text layer are destroyed too — that is the point.
//!
//! Describe this module as "office pipeline, converter-injected with an
//! out-of-process LibreOffice adapter available, subprocess containment
//! pending", never as a complete or safe Office quarantine.

use crate::pdf::{quarantine_pdf, PageRaster};
use crate::{QError, MAX_INPUT_BYTES};

/// Magic bytes of a ZIP local-file header — the container of every OOXML
/// document (`.docx`, `.xlsx`, `.pptx`). `PK\x03\x04`.
pub const OOXML_ZIP_MAGIC: [u8; 4] = [0x50, 0x4B, 0x03, 0x04];

/// Magic bytes of an OLE2 / Compound File Binary — the container of legacy
/// Office documents (`.doc`, `.xls`, `.ppt`). `D0 CF 11 E0 A1 B1 1A E1`.
pub const OLE2_CFB_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

/// The container family an untrusted input was sniffed as. Deliberately
/// coarse: quarantine does not care *which* OOXML application produced the
/// file — the converter treats them uniformly and the output is pixels
/// either way. Distinguishing docx from xlsx would require parsing the
/// untrusted ZIP, which this layer refuses to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfficeKind {
    /// OOXML — a ZIP container (`PK\x03\x04`): docx/xlsx/pptx and kin.
    /// NOTE: any ZIP matches this magic; the injected converter is what
    /// ultimately decides whether the ZIP is a document it can render.
    OoxmlZip,
    /// Legacy OLE2 / CFB container: doc/xls/ppt and kin.
    LegacyOle2,
}

/// Sniff the container family from magic bytes alone — a byte compare, no
/// parsing of the untrusted input. Returns `None` for anything that is not
/// one of the two Office container magics (including PDFs and images, which
/// have their own quarantine paths in this crate).
pub fn sniff_office_kind(input: &[u8]) -> Option<OfficeKind> {
    if input.starts_with(&OOXML_ZIP_MAGIC) {
        Some(OfficeKind::OoxmlZip)
    } else if input.starts_with(&OLE2_CFB_MAGIC) {
        Some(OfficeKind::LegacyOle2)
    } else {
        None
    }
}

/// Neutralise an untrusted Office document by converting it to PDF and
/// rebuilding that PDF from rendered page bitmaps. Uses the crate-wide
/// [`MAX_INPUT_BYTES`] cap; see [`quarantine_office_with_limit`] for a
/// caller-chosen (still fail-closed) cap.
///
/// **Both external tools must be injected.** `convert` receives the
/// untrusted office bytes and must return PDF bytes —
/// [`crate::adapters::soffice_converter`] is the shipped adapter
/// (unmodified LibreOffice headless, out-of-process, wall-clock-killed and
/// output-capped, but **not** Landlock/seccomp-sandboxed — see
/// `adapters.rs`). `render` is the same injected page-raster renderer
/// [`crate::pdf::quarantine_pdf`] takes
/// (`crate::render_hayro::hayro_renderer` behind the default-OFF
/// `render-hayro` feature; in-process — see `render_hayro.rs`). This
/// function itself adds **no containment** around either closure; see the
/// module docs.
///
/// What this function itself enforces, all fail-closed ([`Err`], never a
/// pass-through of the original bytes):
/// - the input starts with a known Office container magic
///   ([`sniff_office_kind`]; else [`QError::Decode`] — the untrusted bytes
///   are never handed to the converter);
/// - the input is at most the size cap (else [`QError::TooLarge`], before
///   the converter runs);
/// - a converter error string is surfaced as [`QError::Decode`];
/// - the converter's output must itself start with the `%PDF-` magic (else
///   [`QError::Decode`] — a converter that emitted garbage, or echoed the
///   input back, is treated as hostile and its output is never rendered);
/// - the rest is delegated to [`crate::pdf::quarantine_pdf`], so the final
///   artifact is the same metadata-free flat PDF as the PDF path (zero
///   pages, raster bombs, oversize converter output — all rejected there).
///
/// On every error path the original untrusted bytes are discarded, never
/// returned or partially copied into an output.
pub fn quarantine_office(
    input: &[u8],
    convert: impl FnOnce(&[u8]) -> Result<Vec<u8>, String>,
    render: impl FnOnce(&[u8]) -> Result<Vec<PageRaster>, String>,
) -> Result<Vec<u8>, QError> {
    quarantine_office_with_limit(input, MAX_INPUT_BYTES, convert, render)
}

/// [`quarantine_office`] with a caller-chosen input-size cap (in bytes).
/// Fail-closed: an input larger than `max_input_bytes` is rejected as
/// [`QError::TooLarge`] before the converter ever sees it — never truncated,
/// never passed through. A cap of `0` therefore rejects everything.
pub fn quarantine_office_with_limit(
    input: &[u8],
    max_input_bytes: usize,
    convert: impl FnOnce(&[u8]) -> Result<Vec<u8>, String>,
    render: impl FnOnce(&[u8]) -> Result<Vec<PageRaster>, String>,
) -> Result<Vec<u8>, QError> {
    let kind = sniff_office_kind(input).ok_or_else(|| {
        QError::Decode(
            "input matches neither the OOXML/ZIP (PK\\x03\\x04) nor the OLE2/CFB \
             Office container magic — refusing to hand it to a converter"
                .to_string(),
        )
    })?;
    if input.len() > max_input_bytes {
        return Err(QError::TooLarge(format!(
            "office input ({kind:?}) is {} bytes (cap {max_input_bytes})",
            input.len()
        )));
    }

    let converted = convert(input).map_err(|e| {
        QError::Decode(format!("office-to-PDF converter failed on {kind:?} input: {e}"))
    })?;
    if !converted.starts_with(b"%PDF-") {
        return Err(QError::Decode(
            "converter output does not start with the %PDF- magic — refusing to \
             render it"
                .to_string(),
        ));
    }

    // From here the office path IS the PDF path: same size cap on the
    // converted bytes, same injected renderer, same flat metadata-free
    // rebuild, same hard errors on zero pages or raster bombs.
    quarantine_pdf(&converted, render)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdf::rebuild_pdf_from_pages;

    /// Deterministic raster, same shape as the pdf.rs test helper.
    fn raster(width: u32, height: u32, seed: u8) -> PageRaster {
        let n = (width * height * 3) as usize;
        let rgb8: Vec<u8> = (0..n).map(|i| seed.wrapping_add((i % 7) as u8)).collect();
        PageRaster::new(width, height, rgb8).unwrap()
    }

    /// A fake untrusted OOXML file: correct ZIP magic followed by every kind
    /// of payload the quarantine must destroy. Never parsed by this module —
    /// only its first four bytes are ever inspected here.
    fn tainted_ooxml_input() -> Vec<u8> {
        let mut v = OOXML_ZIP_MAGIC.to_vec();
        v.extend_from_slice(
            b"word/vbaProject.bin AutoOpen() Shell(\"EVIL_MACRO_MARKER\") \
              docProps/core.xml <dc:creator>secret author</dc:creator> \
              oleObject1.bin EMBEDDED_EXE_MARKER",
        );
        v
    }

    /// A fake legacy .doc: correct OLE2/CFB magic plus payload markers.
    fn tainted_ole2_input() -> Vec<u8> {
        let mut v = OLE2_CFB_MAGIC.to_vec();
        v.extend_from_slice(b"Macros/VBA/ThisDocument EVIL_MACRO_MARKER \x05SummaryInformation");
        v
    }

    /// A fake converter: ignores the untrusted input entirely (as an
    /// out-of-process adapter's *output* effectively would — only rendered
    /// content crosses back) and emits a real, minimal, parseable PDF built
    /// by the crate's own emitter.
    fn fake_convert_ok(pages: usize) -> impl FnOnce(&[u8]) -> Result<Vec<u8>, String> {
        move |_untrusted| {
            let rasters: Vec<PageRaster> =
                (0..pages).map(|j| raster(3, 2, 20 + j as u8)).collect();
            rebuild_pdf_from_pages(&rasters).map_err(|e| e.to_string())
        }
    }

    #[test]
    fn sniffer_accepts_both_office_magics_and_nothing_else() {
        assert_eq!(sniff_office_kind(&tainted_ooxml_input()), Some(OfficeKind::OoxmlZip));
        assert_eq!(sniff_office_kind(&tainted_ole2_input()), Some(OfficeKind::LegacyOle2));
        // Bare magic with nothing after it still sniffs (sniffing is a
        // prefix compare; validity is the converter's problem).
        assert_eq!(sniff_office_kind(&OOXML_ZIP_MAGIC), Some(OfficeKind::OoxmlZip));
        assert_eq!(sniff_office_kind(&OLE2_CFB_MAGIC), Some(OfficeKind::LegacyOle2));

        // Everything else is refused: garbage, empty, truncated magic,
        // JPEG, PDF (PDFs have their own path in this crate).
        assert_eq!(sniff_office_kind(b"not an office file"), None);
        assert_eq!(sniff_office_kind(b""), None);
        assert_eq!(sniff_office_kind(&OOXML_ZIP_MAGIC[..3]), None);
        assert_eq!(sniff_office_kind(&OLE2_CFB_MAGIC[..7]), None);
        assert_eq!(sniff_office_kind(&[0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10]), None); // JPEG
        assert_eq!(sniff_office_kind(b"%PDF-1.7\n..."), None); // PDF
    }

    #[test]
    fn happy_path_emits_the_same_flat_metadata_free_pdf_as_the_pdf_path() {
        let input = tainted_ooxml_input();
        let out = quarantine_office(&input, fake_convert_ok(2), |pdf_bytes| {
            // The renderer must be handed the CONVERTER's output, never the
            // original office bytes.
            assert!(pdf_bytes.starts_with(b"%PDF-"), "renderer got non-PDF bytes");
            assert!(
                !pdf_bytes.windows(17).any(|w| w == b"EVIL_MACRO_MARKER"),
                "original office bytes leaked into the renderer input"
            );
            Ok(vec![raster(4, 3, 10), raster(2, 5, 90), raster(3, 3, 7)])
        })
        .unwrap();

        // Parseable, with exactly the renderer's page count.
        let doc = lopdf::Document::load_mem(&out).expect("output must be a parseable PDF");
        assert_eq!(doc.get_pages().len(), 3);

        // Same banned-token guarantee as the PDF path, asserted on raw bytes.
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
                "forbidden token {:?} found in office-quarantined PDF",
                String::from_utf8_lossy(forbidden)
            );
        }
        assert!(doc.trailer.get(b"Info").is_err(), "trailer must have no /Info");
        assert!(doc.trailer.get(b"ID").is_err(), "trailer must have no /ID");
    }

    #[test]
    fn planted_payloads_in_either_container_never_survive() {
        for input in [tainted_ooxml_input(), tainted_ole2_input()] {
            assert!(
                input.windows(17).any(|w| w == b"EVIL_MACRO_MARKER"),
                "sanity: the payload is in the input"
            );
            let out = quarantine_office(&input, fake_convert_ok(1), |_| {
                Ok(vec![raster(3, 3, 42)])
            })
            .unwrap();
            for marker in [b"EVIL_MACRO_MARKER".as_slice(), b"EMBEDDED_EXE_MARKER", b"secret author"] {
                assert!(
                    !out.windows(marker.len()).any(|w| w == marker),
                    "input payload {:?} leaked into the output",
                    String::from_utf8_lossy(marker)
                );
            }
        }
    }

    #[test]
    fn unknown_magic_errors_before_the_converter_runs() {
        let mut converter_ran = false;
        let res = quarantine_office(
            b"%PDF-1.4 this is a PDF, not an office file",
            |_| {
                converter_ran = true;
                Ok(b"%PDF-1.4".to_vec())
            },
            |_| Ok(vec![raster(1, 1, 0)]),
        );
        assert!(matches!(res, Err(QError::Decode(_))));
        assert!(!converter_ran, "converter must never see unrecognised bytes");
    }

    #[test]
    fn oversized_input_is_rejected_before_the_converter_runs() {
        let mut huge = tainted_ooxml_input();
        huge.resize(MAX_INPUT_BYTES + 1, 0);
        let mut converter_ran = false;
        let res = quarantine_office(
            &huge,
            |_| {
                converter_ran = true;
                Ok(b"%PDF-1.4".to_vec())
            },
            |_| Ok(vec![raster(1, 1, 0)]),
        );
        assert!(matches!(res, Err(QError::TooLarge(_))));
        assert!(!converter_ran, "converter must never see oversize input");
    }

    #[test]
    fn caller_chosen_limit_is_fail_closed_too() {
        let input = tainted_ooxml_input(); // small, but the cap below is smaller
        let res = quarantine_office_with_limit(
            &input,
            4, // just the magic — the payload pushes it over
            |_| Ok(b"%PDF-1.4".to_vec()),
            |_| Ok(vec![raster(1, 1, 0)]),
        );
        assert!(matches!(res, Err(QError::TooLarge(_))));
    }

    #[test]
    fn converter_errors_surface_as_hard_errors_never_pass_through() {
        let input = tainted_ole2_input();
        let res = quarantine_office(
            &input,
            |_| Err("libreoffice exploded".to_string()),
            |_| Ok(vec![raster(1, 1, 0)]),
        );
        match res {
            Err(QError::Decode(msg)) => assert!(msg.contains("libreoffice exploded")),
            other => panic!("expected Decode error, got {other:?}"),
        }
    }

    #[test]
    fn non_pdf_converter_output_is_rejected_before_the_renderer_runs() {
        let input = tainted_ooxml_input();
        let mut renderer_ran = false;
        // A hostile/buggy converter that echoes the untrusted input back.
        let echoed = input.clone();
        let res = quarantine_office(
            &input,
            move |_| Ok(echoed),
            |_| {
                renderer_ran = true;
                Ok(vec![raster(1, 1, 0)])
            },
        );
        assert!(matches!(res, Err(QError::Decode(_))));
        assert!(!renderer_ran, "renderer must never see non-PDF converter output");
    }

    #[test]
    fn zero_pages_from_the_renderer_is_a_hard_error() {
        let res = quarantine_office(&tainted_ooxml_input(), fake_convert_ok(1), |_| Ok(vec![]));
        assert!(matches!(res, Err(QError::Encode(_))));
    }

    #[test]
    fn renderer_errors_surface_as_hard_errors() {
        let res = quarantine_office(&tainted_ooxml_input(), fake_convert_ok(1), |_| {
            Err("pdfium exploded".to_string())
        });
        assert!(matches!(res, Err(QError::Decode(_))));
    }

    #[test]
    fn oversized_converter_output_is_rejected_by_the_delegated_pdf_path() {
        let input = tainted_ole2_input();
        let res = quarantine_office(
            &input,
            |_| {
                let mut bomb = b"%PDF-1.4\n".to_vec();
                bomb.resize(MAX_INPUT_BYTES + 1, 0);
                Ok(bomb)
            },
            |_| Ok(vec![raster(1, 1, 0)]),
        );
        assert!(matches!(res, Err(QError::TooLarge(_))));
    }
}
