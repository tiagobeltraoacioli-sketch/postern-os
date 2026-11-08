//! Top-level dispatcher: magic-sniff one untrusted byte blob and route it to
//! the right quarantine path — image, PDF, or office. **Fail-closed on
//! unknown magic**: bytes that match none of the known paths are rejected
//! with an error, never passed through, never guessed at, and never handed
//! to any external tool.
//!
//! The sniff is a prefix byte-compare only — the untrusted input is never
//! parsed at this layer (the same discipline as
//! [`crate::office::sniff_office_kind`], which this reuses for the two
//! office container magics).
//!
//! ## Containment differs per route — the result says which, honestly
//!
//! - **Image** route: runs via
//!   [`crate::quarantine_image_sandboxed_on_worker`] — Landlock-confined on
//!   a capable Linux kernel, and the achieved
//!   [`sandbox::SandboxStatus`](crate::sandbox::SandboxStatus) is surfaced
//!   in [`Quarantined::sandbox`], never swallowed.
//! - **PDF / office** routes: **no containment from this crate at all**
//!   around the injected converter/renderer (see `office.rs` /
//!   `adapters.rs` / `render_hayro.rs` for exactly what each adapter does
//!   and does not enforce). [`Quarantined::sandbox`] is `None` for these
//!   routes — deliberately, so a caller cannot mistake them for the
//!   image path's Landlock story.

use crate::office::{quarantine_office, sniff_office_kind, OfficeKind};
use crate::pdf::{quarantine_pdf, PageRaster};
use crate::sandbox::SandboxStatus;
use crate::{quarantine_image_sandboxed_on_worker, QError};

/// PNG signature (all 8 bytes — the shortest prefix that is actually the
/// PNG magic rather than a lookalike).
const PNG_MAGIC: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
/// JPEG SOI + marker prefix (`FF D8 FF` — SOI alone is too short to commit).
const JPEG_MAGIC: [u8; 3] = [0xFF, 0xD8, 0xFF];

/// Which quarantine path the dispatcher sniffed and took.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SniffedKind {
    /// PNG or JPEG → the pixel round-trip; output is a clean PNG.
    Image,
    /// `%PDF-` → render + flat rebuild; output is a clean flat PDF.
    Pdf,
    /// OOXML/ZIP or legacy OLE2 → convert + render + flat rebuild; output
    /// is a clean flat PDF.
    Office(OfficeKind),
}

/// The dispatcher's output: what was sniffed, the cleaned bytes, and — for
/// the image route only — the achieved sandbox status.
#[derive(Debug)]
pub struct Quarantined {
    /// Which path handled the input.
    pub kind: SniffedKind,
    /// The cleaned artifact: a PNG for [`SniffedKind::Image`], a flat
    /// metadata-free PDF for [`SniffedKind::Pdf`] / [`SniffedKind::Office`].
    pub bytes: Vec<u8>,
    /// `Some(status)` only for the image route (its decode runs behind
    /// [`crate::sandbox::confine`] on a worker thread; callers MUST inspect
    /// it — `Unsandboxed` is a truthfully-reported real outcome). `None`
    /// for PDF/office: this crate applies no containment around the
    /// injected converter/renderer, and pretending otherwise with a status
    /// would be a lie.
    pub sandbox: Option<SandboxStatus>,
}

/// Sniff which quarantine path a byte blob belongs to — prefix byte-compare
/// only, no parsing. `None` means no path claims it (the dispatcher turns
/// that into a hard error).
pub fn sniff_kind(input: &[u8]) -> Option<SniffedKind> {
    if input.starts_with(&PNG_MAGIC) || input.starts_with(&JPEG_MAGIC) {
        Some(SniffedKind::Image)
    } else if input.starts_with(b"%PDF-") {
        Some(SniffedKind::Pdf)
    } else {
        sniff_office_kind(input).map(SniffedKind::Office)
    }
}

/// Quarantine one untrusted byte blob, routing by magic:
///
/// - PNG/JPEG → [`crate::quarantine_image_sandboxed_on_worker`] (the
///   `convert`/`render` closures are **not** invoked);
/// - `%PDF-` → [`crate::pdf::quarantine_pdf`] with the injected `render`
///   (`convert` is **not** invoked);
/// - `PK\x03\x04` / OLE2 → [`crate::office::quarantine_office`] with both
///   injected closures;
/// - anything else → [`QError::UnknownMagic`], **before any tool or closure
///   runs** — fail-closed, never a pass-through.
///
/// The closures are the same seams the underlying entry points take:
/// inject [`crate::adapters::soffice_converter`] for `convert` and (with
/// the `render-hayro` feature) `crate::render_hayro::hayro_renderer` for
/// `render` — or your own. Each path's per-path limits (size caps, page
/// caps, raster validation, `%PDF-` checks) apply unchanged; see the
/// respective modules. Containment honesty is per-route — see the module
/// docs and [`Quarantined::sandbox`].
pub fn quarantine_bytes(
    input: &[u8],
    convert: impl FnOnce(&[u8]) -> Result<Vec<u8>, String>,
    render: impl FnOnce(&[u8]) -> Result<Vec<PageRaster>, String>,
) -> Result<Quarantined, QError> {
    match sniff_kind(input) {
        Some(SniffedKind::Image) => {
            let (result, status) = quarantine_image_sandboxed_on_worker(input);
            Ok(Quarantined {
                kind: SniffedKind::Image,
                bytes: result?,
                sandbox: Some(status),
            })
        }
        Some(SniffedKind::Pdf) => Ok(Quarantined {
            kind: SniffedKind::Pdf,
            bytes: quarantine_pdf(input, render)?,
            sandbox: None,
        }),
        Some(SniffedKind::Office(kind)) => Ok(Quarantined {
            kind: SniffedKind::Office(kind),
            bytes: quarantine_office(input, convert, render)?,
            sandbox: None,
        }),
        None => Err(QError::UnknownMagic(format!(
            "first bytes {:02X?} match no quarantine path (known: PNG, JPEG, %PDF-, \
             OOXML/ZIP, OLE2/CFB) — rejected without invoking any tool",
            &input[..input.len().min(8)]
        ))),
    }
}

/// The **default, non-injected** quarantine pipeline: route a byte blob by
/// magic through [`quarantine_bytes`], but with **both external tool seams
/// pre-wired to the crate's shipped adapters** instead of caller closures —
///
/// - `convert` = [`crate::adapters::soffice_converter`] with the given
///   [`SofficeConfig`](crate::adapters::SofficeConfig) (out-of-process
///   unmodified LibreOffice headless; wall-clock-killed, output-capped,
///   fail-closed — but **not** Landlock/seccomp-sandboxed, see `adapters.rs`);
/// - `render` = [`crate::render_hayro::hayro_renderer`] (in-process pure-Rust
///   `hayro` rasterizer — see the honest attack-surface register in
///   `render_hayro.rs`).
///
/// Only compiled with the **default-OFF `render-hayro` feature**, because
/// the renderer half lives behind it — a default build has no renderer to
/// wire, so there is no default pipeline to offer, by construction rather
/// than by a silent stub.
///
/// ## Which legs need what — and what runs regardless
///
/// The converter is invoked **only on the office route**
/// ([`SniffedKind::Office`]); the image and PDF routes never touch it (see
/// [`quarantine_bytes`]). So:
///
/// - **Image / PDF input** works with **no LibreOffice installed at all** —
///   the `soffice_converter` closure is constructed but never called, and
///   [`crate::adapters::soffice_convert`] resolves the executable lazily,
///   at call time, not when the closure is built.
/// - **Office input** requires a real `soffice` on the configured path;
///   absent one, the office route fails closed with the adapter's
///   executable-resolution error — never a pass-through.
///
/// Containment honesty is unchanged and per-route — see [`Quarantined::sandbox`]
/// and the module docs. This wires *ready* adapters; it does not add any
/// containment the adapters do not themselves provide.
///
/// ```no_run
/// use postern_quarantine::dispatch::default_pipeline;
///
/// // A PDF or image needs no LibreOffice; an office file does.
/// let untrusted: Vec<u8> = std::fs::read("inbound.pdf").unwrap();
/// let cleaned = default_pipeline(&untrusted).unwrap();
/// assert!(cleaned.bytes.starts_with(b"%PDF-") || cleaned.bytes.starts_with(b"\x89PNG"));
/// ```
#[cfg(feature = "render-hayro")]
pub fn default_pipeline(input: &[u8]) -> Result<Quarantined, QError> {
    default_pipeline_with_soffice_config(input, crate::adapters::SofficeConfig::default())
}

/// [`default_pipeline`] with an explicit
/// [`SofficeConfig`](crate::adapters::SofficeConfig) for the converter leg
/// (e.g. to point at a non-`PATH` LibreOffice install, or tighten the
/// wall-clock/output-size bounds). The renderer leg is
/// [`crate::render_hayro::hayro_renderer`] as in [`default_pipeline`]. Same
/// feature gate, same per-route honesty.
#[cfg(feature = "render-hayro")]
pub fn default_pipeline_with_soffice_config(
    input: &[u8],
    soffice: crate::adapters::SofficeConfig,
) -> Result<Quarantined, QError> {
    quarantine_bytes(
        input,
        crate::adapters::soffice_converter(soffice),
        crate::render_hayro::hayro_renderer(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::office::{OLE2_CFB_MAGIC, OOXML_ZIP_MAGIC};
    use crate::pdf::rebuild_pdf_from_pages;
    use image::{DynamicImage, ImageFormat, Rgb, RgbImage};
    use std::io::Cursor;

    fn raster(width: u32, height: u32, seed: u8) -> PageRaster {
        let n = (width * height * 3) as usize;
        let rgb8: Vec<u8> = (0..n).map(|i| seed.wrapping_add((i % 7) as u8)).collect();
        PageRaster::new(width, height, rgb8).unwrap()
    }

    fn small_jpeg() -> Vec<u8> {
        let mut img = RgbImage::new(3, 2);
        for (i, px) in img.pixels_mut().enumerate() {
            *px = Rgb([(i * 40) as u8, 7, 200]);
        }
        let mut jpeg = Vec::new();
        DynamicImage::ImageRgb8(img)
            .write_to(&mut Cursor::new(&mut jpeg), ImageFormat::Jpeg)
            .unwrap();
        jpeg
    }

    fn small_png() -> Vec<u8> {
        let img = RgbImage::new(2, 2);
        let mut png = Vec::new();
        DynamicImage::ImageRgb8(img)
            .write_to(&mut Cursor::new(&mut png), ImageFormat::Png)
            .unwrap();
        png
    }

    /// Closures that must NOT run on a given route.
    fn convert_must_not_run(_: &[u8]) -> Result<Vec<u8>, String> {
        panic!("convert closure invoked on a route that must not convert")
    }
    fn render_must_not_run(_: &[u8]) -> Result<Vec<PageRaster>, String> {
        panic!("render closure invoked on a route that must not render")
    }

    #[test]
    fn sniffer_recognises_all_five_magics_and_nothing_else() {
        assert_eq!(sniff_kind(&small_png()), Some(SniffedKind::Image));
        assert_eq!(sniff_kind(&small_jpeg()), Some(SniffedKind::Image));
        assert_eq!(sniff_kind(b"%PDF-1.7\n"), Some(SniffedKind::Pdf));
        assert_eq!(
            sniff_kind(&OOXML_ZIP_MAGIC),
            Some(SniffedKind::Office(OfficeKind::OoxmlZip))
        );
        assert_eq!(
            sniff_kind(&OLE2_CFB_MAGIC),
            Some(SniffedKind::Office(OfficeKind::LegacyOle2))
        );

        assert_eq!(sniff_kind(b""), None);
        assert_eq!(sniff_kind(b"hello world"), None);
        assert_eq!(sniff_kind(&[0xFF, 0xD8]), None); // SOI alone: too short
        assert_eq!(sniff_kind(&PNG_MAGIC[..7]), None); // truncated PNG magic
        assert_eq!(sniff_kind(b"<!DOCTYPE html>"), None);
    }

    #[test]
    fn jpeg_routes_to_the_image_path_without_touching_the_tool_closures() {
        let out = quarantine_bytes(&small_jpeg(), convert_must_not_run, render_must_not_run)
            .expect("jpeg must quarantine via the image path");
        assert_eq!(out.kind, SniffedKind::Image);
        assert_eq!(&out.bytes[..8], &PNG_MAGIC, "image output is a clean PNG");
        // The image route surfaces its sandbox status — never swallowed.
        let status = out.sandbox.expect("image route must report a SandboxStatus");
        #[cfg(not(target_os = "linux"))]
        assert!(
            matches!(status, SandboxStatus::Unsandboxed { .. }),
            "non-Linux must truthfully report Unsandboxed, got {status:?}"
        );
        #[cfg(target_os = "linux")]
        let _ = status; // any of the three variants is a truthful report
    }

    #[test]
    fn png_routes_to_the_image_path_too() {
        let out = quarantine_bytes(&small_png(), convert_must_not_run, render_must_not_run)
            .expect("png must quarantine via the image path");
        assert_eq!(out.kind, SniffedKind::Image);
        assert_eq!(&out.bytes[..8], &PNG_MAGIC);
        assert!(out.sandbox.is_some());
    }

    #[test]
    fn pdf_routes_to_the_pdf_path_and_never_invokes_the_converter() {
        let input = b"%PDF-1.7\nfake untrusted pdf".to_vec();
        let mut render_ran = false;
        let out = quarantine_bytes(&input, convert_must_not_run, |bytes| {
            render_ran = true;
            assert!(bytes.starts_with(b"%PDF-"));
            Ok(vec![raster(3, 2, 5)])
        })
        .unwrap();
        assert!(render_ran, "pdf route must use the injected renderer");
        assert_eq!(out.kind, SniffedKind::Pdf);
        assert!(out.bytes.starts_with(b"%PDF-"));
        assert!(
            out.sandbox.is_none(),
            "pdf route must not pretend to a sandbox status this crate does not provide"
        );
        let doc = lopdf::Document::load_mem(&out.bytes).unwrap();
        assert_eq!(doc.get_pages().len(), 1);
    }

    #[test]
    fn office_magics_route_to_the_office_path_with_both_closures() {
        for (input_magic, want_kind) in [
            (OOXML_ZIP_MAGIC.to_vec(), OfficeKind::OoxmlZip),
            (OLE2_CFB_MAGIC.to_vec(), OfficeKind::LegacyOle2),
        ] {
            let mut input = input_magic;
            input.extend_from_slice(b"EVIL_MACRO_MARKER payload");
            let out = quarantine_bytes(
                &input,
                |_| rebuild_pdf_from_pages(&[raster(2, 2, 9)]).map_err(|e| e.to_string()),
                |pdf_bytes| {
                    assert!(pdf_bytes.starts_with(b"%PDF-"));
                    Ok(vec![raster(2, 2, 9)])
                },
            )
            .unwrap();
            assert_eq!(out.kind, SniffedKind::Office(want_kind));
            assert!(out.bytes.starts_with(b"%PDF-"));
            assert!(out.sandbox.is_none());
            assert!(
                !out.bytes.windows(17).any(|w| w == b"EVIL_MACRO_MARKER"),
                "payload leaked through the office route"
            );
        }
    }

    #[test]
    fn unknown_magic_hard_errors_without_invoking_any_closure() {
        for input in [
            b"hello, plain text".as_slice(),
            b"",
            b"<!DOCTYPE html><script>evil()</script>",
            &[0xFF, 0xD8], // bare SOI — deliberately too short to commit
            &PNG_MAGIC[..7],
        ] {
            let res = quarantine_bytes(input, convert_must_not_run, render_must_not_run);
            match res {
                Err(QError::UnknownMagic(msg)) => {
                    assert!(msg.contains("rejected"), "{msg}")
                }
                other => panic!("expected UnknownMagic for {input:02X?}, got {other:?}"),
            }
        }
    }

    /// The dispatcher adds no leniency: a sniffed-but-corrupt input still
    /// fails inside its route (fail-closed end to end).
    #[test]
    fn corrupt_inputs_still_fail_inside_their_route() {
        // Valid JPEG magic, garbage body → image decode error.
        let res = quarantine_bytes(
            &[0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x00, 0x00],
            convert_must_not_run,
            render_must_not_run,
        );
        assert!(matches!(res, Err(QError::Decode(_))));

        // PDF magic, renderer that errors → surfaced, not swallowed.
        let res = quarantine_bytes(b"%PDF-1.4 junk", convert_must_not_run, |_| {
            Err("renderer exploded".to_string())
        });
        assert!(matches!(res, Err(QError::Decode(_))));
    }
}
