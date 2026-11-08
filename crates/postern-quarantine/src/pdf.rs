//! Flat-PDF rebuild from page rasters — the **output half** of the PDF
//! quarantine path, pure Rust, no new runtime dependencies.
//!
//! ## What ships here, honestly
//!
//! - **A renderer adapter now exists — behind the default-OFF `render-hayro`
//!   feature only.** This module can *rebuild* a clean PDF from
//!   already-rendered page bitmaps; rendering an untrusted PDF to those
//!   bitmaps stays an **injected closure** (`render`) on
//!   [`quarantine_pdf`] — the seam is unchanged. A default build still
//!   ships no renderer and there is no default one to inject; with the
//!   `render-hayro` cargo feature, `crate::render_hayro::hayro_renderer`
//!   provides a ready closure built on the pure-Rust `hayro` rasterizer
//!   (Apache-2.0 OR MIT — license re-verified at adoption; see Cargo.toml
//!   and `render_hayro.rs`).
//! - **The text layer is destroyed by design.** The rebuilt PDF contains one
//!   uncompressed `/DeviceRGB` image per page and *nothing else* — no text,
//!   no fonts, no links, no forms, no interactivity. Text can only be
//!   recovered by OCR, which is lossy. That destruction is the point: what
//!   is not carried over cannot carry a payload.
//! - **This is NOT exploit-proof** — same register as the image path. The
//!   *rebuild* step here never parses the untrusted input at all (it only
//!   consumes rasters), but the *render* step is exactly the classic PDF
//!   attack surface: a malicious PDF targets the renderer, and the renderer
//!   runs wherever the caller runs it. The shipped `hayro` adapter runs
//!   **in-process, in the caller's address space** — pure Rust
//!   (`forbid(unsafe_code)` upstream, panics caught and mapped to errors),
//!   which removes the classic C-parser memory-unsafety class but not
//!   logic bugs, `unsafe` in its dependencies, or resource exhaustion. The
//!   design still calls for the render to happen out-of-process under
//!   Landlock/seccomp with a wall-clock timeout (Dangerzone's concept —
//!   Dangerzone is **AGPL**, so reimplemented here, no code taken); **that
//!   containment still does not exist in this crate**, and on
//!   macOS/Windows nothing is sandboxed at all. Describe this module as
//!   "output-side rebuild + optional in-process pure-Rust render,
//!   containment pending", never as a complete or safe PDF quarantine.
//!
//! ## What the rebuilt PDF contains — and provably does not
//!
//! The emitter writes, by hand, the minimal flat structure: a `/Catalog`, a
//! `/Pages` tree, and per page one `/Page`, one uncompressed `/DeviceRGB`
//! image XObject, and one tiny content stream that draws it. It never writes:
//!
//! - a trailer `/Info` dictionary (no producer/author/dates),
//! - a trailer `/ID` (no file-tracking identifier),
//! - `/Metadata` (no XMP),
//! - `/Names`, `/OpenAction`, `/JavaScript`, `/AA` (no actions, no scripts),
//! - `/EmbeddedFiles` or any attachment machinery,
//! - compression filters (streams are raw, so what you see in the bytes is
//!   what a viewer gets — nothing to hide a payload inside).
//!
//! Because these names are simply never emitted, tests can (and do) assert
//! their absence on the raw output bytes, not just via a parser's view.

use crate::{QError, MAX_DIMENSION, MAX_INPUT_BYTES};

/// Hard cap on the number of pages a rebuild will accept (page-count-bomb
/// guard: a renderer coerced into producing millions of pages must be
/// rejected, not serialised). Generous for real documents.
pub const MAX_PAGES: usize = 10_000;

/// One rendered page: raw 8-bit RGB pixels, row-major, no padding.
///
/// Fields are public so a renderer adapter can build one directly, but
/// [`rebuild_pdf_from_pages`] re-validates every raster before emitting, so
/// a malformed `PageRaster` can never produce a malformed PDF — construct
/// via [`PageRaster::new`] to get the same validation up front.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageRaster {
    /// Page width in pixels (1..=[`MAX_DIMENSION`]).
    pub width: u32,
    /// Page height in pixels (1..=[`MAX_DIMENSION`]).
    pub height: u32,
    /// Exactly `width * height * 3` bytes of RGB8 pixel data.
    pub rgb8: Vec<u8>,
}

impl PageRaster {
    /// Validating constructor. Rejects zero or over-[`MAX_DIMENSION`] axes
    /// and any pixel buffer whose length is not exactly `width * height * 3`.
    pub fn new(width: u32, height: u32, rgb8: Vec<u8>) -> Result<Self, QError> {
        let raster = PageRaster { width, height, rgb8 };
        raster.validate()?;
        Ok(raster)
    }

    /// The invariant check shared by [`PageRaster::new`] and
    /// [`rebuild_pdf_from_pages`] (which re-checks because the fields are
    /// public and could have been mutated after construction).
    fn validate(&self) -> Result<(), QError> {
        if self.width > MAX_DIMENSION || self.height > MAX_DIMENSION {
            return Err(QError::TooLarge(format!(
                "page raster is {}x{} (cap {} per axis)",
                self.width, self.height, MAX_DIMENSION
            )));
        }
        if self.width == 0 || self.height == 0 {
            return Err(QError::Decode(format!(
                "page raster has a zero dimension ({}x{})",
                self.width, self.height
            )));
        }
        // Caps above bound this at 16384*16384*3 < 2^31, so no overflow even
        // on 32-bit targets — but compute checked anyway, defensively.
        let expected = (self.width as usize)
            .checked_mul(self.height as usize)
            .and_then(|px| px.checked_mul(3))
            .ok_or_else(|| QError::TooLarge("page raster pixel count overflows".to_string()))?;
        if self.rgb8.len() != expected {
            return Err(QError::Decode(format!(
                "page raster buffer is {} bytes, expected {} ({}x{} RGB8)",
                self.rgb8.len(),
                expected,
                self.width,
                self.height
            )));
        }
        Ok(())
    }
}

/// Push one PDF object onto `out`, recording its byte offset for the xref.
fn push_object(out: &mut Vec<u8>, offsets: &mut Vec<usize>, id: usize, body: &[u8]) {
    offsets.push(out.len());
    out.extend_from_slice(format!("{id} 0 obj\n").as_bytes());
    out.extend_from_slice(body);
    out.extend_from_slice(b"\nendobj\n");
}

/// Rebuild a minimal, flat PDF from rendered page rasters — pixels and
/// nothing else. See the module docs for the exact structure emitted and the
/// full list of what is deliberately absent (`/Info`, trailer `/ID`,
/// `/Metadata`, `/Names`, `/OpenAction`, `/JavaScript`, `/EmbeddedFiles`,
/// compression filters).
///
/// Each page becomes one uncompressed `/DeviceRGB` image XObject drawn at
/// one pixel per PDF point (72 dpi nominal). Limits: at most [`MAX_PAGES`]
/// pages, each raster within [`MAX_DIMENSION`] per axis — violations are
/// rejected as [`QError::TooLarge`], never truncated or downscaled. An empty
/// page list is rejected (a zero-page PDF is not a document).
pub fn rebuild_pdf_from_pages(pages: &[PageRaster]) -> Result<Vec<u8>, QError> {
    if pages.is_empty() {
        return Err(QError::Encode("no pages to rebuild (renderer returned zero pages)".to_string()));
    }
    if pages.len() > MAX_PAGES {
        return Err(QError::TooLarge(format!(
            "{} pages (cap {})",
            pages.len(),
            MAX_PAGES
        )));
    }
    for page in pages {
        page.validate()?;
    }

    // Object numbering: 1 = Catalog, 2 = Pages, then per page j (0-based):
    // 3+3j = Page, 4+3j = image XObject, 5+3j = content stream.
    let total_objects = 2 + 3 * pages.len();
    let mut out: Vec<u8> = Vec::new();
    let mut offsets: Vec<usize> = Vec::with_capacity(total_objects);

    out.extend_from_slice(b"%PDF-1.4\n");
    // Conventional binary-marker comment so transports treat the file as binary.
    out.extend_from_slice(&[b'%', 0xE2, 0xE3, 0xCF, 0xD3, b'\n']);

    push_object(&mut out, &mut offsets, 1, b"<< /Type /Catalog /Pages 2 0 R >>");

    let kids: Vec<String> = (0..pages.len()).map(|j| format!("{} 0 R", 3 + 3 * j)).collect();
    push_object(
        &mut out,
        &mut offsets,
        2,
        format!(
            "<< /Type /Pages /Kids [{}] /Count {} >>",
            kids.join(" "),
            pages.len()
        )
        .as_bytes(),
    );

    for (j, page) in pages.iter().enumerate() {
        let (page_id, image_id, content_id) = (3 + 3 * j, 4 + 3 * j, 5 + 3 * j);
        let (w, h) = (page.width, page.height);

        push_object(
            &mut out,
            &mut offsets,
            page_id,
            format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {w} {h}] \
                 /Resources << /XObject << /Im0 {image_id} 0 R >> >> \
                 /Contents {content_id} 0 R >>"
            )
            .as_bytes(),
        );

        // Uncompressed image XObject: the raster bytes, verbatim.
        let mut image_body = format!(
            "<< /Type /XObject /Subtype /Image /Width {w} /Height {h} \
             /ColorSpace /DeviceRGB /BitsPerComponent 8 /Length {} >>\nstream\n",
            page.rgb8.len()
        )
        .into_bytes();
        image_body.extend_from_slice(&page.rgb8);
        image_body.extend_from_slice(b"\nendstream");
        push_object(&mut out, &mut offsets, image_id, &image_body);

        // Content stream: scale the unit-square image to the page and draw it.
        let content = format!("q\n{w} 0 0 {h} 0 0 cm\n/Im0 Do\nQ");
        let content_body = format!(
            "<< /Length {} >>\nstream\n{content}\nendstream",
            content.len()
        );
        push_object(&mut out, &mut offsets, content_id, content_body.as_bytes());
    }

    // Cross-reference table + trailer. Deliberately NO /Info and NO /ID.
    let xref_offset = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n", total_objects + 1).as_bytes());
    out.extend_from_slice(b"0000000000 65535 f \n");
    for offset in &offsets {
        out.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{}\n%%EOF\n",
            total_objects + 1,
            xref_offset
        )
        .as_bytes(),
    );

    Ok(out)
}

/// Neutralise an untrusted PDF by rebuilding it from rendered page bitmaps.
///
/// **A renderer must be injected.** The `render` closure receives the
/// untrusted bytes and must return one [`PageRaster`] per page. A default
/// build ships no renderer; with the default-OFF `render-hayro` cargo
/// feature, `crate::render_hayro::hayro_renderer()` is a ready closure to
/// inject (pure-Rust, **in-process** — see `render_hayro.rs` for its honest
/// attack-surface register). Whatever the closure does with the untrusted
/// bytes happens with the closure's privileges — this function adds **no
/// containment around the render** (the out-of-process Landlock/seccomp
/// design in the module docs still does not exist).
///
/// What this function itself enforces:
/// - the input is at most [`MAX_INPUT_BYTES`] (else [`QError::TooLarge`]);
/// - the input starts with the `%PDF-` magic (strict prefix — quarantine has
///   no reason to honour preamble junk before the header; else
///   [`QError::Decode`]);
/// - a renderer error string is surfaced as [`QError::Decode`];
/// - the output is rebuilt exclusively from the returned rasters via
///   [`rebuild_pdf_from_pages`], so no byte of the untrusted input can reach
///   the output except by being visible in the rendered pixels.
pub fn quarantine_pdf(
    input: &[u8],
    render: impl FnOnce(&[u8]) -> Result<Vec<PageRaster>, String>,
) -> Result<Vec<u8>, QError> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(QError::TooLarge(format!(
            "input is {} bytes (cap {})",
            input.len(),
            MAX_INPUT_BYTES
        )));
    }
    if !input.starts_with(b"%PDF-") {
        return Err(QError::Decode(
            "input does not start with the %PDF- magic".to_string(),
        ));
    }
    let pages = render(input).map_err(QError::Decode)?;
    rebuild_pdf_from_pages(&pages)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic raster whose bytes cannot collide with any PDF name
    /// token (values stay below ASCII '/' where it matters — pattern is
    /// arbitrary but fixed, so byte-level assertions on the output are
    /// meaningful).
    fn raster(width: u32, height: u32, seed: u8) -> PageRaster {
        let n = (width * height * 3) as usize;
        let rgb8: Vec<u8> = (0..n).map(|i| seed.wrapping_add((i % 7) as u8)).collect();
        PageRaster::new(width, height, rgb8).unwrap()
    }

    /// A fake untrusted PDF stuffed with every payload the rebuild must
    /// destroy. It is never parsed by this module — the fake renderer below
    /// ignores it — which is exactly the design: input bytes reach the
    /// output only via pixels.
    fn tainted_pdf_input() -> Vec<u8> {
        b"%PDF-1.7\n\
          1 0 obj << /Type /Catalog /OpenAction 9 0 R /Names 8 0 R >> endobj\n\
          9 0 obj << /S /JavaScript /JS (app.alert('EVIL_PAYLOAD_MARKER')) >> endobj\n\
          8 0 obj << /EmbeddedFiles << /Names [(evil.exe) 7 0 R] >> >> endobj\n\
          5 0 obj << /Type /Metadata /Subtype /XML >> endobj\n\
          trailer << /Root 1 0 R /Info 6 0 R /ID [<41> <42>] >>\n\
          %%EOF"
            .to_vec()
    }

    #[test]
    fn rebuilt_pdf_parses_with_the_right_page_count() {
        let pages = [raster(4, 3, 10), raster(2, 5, 90)];
        let out = rebuild_pdf_from_pages(&pages).unwrap();
        let doc = lopdf::Document::load_mem(&out).expect("output must be a parseable PDF");
        assert_eq!(doc.get_pages().len(), 2);
    }

    #[test]
    fn forbidden_names_never_appear_in_the_raw_output_bytes() {
        let input = tainted_pdf_input();
        let out = quarantine_pdf(&input, |_untrusted| {
            Ok(vec![raster(4, 3, 10), raster(2, 5, 90)])
        })
        .unwrap();

        // Byte-level, not parser-level: these tokens are simply never emitted.
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
                "forbidden token {:?} found in rebuilt PDF",
                String::from_utf8_lossy(forbidden)
            );
        }
        // And specifically: the trailer carries neither /Info nor /ID.
        let doc = lopdf::Document::load_mem(&out).unwrap();
        assert!(doc.trailer.get(b"Info").is_err(), "trailer must have no /Info");
        assert!(doc.trailer.get(b"ID").is_err(), "trailer must have no /ID");
    }

    #[test]
    fn planted_payload_in_the_input_never_survives() {
        let input = tainted_pdf_input();
        assert!(
            input.windows(19).any(|w| w == b"EVIL_PAYLOAD_MARKER"),
            "sanity: the payload is in the input"
        );
        let out = quarantine_pdf(&input, |_untrusted| Ok(vec![raster(3, 3, 42)])).unwrap();
        assert!(
            !out.windows(19).any(|w| w == b"EVIL_PAYLOAD_MARKER"),
            "input payload leaked into the rebuilt PDF"
        );
    }

    #[test]
    fn pixel_data_round_trips_exactly() {
        let pages = [raster(4, 3, 10), raster(2, 5, 90)];
        let out = rebuild_pdf_from_pages(&pages).unwrap();
        let doc = lopdf::Document::load_mem(&out).unwrap();

        // Collect image streams in ascending object-id order — that is the
        // page order by construction (image ids 4, 7, 10, ...).
        let mut images: Vec<(lopdf::ObjectId, Vec<u8>)> = doc
            .objects
            .iter()
            .filter_map(|(&id, obj)| match obj {
                lopdf::Object::Stream(s)
                    if matches!(s.dict.get(b"Subtype"), Ok(lopdf::Object::Name(n)) if n == b"Image") =>
                {
                    Some((id, s.content.clone()))
                }
                _ => None,
            })
            .collect();
        images.sort_by_key(|(id, _)| *id);

        assert_eq!(images.len(), pages.len());
        for ((_, extracted), page) in images.iter().zip(pages.iter()) {
            assert_eq!(extracted, &page.rgb8, "image stream must be the raster, verbatim");
        }
    }

    #[test]
    fn dimension_bombs_are_rejected() {
        // Over-cap axis at construction …
        let err = PageRaster::new(MAX_DIMENSION + 1, 1, vec![0; 3]).unwrap_err();
        assert!(matches!(err, QError::TooLarge(_)));
        // … and again at rebuild even if the struct was mutated afterwards.
        let mut sneaky = raster(1, 1, 0);
        sneaky.width = MAX_DIMENSION + 1;
        assert!(matches!(
            rebuild_pdf_from_pages(&[sneaky]),
            Err(QError::TooLarge(_))
        ));
    }

    #[test]
    fn page_count_bomb_is_rejected() {
        let pages = vec![raster(1, 1, 0); MAX_PAGES + 1];
        assert!(matches!(
            rebuild_pdf_from_pages(&pages),
            Err(QError::TooLarge(_))
        ));
    }

    #[test]
    fn mismatched_buffer_and_zero_dimensions_are_rejected() {
        assert!(matches!(
            PageRaster::new(2, 2, vec![0; 11]), // needs 12
            Err(QError::Decode(_))
        ));
        assert!(matches!(PageRaster::new(0, 4, vec![]), Err(QError::Decode(_))));
    }

    #[test]
    fn input_without_pdf_magic_errors_before_the_renderer_runs() {
        let mut renderer_ran = false;
        let res = quarantine_pdf(b"not a pdf at all", |_| {
            renderer_ran = true;
            Ok(vec![raster(1, 1, 0)])
        });
        assert!(matches!(res, Err(QError::Decode(_))));
        assert!(!renderer_ran, "renderer must never see non-PDF bytes");
    }

    #[test]
    fn oversized_input_is_rejected_before_the_renderer_runs() {
        let mut huge = b"%PDF-1.4\n".to_vec();
        huge.resize(MAX_INPUT_BYTES + 1, 0);
        let res = quarantine_pdf(&huge, |_| Ok(vec![raster(1, 1, 0)]));
        assert!(matches!(res, Err(QError::TooLarge(_))));
    }

    #[test]
    fn renderer_errors_and_zero_pages_surface_as_errors() {
        let input = b"%PDF-1.4\nstub".to_vec();
        assert!(matches!(
            quarantine_pdf(&input, |_| Err("renderer exploded".to_string())),
            Err(QError::Decode(_))
        ));
        assert!(matches!(
            quarantine_pdf(&input, |_| Ok(vec![])),
            Err(QError::Encode(_))
        ));
    }
}
