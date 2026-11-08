//! Pure-Rust PDF renderer adapter (`hayro`) — a ready `render` closure for
//! [`crate::pdf::quarantine_pdf`] / [`crate::office::quarantine_office`].
//! Compiled ONLY with the default-OFF `render-hayro` cargo feature.
//!
//! ## License + maturity position (re-verified at adoption, 2026-07-16)
//!
//! [`hayro`](https://github.com/LaurenzV/hayro) is **`Apache-2.0 OR MIT`**
//! (crates.io metadata for 0.7.1 and the whole 0.5.0+ line; 0.2.0–0.4.0
//! were Apache-2.0-only — still permissive). It is pure Rust with
//! `#![forbid(unsafe_code)]` at the crate level, actively maintained, and
//! upstream regression-tests against 1000+ PDFs — but upstream itself
//! describes the feature set as incomplete (no encrypted PDFs, gaps in
//! blending/isolation). NOT poppler and NOT mutool: those are GPL/AGPL and
//! off-limits in this repo.
//!
//! ## Honest attack-surface register — read before enabling the feature
//!
//! This renderer runs **in-process, in the caller's address space** — the
//! **same register as the image path** in `lib.rs`, and it must be described
//! the same way. A hostile PDF targets exactly this parser/rasterizer:
//!
//! - Pure Rust removes the classic C-parser memory-unsafety class, and
//!   `hayro` itself forbids `unsafe` — but its dependencies contain
//!   `unsafe` blocks, and logic bugs, panics, and resource exhaustion
//!   remain in scope. A panic during render is caught here and mapped to a
//!   fail-closed error, not a crash — but a panic is the *polite* failure
//!   mode; do not read the catch as containment.
//! - **No out-of-process containment, no Landlock/seccomp, no wall-clock
//!   timeout on the render itself.** The Dangerzone-shaped out-of-process
//!   design in the crate docs still does not exist here. On macOS/Windows
//!   nothing is sandboxed at all.
//! - What IS enforced, fail-closed: the page-count cap ([`crate::pdf::MAX_PAGES`])
//!   is checked before any page is rendered, and every produced raster goes
//!   through [`PageRaster::new`]'s validation ([`crate::MAX_DIMENSION`] per
//!   axis, exact buffer size) — an over-cap render is rejected, never
//!   truncated. [`crate::pdf::quarantine_pdf`] then re-validates everything
//!   on rebuild.
//!
//! Describe this adapter as "in-process pure-Rust render, resource-capped,
//! panic-caught, no OS-level containment" — never as sandboxed or
//! exploit-proof.

use crate::pdf::{PageRaster, MAX_PAGES};
use crate::MAX_INPUT_BYTES;

use hayro::hayro_interpret::InterpreterSettings;
use hayro::hayro_syntax::Pdf;
use hayro::vello_cpu::color::palette::css::WHITE;
use hayro::{render, RenderCache, RenderSettings};

/// Factory: build the `render` closure the PDF/office quarantine entry
/// points take, backed by [`render_pdf_pages`]. The existing injected-
/// closure seams are untouched — this is just a ready-made thing to inject:
///
/// ```
/// use postern_quarantine::pdf::quarantine_pdf;
/// use postern_quarantine::render_hayro::hayro_renderer;
///
/// # let untrusted = postern_quarantine::pdf::rebuild_pdf_from_pages(
/// #     &[postern_quarantine::pdf::PageRaster::new(2, 2, vec![7; 12]).unwrap()],
/// # ).unwrap();
/// let clean = quarantine_pdf(&untrusted, hayro_renderer()).unwrap();
/// assert!(clean.starts_with(b"%PDF-"));
/// ```
pub fn hayro_renderer() -> impl FnOnce(&[u8]) -> Result<Vec<PageRaster>, String> {
    |input| render_pdf_pages(input)
}

/// Render every page of an untrusted PDF to a validated [`PageRaster`] at
/// 1 px per PDF point (72 dpi nominal — the same scale the flat rebuild
/// draws at, so a quarantine round-trip preserves page geometry).
///
/// Fail-closed on: input over [`MAX_INPUT_BYTES`] (defense in depth —
/// [`crate::pdf::quarantine_pdf`] already enforces it), unparseable PDF,
/// zero pages, more than [`MAX_PAGES`] pages (checked BEFORE rendering
/// anything), a panicking render (caught, mapped to `Err`), and any raster
/// [`PageRaster::new`] rejects (over-[`crate::MAX_DIMENSION`] axes, zero
/// axes). See the module docs for what is honestly NOT contained.
pub fn render_pdf_pages(input: &[u8]) -> Result<Vec<PageRaster>, String> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(format!(
            "input is {} bytes (cap {MAX_INPUT_BYTES})",
            input.len()
        ));
    }
    let pdf = Pdf::new(input.to_vec())
        .map_err(|e| format!("hayro could not parse the PDF: {e:?}"))?;
    let pages = pdf.pages();
    if pages.is_empty() {
        return Err("PDF has zero pages".to_string());
    }
    if pages.len() > MAX_PAGES {
        return Err(format!(
            "PDF declares {} pages (cap {MAX_PAGES}) — refusing to render any \
             (page-count-bomb guard)",
            pages.len()
        ));
    }

    // Default interpreter settings; with this crate's default `hayro`
    // features the 14 standard fonts + predefined CMaps are embedded, so
    // text that relies on them still rasterizes (see Cargo.toml).
    let interpreter_settings = InterpreterSettings::default();
    let render_settings = RenderSettings {
        x_scale: 1.0,
        y_scale: 1.0,
        width: None,
        height: None,
        // Opaque white base: PDF viewers draw on white; a transparent base
        // would silently change how pages look after the RGB flatten below.
        bg_color: WHITE,
    };
    let cache = RenderCache::new();

    let mut rasters = Vec::with_capacity(pages.len());
    for (index, page) in pages.iter().enumerate() {
        // A hostile PDF that panics the rasterizer must fail the quarantine,
        // not crash the caller. (Catching is politeness, not containment —
        // module docs.)
        let pixmap = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            render(page, &cache, &interpreter_settings, &render_settings)
        }))
        .map_err(|_| format!("renderer panicked on page {index} — input rejected"))?;

        let (width, height) = (pixmap.width() as u32, pixmap.height() as u32);
        // Flatten premultiplied-RGBA over white to the exact RGB8 layout
        // `PageRaster` requires. With an opaque white bg alpha is already
        // 255 everywhere in practice; the blend below is the defensive
        // general case rather than an assumption.
        let rgba = pixmap.take_unpremultiplied();
        let mut rgb8 = Vec::with_capacity(rgba.len() * 3);
        for px in rgba {
            let a = px.a as u16;
            for c in [px.r, px.g, px.b] {
                rgb8.push(((c as u16 * a + 255 * (255 - a) + 127) / 255) as u8);
            }
        }
        rasters.push(
            PageRaster::new(width, height, rgb8)
                .map_err(|e| format!("page {index} raster rejected: {e}"))?,
        );
    }
    Ok(rasters)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdf::{quarantine_pdf, rebuild_pdf_from_pages};
    use crate::MAX_DIMENSION;

    /// Deterministic raster, same shape as the pdf.rs test helper.
    fn raster(width: u32, height: u32, seed: u8) -> PageRaster {
        let n = (width * height * 3) as usize;
        let rgb8: Vec<u8> = (0..n).map(|i| seed.wrapping_add((i % 7) as u8)).collect();
        PageRaster::new(width, height, rgb8).unwrap()
    }

    /// Hand-emit a minimal, valid PDF with `count` content-less pages of the
    /// given MediaBox — for cap tests that the crate's own emitter (which
    /// enforces the caps at rebuild) can't produce.
    fn minimal_pdf(count: usize, width: u32, height: u32) -> Vec<u8> {
        let mut out: Vec<u8> = b"%PDF-1.4\n".to_vec();
        let mut offsets = Vec::new();
        let push = |out: &mut Vec<u8>, offsets: &mut Vec<usize>, id: usize, body: &str| {
            offsets.push(out.len());
            out.extend_from_slice(format!("{id} 0 obj\n{body}\nendobj\n").as_bytes());
        };
        push(&mut out, &mut offsets, 1, "<< /Type /Catalog /Pages 2 0 R >>");
        let kids: Vec<String> = (0..count).map(|j| format!("{} 0 R", 3 + j)).collect();
        push(
            &mut out,
            &mut offsets,
            2,
            &format!("<< /Type /Pages /Kids [{}] /Count {count} >>", kids.join(" ")),
        );
        for j in 0..count {
            push(
                &mut out,
                &mut offsets,
                3 + j,
                &format!("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {width} {height}] >>"),
            );
        }
        let total = 2 + count;
        let xref = out.len();
        out.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", total + 1).as_bytes());
        for o in &offsets {
            out.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes());
        }
        out.extend_from_slice(
            format!(
                "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
                total + 1
            )
            .as_bytes(),
        );
        out
    }

    fn minimal_pdf_with_mediabox(width: u32, height: u32) -> Vec<u8> {
        minimal_pdf(1, width, height)
    }

    /// OFFLINE round-trip on crate-emitted flat PDFs: page count and page
    /// geometry survive rebuild -> hayro render -> rebuild.
    #[test]
    fn renders_crate_emitted_flat_pdfs_with_matching_page_count_and_geometry() {
        let pages = [raster(4, 3, 10), raster(2, 5, 90)];
        let flat = rebuild_pdf_from_pages(&pages).unwrap();

        let rendered = render_pdf_pages(&flat).unwrap();
        assert_eq!(rendered.len(), pages.len());
        // 1 px/pt both ways, so dimensions round-trip exactly.
        for (got, want) in rendered.iter().zip(pages.iter()) {
            assert_eq!((got.width, got.height), (want.width, want.height));
            assert_eq!(got.rgb8.len(), want.rgb8.len());
        }
    }

    /// OFFLINE end-to-end: the full quarantine_pdf path with this renderer
    /// injected produces a parseable flat PDF that keeps the banned-token
    /// guarantees.
    #[test]
    fn quarantine_pdf_with_hayro_keeps_the_banned_token_guarantees() {
        let flat = rebuild_pdf_from_pages(&[raster(3, 2, 42)]).unwrap();
        let out = quarantine_pdf(&flat, hayro_renderer()).unwrap();

        let doc = lopdf::Document::load_mem(&out).expect("output must be a parseable PDF");
        assert_eq!(doc.get_pages().len(), 1);
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
    }

    #[test]
    fn garbage_and_non_pdf_inputs_are_rejected() {
        assert!(render_pdf_pages(b"not a pdf at all").is_err());
        assert!(render_pdf_pages(b"").is_err());
    }

    /// A page whose MediaBox exceeds MAX_DIMENSION per axis must be
    /// rejected by the PageRaster validation — fail-closed, never scaled
    /// down or truncated.
    #[test]
    fn over_dimension_pages_are_rejected_not_truncated() {
        let bomb = minimal_pdf_with_mediabox(MAX_DIMENSION + 100, 10);
        let err = render_pdf_pages(&bomb).unwrap_err();
        assert!(
            err.contains("rejected") || err.contains("cap"),
            "expected a raster-cap rejection, got: {err}"
        );
    }

    /// A PDF declaring more than MAX_PAGES pages must be rejected BEFORE
    /// any page is rendered (page-count-bomb guard).
    #[test]
    fn page_count_bomb_is_rejected_before_rendering() {
        let bomb = minimal_pdf(MAX_PAGES + 1, 2, 2);
        let start = std::time::Instant::now();
        let err = render_pdf_pages(&bomb).unwrap_err();
        assert!(err.contains("page-count-bomb"), "expected the page cap, got: {err}");
        assert!(
            start.elapsed() < std::time::Duration::from_secs(30),
            "rejection must come from the cap check, not from rendering 10k+ pages"
        );
    }

    /// A sane hand-emitted empty page renders to its MediaBox geometry
    /// (proves the cap test above fails for the right reason, not because
    /// hand-emitted PDFs are unparseable).
    #[test]
    fn sane_hand_emitted_page_renders_to_its_mediabox_geometry() {
        let pdf = minimal_pdf_with_mediabox(7, 9);
        let rendered = render_pdf_pages(&pdf).unwrap();
        assert_eq!(rendered.len(), 1);
        assert_eq!((rendered[0].width, rendered[0].height), (7, 9));
        // Empty page over the white base: pure white pixels.
        assert!(rendered[0].rgb8.iter().all(|&b| b == 255));
    }
}
