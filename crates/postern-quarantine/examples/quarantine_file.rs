//! Runnable end-to-end quarantine of one file:
//!
//! ```sh
//! cargo run -p postern-quarantine --example quarantine_file -- <input> [output]
//! # PDF/office inputs need a renderer — build one in:
//! cargo run -p postern-quarantine --features render-hayro --example quarantine_file -- <input> [output]
//! ```
//!
//! Routes by magic via `dispatch::quarantine_bytes`: PNG/JPEG → pixel
//! round-trip (clean PNG out), `%PDF-` → render + flat rebuild (clean flat
//! PDF out), OOXML/OLE2 → LibreOffice convert + render + flat rebuild.
//! Anything else is rejected fail-closed, without invoking any tool.
//!
//! Honesty, printed rather than assumed:
//! - the image route reports the achieved `SandboxStatus` (Landlock on a
//!   capable Linux kernel; truthfully `Unsandboxed` elsewhere, including
//!   this repo's macOS dev host);
//! - the PDF/office routes have NO OS-level containment from this crate —
//!   LibreOffice runs out-of-process bounded only by a wall-clock kill and
//!   an output cap, and the optional `hayro` renderer runs in-process;
//! - office conversion needs a user-installed LibreOffice (`soffice` on
//!   `PATH`, or the standard macOS app path probed below). MPL,
//!   aggregation-only: spawned, never linked.

use postern_quarantine::adapters::{find_soffice, soffice_converter, SofficeConfig};
use postern_quarantine::dispatch::{quarantine_bytes, SniffedKind};
use postern_quarantine::pdf::PageRaster;

fn render_closure() -> impl FnOnce(&[u8]) -> Result<Vec<PageRaster>, String> {
    #[cfg(feature = "render-hayro")]
    {
        postern_quarantine::render_hayro::hayro_renderer()
    }
    #[cfg(not(feature = "render-hayro"))]
    {
        |_untrusted: &[u8]| {
            Err("no renderer in this build — rebuild with `--features render-hayro` \
                 (or inject your own renderer in code). Fail-closed: the PDF was not \
                 passed through."
                .to_string())
        }
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(input_path) = args.next() else {
        eprintln!("usage: quarantine_file <input> [output]");
        std::process::exit(2);
    };
    let output_path = args.next();

    let input = match std::fs::read(&input_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("could not read {input_path}: {e}");
            std::process::exit(1);
        }
    };

    // Converter: soffice from PATH, plus the standard macOS app-bundle
    // location (LibreOffice.app does not put itself on PATH). Only invoked
    // if the input actually routes to the office path.
    let mut soffice_cfg = SofficeConfig::default();
    if find_soffice(None).is_none() {
        let mac_default =
            std::path::PathBuf::from("/Applications/LibreOffice.app/Contents/MacOS/soffice");
        if mac_default.is_file() {
            soffice_cfg.executable = Some(mac_default);
        }
    }

    match quarantine_bytes(&input, soffice_converter(soffice_cfg), render_closure()) {
        Ok(out) => {
            let (label, ext) = match out.kind {
                SniffedKind::Image => ("image (pixel round-trip)", "png"),
                SniffedKind::Pdf => ("PDF (render + flat rebuild)", "pdf"),
                SniffedKind::Office(_) => ("office (convert + render + flat rebuild)", "pdf"),
            };
            println!("route: {label}");
            match &out.sandbox {
                Some(status) => println!("image-decode sandbox status: {status}"),
                None => println!(
                    "containment: NONE from this crate on this route — the converter \
                     subprocess is bounded only by a wall-clock kill + output cap, and \
                     any in-process renderer runs with this process's full privileges."
                ),
            }
            let dest = output_path.unwrap_or_else(|| format!("{input_path}.quarantined.{ext}"));
            if let Err(e) = std::fs::write(&dest, &out.bytes) {
                eprintln!("could not write {dest}: {e}");
                std::process::exit(1);
            }
            println!("wrote {} bytes to {dest}", out.bytes.len());
            println!(
                "note: the output is rebuilt from pixels alone — metadata, macros, text \
                 layer, and interactivity are destroyed by design. Unaudited software; \
                 see the crate docs for the full honest threat model."
            );
        }
        Err(e) => {
            eprintln!("quarantine REFUSED (fail-closed): {e}");
            std::process::exit(1);
        }
    }
}
