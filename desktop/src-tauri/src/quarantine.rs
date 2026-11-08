// SPDX-License-Identifier: MIT OR Apache-2.0
//! Quarantine — the desktop half of Postern Quarantine (inbound-document
//! safety; the mirror of Hygiene: Hygiene protects what you *send*,
//! Quarantine protects what you *receive*).
//!
//! This module wires the REAL `postern-quarantine` core (crates/
//! postern-quarantine) behind the `quarantine_rebuild` #[tauri::command].
//! An untrusted file is neutralised by rebuilding it from its rendered
//! content, so the original file structure — and any macro/script/tracker/
//! metadata riding in it — never reaches the viewer:
//!
//! - **Images** (PNG/JPEG): decode to raw pixels, re-encode a clean PNG. The
//!   decode runs behind `quarantine_image_sandboxed_on_worker`, so on a
//!   Landlock-capable Linux kernel the decode thread is confined and the
//!   achieved [`postern_quarantine::sandbox::SandboxStatus`] is surfaced to
//!   the UI verbatim (never swallowed; on macOS/Windows it truthfully reports
//!   `Unsandboxed`).
//! - **PDF**: render each page to a bitmap with the pure-Rust `hayro`
//!   rasterizer (the `render-hayro` feature, ON for this dep) and rebuild a
//!   flat, metadata-free PDF from the pixels alone (no `/Info`, `/ID`,
//!   `/Metadata`, `/JavaScript`, `/OpenAction`, `/EmbeddedFiles`, `/Names`,
//!   `/AA`, no compression filters).
//!
//! ## Honesty labels (carried on every result, never weakened)
//!
//! - The rebuild is **local and real**: bytes never leave this process.
//! - **NOT exploit-proof / NO OS-level containment.** The `hayro` PDF render
//!   runs **IN-PROCESS, in this app's address space** — the same
//!   attack-surface register as the image decode. A hostile PDF targets
//!   exactly that renderer; pure Rust removes the classic C-parser
//!   memory-unsafety class but not logic bugs, `unsafe` in dependencies, or
//!   resource exhaustion. There is **no out-of-process sandbox, no
//!   Landlock/seccomp around the renderer, and no wall-clock timeout** on the
//!   render. The image path's Landlock confinement is Linux-only and
//!   best-effort; on macOS/Windows nothing is sandboxed at all. Describe this
//!   as "output-sanitising rebuild, in-process render, containment pending",
//!   never as safe or complete.
//! - The **text layer / interactivity is destroyed by design** (pixels only;
//!   OCR to recover text is lossy). What is not carried over cannot carry a
//!   payload.
//! - The core is **UNAUDITED**, like everything in this repo.
//! - **Fail closed**: office documents (OOXML/OLE2) are rejected here — the
//!   LibreOffice converter adapter is NOT wired into the desktop (it would
//!   spawn a user-installed `soffice`), so an office file errors with a clear
//!   message rather than silently doing nothing. Unknown magic is rejected
//!   without invoking any renderer. No "clean" bytes are ever returned for
//!   input the core could not fully rebuild.
//!
//! The wire contract below is what `desktop/src/modules/quarantine.js`
//! consumes: `{ kind, real, cleanedB64, sandbox, note }`.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde::Serialize;

use postern_quarantine::dispatch::{quarantine_bytes, SniffedKind};
use postern_quarantine::render_hayro::hayro_renderer;
use postern_quarantine::QError;

/// The report shape `quarantine.js` renders. `rename_all = "camelCase"` maps
/// `cleaned_b64` → `cleanedB64` (the exact key the pane reads as
/// `rep.cleanedB64`); the other fields are single words and unchanged.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct QuarantineReport {
    /// Which path handled the input: `"image"` (PNG/JPEG → clean PNG) or
    /// `"pdf"` (`%PDF-` → clean flat PDF). Office/unknown never reach here —
    /// they fail closed with an error.
    pub kind: String,
    /// Always `true` here: this module only ever returns results the REAL
    /// core produced. Simulated results are never emitted — unsupported
    /// input errors out instead (fail closed).
    pub real: bool,
    /// The cleaned file, standard base64 (what `UI.fromB64` decodes). For an
    /// image this starts with the PNG magic; for a PDF it starts with
    /// `%PDF-`.
    pub cleaned_b64: String,
    /// The achieved sandbox status for the **image** route (the decode's
    /// Landlock confinement, surfaced verbatim — `Unsandboxed` on
    /// macOS/Windows and on Linux kernels without `CONFIG_SECURITY_LANDLOCK`,
    /// which is a truthful outcome, not a failure). For the **PDF** route this
    /// is a fixed "no containment" string: this crate applies no sandbox
    /// around the in-process renderer, and pretending otherwise would be a lie.
    pub sandbox: String,
    /// Honesty note surfaced verbatim in the pane (see module docs).
    pub note: String,
}

/// The honesty caveats every successful result carries (see module docs).
/// Kept as a constant so the pane and the tests can pin the exact text.
pub const NOTE_HONESTY: &str = "Rebuilt locally by the postern-quarantine Rust core — real, \
     offline, nothing uploaded. NOT exploit-proof and with NO OS-level containment: the PDF \
     render runs IN-PROCESS (the same attack surface as the image decode), pure Rust but with \
     no out-of-process sandbox, no Landlock/seccomp around the renderer, and no wall-clock \
     timeout; the image path's Landlock confinement is Linux-only and best-effort (macOS/Windows \
     are unsandboxed). The text layer and interactivity are destroyed by design (pixels only). \
     UNAUDITED, like everything in this repo.";

/// Pure, testable rebuild: route `bytes` through the real core
/// ([`postern_quarantine::dispatch::quarantine_bytes`]) and shape the result
/// for `quarantine.js`. `name` is used only in error messages (routing is by
/// magic bytes, never by extension).
///
/// The PDF renderer injected is the pure-Rust `hayro` adapter (feature
/// `render-hayro`, ON for this dep). The office `convert` closure is a
/// fail-closed stub: the desktop does NOT spawn a user-installed LibreOffice,
/// so an office document is rejected with a clear message rather than silently
/// doing nothing. Errors are honest and fail closed — no "clean" bytes are
/// ever returned for input the core could not fully rebuild, and no simulated
/// report is ever returned.
pub fn rebuild(name: &str, bytes: &[u8]) -> Result<QuarantineReport, String> {
    // Office `convert` closure: NOT wired in the desktop. It never runs on the
    // image/PDF routes (the dispatcher only invokes it for office magic); if an
    // office file is sniffed it fails closed with this message instead of
    // spawning a subprocess.
    let convert = |_untrusted: &[u8]| -> Result<Vec<u8>, String> {
        Err("office documents (.docx/.xlsx/.pptx, legacy OLE2) are not quarantined in the \
             desktop suite — that path needs a user-installed LibreOffice `soffice` converter \
             which this app deliberately does not spawn. Convert to PDF yourself first, then \
             quarantine the PDF."
            .to_string())
    };

    let out = quarantine_bytes(bytes, convert, hayro_renderer()).map_err(|e| match e {
        QError::UnknownMagic(_) => format!(
            "'{name}': unrecognized file — quarantine rebuilds images (PNG/JPEG) and PDFs only. \
             Fail closed: nothing was rendered and no clean result is faked."
        ),
        other => format!(
            "'{name}': {other} — fail closed: no partially-rebuilt bytes are ever returned."
        ),
    })?;

    let kind = match out.kind {
        SniffedKind::Image => "image",
        SniffedKind::Pdf => "pdf",
        // Office magic is sniffed but the convert stub above fails closed, so
        // quarantine_bytes returns Err before we get here. This arm exists so
        // the match is total and can never silently mislabel an office file.
        SniffedKind::Office(_) => {
            return Err(format!(
                "'{name}': office documents are not quarantined in the desktop suite (see above)."
            ))
        }
    };

    // The image route surfaces its real SandboxStatus; the PDF route provides
    // none (this crate applies no containment around the in-process renderer),
    // and we say exactly that rather than inventing a status.
    let sandbox = match &out.sandbox {
        Some(status) => status.to_string(),
        None => "no OS-level containment — the renderer runs in-process (see note)".to_string(),
    };

    Ok(QuarantineReport {
        kind: kind.to_string(),
        real: true,
        cleaned_b64: B64.encode(&out.bytes),
        sandbox,
        note: NOTE_HONESTY.to_string(),
    })
}

/// Base64 boundary for the command: decode what `quarantine.js` sends
/// (`UI.toB64` = standard base64 with padding) and run [`rebuild`]. Kept
/// separate and pure so tests can drive the exact wire path.
pub fn rebuild_b64(name: &str, bytes_b64: &str) -> Result<QuarantineReport, String> {
    let bytes = B64
        .decode(bytes_b64.trim())
        .map_err(|e| format!("'{name}': invalid base64 payload: {e}"))?;
    rebuild(name, &bytes)
}

/// `quarantine_rebuild` — the Tauri command `quarantine.js` invokes as
/// `api.invoke("quarantine_rebuild", { name, bytesB64 })`. Tauri v2 maps the
/// JS camelCase arg `bytesB64` to `bytes_b64` automatically.
#[tauri::command]
pub fn quarantine_rebuild(name: String, bytes_b64: String) -> Result<QuarantineReport, String> {
    rebuild_b64(&name, &bytes_b64)
}
