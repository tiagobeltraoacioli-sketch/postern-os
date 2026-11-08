// SPDX-License-Identifier: MIT OR Apache-2.0
//! Hygiene — the desktop half of Postern Hygiene (metadata scrub-by-default).
//!
//! This module wires the REAL `postern-hygiene` Rust core (crates/
//! postern-hygiene: `scrub_bytes` → OOXML/ODF, JPEG, PNG, PDF) behind the
//! `hygiene_scrub` #[tauri::command], replacing the JS preview engine's
//! simulated OOXML/PDF reports. The wire contract below matches EXACTLY what
//! `desktop/src/modules/hygiene.js` already consumes:
//! `{ kind, real, removed: [..], cleanedB64, note }`.
//!
//! FRONTEND LANE NOTE (do not fix here): the Hygiene pane goes live once the
//! frontend lane adds `"hygiene_scrub"` to `api.js`'s `REAL` set — this
//! command's contract already matches `hygiene.js`'s call
//! (`api.invoke("hygiene_scrub", { name, bytesB64 })`) byte-for-byte, so no
//! frontend change beyond that one REAL-set entry is needed.
//!
//! ## Honesty labels (carried, never weakened)
//!
//! - The scrub is **local and real**: bytes never leave this process, and the
//!   `removed` list is change-accurate (the core only reports parts whose
//!   emitted bytes actually differ — see `ScrubReport::cleaned`).
//! - The core is **UNAUDITED** (like everything in this repo, pre-mainnet).
//! - The **opt-in prove/seal backend is still pending** — scrub is the
//!   default; sealing is a separate choice because a provenance trail can
//!   de-anonymize (PRINCIPLES.md §6). The `note` field carries all of this to
//!   the UI on every result.
//! - **Fail closed**: an unrecognized format (`detect_format` → `None`) or a
//!   malformed input returns an error — this backend NEVER returns
//!   `real: true` for a simulated or partially-scrubbed result. If the core
//!   had to pass any part through unscrubbed (e.g. embedded EMF media), the
//!   `note` says so loudly instead of blessing the output as fully clean.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde::Serialize;

/// The report shape `hygiene.js` renders. `rename_all = "camelCase"` maps
/// `cleaned_b64` → `cleanedB64` (the exact key the pane reads as
/// `rep.cleanedB64`); the other fields are single words and unchanged.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HygieneReport {
    /// Detected format: `"ooxml"` (OOXML **and** ODF — both are zip document
    /// packages, one scrubber), `"jpeg"`, `"png"`, or `"pdf"`.
    pub kind: String,
    /// Always `true` here: this module only ever returns results the REAL
    /// core produced. Simulated results are never emitted — unsupported
    /// input errors out instead (fail closed).
    pub real: bool,
    /// Change-accurate list of what was removed/rewritten (empty = the file
    /// was already clean; scrubbing is idempotent).
    pub removed: Vec<String>,
    /// The cleaned file, standard base64 (what `UI.fromB64` decodes).
    pub cleaned_b64: String,
    /// Honesty note surfaced verbatim in the pane (see module docs).
    pub note: String,
}

/// The honesty caveats every successful result carries (see module docs).
const NOTE_HONESTY: &str = "Scrubbed locally by the postern-hygiene Rust core — real, offline, \
     nothing uploaded. The core is UNAUDITED; the opt-in prove/seal backend is still pending \
     (scrub is the default, sealing stays a separate opt-in choice).";

/// Pure, testable scrub: route `bytes` through the real core
/// (`postern_hygiene::scrub_bytes`) and shape the result for `hygiene.js`.
/// `name` is used only in error messages (format detection is by magic
/// bytes, never by extension). Errors are honest and fail closed — no
/// "clean" bytes are ever returned for input the core could not fully parse,
/// and no simulated report is ever returned for a format it cannot scrub.
pub fn scrub(name: &str, bytes: &[u8]) -> Result<HygieneReport, String> {
    use postern_hygiene::{Format, HygieneError};

    let (cleaned, report, format) = postern_hygiene::scrub_bytes(bytes).map_err(|e| match e {
        // detect_format → None. ODF *is* covered (Format::Ooxml handles both
        // zip-package families); everything else (OLE .doc/.xls, plain text,
        // video, …) has no real scrubber here yet, so it FAILS CLOSED — this
        // backend never answers with a simulated `real: true` report.
        HygieneError::UnknownFormat => format!(
            "'{name}': unrecognized file format — no real scrubber is available for it \
             (supported: .docx/.xlsx/.pptx, ODF, .pdf, .jpg, .png). Fail closed: this \
             backend never fakes a clean result."
        ),
        other => format!(
            "'{name}': {other} — fail closed: no partially-scrubbed bytes are ever returned."
        ),
    })?;

    let kind = match format {
        Format::Ooxml => "ooxml",
        Format::Jpeg => "jpeg",
        Format::Png => "png",
        Format::Pdf => "pdf",
    };

    let mut note = String::new();
    if report.cleaned.is_empty() {
        note.push_str("Nothing to remove — the file was already clean. ");
    }
    note.push_str(NOTE_HONESTY);
    if !report.passed_through.is_empty() {
        // The core copied some parts through UNSCRUBBED (e.g. embedded media
        // in a format it cannot scrub). Never bless that silently.
        note.push_str(&format!(
            " WARNING — NOT fully scrubbed: {} part(s) were passed through with their own \
             metadata intact: {}.",
            report.passed_through.len(),
            report.passed_through.join("; ")
        ));
    }

    Ok(HygieneReport {
        kind: kind.to_string(),
        real: true,
        removed: report.cleaned,
        cleaned_b64: B64.encode(&cleaned),
        note,
    })
}

/// Base64 boundary for the command: decode what `hygiene.js` sends
/// (`UI.toB64` = standard base64 with padding) and run [`scrub`]. Kept
/// separate and pure so tests can drive the exact wire path.
pub fn scrub_b64(name: &str, bytes_b64: &str) -> Result<HygieneReport, String> {
    let bytes = B64
        .decode(bytes_b64.trim())
        .map_err(|e| format!("'{name}': invalid base64 payload: {e}"))?;
    scrub(name, &bytes)
}

/// `hygiene_scrub` — the Tauri command `hygiene.js` invokes as
/// `api.invoke("hygiene_scrub", { name, bytesB64 })`. Tauri v2 maps the JS
/// camelCase arg `bytesB64` to `bytes_b64` automatically.
#[tauri::command]
pub fn hygiene_scrub(name: String, bytes_b64: String) -> Result<HygieneReport, String> {
    scrub_b64(&name, &bytes_b64)
}
