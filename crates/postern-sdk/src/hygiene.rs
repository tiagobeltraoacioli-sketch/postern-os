//! Hygiene product — metadata scrubbing for OOXML / PDF / JPEG documents.
//! UniFFI wrapper over `postern_hygiene`. Each scrub returns the cleaned bytes
//! plus a report of what was stripped.

use crate::PosternError;

/// The result of a scrub: the cleaned document + what was removed.
#[derive(uniffi::Record)]
pub struct ScrubResult {
    /// The scrubbed document bytes.
    pub output: Vec<u8>,
    /// Human-readable list of the metadata items that were cleaned.
    pub cleaned: Vec<String>,
}

fn wrap(r: Result<(Vec<u8>, postern_hygiene::ScrubReport), postern_hygiene::HygieneError>) -> Result<ScrubResult, PosternError> {
    r.map(|(output, report)| ScrubResult { output, cleaned: report.cleaned })
        .map_err(|e| PosternError::from(e.to_string()))
}

/// Scrub metadata from an OOXML (docx/xlsx/pptx) document.
#[uniffi::export]
pub fn scrub_ooxml(input: Vec<u8>) -> Result<ScrubResult, PosternError> {
    wrap(postern_hygiene::scrub_ooxml(&input))
}

/// Scrub metadata from a PDF document.
#[uniffi::export]
pub fn scrub_pdf(input: Vec<u8>) -> Result<ScrubResult, PosternError> {
    wrap(postern_hygiene::scrub_pdf(&input))
}

/// Scrub metadata (EXIF etc.) from a JPEG image.
#[uniffi::export]
pub fn scrub_jpeg(input: Vec<u8>) -> Result<ScrubResult, PosternError> {
    wrap(postern_hygiene::scrub_jpeg(&input))
}

/// Whether `data` looks like a zip-based (OOXML/ODF) document.
#[uniffi::export]
pub fn is_zip_doc(data: Vec<u8>) -> bool {
    postern_hygiene::is_zip_doc(&data)
}

/// Whether `data` looks like a JPEG image.
#[uniffi::export]
pub fn is_jpeg(data: Vec<u8>) -> bool {
    postern_hygiene::is_jpeg(&data)
}

/// SHAKE256 digest (32 bytes) of `bytes`.
#[uniffi::export]
pub fn digest_shake256(bytes: Vec<u8>) -> Vec<u8> {
    postern_hygiene::digest_shake256(&bytes).to_vec()
}
