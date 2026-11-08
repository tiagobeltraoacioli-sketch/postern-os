//! Postern Hygiene — document metadata scrubbing (a Postern Labs product).
//!
//! **Claim discipline:** this crate strips exactly what is listed below, reports
//! everything it touched (and everything it could NOT scrub) in a [`ScrubReport`],
//! and **fails closed** — if an input is malformed in a way that prevents a
//! complete parse, the scrub returns an error instead of emitting bytes it
//! cannot vouch for. A privacy scrubber must never hand back a "clean" file
//! that isn't.
//!
//! ## What `scrub_ooxml` strips (OOXML `.docx`/`.xlsx`/`.pptx` + ODF)
//!
//! - `docProps/core.xml` → replaced with an empty core (creator, lastModifiedBy,
//!   dates, revision, keywords, subject, description all gone).
//! - `docProps/app.xml` → `Company`, `Manager`, `Template`, `TotalTime`,
//!   `HyperlinkBase` (local filesystem paths), `TitlesOfParts` removed.
//! - `docProps/custom.xml`, the whole `customXml/` store (SharePoint/DMS
//!   metadata), and `docProps/thumbnail.*` / `Thumbnails/` (page-1 preview
//!   renders) → dropped.
//! - Tracked-change / comment authorship in every `word/`, `ppt/`, `xl/` XML
//!   part: `w:author`, `w15:author`, `w:initials`, `w:date` attribute values
//!   blanked (`w:ins`/`w:del`/`w:comment` keep their structure, lose the who
//!   and when); `w15:userId`/`w15:providerId` (people.xml identity-provider
//!   IDs) blanked; PowerPoint `ppt/commentAuthors.xml` `name`/`initials`
//!   blanked; Excel `xl/comments*.xml` `<author>` text blanked.
//! - Revision-session IDs: every `w:rsid*` attribute stripped and the
//!   `<w:rsids>` table in `word/settings.xml` removed.
//! - Embedded media (`word/media/`, `xl/media/`, `ppt/media/`, ODF `Pictures/`):
//!   JPEGs and PNGs are run through [`scrub_jpeg`] / [`scrub_png`]. Media in any
//!   other format (EMF, GIF, TIFF, …) is passed through **unscrubbed** and
//!   listed in [`ScrubReport::passed_through`] so the caller can warn the user.
//! - ODF: `meta.xml` authorship/date/generator children removed;
//!   `dc:creator`/`dc:date` (annotation + tracked-change authorship) removed
//!   from `content.xml`/`styles.xml`; `settings.xml` printer traces —
//!   `PrinterName`, `PrinterSetup` (a base64 printer blob that can embed
//!   hostnames/queue paths), `PrintParms` config-items — dropped and the
//!   view-settings `ViewId` session values blanked, via a real XML pass
//!   (quick-xml) that fails closed on ill-formed input.
//! - ODF packaging: the `mimetype` entry is written as the FIRST entry,
//!   STORED (uncompressed) and byte-identical, per the OpenDocument package
//!   rule — a scrubbed `.odt`/`.ods`/`.odp` still opens in strict readers.
//! - Output ZIP entries carry a fixed 1980-01-01 timestamp — the scrub is
//!   deterministic and does not stamp "scrubbed at" times onto the package.
//!
//! ## Honest limits (what is NOT covered)
//!
//! - Non-JPEG/PNG embedded media keeps its own metadata (reported, not silent).
//! - Content-level identifiers the user typed (names in the text, headers,
//!   footers, fields) are content, not metadata — out of scope by design.
//! - OLE (`.doc`/`.xls`) and other legacy binary formats are not supported.
//!
//! ## `scrub_jpeg` / `scrub_png` / `scrub_pdf`
//!
//! - JPEG: drops **every APP1–APP15 segment** (EXIF/XMP, APP13 IPTC/Photoshop
//!   IRB with By-line/GPS, ICC device profiles, …) and **COM** comments; keeps
//!   APP0/JFIF and all structural segments; truncates any data appended after
//!   EOI. Malformed segment lengths → error (fail closed), never passthrough.
//! - PNG: drops `tEXt`, `zTXt`, `iTXt` (incl. XMP), `eXIf`, `tIME` chunks and
//!   anything after `IEND`. Malformed chunk bounds → error.
//! - PDF: removes the `/Info` dictionary, **every** `/Metadata` (XMP) stream on
//!   any object (Catalog, pages, image XObjects, embedded-file streams), and
//!   the trailer `/ID` file fingerprint. Limit: metadata *inside* embedded
//!   files (`/EmbeddedFiles`) is not rewritten — extract and scrub those
//!   separately.
//!
//! ## OS / file-manager embed
//!
//! The `postern-hygiene` binary's stdin/stdout embed mode (`scrub -` / `check
//! -`) is wired into a native right-click "Scrub metadata" action under
//! `desktop/file-manager/` (Linux Nautilus Scripts + KDE/`.desktop` action,
//! macOS Automator Quick Action). All of them call one shared script,
//! `desktop/file-manager/postern-scrub.sh`, which pipes the selected file
//! through `scrub -` into a scrubbed sibling. Acceptance for that wiring lives
//! in `tests/file_manager_action.rs` (a real EXIF JPEG + an OOXML with author
//! metadata, asserted clean via `check --json` after the action runs).
//!
//! Ethos rule (`PRINCIPLES.md` §6): **scrub by default** — the `prove`/`seal`
//! (SHAKE-256 + Falcon‖ML-DSA + Postern Seal) is a separate opt-in step, because
//! a provenance trail can de-anonymize.
//!
//! Owned in Rust — auditable, all-permissive, no `mat2` (LGPL) / ExifTool (GPL).

use std::io::{Cursor, Read, Write};

#[derive(Debug, thiserror::Error)]
pub enum HygieneError {
    #[error("not a valid OOXML/ODF (zip) document")]
    NotZipDoc,
    #[error("entry or archive exceeds the safe decompression cap (possible zip bomb)")]
    TooLarge,
    #[error("not a JPEG image")]
    NotJpeg,
    #[error("not a PNG image")]
    NotPng,
    #[error("unrecognized file format")]
    UnknownFormat,
    /// Fail closed: the input could not be fully parsed, so no "clean" output
    /// is produced. Copying unparsed bytes through would risk leaking the very
    /// metadata the scrub promises to remove.
    #[error("malformed input — refusing to emit output that was not fully scrubbed: {0}")]
    Malformed(&'static str),
    #[error("pdf error: {0}")]
    Pdf(String),
    #[error("zip error: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// A scrubbed, PII-free `core.xml` (namespaces kept so the package stays valid;
/// all metadata elements dropped).
const SCRUBBED_CORE: &str = concat!(
    r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>"#,
    r#"<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" "#,
    r#"xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" "#,
    r#"xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/>"#,
);

/// What a scrub touched (for an honest report to the user).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ScrubReport {
    /// Parts actually rewritten (emitted bytes differ from the input part) or
    /// dropped wholesale (e.g. `docProps/core.xml`). **Change-accurate**: a
    /// part that was already clean is NOT listed, so scrubbing an
    /// already-scrubbed file yields an empty list — this is what makes a
    /// dry-run "does this file carry metadata?" check possible.
    pub cleaned: Vec<String>,
    /// Parts copied through that MAY still carry their own metadata (e.g.
    /// embedded media in a format this crate cannot scrub yet). Non-empty means
    /// the output is NOT fully scrubbed — surface this to the user.
    pub passed_through: Vec<String>,
}

/// True if `data` looks like an OOXML/ODF package (ZIP magic + a known root).
pub fn is_zip_doc(data: &[u8]) -> bool {
    data.starts_with(b"PK\x03\x04")
        && zip::ZipArchive::new(Cursor::new(data))
            .map(|mut z| z.by_name("[Content_Types].xml").is_ok() || z.by_name("mimetype").is_ok())
            .unwrap_or(false)
}

/// Remove every `<tag>…</tag>` (and `<tag …>…</tag>`) occurrence from an XML
/// string. Sufficient for the flat, attribute-light metadata elements.
///
/// **DoS fix:** this used to loop `find`-from-0 + `replace_range` (which shifts
/// the whole tail) per occurrence — O(n²) on a crafted part with many matching
/// elements, i.e. a CPU-exhaustion hang on attacker-supplied documents. It is
/// now a single forward-cursor pass that builds the output once, O(n).
/// Semantics note (honest limit): the old rescan-from-0 loop would also remove
/// a `<tag>…</tag>` newly FORMED by the concatenation of bytes around a removed
/// element. Such input is not well-formed XML (it only arises in an
/// attacker-crafted part, never in a genuine Office/ODF document), and the
/// single pass does not re-scan its own output; genuine parts are unaffected.
fn remove_element(xml: &str, tag: &str) -> String {
    let (open_a, open_b, close) = (format!("<{tag}>"), format!("<{tag} "), format!("</{tag}>"));
    let mut out = String::with_capacity(xml.len());
    let mut i = 0usize;
    loop {
        let rest = &xml[i..];
        // Earliest occurrence of either opening form.
        let start_rel = match (rest.find(&open_a), rest.find(&open_b)) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let Some(start_rel) = start_rel else {
            out.push_str(rest);
            break;
        };
        let start = i + start_rel;
        match xml[start..].find(&close) {
            Some(rel) => {
                // Copy everything before the element, skip the element itself.
                out.push_str(&xml[i..start]);
                i = start + rel + close.len();
            }
            None => {
                // No closing tag (same as the old behavior): keep the rest.
                out.push_str(&xml[i..]);
                break;
            }
        }
    }
    out
}

/// Blank the value of every ` attr="…"` / ` attr='…'` occurrence (the attribute
/// stays — OOXML requires e.g. `w:author` on `w:ins`/`w:del` — its value goes).
/// Over-matching a same-shaped pattern in text content would only blank user
/// text, never leak metadata: the failure direction is safe for a scrubber.
fn blank_attr_values(xml: &str, attr: &str) -> (String, bool) {
    // Same DoS class as `remove_element`: the old loop `replace_range`d each
    // value out in place (an O(n) tail shift per occurrence — O(n²) on a part
    // crafted with many matching attributes). Now one linear output-building
    // pass per quote style.
    let mut s = xml.to_string();
    let mut changed = false;
    for q in ['"', '\''] {
        let needle = format!("{attr}={q}");
        let mut out = String::with_capacity(s.len());
        let mut i = 0usize;
        while let Some(pos) = s[i..].find(&needle) {
            let start = i + pos;
            // require a whitespace boundary before the attribute name
            if start == 0 || !s.as_bytes()[start - 1].is_ascii_whitespace() {
                out.push_str(&s[i..start + needle.len()]);
                i = start + needle.len();
                continue;
            }
            let val_start = start + needle.len();
            match s[val_start..].find(q) {
                Some(rel) => {
                    // Keep ` attr="` and the closing quote; drop the value.
                    out.push_str(&s[i..val_start]);
                    if rel > 0 {
                        changed = true;
                    }
                    i = val_start + rel; // resume AT the closing quote (kept)
                }
                None => break, // unterminated value: keep the rest as-is
            }
        }
        out.push_str(&s[i..]);
        s = out;
    }
    (s, changed)
}

/// Strip every attribute whose name starts with `w:rsid` (revision-session IDs
/// that fingerprint the editing machine/session), e.g. `w:rsidR="00AB12CD"`.
fn strip_rsid_attrs(xml: &str) -> (String, bool) {
    const NEEDLE: &str = " w:rsid";
    let bytes_len = xml.len();
    let mut out = String::with_capacity(bytes_len);
    let mut i = 0usize;
    let mut changed = false;
    while let Some(pos) = xml[i..].find(NEEDLE) {
        let start = i + pos; // points at the leading space
        let b = xml.as_bytes();
        let mut j = start + NEEDLE.len();
        while j < bytes_len && (b[j] as char).is_ascii_alphanumeric() {
            j += 1;
        }
        if j + 1 < bytes_len && b[j] == b'=' && (b[j + 1] == b'"' || b[j + 1] == b'\'') {
            let q = b[j + 1] as char;
            if let Some(rel) = xml[j + 2..].find(q) {
                out.push_str(&xml[i..start]); // drop " w:rsidXxx=\"...\"" wholesale
                i = j + 2 + rel + 1;
                changed = true;
                continue;
            }
        }
        // not an attribute pattern — copy the matched region through and go on
        out.push_str(&xml[i..start + NEEDLE.len()]);
        i = start + NEEDLE.len();
    }
    out.push_str(&xml[i..]);
    (out, changed)
}

/// Blank the text content of every `<tag>text</tag>` / `<tag …>text</tag>`
/// (element and attributes stay — index-referenced lists like Excel comment
/// `<author>` entries must keep their positions).
fn blank_element_text(xml: &str, tag: &str) -> (String, bool) {
    // Same DoS class as `remove_element`: was `replace_range` per occurrence
    // (O(n²) on a crafted part with many matching elements); now one linear
    // forward-cursor pass building the output once.
    let (open_a, open_b, close) = (format!("<{tag}>"), format!("<{tag} "), format!("</{tag}>"));
    let mut out = String::with_capacity(xml.len());
    let mut changed = false;
    let mut i = 0usize;
    loop {
        let rest = &xml[i..];
        let start_rel = match (rest.find(&open_a), rest.find(&open_b)) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let Some(start_rel) = start_rel else {
            out.push_str(rest);
            break;
        };
        let start = i + start_rel;
        let Some(gt_rel) = xml[start..].find('>') else {
            out.push_str(&xml[i..]);
            break;
        };
        let tag_end = start + gt_rel + 1;
        let Some(close_rel) = xml[tag_end..].find(&close) else {
            out.push_str(&xml[i..]);
            break;
        };
        let end = tag_end + close_rel;
        // Keep the element + attributes; drop only the text between the tags.
        out.push_str(&xml[i..tag_end]);
        if end > tag_end {
            changed = true;
        }
        i = end; // resume AT `</tag>`, which the next copy keeps
    }
    (out, changed)
}

/// Authorship / revision scrub for one OOXML XML part. Returns the scrubbed
/// text and whether anything changed.
// `name` is matched case-insensitively (the caller passes a lowercased key —
// see the fail-closed fix at the call site) so a differently-cased
// `PPT/.../CommentAuthors.xml` or `XL/.../Comments1.xml` still gets its
// comment-author names/initials blanked instead of silently skipping the
// extra scrub.
fn scrub_ooxml_xml_part(name: &str, xml: &str) -> (String, bool) {
    let mut s = xml.to_string();
    let mut changed = false;
    // Tracked changes, comments, people.xml identity providers.
    for attr in ["w:author", "w15:author", "w:initials", "w:date", "w15:userId", "w15:providerId"] {
        let (next, c) = blank_attr_values(&s, attr);
        s = next;
        changed |= c;
    }
    // Revision-session IDs (attributes everywhere, table in settings.xml).
    let (next, c) = strip_rsid_attrs(&s);
    s = next;
    changed |= c;
    let stripped = remove_element(&s, "w:rsids");
    if stripped != s {
        s = stripped;
        changed = true;
    }
    // PowerPoint comment authors: <p:cmAuthor name="…" initials="…">.
    // `name` is a lowercased key (see call site), so match lowercase literals.
    if name.starts_with("ppt/") && name.contains("commentauthors") {
        for attr in ["name", "initials"] {
            let (next, c) = blank_attr_values(&s, attr);
            s = next;
            changed |= c;
        }
    }
    // Excel comment authors: <authors><author>Name</author></authors>.
    if name.starts_with("xl/") && name.contains("comments") {
        let (next, c) = blank_element_text(&s, "author");
        s = next;
        changed |= c;
    }
    (s, changed)
}

/// ODF metadata children removed from `meta.xml` (authorship, dates, tool).
const ODF_META_ELEMENTS: &[&str] = &[
    "dc:creator",
    "dc:date",
    "dc:title",
    "dc:description",
    "dc:subject",
    "meta:initial-creator",
    "meta:creation-date",
    "meta:editing-cycles",
    "meta:editing-duration",
    "meta:generator",
    "meta:keyword",
    "meta:user-defined",
    "meta:print-date",
    "meta:printed-by",
];

/// Scrub ODF `settings.xml` with a real XML pass (quick-xml, MIT):
///
/// - `<config:config-item>` elements whose `config:name` is `PrinterName`,
///   `PrinterSetup` (a base64-encoded platform printer blob — on every major
///   OS it can embed the machine's printer share path, i.e. hostnames), or
///   `PrintParms` are dropped wholesale;
/// - the text value of `ViewId` config-items (per-session view identifiers
///   inside the `ooo:view-settings` tree) is blanked; the element stays so
///   the settings structure remains valid.
///
/// Matching is on the XML **local name** (`config-item` / `name`), so an
/// unconventional namespace prefix cannot dodge the scrub — over-matching
/// can only drop/blank more, which is the safe failure direction for a
/// scrubber (same rationale as [`blank_attr_values`]).
///
/// **Fails closed:** ill-formed XML returns [`HygieneError::Malformed`]
/// instead of copying bytes through that were not fully scanned.
fn scrub_odf_settings(xml: &str) -> Result<Vec<u8>, HygieneError> {
    use quick_xml::events::{BytesStart, Event};
    use quick_xml::{Reader, Writer};

    /// The `config:name` value of a `config:config-item` start/empty tag
    /// (`None` for any other element). Local-name match — see above.
    fn config_item_name(e: &BytesStart) -> Result<Option<String>, HygieneError> {
        if e.name().local_name().as_ref() != b"config-item" {
            return Ok(None);
        }
        for a in e.attributes() {
            let a = a.map_err(|_| HygieneError::Malformed("bad attribute in ODF settings.xml"))?;
            if a.key.local_name().as_ref() == b"name" {
                let v = a
                    .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                    .map_err(|_| HygieneError::Malformed("bad attribute value in ODF settings.xml"))?;
                return Ok(Some(v.into_owned()));
            }
        }
        Ok(None)
    }
    /// Printer traces dropped wholesale (names are spec/LibreOffice-exact).
    const DROPPED: &[&str] = &["PrinterName", "PrinterSetup", "PrintParms"];
    let werr = |_| HygieneError::Malformed("failed to rewrite ODF settings.xml");

    let mut reader = Reader::from_str(xml);
    let mut writer = Writer::new(Vec::new());
    // Depth inside a dropped config-item subtree (0 = not skipping).
    let mut skip_depth = 0usize;
    // Depth inside a ViewId config-item whose text content is being blanked.
    let mut blank_depth = 0usize;
    loop {
        // Reader-level errors (mismatched end tags, bad syntax, …) fail closed.
        match reader
            .read_event()
            .map_err(|_| HygieneError::Malformed("ill-formed ODF settings.xml"))?
        {
            Event::Eof => {
                if skip_depth > 0 || blank_depth > 0 {
                    return Err(HygieneError::Malformed("unterminated element in ODF settings.xml"));
                }
                break;
            }
            Event::Start(e) => {
                if skip_depth > 0 {
                    skip_depth += 1;
                    continue;
                }
                match config_item_name(&e)?.as_deref() {
                    Some(n) if DROPPED.contains(&n) => {
                        skip_depth = 1;
                        continue;
                    }
                    Some("ViewId") if blank_depth == 0 => blank_depth = 1,
                    _ if blank_depth > 0 => blank_depth += 1,
                    _ => {}
                }
                writer.write_event(Event::Start(e)).map_err(werr)?;
            }
            Event::End(e) => {
                if skip_depth > 0 {
                    skip_depth -= 1;
                    continue;
                }
                blank_depth = blank_depth.saturating_sub(1);
                writer.write_event(Event::End(e)).map_err(werr)?;
            }
            Event::Empty(e) => {
                if skip_depth > 0 {
                    continue;
                }
                if matches!(config_item_name(&e)?.as_deref(), Some(n) if DROPPED.contains(&n)) {
                    continue; // a self-closed printer item: drop it too
                }
                writer.write_event(Event::Empty(e)).map_err(werr)?;
            }
            Event::Text(e) => {
                if skip_depth > 0 || blank_depth > 0 {
                    continue; // dropped subtree / blanked ViewId value
                }
                writer.write_event(Event::Text(e)).map_err(werr)?;
            }
            Event::CData(e) => {
                if skip_depth > 0 || blank_depth > 0 {
                    continue;
                }
                writer.write_event(Event::CData(e)).map_err(werr)?;
            }
            ev => {
                // Decl, comments, PIs, doctype: structural, copied through.
                if skip_depth > 0 {
                    continue;
                }
                writer.write_event(ev).map_err(werr)?;
            }
        }
    }
    Ok(writer.into_inner())
}

/// Scrub an OOXML/ODF document's metadata. See the crate docs for the exact
/// list of what is stripped and what is passed through (always reported).
/// Fails closed on malformed parts rather than copying unscrubbed bytes.
pub fn scrub_ooxml(input: &[u8]) -> Result<(Vec<u8>, ScrubReport), HygieneError> {
    if !is_zip_doc(input) {
        return Err(HygieneError::NotZipDoc);
    }
    let mut zip = zip::ZipArchive::new(Cursor::new(input))?;
    // Zip-bomb guard: bound the entry count, each decompressed entry, and the
    // aggregate decompressed size. OOXML/ODF parts are small in practice; a
    // crafted "42.zip"-style package is the threat, and this scrubs documents
    // that can arrive from an untrusted peer, so it must never OOM the host.
    const MAX_ENTRIES: usize = 8192;
    const MAX_ENTRY: u64 = 64 * 1024 * 1024; // 64 MiB per decompressed entry
    const MAX_TOTAL: u64 = 256 * 1024 * 1024; // 256 MiB aggregate
    // Parser-DoS cap: an XML part is refused BEFORE any scrub pass runs on it.
    // The string scrub helpers are linear now, but this bounds the work (and
    // the intermediate allocations) up front — an attacker cannot make a
    // single crafted part cost unbounded CPU/RAM. Real Office/ODF XML parts
    // sit far below this; an oversized one is rejected with a scrub error
    // (fail closed), never a hang.
    const MAX_XML_PART: usize = 32 * 1024 * 1024; // 32 MiB per XML part
    fn check_xml_part_size(data: &[u8]) -> Result<(), HygieneError> {
        if data.len() > MAX_XML_PART {
            return Err(HygieneError::TooLarge);
        }
        Ok(())
    }
    if zip.len() > MAX_ENTRIES {
        return Err(HygieneError::TooLarge);
    }
    let mut total: u64 = 0;
    let mut out = Vec::new();
    let mut report = ScrubReport::default();
    {
        let mut w = zip::ZipWriter::new(Cursor::new(&mut out));
        // Fixed 1980-01-01 entry timestamp: deterministic output, and no fresh
        // "scrubbed at HH:MM UTC" fingerprint stamped across the package.
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .last_modified_time(zip::DateTime::default());
        // ODF packaging rule (OASIS OpenDocument v1.3 part 2 §3.3): the
        // `mimetype` entry MUST be the first entry in the package and MUST be
        // STORED (uncompressed), so type sniffers can read the media type at a
        // fixed byte offset without inflating anything. Rewriting it deflated
        // (like every other entry) breaks strict readers/validators on the
        // scrubbed output — so it is special-cased: written first, stored,
        // byte-identical. It carries no PII (it is the format identifier), so
        // it is never listed in `report.cleaned`.
        let mut mimetype_index: Option<usize> = None;
        for i in 0..zip.len() {
            if zip.by_index(i)?.name() == "mimetype" {
                mimetype_index = Some(i);
                break;
            }
        }
        if let Some(mi) = mimetype_index {
            let mut f = zip.by_index(mi)?;
            let mut d = Vec::new();
            (&mut f).take(MAX_ENTRY + 1).read_to_end(&mut d)?;
            drop(f);
            if d.len() as u64 > MAX_ENTRY {
                return Err(HygieneError::TooLarge);
            }
            total += d.len() as u64;
            w.start_file("mimetype", opts.compression_method(zip::CompressionMethod::Stored))?;
            w.write_all(&d)?;
        }
        for i in 0..zip.len() {
            if mimetype_index == Some(i) {
                continue; // already written first + stored (see above)
            }
            let (name, data) = {
                let mut f = zip.by_index(i)?;
                let name = f.name().to_string();
                let mut d = Vec::new();
                // Cap the actual decompressed read — a lying zip header cannot
                // force more than MAX_ENTRY bytes into memory.
                (&mut f).take(MAX_ENTRY + 1).read_to_end(&mut d)?;
                if d.len() as u64 > MAX_ENTRY {
                    return Err(HygieneError::TooLarge);
                }
                (name, d)
            };
            total += data.len() as u64;
            if total > MAX_TOTAL {
                return Err(HygieneError::TooLarge);
            }
            // Parts dropped wholesale. **Fail-closed fix**: this used to gate on
            // `name == "docProps/custom.xml"` (case-sensitive `==`) plus
            // case-sensitive `starts_with` prefixes. OOXML/ODF part names are
            // normatively lowercase, so a genuine document never hits the
            // mismatch path — but a crafted archive with e.g.
            // `docProps/Custom.xml` or `THUMBNAILS/x.jpg` would dodge every
            // check here and fall through to the passthrough default,
            // shipping the exact metadata this function promises to strip.
            // Many real-world OOXML/ODF readers (notably on case-insensitive
            // filesystems) still open such an entry, so this was a live
            // bypass, not just a theoretical one. Match on a lowercased key;
            // `name` itself (original case) is still what gets written.
            let key = name.to_ascii_lowercase();
            if key == "docprops/custom.xml"
                || key.starts_with("customxml/")
                || key.starts_with("docprops/thumbnail")
                || key.starts_with("thumbnails/")
            {
                report.cleaned.push(format!("{name} (dropped)"));
                continue;
            }
            // Change-accurate reporting: every arm below pushes to
            // `report.cleaned` ONLY when the emitted bytes actually differ
            // from the input part. An already-scrubbed document therefore
            // yields an empty `cleaned` list (see the idempotence tests) —
            // which is exactly what a dry-run `check` needs to not
            // false-positive on clean files.
            match key.as_str() {
                "docprops/core.xml" => {
                    w.start_file(&name, opts)?;
                    w.write_all(SCRUBBED_CORE.as_bytes())?;
                    if data != SCRUBBED_CORE.as_bytes() {
                        report.cleaned.push(name);
                    }
                }
                "docprops/app.xml" => {
                    check_xml_part_size(&data)?;
                    let mut s = String::from_utf8_lossy(&data).into_owned();
                    for tag in ["Company", "Manager", "Template", "TotalTime", "HyperlinkBase", "TitlesOfParts"] {
                        s = remove_element(&s, tag);
                    }
                    w.start_file(&name, opts)?;
                    w.write_all(s.as_bytes())?;
                    if s.as_bytes() != &data[..] {
                        report.cleaned.push(name);
                    }
                }
                // ODF document metadata.
                "meta.xml" => {
                    check_xml_part_size(&data)?;
                    let mut s = String::from_utf8_lossy(&data).into_owned();
                    for tag in ODF_META_ELEMENTS {
                        s = remove_element(&s, tag);
                    }
                    w.start_file(&name, opts)?;
                    w.write_all(s.as_bytes())?;
                    if s.as_bytes() != &data[..] {
                        report.cleaned.push(name);
                    }
                }
                // ODF annotation / tracked-change authorship lives in content.
                "content.xml" | "styles.xml" => {
                    check_xml_part_size(&data)?;
                    let s = String::from_utf8_lossy(&data).into_owned();
                    let scrubbed = remove_element(&remove_element(&s, "dc:creator"), "dc:date");
                    // Compare emitted bytes to input bytes (not string to
                    // string) so a lossy UTF-8 rewrite is also reported.
                    let changed = scrubbed.as_bytes() != &data[..];
                    w.start_file(&name, opts)?;
                    w.write_all(scrubbed.as_bytes())?;
                    if changed {
                        report.cleaned.push(format!("{name} (annotation/change authors)"));
                    }
                }
                // ODF settings.xml: printer traces + view-session IDs. (The
                // OOXML `word/settings.xml` is a different part and is handled
                // by the `word/` arm below — this exact-name key is only ever
                // the ODF root-level settings part.)
                "settings.xml" => {
                    check_xml_part_size(&data)?;
                    // ODF is UTF-8; a non-UTF-8 part cannot be scanned, and
                    // copying it unscrubbed would leak — refuse (fail closed,
                    // same contract as the OOXML XML arm below).
                    let s = std::str::from_utf8(&data)
                        .map_err(|_| HygieneError::Malformed("non-UTF-8 XML part"))?;
                    let scrubbed = scrub_odf_settings(s)?;
                    // Change-accurate: compare emitted bytes to input bytes.
                    let changed = scrubbed != data;
                    w.start_file(&name, opts)?;
                    w.write_all(&scrubbed)?;
                    if changed {
                        report.cleaned.push(format!("{name} (printer/view-session traces)"));
                    }
                }
                _ if is_media_part(&key) => {
                    if is_jpeg(&data) {
                        let (clean, sub) = scrub_jpeg(&data)?; // fail closed on bad media
                        w.start_file(&name, opts)?;
                        w.write_all(&clean)?;
                        for c in sub.cleaned {
                            report.cleaned.push(format!("{name}: {c}"));
                        }
                    } else if is_png(&data) {
                        let (clean, sub) = scrub_png(&data)?;
                        w.start_file(&name, opts)?;
                        w.write_all(&clean)?;
                        for c in sub.cleaned {
                            report.cleaned.push(format!("{name}: {c}"));
                        }
                    } else {
                        // Unsupported media format: copied through UNSCRUBBED,
                        // and reported so the caller can warn the user.
                        w.start_file(&name, opts)?;
                        w.write_all(&data)?;
                        report.passed_through.push(format!("{name} (unsupported media format — may carry its own metadata)"));
                    }
                }
                // OOXML content parts: strip authorship attributes + rsids.
                n if n.ends_with(".xml")
                    && (n.starts_with("word/") || n.starts_with("ppt/") || n.starts_with("xl/")) =>
                {
                    check_xml_part_size(&data)?;
                    // Office writes UTF-8; a non-UTF-8 XML part cannot be
                    // scanned, and copying it unscrubbed would leak — refuse.
                    let s = std::str::from_utf8(&data)
                        .map_err(|_| HygieneError::Malformed("non-UTF-8 XML part"))?;
                    let (scrubbed, _) = scrub_ooxml_xml_part(&key, s);
                    // Byte-compare (not the helper's flag) so `cleaned` is
                    // exactly "emitted bytes differ from input part".
                    let changed = scrubbed.as_bytes() != &data[..];
                    w.start_file(&name, opts)?;
                    w.write_all(scrubbed.as_bytes())?;
                    if changed {
                        report.cleaned.push(format!("{name} (authors/rsids)"));
                    }
                }
                _ => {
                    w.start_file(&name, opts)?;
                    w.write_all(&data)?;
                }
            }
        }
        w.finish()?;
    }
    Ok((out, report))
}

/// True for embedded-media package paths (OOXML `*/media/`, ODF `Pictures/`).
/// `name` is matched case-insensitively — callers pass a lowercased key, so
/// the literal prefixes here (including ODF's conventionally-capitalized
/// `Pictures/`) are lowercase too.
fn is_media_part(name: &str) -> bool {
    name.starts_with("word/media/")
        || name.starts_with("xl/media/")
        || name.starts_with("ppt/media/")
        || name.starts_with("pictures/")
}

/// Max PDF input size [`scrub_pdf`] will hand to the parser. Oversized input is
/// rejected with [`HygieneError::TooLarge`] before any parsing happens — the
/// scrubber must never let an untrusted file dictate unbounded parse work.
pub const MAX_PDF_BYTES: usize = 256 * 1024 * 1024; // 256 MiB

/// Strip a PDF's identifying metadata: the **Info dictionary** (Author, Producer,
/// Creator, CreationDate, ModDate), **every `/Metadata` (XMP) stream on any
/// object** (Catalog, pages, image XObjects, embedded-file streams), and the
/// trailer **`/ID` file fingerprint** (often seeded from author/path/time and a
/// stable correlator across copies). Page content is untouched. Known limit:
/// metadata *inside* embedded files is not rewritten. Uses `lopdf` (MIT).
pub fn scrub_pdf(input: &[u8]) -> Result<(Vec<u8>, ScrubReport), HygieneError> {
    use lopdf::{Document, Object};
    // Parser-DoS guard 1: bound the input BEFORE handing it to the parser.
    // `lopdf::Document::load_mem` is unbounded in what a crafted file can make
    // it allocate/chew on; documents arrive from untrusted peers, so cap first
    // and fail closed rather than hang or OOM the host.
    if input.len() > MAX_PDF_BYTES {
        return Err(HygieneError::TooLarge);
    }
    // Parser-DoS guard 2: a panic inside the parser (malformed xref/object
    // structures) must surface as a scrub Err, not abort the caller. Honest
    // limit: catch_unwind cannot catch aborts (panic=abort builds, stack
    // exhaustion) — it converts unwinding panics only.
    let mut doc = std::panic::catch_unwind(|| Document::load_mem(input))
        .map_err(|_| HygieneError::Pdf("PDF parser panicked on malformed input".to_string()))?
        .map_err(|e| HygieneError::Pdf(e.to_string()))?;
    let mut report = ScrubReport::default();

    // Info: drop the trailer ref AND the object itself (else lopdf still writes
    // the object and the author/producer leak).
    let info_ref = doc.trailer.get(b"Info").ok().and_then(|o| o.as_reference().ok());
    if doc.trailer.remove(b"Info").is_some() {
        if let Some(id) = info_ref {
            doc.objects.remove(&id);
        }
        report.cleaned.push("PDF/Info (author, producer, dates)".into());
    }
    // /ID: the two-element file identifier, a durable cross-copy fingerprint.
    if doc.trailer.remove(b"ID").is_some() {
        report.cleaned.push("PDF/ID (file fingerprint)".into());
    }
    // XMP: walk EVERY object (not just the Catalog) — pages, image XObjects and
    // embedded-file streams each may carry their own /Metadata stream.
    let mut holders: Vec<lopdf::ObjectId> = Vec::new();
    let mut meta_refs: Vec<lopdf::ObjectId> = Vec::new();
    for (&id, obj) in doc.objects.iter() {
        let dict = match obj {
            Object::Dictionary(d) => Some(d),
            Object::Stream(s) => Some(&s.dict),
            _ => None,
        };
        if let Some(d) = dict {
            if let Ok(m) = d.get(b"Metadata") {
                holders.push(id);
                if let Ok(r) = m.as_reference() {
                    meta_refs.push(r);
                }
            }
        }
    }
    let n_holders = holders.len();
    for id in holders {
        match doc.objects.get_mut(&id) {
            Some(Object::Dictionary(d)) => {
                d.remove(b"Metadata");
            }
            Some(Object::Stream(s)) => {
                s.dict.remove(b"Metadata");
            }
            _ => {}
        }
    }
    for id in meta_refs {
        doc.objects.remove(&id);
    }
    if n_holders > 0 {
        report.cleaned.push(format!("PDF/XMP (/Metadata on {n_holders} object(s))"));
    }

    let mut out = Vec::new();
    doc.save_to(&mut out).map_err(|e| HygieneError::Pdf(e.to_string()))?;
    Ok((out, report))
}

// ── prove / seal (opt-in) ────────────────────────────────────────────────────

/// SHAKE-256 digest (32 bytes) of a document — the content hash the provenance
/// seal signs. Same hash family as the protocol, but this is a plain content
/// digest, not consensus.
pub fn digest_shake256(bytes: &[u8]) -> [u8; 32] {
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    let mut h = sha3::Shake256::default();
    h.update(bytes);
    let mut out = [0u8; 32];
    let mut xof = h.finalize_xof();
    XofReader::read(&mut xof, &mut out);
    out
}

/// A provenance seal over a (usually already-scrubbed) document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seal {
    /// SHAKE-256 of the document bytes.
    pub digest: [u8; 32],
    /// The caller's signature over `digest` (a hybrid Falcon‖ML-DSA signature
    /// from the wallet — produced by the `sign` closure so the key never enters
    /// this crate and hygiene stays crypto-light).
    pub signature: Vec<u8>,
}

/// Seal a document (the **opt-in** "prove" step): hash it (SHAKE-256) and sign the
/// digest with the caller's signer. Provenance can de-anonymize, so — per the
/// ethos rule — this is never automatic; scrub is the default, seal is a choice.
/// Anchor `digest` in a Bloch transaction for third-party timestamping if desired
/// (the app does the tx; this crate stays offline).
pub fn seal(bytes: &[u8], sign: impl FnOnce(&[u8]) -> Vec<u8>) -> Seal {
    let digest = digest_shake256(bytes);
    let signature = sign(&digest);
    Seal { digest, signature }
}

/// True if `data` begins with the JPEG SOI marker.
pub fn is_jpeg(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == 0xFF && data[1] == 0xD8
}

/// True if `data` begins with the PNG signature.
pub fn is_png(data: &[u8]) -> bool {
    data.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
}

/// Strip metadata segments from a JPEG. Drops **every APPn segment except
/// APP0/JFIF** — APP1 (EXIF GPS/camera/timestamps + XMP), APP13 (IPTC-IIM /
/// Photoshop IRB: By-line author, copyright, city/GPS), APP2 (ICC device
/// profile), the rest — and every **COM** free-text comment. Structural
/// segments (quant/Huffman tables, frame headers, the compressed scan) are
/// copied unchanged, so the picture is identical. Data appended **after EOI**
/// (a classic stash for archives/payloads) is truncated and reported.
///
/// **Fails closed:** a malformed or out-of-bounds segment length returns
/// [`HygieneError::Malformed`] — this scrubber never emits "cleaned" bytes it
/// did not fully parse. (An adversary who could overstate one segment length
/// must not be able to smuggle metadata through a successful scrub.)
pub fn scrub_jpeg(input: &[u8]) -> Result<(Vec<u8>, ScrubReport), HygieneError> {
    if !is_jpeg(input) {
        return Err(HygieneError::NotJpeg);
    }
    let mut out = Vec::with_capacity(input.len());
    let mut report = ScrubReport::default();
    out.extend_from_slice(&input[0..2]); // SOI
    let mut i = 2;
    while i < input.len() {
        if i + 1 >= input.len() {
            return Err(HygieneError::Malformed("truncated JPEG marker"));
        }
        if input[i] != 0xFF {
            return Err(HygieneError::Malformed("expected JPEG marker, found other bytes"));
        }
        let marker = input[i + 1];
        if marker == 0xDA {
            // SOS: entropy-coded data follows. Within it, 0xFF is always stuffed
            // (0xFF00) or an RSTn, so the first 0xFFD9 found is the real EOI.
            let scan = &input[i..];
            match scan.windows(2).position(|w| w == [0xFF, 0xD9]) {
                Some(rel) => {
                    let end = i + rel + 2;
                    out.extend_from_slice(&input[i..end]);
                    if end < input.len() {
                        report.cleaned.push("JPEG/trailing data after EOI (dropped)".into());
                    }
                    return Ok((out, report));
                }
                None => return Err(HygieneError::Malformed("no EOI after SOS")),
            }
        }
        if marker == 0xD9 {
            // EOI with no scan (degenerate but terminal).
            out.extend_from_slice(&input[i..i + 2]);
            if i + 2 < input.len() {
                report.cleaned.push("JPEG/trailing data after EOI (dropped)".into());
            }
            return Ok((out, report));
        }
        // Standalone markers (RSTn, TEM) have no length payload.
        if (0xD0..=0xD7).contains(&marker) || marker == 0x01 {
            out.extend_from_slice(&input[i..i + 2]);
            i += 2;
            continue;
        }
        if i + 3 >= input.len() {
            return Err(HygieneError::Malformed("truncated JPEG segment header"));
        }
        let len = ((input[i + 2] as usize) << 8) | (input[i + 3] as usize); // includes the 2 length bytes
        let seg_end = i + 2 + len;
        if len < 2 || seg_end > input.len() {
            // FAIL CLOSED — never copy a tail we could not parse.
            return Err(HygieneError::Malformed("JPEG segment length out of bounds"));
        }
        let drop_label: Option<String> = match marker {
            0xE1 => Some("JPEG/APP1 (EXIF/XMP)".into()),
            0xED => Some("JPEG/APP13 (IPTC/Photoshop IRB)".into()),
            0xE2..=0xEF => Some(format!("JPEG/APP{}", marker - 0xE0)),
            0xFE => Some("JPEG/COM (comment)".into()),
            _ => None,
        };
        match drop_label {
            Some(label) => report.cleaned.push(label),
            None => out.extend_from_slice(&input[i..seg_end]),
        }
        i = seg_end;
    }
    Err(HygieneError::Malformed("JPEG ended without SOS/EOI"))
}

/// Strip metadata chunks from a PNG: **`tEXt`, `zTXt`, `iTXt`** (free text and
/// XMP — Photoshop writes XMP as `iTXt`), **`eXIf`** (EXIF, incl. GPS), and
/// **`tIME`** (last-modified). Everything after `IEND` is truncated and
/// reported. All structural chunks (IHDR, PLTE, IDAT, gAMA, …) are copied
/// byte-for-byte, so the picture is identical.
///
/// **Fails closed:** malformed chunk bounds return [`HygieneError::Malformed`]
/// rather than copying unparsed bytes through.
pub fn scrub_png(input: &[u8]) -> Result<(Vec<u8>, ScrubReport), HygieneError> {
    if !is_png(input) {
        return Err(HygieneError::NotPng);
    }
    let mut out = Vec::with_capacity(input.len());
    let mut report = ScrubReport::default();
    out.extend_from_slice(&input[..8]); // signature
    let mut i = 8usize;
    while i < input.len() {
        if i + 8 > input.len() {
            return Err(HygieneError::Malformed("truncated PNG chunk header"));
        }
        let clen = u32::from_be_bytes([input[i], input[i + 1], input[i + 2], input[i + 3]]) as u64;
        let ctype: [u8; 4] = [input[i + 4], input[i + 5], input[i + 6], input[i + 7]];
        let end = i as u64 + 8 + clen + 4; // header + data + CRC
        if end > input.len() as u64 {
            return Err(HygieneError::Malformed("PNG chunk length out of bounds"));
        }
        let end = end as usize;
        match &ctype {
            b"tEXt" | b"zTXt" | b"iTXt" | b"eXIf" | b"tIME" => {
                report
                    .cleaned
                    .push(format!("PNG/{} (metadata chunk)", String::from_utf8_lossy(&ctype)));
            }
            b"IEND" => {
                out.extend_from_slice(&input[i..end]);
                if end < input.len() {
                    report.cleaned.push("PNG/trailing data after IEND (dropped)".into());
                }
                return Ok((out, report));
            }
            _ => out.extend_from_slice(&input[i..end]),
        }
        i = end;
    }
    Err(HygieneError::Malformed("PNG ended without IEND"))
}

// ── format dispatch ─────────────────────────────────────────────────────────

/// A file format this crate knows how to scrub. `Ooxml` covers both OOXML
/// (`.docx`/`.xlsx`/`.pptx`) and ODF (`.odt`/`.ods`/`.odp`) — both are
/// zip-based document packages and both are handled by [`scrub_ooxml`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// OOXML or ODF — a zip-based document package (see [`is_zip_doc`]).
    Ooxml,
    Jpeg,
    Png,
    Pdf,
}

/// Sniff `data`'s magic bytes and classify it as one of the [`Format`]s this
/// crate can scrub. Returns `None` for anything unrecognized — callers should
/// treat that as "no scrubber available", not silently pass the file through.
pub fn detect_format(data: &[u8]) -> Option<Format> {
    if is_zip_doc(data) {
        Some(Format::Ooxml)
    } else if is_jpeg(data) {
        Some(Format::Jpeg)
    } else if is_png(data) {
        Some(Format::Png)
    } else if data.starts_with(b"%PDF") {
        Some(Format::Pdf)
    } else {
        None
    }
}

/// One-call format dispatch: sniff `data` and route it to the matching
/// scrubber ([`scrub_ooxml`], [`scrub_jpeg`], [`scrub_png`], or [`scrub_pdf`]),
/// returning the scrubbed bytes, the honest [`ScrubReport`], and the detected
/// [`Format`]. Unrecognized input fails closed with
/// [`HygieneError::UnknownFormat`] rather than being passed through unscrubbed.
pub fn scrub_bytes(data: &[u8]) -> Result<(Vec<u8>, ScrubReport, Format), HygieneError> {
    match detect_format(data) {
        Some(Format::Ooxml) => scrub_ooxml(data).map(|(bytes, report)| (bytes, report, Format::Ooxml)),
        Some(Format::Jpeg) => scrub_jpeg(data).map(|(bytes, report)| (bytes, report, Format::Jpeg)),
        Some(Format::Png) => scrub_png(data).map(|(bytes, report)| (bytes, report, Format::Png)),
        Some(Format::Pdf) => scrub_pdf(data).map(|(bytes, report)| (bytes, report, Format::Pdf)),
        None => Err(HygieneError::UnknownFormat),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_doc() -> Vec<u8> {
        let mut buf = Vec::new();
        let mut w = zip::ZipWriter::new(Cursor::new(&mut buf));
        let o = zip::write::SimpleFileOptions::default();
        let put = |w: &mut zip::ZipWriter<Cursor<&mut Vec<u8>>>, n: &str, d: &[u8]| {
            w.start_file(n, o).unwrap();
            w.write_all(d).unwrap();
        };
        put(&mut w, "[Content_Types].xml", b"<Types/>");
        put(&mut w, "docProps/core.xml",
            br#"<cp:coreProperties><dc:creator>Alice Secret</dc:creator><cp:lastModifiedBy>Bob Doe</cp:lastModifiedBy><dcterms:created>2020-01-01</dcterms:created></cp:coreProperties>"#);
        put(&mut w, "docProps/app.xml",
            b"<Properties><Company>ACME Intl</Company><Application>MS Word</Application><Manager>Carol Boss</Manager><Template>Secret.dotm</Template><HyperlinkBase>C:\\Users\\alice\\docs</HyperlinkBase><TotalTime>842</TotalTime></Properties>");
        put(&mut w, "docProps/custom.xml", b"<custom>internal-case-42</custom>");
        put(&mut w, "word/document.xml", b"<w:document>the actual content</w:document>");
        w.finish().unwrap(); // consumes w, releases the &mut buf borrow
        buf
    }

    fn read_entry(doc: &[u8], name: &str) -> Option<String> {
        let mut z = zip::ZipArchive::new(Cursor::new(doc)).ok()?;
        let mut f = z.by_name(name).ok()?;
        let mut s = String::new();
        f.read_to_string(&mut s).ok()?;
        Some(s)
    }

    #[test]
    fn ooxml_scrub_strips_pii_keeps_content() {
        let doc = build_doc();
        assert!(is_zip_doc(&doc));
        let (out, report) = scrub_ooxml(&doc).unwrap();

        let core = read_entry(&out, "docProps/core.xml").unwrap();
        assert!(!core.contains("Alice Secret"), "author removed");
        assert!(!core.contains("Bob Doe"), "lastModifiedBy removed");
        assert!(!core.contains("2020-01-01"), "timestamps removed");

        let app = read_entry(&out, "docProps/app.xml").unwrap();
        assert!(!app.contains("ACME Intl"), "Company removed");
        assert!(!app.contains("Carol Boss"), "Manager removed");
        assert!(!app.contains("Secret.dotm"), "Template removed");
        assert!(!app.contains("alice"), "HyperlinkBase local path removed");
        assert!(!app.contains("842"), "TotalTime removed");
        assert!(app.contains("MS Word"), "benign Application kept");

        assert!(read_entry(&out, "docProps/custom.xml").is_none(), "custom.xml dropped");
        assert!(read_entry(&out, "word/document.xml").unwrap().contains("the actual content"),
            "document content preserved");

        assert!(report.cleaned.iter().any(|c| c.contains("docProps/custom.xml")));
        assert!(report.cleaned.iter().any(|c| c == "docProps/core.xml"));
        assert!(report.passed_through.is_empty(), "nothing unscrubbable in this doc");
    }

    #[test]
    fn ooxml_scrub_strips_revision_authors_rsids_thumbnail_customxml() {
        let mut buf = Vec::new();
        let mut w = zip::ZipWriter::new(Cursor::new(&mut buf));
        let o = zip::write::SimpleFileOptions::default();
        let put = |w: &mut zip::ZipWriter<Cursor<&mut Vec<u8>>>, n: &str, d: &[u8]| {
            w.start_file(n, o).unwrap();
            w.write_all(d).unwrap();
        };
        put(&mut w, "[Content_Types].xml", b"<Types/>");
        put(&mut w, "word/document.xml",
            br#"<w:document><w:p w:rsidR="00AB12CD" w:rsidRDefault="00FF00FF"><w:ins w:id="1" w:author="Alice Editor" w:date="2023-05-01T10:00:00Z"><w:r><w:t>added text</w:t></w:r></w:ins></w:p></w:document>"#);
        put(&mut w, "word/comments.xml",
            br#"<w:comments><w:comment w:id="0" w:author="Bob Reviewer" w:initials="BR" w:date="2023-05-02T11:00:00Z"><w:p><w:r><w:t>a comment</w:t></w:r></w:p></w:comment></w:comments>"#);
        put(&mut w, "word/people.xml",
            br#"<w15:people><w15:person w15:author="Alice Editor"><w15:presenceInfo w15:providerId="AD" w15:userId="alice@corp.example"/></w15:person></w15:people>"#);
        put(&mut w, "word/settings.xml",
            br#"<w:settings><w:rsids><w:rsidRoot w:val="00AB12CD"/><w:rsid w:val="00FF00FF"/></w:rsids></w:settings>"#);
        put(&mut w, "docProps/thumbnail.jpeg", &[0xFF, 0xD8, 0xFF, 0xD9]);
        put(&mut w, "customXml/item1.xml", b"<data>sharepoint-case-7</data>");
        w.finish().unwrap();

        let (out, report) = scrub_ooxml(&buf).unwrap();

        let doc = read_entry(&out, "word/document.xml").unwrap();
        assert!(!doc.contains("Alice Editor"), "tracked-change author gone");
        assert!(!doc.contains("2023-05-01"), "tracked-change date gone");
        assert!(!doc.contains("00AB12CD") && !doc.contains("00FF00FF"), "rsids gone");
        assert!(doc.contains("added text"), "inserted content kept");
        assert!(doc.contains("<w:ins"), "tracked-change structure kept");

        let comments = read_entry(&out, "word/comments.xml").unwrap();
        assert!(!comments.contains("Bob Reviewer") && !comments.contains("BR\""), "comment author/initials gone");
        assert!(comments.contains("a comment"), "comment text kept");

        let people = read_entry(&out, "word/people.xml").unwrap();
        assert!(!people.contains("Alice Editor") && !people.contains("alice@corp.example"), "people.xml identities gone");

        let settings = read_entry(&out, "word/settings.xml").unwrap();
        assert!(!settings.contains("rsidRoot") && !settings.contains("00AB12CD"), "rsid table gone");

        assert!(read_entry(&out, "docProps/thumbnail.jpeg").is_none(), "thumbnail dropped");
        assert!(read_entry(&out, "customXml/item1.xml").is_none(), "customXml store dropped");
        assert!(report.cleaned.iter().any(|c| c.contains("word/document.xml")));
    }

    #[test]
    fn ooxml_scrub_drops_case_varied_metadata_parts() {
        // Adversarial-review fix: the drop/scrub gate used to be a
        // case-sensitive `==`/`starts_with` on the zip entry name
        // (`docProps/custom.xml`, `Thumbnails/`, `customXml/`). A crafted
        // archive using a different case for these normatively-lowercase
        // (or, for `Pictures/`, normatively-fixed-case) part names dodged
        // every check and fell through to the unscrubbed passthrough
        // default. This proves the fix: differently-cased entries are still
        // recognized and stripped/scrubbed.
        let mut buf = Vec::new();
        let mut w = zip::ZipWriter::new(Cursor::new(&mut buf));
        let o = zip::write::SimpleFileOptions::default();
        let put = |w: &mut zip::ZipWriter<Cursor<&mut Vec<u8>>>, n: &str, d: &[u8]| {
            w.start_file(n, o).unwrap();
            w.write_all(d).unwrap();
        };
        put(&mut w, "[Content_Types].xml", b"<Types/>");
        // Wrong-case docProps/custom.xml — should still be dropped wholesale.
        put(&mut w, "docProps/Custom.xml", b"<custom>internal-case-99</custom>");
        // Wrong-case Thumbnails/ prefix — should still be dropped wholesale.
        put(&mut w, "THUMBNAILS/thumb.jpeg", &[0xFF, 0xD8, 0xFF, 0xD9]);
        // Wrong-case docProps/core.xml — should still hit the SCRUBBED_CORE arm.
        put(&mut w, "DocProps/Core.xml",
            br#"<cp:coreProperties><dc:creator>Alice Secret</dc:creator></cp:coreProperties>"#);
        put(&mut w, "word/document.xml", b"<w:document>the actual content</w:document>");
        w.finish().unwrap();

        let (out, report) = scrub_ooxml(&buf).unwrap();

        assert!(read_entry(&out, "docProps/Custom.xml").is_none(), "wrong-case custom.xml still dropped");
        assert!(read_entry(&out, "THUMBNAILS/thumb.jpeg").is_none(), "wrong-case Thumbnails/ still dropped");
        let core = read_entry(&out, "DocProps/Core.xml").unwrap();
        assert!(!core.contains("Alice Secret"), "wrong-case core.xml still scrubbed, not passed through unscrubbed");
        assert!(report.passed_through.is_empty(), "nothing should have fallen through to the unscrubbed default");
        assert!(read_entry(&out, "word/document.xml").unwrap().contains("the actual content"));
    }

    #[test]
    fn ooxml_scrub_cleans_embedded_media_and_reports_unsupported() {
        // A JPEG with an APP1 EXIF segment, embedded as word/media.
        let jpeg_with_exif: &[u8] = &[
            0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x08, b'E', b'x', b'i', b'f', 0x00, 0x00,
            0xFF, 0xDA, 0x00, 0x02, 0x12, 0x34, 0xFF, 0xD9,
        ];
        let mut buf = Vec::new();
        let mut w = zip::ZipWriter::new(Cursor::new(&mut buf));
        let o = zip::write::SimpleFileOptions::default();
        w.start_file("[Content_Types].xml", o).unwrap();
        w.write_all(b"<Types/>").unwrap();
        w.start_file("word/media/image1.jpeg", o).unwrap();
        w.write_all(jpeg_with_exif).unwrap();
        w.start_file("word/media/image2.emf", o).unwrap();
        w.write_all(b"\x01\x00\x00\x00EMF-with-unknown-metadata").unwrap();
        w.finish().unwrap();

        let (out, report) = scrub_ooxml(&buf).unwrap();
        let mut z = zip::ZipArchive::new(Cursor::new(&out[..])).unwrap();
        let mut media = Vec::new();
        z.by_name("word/media/image1.jpeg").unwrap().read_to_end(&mut media).unwrap();
        assert!(!media.windows(4).any(|w| w == b"Exif"), "embedded JPEG EXIF gone");
        assert!(report.cleaned.iter().any(|c| c.contains("image1.jpeg")));
        assert!(
            report.passed_through.iter().any(|c| c.contains("image2.emf")),
            "unsupported media format is reported, not silently blessed"
        );
    }

    #[test]
    fn ooxml_scrub_is_deterministic() {
        // Fixed entry timestamps: scrubbing twice yields identical bytes — no
        // "scrubbed at" clock fingerprint.
        let doc = build_doc();
        let (a, _) = scrub_ooxml(&doc).unwrap();
        let (b, _) = scrub_ooxml(&doc).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn odf_meta_is_scrubbed() {
        let mut buf = Vec::new();
        let mut w = zip::ZipWriter::new(Cursor::new(&mut buf));
        let o = zip::write::SimpleFileOptions::default();
        w.start_file("mimetype", o).unwrap();
        w.write_all(b"application/vnd.oasis.opendocument.text").unwrap();
        w.start_file("meta.xml", o).unwrap();
        w.write_all(br#"<office:document-meta><office:meta><dc:creator>Alice Secret</dc:creator><meta:initial-creator>Alice Secret</meta:initial-creator><meta:generator>LibreOffice/7.6</meta:generator><dc:date>2023-01-01</dc:date></office:meta></office:document-meta>"#).unwrap();
        w.start_file("content.xml", o).unwrap();
        w.write_all(br#"<office:body><office:annotation><dc:creator>Bob Note</dc:creator><text:p>note text</text:p></office:annotation><text:p>body text</text:p></office:body>"#).unwrap();
        w.finish().unwrap();

        let (out, report) = scrub_ooxml(&buf).unwrap();
        let meta = read_entry(&out, "meta.xml").unwrap();
        assert!(!meta.contains("Alice Secret") && !meta.contains("LibreOffice"), "ODF meta gone");
        let content = read_entry(&out, "content.xml").unwrap();
        assert!(!content.contains("Bob Note"), "annotation author gone");
        assert!(content.contains("note text") && content.contains("body text"), "content kept");
        assert!(report.cleaned.iter().any(|c| c == "meta.xml"));
    }

    #[test]
    fn non_zip_is_rejected() {
        assert!(matches!(scrub_ooxml(b"not a zip"), Err(HygieneError::NotZipDoc)));
    }

    #[test]
    fn remove_element_handles_attrs_and_repeats() {
        let x = "<a><Company>x</Company><b/><Company id='2'>y</Company></a>";
        assert_eq!(remove_element(x, "Company"), "<a><b/></a>");
    }

    #[test]
    fn jpeg_scrub_drops_exif_keeps_image() {
        // SOI · APP1(EXIF "Exif\0\0") · SOS(no payload) · entropy · EOI.
        let jpeg: &[u8] = &[
            0xFF, 0xD8, // SOI
            0xFF, 0xE1, 0x00, 0x08, b'E', b'x', b'i', b'f', 0x00, 0x00, // APP1 EXIF
            0xFF, 0xDA, 0x00, 0x02, // SOS
            0x12, 0x34, // (fake) entropy-coded scan
            0xFF, 0xD9, // EOI
        ];
        assert!(is_jpeg(jpeg));
        let (out, report) = scrub_jpeg(jpeg).unwrap();
        // Exact scrubbed output: SOI + (APP1 dropped) + SOS/scan/EOI intact.
        assert_eq!(out, vec![0xFF, 0xD8, 0xFF, 0xDA, 0x00, 0x02, 0x12, 0x34, 0xFF, 0xD9]);
        assert!(!out.windows(4).any(|w| w == b"Exif"), "EXIF removed");
        assert!(report.cleaned.iter().any(|c| c.contains("APP1")));
        assert!(scrub_jpeg(b"not jpeg").is_err());
    }

    #[test]
    fn jpeg_scrub_drops_iptc_com_and_trailing_data() {
        let jpeg: &[u8] = &[
            0xFF, 0xD8, // SOI
            0xFF, 0xED, 0x00, 0x0C, b'P', b'h', b'o', b't', b'o', b's', b'h', b'o', b'p', 0x00, // APP13 IPTC
            0xFF, 0xFE, 0x00, 0x08, b'u', b's', b'e', b'r', b'n', b'm', // COM comment
            0xFF, 0xE2, 0x00, 0x05, b'I', b'C', b'C', // APP2 ICC
            0xFF, 0xDA, 0x00, 0x02, // SOS
            0x12, 0x34, // entropy
            0xFF, 0xD9, // EOI
            b'Z', b'I', b'P', b'!', // appended payload after EOI
        ];
        let (out, report) = scrub_jpeg(jpeg).unwrap();
        assert_eq!(out, vec![0xFF, 0xD8, 0xFF, 0xDA, 0x00, 0x02, 0x12, 0x34, 0xFF, 0xD9]);
        assert!(!out.windows(9).any(|w| w == b"Photoshop"), "IPTC/Photoshop gone");
        assert!(report.cleaned.iter().any(|c| c.contains("APP13")));
        assert!(report.cleaned.iter().any(|c| c.contains("COM")));
        assert!(report.cleaned.iter().any(|c| c.contains("APP2")));
        assert!(report.cleaned.iter().any(|c| c.contains("trailing")));
    }

    #[test]
    fn jpeg_scrub_fails_closed_on_malformed_length() {
        // APP1 declares a length running past end-of-buffer — the old behavior
        // copied the tail through (silent EXIF passthrough). Must now be Err.
        let forged: &[u8] = &[
            0xFF, 0xD8, // SOI
            0xFF, 0xE1, 0xFF, 0xFF, b'E', b'x', b'i', b'f', 0x00, 0x00, // APP1, oversized len
            0xFF, 0xDA, 0x00, 0x02, 0x12, 0x34, 0xFF, 0xD9,
        ];
        assert!(matches!(scrub_jpeg(forged), Err(HygieneError::Malformed(_))));
        // Length < 2 is equally malformed.
        let forged2: &[u8] = &[0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x01, 0xFF, 0xD9];
        assert!(matches!(scrub_jpeg(forged2), Err(HygieneError::Malformed(_))));
        // Non-marker garbage where a marker must be: also refuse.
        let garbage: &[u8] = &[0xFF, 0xD8, 0x00, 0x00, 0xFF, 0xD9];
        assert!(matches!(scrub_jpeg(garbage), Err(HygieneError::Malformed(_))));
        // Truncated (no EOI): refuse.
        let truncated: &[u8] = &[0xFF, 0xD8, 0xFF, 0xDA, 0x00, 0x02, 0x12];
        assert!(matches!(scrub_jpeg(truncated), Err(HygieneError::Malformed(_))));
    }

    /// Build a PNG chunk with a dummy CRC (the scrubber copies, never checks).
    fn png_chunk(ctype: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let mut c = Vec::new();
        c.extend_from_slice(&(data.len() as u32).to_be_bytes());
        c.extend_from_slice(ctype);
        c.extend_from_slice(data);
        c.extend_from_slice(&[0, 0, 0, 0]); // CRC placeholder
        c
    }

    #[test]
    fn png_scrub_drops_text_exif_time_keeps_structure() {
        let mut png = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        png.extend(png_chunk(b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0]));
        png.extend(png_chunk(b"tEXt", b"Author\0Alice Secret"));
        png.extend(png_chunk(b"iTXt", b"XML:com.adobe.xmp\0\0\0\0\0<xmp>gps</xmp>"));
        png.extend(png_chunk(b"eXIf", b"II*\0exif-payload"));
        png.extend(png_chunk(b"tIME", &[7, 230, 1, 1, 0, 0, 0]));
        png.extend(png_chunk(b"IDAT", &[1, 2, 3, 4]));
        png.extend(png_chunk(b"IEND", &[]));
        png.extend_from_slice(b"APPENDED-PAYLOAD");

        let (out, report) = scrub_png(&png).unwrap();
        assert!(is_png(&out));
        assert!(!out.windows(12).any(|w| w == b"Alice Secret"), "tEXt gone");
        assert!(!out.windows(5).any(|w| w == b"<xmp>"), "iTXt/XMP gone");
        assert!(!out.windows(4).any(|w| w == b"eXIf"), "eXIf gone");
        assert!(!out.windows(8).any(|w| w == b"APPENDED"), "post-IEND payload gone");
        // structure kept
        assert!(out.windows(4).any(|w| w == b"IHDR"));
        assert!(out.windows(4).any(|w| w == b"IDAT"));
        assert!(out.windows(4).any(|w| w == b"IEND"));
        assert!(report.cleaned.iter().any(|c| c.contains("tEXt")));
        assert!(report.cleaned.iter().any(|c| c.contains("trailing")));
    }

    #[test]
    fn png_scrub_fails_closed_on_malformed_chunks() {
        // Chunk length pointing past the end of the buffer.
        let mut png = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        png.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]); // absurd length
        png.extend_from_slice(b"IHDR");
        assert!(matches!(scrub_png(&png), Err(HygieneError::Malformed(_))));
        // Missing IEND.
        let mut png2 = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        png2.extend(png_chunk(b"IDAT", &[1, 2, 3]));
        assert!(matches!(scrub_png(&png2), Err(HygieneError::Malformed(_))));
        assert!(matches!(scrub_png(b"not png"), Err(HygieneError::NotPng)));
    }

    #[test]
    fn pdf_scrub_removes_info_xmp_and_id() {
        use lopdf::{dictionary, Document, Object, Stream};
        let mut doc = Document::with_version("1.5");
        // Page-level XMP (the walk must catch non-Catalog /Metadata too).
        let page_meta_id = doc.add_object(Object::Stream(Stream::new(
            dictionary! { "Type" => "Metadata", "Subtype" => "XML" },
            b"<xmp>Page XMP Alice</xmp>".to_vec(),
        )));
        let pages_id = doc.new_object_id();
        let page_id = doc.add_object(dictionary! {
            "Type" => "Page", "Parent" => Object::Reference(pages_id),
            "Metadata" => Object::Reference(page_meta_id),
        });
        doc.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! { "Type" => "Pages", "Kids" => Object::Array(vec![Object::Reference(page_id)]), "Count" => 1 }),
        );
        let meta_id = doc.add_object(Object::Stream(Stream::new(
            dictionary! { "Type" => "Metadata", "Subtype" => "XML" },
            b"<xmp>Alice XMP</xmp>".to_vec(),
        )));
        let catalog_id = doc.add_object(dictionary! {
            "Type" => "Catalog", "Pages" => Object::Reference(pages_id), "Metadata" => Object::Reference(meta_id),
        });
        let info_id = doc.add_object(dictionary! {
            "Author" => Object::string_literal("Alice Secret"),
            "Producer" => Object::string_literal("SecretApp 1.0"),
        });
        doc.trailer.set("Root", Object::Reference(catalog_id));
        doc.trailer.set("Info", Object::Reference(info_id));
        doc.trailer.set(
            "ID",
            Object::Array(vec![
                Object::string_literal("fingerprint-A"),
                Object::string_literal("fingerprint-B"),
            ]),
        );
        let mut bytes = Vec::new();
        doc.save_to(&mut bytes).unwrap();
        // sanity: the PII is present before scrubbing.
        assert!(bytes.windows(12).any(|w| w == b"Alice Secret"));
        assert!(bytes.windows(13).any(|w| w == b"fingerprint-A"));

        let (out, report) = scrub_pdf(&bytes).unwrap();
        assert!(!out.windows(12).any(|w| w == b"Alice Secret"), "author gone");
        assert!(!out.windows(9).any(|w| w == b"Alice XMP"), "catalog XMP gone");
        assert!(!out.windows(14).any(|w| w == b"Page XMP Alice"), "page-level XMP gone");
        assert!(!out.windows(13).any(|w| w == b"fingerprint-A"), "/ID fingerprint gone");
        assert!(report.cleaned.iter().any(|c| c.contains("Info")));
        assert!(report.cleaned.iter().any(|c| c.contains("XMP")));
        assert!(report.cleaned.iter().any(|c| c.contains("ID")));
        // Reloads cleanly with no Info / ID.
        let re = Document::load_mem(&out).unwrap();
        assert!(re.trailer.get(b"Info").is_err(), "Info removed");
        assert!(re.trailer.get(b"ID").is_err(), "ID removed");
    }

    #[test]
    fn digest_is_deterministic_and_seal_signs_it() {
        let doc = b"scrubbed document bytes";
        let d1 = digest_shake256(doc);
        let d2 = digest_shake256(doc);
        assert_eq!(d1, d2, "SHAKE-256 digest deterministic");
        assert_ne!(d1, digest_shake256(b"other"), "different input -> different digest");

        // The signer receives EXACTLY the digest (never the raw doc).
        let mut signed_over = None;
        let seal = seal(doc, |m| {
            signed_over = Some(m.to_vec());
            b"FALCON||MLDSA-sig".to_vec()
        });
        assert_eq!(seal.digest, d1);
        assert_eq!(signed_over.as_deref(), Some(&d1[..]));
        assert_eq!(seal.signature, b"FALCON||MLDSA-sig");
    }

    // ── format dispatch ─────────────────────────────────────────────────────

    fn odf_doc() -> Vec<u8> {
        let mut buf = Vec::new();
        let mut w = zip::ZipWriter::new(Cursor::new(&mut buf));
        let o = zip::write::SimpleFileOptions::default();
        w.start_file("mimetype", o).unwrap();
        w.write_all(b"application/vnd.oasis.opendocument.text").unwrap();
        w.start_file("meta.xml", o).unwrap();
        w.write_all(br#"<office:document-meta><office:meta><dc:creator>Alice Secret</dc:creator></office:meta></office:document-meta>"#).unwrap();
        w.start_file("content.xml", o).unwrap();
        w.write_all(b"<office:body><text:p>body text</text:p></office:body>").unwrap();
        w.finish().unwrap();
        buf
    }

    fn minimal_pdf_with_info() -> Vec<u8> {
        use lopdf::{dictionary, Document, Object};
        let mut doc = Document::with_version("1.5");
        let pages_id = doc.new_object_id();
        let page_id = doc.add_object(dictionary! { "Type" => "Page", "Parent" => Object::Reference(pages_id) });
        doc.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! { "Type" => "Pages", "Kids" => Object::Array(vec![Object::Reference(page_id)]), "Count" => 1 }),
        );
        let catalog_id = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => Object::Reference(pages_id) });
        let info_id = doc.add_object(dictionary! { "Author" => Object::string_literal("Alice Secret") });
        doc.trailer.set("Root", Object::Reference(catalog_id));
        doc.trailer.set("Info", Object::Reference(info_id));
        let mut bytes = Vec::new();
        doc.save_to(&mut bytes).unwrap();
        assert!(bytes.starts_with(b"%PDF"), "sanity: lopdf emits the %PDF magic");
        bytes
    }

    #[test]
    fn detect_format_classifies_ooxml_odf_jpeg_png_pdf() {
        assert_eq!(detect_format(&build_doc()), Some(Format::Ooxml), "OOXML zip-doc");
        assert_eq!(detect_format(&odf_doc()), Some(Format::Ooxml), "ODF is also a zip-doc -> Ooxml");
        let jpeg: &[u8] = &[0xFF, 0xD8, 0xFF, 0xDA, 0x00, 0x02, 0x12, 0x34, 0xFF, 0xD9];
        assert_eq!(detect_format(jpeg), Some(Format::Jpeg));
        let png: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        assert_eq!(detect_format(png), Some(Format::Png));
        assert_eq!(detect_format(&minimal_pdf_with_info()), Some(Format::Pdf));
        assert_eq!(detect_format(b"%PDF-1.4 not a real pdf but has the magic"), Some(Format::Pdf), "PDF via real %PDF magic, not stubbed");
        assert_eq!(detect_format(b"nothing recognizable here"), None);
    }

    #[test]
    fn scrub_bytes_routes_ooxml_and_odf_through_scrub_ooxml() {
        let (out, report, fmt) = scrub_bytes(&build_doc()).unwrap();
        assert_eq!(fmt, Format::Ooxml);
        assert!(read_entry(&out, "docProps/custom.xml").is_none(), "routed to scrub_ooxml (custom.xml dropped)");
        assert!(report.cleaned.iter().any(|c| c == "docProps/core.xml"));

        let (odf_out, odf_report, odf_fmt) = scrub_bytes(&odf_doc()).unwrap();
        assert_eq!(odf_fmt, Format::Ooxml, "ODF also routes through scrub_ooxml");
        let meta = read_entry(&odf_out, "meta.xml").unwrap();
        assert!(!meta.contains("Alice Secret"), "ODF meta scrubbed via the shared OOXML/ODF path");
        assert!(odf_report.cleaned.iter().any(|c| c == "meta.xml"));
    }

    #[test]
    fn scrub_bytes_routes_jpeg_png_pdf() {
        let jpeg: &[u8] = &[
            0xFF, 0xD8, // SOI
            0xFF, 0xE1, 0x00, 0x08, b'E', b'x', b'i', b'f', 0x00, 0x00, // APP1 EXIF
            0xFF, 0xDA, 0x00, 0x02, // SOS
            0x12, 0x34, // entropy
            0xFF, 0xD9, // EOI
        ];
        let (jpeg_out, jpeg_report, jpeg_fmt) = scrub_bytes(jpeg).unwrap();
        assert_eq!(jpeg_fmt, Format::Jpeg);
        assert!(!jpeg_out.windows(4).any(|w| w == b"Exif"), "routed to scrub_jpeg");
        assert!(jpeg_report.cleaned.iter().any(|c| c.contains("APP1")));

        let mut png = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        png.extend(png_chunk(b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0]));
        png.extend(png_chunk(b"tEXt", b"Author\0Alice Secret"));
        png.extend(png_chunk(b"IDAT", &[1, 2, 3, 4]));
        png.extend(png_chunk(b"IEND", &[]));
        let (png_out, png_report, png_fmt) = scrub_bytes(&png).unwrap();
        assert_eq!(png_fmt, Format::Png);
        assert!(!png_out.windows(12).any(|w| w == b"Alice Secret"), "routed to scrub_png");
        assert!(png_report.cleaned.iter().any(|c| c.contains("tEXt")));

        let (pdf_out, pdf_report, pdf_fmt) = scrub_bytes(&minimal_pdf_with_info()).unwrap();
        assert_eq!(pdf_fmt, Format::Pdf);
        assert!(!pdf_out.windows(12).any(|w| w == b"Alice Secret"), "routed to scrub_pdf");
        assert!(pdf_report.cleaned.iter().any(|c| c.contains("Info")));
    }

    #[test]
    fn scrub_bytes_rejects_unrecognized_format() {
        assert!(matches!(scrub_bytes(b"not a recognized file format at all"), Err(HygieneError::UnknownFormat)));
        assert!(matches!(scrub_bytes(&[]), Err(HygieneError::UnknownFormat)));
    }

    // ── idempotence / change-accurate reporting ──────────────────────────────
    // Scrubbing the output of a scrub must (a) report an empty `cleaned` list
    // (nothing left to strip — the report is change-accurate, not a fixed
    // "these parts were visited" list) and (b) emit byte-identical output.
    // This is what a dry-run `check` builds on: a clean file must not
    // false-positive.

    #[test]
    fn ooxml_scrub_is_idempotent_with_empty_report() {
        let doc = build_doc();
        let (out1, r1) = scrub_ooxml(&doc).unwrap();
        assert!(!r1.cleaned.is_empty(), "sanity: first scrub found metadata");
        let (out2, r2) = scrub_ooxml(&out1).unwrap();
        assert!(r2.cleaned.is_empty(), "second scrub must report nothing cleaned: {:?}", r2.cleaned);
        assert!(r2.passed_through.is_empty());
        assert_eq!(out2, out1, "second scrub must be byte-identical");
    }

    #[test]
    fn ooxml_scrub_with_authors_and_media_is_idempotent() {
        // Richer fixture: tracked-change authors, rsids, comments, embedded
        // JPEG media — every scrub arm exercised, then re-scrubbed.
        let jpeg_with_exif: &[u8] = &[
            0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x08, b'E', b'x', b'i', b'f', 0x00, 0x00,
            0xFF, 0xDA, 0x00, 0x02, 0x12, 0x34, 0xFF, 0xD9,
        ];
        let mut buf = Vec::new();
        let mut w = zip::ZipWriter::new(Cursor::new(&mut buf));
        let o = zip::write::SimpleFileOptions::default();
        let put = |w: &mut zip::ZipWriter<Cursor<&mut Vec<u8>>>, n: &str, d: &[u8]| {
            w.start_file(n, o).unwrap();
            w.write_all(d).unwrap();
        };
        put(&mut w, "[Content_Types].xml", b"<Types/>");
        put(&mut w, "word/document.xml",
            br#"<w:document><w:p w:rsidR="00AB12CD"><w:ins w:id="1" w:author="Alice Editor" w:date="2023-05-01T10:00:00Z"><w:r><w:t>added text</w:t></w:r></w:ins></w:p></w:document>"#);
        put(&mut w, "word/settings.xml",
            br#"<w:settings><w:rsids><w:rsid w:val="00FF00FF"/></w:rsids></w:settings>"#);
        put(&mut w, "word/media/image1.jpeg", jpeg_with_exif);
        w.finish().unwrap();

        let (out1, r1) = scrub_ooxml(&buf).unwrap();
        assert!(r1.cleaned.iter().any(|c| c.contains("word/document.xml")), "sanity");
        assert!(r1.cleaned.iter().any(|c| c.contains("image1.jpeg")), "sanity");
        let (out2, r2) = scrub_ooxml(&out1).unwrap();
        assert!(r2.cleaned.is_empty(), "second scrub must report nothing cleaned: {:?}", r2.cleaned);
        assert!(r2.passed_through.is_empty());
        assert_eq!(out2, out1);
    }

    #[test]
    fn odf_scrub_is_idempotent_with_empty_report() {
        let doc = odf_doc();
        let (out1, r1) = scrub_ooxml(&doc).unwrap();
        assert!(r1.cleaned.iter().any(|c| c == "meta.xml"), "sanity: first scrub cleaned meta.xml");
        let (out2, r2) = scrub_ooxml(&out1).unwrap();
        assert!(r2.cleaned.is_empty(), "second scrub must report nothing cleaned: {:?}", r2.cleaned);
        assert!(r2.passed_through.is_empty());
        assert_eq!(out2, out1);
    }

    // ── ODF settings.xml (printer/view traces) + mimetype packaging ─────────

    /// A realistic LibreOffice-shaped settings.xml: view-settings tree with a
    /// per-session ViewId, plus configuration-settings with the printer trio.
    const ODF_SETTINGS: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<office:document-settings xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:config="urn:oasis:names:tc:opendocument:xmlns:config:1.0" office:version="1.3"><office:settings><config:config-item-set config:name="ooo:view-settings"><config:config-item-map-indexed config:name="Views"><config:config-item-map-entry><config:config-item config:name="ViewId" config:type="string">view2</config:config-item><config:config-item config:name="ZoomFactor" config:type="short">100</config:config-item></config:config-item-map-entry></config:config-item-map-indexed></config:config-item-set><config:config-item-set config:name="ooo:configuration-settings"><config:config-item config:name="PrinterName" config:type="string">HP-LJ4-on-ALICE-DESKTOP</config:config-item><config:config-item config:name="PrinterSetup" config:type="base64Binary">QUxJQ0UtREVTS1RPUAo=</config:config-item><config:config-item config:name="PrintParms" config:type="base64Binary">cHJpbnQtcGFybXMK</config:config-item><config:config-item config:name="AddParaTableSpacing" config:type="boolean">true</config:config-item></config:config-item-set></office:settings></office:document-settings>"#;

    fn build_odf_with_settings(mime: &str, mimetype_first: bool) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut w = zip::ZipWriter::new(Cursor::new(&mut buf));
        let o = zip::write::SimpleFileOptions::default();
        let put = |w: &mut zip::ZipWriter<Cursor<&mut Vec<u8>>>, n: &str, d: &[u8]| {
            w.start_file(n, o).unwrap();
            w.write_all(d).unwrap();
        };
        if mimetype_first {
            put(&mut w, "mimetype", mime.as_bytes());
        }
        put(&mut w, "meta.xml",
            br#"<office:document-meta><office:meta><dc:creator>Alice Secret</dc:creator></office:meta></office:document-meta>"#);
        put(&mut w, "settings.xml", ODF_SETTINGS);
        put(&mut w, "content.xml", b"<office:body><text:p>body text</text:p></office:body>");
        if !mimetype_first {
            put(&mut w, "mimetype", mime.as_bytes());
        }
        w.finish().unwrap();
        buf
    }

    #[test]
    fn odf_settings_scrub_and_mimetype_packaging_odt_ods_odp() {
        for mime in [
            "application/vnd.oasis.opendocument.text",         // .odt
            "application/vnd.oasis.opendocument.spreadsheet",  // .ods
            "application/vnd.oasis.opendocument.presentation", // .odp
        ] {
            let doc = build_odf_with_settings(mime, true);
            let (out, report) = scrub_ooxml(&doc).unwrap();

            // settings.xml: printer traces dropped, view-session ID blanked.
            let settings = read_entry(&out, "settings.xml").unwrap();
            assert!(!settings.contains("ALICE-DESKTOP"), "PrinterName value gone ({mime})");
            assert!(!settings.contains("QUxJQ0UtREVTS1RPUAo="), "PrinterSetup base64 blob gone ({mime})");
            assert!(!settings.contains("cHJpbnQtcGFybXMK"), "PrintParms gone ({mime})");
            assert!(!settings.contains("view2"), "ViewId session value blanked ({mime})");
            assert!(settings.contains(r#"config:name="ViewId""#), "ViewId element kept, only its value blanked ({mime})");
            assert!(settings.contains("AddParaTableSpacing") && settings.contains(">true<"), "benign config setting kept ({mime})");
            assert!(settings.contains("ZoomFactor") && settings.contains(">100<"), "benign view setting kept ({mime})");
            assert!(report.cleaned.iter().any(|c| c.contains("settings.xml")), "settings.xml reported ({mime})");

            // mimetype: FIRST entry, STORED, byte-identical (ODF pkg rule) —
            // and the output re-opens as a valid zip archive.
            let mut z = zip::ZipArchive::new(Cursor::new(&out[..])).unwrap();
            {
                let mut f = z.by_index(0).unwrap();
                assert_eq!(f.name(), "mimetype", "mimetype is entry index 0 ({mime})");
                assert_eq!(f.compression(), zip::CompressionMethod::Stored, "mimetype stored uncompressed ({mime})");
                let mut s = String::new();
                f.read_to_string(&mut s).unwrap();
                assert_eq!(s, mime, "mimetype bytes unchanged ({mime})");
            }
            // Change-accurate: unchanged mimetype is never reported cleaned.
            assert!(!report.cleaned.iter().any(|c| c.contains("mimetype")));

            // Idempotence: a second scrub reports nothing cleaned and emits
            // byte-identical output (the dry-run-check contract).
            let (out2, r2) = scrub_ooxml(&out).unwrap();
            assert!(r2.cleaned.is_empty(), "second scrub must clean nothing ({mime}): {:?}", r2.cleaned);
            assert!(r2.passed_through.is_empty());
            assert_eq!(out2, out, "second scrub byte-identical ({mime})");
        }
    }

    #[test]
    fn odf_mimetype_is_moved_first_even_when_input_misplaces_it() {
        // A non-conforming (but zip-valid) ODF with mimetype as the LAST
        // entry: the scrub must still emit it first + stored, unchanged.
        let doc = build_odf_with_settings("application/vnd.oasis.opendocument.text", false);
        let (out, _) = scrub_ooxml(&doc).unwrap();
        let mut z = zip::ZipArchive::new(Cursor::new(&out[..])).unwrap();
        let mut f = z.by_index(0).unwrap();
        assert_eq!(f.name(), "mimetype");
        assert_eq!(f.compression(), zip::CompressionMethod::Stored);
        let mut s = String::new();
        f.read_to_string(&mut s).unwrap();
        assert_eq!(s, "application/vnd.oasis.opendocument.text");
    }

    #[test]
    fn odf_settings_scrub_fails_closed_on_ill_formed_xml() {
        let mut buf = Vec::new();
        let mut w = zip::ZipWriter::new(Cursor::new(&mut buf));
        let o = zip::write::SimpleFileOptions::default();
        w.start_file("mimetype", o).unwrap();
        w.write_all(b"application/vnd.oasis.opendocument.text").unwrap();
        w.start_file("settings.xml", o).unwrap();
        // Mismatched end tag — must not be copied through half-scanned.
        w.write_all(br#"<office:settings><config:config-item config:name="PrinterName">HP</wrong></office:settings>"#).unwrap();
        w.finish().unwrap();
        assert!(matches!(scrub_ooxml(&buf), Err(HygieneError::Malformed(_))));

        // Non-UTF-8 settings.xml: equally refused (same contract as OOXML XML).
        let mut buf2 = Vec::new();
        let mut w2 = zip::ZipWriter::new(Cursor::new(&mut buf2));
        w2.start_file("mimetype", o).unwrap();
        w2.write_all(b"application/vnd.oasis.opendocument.text").unwrap();
        w2.start_file("settings.xml", o).unwrap();
        w2.write_all(&[0xFF, 0xFE, b'<', b'a', b'/', b'>']).unwrap();
        w2.finish().unwrap();
        assert!(matches!(scrub_ooxml(&buf2), Err(HygieneError::Malformed(_))));
    }

    #[test]
    fn odf_settings_scrub_drops_self_closed_and_odd_prefix_printer_items() {
        // Safe-direction matching: local-name match means a self-closed item
        // or an unconventional namespace prefix cannot dodge the drop.
        let xml = r#"<s xmlns:c="urn:oasis:names:tc:opendocument:xmlns:config:1.0"><c:config-item c:name="PrinterSetup" c:type="base64Binary"/><c:config-item c:name="Zoom">75</c:config-item></s>"#;
        let out = scrub_odf_settings(xml).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(!out.contains("PrinterSetup"), "odd-prefix self-closed printer item dropped");
        assert!(out.contains("Zoom") && out.contains(">75<"), "benign item kept");
    }

    #[test]
    fn jpeg_scrub_is_idempotent_with_empty_report() {
        let jpeg: &[u8] = &[
            0xFF, 0xD8, // SOI
            0xFF, 0xE1, 0x00, 0x08, b'E', b'x', b'i', b'f', 0x00, 0x00, // APP1 EXIF
            0xFF, 0xDA, 0x00, 0x02, 0x12, 0x34, 0xFF, 0xD9, // SOS/scan/EOI
        ];
        let (out1, r1) = scrub_jpeg(jpeg).unwrap();
        assert!(!r1.cleaned.is_empty(), "sanity");
        let (out2, r2) = scrub_jpeg(&out1).unwrap();
        assert!(r2.cleaned.is_empty(), "clean JPEG must report nothing cleaned: {:?}", r2.cleaned);
        assert_eq!(out2, out1);
    }

    #[test]
    fn png_scrub_is_idempotent_with_empty_report() {
        let mut png = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        png.extend(png_chunk(b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0]));
        png.extend(png_chunk(b"tEXt", b"Author\0Alice Secret"));
        png.extend(png_chunk(b"IDAT", &[1, 2, 3, 4]));
        png.extend(png_chunk(b"IEND", &[]));
        let (out1, r1) = scrub_png(&png).unwrap();
        assert!(!r1.cleaned.is_empty(), "sanity");
        let (out2, r2) = scrub_png(&out1).unwrap();
        assert!(r2.cleaned.is_empty(), "clean PNG must report nothing cleaned: {:?}", r2.cleaned);
        assert_eq!(out2, out1);
    }

    // ── parser-DoS regressions (bounded time / bounded input, fail closed) ───

    #[test]
    fn remove_element_many_elements_is_linear_not_quadratic() {
        // Regression: `remove_element` used to `find`-from-0 + `replace_range`
        // per occurrence — O(n²). 300k matching elements (~6.6 MB) made it
        // shift ~1e12 bytes (minutes of CPU); the single forward pass finishes
        // in milliseconds. The 20 s bound is deliberately generous (slow CI,
        // debug builds) — it still fails the quadratic implementation by a
        // wide margin while never flaking on the linear one.
        let n = 300_000usize;
        let mut xml = String::with_capacity(n * 30 + 64);
        xml.push_str("<props><Keep>stay</Keep>");
        for i in 0..n {
            // Alternate both opening forms so each match path is exercised.
            if i % 2 == 0 {
                xml.push_str("<Company>x</Company>");
            } else {
                xml.push_str("<Company id='2'>y</Company>");
            }
        }
        xml.push_str("<Keep2>also stay</Keep2></props>");

        let t = std::time::Instant::now();
        let out = remove_element(&xml, "Company");
        let elapsed = t.elapsed();

        assert_eq!(out, "<props><Keep>stay</Keep><Keep2>also stay</Keep2></props>");
        assert!(
            elapsed < std::time::Duration::from_secs(20),
            "remove_element must be linear; took {elapsed:?} on {n} elements"
        );
    }

    #[test]
    fn pathological_many_attr_xml_part_scrubs_in_bounded_time() {
        // End-to-end through scrub_ooxml: a crafted word/document.xml carrying
        // 200k `w:author` attributes. The attribute blanking used to
        // `replace_range` per occurrence (quadratic tail shifts — a CPU-
        // exhaustion hang on an attacker-supplied .docx); it must now complete
        // linearly. Same generous-but-discriminating time bound rationale as
        // remove_element_many_elements_is_linear_not_quadratic.
        let n = 200_000usize;
        let mut part = String::with_capacity(n * 40 + 64);
        part.push_str("<w:document>");
        for _ in 0..n {
            part.push_str(r#"<w:ins w:author="Alice Editor"><w:t>k</w:t></w:ins>"#);
        }
        part.push_str("</w:document>");

        let mut buf = Vec::new();
        let mut w = zip::ZipWriter::new(Cursor::new(&mut buf));
        let o = zip::write::SimpleFileOptions::default();
        w.start_file("[Content_Types].xml", o).unwrap();
        w.write_all(b"<Types/>").unwrap();
        w.start_file("word/document.xml", o).unwrap();
        w.write_all(part.as_bytes()).unwrap();
        w.finish().unwrap();

        let t = std::time::Instant::now();
        let (out, report) = scrub_ooxml(&buf).unwrap();
        let elapsed = t.elapsed();

        assert!(
            elapsed < std::time::Duration::from_secs(20),
            "pathological many-attribute part must scrub in bounded time; took {elapsed:?}"
        );
        let doc = read_entry(&out, "word/document.xml").unwrap();
        assert!(!doc.contains("Alice Editor"), "authors still blanked on the fast path");
        assert!(report.cleaned.iter().any(|c| c.contains("word/document.xml")));
    }

    #[test]
    fn oversized_xml_part_is_rejected_not_scrubbed() {
        // A 33 MiB word/document.xml (over the 32 MiB per-XML-part cap, under
        // the 64 MiB zip entry cap) must be refused with a scrub error before
        // any scrub pass touches it — never hang, never pass through.
        let mut part = vec![b' '; 33 * 1024 * 1024];
        part[..12].copy_from_slice(b"<w:document>");
        let tail = b"</w:document>";
        let len = part.len();
        part[len - tail.len()..].copy_from_slice(tail);

        let mut buf = Vec::new();
        let mut w = zip::ZipWriter::new(Cursor::new(&mut buf));
        let o = zip::write::SimpleFileOptions::default();
        w.start_file("[Content_Types].xml", o).unwrap();
        w.write_all(b"<Types/>").unwrap();
        w.start_file("word/document.xml", o).unwrap();
        w.write_all(&part).unwrap();
        w.finish().unwrap();

        assert!(matches!(scrub_ooxml(&buf), Err(HygieneError::TooLarge)));
    }

    #[test]
    fn oversized_pdf_is_rejected_before_parse() {
        // Input over MAX_PDF_BYTES must be refused up front with TooLarge —
        // the parser never sees it. (Without the cap this returned a parser
        // error at best after unbounded work, so the specific variant is the
        // regression assertion.)
        let mut input = vec![b' '; MAX_PDF_BYTES + 1];
        input[..5].copy_from_slice(b"%PDF-");
        assert!(matches!(scrub_pdf(&input), Err(HygieneError::TooLarge)));
    }

    #[test]
    fn malformed_pdf_is_err_not_panic() {
        // Malformed PDFs must yield Err, never a panic escaping scrub_pdf.
        // Honest caveat: we do not have an input that provably panics the
        // pinned lopdf version, so this asserts the Err contract on assorted
        // malformed inputs; the catch_unwind in scrub_pdf converts any
        // unwinding parser panic on future/other inputs into this same Err
        // path (it cannot catch aborts or stack exhaustion).
        let cases: &[&[u8]] = &[
            b"%PDF-1.5",                                     // header only
            b"%PDF-1.5\nxref\n0 1\ngarbage\n%%EOF",          // bogus xref
            b"%PDF-1.5\n1 0 obj\n<< /Type /Catalog\n%%EOF",  // truncated object
            b"not a pdf at all",
            &[0xFF; 1024],
        ];
        for c in cases {
            assert!(scrub_pdf(c).is_err(), "malformed PDF must be Err: {:?}", &c[..c.len().min(16)]);
        }
    }
}
