//! `postern-hygiene scrub|check <file>` — the static CLI entry point for the
//! `postern-hygiene` document-metadata scrubber. See the `postern_hygiene`
//! crate docs for exactly what each format's scrub strips and what it can't.
//!
//! Std-only argument parsing (`std::env::args_os`, so a non-UTF-8 argv is a
//! clean `error:` + exit 2 instead of a panic) — **no clap, no new
//! dependency**. The `--json` output is hand-rolled with correct string
//! escaping (see [`json_escape`]) — still no new dependency.
//!
//! ```text
//! postern-hygiene scrub <file>            # write <file>.scrubbed
//! postern-hygiene check <file>            # dry-run: report only, write NOTHING
//! postern-hygiene scrub -  < in > out     # stdin -> scrubbed bytes on stdout,
//!                                         #   report on stderr (embed/pipe mode)
//! postern-hygiene check -  < in          # dry-run the document on stdin
//! postern-hygiene scrub|check --json ...  # machine-readable one-object report
//! ```
//!
//! - The format (OOXML/ODF zip, PDF, JPEG, PNG) is detected from magic bytes
//!   by [`postern_hygiene::scrub_bytes`]; an unrecognized format is a clear,
//!   non-zero-exit error (`HygieneError::UnknownFormat`).
//! - `scrub <file>`: output goes to `<file>.scrubbed`. **The input `<file>` is
//!   never opened for writing and never overwritten** — a scrub that fails
//!   partway (bad parse, malformed segment, I/O error) leaves the original
//!   completely untouched, because we only `fs::write` the `.scrubbed` sibling
//!   after the in-memory scrub has fully succeeded.
//! - `scrub -`: the document is read from stdin and the scrubbed bytes are
//!   written to stdout, so a file manager / OS pipeline can embed the scrubber
//!   without temp files. The report (human or `--json`) goes to **stderr** —
//!   stdout carries document bytes only. Bytes reach stdout only after the
//!   in-memory scrub fully succeeded; if the scrub fails, stdout gets nothing
//!   and we exit `2`. Precise limit: if the *stdout write itself* then fails
//!   partway (EPIPE, disk full), whatever was already written is a truncated
//!   prefix of the fully-scrubbed output — never original or unscrubbed
//!   bytes — and the exit code is still `2`, so an embedding pipeline must
//!   discard the output on any non-zero exit. Because `-` names stdin, a
//!   file literally named `-` must be passed as `./-` (standard convention).
//! - `check` (file or `-`): runs the exact same scrub fully in memory and
//!   prints the would-be report, but **writes nothing to disk at all**. Exit
//!   code `0` means the file is already clean (nothing would be cleaned,
//!   nothing would be passed through unscrubbed); exit code `1` means a scrub
//!   would change the file or would have to pass parts through unscrubbed;
//!   exit code `2` means the check itself failed (unreadable file,
//!   unrecognized or malformed format — a fail-closed parse error is NOT
//!   "clean").
//! - The `ScrubReport` (what was cleaned, and — if non-empty — what could NOT
//!   be scrubbed and was passed through unchanged) plus the detected
//!   [`Format`](postern_hygiene::Format) are printed: `cleaned` to stdout,
//!   `passed_through` to stderr (it means the output is not fully scrubbed,
//!   which is exactly what stderr is for). In `scrub -` mode the whole report
//!   moves to stderr (see above).
//! - `--json` (both subcommands): instead of the human report, emit exactly
//!   ONE JSON object — `{"format": "...", "cleaned": [...],
//!   "passed_through": [...], "out_path": "...", "clean": bool}` —
//!   `format` is one of `"ooxml"`, `"pdf"`, `"jpeg"`, `"png"`; note that ODF
//!   input also reports `"ooxml"` (the library detects both zip-package
//!   families as its single [`Format::Ooxml`](postern_hygiene::Format)
//!   variant — see [`format_token`]).
//!   `out_path` present only when `scrub` wrote a `.scrubbed` file. `clean` is
//!   true iff both lists are empty, i.e. exactly the condition under which
//!   `check` exits `0`. The exit-code contract is unchanged by `--json`.
//!   The object goes to stdout, except in `scrub -` mode where stdout carries
//!   the scrubbed bytes and the JSON goes to stderr.
//! - Any failure (missing/extra args, unreadable file/stdin, unrecognized
//!   format, or a `HygieneError` from the scrub itself) prints `error: ...`
//!   to stderr and exits `2` — distinct from `check`'s "file carries
//!   metadata" exit `1`. No JSON is emitted on the error path: exit `2`
//!   means nothing usable on stdout.
//!
//! HONESTY (shipping requirement, not marketing): scrub strips only the
//! metadata classes listed in the crate docs. A non-empty `passed_through`
//! list means the output is NOT fully scrubbed (e.g. embedded EMF/GIF/TIFF
//! media keeps its own metadata) and is always surfaced to the user — in the
//! human report AND in the JSON `passed_through`/`clean` fields. Content the
//! user typed (names in body text, headers) is not metadata and is not
//! touched. Legacy OLE `.doc`/`.xls` is unsupported. Fail-closed: a file
//! that cannot be fully parsed is an error (exit 2), never a "clean" result.
//! This code is unaudited.

use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::process::ExitCode;

use postern_hygiene::{scrub_bytes, Format, ScrubReport};

/// Human-readable label for the detected format (the library's `Format` is a
/// plain enum without a `Display` impl).
fn format_label(format: Format) -> &'static str {
    match format {
        Format::Ooxml => "OOXML/ODF (zip package)",
        Format::Pdf => "PDF",
        Format::Jpeg => "JPEG",
        Format::Png => "PNG",
    }
}

/// Stable machine token for the `"format"` field of the `--json` report.
/// Deliberately NOT the human label — scripts should never have to parse
/// `"OOXML/ODF (zip package)"`. NOTE: the token is `"ooxml"` for ODF input
/// too, because the library detects both zip-package families as its single
/// `Format::Ooxml` variant; if the library ever splits them, this map gains
/// an `"odf"` token, and until then scripts must treat `"ooxml"` as
/// "zip-package document (OOXML or ODF)".
fn format_token(format: Format) -> &'static str {
    match format {
        Format::Ooxml => "ooxml",
        Format::Pdf => "pdf",
        Format::Jpeg => "jpeg",
        Format::Png => "png",
    }
}

fn usage() -> &'static str {
    "usage: postern-hygiene scrub <file>\n       postern-hygiene check <file>\n       \
     postern-hygiene scrub [--json] -   (document on stdin, scrubbed bytes on stdout)\n       \
     postern-hygiene check [--json] -   (document on stdin, dry-run)\n\n\
     scrub: strips identifying metadata (author, timestamps, tracked-change\n\
     authorship, embedded GPS/EXIF, ...) from an OOXML/ODF, PDF, JPEG, or PNG\n\
     file and writes the result to <file>.scrubbed. The input <file> is never\n\
     modified or overwritten, even on failure. With '-' the document is read\n\
     from stdin and the scrubbed bytes go to stdout (report on stderr); a\n\
     file literally named '-' must be passed as './-'.\n\n\
     check: dry-run — reports what a scrub WOULD do, writes nothing to disk.\n\
     With '-' the document is read from stdin. Exits 0 if the file is already\n\
     clean, 1 if a scrub would change it (or would have to pass parts through\n\
     unscrubbed), 2 on error.\n\n\
     --json: emit one JSON object {format, cleaned, passed_through, out_path?,\n\
     clean} instead of the human report (to stderr in 'scrub -' mode, where\n\
     stdout carries the scrubbed bytes). Exit codes are unchanged.\n\n\
     Honest limits: only the metadata classes in the crate docs are stripped;\n\
     a non-empty passed_through list means the output is NOT fully scrubbed\n\
     (embedded EMF/GIF/TIFF media keeps its own metadata). Typed content is\n\
     not touched. Legacy OLE .doc/.xls unsupported. A file that cannot be\n\
     fully parsed is an error, never 'clean'. Unaudited."
}

fn print_report(format: Format, report: &ScrubReport) {
    println!("format: {}", format_label(format));
    if report.cleaned.is_empty() {
        println!("cleaned: (nothing to strip)");
    } else {
        println!("cleaned ({}):", report.cleaned.len());
        for c in &report.cleaned {
            println!("  - {c}");
        }
    }
    if report.passed_through.is_empty() {
        eprintln!("passed_through: (fully scrubbed — nothing left unscrubbed)");
    } else {
        eprintln!(
            "passed_through ({}) — NOT fully scrubbed, may still carry its own metadata:",
            report.passed_through.len()
        );
        for p in &report.passed_through {
            eprintln!("  - {p}");
        }
    }
}

/// `print_report`, but entirely on stderr — for `scrub -`, where stdout must
/// carry nothing but the scrubbed document bytes.
fn print_report_stderr(format: Format, report: &ScrubReport) {
    eprintln!("format: {}", format_label(format));
    if report.cleaned.is_empty() {
        eprintln!("cleaned: (nothing to strip)");
    } else {
        eprintln!("cleaned ({}):", report.cleaned.len());
        for c in &report.cleaned {
            eprintln!("  - {c}");
        }
    }
    if report.passed_through.is_empty() {
        eprintln!("passed_through: (fully scrubbed — nothing left unscrubbed)");
    } else {
        eprintln!(
            "passed_through ({}) — NOT fully scrubbed, may still carry its own metadata:",
            report.passed_through.len()
        );
        for p in &report.passed_through {
            eprintln!("  - {p}");
        }
    }
}

// ── hand-rolled JSON (std-only; correctness of escaping is test-covered) ────

/// Escape `s` for inclusion inside a JSON string literal per RFC 8259:
/// `"` and `\` are backslash-escaped, control characters < 0x20 are emitted
/// as `\uXXXX` (with the common short forms for \n, \r, \t). Everything else
/// — including non-ASCII — passes through as-is (JSON is UTF-8).
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// Render `v` as a JSON array of strings.
fn json_string_array(v: &[String]) -> String {
    let items: Vec<String> = v.iter().map(|s| format!("\"{}\"", json_escape(s))).collect();
    format!("[{}]", items.join(","))
}

/// The single `--json` report object. `clean` is true iff BOTH lists are
/// empty — the exact condition under which `check` exits 0. A non-empty
/// `passed_through` therefore always forces `clean: false`: passthroughs mean
/// the output is NOT fully scrubbed, and hiding that would be lying to the
/// pipeline embedding us.
fn json_report(format: Format, report: &ScrubReport, out_path: Option<&str>) -> String {
    let clean = report.cleaned.is_empty() && report.passed_through.is_empty();
    let mut obj = format!(
        "{{\"format\":\"{}\",\"cleaned\":{},\"passed_through\":{}",
        format_token(format),
        json_string_array(&report.cleaned),
        json_string_array(&report.passed_through),
    );
    if let Some(p) = out_path {
        obj.push_str(&format!(",\"out_path\":\"{}\"", json_escape(p)));
    }
    obj.push_str(&format!(",\"clean\":{clean}}}"));
    obj
}

// ── input plumbing ──────────────────────────────────────────────────────────

/// Read the whole document: from stdin if `arg` is `-`, else from the file at
/// `arg` (opened read-only — the input is never written).
fn read_input(arg: &str) -> Result<Vec<u8>, String> {
    if arg == "-" {
        let mut buf = Vec::new();
        io::stdin()
            .lock()
            .read_to_end(&mut buf)
            .map_err(|e| format!("cannot read stdin: {e}"))?;
        Ok(buf)
    } else {
        fs::read(arg).map_err(|e| format!("cannot read '{arg}': {e}"))
    }
}

/// The name used for `arg` in error messages: the path itself, or `<stdin>`.
fn input_label(arg: &str) -> &str {
    if arg == "-" {
        "<stdin>"
    } else {
        arg
    }
}

// ── subcommands ─────────────────────────────────────────────────────────────

/// Scrub the document named by `input_arg` (`-` = stdin). File mode writes
/// `<file>.scrubbed`; stdin mode streams the scrubbed bytes to stdout and
/// keeps every report line on stderr. Returns a human-readable error message
/// (never panics) on any failure; the original input is opened read-only
/// throughout, so nothing here can destroy it. In stdin mode, a failed scrub
/// writes nothing to stdout; if the stdout write itself fails partway, the
/// bytes already flushed are a truncated prefix of the fully-scrubbed output
/// (never original data) and the error/exit-2 path still fires.
fn scrub(input_arg: &str, json: bool) -> Result<(), String> {
    let from_stdin = input_arg == "-";
    let input = read_input(input_arg)?;

    // Fully scrub in memory first — only once this succeeds do we touch disk
    // or stdout. In file mode we then only write the `.scrubbed` sibling,
    // never the input itself; in stdin mode a failed scrub leaves stdout
    // completely empty (exit 2 = nothing usable on stdout).
    let (cleaned_bytes, report, format) = scrub_bytes(&input)
        .map_err(|e| format!("scrub failed for '{}': {e}", input_label(input_arg)))?;

    if from_stdin {
        let mut stdout = io::stdout().lock();
        stdout
            .write_all(&cleaned_bytes)
            .and_then(|()| stdout.flush())
            .map_err(|e| format!("cannot write scrubbed bytes to stdout: {e}"))?;
        drop(stdout);
        if json {
            // stdout carries the document; the one JSON object goes to stderr.
            eprintln!("{}", json_report(format, &report, None));
        } else {
            print_report_stderr(format, &report);
            eprintln!("wrote {} bytes to stdout", cleaned_bytes.len());
        }
    } else {
        let out_path = format!("{input_arg}.scrubbed");
        fs::write(&out_path, &cleaned_bytes)
            .map_err(|e| format!("cannot write '{out_path}': {e}"))?;
        if json {
            println!("{}", json_report(format, &report, Some(&out_path)));
        } else {
            print_report(format, &report);
            println!("wrote {out_path} ({} bytes)", cleaned_bytes.len());
        }
    }
    Ok(())
}

/// Dry-run: scrub the document named by `input_arg` (`-` = stdin) fully in
/// memory, print the would-be report, and **write nothing to disk**. Returns
/// the exit code: `0` if the file is already clean (empty `cleaned` AND empty
/// `passed_through` — a report with passthroughs means a scrub could not
/// fully clean it, which is not "clean"). `1` if a scrub would change the
/// file or leave parts unscrubbed. Errors (unreadable, unknown/malformed
/// format) propagate as `Err` and exit `2` — a file we cannot parse is never
/// reported clean (fail closed).
fn check(input_arg: &str, json: bool) -> Result<ExitCode, String> {
    let label = input_label(input_arg);
    let input = read_input(input_arg)?;

    // Same scrub as `scrub`, in memory only. The scrubbed bytes are discarded.
    let (_would_be_bytes, report, format) =
        scrub_bytes(&input).map_err(|e| format!("check failed for '{label}': {e}"))?;

    let clean = report.cleaned.is_empty() && report.passed_through.is_empty();
    if json {
        println!("{}", json_report(format, &report, None));
    } else {
        print_report(format, &report);
        if clean {
            println!("clean: '{label}' carries no metadata this scrubber would remove");
        } else {
            println!("not clean: a scrub would change '{label}' (nothing was written)");
        }
    }
    if clean {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(1))
    }
}

fn run(args: &[String]) -> Result<ExitCode, String> {
    // Std-only flag split: `--json` may appear anywhere; everything else is
    // positional. A literal `-` positional means stdin.
    let mut json = false;
    let mut positional: Vec<&str> = Vec::new();
    for a in args {
        if a == "--json" {
            json = true;
        } else {
            positional.push(a.as_str());
        }
    }

    let Some(cmd) = positional.first() else {
        return Err(usage().to_string());
    };
    let rest = &positional[1..];
    match *cmd {
        "scrub" => {
            if rest.len() != 1 {
                return Err(format!("'scrub' takes exactly one <file|-> argument\n\n{}", usage()));
            }
            scrub(rest[0], json).map(|()| ExitCode::SUCCESS)
        }
        "check" => {
            if rest.len() != 1 {
                return Err(format!("'check' takes exactly one <file|-> argument\n\n{}", usage()));
            }
            check(rest[0], json)
        }
        _ => Err(format!("unknown subcommand '{cmd}'\n\n{}", usage())),
    }
}

fn main() -> ExitCode {
    // `args_os` + explicit conversion: `env::args()` PANICS on a non-UTF-8
    // argv element. A CLI that can be embedded in pipelines must instead
    // fail the normal way — clear `error:` on stderr, exit 2.
    let mut args: Vec<String> = Vec::new();
    for a in env::args_os().skip(1) {
        match a.into_string() {
            Ok(s) => args.push(s),
            Err(bad) => {
                eprintln!(
                    "error: argument is not valid UTF-8: '{}'",
                    bad.to_string_lossy()
                );
                return ExitCode::from(2);
            }
        }
    }
    match run(&args) {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("error: {msg}");
            // Exit 2 on every error path — distinct from `check`'s exit 1
            // ("file carries metadata"), so scripts can tell "dirty file"
            // from "the tool failed". No JSON object is emitted on this
            // path: exit 2 means nothing usable on stdout.
            ExitCode::from(2)
        }
    }
}
