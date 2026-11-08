//! Postern Quarantine — inbound-document safety (a Postern Labs product).
//!
//! The **mirror of `postern-hygiene`**: hygiene protects what you *send*;
//! quarantine protects what you *receive*. Untrusted files are neutralised by
//! **rebuilding them from their rendered content**, so the original file
//! structure — and any macro, script, tracker, or hidden metadata riding in
//! it — never reaches the recipient's viewer.
//!
//! - **Images** (this module): decode to raw pixels and re-encode a clean PNG.
//!   Nothing of the original bytes survives except the visible pixels. Pure Rust
//!   (`image`, MIT/Apache), verified here.
//! - **PDF / Office**: render each page to a bitmap and rebuild a flat PDF;
//!   Office files are first converted to PDF with **unmodified LibreOffice
//!   headless** (MPL, aggregation-only — external user-installed binary,
//!   spawned, never linked or forked). Concept: Dangerzone (which is
//!   **AGPL** — reimplemented, no code). Status, honestly: the **rebuild
//!   half ships** in [`pdf`] (pure-Rust flat-PDF emitter from page rasters,
//!   tested), the **office pipeline ships** in [`office`] (magic-byte sniff
//!   → size cap → convert → `%PDF-` check → delegate to the PDF rebuild),
//!   the **LibreOffice converter adapter now ships** in [`adapters`]
//!   (out-of-process `soffice --headless --convert-to pdf` with a fresh
//!   throwaway profile per run, a wall-clock kill, an output-size cap, and
//!   fail-closed error mapping), and a **renderer adapter ships behind the
//!   default-OFF `render-hayro` feature** (`render_hayro` module — the
//!   pure-Rust `hayro` rasterizer, Apache-2.0 OR MIT; a default build still
//!   has no renderer and [`pdf::quarantine_pdf`] still takes it as an
//!   injected closure). A top-level [`dispatch::quarantine_bytes`] sniffs
//!   image / `%PDF-` / office magic and routes, hard-erroring on anything
//!   else. **What still does not exist — do not claim it:** Landlock/seccomp
//!   containment around the converter subprocess (the wall-clock kill +
//!   output cap + magic checks are the only bounds on it), any containment
//!   at all on macOS/Windows, and out-of-process rendering — the `hayro`
//!   render runs **in-process, the same attack-surface register as the
//!   image decode below**. Do not describe the PDF or Office paths as
//!   "exploit-proof" or "complete".
//!
//! ## Honest threat model — what the pixel round-trip does and does not cover
//!
//! - **Covered:** the *output* is rebuilt from pixels alone, so nothing of the
//!   input file (metadata, appended payloads, exploit bytes aimed at the
//!   *recipient's* viewer) survives into the cleaned file.
//! - **Enforced (Linux ≥ 5.13 with `CONFIG_SECURITY_LANDLOCK`, via
//!   [`quarantine_image_sandboxed`]):** before the decoder ever touches the
//!   untrusted bytes, [`sandbox::confine`] applies a Landlock ruleset to the
//!   calling thread with **no allow-rules**, so the thread loses the ability
//!   to open, create, or modify any filesystem path for the rest of its
//!   life. This is **best-effort defense-in-depth**: it is irreversible
//!   (once applied it cannot be lifted) and **thread-wide** (it binds the OS
//!   thread the decode runs on, not just the decode call —
//!   [`quarantine_image_sandboxed_on_worker`] pays that price on a dedicated
//!   short-lived worker thread so long-lived callers are never poisoned), and
//!   [`sandbox::SandboxStatus`] is always returned to the caller so a
//!   `Partial`/`Unsandboxed` result is visible rather than assumed away.
//!   **Observed, not just designed:** `cargo test -p postern-quarantine` has
//!   now actually run on a real Linux host — the Fly.io `postern-os-build`
//!   machine, kernel `6.12.91-fly` — and passed. The status that kernel
//!   reports is **`Unsandboxed`**: it was built without
//!   `CONFIG_SECURITY_LANDLOCK` (confirmed from that kernel's own build
//!   config and the absence of `/sys/kernel/security/landlock`), so
//!   `confine()` degrades there exactly as designed rather than enforcing
//!   anything. See `sandbox.rs` for the full detail. This one host's result
//!   does not demonstrate the `Enforced`/`Partial` branches — read "Enforced
//!   (Linux ≥ 5.13 with `CONFIG_SECURITY_LANDLOCK`)" above as the designed
//!   behavior on a Landlock-capable kernel, not as something this project
//!   has yet observed end-to-end.
//! - **NOT covered, even with `quarantine_image_sandboxed`:** the decode still
//!   runs **in-process, in the same address space** as the caller — Landlock
//!   restricts filesystem access, it does not isolate memory. There is **no
//!   seccomp filter yet** (syscalls other than filesystem access, e.g.
//!   networking primitives if any dependency ever tried one, are not
//!   restricted), and **no wall-clock timeout** on the decode itself. On
//!   **non-Linux targets Landlock does not exist at all** — the decode runs
//!   **fully unsandboxed**, and [`sandbox::confine`] reports that truthfully
//!   via `SandboxStatus::Unsandboxed` rather than staying silent about it.
//!   The image decoder remains the in-process attack surface: a memory-safety
//!   bug in a decoder would still execute during decode, on this host, before
//!   any neutralisation. The decoders are pure Rust (`image`), which removes
//!   the classic C-parser memory-unsafety class but not logic bugs or
//!   `unsafe` blocks in dependencies. Decompression-bomb DoS is bounded by the
//!   hard limits below.
//! - **SOTA target (deferred, tracked):** run the decode out-of-process — a
//!   short-lived subprocess with a wall-clock timeout, under the same
//!   Landlock/seccomp policy planned for the PDF path — so a decoder
//!   compromise is contained. Until that lands, do not describe the image path
//!   as "exploit-proof"; describe it as "output-sanitising with a
//!   memory-safe, resource-capped, Landlock-confined (Linux) in-process
//!   decoder".
//!
//! Other limits: the pixel/bitmap round-trip **destroys the text layer and
//! interactivity** (OCR to recover text is lossy); a sandbox reduces, not
//! eliminates, kernel-exploit risk. Optionally hygiene-`seal` the cleaned
//! output ("sanitised on a genuine Postern build").

use std::io::Cursor;

pub mod adapters;
pub mod dispatch;
pub mod office;
pub mod pdf;
#[cfg(feature = "render-hayro")]
pub mod render_hayro;
pub mod sandbox;

/// Hard cap on the encoded input size (a decode bomb is small; a legitimate
/// photo under this cap is essentially universal).
pub const MAX_INPUT_BYTES: usize = 64 * 1024 * 1024; // 64 MiB
/// Hard cap on decoded dimensions, each axis.
pub const MAX_DIMENSION: u32 = 16_384;
/// Hard cap on decoder allocations (bounds width × height × bytes-per-pixel
/// regardless of what the header claims — a ~1 KB file declaring enormous
/// dimensions is rejected instead of pinning memory).
pub const MAX_DECODE_ALLOC: u64 = 512 * 1024 * 1024; // 512 MiB

#[derive(Debug, thiserror::Error)]
pub enum QError {
    #[error("could not decode the image (unsupported or corrupt): {0}")]
    Decode(String),
    #[error("could not encode the clean image: {0}")]
    Encode(String),
    #[error("image exceeds quarantine limits (decode-bomb guard): {0}")]
    TooLarge(String),
    #[error("input matches no quarantine path (fail-closed, nothing was invoked): {0}")]
    UnknownMagic(String),
}

/// The actual pixel round-trip, shared by [`quarantine_image`] and
/// [`quarantine_image_sandboxed`]. Callers of this module should not call
/// this directly — go through one of the two public entry points so the
/// sandboxing (or its deliberate absence) is explicit at the call site.
fn decode_and_reencode(input: &[u8]) -> Result<Vec<u8>, QError> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(QError::TooLarge(format!(
            "input is {} bytes (cap {})",
            input.len(),
            MAX_INPUT_BYTES
        )));
    }
    let mut reader = image::ImageReader::new(Cursor::new(input))
        .with_guessed_format()
        .map_err(|e| QError::Decode(e.to_string()))?;
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(MAX_DIMENSION);
    limits.max_image_height = Some(MAX_DIMENSION);
    limits.max_alloc = Some(MAX_DECODE_ALLOC);
    reader.limits(limits);
    let img = reader.decode().map_err(|e| match e {
        image::ImageError::Limits(l) => QError::TooLarge(l.to_string()),
        other => QError::Decode(other.to_string()),
    })?;
    let mut out = Vec::new();
    img.write_to(&mut Cursor::new(&mut out), image::ImageFormat::Png)
        .map_err(|e| QError::Encode(e.to_string()))?;
    Ok(out)
}

/// Neutralise an untrusted image: decode it to raw pixels (dropping the file
/// container, all metadata, and any payload aimed at the recipient's viewer)
/// and re-encode a clean **PNG** from the pixels alone. The visible picture is
/// preserved; nothing else of the input survives *into the output*. Accepts any
/// input format the build supports (PNG/JPEG).
///
/// Resource limits (decode-bomb guard): input ≤ [`MAX_INPUT_BYTES`], dimensions
/// ≤ [`MAX_DIMENSION`] per axis, decoder allocations ≤ [`MAX_DECODE_ALLOC`].
/// Inputs beyond any limit are **rejected**, never downscaled.
///
/// NOTE: this entry point does **not** confine the decode — it runs with the
/// caller's full process/thread privileges. Prefer
/// [`quarantine_image_sandboxed`], which calls [`sandbox::confine`] before
/// decoding and hands back the [`sandbox::SandboxStatus`] so the caller can
/// record what was actually enforced. This function is kept as-is, unchanged,
/// for callers that already handle sandboxing themselves or that cannot
/// tolerate the irreversible, thread-wide effect of `confine()` (see the
/// module docs for the full honest threat model and the out-of-process SOTA
/// target).
pub fn quarantine_image(input: &[u8]) -> Result<Vec<u8>, QError> {
    decode_and_reencode(input)
}

/// Neutralise an untrusted image, first confining the calling thread with
/// [`sandbox::confine`]. Confinement is attempted **before** the decoder (or
/// even the format-guessing reader) is constructed, so the untrusted bytes
/// are never handed to a decoder that still has full filesystem access.
///
/// Returns both the pixel round-trip's result *and* the [`sandbox::SandboxStatus`]
/// that was actually achieved — the status is never swallowed. Callers MUST
/// inspect it (e.g. via [`sandbox::SandboxStatus::is_enforced`]) and record or
/// surface a `Partial`/`Unsandboxed` result rather than treating every call as
/// confined; on non-Linux targets this will always be `Unsandboxed`.
///
/// See the module docs for exactly what Landlock confinement here does and
/// does not cover (still in-process, no seccomp yet, no wall-clock timeout).
///
/// **Caller-thread footgun:** `confine()` irreversibly restricts *the thread
/// this function is called on* — after this returns on a Landlock-enforcing
/// kernel, the calling thread can never open a file again. That is correct
/// for a thread dedicated to decoding, but poison for e.g. a long-lived
/// server thread. Long-lived callers should prefer
/// [`quarantine_image_sandboxed_on_worker`], which pays the restriction on a
/// short-lived worker thread instead.
pub fn quarantine_image_sandboxed(input: &[u8]) -> (Result<Vec<u8>, QError>, sandbox::SandboxStatus) {
    let status = sandbox::confine();
    let result = decode_and_reencode(input);
    (result, status)
}

/// Like [`quarantine_image_sandboxed`], but the irreversible Landlock
/// restriction is paid by a dedicated, short-lived worker thread — never by
/// the caller. The worker calls [`sandbox::confine`] on itself, runs the
/// decode there (the untrusted bytes are only ever handed to the decoder on
/// the already-confined thread), and exits; the caller's own thread keeps
/// its full filesystem access.
///
/// Landlock restrictions bind a thread for its remaining lifetime and are
/// inherited by what that thread *subsequently* spawns — they do not reach
/// *backwards* to the thread that spawned the worker. So this is the safe
/// entry point for long-lived callers (servers, UI threads), at the cost of
/// one thread spawn per call.
///
/// The returned [`sandbox::SandboxStatus`] is the worker's own report and is
/// never swallowed — same contract as [`quarantine_image_sandboxed`]: callers
/// MUST inspect it and surface `Partial`/`Unsandboxed` truthfully. If the
/// worker thread panics, this returns a `Decode` error plus an `Unsandboxed`
/// status with a truthful reason (a panic before/at `confine()` means no
/// confinement claim can be made) rather than propagating the panic.
pub fn quarantine_image_sandboxed_on_worker(
    input: &[u8],
) -> (Result<Vec<u8>, QError>, sandbox::SandboxStatus) {
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("postern-quarantine-decode".to_string())
            .spawn_scoped(scope, || {
                let status = sandbox::confine();
                let result = decode_and_reencode(input);
                (result, status)
            })
            .map_or_else(
                |spawn_err| {
                    (
                        Err(QError::Decode(format!(
                            "could not spawn the sandboxed decode worker thread: {spawn_err}"
                        ))),
                        sandbox::SandboxStatus::Unsandboxed {
                            reason: format!(
                                "decode worker thread failed to spawn ({spawn_err}); \
                                 no confinement was attempted"
                            ),
                        },
                    )
                },
                |handle| {
                    handle.join().unwrap_or_else(|_| {
                        (
                            Err(QError::Decode(
                                "sandboxed decode worker thread panicked".to_string(),
                            )),
                            sandbox::SandboxStatus::Unsandboxed {
                                reason: "decode worker thread panicked; whether confine() \
                                         ran cannot be known, so no confinement is claimed"
                                    .to_string(),
                            },
                        )
                    })
                },
            )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{DynamicImage, ImageFormat, Rgb, RgbImage};

    /// A valid 3×2 JPEG with a malicious/EXIF APP1 segment spliced in after SOI.
    fn tainted_jpeg() -> Vec<u8> {
        let mut img = RgbImage::new(3, 2);
        for (i, px) in img.pixels_mut().enumerate() {
            *px = Rgb([(i * 40) as u8, 0, 255 - (i * 20) as u8]);
        }
        let mut jpeg = Vec::new();
        DynamicImage::ImageRgb8(img)
            .write_to(&mut Cursor::new(&mut jpeg), ImageFormat::Jpeg)
            .unwrap();
        // Splice an APP1 (EXIF) marker right after the SOI (0xFFD8).
        let mut tainted = vec![0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x08, b'E', b'x', b'i', b'f', 0x00, 0x00];
        tainted.extend_from_slice(&jpeg[2..]);
        tainted
    }

    #[test]
    fn quarantine_rebuilds_a_clean_png_dropping_everything_but_pixels() {
        let tainted = tainted_jpeg();
        assert!(tainted.windows(4).any(|w| w == b"Exif"), "input carries EXIF");

        let clean = quarantine_image(&tainted).unwrap();
        // Output is a PNG (format normalised) …
        assert_eq!(&clean[..8], &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
        // … with none of the injected metadata …
        assert!(!clean.windows(4).any(|w| w == b"Exif"), "EXIF gone");
        // … and the picture (dimensions) preserved.
        let re = image::load_from_memory(&clean).unwrap();
        assert_eq!((re.width(), re.height()), (3, 2));
    }

    #[test]
    fn corrupt_input_errors_not_panics() {
        assert!(matches!(quarantine_image(b"not an image"), Err(QError::Decode(_))));
    }

    /// Bitwise CRC-32 (IEEE) — only for building a well-formed test PNG.
    fn crc32(data: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for &b in data {
            crc ^= b as u32;
            for _ in 0..8 {
                crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
            }
        }
        !crc
    }

    #[test]
    fn decode_bomb_is_rejected_not_decoded() {
        // A tiny, well-formed PNG whose IHDR declares 100000×100000 (8-bit RGB
        // ≈ 30 GB raster). Without limits this pins memory; with the quarantine
        // limits it must be rejected fast.
        let mut png = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(b"IHDR");
        ihdr.extend_from_slice(&100_000u32.to_be_bytes()); // width
        ihdr.extend_from_slice(&100_000u32.to_be_bytes()); // height
        ihdr.extend_from_slice(&[8, 2, 0, 0, 0]); // bit depth 8, RGB
        png.extend_from_slice(&13u32.to_be_bytes());
        png.extend_from_slice(&ihdr);
        png.extend_from_slice(&crc32(&ihdr).to_be_bytes());
        // (No IDAT needed — the dimension check must fire on the header.)
        let start = std::time::Instant::now();
        let res = quarantine_image(&png);
        assert!(matches!(res, Err(QError::TooLarge(_))), "bomb rejected: {res:?}");
        assert!(start.elapsed().as_secs() < 5, "rejection is immediate, not after decode");
    }

    #[test]
    fn oversized_input_bytes_are_rejected() {
        let huge = vec![0u8; MAX_INPUT_BYTES + 1];
        assert!(matches!(quarantine_image(&huge), Err(QError::TooLarge(_))));
    }

    #[test]
    fn sandboxed_variant_confines_before_decoding_and_never_swallows_status() {
        let tainted = tainted_jpeg();
        assert!(tainted.windows(4).any(|w| w == b"Exif"), "input carries EXIF");

        let (result, status) = quarantine_image_sandboxed(&tainted);
        // The pixel round-trip result must match the unsandboxed path bit for
        // bit — confine() must not change what gets decoded.
        let clean = result.expect("sandboxed decode should still succeed");
        assert_eq!(&clean[..8], &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
        // … and none of the injected metadata survives the sandboxed path
        // either — confine() must not change *what* gets decoded/re-encoded.
        assert!(!clean.windows(4).any(|w| w == b"Exif"), "EXIF gone from sandboxed output too");

        // The status is a real SandboxStatus, not a placeholder — on Linux
        // it's Enforced/Partial/Unsandboxed depending on kernel support; on
        // every other target it's always Unsandboxed with a truthful reason.
        match &status {
            sandbox::SandboxStatus::Unsandboxed { reason } => assert!(!reason.is_empty()),
            sandbox::SandboxStatus::Enforced { abi } | sandbox::SandboxStatus::Partial { abi, .. } => {
                assert!(!abi.is_empty())
            }
        }
        let _ = status.is_enforced(); // must be callable — never swallowed by the API

        // On this host (macOS/Windows/any non-Linux CI runner) the status
        // must never be falsely reported as Enforced or Partial — Landlock
        // does not exist here, so a true claim of confinement would be a lie.
        #[cfg(not(target_os = "linux"))]
        {
            assert!(
                matches!(status, sandbox::SandboxStatus::Unsandboxed { .. }),
                "non-Linux host must never report Enforced/Partial confinement, got {status:?}"
            );
        }
    }

    /// The worker variant must (a) produce the same clean output as the
    /// other entry points and (b) NEVER leave the *calling* thread
    /// restricted — the whole point of paying the irreversible Landlock
    /// restriction on a short-lived worker instead.
    ///
    /// HONESTY CAVEAT on (b): the post-call `File::open` below is a real
    /// caller-poisoning probe only on a Landlock-enforcing kernel, where a
    /// leaked restriction would actually make it fail with
    /// PermissionDenied. On this macOS dev host (and on Linux kernels
    /// without `CONFIG_SECURITY_LANDLOCK`, e.g. the Fly `postern-os-build`
    /// machine) `confine()` is a no-op/`Unsandboxed`, so the open succeeds
    /// trivially and this asserts only the API contract, not enforcement.
    /// See `sandbox.rs` and the crate README for the exact host required to
    /// observe the enforcing branch.
    #[test]
    fn worker_variant_cleans_the_image_and_never_poisons_the_calling_thread() {
        let tainted = tainted_jpeg();

        let (result, status) = quarantine_image_sandboxed_on_worker(&tainted);
        let clean = result.expect("worker-sandboxed decode should still succeed");
        assert_eq!(&clean[..8], &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
        assert!(!clean.windows(4).any(|w| w == b"Exif"), "EXIF gone from worker output too");
        match &status {
            sandbox::SandboxStatus::Unsandboxed { reason } => assert!(!reason.is_empty()),
            sandbox::SandboxStatus::Enforced { abi }
            | sandbox::SandboxStatus::Partial { abi, .. } => assert!(!abi.is_empty()),
        }

        // (b): the CALLING thread must still have filesystem access after
        // the call — the restriction must have died with the worker. On an
        // enforcing kernel a leaked restriction fails this with
        // PermissionDenied; elsewhere it passes trivially (see doc caveat).
        let self_probe =
            std::fs::File::open(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));
        assert!(
            self_probe.is_ok(),
            "calling thread lost filesystem access after \
             quarantine_image_sandboxed_on_worker — the worker's Landlock \
             restriction leaked to the caller: {self_probe:?}"
        );
    }
}
