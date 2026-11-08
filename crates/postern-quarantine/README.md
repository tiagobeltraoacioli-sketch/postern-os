# postern-quarantine

Inbound-document safety: neutralise untrusted images by decoding them to raw
pixels and re-encoding a clean PNG, optionally with the decode thread confined
by the Linux **Landlock** LSM before it ever touches the untrusted bytes.
The mirror of `postern-hygiene` (hygiene protects what you *send*; quarantine
protects what you *receive*). MIT OR Apache-2.0; all dependencies permissive
(`image`, `thiserror`, `rust-landlock`; optional `hayro` behind the
default-OFF `render-hayro` feature — `Apache-2.0 OR MIT`, and its whole
dependency tree re-verified permissive at adoption). LibreOffice (MPL) is
never a dependency: the converter adapter only spawns a user-installed
`soffice` binary, unmodified — aggregation, not linkage.

See `src/lib.rs` for the full, honest threat model (what the pixel round-trip
covers, what it does not, no seccomp yet, decode still in-process).

**PDF / Office path status:** the rebuild half is implemented (`src/pdf.rs` —
pure-Rust flat-PDF emitter from page rasters, no `/Info`, no trailer `/ID`, no
`/Metadata`/`/Names`/`/OpenAction`/`/JavaScript`/`/EmbeddedFiles`, tested),
the office pipeline is implemented (`src/office.rs` — magic-byte sniffer for
OOXML/ZIP and legacy OLE2/CFB containers, fail-closed size cap,
converter-output `%PDF-` verification, then delegation to the same flat
rebuild; cargo-tested with closure fakes), and **both adapters now ship**:

- **Converter adapter** (`src/adapters.rs`): spawns **unmodified LibreOffice
  headless** (`soffice --headless --convert-to pdf`) out-of-process — MPL,
  aggregation-only per `deny.toml`: a user-installed external binary,
  spawned via `std::process`, never linked, never forked. Fresh throwaway
  `-env:UserInstallation` profile per run, wall-clock timeout with
  kill-on-expiry, output-size cap checked before the output is read,
  fail-closed error mapping. Stub-driven offline tests cover the good path
  and every bad path (garbage output, nonzero exit, hang-past-timeout,
  oversized output, missing output/executable); a `#[ignore]`-gated live
  test drives a real LibreOffice where one is installed.
- **Renderer adapter** (`src/render_hayro.rs`, cargo feature `render-hayro`,
  **default OFF**): a ready `render` closure built on
  [`hayro`](https://github.com/LaurenzV/hayro) — a pure-Rust PDF rasterizer,
  `Apache-2.0 OR MIT` (license re-verified on crates.io at adoption,
  2026-07-16). Runs **in-process**: the same attack-surface register as the
  image path, stated plainly in its module docs. Page-count and
  raster-dimension caps enforced fail-closed; render panics caught and
  mapped to errors. Tested offline against crate-emitted flat PDFs.
- **Dispatcher** (`src/dispatch.rs`): `quarantine_bytes` magic-sniffs
  PNG/JPEG/`%PDF-`/OOXML-ZIP/OLE2 and routes to the right path,
  hard-erroring on unknown magic before any tool or closure runs. Runnable
  end to end: `cargo run -p postern-quarantine --features render-hayro
  --example quarantine_file -- <input>`.

The injected-closure seams on `pdf::quarantine_pdf` /
`office::quarantine_office` are unchanged — the adapters are ready-made
things to inject, not a bypass. **Still absent, stated plainly:** any
Landlock/seccomp containment around the converter subprocess (its only
bounds are the wall-clock kill, the output cap, and the fail-closed magic
checks), any OS-level sandbox on macOS/Windows, and out-of-process
rendering. The PDF and Office paths are **not** "exploit-proof" and not
complete.

## Entry points

| Function | Confinement | Who pays the irreversible restriction |
| --- | --- | --- |
| `quarantine_image` | none (explicitly) | nobody — caller handles sandboxing itself |
| `quarantine_image_sandboxed` | Landlock, before decode | **the calling thread, forever** — only for threads dedicated to decoding |
| `quarantine_image_sandboxed_on_worker` | Landlock, before decode | a short-lived worker thread; the caller is never poisoned |

All sandboxed variants return the achieved `sandbox::SandboxStatus`
(`Enforced` / `Partial` / `Unsandboxed { reason }`) — never a silent claim.
`SandboxStatus::is_enforced()` is true **only** for `Enforced`.

## EXACT host requirement for real Landlock enforcement

Landlock confinement is only enforced on a host where **all** of the
following hold:

1. **Linux** (Landlock is a Linux-only LSM; macOS/Windows always report
   `Unsandboxed`, truthfully).
2. **Kernel ≥ 5.13** (first kernel with Landlock; newer kernels enforce more
   access rights — this crate requests `ABI::V7` and lets `rust-landlock`'s
   best-effort layer negotiate down, so 5.13+ gives at least `Partial`).
3. The kernel was **built with `CONFIG_SECURITY_LANDLOCK=y`**.
4. `landlock` is in the **active LSM list at boot** (in `CONFIG_LSM` or the
   `lsm=` kernel command line).

How to check a host:

```sh
grep CONFIG_SECURITY_LANDLOCK "/boot/config-$(uname -r)"   # want: =y
cat /sys/kernel/security/lsm                                # want: ...,landlock,...
cargo run -p postern-quarantine --example confine_probe     # prints the observed truth
```

## Honest status of verification (as of 2026-07)

- `cargo test -p postern-quarantine` **passes on macOS** (non-Linux fallback
  paths) and the Linux-gated code **compile-checks** via
  `cargo check -p postern-quarantine --all-targets --target x86_64-unknown-linux-gnu`.
- The full suite **has run on one real Linux host**: the Fly.io
  `postern-os-build` machine, kernel `6.12.91-fly`. That kernel is built
  **without** `CONFIG_SECURITY_LANDLOCK` (confirmed from its
  `/boot/config-6.12.91-fly` and the absence of
  `/sys/kernel/security/landlock`), so the observed status there is
  `Unsandboxed` — the graceful-degradation branch is verified end-to-end;
  the `Enforced`/`Partial` branches are **not yet observed** anywhere.
- **BLOCKED until a Landlock-capable host is available:** running
  `cargo test -p postern-quarantine` on a kernel meeting the requirement
  above. The test
  `sandbox::tests::confine_actually_denies_filesystem_access_when_enforced`
  is the behavioral proof waiting for that host: it spawns a fresh thread,
  calls `confine()` there, then performs a **real** post-confine
  `File::open("/etc/hostname")` (ReadFile) and `File::create` in the temp dir
  (WriteFile/MakeReg) on that same thread. On an `Enforced`/`Partial` status
  it asserts **both fail with `PermissionDenied`** — i.e. the kernel actually
  denied filesystem access, not merely that `confine()` returned a
  plausible-looking enum. On `Unsandboxed` it asserts the opposite (both
  succeed), which is what makes the denial assertions meaningful rather than
  confusable with an unrelated environment failure. A pass of that test on a
  Landlock-capable kernel is what would upgrade "Enforced" from *designed*
  to *observed*. Do not claim enforcement before that run exists.

Stock kernels of mainstream distros (Debian 12+, Ubuntu 22.04+, Fedora,
Arch) ship `CONFIG_SECURITY_LANDLOCK=y` with landlock active — any such VM
or bare-metal box qualifies; the Fly `postern-os-build` builder does not.
