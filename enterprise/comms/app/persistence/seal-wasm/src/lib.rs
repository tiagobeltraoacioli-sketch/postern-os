// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
//! Bloch comms — REAL in-process seal binding (WASM). **Business/Enterprise
//! edition only.** Pre-release and **UNAUDITED**.
//!
//! This is the honest at-rest seal for `../sealed-store.mjs`: a WebAssembly
//! module that the JS store instantiates **in-process** and calls to seal/open
//! its session/message store with the ONE canonical Postern seal
//! ([`postern_core::aead`] — XChaCha20-Poly1305, versioned, **key-committing**,
//! context-bound). It defines **no** cryptography of its own.
//!
//! Why WASM and not a spawned CLI: the 32-byte store key **never crosses a
//! process boundary**. The JS loader writes the key into this module's linear
//! memory, calls [`postern_seal`]/[`postern_open`], and reads the result back —
//! all inside the Node process. (The SHIELD container's `real-seal-engine.mjs`
//! spawns a subprocess and *documents* that a production build would move to
//! in-process FFI/WASM; this binding is that in-process form.)
//!
//! ## Randomness
//!
//! `wasm32-unknown-unknown` has no OS RNG, so [`postern_core::aead::seal`]'s
//! `OsRng` nonce draw would fail. We register a **custom getrandom** that calls
//! an imported host function `postern_seal::host_getrandom`, which the JS loader
//! backs with Node's `crypto.randomFillSync` (a CSPRNG). The seal nonce is thus
//! drawn from the host CSPRNG, in-process.
//!
//! ## ABI (kept trivial; the JS loader owns all (de)allocation)
//!
//! - [`postern_alloc`] / [`postern_dealloc`] — byte buffers, `align = 1`. Every
//!   buffer the loader touches (inputs AND the returned output) is allocated
//!   and freed through this exact pair, so the size passed to free always
//!   matches the size used to allocate.
//! - [`postern_seal`] / [`postern_open`] return a packed `u64` =
//!   `(ptr as u32) << 32 | (len as u32)` pointing at a freshly-allocated output
//!   buffer, or **`0`** on failure (wrong key / wrong context / tamper / bad
//!   length). `0` is unambiguous: a real seal output is never empty and a
//!   success buffer is allocated with a non-null pointer.

use std::alloc::{alloc, dealloc, Layout};
use std::slice;

/// Context string binding Bloch persistence blobs to this product/format — the
/// SAME bytes as `seal-rs`'s `STORE_CONTEXT` and the JS store's `STORE_CONTEXT`.
/// A blob sealed by another Postern product under the same 32-byte key can NOT
/// be opened as a Bloch store. Passed in from JS on every call (below) so the
/// three implementations can never drift; kept here only for documentation.
pub const STORE_CONTEXT_DOC: &[u8] = b"bloch-comms/persistence/v1";

// ── host-provided randomness ────────────────────────────────────────────────
// On wasm32-unknown-unknown getrandom has no backend. Import one from the host
// (module name must match the JS import object key) and register it globally.
#[link(wasm_import_module = "postern_seal")]
extern "C" {
    /// Fill `len` bytes at `ptr` with CSPRNG output. Provided by the JS loader
    /// (Node `crypto.randomFillSync`). Never returns partial/predictable bytes.
    fn host_getrandom(ptr: *mut u8, len: usize);
}

fn wasm_getrandom(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    // SAFETY: `buf` is a valid, uniquely-borrowed slice for `buf.len()` bytes.
    unsafe { host_getrandom(buf.as_mut_ptr(), buf.len()) };
    Ok(())
}
getrandom::register_custom_getrandom!(wasm_getrandom);

// ── linear-memory allocation (owned by the JS loader) ───────────────────────

/// Allocate `len` bytes (`align = 1`) and return the pointer. A zero-length
/// request returns a non-null dangling pointer (never dereferenced).
#[no_mangle]
pub extern "C" fn postern_alloc(len: usize) -> *mut u8 {
    if len == 0 {
        return 1 as *mut u8;
    }
    // SAFETY: len > 0, align = 1 is always valid.
    unsafe { alloc(Layout::from_size_align_unchecked(len, 1)) }
}

/// Free a buffer previously returned by [`postern_alloc`] (or by a seal/open
/// output). `len` MUST equal the length it was allocated with.
#[no_mangle]
pub extern "C" fn postern_dealloc(ptr: *mut u8, len: usize) {
    if len == 0 || ptr.is_null() {
        return;
    }
    // SAFETY: ptr came from postern_alloc(len) with the same Layout.
    unsafe { dealloc(ptr, Layout::from_size_align_unchecked(len, 1)) };
}

/// Pack a (ptr, len) pair into the u64 the JS loader unpacks. `0` is reserved
/// for "failure" and is never produced for a successful, non-empty output.
fn pack(ptr: *const u8, len: usize) -> u64 {
    ((ptr as u32 as u64) << 32) | (len as u32 as u64)
}

/// Copy `data` into a fresh [`postern_alloc`] buffer and return the packed
/// handle, so the JS loader frees it with the matching [`postern_dealloc`].
fn ret_bytes(data: &[u8]) -> u64 {
    let len = data.len();
    let ptr = postern_alloc(len);
    if len > 0 {
        // SAFETY: ptr owns `len` freshly-allocated bytes; src is valid for len.
        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), ptr, len) };
    }
    pack(ptr, len)
}

fn read32(ptr: *const u8, len: usize) -> Option<[u8; 32]> {
    if len != 32 || ptr.is_null() {
        return None;
    }
    // SAFETY: caller guarantees `ptr` is valid for 32 bytes.
    let s = unsafe { slice::from_raw_parts(ptr, 32) };
    let mut k = [0u8; 32];
    k.copy_from_slice(s);
    Some(k)
}

// ── the seal, delegated to postern-core ─────────────────────────────────────

/// Seal `plaintext` under the 32-byte `key`, bound to `context`, with the
/// canonical Postern v2 seal. Returns a packed handle to
/// `0x02 ‖ nonce ‖ commit ‖ ciphertext`, or `0` on failure (bad key length or
/// a seal error).
#[no_mangle]
pub extern "C" fn postern_seal(
    key_ptr: *const u8,
    key_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    pt_ptr: *const u8,
    pt_len: usize,
) -> u64 {
    let key = match read32(key_ptr, key_len) {
        Some(k) => k,
        None => return 0,
    };
    // SAFETY: the JS loader passes valid ptr/len for context and plaintext.
    let ctx = unsafe { slice::from_raw_parts(ctx_ptr, ctx_len) };
    let pt = unsafe { slice::from_raw_parts(pt_ptr, pt_len) };
    match postern_core::aead::seal_with_context(&key, ctx, pt) {
        Ok(out) => ret_bytes(&out),
        Err(_) => 0,
    }
}

/// Open a blob sealed by [`postern_seal`] under the same `key` and `context`.
/// FAIL-CLOSED: a wrong key, wrong context, or tampered/corrupt blob returns
/// `0` (no plaintext). Returns a packed handle to the plaintext on success.
#[no_mangle]
pub extern "C" fn postern_open(
    key_ptr: *const u8,
    key_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    sealed_ptr: *const u8,
    sealed_len: usize,
) -> u64 {
    let key = match read32(key_ptr, key_len) {
        Some(k) => k,
        None => return 0,
    };
    // SAFETY: the JS loader passes valid ptr/len for context and sealed blob.
    let ctx = unsafe { slice::from_raw_parts(ctx_ptr, ctx_len) };
    let sealed = unsafe { slice::from_raw_parts(sealed_ptr, sealed_len) };
    match postern_core::aead::open_with_context(&key, ctx, sealed) {
        Ok(pt) => ret_bytes(&pt),
        Err(_) => 0,
    }
}
