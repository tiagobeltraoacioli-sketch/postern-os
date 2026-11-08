// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// postern-shield-seal-wasm — IN-PROCESS seal adapter for the SHIELD work-container.
//
// STATUS: reference prototype — UNAUDITED, pre-production.
//
// WHAT THIS IS
// ------------
// The container (src/shield-container.mjs) seals its corporate data at rest
// through an INJECTED seal engine with three ops:
//
//     deriveKey(secretBytes, salt) -> key32   (Argon2id, per postern-vault)
//     seal(key32, plaintextBytes)  -> sealedBytes
//     open(key32, sealedBytes)     -> plaintextBytes   (throws on wrong key / tamper)
//
// This is the SAME real implementation as the `../seal/` CLI adapter, but built
// as a WebAssembly module so src/real-seal-engine.mjs can call it IN-PROCESS:
// the 32-byte key is written into THIS module's linear memory (the same address
// space as the Node process) and never crosses a process boundary / pipe. It
// defines NO crypto of its own: every op delegates to the ONE canonical Postern
// seal in `postern_core` — XChaCha20-Poly1305 (v2, versioned, key-committing,
// context-bound) with the 32-byte key from Argon2id at the at-rest tier.
//
// HONEST LIMITS (unchanged by moving the seal in-process)
// -------------------------------------------------------
//  * The seal is real, but the CONTAINER around it is still containment BY
//    CONSTRUCTION (userland), NOT a kernel boundary. A rooted / jailbroken phone,
//    a debugger, or a RAM capture defeats it. Keeping the key in-process removes
//    ONE prototype smell (the pipe); it does not add a hardware boundary.
//  * "In-process" here means the Node process's own address space (wasm linear
//    memory). That is strictly better than a spawned CLI (no key on a pipe, no
//    argv/stdout exposure) but it is NOT a TEE/enclave. A production build would
//    additionally isolate the key in an enclave / secure element.
//  * This module only transforms bytes the corporate container hands it. It has
//    no syscalls, no filesystem, no network — it CANNOT reach the personal side.
//
// C-ABI over linear memory (no wasm-bindgen)
// ------------------------------------------
//   sh_alloc(len) -> ptr                     host allocates an input region
//   sh_free(ptr, len)                        host frees a region
//   sh_derive_key(sPtr,sLen, saltPtr,saltLen) -> u64 packed (ptr<<32 | len)
//   sh_seal(kPtr,kLen, ptPtr,ptLen)           -> u64 packed
//   sh_open(kPtr,kLen, sPtr,sLen)             -> u64 packed
//   sh_context() -> u64 packed                the SHIELD context string
//   sh_last_status() -> i32                   0 ok · 2 usage · 3 open-fail · 4 kdf/other
// A packed value of 0 means "error" — read sh_last_status() for the code. On
// success the host copies `len` bytes from `ptr`, then calls sh_free(ptr, len).
//
// Randomness: `sh_host_random(ptr, len)` is IMPORTED from the host ("env"
// module). Node fills it from node:crypto randomFillSync (the OS CSPRNG), so the
// AEAD nonce is OS-random even though wasm has no ambient RNG.

use core::slice;
use zeroize::Zeroize;

// Domain/context string binding blobs to the SHIELD container. MUST match the
// `../seal/` CLI adapter's SHIELD_CONTEXT byte-for-byte so a blob sealed by one
// path opens through the other. A blob sealed here under a given 32-byte key can
// NOT be opened as a vault, a courier message, or any other Postern product,
// even under the same key — and vice versa.
const SHIELD_CONTEXT: &[u8] = b"postern-shield/container/v1";

// Status of the most recent op. Wasm is single-threaded here, so a plain static
// is sound (all access is on the one Node thread that owns this instance).
static mut LAST_STATUS: i32 = 0;

const STATUS_OK: i32 = 0;
const STATUS_USAGE: i32 = 2;
const STATUS_OPEN_FAIL: i32 = 3;
const STATUS_OTHER: i32 = 4;

// ── host-provided randomness ────────────────────────────────────────────────
// Imported from the "env" module (the default for a wasm `extern "C"` block).
extern "C" {
    fn sh_host_random(ptr: *mut u8, len: usize);
}

fn custom_getrandom(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    // Safety: the host writes exactly `len` bytes into `[ptr, ptr+len)`, which is
    // the caller's live buffer. No aliasing: `buf` is exclusively borrowed here.
    unsafe { sh_host_random(buf.as_mut_ptr(), buf.len()) };
    Ok(())
}
getrandom::register_custom_getrandom!(custom_getrandom);

// ── linear-memory allocation (host <-> wasm handoff) ─────────────────────────

/// Allocate `len` zeroed bytes in wasm memory and return the pointer. The host
/// writes its operand there, then passes the pointer to an op. Paired with
/// [`sh_free`].
#[no_mangle]
pub extern "C" fn sh_alloc(len: u32) -> u32 {
    let mut buf = vec![0u8; len as usize];
    let ptr = buf.as_mut_ptr() as u32;
    core::mem::forget(buf);
    ptr
}

/// Free a region previously returned by [`sh_alloc`] or by an op's packed
/// pointer. `len` MUST be the exact length the region was created with.
#[no_mangle]
pub extern "C" fn sh_free(ptr: u32, len: u32) {
    if ptr == 0 {
        return;
    }
    // Safety: reconstruct the exact Vec (ptr,len,cap) we leaked, then drop it.
    unsafe {
        let _ = Vec::from_raw_parts(ptr as *mut u8, len as usize, len as usize);
    }
}

/// Status code of the most recent op (see the module header).
#[no_mangle]
pub extern "C" fn sh_last_status() -> i32 {
    unsafe { LAST_STATUS }
}

// ── ops ──────────────────────────────────────────────────────────────────────

/// Argon2id (at-rest tier) via `postern_core::kdf`. Returns packed(ptr,len) of a
/// 32-byte key, or 0 with status set.
#[no_mangle]
pub extern "C" fn sh_derive_key(s_ptr: u32, s_len: u32, salt_ptr: u32, salt_len: u32) -> u64 {
    let secret = borrow(s_ptr, s_len);
    let salt = borrow(salt_ptr, salt_len);
    match postern_core::kdf::derive_key(secret, salt) {
        // `k` derefs to [u8; 32]; copy into an owned Vec and hand it back. The
        // Zeroizing source wipes on drop at end of scope.
        Ok(k) => ret_ok(k[..].to_vec()),
        Err(_) => ret_err(STATUS_OTHER),
    }
}

/// XChaCha20-Poly1305 seal (v2, key-committing, context-bound) via
/// `postern_core::aead`. Returns packed(ptr,len) of the sealed blob, or 0.
#[no_mangle]
pub extern "C" fn sh_seal(k_ptr: u32, k_len: u32, pt_ptr: u32, pt_len: u32) -> u64 {
    let mut key = match key32(k_ptr, k_len) {
        Ok(k) => k,
        Err(code) => return ret_err(code),
    };
    let pt = borrow(pt_ptr, pt_len);
    let out = postern_core::aead::seal_with_context(&key, SHIELD_CONTEXT, pt);
    key.zeroize();
    match out {
        Ok(sealed) => ret_ok(sealed),
        Err(_) => ret_err(STATUS_OTHER),
    }
}

/// Open a v2 sealed blob. Wrong key / wrong context / tamper / corrupt -> 0 with
/// status = 3 (mirrors the CLI adapter's exit-3), so the JS engine maps it to a
/// thrown open() — the "revoke => key gone => unreadable" path.
#[no_mangle]
pub extern "C" fn sh_open(k_ptr: u32, k_len: u32, s_ptr: u32, s_len: u32) -> u64 {
    let mut key = match key32(k_ptr, k_len) {
        Ok(k) => k,
        Err(code) => return ret_err(code),
    };
    let sealed = borrow(s_ptr, s_len);
    let out = postern_core::aead::open_with_context(&key, SHIELD_CONTEXT, sealed);
    key.zeroize();
    match out {
        Ok(pt) => ret_ok(pt),
        Err(_) => ret_err(STATUS_OPEN_FAIL),
    }
}

/// The SHIELD context string, so the host can assert parity with the CLI adapter.
#[no_mangle]
pub extern "C" fn sh_context() -> u64 {
    ret_ok(SHIELD_CONTEXT.to_vec())
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Borrow a host-provided region as a slice for the duration of one call.
/// Safety: the host guarantees `[ptr, ptr+len)` is a live region it wrote and
/// does not mutate for the duration of the call.
fn borrow<'a>(ptr: u32, len: u32) -> &'a [u8] {
    if len == 0 {
        return &[];
    }
    unsafe { slice::from_raw_parts(ptr as *const u8, len as usize) }
}

/// Copy out a 32-byte key from a host region, or set a usage status.
fn key32(ptr: u32, len: u32) -> Result<[u8; 32], i32> {
    if len != 32 {
        return Err(STATUS_USAGE);
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(borrow(ptr, len));
    Ok(k)
}

/// Leak `bytes` into wasm memory and return packed(ptr,len); set status OK.
fn ret_ok(bytes: Vec<u8>) -> u64 {
    unsafe { LAST_STATUS = STATUS_OK };
    let len = bytes.len() as u64;
    let mut b = bytes;
    let ptr = b.as_mut_ptr() as u64;
    core::mem::forget(b);
    // An empty result still returns a non-zero (dangling-but-aligned) pointer,
    // so packed != 0. Only errors return 0.
    (ptr << 32) | len
}

/// Set the error status and return the sentinel 0.
fn ret_err(code: i32) -> u64 {
    unsafe { LAST_STATUS = code };
    0
}
