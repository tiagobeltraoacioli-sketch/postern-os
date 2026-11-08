// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Bloch — comms persistence: REAL seal loader (in-process WASM). Business/Enterprise ONLY.
//
// STATUS: reference prototype — UNAUDITED, pre-production. ADDITIVE.
//
// WHAT THIS IS
// ------------
// The honest at-rest seal for `sealed-store.mjs`. It instantiates the WASM
// module built from `seal-wasm/` (Rust) IN-PROCESS and exposes a sealer with the
// exact shape the store expects:
//
//     { label, seal(key,ctx,pt)->Promise<Uint8Array>, open(key,ctx,blob)->Promise<Uint8Array> }
//
// Every op delegates to the ONE canonical Postern seal (postern_core::aead —
// XChaCha20-Poly1305, versioned, key-committing, context-bound). NO cryptography
// is implemented here or in the WASM; both are thin bindings.
//
// WHY IN-PROCESS (no process-boundary key crossing)
// -------------------------------------------------
// The 32-byte store key is written into the module's linear memory and read back
// out entirely inside this Node process — it never crosses a process boundary
// (contrast the SHIELD container's prototype CLI adapter, which spawns a
// subprocess). The seal's fresh nonce is drawn from Node's `crypto.randomFillSync`
// (a CSPRNG) via the single imported `host_getrandom`.
//
// HONEST LIMITS
// -------------
//  * The SEAL is real and audited-primitive-backed; it does NOT make Bloch
//    "fully private" (metadata stays org-visible; employer-run tool) and the
//    at-rest bytes are only as safe as this device (a rooted OS, a debugger on
//    this process, or a RAM capture defeats any userland seal).
//  * This module is a Node loader (uses node:fs / node:crypto). In a browser the
//    store's WebCrypto reference sealer is the standalone path; a browser
//    deployment would load this same WASM via fetch + WebCrypto.getRandomValues.

import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { randomFillSync } from "node:crypto";

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * Locate the compiled WASM artifact (release preferred over debug), relative to
 * this module: seal-wasm/target/wasm32-unknown-unknown/{release,debug}/...
 * @returns {string|null} an existing path, or null if the module is not built.
 */
export function defaultWasmPath() {
  const base = join(__dirname, "seal-wasm", "target", "wasm32-unknown-unknown");
  const candidates = [
    join(base, "release", "bloch_comms_seal_wasm.wasm"),
    join(base, "debug", "bloch_comms_seal_wasm.wasm"),
  ];
  for (const p of candidates) if (existsSync(p)) return p;
  return null;
}

/**
 * Is a usable real-seal WASM artifact available? A deployment/test can branch on
 * this to decide between the real seal and the reference fallback.
 * @param {string} [path]
 * @returns {boolean}
 */
export function realSealAvailable(path = defaultWasmPath()) {
  return typeof path === "string" && existsSync(path);
}

/** Human-readable label for the real, audited-primitive-backed seal. */
export const REAL_SEAL_LABEL =
  "REAL postern-core seal (XChaCha20-Poly1305, key-committing, context-bound) — in-process WASM";

/**
 * Load and instantiate the WASM binding, returning a `{ label, seal, open }`
 * sealer. Synchronous instantiation (the module is tiny); the returned
 * seal/open are async only to match the store's sealer contract (real seals —
 * WASM/HSM — may be async elsewhere).
 *
 * FAIL-CLOSED: if the artifact is missing or fails to instantiate, this THROWS
 * — it never silently degrades to a non-audited seal. The caller (the store's
 * default-sealer resolver) decides whether to fall back to the reference sealer.
 *
 * @param {object} [opts]
 * @param {string} [opts.path] path to the .wasm (defaults to defaultWasmPath()).
 * @returns {{ label: string, seal: Function, open: Function }}
 */
export function loadRealSealer(opts = {}) {
  const path = opts.path || defaultWasmPath();
  if (!path || !existsSync(path)) {
    throw new Error(
      "postern-seal-wasm: WASM artifact not found. Build it with " +
        "`./build-wasm.sh` (or `cargo build --release --target wasm32-unknown-unknown` " +
        "in persistence/seal-wasm/). This loader never falls back to a non-audited seal.",
    );
  }

  const bytes = readFileSync(path);
  const module = new WebAssembly.Module(bytes);
  const instance = new WebAssembly.Instance(module, {
    // The one host import: fill wasm memory with CSPRNG bytes for the seal nonce.
    postern_seal: {
      host_getrandom(ptr, len) {
        const view = new Uint8Array(instance.exports.memory.buffer, ptr, len);
        randomFillSync(view);
      },
    },
  });

  const ex = instance.exports;
  const { memory, postern_alloc, postern_dealloc, postern_seal, postern_open } = ex;

  // Copy `bytes` into wasm memory; return the pointer (caller frees it).
  function into(u8) {
    const len = u8.length;
    const ptr = postern_alloc(len);
    if (len > 0) new Uint8Array(memory.buffer, ptr, len).set(u8);
    return { ptr, len };
  }
  // Unpack the u64 handle (BigInt) into { ptr, len }. 0n => failure.
  function unpack(handle) {
    const h = BigInt.asUintN(64, handle);
    return { ptr: Number(h >> 32n), len: Number(h & 0xffffffffn), ok: h !== 0n };
  }
  // Read `len` bytes at `ptr` into a fresh Uint8Array (copy out of wasm memory).
  function out(ptr, len) {
    return len === 0 ? new Uint8Array(0) : new Uint8Array(memory.buffer, ptr, len).slice();
  }

  function call(fn, key, context, data) {
    if (!(key instanceof Uint8Array) || key.length !== 32) {
      throw new Error("postern-seal-wasm: store key must be a 32-byte Uint8Array");
    }
    const ctxBytes = context instanceof Uint8Array ? context : new TextEncoder().encode(String(context));
    const dataBytes = data instanceof Uint8Array ? data : new Uint8Array(data);
    const k = into(key);
    const c = into(ctxBytes);
    const d = into(dataBytes);
    try {
      const { ptr, len, ok } = unpack(fn(k.ptr, k.len, c.ptr, c.len, d.ptr, d.len));
      if (!ok) return null; // fail-closed: caller maps to a thrown SealError
      const result = out(ptr, len);
      postern_dealloc(ptr, len);
      return result;
    } finally {
      // Wipe the key bytes we copied into wasm memory, then free every input.
      new Uint8Array(memory.buffer, k.ptr, k.len).fill(0);
      postern_dealloc(k.ptr, k.len);
      postern_dealloc(c.ptr, c.len);
      postern_dealloc(d.ptr, d.len);
    }
  }

  return {
    label: REAL_SEAL_LABEL,
    __real: true,
    async seal(key, context, plaintext) {
      const r = call(postern_seal, key, context, plaintext);
      if (r === null) throw new Error("postern-seal-wasm: seal failed");
      return r;
    },
    async open(key, context, sealed) {
      const r = call(postern_open, key, context, sealed);
      if (r === null) {
        // Wrong key, wrong context, or tampered/corrupt blob -> no plaintext.
        throw new Error("open failed — wrong key, wrong context, or tampered data");
      }
      return r;
    },
  };
}

export default { loadRealSealer, defaultWasmPath, realSealAvailable, REAL_SEAL_LABEL };
