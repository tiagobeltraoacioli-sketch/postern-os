// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern SHIELD — REAL seal engine (integration adapter). Business/Enterprise ONLY.
//
// STATUS: reference prototype — UNAUDITED, pre-production.
//
// WHAT THIS IS
// ------------
// The container (shield-container.mjs) seals corporate data at rest through an
// INJECTED seal engine exposing three ops:
//
//     deriveKey(secretBytes, salt) -> key32   (Argon2id, per postern-vault)
//     seal(key32, plaintextBytes)  -> sealedBytes
//     open(key32, sealedBytes)     -> plaintextBytes   (throws on wrong key / tamper)
//
// This module is the REAL engine, replacing the labelled non-cryptographic demo
// engine (makeDemoSealEngine). It defines NO crypto itself: it bridges the three
// ops to the ONE canonical Postern seal — postern_core::aead (XChaCha20-Poly1305,
// versioned, key-committing, context-bound) + postern_core::kdf (Argon2id,
// at-rest tier) — through one of two backends:
//
//   1. WASM (in-process, PREFERRED) — ../seal-wasm/ compiled to a small
//      WebAssembly module, loaded by Node's built-in `WebAssembly`. The 32-byte
//      key is written into THIS process's wasm linear memory and is NEVER
//      serialized to a pipe, argv, or another process. This closes the
//      production gap the CLI backend had (key + plaintext transiting a process
//      boundary over stdin/stdout).
//
//   2. CLI (subprocess, DOCUMENTED FALLBACK) — spawns the ../seal/ binary once
//      per op, passing hex operands over stdin. Kept so the engine still works
//      where the wasm module has not been built, but it is explicitly the
//      PROTOTYPE-ONLY key-handling path: the key crosses a process boundary.
//
// createRealSealEngine() auto-selects: wasm if built, else the CLI, else it
// FAILS CLOSED (never a silent downgrade to the non-crypto demo engine).
//
// Because the ops are grant-bound in the container (the deriveKey secret is
// released ONLY while the access grant is live), a revoked/expired grant means
// the key can never be re-derived and the real AEAD blob is unrecoverable —
// "revoke => key gone => data inert" — with the confidentiality now REAL.
//
// HONEST LIMITS
// -------------
//  * The SEAL is real; the CONTAINER around it is still containment BY
//    CONSTRUCTION (userland), NOT a kernel boundary. A rooted / jailbroken phone,
//    a debugger on this process, or a RAM capture defeats it. A real seal does
//    not change that.
//  * "In-process" (wasm) means the Node process's OWN address space — strictly
//    better than the spawned CLI (no key on a pipe), but it is NOT a TEE /
//    enclave / secure element. A production build would additionally isolate the
//    derived key in hardware. We say so plainly.
//  * The wasm module is a BUILD ARTIFACT: it must be compiled once
//    (`./build-wasm.sh` or the cargo command in that script). Until then this
//    engine transparently uses the CLI fallback, or fails closed if neither
//    backend exists. Nothing here fakes real crypto.
//  * This adapter only transforms bytes the corporate container hands it. It has
//    no path to, and never touches, the personal side of the device.

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { randomFillSync } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));

// The SHIELD container context string. Kept in lock-step with both backends
// (seal/src/main.rs SHIELD_CONTEXT and seal-wasm/src/lib.rs SHIELD_CONTEXT) so a
// blob sealed by one path opens through the other.
const SHIELD_CONTEXT = "postern-shield/container/v1";

// ── backend discovery ─────────────────────────────────────────────────────────

/**
 * Path to the compiled in-process WASM seal module, relative to this module
 * (../seal-wasm/target/wasm32-unknown-unknown/{release,debug}/postern_shield_seal_wasm.wasm).
 * The release build is preferred.
 * @returns {string|null} an existing path, or null if the module is not built.
 */
export function defaultSealWasmPath() {
  const base = join(__dirname, "..", "seal-wasm", "target", "wasm32-unknown-unknown");
  const candidates = [
    join(base, "release", "postern_shield_seal_wasm.wasm"),
    join(base, "debug", "postern_shield_seal_wasm.wasm"),
  ];
  for (const p of candidates) if (existsSync(p)) return p;
  return null;
}

/**
 * Path to the compiled `postern-shield-seal` CLI binary, relative to this module
 * (../seal/target/{release,debug}/postern-shield-seal). The release build is
 * preferred when both exist.
 * @returns {string|null} an existing path, or null if the binary is not built.
 */
export function defaultSealBinPath() {
  const base = join(__dirname, "..", "seal", "target");
  const candidates = [
    join(base, "release", "postern-shield-seal"),
    join(base, "debug", "postern-shield-seal"),
  ];
  for (const p of candidates) if (existsSync(p)) return p;
  return null;
}

/** Is the in-process WASM seal module available? */
export function wasmSealAvailable(wasm = defaultSealWasmPath()) {
  return typeof wasm === "string" && existsSync(wasm);
}

/**
 * Is a usable real-seal CLI binary available? (Legacy name kept for callers that
 * branch on the subprocess backend specifically.)
 */
export function sealBinaryAvailable(bin = defaultSealBinPath()) {
  return typeof bin === "string" && existsSync(bin);
}

/**
 * Is ANY real backend available (in-process wasm OR the CLI fallback)? Callers
 * that just want "can I use the real seal at all?" should branch on this.
 */
export function sealEngineAvailable() {
  return wasmSealAvailable() || sealBinaryAvailable();
}

// ── the WASM (in-process) backend ──────────────────────────────────────────────

/**
 * Build the REAL seal engine backed by the IN-PROCESS WASM module. The key is
 * written into this process's wasm linear memory only — it never crosses a
 * process boundary.
 *
 * @param {object} [opts]
 * @param {string} [opts.wasm] path to the compiled .wasm (defaults to the
 *        compiled module under ../seal-wasm/target/...).
 * @throws if the module is not built (the caller should fall back to the CLI or
 *         fail closed — createRealSealEngine() does this).
 */
export function createWasmSealEngine(opts = {}) {
  const wasmPath = opts.wasm || defaultSealWasmPath();
  if (!wasmPath || !existsSync(wasmPath)) {
    throw new Error(
      "real-seal-engine: in-process wasm module not found. Build it with " +
        "`./build-wasm.sh` in enterprise/shield/container/, or pass { wasm }."
    );
  }

  const bytes = readFileSync(wasmPath);
  const mod = new WebAssembly.Module(bytes); // synchronous compile (Node)
  let memory; // set after instantiation; sh_host_random is only called during ops
  const instance = new WebAssembly.Instance(mod, {
    env: {
      // The one import: OS-random bytes for the AEAD nonce. Wasm has no ambient
      // RNG, so the host fills it from node:crypto (the OS CSPRNG). Recomputes
      // the view each call in case memory grew (buffer would have detached).
      sh_host_random(ptr, len) {
        randomFillSync(new Uint8Array(memory.buffer, ptr, len));
      },
    },
  });
  const x = instance.exports;
  memory = x.memory;

  // Assert the wasm module's SHIELD context matches this module's constant (and
  // therefore the CLI's) — a build/skew guard, not a security check.
  const ctx = new TextDecoder().decode(readPacked(x.sh_context()));
  if (ctx !== SHIELD_CONTEXT) {
    throw new Error(`real-seal-engine: wasm context ${JSON.stringify(ctx)} != ${JSON.stringify(SHIELD_CONTEXT)}`);
  }

  // Copy `u8` into a fresh wasm region, returning its pointer. Caller frees.
  function alloc(u8) {
    const ptr = x.sh_alloc(u8.length);
    if (u8.length) new Uint8Array(memory.buffer, ptr, u8.length).set(u8);
    return ptr;
  }
  // Best-effort wipe of a wasm region before freeing it (for key material).
  function wipeFree(ptr, len) {
    if (len) new Uint8Array(memory.buffer, ptr, len).fill(0);
    x.sh_free(ptr, len);
  }
  // Decode a packed(ptr<<32 | len) result. 0 => null (error). Copies the bytes
  // out (detaching from wasm memory) and frees the wasm region.
  function readPacked(packed) {
    if (packed === 0n) return null;
    const ptr = Number(packed >> 32n);
    const len = Number(packed & 0xffffffffn);
    const out = new Uint8Array(len);
    if (len) out.set(new Uint8Array(memory.buffer, ptr, len));
    x.sh_free(ptr, len);
    return out;
  }

  function seal(key, plaintext) {
    const k = toBytes(key);
    const pt = toBytes(plaintext);
    const kp = alloc(k);
    const pp = alloc(pt);
    try {
      const out = readPacked(x.sh_seal(kp, k.length, pp, pt.length));
      if (out === null) throw new Error(`real-seal(wasm): seal errored (status ${x.sh_last_status()})`);
      return out;
    } finally {
      wipeFree(kp, k.length);
      x.sh_free(pp, pt.length);
    }
  }

  function open(key, sealed) {
    const k = toBytes(key);
    const s = toBytes(sealed);
    const kp = alloc(k);
    const sp = alloc(s);
    try {
      const out = readPacked(x.sh_open(kp, k.length, sp, s.length));
      if (out === null) {
        const status = x.sh_last_status();
        // status 3 = wrong key / tamper / corrupt — the "revoke => unreadable" path.
        throw new Error(
          status === 3
            ? "real-seal(wasm): open failed (wrong key, tampered, or corrupt)"
            : `real-seal(wasm): open errored (status ${status})`
        );
      }
      return out;
    } finally {
      wipeFree(kp, k.length);
      x.sh_free(sp, s.length);
    }
  }

  function deriveKey(secret, salt) {
    const sec = toBytes(secret);
    const sa = toBytes(salt);
    const sp = alloc(sec);
    const sap = alloc(sa);
    try {
      const out = readPacked(x.sh_derive_key(sp, sec.length, sap, sa.length));
      if (out === null) throw new Error(`real-seal(wasm): derive-key errored (status ${x.sh_last_status()})`);
      if (out.length !== 32) throw new Error(`real-seal(wasm): derive-key returned ${out.length} bytes, expected 32`);
      return out;
    } finally {
      wipeFree(sp, sec.length); // secret is key material — wipe the wasm region
      x.sh_free(sap, sa.length);
    }
  }

  return {
    __demo: false,
    __real: true,
    __backend: "wasm",
    context: SHIELD_CONTEXT,
    seal,
    open,
    deriveKey,
  };
}

// ── the CLI (subprocess) backend — DOCUMENTED FALLBACK ─────────────────────────

/**
 * Build the REAL seal engine backed by the ../seal/ CLI binary (one spawn per
 * op). This is the PROTOTYPE-ONLY key-handling path: the 32-byte key and the
 * plaintext transit a process boundary over stdin/stdout. Prefer the wasm
 * backend; this exists so the engine still functions where the wasm module has
 * not been built.
 *
 * @param {object} [opts]
 * @param {string} [opts.bin] path to the `postern-shield-seal` binary.
 * @throws if no binary is available.
 */
export function createCliSealEngine(opts = {}) {
  const bin = opts.bin || defaultSealBinPath();
  if (!bin || !existsSync(bin)) {
    throw new Error(
      "real-seal-engine: postern-shield-seal binary not found. Build it with " +
        "`cargo build --release` in enterprise/shield/container/seal/, or pass { bin }. " +
        "This adapter never falls back to non-crypto silently."
    );
  }

  // One CLI op = one spawn. stdin carries the hex operands, one per line.
  function run(cmd, hexLines, { failCode } = {}) {
    try {
      const out = execFileSync(bin, [cmd], {
        input: hexLines.join("\n") + "\n",
        encoding: "utf8",
        maxBuffer: 64 * 1024 * 1024,
      });
      return fromHex(out.trim());
    } catch (e) {
      // Exit 3 = open failed (wrong key / tamper / corrupt). Surface it as a
      // clean throw so the container's open()/unlock() propagate "unreadable".
      const status = e && typeof e.status === "number" ? e.status : null;
      const stderr = e && e.stderr ? String(e.stderr).trim() : "";
      if (failCode && status === failCode) {
        throw new Error(`real-seal(cli): ${cmd} failed (wrong key, tampered, or corrupt): ${stderr}`);
      }
      throw new Error(`real-seal(cli): ${cmd} errored (exit ${status}): ${stderr || (e && e.message) || "unknown"}`);
    }
  }

  return {
    __demo: false,
    __real: true,
    __backend: "cli",
    context: SHIELD_CONTEXT,

    /** Argon2id (at-rest tier) via postern-core::kdf. Returns a 32-byte key. */
    deriveKey(secret, salt) {
      const key = run("derive-key", [toHex(toBytes(secret)), toHex(toBytes(salt))]);
      if (key.length !== 32) throw new Error(`real-seal(cli): derive-key returned ${key.length} bytes, expected 32`);
      return key;
    },

    /** XChaCha20-Poly1305 seal (v2, key-committing, context-bound) via postern-core::aead. */
    seal(key, plaintext) {
      return run("seal", [toHex(toBytes(key)), toHex(toBytes(plaintext))]);
    },

    /** Open a v2 sealed blob; throws on wrong key / tamper / corrupt. */
    open(key, sealed) {
      return run("open", [toHex(toBytes(key)), toHex(toBytes(sealed))], { failCode: 3 });
    },
  };
}

// ── auto-selecting factory ─────────────────────────────────────────────────────

/**
 * Build the REAL seal engine, PREFERRING the in-process WASM backend (key never
 * leaves the process) and falling back to the CLI subprocess backend only when
 * the wasm module has not been built. Fails closed if neither is available —
 * NEVER silently degrades to the non-cryptographic demo engine (the caller must
 * choose makeDemoSealEngine() explicitly if that is what they want).
 *
 * @param {object} [opts]
 * @param {"auto"|"wasm"|"cli"} [opts.backend="auto"] force a backend.
 * @param {string} [opts.wasm] path to the wasm module.
 * @param {string} [opts.bin] path to the CLI binary.
 * @returns {{seal:Function, open:Function, deriveKey:Function, __demo:false, __real:true, __backend:string, context:string}}
 */
export function createRealSealEngine(opts = {}) {
  const backend = opts.backend || "auto";

  if (backend === "wasm") return createWasmSealEngine(opts);
  if (backend === "cli") return createCliSealEngine(opts);

  // auto: in-process wasm first, then the CLI fallback, then fail closed.
  if (wasmSealAvailable(opts.wasm)) {
    try {
      return createWasmSealEngine(opts);
    } catch (e) {
      // The wasm module exists but would not instantiate. Do NOT silently use a
      // weaker path without a trace; try the CLI, and if that is also missing
      // the throw below is fail-closed.
      if (!sealBinaryAvailable(opts.bin)) throw e;
    }
  }
  if (sealBinaryAvailable(opts.bin)) return createCliSealEngine(opts);

  throw new Error(
    "real-seal-engine: no real seal backend available. Build the in-process wasm " +
      "module (`./build-wasm.sh` in enterprise/shield/container/) — PREFERRED, key " +
      "never leaves the process — or the CLI fallback (`cargo build --release` in " +
      "enterprise/shield/container/seal/). This adapter never falls back to " +
      "non-crypto silently."
  );
}

// ── helpers ──────────────────────────────────────────────────────────────────

function toBytes(x) {
  if (x instanceof Uint8Array) return x;
  if (typeof x === "string") return new TextEncoder().encode(x);
  if (Array.isArray(x)) return Uint8Array.from(x);
  if (x && x.buffer) return new Uint8Array(x.buffer, x.byteOffset || 0, x.byteLength);
  throw new Error("real-seal-engine: expected bytes or string");
}

function toHex(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, "0");
  return s;
}

function fromHex(s) {
  const clean = s.trim();
  if (clean.length % 2 !== 0) throw new Error("real-seal-engine: odd-length hex from binary");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new Error("real-seal-engine: non-hex output from binary");
    out[i] = byte;
  }
  return out;
}

export default {
  createRealSealEngine,
  createWasmSealEngine,
  createCliSealEngine,
  defaultSealWasmPath,
  defaultSealBinPath,
  wasmSealAvailable,
  sealBinaryAvailable,
  sealEngineAvailable,
};
