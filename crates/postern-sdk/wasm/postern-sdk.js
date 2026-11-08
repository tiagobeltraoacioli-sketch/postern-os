// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Postern SDK — reference browser loader (the wiring seam, JS side).
//
// This ES module adapts the `wasm-bindgen --target web` output of the
// `postern-sdk` `wasm` build into ONE stable, versioned global the HTML
// front-ends probe:  `globalThis.PosternSDK`.
//
// The front-ends (Chiave, Sotto, Vedetta, Tolmach) NEVER import a per-app
// crypto binding. They call `globalThis.PosternSDK` if — and only if — a host
// shell (Tauri / mobile WebView / a relaxed-CSP build) has installed it. If it
// is absent, every page keeps its clearly-labeled *classical stand-in* and
// shows the honest label. That is the whole contract: the seam upgrades the
// primitive when the real core is present, and never fakes it when it is not.
//
// HONESTY (carried from the Rust side, do not soften):
//   * KDF/AEAD are REAL here — Argon2id(64 MiB, t=3) + XChaCha20-Poly1305 from
//     postern-core / postern-vault. This kills stand-in S2 wherever the seam is
//     installed.
//   * Hybrid PQ signing (Falcon-1024 ‖ ML-DSA-65) is NOT in the wasm build:
//     bloch-crypto links PQClean C and does not target wasm32. `pq.available`
//     is therefore `false`; pages must keep the S1 classical stand-in until the
//     native/UniFFI shell or a pure-Rust PQ backend provides it.
//
// USAGE (host shell):
//   import { installPosternSDK } from "./postern-sdk.js";
//   await installPosternSDK("./postern_sdk_bg.wasm");   // sets globalThis.PosternSDK
//
// The named imports below match the `#[wasm_bindgen(js_name = …)]` exports in
// crates/postern-sdk/src/wasm.rs. Regenerate the glue with wasm/build-wasm.sh.

import init, {
  sdkVersion,
  backendLabel,
  kdfLabel,
  hasKdf,
  hasAead,
  hasPqSign,
  pqUnavailableReason,
  generateSalt,
  VaultKey,
} from "./postern_sdk.js";

/**
 * Initialise the wasm core and install the stable facade on `globalThis`.
 * Idempotent: a second call returns the already-installed facade.
 *
 * @param {string|URL|Request|BufferSource|WebAssembly.Module} [wasmInput]
 *        Where to fetch `postern_sdk_bg.wasm` (default: alongside this module).
 * @returns {Promise<object>} the installed `globalThis.PosternSDK`.
 */
export async function installPosternSDK(wasmInput) {
  if (globalThis.PosternSDK && globalThis.PosternSDK.__postern) {
    return globalThis.PosternSDK;
  }
  await init(wasmInput);

  const kdfOk = hasKdf() && hasAead();
  const pqOk = hasPqSign();

  const facade = {
    __postern: true,
    version: sdkVersion(),
    backend: "wasm",
    label: backendLabel(),

    // ── S2: at-rest KDF + AEAD (REAL in this build) ──────────────────────────
    kdf: {
      available: kdfOk,
      label: kdfLabel(),

      /** Fresh 16-byte salt (store it alongside the sealed blob). */
      generateSalt() {
        return generateSalt();
      },

      /**
       * Argon2id-derive an opaque at-rest key handle. The key bytes stay in
       * wasm linear memory (never copied into the JS GC heap). Call
       * `key.free()` when done, or seal/open through it.
       *
       * @param {Uint8Array} passphraseBytes
       * @param {Uint8Array} saltBytes  (>= 8 bytes)
       * @returns {VaultKey} opaque handle with .aeadSeal / .aeadOpen / .free
       */
      deriveKey(passphraseBytes, saltBytes) {
        return VaultKey.deriveArgon2id(passphraseBytes, saltBytes);
      },

      /** Wrap externally provided 32-byte key bytes (e.g. host-TEE released). */
      keyFromBytes(keyBytes) {
        return VaultKey.fromBytes(keyBytes);
      },

      /** Seal `plaintextBytes` under `keyHandle`, bound to `contextBytes` (AAD). */
      seal(keyHandle, contextBytes, plaintextBytes) {
        return keyHandle.aeadSeal(contextBytes, plaintextBytes);
      },

      /** Open a blob sealed under the same key + context. Throws on wrong key. */
      open(keyHandle, contextBytes, sealedBytes) {
        return keyHandle.aeadOpen(contextBytes, sealedBytes);
      },
    },

    // ── S1: hybrid PQ signing (NOT in the wasm build) ────────────────────────
    pq: {
      available: pqOk,
      reason: pqOk ? "" : pqUnavailableReason(),
    },
  };

  globalThis.PosternSDK = facade;
  return facade;
}

/**
 * Probe helper for front-ends: returns the installed facade or null. Pages call
 * this on boot and choose the real primitive when non-null, the labeled
 * classical stand-in otherwise.
 */
export function posternSDK() {
  return globalThis.PosternSDK && globalThis.PosternSDK.__postern ? globalThis.PosternSDK : null;
}
