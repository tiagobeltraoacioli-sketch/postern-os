// browser/core.js — loader for the REAL hybrid-PQ wallet core in the browser.
//
// Instantiates bloch_wallet_wasm.wasm — the wasm32-wasip1 build of the node's
// own bloch-crypto (ML-DSA-65 ‖ Falcon-1024) — through the same minimal
// 5-function wasi_snapshot_preview1 shim + C-ABI marshalling
// (bw_alloc / bw_call / bw_free) that apps/mobile-wallet's wallet-live.js and
// test-wasm.mjs use. This is NOT wasm-bindgen: there is no .js glue file, and
// everything goes through the single bw_call(method, jsonArgs) dispatcher.
//
// FAIL LOUD: loadCore() rejecting means the core is NOT available — callers
// (browser/wallet.js) must then register NOTHING with PosternBrowser, so
// api.isReal() stays false and every pane shows its labelled preview badge
// instead of a half-dead "live" one. call() before a successful load throws.
//
// Classic script, no bundler. Load BEFORE browser/wallet.js.
(function () {
  "use strict";
  if (window.PosternBrowserCore) return; // idempotent across double-include

  // Same-origin wasm asset (T3 ships it next to index.html). Overridable for
  // dev shells that serve it elsewhere — still same-origin, never a CDN.
  const WASM_URL = window.POSTERN_WASM_URL || "bloch_wallet_wasm.wasm";

  let ex = null;   // wasm exports after a successful instantiation
  let mem = null;  // the module's own exported WebAssembly.Memory
  let loading = null; // in-flight/settled load promise (idempotent)

  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  // The module imports 5 wasi_snapshot_preview1 functions. It does no real IO;
  // only random_get matters (OS CSPRNG for fresh mnemonics + the Falcon hedged
  // signing nonce). The rest are satisfied with safe stubs.
  function wasiShim() {
    const view = () => new DataView(mem.buffer);
    return {
      wasi_snapshot_preview1: {
        random_get: (ptr, len) => {
          crypto.getRandomValues(new Uint8Array(mem.buffer, ptr, len));
          return 0;
        },
        environ_sizes_get: (cptr, sptr) => {
          const v = view();
          v.setUint32(cptr, 0, true);
          v.setUint32(sptr, 0, true);
          return 0;
        },
        environ_get: () => 0,
        fd_write: (fd, iovs, n, nwritten) => {
          // Tally the bytes but write nothing (no stdout in the browser).
          const v = view();
          let total = 0;
          for (let i = 0; i < n; i++) total += v.getUint32(iovs + i * 8 + 4, true);
          v.setUint32(nwritten, total, true);
          return 0;
        },
        proc_exit: (code) => {
          throw new Error("wallet core aborted (proc_exit " + code + ")");
        },
      },
    };
  }

  async function instantiate() {
    const resp = await fetch(WASM_URL);
    if (!resp.ok) throw new Error("failed to load wallet core (" + resp.status + ")");
    const shim = wasiShim();
    let instance;
    if (WebAssembly.instantiateStreaming) {
      try {
        ({ instance } = await WebAssembly.instantiateStreaming(resp.clone(), shim));
      } catch (_) {
        const bytes = await resp.arrayBuffer();
        ({ instance } = await WebAssembly.instantiate(bytes, shim));
      }
    } else {
      const bytes = await resp.arrayBuffer();
      ({ instance } = await WebAssembly.instantiate(bytes, shim));
    }
    if (!instance.exports || typeof instance.exports.bw_call !== "function") {
      throw new Error("wallet core wasm has no bw_call export — wrong module");
    }
    ex = instance.exports;
    mem = ex.memory;
  }

  /** Lazy + idempotent: the first call starts instantiation, every later call
      returns the same promise. A failed load clears the cache so a retry (e.g.
      after the network comes back) is possible — but until one SUCCEEDS,
      ready() stays false and call() throws. */
  function loadCore() {
    if (!loading) {
      loading = instantiate().catch((e) => {
        loading = null; // allow an explicit retry; nothing was registered
        throw e;
      });
    }
    return loading;
  }

  /** bw_call(method, args) -> parsed JSON result (throws on a wasm error
      result, and throws if the core never loaded — no silent fakes). */
  function call(method, args) {
    if (!ex) throw new Error("wallet core not loaded — loadCore() has not succeeded");
    const mb = encoder.encode(method);
    const ab = encoder.encode(JSON.stringify(args || {}));
    const mp = ex.bw_alloc(mb.length);
    new Uint8Array(mem.buffer, mp, mb.length).set(mb);
    const ap = ex.bw_alloc(ab.length);
    new Uint8Array(mem.buffer, ap, ab.length).set(ab);
    const rp = ex.bw_call(mp, mb.length, ap, ab.length);
    const dv = new DataView(mem.buffer);
    const ok = dv.getUint8(rp);
    const len = dv.getUint32(rp + 1, true);
    const payload = decoder.decode(new Uint8Array(mem.buffer, rp + 5, len));
    ex.bw_free(rp, 5 + len);
    ex.bw_free(mp, mb.length);
    ex.bw_free(ap, ab.length);
    if (!ok) throw new Error(payload);
    return JSON.parse(payload);
  }

  window.PosternBrowserCore = { loadCore, call, ready: () => !!ex };
})();
