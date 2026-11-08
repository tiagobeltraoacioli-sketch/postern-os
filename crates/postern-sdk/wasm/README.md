<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# postern-sdk — the browser seam (wasm)

This is **item 0** of the apps-productionization work: the single wiring seam so
the HTML front-ends can reach the audited cores instead of doing crypto ad-hoc
in WebCrypto. Native builds the UniFFI/cdylib facade for the mobile/desktop
shells; **this directory is the browser half.**

## The contract

The front-ends never import a per-app crypto binding. They probe **one** global:

```js
const sdk = globalThis.PosternSDK;   // installed by a host shell, or absent
```

- **Present** → the page uses the real audited primitive and flips its label to
  say so.
- **Absent** → the page keeps its **clearly-labeled classical stand-in** (this is
  the honest default for a plain browser tab). The seam never fabricates a
  "verified/real" state it cannot back.

A host shell installs it with the reference loader:

```js
import { installPosternSDK } from "./postern-sdk.js";
await installPosternSDK("./postern_sdk_bg.wasm");   // sets globalThis.PosternSDK
```

## What this build backs — honestly

| Surface | Status in the **wasm** build | Core |
|---|---|---|
| **S2 — at-rest KDF** | **REAL**: Argon2id **m=65536 KiB (64 MiB), t=3, p=1** | `postern-core::kdf` |
| **S2 — AEAD seal/open** | **REAL**: key-committing XChaCha20-Poly1305, versioned, context-bound | `postern-core::aead` / `postern-vault` |
| **S1 — hybrid PQ signing** | **NOT in this build** | `bloch-crypto` (excluded) |

Two honesty notes that must not be softened:

1. **The pinned KDF is 64 MiB / t=3, not 256 MiB / t=4.** Some design docs aspire
   to the larger tier; the code (`postern-core`) is the at-rest tier above. The
   seam reports the truth via `kdfLabel()`; UIs should show that string, not the
   aspiration.
2. **Hybrid Falcon-1024 ‖ ML-DSA-65 is not wasm-buildable.** `bloch-crypto`
   links PQClean **C** (`cc` + `libc`), which does not target
   `wasm32-unknown-unknown`. So in the browser, S1 stays a labeled classical
   stand-in. `globalThis.PosternSDK.pq.available` is `false` and carries the
   reason. Real hybrid PQ signing is in the **native/UniFFI** build (the wallet
   core) or waits on a pure-Rust PQ backend. Do not ship a browser "PQ" claim.

## Build

```sh
# compile gate — always runnable, no extra tooling (this is the CI gate):
cargo build -p postern-sdk --target wasm32-unknown-unknown \
      --no-default-features --features wasm --lib

# full glue (needs wasm-bindgen-cli / wasm-pack — see the script):
crates/postern-sdk/wasm/build-wasm.sh
```

`built ≠ produced`: the compile gate is verified in this tree. Emitting the
browser-ready `postern_sdk.js` + `postern_sdk_bg.wasm` needs `wasm-bindgen-cli`
(version-matched to the `wasm-bindgen` crate); `build-wasm.sh` checks for it and
prints the install command rather than pretending it ran.

## Reproducibility — what is (and is not) committed

The wasm artifact is **generated, never committed.** The `.gitignore` in this
directory excludes everything `wasm-bindgen --target web` emits (`pkg/`,
`postern_sdk.js`, `postern_sdk_bg.wasm`, and the `.d.ts` glue — note the crate
lib name is `postern_sdk`, underscored, distinct from the hand-written
`postern-sdk.js` loader). Rationale: a checked-in binary blob is an
unauditable, unreproducible trust hole for a security product. Anyone can
regenerate a byte-identical artifact from source by running `build-wasm.sh`
with a `wasm-bindgen-cli` whose version matches the `wasm-bindgen` crate pinned
in the repo `Cargo.lock`.

**Committed here (the source of the seam):** `build-wasm.sh`, `postern-sdk.js`
(the loader), `README.md`. **Regenerated locally (git-ignored):** the wasm
module + its `--target web` glue.

## CSP note for the strict single-file pages

Chiave (and the other single-file front-ends) ship `connect-src 'none'` and
`script-src 'unsafe-inline'`, which by design **cannot** fetch a `.wasm` or load
an external module. That is intentional: in a plain browser tab those pages stay
on the labeled stand-in. The seam becomes live when the page runs **inside a
Postern host shell** (Tauri / mobile WebView) that installs `globalThis.PosternSDK`
before the page's scripts run — or in a packaged build that relaxes CSP to
`script-src 'self' 'wasm-unsafe-eval'; connect-src 'self'`. The page code is
already wired to consume the seam either way.

## Files

- `postern-sdk.js` — the reference loader; adapts the `wasm-bindgen --target web`
  output into `globalThis.PosternSDK`.
- `build-wasm.sh` — compile gate + glue generation (with an honest skip).
- The Rust surface is `crates/postern-sdk/src/wasm.rs` (feature `wasm`,
  `cfg(target_arch = "wasm32")` — inert on native).
