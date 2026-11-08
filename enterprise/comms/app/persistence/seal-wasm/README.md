<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# bloch-comms-seal-wasm

A thin `wasm32-unknown-unknown` cdylib that binds the enterprise comms
sealed-store to the **audited `postern-core` seal** (XChaCha20-Poly1305 v2,
key-committing, context-bound; Argon2id at-rest). It **implements no crypto of
its own** — every operation delegates to `postern_core::aead::{seal_with_context,
open_with_context}`, so blobs and keys are byte-for-byte cross-compatible with
the native reference path (`../seal-rs`).

## Why WASM

Loaded in-process by Node's built-in `WebAssembly` (no wasm-bindgen / wasm-pack /
npm build deps). The 32-byte store key and plaintext are written into and read
back from wasm **linear memory** — they never cross a process boundary. This is
the in-process form the sealed-store uses as its **default** sealer; the AES-GCM
placeholder is only a labeled last-resort fallback (never plaintext).

`wasm32-unknown-unknown` has no OS RNG, so getrandom uses its `custom` backend
and imports a single host function (`postern_seal.host_getrandom`), backed by
Node's `crypto.randomFillSync` (the OS CSPRNG). The AEAD nonce is drawn from the
host. Key bytes in wasm memory are zeroized after each op.

## Build

```sh
../build-wasm.sh        # adds the wasm32 target if missing, builds release
```

Output (`target/…/bloch_comms_seal_wasm.wasm`) is a build artifact — **gitignored**;
the loader (`../postern-seal-wasm.mjs`) auto-discovers it. On a checkout without
the wasm target, source + `build-wasm.sh` ship and the seal stays selectable;
build the artifact and it's picked up with no code change.

## Honest status

Reference prototype, **UNAUDITED**. "In-process" means the Node process address
space (wasm linear memory) — strictly better than a spawned CLI, but **not** a
TEE/enclave: a rooted device, an attached debugger, or a RAM capture still
defeats containment by construction.

## License

`MIT OR Apache-2.0` — see [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).
