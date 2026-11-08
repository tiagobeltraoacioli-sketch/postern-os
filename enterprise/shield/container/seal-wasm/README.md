<!--
SPDX-License-Identifier: MIT OR Apache-2.0
SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
-->

# postern-shield-seal-wasm — the IN-PROCESS seal adapter for the SHIELD container

**STATUS: reference prototype — UNAUDITED, pre-production.**

The in-process sibling of `../seal/` (the CLI adapter). Compiled to a small
WebAssembly module so the container's JS engine (`../src/real-seal-engine.mjs`)
can call the real Postern seal **without spawning a subprocess** — the 32-byte
key is written into the Node process's own wasm linear memory and **never crosses
a process boundary / pipe** (that was the SEAL-3 prototype gap the CLI backend
has).

Like the CLI adapter it defines **no crypto of its own**: every op delegates to
the ONE canonical Postern seal in `crates/postern-core` — XChaCha20-Poly1305 v2
(versioned, key-committing, context-bound) with the 32-byte key from Argon2id at
the at-rest tier. It exposes a hand-rolled C-ABI over linear memory (`sh_alloc`,
`sh_free`, `sh_derive_key`, `sh_seal`, `sh_open`, `sh_context`,
`sh_last_status`) — **no wasm-bindgen, no wasm-pack, no npm build deps**.

## Build (a real compile step — nothing is prebuilt)

```sh
../build-wasm.sh
# equivalently:
cargo build --release --target wasm32-unknown-unknown
# -> target/wasm32-unknown-unknown/release/postern_shield_seal_wasm.wasm
```

Needs `cargo` + the `wasm32-unknown-unknown` target and Node ≥ 16. Randomness for
the AEAD nonce is imported in-process from the host (`sh_host_random`, backed by
`node:crypto` — the OS CSPRNG); wasm has no ambient RNG.

## Honest limits

The seal is real, but "in-process" means the Node process's **own address space**
(wasm linear memory) — strictly better than a spawned CLI (no key on a pipe), but
**NOT** a TEE / enclave / secure element. A rooted / jailbroken phone, a debugger
on this process, or a RAM capture still defeats the container. Containment is by
construction, not a kernel boundary.

## License

Dual-licensed **MIT OR Apache-2.0** — see `LICENSE-MIT` and `LICENSE-APACHE`.
