<!--
SPDX-License-Identifier: MIT OR Apache-2.0
SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
-->

# postern-shield-seal — the REAL seal adapter for the SHIELD work-container

**STATUS: reference prototype — UNAUDITED, pre-production. Not secure, not deployed.**

This crate turns the SHIELD container's injected seal interface — the `seal` /
`open` / `deriveKey` ops that `shield-container.mjs` calls — into the **real
Postern seal**, replacing the labelled non-cryptographic demo engine. It defines
**no cryptography of its own**: every op delegates to the ONE canonical seal in
[`postern-core`](../../../../crates/postern-core):

- `deriveKey` → `postern_core::kdf::derive_key` — **Argon2id**, at-rest tier (64 MiB, t = 3).
- `seal` → `postern_core::aead::seal_with_context` — **XChaCha20-Poly1305**, v2 wire format (versioned, key-committing), context-bound to `postern-shield/container/v1`.
- `open` → `postern_core::aead::open_with_context` — throws on wrong key / tamper / corrupt.

It is exposed as a tiny stdin/stdout CLI that the JS integration adapter
([`../src/real-seal-engine.mjs`](../src/real-seal-engine.mjs)) spawns once per op.

## Why a CLI, and the honest limit

Passing the derived key across a process boundary is a **prototype wiring**, not
a production key-handling design — a real deployment would embed this via
in-process FFI/WASM so the 32-byte key never leaves the address space. The
**seal is real**, but the **container** around it is still containment *by
construction* (userland), **not a kernel boundary**: a rooted / jailbroken
phone, a debugger, or a RAM capture defeats it. Making the at-rest bytes
genuinely AEAD-sealed does not change that.

## Own workspace root (no root-manifest edit)

The `[workspace]` table in `Cargo.toml` makes this crate its **own** workspace
root, so it is excluded from the repo's virtual workspace and needs no change to
the root `Cargo.toml`. Its only dependency is the path crate `postern-core`.

## Build & verify

```sh
cargo check                 # type-check the adapter
cargo build --release       # produce target/release/postern-shield-seal
```

Wire protocol (operands are hex, one per line on stdin):

```
postern-shield-seal derive-key   # stdin: secretHex, saltHex   -> stdout: keyHex (64)
postern-shield-seal seal         # stdin: keyHex(64), ptHex      -> stdout: sealedHex
postern-shield-seal open         # stdin: keyHex(64), sealedHex  -> stdout: ptHex
```

Exit codes: `0` ok · `2` usage/parse · `3` open failed (wrong key / tamper /
corrupt) · `4` kdf/other.

The container's `self-check.mjs` exercises the real round-trip and the
revoke→unreadable property automatically when this binary is built.

## License

Dual-licensed **MIT OR Apache-2.0** — see `LICENSE-MIT` and `LICENSE-APACHE`.
