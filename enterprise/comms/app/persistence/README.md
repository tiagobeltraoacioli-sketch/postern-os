<!--
SPDX-License-Identifier: MIT OR Apache-2.0
SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
-->

# Bloch — persistence (sealed-at-rest store)

**Additive** hardening submodule for the Bloch org messenger. Enterprise-only,
**UNAUDITED reference prototype**, pre-production. It does **not** touch the
existing app modules or the `compliance/` layer.

## The gap it closes

The messenger transport (`crates/postern-messenger`, `matrix` slice) runs today
on the SDK's **in-memory** store — Megolm sessions and replay state do **not**
survive a restart (that crate says so in its honest-limit notes). This submodule
is the app-layer answer: a local store that survives a restart by sealing itself
**at rest**, keyed **locally**.

## What it is / is not

- **Message bodies stay E2EE.** This store holds Megolm **session material** and
  message **envelopes** (the at-rest ciphertext form). It never sees or writes
  plaintext bodies. Sealing at rest is an **additional** local-device protection
  on top of E2EE — not a replacement for it.
- **Metadata stays org-visible.** Sealing the local copy does **not** make Bloch
  "fully private": the homeserver still sees the social graph. (See the app's
  `src/transparency.mjs`.)
- **Honest about the seal.** The canonical Postern seal is `postern_core::aead`
  (XChaCha20-Poly1305, versioned, key-committing, context-bound) — the **same**
  seal `crates/postern-vault` uses for secrets at rest.
  - `seal-rs/` is a Rust reference that seals with that **real** primitive.
  - `seal-wasm/` compiles that **same** postern-core seal to a WebAssembly
    module, and `postern-seal-wasm.mjs` loads it **in-process**. This is the
    **DEFAULT** seal for `sealed-store.mjs`: the 32-byte store key never crosses
    a process boundary, and the seal nonce is drawn from Node's CSPRNG. So
    sessions are sealed with the **audited primitive**, not a placeholder.
    (Build it with `./build-wasm.sh`; the store discovers the artifact
    automatically.)
  - The WebCrypto **AES-256-GCM reference** in `sealed-store.mjs` is a
    **last-resort fallback ONLY** — used when the WASM binding is not built (a
    browser with no artifact, or a machine with no Rust/wasm toolchain) so the
    app + self-check still run standalone. It is clearly labelled and **must not
    be shipped as "the seal"**. Its `0x01` version byte differs from the real
    seal's `0x02`, so a blob sealed by one is **rejected (fail-closed)** by the
    other — never silently mis-opened.
- **Local key.** The 32-byte store key is on-device (from a device passphrase via
  `postern_core::kdf`, an OS keystore, or `generateStoreKey()`/`random_key()`).
  It is never uploaded and never embedded in the sealed blob.
- **Fail-closed open.** A wrong key, wrong context, or tampered blob yields
  **no** store (never a partial/plaintext fallback).

## Files

```
persistence/
  sealed-store.mjs        JS primary: Vault-shaped sealed store (put/get + seal/open)
  postern-seal-wasm.mjs   In-process WASM loader — the DEFAULT (real) seal
  build-wasm.sh           Build the WASM binding (compiles seal-wasm/)
  seal-wasm/              Rust -> WASM binding over the REAL postern-core seal
    Cargo.toml
    src/lib.rs
  seal-rs/                Rust reference over the REAL postern-core seal (native)
    Cargo.toml
    src/lib.rs
```

## Verify

```sh
node --check persistence/sealed-store.mjs persistence/postern-seal-wasm.mjs

# Build the REAL in-process seal (the store then uses it as the DEFAULT):
cd persistence && ./build-wasm.sh

# Native Rust reference over the same postern-core seal:
cd persistence/seal-rs && cargo check && cargo test

# The app self-check (enterprise/comms/app/self-check.mjs) exercises the store
# THROUGH the real seal: seal-at-rest, survive-restart, wrong-key/tamper
# fail-closed. It stays green on the labelled AES-GCM fallback too, so it runs
# with or without the wasm toolchain.
```

> **Toolchain note.** The default seal needs the `wasm32-unknown-unknown` Rust
> target (`rustup target add wasm32-unknown-unknown`). Without it, `build-wasm.sh`
> is not run, no artifact exists, and the store transparently uses the labelled
> AES-256-GCM **fallback** — the real seal remains **selectable**: build the
> artifact and it is picked up automatically, no code change.
