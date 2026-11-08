# Postern Wallet

A Postern Labs product — a **light client / wallet** for the ownerless Bloch-SIS-PoW
protocol (crate: `bloch-mobile`). The zero-cost, decentralized
bootstrap of the attested layer (`docs/specs/BLOCH-SIS-ATTESTATION.md §4`). The
wallet key is protected at rest by the device TEE (Android StrongBox / iOS
Secure Enclave) and the device+app are attested (Android Key Attestation / iOS
App Attest) — free hardware trust on phones people already own.

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│  Native UI + hardware  (per platform)                    │
│   Android: Kotlin/Compose · Keystore(StrongBox) · Key    │
│            Attestation · OkHttp                           │
│   iOS:     SwiftUI · Secure Enclave · App Attest · URLSession │
├──────────────────────────────────────────────────────────┤
│  UniFFI bindings  (generated Kotlin / Swift)             │
├──────────────────────────────────────────────────────────┤
│  bloch-mobile  (this: mobile/core, pure Rust)            │
│   • wallet: mnemonic ↔ address, hybrid Falcon‖ML-DSA sign │
│   • JSON-RPC request builders + response parsers          │
│   • device-attestation challenge plumbing                 │
│   • reuses bloch::crypto → byte-compatible (golden test)  │
└──────────────────────────────────────────────────────────┘
```

**Split of duties:** the Rust core is **pure** (crypto + tx + RPC shaping, fully
unit-tested). The native side does everything with the outside world: HTTP to a
node's RPC, hardware-backed key storage, device attestation, and UI.

## Native responsibilities

| Concern | Android | iOS |
|---|---|---|
| Protect the PQ key at rest | Keystore **StrongBox** (wrap key) | **Secure Enclave** (wrap key) |
| Device/app attestation | **Key Attestation** (X.509 chain, echoes node nonce) | **App Attest** (chain to Apple CA, echoes nonce) |
| HTTP to node RPC | OkHttp | URLSession |
| UI | Jetpack Compose | SwiftUI |

The node issues a nonce (`getattestation` challenge); the app returns a device
attestation over it; a verifier runs `bloch::attestation::verify` with the
`mobile` backend. **Honest limit:** mobile TEEs are classical (P-256) — they do
NOT hold the post-quantum key in hardware; they **protect it at rest** and
attest the device/app. Light-client role only (never a miner).

## Building (mobile targets)

Not built in this repo's CI (needs the platform SDKs). To build the core for
devices:

```bash
# The app shells bind the ONE unified Postern SDK facade (crates/postern-sdk),
# not bloch-mobile's old per-wallet FFI. Build `-p postern-sdk`; the wrapper
# scripts mobile/build-android.sh / mobile/build-ios.sh do exactly this.

# Android
rustup target add aarch64-linux-android armv7-linux-androideabi
cargo install cargo-ndk
cargo ndk -t arm64-v8a build --release -p postern-sdk
cargo run -p postern-sdk --bin uniffi-bindgen -- generate --language kotlin ...

# iOS
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
cargo build --release -p postern-sdk --target aarch64-apple-ios
cargo run -p postern-sdk --bin uniffi-bindgen -- generate --language swift ...   # → .xcframework
```

> **Cross-compile (RESOLVED):** `bloch-mobile` depends on `bloch` with
> `default-features = false`, so the node's `rocksdb`/`libp2p` (and axum/tower/
> prometheus/…) are gated out behind the default `node` Cargo feature, and only
> the lean crypto/address/tx/wallet subset compiles for Android/iOS. Verified:
> `cargo build --no-default-features --lib` is clean and `cargo tree
> --no-default-features` shows **no** rocksdb/libp2p. No separate `bloch-core`
> crate was needed — one source of truth stays in `bloch` (feature-gated), so the
> mobile wallet can never drift from the node's crypto.

## Status

- ✅ `mobile/core` (`bloch-mobile`): pure wallet + RPC + attestation core, with a
  **golden test** asserting byte-compatibility with the node's crypto
  (documented seed → same `bloch1q…` address), sign-verify, and RPC shape.
- ✅ Lean cross-compile: `bloch` with `default-features = false` (the `node`
  feature gates rocksdb/libp2p/axum/…) — mobile builds without the node's heavy
  deps; golden test still passes. No separate crate needed.
- ✅ UniFFI export CONVERGED (Dev-F1): the wallet FFI now lives in the unified
  facade `crates/postern-sdk` (`src/wallet.rs`: `Wallet` object + `generateWallet`
  + RPC helpers), a thin wrapper over this crate's pure `WalletCore` (untouched).
  `mobile/core` no longer registers its own `setup_scaffolding!` — so exactly ONE
  scaffolding ships (guarded by `mobile/ci/check-one-setup-scaffolding.sh`).
  `cargo run -p postern-sdk --bin uniffi-bindgen -- generate --library <lib>
  --language kotlin|swift` produces the `postern_sdk.kt` / `postern_sdk.swift`
  bindings (imported as `uniffi.postern_sdk.*` / `import postern_sdk`).
- ⏳ Android (Compose + StrongBox + Key Attestation) and iOS (SwiftUI + Secure
  Enclave + App Attest) app shells.
