# Postern Wallet — Android (app shell)

A **Postern Labs** product: a light client / wallet for the ownerless
**Bloch-SIS-PoW** protocol. Package `labs.postern.wallet`. Kotlin + Jetpack
Compose UI over the shared Rust core, exposed through the unified Postern SDK
UniFFI facade (`crates/postern-sdk`; folds in `bloch-mobile`'s `WalletCore`).

> **This is a SKELETON. It is NOT built in this repo** — building it needs the
> Android SDK / Android Studio, the NDK, and the cross-compiled Rust core, none
> of which run in this repo's CI. The **tested** part of the mobile stack is the
> Rust core (`mobile/core`, `bloch-mobile`): pure wallet crypto + RPC shaping,
> unit-tested with a golden byte-compatibility test against the node, and
> UniFFI-exported (host-verified bindings). Everything under `android/` is the
> native shell that wires to that core — idiomatic, but unbuilt here.

## What's here

```
android/
├── settings.gradle.kts
├── build.gradle.kts
├── app/
│   ├── build.gradle.kts            compileSdk 34, Compose, OkHttp, JNA (uniffi runtime)
│   └── src/main/
│       ├── AndroidManifest.xml     INTERNET; strongbox_keystore feature (optional)
│       ├── java/labs/postern/wallet/
│       │   ├── MainActivity.kt         Compose host
│       │   ├── WalletViewModel.kt      generateWallet / Wallet.fromMnemonic; balance; signTxHex
│       │   ├── StrongBoxKey.kt         StrongBox Keystore key + Key Attestation (the Postern Seal)
│       │   ├── NodeRpc.kt              OkHttp POST → node JSON-RPC (bodies/parsing from the core)
│       │   └── ui/WalletScreen.kt      create/restore, address, balance, send stub
│       ├── java/uniffi/postern_sdk/   ← generated postern_sdk.kt goes here (placeholder note)
│       └── jniLibs/                    ← per-ABI libpostern_sdk.so goes here (placeholder note)
└── README.md
```

## Build chain (what a real build does)

The easy path is `./mobile/build-android.sh` (repo root), which runs both steps
below against `-p postern-sdk`. Manually:

1. **Cross-compile the SDK → native libs** (`.so` per ABI), with `cargo-ndk`,
   from the repo root (so `-p` resolves the workspace crate):
   ```bash
   rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
   cargo install cargo-ndk
   cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 \
     -o mobile/android/app/src/main/jniLibs build --release -p postern-sdk
   ```
   (See `app/src/main/jniLibs/PLACE_NATIVE_LIBS_HERE.md`.)

2. **Generate the Kotlin bindings** from the built library:
   ```bash
   cargo run -p postern-sdk --bin uniffi-bindgen -- generate \
     --library mobile/android/app/src/main/jniLibs/arm64-v8a/libpostern_sdk.so \
     --language kotlin --out-dir mobile/android/app/src/main/java
   ```
   → `app/src/main/java/uniffi/postern_sdk/postern_sdk.kt` (imported as
   `uniffi.postern_sdk.*`). See `.../uniffi/postern_sdk/PLACE_GENERATED_BINDINGS_HERE.md`.

3. **Build the app** (needs Android Studio / SDK; not done here):
   ```bash
   ./gradlew :app:assembleDebug
   ```

A real release additionally needs **app signing** (a keystore + signing config)
and a reachable node RPC endpoint (`WalletViewModel.DEFAULT_NODE_ENDPOINT`).

## The pure/impure split

The Rust core is pure: it derives addresses, signs (hybrid Falcon‖ML-DSA), and
**shapes the JSON-RPC request bodies + parses responses** — byte-compatible with
the node (golden test). The Kotlin shell does everything with the outside world:
OkHttp to the node (`NodeRpc.kt`), hardware-backed key storage + device
attestation (`StrongBoxKey.kt`), and the Compose UI.

## Hardware trust — and its honest limit

`StrongBoxKey.kt` generates a StrongBox-backed (discrete HSM) P-256 key and emits
a **Key Attestation** X.509 chain over a node-issued **nonce** — the mobile
**Postern Seal** a verifier checks with `bloch::attestation::verify` (`mobile`
backend). **Honest limit** (see `mobile/README.md` and
`docs/specs/POSTERN-CONTAINER.md`): mobile TEEs are **classical** (P-256). They
do **not** hold the post-quantum wallet key *in* hardware — they **protect it at
rest** (wrap it) and **attest the device/app**. PQ signing runs in the Rust core
in RAM (zeroized on drop). Not every device has StrongBox (fallback to a weaker
TEE-backed key). **Light-client / wallet role only — never a miner.** Nothing
here is audited.
