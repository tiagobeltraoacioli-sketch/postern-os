# Postern Wallet — iOS (app shell)

A **Postern Labs** product: a light client / wallet for the ownerless
**Bloch-SIS-PoW** protocol. Bundle id `labs.postern.wallet`. SwiftUI over the
shared Rust core, exposed through the unified Postern SDK UniFFI facade
(`crates/postern-sdk`; folds in `bloch-mobile`'s `WalletCore`).

> **This is a SKELETON. It is NOT built in this repo** — building it needs Xcode,
> the iOS SDK, and the cross-compiled Rust core (an `.xcframework`), none of
> which run in this repo's CI. There is deliberately **no `.xcodeproj`** here:
> the sources + this README are provided, and you create the Xcode project
> around them (below). The **tested** part of the mobile stack is the Rust core
> (`mobile/core`, `bloch-mobile`): pure wallet crypto + RPC shaping, unit-tested
> with a golden byte-compatibility test against the node, and UniFFI-exported.
> Everything under `ios/` is the native shell — idiomatic, but unbuilt here.

## What's here

```
ios/
├── PosternWallet/
│   ├── PosternWalletApp.swift    @main App entry
│   ├── ContentView.swift         SwiftUI: create/restore, address, balance, send stub
│   ├── WalletStore.swift         ObservableObject: generateWallet / Wallet.fromMnemonic; signTxHex
│   ├── SecureEnclaveKey.swift    Secure Enclave wrap key + App Attest (the Postern Seal)
│   └── NodeRpc.swift             URLSession POST → node JSON-RPC (bodies/parsing from the core)
└── README.md
```

## Xcode setup (what a real build does)

There is no checked-in project; create one and add these sources:

1. **Xcode → New → App**, SwiftUI lifecycle, bundle id `labs.postern.wallet`.
   Delete the template `App`/`ContentView` and add the files in
   `PosternWallet/` to the target.

   The easy path is `./mobile/build-ios.sh` (repo root), which runs the steps
   below against `-p postern-sdk` and emits `mobile/ios/PosternSdk.xcframework`.
   Manually, from the repo root:
   ```bash
   rustup target add aarch64-apple-ios aarch64-apple-ios-sim

   # device + simulator static libs (unified SDK; artifacts under repo target/)
   cargo build --release -p postern-sdk --target aarch64-apple-ios
   cargo build --release -p postern-sdk --target aarch64-apple-ios-sim

   # Swift bindings (postern_sdk.swift + postern_sdkFFI.h + module.modulemap)
   cargo run -p postern-sdk --bin uniffi-bindgen -- generate \
     --library target/aarch64-apple-ios/release/libpostern_sdk.a \
     --language swift --out-dir ./generated

   # bundle the static libs + headers into an .xcframework
   xcodebuild -create-xcframework \
     -library target/aarch64-apple-ios/release/libpostern_sdk.a \
       -headers ./generated \
     -library target/aarch64-apple-ios-sim/release/libpostern_sdk.a \
       -headers ./generated \
     -output ./PosternSdk.xcframework
   ```

3. **Add to the target:**
   - Drag `PosternSdk.xcframework` into the project (Frameworks, Embed & Sign).
   - Add the generated `postern_sdk.swift` to the target's sources. The app
     imports it as `import postern_sdk` (the modulemap names the module).
   - Ensure the generated `module.modulemap` / `postern_sdkFFI.h` are on the
     framework's header search path so Swift can see the C FFI symbols.

4. **Entitlements / capabilities** a real build needs:
   - **App Attest** capability (`com.apple.developer.devicecheck.appattest-environment`)
     for `DCAppAttestService` in `SecureEnclaveKey.swift`.
   - A development team for **code signing** (App Attest + Secure Enclave need a
     real signed app on a real device — neither works in the simulator).
   - A reachable node RPC endpoint (`WalletStore.init(nodeEndpoint:)`); if it is
     plain HTTP, add an ATS exception.

## The pure/impure split

The Rust core is pure: it derives addresses, signs (hybrid Falcon‖ML-DSA), and
**shapes the JSON-RPC request bodies + parses responses** — byte-compatible with
the node (golden test). The Swift shell does everything with the outside world:
URLSession to the node (`NodeRpc.swift`), hardware-backed key storage + device
attestation (`SecureEnclaveKey.swift`), and the SwiftUI views.

## Hardware trust — and its honest limit

`SecureEnclaveKey.swift` creates a **Secure Enclave** P-256 key
(`kSecAttrTokenIDSecureEnclave`) to wrap the wallet secret at rest, and uses
**App Attest** (`DCAppAttestService`) to attest the device/app over a node-issued
**nonce** — the mobile **Postern Seal** a verifier checks with
`bloch::attestation::verify` (`mobile` backend). **Honest limit** (see
`mobile/README.md`): mobile TEEs are **classical** (P-256). They do **not** hold
the post-quantum wallet key *in* hardware — they **protect it at rest** (wrap it)
and **attest the device/app**. PQ signing runs in the Rust core in RAM (zeroized
on drop). **Light-client / wallet role only — never a miner.** Nothing here is
audited.
