# jniLibs — generated

`libpostern_sdk.so` (per ABI: arm64-v8a, armeabi-v7a, x86_64, x86) lands here.
Generate it: `ANDROID_NDK_HOME=... ../../../../../../build-android.sh` (repo:
`mobile/build-android.sh`). Not committed — built from the unified Postern SDK
(`crates/postern-sdk`, which folds in `mobile/core`'s `WalletCore`; lean,
`default-features=false`, no rocksdb/libp2p).
