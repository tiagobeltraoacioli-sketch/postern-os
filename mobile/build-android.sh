#!/usr/bin/env bash
# Build the unified Postern SDK native lib + Kotlin bindings for Android, and
# drop them into mobile/android/. Run on a host with the Android NDK + Rust.
# NOT run in this repo's sandbox — this is the ready recipe.
#
#   ANDROID_NDK_HOME=/path/to/ndk ./mobile/build-android.sh
#
# Dev-F1 UniFFI convergence: the app now binds the ONE `postern_sdk` facade
# (crates/postern-sdk), NOT the old per-wallet `bloch-mobile` FFI surface. So
# this builds `-p postern-sdk` → libpostern_sdk.so and generates
# uniffi/postern_sdk/postern_sdk.kt.
#
# Prereqs (one-time):
#   rustup target add aarch64-linux-android armv7-linux-androideabi \
#                     x86_64-linux-android i686-linux-android
#   cargo install cargo-ndk
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
ANDROID="$HERE/android"
JNILIBS="$ANDROID/app/src/main/jniLibs"
BINDINGS="$ANDROID/app/src/main/java"   # uniffi writes uniffi/postern_sdk/*.kt here

: "${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME to your NDK path}"

echo "==> building libpostern_sdk.so for all ABIs (release, lean: no rocksdb/libp2p)"
# cargo-ndk maps ABIs -> targets and places the .so under jniLibs/<abi>/. Build
# the unified SDK cdylib (folds the wallet core in behind ONE
# setup_scaffolding!). Run from the repo root so `-p` resolves the workspace crate.
( cd "$REPO" && cargo ndk \
    -t arm64-v8a -t armeabi-v7a -t x86_64 -t x86 \
    -o "$JNILIBS" \
    build --release -p postern-sdk )

echo "==> generating Kotlin bindings from the built library"
# Use the SDK's own uniffi-bindgen bin against one built .so.
LIB="$JNILIBS/arm64-v8a/libpostern_sdk.so"
( cd "$REPO" && cargo run --release -p postern-sdk --bin uniffi-bindgen -- \
    generate --library "$LIB" --language kotlin --out-dir "$BINDINGS" )

echo "==> done."
echo "    .so  -> $JNILIBS/<abi>/libpostern_sdk.so"
echo "    .kt  -> $BINDINGS/uniffi/postern_sdk/postern_sdk.kt"
echo "    Now open mobile/android/ in Android Studio and build the app."
