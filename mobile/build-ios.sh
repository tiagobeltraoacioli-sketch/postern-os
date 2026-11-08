#!/usr/bin/env bash
# Build the unified Postern SDK native lib + Swift bindings for iOS as an
# .xcframework, and drop it + the Swift bindings into mobile/ios/. Run on macOS
# with Xcode + Rust. NOT run in this repo's sandbox — this is the ready recipe.
#
#   ./mobile/build-ios.sh
#
# Dev-F1 UniFFI convergence: the app now binds the ONE `postern_sdk` facade
# (crates/postern-sdk), NOT the old per-wallet `bloch-mobile` FFI surface. So
# this builds `-p postern-sdk` → libpostern_sdk.a and generates postern_sdk.swift
# into a PosternSdk.xcframework.
#
# Prereqs (one-time):
#   rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
IOS="$HERE/ios"
BUILD="$IOS/build"
XCF="$IOS/PosternSdk.xcframework"
mkdir -p "$BUILD"

echo "==> building static libs (release, lean: no rocksdb/libp2p)"
# Build the unified SDK from the workspace root; artifacts land in REPO/target.
( cd "$REPO"
  cargo build --release -p postern-sdk --target aarch64-apple-ios           # device
  cargo build --release -p postern-sdk --target aarch64-apple-ios-sim       # arm sim
  cargo build --release -p postern-sdk --target x86_64-apple-ios            # intel sim
)
TARGETS="$REPO/target"

echo "==> generating Swift bindings from the device library"
( cd "$REPO" && cargo run --release -p postern-sdk --bin uniffi-bindgen -- \
    generate --library "$TARGETS/aarch64-apple-ios/release/libpostern_sdk.a" \
    --language swift --out-dir "$BUILD/swift" )

echo "==> lipo the simulator slices into one fat lib"
mkdir -p "$BUILD/sim"
lipo -create \
  "$TARGETS/aarch64-apple-ios-sim/release/libpostern_sdk.a" \
  "$TARGETS/x86_64-apple-ios/release/libpostern_sdk.a" \
  -output "$BUILD/sim/libpostern_sdk.a"

echo "==> assembling the xcframework (headers from the generated modulemap)"
# uniffi emits postern_sdkFFI.h + .modulemap alongside the .swift; xcframework
# wants a headers dir containing them.
HEADERS="$BUILD/headers"; mkdir -p "$HEADERS"
cp "$BUILD/swift/"*.h "$HEADERS/" 2>/dev/null || true
cp "$BUILD/swift/"*.modulemap "$HEADERS/module.modulemap" 2>/dev/null || true
rm -rf "$XCF"
xcodebuild -create-xcframework \
  -library "$TARGETS/aarch64-apple-ios/release/libpostern_sdk.a" -headers "$HEADERS" \
  -library "$BUILD/sim/libpostern_sdk.a" -headers "$HEADERS" \
  -output "$XCF"

echo "==> done."
echo "    xcframework -> $XCF"
echo "    swift       -> $BUILD/swift/postern_sdk.swift  (add to the Xcode target)"
echo "    Create an Xcode app around mobile/ios/PosternWallet/ and link PosternSdk.xcframework."
