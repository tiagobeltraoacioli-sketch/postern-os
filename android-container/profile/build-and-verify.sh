#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Porog (Postern Container) DPC app shell — reproducible debug-APK build + the
# acceptance gate that proves it. This is the "first-ever real build" the toolchain
# README describes: it is NOT deferred-to-VM. Any host with the Android SDK
# (platform android-34 + build-tools 34.0.0) and a JDK 17 can run it.
#
# It runs `./gradlew :app:assembleDebug` and then asserts, via `aapt dump`, that the
# produced APK actually carries:
#   1. the PosternDeviceAdminReceiver (a real DeviceAdminReceiver, BIND_DEVICE_ADMIN,
#      DEVICE_ADMIN_ENABLED + PROFILE_PROVISIONING_COMPLETE intent filters), and
#   2. minSdk 30 / targetSdk 34.
#
# HONESTY: building a debug APK is `built`, not `booted`. It is NOT provisioned on
# hardware, NOT audited, and the release signing config is intentionally absent.
# `built ≠ booted · emulator ≠ hardware · self-checked ≠ audited`. UNAUDITED.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

# ── Toolchain resolution (override via env) ──────────────────────────────────
: "${ANDROID_HOME:=${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}}"
export ANDROID_HOME
export ANDROID_SDK_ROOT="$ANDROID_HOME"
BUILD_TOOLS_VER="${BUILD_TOOLS_VER:-34.0.0}"
AAPT="$ANDROID_HOME/build-tools/$BUILD_TOOLS_VER/aapt"

if [ ! -x "$ANDROID_HOME/platforms/android-34/android.jar" ] 2>/dev/null; then :; fi
[ -d "$ANDROID_HOME/platforms/android-34" ] || {
  echo "FAIL: android-34 platform not found under $ANDROID_HOME/platforms" >&2; exit 2; }
[ -x "$AAPT" ] || { echo "FAIL: aapt not found at $AAPT" >&2; exit 2; }

# Gradle needs sdk.dir; local.properties is git-ignored and per-host.
if [ ! -f local.properties ]; then
  printf 'sdk.dir=%s\n' "$ANDROID_HOME" > local.properties
fi

# JDK 17 required by AGP 8.5. Honour JAVA_HOME if it already points at 17.
java_major() { "$1/bin/java" -version 2>&1 | sed -n 's/.*version "\([0-9]*\).*/\1/p' | head -1; }
if [ -n "${JAVA_HOME:-}" ] && [ "$(java_major "$JAVA_HOME")" = "17" ]; then
  : # good
elif [ -d /usr/local/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home ]; then
  export JAVA_HOME=/usr/local/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home
elif [ -d /opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home ]; then
  export JAVA_HOME=/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home
fi
[ "$(java_major "${JAVA_HOME:-/usr}")" = "17" ] || {
  echo "FAIL: JDK 17 required (AGP 8.5). Set JAVA_HOME to a JDK 17." >&2; exit 2; }

echo "== toolchain =="
echo "  ANDROID_HOME=$ANDROID_HOME"
echo "  JAVA_HOME=$JAVA_HOME"
echo "  aapt=$AAPT"

# ── Build ────────────────────────────────────────────────────────────────────
echo "== ./gradlew :app:assembleDebug =="
# GRADLE_EXTRA_ARGS is optional and word-split on purpose (e.g. "--no-build-cache").
# shellcheck disable=SC2206
extra=(${GRADLE_EXTRA_ARGS:-})
./gradlew --no-daemon "${extra[@]}" :app:assembleDebug

APK="app/build/outputs/apk/debug/app-debug.apk"
[ -f "$APK" ] || { echo "FAIL: expected APK artifact not found at $APK" >&2; exit 1; }
echo "== artifact: $APK ($(du -h "$APK" | cut -f1)) =="

# ── Acceptance assertions ────────────────────────────────────────────────────
badging="$("$AAPT" dump badging "$APK")"
xmltree="$("$AAPT" dump xmltree "$APK" AndroidManifest.xml)"

fail=0
check() { # <description> <grep-pattern> <haystack-var>
  if printf '%s\n' "$3" | grep -qE "$2"; then
    echo "  ok  : $1"
  else
    echo "  FAIL: $1 (pattern: $2)" >&2; fail=1
  fi
}

echo "== acceptance =="
check "minSdk 30"                       "^sdkVersion:'30'"        "$badging"
check "targetSdk 34"                    "^targetSdkVersion:'34'"  "$badging"
check "declares a device-admin component" "provides-component:'device-admin'" "$badging"
check "PosternDeviceAdminReceiver present" 'name.*="labs\.postern\.container\.dpc\.PosternDeviceAdminReceiver"' "$xmltree"
check "BIND_DEVICE_ADMIN gate on receiver" 'android\.permission\.BIND_DEVICE_ADMIN' "$xmltree"
check "DEVICE_ADMIN_ENABLED intent filter"  'android\.app\.action\.DEVICE_ADMIN_ENABLED' "$xmltree"
check "PROFILE_PROVISIONING_COMPLETE filter" 'android\.app\.action\.PROFILE_PROVISIONING_COMPLETE' "$xmltree"

if [ "$fail" -ne 0 ]; then
  echo "ACCEPTANCE: FAILED" >&2; exit 1
fi
echo "ACCEPTANCE: PASSED (built debug APK — UNAUDITED, not provisioned on hardware)"
