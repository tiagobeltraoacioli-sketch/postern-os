#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# capture-android-attestation.sh — reproducible Android Key-Attestation capture.
#
# Regenerates the REAL (non-synthetic) Android Key-Attestation vectors consumed
# by the Rust test module `mobile::captured_emulator_attestation` in
#   crates/postern-seal-companion/src/mobile.rs
# so those vectors are reproducible instead of a one-off. It:
#
#   1. builds a stripped, android.jar-only capture APK (no Gradle/AndroidX),
#   2. boots an Android emulator (default: API-34 google_apis x86_64),
#   3. runs the APK, which generates an EC P-256 key in AndroidKeyStore with our
#      attestation challenge (nonce) and StrongBox OFF — the exact path
#      StrongBoxKey.generateTeeFallbackKey drives on hardware,
#   4. extracts the leaf-first DER attestation chain + nonce the Keystore minted,
#   5. drops chain-0.der, chain-1.der, ..., nonce.bin where the test expects them
#      (crates/postern-seal-companion/src/testdata/), then
#   6. can re-run the Rust test to prove the drop verifies (offline).
#
# HONEST LIMIT: the google_apis emulator's KeyMint is a SOFTWARE reference
# implementation (attested securityLevel = Software(0), RootOfTrust NOT
# hardware-enforced). This reproduces a real Keystore-minted chain that flows
# through the whole parse+evaluate pipeline; it is NOT a StrongBox / secure-
# element attestation and makes no hardware security claim.
# `captured != StrongBox-hardware-attested`.
#
# This script NEVER fabricates a vector: every DER it writes is produced by a
# live emulator run. If the SDK/emulator is unavailable it fails loud and writes
# nothing. See CAPTURE.md (../../CAPTURE.md) for the full runbook + provenance.
#
# Usage:
#   capture-android-attestation.sh check       # tool/SDK readiness, no side effects
#   capture-android-attestation.sh build       # build the capture APK only
#   capture-android-attestation.sh capture     # full pipeline (default)
#   capture-android-attestation.sh verify      # run the Rust vector test (offline)
#
# Key options (see --help):
#   --sdk DIR         Android SDK root (default: $ANDROID_SDK_ROOT/$ANDROID_HOME/~/Library/Android/sdk)
#   --out DIR         where to drop the DER files (default: the testdata dir)
#   --avd NAME        emulator AVD name (default: postern-capture)
#   --api N           API level (default: 34)
#   --nonce-str S     32-byte-or-shorter ASCII nonce (default: the committed nonce)
#   --nonce-hex H     nonce as hex (overrides --nonce-str)
#   --overwrite       allow overwriting existing DER files in --out
#   --keep-emulator   do not kill the emulator we started on exit
#   --install-sdk     sdkmanager-install missing SDK packages before running

set -Eeuo pipefail

# ── Paths ───────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
APP_DIR="$SCRIPT_DIR/app"
# tools/capture-android-attestation -> tools -> postern-seal-companion (crate root)
CRATE_DIR="$(cd -- "$SCRIPT_DIR/../.." >/dev/null 2>&1 && pwd -P)"
TESTDATA_DIR="$CRATE_DIR/src/testdata"

# ── Defaults ────────────────────────────────────────────────────────────────
CMD="capture"
SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$HOME/Library/Android/sdk}}"
OUT_DIR="$TESTDATA_DIR"
AVD_NAME="postern-capture"
API_LEVEL="34"
SYS_TAG="google_apis"
ABI="x86_64"
NONCE_STR="postern-seal-mobile-attest-nnc32"   # == committed testdata/nonce.bin
NONCE_HEX=""
OVERWRITE=0
KEEP_EMULATOR=0
INSTALL_SDK=0
BOOT_TIMEOUT=600      # seconds to wait for the emulator to finish booting
CAPTURE_TIMEOUT=180   # seconds to wait for the on-device capture to complete
PKG="labs.postern.capture"
ACTIVITY=".CaptureActivity"

# State used by cleanup.
EMULATOR_PID=""
WE_STARTED_EMULATOR=0
BUILD_DIR=""

# ── Logging ─────────────────────────────────────────────────────────────────
c_red=$'\033[31m'; c_grn=$'\033[32m'; c_yel=$'\033[33m'; c_dim=$'\033[2m'; c_rst=$'\033[0m'
if [ ! -t 2 ]; then c_red=""; c_grn=""; c_yel=""; c_dim=""; c_rst=""; fi
log()  { printf '%s[capture]%s %s\n' "$c_dim" "$c_rst" "$*" >&2; }
ok()   { printf '%s[capture] OK%s %s\n' "$c_grn" "$c_rst" "$*" >&2; }
warn() { printf '%s[capture] WARN%s %s\n' "$c_yel" "$c_rst" "$*" >&2; }
die()  { printf '%s[capture] FATAL%s %s\n' "$c_red" "$c_rst" "$*" >&2; exit 1; }

usage() { sed -n '2,60p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

# ── Arg parsing ─────────────────────────────────────────────────────────────
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            check|build|capture|verify) CMD="$1" ;;
            --sdk)           SDK_ROOT="${2:?}"; shift ;;
            --out)           OUT_DIR="${2:?}"; shift ;;
            --avd)           AVD_NAME="${2:?}"; shift ;;
            --api)           API_LEVEL="${2:?}"; shift ;;
            --sys-tag)       SYS_TAG="${2:?}"; shift ;;
            --abi)           ABI="${2:?}"; shift ;;
            --nonce-str)     NONCE_STR="${2:?}"; NONCE_HEX="" ; shift ;;
            --nonce-hex)     NONCE_HEX="${2:?}"; shift ;;
            --overwrite)     OVERWRITE=1 ;;
            --keep-emulator) KEEP_EMULATOR=1 ;;
            --install-sdk)   INSTALL_SDK=1 ;;
            --boot-timeout)  BOOT_TIMEOUT="${2:?}"; shift ;;
            -h|--help)       usage; exit 0 ;;
            *) die "unknown argument: $1 (try --help)" ;;
        esac
        shift
    done
}

# ── SDK tool resolution ─────────────────────────────────────────────────────
# Prints the newest build-tools dir under the SDK, or empty.
newest_build_tools() {
    local bt="$SDK_ROOT/build-tools"
    [ -d "$bt" ] || return 0
    # Highest version by natural sort.
    ls -1 "$bt" 2>/dev/null | sort -V | tail -1
}

resolve_tools() {
    ANDROID_JAR="$SDK_ROOT/platforms/android-$API_LEVEL/android.jar"
    ADB="$SDK_ROOT/platform-tools/adb"
    EMULATOR_BIN="$SDK_ROOT/emulator/emulator"
    SDKMANAGER="$SDK_ROOT/cmdline-tools/latest/bin/sdkmanager"
    AVDMANAGER="$SDK_ROOT/cmdline-tools/latest/bin/avdmanager"
    local btv; btv="$(newest_build_tools)"
    if [ -n "$btv" ]; then
        BUILD_TOOLS="$SDK_ROOT/build-tools/$btv"
        AAPT="$BUILD_TOOLS/aapt"
        AAPT2="$BUILD_TOOLS/aapt2"
        D8="$BUILD_TOOLS/d8"
        ZIPALIGN="$BUILD_TOOLS/zipalign"
        APKSIGNER="$BUILD_TOOLS/apksigner"
    else
        BUILD_TOOLS=""; AAPT=""; AAPT2=""; D8=""; ZIPALIGN=""; APKSIGNER=""
    fi
    # javac/keytool from the JDK on PATH.
    JAVAC="$(command -v javac || true)"
    KEYTOOL="$(command -v keytool || true)"
}

have() { [ -n "${1:-}" ] && [ -x "$1" ]; }

# Report readiness of everything. Returns nonzero if a hard requirement is
# missing. NO side effects, NO fabrication.
cmd_check() {
    resolve_tools
    local missing=0
    printf '\n  Android capture harness — environment check\n\n' >&2
    printf '  SDK root : %s\n' "$SDK_ROOT" >&2
    printf '  Out dir  : %s\n' "$OUT_DIR" >&2
    printf '  Crate    : %s\n\n' "$CRATE_DIR" >&2

    _row() { # name path
        if have "$2"; then printf '  %s %-14s %s\n' "${c_grn}[ok]${c_rst}" "$1" "$2" >&2
        else printf '  %s %-14s (missing)\n' "${c_red}[--]${c_rst}" "$1" >&2; missing=$((missing+1)); fi
    }
    _file() { # name path
        if [ -f "$2" ]; then printf '  %s %-14s %s\n' "${c_grn}[ok]${c_rst}" "$1" "$2" >&2
        else printf '  %s %-14s (missing)\n' "${c_red}[--]${c_rst}" "$1" >&2; missing=$((missing+1)); fi
    }
    _row javac "$JAVAC"
    _row keytool "$KEYTOOL"
    _row adb "$ADB"
    _row emulator "$EMULATOR_BIN"
    _row aapt "$AAPT"
    _row d8 "$D8"
    _row zipalign "$ZIPALIGN"
    _row apksigner "$APKSIGNER"
    _file android.jar "$ANDROID_JAR"
    # Optional-but-recommended.
    if command -v openssl >/dev/null 2>&1; then
        printf '  %s %-14s %s\n' "${c_grn}[ok]${c_rst}" openssl "$(command -v openssl)" >&2
    else
        printf '  %s %-14s (recommended, for DER validation)\n' "${c_yel}[..]${c_rst}" openssl >&2
    fi
    if command -v cargo >/dev/null 2>&1; then
        printf '  %s %-14s %s\n' "${c_grn}[ok]${c_rst}" cargo "$(command -v cargo)" >&2
    else
        printf '  %s %-14s (needed only for `verify`)\n' "${c_yel}[..]${c_rst}" cargo >&2
    fi

    # AVD presence (informational).
    if have "$EMULATOR_BIN"; then
        if "$EMULATOR_BIN" -list-avds 2>/dev/null | grep -qx "$AVD_NAME"; then
            printf '\n  AVD "%s": present\n' "$AVD_NAME" >&2
        else
            printf '\n  AVD "%s": not created yet (capture will create it if packages exist)\n' "$AVD_NAME" >&2
        fi
    fi

    echo >&2
    if [ "$missing" -eq 0 ]; then
        ok "environment is ready to build + capture"
        return 0
    fi
    warn "$missing required tool(s) missing — install the SDK (see CAPTURE.md) or pass --install-sdk"
    return 1
}

# ── SDK install (opt-in) ────────────────────────────────────────────────────
install_sdk_packages() {
    have "$SDKMANAGER" || die "sdkmanager not found at $SDKMANAGER — install cmdline-tools first (see CAPTURE.md)"
    log "accepting licenses + installing SDK packages (this downloads ~1-2 GB)"
    yes | "$SDKMANAGER" --licenses >/dev/null 2>&1 || true
    "$SDKMANAGER" \
        "platform-tools" \
        "emulator" \
        "build-tools;34.0.0" \
        "platforms;android-$API_LEVEL" \
        "system-images;android-$API_LEVEL;$SYS_TAG;$ABI"
    ok "SDK packages installed"
}

ensure_avd() {
    have "$AVDMANAGER" || die "avdmanager not found at $AVDMANAGER"
    if "$EMULATOR_BIN" -list-avds 2>/dev/null | grep -qx "$AVD_NAME"; then
        log "AVD $AVD_NAME already exists"
        return 0
    fi
    log "creating AVD $AVD_NAME (system-images;android-$API_LEVEL;$SYS_TAG;$ABI)"
    echo "no" | "$AVDMANAGER" create avd \
        --name "$AVD_NAME" \
        --package "system-images;android-$API_LEVEL;$SYS_TAG;$ABI" \
        --device "pixel_6" --force
    ok "AVD $AVD_NAME created"
}

# ── APK build ───────────────────────────────────────────────────────────────
require_build_tools() {
    have "$JAVAC"      || die "javac not on PATH (install a JDK)"
    have "$KEYTOOL"    || die "keytool not on PATH (install a JDK)"
    [ -f "$ANDROID_JAR" ] || die "android.jar missing: $ANDROID_JAR (install platforms;android-$API_LEVEL)"
    have "$D8"         || die "d8 missing in build-tools ($BUILD_TOOLS)"
    have "$ZIPALIGN"   || die "zipalign missing in build-tools ($BUILD_TOOLS)"
    have "$APKSIGNER"  || die "apksigner missing in build-tools ($BUILD_TOOLS)"
    have "$AAPT" || have "$AAPT2" || die "neither aapt nor aapt2 found in build-tools ($BUILD_TOOLS)"
}

# Build capture.apk into $BUILD_DIR, echo its path.
build_apk() {
    require_build_tools
    BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/postern-capture-build.XXXXXX")"
    local classes="$BUILD_DIR/classes"
    mkdir -p "$classes"

    log "javac -> $classes"
    # shellcheck disable=SC2046
    "$JAVAC" -source 8 -target 8 -classpath "$ANDROID_JAR" -d "$classes" \
        $(find "$APP_DIR/src" -name '*.java')

    log "d8 -> classes.dex (min-api 24)"
    # shellcheck disable=SC2046
    "$D8" --lib "$ANDROID_JAR" --min-api 24 --output "$BUILD_DIR" \
        $(find "$classes" -name '*.class')
    [ -f "$BUILD_DIR/classes.dex" ] || die "d8 produced no classes.dex"

    log "package resources+manifest -> base.apk"
    if have "$AAPT"; then
        "$AAPT" package -f -M "$APP_DIR/AndroidManifest.xml" -I "$ANDROID_JAR" -F "$BUILD_DIR/base.apk"
        ( cd "$BUILD_DIR" && "$AAPT" add -f base.apk classes.dex >/dev/null )
    else
        "$AAPT2" link -o "$BUILD_DIR/base.apk" -I "$ANDROID_JAR" \
            --manifest "$APP_DIR/AndroidManifest.xml"
        # aapt2 has no `add`; splice the dex with the zip tool.
        ( cd "$BUILD_DIR" && zip -q -j base.apk classes.dex )
    fi

    log "zipalign -> aligned.apk"
    "$ZIPALIGN" -f 4 "$BUILD_DIR/base.apk" "$BUILD_DIR/aligned.apk"

    # Debug signing key (throwaway; the emulator accepts any signature).
    local ks="$BUILD_DIR/debug.keystore"
    log "generate throwaway debug signing key"
    "$KEYTOOL" -genkeypair -v -keystore "$ks" -storepass android -keypass android \
        -alias androiddebugkey -keyalg RSA -keysize 2048 -validity 365 \
        -dname "CN=Postern Capture Debug,O=Postern Labs,C=00" >/dev/null 2>&1

    log "apksigner -> capture.apk"
    "$APKSIGNER" sign --ks "$ks" --ks-pass pass:android --key-pass pass:android \
        --out "$BUILD_DIR/capture.apk" "$BUILD_DIR/aligned.apk" >/dev/null 2>&1
    "$APKSIGNER" verify "$BUILD_DIR/capture.apk" >/dev/null 2>&1 \
        || die "apksigner could not verify the freshly-signed APK"

    ok "built $BUILD_DIR/capture.apk"
    printf '%s\n' "$BUILD_DIR/capture.apk"
}

# ── Emulator lifecycle ──────────────────────────────────────────────────────
adb() { "$ADB" "$@"; }

boot_emulator() {
    have "$EMULATOR_BIN" || die "emulator not found: $EMULATOR_BIN"
    have "$ADB"          || die "adb not found: $ADB"
    ensure_avd

    # Reuse an already-running device if present.
    if adb devices | awk 'NR>1 && $2=="device"{found=1} END{exit !found}'; then
        warn "an adb device is already online — reusing it (not starting a new emulator)"
        return 0
    fi

    log "booting emulator $AVD_NAME (headless, swiftshader) — up to ${BOOT_TIMEOUT}s"
    "$EMULATOR_BIN" -avd "$AVD_NAME" \
        -no-window -no-audio -no-boot-anim -no-snapshot \
        -gpu swiftshader_indirect -read-only \
        >"${BUILD_DIR:-/tmp}/emulator.log" 2>&1 &
    EMULATOR_PID=$!
    WE_STARTED_EMULATOR=1

    adb start-server >/dev/null 2>&1 || true
    adb wait-for-device

    local deadline=$(( $(date +%s) + BOOT_TIMEOUT ))
    while :; do
        local booted; booted="$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')"
        if [ "$booted" = "1" ]; then break; fi
        if ! kill -0 "$EMULATOR_PID" 2>/dev/null; then
            die "emulator process exited during boot (see ${BUILD_DIR:-/tmp}/emulator.log)"
        fi
        if [ "$(date +%s)" -ge "$deadline" ]; then
            die "emulator did not finish booting within ${BOOT_TIMEOUT}s"
        fi
        sleep 2
    done
    adb shell input keyevent 82 >/dev/null 2>&1 || true  # dismiss keyguard
    ok "emulator booted"
}

# ── Nonce resolution ────────────────────────────────────────────────────────
# Writes the resolved nonce bytes to $1, echoes its base64 (NO_WRAP).
resolve_nonce() {
    local out="$1"
    if [ -n "$NONCE_HEX" ]; then
        # Strip whitespace; xxd -r -p decodes hex to bytes.
        printf '%s' "$NONCE_HEX" | tr -d ' \n\r\t' | xxd -r -p > "$out"
    else
        printf '%s' "$NONCE_STR" > "$out"
    fi
    # base64 without newlines (portable across GNU/BSD base64).
    base64 < "$out" | tr -d '\n'
}

# ── The capture ─────────────────────────────────────────────────────────────
run_capture() {
    local apk="$1"
    local remote_dir="/sdcard/Android/data/$PKG/files"
    local nonce_local="${BUILD_DIR:-/tmp}/nonce.bin"
    local nonce_b64; nonce_b64="$(resolve_nonce "$nonce_local")"

    log "installing capture APK"
    adb install -r -g "$apk" >/dev/null 2>&1 || adb install -r "$apk" >/dev/null

    log "clearing prior capture artifacts on device"
    adb shell "run-as $PKG rm -f $remote_dir/capture.ok $remote_dir/capture.err $remote_dir/chain-*.der $remote_dir/nonce.bin" 2>/dev/null || true
    adb shell "rm -f $remote_dir/capture.ok $remote_dir/capture.err $remote_dir/chain-*.der $remote_dir/nonce.bin" 2>/dev/null || true
    adb logcat -c 2>/dev/null || true

    log "launching $PKG/$ACTIVITY with our nonce"
    adb shell am start -W -n "$PKG/$ACTIVITY" --es nonce_b64 "$nonce_b64" >/dev/null

    # Wait for capture.ok (success) or capture.err (loud device-side failure).
    local deadline=$(( $(date +%s) + CAPTURE_TIMEOUT ))
    local count=""
    while :; do
        if adb shell "test -f $remote_dir/capture.ok" 2>/dev/null; then
            count="$(adb shell "cat $remote_dir/capture.ok" 2>/dev/null | tr -d '\r\n ')"
            break
        fi
        if adb shell "test -f $remote_dir/capture.err" 2>/dev/null; then
            local err; err="$(adb shell "cat $remote_dir/capture.err" 2>/dev/null | tr -d '\r')"
            die "on-device capture FAILED: $err"
        fi
        if [ "$(date +%s)" -ge "$deadline" ]; then
            die "capture did not complete within ${CAPTURE_TIMEOUT}s (see 'adb logcat -s POSTERN_CAP')"
        fi
        sleep 1
    done
    [ -n "$count" ] || die "capture.ok present but empty (chain length unknown)"
    log "device reports chain length = $count"

    # Pull into a staging dir first; only promote to $OUT_DIR after validation.
    local stage="${BUILD_DIR:-/tmp}/pull"
    mkdir -p "$stage"
    adb pull "$remote_dir/nonce.bin" "$stage/nonce.bin" >/dev/null
    local i=0
    while [ "$i" -lt "$count" ]; do
        adb pull "$remote_dir/chain-$i.der" "$stage/chain-$i.der" >/dev/null
        i=$((i+1))
    done

    validate_capture "$stage" "$count" "$nonce_local"
    promote_capture "$stage" "$count"
}

# Validate the pulled artifacts BEFORE touching $OUT_DIR.
validate_capture() {
    local stage="$1" count="$2" nonce_local="$3"

    # Nonce must match exactly what we asked for.
    if ! cmp -s "$stage/nonce.bin" "$nonce_local"; then
        die "pulled nonce.bin does not match the requested nonce — refusing (possible truncation)"
    fi

    # Each cert must be well-formed DER (if openssl is available) and non-empty.
    local i=0
    while [ "$i" -lt "$count" ]; do
        local f="$stage/chain-$i.der"
        [ -s "$f" ] || die "chain-$i.der is empty — refusing"
        if command -v openssl >/dev/null 2>&1; then
            openssl x509 -in "$f" -inform DER -noout >/dev/null 2>&1 \
                || die "chain-$i.der is not parseable X.509 DER — refusing (truncated capture?)"
        fi
        i=$((i+1))
    done

    # The leaf must actually carry the Android Key-Attestation extension
    # (OID 1.3.6.1.4.1.11129.2.1.17) — otherwise it is not an attestation chain.
    if command -v openssl >/dev/null 2>&1; then
        if ! openssl x509 -in "$stage/chain-0.der" -inform DER -noout -text 2>/dev/null \
             | grep -q '1.3.6.1.4.1.11129.2.1.17'; then
            die "captured leaf carries no Key-Attestation extension (1.3.6.1.4.1.11129.2.1.17) — refusing"
        fi
    fi
    ok "capture validated: $count-cert chain, nonce matches, leaf carries the attestation extension"
}

# Copy validated artifacts into $OUT_DIR (guarding existing files unless --overwrite).
promote_capture() {
    local stage="$1" count="$2"
    mkdir -p "$OUT_DIR"

    if [ "$OVERWRITE" -ne 1 ]; then
        local existing=""
        for f in nonce.bin $(seq -f 'chain-%g.der' 0 $((count-1))); do
            [ -e "$OUT_DIR/$f" ] && existing="$existing $f"
        done
        if [ -n "$existing" ]; then
            die "refusing to overwrite existing file(s) in $OUT_DIR:$existing
    Re-run with --overwrite to replace them, or --out DIR to write elsewhere.
    (The committed vectors are intentionally protected; see CAPTURE.md.)"
        fi
    fi

    cp "$stage/nonce.bin" "$OUT_DIR/nonce.bin"
    local i=0
    while [ "$i" -lt "$count" ]; do
        cp "$stage/chain-$i.der" "$OUT_DIR/chain-$i.der"
        i=$((i+1))
    done
    ok "dropped nonce.bin + chain-0..$((count-1)).der into $OUT_DIR"

    # Print the new leaf-first chain's validity window + a suggested pinned
    # verifier clock, because a FRESH capture has a NEW short-lived emulator
    # intermediate. A maintainer may need to update CAPTURE_CLOCK_UNIX /
    # PROVENANCE.md in the crate (files this script does NOT own/modify).
    print_reproduce_hint "$count"
}

print_reproduce_hint() {
    local count="$1"
    command -v openssl >/dev/null 2>&1 || return 0
    warn "a fresh capture mints a NEW emulator intermediate with NEW validity dates."
    warn "if this REPLACED the committed vectors, a maintainer must re-pin the test clock:"
    local i=0
    while [ "$i" -lt "$count" ]; do
        local subj dates
        subj="$(openssl x509 -in "$OUT_DIR/chain-$i.der" -inform DER -noout -subject 2>/dev/null)"
        dates="$(openssl x509 -in "$OUT_DIR/chain-$i.der" -inform DER -noout -dates 2>/dev/null | tr '\n' ' ')"
        printf '    chain-%d: %s | %s\n' "$i" "$subj" "$dates" >&2
        i=$((i+1))
    done
    # Suggest a clock at the intermediate's notBefore + 1 day, if we can parse it.
    if [ "$count" -ge 2 ]; then
        local nb
        nb="$(openssl x509 -in "$OUT_DIR/chain-1.der" -inform DER -noout -startdate 2>/dev/null | cut -d= -f2)"
        [ -n "$nb" ] && warn "pick CAPTURE_CLOCK_UNIX inside chain-1's window (e.g. just after: $nb)."
    fi
    warn "NOTE: this script does not edit mobile.rs/PROVENANCE.md — that re-pin is a manual, reviewed step."
}

# ── Verify (offline) ────────────────────────────────────────────────────────
cmd_verify() {
    command -v cargo >/dev/null 2>&1 || die "cargo not found — needed to run the vector test"
    log "running the Rust vector test over whatever is in the testdata dir (OFFLINE, no network)"
    ( cd "$CRATE_DIR" && cargo test -p postern-seal-companion --features mobile-attest \
        captured_emulator_attestation -- --nocapture )
    ok "captured_emulator_attestation vectors verify"
}

# ── Cleanup ─────────────────────────────────────────────────────────────────
cleanup() {
    local rc=$?
    if [ "$WE_STARTED_EMULATOR" -eq 1 ] && [ -n "$EMULATOR_PID" ] && [ "$KEEP_EMULATOR" -ne 1 ]; then
        if kill -0 "$EMULATOR_PID" 2>/dev/null; then
            log "shutting down the emulator we started (pid $EMULATOR_PID)"
            adb emu kill >/dev/null 2>&1 || kill "$EMULATOR_PID" 2>/dev/null || true
        fi
    fi
    [ -n "$BUILD_DIR" ] && [ -d "$BUILD_DIR" ] && rm -rf "$BUILD_DIR" 2>/dev/null || true
    exit "$rc"
}

# ── Main ────────────────────────────────────────────────────────────────────
main() {
    parse_args "$@"
    trap cleanup EXIT INT TERM

    case "$CMD" in
        check)  cmd_check ;;
        verify) cmd_verify ;;
        build)
            resolve_tools
            local apk; apk="$(build_apk)"
            ok "APK ready: $apk (build dir kept until exit)"
            KEEP_EMULATOR=1  # nothing to stop; harmless
            ;;
        capture)
            resolve_tools
            [ "$INSTALL_SDK" -eq 1 ] && install_sdk_packages && resolve_tools
            log "building capture APK"
            local apk; apk="$(build_apk)"
            boot_emulator
            run_capture "$apk"
            ok "capture complete."
            if command -v cargo >/dev/null 2>&1 && [ "$OUT_DIR" = "$TESTDATA_DIR" ]; then
                log "auto-verifying the dropped vectors"
                cmd_verify || warn "vectors did not verify — a fresh capture likely needs the test clock re-pinned (see hint above)"
            fi
            ;;
        *) die "unknown command: $CMD" ;;
    esac
}

# Only run when executed directly; sourcing (e.g. from the offline self-test in
# CAPTURE.md) exposes the functions without booting anything.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
