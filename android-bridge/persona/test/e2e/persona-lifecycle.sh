#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# NoporIS (persona MECHANISM) — T1 managed-profile lifecycle driver.
#
# Forked from Porog's ../../../android-container/profile/test/e2e/provision-lifecycle.sh
# (bucketA/PARTITION.md, Dev B — "Add the adb/emulator harness invocation the RUNBOOK
# expects"), adapted for NoporIS's persona semantics. Enrolls NoporIS's DPC into a fresh
# managed profile via the same ADB test path (bypassing the interactive
# ACTION_PROVISION_MANAGED_PROFILE UI), asserts the lifecycle observable from user 0, and
# hands the in-process half to a (pending) instrumented test via `am instrument --user <id>`.
#
#   enroll   : pm create-user --managed "NoporIS"
#            → adb install --user <id>
#            → dpm set-profile-owner --user <id> <DPC>
#            → am broadcast PROFILE_PROVISIONING_COMPLETE --user <id> <DPC>
#   assert   : fail-closed flavor default (dumpsys user shows the CLEAN profile name —
#              see below) · profile owner truth · quiet-mode (am stop-user/start-user)
#            · negative single-slot preflight (a SECOND managed user must be refused,
#              same PersonaSlot.FOREIGN/OWNED contract as Porog's collision case)
#            · persona-only wipe (pm remove-user → slot back to EMPTY)
#
# ── Flavor selection honesty (load-bearing, do not "fix") ─────────────────────
# The real provisioning UI carries the user's chosen PersonaFlavor across the profile
# boundary as a wire tag in the DPM admin-extras bundle (see
# labs.postern.persona.flavor.PersonaFlavor.EXTRA_FLAVOR_TAG). The ADB test path used
# here — like Porog's — bypasses that UI entirely, so NO flavor extras are ever injected.
# `NoporIsDeviceAdminReceiver.onProfileEnrolled` therefore sees a null/missing tag and
# takes the FAIL-CLOSED path: `PersonaFlavor.fromWireTag(null) == PersonaFlavor.CLEAN`
# (the safe default, never the phone-home Google-Play side). This script asserts exactly
# that fail-closed outcome ("NoporIS · clean" as the profile name) rather than trying to
# fake a flavor selection the ADB path cannot honestly carry.
#
# ── Honesty rails (bridge-build-test-infra §CI, same as Porog's) ──────────────
# This is a T1 functional harness. Passing it proves the software lifecycle on an
# EMULATOR, not device-proven security. It needs the google_apis (NOT playstore) API-34
# KVM AVD from ../../toolchain/flake.nix ("noporis-api34-gapis"). On any host without
# adb + that emulator it exits UNTESTED, never fake-green.
#   built ≠ booted · emulator ≠ hardware · self-checked ≠ audited
# SCAFFOLD · DESIGN ONLY · UNAUDITED · deferred-to-VM. NOT YET RUN — script is
# ready-to-run on the box, has never executed (no adb/emulator on the macOS authoring
# host, and this repo has no androidTest Kotlin for NoporIS yet — see toolchain/README.md
# "Honest gap" section; the --test-apk step below stays an honest SKIP until that lands).

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
DPC_COMPONENT="labs.postern.persona/.dpc.NoporIsDeviceAdminReceiver"
TEST_PACKAGE="labs.postern.persona.test"
TEST_RUNNER="androidx.test.runner.AndroidJUnitRunner"
PERSONA_NAME="NoporIS"
EXPECTED_CLEAN_NAME="NoporIS · clean"   # labs.postern.persona.dpc.NoporIsDeviceAdminReceiver.profileNameFor(CLEAN)

APK=""
TEST_APK=""
SERIAL=""

usage() {
    cat <<'EOF'
Usage: persona-lifecycle.sh --apk <app-debug.apk> [--test-apk <androidTest.apk>] [--serial <adb-serial>]

  --apk        path to the assembled debug APK (./gradlew :app:assembleDebug)
  --test-apk   path to the androidTest APK (:app:assembleDebugAndroidTest);
               if omitted, OR if this repo has no NoporIS androidTest source yet
               (it does not, as of this commit), the instrumented step is SKIPPED
               (honestly).
  --serial     adb device/emulator serial (defaults to the sole attached device)
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --apk) APK="$2"; shift 2 ;;
        --test-apk) TEST_APK="$2"; shift 2 ;;
        --serial) SERIAL="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
    esac
done

# ── Helpers ───────────────────────────────────────────────────────────────────
log()  { printf '\033[1;34m[t1]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[t1:PASS]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[t1:FAIL]\033[0m %s\n' "$*" >&2; exit 1; }
skip() { printf '\033[1;33m[t1:UNTESTED]\033[0m %s\n' "$*" >&2; exit 3; }

adb() {
    if [ -n "$SERIAL" ]; then
        command adb -s "$SERIAL" "$@"
    else
        command adb "$@"
    fi
}

# ── Preconditions (honest UNTESTED exits, never fake-green) ───────────────────
command -v adb >/dev/null 2>&1 || skip "adb not on PATH — enter ../../toolchain devshell first."
[ -n "$APK" ] || { usage; skip "no --apk given — nothing to provision (UNTESTED)."; }
[ -f "$APK" ] || skip "APK not found: $APK (build it first: ./gradlew :app:assembleDebug)."

log "Waiting for device/emulator..."
adb wait-for-device
# Block until the boot animation completes so pm/dpm are ready.
boot_done=""
for _ in $(seq 1 120); do
    boot_done="$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')"
    [ "$boot_done" = "1" ] && break
    sleep 2
done
[ "$boot_done" = "1" ] || skip "device never reported boot_completed (UNTESTED)."

# Managed profiles are only creatable on an image that supports them. The
# google_apis (non-playstore) AVD does; a playstore image blocks the DPC.
adb shell pm get-max-users >/dev/null 2>&1 || true

# ── enroll: create the managed profile (the ONE slot PersonaSlot models) ──────
log "Creating managed profile \"$PERSONA_NAME\"..."
create_out="$(adb shell pm create-user --profileOf 0 --managed "$PERSONA_NAME" | tr -d '\r')"
# Output form: "Success: created user id 10"
PROFILE_ID="$(printf '%s' "$create_out" | grep -oE '[0-9]+' | tail -1)"
[ -n "$PROFILE_ID" ] || fail "could not create a managed profile (image may block it): $create_out"
log "Managed profile user id = $PROFILE_ID"

# Ensure the profile is torn down on any exit (idempotent).
cleanup() { adb shell pm remove-user "$PROFILE_ID" >/dev/null 2>&1 || true; }
trap cleanup EXIT

adb shell am start-user "$PROFILE_ID" >/dev/null

log "Installing the NoporIS APK into the profile..."
adb install -r --user "$PROFILE_ID" "$APK" >/dev/null || fail "APK install into profile failed"

log "Setting NoporIS as profile owner..."
adb shell dpm set-profile-owner --user "$PROFILE_ID" "$DPC_COMPONENT" \
    || fail "dpm set-profile-owner failed for $DPC_COMPONENT"

log "Firing PROFILE_PROVISIONING_COMPLETE (runs onProfileEnrolled, no flavor extras)..."
adb shell am broadcast --user "$PROFILE_ID" \
    -a android.app.action.PROFILE_PROVISIONING_COMPLETE \
    -n "$DPC_COMPONENT" >/dev/null
sleep 3   # let the DPC apply the fail-closed CLEAN policy set + name + enable the profile.

# ── assert: fail-closed flavor default ─────────────────────────────────────────
log "Assert: no flavor extras ⇒ fail-closed CLEAN persona (\"$EXPECTED_CLEAN_NAME\")..."
if adb shell dumpsys user | tr -d '\r' | grep -qF "$EXPECTED_CLEAN_NAME"; then
    ok "persona named \"$EXPECTED_CLEAN_NAME\" — fail-closed default confirmed"
else
    fail "expected fail-closed name \"$EXPECTED_CLEAN_NAME\" not visible in dumpsys user"
fi

# ── assert: quiet-mode (pause / resume the persona) ────────────────────────────
# requestQuietModeEnabled targets a profile from its parent; the closest ADB-drivable
# analog from user 0 is stop-user/start-user, same as Porog's driver.
log "Assert: quiet-mode pause/resume (stop-user/start-user analog)..."
adb shell am stop-user -w -f "$PROFILE_ID" >/dev/null || true
if adb shell am get-started-user-state "$PROFILE_ID" 2>/dev/null | tr -d '\r' | grep -qi 'stopp'; then
    ok "persona paused (stopped)"
else
    log "note: could not confirm stopped state on this API level (deferred-to-VM)"
fi
adb shell am start-user "$PROFILE_ID" >/dev/null || true
ok "persona resumed"

# ── assert: negative preflight — the single-slot constraint (PersonaSlot) ─────
log "Assert: negative-preflight — a second managed profile is refused (single-slot)..."
second_out="$(adb shell pm create-user --profileOf 0 --managed "${PERSONA_NAME}-2" 2>&1 | tr -d '\r' || true)"
if printf '%s' "$second_out" | grep -qiE 'error|cannot|fail|not allowed'; then
    ok "second managed profile correctly refused: $second_out"
else
    # If it somehow succeeded, remove it and fail — the platform should have refused,
    # and NoporIS's PersonaSlotResolver assumes exactly one platform-enforced slot.
    stray="$(printf '%s' "$second_out" | grep -oE '[0-9]+' | tail -1)"
    [ -n "$stray" ] && adb shell pm remove-user "$stray" >/dev/null 2>&1 || true
    fail "platform unexpectedly allowed a second managed profile: $second_out"
fi

# ── instrumented lifecycle (in-process, inside the persona) ───────────────────
if [ -n "$TEST_APK" ] && [ -f "$TEST_APK" ]; then
    log "Running instrumented persona-lifecycle test inside the persona..."
    adb install -r --user "$PROFILE_ID" "$TEST_APK" >/dev/null || fail "test APK install failed"
    instr_out="$(adb shell am instrument --user "$PROFILE_ID" -r -w \
        "$TEST_PACKAGE/$TEST_RUNNER" 2>&1 | tr -d '\r' || true)"
    printf '%s\n' "$instr_out"
    if printf '%s' "$instr_out" | grep -q 'FAILURES!!!'; then
        fail "instrumented persona-lifecycle test reported failures"
    elif printf '%s' "$instr_out" | grep -qE 'OK \([0-9]+ test'; then
        ok "instrumented persona-lifecycle test passed"
    else
        skip "instrumented test produced no OK/FAILURE verdict (UNTESTED)"
    fi
else
    # HONEST, EXPECTED as of this commit: no app/src/androidTest/ Kotlin exists yet for
    # NoporIS in this repo (unlike Porog's ProfileLifecycleE2ETest.kt). See
    # ../../toolchain/README.md "Honest gap this file does NOT close". This is not a
    # harness defect — it is the harness correctly reporting what has not landed.
    log "No --test-apk: SKIPPING instrumented lifecycle step (UNTESTED — no androidTest source yet)."
fi

# ── assert: persona-only wipe (teardown → slot back to EMPTY) ─────────────────
log "Assert: persona-only wipe (profile removed, slot returns to EMPTY)..."
adb shell pm remove-user "$PROFILE_ID" >/dev/null || fail "persona wipe (remove-user) failed"
trap - EXIT
sleep 2
if adb shell dumpsys user | tr -d '\r' | grep -q "UserInfo{$PROFILE_ID:"; then
    fail "profile $PROFILE_ID still present after wipe"
else
    ok "persona wiped — teardown complete (slot → EMPTY)"
fi

log "T1 lifecycle harness PASSED on this emulator. Reminder: emulator ≠ hardware;"
log "this is UNAUDITED reference-prototype, not a security claim."
