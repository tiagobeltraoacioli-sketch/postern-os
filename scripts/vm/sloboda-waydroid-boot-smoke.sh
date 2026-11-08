#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# ─────────────────────────────────────────────────────────────────────────────
#  sloboda-waydroid-boot-smoke.sh — VM boot-to-`Session: RUNNING` smoke (T1)
# ─────────────────────────────────────────────────────────────────────────────
#  ⚠  HONESTY / TIER — read before trusting any "PASS" this prints  ⚠
#
#  This is the ONLY test that BOOTS A REAL Waydroid container. It drives the
#  sloboda wrapper (`bin/sloboda`, a black box owned by another
#  dev) against a REAL `waydroid` on PATH — NOT the mock — and asserts the boot
#  bring-up: init → `Session: RUNNING` → app list/launch → host launchers → kill.
#
#    • TIER T1 — "UNTESTED-until-VM" / "deferred-to-VM". It is BLOCKED on a VM
#      host that has: a binder-capable kernel (CONFIG_ANDROID_BINDER_IPC /
#      _BINDERFS), a Wayland compositor (Weston/cage), and a real `waydroid`
#      installed. Host CI has NONE of these — there this script SKIPS (exit 77,
#      the automake "skipped" code), it NEVER reports a green it did not earn.
#    • NON-ATTESTABLE. Entering Android = DATA LEAVES the sealed base. Play
#      Integrity STRONG fails; not covered by the Postern Seal. UNAUDITED.
#    • It refuses to run if PATH resolves `waydroid` to the test mock — a real
#      boot cannot be faked green.
#    • The T2 half of the A7 matrix (visual display, hardware GL, real Play
#      Integrity, Aurora behaviour, consent-gate integration) is manual/logged
#      below and is NEVER asserted as CI-green here.
#
#  Prefixed `sloboda-` so it coexists with `scripts/vm/noporis-*`; it does NOT
#  claim the whole scripts/vm dir. Not legal advice.
#
#  USAGE (on a prepared VM host only):
#     PAW_VM_SMOKE=1 sh scripts/vm/sloboda-waydroid-boot-smoke.sh
#     PAW_VM_SMOKE=1 PAW_VM_ALLOW_INIT=1 sh …   # also pull an image (item 2)
#  EXIT: 0 = T1 subset passed · 1 = a T1 assertion failed · 77 = SKIP (no VM).
# ─────────────────────────────────────────────────────────────────────────────
set -eu

_here="$(unset CDPATH; cd -- "$(dirname -- "$0")" && pwd)"
_repo="$(unset CDPATH; cd -- "$_here/../.." && pwd)"
_paw="$_repo/apps/sloboda"
_wrapper="$_paw/bin/sloboda"
_dryrun="$_paw/test/dry-run.sh"
_mock="$_paw/test/mock-waydroid"

SKIP_RC=77

say()  { printf '%s\n' "sloboda-vm-smoke: $*" >&2; }
skip() { say "SKIP (deferred-to-VM): $*"; exit "$SKIP_RC"; }

say "──────────────────────────────────────────────────────────────────────"
say " Waydroid boot smoke — TIER T1 (UNTESTED-until-VM). Non-attestable."
say " Boots a REAL container: data leaves the sealed base. UNAUDITED."
say "──────────────────────────────────────────────────────────────────────"

# Sanity: the files we drive must exist.
[ -f "$_wrapper" ] || skip "wrapper not found at $_wrapper"
[ -f "$_dryrun" ]  || skip "dry-run harness not found at $_dryrun"

# ── 0. Opt-in guard ─────────────────────────────────────────────────────────
# This BOOTS Android. It must never run by accident in host CI (no Waydroid
# there). Require an explicit PAW_VM_SMOKE=1 from the VM operator.
[ "${PAW_VM_SMOKE:-0}" = "1" ] \
    || skip "set PAW_VM_SMOKE=1 on a prepared VM host to run this (T1)."

# ── 1. A real waydroid on PATH, and NOT the mock ────────────────────────────
_wd="$(command -v waydroid 2>/dev/null || true)"
[ -n "$_wd" ] || skip "no 'waydroid' on PATH — need a real Waydroid on the VM host."
case "$_wd" in
    "$_mock"|*/test/*|*mock*)
        skip "'waydroid' on PATH resolves to the test MOCK ($_wd) — refusing to fake a real boot." ;;
esac
# Behavioural anti-fake-green probe: the mock can be copied to any path/name, but
# it answers a private ident subcommand with a token the real binary never emits.
if waydroid __postern_mock_ident__ 2>/dev/null | grep -q 'POSTERN-MOCK-WAYDROID'; then
    skip "on-PATH 'waydroid' self-identifies as the test MOCK — refusing to fake a real boot."
fi
say "real waydroid: $_wd"

# ── 2. Binder-capable kernel (matrix item 1) ────────────────────────────────
_has_binder() {
    [ -d /dev/binderfs ] && return 0
    [ -e /dev/binder ]   && return 0
    for _c in /proc/config.gz "/boot/config-$(uname -r 2>/dev/null)"; do
        [ -r "$_c" ] || continue
        if { case "$_c" in
                 *.gz) gzip -dc "$_c" ;;
                 *)    cat "$_c" ;;
             esac; } 2>/dev/null | grep -q 'CONFIG_ANDROID_BINDER_IPC=y'; then
            return 0
        fi
    done
    return 1
}
if _has_binder; then
    say "binder support: present (matrix item 1 precondition met)."
else
    skip "no binder support (/dev/binderfs & /dev/binder absent, CONFIG_ANDROID_BINDER_IPC not found) — item 1 unmet."
fi

# ── 3. Wayland compositor (needed to DISPLAY; visual check is item 5/T2) ─────
if [ -n "${WAYLAND_DISPLAY:-}" ]; then
    say "wayland compositor: $WAYLAND_DISPLAY (display is present; visual UI check is item 5, T2/manual)."
else
    say "WARN: no WAYLAND_DISPLAY — the container may reach RUNNING 'headless'."
    say "      show-full-ui/app foregrounding are item 5 (T2, manual) and are NOT asserted here."
fi

# ── 4. Optional image provisioning (matrix item 2) ──────────────────────────
# `waydroid init` pulls a multi-GB image over the network and re-provisions —
# destructive and slow, so it is gated behind an explicit opt-in.
if [ "${PAW_VM_ALLOW_INIT:-0}" = "1" ]; then
    say "PAW_VM_ALLOW_INIT=1 → provisioning image via 'sloboda init' (pulls GB) [item 2]…"
    PAW_DRYRUN=0 sh "$_wrapper" init || say "WARN: init returned non-zero (image may already be provisioned)."
else
    say "init SKIPPED (set PAW_VM_ALLOW_INIT=1 to pull an image) — matrix item 2 not exercised this run."
fi

# ── 5. Core boot sequence: dry-run.sh in REAL-WAYDROID mode ─────────────────
# Reuses the wrapper's control-flow assertions (start→RUNNING, status, app list,
# store/app launch, launchers, kill) but against the REAL waydroid, not the mock.
say "── running dry-run.sh in REAL-WAYDROID mode (this boots the container) ──"
if PAW_REAL_WAYDROID=1 \
   PAW_READY_TIMEOUT_REAL="${PAW_READY_TIMEOUT_REAL:-180}" \
   sh "$_dryrun"; then
    _core_ok=1
else
    _core_ok=0
fi

# ── 6. A7 13-item matrix — coverage of THIS run ─────────────────────────────
say "──────────── A7 13-item matrix — coverage of THIS run ────────────"
say "T1 (VM-automatable — asserted above when the run passed):"
say "  [1]  binder kernel .............. precondition asserted (T1)"
if [ "${PAW_VM_ALLOW_INIT:-0}" = "1" ]; then
    say "  [2]  waydroid init pulls image .. exercised (T1)"
else
    say "  [2]  waydroid init pulls image .. SKIPPED (needs PAW_VM_ALLOW_INIT=1)"
fi
say "  [4]  boot to Session: RUNNING ... proven by dry-run real mode (T1)"
say "  [6]  app list format ............ proven by dry-run real mode (T1)"
say "  [7]  app launch / store ......... invoked by dry-run real mode (T1; foregrounding is visual → T2)"
say "  [9]  host .desktop launchers .... files written (T1); appear-in-grid + click-through is T2/manual"
say "  [10] kill-switch ................ proven by dry-run real mode (T1)"
say "T2 (manual / logged — NEVER CI-green-faked here):"
say "  [3]  microG post-init path ...... T2 manual"
say "  [5]  Wayland display of the UI .. T2 manual (visual)"
say "  [8]  Aurora account-free deliver. T2 manual (network/behavioural)"
say "  [11] hardware GL (Lima/Panfrost). T2 manual (device GPU panel)"
say "  [12] Play Integrity STRONG fails. T2 device-only (T0 mock only SIMULATES the refusal path)"
say "  [13] consent-gate real path/fmt . T2 manual (integration)"
say "──────────────────────────────────────────────────────────────────"

if [ "$_core_ok" = "1" ]; then
    say "RESULT: T1 VM smoke PASSED. 'UNTESTED-until-VM' cleared for the T1 subset ONLY."
    say "        T2 items above remain manual/logged. Non-attestable tier. UNAUDITED."
    exit 0
else
    say "RESULT: T1 VM smoke FAILED — see the dry-run real-mode failures above."
    exit 1
fi
