#!/bin/sh
# ─────────────────────────────────────────────────────────────────────────────
#  SLOBODA — offline validation harness
# ─────────────────────────────────────────────────────────────────────────────
#  ⚠  HONESTY: validates ONLY what is checkable without Waydroid. It runs the
#     wrapper in two modes: (1) PAW_DRYRUN=1 trace with NO waydroid, and (2)
#     PAW_DRYRUN=0 against a MOCK waydroid on PATH. Neither boots Android.
#     On-device behaviour (real container, integrity, GPU, Wayland) stays
#     UNTESTED. Non-attestable tier; not Sealed; personal-free; not legal advice.
#
#  TEST SURFACE (for sweep tooling): this shell script + ./mock-waydroid are
#  the ENTIRE sloboda test suite. Sloboda is a POSIX-sh wrapper; there is
#  intentionally NO node/JS test suite here — zero *.mjs / *.test.mjs files
#  exist under apps/sloboda, so a node test sweep has nothing to run and
#  should skip this app (that is correct, not a gap). Run THIS file instead:
#      sh apps/sloboda/test/dry-run.sh
# ─────────────────────────────────────────────────────────────────────────────
set -eu

_here="$(unset CDPATH; cd -- "$(dirname -- "$0")" && pwd)"
_bin="$_here/../bin/sloboda"
_cli="$_here/../bin/sloboda"

# Scratch dirs so we never touch the real user environment.
_tmp="$(mktemp -d "${TMPDIR:-/tmp}/paw-dryrun.XXXXXX")"
trap 'rm -rf "$_tmp"' EXIT INT TERM
export PAW_MOCK_STATE="$_tmp/mock.state"
export PAW_DESKTOP_DIR="$_tmp/applications"
export PAW_BRIDGE_STATE="$_tmp/bridge.state"   # absent → bridge OFF (default-safe)
export PAW_READY_TIMEOUT=6
export PAW_READY_INTERVAL=1
export PAW_WATCH_INTERVAL=1

_hr()  { printf '\n=== %s ===\n' "$*"; }
_pass=0; _fail=0
_ok()   { printf 'PASS: %s\n' "$*"; _pass=$((_pass+1)); }
_no()   { printf 'FAIL: %s\n' "$*"; _fail=$((_fail+1)); }

########################################################################
# REAL-WAYDROID MODE (T1, deferred-to-VM). Triggered by PAW_REAL_WAYDROID=1,
# driven by scripts/vm/sloboda-waydroid-boot-smoke.sh on a VM host that has a
# binder-capable kernel + a Wayland compositor (Weston) + a REAL `waydroid` on
# PATH. This path is NEVER exercised by host CI (no Waydroid in the sandbox);
# it is authored VM-ready and kept `sh -n`/shellcheck clean. It is the ONLY
# place that can prove boot-to-`Session: RUNNING`. Non-attestable; UNAUDITED —
# it green-refuses to run if PATH resolves `waydroid` to the mock.
########################################################################
_real_waydroid_mode() {
    _hr "REAL waydroid mode · PAW_DRYRUN=0 against the on-PATH waydroid"
    _rw="$(command -v waydroid 2>/dev/null || true)"
    if [ -z "$_rw" ]; then
        _no "no real 'waydroid' on PATH (needed for real mode)"
        printf 'passed: %s   failed: %s\n' "$_pass" "$_fail"
        return 1
    fi
    case "$_rw" in
        */test/*|*mock*)
            _no "PATH resolves 'waydroid' to the MOCK ($_rw) — refusing to fake a real run"
            printf 'passed: %s   failed: %s\n' "$_pass" "$_fail"
            return 1 ;;
    esac
    # Path heuristics are not enough (the mock can be copied to any name). Probe
    # behaviourally: the mock answers a private ident subcommand with a token the
    # real binary never prints. This is the load-bearing anti-fake-green guard.
    if waydroid __postern_mock_ident__ 2>/dev/null | grep -q 'POSTERN-MOCK-WAYDROID'; then
        _no "on-PATH 'waydroid' self-identifies as the TEST MOCK — refusing to fake a real run"
        printf 'passed: %s   failed: %s\n' "$_pass" "$_fail"
        return 1
    fi
    _ok "real waydroid on PATH: $_rw"

    # Real boots need real time; the mock timeouts are far too short.
    export PAW_DRYRUN=0
    export PAW_WAYDROID=waydroid
    export PAW_READY_TIMEOUT="${PAW_READY_TIMEOUT_REAL:-120}"
    export PAW_READY_INTERVAL=3

    _hr "doctor (real)"
    PAW_DRYRUN=0 sh "$_cli" doctor || true

    _hr "start -> Session: RUNNING  [matrix items 1,2,4]"
    if PAW_DRYRUN=0 sh "$_cli" start; then _ok "start reached RUNNING on real waydroid"; else _no "start did not reach RUNNING"; fi
    if PAW_DRYRUN=0 sh "$_cli" status | grep -q 'session:.*RUNNING'; then _ok "status reports RUNNING"; else _no "status not RUNNING"; fi

    _hr "app list — real output format  [matrix item 6]"
    if waydroid app list 2>/dev/null | grep -q '^[[:space:]]*packageName:'; then
        _ok "waydroid app list yields packageName entries"
    else
        _no "waydroid app list returned no packageName entries (session down or format drift)"
    fi

    _hr "store / app launch  [matrix items 7,8]"
    if PAW_DRYRUN=0 sh "$_cli" store >/dev/null 2>&1; then
        _ok "store launch returned 0 (foregrounding is visual -> item 8/T2)"
    else
        _no "store launch failed (store may not be installed yet — see item 8, T2)"
    fi

    _hr "launchers written for installed apps  [matrix item 9]"
    PAW_DRYRUN=0 sh "$_cli" launchers || true
    if find "$PAW_DESKTOP_DIR" -name 'sloboda-*.desktop' 2>/dev/null | grep -q .; then
        _ok "at least one host .desktop launcher written (appear-in-grid + click is T2/manual)"
    else
        _no "no host launchers written"
    fi

    _hr "kill-switch  [matrix item 10]"
    if PAW_DRYRUN=0 sh "$_cli" kill; then _ok "kill-switch returned 0"; else _no "kill failed"; fi
    if PAW_DRYRUN=0 sh "$_cli" status | grep -q 'session:.*STOPPED'; then _ok "session STOPPED after kill"; else _no "session not stopped after kill"; fi

    _hr "REAL-MODE SUMMARY (T1 · non-attestable · UNAUDITED)"
    printf 'passed: %s   failed: %s\n' "$_pass" "$_fail"
    [ "$_fail" -eq 0 ]
}

if [ "${PAW_REAL_WAYDROID:-0}" = "1" ]; then
    if _real_waydroid_mode; then exit 0; else exit 1; fi
fi

########################################################################
# MODE 1 — pure dry-run TRACE, no waydroid on PATH.
########################################################################
_hr "MODE 1 · PAW_DRYRUN=1 trace (no waydroid binary)"
# Ensure the mock is NOT on PATH for this mode.
PATH_NO_MOCK="$PATH"
PAW_DRYRUN=1 PATH="$PATH_NO_MOCK" sh "$_cli" doctor       || true
PAW_DRYRUN=1 PATH="$PATH_NO_MOCK" sh "$_cli" config       || true
PAW_DRYRUN=1 PATH="$PATH_NO_MOCK" sh "$_cli" init         || true
PAW_DRYRUN=1 PATH="$PATH_NO_MOCK" sh "$_cli" store        || true
PAW_DRYRUN=1 PATH="$PATH_NO_MOCK" sh "$_cli" app com.example.foo || true
PAW_DRYRUN=1 PATH="$PATH_NO_MOCK" sh "$_cli" kill         || true
_ok "dry-run trace commands ran without executing waydroid"

########################################################################
# MODE 2 — real exec path against the MOCK waydroid on PATH.
########################################################################
_hr "MODE 2 · PAW_DRYRUN=0 against mock-waydroid on PATH"
# Put the mock on PATH under the name 'waydroid'.
_mockdir="$_tmp/mockbin"
mkdir -p "$_mockdir"
cp "$_here/mock-waydroid" "$_mockdir/waydroid"
chmod +x "$_mockdir/waydroid"
# Fake `update-desktop-database` so we can PROVE the launcher path triggers the
# best-effort desktop-index refresh. The real tool is absent on macOS / any
# off-device host, so without this the guarded refresh would be a silent no-op
# and untestable. It just records each invocation's target dir to a log.
_dblog="$_tmp/desktopdb.log"
cat > "$_mockdir/update-desktop-database" <<EOF
#!/bin/sh
printf '%s\n' "\${1:-}" >> "$_dblog"
EOF
chmod +x "$_mockdir/update-desktop-database"
export PATH="$_mockdir:$PATH"

# The wrapper adds a REFUSE-GATE: entering Android (start/store/app) requires a
# consent-gate projection that ALLOWS the container. The consent-gate writer
# (sloboda-gated) owns this file; the wrapper only READS it (fail-safe). Plant a
# minimal projection that GRANTS container entry while keeping the privacy BRIDGE
# OFF (line 1 is not "enabled"), so the default-safe bridge assertions further
# down still hold. We remove it again before the bridge default-safe section so
# its "state file absent" precondition stays honest.
printf 'disabled\ncontainer=allowed\n' > "$PAW_BRIDGE_STATE"

_run() { PAW_DRYRUN=0 sh "$_cli" "$@"; }

_hr "doctor (mock present)"
_run doctor || true

_hr "start → wait-for-ready"
if _run start; then _ok "start reached RUNNING via mock"; else _no "start did not reach RUNNING"; fi

_hr "status"
if _run status | grep -q 'session:.*RUNNING'; then _ok "status reports RUNNING"; else _no "status not RUNNING"; fi

_hr "store (app-store-first)"
if _run store; then _ok "store launch invoked"; else _no "store launch failed"; fi

_hr "app <pkg> (single-app path)"
if _run app com.aurora.store; then _ok "single-app launch invoked"; else _no "app launch failed"; fi

_hr "app <pkg> REFUSAL (integrity-gated app — SIMULATED, mirrors matrix item 12)"
# A normal app launches; an integrity-gated app (banking / Wallet / DRM) is
# refused BY THE ENVIRONMENT. The mock SIMULATES the refusal (exit 3); this
# proves the wrapper surfaces a non-zero/refused outcome honestly instead of
# claiming success. It proves NOTHING about real Play Integrity — item 12 stays
# device-only (T2). A normal launch must still succeed alongside it.
if _run app com.aurora.store >/dev/null 2>&1; then
    _ok "normal app launch still succeeds"
else
    _no "normal app launch unexpectedly failed"
fi
if _run app com.google.android.apps.walletnfcrel >/dev/null 2>&1; then
    _no "integrity-gated app did NOT surface refusal (should exit non-zero)"
else
    _ok "integrity-gated app refusal surfaced honestly (wrapper returned non-zero)"
fi

_hr "launchers (write host .desktop icons)"
_run launchers || true
if [ -f "$PAW_DESKTOP_DIR/sloboda-com.aurora.store.desktop" ] \
   && [ -f "$PAW_DESKTOP_DIR/sloboda-app.organicmaps.desktop" ]; then
    _ok "two .desktop launchers written from 'waydroid app list'"
else
    _no ".desktop launchers missing"
fi
# Verify a launcher Exec calls back through the wrapper, not bare waydroid.
if grep -q 'Exec=.*sloboda app com.aurora.store' \
      "$PAW_DESKTOP_DIR/sloboda-com.aurora.store.desktop" 2>/dev/null; then
    _ok "launcher Exec routes through the wrapper (honesty path preserved)"
else
    _no "launcher Exec does not route through the wrapper"
fi
# After writing launchers the wrapper best-effort refreshes the desktop index so
# the shell app grid re-indexes without a session restart (§4.1).
if grep -qx "$PAW_DESKTOP_DIR" "$_dblog" 2>/dev/null; then
    _ok "launchers refreshed the host desktop database (update-desktop-database)"
else
    _no "launchers did not refresh the host desktop database"
fi

_hr "launcher honesty markers + idempotency"
_lf="$PAW_DESKTOP_DIR/sloboda-com.aurora.store.desktop"
# Every launcher must carry the non-attestable tier marker so the app grid never
# implies these Android apps are Sealed/attested.
if grep -q '^X-Postern-Tier=sloboda-compat-non-attestable' "$_lf" 2>/dev/null; then
    _ok "launcher carries the non-attestable tier marker"
else
    _no "launcher missing the non-attestable tier marker"
fi
# And record its package so prune can match it back to `waydroid app list`.
if grep -q '^X-Postern-Package=com.aurora.store' "$_lf" 2>/dev/null; then
    _ok "launcher records X-Postern-Package for prune matching"
else
    _no "launcher missing X-Postern-Package"
fi
# Re-running launchers must be idempotent — no duplicate .desktop files pile up.
_run launchers >/dev/null 2>&1 || true
_n1="$(find "$PAW_DESKTOP_DIR" -name 'sloboda-*.desktop' 2>/dev/null | wc -l | tr -d ' ')"
_run launchers >/dev/null 2>&1 || true
_n2="$(find "$PAW_DESKTOP_DIR" -name 'sloboda-*.desktop' 2>/dev/null | wc -l | tr -d ' ')"
if [ "$_n1" = "$_n2" ]; then
    _ok "launchers idempotent (count stable at $_n2 across re-runs)"
else
    _no "launchers not idempotent (count drifted $_n1 -> $_n2)"
fi

_hr "install-watch (single bounded pass) + prune"
# Plant a stale launcher for a package the mock no longer lists, expect prune.
cat > "$PAW_DESKTOP_DIR/sloboda-com.gone.stale.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Gone (Android)
Exec=$_cli app com.gone.stale
X-Postern-Package=com.gone.stale
EOF
# One bounded exec-mode pass: prunes stale, (re)writes current from the mock.
: > "$_dblog"   # clear the refresh log so we can attribute a refresh to THIS pass
PAW_DRYRUN=0 PAW_WATCH_ONCE=1 sh "$_cli" install-watch >/dev/null 2>&1 || true
if [ ! -f "$PAW_DESKTOP_DIR/sloboda-com.gone.stale.desktop" ]; then
    _ok "stale launcher pruned by install-watch"
else
    _no "stale launcher not pruned"
fi
# Removing a stale launcher must trigger a desktop-index refresh so the pruned
# icon disappears from the grid (prune-path refresh; only fires on real removal).
if [ -s "$_dblog" ]; then
    _ok "install-watch prune/write refreshed the desktop database"
else
    _no "install-watch pass did not refresh the desktop database after pruning"
fi
if [ -f "$PAW_DESKTOP_DIR/sloboda-com.aurora.store.desktop" ]; then
    _ok "install-watch kept current launcher"
else
    _no "install-watch dropped a current launcher"
fi

_hr "bridge state is READ-ONLY and default-safe"
# Drop the container-entry projection planted for the launch tests so the
# "state file absent" precondition below is literally true again.
rm -f "$PAW_BRIDGE_STATE"
if _run status | grep -q 'bridge:.*off'; then _ok "bridge OFF when state file absent"; else _no "bridge not defaulting off"; fi
printf 'enabled\n' > "$PAW_BRIDGE_STATE"
if _run status | grep -qi 'bridge:.*ENABLED'; then _ok "bridge reads ENABLED from consent-gate file"; else _no "bridge did not read enabled state"; fi
# Prove the wrapper never wrote the bridge file itself: content is still ours.
if [ "$(cat "$PAW_BRIDGE_STATE")" = "enabled" ]; then _ok "wrapper did not rewrite consent-gate state"; else _no "consent-gate state was modified"; fi
rm -f "$PAW_BRIDGE_STATE"

_hr "consent-gate EGRESS posture is SURFACED (read-only, non-load-bearing)"
# The consent-gate writer (sloboda-gated) projects the Tor-only network-egress
# rail on an additive `egress=tor|held|blocked` line. The wrapper only READS it so
# status/doctor can show it — ENFORCEMENT stays the tor-glue's job. Fail-safe: a
# missing/unreadable/blocked projection reads as blocked.
# (1) absent projection → blocked.
rm -f "$PAW_BRIDGE_STATE"
if _run status | grep -q 'egress:.*blocked'; then _ok "egress reads blocked when projection absent (fail-safe)"; else _no "egress did not default to blocked when absent"; fi
# (2) egress=held → status shows held. Line 1 stays "disabled" (bridge OFF) so the
#     held projection is honoured on its own additive line, not via the bridge.
printf 'disabled\ncontainer=allowed\negress=held\n' > "$PAW_BRIDGE_STATE"
if _run status | grep -q 'egress:.*held'; then _ok "egress=held projection surfaces as held"; else _no "egress=held not surfaced as held"; fi
# (3) egress=tor → status shows tor.
printf 'disabled\ncontainer=allowed\negress=tor\n' > "$PAW_BRIDGE_STATE"
if _run status | grep -q 'egress:.*tor'; then _ok "egress=tor projection surfaces as tor"; else _no "egress=tor not surfaced as tor"; fi
# doctor surfaces the same posture (read-only, no waydroid calls).
if _run doctor | grep -q 'egress posture:.*tor'; then _ok "doctor surfaces the egress posture"; else _no "doctor did not surface the egress posture"; fi
# An explicit egress=blocked line must read blocked (not just an absent line).
printf 'disabled\ncontainer=blocked\negress=blocked\n' > "$PAW_BRIDGE_STATE"
if _run status | grep -q 'egress:.*blocked'; then _ok "explicit egress=blocked surfaces as blocked"; else _no "explicit egress=blocked not surfaced as blocked"; fi
# Read-only: the wrapper never rewrote the projection we planted.
printf 'disabled\ncontainer=allowed\negress=tor\n' > "$PAW_BRIDGE_STATE"
_run status >/dev/null 2>&1 || true
if [ "$(cat "$PAW_BRIDGE_STATE")" = "$(printf 'disabled\ncontainer=allowed\negress=tor')" ]; then _ok "wrapper did not rewrite the egress projection"; else _no "egress projection was modified by the wrapper"; fi
rm -f "$PAW_BRIDGE_STATE"

_hr "stop + kill-switch"
if _run stop; then _ok "stop invoked"; else _no "stop failed"; fi
_run start >/dev/null 2>&1 || true
if _run kill; then _ok "kill-switch invoked"; else _no "kill failed"; fi
if _run status | grep -q 'session:.*STOPPED'; then _ok "session STOPPED after kill"; else _no "session not stopped after kill"; fi

_hr "kill-switch hardening (clears session runtime, KEEPS the provisioned image)"
# Point XDG_RUNTIME_DIR at scratch so the kill clears OUR planted session state,
# never the tester's real runtime. Plant a stand-in provisioned image and prove
# the kill-switch does NOT delete it (kill is 'get Android out of memory', not
# 'wipe the image' — that is a bigger, separate hammer).
export XDG_RUNTIME_DIR="$_tmp/run"
mkdir -p "$XDG_RUNTIME_DIR/waydroid"
_img_marker="$_tmp/waydroid-image/system.img"
mkdir -p "$(dirname "$_img_marker")"; : > "$_img_marker"
_run start >/dev/null 2>&1 || true
_run kill  >/dev/null 2>&1 || true
if [ ! -d "$XDG_RUNTIME_DIR/waydroid" ]; then
    _ok "kill cleared the per-user session runtime dir"
else
    _no "kill left the session runtime dir behind"
fi
if [ -f "$_img_marker" ]; then
    _ok "kill left the provisioned image intact (image untouched)"
else
    _no "kill deleted the provisioned image (should not)"
fi
# Idempotent: killing an already-dead session must still exit 0.
if _run kill >/dev/null 2>&1; then
    _ok "kill is idempotent (second kill on a dead session exits 0)"
else
    _no "second kill on a dead session failed"
fi

########################################################################
_hr "SUMMARY"
printf 'passed: %s   failed: %s\n' "$_pass" "$_fail"
[ "$_fail" -eq 0 ] || exit 1
