# shellcheck shell=sh
# ─────────────────────────────────────────────────────────────────────────────
#  SLOBODA — shared shell library (paw-lib.sh)
# ─────────────────────────────────────────────────────────────────────────────
#  ⚠  HONESTY HEADER — read before trusting anything in this file  ⚠
#
#  This is the NON-ATTESTABLE escape-hatch tier of Postern — "Postern for
#  postmarketOS — community edition". It is NOT "Porog" (the stock-Android
#  managed-profile container, a different product) and NEVER "Postern OS". It
#  drives Waydroid: a full Google/AOSP Android userland in an LXC container.
#    • ENTERING ANDROID = DATA LEAVES the sealed base. The container is a large,
#      opaque trust surface next to your wallet — keep secrets OUT of it.
#    • Play Integrity STRONG WILL FAIL. Banking, Google Wallet/Pay and DRM
#      (Widevine L1) apps detect the environment and REFUSE to run. Expected,
#      not a bug we can fix.
#    • NOT covered by the Postern Seal (os_roothash says nothing about what runs
#      inside Waydroid). The coin is worthless. Personal use is free.
#    • UNTESTED: there is no Waydroid in the build sandbox. Every `waydroid …`
#      call here is a SCAFFOLD, validated only by shellcheck + a mock trace.
#      Nothing below has ever booted an Android container. Not legal advice.
#    • DEFAULT-SAFE: this wrapper NEVER opens a privacy bridge. It only READS a
#      toggle state owned by the consent-gate; absent/anything-but-enabled = off.
# ─────────────────────────────────────────────────────────────────────────────

# All functions are prefixed `paw_`. This file is meant to be sourced, never
# executed. POSIX sh only (no bashisms) so it runs under busybox ash / dash on
# postmarketOS. We deliberately avoid `local` (undefined in POSIX sh); helper
# variables are prefixed `_paw_` to keep the global namespace tidy.

# ---- logging ---------------------------------------------------------------
paw_log()  { printf '%s\n' "sloboda: $*" >&2; }
paw_warn() { printf '%s\n' "sloboda: WARN: $*" >&2; }
paw_err()  { printf '%s\n' "sloboda: ERROR: $*" >&2; }
paw_die()  { paw_err "$@"; exit 1; }

# ---- config ----------------------------------------------------------------
# Defaults are the PRIVATE, Google-free posture. A config file may override any
# of these but the microG-vs-GApps choice is ALWAYS a config input, never
# hardcoded to Google here.
paw_config_defaults() {
    # Where to look for the operator config (first hit wins). Overridable via
    # PAW_CONFIG for tests.
    : "${PAW_CONFIG:=}"

    # Android image system type passed to `waydroid init -s`:
    #   VANILLA  — AOSP, NO Google, NO microG (private default base)
    #   GAPPS    — Google Play Services (EXPLICIT, less-private opt-in)
    #   FOSS     — microG-preinstalled image (upstream images are flaky; see
    #              PAW_MICROG below for the community post-init path instead)
    : "${PAW_SYSTEM_TYPE:=VANILLA}"

    # After a VANILLA init, optionally run the community microG installer
    # (waydroid_script) as a SEPARATE, honest step. Default: leave the base
    # Google-free-and-serviceless; the operator opts into microG explicitly.
    : "${PAW_MICROG:=0}"

    # App-store-first: the package the wrapper lands you on. Aurora Store is the
    # account-free default (delivery only — it does NOT defeat Play Integrity).
    : "${PAW_STORE_PKG:=com.aurora.store}"

    # Readiness poll: seconds to wait for Session: RUNNING before giving up.
    : "${PAW_READY_TIMEOUT:=90}"
    : "${PAW_READY_INTERVAL:=2}"

    # Host .desktop launcher output dir. Per-user by default (no root needed).
    # The NixOS module / packager may point this at /usr/share/applications.
    : "${PAW_DESKTOP_DIR:=${XDG_DATA_HOME:-$HOME/.local/share}/applications}"

    # Consent-gate toggle. OWNED BY ANOTHER COMPONENT. This wrapper only READS
    # it and NEVER writes it. Bridge is enabled ONLY if this file exists and its
    # first line is exactly "enabled". Anything else (missing, empty, "disabled",
    # garbage) is treated as OFF — fail safe.
    : "${PAW_BRIDGE_STATE:=/run/postern/consent/sloboda-bridge.state}"

    # Set to 1 to TRACE instead of EXEC every waydroid call (dry-run). The test
    # harness sets this; operators generally do not.
    : "${PAW_DRYRUN:=0}"

    # The waydroid binary. Overridable so the mock can stand in on PATH.
    : "${PAW_WAYDROID:=waydroid}"
}

# Load config: apply defaults, then source an operator config file if present.
# The config file is plain KEY=VALUE sh (sourced), e.g. PAW_SYSTEM_TYPE=GAPPS.
paw_load_config() {
    paw_config_defaults
    _paw_cfg="$PAW_CONFIG"
    if [ -z "$_paw_cfg" ]; then
        for _paw_c in \
            "${XDG_CONFIG_HOME:-$HOME/.config}/sloboda/sloboda.conf" \
            "/etc/sloboda/sloboda.conf"; do
            [ -f "$_paw_c" ] && { _paw_cfg="$_paw_c"; break; }
        done
    fi
    if [ -n "$_paw_cfg" ] && [ -f "$_paw_cfg" ]; then
        paw_log "loading config: $_paw_cfg"
        # shellcheck disable=SC1090  # operator-provided path, sourced on purpose
        . "$_paw_cfg"
        # Re-apply defaults so any key the config DIDN'T set is still populated.
        paw_config_defaults
    fi
}

# ---- waydroid presence -----------------------------------------------------
paw_have_waydroid() {
    command -v "$PAW_WAYDROID" >/dev/null 2>&1
}

paw_require_waydroid() {
    paw_have_waydroid && return 0
    paw_err "waydroid not found on PATH (looked for '$PAW_WAYDROID')."
    paw_err "This is expected off-device: the wrapper is UNTESTED without it."
    return 1
}

# The single choke point for every Waydroid invocation. In dry-run it only
# TRACES the command; otherwise it execs it. This is what makes the whole
# wrapper testable with a mock and honest about what it would run.
paw_waydroid() {
    if [ "$PAW_DRYRUN" = "1" ]; then
        printf 'TRACE would run: %s %s\n' "$PAW_WAYDROID" "$*" >&2
        return 0
    fi
    paw_require_waydroid || return 1
    "$PAW_WAYDROID" "$@"
}

# Some container operations require root; surface that honestly rather than
# silently failing. Returns the privilege-escalation prefix to use ("" if root
# or if sudo is unavailable — caller then reports the manual command).
paw_priv() {
    if [ "$(id -u 2>/dev/null || echo 1000)" = "0" ]; then
        printf ''
    elif command -v sudo >/dev/null 2>&1; then
        printf 'sudo'
    else
        printf ''
    fi
}

# ---- status ----------------------------------------------------------------
# Parse `waydroid status`. Echoes RUNNING / STOPPED / UNKNOWN for the session.
paw_session_state() {
    if [ "$PAW_DRYRUN" = "1" ]; then
        # Mock/dry-run: defer to the mock's own `status` output if reachable.
        _paw_out="$("$PAW_WAYDROID" status 2>/dev/null || true)"
    else
        paw_have_waydroid || { echo UNKNOWN; return; }
        _paw_out="$("$PAW_WAYDROID" status 2>/dev/null || true)"
    fi
    case "$_paw_out" in
        *Session*RUNNING*|*Session*Running*) echo RUNNING ;;
        *Session*STOPPED*|*Session*Stopped*) echo STOPPED ;;
        '') echo UNKNOWN ;;
        *) echo STOPPED ;;
    esac
}

# Poll until the session reports RUNNING or the timeout elapses.
paw_wait_ready() {
    _paw_waited=0
    while [ "$_paw_waited" -lt "$PAW_READY_TIMEOUT" ]; do
        if [ "$(paw_session_state)" = "RUNNING" ]; then
            paw_log "session is RUNNING (after ${_paw_waited}s)."
            return 0
        fi
        sleep "$PAW_READY_INTERVAL"
        _paw_waited=$((_paw_waited + PAW_READY_INTERVAL))
        paw_log "waiting for Android session… (${_paw_waited}/${PAW_READY_TIMEOUT}s)"
    done
    paw_err "timed out after ${PAW_READY_TIMEOUT}s waiting for Session: RUNNING."
    paw_err "UNTESTED on-device: on a real device confirm a Wayland compositor"
    paw_err "is active and the waydroid-container service is up."
    return 1
}

# ---- consent-gate bridge state (READ-ONLY) ---------------------------------
# Returns 0 (enabled) ONLY if the consent-gate state file's first line is
# exactly "enabled". This wrapper NEVER writes this file — the consent-gate dev
# owns it. Fail-safe: any doubt = disabled.
paw_bridge_enabled() {
    [ -r "$PAW_BRIDGE_STATE" ] || return 1
    _paw_first="$(head -n 1 "$PAW_BRIDGE_STATE" 2>/dev/null | tr -d '[:space:]')"
    [ "$_paw_first" = "enabled" ]
}

paw_bridge_report() {
    if paw_bridge_enabled; then
        paw_warn "consent-gate privacy bridge reads ENABLED ($PAW_BRIDGE_STATE)."
        paw_warn "clipboard/host sharing may be open — this wrapper did not open it."
    else
        paw_log "privacy bridge: OFF (default-safe). State: $PAW_BRIDGE_STATE"
    fi
}

# ---- consent-gate CONTAINER posture (READ-ONLY refuse-gate) -----------------
# Whether the container is allowed to ENTER Android at all. This is a DIFFERENT
# question from paw_bridge_enabled (which is only "is a privacy bridge open").
# Entering is gated on consent + kill-switch; a consented user with NO bridges
# may still enter (accept is permission to RUN, not permission to SHARE).
#
# The projection the consent-gate writer (sloboda-gated) compiles carries
# an additive `container=allowed|blocked` line plus, defensively, `kill=engaged`.
# We still NEVER write this file — pure read, fail-safe on any doubt. Any BLOCK
# marker wins over any ALLOW marker (a corrupt projection carrying both refuses):
#   • file absent/unreadable            → BLOCKED
#   • `kill=engaged` present            → BLOCKED (defensive; overrides anything)
#   • `container=blocked` present       → BLOCKED (explicit refusal wins)
#   • `container=allowed` present       → allowed (only if no block marker above)
#   • else, legacy/minimal projection   → allowed iff line 1 is exactly "enabled"
#     (by the writer's derivation, an "enabled" line implies consent + kill-clear)
paw_container_allowed() {
    [ -r "$PAW_BRIDGE_STATE" ] || return 1
    # Read the projection once; a tmpfs line-file is tiny. Parsing a snapshot
    # avoids re-reading a file that could change under us between greps.
    _paw_proj="$(cat "$PAW_BRIDGE_STATE" 2>/dev/null)" || return 1
    # BLOCK markers first — fail-safe precedence. Either one refuses outright,
    # even if a stray `container=allowed`/`enabled` also appears in a bad file.
    case "
$_paw_proj
" in
        *"
kill=engaged
"*)      return 1 ;;
        *"
container=blocked
"*) return 1 ;;
    esac
    # Explicit ALLOW marker (only reached when no block marker was present).
    case "
$_paw_proj
" in
        *"
container=allowed
"*) return 0 ;;
    esac
    # No explicit container marker: fall back to the shipped line-1 bridge
    # contract. "enabled" line 1 can only be written when the container is
    # allowed, so honouring it here is safe (and keeps an old projection usable).
    _paw_first="$(printf '%s\n' "$_paw_proj" | head -n 1 | tr -d '[:space:]')"
    [ "$_paw_first" = "enabled" ]
}

# Why the gate is closed, for an honest refusal message. Echoes a short reason.
paw_container_block_reason() {
    if [ ! -r "$PAW_BRIDGE_STATE" ]; then
        printf 'no consent projection present (%s) — run the consent gate to accept' "$PAW_BRIDGE_STATE"
    elif grep -q '^kill=engaged$' "$PAW_BRIDGE_STATE" 2>/dev/null; then
        printf 'kill-switch is ENGAGED — disengage it in the consent gate first'
    else
        printf 'consent not given — run the consent gate to accept before entering Android'
    fi
}

# REFUSE the current entry path unless the container is allowed. Returns 0 to
# proceed; prints an honest refusal and returns 1 to abort. This CLOSES the real
# gap: previously the wrapper only *reported* posture and entered anyway.
paw_require_container_allowed() {
    _paw_what="${1:-enter Android}"
    paw_container_allowed && return 0
    paw_err "REFUSED to $_paw_what: $(paw_container_block_reason)."
    paw_err "The wrapper never opens the consent gate itself — it only reads it (fail-safe)."
    return 1
}

# ---- per-capability bridge read (READ-ONLY, non-load-bearing) ---------------
# Names the bridges the projection says are open, one per line (e.g. "clipboard").
# Line 1 stays the authority; this only parses the additive `<cap>=on` lines so
# status/doctor can enumerate exactly which bridges are open. Empty when off.
paw_bridge_caps() {
    [ -r "$PAW_BRIDGE_STATE" ] || return 0
    paw_bridge_enabled || return 0
    sed -n 's/^\([a-z][a-z]*\)=on$/\1/p' "$PAW_BRIDGE_STATE" 2>/dev/null
}

# ---- consent-gate EGRESS posture (READ-ONLY, non-load-bearing) --------------
# The consent-gate writer (sloboda-gated) projects the Tor-only network-egress
# rail on an additive `egress=tor|held|blocked` line (design §2.2):
#   • egress=blocked   container not allowed to run at all → no network.
#   • egress=held      container allowed, but Tor is NOT yet bootstrapped → the
#                      tor-glue HOLDS traffic (fail-closed) until a circuit is up.
#   • egress=tor       container allowed AND Tor live → egress may flow, Tor-only.
# SURFACING ONLY: this wrapper merely READS the projected posture so status/doctor
# can show it — ENFORCEMENT stays the tor-glue's job, exactly like the container
# refuse-gate reads (but does not write) the consent state. Mirrors the per-cap
# reader's sed style; NEVER writes the file. Fail-safe: a missing/unreadable/
# blocked projection — or any value that is not exactly `tor`/`held` — reads as
# "blocked". Echoes one of: tor | held | blocked.
paw_egress_posture() {
    [ -r "$PAW_BRIDGE_STATE" ] || { echo blocked; return; }
    _paw_egr="$(sed -n 's/^egress=\([a-z][a-z]*\)$/\1/p' "$PAW_BRIDGE_STATE" 2>/dev/null | head -n 1)"
    case "$_paw_egr" in
        tor)  echo tor ;;
        held) echo held ;;
        *)    echo blocked ;;  # blocked / absent line / garbage → blocked (fail-safe)
    esac
}

# ---- host launcher integration (write-perm reality + grid refresh) ----------
# Ensure PAW_DESKTOP_DIR exists and is writable BEFORE we try to write .desktop
# files, with an honest message about the per-user vs system-wide split:
#   • per-user (default $XDG_DATA_HOME/applications) → user-writable, no root.
#   • system-wide (/usr/share/applications, /etc/…)  → needs root/packager; the
#     NixOS module owns that, not this wrapper. We fail honestly, never silently.
# Returns 0 when the dir is ready to write, 1 (with a reason) otherwise.
paw_ensure_desktop_dir() {
    if ! mkdir -p "$PAW_DESKTOP_DIR" 2>/dev/null; then
        paw_err "cannot create launcher dir: $PAW_DESKTOP_DIR"
        case "$PAW_DESKTOP_DIR" in
            /usr/*|/etc/*|/opt/*)
                paw_err "system-wide launcher dirs need root/packager — point PAW_DESKTOP_DIR at a"
                paw_err "per-user dir (default \$XDG_DATA_HOME/applications) or run from the packaged context." ;;
        esac
        return 1
    fi
    if [ ! -w "$PAW_DESKTOP_DIR" ]; then
        paw_err "launcher dir not writable: $PAW_DESKTOP_DIR"
        case "$PAW_DESKTOP_DIR" in
            /usr/*|/etc/*|/opt/*)
                paw_err "writing system-wide launchers needs root — this is the NixOS module/packager's job." ;;
        esac
        return 1
    fi
    return 0
}

# Re-index the desktop database so a live shell (Phosh app-grid, etc.) picks up
# newly written / pruned launchers without a session restart. Best-effort and
# guarded by command -v — absent on-host and off a mobile shell, so a no-op there.
paw_refresh_desktop_db() {
    _paw_ddir="${1:-$PAW_DESKTOP_DIR}"
    [ -d "$_paw_ddir" ] || return 0
    if [ "$PAW_DRYRUN" = "1" ]; then
        printf 'TRACE would run: update-desktop-database %s\n' "$_paw_ddir" >&2
        return 0
    fi
    command -v update-desktop-database >/dev/null 2>&1 || return 0
    update-desktop-database "$_paw_ddir" 2>/dev/null || true
}
