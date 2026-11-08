#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# ─────────────────────────────────────────────────────────────────────────────
#  terem-app-mode-sandbox-poc.sh — App Mode (Wine/Proton) bubblewrap POC
# ─────────────────────────────────────────────────────────────────────────────
#  ⚠  HONESTY / TIER — read before trusting any "PASS" this prints  ⚠
#
#   - PROTOTYPE ONLY. Confines a SAMPLE PROCESS (default: this script's own
#     self-check; or, with `--`, any command you name, e.g. `wine app.exe`).
#     No code in apps/ or desktop/src-tauri calls this today — see
#     docs/os-portal-v2/APP-MODE-SANDBOX.md, which this script is the POC for.
#   - LINUX-ONLY, HONESTLY. `bwrap` is built on Linux kernel namespaces
#     (unshare(2) / user namespaces). On any non-Linux host (incl. the macOS
#     box this repo's own dev workstation runs on) this SKIPS with exit 77 —
#     it does NOT fake a pass. Same discipline as
#     scripts/vm/sloboda-waydroid-boot-smoke.sh's SKIP_RC=77 convention.
#   - App Mode's sandbox is WEAKER than Guest Mode's KVM boundary — a shared
#     host kernel, not a hypervisor. This script demonstrates a namespace
#     jail (filesystem allowlist, network off), not hardware isolation. See
#     APP-MODE-SANDBOX.md §"honest limits" for the full statement.
#   - No seccomp filter is applied in this POC (flagged as follow-on
#     hardening, not built here — APP-MODE-SANDBOX.md §4.5). Namespace
#     confinement only.
#   - UNAUDITED. Nothing here has been security-reviewed. `written ≠ built`,
#     `built ≠ booted`, `designed ≠ audited`.
#
#  WHAT IT DOES (self-check mode, the default, no args):
#     Creates a throwaway "prefix" directory (stands in for a WINEPREFIX),
#     drops a canary file in the REAL $HOME, then runs a bwrap sandbox that
#     can see only: a minimal read-only system base (/usr,/bin,/lib,/lib64
#     where they exist) + the prefix dir (read-write) + /proc + /dev + a
#     private /tmp. It asserts, from INSIDE the sandbox:
#       1. the real $HOME canary is unreachable
#       2. writing outside the prefix (e.g. into the ro-bound /usr) fails
#       3. writing/reading INSIDE the prefix works
#       4. no /etc/resolv.conf exists -> DNS resolution is structurally
#          impossible (network unshared by default)
#       5. best-effort: if python3 is available inside the sandbox, an
#          outbound TCP connect attempt must fail/timeout (informational
#          if python3 is missing; a REAL FAIL if it unexpectedly succeeds)
#
#  USAGE:
#     scripts/terem-app-mode-sandbox-poc.sh                    # self-check (default)
#     scripts/terem-app-mode-sandbox-poc.sh --with-net          # self-check, network ALLOWED (mirrors an
#                                                                 # explicit, consented terem-gate exception —
#                                                                 # never the default)
#     TEREM_PREFIX=/path/to/dir scripts/terem-app-mode-sandbox-poc.sh -- wine app.exe
#                                                                # confine an arbitrary command (e.g. real Wine)
#                                                                # in the SAME jail, prefix bound read-write
#
#  EXIT: 0  = every check passed (or, in `--` mode, the given command exited 0)
#        1  = a confinement check FAILED (the sandbox leaked) or the given
#             command exited non-zero
#        77 = SKIP — not on Linux, or `bwrap` is not on PATH (box-gated,
#             honestly reported, never a silent/fake pass)
# ─────────────────────────────────────────────────────────────────────────────
set -eu

SKIP_RC=77
FAIL_RC=1

say()  { printf '%s\n' "terem-sandbox-poc: $*" >&2; }
skip() { say "SKIP (box-gated): $*"; exit "$SKIP_RC"; }

# ── 1. Honest platform/tool gate — never fake a pass ─────────────────────────
_uname="$(uname -s 2>/dev/null || echo unknown)"
if [ "$_uname" != "Linux" ]; then
  skip "this host is '$_uname', not Linux. bwrap needs Linux kernel namespaces (unshare(2)). Nothing below this line has run."
fi

if ! command -v bwrap >/dev/null 2>&1; then
  skip "'bwrap' (bubblewrap) not found on PATH. Install it (e.g. 'apt install bubblewrap' / 'dnf install bubblewrap' / 'pacman -S bubblewrap' / nix 'pkgs.bubblewrap') and re-run."
fi

say "Linux + bwrap present. Proceeding — everything from here is a REAL sandboxed run, not a simulation."

# ── 2. Work area ──────────────────────────────────────────────────────────────
_tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/terem-sandbox-poc.XXXXXX")"
cleanup() { rm -rf "$_tmp_root" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

WITH_NET=0
RUN_CMD=""
case "${1:-}" in
  --with-net)
    WITH_NET=1
    shift
    ;;
esac
if [ "${1:-}" = "--" ]; then
  shift
  RUN_CMD="$*"
fi

PREFIX_DIR="${TEREM_PREFIX:-$_tmp_root/wineprefix}"
mkdir -p "$PREFIX_DIR"
PREFIX_MOUNT="/prefix"   # where PREFIX_DIR appears INSIDE the sandbox

# ── 3. Build the bwrap argument list — the actual confinement policy ─────────
# Filesystem model: bwrap's mount namespace starts EMPTY. We add ONLY what's
# named below — nothing else in the real filesystem is visible, by
# construction, not by a denylist. This is the same "cannot reach cell holds
# because there is no device/tag wired up, not because a policy promises not
# to" discipline docs/os-portal-v2/02-security-consent-privacy.md §2.1 states
# for Guest Mode, applied here to App Mode's namespace jail instead of KVM.
set -- \
  --unshare-user \
  --unshare-ipc \
  --unshare-pid \
  --unshare-uts \
  --unshare-cgroup-try \
  --die-with-parent \
  --new-session \
  --cap-drop ALL \
  --clearenv \
  --setenv HOME "$PREFIX_MOUNT/home" \
  --setenv WINEPREFIX "$PREFIX_MOUNT" \
  --setenv PATH "/usr/bin:/bin" \
  --setenv TEREM_SANDBOXED "1" \
  --proc /proc \
  --dev /dev \
  --tmpfs /tmp \
  --chdir "$PREFIX_MOUNT"

# Minimal read-only system base — only what's needed to exec anything at all.
# Each is bound ONLY if it exists on this host; nothing is invented.
for d in /usr /bin /lib /lib64 /sbin; do
  [ -e "$d" ] && set -- "$@" --ro-bind "$d" "$d"
done

# The one read-write directory the sandboxed process ever sees: the prefix.
set -- "$@" --bind "$PREFIX_DIR" "$PREFIX_MOUNT"
mkdir -p "$PREFIX_DIR/home"

# Network: OFF by default (real namespace unshare, not just "no route").
# `--with-net` mirrors an explicit, per-app, consent-gated terem-gate
# exception (docs/os-portal-v2/APP-MODE-SANDBOX.md §5) — never the default.
if [ "$WITH_NET" -eq 0 ]; then
  set -- "$@" --unshare-net
else
  say "NETWORK ALLOWED for this run (--with-net) — this is the consented exception, never the shipped default."
  for f in /etc/resolv.conf /etc/hosts /etc/ssl /etc/nsswitch.conf; do
    [ -e "$f" ] && set -- "$@" --ro-bind "$f" "$f"
  done
fi

BWRAP_ARGS="$*"

# ── 4. Arbitrary-command mode — confine whatever the caller named ───────────
if [ -n "$RUN_CMD" ]; then
  say "running caller-supplied command inside the sandbox: $RUN_CMD"
  # shellcheck disable=SC2086
  exec bwrap $BWRAP_ARGS -- /bin/sh -c "$RUN_CMD"
fi

# ── 5. Self-check mode (default) — prove the confinement, don't just assert it ─
CANARY_NAME="terem-poc-canary-$$"
REAL_HOME="${HOME:-}"
CANARY_PATH=""
if [ -n "$REAL_HOME" ] && [ -d "$REAL_HOME" ] && [ -w "$REAL_HOME" ]; then
  CANARY_PATH="$REAL_HOME/.$CANARY_NAME"
  echo "if-the-sandbox-can-read-this-it-leaked" > "$CANARY_PATH"
  trap 'rm -f "$CANARY_PATH" 2>/dev/null || true; cleanup' EXIT INT TERM
fi

INNER='
set -eu
fails=0

# check 1: real host $HOME is unreachable (only relevant if a canary exists)
if [ -n "'"$CANARY_PATH"'" ]; then
  if find / -xdev -name "'"$CANARY_NAME"'" 2>/dev/null | grep -q .; then
    echo "  [1] FAIL: found the host-HOME canary from inside the sandbox — host $HOME leaked in"
    fails=$((fails+1))
  else
    echo "  [1] PASS: host \$HOME canary is unreachable from inside the sandbox"
  fi
else
  echo "  [1] SKIP: no writable real \$HOME to canary against on this run"
fi

# check 2: cannot write outside the prefix (the ro-bound system base)
if touch /usr/terem-poc-write-test 2>/dev/null; then
  echo "  [2] FAIL: wrote into /usr — read-only bind is not holding"
  fails=$((fails+1))
else
  echo "  [2] PASS: write into /usr (read-only bind) correctly refused"
fi

# check 3: CAN write/read inside the prefix
echo "prefix-write-ok" > /prefix/terem-poc-write-test 2>/dev/null || { echo "  [3] FAIL: could not write inside the prefix at all"; fails=$((fails+1)); }
if [ "$(cat /prefix/terem-poc-write-test 2>/dev/null)" = "prefix-write-ok" ]; then
  echo "  [3] PASS: read/write inside the prefix works as expected"
else
  echo "  [3] FAIL: wrote inside the prefix but could not read it back"
  fails=$((fails+1))
fi

# check 4: network posture
if [ "'"$WITH_NET"'" -eq 0 ]; then
  if [ -e /etc/resolv.conf ]; then
    echo "  [4] FAIL: /etc/resolv.conf exists — DNS should be structurally impossible by default"
    fails=$((fails+1))
  else
    echo "  [4] PASS: no /etc/resolv.conf — DNS resolution is structurally impossible (default, no consent given)"
  fi
  if command -v python3 >/dev/null 2>&1; then
    if python3 -c "import socket; s=socket.socket(); s.settimeout(2); s.connect((\"1.1.1.1\",80))" 2>/dev/null; then
      echo "  [4b] FAIL: outbound TCP connect SUCCEEDED despite --unshare-net — real leak"
      fails=$((fails+1))
    else
      echo "  [4b] PASS (best-effort): outbound TCP connect failed, as expected with no network namespace"
    fi
  else
    echo "  [4b] INFO: python3 not present in the sandbox base — best-effort connect check skipped, not required for PASS"
  fi
else
  if [ -e /etc/resolv.conf ]; then
    echo "  [4] PASS: --with-net requested, DNS config is present (the consented exception is in effect)"
  else
    echo "  [4] INFO: --with-net requested but no /etc/resolv.conf found on the host to bind — nothing to assert"
  fi
fi

if [ "$fails" -gt 0 ]; then
  echo "SELF-CHECK: $fails check(s) FAILED"
  exit 1
fi
echo "SELF-CHECK: all checks PASSED"
'

say "prefix dir  : $PREFIX_DIR (bound read-write at $PREFIX_MOUNT)"
say "network     : $([ "$WITH_NET" -eq 0 ] && echo 'OFF (default, --unshare-net)' || echo 'ON (--with-net, consented exception)')"
say "running self-check inside the sandbox..."
# shellcheck disable=SC2086
if bwrap $BWRAP_ARGS -- /bin/sh -c "$INNER"; then
  say "RESULT: PASS — confinement held for every check on this Linux host."
  exit 0
else
  say "RESULT: FAIL — see the [n] FAIL lines above. The sandbox leaked."
  exit "$FAIL_RC"
fi
