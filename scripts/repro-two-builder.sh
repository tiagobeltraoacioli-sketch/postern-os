#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# repro-two-builder.sh — two-host bit-for-bit reproducibility ORCHESTRATOR for
# the Postern OS L1 image (backlog #19, docs/plan/FLAKE-REPRO.md §4, the same
# procedure os/repro/repro-verify-iso.sh implements one host at a time). This
# script drives BOTH sides of that procedure from one place:
#
#   builder-A: local host, or a remote host over plain ssh (--host-a)
#   builder-B: the Fly `postern-os-build` machine, driven over
#              `fly ssh console -C '<remote command>'`
#
# It does NOT reimplement the manifest/compare logic — that lives in
# os/repro/repro-verify-iso.sh and stays the single source of truth for what
# "build" and "compare" mean. This script only: (1) fails closed on missing
# prerequisites, (2) runs `repro-verify-iso.sh build` on each side at the
# SAME pinned commit, (3) fetches both JSON manifests locally, (4) runs
# `repro-verify-iso.sh compare` on them, and (5) prints one honest verdict.
#
# ---------------------------------------------------------------------------
# STATUS: SCAFFOLD. STAGED, NOT RUN — authored on a non-Nix macOS host.
# ---------------------------------------------------------------------------
# No `nix build` has happened anywhere via this script. The only validation
# performed on this authoring host is `shellcheck` + `bash -n`. A real
# MATCH/MISMATCH verdict needs: a Nix host for builder-A (this mac has none),
# an authenticated `fly` CLI + a launched/reachable `postern-os-build` Fly
# machine for builder-B, and a git commit that carries a FILLED (non-empty-
# seed) flake.lock. None of that is available here — see the FAIL-CLOSED
# section below for exactly what this script does about that: it refuses to
# print MATCH and exits non-zero with a BLOCKED verdict instead.
#
#   built != booted . QEMU != hardware . reproducible-by-design != reproduced.
#   A MATCH verdict from this script proves `binary == source` for the pinned
#   flake input closure on TWO independent hosts — nothing about whether that
#   source is safe, correct, or non-malicious, whether the resulting image
#   BOOTS, or how it behaves on real hardware. See os/repro/README.md
#   §"Honest interpretation" (same distinction docs/store-fdroid/
#   02-reproducible-builds.md §4 draws for the app-store verifier tier).
#
# ---------------------------------------------------------------------------
# FAIL-CLOSED PREFLIGHT (this is the part that actually runs on this mac)
# ---------------------------------------------------------------------------
# Before touching either builder, this script refuses to proceed — and prints
# a BLOCKED verdict, never MATCH — if ANY of:
#   - `nix` is absent on whichever host will run builder-A (this macOS
#     authoring host, unless --host-a points at a real Nix box);
#   - `fly` is absent, OR `fly auth whoami` fails (not authenticated);
#   - flake.lock at the target commit is the EMPTY SEED, or is missing the
#     `nixpkgs` / `mobile-nixos` locked inputs (same guard
#     os/repro/repro-verify-iso.sh and scripts/flake-check.sh already apply —
#     duplicated here only as an orchestrator-level pre-check so a doomed run
#     never reaches either builder; the authoritative check still lives in
#     repro-verify-iso.sh and runs again on each builder);
#   - required arguments for the chosen builder-A mode are missing
#     (--remote-path-a when --host-a is set).
#
# ---------------------------------------------------------------------------
# USAGE
# ---------------------------------------------------------------------------
#   scripts/repro-two-builder.sh [options]
#
#   --attr ATTR            iso | desktop-iso | mobile-image | attested-image |
#                           cloud-image   (default: iso)
#   --commit SHA            the <LOCK_COMMIT> both builders must check out
#                           (default: `git rev-parse HEAD` at --flake)
#   --flake PATH            local repo checkout used for builder-A and to run
#                           `compare` (default: this script's repo root)
#   --host-a SSH_TARGET      run builder-A over ssh instead of locally
#   --remote-path-a PATH     repo checkout path on --host-a (required if
#                           --host-a is set)
#   --fly-app NAME           Fly app name for builder-B (default:
#                           postern-os-build)
#   --remote-path-b PATH     repo checkout path on the Fly machine (default:
#                           /root/bloch-protocol — adjust to the real launched
#                           postern-os-build machine's layout)
#   --out-dir DIR            where to write/fetch the two JSON manifests
#                           (default: a fresh mktemp directory)
#   -h, --help                this text
#
# Exit codes:
#   0   MATCH        — compare mode PASS (identical store path + narHash)
#   8   BLOCKED       — compare mode FAIL_SETUP (different commit/lock/dirty
#                       worktree between the two manifests — not a valid
#                       two-builder comparison)
#   9   MISMATCH      — compare mode FAIL_DIVERGENCE (same source, different
#                       output — see repro-verify-iso.sh's diffoscope-style
#                       next-step output)
#   2   usage error
#   5   missing required local tool (fly, ssh, jq, or git)
#   10  BLOCKED        — orchestrator-level preflight gate failed (no nix, fly
#                       unauthenticated/absent, empty-seed lock, missing
#                       required args, or an ssh/fly transport failure)
set -euo pipefail

PROG="repro-two-builder.sh"
die() { printf '%s: %s\n' "$PROG" "$1" >&2; exit "${2:-1}"; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing tool: $1" 5; }

usage() {
  sed -n '2,80p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
}

blocked() {
  # blocked "reason one" "reason two" ...  — prints the BLOCKED verdict and
  # exits non-zero. NEVER call this after a MATCH has been determined.
  printf '\n'
  printf '== repro-two-builder.sh: FAIL-CLOSED ==\n' >&2
  for reason in "$@"; do
    printf '  - %s\n' "$reason" >&2
  done
  printf '\n' >&2
  printf 'VERDICT: BLOCKED\n' >&2
  printf '  This is NOT a MATCH. This is NOT a MISMATCH. The two-builder\n' >&2
  printf '  comparison never ran — fix the reason(s) above and re-run.\n' >&2
  printf '  built != booted . reproducible-by-design != reproduced.\n' >&2
  exit 10
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT_DEFAULT="$(cd "$SCRIPT_DIR/.." && pwd)"

ATTR="iso"
LOCK_COMMIT=""
FLAKE="$REPO_ROOT_DEFAULT"
HOST_A=""
REMOTE_PATH_A=""
FLY_APP="postern-os-build"
REMOTE_PATH_B="/root/bloch-protocol"
OUT_DIR=""

while [ $# -gt 0 ]; do
  case "$1" in
    --attr) ATTR=$2; shift 2 ;;
    --commit) LOCK_COMMIT=$2; shift 2 ;;
    --flake) FLAKE=$2; shift 2 ;;
    --host-a) HOST_A=$2; shift 2 ;;
    --remote-path-a) REMOTE_PATH_A=$2; shift 2 ;;
    --fly-app) FLY_APP=$2; shift 2 ;;
    --remote-path-b) REMOTE_PATH_B=$2; shift 2 ;;
    --out-dir) OUT_DIR=$2; shift 2 ;;
    -h|--help) usage ;;
    *) die "unknown arg: $1 (see --help)" 2 ;;
  esac
done

case "$ATTR" in
  iso|desktop-iso|mobile-image|attested-image|cloud-image) ;;
  *) die "--attr must be one of: iso desktop-iso mobile-image attested-image cloud-image (got '$ATTR')" 2 ;;
esac

need git
need jq

REPRO_VERIFY="$FLAKE/os/repro/repro-verify-iso.sh"
[ -x "$REPRO_VERIFY" ] || [ -f "$REPRO_VERIFY" ] \
  || die "cannot find os/repro/repro-verify-iso.sh under --flake ($FLAKE) — this orchestrator calls it, it does not reimplement it." 2

# Resolve <LOCK_COMMIT> if not given explicitly, purely for the plan/manifest
# pinning below — this does NOT skip the empty-seed guard.
if [ -z "$LOCK_COMMIT" ]; then
  LOCK_COMMIT=$(cd "$FLAKE" && git rev-parse HEAD 2>/dev/null) || LOCK_COMMIT=""
fi

# ============================================================================
# FAIL-CLOSED PREFLIGHT — collect every reason before deciding, so a single
# run tells the operator everything wrong at once instead of one-at-a-time.
# ============================================================================
GATE_FAILS=()

if [ -z "$LOCK_COMMIT" ]; then
  GATE_FAILS+=("no --commit given and \`git rev-parse HEAD\` failed at --flake ($FLAKE) — not a git checkout, or no commits yet. Both builders must pin the exact same <LOCK_COMMIT>; nothing to pin here.")
fi

LOCK_FILE="$FLAKE/flake.lock"
if [ ! -f "$LOCK_FILE" ]; then
  GATE_FAILS+=("no flake.lock at $FLAKE — nothing pinned, nothing to reproduce. Run scripts/flake-lock.sh on a Nix host first and commit the FILLED lock.")
elif ! grep -q '"locked"' "$LOCK_FILE"; then
  GATE_FAILS+=("flake.lock at $FLAKE is the EMPTY SEED (no frozen revisions). Run scripts/flake-lock.sh on a Nix host and commit the FILLED lock as <LOCK_COMMIT> BEFORE this proof means anything — see os/repro/repro-verify-iso.sh's header for why each builder re-locking independently would prove nothing.")
else
  for input in nixpkgs mobile-nixos; do
    grep -q "\"${input}\"" "$LOCK_FILE" \
      || GATE_FAILS+=("flake.lock input '${input}' is not frozen — refusing an unpinned two-builder run.")
  done
fi

if [ -n "$HOST_A" ]; then
  [ -n "$REMOTE_PATH_A" ] \
    || GATE_FAILS+=("--host-a $HOST_A given but --remote-path-a is not set — need the repo checkout path on that host.")
  if command -v ssh >/dev/null 2>&1; then
    if ! ssh -o BatchMode=yes -o ConnectTimeout=10 "$HOST_A" 'command -v nix' >/dev/null 2>&1; then
      GATE_FAILS+=("no \`nix\` on PATH on --host-a ($HOST_A), or that host is unreachable over ssh. builder-A needs a real Nix host.")
    fi
  else
    GATE_FAILS+=("no \`ssh\` on PATH locally — cannot drive --host-a ($HOST_A).")
  fi
else
  if ! command -v nix >/dev/null 2>&1; then
    GATE_FAILS+=("no \`nix\` on PATH on this host — this is VM-gated (same as scripts/flake-lock.sh / scripts/flake-check.sh). Run builder-A on a real Linux + Nix host, either locally there or via --host-a <ssh-target> from here. macOS dev workstations are never a valid Nix builder.")
  fi
fi

if ! command -v fly >/dev/null 2>&1; then
  GATE_FAILS+=("no \`fly\` CLI on PATH — cannot drive builder-B on the Fly $FLY_APP host via \`fly ssh console -C\`.")
else
  if ! fly auth whoami >/dev/null 2>&1; then
    GATE_FAILS+=("\`fly\` CLI is present but not authenticated (\`fly auth whoami\` failed) — run \`fly auth login\` first.")
  fi
fi

if [ "${#GATE_FAILS[@]}" -gt 0 ]; then
  blocked "${GATE_FAILS[@]}"
fi

# ============================================================================
# From here on, every prerequisite above was verified present and reachable.
# On THIS mac (no nix, and fly not pre-authenticated in this environment)
# execution never reaches this point — see the reported result below.
# ============================================================================

OUT_DIR="${OUT_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/repro-two-builder.XXXXXX")}"
mkdir -p "$OUT_DIR"
OUT_A="$OUT_DIR/builder-a-$ATTR.json"
OUT_B="$OUT_DIR/builder-b-$ATTR.json"

echo "== repro-two-builder.sh =="
echo "  attr:        $ATTR"
echo "  commit:      $LOCK_COMMIT"
echo "  builder-A:   $( [ -n "$HOST_A" ] && echo "$HOST_A:$REMOTE_PATH_A" || echo "local:$FLAKE" )"
echo "  builder-B:   fly:$FLY_APP:$REMOTE_PATH_B"
echo "  out-dir:     $OUT_DIR"
echo ""

# build_remote_cmd REPO_PATH ROLE OUT_PATH — one safely-quoted remote command
# string, run via ssh or `fly ssh console -C`. Best-effort `git fetch` (a
# machine that only ever sees one pinned commit may have no remote reachable,
# or may already have it) — checkout failure is what actually fails the run.
build_remote_cmd() {
  local repo_path=$1 role=$2 out_path=$3
  printf 'cd %q && { git fetch --tags >/dev/null 2>&1 || true; } && git checkout %q && ./os/repro/repro-verify-iso.sh build --attr %q --role %q --commit %q --out %q && cat %q' \
    "$repo_path" "$LOCK_COMMIT" "$ATTR" "$role" "$LOCK_COMMIT" "$out_path" "$out_path"
}

echo "==> [builder-a] running repro-verify-iso.sh build ..." >&2
if [ -n "$HOST_A" ]; then
  REMOTE_CMD_A=$(build_remote_cmd "$REMOTE_PATH_A" builder-a "/tmp/repro-builder-a-$ATTR.json")
  ssh -o BatchMode=yes -o ConnectTimeout=10 "$HOST_A" "$REMOTE_CMD_A" > "$OUT_A" \
    || die "builder-A ssh run failed — see output above. Not a reproducibility result; the build/transport itself failed." 10
else
  "$REPRO_VERIFY" build --attr "$ATTR" --role builder-a --commit "$LOCK_COMMIT" --flake "$FLAKE" --out "$OUT_A" \
    || die "builder-A local run failed — see output above." 10
fi
echo "==> [builder-a] manifest: $OUT_A" >&2

echo "==> [builder-b] running repro-verify-iso.sh build on Fly ($FLY_APP) via fly ssh console -C ..." >&2
REMOTE_CMD_B=$(build_remote_cmd "$REMOTE_PATH_B" builder-b "/tmp/repro-builder-b-$ATTR.json")
fly ssh console -a "$FLY_APP" -C "$REMOTE_CMD_B" > "$OUT_B" \
  || die "builder-B \`fly ssh console -C\` run failed — see output above. Not a reproducibility result; the build/transport itself failed." 10
echo "==> [builder-b] manifest: $OUT_B" >&2
echo ""

# ============================================================================
# Compare — delegated entirely to repro-verify-iso.sh; this script only maps
# its exit code to the MATCH / MISMATCH / BLOCKED vocabulary requested here.
# ============================================================================
set +e
"$REPRO_VERIFY" compare --a "$OUT_A" --b "$OUT_B"
COMPARE_RC=$?
set -e

echo ""
case "$COMPARE_RC" in
  0)
    echo "VERDICT: MATCH — identical store path + narHash, same commit ($LOCK_COMMIT), same flake.lock, on two independent builders."
    echo "  built != booted . QEMU != hardware . reproducible-by-design != reproduced."
    echo "  This proves binary == source for .#$ATTR at $LOCK_COMMIT — nothing about"
    echo "  whether that source is safe, whether the image boots, or real-hardware behavior."
    exit 0
    ;;
  9)
    echo "VERDICT: MISMATCH (FAIL_DIVERGENCE) — same commit, same flake.lock, DIFFERENT output." >&2
    echo "  See the diffoscope-style next steps repro-verify-iso.sh printed above." >&2
    exit 9
    ;;
  8)
    blocked "repro-verify-iso.sh compare returned FAIL_SETUP (exit 8) — the two manifests are not a valid two-builder comparison (different commit, different flake.lock fingerprint, or a dirty worktree on one side). See its output above."
    ;;
  *)
    blocked "repro-verify-iso.sh compare exited with an unexpected code ($COMPARE_RC) — treat as unresolved, not as MATCH or MISMATCH."
    ;;
esac
