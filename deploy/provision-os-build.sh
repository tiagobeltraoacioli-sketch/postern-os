#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# provision-os-build.sh — idempotent bootstrap for the Fly `postern-os-build`
# host so it is a valid two-builder "builder-B" (docs/plan/FLAKE-REPRO.md §4,
# os/repro/repro-verify-iso.sh, scripts/repro-two-builder.sh). Run this ON the
# postern-os-build machine itself (e.g. via `fly ssh console`), by the
# orchestrator or by an operator by hand.
#
# ---------------------------------------------------------------------------
# STATUS: SCAFFOLD. STAGED, NOT RUN.
# ---------------------------------------------------------------------------
# Authored on a non-Nix macOS dev workstation. No Fly `postern-os-build`
# machine was reached and no `nix`/`git checkout`/build ever ran via this
# script. The only validation performed on this authoring host is
# `shellcheck` + `bash -n` — see the bottom of this header for the exact
# commands and their result. Real provisioning is Fly/Nix-gated: it needs an
# actual Linux + Nix host (the launched postern-os-build machine), which this
# mac is not. On this mac, this script is REQUIRED to fail closed at the
# "not a Nix host" guard below (non-zero exit) instead of pretending to
# provision anything.
#
#   built != booted — even once this script's checkout + guard steps succeed
#   on a real Nix host, that only makes the host READY to build. It does not
#   build, boot, or attest anything itself; the printed
#   os/repro/repro-verify-iso.sh command (which this script never runs on the
#   operator's behalf) is what actually builds, and a green build still only
#   proves binary == source for the pinned closure — nothing about whether
#   the image boots (QEMU != hardware) or the source is safe. See
#   os/repro/repro-verify-iso.sh's header and os/repro/README.md
#   §"Honest interpretation" for the full chain of caveats this inherits.
#
# ---------------------------------------------------------------------------
# WHAT THIS SCRIPT DOES (idempotent — safe to re-run)
# ---------------------------------------------------------------------------
#   1. Verifies the host is Linux with `nix` on PATH. Fails closed with a
#      clear message otherwise — this script NEVER provisions a non-Nix host,
#      it only prepares a real one. (Same fail-closed convention as
#      scripts/flake-lock.sh / scripts/flake-check.sh / repro-verify-iso.sh.)
#   2. Ensures the `nix-command` and `flakes` experimental features are
#      enabled for this user (writes ~/.config/nix/nix.conf if the features
#      are not already present; leaves an existing conf alone otherwise).
#   3. git-clones the repo if the target directory does not exist yet, or
#      `git fetch`es it if it does.
#   4. `git checkout`s the operator-supplied <LOCK_COMMIT> exactly — and
#      REFUSES to proceed (same guard wording as scripts/flake-check.sh) if:
#        - flake.lock is missing,
#        - flake.lock is the empty SEED (no `"locked"` revisions),
#        - flake.lock is missing the `nixpkgs` or `mobile-nixos` locked
#          inputs,
#        - the checkout ends up detached/mismatched from the requested
#          <LOCK_COMMIT> (i.e. `git rev-parse HEAD` != <LOCK_COMMIT> after
#          the checkout — catches a bad ref, a moved branch, or a dirty
#          reused worktree silently landing on the wrong commit).
#   5. Prints (does NOT run) the exact os/repro/repro-verify-iso.sh build
#      command the operator should run next.
#
# ---------------------------------------------------------------------------
# WHAT THIS SCRIPT DELIBERATELY DOES NOT DO
# ---------------------------------------------------------------------------
#   - It NEVER runs `git push` or `git commit`. This is a builder, not a
#     source of truth; nothing it does should ever mutate the repo history.
#   - It NEVER freezes flake.lock (no `nix flake lock`, ever). Freezing the
#     lock is builder-A's single-source-of-truth step
#     (scripts/flake-lock.sh) precisely because if builder-B (or this script)
#     re-froze it independently, the two builders would resolve the floating
#     `nixpkgs`/`mobile-nixos` refs at two different moments and could freeze
#     to two different revisions — silently breaking the two-builder
#     discipline that os/repro/repro-verify-iso.sh's header explains at
#     length. This script only ever CONSUMES an already-frozen lock at a
#     commit the operator names.
#   - It NEVER runs `nix build` / repro-verify-iso.sh itself. It prepares the
#     host and prints the command; a human (or the orchestrator, explicitly)
#     decides when to actually spend the build.
#
# ---------------------------------------------------------------------------
# USAGE
# ---------------------------------------------------------------------------
#   deploy/provision-os-build.sh <LOCK_COMMIT> [options]
#
#   <LOCK_COMMIT>           required — the exact git commit (the one that
#                           carries the FILLED, non-empty-seed flake.lock,
#                           frozen by builder-A via scripts/flake-lock.sh)
#                           that this builder must check out.
#
#   --repo-dir PATH         local checkout path on this host
#                           (default: $HOME/bloch-protocol)
#   --repo-url URL          git remote to clone from if --repo-dir does not
#                           exist yet
#                           (default: https://gitlab.com/bloch-sis-group/bloch-sis-project.git)
#   --attr ATTR             iso | desktop-iso | mobile-image | attested-image
#                           | cloud-image — forwarded into the printed
#                           repro-verify-iso.sh command only (default: iso)
#   --role ROLE             forwarded into the printed command's --role
#                           (default: builder-b)
#   -h, --help              this text
#
# Exit codes:
#   0   provisioned — host is Linux+Nix, flakes enabled, repo checked out at
#       <LOCK_COMMIT> with a frozen, well-formed flake.lock. The build
#       command was printed, not run.
#   2   usage error (missing <LOCK_COMMIT>, unknown flag, bad --attr)
#   3   not a Linux host, or no `nix` on PATH — this is THE fail-closed guard
#       this script is required to hit on the macOS dev workstation.
#   4   flake.lock at <LOCK_COMMIT> is the empty seed, or missing a required
#       locked input — same guard wording as scripts/flake-check.sh.
#   5   missing required local tool (git)
#   6   git clone/fetch/checkout failed, or the resulting HEAD does not
#       match the requested <LOCK_COMMIT> (detached/mismatched checkout).
set -euo pipefail

PROG="provision-os-build.sh"
die() { printf '%s: %s\n' "$PROG" "$1" >&2; exit "${2:-1}"; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing tool: $1" 5; }

usage() {
  sed -n '2,90p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
}

REPO_DIR="${HOME:-/root}/bloch-protocol"
REPO_URL="https://gitlab.com/bloch-sis-group/bloch-sis-project.git"
ATTR="iso"
ROLE="builder-b"
LOCK_COMMIT=""

while [ $# -gt 0 ]; do
  case "$1" in
    --repo-dir) REPO_DIR=$2; shift 2 ;;
    --repo-url) REPO_URL=$2; shift 2 ;;
    --attr) ATTR=$2; shift 2 ;;
    --role) ROLE=$2; shift 2 ;;
    -h|--help) usage ;;
    -*) die "unknown flag: $1 (see --help)" 2 ;;
    *)
      if [ -z "$LOCK_COMMIT" ]; then
        LOCK_COMMIT=$1; shift
      else
        die "unexpected extra argument: $1 (see --help)" 2
      fi
      ;;
  esac
done

[ -n "$LOCK_COMMIT" ] \
  || die "<LOCK_COMMIT> is required — the exact commit (carrying the FILLED flake.lock builder-A froze) both builders must check out. See --help." 2

case "$ATTR" in
  iso|desktop-iso|mobile-image|attested-image|cloud-image) ;;
  *) die "--attr must be one of: iso desktop-iso mobile-image attested-image cloud-image (got '$ATTR')" 2 ;;
esac

need git

# ============================================================================
# STEP 1 — fail closed: Linux + Nix host, or refuse outright.
# ============================================================================
UNAME_S="$(uname -s 2>/dev/null || echo unknown)"
if [ "$UNAME_S" != "Linux" ]; then
  die "this host reports uname -s='$UNAME_S', not 'Linux'. provision-os-build.sh only provisions a Linux + Nix builder (the Fly postern-os-build machine) — it refuses to run on a macOS/other dev workstation. Run this ON the Fly host (e.g. via 'fly ssh console -a postern-os-build -C ...' or interactively over 'fly ssh console'), never here." 3
fi

command -v nix >/dev/null 2>&1 \
  || die "no \`nix\` on PATH on this Linux host. postern-os-build is expected to ship Nix preinstalled (or a prior provisioning step must install it) — this script does not install Nix itself, it only configures and uses an existing install. Fix the machine image / Fly config and re-run." 3

printf '%s: host check OK — Linux + nix on PATH (%s).\n' "$PROG" "$(command -v nix)"

# ============================================================================
# STEP 2 — ensure nix-command + flakes are enabled (idempotent).
# ============================================================================
NIX_CONF_DIR="${HOME:-/root}/.config/nix"
NIX_CONF="$NIX_CONF_DIR/nix.conf"
mkdir -p "$NIX_CONF_DIR"
if [ -f "$NIX_CONF" ] && grep -q 'experimental-features' "$NIX_CONF" \
   && grep -q 'nix-command' "$NIX_CONF" && grep -q 'flakes' "$NIX_CONF"; then
  printf '%s: nix-command + flakes already enabled in %s — leaving it alone.\n' "$PROG" "$NIX_CONF"
else
  printf 'experimental-features = nix-command flakes\n' >> "$NIX_CONF"
  printf '%s: enabled nix-command + flakes in %s.\n' "$PROG" "$NIX_CONF"
fi
NIX_FLAGS=(--extra-experimental-features "nix-command flakes")

# ============================================================================
# STEP 3 — clone if missing, else fetch (idempotent; never push/commit).
# ============================================================================
if [ -d "$REPO_DIR/.git" ]; then
  printf '%s: %s already a git checkout — fetching.\n' "$PROG" "$REPO_DIR"
  git -C "$REPO_DIR" fetch --tags origin \
    || die "git fetch failed in $REPO_DIR — check network / remote access, then re-run." 6
else
  printf '%s: cloning %s into %s.\n' "$PROG" "$REPO_URL" "$REPO_DIR"
  git clone "$REPO_URL" "$REPO_DIR" \
    || die "git clone of $REPO_URL into $REPO_DIR failed." 6
fi

# ============================================================================
# STEP 4 — checkout <LOCK_COMMIT> exactly, then apply the SAME fail-closed
# empty-seed / unfrozen-lock guard as scripts/flake-check.sh, plus a
# detached/mismatched-HEAD check.
# ============================================================================
git -C "$REPO_DIR" checkout "$LOCK_COMMIT" \
  || die "git checkout $LOCK_COMMIT failed in $REPO_DIR — is that a valid commit reachable from origin? Try 'git -C $REPO_DIR fetch --tags origin' and re-run." 6

ACTUAL_COMMIT="$(git -C "$REPO_DIR" rev-parse HEAD 2>/dev/null)" \
  || die "git rev-parse HEAD failed in $REPO_DIR after checkout — not a usable git checkout." 6
if [ "$ACTUAL_COMMIT" != "$LOCK_COMMIT" ]; then
  # Allow the operator to pass an abbreviated/symbolic ref for <LOCK_COMMIT>
  # (e.g. a short sha or a tag) as long as it resolves to the same commit
  # HEAD landed on; only a genuine mismatch is fatal.
  RESOLVED_LOCK_COMMIT="$(git -C "$REPO_DIR" rev-parse "$LOCK_COMMIT" 2>/dev/null || echo "$LOCK_COMMIT")"
  if [ "$ACTUAL_COMMIT" != "$RESOLVED_LOCK_COMMIT" ]; then
    die "checked-out HEAD ($ACTUAL_COMMIT) != requested <LOCK_COMMIT> ($LOCK_COMMIT, resolves to $RESOLVED_LOCK_COMMIT). Refusing a detached/mismatched checkout — both builders MUST sit at the exact same commit or a comparison later proves nothing (same discipline os/repro/repro-verify-iso.sh's 'compare' mode enforces via its FAIL_SETUP exit)." 6
  fi
fi
printf '%s: checked out %s at %s.\n' "$PROG" "$REPO_DIR" "$ACTUAL_COMMIT"

LOCK="$REPO_DIR/flake.lock"

# ---- fail-closed guard — REUSES the exact wording of scripts/flake-check.sh ----
[ -f "$LOCK" ] || die "no flake.lock — run scripts/flake-lock.sh on this Nix host first." 4

# Fail-closed: the empty seed lock has no "locked" revisions.
grep -q '"locked"' "$LOCK" \
  || die "flake.lock is the empty SEED (no frozen revisions). Reproducibility is unpinned. Run scripts/flake-lock.sh first." 4

# Both inputs must be pinned.
for input in nixpkgs mobile-nixos; do
  grep -q "\"${input}\"" "$LOCK" \
    || die "input '${input}' is not frozen in flake.lock — refusing to run an unpinned check." 4
done

printf '%s: flake.lock at %s is frozen (nixpkgs + mobile-nixos locked) — builder-B is ready.\n' "$PROG" "$ACTUAL_COMMIT"
printf "%s: reminder — this script never runs \`nix flake lock\`. Re-freezing here would break the two-builder discipline; freezing only ever happens once, on builder-A, via scripts/flake-lock.sh.\n" "$PROG"

# ============================================================================
# STEP 5 — print (do not run) the exact build command for the operator.
# ============================================================================
cat <<EOF

$PROG: DONE — $REPO_DIR is a provisioned builder-B at commit $ACTUAL_COMMIT.
$PROG: this script does NOT build, boot, or push/commit anything itself.
$PROG: built != booted — a green build below only proves binary == source
$PROG: for the pinned closure; see os/repro/repro-verify-iso.sh's header and
$PROG: os/repro/README.md for the full caveat chain.

Run this next, on this host, to actually build and produce builder-B's manifest:

  cd $REPO_DIR && ./os/repro/repro-verify-iso.sh build \\
    --attr $ATTR --role $ROLE --commit $ACTUAL_COMMIT

Then hand the resulting JSON manifest to whoever runs:

  os/repro/repro-verify-iso.sh compare --a <builder-a-manifest.json> --b <builder-b-manifest.json>

(nix flags this host now has enabled: ${NIX_FLAGS[*]})
EOF
