#!/usr/bin/env bash
#
# fill-outputhashes.sh — VM-GATED hash-filler for os/seal-gate.nix
# =================================================================
#
# HONEST STATUS / TIER: this script is SCAFFOLD, UNAUDITED, and VM-GATED. It is
# written on a non-Nix host and has NEVER been executed here — the only
# static-validation done on macOS is `shellcheck`. It fails-closed on any host
# without a working `nix` + `/nix/store`, so it can neither run nor "fill a
# hash" on the macOS workstation. A real fill only happens inside a Nix VM.
#
# WHAT IT DOES
#   os/seal-gate.nix pins 5 git-sourced crates via cargoLock.outputHashes, each
#   currently set to the fail-closed sentinel `lib.fakeHash`. On a Nix host the
#   first `nix build .#seal-gate` DELIBERATELY FAILS, printing the real
#   `sha256-…` for every mismatched fixed-output derivation. This script:
#     1. refuses to run unless it is really on a Nix host (fail-closed),
#     2. runs `nix build .#seal-gate --keep-going` and captures the log,
#     3. parses every "hash mismatch in fixed-output derivation" block,
#     4. rewrites ONLY the 5 known `lib.fakeHash` sentinels in os/seal-gate.nix
#        with the matching real hashes (in place, backup kept),
#     5. detects a dual-git-rev Cargo.lock collision and, if hit, prints the
#        dedupe workaround and exits non-zero WITHOUT lying about success.
#        NOTE: the collision this originally guarded against (bloch-crypto /
#        bloch-sis-pow / coherence-core / pqcrypto-internals pinned at both
#        `branch=main#ce85756…` and `rev=dd8df35…`) was ROOT-CAUSED AND FIXED
#        pre-box — see ./README.md's "§Dual-rev dedupe — FIXED pre-box" and
#        os/seal-gate.nix's header comment. `cargo metadata --locked` confirms
#        the lock is coherent with a single rev per crate. This step 5 guard is
#        left in place as defense-in-depth (fail-closed, not fail-silent) in
#        case a future dependency edit reintroduces a split git source.
#
# It never claims a build succeeded that did not; re-run `nix build .#seal-gate`
# yourself after this to get the actual bins. See ./README.md for the full
# procedure and the dual-rev caveat.
#
set -euo pipefail

# ── The 5 sentinel keys we are allowed to fill. These MUST match the git-sourced
#    crate `name-version`s in Cargo.lock and the keys in os/seal-gate.nix. If you
#    add/remove a git dependency, update this list AND os/seal-gate.nix together.
SENTINEL_KEYS=(
  "bloch-0.1.0-genesis"
  "bloch-crypto-0.1.0-genesis"
  "bloch-sis-pow-0.1.0"
  "coherence-core-0.1.0"
  "pqcrypto-internals-0.2.11"
)

log() { printf '[fill-outputhashes] %s\n' "$*" >&2; }
die() { printf '[fill-outputhashes] ERROR: %s\n' "$*" >&2; exit 1; }

# ── Locate the repo root and the target .nix file. ────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
NIX_FILE="${REPO_ROOT}/os/seal-gate.nix"
[ -f "${NIX_FILE}" ] || die "cannot find ${NIX_FILE}"
[ -f "${REPO_ROOT}/flake.nix" ] || die "cannot find ${REPO_ROOT}/flake.nix"

# ── FAIL-CLOSED host guard. This is the whole point of the VM gate: the script
#    must be inert on a non-Nix host so nobody can claim a fill happened on mac.
command -v nix >/dev/null 2>&1 || die "no \`nix\` on PATH — this is VM-gated; run it inside a Nix host, not macOS."
[ -d /nix/store ] || die "no /nix/store — not a Nix host; refusing to run (fail-closed)."

# ── 1. Confirm the flake actually exposes .#seal-gate (O2 must have wired it). ─
if ! nix eval ".#seal-gate.name" >/dev/null 2>&1; then
  die "flake output .#seal-gate does not evaluate — ask OS Dev O2 to wire the \`packages.<sys>.seal-gate\` attr into flake.nix first (see ./README.md)."
fi

# ── 2. Build (expected to FAIL on first run) and capture the log. ─────────────
BUILD_LOG="$(mktemp -t seal-gate-build.XXXXXX.log)"
trap 'rm -f "${BUILD_LOG}"' EXIT
log "running: nix build .#seal-gate --keep-going --no-link (first run is EXPECTED to fail-closed)"
# `--keep-going` so every FOD hash is reported in one pass, not just the first.
set +e
nix build "${REPO_ROOT}#seal-gate" --keep-going --no-link >"${BUILD_LOG}" 2>&1
BUILD_RC=$?
set -e
log "nix build exited ${BUILD_RC} (a non-zero code with hash mismatches is normal on the first run)."

# ── 3. Detect the dual-git-rev collision documented in os/seal-gate.nix. ──────
if grep -qiE 'duplicate|two .*sources|multiple .*rev|conflicting' "${BUILD_LOG}" \
   && grep -qiE 'git\+' "${BUILD_LOG}"; then
  log "-----------------------------------------------------------------------"
  log "POSSIBLE DUAL-GIT-REV COLLISION detected in the build log."
  log "Cargo.lock pins bloch-crypto / bloch-sis-pow / coherence-core at TWO"
  log "git revs (?branch=main#ce85756… AND ?rev=dd8df35…). importCargoLock keys"
  log "outputHashes by name-version and cannot hold two revs of one crate."
  log "FIX (needs cargo + repo access, NOT done by this script):"
  log "  regenerate Cargo.lock so each crate resolves to a SINGLE git rev, e.g."
  log "  align crates/postern-seal-companion's dep on the Bloch protocol to one"
  log "  rev, then \`cargo update -p bloch-crypto\` etc. and commit Cargo.lock."
  log "See ./README.md §Dual-rev dedupe. Aborting without filling (fail-closed)."
  log "-----------------------------------------------------------------------"
  exit 3
fi

# ── 4. Parse "hash mismatch in fixed-output derivation" blocks into name→hash. ─
#    Nix prints, per mismatched FOD:
#      error: hash mismatch in fixed-output derivation '/nix/store/<h>-<name>.drv':
#               specified: sha256-AAAA…   (our fakeHash)
#                  got:    sha256-<REAL>
#    We strip the 32-char store-hash prefix + .drv to recover <name-version>.
PARSED="$(awk '
  /hash mismatch in fixed-output derivation/ {
    if (match($0, /\x27[^\x27]+\x27/)) {
      drv = substr($0, RSTART + 1, RLENGTH - 2)
      k = split(drv, parts, "/")
      base = parts[k]
      sub(/\.drv$/, "", base)
      sub(/^[0-9a-df-np-sv-z]{32}-/, "", base)   # nix base32 store-hash prefix
      current = base
    }
    next
  }
  /got:/ && current != "" {
    for (i = 1; i <= NF; i++) {
      if ($i ~ /^sha256-/) { print current "\t" $i; current = ""; break }
    }
  }
' "${BUILD_LOG}")"

if [ -z "${PARSED}" ]; then
  log "no hash mismatches found in the build log."
  if [ "${BUILD_RC}" -eq 0 ]; then
    log "nix build SUCCEEDED — hashes appear already filled. Nothing to do."
    exit 0
  fi
  log "build failed but no fixed-output hash mismatch was parsed. Inspect the log:"
  cat "${BUILD_LOG}" >&2
  die "unrecognised nix build failure (see log above)."
fi

log "discovered the following (crate → got-hash) pairs — eyeball these:"
printf '%s\n' "${PARSED}" | sed 's/^/[fill-outputhashes]   /' >&2

# ── 5. Rewrite ONLY the known sentinel keys, in place, with a backup. ─────────
cp -p "${NIX_FILE}" "${NIX_FILE}.bak"
log "backup written to ${NIX_FILE}.bak"

filled=0
for key in "${SENTINEL_KEYS[@]}"; do
  hash="$(printf '%s\n' "${PARSED}" | awk -F'\t' -v k="${key}" '$1 == k { print $2; exit }')"
  if [ -z "${hash}" ]; then
    log "WARN: no got-hash reported for sentinel \"${key}\" (left as-is)."
    continue
  fi
  # Only touch a line that still holds the fakeHash sentinel for this exact key.
  if grep -qE "\"${key}\"[[:space:]]*=[[:space:]]*lib\.fakeHash;" "${NIX_FILE}"; then
    # Portable in-place edit (GNU + BSD sed differ on -i; write to temp instead).
    tmp="$(mktemp)"
    sed "s|\"${key}\"[[:space:]]*=[[:space:]]*lib\.fakeHash;|\"${key}\" = \"${hash}\";|" \
      "${NIX_FILE}" >"${tmp}"
    mv "${tmp}" "${NIX_FILE}"
    log "filled \"${key}\" = ${hash}"
    filled=$((filled + 1))
  else
    log "NOTE: \"${key}\" is not a lib.fakeHash sentinel anymore (already filled?) — skipped."
  fi
done

log "-----------------------------------------------------------------------"
log "filled ${filled}/${#SENTINEL_KEYS[@]} sentinel(s)."
if [ "${filled}" -ne "${#SENTINEL_KEYS[@]}" ]; then
  log "NOT all sentinels were filled. Do NOT claim a reproducible pin yet."
  log "Restore with:  mv ${NIX_FILE}.bak ${NIX_FILE}   if you want to retry clean."
  log "Then re-run \`nix build .#seal-gate --keep-going\` and inspect the diff."
  exit 4
fi

log "all sentinels filled. NEXT (this script does NOT do it for you):"
log "  1. re-run:  nix build .#seal-gate   → should now build postern-seal-gate"
log "             + postern-seal-verify, or reveal a dual-rev collision to dedupe."
log "  2. review:  git diff os/seal-gate.nix   (confirm 5 real sha256- values)"
log "  3. only after a clean build may you call the pin 'built' — not before."
log "-----------------------------------------------------------------------"
