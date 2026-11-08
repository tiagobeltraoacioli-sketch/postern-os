#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# repro-verify-iso.sh — the two-builder bit-for-bit reproducibility PROOF for
# the Postern OS ISO (backlog item #19, docs/plan/FLAKE-REPRO.md §4), turned
# into a runnable tool instead of a narrative runbook.
#
# STATUS: STAGED, NOT RUN. Authored on a non-Nix macOS host. No `nix build`
# has ever happened against this repo here — this script cannot self-validate
# beyond `shellcheck` + a brace/usage read-through. Everything below is
# VM-gated (needs a real Linux + Nix host) exactly like scripts/flake-lock.sh
# and scripts/flake-check.sh, whose fail-closed conventions this mirrors.
#
#   built != booted . QEMU != hardware . reproducible-by-design != reproduced.
#   A PASS from this script proves `binary == source` for the pinned flake
#   input closure — nothing about whether that source is safe, correct, or
#   non-malicious (see the README.md next to this file, §"Honest
#   interpretation" — same distinction docs/store-fdroid/02-reproducible-
#   builds.md §4 draws for the app-store verifier; this is the OS-tier twin).
#
# ---------------------------------------------------------------------------
# WHY THIS CANNOT JUST BE "EACH BUILDER RUNS scripts/flake-lock.sh"
# ---------------------------------------------------------------------------
# `nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05"` and the `mobile-nixos`
# input are FLOATING refs. If builder A and builder B each independently ran
# `nix flake lock`, at two different moments, upstream `nixos-24.05` could have
# advanced between the two runs — they would freeze to *different* revisions
# and a store-path mismatch would prove nothing (a setup error, not
# nondeterminism). The only valid two-builder proof is:
#
#   1. ONE host freezes the lock (scripts/flake-lock.sh) and commits the
#      FILLED flake.lock — call that commit <LOCK_COMMIT>.
#   2. BOTH builder A and builder B check out the EXACT SAME <LOCK_COMMIT>
#      (not just "the same day" — the same git sha, carrying the same
#      byte-identical flake.lock).
#   3. Each builds `.#<attr>` and this script's `compare` mode diffs the
#      results.
#
# This script enforces that discipline: `build` mode refuses to run against
# the empty-seed lock (identical guard to scripts/flake-check.sh) and records
# both the git commit AND a sha256 of flake.lock itself in its output
# manifest; `compare` mode refuses to call a run a valid two-builder proof at
# all (FAIL_SETUP, not FAIL_DIVERGENCE) if those two fingerprints don't match
# between the two manifests being compared.
#
# ---------------------------------------------------------------------------
# USAGE
# ---------------------------------------------------------------------------
#   # On EACH builder (independent Nix host, already at the SAME <LOCK_COMMIT>):
#   repro-verify-iso.sh build --attr iso --role builder-a \
#       [--commit <expected-git-sha>] [--flake .] [--out FILE] [--s3 s3://bucket/prefix]
#
#   # Once both manifests exist (locally, or fetched from S3):
#   repro-verify-iso.sh compare --a builder-a.iso.json --b builder-b.iso.json
#   repro-verify-iso.sh compare --a s3://bucket/prefix/builder-a-iso.json \
#                                --b s3://bucket/prefix/builder-b-iso.json
#
# `--attr` accepts any of: iso, desktop-iso, mobile-image, attested-image,
# cloud-image (the same list FLAKE-REPRO.md §4 names as needing this same
# procedure repeated per artifact). Default: iso.
#
# Exit codes:
#   build:    0 manifest written; 3 not a Nix host; 4 empty-seed / unfrozen
#             lock; 5 missing tool; 6 commit mismatch; 7 `nix build` failed.
#   compare:  0 PASS (identical store path + narHash, same commit + lock);
#             2 usage; 5 missing tool; 8 FAIL_SETUP (different commit or
#             flake.lock fingerprint — not a valid two-builder comparison);
#             9 FAIL_DIVERGENCE (same source, different output — a real
#             nondeterminism/tamper signal, see the diffoscope-style next
#             step printed on this exit).
set -euo pipefail

PROG="repro-verify-iso.sh"
# Usage: die "message" [exit_code]  — exit_code defaults to 1. Deliberately
# uses "$1" (not "$*") so a trailing numeric exit-code arg never leaks into
# the printed message text.
die() { printf '%s: %s\n' "$PROG" "$1" >&2; exit "${2:-1}"; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing tool: $1" 5; }

usage() {
  sed -n '2,60p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
}

[ "${1:-}" = "build" ] || [ "${1:-}" = "compare" ] || usage
MODE=$1; shift

# ============================================================================
# MODE: build — run on ONE Nix host. Produces a JSON manifest.
# ============================================================================
build_mode() {
  ATTR="iso"
  ROLE=""
  EXPECT_COMMIT=""
  FLAKE="."
  OUT=""
  S3=""

  while [ $# -gt 0 ]; do
    case "$1" in
      --attr) ATTR=$2; shift 2 ;;
      --role) ROLE=$2; shift 2 ;;
      --commit) EXPECT_COMMIT=$2; shift 2 ;;
      --flake) FLAKE=$2; shift 2 ;;
      --out) OUT=$2; shift 2 ;;
      --s3) S3=$2; shift 2 ;;
      -h|--help) usage ;;
      *) die "build: unknown arg: $1" 2 ;;
    esac
  done
  [ -n "$ROLE" ] || die "build: --role builder-a|builder-b (or any label) is required — it goes in the manifest so compare mode can tell the two runs apart" 2

  case "$ATTR" in
    iso|desktop-iso|mobile-image|attested-image|cloud-image) ;;
    *) die "build: --attr must be one of: iso desktop-iso mobile-image attested-image cloud-image (got '$ATTR')" 2 ;;
  esac

  need nix
  need jq
  need git
  # sha256sum (Linux) vs shasum -a 256 (macOS/BSD) — checked inline below,
  # not with `need`, since exactly one of the two is expected to be present.

  NIX_FLAGS=(--extra-experimental-features "nix-command flakes")

  cd "$FLAKE"
  ROOT="$(pwd)"
  LOCK="$ROOT/flake.lock"

  command -v nix >/dev/null 2>&1 \
    || die "no 'nix' on PATH. This is VM-gated — run on a Linux + Nix host, never the macOS dev workstation." 3

  # ---- fail-closed: refuse the empty seed, exactly like scripts/flake-check.sh ----
  [ -f "$LOCK" ] || die "no flake.lock at $ROOT — nothing pinned, nothing to reproduce." 4
  grep -q '"locked"' "$LOCK" \
    || die "flake.lock is the EMPTY SEED (no frozen revisions). Run scripts/flake-lock.sh and commit the FILLED lock FIRST — both builders must share that exact commit before this proof means anything." 4
  for input in nixpkgs mobile-nixos; do
    grep -q "\"${input}\"" "$LOCK" \
      || die "input '${input}' is not frozen in flake.lock — refusing an unpinned run." 4
  done

  # ---- commit pin: refuse a checkout that isn't the agreed <LOCK_COMMIT> ----
  ACTUAL_COMMIT=$(git rev-parse HEAD 2>/dev/null) \
    || die "not inside a git checkout — cannot record/verify the commit this build ran against." 6
  if [ -n "$EXPECT_COMMIT" ] && [ "$ACTUAL_COMMIT" != "$EXPECT_COMMIT" ]; then
    die "checked-out commit ($ACTUAL_COMMIT) != --commit expected ($EXPECT_COMMIT). Both builders MUST be at the exact same commit (the one that carries the FILLED flake.lock) or a mismatch proves nothing about reproducibility — it just proves two different sources were compared." 6
  fi
  DIRTY=""
  git diff --quiet 2>/dev/null || DIRTY="dirty-worktree"
  git diff --cached --quiet 2>/dev/null || DIRTY="dirty-worktree"
  [ -z "$DIRTY" ] || echo "WARN: worktree has uncommitted changes — the build reflects the working tree, not just $ACTUAL_COMMIT. This is honestly recorded in the manifest, not hidden." >&2

  # ---- fingerprint flake.lock itself (belt-and-suspenders vs. "same commit") ----
  if command -v sha256sum >/dev/null 2>&1; then
    LOCK_SHA=$(sha256sum "$LOCK" | awk '{print $1}')
  else
    LOCK_SHA=$(shasum -a 256 "$LOCK" | awk '{print $1}')
  fi

  HOSTNAME_STR=$(hostname 2>/dev/null || echo unknown-host)
  NIX_VERSION=$(nix "${NIX_FLAGS[@]}" --version 2>/dev/null | head -n1 || echo unknown)
  SYSTEM=$(nix "${NIX_FLAGS[@]}" eval --raw --impure --expr 'builtins.currentSystem' 2>/dev/null || echo unknown)
  TS=$(date -u +%FT%TZ)

  echo "==> [$ROLE] building .#$ATTR at commit $ACTUAL_COMMIT (flake.lock sha256:$LOCK_SHA) on $HOSTNAME_STR ($SYSTEM, $NIX_VERSION)" >&2

  # ---- the actual build ----
  STORE_PATH=$(nix "${NIX_FLAGS[@]}" build ".#${ATTR}" --print-out-paths 2>&1 | tee /dev/stderr | tail -n1) \
    || die "'nix build .#${ATTR} --print-out-paths' failed — see output above. Not a reproducibility result; the build itself is broken." 7
  case "$STORE_PATH" in
    /nix/store/*) ;;
    *) die "did not get a /nix/store/... path from --print-out-paths (got: '$STORE_PATH'). Build likely failed silently or printed extra noise; investigate before trusting any manifest." 7 ;;
  esac
  echo "==> [$ROLE] store path: $STORE_PATH" >&2

  PATH_INFO_JSON=$(nix "${NIX_FLAGS[@]}" path-info --json "$STORE_PATH")

  # `nix path-info --json` has shipped both as a bare array (recent Nix) and,
  # on older Nix, as an object keyed by store path. Normalize to the fields we
  # actually compare so `compare` mode doesn't have to guess the shape twice.
  NORM=$(printf '%s' "$PATH_INFO_JSON" | jq -c '
    if type == "array" then .[0]
    else (to_entries[0] | .value + {path: .key})
    end
    | {path: .path, narHash: .narHash, narSize: .narSize}
  ')
  [ -n "$NORM" ] && [ "$NORM" != "null" ] \
    || die "could not parse a {path, narHash, narSize} record out of 'nix path-info --json' output — inspect it by hand: $PATH_INFO_JSON" 7

  MANIFEST=$(jq -n \
    --arg role "$ROLE" \
    --arg attr "$ATTR" \
    --arg commit "$ACTUAL_COMMIT" \
    --arg dirty "$DIRTY" \
    --arg lock_sha256 "$LOCK_SHA" \
    --arg hostname "$HOSTNAME_STR" \
    --arg system "$SYSTEM" \
    --arg nix_version "$NIX_VERSION" \
    --arg timestamp "$TS" \
    --argjson output "$NORM" \
    --argjson path_info_raw "$PATH_INFO_JSON" \
    '{
      role: $role,
      attr: $attr,
      source: { commit: $commit, worktree: (if $dirty == "" then "clean" else $dirty end), flake_lock_sha256: $lock_sha256 },
      build_env: { hostname: $hostname, system: $system, nix_version: $nix_version },
      output: $output,
      path_info_raw: $path_info_raw,
      timestamp: $timestamp
    }')

  OUT=${OUT:-"repro-${ROLE}-${ATTR}.json"}
  printf '%s\n' "$MANIFEST" | jq . > "$OUT"
  echo "==> [$ROLE] manifest written: $OUT" >&2
  echo "==> [$ROLE] store_path=$(printf '%s' "$NORM" | jq -r .path)  narHash=$(printf '%s' "$NORM" | jq -r .narHash)" >&2

  if [ -n "$S3" ]; then
    need aws
    DEST="${S3%/}/${ROLE}-${ATTR}.json"
    echo "==> [$ROLE] uploading manifest to $DEST" >&2
    aws s3 cp "$OUT" "$DEST" || echo "WARN: manifest upload to $DEST failed — manifest is still on disk at $OUT, retry the upload by hand." >&2
  fi

  echo "==> [$ROLE] DONE. Hand this manifest ($OUT) to 'repro-verify-iso.sh compare' once the other builder's manifest also exists." >&2
}

# ============================================================================
# MODE: compare — run ANYWHERE with jq (does not need Nix itself).
# ============================================================================
compare_mode() {
  A="" B=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --a) A=$2; shift 2 ;;
      --b) B=$2; shift 2 ;;
      -h|--help) usage ;;
      *) die "compare: unknown arg: $1" 2 ;;
    esac
  done
  [ -n "$A" ] && [ -n "$B" ] || die "compare: --a FILE_OR_S3 --b FILE_OR_S3 are both required" 2
  need jq

  fetch() {
    case "$1" in
      s3://*)
        need aws
        LOCAL="${TMPDIR:-/tmp}/repro-cmp-$(basename "$1")"
        aws s3 cp "$1" "$LOCAL" >&2 || die "fetch: aws s3 cp failed for $1" 2
        printf '%s' "$LOCAL"
        ;;
      *)
        [ -r "$1" ] || die "fetch: cannot read $1" 2
        printf '%s' "$1"
        ;;
    esac
  }

  AF=$(fetch "$A")
  BF=$(fetch "$B")

  A_ROLE=$(jq -r '.role' "$AF"); B_ROLE=$(jq -r '.role' "$BF")
  A_ATTR=$(jq -r '.attr' "$AF"); B_ATTR=$(jq -r '.attr' "$BF")
  A_COMMIT=$(jq -r '.source.commit' "$AF"); B_COMMIT=$(jq -r '.source.commit' "$BF")
  A_LOCK=$(jq -r '.source.flake_lock_sha256' "$AF"); B_LOCK=$(jq -r '.source.flake_lock_sha256' "$BF")
  A_DIRTY=$(jq -r '.source.worktree' "$AF"); B_DIRTY=$(jq -r '.source.worktree' "$BF")
  A_PATH=$(jq -r '.output.path' "$AF"); B_PATH=$(jq -r '.output.path' "$BF")
  A_HASH=$(jq -r '.output.narHash' "$AF"); B_HASH=$(jq -r '.output.narHash' "$BF")
  A_HOST=$(jq -r '.build_env.hostname' "$AF"); B_HOST=$(jq -r '.build_env.hostname' "$BF")

  echo "== repro-verify-iso.sh compare =="
  echo "  builder A: role=$A_ROLE host=$A_HOST attr=$A_ATTR commit=$A_COMMIT worktree=$A_DIRTY"
  echo "  builder B: role=$B_ROLE host=$B_HOST attr=$B_ATTR commit=$B_COMMIT worktree=$B_DIRTY"
  echo ""

  # ---- setup validity FIRST: same attr, same commit, same flake.lock bytes ----
  FAIL_SETUP=0
  [ "$A_ATTR" = "$B_ATTR" ] || { echo "SETUP FAIL: different attrs compared ($A_ATTR vs $B_ATTR) — not the same artifact." >&2; FAIL_SETUP=1; }
  [ "$A_COMMIT" = "$B_COMMIT" ] || { echo "SETUP FAIL: different commits ($A_COMMIT vs $B_COMMIT) — the two builders were NOT building the same source. A store-path mismatch here would prove nothing; fix the checkout and re-run both builds." >&2; FAIL_SETUP=1; }
  [ "$A_LOCK" = "$B_LOCK" ] || { echo "SETUP FAIL: flake.lock sha256 differs ($A_LOCK vs $B_LOCK) even though commits match?! Investigate immediately — this should be impossible for a clean checkout of the same commit and likely means a dirty worktree or a corrupted clone." >&2; FAIL_SETUP=1; }
  if [ "$A_DIRTY" != "clean" ] || [ "$B_DIRTY" != "clean" ]; then
    echo "SETUP WARN: at least one builder had a dirty worktree (A=$A_DIRTY, B=$B_DIRTY). The comparison below is still computed, but this is not a clean two-builder proof — commit or stash local changes and re-run." >&2
    FAIL_SETUP=1
  fi

  if [ "$FAIL_SETUP" -ne 0 ]; then
    echo ""
    echo "RESULT: FAIL_SETUP — this is not a valid two-builder comparison yet. Fix the setup issue(s) above and re-run 'build' on whichever side is wrong before drawing any reproducibility conclusion." >&2
    exit 8
  fi

  echo "  store path (A): $A_PATH"
  echo "  store path (B): $B_PATH"
  echo "  narHash    (A): $A_HASH"
  echo "  narHash    (B): $B_HASH"
  echo ""

  if [ "$A_PATH" = "$B_PATH" ] && [ "$A_HASH" = "$B_HASH" ]; then
    echo "RESULT: PASS — identical store path AND identical narHash."
    echo "  Two independent builders, same commit ($A_COMMIT), same flake.lock"
    echo "  (sha256:$A_LOCK), produced byte-for-byte identical output for .#$A_ATTR."
    echo "  This is the strongest *build*-reproducibility signal Nix gives."
    echo ""
    echo "  What this does NOT prove: that the source at $A_COMMIT is safe,"
    echo "  correct, or non-malicious (binary == source, not source == safe —"
    echo "  see README.md next to this script); that the ISO boots (built !="
    echo "  booted — os/boot-harness-x86/); or anything about real hardware"
    echo "  (QEMU != hardware)."
    exit 0
  fi

  echo "RESULT: FAIL_DIVERGENCE — same commit, same flake.lock, DIFFERENT output." >&2
  echo "  This is either genuine build nondeterminism in .#$A_ATTR's derivation" >&2
  echo "  graph (a real bug: unpinned timestamps, parallelism-dependent ordering," >&2
  echo "  embedded build paths/hostnames, non-deterministic codegen, etc.) or —" >&2
  echo "  less likely but not excludable from this script alone — a compromised" >&2
  echo "  builder. A mismatch is not automatically evidence of tampering; Nix" >&2
  echo "  substantially reduces but does not eliminate nondeterminism sources." >&2
  echo "" >&2
  echo "  DIFFOSCOPE-STYLE NEXT STEP (do this before concluding anything):" >&2
  echo "    1. Get both outputs onto one machine, e.g.:" >&2
  echo "         nix copy --to file:///tmp/repro-diff $A_PATH   # from builder A" >&2
  echo "         nix copy --to file:///tmp/repro-diff $B_PATH   # from builder B" >&2
  echo "       or fetch each store path's nar via 'nix store dump-path' over ssh" >&2
  echo "       from each builder if they are reachable." >&2
  echo "    2. Coarse, Nix-native closure diff first (cheap, no extra tooling):" >&2
  echo "         nix store diff-closures $A_PATH $B_PATH" >&2
  echo "       (needs both closures present/substitutable on the comparing host)" >&2
  echo "    3. Byte-level diff with diffoscope (the real tool for this — same" >&2
  echo "       recommendation docs/store-fdroid/02-reproducible-builds.md makes" >&2
  echo "       for the app-store tier):" >&2
  echo "         nix run nixpkgs#diffoscope -- $A_PATH $B_PATH" >&2
  echo "       diffoscope recurses into the ISO filesystem, squashfs, individual" >&2
  echo "       binaries (strings/objdump/etc.) and reports the FIRST actual" >&2
  echo "       differing bytes/files — usually one of: embedded build timestamp," >&2
  echo "       embedded /nix/store/<hash> self-reference that Nix's own hash" >&2
  echo "       rewriting missed, locale/PATH-dependent ordering in a generated" >&2
  echo "       manifest, or (rare, worth escalating) an actually different input." >&2
  echo "    4. Classify the diff per the known-benign / unexplained split before" >&2
  echo "       calling this either 'explained nondeterminism, low severity' or" >&2
  echo "       'unexplained — do not ship, do not sign, escalate.'" >&2
  echo "" >&2
  echo "  Record the diffoscope output alongside these two manifests as the" >&2
  echo "  committed evidence for whatever verdict is reached — do not silently" >&2
  echo "  re-run until it happens to match; that would hide the nondeterminism," >&2
  echo "  not fix it." >&2
  exit 9
}

case "$MODE" in
  build) build_mode "$@" ;;
  compare) compare_mode "$@" ;;
esac
