#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# pmos-overlay/test/lint-shell.sh -- repeatable shellcheck + `sh -n` gate for
# every shell script in the pmOS community-edition overlay, baselined against
# pmos-overlay/test/BASELINE.md so the gate is both GREEN and DETERMINISTIC:
#
#   1. `sh -n FILE`    -- POSIX-sh parse check. Any failure here is always a
#      hard FAIL; there is no baseline for syntax errors.
#   2. `shellcheck FILE` (with the per-file arguments in shellcheck_args_for
#      below) -- static analysis. Its findings are reduced to a fingerprint
#      set of `path:line SCcode` and compared *exactly* against the
#      `BASELINE:` lines in ./BASELINE.md:
#         - a finding NOT in the baseline is a NEW issue        -> FAIL
#         - a baselined finding that no longer reproduces       -> FAIL
#           (drift: BASELINE.md is now describing a fix that isn't real, or
#           a finding shellcheck no longer reports for some other reason --
#           either way BASELINE.md must be edited to match reality)
#         - a baselined finding that still reproduces           -> PASS,
#           printed with a "known, baselined" note (NOT silence, and NOT
#           claimed as fixed)
#
# This script, and this repo's test/ scope generally, NEVER edits any file
# outside pmos-overlay/test/. Per-file shellcheck arguments below (-s sh,
# -x -P overlay, --exclude=SCxxxx) are targeted, one-file-(or-group)-at-a-
# time suppressions of specific, justified false positives -- never a
# blanket --exclude applied to every file, and never a rule disabled
# project-wide. See BASELINE.md for the false-positive rationale behind each
# excluded code, and its "Details" table for the one true positive (SC2015)
# that is deliberately left in place, unfixed, as a recorded known issue.
#
# This is a HOST-SIDE STATIC CHECK ONLY. It never executes, builds, or boots
# any of the scripts below -- it only parses and lints their source text.
#
# Usage (from any cwd -- paths resolve relative to this script's own
# location, not the caller's cwd):
#   sh pmos-overlay/test/lint-shell.sh
set -eu

# ---- resolve paths relative to this script, regardless of caller's cwd ----
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
OVERLAY_DIR=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)
cd "$OVERLAY_DIR"

BASELINE_FILE="test/BASELINE.md"

# The file list is maintained BY HAND, not by `find`, so that adding a new
# shell script to the overlay is a deliberate, reviewable one-line change --
# not something that silently starts (or stops) being linted. Paths are
# relative to $OVERLAY_DIR (i.e. pmos-overlay/).
FILES="
build/build.sh
build/verify-apks.sh
flavor/first-run/postern-first-run.sh
flavor/postern-flavor/postern-flavor.post-install
flavor/postern-flavor/postern-flavor.post-upgrade
keys/postern-keygen.sh
overlay/etc/conf.d/postern-node
overlay/etc/conf.d/postern-tor
overlay/etc/init.d/postern-firewall
overlay/etc/init.d/postern-node
overlay/etc/init.d/postern-tor
overlay/usr/libexec/postern/postern-common.sh
postern/postern.post-install
publish-apk-repo.sh
publish-to-r2.sh
setup-aarch64.sh
test/check-drift.sh
test/lint-shell.sh
test/run-checks.sh
"

# Function: shellcheck_args_for <path-relative-to-OVERLAY_DIR>
# Prints the extra shellcheck arguments for that file, one file group per
# case arm. Every arm below is a targeted, justified false-positive
# suppression for that exact file (or file group) -- see BASELINE.md's
# "False positives" section for the full rationale on each SC code.
shellcheck_args_for() {
	case "$1" in
	overlay/usr/libexec/postern/postern-common.sh)
		# SC2148 false positive: this file is meant to be `.`-sourced by the
		# postern-node/postern-tor OpenRC init scripts and intentionally
		# carries no shebang of its own. Every other script in this overlay
		# is POSIX sh, so we state that explicitly instead of asking a
		# sourced-only fragment to grow a shebang it will never use.
		printf '%s' '-s sh'
		;;
	overlay/etc/init.d/postern-firewall | overlay/etc/init.d/postern-node | overlay/etc/init.d/postern-tor)
		# SC1008 false positive: '#!/sbin/openrc-run' is a real,
		# POSIX-sh-compatible interpreter on postmarketOS/Alpine, but its
		# shebang parser doesn't recognize that; -s sh states the real
		# target shell directly.
		# SC1091 false positive (via -x -P overlay): the
		# `. /usr/libexec/postern/postern-common.sh` line sources by the
		# script's *installed* absolute path, not its repo-relative path;
		# -P overlay lets shellcheck resolve it against
		# overlay/usr/libexec/postern/postern-common.sh instead.
		# SC2034 false positive: name/description/command/command_*/
		# pidfile/*_log/supervisor/postern_*/supervise_daemon_args are
		# OpenRC's own special variable names, read by the openrc-run
		# framework that sources this script -- not by the script's own
		# text, which is exactly the blind spot SC2034 warns it has.
		printf '%s' '-s sh -x -P overlay --exclude=SC2034'
		;;
	overlay/etc/conf.d/postern-node | overlay/etc/conf.d/postern-tor)
		# SC2148 false positive: conf.d fragments are `.`-sourced by their
		# init.d script and intentionally carry no shebang; real shell is sh.
		# SC2034 false positive: postern_*/supervise_daemon_args here are
		# read by the corresponding init.d script (and the OpenRC framework)
		# after this file is sourced, not by this file itself.
		printf '%s' '-s sh --exclude=SC2034'
		;;
	*)
		# Every other script in this overlay carries its own correct
		# `#!/bin/sh` shebang already; -s sh just makes that explicit so the
		# result can't depend on a given host's shellcheck auto-detection.
		printf '%s' '-s sh'
		;;
	esac
}

# The shellcheck binary to use: the $SHELLCHECK env var overrides the PATH
# lookup (which also lets a test point it at a nonexistent path to prove the
# next line really bites). A missing shellcheck is a HARD FAILURE, not a
# degraded sh-n-only pass: the BASELINE.md comparison below is meaningless
# without it, and a host (or CI runner) missing the tool must go red, not
# quietly green.
SHELLCHECK_BIN="${SHELLCHECK:-shellcheck}"
if ! command -v "$SHELLCHECK_BIN" >/dev/null 2>&1; then
	printf 'lint-shell: FAIL  shellcheck is required but "%s" was not found -- install shellcheck (https://www.shellcheck.net/) or set the SHELLCHECK env var to its path. Refusing to pass a degraded sh-n-only gate.\n' "$SHELLCHECK_BIN" >&2
	exit 1
fi

WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/lint-shell.XXXXXX")
trap 'rm -rf "$WORK_DIR"' EXIT INT TERM

CURRENT_FP="$WORK_DIR/current-fingerprints.txt"
RAW_OUT="$WORK_DIR/raw-shellcheck-output.txt"
: >"$CURRENT_FP"
: >"$RAW_OUT"

fail=0
checked=0

for f in $FILES; do
	if [ ! -f "$f" ]; then
		printf 'lint-shell: FAIL  %s (file listed in FILES but not found)\n' "$f" >&2
		fail=1
		continue
	fi
	checked=$((checked + 1))

	if ! sh -n "$f" 2>&1; then
		printf 'lint-shell: FAIL  %s (sh -n: syntax error)\n' "$f" >&2
		fail=1
		continue
	fi

	extra_args=$(shellcheck_args_for "$f")
	# extra_args is a controlled, space-separated flag list built
	# entirely by shellcheck_args_for above (no user input, no globs);
	# word-splitting it below is intentional.
	# shellcheck disable=SC2086
	"$SHELLCHECK_BIN" $extra_args -f gcc "$f" >>"$RAW_OUT" 2>&1 || :
done

# Reduce raw gcc-format output to a sorted, unique `path:line SCcode`
# fingerprint set. gcc format:
#   path:line:col: severity: message [SCxxxx]
sed -nE 's/^([^:]+):([0-9]+):[0-9]+: [a-z]+: .*\[(SC[0-9]+)\]$/\1:\2 \3/p' \
	"$RAW_OUT" | sort -u >"$CURRENT_FP"

BASELINE_FP="$WORK_DIR/baseline-fingerprints.txt"
if [ -f "$BASELINE_FILE" ]; then
	sed -nE 's/^BASELINE: (.+)$/\1/p' "$BASELINE_FILE" | sort -u >"$BASELINE_FP"
else
	: >"$BASELINE_FP"
fi

NEW_FP="$WORK_DIR/new-findings.txt"
MISSING_FP="$WORK_DIR/missing-baseline-entries.txt"
comm -23 "$CURRENT_FP" "$BASELINE_FP" >"$NEW_FP"
comm -13 "$CURRENT_FP" "$BASELINE_FP" >"$MISSING_FP"

if [ -s "$NEW_FP" ]; then
	printf 'lint-shell: FAIL  NEW shellcheck finding(s) not present in %s:\n' "$BASELINE_FILE" >&2
	while IFS=' ' read -r loc code; do
		printf '  %s %s\n' "$loc" "$code" >&2
	done <"$NEW_FP"
	printf '  -> either fix the issue, or if it is a genuine false positive, add a targeted --exclude for it in shellcheck_args_for(); otherwise record it as a known issue in %s (see "How to update this baseline")\n' "$BASELINE_FILE" >&2
	fail=1
fi

if [ -s "$MISSING_FP" ]; then
	printf 'lint-shell: FAIL  baseline entr(y/ies) in %s no longer reproduce (drift -- BASELINE.md is now out of date):\n' "$BASELINE_FILE" >&2
	while IFS=' ' read -r loc code; do
		printf '  %s %s\n' "$loc" "$code" >&2
	done <"$MISSING_FP"
	printf '  -> update %s to match reality: remove the stale BASELINE: line and its table row (this usually means the underlying issue got fixed -- good, but do not leave a stale baseline entry claiming it as still-open)\n' "$BASELINE_FILE" >&2
	fail=1
fi

if [ "$fail" -eq 0 ] && [ -s "$CURRENT_FP" ]; then
	printf 'lint-shell: known, baselined (see %s):\n' "$BASELINE_FILE"
	while IFS=' ' read -r loc code; do
		printf '  %s %s\n' "$loc" "$code"
	done <"$CURRENT_FP"
fi

if [ "$fail" -ne 0 ]; then
	printf 'lint-shell: FAIL (%d file(s) checked)\n' "$checked" >&2
	exit 1
fi

baselined_count=$(wc -l <"$CURRENT_FP" | tr -d ' ')
printf 'lint-shell: PASS (%d file(s): sh -n clean; shellcheck matches %s exactly -- %s known/baselined finding(s), 0 new, 0 drift)\n' \
	"$checked" "$BASELINE_FILE" "$baselined_count"
