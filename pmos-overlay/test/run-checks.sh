#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# pmos-overlay/test/run-checks.sh -- single entrypoint for the pmOS
# community-edition overlay's static test harness. Runs, in order:
#
#   1. lint-shell.sh   -- sh -n + shellcheck over every shell script in the
#                          overlay (see that script's own header for the
#                          exact file list and rules).
#   2. check-drift.sh  -- cross-file string agreement: do the apk filenames
#                          composed from each APKBUILD's pkgname/pkgver/pkgrel
#                          still match PUBLISHED.md and build/verify-apks.sh,
#                          and does the signing-key name still agree between
#                          them.
#
# Both are STATIC, HOST-SIDE, TEXT-ONLY checks. This harness does not build,
# boot, sign, or attest anything, and it does not execute any of the scripts
# it is checking -- it only parses/lints their source text (lint-shell.sh)
# and greps/diffs plain-text files (check-drift.sh). See ./README.md for the
# full, exact scope statement -- read that before relying on a green run
# here for anything more than "the source text is internally consistent".
#
# Exit status: the FIRST nonzero exit among the two checks is propagated as
# this script's own exit status, and neither check's normal stdout/stderr is
# suppressed -- run-checks.sh only adds one PASS/FAIL summary line per check
# on top of that. If lint-shell.sh fails, check-drift.sh still runs (so a
# single invocation reports on both checks), but the exit code reflects the
# first failure.
#
# Usage (from any cwd -- paths resolve relative to this script's own
# location, not the caller's cwd):
#   sh pmos-overlay/test/run-checks.sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

overall_exit=0

printf '=== run-checks: lint-shell.sh ===\n'
if sh "$SCRIPT_DIR/lint-shell.sh"; then
	printf 'run-checks: PASS  lint-shell.sh\n'
else
	lint_exit=$?
	printf 'run-checks: FAIL  lint-shell.sh (exit %d)\n' "$lint_exit" >&2
	overall_exit=$lint_exit
fi

printf '\n=== run-checks: check-drift.sh ===\n'
if sh "$SCRIPT_DIR/check-drift.sh"; then
	printf 'run-checks: PASS  check-drift.sh\n'
else
	drift_exit=$?
	printf 'run-checks: FAIL  check-drift.sh (exit %d)\n' "$drift_exit" >&2
	if [ "$overall_exit" -eq 0 ]; then
		overall_exit=$drift_exit
	fi
fi

exit "$overall_exit"
