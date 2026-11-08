#!/usr/bin/env sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# test-check-boot-log.sh — self-test for check-boot-log.sh, the shared boot-log
# grader used by BOTH the QEMU rung (this dir's harness) and the hardware rung
# (the PinePhone serial capture).
#
# This validates the GRADER ONLY against synthetic logs — it does not boot
# anything; built ≠ booted, QEMU ≠ hardware, and the image remains unaudited.
#
# It runs check-boot-log.sh against hand-written fixtures under fixtures/ and
# asserts the documented exit codes, plus two no-fixture usage-error cases.
# It is strict POSIX sh (no bashisms: no arrays, no [[ ]], no bare `local`) and
# self-locates its own directory so it works from any cwd.
#
# Usage:  sh test-check-boot-log.sh   (no arguments)
#         CHECK_BOOT_LOG=/path/to/alternate-grader.sh sh test-check-boot-log.sh
#           — points the self-test at a different grader script instead of the
#           in-tree check-boot-log.sh. This exists so a mutation/negative-path
#           check can prove the self-test actually detects a regressed grader,
#           without ever touching the real check-boot-log.sh. Unset (the
#           default), it runs the real, shared grader.
# Exit:   0 all self-test cases passed
#         1 one or more self-test cases failed
set -eu

# Resolve our own directory (CDPATH= cd is the scoped-empty idiom, matching
# check-boot-log.sh) so this runs the same whether invoked as
# `sh test-check-boot-log.sh` from this dir or `sh os/boot-harness/…` from the
# repo root.
# shellcheck disable=SC1007
SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

GRADER="${CHECK_BOOT_LOG:-$SELF_DIR/check-boot-log.sh}"
MARKERS="$SELF_DIR/success-markers.txt"
FIXTURES="$SELF_DIR/fixtures"

if [ -n "${CHECK_BOOT_LOG:-}" ]; then
  echo "CHECK_BOOT_LOG override in effect: grading against '$GRADER', NOT the in-tree check-boot-log.sh."
fi

pass_count=0
total_count=0

# run_case NAME LOG_ARG MARKERS_ARG EXPECTED_RC
# LOG_ARG/MARKERS_ARG of "-" mean "omit this argument".
run_case() {
  name=$1
  log_arg=$2
  markers_arg=$3
  expected=$4

  total_count=$((total_count + 1))

  rc=0
  if [ "$log_arg" = "-" ]; then
    sh "$GRADER" >/dev/null 2>&1 || rc=$?
  elif [ "$markers_arg" = "-" ]; then
    sh "$GRADER" "$log_arg" >/dev/null 2>&1 || rc=$?
  else
    sh "$GRADER" "$log_arg" "$markers_arg" >/dev/null 2>&1 || rc=$?
  fi

  if [ "$rc" -eq "$expected" ]; then
    echo "ok    $name (rc=$rc, expected $expected)"
    pass_count=$((pass_count + 1))
  else
    echo "FAIL  $name (rc=$rc, expected $expected)"
  fi
}

run_case "pass.log -> 0"              "$FIXTURES/pass.log"              "$MARKERS" 0
run_case "kernel-panic.log -> 2"      "$FIXTURES/kernel-panic.log"      "$MARKERS" 2
run_case "stage1-emergency.log -> 2"  "$FIXTURES/stage1-emergency.log"  "$MARKERS" 2
run_case "out-of-order.log -> 1"      "$FIXTURES/out-of-order.log"      "$MARKERS" 1
run_case "no arguments -> 3"          "-"                               "-"        3
run_case "nonexistent markers -> 3"   "$FIXTURES/pass.log"              "$SELF_DIR/does-not-exist-markers.txt" 3

echo "$pass_count/$total_count grader self-test cases passed"

if [ "$pass_count" -eq "$total_count" ]; then
  exit 0
else
  exit 1
fi
