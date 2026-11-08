#!/usr/bin/env bash
# check-porog-tor-glue-live.sh — the LIVE-FEATURE OFFLINE GATE for
# apps/porog-tor-glue, part of the offline HOST battery (docs/noporis-porog/TEST-GATE.md #10).
#
# Parity with scripts/check-noporis-tor-glue-live.sh, adapted for Porog. Where the
# NoporIS wrapper only COMPILE-CHECKS its live surface (`cargo check --features live`),
# Porog already ships offline live-feature TESTS (`live_tests`, 9 passed) that
# behavior-verify the arti-backed path's *types* — the `EgressError` enum, its
# `#[from] postern_tor::TorError` conversion — and re-prove the shared fail-closed
# egress rule UNDER the `live` feature, all without ever calling
# `ContainerTor::bootstrap()` or touching the network. So this gate RUNS that
# surface (`cargo test --features live --offline`) rather than merely checking it.
#
# WHY THIS EXISTS
# The pure per-container egress policy layer (`egress_decision`, the fail-closed
# "no Tor is a deny" rule, `honest_enforcement_label`, the anti-round-up guard)
# compiles and tests WITHOUT the heavy `live` feature — that is what the default
# `cargo test` covers fast (5 passed). But the `cfg(feature = "live")` module
# (`ContainerTor` / `EgressError`, the arti-backed egress path) is NOT built by the
# default battery, so it can silently rot as the policy layer it calls into evolves
# (a renamed `Decision` method, a changed egress-note signature, etc.). The runtime
# bootstrap is — correctly — network-dependent and never run in the offline battery
# (`ContainerTor::bootstrap()` is documented "not built in this sandbox"), so it
# cannot catch a compile/behavior break either.
#
# This gate closes that hole: it builds AND runs the `cfg(feature = "live")` surface
# offline (arti / postern-tor already vendored in Cargo.lock + the local cargo
# cache), guaranteeing the live API keeps building and its type/fail-closed
# invariants keep holding as the pure layer changes — WITHOUT bootstrapping Tor,
# touching the network, or claiming any runtime / anonymity property.
#
# What green here proves, and NOTHING more: the live-path source still type-checks
# against the current policy layer and its offline type/fail-closed tests pass. It
# does NOT run the live bootstrap, does NOT prove reachability, and says nothing
# about isolation strength or anonymity. Tor here is metadata-reduction, not
# anonymity — "hardened, not anonymous." And this is an UNAUDITED reference
# prototype: compile-checked != booted != anonymous, and none of it is on-device
# DPC enforcement.
#
# Exit non-zero on a compile/test break so CI/host battery fails loudly.
set -uo pipefail
cd "$(dirname "$0")/../apps/porog-tor-glue"

echo "== porog-tor-glue live-feature offline gate (TEST-GATE #10) =="
echo "   cargo test --features live --offline   (no network, no bootstrap)"
echo
echo "   HONEST BANNER: compile-checked != booted != anonymous, UNAUDITED."
echo "   - Runs the cfg(feature=\"live\") ContainerTor/EgressError type + fail-closed"
echo "     surface OFFLINE; never calls ContainerTor::bootstrap(), never touches the net."
echo "   - Tor is metadata-reduction, NOT anonymity — hardened, not anonymous."
echo "   - Proves nothing about on-device DPC enforcement or live Tor reachability."
echo

if cargo test --features live --offline; then
  echo
  echo "OK: cfg(feature=\"live\") ContainerTor/EgressError still compiles AND its"
  echo "    offline type/fail-closed tests pass — no network, no Tor bootstrap."
  echo "    compile-checked != booted != anonymous, UNAUDITED reference-prototype."
  exit 0
else
  status=$?
  echo "FAIL: the live-feature path no longer builds/passes offline (exit ${status})." >&2
  echo "      The pure egress-policy layer likely changed an API the" >&2
  echo "      cfg(feature=\"live\") module depends on. Fix apps/porog-tor-glue/src/lib.rs" >&2
  echo "      'mod live' (and its live_tests)." >&2
  exit "${status}"
fi
