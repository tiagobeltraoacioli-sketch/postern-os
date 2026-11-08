#!/usr/bin/env bash
# check-noporis-tor-glue-live.sh — the LIVE-FEATURE COMPILE GATE for
# apps/noporis-tor-glue, part of the offline HOST battery (docs/noporis-porog/TEST-GATE.md).
#
# WHY THIS EXISTS
# The pure per-persona policy layer (`persona_egress_decision`, the fail-closed
# egress rule, the honesty caveats) compiles and tests WITHOUT the heavy `live`
# feature — that is what `cargo test` covers fast (7 passed). But the
# `cfg(feature = "live")` module (`PersonaTor` / `PersonaWorlds`, the arti-backed
# egress path) is NOT type-checked by the default battery, so it can silently rot
# as the policy layer it calls into evolves (a renamed `Decision` method, a changed
# `persona_egress_note` signature, etc.). The runtime bootstrap is — correctly —
# a network-dependent `#[ignore]` test (`live_smoke_bootstrap_reaches_the_network`,
# run only with `--features live -- --ignored`), so it never runs in the offline
# battery and cannot catch a compile break either.
#
# This gate closes that hole: it COMPILE-CHECKS the live API offline (arti /
# postern-tor already vendored in Cargo.lock + the local cargo cache), guaranteeing
# the `cfg(feature = "live")` surface keeps building as the pure layer changes —
# WITHOUT bootstrapping Tor, touching the network, or claiming any runtime/anonymity
# property. Compile-checked != booted != anonymous.
#
# What green here proves, and NOTHING more: the live-path source still type-checks
# against the current policy layer. It does NOT run the live path, does NOT prove
# reachability (that stays the ignored smoke test), and says nothing about isolation
# strength or the GMS-out-of-scope ceiling.
#
# Exit non-zero on a compile break so CI/host battery fails loudly.
set -uo pipefail
cd "$(dirname "$0")/../apps/noporis-tor-glue"

echo "== noporis-tor-glue live-feature compile gate (offline) =="
echo "   cargo check --features live --offline"
if cargo check --features live --offline; then
  echo "OK: cfg(feature=\"live\") PersonaTor/PersonaWorlds still compiles offline."
  echo "    (compile-checked only — runtime bootstrap stays the ignored live smoke test)"
  exit 0
else
  status=$?
  echo "FAIL: the live-feature path no longer compiles (exit ${status})." >&2
  echo "      The pure policy layer likely changed an API the cfg(feature=\"live\")" >&2
  echo "      module depends on. Fix apps/noporis-tor-glue/src/lib.rs 'mod live'." >&2
  exit "${status}"
fi
