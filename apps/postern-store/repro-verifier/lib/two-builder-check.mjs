// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Postern Labs and Postern community contributors
//
// The two-builder reproducibility check — docs/store-fdroid/
// 02-reproducible-builds.md §1b steps 2-5 and the exact mechanism
// docs/store-fdroid/POC-repro-and-agpl.md Part 1 walks through by hand:
//   1. `nix build <flakeRef> --print-out-paths` on builder A.
//   2. `nix build <flakeRef> --print-out-paths` again, independently, on
//      builder B.
//   3. Compare A vs B. Mismatch -> FAIL_NONDETERMINISM (step 4).
//   4. If a `shippedPath` is given, compare the agreed rebuild vs it.
//      Mismatch -> FAIL_DIVERGENCE (step 5).
//   5. Otherwise PASS.
//
// HONESTY NOTE (matches POC-repro-and-agpl.md's own banner): this host has
// no Nix installed (`which nix` -> not found, verified when this file was
// written). `nixBuildOnce`'s default `execFn` genuinely spawns the real
// `nix` binary via node:child_process — it is REAL, RUNNABLE-ON-A-NIX-BOX
// code, not a simulation, and on THIS host it will genuinely fail with
// ENOENT/"command not found" if invoked without an injected `execFn`,
// exactly as it should. `execFn` is injectable ONLY so tests can exercise
// the compare/verdict logic in twoBuilderCheck() below without a Nix
// installation — production callers (scripts/two-builder-check.mjs) never
// pass it. No hash is ever fabricated here: the default path either gets a
// real Nix-computed store path or throws.

import { execFileSync } from "node:child_process";

function defaultExec(cmd, args, opts = {}) {
  return execFileSync(cmd, args, { encoding: "utf8", ...opts });
}

/** True iff a real `nix` binary answers `nix --version` on this host. */
export function checkNixAvailable(execFn = defaultExec) {
  try {
    execFn("nix", ["--version"], {});
    return true;
  } catch {
    return false;
  }
}

/**
 * Runs `nix build <flakeRef> --print-out-paths --no-link` once. Real by
 * default. Returns the store path(s) Nix printed, one per line, trimmed.
 * Throws if Nix is unavailable or the build fails — never returns a
 * fabricated path.
 */
export function nixBuildOnce(flakeRef, { execFn = defaultExec, cwd } = {}) {
  const stdout = execFn("nix", ["build", flakeRef, "--print-out-paths", "--no-link"], cwd ? { cwd } : {});
  const paths = stdout
    .trim()
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);
  if (paths.length === 0) {
    throw new Error(`nix build ${flakeRef} produced no --print-out-paths output`);
  }
  return paths;
}

/**
 * The full two-builder check. `cwdA`/`cwdB` should be genuinely independent
 * checkouts (separate hosts/containers in production — 02-reproducible-
 * builds.md §1b step 2 names same-host-two-invocations as "the weaker
 * fallback if only one builder is available", not the real bar).
 *
 * @param {{flakeRef: string, shippedPath?: string|null, execFn?: Function, cwdA?: string, cwdB?: string}} opts
 */
export function twoBuilderCheck({ flakeRef, shippedPath = null, execFn = defaultExec, cwdA, cwdB }) {
  const [pathA] = nixBuildOnce(flakeRef, { execFn, cwd: cwdA });
  const [pathB] = nixBuildOnce(flakeRef, { execFn, cwd: cwdB });

  if (pathA !== pathB) {
    return {
      verdict: "FAIL_NONDETERMINISM",
      rebuild_match: false,
      shipped_match: null, // step 5 is not even attempted once step 4 already fails
      builderA_path: pathA,
      builderB_path: pathB,
      shipped_path: shippedPath,
      diagnostic: `builder A produced ${pathA}, builder B produced ${pathB} — independent rebuilds disagree (02-reproducible-builds.md §1d)`,
    };
  }

  if (shippedPath != null && pathA !== shippedPath) {
    return {
      verdict: "FAIL_DIVERGENCE",
      rebuild_match: true,
      shipped_match: false,
      builderA_path: pathA,
      builderB_path: pathB,
      shipped_path: shippedPath,
      diagnostic: `rebuild is internally reproducible (${pathA}) but does not match the shipped artifact (${shippedPath}) — §1d divergence FAIL`,
    };
  }

  return {
    verdict: "PASS",
    rebuild_match: true,
    shipped_match: shippedPath == null ? null : true,
    builderA_path: pathA,
    builderB_path: pathB,
    shipped_path: shippedPath,
    diagnostic: null,
  };
}
