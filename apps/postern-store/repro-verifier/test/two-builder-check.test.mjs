// Real, executable proof that lib/two-builder-check.mjs's compare/verdict
// logic (02-reproducible-builds.md §1b steps 2-5) works, WITHOUT requiring a
// Nix installation on this host (this host genuinely has none — see the
// honesty banner in docs/store-fdroid/POC-repro-and-agpl.md and
// lib/two-builder-check.mjs's header comment).
//
// The store-path strings below are MOCK values used only to drive
// twoBuilderCheck()'s comparison logic in isolation. They are deliberately
// NOT plausible-looking real Nix hashes (no `nix-store`-style base32) —
// prefixed "MOCK-" precisely so nobody mistakes them for a real computed
// hash, per this repo's discipline of never fabricating a hash and passing
// it off as real (docs/store-fdroid/POC-repro-and-agpl.md §0). The REAL,
// nix-calling entry point this same compare logic backs is
// scripts/two-builder-check.mjs, proven-real by the last test below.
import { test } from "node:test";
import assert from "node:assert/strict";

import { twoBuilderCheck, nixBuildOnce, checkNixAvailable } from "../lib/two-builder-check.mjs";

const MOCK_PATH_A = "/nix/store/MOCK-deadbeef-postern-repro-poc";
const MOCK_PATH_B_DIFFERENT = "/nix/store/MOCK-c0ffee00-postern-repro-poc";
const MOCK_SHIPPED_MISMATCH = "/nix/store/MOCK-fee1dead-postern-repro-poc";

/** Injectable mock execFn: returns each queued stdout string in sequence. */
function mockExec(sequence) {
  let i = 0;
  return () => {
    const v = sequence[Math.min(i, sequence.length - 1)];
    i++;
    return v + "\n";
  };
}

test("twoBuilderCheck: PASS when builder A, builder B, and the shipped artifact all match", () => {
  const execFn = mockExec([MOCK_PATH_A, MOCK_PATH_A]);
  const result = twoBuilderCheck({ flakeRef: ".#poc", shippedPath: MOCK_PATH_A, execFn });
  assert.equal(result.verdict, "PASS");
  assert.equal(result.rebuild_match, true);
  assert.equal(result.shipped_match, true);
});

test("twoBuilderCheck: PASS with no shippedPath given (rebuild-only check, step 4 only)", () => {
  const execFn = mockExec([MOCK_PATH_A, MOCK_PATH_A]);
  const result = twoBuilderCheck({ flakeRef: ".#poc", execFn });
  assert.equal(result.verdict, "PASS");
  assert.equal(result.shipped_match, null);
});

test("twoBuilderCheck: FAIL_NONDETERMINISM when independent rebuilds disagree with each other (step 4)", () => {
  const execFn = mockExec([MOCK_PATH_A, MOCK_PATH_B_DIFFERENT]);
  const result = twoBuilderCheck({ flakeRef: ".#poc", shippedPath: MOCK_PATH_A, execFn });
  assert.equal(result.verdict, "FAIL_NONDETERMINISM");
  assert.equal(result.rebuild_match, false);
  assert.equal(result.shipped_match, null, "step 5 must not even run once step 4 already fails");
});

test("twoBuilderCheck: FAIL_DIVERGENCE when rebuilds agree with each other but not the shipped artifact — the 'mutate' scenario (step 5)", () => {
  const execFn = mockExec([MOCK_PATH_A, MOCK_PATH_A]);
  const result = twoBuilderCheck({ flakeRef: ".#poc", shippedPath: MOCK_SHIPPED_MISMATCH, execFn });
  assert.equal(result.verdict, "FAIL_DIVERGENCE");
  assert.equal(result.rebuild_match, true, "the verifier's own two rebuilds ARE internally reproducible...");
  assert.equal(result.shipped_match, false, "...but disagree with what was actually shipped, per 02-reproducible-builds.md §1d");
});

test("checkNixAvailable/nixBuildOnce REAL default path: this host genuinely has no Nix, proving the script is real and not a simulation", () => {
  assert.equal(checkNixAvailable(), false, "this host has no nix binary (see POC-repro-and-agpl.md honesty banner)");
  assert.throws(() => nixBuildOnce(".#poc"), /ENOENT|command not found|not found/i);
});
