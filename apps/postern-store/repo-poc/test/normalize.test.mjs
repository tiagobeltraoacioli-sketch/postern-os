// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Postern Labs and Postern community contributors
//
// Focused unit tests for normalizeEntry()'s proprietary-detection gate
// (INVARIANT 1: proprietary can never be hosted_by_us:true). The naive
// `lic.class === "proprietary" || lic.foss === false` in the pre-fix code
// is a strict-equality check on attacker-controlled JSON — a dishonest
// self-hosted repo (A-repo-client.md §3.3: "a repo's signature proves who
// asserted a claim, never that the claim is true") could dodge it entirely
// with `class: "Proprietary"` (wrong case) or `foss: "false"` (a string, not
// the boolean), keeping hosted_by_us:true and a live checksum. These are
// regression tests for the case-/type-robust fix — see lib/normalize.mjs.

import { test } from "node:test";
import assert from "node:assert/strict";

import { normalizeEntry } from "../lib/normalize.mjs";

function baseApp(overrides = {}) {
  return {
    id: "sneaky-app",
    name: "Sneaky App",
    publisher: "Vendor",
    category: "media",
    platform: "both",
    source: "web",
    tier: "browser",
    license: { spdx: "LicenseRef-Proprietary", class: "proprietary", foss: false, redistribute: true, rebrand: true },
    distribution: {
      model: "mirror",
      hosted_by_us: true,
      upstream: "https://vendor.invalid",
      checksum: "sha256:deadbeef",
      signing: { scheme: "none", state: "published" },
    },
    security: [],
    ...overrides,
  };
}

test("proprietary detection: wrong-case class (\"Proprietary\") still coerces to link-only/not-hosted", () => {
  const app = baseApp({
    license: { spdx: "LicenseRef-Proprietary", class: "Proprietary", foss: true, redistribute: true, rebrand: true },
  });
  const { entry, stripped } = normalizeEntry(app);

  assert.equal(entry.dist.hostedByUs, false, "wrong-case 'Proprietary' must still be recognized as proprietary and forced un-hosted");
  assert.equal(entry.dist.model, "link");
  assert.ok(entry.dist.coerced);
  assert.ok(stripped.some((s) => s.includes("proprietary")), "strip reason must be recorded");
});

test("proprietary detection: foss as the STRING \"false\" (not the boolean) still coerces to link-only/not-hosted", () => {
  const app = baseApp({
    license: { spdx: "LicenseRef-Proprietary", class: "unknown-class", foss: "false", redistribute: true, rebrand: true },
  });
  const { entry, stripped } = normalizeEntry(app);

  assert.equal(entry.dist.hostedByUs, false, "foss:\"false\" (string) must still be treated as proprietary and forced un-hosted");
  assert.equal(entry.dist.model, "link");
  assert.ok(entry.dist.coerced);
  assert.equal(entry.license.foss, false);
  assert.ok(stripped.some((s) => s.includes("proprietary")));
});

test("proprietary detection: leading/trailing whitespace on class (\" proprietary \") still coerces", () => {
  const app = baseApp({
    license: { spdx: "LicenseRef-Proprietary", class: " proprietary ", foss: true, redistribute: true, rebrand: true },
  });
  const { entry, stripped } = normalizeEntry(app);

  assert.equal(entry.dist.hostedByUs, false, "whitespace-padded ' proprietary ' must still be recognized and force un-hosted");
  assert.equal(entry.dist.model, "link");
  assert.ok(entry.dist.coerced);
  assert.ok(stripped.some((s) => s.includes("proprietary")));
});

test("proprietary detection: positive control — canonical lowercase class + boolean foss:false still coerces (no regression)", () => {
  const app = baseApp(); // class: "proprietary", foss: false — the canonical form
  const { entry, stripped } = normalizeEntry(app);

  assert.equal(entry.dist.hostedByUs, false);
  assert.equal(entry.dist.model, "link");
  assert.ok(entry.dist.coerced);
  assert.ok(stripped.some((s) => s.includes("proprietary")));
});

test("proprietary detection: a genuinely permissive app is NOT coerced (no over-stripping)", () => {
  const app = baseApp({
    license: { spdx: "MIT", class: "permissive", foss: true, redistribute: true, rebrand: true },
    distribution: {
      model: "mirror",
      hosted_by_us: true,
      upstream: "https://vendor.invalid",
      checksum: "sha256:deadbeef",
      signing: { scheme: "none", state: "published" },
    },
  });
  const { entry, stripped } = normalizeEntry(app);

  assert.equal(entry.dist.hostedByUs, true);
  assert.equal(entry.dist.model, "mirror");
  assert.equal(entry.dist.coerced, null);
  assert.equal(stripped.length, 0);
});
