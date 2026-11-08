"use strict";
/* SPDX-License-Identifier: MIT OR Apache-2.0
   SPDX-FileCopyrightText: 2026 Postern Labs

   Tests for the NoporIS Google-Play flavor policy invariants. Pure node, no deps:
     node --test android-bridge/persona/play/policy/test-play-flavor-policy.mjs
   Mirrors apps/sloboda-gate/test-store.mjs (the suite's node-test style). */

import { test } from "node:test";
import assert from "node:assert/strict";
import P, {
  FLAVOR,
  LESS_PRIVATE, PROVIDES_PRIVACY, REDISTRIBUTES_GMS, CIRCUMVENTS_INTEGRITY, HOSTS_WALLET_KEYS,
  PLAY_STORE_PACKAGE, GMS_CORE_PACKAGE, PLAY_SYSTEM_APP_ALLOWLIST,
  isWalletOwnedPackage, isWalletKeyAlias, mayEnableSystemApp, systemAppsToEnable,
  walletExclusionViolations, normalize,
} from "./play-flavor-policy.mjs";

// ── Honesty / licensing rails are pinned (cannot be flipped) ────────────────

test("less-private and no-privacy are pinned by design", () => {
  assert.equal(LESS_PRIVATE, true);
  assert.equal(PROVIDES_PRIVACY, false);
  assert.equal(FLAVOR, "google-play");
});

test("we neither redistribute GMS nor circumvent integrity nor host wallet keys", () => {
  assert.equal(REDISTRIBUTES_GMS, false);
  assert.equal(CIRCUMVENTS_INTEGRITY, false);
  assert.equal(HOSTS_WALLET_KEYS, false);
});

test("a hostile config cannot flip the honesty rails", () => {
  const s = normalize({
    flavor: "clean",
    lessPrivate: false,
    providesPrivacy: true,
    redistributesGms: true,
    circumventsIntegrity: true,
    hostsWalletKeys: true,
    crossPersonaSharing: true,
  });
  assert.equal(s.flavor, "google-play");
  assert.equal(s.lessPrivate, true);
  assert.equal(s.providesPrivacy, false);
  assert.equal(s.redistributesGms, false);
  assert.equal(s.circumventsIntegrity, false);
  assert.equal(s.hostsWalletKeys, false);
  assert.equal(s.crossPersonaSharing, false); // Play persona never sees the clean side.
});

// ── enableSystemApp: deny-by-default, allowlist only ────────────────────────

test("Play Store and GMS core are enable-able; nothing else is", () => {
  assert.equal(mayEnableSystemApp(PLAY_STORE_PACKAGE).allow, true);
  assert.equal(mayEnableSystemApp(GMS_CORE_PACKAGE).allow, true);
  assert.equal(mayEnableSystemApp("com.some.random.app").allow, false);
  assert.equal(mayEnableSystemApp("").allow, false);
  assert.equal(mayEnableSystemApp(undefined).allow, false);
  assert.equal(mayEnableSystemApp(null).allow, false);
});

test("systemAppsToEnable is exactly the allowlist, stable order", () => {
  assert.deepEqual(systemAppsToEnable(), [...PLAY_SYSTEM_APP_ALLOWLIST]);
});

test("normalize enables the allowlist by default and de-dups requested apps", () => {
  assert.deepEqual(normalize().enableSystemApps, [...PLAY_SYSTEM_APP_ALLOWLIST]);
  assert.deepEqual(
    normalize({ enableSystemApps: [PLAY_STORE_PACKAGE, PLAY_STORE_PACKAGE] }).enableSystemApps,
    [PLAY_STORE_PACKAGE],
  );
  // An unknown app requested is silently dropped (deny-by-default), not enabled.
  assert.deepEqual(
    normalize({ enableSystemApps: ["com.evil.spyware"] }).enableSystemApps,
    [],
  );
});

// ── NO wallet keys on the Google side ───────────────────────────────────────

test("wallet/signer packages are recognised and force-denied", () => {
  assert.equal(isWalletOwnedPackage("labs.postern.wallet"), true);
  assert.equal(isWalletOwnedPackage("labs.postern.wallet.debug"), true);
  assert.equal(isWalletOwnedPackage("labs.postern.signer"), true);
  assert.equal(isWalletOwnedPackage("com.android.vending"), false);

  // Even if a config tried to enable a wallet package, the gate refuses it.
  const d = mayEnableSystemApp("labs.postern.wallet");
  assert.equal(d.allow, false);
  assert.match(d.reason, /wallet\/signer package is forbidden/);
});

test("wallet key aliases are recognised (StrongBox material never lives here)", () => {
  assert.equal(isWalletKeyAlias("postern.wallet.wrap"), true);
  assert.equal(isWalletKeyAlias("postern.seal.attest"), true);
  assert.equal(isWalletKeyAlias("postern.signer.session"), true);
  assert.equal(isWalletKeyAlias("random.key"), false);
});

test("walletExclusionViolations flags any wallet package or key alias observed", () => {
  assert.deepEqual(walletExclusionViolations(), []);
  assert.deepEqual(
    walletExclusionViolations({ keyAliases: ["random.key"], packages: ["com.android.vending"] }),
    [],
  );
  const bad = walletExclusionViolations({
    keyAliases: ["postern.wallet.wrap", "ok.key"],
    packages: ["labs.postern.container", "com.google.android.gms"],
  });
  assert.deepEqual(bad, [
    { kind: "keyAlias", value: "postern.wallet.wrap" },
    { kind: "package", value: "labs.postern.container" },
  ]);
});

// ── malformed input collapses safe ──────────────────────────────────────────

test("garbage input normalises to a fully-labelled, wallet-excluded state", () => {
  for (const junk of [null, undefined, 42, "nope", [], { enableSystemApps: "not-an-array" }]) {
    const s = normalize(junk);
    assert.equal(s.flavor, "google-play");
    assert.equal(s.lessPrivate, true);
    assert.equal(s.hostsWalletKeys, false);
    // default enable set is the allowlist; none is wallet-owned.
    assert.deepEqual(walletExclusionViolations({ packages: s.enableSystemApps }), []);
  }
});

// exercise default export surface
test("default export exposes the contract", () => {
  assert.equal(typeof P.mayEnableSystemApp, "function");
  assert.equal(typeof P.normalize, "function");
});
