// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Postern Labs and Postern community contributors
//
// Regenerates the three demo Depot repos in this directory. Run from
// apps/postern-store/depot-example/:  node gen-fixtures.mjs
//
// These are FIXTURES for exercising the Store's multi-repo add-repo/trust
// UI live, same-origin (so they work under this page's real CSP without
// any allowlist change — see the CSP comment at the top of index.html).
// They are not real third-party apps. Every keypair here is generated
// fresh by this script and discarded — nothing here is a real trust root,
// and the private keys are never written to disk or committed, exactly the
// posture docs/store-fdroid/A-repo-client.md §2 asks of a real repo
// operator ("Never commit or publish the private half").
//
// Regenerating replaces the pinned public keys below — if you regenerate,
// update the labels/keys quoted in this file's own console output and in
// any place a demo walkthrough references them.
import { webcrypto } from "node:crypto";
import { writeFileSync } from "node:fs";
const { subtle } = webcrypto;

const OUT = new URL(".", import.meta.url).pathname;

function b64(bytes) { return Buffer.from(bytes).toString("base64"); }

async function genKey() {
  const kp = await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const pub = new Uint8Array(await subtle.exportKey("raw", kp.publicKey));
  return { kp, pubB64: b64(pub) };
}
async function sign(privateKey, bytes) {
  return new Uint8Array(await subtle.sign({ name: "Ed25519" }, privateKey, bytes));
}
// MUST match rotationTransitionMessage() in index.html byte-for-byte.
function rotationMsg(repoId, oldB64, newB64, ts) {
  return new TextEncoder().encode(`postern-repo-key-rotation/v1\n${repoId}\n${oldB64}\n${newB64}\n${ts}`);
}

function baseApps() {
  return [
    {
      id: "example-notes", name: "Example Notes", publisher: "Example Depot Operator", glyph: "N",
      category: "files", platform: "both", source: "web", tier: "browser",
      oneliner: "A demo third-party catalog entry — proves the multi-repo merge + honesty invariants, not a real product.",
      license: { spdx: "MIT", class: "permissive", foss: true, redistribute: true, rebrand: true, trademark: false, note: "Demo fixture." },
      distribution: { model: "link", hosted_by_us: false, upstream: "https://example.com/notes", artifact: "", checksum: null, signing: { scheme: "none", state: "none" }, verify: "Demo fixture — link only." },
      privacy: { level: "local-only", stays: "Nothing real — this is a fixture.", leaves: "Nothing." },
      security: [], capabilities: ["demonstrate multi-repo merge"], tags: ["demo", "fixture"], limits: "Not a real app.",
    },
    {
      id: "example-proprietary-attempt", name: "Example Corp Cloud", publisher: "Example Corp", glyph: "E",
      category: "files", platform: "both", source: "web", tier: "browser",
      oneliner: "A demo PROPRIETARY entry that also claims hosted_by_us:true — proves normalizeEntry strips this even from a validly-signed third-party repo.",
      license: { spdx: "LicenseRef-Proprietary", class: "proprietary", foss: false, redistribute: false, rebrand: false, trademark: true, note: "Demo fixture for INVARIANT 1." },
      distribution: { model: "mirror", hosted_by_us: true, upstream: "https://example.com/corp", artifact: "https://example.com/corp.bin", checksum: "sha256:deadbeef", signing: { scheme: "abuild-rsa", state: "published" }, verify: "Demo fixture — this claim should be COERCED to link/hosted_by_us:false by the client regardless of this repo's valid signature." },
      privacy: { level: "metadata-exposed", stays: "Nothing real.", leaves: "Nothing real — fixture." },
      security: ["attestable"], capabilities: ["demonstrate honesty invariant stripping"], tags: ["demo", "fixture"], limits: "Not a real app — a signed lie is still a lie.",
    },
  ];
}

async function writeIndex(filename, repoBlock, signingKey) {
  const doc = { schema: "postern.repo/v1", generated: new Date().toISOString(), repo: repoBlock, apps: baseApps() };
  const json = JSON.stringify(doc);
  writeFileSync(`${OUT}${filename}`, json, "utf8");
  const sig = await sign(signingKey, new TextEncoder().encode(json));
  writeFileSync(`${OUT}${filename}.sig`, Buffer.from(sig));
}

async function main() {
  // ---- 1. plain VERIFIED demo ----
  const A = await genKey();
  const repoIdA = "example-depot"; // must equal slugify("Example Depot") — see index.html's slugify()
  await writeIndex("index.json", {
    id: repoIdA, name: "Example Depot", url: "./depot-example/index.json",
    description: "A same-origin demo Depot repo — proves the add-repo + VERIFIED flow live, under this page's real CSP (connect-src 'self').",
    priority: 1, pubkey_b64: A.pubB64, timestamp: Date.now(),
  }, A.kp.privateKey);
  console.log("VERIFIED demo — Add repo with label EXACTLY 'Example Depot', url ./depot-example/index.json, key:\n  " + A.pubB64);

  // ---- 2. legitimate ROTATION_PENDING demo ----
  const B_old = await genKey();
  const B_new = await genKey();
  const repoIdB = "rotated-depot";
  const tsB = Date.now();
  const transitionSigB = await sign(B_old.kp.privateKey, rotationMsg(repoIdB, B_old.pubB64, B_new.pubB64, tsB));
  await writeIndex("index-rotated.json", {
    id: repoIdB, name: "Rotated Depot", url: "./depot-example/index-rotated.json",
    description: "Same repo as above, but its key has legitimately rotated — the transition is signed by the OLD key.",
    priority: 2, pubkey_b64: B_new.pubB64, timestamp: tsB,
    key_rotation: { old_pubkey_b64: B_old.pubB64, new_pubkey_b64: B_new.pubB64, timestamp: tsB, transition_signature_b64: b64(transitionSigB) },
  }, B_new.kp.privateKey); // index itself signed by the NEW key
  console.log("\nROTATION_PENDING demo — Add repo with label EXACTLY 'Rotated Depot', url ./depot-example/index-rotated.json, PIN THE OLD key:\n  " + B_old.pubB64 + "\n  (new key the client should offer to accept: " + B_new.pubB64 + ")");

  // ---- 3. attack demo: claimed new key, NO valid transition -> hard TAMPERED ----
  const C_old = await genKey();
  const C_new = await genKey();
  const repoIdC = "rotated-depot-bad";
  const tsC = Date.now();
  const garbageSig = webcrypto.getRandomValues(new Uint8Array(64)); // NOT signed by C_old
  await writeIndex("index-rotated-bad.json", {
    id: repoIdC, name: "Rotated Depot Bad", url: "./depot-example/index-rotated-bad.json",
    description: "Attack demo — claims a new key via key_rotation, but the transition signature does not verify against the old pinned key. Must render hard TAMPERED, never a click-through prompt.",
    priority: 3, pubkey_b64: C_new.pubB64, timestamp: tsC,
    key_rotation: { old_pubkey_b64: C_old.pubB64, new_pubkey_b64: C_new.pubB64, timestamp: tsC, transition_signature_b64: b64(garbageSig) },
  }, C_new.kp.privateKey);
  console.log("\nTAMPERED (rejected rotation) demo — Add repo with label EXACTLY 'Rotated Depot Bad', url ./depot-example/index-rotated-bad.json, PIN THE OLD key:\n  " + C_old.pubB64 + "\n  (attacker-claimed new key, must be REJECTED: " + C_new.pubB64 + ")");
}
main();
