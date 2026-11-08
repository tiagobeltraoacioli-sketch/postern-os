// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Postern Labs and Postern community contributors
//
// Builds a sample postern.repo/v1 index (A-repo-client.md §1.1) and signs it
// with detached Ed25519 over the exact served bytes (§1.3, §2.1) — same rule
// as SIGNING.md: sign the file, don't canonicalize it, so the JSON is
// serialized exactly ONCE and those exact bytes are both what gets signed
// and what gets written to disk / handed to the verifier.
//
// The sample repo deliberately includes both HONEST entries and entries that
// self-declare claims the client's honesty invariants (normalize.mjs) must
// strip — a self-hosted third-party repo is exactly the case §3.3 says a
// signature can't launder ("a repo's Ed25519 signature only proves the repo
// operator asserted that claim, not that the claim is true").

import { ed25519SignRaw, sha256Hex } from "./keys.mjs";

/** A fixture "artifact" the fake repo claims to host — its real bytes and hash. */
export const GOOD_ARTIFACT_BYTES = Buffer.from("this is the real, unmodified postern-vault-mirror.apk bytes\n");
export const GOOD_ARTIFACT_SHA256 = sha256Hex(GOOD_ARTIFACT_BYTES);

/** A DIFFERENT artifact than the one the index claims for courier-mirror —
 *  simulates a swapped/corrupted download so the checksum check has
 *  something real to catch. */
export const SWAPPED_ARTIFACT_BYTES = Buffer.from("a swapped/corrupted courier-mirror.apk payload\n");

export function sampleApps() {
  return [
    {
      // HONEST baseline: link-only, nothing hosted, nothing to lie about.
      id: "organic-maps",
      name: "Organic Maps",
      publisher: "Organic Maps",
      category: "assistants",
      platform: "mobile",
      source: "fdroid",
      tier: "sloboda-compat",
      license: { spdx: "Apache-2.0", class: "permissive", foss: true, redistribute: true, rebrand: true },
      distribution: { model: "link", hosted_by_us: false, upstream: "https://organicmaps.app/", checksum: null, signing: { state: "upstream" } },
      security: [],
    },
    {
      // HONEST hosted mirror WITH a real, matching checksum — §1.4's happy path.
      id: "vault-mirror",
      name: "Postern Vault (mirror)",
      publisher: "Postern Labs",
      category: "security",
      platform: "both",
      source: "postern-apk",
      tier: "attestable-nix",
      license: { spdx: "MIT OR Apache-2.0", class: "permissive", foss: true, redistribute: true, rebrand: true },
      distribution: {
        model: "mirror",
        hosted_by_us: true,
        upstream: "https://posternlabs.com/vault",
        checksum: `sha256:${GOOD_ARTIFACT_SHA256}`,
        signing: { scheme: "abuild-rsa", key_id: "packages@example.org", state: "published" },
      },
      security: ["attestable", "on-device-only"], // legitimate here: tier IS attestable-nix
    },
    {
      // DISHONEST #1: a hosted mirror whose PUBLISHED checksum does not match
      // what actually gets served — exercises the mismatch branch of §1.4.
      id: "courier-mirror",
      name: "Postern Courier (mirror, bad checksum)",
      publisher: "Postern Labs",
      category: "files",
      platform: "both",
      source: "postern-apk",
      tier: "pmos-overlay",
      license: { spdx: "MIT OR Apache-2.0", class: "permissive", foss: true, redistribute: true, rebrand: true },
      distribution: {
        model: "overlay-build",
        hosted_by_us: true,
        upstream: "https://posternlabs.com/courier",
        // Deliberately claims the GOOD artifact's hash while a different
        // (SWAPPED_ARTIFACT_BYTES) payload is what the test "fetches" —
        // simulating a swapped/corrupted download.
        checksum: `sha256:${GOOD_ARTIFACT_SHA256}`,
        signing: { scheme: "abuild-rsa", key_id: "packages@example.org", state: "published" },
      },
      security: [],
    },
    {
      // DISHONEST #2: proprietary app self-declaring hosted_by_us:true —
      // structurally impossible, invariant 1 must coerce to link.
      id: "some-proprietary-app",
      name: "Some Proprietary App",
      publisher: "Some Vendor Inc.",
      category: "media",
      platform: "both",
      source: "web",
      tier: "browser",
      license: { spdx: "LicenseRef-Proprietary", class: "proprietary", foss: false, redistribute: false, rebrand: false },
      distribution: {
        model: "mirror", // also structurally disallowed for proprietary — invariant re-coerces to link
        hosted_by_us: true,
        upstream: "https://example.com/proprietary-app",
        checksum: `sha256:${GOOD_ARTIFACT_SHA256}`, // claims a checksum too — should be nulled once coerced
        signing: { scheme: "none", state: "unpublished" },
      },
      security: [],
    },
    {
      // DISHONEST #3, the one the task calls out by name: a repo
      // self-declaring "attestable" on a non-Nix tier (pmos-overlay). This
      // is badge laundering per A-repo-client.md §5.4 — invariant 2 must
      // strip the `attestable` security tag.
      id: "laundered-attestable-tool",
      name: "Definitely Attestable Tool (not really)",
      publisher: "Some Self-Hoster",
      category: "developer",
      platform: "desktop",
      source: "postern-apk",
      tier: "pmos-overlay", // NOT attestable-nix
      license: { spdx: "MIT", class: "permissive", foss: true, redistribute: true, rebrand: true },
      distribution: {
        model: "overlay-build",
        hosted_by_us: true,
        upstream: "https://example.org/tool",
        checksum: null,
        signing: { scheme: "abuild-rsa", key_id: "self-hoster@example.org", state: "unpublished" },
      },
      security: ["attestable", "post-quantum"], // the false claim under test
    },
  ];
}

/**
 * Build + sign a postern.repo/v1 index. Returns the exact bytes signed
 * (indexBytes), the raw 64-byte signature (sigBytes), and the parsed object
 * for convenience — indexBytes is the ONLY thing that was ever hashed/signed,
 * matching SIGNING.md's "sign the file, don't canonicalize it."
 */
export function buildSignedIndex({ privateKeyB64, publicKeyB64, timestamp, apps = sampleApps(), repoOverrides = {} }) {
  const indexObj = {
    schema: "postern.repo/v1",
    repo: {
      name: "Example Journalist Kit",
      description: "A self-hosted third-party Postern repo — the A-repo-client.md §1.1 worked example.",
      address: "https://example.org/postern-repo",
      timestamp,
      pubkey_b64: publicKeyB64,
      pq_pubkey_b64: null,
      mirrors: [],
      ...repoOverrides,
    },
    honesty:
      "This is a self-hosted, third-party POC repo, not Postern's own catalog. Its index is signed by the key above; that signature proves authorship of these bytes, never the truth of any claim inside them.",
    vocab: { note: "unchanged from postern.catalog/v1 — omitted in this POC fixture for brevity" },
    apps,
  };

  const indexBytes = Buffer.from(JSON.stringify(indexObj, null, 2), "utf8");
  const sigBytes = ed25519SignRaw(privateKeyB64, indexBytes);
  return { indexBytes, sigBytes, indexObj };
}
