// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Postern Labs and Postern community contributors
//
// Depot repo client — generalizes apps/postern-store/index.html's
// resolveCatalogTrust() (one hardcoded CATALOG_PUBKEY_B64) to N pinned repo
// keys (01-architecture.md §2/§3). Reads the SAME wire format
// (postern.catalog/v1), verifies the SAME raw-64-byte detached Ed25519
// scheme over exact served bytes (SIGNING.md), but does it once per repo
// against that repo's own pin instead of one global constant, then merges
// every enabled repo's normalized listing WITHOUT ever collapsing
// cross-repo id collisions into one card (01-architecture.md §3, "Id
// collisions across repos").

import { SCHEMA_ID, TRUST } from "./schema.mjs";
import { verifyRawDetached } from "./crypto-bridge.mjs";
import { normalizeEntry } from "./normalize.mjs";
import { isRepoKeyRevoked, verifyDepotCrl } from "./depot-crl.mjs";

/**
 * Resolve the trust state of ONE repo's index from its exact served bytes —
 * the per-repo generalization of index.html's resolveCatalogTrust(). Pure:
 * takes bytes/sig already fetched by the caller so it's independently
 * testable without a network stack, matching 01-architecture.md §2's state
 * table (VERIFIED / TAMPERED / UNSIGNED / UNVERIFIABLE), plus REVOKED when a
 * Depot CRL is supplied and lists the pinned key.
 *
 * @param {object} args
 * @param {Uint8Array} args.bytes - exact served bytes of the repo's index file
 * @param {Uint8Array|null} args.sigBytes - exact served bytes of the .sig file (64 raw bytes), or null if absent
 * @param {string} args.pinnedPubkeyB64 - the key the USER pinned when adding this repo (never a key read from the index itself)
 * @param {object|null} [args.crl] - a verified Depot CRL (depot-crl.mjs), if one is loaded
 * @returns {Promise<{state: string, reason: string}>}
 */
export async function resolveRepoTrust({ bytes, sigBytes, pinnedPubkeyB64, crl = null }) {
  if (!pinnedPubkeyB64) {
    return { state: TRUST.UNSIGNED, reason: "no key pinned for this repo" };
  }
  if (!sigBytes || sigBytes.length !== 64) {
    return { state: TRUST.UNSIGNED, reason: "no detached signature published alongside this repo's index" };
  }
  if (crl && isRepoKeyRevoked(crl, pinnedPubkeyB64)) {
    return { state: TRUST.REVOKED, reason: "this repo's pinned key is on the Depot CRL — revoked, never trusted regardless of signature validity" };
  }
  const result = await verifyRawDetached(pinnedPubkeyB64, sigBytes, bytes);
  if (result.throws) {
    // The check could not even be RUN — e.g. the pinned key material itself
    // is malformed (wrong length / not a valid point), or this engine has no
    // Ed25519. Must not be reported as TAMPERED (that implies "we checked,
    // it's wrong"); UNVERIFIABLE is the honest state — "we could not check".
    return { state: TRUST.UNVERIFIABLE, reason: `signature could not be verified: ${result.error}` };
  }
  if (!result.ok) {
    return { state: TRUST.TAMPERED, reason: "a signature is present but does NOT match this repo's pinned key — the fetched copy is rejected" };
  }
  return { state: TRUST.VERIFIED, reason: "detached Ed25519 signature is valid for this repo's pinned key" };
}

/**
 * Multi-repo Depot client. Holds N repo pins, verifies+normalizes each
 * repo's fetched index independently, and produces a merged listing that
 * keeps id collisions visually/structurally distinct (never auto-merged).
 */
export class DepotClient {
  constructor() {
    /** repo_id -> pin { repo_id, url, pubkey_b64, label, priority, added_at, enabled } */
    this.pins = new Map();
    /** repo_id -> { trust: {state,reason}, entries: normalizedEntry[], repoMeta } — last VERIFIED (or best-known) snapshot */
    this.repos = new Map();
    /** builder_identity.id -> pinned trust entry {pubkey_b64, label} — the
     *  SAME shape reproducible-build-record.mjs's makeTrustStore() produces,
     *  used identically by both depot and repro-verifier (Depot M4 fix). */
    this.trustedBuilders = new Map();
    /** app_id -> { repoId, pubkey_b64 } — per-installed-app repo/key pinning (01-architecture.md §3) */
    this.installPins = new Map();
    /** currently-loaded, verified Depot CRL, if any */
    this.crl = null;
    /** the pinned Depot-ops Ed25519 public key that MUST sign any CRL before it is ever applied (see setCrl) */
    this.depotOpsPubkey = null;
  }

  /** Pin the Depot-ops public key a CRL's signature must verify against — out of band, never read from a fetched CRL itself. */
  pinDepotOpsKey(pubkeyB64) {
    this.depotOpsPubkey = pubkeyB64;
  }

  /** Pin a repo by URL + key, out of band (never fetched from the server and trusted-on-first-use). */
  addRepo({ repo_id, url, pubkey_b64, label, priority = 10, enabled = true }) {
    if (!repo_id) throw new Error("addRepo requires repo_id");
    this.pins.set(repo_id, {
      repo_id, url, pubkey_b64, label: label || repo_id, priority,
      added_at: new Date().toISOString(), enabled,
    });
  }

  removeRepo(repo_id) {
    this.pins.delete(repo_id);
    this.repos.delete(repo_id);
  }

  setEnabled(repo_id, enabled) {
    const p = this.pins.get(repo_id);
    if (p) p.enabled = enabled;
  }

  pinTrustedBuilder(builderIdentity, pubkeyB64) {
    this.trustedBuilders.set(builderIdentity, { pubkey_b64: pubkeyB64, label: builderIdentity });
  }

  /**
   * Adversarial-review fix: `verifyDepotCrl()` (depot-crl.mjs) has ALWAYS
   * existed, but nothing called it here — this method used to store
   * whatever object it was handed, trusting an unsigned or badly-signed CRL
   * exactly as much as a genuine one. A forged CRL is worse than none: it can
   * silently "un-revoke" (an attacker publishes a CRL with empty revocation
   * lists) or falsely revoke a legitimate repo/builder/artifact. This now
   * REQUIRES a Depot-ops key to be pinned first (pinDepotOpsKey) and REJECTS
   * — never applies — any CRL whose signature doesn't verify against it.
   *
   * @param {object} crl - the {payload, sig} envelope depot-crl.mjs's buildDepotCrl() produces
   * @returns {Promise<{ok: boolean, reason?: string}>}
   */
  async setCrl(crl) {
    if (!this.depotOpsPubkey) {
      return { ok: false, reason: "no Depot-ops key pinned — call pinDepotOpsKey() before setCrl(); a CRL is never applied without a pinned verification key" };
    }
    const verdict = await verifyDepotCrl(this.depotOpsPubkey, crl);
    if (!verdict.ok) {
      return verdict; // reject: this.crl is left untouched (fail-safe, keeps any previously-adopted CRL)
    }
    this.crl = crl;
    return { ok: true };
  }

  /**
   * Fetch-and-verify (bytes already supplied by the caller — this module has
   * no opinion on transport) one repo's index, normalize its apps[] through
   * the SAME honesty spine every repo gets, and store the result.
   *
   * On TAMPERED/REVOKED: the fetched copy is REJECTED. If a previously
   * VERIFIED snapshot for this repo exists, it is kept (fail-safe, never
   * fail-open). If none exists, the repo contributes zero apps with a
   * red-warning trust state — it is never silently dropped from the pin list.
   */
  async loadRepoIndex(repo_id, bytes, sigBytes) {
    const pin = this.pins.get(repo_id);
    if (!pin) throw new Error(`repo "${repo_id}" is not pinned — call addRepo() first`);

    const trust = await resolveRepoTrust({ bytes, sigBytes, pinnedPubkeyB64: pin.pubkey_b64, crl: this.crl });

    if (trust.state === TRUST.TAMPERED || trust.state === TRUST.REVOKED) {
      const prev = this.repos.get(repo_id);
      if (prev && (prev.trust.state === TRUST.VERIFIED)) {
        // Keep serving the last verified snapshot; record why we didn't refresh.
        this.repos.set(repo_id, { ...prev, trust, staleFallback: true });
      } else {
        this.repos.set(repo_id, { trust, entries: [], repoMeta: null, staleFallback: false });
      }
      return this.repos.get(repo_id);
    }

    let parsed;
    try {
      parsed = JSON.parse(Buffer.from(bytes).toString("utf8"));
    } catch {
      // Malformed JSON is not a signature failure but must still never crash
      // the merged view — render as UNSIGNED-equivalent, zero apps from this refresh.
      const prev = this.repos.get(repo_id);
      if (prev) return prev;
      this.repos.set(repo_id, { trust: { state: TRUST.UNSIGNED, reason: "index body is not valid JSON" }, entries: [], repoMeta: null });
      return this.repos.get(repo_id);
    }
    if (parsed.schema !== SCHEMA_ID) {
      const prev = this.repos.get(repo_id);
      if (prev) return prev;
      this.repos.set(repo_id, { trust: { state: TRUST.UNSIGNED, reason: `unrecognized schema "${parsed.schema}"` }, entries: [], repoMeta: null });
      return this.repos.get(repo_id);
    }

    const repoMeta = parsed.repo || null;
    const rawApps = Array.isArray(parsed.apps) ? parsed.apps : [];
    const entries = [];
    const seenInRepo = new Set();
    for (const a of rawApps) {
      if (!a || !a.id || seenInRepo.has(a.id)) continue; // within-repo dedupe: first wins, same as today's parseCatalog
      seenInRepo.add(a.id);
      try {
        entries.push(await normalizeEntry(a, {
          repoId: repo_id, repoLabel: pin.label, repoPriority: pin.priority,
          trustedBuilders: this.trustedBuilders, crl: this.crl,
        }));
      } catch {
        /* skip one malformed entry, never the whole repo */
      }
    }

    this.repos.set(repo_id, { trust, entries, repoMeta, staleFallback: false });
    return this.repos.get(repo_id);
  }

  /**
   * Merged listing across every ENABLED pinned repo. Each (repo, id) pair is
   * a DISTINCT listing item — two repos both listing id "signal-android"
   * produce two entries, never one merged card (01-architecture.md §3). The
   * first-party repo (priority 0) is authoritative for any id it lists; a
   * lower-priority repo reusing that id gets a cross-reference note, never
   * inheriting the first-party badge.
   *
   * @returns {Array<{repoId:string, repoLabel:string, trust:object, entry:object, shadowNote:string|null}>}
   */
  mergedListing() {
    const out = [];
    // Determine, per app id, whether the first-party (priority 0) repo lists it.
    const firstPartyIds = new Set();
    for (const [repoId, pin] of this.pins) {
      if (pin.priority !== 0) continue;
      const r = this.repos.get(repoId);
      if (!r) continue;
      for (const e of r.entries) firstPartyIds.add(e.id);
    }

    for (const [repoId, pin] of this.pins) {
      if (!pin.enabled) continue;
      const r = this.repos.get(repoId);
      if (!r) continue;
      for (const entry of r.entries) {
        let shadowNote = null;
        if (pin.priority !== 0 && firstPartyIds.has(entry.id)) {
          shadowNote = `also listed by the first-party Postern Store — not verified by "${pin.label}"; this listing does not inherit that badge`;
        }
        out.push({ repoId, repoLabel: pin.label, repoPriority: pin.priority, trust: r.trust, entry, shadowNote });
      }
    }
    // Stable presentation order: first-party/lowest-priority first, then by id.
    out.sort((a, b) => (a.repoPriority - b.repoPriority) || a.entry.id.localeCompare(b.entry.id));
    return out;
  }

  /** Record which repo/key an app was actually installed from — future updates only ever come from that same source. */
  installFrom(appId, repoId) {
    const pin = this.pins.get(repoId);
    if (!pin) throw new Error(`cannot install from unpinned repo "${repoId}"`);
    this.installPins.set(appId, { repoId, pubkey_b64: pin.pubkey_b64 });
  }

  /** Is `candidateRepoId` allowed to offer an update for `appId`? False if installed from a different repo/key. */
  isAllowedUpdateSource(appId, candidateRepoId) {
    const pinned = this.installPins.get(appId);
    if (!pinned) return true; // not installed via Depot tracking yet — no restriction
    const candidatePin = this.pins.get(candidateRepoId);
    return !!candidatePin && candidatePin.repo_id === pinned.repoId && candidatePin.pubkey_b64 === pinned.pubkey_b64;
  }
}
