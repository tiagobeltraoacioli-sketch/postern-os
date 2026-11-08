// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Bloch Shield (Enterprise) — DLP data-classification model + third-party
// sharing policy.
//
// STATUS: design / reference prototype. UNAUDITED. Pre-production. NOT LEGAL
// ADVICE — see COMPLIANCE.md. Compliance-BY-DESIGN, not certified compliance.
//
// WHAT THIS IS
// ------------
// The DLP layer does NOT own the container/access surface — that lives in
// `enterprise/shield/container/` and is another developer's. This module is the
// *classification contract*: a declared taxonomy of CORPORATE data sensitivity
// classes, and — driven by the same fail-closed policy kernel the rest of the
// suite uses (postern-policy in `crates/`, ezekiel1 in `apps/ezekiel1/`) — the
// rule of what MAY vs MAY NOT be shared with a third party per class.
//
// THE ONE RAIL THAT NEVER BENDS: CORPORATE SCOPE ONLY.
//   This engine classifies and gates CORPORATE data leaving the container to a
//   third party. It has NO concept of, and will never touch, the employee's
//   PERSONAL activity. `PERSONAL` is a first-class sentinel here for exactly one
//   reason: so the engine can RECOGNISE personal data and REFUSE to classify,
//   gate, or trace it. Personal-side surveillance is the red line; this file is
//   built so that crossing it is a thrown error, not a config toggle.
//
// FAIL-CLOSED, LIKE THE KERNEL
//   Mirrors postern-policy's `Decision`: silence is "no". Where the sharing
//   policy does not explicitly permit a class->destination flow, the answer is
//   BLOCK, never a silent allow. Grants carry a required, future-dated expiry
//   (postern-policy's `Expiry`) and are revocable (its `Revocation`); an expired
//   or revoked grant is treated as never given. This module does NOT implement
//   crypto or a daemon — like org-policy.mjs it *describes and evaluates* intent;
//   the container is authoritative at the real egress boundary.

/**
 * A gate outcome, mirroring postern-policy's fail-closed `Decision` but with the
 * DLP three-way egress verdict (allow / warn / block). Silence is BLOCK.
 * @typedef {"allow"|"warn"|"block"} Verdict
 * @typedef {{verdict:Verdict, reason:string, class?:string, destination?:string}} GateDecision
 */

/** The canonical reason for the fail-closed default, echoing SILENT_DENY_REASON. */
export const SILENT_BLOCK_REASON =
  "sharing policy is silent for this class/destination; fail-closed default is block";

/**
 * The corporate data-sensitivity taxonomy. `rank` ascends with sensitivity.
 * `defaultThirdParty` is the verdict when NO explicit grant applies — it is the
 * floor the policy may only *narrow* (make stricter), never widen.
 *
 * @typedef {Object} DataClassDef
 * @property {string} id
 * @property {number} rank
 * @property {string} label
 * @property {Verdict} defaultThirdParty  verdict for third-party egress absent a grant
 * @property {boolean} grantable          may a policy grant EVER permit third-party egress?
 * @property {string} lawfulBasisHint     LGPD/GDPR hint (NOT legal advice)
 * @property {string} notes
 */

/** The four corporate classes. Frozen — the taxonomy is a contract. */
export const CLASSES = Object.freeze([
  {
    id: "public",
    rank: 0,
    label: "Public",
    defaultThirdParty: "allow",
    grantable: true,
    lawfulBasisHint: "no restriction — already public corporate information",
    notes:
      "Marketing copy, published docs, open-source. Egress to third parties is " +
      "unrestricted. Still recorded as corporate egress for completeness, never " +
      "blocked.",
  },
  {
    id: "internal",
    rank: 1,
    label: "Internal",
    defaultThirdParty: "warn",
    grantable: true,
    lawfulBasisHint: "legitimate-interest (business operations)",
    notes:
      "Default corporate working data. Not secret, but not for casual external " +
      "release. Third-party egress WARNS by default (employee sees it, it is " +
      "logged) and BLOCKS to an unknown/untrusted destination.",
  },
  {
    id: "confidential",
    rank: 2,
    label: "Confidential",
    defaultThirdParty: "block",
    grantable: true,
    lawfulBasisHint:
      "contract / legitimate-interest; third-party transfer needs a DPA (LGPD Art. 39 / GDPR Art. 28)",
    notes:
      "Commercially sensitive: contracts, roadmaps, non-public financials, " +
      "customer lists. Third-party egress BLOCKS unless an explicit, unexpired " +
      "policy grant permits a vetted processor under a data-processing agreement.",
  },
  {
    id: "restricted",
    rank: 3,
    label: "Restricted",
    defaultThirdParty: "block",
    grantable: false,
    lawfulBasisHint:
      "special-category / regulated data — transfer typically requires explicit legal basis",
    notes:
      "The most sensitive corporate data: secrets/keys, regulated personal data " +
      "the CORPORATION holds about its customers, trade secrets. NEVER shareable " +
      "with a third party through this engine — `grantable:false` means no policy " +
      "grant can widen it. Fail-closed and un-widenable.",
  },
]);

/**
 * The PERSONAL sentinel. This is NOT a corporate class and is deliberately kept
 * OUT of `CLASSES`. Its only job is recognition-and-refusal: if data classifies
 * as personal, the engine must not gate or trace it. The employee's own life is
 * not the employer's to watch. See `classify()` and the audit trail's refusal.
 */
export const PERSONAL = Object.freeze({
  id: "personal",
  label: "Personal (employee's own — OUT OF SCOPE)",
  corporate: false,
  notes:
    "BYOD red line: the employee's personal data, apps, messages, browsing, and " +
    "location are none of this engine's business. Recognised only so the engine " +
    "can REFUSE to classify/gate/trace it. There is no policy toggle that turns " +
    "this into surveillance.",
});

/** O(1) lookup for corporate classes. */
const _byId = Object.freeze(Object.fromEntries(CLASSES.map((c) => [c.id, c])));

/** @param {string} id @returns {DataClassDef|null} */
export function dataClass(id) {
  return _byId[id] || null;
}

/**
 * Classify a piece of data leaving the container.
 *
 * The caller (the container/access layer) supplies a descriptor. Two honest
 * cases:
 *   - `scope: "personal"` (or any non-corporate origin) => classified PERSONAL,
 *     `corporate:false`. The engine will REFUSE to gate/trace it downstream.
 *   - corporate data => classified into a corporate class. If the descriptor
 *     carries no usable label, we FAIL CLOSED to the most restrictive class
 *     ("restricted") rather than guess low — silence must never under-classify.
 *
 * This is a light, deterministic classifier: it maps an explicit label/tags to a
 * class. It intentionally does NOT scan personal content. Real deployments layer
 * their own corporate content matchers ON TOP; they must never point them at the
 * personal side.
 *
 * @param {Object} d
 * @param {"corporate"|"personal"|string} [d.scope]  origin scope; anything not "corporate" is treated as personal/out-of-scope
 * @param {string} [d.classId]  an explicit corporate class id, if the caller already knows it
 * @param {string[]} [d.tags]   corporate tags that hint a class (e.g. "secret", "contract")
 * @returns {{class:string, corporate:boolean, rank:number|null, reason:string}}
 */
export function classify(d = {}) {
  const scope = d.scope == null ? "corporate" : String(d.scope);
  // The red line, evaluated FIRST: anything not corporate is personal/out-of-scope.
  if (scope !== "corporate") {
    return Object.freeze({
      class: PERSONAL.id,
      corporate: false,
      rank: null,
      reason:
        "origin is not corporate scope — classified PERSONAL and left untouched " +
        "(the engine does not classify, gate, or trace personal data)",
    });
  }

  // Explicit corporate class wins if valid.
  if (d.classId && _byId[d.classId]) {
    const c = _byId[d.classId];
    return Object.freeze({
      class: c.id,
      corporate: true,
      rank: c.rank,
      reason: `explicit corporate class "${c.id}"`,
    });
  }

  // Tag hints, most-sensitive-wins.
  const tags = Array.isArray(d.tags) ? d.tags.map((t) => String(t).toLowerCase()) : [];
  const hint = _mostSensitiveTag(tags);
  if (hint) {
    const c = _byId[hint];
    return Object.freeze({
      class: c.id,
      corporate: true,
      rank: c.rank,
      reason: `inferred from tags -> "${c.id}"`,
    });
  }

  // No usable label on corporate data => fail CLOSED to the strictest class.
  return Object.freeze({
    class: "restricted",
    corporate: true,
    rank: _byId.restricted.rank,
    reason:
      "corporate data with no usable classification label — failing closed to " +
      "the most restrictive class rather than under-classifying",
  });
}

/** Map corporate tags to a class, most sensitive wins. Personal-ish tags are ignored (not our job). */
function _mostSensitiveTag(tags) {
  const table = {
    public: "public",
    published: "public",
    internal: "internal",
    confidential: "confidential",
    contract: "confidential",
    financial: "confidential",
    customer: "confidential",
    restricted: "restricted",
    secret: "restricted",
    key: "restricted",
    regulated: "restricted",
    "trade-secret": "restricted",
  };
  let best = null;
  for (const t of tags) {
    const cls = table[t];
    if (!cls) continue;
    if (!best || _byId[cls].rank > _byId[best].rank) best = cls;
  }
  return best;
}

/**
 * The third-party sharing policy — an org-authored document, evaluated
 * fail-closed. Same shape philosophy as org-policy.mjs: a plain, dependency-free
 * description of INTENT that the container enforces at the real boundary.
 *
 * A grant permits egress of one corporate class to one destination, and MUST
 * carry a future-dated `expires` (postern-policy's required `Expiry`). It may be
 * revoked. An expired or revoked grant is treated as never given.
 *
 * @typedef {Object} SharingGrant
 * @property {string} class        corporate class id this grant unblocks
 * @property {string} destination  third-party destination id (see Destination)
 * @property {Verdict} verdict     the verdict this grant asserts (allow|warn) — never a grant to "block"
 * @property {string} expires      REQUIRED RFC-3339 instant, must be in the future at check time
 * @property {boolean} [revoked]   a revoked grant can never un-revoke
 * @property {boolean} [dpa]       is a data-processing agreement on file for this destination?
 * @property {string} [note]
 *
 * @returns {{schema:string, org:string|null, grants:SharingGrant[]}}
 */
export function emptySharingPolicy() {
  return { schema: "bloch.shield.dlp.sharing-policy/1", org: null, grants: [] };
}

/**
 * A third-party destination the corporate data would leave to.
 * @typedef {Object} Destination
 * @property {string} id
 * @property {"vetted-processor"|"known"|"unknown"} [trust]
 * @property {boolean} [dpa]  data-processing agreement on file
 */

/**
 * The core API: may this corporate class be shared with this third-party
 * destination, under this policy, at this instant?
 *
 * Fail-closed and no-widening, mirroring postern-policy's `Decision::all`:
 *   1. PERSONAL / non-corporate => THROWS. Personal data is never evaluated for
 *      third-party sharing; asking is a category error and the red line.
 *   2. `restricted` (grantable:false) => always BLOCK; no grant can widen it.
 *   3. otherwise start from the class's `defaultThirdParty` floor, then apply the
 *      strictest of {destination trust, matching unexpired grant}. A grant may
 *      only make the verdict MORE permissive up to its own asserted verdict, and
 *      only if unexpired, unrevoked, and (for confidential) backed by a DPA.
 *      The floor and every narrowing rule are applied; the STRICTEST wins.
 *
 * @param {string} classId
 * @param {Destination|string} destination
 * @param {{policy?:object, now?:Date|string|number}} [ctx]
 * @returns {GateDecision}
 */
export function mayShareWithThirdParty(classId, destination, ctx = {}) {
  if (classId === PERSONAL.id || classId === "personal") {
    throw new Error(
      "dlp: refused — personal data is never evaluated for third-party sharing " +
        "(corporate-scope only; this is the red line, not a policy toggle)",
    );
  }
  const c = _byId[classId];
  if (!c) {
    // Unknown class: fail closed.
    return _decision("block", `unknown class "${classId}" — ${SILENT_BLOCK_REASON}`, classId, _destId(destination));
  }

  const dest = _normDest(destination);
  const now = new Date(ctx.now || Date.now());

  // Un-widenable class: no grant can ever open it.
  if (c.grantable === false) {
    return _decision(
      "block",
      `class "${c.id}" is not grantable — it may never be shared with a third party (un-widenable, fail-closed)`,
      c.id,
      dest.id,
    );
  }

  // Start from the class floor.
  let verdict = c.defaultThirdParty;
  let reason = `class "${c.id}" default third-party verdict is "${verdict}"`;

  // Destination trust narrows (never widens) the floor.
  if (dest.trust === "unknown") {
    // Unknown destinations are always at least a warn; for anything above public, block.
    if (c.rank >= 1) {
      return _decision("block", `destination "${dest.id}" is untrusted/unknown and class is "${c.id}" — blocked`, c.id, dest.id);
    }
  }

  // Look for an explicit grant that would (up to its own verdict) permit egress.
  const grant = _matchingGrant(ctx.policy, c.id, dest.id, now);
  if (grant.state === "active") {
    // A grant may only make things MORE permissive, capped at its asserted verdict,
    // and confidential additionally requires a DPA on file.
    if (c.id === "confidential" && !(grant.grant.dpa || dest.dpa)) {
      return _decision(
        "block",
        `class "confidential" to "${dest.id}" needs a data-processing agreement (DPA) on file — none found`,
        c.id,
        dest.id,
      );
    }
    verdict = _morePermissive(verdict, grant.grant.verdict === "allow" ? "allow" : "warn");
    reason = `explicit unexpired grant permits "${c.id}" -> "${dest.id}" as "${verdict}"`;
  } else if (grant.state === "expired" || grant.state === "revoked") {
    // A grant existed but is no longer given => fail closed, and say why honestly.
    return _decision(
      "block",
      `a "${c.id}" -> "${dest.id}" grant exists but is ${grant.state} — treated as never given (fail-closed)`,
      c.id,
      dest.id,
    );
  }
  // grant.state === "none" => stay on the class floor (which may itself be warn/block).

  return _decision(verdict, reason, c.id, dest.id);
}

/** Find the most relevant grant for class->dest and classify its temporal state. */
function _matchingGrant(policy, classId, destId, now) {
  const grants = (policy && Array.isArray(policy.grants) && policy.grants) || [];
  let sawStale = null;
  for (const g of grants) {
    if (g.class !== classId || g.destination !== destId) continue;
    if (g.revoked === true) {
      sawStale = "revoked";
      continue;
    }
    // Expiry is REQUIRED and must be a valid, future instant (postern-policy Expiry).
    const exp = g.expires ? new Date(g.expires) : null;
    if (!exp || Number.isNaN(exp.getTime())) {
      sawStale = "expired"; // an unparseable/absent expiry is fail-closed as expired
      continue;
    }
    if (exp.getTime() <= now.getTime()) {
      sawStale = "expired";
      continue;
    }
    return { state: "active", grant: g };
  }
  return { state: sawStale || "none", grant: null };
}

/** allow > warn > block; return the MORE permissive of two verdicts. */
function _morePermissive(a, b) {
  const rank = { block: 0, warn: 1, allow: 2 };
  return rank[a] >= rank[b] ? a : b;
}

function _decision(verdict, reason, cls, dest) {
  return Object.freeze({ verdict, reason, class: cls, destination: dest });
}

function _normDest(d) {
  if (typeof d === "string") return { id: d, trust: "unknown", dpa: false };
  return { id: String(d.id || "unknown"), trust: d.trust || "unknown", dpa: !!d.dpa };
}
function _destId(d) {
  return typeof d === "string" ? d : String((d && d.id) || "unknown");
}

export default {
  CLASSES,
  PERSONAL,
  SILENT_BLOCK_REASON,
  dataClass,
  classify,
  emptySharingPolicy,
  mayShareWithThirdParty,
};
