// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Bloch — org internal messenger (Business/Enterprise edition ONLY).
// Compliance disclosure HOOK — the seam where the compliance layer plugs in.
//
// STATUS: design / reference prototype — unaudited, pre-production.
//
// OWNERSHIP BOUNDARY
// ------------------
// This file defines ONLY the shape of the disclosure the transparency banner
// renders. It does NOT contain policy text, retention rules, or legal wording.
// The actual disclosure is owned by ANOTHER developer's compliance layer
// (enterprise/comms/compliance/), injected at runtime. We accept BOTH the
// compliance layer's OWN export shape and a generic hook, so a deployment can
// wire the real layer in with no adapter:
//
//   // (a) The compliance layer's real export (enterprise/comms/compliance/
//   //     transparency.mjs :: transparencyNotice()) — schema
//   //     "postern.comms.transparency/1". Pass the function or the notice:
//   window.PosternCommsCompliance = { transparencyNotice };           // function
//   window.PosternCommsCompliance = transparencyNotice({ orgName });  // notice object
//
//   // (b) A generic hook, if a deployment prefers to shape it itself:
//   window.PosternCommsCompliance = {
//     disclosure() {
//       return {
//         retention:       "...",        // what (if anything) is retained, by whom, how long
//         employerVisible: ["...", ...], // what the employer/admin can see
//         e2ee:            ["...", ...], // what is end-to-end encrypted (bodies)
//         notRetained:     ["...", ...], // what is explicitly NOT retained (optional)
//         legalBasis:      "...",        // optional: policy/regulation reference
//         contact:         "...",        // optional: DPO / who to ask
//         updatedAt:       "2026-..",    // optional
//       };
//     }
//   };
//
// FAIL-HONEST DEFAULT
// -------------------
// If no compliance layer is wired in, we do NOT invent a reassuring policy and
// we do NOT claim "nothing is retained". We return a clearly-labelled default
// that tells the employee the retention posture is UNKNOWN for this deployment
// and to ask their admin. Silence is never rendered as "private".

/** The honest stand-in used until the compliance layer injects real text. */
export const UNINJECTED_DISCLOSURE = Object.freeze({
  source: "none",
  injected: false,
  summary:
    "No employer compliance disclosure has been wired into this build. The retention and " +
    "employer-visibility posture for THIS deployment is therefore UNKNOWN here — do not assume " +
    "nothing is retained. Ask your organisation's admin / DPO before treating any chat as private.",
  retention:
    "Unknown in this build — not disclosed by the compliance layer. Assume your employer's policy may apply.",
  employerVisible: [
    "Unknown in this build. At minimum, the homeserver/admin can see conversation metadata " +
      "(that a chat exists, when, and between whom) — see the transparency panel.",
  ],
  e2ee: [],
  notRetained: [],
  legalBasis: null,
  contact: null,
  updatedAt: null,
});

/**
 * Resolve the compliance disclosure, preferring an injected compliance layer and
 * falling back to the fail-honest default. Never throws; a broken injector is
 * treated as "not injected".
 *
 * @param {object} [opts]
 * @param {object} [opts.injected] window.PosternCommsCompliance (or a test double)
 */
export function resolveComplianceDisclosure(opts = {}) {
  const injected = opts.injected || globalThisCompliance();
  if (!injected) return UNINJECTED_DISCLOSURE;

  // (a) The compliance layer's own `transparencyNotice` export (or a raw notice).
  const notice = extractNotice(injected, opts);
  if (notice) return fromTransparencyNotice(notice);

  // (b) The generic `disclosure()` hook.
  if (typeof injected.disclosure === "function") {
    let d = null;
    try {
      d = injected.disclosure();
    } catch {
      d = null;
    }
    if (d && typeof d === "object") {
      // A `disclosure()` that itself returns a compliance-layer notice is fine.
      return isTransparencyNotice(d) ? fromTransparencyNotice(d) : normalize(d);
    }
  }
  return UNINJECTED_DISCLOSURE;
}

/** True for the compliance layer's own disclosure object. */
function isTransparencyNotice(o) {
  return !!(o && typeof o === "object" && typeof o.schema === "string" && o.schema.startsWith("postern.comms.transparency/"));
}

/** Pull a notice object out of the injected value, however it was supplied. */
function extractNotice(injected, opts) {
  if (isTransparencyNotice(injected)) return injected; // notice passed directly
  const fn =
    typeof injected.transparencyNotice === "function"
      ? injected.transparencyNotice
      : injected.default && typeof injected.default.transparencyNotice === "function"
        ? injected.default.transparencyNotice
        : null;
  if (fn) {
    try {
      const n = fn(opts.noticeArgs || {});
      if (isTransparencyNotice(n)) return n;
    } catch {
      /* fall through */
    }
  }
  return null;
}

/**
 * Adapt the compliance layer's `postern.comms.transparency/1` notice into our
 * canonical disclosure shape — mapping only, inventing no content.
 */
function fromTransparencyNotice(n) {
  const say = (d) => (d && d.what ? (d.why ? `${d.what} — ${d.why}` : d.what) : "");
  const canSee = Array.isArray(n.canSee) ? n.canSee.map(say).filter(Boolean) : [];
  const cannotSee = Array.isArray(n.cannotSee) ? n.cannotSee.map((d) => d && d.what).filter(Boolean) : [];
  const retention = typeof n.retention === "string" ? n.retention : "See your org's published retention policy.";
  return Object.freeze({
    source: "compliance-layer",
    injected: true,
    summary: Array.isArray(n.keyFacts) && n.keyFacts.length ? n.keyFacts[0] : n.heading || "Employer compliance disclosure.",
    retention,
    employerVisible: canSee,
    e2ee: cannotSee, // what the employer CANNOT read == what E2EE protects
    notRetained: [],
    legalBasis: n.yourRights && n.yourRights.articles ? n.yourRights.articles : null,
    contact: n.yourRights && n.yourRights.how ? n.yourRights.how : null,
    updatedAt: null,
  });
}

/** Coerce an injected disclosure into the canonical shape without inventing content. */
function normalize(d) {
  const arr = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === "string" && x.trim()) : []);
  const str = (v) => (typeof v === "string" && v.trim() ? v.trim() : null);
  return Object.freeze({
    source: "compliance-layer",
    injected: true,
    summary:
      str(d.summary) ||
      "Employer compliance disclosure provided by the compliance layer (see fields below).",
    retention: str(d.retention) || "Not stated by the compliance layer.",
    employerVisible: arr(d.employerVisible),
    e2ee: arr(d.e2ee),
    notRetained: arr(d.notRetained),
    legalBasis: str(d.legalBasis),
    contact: str(d.contact),
    updatedAt: str(d.updatedAt),
  });
}

function globalThisCompliance() {
  try {
    // eslint-disable-next-line no-undef
    return typeof window !== "undefined" ? window.PosternCommsCompliance : undefined;
  } catch {
    return undefined;
  }
}

export default { UNINJECTED_DISCLOSURE, resolveComplianceDisclosure };
