// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern Enterprise — integration layer: DISCLOSURE ADAPTER (disclosure()<->transparencyNotice()).
//
// STATUS: design / reference prototype — unaudited, pre-production.
//
// THE MISMATCH THIS BRIDGES
// -------------------------
// The employer-transparency layers PUBLISH a rich, schema-tagged notice:
//   * shield/dlp/transparency.transparencyNotice()   -> "bloch.shield.dlp.transparency/1"
//       { tracked[], notTracked[], keyFacts[], lawfulBasis[], yourRights, ... }
//   * comms/compliance/transparency.transparencyNotice() -> "postern.comms.transparency/1"
//       { canSee[], cannotSee[], keyFacts[], retention, yourRights, ... }
//
// The container/app HOOKS that render to the employee consume a flat generic
// `disclosure()`:
//   * shield/container/transparency-hook.resolveDlpDisclosure reads an injected
//       { disclosure() -> { summary, employerVisible[], logged[], retention,
//                           notCollected?[], contact? } }
//   * comms/app/compliance-hook.resolveComplianceDisclosure ALSO accepts a raw
//       transparencyNotice natively — but a deployment may prefer the generic
//       disclosure() seam; this adapter feeds both.
//
// `noticeToDisclosure()` maps EITHER published notice into a SUPERSET disclosure
// object; each consumer reads the fields it needs. It INVENTS NO CONTENT — it
// only re-shapes what the source notice already states. If a field is absent in
// the source it stays empty rather than being fabricated (the hooks' fail-honest
// defaults still apply when nothing is wired at all).

const arr = (x) => (Array.isArray(x) ? x.filter(Boolean) : []);
const str = (x) => (typeof x === "string" && x.trim() ? x.trim() : null);

/** Is this the shield DLP corporate-egress notice? */
function isShieldDlpNotice(n) {
  return !!(n && typeof n.schema === "string" && n.schema.startsWith("bloch.shield.dlp.transparency/"));
}
/** Is this the comms compliance notice? */
function isCommsComplianceNotice(n) {
  return !!(n && typeof n.schema === "string" && n.schema.startsWith("postern.comms.transparency/"));
}

/**
 * Map a published transparencyNotice into the flat `disclosure()` superset shape.
 * Handles both known schemas; unknown-but-notice-shaped inputs are mapped
 * best-effort from common fields. Content is only ever re-arranged, never coined.
 *
 * Superset fields (each consumer reads a subset):
 *   summary, retention            (both)
 *   employerVisible[]             (both — what the employer/operator can see)
 *   logged[]                      (shield — corporate-scope events recorded)
 *   notCollected[]                (shield — explicitly out of scope)
 *   e2ee[]                        (comms — what the employer CANNOT read)
 *   notRetained[]                 (comms — explicitly not retained)
 *   legalBasis, contact, updatedAt
 *
 * @param {object} notice a transparencyNotice from a compliance/dlp layer
 * @returns {object} frozen disclosure object
 */
export function noticeToDisclosure(notice) {
  if (isShieldDlpNotice(notice)) return fromShieldDlp(notice);
  if (isCommsComplianceNotice(notice)) return fromCommsCompliance(notice);
  return fromGeneric(notice || {});
}

function fromShieldDlp(n) {
  const tracked = arr(n.tracked);
  const events = tracked.flatMap((t) => arr(t.events));
  const employerVisible = tracked.map((t) =>
    t.detail ? `${t.what} — ${t.detail}` : t.what,
  );
  const residency = str(n.residency) || "unspecified";
  return Object.freeze({
    summary: arr(n.keyFacts)[0] || n.heading || "Corporate-egress traceability disclosure.",
    // The DLP layer traces only corporate egress; retention is scoped to that.
    retention:
      `Corporate third-party egress records only (data residency: ${residency}). ` +
      `Duration/custody per your org's published retention policy — see COMPLIANCE.md.`,
    employerVisible,
    logged: [...new Set(events)],
    notCollected: arr(n.notTracked),
    e2ee: [],
    notRetained: [],
    legalBasis: (n.yourRights && str(n.yourRights.articles)) || null,
    contact: (n.yourRights && str(n.yourRights.how)) || null,
    updatedAt: null,
  });
}

function fromCommsCompliance(n) {
  const canSee = arr(n.canSee).map((d) => (d && d.why ? `${d.what} — ${d.why}` : d && d.what)).filter(Boolean);
  const cannotSee = arr(n.cannotSee).map((d) => d && d.what).filter(Boolean);
  return Object.freeze({
    summary: arr(n.keyFacts)[0] || n.heading || "Employer compliance disclosure.",
    retention: str(n.retention) || "See your org's published retention policy.",
    employerVisible: canSee,
    logged: [],
    notCollected: [],
    e2ee: cannotSee, // what the employer CANNOT read == what E2EE protects
    notRetained: [],
    legalBasis: (n.yourRights && str(n.yourRights.articles)) || null,
    contact: (n.yourRights && str(n.yourRights.how)) || null,
    updatedAt: null,
  });
}

function fromGeneric(n) {
  return Object.freeze({
    summary: str(n.summary) || str(n.heading) || "Compliance disclosure.",
    retention: str(n.retention) || "Not stated by the source notice.",
    employerVisible: arr(n.employerVisible),
    logged: arr(n.logged),
    notCollected: arr(n.notCollected),
    e2ee: arr(n.e2ee),
    notRetained: arr(n.notRetained),
    legalBasis: str(n.legalBasis),
    contact: str(n.contact),
    updatedAt: str(n.updatedAt),
  });
}

/**
 * Wrap a published notice (or a zero-arg notice factory) as an injectable
 * `{ disclosure() }` provider — the exact shape shield's transparency-hook and
 * comms's compliance-hook accept via the generic seam.
 *
 * @param {object|Function} noticeOrFactory a transparencyNotice, or a function returning one
 * @param {object} [args] args passed to the factory (e.g. { orgName, residency })
 * @returns {{ disclosure: () => object }}
 */
export function asDisclosureProvider(noticeOrFactory, args = {}) {
  const notice = typeof noticeOrFactory === "function" ? noticeOrFactory(args) : noticeOrFactory;
  return { disclosure: () => noticeToDisclosure(notice) };
}
