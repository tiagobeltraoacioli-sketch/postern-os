// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern SHIELD — employee-facing transparency panel HOOK (Enterprise ONLY).
//
// STATUS: design / reference prototype — unaudited, pre-production.
//
// WHAT THIS IS
// ------------
// The place the SHIELD container tells the EMPLOYEE, honestly, what the corporate
// work-container does and does NOT do on their personal phone. It assembles two
// honest sources and invents no policy of its own:
//
//   1. CONTAINER FACTS (owned here): the boundary is corporate-scope-only; the
//      personal side is never touched or surveilled; containment is by
//      construction (userland), not a kernel boundary; a rooted phone defeats it;
//      de-provisioning self-wipes the corporate data but a personal device cannot
//      be guaranteed remote-wiped.
//   2. The DLP / COMPLIANCE DISCLOSURE, INJECTED by the DLP/traceability dev's
//      layer (enterprise/shield/dlp/, a separate module). The disclosure TEXT —
//      what the employer can see, what is logged, retention — is OWNED THERE, not
//      here. We only define the hook shape and render it; when nothing is wired we
//      stay fail-honest and say the disclosure is NOT available in this build.
//
// House rule: never claim "100% private" or "fully secure". This is an
// EMPLOYER-PROVISIONED container on a personal device. We disclose the wrinkle.

/** Facts the container layer owns and will always state, regardless of the DLP layer. */
export const CONTAINER_FACTS = Object.freeze({
  scope: "corporate-container-only",
  corporateScopeOnly: [
    "This work-container holds ONLY corporate data. It is provisioned by your employer.",
    "It is strictly segregated from your personal apps and files. The container cannot read, list, or touch your personal side — there is no code path here that reaches it.",
  ],
  neverSurveilled: [
    "Your PERSONAL side is never accessed, scanned, or surveilled by this container. Corporate-scope only.",
    "Nothing here logs your personal activity, location, contacts, or other apps.",
  ],
  boundaryHonesty: [
    // Mirrors postern-policy EnforcementMode::ByConstruction wording.
    "Containment is by construction (a userland, in-process check), NOT an OS sandbox or kernel boundary.",
    "A rooted / jailbroken phone, or malware with root, can defeat this container. Containment assumes an unrooted device — it is not unbreakable.",
  ],
  deprovisioning: [
    "When your access is revoked or expires, the container refuses access and SELF-WIPES its own corporate data.",
    "Honest limit: on a personal device we cannot GUARANTEE a remote wipe — if the phone is offline, off, or was already rooted and copied the data, those bytes may persist outside our reach.",
    "Offline revocation is best-effort and clock-based: the container may only learn of a revocation when it can re-check, or when the grant's expiry passes on the local clock.",
  ],
  refusals: [
    "We do NOT claim this container is '100% private' or 'fully secure' — it is an employer-provisioned tool on your personal device.",
    "This is a reference prototype: UNAUDITED, pre-production. Do not rely on it for real secrets.",
  ],
});

/**
 * The pluggable DLP/compliance disclosure interface, owned by
 * enterprise/shield/dlp/ (a separate developer's module):
 *
 *   disclosure() -> {
 *     summary: string,
 *     employerVisible: string[],   // what the employer/DLP layer can see or log
 *     logged: string[],            // corporate-scope events recorded
 *     retention: string,           // how long, by whom
 *     notCollected?: string[],     // explicitly out of scope
 *     contact?: string,
 *   }
 *
 * Passed in as `injected` (e.g. window.PosternShieldDlp or a server-provided
 * object). We never fabricate this text; absence is disclosed as absence.
 *
 * @param {object} [opts]
 * @param {{disclosure:Function}} [opts.injected]
 */
export function resolveDlpDisclosure(opts = {}) {
  const injected = opts.injected;
  if (injected && typeof injected.disclosure === "function") {
    let d = null;
    try {
      d = injected.disclosure();
    } catch {
      d = null;
    }
    if (d && typeof d === "object") {
      return Object.freeze({
        injected: true,
        source: "shield-dlp-layer",
        summary: String(d.summary || "(no summary provided by DLP layer)"),
        employerVisible: arr(d.employerVisible),
        logged: arr(d.logged),
        retention: String(d.retention || "UNSPECIFIED by the DLP layer"),
        notCollected: arr(d.notCollected),
        contact: d.contact ? String(d.contact) : null,
      });
    }
  }
  // Fail-honest default: no DLP layer wired => say so, never fake "nothing logged".
  return Object.freeze({
    injected: false,
    source: "none (DLP/compliance layer not wired in this build)",
    summary:
      "The DLP/traceability disclosure for this deployment is NOT available in this build. What the employer can see or log is governed by enterprise/shield/dlp/ — ask your admin. Do NOT assume nothing is logged.",
    employerVisible: ["UNKNOWN in this build — the DLP layer is not wired."],
    logged: ["UNKNOWN in this build — the DLP layer is not wired."],
    retention: "UNKNOWN in this build.",
    notCollected: [],
    contact: null,
  });
}

/**
 * Build the full transparency model an employee sees for the SHIELD container.
 *
 * @param {object} [opts]
 * @param {object} [opts.injectedDlp]  the DLP layer's disclosure provider
 * @param {object} [opts.gate]         resolved license gate (for org name)
 */
export function buildTransparency(opts = {}) {
  const dlp = resolveDlpDisclosure({ injected: opts.injectedDlp });
  const gate = opts.gate || null;
  return Object.freeze({
    orgName: (gate && gate.orgName) || null,
    scope: CONTAINER_FACTS.scope,
    container: CONTAINER_FACTS,
    dlp,
    status: "Design / reference prototype — unaudited, pre-production. Containment by construction, not certified or unbreakable.",
  });
}

/** One-line, always-visible banner for the container UI. */
export function transparencyBanner(opts = {}) {
  const t = buildTransparency(opts);
  const who = t.orgName ? `${t.orgName}'s ` : "your employer's ";
  const dlpClause = t.dlp.injected
    ? "What your employer can see/log is disclosed in the panel."
    : "What your employer can see/log is NOT disclosed in this build — ask your admin; do not assume nothing is logged.";
  return (
    `This is ${who}corporate work-container: corporate data only, sealed at rest, self-wiped when your access ends. ` +
    `It never touches your personal side. Containment is by construction (a rooted phone can defeat it), not a kernel boundary. ${dlpClause}`
  );
}

/** Compact plain-text rendering for a text pane / self-check / logs. */
export function transparencyText(opts = {}) {
  const t = buildTransparency(opts);
  const bullet = (s) => `  • ${s}`;
  const lines = [
    "TRANSPARENCY — Postern SHIELD work-container (Business edition, reference prototype)",
    "",
    "Banner:",
    "  " + transparencyBanner(opts),
    "",
    "Corporate-scope only (what this container is):",
    ...t.container.corporateScopeOnly.map(bullet),
    "",
    "Your personal side (never touched):",
    ...t.container.neverSurveilled.map(bullet),
    "",
    "Honest boundary:",
    ...t.container.boundaryHonesty.map(bullet),
    "",
    "When you leave (de-provisioning):",
    ...t.container.deprovisioning.map(bullet),
    "",
    `DLP / compliance disclosure [source: ${t.dlp.source}]:`,
    bullet(t.dlp.summary),
    bullet("Retention: " + t.dlp.retention),
    ...t.dlp.employerVisible.map((s) => bullet("Employer can see: " + s)),
    ...t.dlp.logged.map((s) => bullet("Logged: " + s)),
    ...t.dlp.notCollected.map((s) => bullet("Explicitly NOT collected: " + s)),
    "",
    "What we refuse to claim:",
    ...t.container.refusals.map(bullet),
    "",
    `Status: ${t.status}`,
  ];
  return lines.join("\n");
}

function arr(x) {
  return Array.isArray(x) ? x.map(String) : [];
}

export default { CONTAINER_FACTS, resolveDlpDisclosure, buildTransparency, transparencyBanner, transparencyText };
