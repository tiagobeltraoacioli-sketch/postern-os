// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern CLOUD control plane — honest hosted-privacy statement (machine + human).
//
// The house rule, stated plainly: HOSTED IS LESS PRIVATE THAN SELF-HOSTING.
// A managed Postern node runs on operator infrastructure the org does not own,
// under a control plane the org does not run. That is a real privacy cost and we
// say so up front, in the README and in every user-facing surface — we never
// pitch the managed service as "just as private" as running your own node.

export const CLOUD_PRIVACY = Object.freeze({
  schema: "postern.cloud.control-plane.privacy/1",
  status: "Design / reference prototype — unaudited, pre-production. No real hosts are provisioned by this code.",

  // The headline, non-negotiable disclosure.
  hostedIsLessPrivate:
    "Hosting a managed Postern node with an operator is LESS PRIVATE than self-hosting your own node. " +
    "Your nodes run on infrastructure you do not own, under a control plane you do not run. " +
    "If maximum privacy is the goal, self-host — the personal apps and self-run nodes are always free.",

  // Isolation is by-construction — and a compromised control plane defeats it.
  isolationHonesty:
    "Tenant isolation here is BY CONSTRUCTION (in-process namespacing), not a kernel or hypervisor boundary. " +
    "A COMPROMISED CONTROL PLANE DEFEATS IT: whoever controls the orchestrator can read any tenant.",

  // Business-only. Personal never touches the cloud.
  businessOnly:
    "The managed service is corporate-only (a DUNS-backed master license is required). " +
    "Personal Postern apps and personal data NEVER touch this control plane — there is no code path for it.",

  // Exactly the operational metrics the control plane records. Nothing else.
  disclosedMetrics: [
    "Per-tenant managed-node count and lifecycle state (pending/running/deprovisioned/failed).",
    "Provision / deprovision events, keyed to the org's master license, for the operator's audit trail.",
    "Control-process uptime and aggregate node counts (for operator health dashboards).",
  ],

  // What it does NOT do.
  noTelemetry: true,
  noPhoneHome: true,
  refusals: [
    "We do NOT collect telemetry from inside a managed node, nor from any personal app.",
    "We do NOT claim the managed service is '100% private', 'zero-knowledge', or 'as private as self-hosting'. It is not.",
    "We do NOT hold personal-app data — the control plane orchestrates business nodes only.",
    "The Bloch-SIS-PoW coin is not a security and buys no software. Payment (after evaluation) is fiat.",
  ],
});

/** A compact plain-text rendering for logs, a text pane, or a README block. */
export function cloudPrivacyText() {
  const p = CLOUD_PRIVACY;
  return [
    "PRIVACY — Postern CLOUD control plane (reference prototype)",
    "",
    "Hosted vs self-hosted:",
    "  • " + p.hostedIsLessPrivate,
    "",
    "Isolation honesty:",
    "  • " + p.isolationHonesty,
    "",
    "Business only:",
    "  • " + p.businessOnly,
    "",
    "Operational metrics we record (and only these):",
    ...p.disclosedMetrics.map((m) => "  • " + m),
    "",
    "What we refuse to claim:",
    ...p.refusals.map((r) => "  • " + r),
    "",
    "Status: " + p.status,
  ].join("\n");
}

export default { CLOUD_PRIVACY, cloudPrivacyText };
