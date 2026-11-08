// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern Business/Enterprise edition — honest privacy statement (machine + human).
//
// Same standard as the personal apps: say plainly what leaves the device, refuse
// to claim "100% private", and carry no telemetry. The enterprise console does
// add ONE honest wrinkle the personal apps don't have: an employer running an
// org console can, by policy, collect an audit trail of admin actions. We say so.

export const PRIVACY = Object.freeze({
  schema: "postern.enterprise.privacy/1",

  // What the console itself sends over the network.
  networkEgress: [
    {
      destination: "api.anthropic.com",
      when: "Only if YOU use the optional policy assistant, with your own Claude key.",
      contains: "Only the text you type into the assistant. Nothing else.",
      optional: true,
    },
  ],
  noTelemetry: true,
  noPhoneHome: true,
  storage: "Org config, directory, and audit chain live in this browser's localStorage (demo) / on-device store (product). No Postern server holds them.",

  // The honest employer wrinkle — the difference from a purely personal app.
  employerVisibility: [
    "An org admin console, by design, keeps an audit trail of ADMIN actions " +
      "(provisioning, policy changes, escrow/quorum acts). That trail is the point.",
    "The transparency panel shows every employee exactly what the org can and " +
      "cannot see. Admin ≠ access: an IT-admin role has no data-volume entitlements.",
    "Enterprise policy is additive: it can add managed config, it cannot read a " +
      "person's personal-app data or lock them out of their own device.",
  ],

  // The refusal — the house style.
  refusals: [
    "We do NOT claim '100% private' or 'unhackable'. No honest software can.",
    "We do NOT ship telemetry, analytics, crash beacons, or phone-home.",
    "The coin is not a security. Nothing here is a certified security product yet.",
  ],

  status: "Design / reference prototype — unaudited, pre-production.",
});

/** A compact plain-text rendering, for logs or a text pane. */
export function privacyText() {
  const p = PRIVACY;
  const lines = [
    "PRIVACY — Postern Business edition (reference prototype)",
    "",
    "What leaves this device:",
    ...p.networkEgress.map((e) => `  • ${e.destination} — ${e.when} (${e.contains})`),
    "",
    "Employer visibility (the honest wrinkle):",
    ...p.employerVisibility.map((s) => `  • ${s}`),
    "",
    "What we refuse to claim:",
    ...p.refusals.map((s) => `  • ${s}`),
    "",
    `Status: ${p.status}`,
  ];
  return lines.join("\n");
}

export default { PRIVACY, privacyText };
