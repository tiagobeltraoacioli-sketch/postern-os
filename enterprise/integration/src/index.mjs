// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern Enterprise — integration layer PUBLIC BARREL.
//
// STATUS: design / reference prototype — unaudited, pre-production. Not a
// security product; do not rely on it for safety- or compliance-critical
// decisions without an independent review.
//
// This package wires the four reference prototypes together end-to-end WITHOUT
// editing any of them — it consumes their public exports and adds the adapters
// and orchestration the seams require:
//
//   * license-adapter.mjs    — verifyChain() -> console + comms + shield gates
//   * disclosure-adapter.mjs — transparencyNotice() -> disclosure() hook shape
//   * identity.mjs           — one master -> sub identity across comms + shield
//   * wireEnterprise()       — the whole flow assembled behind one call
//
// RAILS (non-negotiable, inherited from every module):
//   personal is free & never gated; verification is offline (no phone-home);
//   fail-closed everywhere (a token that does not verify is NEVER "licensed");
//   honest employer-visibility/BYOD disclosures preserved; the coin is not a
//   security and buys no software; adherence-by-design, not certified.

export * from "./license-adapter.mjs";
export * from "./disclosure-adapter.mjs";
export {
  provisionOrg,
  createEnterpriseConsole,
} from "./identity.mjs";

import {
  provisionOrg,
  createEnterpriseConsole,
} from "./identity.mjs";
import {
  buildCommsTransparency,
  commsTransparencyBanner,
  buildShieldTransparency,
  shieldTransparencyBanner,
  commsComplianceNotice,
  shieldDlpNotice,
} from "./siblings.mjs";
import { asDisclosureProvider } from "./disclosure-adapter.mjs";

/**
 * Assemble the whole enterprise suite for one org behind a single call: provision
 * the master, build the admin console (one verifyChain-backed gate), and expose
 * helpers to mint identities, open comms, build shield stacks, and render the
 * honest transparency banners with the compliance/DLP notices wired through the
 * disclosure() adapter.
 *
 * This is the object the self-check and any demo drives. It creates nothing that
 * could pass a gate it should not — every decision routes to a real module.
 *
 * @param {object} o
 * @param {string} o.orgName
 * @param {string} o.duns    9-digit DUNS
 * @param {Date|string|number} [o.now]
 * @param {object} [o.sealEngine] shared shield seal engine (default: labelled demo engine)
 */
export function wireEnterprise({ orgName, duns, now, sealEngine } = {}) {
  const prov = provisionOrg({ orgName, duns, now });
  const console_ = createEnterpriseConsole(prov, { now, sealEngine });

  // Employer-transparency notices, wired to the container/app hooks via the
  // disclosure() adapter. The comms hook accepts a raw notice natively too, but
  // we route it through the SAME adapter to prove the one seam serves both.
  const commsCompliance = asDisclosureProvider(commsComplianceNotice, {
    orgName,
    residency: "eu",
  });
  const shieldDlp = asDisclosureProvider(shieldDlpNotice, { orgName, residency: "eu" });

  return {
    prov,
    console: console_,
    gate: console_.gate,

    mintIdentity: (req) => console_.mintIdentity(req),
    openComms: (selfLabel) => console_.openComms(selfLabel),
    shieldFor: (id, opts) => console_.shieldFor(id, opts),
    revokeIdentity: (id, reason) => console_.revokeIdentity(id, reason),

    // Injectable disclosure providers (the disclosure()<->transparencyNotice seam).
    disclosures: { commsCompliance, shieldDlp },

    /** Bloch employee transparency (E2EE facts + employer wrinkle + injected compliance). */
    commsTransparency: () =>
      buildCommsTransparency({ injectedCompliance: commsCompliance, gate: console_.gate }),
    commsBanner: () =>
      commsTransparencyBanner({ injectedCompliance: commsCompliance, gate: console_.gate }),

    /** SHIELD employee transparency (container facts + injected DLP disclosure). */
    shieldTransparency: () =>
      buildShieldTransparency({ injectedDlp: shieldDlp, gate: console_.gate }),
    shieldBanner: () => shieldTransparencyBanner({ injectedDlp: shieldDlp, gate: console_.gate }),
  };
}

export default { wireEnterprise, provisionOrg, createEnterpriseConsole };
