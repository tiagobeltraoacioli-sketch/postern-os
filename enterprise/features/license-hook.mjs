// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern Business/Enterprise edition — licensing NOTICE + offline verify hook.
//
// STATUS: design / reference prototype, unaudited, pre-production.
//
// WHAT THIS IS
// ------------
// A HONEST notice and a stable INTERFACE where a real, OFFLINE license check
// plugs in. This file contains NO cryptography and NO verification. The real
// verifier is another developer's library (enterprise/licensing/) whose public
// key checks a master token WITHOUT a network call; the token itself is minted
// on posternlabs.com by a company against its DUNS number. This module does NOT
// import that library and must not — it only defines the shape of verify() so
// the console can render an honest banner and call an injected verifier.
//
// THE ACCESS MODEL (surfaced verbatim in the UI)
// ----------------------------------------------
//  PERSONAL          — free, forever. No login, no account, no tracking. Nothing
//                      below applies to it. It is never gated.
//  BUSINESS FREEMIUM — free for up to 3 desktops for 2 years. No account, no
//                      server login, no per-user tracking.
//  CORPORATE MASTER  — a company with a DUNS number mints ONE master token on
//                      posternlabs.com. That token is the ORG's access grant:
//                      it unlocks the Business edition for UNLIMITED users for a
//                      6-month evaluation. Users under the master do NOT each
//                      make an account and there is NO per-user server login —
//                      access == the master token is present and verifies
//                      OFFLINE against the licensing lib's public key.
//
//  Payment (after the evaluation) is FIAT — invoice / card. Pricing is still
//  being structured. It is NEVER a coin: the Bloch-SIS-PoW coin is not a
//  security, not an asset, and buys no software.

/** Business-freemium window: up to 3 desktops for 2 years. */
export const FREEMIUM_SEATS = 3;
export const FREEMIUM_DAYS = 730; // ~2 years

/** Corporate master evaluation: unlimited seats, 6 months. */
export const CORPORATE_EVAL_DAYS = 183; // ~6 months

export const EDITION_NOTICE = Object.freeze({
  edition: "Postern Business (reference prototype)",
  personal: "Free forever. No login, no account, no tracking. Never gated by anything here.",
  businessFreemium: "Free for up to 3 desktops for 2 years. No account, no per-user login, no tracking.",
  corporateMaster:
    "A company with a DUNS number mints one master token on posternlabs.com; that token unlocks the Business edition for UNLIMITED users for a 6-month evaluation, verified OFFLINE. No per-user accounts, no per-user login.",
  afterEval: "A paid license will be required after the evaluation — for the enterprise features only, never for the personal apps or your data.",
  payment: "Fiat only (invoice / card); pricing is still being structured. Never a coin. The coin is not a security and buys no software.",
  verification: "Offline — the master token is checked against the licensing lib's public key. No phone-home, no telemetry.",
  audited: false,
  production: false,
});

/**
 * @typedef {"personal"|"business-freemium"|"corporate-master"|"expired"|"unverified"} LicenseState
 */

/**
 * The pluggable OFFLINE verifier interface. A real implementation (from
 * enterprise/licensing/) verifies a master token against a bundled public key —
 * no network — and returns claims. When no verifier is injected we stay honest:
 * a token present but unverifiable yields `unverified`, NEVER `corporate-master`.
 *
 * @typedef {(masterToken: string) => (
 *   { valid: boolean, orgName?: string, duns?: string, seats?: number|"unlimited", expires?: string }
 *   | null
 * )} MasterTokenVerifier
 */

/**
 * Create the license gate for the Business edition.
 *
 * @param {object} [opts]
 * @param {string|null} [opts.masterToken]  the org's master token (offline-verified), or null
 * @param {MasterTokenVerifier} [opts.verify] injected offline verifier from the licensing lib
 * @param {Date|string|number} [opts.installDate] when the freemium clock started
 * @param {Date|string|number} [opts.now]         override "now" (for tests)
 */
export function createLicenseGate(opts = {}) {
  const now = new Date(opts.now || Date.now());
  const installDate = new Date(opts.installDate || now);
  const masterToken = opts.masterToken || null;
  const verify = typeof opts.verify === "function" ? opts.verify : null;
  const msPerDay = 86_400_000;
  const daysBetween = (a, b) => Math.floor((b.getTime() - a.getTime()) / msPerDay);

  // ---- Corporate master path: an org token, verified OFFLINE ----
  if (masterToken) {
    if (!verify) {
      // A token is present but no offline verifier is wired in. Stay honest.
      return gate("unverified", {
        masterTokenPresent: true,
        verifierWired: false,
        seats: 0,
        daysRemaining: 0,
      });
    }
    let claims = null;
    try {
      claims = verify(masterToken);
    } catch {
      claims = null; // broken verifier fails closed
    }
    if (!claims || claims.valid !== true) {
      return gate("unverified", { masterTokenPresent: true, verifierWired: true, seats: 0, daysRemaining: 0 });
    }
    const expires = claims.expires ? new Date(claims.expires) : new Date(now.getTime() + CORPORATE_EVAL_DAYS * msPerDay);
    const daysRemaining = Math.max(0, daysBetween(now, expires));
    if (daysRemaining <= 0) {
      return gate("expired", {
        masterTokenPresent: true,
        verifierWired: true,
        orgName: claims.orgName || null,
        duns: claims.duns || null,
        seats: "unlimited",
        daysRemaining: 0,
        expires: expires.toISOString().slice(0, 10),
      });
    }
    return gate("corporate-master", {
      masterTokenPresent: true,
      verifierWired: true,
      orgName: claims.orgName || null,
      duns: claims.duns || null,
      seats: claims.seats || "unlimited",
      daysRemaining,
      expires: expires.toISOString().slice(0, 10),
    });
  }

  // ---- Business-freemium path: 3 desktops, 2 years, no token, no login ----
  const elapsed = daysBetween(installDate, now);
  const daysRemaining = Math.max(0, FREEMIUM_DAYS - elapsed);
  if (daysRemaining <= 0) {
    return gate("expired", { masterTokenPresent: false, verifierWired: !!verify, seats: FREEMIUM_SEATS, daysRemaining: 0 });
  }
  return gate("business-freemium", {
    masterTokenPresent: false,
    verifierWired: !!verify,
    seats: FREEMIUM_SEATS,
    daysRemaining,
  });

  /** @param {LicenseState} state */
  function gate(state, extra) {
    const allowed = state === "corporate-master" || state === "business-freemium";
    return Object.freeze({
      state,
      tier:
        state === "corporate-master"
          ? "corporate"
          : state === "business-freemium"
            ? "freemium"
            : state,
      seats: extra.seats,
      seatsUnlimited: extra.seats === "unlimited",
      daysRemaining: extra.daysRemaining,
      expires: extra.expires || null,
      orgName: extra.orgName || null,
      duns: extra.duns || null,
      masterTokenPresent: !!extra.masterTokenPresent,
      verifierWired: !!extra.verifierWired,
      enterpriseFeaturesAllowed: allowed,
      // The boundary, restated: none of this ever touches the personal apps.
      personalUnaffected: true,
      notice: EDITION_NOTICE,
      banner: bannerFor(state, extra),
    });
  }
}

function bannerFor(state, x) {
  const d = x.daysRemaining;
  const day = (n) => `${n} day${n === 1 ? "" : "s"}`;
  switch (state) {
    case "corporate-master":
      return `Business edition — corporate master token${x.orgName ? " for " + x.orgName : ""}: unlimited seats, offline-verified, ${day(d)} of evaluation remaining. A license will be required after.`;
    case "business-freemium":
      return `Business edition — free freemium (up to ${FREEMIUM_SEATS} desktops), ${day(d)} remaining. No account, no login. A corporate master token lifts the seat cap.`;
    case "expired":
      return x.masterTokenPresent
        ? "Business edition — the corporate evaluation has ended. A paid license is required to keep the enterprise features (personal apps and your data are unaffected)."
        : "Business edition — the 2-year freemium has ended. Enter a corporate master token or take a license. Personal apps stay free.";
    case "unverified":
    default:
      return "Business edition — a master token is present but could not be verified offline (no verifier wired, or invalid token). Enterprise features run in demo only. Personal apps are unaffected.";
  }
}

export default {
  FREEMIUM_SEATS,
  FREEMIUM_DAYS,
  CORPORATE_EVAL_DAYS,
  EDITION_NOTICE,
  createLicenseGate,
};
