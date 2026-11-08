// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Bloch — org internal messenger (Business/Enterprise edition ONLY).
// License bridge: this is the gate the whole app runs behind.
//
// STATUS: design / reference prototype — unaudited, pre-production.
//
// WHAT THIS IS
// ------------
// A thin, FAIL-CLOSED adapter that plugs the comms app into the enterprise
// license layer. It contains NO cryptography and NO verification of its own.
// It defers entirely to enterprise/features/license-hook.mjs (createLicenseGate)
// and/or an injected `window.PosternLicense` interface supplied by the real
// deployment. It NEVER fabricates a "licensed" state: if nothing valid is wired
// in, the answer is "not allowed", and the app refuses to run.
//
// THE INJECTED INTERFACE (`window.PosternLicense`)
// ------------------------------------------------
// A real Business deployment injects one of:
//   window.PosternLicense = { gate }                     // a resolved gate object
//   window.PosternLicense = { verify, masterToken }      // offline verifier + org token
// where `gate` is the object returned by createLicenseGate() and `verify` is the
// MasterTokenVerifier from the licensing lib (offline, no network). We accept a
// gate only if it looks like a real gate (has the enterpriseFeaturesAllowed
// boolean the license layer sets); a hand-forged `{enterpriseFeaturesAllowed:true}`
// is rejected because it carries none of the corroborating claim fields.

import { createLicenseGate } from "../../../features/license-hook.mjs";

/** Tiers whose presence lets THIS enterprise-only app run at all. */
export const ALLOWED_TIERS = Object.freeze(["corporate", "freemium"]);

/**
 * Resolve the effective license gate for the comms app, fail-closed.
 *
 * Precedence:
 *   1. an injected, real gate object (window.PosternLicense.gate)
 *   2. an injected offline verifier + master token -> build a gate with it
 *   3. no token at all -> business-freemium clock via createLicenseGate
 *   4. nothing usable -> a synthetic `unlicensed` gate (app refuses to run)
 *
 * @param {object} [opts]
 * @param {object} [opts.injected]   window.PosternLicense (or a test double)
 * @param {string|null} [opts.masterToken]
 * @param {Function} [opts.verify]   offline MasterTokenVerifier from licensing lib
 * @param {Date|string|number} [opts.installDate]
 * @param {Date|string|number} [opts.now]
 */
export function resolveLicense(opts = {}) {
  const injected = opts.injected || globalThisPosternLicense();

  // 1. A real, resolved gate handed to us by the deployment.
  if (injected && injected.gate && looksLikeRealGate(injected.gate)) {
    return { ...injected.gate, source: "injected-gate" };
  }

  // 2. An injected offline verifier (+ token). This is the corporate-master path.
  const verify =
    typeof opts.verify === "function"
      ? opts.verify
      : injected && typeof injected.verify === "function"
        ? injected.verify
        : null;
  const masterToken =
    opts.masterToken != null
      ? opts.masterToken
      : injected && injected.masterToken != null
        ? injected.masterToken
        : null;

  // 3/2. Let the license layer decide. With a token but no verifier it returns
  // `unverified` (fails closed) — we do NOT paper over that.
  try {
    const gate = createLicenseGate({
      masterToken,
      verify,
      installDate: opts.installDate,
      now: opts.now,
    });
    return { ...gate, source: masterToken ? "master-token" : "freemium-clock" };
  } catch {
    // 4. Anything unexpected -> fail closed with an honest synthetic gate.
    return unlicensedGate("license layer threw");
  }
}

/**
 * The single yes/no the app runs behind. Enterprise-only: allowed ONLY when the
 * license layer says an enterprise tier is active AND the tier is one we accept.
 * Never returns true on a fabricated or partial gate.
 */
export function commsAllowed(gate) {
  return !!(
    gate &&
    gate.enterpriseFeaturesAllowed === true &&
    ALLOWED_TIERS.includes(gate.tier)
  );
}

/**
 * A one-line, honest reason string for the UI when the app is NOT allowed.
 */
export function refusalReason(gate) {
  if (!gate) return "No license context — Bloch is Business-edition only and will not run.";
  if (commsAllowed(gate)) return "";
  switch (gate.state) {
    case "unverified":
      return "A master token is present but could not be verified OFFLINE (no verifier wired, or invalid). Bloch will not run on an unverified token.";
    case "expired":
      return "The enterprise license/evaluation has ended. Bloch will not run. (Your personal apps and data are unaffected.)";
    default:
      return "No valid Business/Enterprise license is active. Bloch is enterprise-only and refuses to run.";
  }
}

/** A real gate carries the boolean the license layer stamps AND its own notice. */
function looksLikeRealGate(g) {
  return (
    g &&
    typeof g === "object" &&
    typeof g.enterpriseFeaturesAllowed === "boolean" &&
    typeof g.state === "string" &&
    typeof g.personalUnaffected === "boolean"
  );
}

function unlicensedGate(why) {
  return Object.freeze({
    state: "unlicensed",
    tier: "unlicensed",
    enterpriseFeaturesAllowed: false,
    personalUnaffected: true,
    seats: 0,
    seatsUnlimited: false,
    daysRemaining: 0,
    orgName: null,
    duns: null,
    masterTokenPresent: false,
    verifierWired: false,
    source: "synthetic",
    banner: `Bloch (Business edition) — no valid license (${why}). The app refuses to run. Personal apps are unaffected.`,
  });
}

function globalThisPosternLicense() {
  try {
    // eslint-disable-next-line no-undef
    return typeof window !== "undefined" ? window.PosternLicense : undefined;
  } catch {
    return undefined;
  }
}

export default { ALLOWED_TIERS, resolveLicense, commsAllowed, refusalReason };
