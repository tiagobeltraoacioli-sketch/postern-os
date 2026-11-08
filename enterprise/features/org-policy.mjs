// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern Business/Enterprise edition — org policy engine (reference prototype).
//
// STATUS: design / reference prototype, unaudited, pre-production. This is a
// pure, dependency-free policy model. It does NOT enforce anything by itself —
// on a real deployment the daemon / device profile is authoritative; this file
// only *describes and evaluates* an org's intent.
//
// THE ONE RAIL THAT NEVER BENDS
// -----------------------------
// Enterprise policy is strictly ADDITIVE. The free personal app suite is free
// and unrestricted. Nothing an admin does here can take a personal app away
// from a person or lock them out of their own device/data. Enterprise policy
// can only *add* org-managed capabilities on top (managed config, SSO, audit
// export, fleet defaults). `assertAdditive()` enforces this at evaluation time
// and throws on any attempt to gate a personal-free app.

/** @typedef {"personal-free"|"business"} Tier */

/**
 * A default, empty org policy. Teams and per-feature toggles are layered on top.
 * @returns {{schema:string, org:string|null, teams:Object, defaults:Object}}
 */
export function emptyPolicy() {
  return {
    schema: "postern.enterprise.org-policy/1",
    org: null,
    // Per-team enablement of enterprise-additive features, keyed by
    // `${appId}:${featureId}` -> boolean. Absent = feature's catalog default.
    teams: {},
    // Org-wide defaults applied when a team has no explicit setting.
    defaults: {},
  };
}

/**
 * Look up a catalog app by id.
 * @param {object} catalog
 * @param {string} appId
 */
export function findApp(catalog, appId) {
  return (catalog.apps || []).find((a) => a.id === appId) || null;
}

/**
 * Guard: a policy must never mark a personal-free app unavailable. The personal
 * suite is free and unrestricted — enterprise features are additive only.
 * Throws if a caller tries to smuggle a "disable app" toggle into policy.
 * @param {object} catalog
 * @param {object} policy
 */
export function assertAdditive(catalog, policy) {
  for (const key of Object.keys(policy.teams || {})) {
    for (const flag of Object.keys(policy.teams[key] || {})) {
      const [appId, featureId] = flag.split(":");
      const app = findApp(catalog, appId);
      if (!app) continue;
      // A reserved feature id that would remove the base app is forbidden.
      if (featureId === "app-available" || featureId === "app-disabled") {
        throw new Error(
          `additive-boundary: policy may not gate base app "${appId}" ` +
            `(personal suite is free and unrestricted; enterprise features are additive only)`,
        );
      }
      const feat = (app.enterpriseFeatures || []).find((f) => f.id === featureId);
      if (feat && feat.additive === false) {
        throw new Error(
          `additive-boundary: feature "${appId}:${featureId}" is marked non-additive; ` +
            `enterprise policy may only ADD capabilities, never subtract`,
        );
      }
    }
  }
  return true;
}

/**
 * Resolve whether an enterprise-additive feature is enabled for a given team.
 * Precedence: explicit team setting > org default > catalog default.
 */
function featureEnabled(policy, appId, feat, team) {
  const key = `${appId}:${feat.id}`;
  const teamCfg = (policy.teams && policy.teams[team]) || {};
  if (Object.prototype.hasOwnProperty.call(teamCfg, key)) return !!teamCfg[key];
  if (policy.defaults && Object.prototype.hasOwnProperty.call(policy.defaults, key)) {
    return !!policy.defaults[key];
  }
  return !!feat.default;
}

/**
 * Evaluate the effective posture of the personal suite for one team/person.
 *
 * Returns, for every app in the catalog:
 *   - available: ALWAYS true for personal-free apps (this is the boundary).
 *   - enterpriseFeatures: which additive features the org has switched on.
 *
 * @param {object} catalog  parsed app-catalog.json
 * @param {object} policy   an org policy (see emptyPolicy)
 * @param {{team?:string}} [ctx]
 */
export function evaluatePolicy(catalog, policy, ctx = {}) {
  assertAdditive(catalog, policy);
  const team = ctx.team || "default";
  const apps = (catalog.apps || []).map((app) => {
    const feats = (app.enterpriseFeatures || []).map((f) => ({
      id: f.id,
      name: f.name,
      enabled: featureEnabled(policy, app.id, f, team),
      requiresLicense: f.requiresLicense !== false, // enterprise features need a license after eval
    }));
    return {
      id: app.id,
      name: app.name,
      tier: app.tier,
      // The load-bearing invariant: personal apps are never withheld.
      available: app.tier === "personal-free" ? true : featuresGateAvailable(app, feats),
      enterpriseFeatures: feats,
    };
  });
  return { org: policy.org, team, apps };
}

/**
 * Business-only surfaces (e.g. the admin console itself) are available only when
 * at least their base capability is licensed/enabled. Personal apps never reach
 * this path.
 */
function featuresGateAvailable(app, feats) {
  if (!feats.length) return true;
  return feats.some((f) => f.enabled);
}

/**
 * Human-readable one-liner describing the boundary, for surfacing in UIs.
 */
export const ADDITIVE_STATEMENT =
  "The personal Postern app suite is free and unrestricted. Business-edition " +
  "policy can only ADD org-managed capabilities (managed config, SSO, audit " +
  "export, fleet defaults). It can never disable a personal app or lock a " +
  "person out of their own device or data.";

export default { emptyPolicy, findApp, assertAdditive, evaluatePolicy, ADDITIVE_STATEMENT };
