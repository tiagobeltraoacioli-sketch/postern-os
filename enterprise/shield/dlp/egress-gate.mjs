// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Bloch Shield (Enterprise) — DLP egress gate.
//
// STATUS: design / reference prototype. UNAUDITED. Pre-production. NOT LEGAL
// ADVICE — see COMPLIANCE.md. Compliance-BY-DESIGN, not certified.
//
// WHAT THIS IS
// ------------
// The single point where the DLP layer is called when corporate data is about to
// LEAVE the container (`enterprise/shield/container/`, another dev's) to a third
// party. It: (1) classifies the data, (2) evaluates the fail-closed sharing
// policy to an allow/warn/block verdict, and (3) if — and ONLY if — the data is
// corporate, records the egress in the disclosed, hash-chained traceability
// trail, scoped by the acting master/sub identity.
//
// THE RAIL: this gate is authoritative for RECORDING intent, not for OS-level
// blocking. Like org-policy.mjs it evaluates; the container is the real boundary.
// And it will NEVER classify, gate, or trace the employee's personal data —
// personal-scoped data is returned as "not our concern", untouched and untraced.

import { classify, mayShareWithThirdParty, PERSONAL } from "./classification.mjs";

/**
 * Gate one egress event.
 *
 * @param {Object} req
 * @param {Object} req.data          descriptor of the data leaving (see classify())
 * @param {Object|string} req.destination  the third-party destination
 * @param {Object} req.identity      the acting identity — { masterId, subAccessId }
 * @param {Object} [req.policy]      the org sharing policy (emptySharingPolicy() shape)
 * @param {import("./audit-trail.mjs").EgressTrail} [req.trail]  the traceability trail to append to
 * @param {Date|string|number} [req.now]
 * @returns {{verdict:"allow"|"warn"|"block", class:string, corporate:boolean, destination:string, reason:string, traced:boolean, record:object|null}}
 */
export function gateEgress(req = {}) {
  const now = new Date(req.now || Date.now());
  const cls = classify(req.data || {});

  // --- THE RED LINE ---------------------------------------------------------
  // Personal / non-corporate data is NONE of this engine's business. Do not
  // classify further, do not gate, do not trace. Return honestly and stop.
  if (!cls.corporate || cls.class === PERSONAL.id) {
    return Object.freeze({
      verdict: "allow", // the engine does not gate personal egress — it simply is not in scope
      class: PERSONAL.id,
      corporate: false,
      destination: _destId(req.destination),
      reason:
        "data is personal / out of corporate scope — not classified, not gated, " +
        "and NOT recorded (the DLP layer never traces personal activity)",
      traced: false,
      record: null,
    });
  }

  // --- Corporate data: classify, then evaluate the fail-closed sharing policy.
  const decision = mayShareWithThirdParty(cls.class, req.destination, { policy: req.policy, now });

  // --- Traceability: corporate egress is recorded (disclosed, employee-visible).
  let record = null;
  let traced = false;
  if (req.trail && req.identity && req.identity.masterId && req.identity.subAccessId) {
    record = req.trail.append(
      {
        masterId: req.identity.masterId,
        subAccessId: req.identity.subAccessId,
        class: cls.class,
        destination: decision.destination,
        verdict: decision.verdict,
        reason: decision.reason,
        corporate: true,
      },
      now,
    );
    traced = true;
  }

  return Object.freeze({
    verdict: decision.verdict,
    class: cls.class,
    corporate: true,
    destination: decision.destination,
    reason: decision.reason,
    traced,
    record,
  });
}

function _destId(d) {
  return typeof d === "string" ? d : String((d && d.id) || "unknown");
}

export default { gateEgress };
