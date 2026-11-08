// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern SHIELD — access broker to the corporate Linux system (Enterprise ONLY).
//
// STATUS: design / reference prototype — unaudited, pre-production.
//
// WHAT THIS IS
// ------------
// The broker that gates an employee's remote session into the CORPORATE Linux
// system from inside the SHIELD container. It answers one question at every
// access boundary: "may this device open a corporate session RIGHT NOW?" and
// wires four honest gates in series, fail-closed (first refusal wins):
//
//   1. LICENSE   — the org's enterprise license must be corporate-master/allowed
//                  (enterprise/features/license-hook.mjs, injected — not re-done here).
//   2. GRANT     — the employee's access grant must be LIVE (unrevoked, unexpired;
//                  grant-binding.mjs, mirroring postern-policy consent semantics).
//   3. SUB-TOKEN — a valid enterprise SUB-token under the org master, proven by a
//                  Consiglio wallet challenge/response (consiglio-bridge.mjs).
//   4. CONTAINER — the SHIELD container must not be self-wiped; on a failed grant
//                  it self-wipes the corporate data (de-provisioning = leaving).
//
// THE TRANSPORT, HONESTLY
// -----------------------
// This broker does NOT open sockets or run a server. It PLANS and AUTHORIZES a
// session and hands an opaque session ticket to an injected transport. The honest
// transport is an SSH / remote session (e.g. mosh/SSH or an RDP-like remote
// desktop) carried over the paired, authenticated channel to an OPERATOR-RUN
// corporate host. The server side (sshd, the Linux box, its own authN/authZ) is
// run by the customer's operators — it is NOT implemented or shipped here. We only
// decide whether to START, and we can tear the session down.
//
// HONEST LIMITS
// -------------
//  * All gating is BY CONSTRUCTION in userland — NOT a kernel boundary. A rooted
//    phone can bypass this broker and talk to the corporate host directly if it
//    already holds valid credentials; containment assumes an unrooted device.
//  * Offline revocation is best-effort (local clock). A live session already open
//    is torn down at the NEXT boundary re-check, not necessarily instantly.

import { createConsiglioBridge } from "./consiglio-bridge.mjs";

export class AccessRefused extends Error {
  constructor(reason, gate) {
    super(reason);
    this.name = "AccessRefused";
    this.gate = gate || null;
  }
}

/**
 * @param {object} opts
 * @param {object} opts.licenseGate  resolved gate from enterprise/features/license-hook.mjs
 * @param {ReturnType<import("./grant-binding.mjs").createAccessGrant>} opts.grant
 * @param {ReturnType<import("./shield-container.mjs").createShieldContainer>} opts.container
 * @param {object} [opts.consiglio]  createConsiglioBridge(...) result; default = unauthenticated stand-in
 * @param {object} [opts.walletSigner] { sign(challenge) -> response } from the wallet (injected)
 * @param {object} [opts.transport]  { open(ticket)->session, close(session) } injected SSH/remote transport
 * @param {(evt:object)=>void} [opts.audit]
 */
export function createAccessBroker(opts = {}) {
  const gate = opts.licenseGate;
  const grant = opts.grant;
  const container = opts.container;
  if (!gate) throw new Error("access-broker: a resolved license gate is required");
  if (!grant) throw new Error("access-broker: an access grant is required");
  if (!container) throw new Error("access-broker: a shield container is required");
  const consiglio = opts.consiglio || createConsiglioBridge();
  const walletSigner = opts.walletSigner || null;
  const transport = opts.transport || null;
  const audit = typeof opts.audit === "function" ? opts.audit : () => {};

  let session = null;

  /**
   * Evaluate all four gates in series without side effects (except the
   * container's revoke-triggered self-wipe, which is the intended de-provisioning
   * effect). Returns a decision object; does NOT open the transport.
   */
  function authorize(now) {
    // 1. License gate (owned by license-hook; we only read its verdict).
    if (!gate.enterpriseFeaturesAllowed) {
      return refusal("license", licenseReason(gate));
    }
    // 2. Live grant (postern-policy consent semantics via grant-binding).
    const gd = grant.decide(new Date(now || Date.now()));
    if (!gd.allow) {
      // De-provisioning = leaving: refuse AND self-wipe the corporate data.
      const wipe = container.enforceOrWipe(now);
      return refusal("grant", gd.reason, { selfWiped: wipe.wiped });
    }
    // 4 (early): a container already wiped can never be entered.
    if (container.isWiped()) {
      return refusal("container", "container has been self-wiped (de-provisioned)");
    }
    return { allowed: true, gate: null, reason: null };
  }

  return {
    consiglioWired: consiglio.authenticatorWired,
    transportWired: !!transport,

    authorize,

    /**
     * Full open sequence: authorize the four gates, run the Consiglio wallet
     * challenge/response for the SUB-token, unlock the container, then hand an
     * opaque session ticket to the injected transport. Fail-closed at every step.
     *
     * @returns {{session:object, gates:object}}
     */
    openSession(now) {
      const auth = authorize(now);
      if (!auth.allowed) throw new AccessRefused(auth.reason, auth.gate);

      // 3. SUB-TOKEN via Consiglio challenge/response (PQ signature, injected verifier).
      const challenge = consiglio.issueChallenge({ orgId: grant.orgId, employeeId: grant.employeeId }, now);
      if (!walletSigner || typeof walletSigner.sign !== "function") {
        throw new AccessRefused(
          "no wallet signer wired — cannot answer the Consiglio challenge (demo). Refusing session.",
          "sub-token",
        );
      }
      const response = walletSigner.sign(challenge, grant.subTokenForBroker());
      const verdict = consiglio.verifyResponse(challenge, response, now);
      if (!verdict.ok) throw new AccessRefused(`SUB-token challenge failed: ${verdict.reason}`, "sub-token");

      // 4. Unlock the container (key bound to the live grant).
      container.unlock(now);

      // Transport: hand off an OPAQUE ticket. The corporate host (sshd + Linux) is
      // operator-run; we neither implement nor authenticate the server here.
      const ticket = Object.freeze({
        kind: "ssh-remote-session",
        orgId: grant.orgId,
        employeeId: grant.employeeId,
        subjectRole: verdict.role || null,
        // The channel is assumed already paired/authenticated out of band; we do
        // NOT embed long-term secrets in the ticket.
        boundToGrantExpiry: grant.expires,
        note: "server side is operator-run; broker authorizes start only",
      });

      let live;
      if (transport && typeof transport.open === "function") {
        live = transport.open(ticket);
      } else {
        // Honest stand-in: a described-but-not-connected session object.
        live = Object.freeze({ id: "session-" + Math.random().toString(36).slice(2, 10), ticket, connected: false, transport: "none-wired (demo)" });
      }
      session = live;
      audit({ event: "broker.session_open", orgId: grant.orgId, employeeId: grant.employeeId, transport: transport ? "wired" : "demo", at: nowIso(now) });
      return { session: live, gates: { license: "ok", grant: "ok", subToken: "ok", container: "unlocked" } };
    },

    /**
     * Re-check the gates on an OPEN session (call periodically / on heartbeat). If
     * access is no longer valid, tear the session down AND self-wipe. This is how
     * a revocation that lands mid-session ends it — best-effort, at the re-check.
     */
    revalidate(now) {
      const auth = authorize(now);
      if (!auth.allowed) {
        this.closeSession("revalidation failed: " + auth.reason, now);
        return { stillValid: false, reason: auth.reason, selfWiped: !!(auth.selfWiped) };
      }
      return { stillValid: true, reason: null };
    },

    /** Close the session (and lock the container). Does not by itself wipe. */
    closeSession(reason, now) {
      if (session && transport && typeof transport.close === "function") {
        try {
          transport.close(session);
        } catch {
          /* best-effort teardown */
        }
      }
      session = null;
      if (!container.isWiped()) container.lock();
      audit({ event: "broker.session_close", reason: reason || "closed", at: nowIso(now) });
      return true;
    },

    hasSession() {
      return !!session;
    },
  };

  function refusal(gateName, reason, extra) {
    return { allowed: false, gate: gateName, reason, ...(extra || {}) };
  }
}

function licenseReason(gate) {
  if (gate.state === "unverified") return "enterprise license present but not verified offline — access refused (fail-closed)";
  if (gate.state === "expired") return "enterprise license/evaluation has expired — access refused";
  return `enterprise features not allowed under license state '${gate.state}'`;
}

function nowIso(now) {
  return new Date(now || Date.now()).toISOString();
}

export default { createAccessBroker, AccessRefused };
