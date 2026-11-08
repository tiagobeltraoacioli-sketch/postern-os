// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern CLOUD — Consiglio SEAT/DEVICE HOST over sub-access (reference proto).
//
// STATUS: reference prototype. UNAUDITED. Pre-production. NO SECURITY CLAIMS.
//
// WHAT THIS IS
// ------------
// Hosts `enterprise/features/sub-access.mjs` as the console's seat/device
// registry and connects it to the two fail-closed verbs:
//
//   grantAccess(device)  ── mintSubAccess({label, expires?}) ─▶ sub token (a seat)
//                           counts against the (unlimited) corporate master
//   revokeAccess(device) ── revoke(id) ─▶ crlSerial (jti) ─▶ DEPROVISION signal
//
// The lifecycle the integration doc calls out (§6):
//   enroll a device -> mint a sub -> count against the unlimited master ->
//   CRL-revoke ⇒ deprovision.
// sub-access owns the seat invariants (sub.exp <= master.exp, seat cap, jti);
// this host owns the WIRING: durable persistence (onChange -> store), the real
// signer injection (licensing lib, or the honest demo stand-in), and emitting
// the CRL serial + a deprovision signal on revoke. It rolls NO crypto.
//
// "revoke ⇒ deprovision" here EMITS the join key (`jti`) the CRL revokes by and
// fires an injected `onDeprovision(jti)` hook — the ACTUAL node teardown lives
// in the control-plane license-binding loop (`reverify()` deprovisions nodes
// whose master no longer verifies). This host is the console-side trigger, not
// that loop. Honest by construction.

import { createSubAccessManager } from "../../../../features/sub-access.mjs";

/**
 * Build the seat/device host.
 * @param {object} opts
 * @param {object} opts.master     verified master { token, masterKey, expires, seats }.
 * @param {object} opts.store      durable store (loadSubs/saveSubs).
 * @param {object} [opts.audit]    audit trail (append) — every grant/revoke logged.
 * @param {object} [opts.signer]   real {mintSub, verifyChain} from licensing-signer,
 *                                  or null to use the honest UNSIGNED demo stand-in.
 * @param {(jti:string, meta:object)=>void|Promise<void>} [opts.onDeprovision]
 *        fired on revoke with the CRL serial — the console-side deprovision trigger.
 * @param {Array<object>} [opts.records]  hydrate from a durable snapshot.
 * @param {Date|string|number} [opts.now]
 */
export function createSubAccessHost(opts = {}) {
  const { master, store, audit } = opts;
  const signer = opts.signer || null;
  const onDeprovision = typeof opts.onDeprovision === "function" ? opts.onDeprovision : null;

  const manager = createSubAccessManager({
    master,
    mintSub: signer ? signer.mintSub : undefined,
    verifyChain: signer ? signer.verifyChain : undefined,
    records: opts.records || [],
    now: opts.now,
    // Durable persistence of the registry on every mutation.
    onChange: (records) => {
      if (store) Promise.resolve(store.saveSubs(records)).catch(() => {});
    },
  });

  return {
    manager,
    signerWired: manager.signerWired,
    verifierWired: manager.verifierWired,
    seatLimit: manager.seatLimit,
    masterExpires: manager.masterExpires,

    /** grantAccess(device): enroll a device by minting a seat-consuming sub. */
    async grantDevice({ label, expires } = {}, actor) {
      const rec = manager.mintSubAccess({ label, expires });
      const token = manager.exportToken(rec.id);
      if (audit) {
        await audit.append("grant.device", `mint sub ${rec.id} '${rec.label}'`, {
          actor: actor ? `${actor.orgId}/${actor.userId}` : null,
          subId: rec.id,
          jti: rec.jti,
          signed: rec.signed,
          expires: rec.expires,
          activeSeats: manager.activeSeats(),
          seatLimit: manager.seatLimit,
        });
      }
      return { sub: rec, token };
    },

    /**
     * revokeAccess(device): revoke a sub, surface its CRL serial (jti), and fire
     * the deprovision signal (revoke ⇒ deprovision). Belt-and-suspenders: revoke
     * also pulls the sub's local expiry back to now for never-online installs.
     */
    async revokeDevice(id, actor) {
      const rec = manager.revoke(id);
      const crlSerial = rec.crlSerial || null;
      if (audit) {
        await audit.append("revoke.device", `revoke sub ${id}`, {
          actor: actor ? `${actor.orgId}/${actor.userId}` : null,
          subId: id,
          crlSerial,
          activeSeats: manager.activeSeats(),
        });
      }
      // revoke ⇒ deprovision: emit the join key the CRL revokes by.
      if (onDeprovision && crlSerial) {
        await onDeprovision(crlSerial, { subId: id });
      }
      return { record: rec, crlSerial };
    },

    /** Live console surface for the seat meter + CRL feed. */
    status() {
      return {
        seatLimit: manager.seatLimit,
        activeSeats: manager.activeSeats(),
        masterExpires: manager.masterExpires,
        signerWired: manager.signerWired,
        verifierWired: manager.verifierWired,
        revokedSerials: manager.revokedSerials(),
        subs: manager.list(),
      };
    },
  };
}

export default { createSubAccessHost };
