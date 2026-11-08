// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern Enterprise — integration layer: SHARED IDENTITY FLOW (master -> sub -> apps).
//
// STATUS: design / reference prototype — unaudited, pre-production.
//
// WHAT THIS TIES TOGETHER
// -----------------------
// One org identity hierarchy drives BOTH enterprise apps:
//
//   posternlabs.com (vendor)              provisionOrg()
//        | issue() signs a MASTER
//        v
//   ORG ADMIN CONSOLE                     createEnterpriseConsole()
//        | createLicenseGate (verifyChain)  -> ONE gate the whole suite reads
//        | createSubAccessManager           -> mints ORG-master SUB tokens
//        v
//   ONE SUB IDENTITY per person           mintIdentity()
//        |                                    the SAME signed sub token becomes:
//        |-- comms roster membership  (features sub-access record -> Bloch roster)
//        '-- shield access grant      (grant-binding grant -> container + broker)
//
// Because both apps hang off the SAME sub token and the SAME live grant/record,
// revoking the identity (revokeIdentity) drops the person from the Bloch roster
// AND kills the shield grant — so comms refuses to carry them and shield refuses
// access and self-wipes. That is the end-to-end invariant the harness proves.
//
// FAIL-CLOSED: every gate is the real module's gate; nothing here fakes a pass.

import { randomBytes } from "node:crypto";
import {
  generateKeypair,
  issue,
  createSubAccessManager,
  createCommsOrg,
  createAccessGrant,
  createShieldContainer,
  createAccessBroker,
  createConsiglioBridge,
} from "./siblings.mjs";
import {
  serializeToken,
  resolveConsoleGate,
  makeSubAccessBridge,
  makeConsiglioVerifier,
  makeWalletSigner,
} from "./license-adapter.mjs";

const asDate = (now) => (now == null ? undefined : new Date(now));

/**
 * VENDOR-SIDE provisioning (posternlabs.com). Generates a vendor keypair, issues
 * a corporate-master token against a DUNS number, and returns everything a
 * single-process demo needs. In a real split, the vendor private key never
 * leaves the server and the org keeps only the master token + org master key.
 *
 * @param {object} o
 * @param {string} o.orgName
 * @param {string} o.duns    9-digit DUNS (format-checked by the licensing lib)
 * @param {Date|string|number} [o.now]
 */
export function provisionOrg({ orgName, duns, now } = {}) {
  const vendor = generateKeypair();
  const issued = issue(vendor.privateKey, { tier: "corporate-master", duns, now: asDate(now) });
  const masterExpiresIso = new Date(issued.masterToken.payload.exp * 1000).toISOString();
  return Object.freeze({
    orgName,
    duns,
    // Ships in the apps for offline verification:
    vendorPublicKey: vendor.publicKey,
    // Server secret in production; returned here only so one process can show the
    // whole flow. DO NOT retain org-side in a real deployment.
    vendorPrivateKey: vendor.privateKey,
    // Vendor-signed master token (object) delivered to the org:
    master: issued.masterToken,
    // Org master private key (held by the customer) used to mint subs:
    orgMasterPrivateKey: issued.orgMasterPrivateKey,
    masterExpiresIso,
  });
}

/**
 * Build the ORG ADMIN CONSOLE: the single license gate, the sub-access manager
 * (both verifyChain-wired), and the identity registry that fans one sub token out
 * to comms and shield.
 *
 * @param {ReturnType<typeof provisionOrg>} prov
 * @param {object} [opts]
 * @param {Date|string|number} [opts.now]
 * @param {{seal:Function,open:Function,deriveKey:Function}} [opts.sealEngine] shared shield seal engine
 */
export function createEnterpriseConsole(prov, opts = {}) {
  const now = opts.now;
  const sealEngine = opts.sealEngine || null;

  // ONE gate for the whole suite, decided by the licensing lib's verifyChain.
  const gate = resolveConsoleGate({
    vendorPublicKey: prov.vendorPublicKey,
    master: prov.master,
    orgName: prov.orgName,
    now,
  });

  // Sub-access manager (Bloch roster source) wired to the real signer/verifier.
  const bridge = makeSubAccessBridge({ vendorPublicKey: prov.vendorPublicKey, master: prov.master, now });
  const subAccess = createSubAccessManager({
    master: {
      token: serializeToken(prov.master),
      masterKey: prov.orgMasterPrivateKey,
      orgName: prov.orgName,
      expires: prov.masterExpiresIso,
    },
    mintSub: bridge.mintSub,
    verifyChain: bridge.verifyChain,
    now,
  });

  /** @type {Map<string,{record:object,grant:object,employeeId:string,subToken:string}>} */
  const identities = new Map();

  /**
   * Mint one person's identity: a signed ORG-master sub token that simultaneously
   * (a) becomes their Bloch roster membership (via the sub-access record) and
   * (b) backs their shield access grant (same sub token, live-grant-bound key).
   *
   * @param {object} req
   * @param {string} req.label       roster/display label (also the sub subject)
   * @param {string} [req.employeeId] Consiglio/shield identity (defaults to label)
   * @param {Uint8Array} [req.grantSecret] container key material (>=16 bytes)
   */
  function mintIdentity(req) {
    const label = req && req.label;
    if (!label) throw new Error("mintIdentity: a label is required");
    const employeeId = (req && req.employeeId) || label;

    // One signed sub token (the sub subject is the label, per the licensing lib).
    const record = subAccess.mintSubAccess({ label });

    const grantSecret = req && req.grantSecret instanceof Uint8Array
      ? req.grantSecret
      : new Uint8Array(randomBytes(32));

    const grant = createAccessGrant({
      orgId: prov.duns,
      employeeId,
      subToken: record.token, // SAME sub token backs the shield grant
      expires: prov.masterExpiresIso,
      grantSecret,
      now,
    });

    const idn = { record, grant, employeeId, subToken: record.token };
    identities.set(record.id, idn);
    return Object.freeze({ id: record.id, label, employeeId, subToken: record.token, grant });
  }

  /**
   * Build the SHIELD stack (container + access broker) for one minted identity.
   * The broker reads the SAME console gate (license) and the identity's live grant
   * (consent), and its sub-token challenge is verified by the licensing chain.
   *
   * @param {string} id identity id from mintIdentity
   * @param {object} [o]
   * @param {object} [o.sealEngine] override the shared seal engine
   * @param {object} [o.transport]  injected SSH/remote transport
   * @param {Function} [o.audit]
   */
  function shieldFor(id, o = {}) {
    const idn = identities.get(id);
    if (!idn) throw new Error("shieldFor: unknown identity " + id);
    const container = createShieldContainer({
      grant: idn.grant,
      sealEngine: o.sealEngine || sealEngine || undefined,
      audit: o.audit,
    });
    const consiglio = createConsiglioBridge(
      makeConsiglioVerifier({ vendorPublicKey: prov.vendorPublicKey, master: prov.master, now }),
    );
    const walletSigner = makeWalletSigner({ orgId: prov.duns, employeeId: idn.employeeId });
    const broker = createAccessBroker({
      licenseGate: gate,
      grant: idn.grant,
      container,
      consiglio,
      walletSigner,
      transport: o.transport,
      audit: o.audit,
    });
    return { grant: idn.grant, container, broker, consiglio };
  }

  /**
   * De-provision an identity across the WHOLE suite: revoke the Bloch roster
   * record (drops them from comms) AND revoke the shield grant (kills the
   * container key + triggers self-wipe at the next boundary). Idempotent-ish.
   *
   * @param {string} id
   * @param {string} [reason]
   */
  function revokeIdentity(id, reason) {
    const idn = identities.get(id);
    if (!idn) throw new Error("revokeIdentity: unknown identity " + id);
    subAccess.revoke(idn.record.id); // comms: pulls roster membership
    idn.grant.revoke(reason || "de-provisioned"); // shield: grant no longer live
    return true;
  }

  /**
   * Open the Bloch messenger for this org. Fail-closed: createCommsOrg throws
   * CommsRefused unless the console gate permits enterprise features. The roster
   * is derived live from active sub-access records.
   *
   * @param {string} [selfLabel] the admin/master-holder label in the messenger
   */
  function openComms(selfLabel) {
    return createCommsOrg({ gate, subAccess, selfLabel, now });
  }

  return {
    prov,
    gate,
    subAccess,
    identities,
    mintIdentity,
    shieldFor,
    revokeIdentity,
    openComms,
  };
}
