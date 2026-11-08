// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern Enterprise — integration layer: LICENSE ADAPTERS.
//
// STATUS: design / reference prototype — unaudited, pre-production.
//
// THE MISMATCH THIS BRIDGES
// -------------------------
// The licensing lib (enterprise/licensing) is the ONLY module that owns crypto.
// It speaks in token OBJECTS `{ payload, sig }`, tiers `"corporate-master"` /
// `"business-freemium"`, and a rich `verifyChain(vendorPub, master, sub?)`.
//
// The consumers speak different, simpler shapes:
//   * features/license-hook.createLicenseGate wants a MasterTokenVerifier
//       (masterToken:string) => { valid, orgName?, duns?, seats?, expires? } | null
//   * features/sub-access.createSubAccessManager wants
//       mintSub(masterKey:string, {masterToken:string,label,expires:ISO}) => string
//       verifyChain(subToken:string) => { valid, label?, expires?, chain? } | null
//   * shield/consiglio-bridge.verifyResponse wants a signature verdict
//       (challenge, response) => { ok, employeeId?, role?, reason? }
//
// These adapters are the seam. They contain NO cryptography of their own — every
// authenticity decision is delegated to the licensing lib's `verifyChain`, wired
// once here and reused by the console gate, the comms sub-access manager, and the
// shield access broker's sub-token challenge. FAIL-CLOSED throughout: a bad
// signature, a bad DUNS, a broken/expired chain, or a parse error all collapse to
// a negative verdict. Nothing ever fabricates a "licensed"/"ok" result.

import {
  verifyChain,
  mintSubUnderMaster,
  createLicenseGate,
} from "./siblings.mjs";

/** Wire-form of a signed token is a JSON string of the `{payload,sig}` object. */
export function serializeToken(tok) {
  return typeof tok === "string" ? tok : JSON.stringify(tok);
}
/** Parse a token that may be a JSON string or an already-decoded object. */
export function parseToken(tok) {
  if (tok == null) return null;
  return typeof tok === "string" ? JSON.parse(tok) : tok;
}

const toSec = (iso) => Math.floor(new Date(iso).getTime() / 1000);
const toIso = (sec) => new Date(sec * 1000).toISOString();
const asDate = (now) => (now == null ? undefined : new Date(now));

/**
 * Build the features `MasterTokenVerifier` from the licensing lib's verifyChain.
 * Wraps the OBJECT-level chain check behind the (masterToken:string)->claims
 * interface the license gate expects. Returns `null` (fail-closed => `unverified`
 * gate) on any authenticity failure; otherwise passes the master's window through
 * so the gate itself decides valid-vs-expired from `expires`.
 *
 * @param {object} o
 * @param {string} o.vendorPublicKey base64 vendor public key shipped in the app
 * @param {string|null} [o.orgName]   org display name (licensing carries only DUNS)
 * @param {Date|string|number} [o.now]
 */
export function makeMasterTokenVerifier({ vendorPublicKey, orgName = null, now } = {}) {
  return (masterTokenStr) => {
    let master;
    try {
      master = parseToken(masterTokenStr);
    } catch {
      return null; // unparseable => fail-closed
    }
    const res = verifyChain(vendorPublicKey, master, null, asDate(now));
    if (!res.ok) return null; // bad signature / bad duns / malformed => unverified
    return {
      valid: true, // authentic; the gate turns a past `expires` into `expired`
      orgName: orgName || null,
      duns: res.duns || undefined,
      seats: res.seats,
      expires: toIso(res.exp),
    };
  };
}

/**
 * Build the mintSub/verifyChain pair the features sub-access manager plugs into.
 * `mintSub` signs a real ORG-master sub token (via the licensing lib) and returns
 * it in wire (string) form; `verifyChain` runs the full offline vendor->master->
 * sub chain and reports an honest verdict. No crypto here — all delegated.
 *
 * @param {object} o
 * @param {string} o.vendorPublicKey
 * @param {object|string} o.master  the vendor-signed master token
 * @param {Date|string|number} [o.now]
 */
export function makeSubAccessBridge({ vendorPublicKey, master, now } = {}) {
  const masterObj = parseToken(master);
  return {
    /** (masterKey, {masterToken, label, expires:ISO}) -> signed sub token (string) */
    mintSub(masterKey, claims) {
      const sub = mintSubUnderMaster(
        masterKey,
        masterObj,
        claims.label,
        toSec(claims.expires),
        asDate(now) || new Date(),
      );
      return serializeToken(sub);
    },
    /** (subToken:string) -> honest chain verdict for the manager */
    verifyChain(subTokenStr) {
      let sub;
      try {
        sub = parseToken(subTokenStr);
      } catch {
        return null;
      }
      const res = verifyChain(vendorPublicKey, masterObj, sub, asDate(now));
      if (!res.ok) return null; // fail-closed
      return {
        valid: !res.expired, // authentic-but-expired is not currently valid
        label: res.sub,
        expires: toIso(res.exp),
        chain: ["vendor", "master", "sub"],
      };
    },
  };
}

/**
 * Resolve the ORG ADMIN CONSOLE license gate: createLicenseGate driven by the
 * verifyChain-backed MasterTokenVerifier. This same gate object is what the comms
 * app and the shield access broker both read (`enterpriseFeaturesAllowed`), so a
 * single offline verification decides the whole suite.
 *
 * @param {object} o
 * @param {string} o.vendorPublicKey
 * @param {object|string} o.master
 * @param {string|null} [o.orgName]
 * @param {Date|string|number} [o.now]
 * @param {Date|string|number} [o.installDate]
 */
export function resolveConsoleGate({ vendorPublicKey, master, orgName = null, now, installDate } = {}) {
  const verify = makeMasterTokenVerifier({ vendorPublicKey, orgName, now });
  return createLicenseGate({
    masterToken: serializeToken(master),
    verify,
    now,
    installDate,
  });
}

/**
 * Wire verifyChain into the SHIELD sub-token gate. The shield access broker asks
 * the Consiglio bridge to verify a wallet response; here the "signature" the
 * bridge checks IS the offline vendor->master->sub chain of the sub token the
 * grant carries, plus a subject-identity match. Returns an injectable
 * `verifyResponse` (and passes local nonce/identity sanity to the bridge).
 *
 * @param {object} o
 * @param {string} o.vendorPublicKey
 * @param {object|string} o.master
 * @param {Date|string|number} [o.now]
 */
export function makeConsiglioVerifier({ vendorPublicKey, master, now } = {}) {
  const masterObj = parseToken(master);
  return {
    verifyResponse(challenge, response) {
      let sub = null;
      try {
        sub = response && response.subToken ? parseToken(response.subToken) : null;
      } catch {
        sub = null;
      }
      if (!sub) return { ok: false, reason: "no sub-token presented in wallet response" };
      const res = verifyChain(vendorPublicKey, masterObj, sub, asDate(now));
      if (!res.ok) return { ok: false, reason: `sub chain did not verify: ${res.reason}` };
      if (res.expired) return { ok: false, reason: "sub/master chain expired" };
      if (res.sub !== (challenge && challenge.employeeId)) {
        return { ok: false, reason: "sub-token subject does not match the challenged employee" };
      }
      return { ok: true, employeeId: res.sub, role: "member" };
    },
  };
}

/**
 * A minimal wallet signer for the Consiglio challenge/response. In production the
 * wallet holds a hybrid Falcon-1024 ‖ ML-DSA-65 key and signs the transcript; in
 * this reference the sub-token IS the credential and the verifier above checks it
 * against the offline chain. The signer only echoes the challenge and presents
 * the grant's sub-token.
 *
 * @param {object} o
 * @param {string} o.orgId
 * @param {string} o.employeeId
 */
export function makeWalletSigner({ orgId, employeeId } = {}) {
  return {
    sign(challenge, subToken) {
      return {
        orgId,
        employeeId,
        nonce: challenge && challenge.nonce,
        subToken, // supplied by grant.subTokenForBroker()
        publicKey: "wallet-pub(reference)",
        signature: "chain-is-the-credential(reference)",
      };
    },
  };
}
