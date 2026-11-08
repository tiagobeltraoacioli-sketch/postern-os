// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern CLOUD — REAL licensing signer adapter for sub-access (reference proto).
//
// STATUS: reference prototype. UNAUDITED. Pre-production.
//
// WHAT THIS IS
// ------------
// sub-access.mjs deliberately implements NO crypto: it plugs into injected
// `mintSub()` / `verifyChain()` and, absent a real signer, emits an HONESTLY
// LABELLED unsigned demo token. This adapter is the seam that injects the REAL
// signer — the licensing library (`@postern/licensing`, canonical Ed25519 JSON,
// vendor -> master -> sub chain, which OWNS the crypto). It rolls NO crypto of
// its own; it only translates between the licensing lib's shape and the shape
// sub-access expects.
//
// It loads the licensing lib LAZILY and returns `null` when it is not built /
// not resolvable — so the console still boots (with the honest demo stand-in)
// and the status endpoint reports `signerWired:false` rather than pretending.

/**
 * Try to build a real {mintSub, verifyChain} pair for sub-access from the
 * licensing library. Returns null (honest) if the lib or the required master
 * key material is unavailable.
 *
 * @param {object} cfg
 * @param {string} [cfg.moduleSpecifier]   default "@postern/licensing".
 * @param {string} cfg.masterPublicKey     org master PUBLIC key (base64 raw).
 * @param {string} cfg.vendorPublicKey     vendor PUBLIC key (base64 raw).
 * @param {object} cfg.masterTokenObj      the parsed master token { payload, sig }.
 * @returns {Promise<{mintSub:Function, verifyChain:Function, label:string}|null>}
 */
export async function loadLicensingSigner(cfg = {}) {
  const spec = cfg.moduleSpecifier || "@postern/licensing";
  if (!cfg.masterPublicKey || !cfg.vendorPublicKey || !cfg.masterTokenObj) {
    return null; // not enough material to wire the real chain — stay honest
  }
  let lib;
  try {
    lib = await import(spec);
  } catch {
    return null; // licensing lib not built/resolvable — caller uses demo stand-in
  }
  const realMint = lib.mintSub || (lib.default && lib.default.mintSub);
  const realVerify = lib.verifyChain || (lib.default && lib.default.verifyChain);
  if (typeof realMint !== "function" || typeof realVerify !== "function") return null;

  const toUnix = (expires) => Math.floor(new Date(expires).getTime() / 1000);

  return {
    label: `REAL licensing signer (${spec}, canonical Ed25519 vendor->master->sub)`,

    // sub-access calls: mintSub(masterKey, { masterToken, label, expires, jti }) -> string
    mintSub(masterKey, claims) {
      const subToken = realMint(masterKey, {
        masterPublicKey: cfg.masterPublicKey,
        sub: claims.label,
        exp: toUnix(claims.expires),
        jti: claims.jti,
      });
      // sub-access stores the token as an opaque STRING; serialize the signed obj.
      return JSON.stringify(subToken);
    },

    // sub-access calls: verifyChain(subToken) -> { valid, label?, expires?, chain? }
    verifyChain(subToken) {
      let sub;
      try {
        sub = typeof subToken === "string" ? JSON.parse(subToken) : subToken;
      } catch {
        return { valid: false };
      }
      const res = realVerify(cfg.vendorPublicKey, cfg.masterTokenObj, sub);
      if (!res || res.ok !== true) return { valid: false };
      return {
        valid: true,
        label: res.sub,
        expires: res.exp ? new Date(res.exp * 1000).toISOString() : undefined,
        chain: ["vendor", "master", "sub"],
      };
    },
  };
}

export default { loadLicensingSigner };
