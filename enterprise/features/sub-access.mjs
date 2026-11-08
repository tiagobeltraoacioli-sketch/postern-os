// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern Business/Enterprise edition — sub-access delegation (reference prototype).
//
// STATUS: design / reference prototype, unaudited, pre-production.
//
// THE MODEL
// ---------
// A corporate org gets, from posternlabs.com, a vendor-signed MASTER token AND
// its master PRIVATE key. In the console the admin mints SUB tokens, signed by
// the org's master key, for individual users/teams — UNLIMITED subs under a
// master, each with `sub.exp <= master.exp`. A sub-user installs their sub token
// and the app verifies the OFFLINE chain vendor -> master -> sub against bundled
// public keys. No server, no per-user account, no telemetry.
//
// NO HARDCODED CRYPTO
// -------------------
// The signing/format is owned by the licensing lib (canonical Ed25519 JSON,
// vendor->master->sub chain). This module does NOT implement crypto and does NOT
// import that lib. It plugs into injected `mintSub()` / `verifyChain()` functions
// and only enforces the business invariants (expiry <= master, revoke, listing).
// If no real signer is injected it produces a clearly-labelled UNSIGNED demo
// token so the console is explorable — never claiming it is verified.

/**
 * The pluggable signer/verifier interface, provided by enterprise/licensing/:
 *
 *   mintSub(masterKey, { masterToken, label, expires }) -> string  // signed sub token
 *   verifyChain(subToken) -> { valid:boolean, label?, expires?, chain?:string[] } | null
 *
 * @typedef {(masterKey:string, claims:{masterToken:string,label:string,expires:string}) => string} SubSigner
 * @typedef {(subToken:string) => ({valid:boolean,label?:string,expires?:string,chain?:string[]}|null)} ChainVerifier
 */

/**
 * @param {object} opts
 * @param {{token:string, masterKey:string, orgName?:string, expires:string|Date, seats?:number|"unlimited"}} opts.master
 *        a VERIFIED corporate master (token + private key), its expiry, and the
 *        seat allowance carried in the token (number for freemium, "unlimited"
 *        for a corporate master). Seat counting enforces a finite cap.
 * @param {SubSigner} [opts.mintSub]        real signer from the licensing lib
 * @param {ChainVerifier} [opts.verifyChain] real offline chain verifier
 * @param {Array<object>} [opts.records]    a DURABLE snapshot to hydrate from
 *        (the registry the console persists in Postgres/KV). Restores seat count
 *        and per-sub serials across restarts.
 * @param {(records:Array<object>)=>void} [opts.onChange]  called after every
 *        mutation with the full record set, so the caller can persist it durably.
 * @param {Date|string|number} [opts.now]
 */
export function createSubAccessManager(opts = {}) {
  const master = opts.master;
  if (!master || !master.token || !master.masterKey) {
    throw new Error("sub-access: a verified master token AND master private key are required");
  }
  const masterExp = new Date(master.expires);
  const now = () => new Date(opts.now || Date.now());
  const mintSub = typeof opts.mintSub === "function" ? opts.mintSub : null;
  const verifyChain = typeof opts.verifyChain === "function" ? opts.verifyChain : null;
  const onChange = typeof opts.onChange === "function" ? opts.onChange : null;

  // Seat allowance from the token. A finite number caps ACTIVE (non-revoked,
  // non-expired) subs; "unlimited" (corporate master) imposes no cap.
  const seatLimit = typeof master.seats === "number" && master.seats >= 0 ? master.seats : Infinity;

  /** @type {Array<{id:string,jti:string,label:string,expires:string,token:string,signed:boolean,revoked:boolean,createdAt:string}>} */
  const subs = Array.isArray(opts.records) ? opts.records.map((r) => ({ ...r })) : [];
  // Continue the id sequence past any hydrated records.
  let seq = subs.reduce((m, s) => Math.max(m, parseInt(String(s.id || "sub-0").slice(4), 10) || 0), 0);

  const persist = () => { if (onChange) { try { onChange(subs.map((s) => ({ ...s }))); } catch { /* persistence is best-effort */ } } };
  const isActive = (s, t) => !s.revoked && new Date(s.expires).getTime() >= t.getTime();

  return {
    signerWired: !!mintSub,
    verifierWired: !!verifyChain,
    masterExpires: masterExp.toISOString().slice(0, 10),
    seatLimit: seatLimit === Infinity ? "unlimited" : seatLimit,

    /** Count of ACTIVE seats consumed right now (non-revoked, non-expired). */
    activeSeats() {
      const t = now();
      return subs.filter((s) => isActive(s, t)).length;
    },

    /** Serials (jti) of every REVOKED sub — feed this into the CRL (D4). */
    revokedSerials() {
      return subs.filter((s) => s.revoked && s.jti).map((s) => s.jti);
    },

    /**
     * Mint a sub-access token. Enforces sub.exp <= master.exp. Unlimited subs.
     * @param {{label:string, expires?:string|Date}} req
     */
    mintSubAccess(req) {
      const label = (req && req.label ? String(req.label) : "").trim();
      if (!label) throw new Error("sub-access: a label is required");
      // Seat cap: a finite allowance may not be exceeded by ACTIVE subs (D4.4).
      if (seatLimit !== Infinity) {
        const active = subs.filter((s) => isActive(s, now())).length;
        if (active >= seatLimit) {
          throw new Error(
            `sub-access: seat cap reached (${active}/${seatLimit}). Revoke an active sub or take a license that lifts the cap.`,
          );
        }
      }
      // Default sub expiry to the master expiry; never allow it to exceed it.
      let exp = req && req.expires ? new Date(req.expires) : new Date(masterExp);
      if (exp.getTime() > masterExp.getTime()) {
        throw new Error(
          `sub-access: sub.exp (${exp.toISOString().slice(0, 10)}) may not exceed master.exp (${masterExp.toISOString().slice(0, 10)})`,
        );
      }
      const expires = exp.toISOString();
      // Per-sub serial (jti) so this sub can be individually put on the CRL (D4).
      // Passed into the injected signer so the token it mints carries the SAME
      // jti the registry tracks — otherwise a CRL could never match the token.
      const jti = randomSerial();
      const claims = { masterToken: master.token, label, expires, jti };
      let token;
      let signed;
      if (mintSub) {
        token = mintSub(master.masterKey, claims);
        signed = true;
      } else {
        // Honest demo stand-in — clearly NOT a signed token.
        token = "SUB-DEMO-UNSIGNED." + btoaSafe(JSON.stringify(claims));
        signed = false;
      }
      const rec = {
        id: "sub-" + ++seq,
        jti,
        label,
        expires: expires.slice(0, 10),
        token,
        signed,
        revoked: false,
        createdAt: now().toISOString(),
      };
      subs.push(rec);
      persist();
      return rec;
    },

    /** All sub records (including revoked/expired), newest first. */
    list() {
      return subs.slice().reverse().map((s) => ({ ...s, status: statusOf(s, now()) }));
    },

    /**
     * Revoke a sub. Pulls the expiry back to now, flags revoked, and returns the
     * record INCLUDING its `jti` so the caller can add it to the signed CRL (D4)
     * — offline installs then enforce the revocation. (Local expiry-pull remains
     * as the belt-and-suspenders for installs that never fetch the CRL.)
     */
    revoke(id) {
      const rec = subs.find((s) => s.id === id);
      if (!rec) throw new Error("sub-access: unknown sub id " + id);
      rec.revoked = true;
      rec.expires = now().toISOString().slice(0, 10);
      persist();
      return { ...rec, status: statusOf(rec, now()), crlSerial: rec.jti || null };
    },

    /** Export a sub token for delivery to the user (out of band). */
    exportToken(id) {
      const rec = subs.find((s) => s.id === id);
      if (!rec) throw new Error("sub-access: unknown sub id " + id);
      return rec.token;
    },

    /**
     * Verify a sub token's OFFLINE chain vendor->master->sub. Returns an honest
     * result: when no real verifier is wired, reports unverified rather than
     * pretending. Also independently checks sub.exp <= master.exp locally.
     */
    verify(subToken) {
      if (!verifyChain) {
        return { valid: false, reason: "no offline chain verifier wired (demo)", chain: [] };
      }
      let res = null;
      try {
        res = verifyChain(subToken);
      } catch {
        res = null;
      }
      if (!res || res.valid !== true) return { valid: false, reason: "chain did not verify", chain: (res && res.chain) || [] };
      const withinMaster = !res.expires || new Date(res.expires).getTime() <= masterExp.getTime();
      return {
        valid: withinMaster,
        reason: withinMaster ? "vendor->master->sub chain verified offline" : "sub outlives master (rejected)",
        label: res.label,
        expires: res.expires,
        chain: res.chain || ["vendor", "master", "sub"],
      };
    },
  };
}

function statusOf(rec, now) {
  if (rec.revoked) return "revoked";
  if (new Date(rec.expires).getTime() < now.getTime()) return "expired";
  return rec.signed ? "active" : "active-demo";
}

// UTF-8-safe base64 that works in Node and browsers without hardcoding crypto.
function btoaSafe(s) {
  if (typeof Buffer !== "undefined") return Buffer.from(s, "utf8").toString("base64");
  return btoa(unescape(encodeURIComponent(s)));
}

// A random 128-bit serial (hex) for a sub's jti (D4). CSPRNG-backed via the
// WebCrypto global present in Node 18+ and browsers — no dependency, no
// hardcoded crypto primitive. Matches the licensing lib's `randomSerial()` shape.
function randomSerial() {
  const b = new Uint8Array(16);
  (globalThis.crypto || {}).getRandomValues(b);
  let s = "";
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, "0");
  return s;
}

export default { createSubAccessManager };
