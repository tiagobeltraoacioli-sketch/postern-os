// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Postern license RENEWAL + KYC endpoint (D5.3) — where fiat billing attaches.
//
// DEPLOY TARGET: bp-wt-site/functions/license/renew.js  (Cloudflare Pages Fn)
// Staged in the licensing package (owned path) because the implementing agent is
// isolated to the bloch-protocol worktree and cannot write into bp-wt-site. Copy
// verbatim. Self-contained (no imports), like the other license functions.
//
// POST /license/renew  → the 6-month renewal. Given the org's current master
//   token, it: (a) verifies that token offline, (b) runs the KYC step — a real
//   Dun & Bradstreet lookup of the contracting company plus a re-attestation,
//   (c) on PASS re-mints the master with a FRESH exp + a NEW jti but the SAME
//   master_pub (so the org's existing sub tokens keep working), records the fiat
//   billing onboarding intent, and returns the new master token; (d) on FAIL or
//   explicit non-renewal, adds the old master_pub to the CRL revoked set and lets
//   it expire.
//
// Billing is FIAT only — pricing is still TBD. The coin is NEVER a billing
// instrument and is not a security. This endpoint records billing INTENT; it does
// not charge (no billing implementation exists yet).
//
// KV: env.LICENSES holds "duns:<duns>", "crl:state" (shared with status.js), and
//     "billing:<duns>" (fiat onboarding intent).

const VENDOR_PUB_RAW_B64 = "iW52PuhJm0+JE+g5UhfrArJ7ONfuUjrm0C38NSwQGm0=";
const ISSUER = "posternlabs.com";
const MONTH = 30 * 24 * 3600;
const RENEW_MONTHS = 6;
const CRL_KEY = "crl:state";
const DNB_AUTH_URL = "https://plus.dnb.com/v3/token";
const DNB_DATA_URL = "https://plus.dnb.com/v1/data/duns";

function canonical(obj) {
  if (Array.isArray(obj)) return "[" + obj.map(canonical).join(",") + "]";
  if (obj && typeof obj === "object") {
    return "{" + Object.keys(obj).sort()
      .map((k) => JSON.stringify(k) + ":" + canonical(obj[k])).join(",") + "}";
  }
  return JSON.stringify(obj);
}
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const b64d = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const hex = (buf) => [...new Uint8Array(buf)].map((x) => x.toString(16).padStart(2, "0")).join("");

function json(status, body) {
  return new Response(JSON.stringify(body, null, 2), {
    status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}
function randomSerial() { return hex(crypto.getRandomValues(new Uint8Array(16))); }
async function keyId(rawPubB64) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rawPubB64));
  return hex(d).slice(0, 16);
}

/** Verify a vendor-signed master token offline in the worker. */
async function verifyMasterSig(token, sigB64) {
  try {
    const vpk = await crypto.subtle.importKey("raw", b64d(VENDOR_PUB_RAW_B64), { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "Ed25519" }, vpk, b64d(sigB64), new TextEncoder().encode(canonical(token)));
  } catch { return false; }
}

// --- D&B Direct+ (same contract as master.js verifyDunsWithDnB) ---------------
// F2 fix (Bucket D, docs/bucketD/PARTITION.md §4): AbortController timeout on
// every fetch (env.DNB_TIMEOUT_MS, default 8s) -> fail-open to format-only on
// timeout, same as any other DNB outage. Never confused with "not-found".
const DNB_TIMEOUT_MS_DEFAULT = 8000;
async function verifyDunsWithDnB(duns, env, fetchImpl = fetch) {
  const clientId = env && env.DNB_CLIENT_ID, clientSecret = env && env.DNB_CLIENT_SECRET, staticBearer = env && env.DNB_BEARER;
  if (!staticBearer && !(clientId && clientSecret)) return { status: "unavailable", reason: "dnb-not-configured" };
  const timeoutMs = Number(env && env.DNB_TIMEOUT_MS) > 0 ? Number(env.DNB_TIMEOUT_MS) : DNB_TIMEOUT_MS_DEFAULT;
  try {
    let bearer = staticBearer;
    if (!bearer) {
      const ac = new AbortController();
      const timer = setTimeout(() => ac.abort(), timeoutMs);
      let tokRes;
      try {
        tokRes = await fetchImpl(DNB_AUTH_URL, {
          method: "POST",
          headers: { authorization: "Basic " + btoa(`${clientId}:${clientSecret}`), "content-type": "application/x-www-form-urlencoded" },
          body: "grant_type=client_credentials",
          signal: ac.signal,
        });
      } finally { clearTimeout(timer); }
      if (!tokRes.ok) return { status: "unavailable", reason: `dnb-auth-http-${tokRes.status}` };
      const tj = await tokRes.json();
      bearer = tj && (tj.access_token || tj.accessToken);
      if (!bearer) return { status: "unavailable", reason: "dnb-auth-no-token" };
    }
    const ac2 = new AbortController();
    const timer2 = setTimeout(() => ac2.abort(), timeoutMs);
    let res;
    try {
      res = await fetchImpl(`${DNB_DATA_URL}/${encodeURIComponent(duns)}?blockIDs=companyinfo_L1_v1`, { headers: { authorization: "Bearer " + bearer }, signal: ac2.signal });
    } finally { clearTimeout(timer2); }
    if (res.status === 404) return { status: "not-found", reason: "dnb-duns-not-found" };
    if (!res.ok) return { status: "unavailable", reason: `dnb-data-http-${res.status}` };
    const data = await res.json();
    const org = data && data.organization;
    if (!org || !org.primaryName) return { status: "not-found", reason: "dnb-no-organization" };
    return {
      status: "verified",
      legalName: String(org.primaryName),
      country: org.primaryAddress && org.primaryAddress.addressCountry ? String(org.primaryAddress.addressCountry.isoAlpha2Code || "") : "",
    };
  } catch (e) {
    if (e && (e.name === "AbortError" || /abort/i.test(String(e.message || "")))) return { status: "unavailable", reason: "dnb-timeout" };
    return { status: "unavailable", reason: "dnb-network-error" };
  }
}
function dnbDecisionFrom(result, now) {
  if (result.status === "verified") {
    return { verified: true, source: "dnb-direct-plus", ...(result.legalName ? { legalName: result.legalName } : {}), ...(result.country ? { country: result.country } : {}), checkedAt: now };
  }
  return { verified: false, source: "format-only", checkedAt: now, fallbackReason: result.reason || "dnb-unavailable" };
}

// --- Gramota KYC — ADDITIVE, canonical-safe person->entity verdict (design §4) --
// Same contract as master.js: bind the AUTHORITATIVE verdict from KV kyc:<ref> by
// reference (client cannot inflate its LoA); parity self-declared LoA-0 otherwise.
// Renewal RE-RUNS the verdict, so a provisional token cannot silently ride to full
// term. PII-free by construction — on-device OCR never sends documents here.
const ALLOWED_KYC_FIELDS = new Set(["legalName", "country", "officer"]);
function selfDeclaredKyc(dnb, now) {
  const methods = ["self-declared"];
  if (dnb && dnb.verified) methods.push("dnb-entity");
  return { loa: 0, methods, self_declared: true, idvRef: null, verifiedAt: now };
}
function boundKycFrom(stored, dnb, now) {
  if (!stored || typeof stored !== "object") return selfDeclaredKyc(dnb, now);
  const methods = Array.isArray(stored.methods) ? stored.methods.filter((m) => typeof m === "string").slice(0, 12) : ["self-declared"];
  const kyc = {
    loa: Number.isInteger(stored.loa) ? Math.max(0, Math.min(3, stored.loa)) : 0,
    methods, self_declared: true,
    idvRef: typeof stored.idvRef === "string" && stored.idvRef ? stored.idvRef.slice(0, 128) : null,
    verifiedAt: Number(stored.verifiedAt) || now,
  };
  if (stored.ocr && typeof stored.ocr === "object") {
    kyc.ocr = {
      onDevice: stored.ocr.onDevice === true, match: stored.ocr.match === true,
      fieldsMatched: Array.isArray(stored.ocr.fieldsMatched) ? stored.ocr.fieldsMatched.filter((f) => ALLOWED_KYC_FIELDS.has(f)) : [],
      liveness: stored.ocr.liveness === true,
    };
  }
  if (stored.principalMatch === true || stored.principalMatch === false) kyc.principalMatch = stored.principalMatch;
  if (typeof stored.domain === "string" && /^[a-z0-9.-]{1,253}$/i.test(stored.domain)) {
    kyc.domain = stored.domain.toLowerCase();
    kyc.domainProofAt = Number(stored.domainProofAt) || now;
  }
  return kyc;
}
async function resolveKyc(body, duns, env, dnb, now) {
  const ref = body && typeof body.kyc_ref === "string" ? body.kyc_ref.replace(/[^a-f0-9]/gi, "").slice(0, 64) : "";
  if (ref && env && env.LICENSES) {
    try {
      const raw = await env.LICENSES.get("kyc:" + ref);
      if (raw) {
        const stored = JSON.parse(raw);
        if (stored && String(stored.duns || "").replace(/\D/g, "") === String(duns || "").replace(/\D/g, "")) {
          return boundKycFrom(stored, dnb, now);
        }
      }
    } catch { /* fall through to self-declared parity */ }
  }
  return selfDeclaredKyc(dnb, now);
}

/** Add an org master_pub to the shared CRL revoked set + bump version. */
async function revokeMasterPub(env, masterPub, reason) {
  if (!env.LICENSES) return { version: null };
  let state = { version: 0, revoked_jti: [], revoked_master_pub: [] };
  const raw = await env.LICENSES.get(CRL_KEY);
  if (raw) { try { const s = JSON.parse(raw); state = { version: Number(s.version) || 0, revoked_jti: s.revoked_jti || [], revoked_master_pub: s.revoked_master_pub || [] }; } catch { /* reset */ } }
  if (!state.revoked_master_pub.includes(masterPub)) { state.revoked_master_pub.push(masterPub); state.version += 1; }
  await env.LICENSES.put(CRL_KEY, JSON.stringify({ ...state, reason: String(reason || "non-renewal").slice(0, 200), updatedAt: new Date().toISOString() }));
  return { version: state.version };
}

export async function onRequestPost(context) {
  const { request, env } = context;
  let body;
  try { body = await request.json(); } catch { return json(400, { error: "invalid JSON body" }); }

  const token = body.master_token;
  const sig = body.master_sig;
  if (!token || typeof token !== "object" || typeof sig !== "string") {
    return json(400, { error: "provide { master_token, master_sig } — the current vendor-signed master bundle" });
  }
  if (token.typ !== "master" || token.tier !== "corporate-master") {
    return json(400, { error: "renewal applies to a corporate-master token only" });
  }
  if (!(await verifyMasterSig(token, sig))) {
    return json(400, { error: "master token signature did not verify against the vendor key" });
  }
  const duns = String(token.duns || "").replace(/\D/g, "");
  if (!/^\d{9}$/.test(duns)) return json(400, { error: "token carries no valid DUNS" });
  const masterPub = token.master_pub;

  // Explicit non-renewal: revoke the org master key and let the token expire.
  if (body.renew === false) {
    const { version } = await revokeMasterPub(env, masterPub, "explicit non-renewal");
    return json(200, { renewed: false, revoked: true, crl_version: version,
      note: "Org master key added to the CRL. Existing tokens under it will be rejected once installs fetch a fresh CRL; the master also expires on its own clock. Personal apps are unaffected." });
  }

  if (!env.VENDOR_PRIV_PKCS8_B64) return json(503, { error: "license signing key not configured on this deployment" });

  const now = Math.floor(Date.now() / 1000);

  // --- KYC step: re-attestation + real D&B lookup of the contracting company.
  if (body.attestation !== true) {
    return json(400, { error: "renewal requires re-attestation that you remain the owner or an authorized manager of the company that holds this DUNS number" });
  }
  const dnbResult = await verifyDunsWithDnB(duns, env);
  if (dnbResult.status === "not-found") {
    // D&B answered and the DUNS is not a real entity: refuse renewal + revoke.
    const { version } = await revokeMasterPub(env, masterPub, "renewal KYC failed: DUNS did not resolve at D&B");
    return json(422, { renewed: false, revoked: true, crl_version: version,
      error: "renewal KYC failed — this DUNS did not resolve to a real legal entity at Dun & Bradstreet; the master key has been revoked",
      dnb: { verified: false, source: "dnb-direct-plus", reason: dnbResult.reason } });
  }
  const dnb = dnbDecisionFrom(dnbResult, now);
  // Re-run the person->entity verdict at renewal (bind by ref; parity if absent).
  const kyc = await resolveKyc(body, duns, env, dnb, now);

  // --- PASS: re-mint the master, SAME master_pub, fresh exp + new jti. --------
  const kid = await keyId(VENDOR_PUB_RAW_B64);
  const renewed = {
    v: 1,
    typ: "master",
    tier: "corporate-master",
    duns,
    seats: "unlimited",
    iat: now,
    exp: now + RENEW_MONTHS * MONTH,
    master_pub: masterPub, // unchanged — the org's existing subs keep verifying
    attestation: {
      role: token.attestation && token.attestation.role === "owner" ? "owner" : "manager",
      self_declared: true,
      statement: "Renewal re-attestation: requester remains the owner or an authorized manager of the company that holds this DUNS number. KYC performed at renewal.",
      kyc: "performed-at-renewal",
    },
    jti: randomSerial(),
    kid,
    iss: ISSUER,
    dnb,
    ...(kyc ? { kyc } : {}), // NEW (additive): minimal person->entity KYC verdict, PII-free
  };
  const vk = await crypto.subtle.importKey("pkcs8", b64d(env.VENDOR_PRIV_PKCS8_B64), { name: "Ed25519" }, false, ["sign"]);
  const renewedSig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, vk, new TextEncoder().encode(canonical(renewed))));

  // --- Fiat billing onboarding hook (records INTENT; never charges the coin). -
  if (env.LICENSES) {
    context.waitUntil(Promise.all([
      env.LICENSES.put("duns:" + duns, JSON.stringify({
        iat: now, exp: renewed.exp, tier: "corporate-master", jti: renewed.jti,
        role: renewed.attestation.role, self_declared: true, kyc: "performed-at-renewal",
        kyc_verdict: kyc || null, // minimal person->entity verdict (loa/methods/ocr-match; no PII)
        dnb, master_pub: masterPub, renewedAt: new Date().toISOString(),
      })),
      env.LICENSES.put("billing:" + duns, JSON.stringify({
        currency: "fiat", instrument: "invoice-or-card", coin: "never",
        status: "onboarding", pricing: "TBD", note: "Fiat billing attaches at renewal. The coin is never billed and is not a security.",
        onboardedAt: new Date().toISOString(),
      })),
    ]));
  }

  return json(200, {
    renewed: true,
    master_token: renewed,
    master_sig: b64(renewedSig),
    vendor_pub_raw: VENDOR_PUB_RAW_B64,
    kyc: dnb.verified ? "passed (D&B verified)" : "passed (re-attested; D&B unavailable — flagged for manual review)",
    billing: { currency: "fiat", pricing: "TBD", coin: "never billed; not a security" },
    note: "Master re-minted with a fresh 6-month window, a new serial (jti), and the SAME master_pub — your existing sub-accesses keep working. Fiat billing onboarding recorded (no charge; pricing TBD). Verification stays fully offline.",
  });
}

export async function onRequestGet() {
  return json(200, {
    endpoint: "/license/renew",
    method: "POST",
    body: { master_token: "<the current master token object>", master_sig: "<base64 sig>", attestation: true, renew: "true (default) | false to decline and revoke" },
    kyc: "A real Dun & Bradstreet lookup of the contracting company runs at renewal; a DUNS that does not resolve is refused and the master key is revoked.",
    billing: "Fiat only (invoice/card); pricing TBD. The coin is never billed and is not a security.",
    note: "Reference prototype — UNAUDITED, pre-production. Not legal advice.",
  });
}
