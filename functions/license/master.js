// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Postern Business/Corporate — master license generator.
//
// DEPLOY TARGET: bp-wt-site/functions/license/master.js  (Cloudflare Pages Fn)
// This file is staged here (in the licensing package, an owned path) because the
// implementing agent is isolated to the bloch-protocol worktree and cannot write
// into the separate bp-wt-site repo. Copy it verbatim to the deploy target. It is
// self-contained (no imports) exactly like the shipped function, so a copy is
// drop-in. The core helpers are also unit-tested by ../../site-functions.test.mjs.
//
// GET  /license/master  → a self-contained HTML form (its own CSP; no tracking).
// POST /license/master  → issues a vendor-signed, OFFLINE-VERIFIABLE master token.
//
// Model (honest, disclosed on the page):
//   • Personal editions are FREE forever — no license, no login, no tracking.
//   • Business/Corporate master: a company with a DUNS number gets a MASTER token,
//     UNLIMITED users, valid 6 months.
//   • Business freemium: up to 3 desktops for 2 years (no DUNS).
//
// CHANGES (D4 revocation + D5 real D&B):
//   • Every issued token carries a random 128-bit serial `jti` + `kid` + `iss`, so
//     it can be revoked via the signed CRL (see status.js / the licensing lib).
//   • DUNS is verified against Dun & Bradstreet Direct+ when credentials are
//     configured (DNB_CLIENT_ID + DNB_CLIENT_SECRET, or DNB_BEARER). A DUNS that
//     does not resolve to a real legal entity is REFUSED. When D&B is unavailable
//     or unconfigured, issuance falls back to FORMAT-ONLY, flagged for manual
//     review at renewal — never a hard failure on an outage. The decision is
//     bound into the token's `dnb` field so it cannot be silently over-claimed.

const VENDOR_PUB_RAW_B64 = "iW52PuhJm0+JE+g5UhfrArJ7ONfuUjrm0C38NSwQGm0=";
const ISSUER = "posternlabs.com";
const MONTH = 30 * 24 * 3600; // 30-day months (documented approximation)
// D&B Direct+ endpoints (production). Auth is OAuth2 client-credentials.
const DNB_AUTH_URL = "https://plus.dnb.com/v3/token";
const DNB_DATA_URL = "https://plus.dnb.com/v1/data/duns"; // /{DUNS}?blockIDs=companyinfo_L1_v1

// Stable, sorted-key, compact JSON — the license lib + console must match this
// byte-for-byte so the offline signature verifies. UNCHANGED from the original:
// adding optional token fields (jti/kid/iss/dnb) does not change this algorithm,
// so tokens issued before the change still verify.
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

/** Random 128-bit serial (hex) for a token jti (D4). */
function randomSerial() {
  return hex(crypto.getRandomValues(new Uint8Array(16)));
}

/** Short, deterministic key id for the vendor public key (D4). */
async function keyId(rawPubB64) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rawPubB64));
  return hex(d).slice(0, 16);
}

function json(status, body) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}

// ---------------------------------------------------------------------------
// Rate limit the D&B-driving path (hardening, pairs with functions/license/
// review.js's kycGate 429-handling).
//
// WHY: verifyDunsWithDnB below calls Dun & Bradstreet on every corporate-master
// request. An attacker who hammers THIS endpoint can exhaust Postern's own D&B
// Direct+ quota faster than genuine traffic would — and once D&B starts
// answering 429, review.js's kycGate has to fall back to a degraded state
// rather than the normal verified path. Throttling the request rate that can
// ever reach D&B through this endpoint bounds how cheaply an attacker can
// induce that condition in the first place.
//
// GLOBAL (not per-IP) fixed-window counter in the existing LICENSES KV — no
// new per-visitor identifier is stored, consistent with this site's
// no-telemetry posture (see functions/dl/[[path]].js's aggregate-only download
// counter for the same pattern). A shared cap naturally bounds how fast
// ANYONE — including an attacker — can drive D&B calls through this path.
// Best-effort: a KV hiccup fails OPEN (never a hard outage over a rate-limit
// bookkeeping problem), matching this file's existing "an outage is never a
// hard failure" posture for its optional infra.
const MASTER_RATE_LIMIT_WINDOW_S = 60;
const MASTER_RATE_LIMIT_DEFAULT = 20; // requests / window; tune via env.MASTER_RATE_LIMIT_PER_MIN

async function rateLimitMasterDnbLookups(env, now) {
  if (!env || !env.LICENSES) return { limited: false }; // no KV bound: no limiter, same as today
  const limit = Number(env.MASTER_RATE_LIMIT_PER_MIN) > 0 ? Number(env.MASTER_RATE_LIMIT_PER_MIN) : MASTER_RATE_LIMIT_DEFAULT;
  const bucket = Math.floor(now / MASTER_RATE_LIMIT_WINDOW_S);
  const key = `ratelimit:master:${bucket}`;
  try {
    const cur = Number(await env.LICENSES.get(key)) || 0;
    if (cur >= limit) return { limited: true, retryAfter: MASTER_RATE_LIMIT_WINDOW_S };
    await env.LICENSES.put(key, String(cur + 1), { expirationTtl: MASTER_RATE_LIMIT_WINDOW_S * 2 });
    return { limited: false };
  } catch {
    return { limited: false }; // best-effort: a KV hiccup must not become a hard outage
  }
}

/**
 * Verify a DUNS against Dun & Bradstreet Direct+ (D5).
 * @returns {Promise<{status:"verified"|"not-found"|"unavailable", legalName?:string, country?:string, reason?:string}>}
 *   - "verified"    → the DUNS resolves to a real legal entity (gate: proceed).
 *   - "not-found"   → D&B answered but the DUNS is not a real entity (gate: refuse).
 *   - "unavailable" → D&B not configured / auth/5xx/network/timeout error (gate: fallback).
 */
// F2 fix (Bucket D, docs/bucketD/PARTITION.md §4): every DNB fetch is now bounded
// by an AbortController timeout (env.DNB_TIMEOUT_MS, default 8s) so a slow/hanging
// D&B response cannot block the request indefinitely on this code's own terms.
// A timeout maps to the SAME fail-open-to-format-only outcome as any other outage.
const DNB_TIMEOUT_MS_DEFAULT = 8000;

export async function verifyDunsWithDnB(duns, env, fetchImpl = fetch) {
  const clientId = env && env.DNB_CLIENT_ID;
  const clientSecret = env && env.DNB_CLIENT_SECRET;
  const staticBearer = env && env.DNB_BEARER;
  if (!staticBearer && !(clientId && clientSecret)) {
    return { status: "unavailable", reason: "dnb-not-configured" };
  }
  const timeoutMs = Number(env && env.DNB_TIMEOUT_MS) > 0 ? Number(env.DNB_TIMEOUT_MS) : DNB_TIMEOUT_MS_DEFAULT;
  try {
    let bearer = staticBearer;
    if (!bearer) {
      const auth = "Basic " + btoa(`${clientId}:${clientSecret}`);
      const ac = new AbortController();
      const timer = setTimeout(() => ac.abort(), timeoutMs);
      let tokRes;
      try {
        tokRes = await fetchImpl(DNB_AUTH_URL, {
          method: "POST",
          headers: { authorization: auth, "content-type": "application/x-www-form-urlencoded" },
          body: "grant_type=client_credentials",
          signal: ac.signal,
        });
      } finally {
        clearTimeout(timer);
      }
      if (!tokRes.ok) return { status: "unavailable", reason: `dnb-auth-http-${tokRes.status}` };
      const tokJson = await tokRes.json();
      bearer = tokJson && (tokJson.access_token || tokJson.accessToken);
      if (!bearer) return { status: "unavailable", reason: "dnb-auth-no-token" };
    }
    const url = `${DNB_DATA_URL}/${encodeURIComponent(duns)}?blockIDs=companyinfo_L1_v1`;
    const ac2 = new AbortController();
    const timer2 = setTimeout(() => ac2.abort(), timeoutMs);
    let res;
    try {
      res = await fetchImpl(url, { headers: { authorization: "Bearer " + bearer }, signal: ac2.signal });
    } finally {
      clearTimeout(timer2);
    }
    if (res.status === 404) return { status: "not-found", reason: "dnb-duns-not-found" };
    if (!res.ok) return { status: "unavailable", reason: `dnb-data-http-${res.status}` };
    const data = await res.json();
    const org = data && data.organization;
    if (!org || !org.primaryName) return { status: "not-found", reason: "dnb-no-organization" };
    return {
      status: "verified",
      legalName: String(org.primaryName),
      country: org.primaryAddress && org.primaryAddress.addressCountry
        ? String(org.primaryAddress.addressCountry.isoAlpha2Code || "")
        : "",
    };
  } catch (e) {
    if (e && (e.name === "AbortError" || /abort/i.test(String(e.message || "")))) {
      return { status: "unavailable", reason: "dnb-timeout" };
    }
    return { status: "unavailable", reason: "dnb-network-error" };
  }
}

/** Map a D&B result to the token's bound `dnb` decision (never over-claims). */
export function dnbDecisionFrom(result, now) {
  if (result.status === "verified") {
    return {
      verified: true,
      source: "dnb-direct-plus",
      ...(result.legalName ? { legalName: result.legalName } : {}),
      ...(result.country ? { country: result.country } : {}),
      checkedAt: now,
    };
  }
  return {
    verified: false,
    source: "format-only",
    checkedAt: now,
    fallbackReason: result.reason || "dnb-unavailable",
  };
}

// --- Gramota owner/manager KYC — ADDITIVE, canonical-safe token binding --------
// The MINIMAL, PII-free person->entity verdict (design §4). Old tokens simply lack
// the `kyc` key and still verify (canonical() is absent-key-safe). The AUTHORITATIVE
// verdict is computed by /license/review (kycGate) with a fresh D&B re-check and
// stored under KV `kyc:<ref>`; here we bind it BY REFERENCE so a client cannot
// inflate its own LoA. Absent a valid ref we bind today's honest self-declared
// LoA-0 verdict — EXACT parity with prior behavior (no regression). On-device OCR
// (apps/gramota-kyc) means images/raw PII never reached this server by construction.
const ALLOWED_KYC_FIELDS = new Set(["legalName", "country", "officer"]);

/** Self-declared LoA-0 verdict — parity with the pre-KYC behavior. PII-free. */
function selfDeclaredKyc(dnb, now) {
  const methods = ["self-declared"];
  if (dnb && dnb.verified) methods.push("dnb-entity");
  return { loa: 0, methods, self_declared: true, idvRef: null, verifiedAt: now };
}

/** Reduce a stored authoritative verdict to the minimal bound shape (PII-free). */
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
      onDevice: stored.ocr.onDevice === true,
      match: stored.ocr.match === true,
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

/** Resolve the person-side verdict to bind: KV kyc:<ref> (authoritative) or parity. */
export async function resolveKyc(body, env, dnb, now) {
  const ref = body && typeof body.kyc_ref === "string" ? body.kyc_ref.replace(/[^a-f0-9]/gi, "").slice(0, 64) : "";
  if (ref && env && env.LICENSES) {
    try {
      const raw = await env.LICENSES.get("kyc:" + ref);
      if (raw) {
        const stored = JSON.parse(raw);
        // bind only if the verdict was issued for THIS DUNS (anti-swap)
        if (stored && String(stored.duns || "").replace(/\D/g, "") === String((body && body.duns) || "").replace(/\D/g, "")) {
          return boundKycFrom(stored, dnb, now);
        }
      }
    } catch { /* fall through to self-declared parity */ }
  }
  return selfDeclaredKyc(dnb, now);
}

export async function onRequestPost(context) {
  const { request, env } = context;
  let body;
  try { body = await request.json(); } catch { return json(400, { error: "invalid JSON body" }); }

  const tier = body.tier === "business-freemium" ? "business-freemium" : "corporate-master";
  let duns = null, seats, months, attestation = null, dnb = null, kyc = null;
  const now = Math.floor(Date.now() / 1000);

  if (tier === "corporate-master") {
    duns = String(body.duns || "").replace(/\D/g, "");
    if (!/^\d{9}$/.test(duns)) {
      return json(400, { error: "a valid 9-digit DUNS number is required for a corporate master license" });
    }
    const role = body.role === "owner" ? "owner" : body.role === "manager" ? "manager" : null;
    if (!role) {
      return json(400, { error: "declare your role: 'owner' or an authorized 'manager' of the company that holds this DUNS number" });
    }
    if (body.attestation !== true) {
      return json(400, { error: "you must attest that you are the owner or an authorized manager of the company that holds this DUNS number, and that Postern Labs may validate this (KYC) at the 6-month renewal" });
    }

    // Rate-limit BEFORE spending a D&B call (hardening: see rateLimitMasterDnbLookups
    // above for why — this is the path that actually drives D&B lookups).
    const rl = await rateLimitMasterDnbLookups(env, now);
    if (rl.limited) {
      return json(429, {
        error: "too many corporate-master / D&B verification requests right now — please retry shortly",
        retryAfterSeconds: rl.retryAfter,
      });
    }

    // --- D5: real Dun & Bradstreet verification -----------------------------
    const dnbResult = await verifyDunsWithDnB(duns, env);
    if (dnbResult.status === "not-found") {
      // D&B is configured AND answered: this DUNS is not a real entity. Refuse.
      return json(422, {
        error: "this DUNS number did not resolve to a real legal entity at Dun & Bradstreet — issuance refused",
        dnb: { verified: false, source: "dnb-direct-plus", reason: dnbResult.reason },
      });
    }
    dnb = dnbDecisionFrom(dnbResult, now);

    // Bind the minimal person->entity verdict (by reference; parity if absent).
    kyc = await resolveKyc(body, env, dnb, now);

    attestation = {
      role,
      self_declared: true,
      statement: "Requester attests to be the owner or an authorized manager of the company that holds this DUNS number, with authority to accept these terms. Subject to Postern Labs KYC validation of the contracting company at the 6-month renewal; inappropriate use of a DUNS number will not renew.",
      kyc: "at-renewal-6mo",
    };
    seats = "unlimited";
    months = 6;
  } else {
    seats = 3;      // business freemium: up to 3 desktops
    months = 24;    // for 2 years
  }

  if (!env.VENDOR_PRIV_PKCS8_B64) {
    return json(503, { error: "license signing key not configured on this deployment" });
  }

  // Generate THIS org's master keypair (org keeps the private key to mint subs).
  const orgKp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const masterPubRaw = new Uint8Array(await crypto.subtle.exportKey("raw", orgKp.publicKey));
  const masterPrivPkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", orgKp.privateKey));

  const kid = await keyId(VENDOR_PUB_RAW_B64);
  const token = {
    v: 1,
    typ: "master",
    tier,
    duns,
    seats,
    iat: now,
    exp: now + months * MONTH,
    master_pub: b64(masterPubRaw),
    attestation, // corporate: self-declared owner/manager + KYC-at-renewal; null for freemium
    // --- D4/D5 additive fields (absent-key-safe in canonical()) ---
    jti: randomSerial(),
    kid,
    iss: ISSUER,
    ...(dnb ? { dnb } : {}),
    ...(kyc ? { kyc } : {}), // NEW (additive): minimal person->entity KYC verdict, PII-free
  };

  // Vendor-sign the canonical token.
  const vk = await crypto.subtle.importKey("pkcs8", b64d(env.VENDOR_PRIV_PKCS8_B64), { name: "Ed25519" }, false, ["sign"]);
  const msg = new TextEncoder().encode(canonical(token));
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, vk, msg));

  // Privacy-minimal record: DUNS + issue/expiry + role + jti + the D&B decision,
  // to honor + dedupe and to drive the 6-month renewal KYC. No marketing PII.
  if (env.LICENSES && duns) {
    context.waitUntil(env.LICENSES.put(
      "duns:" + duns,
      JSON.stringify({
        iat: now, exp: token.exp, tier, jti: token.jti,
        role: attestation?.role || null, self_declared: true, kyc: "at-renewal-6mo",
        kyc_verdict: kyc || null, // minimal person->entity verdict (loa/methods/ocr-match; no PII)
        dnb: dnb || null, master_pub: token.master_pub,
      }),
      { metadata: {} },
    ));
  }

  const dnbNote = dnb && dnb.verified
    ? `DUNS verified at Dun & Bradstreet (${dnb.legalName || "entity confirmed"}). `
    : "DUNS accepted by FORMAT ONLY (D&B unavailable) — flagged for manual review at renewal. ";

  return json(200, {
    master_token: token,
    master_sig: b64(sig),
    master_private_key_pkcs8: b64(masterPrivPkcs8),
    vendor_pub_raw: VENDOR_PUB_RAW_B64,
    notice: "Business edition — FREE 6-month evaluation (structuring the revenue model; pricing TBD, later billed in fiat, never the coin). " +
      (tier === "corporate-master" ? dnbNote : "") +
      (tier === "corporate-master"
        ? "You attested to being the owner or an authorized manager of the company that holds this DUNS number. At the 6-month renewal, Postern Labs validates this (KYC of the contracting company); a DUNS used inappropriately will not renew. "
        : "") +
      "KEEP master_private_key_pkcs8 SECRET — it mints your sub-accesses; we do not store it. " +
      "This token carries a serial (jti) so it can be revoked via the signed CRL. " +
      "Verification is fully offline. This certifies nothing about security — the software is unaudited, pre-production. Personal editions stay free.",
  });
}

export async function onRequestGet() {
  const nonce = b64(crypto.getRandomValues(new Uint8Array(16)));
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}'; connect-src 'self'; base-uri 'none'; form-action 'none'">
<title>Postern — Business master license</title>
<style nonce="${nonce}">
body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:#0d1014;color:#e9e5da;max-width:44rem;margin:0 auto;padding:2rem 1.25rem;line-height:1.6}
h1{font-size:1.5rem} a{color:#e4c465} label{display:block;margin:1rem 0 .3rem;font-weight:600}
input,select,button{font:inherit;padding:.6rem .7rem;border-radius:6px;border:1px solid #29323e;background:#14181f;color:#e9e5da;width:100%;box-sizing:border-box}
button{background:#c9a648;color:#16130a;font-weight:700;border:none;cursor:pointer;margin-top:1.2rem}
.warn{background:#1d1708;border:1px solid #6b5720;border-left:4px solid #c9a648;padding:1rem 1.2rem;border-radius:8px;font-size:.9rem;margin:1.2rem 0}
pre{white-space:pre-wrap;word-break:break-all;background:#14181f;border:1px solid #29323e;border-radius:8px;padding:1rem;font-size:.8rem;overflow:auto}
.dim{color:#a8adb5;font-size:.86rem}
.check{display:flex;align-items:flex-start;gap:.6rem;margin:1rem 0 .3rem}
.check input{width:auto;margin-top:.35rem;flex:0 0 auto}
.check label{margin:0;font-weight:400}
.corp{border-left:3px solid #6b5720;padding-left:1rem;margin:1.2rem 0}
</style></head><body>
<h1>Postern — Business / Corporate master license</h1>
<div class="warn"><strong>Free 6-month evaluation.</strong> This is the window while we structure the revenue model — <strong>no price on anything today</strong>, and any future charge is in fiat, <strong>never the coin</strong>. The software is <strong>unaudited and pre-production</strong>; this license certifies nothing about security. <strong>Personal editions are free forever</strong> and need no license. <a href="/disclaimer">Full disclaimer</a>.</div>
<form id="f">
<label for="tier">Edition</label>
<select id="tier" name="tier">
<option value="corporate-master">Corporate master — unlimited users, 6 months (requires a DUNS number)</option>
<option value="business-freemium">Business freemium — up to 3 desktops, 2 years (no DUNS)</option>
</select>
<div id="corp" class="corp">
<label for="duns">DUNS number (9 digits)</label>
<input id="duns" name="duns" inputmode="numeric" placeholder="e.g. 150483782" autocomplete="off">
<p class="dim">Verified against Dun&amp;Bradstreet when available (a DUNS that does not resolve is refused); otherwise accepted by format and flagged for review at renewal. We store only your DUNS + issue/expiry + declared role + the D&amp;B decision to honor the license and drive the renewal check — no name beyond the D&amp;B legal entity, no tracking.</p>
<label for="role">Your role at the company that holds this DUNS number</label>
<select id="role" name="role">
<option value="owner">Owner</option>
<option value="manager">Authorized manager</option>
</select>
<div class="check">
<input type="checkbox" id="attestation" name="attestation">
<label for="attestation">I declare that I am the <strong>owner or an authorized manager</strong> of the company that holds this DUNS number, with authority to accept these terms — and I understand that at the <strong>6-month renewal Postern Labs will validate this (KYC of the contracting company)</strong>, so a DUNS number used inappropriately will not renew.</label>
</div>
</div>
<button type="submit">Generate master license</button>
</form>
<div id="out"></div>
<script nonce="${nonce}">
const f=document.getElementById('f'), out=document.getElementById('out');
const tierSel=document.getElementById('tier'), corp=document.getElementById('corp'), att=document.getElementById('attestation');
function syncTier(){ corp.style.display = tierSel.value==='corporate-master' ? '' : 'none'; }
tierSel.addEventListener('change', syncTier); syncTier();
f.addEventListener('submit', async (e)=>{
  e.preventDefault();
  const tier=tierSel.value;
  const duns=document.getElementById('duns').value;
  const role=document.getElementById('role').value;
  const attestation=att.checked;
  if(tier==='corporate-master' && !attestation){
    out.textContent='❌ Please tick the attestation: you must declare you are the owner or an authorized manager of the DUNS holder.';
    return;
  }
  out.textContent='Generating…';
  try{
    const r=await fetch('/license/master',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({tier,duns,role,attestation})});
    const j=await r.json();
    if(!r.ok){ out.textContent='❌ '+(j.error||('HTTP '+r.status)); return; }
    const bundle=JSON.stringify(j,null,2);
    out.innerHTML='';
    const p=document.createElement('p'); p.textContent='✅ Master license issued. Save this bundle — keep master_private_key_pkcs8 secret (it mints your sub-accesses; we do not store it).';
    const pre=document.createElement('pre'); pre.textContent=bundle;
    out.appendChild(p); out.appendChild(pre);
  }catch(err){ out.textContent='❌ request failed: '+err; }
});
</script>
</body></html>`;
  return new Response(html, {
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "content-security-policy": `default-src 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}'; connect-src 'self'; base-uri 'none'; form-action 'none'`,
    },
  });
}
