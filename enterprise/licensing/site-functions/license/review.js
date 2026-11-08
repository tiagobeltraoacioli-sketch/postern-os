// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Postern Enterprise — Gramota owner/manager KYC review endpoint + kycGate seam.
//
// DEPLOY TARGET: bp-wt-site/functions/license/review.js  (Cloudflare Pages Fn)
// Staged in the licensing package (owned path) because the implementing agent is
// isolated to the bloch-protocol worktree and cannot write into bp-wt-site. Copy
// verbatim. Self-contained (no imports), like master.js / renew.js / status.js.
//
// WHAT THIS IS (design: Postern-Enterprise-Owner-KYC-Design.md, Gramota / Option E):
//   The person->entity binder. It ties the requesting HUMAN to the DUNS holder so
//   Company A cannot register a corporate master against Company B's public DUNS.
//   It computes a MINIMAL, PII-free assurance verdict (LoA 0..3) that master.js /
//   renew.js bind into the vendor-signed token by reference.
//
// CRITICAL PRIVACY RULE (non-negotiable):
//   OCR of the authority + ID documents runs ENTIRELY ON-DEVICE (apps/gramota-kyc).
//   Document images, raw OCR text, names, and document numbers NEVER reach this
//   server. This endpoint accepts ONLY a minimal verdict: booleans + field NAMES
//   (never their values) + an LoA. A PII/image tripwire (scanForPII) REFUSES any
//   request that carries documents or raw personal data (LGPD/GDPR minimization).
//   A server/third-party OCR path, if ever offered, is a strictly opt-in, clearly
//   less-private option under a DPA — never the default and NOT implemented here.
//
// HONEST LIMITATION (stated plainly, per the design):
//   A document READ is NOT proof of authority. OCR proves text was extracted, not
//   that a document is authentic, current, unrevoked, or that it genuinely grants
//   authority — and not that the presenter is its subject. "Authorized manager" is
//   an internal delegation in no public registry and cannot be verified absolutely.
//   Every verdict carries self_declared:true and ocr.onDevice:true so nothing ever
//   reads as identity- or authority-PROVEN when it was only attested on-device.
//   Reference prototype / UNAUDITED / pre-production. Not legal advice.
//
// GET  /license/review           -> the JSON contract + honest disclosure.
// POST /license/review {duns, resolve:true}
//                                -> entity-side resolve: returns the D&B legalName
//                                   + country so the client can compare ON-DEVICE.
//                                   (Business/entity data only, already public in
//                                   the issued token; never requester PII.)
// POST /license/review {duns, role, attestation:true, kyc:{...minimal verdict...}}
//                                -> re-verifies the DUNS at D&B (fail-closed on
//                                   not-found), sanitizes the client verdict,
//                                   computes the AUTHORITATIVE LoA, stores it under
//                                   KV kyc:<ref> (short TTL) and returns {ref, ...}.
//                                   master.js / renew.js bind that stored verdict
//                                   BY REFERENCE, so a client cannot inflate its LoA.
//
// KV: env.LICENSES holds "kyc:<ref>" (the authoritative verdict, TTL ~1h) alongside
//     "duns:<duns>" / "crl:state" used by the other functions.
// Config: env.KYC_MODE === "enforce" turns on the LoA cap (LoA-0 -> provisional).
//         Default (unconfigured) returns today's self-declared parity: no regression.

const ISSUER = "posternlabs.com";
const DNB_AUTH_URL = "https://plus.dnb.com/v3/token";
const DNB_DATA_URL = "https://plus.dnb.com/v1/data/duns";
const KYC_REF_TTL = 3600; // authoritative verdict lives ~1h until issuance consumes it
const ALLOWED_FIELDS = new Set(["legalName", "country", "officer"]);

const b64d = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const hex = (buf) => [...new Uint8Array(buf)].map((x) => x.toString(16).padStart(2, "0")).join("");
function randomRef() { return hex(crypto.getRandomValues(new Uint8Array(16))); }

function json(status, body) {
  return new Response(JSON.stringify(body, null, 2), {
    status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}

// ---------------------------------------------------------------------------
// D&B Direct+ entity resolve — SAME contract as master.js verifyDunsWithDnB.
// Only companyinfo_L1_v1 (entity existence + primaryName + country). No principals
// are fetched by default: principals are third-party PII (design §5).
// ---------------------------------------------------------------------------
export async function verifyDunsWithDnB(duns, env, fetchImpl = fetch) {
  const clientId = env && env.DNB_CLIENT_ID, clientSecret = env && env.DNB_CLIENT_SECRET, staticBearer = env && env.DNB_BEARER;
  if (!staticBearer && !(clientId && clientSecret)) return { status: "unavailable", reason: "dnb-not-configured" };
  try {
    let bearer = staticBearer;
    if (!bearer) {
      const tokRes = await fetchImpl(DNB_AUTH_URL, {
        method: "POST",
        headers: { authorization: "Basic " + btoa(`${clientId}:${clientSecret}`), "content-type": "application/x-www-form-urlencoded" },
        body: "grant_type=client_credentials",
      });
      if (!tokRes.ok) return { status: "unavailable", reason: `dnb-auth-http-${tokRes.status}` };
      const tj = await tokRes.json();
      bearer = tj && (tj.access_token || tj.accessToken);
      if (!bearer) return { status: "unavailable", reason: "dnb-auth-no-token" };
    }
    const res = await fetchImpl(`${DNB_DATA_URL}/${encodeURIComponent(duns)}?blockIDs=companyinfo_L1_v1`, { headers: { authorization: "Bearer " + bearer } });
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
  } catch { return { status: "unavailable", reason: "dnb-network-error" }; }
}

export function dnbDecisionFrom(result, now) {
  if (result.status === "verified") {
    return { verified: true, source: "dnb-direct-plus", ...(result.legalName ? { legalName: result.legalName } : {}), ...(result.country ? { country: result.country } : {}), checkedAt: now };
  }
  return { verified: false, source: "format-only", checkedAt: now, fallbackReason: result.reason || "dnb-unavailable" };
}

// ---------------------------------------------------------------------------
// Fail-closed, PII-free LoA computation (design §3 table). PURE. This is the
// AUTHORITATIVE server copy; apps/gramota-kyc mirrors the same normalizers on the
// device. Any signal absent -> no LoA credit (never pass-by-default).
// ---------------------------------------------------------------------------
export function ocrValidated(ocr) {
  return !!(ocr && ocr.onDevice === true && ocr.match === true &&
    Array.isArray(ocr.fieldsMatched) &&
    ocr.fieldsMatched.includes("legalName") && ocr.fieldsMatched.includes("country"));
}

/**
 * Faithful LoA table (design §3):
 *   0  self-declared only (today's behavior)
 *   1  + corporate-domain proof (Option B)
 *   2  LoA-1 + (D&B principal match OR on-device OCR validated)
 *   3  (on-device OCR + liveness/authenticity) OR full IDV pass
 * Fail-closed: OCR/liveness/idv signals are self-attested on-device; a bare OCR
 * match WITHOUT a corroborating signal never lifts LoA above 0 — a document read
 * is not proof of authority.
 */
export function computeLoa(x) {
  const methods = [];
  if (x.selfDeclared !== false) methods.push("self-declared");
  if (x.dnbVerified) methods.push("dnb-entity");         // entity is real (NOT the person link)
  const ov = ocrValidated(x.ocr);
  if (x.corpDomain) methods.push("corp-domain");
  if (x.principalMatch) methods.push("dnb-principal");
  if (x.ocr && x.ocr.onDevice) methods.push("ocr-ondevice");
  if (x.idvPass) methods.push("idv");

  let loa = 0;
  if (x.corpDomain) loa = 1;
  if (loa >= 1 && (x.principalMatch || ov)) loa = 2;
  if ((ov && x.liveness) || x.idvPass) loa = 3;
  return { loa, methods, ocrValidated: ov };
}

const ASSURANCE = ["self-declared", "domain-verified", "higher-assurance", "top-assurance"];

/**
 * The KYC SEAM consumed by Dev-1's onboarding.
 * @param env  worker env (DNB_* creds, KYC_MODE, LICENSES KV)
 * @param ctx  { duns, role, attestation, kyc?, fetchImpl?, dnbResult? }
 *             `kyc` is the client's MINIMAL, PII-free on-device verdict (or absent).
 * @returns { decision, ref, loa, assurance, methods, ocr?, dnb, enforced, checkedAt }
 *   decision: "pass" | "provisional" | "refuse"
 *   Default-UNCONFIGURED (no KYC_MODE): returns today's self-declared parity —
 *   decision "pass", loa 0, enforced:false — so onboarding issues exactly as today.
 */
export async function kycGate(env, ctx) {
  const now = Math.floor(Date.now() / 1000);
  const enforced = !!(env && (env.KYC_MODE === "enforce" || env.GRAMOTA_KYC === "enforce"));
  const duns = String((ctx && ctx.duns) || "").replace(/\D/g, "");
  const fetchImpl = (ctx && ctx.fetchImpl) || fetch;

  // Entity-side check (reuses master.js's contract). Allow a pre-computed result.
  const dnbResult = (ctx && ctx.dnbResult) || await verifyDunsWithDnB(duns, env, fetchImpl);
  const dnb = dnbDecisionFrom(dnbResult, now);

  // fail-closed: a configured D&B that says "not a real entity" refuses outright.
  if (dnbResult.status === "not-found") {
    return {
      decision: "refuse", ref: null, loa: 0, assurance: "refused",
      methods: [], dnb: { verified: false, source: "dnb-direct-plus", reason: dnbResult.reason },
      enforced, checkedAt: now,
      note: "DUNS did not resolve to a real legal entity at Dun & Bradstreet — refused (fail-closed).",
    };
  }

  const cv = sanitizeClientVerdict((ctx && ctx.kyc) || null);
  const { loa, methods } = computeLoa({
    selfDeclared: true,
    dnbVerified: dnb.verified,
    corpDomain: cv.corpDomain,
    principalMatch: cv.principalMatch === true,
    ocr: cv.ocr,
    liveness: cv.ocr ? cv.ocr.liveness : false,
    idvPass: !!cv.idvRef,
  });

  // Default-unconfigured => parity: always "pass" (issue as today). When enforced,
  // the LoA cap applies: LoA-0 person->entity evidence => provisional, never a
  // silent full grant.
  const decision = !enforced ? "pass" : (loa >= 1 ? "pass" : "provisional");
  const ref = randomRef();
  const verdict = {
    duns, role: (ctx && ctx.role) || null,
    decision, ref, loa, assurance: ASSURANCE[loa] || "self-declared",
    methods, self_declared: true,
    ...(cv.ocr ? { ocr: cv.ocr } : {}),
    ...(cv.principalMatch === true || cv.principalMatch === false ? { principalMatch: cv.principalMatch } : {}),
    ...(cv.domain ? { domain: cv.domain, domainProofAt: cv.domainProofAt || now } : {}),
    idvRef: cv.idvRef || null,
    dnb: { verified: dnb.verified, source: dnb.source, ...(dnb.legalName ? { legalName: dnb.legalName } : {}), ...(dnb.country ? { country: dnb.country } : {}) },
    enforced, verifiedAt: now, checkedAt: now, iss: ISSUER,
  };

  // Persist the AUTHORITATIVE verdict under kyc:<ref> so master.js / renew.js bind
  // it by reference (client cannot inflate its own LoA). Short TTL.
  if (env && env.LICENSES && ref) {
    try { await env.LICENSES.put("kyc:" + ref, JSON.stringify(verdict), { expirationTtl: KYC_REF_TTL }); } catch { /* best-effort */ }
  }
  return verdict;
}

// ---------------------------------------------------------------------------
// PII / image tripwire — refuse anything but a minimal, PII-free verdict.
// Walks the whole body: any blocked key, any data: URI, any over-long string
// (an image/raw-OCR payload) => reject. fieldsMatched carries field NAMES only.
// ---------------------------------------------------------------------------
const BLOCKED_KEYS = new Set([
  "image", "images", "imagedata", "imageb64", "imagebase64", "photo", "photos", "selfie",
  "document", "documents", "documentimage", "docimage", "scan", "scans", "attachment",
  "documentnumber", "docnumber", "idnumber", "nationalid", "passport", "passportnumber", "mrz",
  "rawtext", "ocrtext", "fulltext", "text", "extracted", "extractedtext",
  "name", "fullname", "firstname", "lastname", "surname", "givenname", "middlename",
  "personname", "officername", "holdername", "legalname", "companyname", "entityname",
  "dob", "dateofbirth", "birthdate", "birthday", "address", "street", "city", "postalcode",
  "ssn", "taxid", "cpf", "cnpj", "email", "phone", "telephone",
]);
const MAX_STRING = 512; // anything longer is presumed to be an image / raw text blob

export function scanForPII(node, depth = 0) {
  if (depth > 8) return "nesting-too-deep";
  if (node == null) return null;
  if (typeof node === "string") {
    if (node.length > MAX_STRING) return "over-long-string (possible image/raw text)";
    if (/^data:/i.test(node.trim())) return "data-uri (image/blob not accepted)";
    return null;
  }
  if (typeof node !== "object") return null;
  if (Array.isArray(node)) {
    for (const v of node) { const r = scanForPII(v, depth + 1); if (r) return r; }
    return null;
  }
  for (const [k, v] of Object.entries(node)) {
    const nk = String(k).toLowerCase().replace(/[^a-z0-9]/g, "");
    if (BLOCKED_KEYS.has(nk)) return `blocked field "${k}" — documents / raw PII never leave the device`;
    const r = scanForPII(v, depth + 1); if (r) return r;
  }
  return null;
}

/** Reduce an untrusted client verdict to the minimal, PII-free bound shape. */
export function sanitizeClientVerdict(cv) {
  const out = { ocr: null, principalMatch: undefined, domain: null, domainProofAt: null, idvRef: null, corpDomain: false };
  if (!cv || typeof cv !== "object") return out;
  if (cv.ocr && typeof cv.ocr === "object") {
    out.ocr = {
      onDevice: cv.ocr.onDevice === true,
      match: cv.ocr.match === true,
      fieldsMatched: Array.isArray(cv.ocr.fieldsMatched) ? cv.ocr.fieldsMatched.filter((f) => ALLOWED_FIELDS.has(f)).slice(0, 8) : [],
      liveness: cv.ocr.liveness === true,
    };
  }
  if (cv.principalMatch === true || cv.principalMatch === false) out.principalMatch = cv.principalMatch;
  if (typeof cv.domain === "string" && /^[a-z0-9.-]{1,253}$/i.test(cv.domain)) {
    out.domain = cv.domain.toLowerCase();
    out.domainProofAt = Number(cv.domainProofAt) || null;
    out.corpDomain = true; // a submitted, mapped corp-domain proof (design Option B)
  }
  if (typeof cv.idvRef === "string" && /^[A-Za-z0-9._-]{1,128}$/.test(cv.idvRef)) out.idvRef = cv.idvRef;
  return out;
}

// ---------------------------------------------------------------------------
// HTTP surface.
// ---------------------------------------------------------------------------
export async function onRequestPost(context) {
  const { request, env } = context;
  let body;
  try { body = await request.json(); } catch { return json(400, { error: "invalid JSON body" }); }

  // Tripwire FIRST — before anything else touches the payload.
  const pii = scanForPII(body);
  if (pii) {
    return json(400, {
      error: "privacy violation: /license/review never accepts document images or raw PII. " +
        "OCR must run ON-DEVICE (apps/gramota-kyc) and submit ONLY the minimal verdict " +
        "{ ocr:{ onDevice, match, fieldsMatched (field NAMES only), liveness } }. Offending: " + pii,
    });
  }

  const duns = String(body.duns || "").replace(/\D/g, "");
  if (!/^\d{9}$/.test(duns)) return json(400, { error: "a valid 9-digit DUNS number is required" });

  // Mode 1: entity resolve for ON-DEVICE comparison (business data only).
  if (body.resolve === true) {
    const r = await verifyDunsWithDnB(duns, env);
    if (r.status === "not-found") {
      return json(422, { error: "this DUNS did not resolve to a real legal entity at Dun & Bradstreet — refused (fail-closed)", dnb: { verified: false, source: "dnb-direct-plus", reason: r.reason } });
    }
    const dnb = dnbDecisionFrom(r, Math.floor(Date.now() / 1000));
    return json(200, {
      // entity-side fields ONLY, so the browser can compare its on-device OCR to
      // the D&B entity WITHOUT ever sending the OCR text back. Compare on-device.
      dnb: { verified: dnb.verified, source: dnb.source, legalName: dnb.legalName || null, country: dnb.country || null, checkedAt: dnb.checkedAt },
      note: "Compare your on-device OCR fields against these entity values IN THE BROWSER. Submit only the boolean match verdict. A document read is not proof of authority.",
    });
  }

  // Mode 2: verdict. role + re-attestation required, then compute authoritative LoA.
  const role = body.role === "owner" ? "owner" : body.role === "manager" ? "manager" : null;
  if (!role) return json(400, { error: "declare your role: 'owner' or an authorized 'manager' of the DUNS holder" });
  if (body.attestation !== true) return json(400, { error: "you must attest (KYC consent) before a verdict is computed" });

  const verdict = await kycGate(env, { duns, role, attestation: true, kyc: body.kyc || null });
  if (verdict.decision === "refuse") return json(422, verdict);

  return json(200, {
    ...verdict,
    consume: "Pass { kyc_ref: ref } to POST /license/master (or /license/renew) to BIND this verdict into the signed token. The server binds the stored verdict by reference; a client cannot inflate its own LoA.",
    honest: "A document read is NOT proof of authority. self_declared stays true; ocr.onDevice records that OCR ran client-side. UNAUDITED reference prototype; not legal advice.",
  });
}

export async function onRequestGet() {
  return json(200, {
    endpoint: "/license/review",
    product: "Gramota — owner/manager identity KYC (person->entity binder)",
    method: "POST",
    modes: {
      resolve: { body: { duns: "<9 digits>", resolve: true }, returns: "D&B entity legalName + country for ON-DEVICE comparison (business data only)" },
      verdict: { body: { duns: "<9 digits>", role: "owner|manager", attestation: true, kyc: { ocr: { onDevice: true, match: true, fieldsMatched: ["legalName", "country"], liveness: false } } }, returns: "{ ref, decision, loa, methods, ... } — the authoritative, PII-free verdict, stored under kyc:<ref> for issuance to bind" },
    },
    privacy: "On-device OCR ONLY. Document images, raw OCR text, and PII NEVER reach this server; a tripwire refuses them. Only booleans + field NAMES + LoA cross the wire (LGPD/GDPR data minimization).",
    loa: { 0: "self-declared (today's parity)", 1: "+ corporate-domain proof", 2: "LoA-1 + D&B principal match OR on-device OCR validated", 3: "on-device OCR + liveness, or full IDV pass" },
    enforcement: "env.KYC_MODE='enforce' caps LoA-0 at 'provisional'. Default (unconfigured) returns today's self-declared parity — no regression.",
    honest: "A document read is NOT proof of authority. 'Authorized manager' is an internal delegation in no public registry and cannot be verified absolutely. Reference prototype — UNAUDITED, pre-production. Not legal advice.",
    coin: "Any future billing is fiat only; the coin is never a billing instrument and is not a security.",
  });
}
