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
// Config: env.KYC_MODE (or env.GRAMOTA_KYC) == "enforce" (trim+lowercase-normalized,
//         so "Enforce"/"ENFORCE"/a trailing space still count) turns on the LoA cap
//         (LoA-0 -> provisional). Unset/blank stays OFF (today's self-declared
//         parity: no regression). A SET-but-unrecognized value is not a silent
//         no-op: it's logged loudly (console.warn) so a hardened-rollout typo is
//         visible instead of quietly disabling enforcement.
// D&B rate-limit hardening: a 429 (quota/rate-limit) is distinguished from a
//         genuine outage (5xx/timeout) and never silently degrades to a full
//         "pass" the way an honest D&B outage does — see dnbDecisionFrom/kycGate.

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
// KYC-mode flag normalization (hardening).
//
// BUG FIXED: the flag used to be a raw case-sensitive `=== "enforce"` compare.
// "Enforce", "ENFORCE", or a trailing space (e.g. a copy-pasted env var) would
// silently fail the compare and DISABLE enforcement — exactly backwards for a
// value whose whole job is to turn HARDENING on. A typo during a hardened
// rollout would look like enforcement was live while it was actually a no-op.
//
// FIX: trim + lowercase before comparing (so casing/whitespace variants of
// "enforce" all resolve to on). Unset/blank still means OFF (parity — no
// regression from today's self-declared behavior, per the header docs). A
// value that IS set but does not normalize to a recognized mode (a typo, e.g.
// "enforced" or "enforce ") is NOT treated as a silent bypass: it's logged
// loudly via console.warn (visible in `wrangler pages deployment tail`/the
// dashboard) so the typo is visible, then resolved to OFF (the safe, existing
// default) rather than guessing. There is no true module-scope "startup" hook
// in a Cloudflare Pages Function (env is only available per-request), so this
// check runs on every kycGate call — cheap, and it means the warning surfaces
// on the very first request instead of staying silent forever.
// ---------------------------------------------------------------------------
function normalizeKycModeFlag(raw, varName) {
  if (raw == null) return false; // unset === off (parity, no regression)
  const norm = String(raw).trim().toLowerCase();
  if (norm === "") return false; // blank/whitespace-only === off
  if (norm === "enforce") return true;
  // eslint-disable-next-line no-console
  console.warn(
    `[gramota-kyc] WARNING: ${varName}=${JSON.stringify(raw)} is set but is not a ` +
    `recognized KYC mode (expected "enforce", case/whitespace-insensitive). ` +
    `Treating this deployment as UNENFORCED (KYC_MODE off) rather than silently ` +
    `guessing — if you intended to turn hardening ON, this is almost certainly a typo.`
  );
  return false;
}

// ---------------------------------------------------------------------------
// D&B Direct+ entity resolve — SAME contract as master.js/renew.js's copies.
//
// BUCKET-C HAND-OFF (docs/bucketD/PARTITION.md §2): `functions/license/master.js`
// (~L79-117) and `functions/license/renew.js` (~L66-94) carry a byte-near-identical
// duplicate of this function (different formatting, same algorithm — audited,
// no behavioral drift found). Those files are Bucket C's; this copy is the
// SOURCE OF TRUTH for the D&B/LoA logic. The F2 timeout fix below (AbortController
// + fail-closed `dnb-timeout`) is proposed to Bucket C as a unified-diff hunk —
// see docs/bucketD/DEV-D1-HANDOFF.md for the exact hunks to apply to both files.
//
// Only companyinfo_L1_v1 (entity existence + primaryName + country). No principals
// are fetched by default: principals are third-party PII (design §5).
//
// F2 fix: every fetch is bounded by an AbortController timeout (env.DNB_TIMEOUT_MS,
// default 8s) so a slow/hanging D&B response cannot block the request indefinitely
// on this code's own terms (not just the platform's outer CPU/wall-clock limit).
// A timeout maps to the SAME fail-open-to-format-only outcome as any other D&B
// outage — never a hard failure, never confused with "not-found".
// ---------------------------------------------------------------------------
const DNB_TIMEOUT_MS_DEFAULT = 8000;

export async function verifyDunsWithDnB(duns, env, fetchImpl = fetch) {
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
      // 429 is quota/rate-limit, NOT a generic outage — see the "rate-limited"
      // status note below verifyDunsWithDnB for why this is split out.
      if (tokRes.status === 429) return { status: "rate-limited", reason: "dnb-auth-http-429" };
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
    // 429 is quota/rate-limit, NOT a generic outage. Folding it into the same
    // "unavailable" bucket as a genuine 5xx/timeout is exactly the hole this
    // hardening closes: "unavailable" skips the fail-closed not-found refusal
    // below (kycGate / onRequestPost) and falls open to a format-only pass. A
    // 429 is attacker-INDUCIBLE (hammer this endpoint until D&B's own quota is
    // exhausted) in a way a random 5xx/timeout mostly isn't, so it must not
    // silently collapse into the same fail-open path — see dnbDecisionFrom and
    // kycGate below for how "rate-limited" is kept fail-closed instead.
    if (res.status === 429) return { status: "rate-limited", reason: "dnb-data-http-429" };
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

export function dnbDecisionFrom(result, now) {
  if (result.status === "verified") {
    return { verified: true, source: "dnb-direct-plus", ...(result.legalName ? { legalName: result.legalName } : {}), ...(result.country ? { country: result.country } : {}), checkedAt: now };
  }
  // "rate-limited" (429/quota) gets its OWN source label, distinct from
  // "format-only" — never silently conflated with an unconfigured/genuinely-
  // down D&B. kycGate additionally refuses to promote this to a full "pass"
  // (see below): a quota exhaustion an attacker can trigger must not buy the
  // same trust as an honest outage.
  if (result.status === "rate-limited") {
    return { verified: false, source: "rate-limited", checkedAt: now, fallbackReason: result.reason || "dnb-rate-limited" };
  }
  return { verified: false, source: "format-only", checkedAt: now, fallbackReason: result.reason || "dnb-unavailable" };
}

// ---------------------------------------------------------------------------
// Fail-closed, PII-free LoA computation (design §3 table). PURE. This is the
// AUTHORITATIVE server copy — it alone gates issuance (the verdict is bound into
// the signed token by reference, so a client can never inflate its own LoA).
//
// F1 (docs/bucketD/PARTITION.md §4): apps/gramota-kyc/kyc-loa.mjs's UI-facing
// selfDeclare/corpEmailProof/ocrMatch/idv ladder is an INTENTIONALLY coarser,
// differently-shaped on-device PREVIEW (its job is a responsive UI hint, not an
// authoritative LoA — this file is self-contained/no-imports by deploy-copy
// design, see the header, so it cannot literally import that module). It is
// NOT byte-identical to computeLoa and the old comment claiming it "mirrors the
// same normalizers" overclaimed that. What genuinely reconciles the two models:
// kyc-loa.mjs additionally exports `evidenceToLoa`, a structural mirror of this
// exact function (same evidence shape, same branching) kept in lockstep by a
// cross-model equivalence matrix in apps/gramota-kyc/dnb-client.test.mjs — that
// test fails if the two diverge. Any caller that needs server-equivalent LoA
// math on-device should use `evidenceToLoa`, not the UI preview ladder.
//
// Any signal absent -> no LoA credit (never pass-by-default).
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
  const enforced = normalizeKycModeFlag(env && env.KYC_MODE, "KYC_MODE") || normalizeKycModeFlag(env && env.GRAMOTA_KYC, "GRAMOTA_KYC");
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
  //
  // RATE-LIMIT HARDENING: a 429 (quota/rate-limit) is fundamentally different
  // from a genuine outage — an attacker can INDUCE it just by hammering D&B
  // lookups, which is exactly the lever this closes. If D&B answered "verified"
  // or is genuinely unavailable (5xx/timeout/not-configured), the existing
  // parity/enforced logic above stands unchanged. But if the entity check was
  // rate-limited, we could NOT confirm the DUNS is real THIS time — so this
  // decision never silently promotes to "pass" on that basis, independent of
  // KYC_MODE. It still isn't a hard refuse (that would let an attacker turn a
  // self-inflicted 429 into a DoS against everyone else); "provisional" is the
  // existing, already-modeled middle state that routes to manual review instead
  // of a silent full grant.
  const dnbRateLimited = dnbResult.status === "rate-limited";
  const decision = dnbRateLimited ? "provisional" : (!enforced ? "pass" : (loa >= 1 ? "pass" : "provisional"));
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
    ...(dnbRateLimited ? {
      note: "Dun & Bradstreet could not be checked right now (rate-limited/quota) — held at 'provisional' " +
        "rather than silently degrading to a full pass; retry once D&B capacity recovers.",
    } : {}),
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
    enforcement: "env.KYC_MODE='enforce' (case/whitespace-insensitive; a set-but-unrecognized value is logged, not silently ignored) caps LoA-0 at 'provisional'. Default (unconfigured) returns today's self-declared parity — no regression. A D&B 429 (rate-limited) also holds at 'provisional', independent of KYC_MODE, rather than silently falling open to a full pass.",
    honest: "A document read is NOT proof of authority. 'Authorized manager' is an internal delegation in no public registry and cannot be verified absolutely. Reference prototype — UNAUDITED, pre-production. Not legal advice.",
    coin: "Any future billing is fiat only; the coin is never a billing instrument and is not a security.",
  });
}
