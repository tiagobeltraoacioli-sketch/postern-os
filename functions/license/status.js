// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Postern license status / CRL endpoint (D4) — the missing revocation mechanism.
//
// DEPLOY TARGET: bp-wt-site/functions/license/status.js  (Cloudflare Pages Fn)
// Staged in the licensing package (owned path) because the implementing agent is
// isolated to the bloch-protocol worktree and cannot write into bp-wt-site. Copy
// verbatim. Self-contained (no imports), like the other license functions.
//
// GET  /license/status  → the current VENDOR-SIGNED, versioned CRL for offline
//                         installs to fetch + cache. Public, offline verification
//                         preserved: the CRL only REVOKES, never grants.
// POST /license/status  → admin-only (LICENSE_ADMIN_TOKEN bearer): add a token
//                         serial (jti) or a whole org master_pub to the revoked
//                         set and bump the monotonic version.
//
// This function holds the VENDOR PRIVATE key (env.VENDOR_PRIV_PKCS8_B64), so it
// signs the CRL here — the correct place. The standalone hosted verifier
// (enterprise/cloud/services/src/license-service.mjs) holds only the PUBLIC key
// and merely re-serves / verifies a CRL published to it. Same CRL schema on both.
//
// KV: env.LICENSES holds "crl:state" = { version, revoked_jti[], revoked_master_pub[] }.

const VENDOR_PUB_RAW_B64 = "iW52PuhJm0+JE+g5UhfrArJ7ONfuUjrm0C38NSwQGm0=";
const ISSUER = "posternlabs.com";
const CRL_KEY = "crl:state";
const NEXT_UPDATE_SECS = 24 * 3600;   // publish daily
const MAX_STALE_SECS = 14 * 24 * 3600; // 14-day soft-offline grace

// Same canonical() as master.js / the licensing lib. DO NOT change — the CRL
// signature must verify byte-identically against the vendor public key.
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

async function keyId(rawPubB64) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rawPubB64));
  return hex(d).slice(0, 16);
}

function json(status, body, extraHeaders = {}) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...extraHeaders },
  });
}

function timingSafeEqual(a, b) {
  a = String(a || ""); b = String(b || "");
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

async function readCrlState(env) {
  if (!env.LICENSES) return { version: 0, revoked_jti: [], revoked_master_pub: [] };
  const raw = await env.LICENSES.get(CRL_KEY);
  if (!raw) return { version: 0, revoked_jti: [], revoked_master_pub: [] };
  try {
    const s = JSON.parse(raw);
    return {
      version: Number(s.version) || 0,
      revoked_jti: Array.isArray(s.revoked_jti) ? s.revoked_jti : [],
      revoked_master_pub: Array.isArray(s.revoked_master_pub) ? s.revoked_master_pub : [],
    };
  } catch {
    return { version: 0, revoked_jti: [], revoked_master_pub: [] };
  }
}

/** Build + vendor-sign a CRL payload from the persisted revoked set. */
export async function buildSignedCrl(env, state, now) {
  const kid = await keyId(VENDOR_PUB_RAW_B64);
  const payload = {
    v: 1,
    typ: "crl",
    iss: ISSUER,
    kid,
    version: state.version,
    issued_at: now,
    next_update: now + NEXT_UPDATE_SECS,
    max_stale_secs: MAX_STALE_SECS,
    // De-dupe + sort so the signed bytes are stable for a given set.
    revoked_jti: [...new Set(state.revoked_jti)].sort(),
    revoked_master_pub: [...new Set(state.revoked_master_pub)].sort(),
  };
  const vk = await crypto.subtle.importKey("pkcs8", b64d(env.VENDOR_PRIV_PKCS8_B64), { name: "Ed25519" }, false, ["sign"]);
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, vk, new TextEncoder().encode(canonical(payload))));
  return { payload, sig: b64(sig) };
}

export async function onRequestGet(context) {
  const { env } = context;
  if (!env.VENDOR_PRIV_PKCS8_B64) {
    return json(503, { error: "CRL signing key not configured on this deployment" });
  }
  const now = Math.floor(Date.now() / 1000);
  const state = await readCrlState(env);
  const crl = await buildSignedCrl(env, state, now);
  // Freshly signed on each fetch, so the served copy is always "fresh"; the
  // freshness window matters for the CACHED copy on the client. Short public
  // cache is fine — the CRL is public data and carries no secret.
  return json(200, {
    crl,
    freshness: "fresh",
    note: "Vendor-signed, versioned CRL. Verify against the vendor PUBLIC key you already trust, cache it, and prefer the higher `version`. Offline verification is preserved — the CRL only revokes, never grants. Revocation is best-effort and freshness-bound (soft-offline).",
  }, { "cache-control": "public, max-age=300" });
}

export async function onRequestPost(context) {
  const { request, env } = context;
  const admin = env.LICENSE_ADMIN_TOKEN;
  if (!admin) return json(501, { error: "revocation writes are disabled (LICENSE_ADMIN_TOKEN unset)" });
  const auth = request.headers.get("authorization") || "";
  const tok = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!timingSafeEqual(tok, admin)) return json(401, { error: "admin bearer token required" });
  if (!env.LICENSES) return json(503, { error: "no durable store (LICENSES KV) bound" });

  let body;
  try { body = await request.json(); } catch { return json(400, { error: "invalid JSON body" }); }
  const jti = body.jti ? String(body.jti) : null;
  const masterPub = body.master_pub ? String(body.master_pub) : null;
  if (!jti && !masterPub) {
    return json(400, { error: "provide { jti } (a token serial) and/or { master_pub } (a whole org) to revoke" });
  }

  const state = await readCrlState(env);
  const added = {};
  if (jti && !state.revoked_jti.includes(jti)) { state.revoked_jti.push(jti); added.jti = jti; }
  if (masterPub && !state.revoked_master_pub.includes(masterPub)) { state.revoked_master_pub.push(masterPub); added.master_pub = masterPub; }
  // Bump the monotonic version whenever the set actually changes (anti-rollback).
  if (added.jti || added.master_pub) state.version += 1;
  await env.LICENSES.put(CRL_KEY, JSON.stringify({
    version: state.version,
    revoked_jti: state.revoked_jti,
    revoked_master_pub: state.revoked_master_pub,
    reason: String(body.reason || "unspecified").slice(0, 200),
    updatedAt: new Date().toISOString(),
  }));
  return json(200, {
    ok: true,
    version: state.version,
    added,
    counts: { revoked_jti: state.revoked_jti.length, revoked_master_pub: state.revoked_master_pub.length },
    note: "Offline installs enforce this once they fetch GET /license/status (best-effort, freshness-bound). The personal-free base is never affected.",
  });
}
