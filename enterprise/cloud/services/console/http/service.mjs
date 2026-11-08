// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern CLOUD — Consiglio CONSOLE HTTP SERVICE (reference prototype).
//
// STATUS: reference prototype. UNAUDITED. Pre-production. NO SECURITY CLAIMS —
// a signature proves origin+integrity, nothing about what it signs. This
// DEMONSTRATES controls that ENABLE compliance/governance; it is NOT compliance
// and NOT legal advice. Tamper-EVIDENT, not tamper-proof. Fiat only; the coin is
// never billed. LGPD/GDPR-minimal by construction (public keys + metadata only).
//
// WHAT THIS IS
// ------------
// The HTTP surface that turns the Consiglio wallet-login CONSOLE (the Node
// mirror of the authoritative Rust crate `postern-consiglio-auth`) into a real,
// durable admin service for "liberação de acessos" — releasing accesses. It
// exposes Consiglio's verbs over HTTP, all FAIL-CLOSED:
//
//   • Wallet-as-login          POST /v1/login/challenge, /v1/login/verify
//                              (the signature check is the REAL hybrid-PQ verify
//                              via the consiglio-verify native binary — no stub).
//   • Sessions                 GET /v1/session, POST /v1/session/logout, /sweep.
//   • Enroll/offboard          dual-controlled: /v1/changes (propose),
//                              /v1/changes/:id/approve|reject  (SoD enforced).
//   • grantAccess              POST /v1/grant  (routed: enroll-person | device).
//   • revokeAccess             POST /v1/revoke (routed: offboard-person | device
//                              | org-kill).
//   • Console surface          GET /v1/status, GET /v1/audit.
//
// DURABILITY. All state is injected over the existing seams into a real backend
// (store.mjs, atomic JSON files): console-auth `snapshot()`/`{state}`,
// sub-access `onChange`, and the tamper-EVIDENT audit chain. Every mutating verb
// persists; a restart restores enrollments, live sessions, the sub registry, and
// the audit trail. See http/README.md.
//
// SESSION GATE. Every verb except health/posture, login, and FIRST-ADMIN
// bootstrap requires a live, in-TTL session presented as `Authorization: Bearer
// <sessionId>`. bootstrap is the ONE dual-control bypass and is refused once the
// org already has an admin enrolled (first-admin seeding only).

import { createConsoleAuth, ConsoleAuthError, ADMIN_ROLES } from "../console-auth.mjs";
import { createConsiglioVerifier } from "../consiglio-verifier.mjs";
import { createFileStore } from "./store.mjs";
import { createAuditTrail } from "./audit.mjs";
import { createSubAccessHost } from "./sub-access-host.mjs";

const RAILS = Object.freeze({
  status: "reference prototype — UNAUDITED, pre-production, no security claims",
  walletLogin: "REAL hybrid post-quantum (Falcon-1024 ‖ ML-DSA-65) via the consiglio-verify native binary",
  compliance: "demonstrates controls that ENABLE compliance/governance — NOT compliance, NOT legal advice",
  audit: "tamper-EVIDENT (SHAKE-256 hash chain), not tamper-proof",
  billing: "fiat only; the coin is never billed and is not a security",
  privacy: "LGPD/GDPR-minimal: sessions/enrollments/snapshots hold PUBLIC keys + metadata only, no secret material",
  spdx: "MIT OR Apache-2.0",
});

/**
 * Build the console HTTP service.
 *
 * @param {object} [opts]
 * @param {string} [opts.dataDir]     durable store directory (default ./console-data).
 * @param {object} [opts.verifier]    verifier bridge (default: real consiglio-verify).
 * @param {number} [opts.sessionTtlSecs]
 * @param {number} [opts.challengeTtlSecs]
 * @param {object} [opts.master]      verified master {token, masterKey, expires, seats}
 *                                    — enables the seat/device verbs. Omit to run
 *                                    auth-only.
 * @param {object} [opts.signer]      real {mintSub, verifyChain} (else demo stand-in).
 * @param {(jti:string,meta:object)=>void} [opts.onDeprovision]
 * @returns {Promise<{handler:Function, close:Function, _internals:object}>}
 */
export async function createConsoleService(opts = {}) {
  const store = createFileStore(opts.dataDir || "./console-data");
  const verifier = opts.verifier || createConsiglioVerifier();

  // Restore prior state from the durable store (fail-closed: a read fault throws
  // here and the caller does not start a half-initialized service).
  const authState = await store.loadAuth();
  const auth = createConsoleAuth({
    verifier,
    sessionTtlSecs: opts.sessionTtlSecs,
    challengeTtlSecs: opts.challengeTtlSecs,
    state: authState || undefined,
  });
  const persistAuth = () => Promise.resolve(store.saveAuth(auth.snapshot())).catch(() => {});

  const audit = createAuditTrail({
    entries: await store.loadAudit(),
    onChange: (entries) => Promise.resolve(store.saveAudit(entries)).catch(() => {}),
  });

  let subHost = null;
  if (opts.master) {
    subHost = createSubAccessHost({
      master: opts.master,
      store,
      audit,
      signer: opts.signer || null,
      onDeprovision: opts.onDeprovision,
      records: (await store.loadSubs()) || [],
    });
  }

  // ---- helpers -----------------------------------------------------------

  const nowSecs = () => Math.floor(Date.now() / 1000);

  function readBody(req) {
    return new Promise((resolve, reject) => {
      let raw = "";
      req.on("data", (c) => {
        raw += c;
        if (raw.length > 1_000_000) reject(new Error("body too large"));
      });
      req.on("end", () => {
        if (!raw) return resolve({});
        try {
          resolve(JSON.parse(raw));
        } catch {
          reject(new HttpError(400, "invalid_json", "request body is not valid JSON"));
        }
      });
      req.on("error", reject);
    });
  }

  function bearer(req) {
    const h = req.headers["authorization"] || "";
    const m = /^Bearer\s+(.+)$/i.exec(h);
    return m ? m[1].trim() : (req.headers["x-consiglio-session"] || null);
  }

  // The session gate: resolve + validate the bearer session, or throw 401.
  function requireSession(req) {
    const id = bearer(req);
    if (!id) throw new HttpError(401, "no_session", "a live session (Bearer token) is required");
    const s = auth.validateSession(id);
    if (!s) throw new HttpError(401, "session_invalid", "session is unknown or expired (fail-closed)");
    return s;
  }

  function bootstrapClosed(orgId) {
    // Bootstrap seeds the FIRST separated admin PAIR (one it-admin AND one
    // compliance-officer) — that is exactly what dual-control needs to exist.
    // Once both sides of the wall are present, bootstrap is CLOSED: every
    // further enroll must go through dual-control. (Refusing after the very
    // first admin would make seeding the pair impossible.)
    const snap = auth.snapshot();
    const roles = new Set(
      (snap.enrollments || []).filter((e) => e.orgId === orgId && ADMIN_ROLES.includes(e.role)).map((e) => e.role),
    );
    return roles.has("it-admin") && roles.has("compliance-officer");
  }

  // ---- route table -------------------------------------------------------
  // Each handler returns a JSON-able value (200) or throws HttpError/ConsoleAuthError.

  const routes = [
    // Health + posture (public).
    ["GET", /^\/healthz$/, () => ({
      ok: true,
      service: "consiglio-console",
      verifierLabel: auth.verifierLabel,
      verifierAvailable: auth.verifierAvailable(),
      seatHostWired: !!subHost,
      rails: RAILS,
    })],
    ["GET", /^\/v1\/posture$/, () => ({ rails: RAILS })],

    // Wallet-as-login (public — the login IS the credential).
    ["POST", /^\/v1\/login\/challenge$/, async (req) => {
      const b = await readBody(req);
      if (!b.orgId || !b.userId) throw new HttpError(400, "invalid_request", "orgId and userId are required");
      const ch = auth.issueChallenge(b.orgId, b.userId);
      await persistAuth();
      return { challenge: ch };
    }],
    ["POST", /^\/v1\/login\/verify$/, async (req) => {
      const b = await readBody(req);
      const response = b.response || b;
      const challenge = b.challenge;
      if (!challenge) throw new HttpError(400, "invalid_request", "the issued challenge must be echoed back");
      const session = await auth.verifyLogin(response, challenge);
      await persistAuth();
      await audit.append("login", `wallet login ${session.orgId}/${session.userId}`, {
        role: session.role, clearance: session.clearance, sessionId: session.id,
      });
      return { session };
    }],

    // First-admin bootstrap (the ONE dual-control bypass; refused once seeded).
    ["POST", /^\/v1\/bootstrap-enroll$/, async (req) => {
      const b = await readBody(req);
      if (!b.orgId) throw new HttpError(400, "invalid_request", "orgId is required");
      if (bootstrapClosed(b.orgId)) {
        throw new HttpError(403, "bootstrap_closed",
          "bootstrap is first-admin-pair seeding only; this org already has an it-admin AND a compliance-officer — use dual-controlled /v1/grant");
      }
      const enrollment = auth.bootstrapEnroll(b);
      await persistAuth();
      await audit.append("bootstrap.enroll", `seed ${b.orgId}/${b.userId} as ${b.role}`, {
        role: b.role, clearance: b.clearance | 0,
      });
      return { enrollment };
    }],

    // Sessions (gated).
    ["GET", /^\/v1\/session$/, (req) => ({ session: requireSession(req) })],
    ["POST", /^\/v1\/session\/logout$/, async (req) => {
      const s = requireSession(req);
      const revoked = auth.revokeSession(s.id);
      await persistAuth();
      return { revoked };
    }],
    ["POST", /^\/v1\/session\/sweep$/, async (req) => {
      requireSession(req);
      const dropped = auth.sweep();
      await persistAuth();
      return { dropped };
    }],

    // Console surface (gated).
    ["GET", /^\/v1\/status$/, (req) => {
      requireSession(req);
      return status();
    }],
    ["GET", /^\/v1\/audit$/, (req) => {
      requireSession(req);
      return { entries: audit.list(), head: audit.head(), integrity: audit.verify() };
    }],

    // Dual-control change queue (gated; proposer/approver = the live session).
    ["POST", /^\/v1\/changes$/, async (req) => {
      const actor = requireSession(req);
      const b = await readBody(req);
      const out = auth.proposeChange(actor, b.kind, b.payload || {});
      await persistAuth();
      await audit.append(`change.propose.${b.kind}`, out.summary, { proposer: `${actor.orgId}/${actor.userId}`, changeId: out.id });
      return out;
    }],
    ["GET", /^\/v1\/changes$/, (req) => {
      requireSession(req);
      return { pending: auth.pendingChangeIds().map((id) => auth.pendingChange(id)).filter(Boolean) };
    }],
    ["POST", /^\/v1\/changes\/([0-9a-f]+)\/approve$/, async (req, m) => {
      const approver = requireSession(req);
      const outcome = auth.approveChange(m[1], approver);
      await persistAuth();
      await audit.append("change.commit", outcome.summary, {
        approver: `${approver.orgId}/${approver.userId}`, changeId: outcome.changeId,
        sessionsRevoked: outcome.sessionsRevoked || 0,
      });
      return outcome;
    }],
    ["POST", /^\/v1\/changes\/([0-9a-f]+)\/reject$/, async (req, m) => {
      const actor = requireSession(req);
      const rejected = auth.rejectChange(m[1]);
      await persistAuth();
      await audit.append("change.reject", `reject ${m[1]}`, { actor: `${actor.orgId}/${actor.userId}` });
      return { rejected };
    }],

    // grantAccess — a single fail-closed verb with a routed payload (§5.2).
    ["POST", /^\/v1\/grant$/, async (req) => {
      const actor = requireSession(req);
      const b = await readBody(req);
      switch (b.kind) {
        case "enroll-person": {
          // Privileged: goes through dual-control. Returns a PENDING change; a
          // separated admin must approve via /v1/changes/:id/approve.
          const out = auth.proposeChange(actor, "enroll", b.payload || b);
          await persistAuth();
          await audit.append("grant.enroll.propose", out.summary, { proposer: `${actor.orgId}/${actor.userId}`, changeId: out.id });
          return { kind: "enroll-person", dualControl: true, pending: out,
            note: "proposed — awaiting a SEPARATED admin's approval (one it-admin AND one compliance-officer)" };
        }
        case "device": {
          if (!subHost) throw new HttpError(409, "no_seat_host", "no master configured — the seat/device host is not wired");
          const res = await subHost.grantDevice({ label: b.label, expires: b.expires }, actor);
          return { kind: "device", ...res };
        }
        case "compartment":
          throw new HttpError(400, "wrong_seam",
            "Chinese-wall compartment binds are DECLARED in Ezekiel1 (S.bindings), not here; see integration §5.2");
        default:
          throw new HttpError(400, "invalid_request", `unknown grant kind '${b.kind}' (enroll-person | device)`);
      }
    }],

    // revokeAccess — the mirror fail-closed verb (§5.3).
    ["POST", /^\/v1\/revoke$/, async (req) => {
      const actor = requireSession(req);
      const b = await readBody(req);
      switch (b.kind) {
        case "offboard-person": {
          const payload = b.payload || b;
          if (!payload.orgId || !payload.userId) throw new HttpError(400, "invalid_request", "offboard needs orgId + userId");
          const out = auth.proposeChange(actor, "offboard", { orgId: payload.orgId, userId: payload.userId });
          await persistAuth();
          await audit.append("revoke.offboard.propose", out.summary, { proposer: `${actor.orgId}/${actor.userId}`, changeId: out.id });
          return { kind: "offboard-person", dualControl: true, pending: out,
            note: "proposed — awaiting a SEPARATED admin's approval; commit kills live sessions + purges challenges" };
        }
        case "device": {
          if (!subHost) throw new HttpError(409, "no_seat_host", "no master configured — the seat/device host is not wired");
          if (!b.id) throw new HttpError(400, "invalid_request", "device revoke needs the sub id");
          const res = await subHost.revokeDevice(b.id, actor);
          return { kind: "device", ...res };
        }
        case "org-kill": {
          // Whole-org kill: the CRL revokes by master_pub and the control-plane
          // license-binding loop deprovisions every node. This console EMITS the
          // signal; the CRL build + deprovision loop live in the control plane.
          const masterPub = (opts.master && opts.master.masterPublicKey) || null;
          await audit.append("revoke.org-kill", "whole-org kill requested", { actor: `${actor.orgId}/${actor.userId}`, masterPub });
          return { kind: "org-kill", masterPub,
            action: "add masterPub to CRL revoked_master_pub; control-plane license-binding deprovisions all nodes",
            note: "console-side signal only — CRL build + reverify()/deprovision loop live in the control plane" };
        }
        default:
          throw new HttpError(400, "invalid_request", `unknown revoke kind '${b.kind}' (offboard-person | device | org-kill)`);
      }
    }],
  ];

  function status() {
    const snap = auth.snapshot();
    return {
      liveSessions: auth.liveSessionCount(),
      enrollments: (snap.enrollments || []).length,
      pendingChanges: auth.pendingChangeIds().length,
      verifierAvailable: auth.verifierAvailable(),
      seats: subHost ? subHost.status() : null,
      auditIntegrity: audit.verify(),
      auditLength: audit.length(),
      rails: RAILS,
    };
  }

  // ---- the request handler ----------------------------------------------

  async function handler(req, res) {
    const url = new URL(req.url, "http://localhost");
    const path = url.pathname;
    try {
      for (const [method, re, fn] of routes) {
        if (req.method !== method) continue;
        const m = re.exec(path);
        if (!m) continue;
        const out = await fn(req, m);
        return send(res, 200, out);
      }
      return send(res, 404, { error: "not_found", message: `no route for ${req.method} ${path}` });
    } catch (e) {
      if (e instanceof HttpError) return send(res, e.status, { error: e.type, message: e.message });
      if (e instanceof ConsoleAuthError) return send(res, statusForAuthError(e.type), { error: e.type, message: e.message });
      // Fail-closed: an unexpected error is a refusal, not a partial success.
      return send(res, 500, { error: "internal", message: String(e && e.message || e) });
    }
  }

  return {
    handler,
    close: () => persistAuth(),
    _internals: { auth, subHost, audit, store, status },
  };
}

class HttpError extends Error {
  constructor(status, type, message) {
    super(message);
    this.status = status;
    this.type = type;
  }
}

// Map a console-auth error type to an HTTP status. Deny/authz failures are 4xx;
// nothing leaks WHICH internal check failed beyond the machine `type`.
function statusForAuthError(type) {
  switch (type) {
    case "invalid_request": return 400;
    case "not_authorized": return 403;
    case "dual_control":
    case "sod_violation": return 409;
    case "unknown_change": return 404;
    case "not_enrolled":
    case "wrong_key":
    case "bad_signature":
    case "replay":
    case "expired":
    case "unknown_nonce": return 401;
    default: return 400;
  }
}

function send(res, status, body) {
  const json = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "content-length": Buffer.byteLength(json) });
  res.end(json);
}

export { HttpError, RAILS };
export default { createConsoleService };
