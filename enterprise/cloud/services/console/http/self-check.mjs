// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Consiglio console HTTP-service end-to-end self-check. No framework:
//   node enterprise/cloud/services/console/http/self-check.mjs
// Non-zero exit on failure. STATUS: reference prototype, UNAUDITED.
//
// It boots the REAL durable HTTP service on an ephemeral port and drives the
// whole release/revocation narrative over HTTP:
//   bootstrap two admins -> wallet login -> session gate -> dual-controlled
//   grant (enroll-person) -> mint a device/seat -> seat meter -> revoke device
//   (CRL serial + deprovision) -> dual-controlled offboard (kills sessions) ->
//   audit chain integrity -> DURABILITY across a restart.
// The signature check is an injected STUB here so the orchestration is testable
// without the native binary; a final section runs the REAL hybrid-PQ login
// through the consiglio-verify binary when it is built (proving no stub).

import http from "node:http";
import { spawnSync } from "node:child_process";
import { existsSync, rmSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";

import { createConsoleService } from "./service.mjs";
import { createConsiglioVerifier } from "../consiglio-verifier.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));

let failures = 0;
const ok = (cond, msg) => {
  console.log(`${cond ? "  ok  " : " FAIL "} ${msg}`);
  if (!cond) failures++;
};

// Stub verifier: only stands in for the SIGNATURE CHECK (accepts 'GOOD'); every
// other rule in the service is real.
const stubVerifier = {
  label: "STUB verifier (self-check only — accepts signatureB64 === 'GOOD')",
  available: () => true,
  verify: async (req) => ({ ok: req.signature_b64 === "GOOD" }),
};

async function startService(opts) {
  const svc = await createConsoleService(opts);
  const server = http.createServer(svc.handler);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address();
  const base = `http://127.0.0.1:${port}`;
  const call = async (method, path, body, token) => {
    const res = await fetch(base + path, {
      method,
      headers: {
        "content-type": "application/json",
        ...(token ? { authorization: `Bearer ${token}` } : {}),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    let json = null;
    try { json = await res.json(); } catch { /* empty */ }
    return { status: res.status, json };
  };
  const stop = () => new Promise((r) => { svc.close().finally(() => server.close(r)); });
  return { call, stop, svc };
}

// Log in a bootstrapped user via challenge -> verify (stub 'GOOD'). Returns token.
async function login(call, orgId, userId, publicKeyB64) {
  const ch = await call("POST", "/v1/login/challenge", { orgId, userId });
  const v = await call("POST", "/v1/login/verify", {
    response: { orgId, userId, nonceHex: ch.json.challenge.nonceHex, publicKeyB64, signatureB64: "GOOD" },
    challenge: ch.json.challenge,
  });
  return v.json && v.json.session ? v.json.session.id : null;
}

const dataDir = join(tmpdir(), `consiglio-http-selfcheck-${process.pid}`);
rmSync(dataDir, { recursive: true, force: true });

const master = { token: "MASTER-DEMO", masterKey: "MK-DEMO", expires: "2026-12-31T00:00:00Z", seats: "unlimited" };

let deprovisioned = [];

// ---------- Main orchestration (stub verifier, durable store) ----------
await (async () => {
  const svc = await startService({
    dataDir, verifier: stubVerifier, sessionTtlSecs: 100, challengeTtlSecs: 60,
    master, onDeprovision: (jti) => { deprovisioned.push(jti); },
  });
  const { call } = svc;

  // 1. Bootstrap the two admins (first-admin seeding).
  const b1 = await call("POST", "/v1/bootstrap-enroll", { orgId: "acme", userId: "ivan", role: "it-admin", clearance: 5, publicKeyB64: "IT-KEY" });
  const b2 = await call("POST", "/v1/bootstrap-enroll", { orgId: "acme", userId: "carol", role: "compliance-officer", clearance: 5, publicKeyB64: "COMP-KEY" });
  ok(b1.status === 200 && b2.status === 200, "bootstrap seeds the two admins");

  // 2. Bootstrap is refused once the org has an admin (first-admin only).
  const b3 = await call("POST", "/v1/bootstrap-enroll", { orgId: "acme", userId: "mallory", role: "it-admin", clearance: 5, publicKeyB64: "M-KEY" });
  ok(b3.status === 403 && b3.json.error === "bootstrap_closed", "bootstrap is refused after the org is seeded (fail-closed)");

  // 3. The session gate: an ungated privileged call is 401.
  const gated = await call("GET", "/v1/status");
  ok(gated.status === 401, "session gate: /v1/status without a Bearer session is refused (401)");

  // 4. Wallet login mints sessions for both admins.
  const itTok = await login(call, "acme", "ivan", "IT-KEY");
  const compTok = await login(call, "acme", "carol", "COMP-KEY");
  ok(!!itTok && !!compTok, "wallet login mints sessions for both admins");
  const statusGated = await call("GET", "/v1/status", undefined, itTok);
  ok(statusGated.status === 200 && statusGated.json.liveSessions >= 2, "a live session unlocks /v1/status; two sessions live");

  // 5. grantAccess enroll-person is dual-controlled: propose (it-admin), self-approve refused, separated approve commits.
  const grant = await call("POST", "/v1/grant", { kind: "enroll-person", payload: { orgId: "acme", userId: "dave", role: "finance-analyst", clearance: 2, publicKeyB64: "DAVE-KEY" } }, itTok);
  ok(grant.status === 200 && grant.json.dualControl && grant.json.pending.id, "grant(enroll-person) proposes a dual-control change (not yet committed)");
  const changeId = grant.json.pending.id;
  const selfApprove = await call("POST", `/v1/changes/${changeId}/approve`, {}, itTok);
  ok(selfApprove.status === 409 && selfApprove.json.error === "dual_control", "self-approval is refused (dual_control)");
  const commit = await call("POST", `/v1/changes/${changeId}/approve`, {}, compTok);
  ok(commit.status === 200 && commit.json.applied, "a SEPARATED admin (compliance) commits the enroll");

  // 6. grantAccess device: mint a seat-consuming sub against the unlimited master.
  const dev1 = await call("POST", "/v1/grant", { kind: "device", label: "dave-laptop" }, itTok);
  ok(dev1.status === 200 && dev1.json.sub && dev1.json.token, "grant(device) mints a sub token (a seat)");
  const st1 = await call("GET", "/v1/status", undefined, itTok);
  ok(st1.json.seats && st1.json.seats.activeSeats === 1 && st1.json.seats.seatLimit === "unlimited", "seat meter counts 1 active seat against the unlimited master");

  // 7. revokeAccess device: revoke -> CRL serial (jti) -> deprovision signal.
  const subId = dev1.json.sub.id;
  const rev = await call("POST", "/v1/revoke", { kind: "device", id: subId }, itTok);
  ok(rev.status === 200 && rev.json.crlSerial, "revoke(device) returns a CRL serial (jti)");
  const st2 = await call("GET", "/v1/status", undefined, itTok);
  ok(st2.json.seats.activeSeats === 0 && st2.json.seats.revokedSerials.includes(rev.json.crlSerial), "revoked sub leaves the seat meter and appears in revokedSerials");
  ok(deprovisioned.includes(rev.json.crlSerial), "revoke ⇒ deprovision: the deprovision hook fired with the CRL serial");

  // 8. revokeAccess offboard-person (dual-control) kills the target's live sessions.
  const daveTok = await login(call, "acme", "dave", "DAVE-KEY");
  ok(!!daveTok, "the enrolled person can log in");
  const off = await call("POST", "/v1/revoke", { kind: "offboard-person", payload: { orgId: "acme", userId: "dave" } }, compTok);
  const offCommit = await call("POST", `/v1/changes/${off.json.pending.id}/approve`, {}, itTok);
  ok(offCommit.status === 200 && offCommit.json.applied && offCommit.json.sessionsRevoked >= 1, "dual-controlled offboard commits and revokes live sessions");
  const daveSession = await call("GET", "/v1/session", undefined, daveTok);
  ok(daveSession.status === 401, "the offboarded user's session is dead (fail-closed)");

  // 9. Audit chain: every grant/revoke logged, chain intact.
  const audit = await call("GET", "/v1/audit", undefined, itTok);
  ok(audit.json.integrity.ok && audit.json.entries.length >= 6, "audit trail is intact (SHAKE-256 chain) and logged every verb");
  const acts = audit.json.entries.map((e) => e.act);
  ok(acts.includes("grant.device") && acts.includes("revoke.device") && acts.includes("change.commit"), "audit recorded grant.device, revoke.device, and the dual-control commit");

  await svc.stop();
})();

// ---------- Durability: a fresh service over the SAME store ----------
await (async () => {
  const svc = await startService({ dataDir, verifier: stubVerifier, sessionTtlSecs: 100, master });
  const { call } = svc;
  // Re-login (sessions may persist, but re-auth is the honest check of enrollment survival).
  const itTok = await login(call, "acme", "ivan", "IT-KEY");
  const st = await call("GET", "/v1/status", undefined, itTok);
  ok(st.status === 200 && st.json.enrollments >= 2, "restart: enrollments survived (restored from the durable store)");
  ok(st.json.seats && st.json.seats.subs.length >= 1, "restart: the sub registry survived");
  ok(st.json.seats.revokedSerials.length >= 1, "restart: the revoked serial survived (CRL feed persists)");
  const audit = await call("GET", "/v1/audit", undefined, itTok);
  ok(audit.json.integrity.ok, "restart: the audit chain restored intact and continues to verify");
  await svc.stop();
})();

rmSync(dataDir, { recursive: true, force: true });

// ---------- REAL hybrid-PQ login (only if the verifier binary is built) ----------
function signBinPath() {
  const root = join(__dirname, "..", "..", "..", "..", "..");
  for (const p of [join(root, "target", "release", "consiglio-sign"), join(root, "target", "debug", "consiglio-sign")]) {
    if (existsSync(p)) return p;
  }
  return null;
}

await (async () => {
  const verifier = createConsiglioVerifier();
  const signBin = signBinPath();
  if (!verifier.available() || !signBin) {
    console.log("\n  (skipping REAL PQ login over HTTP: build the bins with " +
      "`cargo build --release --features verifier-bin --bins` in crates/postern-consiglio-auth)");
    return;
  }
  const rdir = join(tmpdir(), `consiglio-http-selfcheck-real-${process.pid}`);
  rmSync(rdir, { recursive: true, force: true });
  const svc = await startService({ dataDir: rdir, verifier, sessionTtlSecs: 100 });
  const { call } = svc;

  const issuedAt = 1752300000;
  // Issue the challenge from the service, sign THAT nonce with a real wallet key.
  const ch = await call("POST", "/v1/login/challenge", { orgId: "acme", userId: "alice" });
  const nonceHex = ch.json.challenge.nonceHex;
  const issued = ch.json.challenge.issuedAt;
  const signed = spawnSync(signBin, ["acme", "alice", nonceHex, String(issued)], { encoding: "utf8" });
  const req = JSON.parse(signed.stdout.trim());
  // Bootstrap-enroll alice under the real wallet public key.
  await call("POST", "/v1/bootstrap-enroll", { orgId: "acme", userId: "alice", role: "engineer", clearance: 3, publicKeyB64: req.public_key_b64 });

  const v = await call("POST", "/v1/login/verify", {
    response: { orgId: "acme", userId: "alice", nonceHex, publicKeyB64: req.public_key_b64, signatureB64: req.signature_b64 },
    challenge: ch.json.challenge,
  });
  ok(v.status === 200 && v.json.session && v.json.session.id, "REAL hybrid-PQ login verifies over HTTP via the consiglio-verify binary");

  // Tampered signature must be rejected by the real verifier.
  const ch3 = await call("POST", "/v1/login/challenge", { orgId: "acme", userId: "alice" });
  const tampered = spawnSync(signBin, ["acme", "alice", ch3.json.challenge.nonceHex, String(ch3.json.challenge.issuedAt), "--tamper"], { encoding: "utf8" });
  const reqT = JSON.parse(tampered.stdout.trim());
  await call("POST", "/v1/bootstrap-enroll", { orgId: "acme", userId: "alice", role: "engineer", clearance: 3, publicKeyB64: reqT.public_key_b64 });
  const vt = await call("POST", "/v1/login/verify", {
    response: { orgId: "acme", userId: "alice", nonceHex: ch3.json.challenge.nonceHex, publicKeyB64: reqT.public_key_b64, signatureB64: reqT.signature_b64 },
    challenge: ch3.json.challenge,
  });
  ok(vt.status === 401 && vt.json.error === "bad_signature", "REAL verifier over HTTP rejects a TAMPERED signature (genuine crypto, not a stub)");

  await svc.stop();
  rmSync(rdir, { recursive: true, force: true });
})();

if (failures) {
  console.error(`\n${failures} check(s) failed`);
  process.exit(1);
}
console.log("\nAll Consiglio console HTTP-service checks passed.");
