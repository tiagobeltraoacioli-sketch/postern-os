#!/usr/bin/env node
// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern CLOUD hosted services — smoke test / self-check. No test framework:
//   node enterprise/cloud/services/self-check.mjs
// Exits non-zero on any failure. Spins each service up on an ephemeral port and
// drives it over real HTTP with the built-in fetch.

"use strict";

import crypto from "node:crypto";
import { canonicalJson, resolveAllowedOrigin, sendJSON, DEFAULT_DENY_ORIGIN } from "./src/common.mjs";

let failures = 0;
const ok = (cond, msg) => {
  console.log(`${cond ? "  ok  " : " FAIL "} ${msg}`);
  if (!cond) failures++;
};

/* ---- tiny Ed25519 helpers mirroring enterprise/licensing (raw base64) ---- */
const SPKI = Buffer.from("302a300506032b6570032100", "hex");
const PKCS8 = Buffer.from("302e020100300506032b657004220420", "hex");
function genKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const x = publicKey.export({ format: "jwk" }).x;
  const d = privateKey.export({ format: "jwk" }).d;
  return {
    publicKey: Buffer.from(x, "base64url").toString("base64"),
    privateKey: Buffer.from(d, "base64url").toString("base64"),
  };
}
function signToken(privB64, payload) {
  const der = Buffer.concat([PKCS8, Buffer.from(privB64, "base64")]);
  const key = crypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  const sig = crypto.sign(null, Buffer.from(canonicalJson(payload), "utf8"), key).toString("base64");
  return { payload, sig };
}

async function serve(createServer) {
  const server = createServer();
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const port = server.address().port;
  return { base: `http://127.0.0.1:${port}`, close: () => new Promise((r) => server.close(r)) };
}
async function req(base, method, path, { token, body } = {}) {
  const headers = { "content-type": "application/json" };
  if (token) headers.authorization = "Bearer " + token;
  const res = await fetch(base + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  let json = null;
  try { json = await res.json(); } catch {}
  return { status: res.status, json };
}

const NOW = Math.floor(Date.now() / 1000);
const YEAR = 365 * 24 * 3600;
const vendor = genKeypair();
const org = genKeypair();

const masterPayload = {
  v: 1, typ: "master", tier: "corporate-master", duns: "123456789",
  seats: "unlimited", iat: NOW - 10, exp: NOW + YEAR, master_pub: org.publicKey,
};
const masterToken = signToken(vendor.privateKey, masterPayload);
const subPayload = { v: 1, typ: "sub", master_pub: org.publicKey, sub: "Ana — Eng", iat: NOW - 10, exp: NOW + YEAR };
const subToken = signToken(org.privateKey, subPayload);

// Env must be set BEFORE importing the services (they read env at module load).
process.env.VENDOR_PUBLIC_KEY = vendor.publicKey;
process.env.ADMIN_TOKEN = "admin-secret-token";
process.env.ALLOWED_ORIGIN = "*";

async function main() {
  /* ============================ LICENSE SERVICE ============================ */
  console.log("\n--- license-verification service ---");
  const lic = await import("./src/license-service.mjs");
  const L = await serve(lic.createServer);

  let r = await req(L.base, "GET", "/v1/posture");
  ok(r.status === 200 && r.json.posture.service === "postern-cloud-license", "posture served; correct service id");
  ok(/less private/i.test(r.json.posture.lessPrivateThan) || r.json.posture.lessPrivateThan.length > 0, "posture states the more-private alternative");
  ok(r.json.posture.cannotSee.some((s) => /signing key/i.test(s)), "posture: cannot see any signing key");

  r = await req(L.base, "GET", "/v1/vendor-key");
  ok(r.status === 200 && r.json.vendor_public_key === vendor.publicKey, "vendor-key endpoint returns the configured public key");

  r = await req(L.base, "POST", "/v1/verify", { body: { master: masterToken } });
  ok(r.status === 200 && r.json.state === "in-eval" && r.json.tier === "corporate-master", "master-only verify => in-eval (corporate 'free now' window)");
  ok(/offline/i.test(r.json.disclosure), "verify answer carries the honest offline-is-more-private disclosure");

  r = await req(L.base, "POST", "/v1/verify", { body: { master: masterToken, sub: subToken } });
  ok(r.status === 200 && r.json.state === "in-eval" && r.json.level === "sub", "master+sub verify => in-window at sub level (inherits corporate 'in-eval' tier)");

  const tampered = { payload: { ...subPayload, sub: "Attacker" }, sig: subToken.sig };
  r = await req(L.base, "POST", "/v1/verify", { body: { master: masterToken, sub: tampered } });
  ok(r.status === 200 && r.json.state === "invalid", "tampered sub token => invalid (signature check holds)");

  r = await req(L.base, "POST", "/v1/revocations", { body: { sub: subToken, reason: "leaked" } });
  ok(r.status === 401, "revocation write without admin bearer => 401");
  r = await req(L.base, "POST", "/v1/revocations", { token: "admin-secret-token", body: { sub: subToken, reason: "leaked" } });
  // The revocation service returns { ok, added, counts:{hashes,jti,master_pub} }.
  // Revoking a sub by its token hashes it, so `counts.hashes` is the added tally.
  ok(r.status === 200 && r.json.ok === true && r.json.counts.hashes === 1, "admin can add a revocation");
  r = await req(L.base, "POST", "/v1/verify", { body: { master: masterToken, sub: subToken } });
  ok(r.status === 200 && r.json.state === "revoked", "a revoked sub now verifies as revoked (was valid before)");
  r = await req(L.base, "GET", "/v1/revocations");
  // GET returns arrays keyed by revocation kind: { hashes[], jti[], master_pub[] }.
  ok(r.status === 200 && r.json.hashes.length === 1, "revocation list is publicly readable");

  const expiredMaster = signToken(vendor.privateKey, { ...masterPayload, iat: NOW - 2 * YEAR, exp: NOW - YEAR });
  r = await req(L.base, "POST", "/v1/verify", { body: { master: expiredMaster } });
  ok(r.status === 200 && r.json.state === "expired", "an authentic but past-window master => expired (graceful, not a hard error)");

  await L.close();

  /* ===================== CONSOLE SERVICE (client-sign) ===================== */
  console.log("\n--- console backend (client-sign, default) ---");
  const con = await import("./src/console-service.mjs");
  ok(con.DELEGATED === false, "default signing mode is client-sign (server never holds the key)");
  const C = await serve(con.createServer);

  r = await req(C.base, "GET", "/v1/posture");
  ok(r.status === 200 && r.json.posture.cannotSee.some((s) => /private key/i.test(s)), "console posture: client-sign never sees the private key");

  r = await req(C.base, "POST", "/v1/orgs", { body: { orgName: "Acme Ltda.", masterToken } });
  ok(r.status === 200 && r.json.signing_mode === "client-sign" && r.json.admin_token, "org registers with a verified master; gets an admin token");
  const admin = r.json.admin_token;

  r = await req(C.base, "POST", "/v1/orgs", { body: { orgName: "Forged", masterToken: { payload: masterPayload, sig: "AAAA" } } });
  ok(r.status === 400, "a forged master token is rejected at workspace registration");

  r = await req(C.base, "POST", "/v1/roster", { token: admin, body: { label: "Ana — Eng" } });
  ok(r.status === 200 && r.json.status === "pending-signature" && r.json.toSign.master_pub === org.publicKey, "roster add returns claims to sign locally (no token yet)");
  const rid = r.json.id;
  const toSign = r.json.toSign;

  // The admin signs LOCALLY with the org master key, uploads only the token.
  const localSigned = signToken(org.privateKey, toSign);
  r = await req(C.base, "POST", `/v1/roster/${rid}/token`, { token: admin, body: { signedToken: localSigned } });
  ok(r.status === 200 && r.json.status === "active" && r.json.signed === true, "client-signed token attaches and activates the roster entry");

  const wrongKey = genKeypair();
  const badSigned = signToken(wrongKey.privateKey, toSign);
  r = await req(C.base, "POST", "/v1/roster", { token: admin, body: { label: "Bruno" } });
  const rid2 = r.json.id;
  r = await req(C.base, "POST", `/v1/roster/${rid2}/token`, { token: admin, body: { signedToken: { ...badSigned, payload: { ...toSign, sub: "Bruno" } } } });
  ok(r.status === 400, "a token NOT signed by the org master key is refused");

  r = await req(C.base, "POST", `/v1/roster/${rid}/mint`, { token: admin, body: { masterPrivateKey: org.privateKey } });
  ok(r.status === 403, "server-side (delegated) minting is refused in client-sign mode");

  r = await req(C.base, "GET", "/v1/roster", { token: admin });
  ok(r.status === 200 && r.json.roster.find((x) => x.id === rid).status === "active", "roster lists the active member");

  r = await req(C.base, "POST", `/v1/roster/${rid}/revoke`, { token: admin });
  ok(r.status === 200 && r.json.status === "revoked", "a roster entry can be revoked");

  r = await req(C.base, "GET", "/v1/roster");
  ok(r.status === 401, "roster access requires the org admin bearer");

  await C.close();

  /* ===================== CONSOLE SERVICE (delegated) ====================== */
  console.log("\n--- console backend (delegated — disclosed regression) ---");
  process.env.CONSOLE_SIGNING_MODE = "delegated";
  const conD = await import("./src/console-service.mjs?delegated");
  ok(conD.DELEGATED === true, "delegated mode is active when CONSOLE_SIGNING_MODE=delegated");
  ok(conD.POSTURE.canSee.some((s) => /master PRIVATE KEY/i.test(s)), "delegated posture DISCLOSES the operator sees the master key at mint time");
  const D = await serve(conD.createServer);
  r = await req(D.base, "POST", "/v1/orgs", { body: { orgName: "Acme Ltda.", masterToken } });
  const adminD = r.json.admin_token;
  r = await req(D.base, "POST", "/v1/roster", { token: adminD, body: { label: "Ana — Eng" } });
  const ridD = r.json.id;
  r = await req(D.base, "POST", `/v1/roster/${ridD}/mint`, { token: adminD, body: { masterPrivateKey: org.privateKey } });
  ok(r.status === 200 && r.json.signed === true && r.json.token && r.json.token.sig, "delegated mint produces a signed sub token server-side");
  ok(/promise, not a proof|saw your master private key/i.test(r.json.disclosure), "delegated mint response discloses the key was seen (a promise, not a proof)");
  await D.close();

  /* ============================= COMMS RELAY ============================== */
  console.log("\n--- comms relay (transport only, E2EE bodies opaque) ---");
  const relay = await import("./src/relay-service.mjs");
  const R = await serve(relay.createServer);

  r = await req(R.base, "GET", "/v1/posture");
  ok(r.status === 200 && r.json.posture.cannotSee.some((s) => /PLAINTEXT/i.test(s)), "relay posture: cannot see message plaintext (E2EE opaque)");
  ok(r.json.posture.canSee.some((s) => /RECIPIENT/i.test(s)) && r.json.posture.metadataExposed.some((s) => /social graph/i.test(s)), "relay posture DISCLOSES routing metadata / social-graph exposure");

  r = await req(R.base, "POST", "/auth/register", { body: { label: "Ana device" } });
  const A = r.json;
  r = await req(R.base, "POST", "/auth/register", {});
  const B = r.json;
  ok(A.routing_id && A.token && B.routing_id, "two clients register and get routing ids + tokens");

  const CIPHER = Buffer.from("this-would-be-a-megolm-ciphertext-blob").toString("base64");
  r = await req(R.base, "POST", "/v1/send", { token: A.token, body: { to: B.routing_id, ciphertext: CIPHER } });
  ok(r.status === 200 && r.json.queued === true && r.json.sealed === false, "A sends an opaque blob to B (unsealed)");

  r = await req(R.base, "GET", "/v1/inbox", { token: B.token });
  ok(r.status === 200 && r.json.messages.length === 1 && r.json.messages[0].ciphertext === CIPHER, "B collects the exact opaque ciphertext back");
  ok(r.json.messages[0].from === A.routing_id, "unsealed message carries the sender routing id (metadata the relay saw)");
  r = await req(R.base, "GET", "/v1/inbox", { token: B.token });
  ok(r.status === 200 && r.json.messages.length === 0, "deliver-then-drop: the mailbox is empty on the second poll");

  r = await req(R.base, "POST", "/v1/send", { token: A.token, body: { to: B.routing_id, ciphertext: CIPHER, sealedSender: true } });
  ok(r.status === 200 && r.json.sealed === true, "A sends a sealed-sender blob");
  r = await req(R.base, "GET", "/v1/inbox", { token: B.token });
  ok(r.json.messages.length === 1 && r.json.messages[0].from === null, "sealed message reaches B with from:null (relay never saw the sender)");

  r = await req(R.base, "POST", "/v1/send", { token: A.token, body: { to: "rid_nonexistent", ciphertext: CIPHER } });
  ok(r.status === 404, "sending to an unknown routing id is refused honestly");
  r = await req(R.base, "POST", "/v1/send", { body: { to: B.routing_id, ciphertext: CIPHER } });
  ok(r.status === 401, "sending without a bearer token is unauthorized");

  await R.close();

  /* ===== SVC-2: CORS is deny-by-default, never "*" unless explicit ===== */
  console.log("\n--- SVC-2: ALLOWED_ORIGIN fail-closed (deny-by-default, never '*') ---");
  ok(resolveAllowedOrigin("").origin !== "*", "unset ALLOWED_ORIGIN does NOT default to '*'");
  ok(resolveAllowedOrigin("").origin === "http://localhost" && resolveAllowedOrigin(undefined).origin === "http://localhost", "unset/blank ALLOWED_ORIGIN falls back to localhost-only (deny cross-origin)");
  ok(resolveAllowedOrigin("").explicit === false, "an unset origin is flagged non-explicit");
  ok(resolveAllowedOrigin("*").wildcard === true && resolveAllowedOrigin("*").explicit === true, "'*' is honored ONLY when set explicitly");
  ok(resolveAllowedOrigin("https://console.example").origin === "https://console.example", "an explicit origin passes through unchanged");

  // Regression: sendJSON's own DEFAULT must be deny too. It used to default
  // allowedOrigin to "*", which silently defeated the fail-closed design for
  // any call site that omitted the argument.
  const mockRes = () => ({
    status: 0, headers: null, body: null, headersSent: false,
    writeHead(status, headers) { this.status = status; this.headers = headers; },
    end(body) { this.body = body; },
  });
  const omitted = mockRes();
  sendJSON(omitted, 200, { ok: true }); // origin argument deliberately omitted
  ok(omitted.headers["access-control-allow-origin"] !== "*", "sendJSON with the origin argument OMITTED does not emit '*'");
  ok(omitted.headers["access-control-allow-origin"] === DEFAULT_DENY_ORIGIN, "sendJSON's omitted-origin default is the deny origin (localhost-only)");
  const explicitWildcard = mockRes();
  sendJSON(explicitWildcard, 200, { ok: true }, "*");
  ok(explicitWildcard.headers["access-control-allow-origin"] === "*", "an EXPLICIT '*' (operator-set) still passes through sendJSON");

  /* ===== SVC-1: a missing VENDOR_PUBLIC_KEY => the service REFUSES to start ===== */
  console.log("\n--- SVC-1: missing VENDOR_PUBLIC_KEY => fail-closed refusal to start ---");
  delete process.env.VENDOR_PUBLIC_KEY; // re-import fresh (query-buster) with the key absent
  const licNoKey = await import("./src/license-service.mjs?nokey");
  let licRefused = false;
  try { licNoKey.createServer(); } catch (e) { licRefused = /VENDOR_PUBLIC_KEY is MANDATORY/.test(e.message); }
  ok(licRefused, "license-service.createServer() REFUSES to start with no vendor key (fail-closed, not fail-open)");
  const conNoKey = await import("./src/console-service.mjs?nokey");
  let conRefused = false;
  try { conNoKey.createServer(); } catch (e) { conRefused = /VENDOR_PUBLIC_KEY is MANDATORY/.test(e.message); }
  ok(conRefused, "console-service.createServer() REFUSES to start with no vendor key (forged masters can't be admitted unverified)");

  console.log(
    "\n" +
    (failures ? `${failures} check(s) FAILED` : "All checks passed.") +
    "\n\nHONEST POSTURE (rendered):\n" +
    (await import("./src/common.mjs")).postureText(relay.POSTURE),
  );
  if (failures) process.exit(1);
}

main().catch((e) => { console.error(e); process.exit(1); });
