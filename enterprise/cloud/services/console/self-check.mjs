// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Consiglio console-auth smoke test / demo. No framework:
//   node enterprise/cloud/services/console/self-check.mjs
// Non-zero exit on failure. STATUS: reference prototype, UNAUDITED.
//
// It exercises the console orchestration (session id+TTL, dual-control + SoD,
// offboard-revocation, durable snapshot/restore) with an INJECTED stub verifier,
// then — if the real `consiglio-verify` binary is built — runs a REAL hybrid-PQ
// login end-to-end through the Rust bridge (signing with `consiglio-sign`),
// proving the JS `"SIG(...)"` stub is gone.

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { createConsoleAuth, ConsoleAuthError } from "./console-auth.mjs";
import { createConsiglioVerifier } from "./consiglio-verifier.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const NOW = "2026-07-12T00:00:00Z";

let failures = 0;
const ok = (cond, msg) => {
  console.log(`${cond ? "  ok  " : " FAIL "} ${msg}`);
  if (!cond) failures++;
};
const threwType = (fn, type) => {
  try { fn(); return false; }
  catch (e) { return e instanceof ConsoleAuthError && e.type === type; }
};

// An injected stub verifier so the orchestration is testable without the binary.
// (It only stands in for the SIGNATURE CHECK; every other rule is real here.)
const stubVerifier = {
  label: "STUB verifier (self-check only — accepts signatureB64 === 'GOOD')",
  available: () => true,
  verify: async (req) => ({ ok: req.signature_b64 === "GOOD" }),
};

const it = { orgId: "acme", userId: "ivan", role: "it-admin" };
const comp = { orgId: "acme", userId: "carol", role: "compliance-officer" };
const eng = { orgId: "acme", userId: "eve", role: "engineer" };

await (async () => {
  const auth = createConsoleAuth({ verifier: stubVerifier, sessionTtlSecs: 100, challengeTtlSecs: 60, now: NOW });
  // Seed the two admins (bootstrap path).
  auth.bootstrapEnroll({ ...it, clearance: 5, publicKeyB64: "IT-KEY" });
  auth.bootstrapEnroll({ ...comp, clearance: 5, publicKeyB64: "COMP-KEY" });

  // 1. Dual-control: a business role cannot even propose.
  ok(threwType(() => auth.proposeChange(eng, "enroll", { orgId: "acme", userId: "dave", role: "finance-analyst", publicKeyB64: "K" }), "not_authorized"),
    "dual-control: a non-admin (engineer) cannot propose a change");

  // 2. Propose an enroll; self-approval and same-side approval are refused.
  const { id } = auth.proposeChange(it, "enroll", { orgId: "acme", userId: "dave", role: "finance-analyst", clearance: 2, publicKeyB64: "DAVE-KEY" });
  ok(threwType(() => auth.approveChange(id, it), "dual_control"), "dual-control: self-approval is refused");
  const it2 = { orgId: "acme", userId: "ian", role: "it-admin" };
  ok(threwType(() => auth.approveChange(id, it2), "sod_violation"), "SoD: two it-admins (same side of the wall) cannot commit");
  ok(auth.enrollment("acme", "dave") === null && auth.pendingChange(id) !== null, "the change is still pending; nothing was enrolled");

  // 3. A separated admin (compliance-officer) commits it.
  const outcome = auth.approveChange(id, comp);
  ok(outcome.applied && auth.enrollment("acme", "dave") !== null, "dual-control: one it-admin + one compliance-officer commits the enroll");
  ok(auth.pendingChange(id) === null, "pending entry is cleared on commit");

  // 4. Login mints a session with an id + TTL (stub signature 'GOOD').
  const ch = auth.issueChallenge("acme", "dave", NOW);
  const session = await auth.verifyLogin(
    { orgId: "acme", userId: "dave", nonceHex: ch.nonceHex, publicKeyB64: "DAVE-KEY", signatureB64: "GOOD" }, ch, NOW);
  ok(typeof session.id === "string" && session.id.length === 32 && session.expiresAt > session.issuedAt, "login mints a session with a 128-bit id + TTL");
  ok(auth.session(session.id, NOW) !== null, "session is retrievable while live");
  ok(auth.session(session.id, "2026-07-13T00:00:00Z") === null, "an EXPIRED session id is rejected (fail-closed)");

  // 5. Replay + wrong-key + bad-signature are fail-closed; a bad sig does NOT burn the nonce.
  const ch2 = auth.issueChallenge("acme", "dave", NOW);
  let badSig = false;
  try { await auth.verifyLogin({ orgId: "acme", userId: "dave", nonceHex: ch2.nonceHex, publicKeyB64: "DAVE-KEY", signatureB64: "BAD" }, ch2, NOW); }
  catch (e) { badSig = e.type === "bad_signature"; }
  ok(badSig, "a bad signature is rejected");
  const retry = await auth.verifyLogin({ orgId: "acme", userId: "dave", nonceHex: ch2.nonceHex, publicKeyB64: "DAVE-KEY", signatureB64: "GOOD" }, ch2, NOW);
  ok(retry.id, "a bad signature did NOT burn the nonce — a good retry on the same challenge works");

  // 6. Offboard via dual-control revokes live sessions immediately.
  const sBefore = auth.liveSessionCount(NOW);
  const off = auth.proposeChange(comp, "offboard", { orgId: "acme", userId: "dave" });
  const offOutcome = auth.approveChange(off.id, it);
  ok(offOutcome.applied && offOutcome.sessionsRevoked >= 1, "offboard (dual-control) removes the user AND revokes live sessions");
  ok(auth.liveSessionCount(NOW) < sBefore && auth.enrollment("acme", "dave") === null, "the offboarded user is gone and logged out");

  // 7. Durability: snapshot -> JSON -> restore preserves enrollment + sessions.
  const itSession = await (async () => {
    const c = auth.issueChallenge("acme", "ivan", NOW);
    return auth.verifyLogin({ orgId: "acme", userId: "ivan", nonceHex: c.nonceHex, publicKeyB64: "IT-KEY", signatureB64: "GOOD" }, c, NOW);
  })();
  const snap = JSON.parse(JSON.stringify(auth.snapshot()));
  const restored = createConsoleAuth({ verifier: stubVerifier, sessionTtlSecs: 100, state: snap });
  ok(restored.enrollment("acme", "ivan") !== null, "restore: enrollment survives a restart");
  ok(restored.session(itSession.id, NOW) !== null, "restore: a live session survives a restart");
})();

// ---- REAL crypto path (only if the verifier binary is built) ----
function signBinPath() {
  const root = join(__dirname, "..", "..", "..", "..");
  for (const p of [
    join(root, "target", "release", "consiglio-sign"),
    join(root, "target", "debug", "consiglio-sign"),
  ]) if (existsSync(p)) return p;
  return null;
}

await (async () => {
  const verifier = createConsiglioVerifier();
  const signBin = signBinPath();
  if (!verifier.available() || !signBin) {
    console.log("\n  (skipping REAL PQ login: build the bins with " +
      "`cargo build --release --features verifier-bin --bins` in crates/postern-consiglio-auth)");
    // Fail-closed contract: without the binary, verify() MUST throw, never accept.
    const bare = createConsiglioVerifier({ binPath: "/nonexistent/consiglio-verify" });
    let threw = false;
    try { await bare.verify({ public_key_b64: "x", signature_b64: "x", org_id: "a", user_id: "b", nonce_hex: "0".repeat(64), issued_at: 1 }); }
    catch { threw = true; }
    ok(threw && !bare.available(), "fail-closed: with no verifier binary the bridge THROWS (never a signature stub)");
    return;
  }

  const auth = createConsoleAuth({ verifier });
  const issuedAt = 1752300000;
  // Issue a challenge from the store, then sign THAT nonce so the transcript
  // matches, and enroll alice under the public key the signer produced.
  const ch = auth.issueChallenge("acme", "alice", new Date(issuedAt * 1000));
  const signed = spawnSync(signBin, ["acme", "alice", ch.nonceHex, String(ch.issuedAt)], { encoding: "utf8" });
  const req = JSON.parse(signed.stdout.trim());
  auth.bootstrapEnroll({ orgId: "acme", userId: "alice", role: "engineer", clearance: 3, publicKeyB64: req.public_key_b64 });

  const session = await auth.verifyLogin(
    { orgId: "acme", userId: "alice", nonceHex: ch.nonceHex, publicKeyB64: req.public_key_b64, signatureB64: req.signature_b64 },
    ch, new Date(ch.issuedAt * 1000));
  ok(!!session.id, "REAL hybrid-PQ login verifies via the Rust bridge and mints a session");

  // Tampered signature must be rejected by the real verifier.
  const ch3 = auth.issueChallenge("acme", "alice", new Date(issuedAt * 1000));
  const tampered = spawnSync(signBin, ["acme", "alice", ch3.nonceHex, String(ch3.issuedAt), "--tamper"], { encoding: "utf8" });
  const reqT = JSON.parse(tampered.stdout.trim());
  auth.bootstrapEnroll({ orgId: "acme", userId: "alice", role: "engineer", clearance: 3, publicKeyB64: reqT.public_key_b64 });
  let rejected = false;
  try {
    await auth.verifyLogin(
      { orgId: "acme", userId: "alice", nonceHex: ch3.nonceHex, publicKeyB64: reqT.public_key_b64, signatureB64: reqT.signature_b64 },
      ch3, new Date(ch3.issuedAt * 1000));
  } catch (e) { rejected = e.type === "bad_signature"; }
  ok(rejected, "REAL verifier: a TAMPERED signature is rejected (genuine crypto, not a stub)");
})();

if (failures) {
  console.error(`\n${failures} check(s) failed`);
  process.exit(1);
}
console.log("\nAll console-auth checks passed.");
