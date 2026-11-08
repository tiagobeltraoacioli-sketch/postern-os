// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern SHIELD container — smoke test / demo. No test framework:
//   node enterprise/shield/container/self-check.mjs
// Exits non-zero on failure.

import { createLicenseGate } from "../../features/license-hook.mjs";
import { createAccessGrant, checkedExpiry, GrantRevoked } from "./src/grant-binding.mjs";
import { createShieldContainer, makeDemoSealEngine, ContainerWiped, ScopeViolation } from "./src/shield-container.mjs";
import { createConsiglioBridge } from "./src/consiglio-bridge.mjs";
import { createAccessBroker, AccessRefused } from "./src/access-broker.mjs";
import { buildTransparency, transparencyText, transparencyBanner } from "./src/transparency-hook.mjs";
import { createRealSealEngine, sealEngineAvailable, wasmSealAvailable, sealBinaryAvailable } from "./src/real-seal-engine.mjs";

let failures = 0;
const ok = (cond, msg) => {
  console.log(`${cond ? "  ok  " : " FAIL "} ${msg}`);
  if (!cond) failures++;
};
const threws = (fn, Type) => {
  try {
    fn();
    return false;
  } catch (e) {
    return Type ? e instanceof Type : true;
  }
};

const NOW = new Date("2026-07-12T00:00:00Z");
const MASTER_EXP = "2027-01-11";
const GRANT_EXP = "2026-08-12T00:00:00Z"; // a month out, well within master
const SECRET = new Uint8Array(32).fill(9); // stand-in grant key material

// A verified corporate license gate (offline-verified master token).
const verify = (t) =>
  t === "MASTER-acme" ? { valid: true, orgName: "Acme Ltda.", duns: "00-123-4567", seats: "unlimited", expires: MASTER_EXP } : null;
const gate = createLicenseGate({ masterToken: "MASTER-acme", verify, now: NOW });

// ── 1. Grant binding mirrors postern-policy consent semantics ────────────────
ok(checkedExpiry("", NOW).ok === false, "expiry is REQUIRED (empty => fail-closed)");
ok(checkedExpiry("2026-07-11T00:00:00Z", NOW).ok === false, "past/at-now expiry => fail-closed (strictly-future required)");
ok(checkedExpiry(GRANT_EXP, NOW).ok === true, "a future RFC-3339 expiry is accepted");

const grant = createAccessGrant({ orgId: "acme", employeeId: "ana", subToken: "SUB-ana", expires: GRANT_EXP, grantSecret: SECRET, now: NOW });
ok(grant.isLive(NOW) === true, "fresh grant within expiry is LIVE");
ok(grant.scope === "corporate-container-only", "grant scope is corporate-container-only (no personal fields exist)");
ok(threws(() => createAccessGrant({ orgId: "acme", employeeId: "x", subToken: "s", expires: GRANT_EXP, grantSecret: new Uint8Array(4) })), "grant rejects too-short key material");

// ── 2. Container sealed at rest; key BOUND to the live grant ──────────────────
const audit = [];
const container = createShieldContainer({ grant, sealEngine: makeDemoSealEngine(), audit: (e) => audit.push(e) });
ok(container.usingRealCrypto === false, "demo seal engine reports usingRealCrypto=false (honest — NOT encryption)");
container.unlock(NOW);
container.put("payroll.csv", "salary data", NOW);
ok(threws(() => container.put("../etc/passwd", "nope", NOW), ScopeViolation), "path-escape names are REFUSED (cannot address the personal side / host OS)");
ok(container.names().every((n) => n.startsWith("corp/")), "every item is forced into the corporate namespace (no personal/OS paths)");
const sealed = container.seal(NOW);
ok(sealed && sealed.length > 0 && container.sealedAtRest() !== null, "container seals corporate data at rest");
// The sealed blob must not contain the plaintext in the clear... but the DEMO engine is XOR, so just prove it differs.
ok(!bytesContain(sealed, "salary data"), "demo-sealed blob does not carry the plaintext verbatim");
container.lock();
ok(container.isOpen() === false && container.sealedAtRest() !== null, "lock() drops in-memory plaintext but keeps the sealed-at-rest blob");

// ── 3. Consiglio SUB-token challenge/response gates the broker ────────────────
// A wallet signer stand-in + an injected verifier that accepts it (models the PQ verify).
const walletSigner = {
  sign(challenge, subToken) {
    return { orgId: challenge.orgId, employeeId: challenge.employeeId, nonce: challenge.nonce, publicKey: "PK-ana", signature: "SIG(" + subToken + ")" };
  },
};
const consiglioGood = createConsiglioBridge({
  verifyResponse: (ch, resp) => ({ ok: resp.signature === "SIG(SUB-ana)", employeeId: ch.employeeId, role: "engineer" }),
});
const consiglioNone = createConsiglioBridge(); // no verifier wired

// Broker with NO Consiglio verifier => refuses (fail-closed, honest).
const brokerNoAuth = createAccessBroker({ licenseGate: gate, grant, container, consiglio: consiglioNone, walletSigner, audit: (e) => audit.push(e) });
ok(threws(() => brokerNoAuth.openSession(NOW), AccessRefused), "no Consiglio verifier wired => session refused (PQ signature not checked)");

// Broker with verifier + wallet signer => opens (unlocks the sealed-at-rest container).
const broker = createAccessBroker({ licenseGate: gate, grant, container, consiglio: consiglioGood, walletSigner, audit: (e) => audit.push(e) });
const opened = broker.openSession(NOW);
ok(opened.session && opened.gates.subToken === "ok", "all four gates pass => broker authorizes an SSH/remote session ticket");
ok(opened.session.ticket.kind === "ssh-remote-session" && /operator-run/.test(opened.session.ticket.note), "transport is honest: SSH/remote, server side operator-run (not shipped here)");
ok(container.isOpen() === true, "container is unlocked once the session opens (key derived from live grant)");
ok(bytesEq(container.get("payroll.csv"), "salary data"), "corporate data recovered from rest through the live-grant-derived key");

// Missing wallet signer => refused even with a verifier.
const brokerNoWallet = createAccessBroker({ licenseGate: gate, grant, container, consiglio: consiglioGood });
ok(threws(() => brokerNoWallet.openSession(NOW), AccessRefused), "no wallet signer => cannot answer challenge => refused");

// ── 4. License gate refuses when not corporate/allowed ───────────────────────
const unverifiedGate = createLicenseGate({ masterToken: "MASTER-acme", now: NOW }); // no verifier => unverified
const brokerBadLicense = createAccessBroker({ licenseGate: unverifiedGate, grant, container, consiglio: consiglioGood, walletSigner });
const badAuth = brokerBadLicense.authorize(NOW);
ok(badAuth.allowed === false && badAuth.gate === "license", "unverified enterprise license => access refused at the license gate");

// ── 5. DE-PROVISIONING = LEAVING: revoke => refuse + self-wipe ────────────────
// A fresh grant+container so we can revoke without disturbing the open session above.
const grant2 = createAccessGrant({ orgId: "acme", employeeId: "bruno", subToken: "SUB-bruno", expires: GRANT_EXP, grantSecret: new Uint8Array(32).fill(7), now: NOW });
const container2 = createShieldContainer({ grant: grant2, sealEngine: makeDemoSealEngine() });
container2.unlock(NOW);
container2.put("deals.txt", "confidential", NOW);
container2.seal(NOW);

grant2.revoke("admin de-provisioned Bruno");
ok(grant2.isLive(NOW) === false, "revocation is honored (monotonic, never given)");
ok(threws(() => grant2.releaseKeyMaterial(NOW), GrantRevoked), "revoked grant refuses to release key material => sealed data unreadable");
ok(threws(() => container2.unlock(NOW), GrantRevoked), "revoked grant cannot unlock the container (key cannot be re-derived)");

const enf = container2.enforceOrWipe(NOW);
ok(enf.allowed === false && enf.wiped && enf.wiped.event === "container.self_wipe", "boundary re-check on a revoked grant SELF-WIPES the corporate data");
ok(enf.wiped.personalUntouched === true && enf.wiped.scope === "corporate-container-only", "self-wipe is corporate-scope only; personal side untouched");
ok(container2.isWiped() && container2.sealedAtRest() === null, "after self-wipe the sealed corporate blob is gone");
ok(threws(() => container2.get("deals.txt"), ContainerWiped), "a wiped container refuses all access");

// Expiry-driven de-provisioning (offline, local clock) also self-wipes.
const LATER = new Date("2026-09-01T00:00:00Z"); // past GRANT_EXP
const grant3 = createAccessGrant({ orgId: "acme", employeeId: "cara", subToken: "SUB-cara", expires: GRANT_EXP, grantSecret: new Uint8Array(32).fill(3) });
const container3 = createShieldContainer({ grant: grant3 });
ok(grant3.isLive(LATER) === false, "expiry past the local clock => grant no longer live (best-effort offline revocation)");
const enf3 = container3.enforceOrWipe(LATER);
ok(enf3.allowed === false && enf3.wiped, "expired grant self-wipes at the next boundary");

// Revalidate on the earlier OPEN session after revoking THAT grant tears it down.
grant.revoke("de-provision Ana too");
const reval = broker.revalidate(NOW);
ok(reval.stillValid === false && broker.hasSession() === false, "a mid-session revocation is caught at revalidate: session torn down");

// ── 6. Transparency hook: honest by default; DLP disclosure injected ─────────
const t0 = buildTransparency({ gate });
ok(t0.dlp.injected === false, "no DLP layer wired => disclosure marked NOT injected (fail-honest)");
ok(/UNKNOWN/i.test(t0.dlp.retention), "retention posture stated UNKNOWN, never faked as 'nothing logged'");
ok(t0.container.refusals.some((r) => /100% private|fully secure/i.test(r)), "refuses to claim '100% private' / 'fully secure'");
ok(t0.container.neverSurveilled.length >= 1 && t0.container.boundaryHonesty.some((s) => /rooted/i.test(s)), "states personal side untouched AND that a rooted phone defeats it");
ok(/never touches your personal/i.test(transparencyBanner({ gate })), "banner discloses corporate-only scope + personal side untouched");

const injectedDlp = {
  disclosure: () => ({
    summary: "Acme logs corporate-container provisioning + access events; message/file bodies are sealed and not read.",
    employerVisible: ["Which corporate items exist (names, sizes)", "Session open/close times"],
    logged: ["Provisioning and de-provisioning actions", "Access-broker authorize/refuse events"],
    retention: "Corporate access logs retained 180 days for security.",
    notCollected: ["Anything on your personal side", "Your location"],
    contact: "dpo@acme.example",
  }),
};
const t1 = buildTransparency({ gate, injectedDlp });
ok(t1.dlp.injected === true && t1.dlp.source === "shield-dlp-layer", "an injected DLP disclosure is used when present (text owned by the DLP dev)");
ok(t1.dlp.notCollected.includes("Your location"), "DLP-owned disclosure text flows through untouched");

// ── 7. Rails: honest labels, no forbidden claims ─────────────────────────────
ok(grant.enforcement.osEnforced === false && /not an OS sandbox or kernel boundary/.test(grant.enforcement.label), "enforcement is by-construction, explicitly NOT a kernel boundary");
const corpus = transparencyText({ gate }) + transparencyText({ gate, injectedDlp });
ok(!/BABA\s*YAGA/i.test(corpus) && !/Postern OS/.test(corpus), "no forbidden strings ('BABA YAGA', 'Postern OS') in employee-facing text");
// The honest text NAMES these phrases only to DENY them; guard against the
// affirmative over-claim (e.g. "is fully secure", "guaranteed private"), not the
// disclaimer. Every occurrence here must sit in a negated/refusal context.
const affirmativeOverclaim = /\bis (fully secure|unbreakable|100% (secure|private))\b|guarantee[ds]? (complete |total )?(privacy|security)/i;
ok(!affirmativeOverclaim.test(corpus), "no AFFIRMATIVE over-claim (the phrases appear only inside honest disclaimers)");
ok(/do NOT claim/i.test(corpus) && /not unbreakable/i.test(corpus), "the over-claim phrases are present ONLY as explicit refusals");

// ── 8. REAL seal engine: canonical Postern seal round-trip + revoke⇒unreadable ─
// Wires the container to the REAL seal — postern-core XChaCha20-Poly1305 (v2,
// key-committing, context-bound) with an Argon2id at-rest key — REPLACING the
// labelled demo engine. createRealSealEngine() PREFERS the in-process WASM
// backend (../seal-wasm/, key never leaves the process) and falls back to the
// ../seal/ CLI binary (prototype-only: key crosses a process boundary). It runs
// only when a real backend is built; on a checkout without either we say so
// honestly and skip (never a silent pass, never a faked claim of real crypto).
if (!sealEngineAvailable()) {
  console.log(
    "\n[real-seal] no real seal backend built — skipping the REAL seal round-trip.\n" +
      "            PREFERRED (in-process, key never leaves the process):\n" +
      "              (cd enterprise/shield/container && ./build-wasm.sh)\n" +
      "            Fallback (CLI subprocess, prototype-only key handling):\n" +
      "              (cd enterprise/shield/container/seal && cargo build --release)\n" +
      "            The 40 checks above used the labelled NON-CRYPTO demo engine, honestly."
  );
} else {
  const realEngine = createRealSealEngine();
  // Honest disclosure of the active backend. WASM = in-process (key never leaves
  // the process); CLI = prototype-only (key crosses a process boundary).
  console.log(
    `\n[real-seal] backend = ${realEngine.__backend} ` +
      (realEngine.__backend === "wasm"
        ? "(IN-PROCESS: 32-byte key stays in this process's wasm memory, no pipe)"
        : "(CLI subprocess fallback: PROTOTYPE-ONLY, key crosses a process boundary — build the wasm module to close this gap)") +
      (wasmSealAvailable() ? "" : "   [wasm module not built]") +
      (sealBinaryAvailable() ? "" : "   [cli binary not built]")
  );
  ok(realEngine.__real === true && realEngine.__demo === false, "real seal engine present (postern-core XChaCha20-Poly1305 + Argon2id)");

  const grantR = createAccessGrant({ orgId: "acme", employeeId: "dora", subToken: "SUB-dora", expires: GRANT_EXP, grantSecret: new Uint8Array(32).fill(11), now: NOW });
  const containerR = createShieldContainer({ grant: grantR, sealEngine: realEngine });
  ok(containerR.usingRealCrypto === true, "container with the real engine reports usingRealCrypto=true (honest — this IS encryption)");

  containerR.unlock(NOW);
  containerR.put("payroll.csv", "salary data", NOW);
  const sealedR = containerR.seal(NOW);
  ok(sealedR && sealedR[0] === 0x02, "at-rest blob is the canonical Postern v2 seal (version byte 0x02, key-committing, context-bound)");
  ok(!bytesContain(sealedR, "salary data"), "REAL-sealed blob does NOT carry the plaintext (genuine AEAD confidentiality, not a demo XOR)");

  containerR.lock();
  ok(containerR.isOpen() === false && containerR.sealedAtRest() !== null, "real container locks: plaintext dropped, sealed-at-rest blob kept");
  containerR.unlock(NOW); // key re-derived (Argon2id) from the LIVE grant material
  ok(bytesEq(containerR.get("payroll.csv"), "salary data"), "REAL round-trip: corporate data recovered through the live-grant-derived Argon2id key");

  // Capture the at-rest blob, THEN de-provision. The grant now refuses to
  // release key material, so the Argon2id key can never be re-derived.
  const atRest = containerR.sealedAtRest();
  containerR.lock();
  grantR.revoke("admin de-provisioned Dora");
  ok(threws(() => containerR.unlock(NOW), GrantRevoked), "revoked grant cannot re-derive the key => real container refuses to unlock");

  // Prove revoke⇒unreadable at the crypto layer: without the grant-derived key
  // the REAL AEAD blob is inert. A correctly-shaped-but-wrong key (all anyone can
  // form once the grant is revoked) fails the key-commitment + AEAD check.
  const wrongKey = new Uint8Array(32).fill(0xab);
  ok(threws(() => realEngine.open(wrongKey, atRest)), "revoke⇒unreadable: the real AEAD blob will not open without the grant-derived key");

  // The boundary re-check still self-wipes the corporate bytes (same policy, real seal).
  const enfR = containerR.enforceOrWipe(NOW);
  ok(enfR.allowed === false && enfR.wiped && enfR.wiped.personalUntouched === true, "revoked real container self-wipes corporate data; personal side untouched");
}

console.log("\n--- transparency (no DLP layer wired) ---\n" + transparencyText({ gate }));

if (failures) {
  console.error(`\n${failures} check(s) failed`);
  process.exit(1);
}
console.log("\nAll checks passed.");

// ── helpers ──────────────────────────────────────────────────────────────────
function bytesContain(bytes, str) {
  const needle = new TextEncoder().encode(str);
  outer: for (let i = 0; i + needle.length <= bytes.length; i++) {
    for (let j = 0; j < needle.length; j++) if (bytes[i + j] !== needle[j]) continue outer;
    return true;
  }
  return false;
}
function bytesEq(bytes, str) {
  if (!bytes) return false;
  const b = new TextEncoder().encode(str);
  if (bytes.length !== b.length) return false;
  for (let i = 0; i < b.length; i++) if (bytes[i] !== b[i]) return false;
  return true;
}
