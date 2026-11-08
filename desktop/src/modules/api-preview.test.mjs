// desktop/src/modules/api-preview.test.mjs — run with: node --test desktop/src/modules/
//
// Functional coverage for the api.js PREVIEW ENGINES that previously had only
// their caveat STRINGS asserted (panes.test.mjs / suite.test.mjs). These
// engines only run when there is NO Tauri backend (hasBackend === false — the
// plain-browser preview), so Node can reach and exercise them directly, the
// same surface vault.test.mjs proves. What is pinned here is the HONEST +
// FAIL-CLOSED behaviour of each engine, so a future edit can't quietly:
//
//   * turn the JPEG hygiene scrub into a pass-through (it must actually drop
//     EXIF/APP1/APP2/APP13/COM and keep the image + non-metadata segments),
//     or claim OOXML/PDF were really cleaned (they are simulated reports);
//   * leak a private key out of the keys engine, or stop the WebAuthn-style
//     signCount from advancing (the clone/replay signal);
//   * let the phone-signer pairing persist a device whose SAS the human
//     REFUSED, mint a login grant with no approval frame, or treat a revoked
//     grant as still-allowed;
//   * report a preview attestation as GENUINE, or a PQ signature as verified,
//     when the backend that could check them is absent;
//   * accept a < 12-word mnemonic as a wallet.
//
// Mock-level only: no network, no Tauri, no real backend. ui.js / api.js are
// classic (non-module) browser scripts, loaded via indirect eval over a stub
// window, exactly like the sibling *.test.mjs files.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { webcrypto } from "node:crypto";

if (!globalThis.crypto) globalThis.crypto = webcrypto;
globalThis.window = globalThis;

// ---- minimal localStorage polyfill ----
{
  const mem = new Map();
  globalThis.localStorage = {
    getItem: (k) => (mem.has(k) ? mem.get(k) : null),
    setItem: (k, v) => { mem.set(k, String(v)); },
    removeItem: (k) => { mem.delete(k); },
    clear: () => mem.clear(),
  };
}

const here = path.dirname(fileURLToPath(import.meta.url));
const src = (rel) => readFileSync(path.join(here, rel), "utf8");
const load = (rel) => (0, eval)(src(rel));

load("../ui.js");
load("../api.js"); // no window.__TAURI__ → hasBackend false → preview engines are live
const P = window.Postern;
const UI = P.ui;
const invoke = (cmd, args) => P.api.invoke(cmd, args);

assert.equal(P.api.hasBackend, false, "no backend → this file exercises the preview engines");

// ════════════════════════ HYGIENE — JPEG scrub is REAL ════════════════════
// Build a tiny but structurally-valid JPEG: SOI, an APP1 (EXIF) segment that
// MUST be dropped, an APP0 (JFIF) segment that MUST be kept (not metadata),
// then SOS + entropy-coded image bytes + EOI (everything from SOS is copied
// verbatim). The parser keys on real marker bytes, so this is a faithful
// exercise of the actual scrub, not a shape stub.
function seg(marker, payload) {
  const len = payload.length + 2; // length field counts itself (2 bytes)
  return [0xff, marker, (len >> 8) & 0xff, len & 0xff, ...payload];
}
const EXIF_PAYLOAD = [...UI.utf8("Exif\0\0GPS:secret-location")];
const JFIF_PAYLOAD = [...UI.utf8("JFIF\0")];
const IMAGE_TAIL = [0xff, 0xda, 0x00, 0x08, 0x01, 0x01, 0x00, 0x3f, 0xab, 0xcd, 0xff, 0xd9];

function jpeg(withExif) {
  const bytes = [0xff, 0xd8]; // SOI
  if (withExif) bytes.push(...seg(0xe1, EXIF_PAYLOAD)); // APP1 EXIF — must go
  bytes.push(...seg(0xe0, JFIF_PAYLOAD));               // APP0 JFIF — must stay
  bytes.push(...IMAGE_TAIL);                            // SOS + scan + EOI
  return new Uint8Array(bytes);
}

test("hygiene: JPEG scrub really drops EXIF, keeps the image + non-metadata segments", async () => {
  const dirty = jpeg(true);
  const rep = await invoke("hygiene_scrub", { name: "photo.jpg", bytesB64: UI.toB64(dirty) });
  assert.equal(rep.kind, "jpeg");
  assert.equal(rep.real, true, "JPEG scrub is done locally for real, never a simulated report");
  assert.ok(rep.removed.some((r) => /APP1 \(EXIF\/XMP\)/.test(r)), "reports the removed EXIF segment");
  assert.ok(rep.cleanedB64, "produces a downloadable cleaned file");

  const cleaned = UI.fromB64(rep.cleanedB64);
  const cleanedText = UI.utf8dec(cleaned);
  assert.ok(!cleanedText.includes("GPS:secret-location"), "EXIF payload must be gone from the bytes");
  assert.ok(cleanedText.includes("JFIF"), "the non-metadata JFIF/APP0 segment must survive");
  assert.equal(cleaned[0], 0xff, "still a JPEG (SOI preserved)");
  assert.equal(cleaned[1], 0xd8);
  assert.equal(cleaned[cleaned.length - 1], 0xd9, "EOI + image tail preserved verbatim");
  assert.ok(cleaned.length < dirty.length, "cleaned file is smaller — bytes actually removed");
});

test("hygiene: a JPEG with no metadata reports already-clean, not a false removal", async () => {
  const rep = await invoke("hygiene_scrub", { name: "clean.jpg", bytesB64: UI.toB64(jpeg(false)) });
  assert.equal(rep.real, true);
  assert.equal(rep.removed.length, 0);
  assert.match(rep.note, /already clean/);
});

test("hygiene: OOXML/PDF are HONESTLY simulated reports (real:false), not faked clean files", async () => {
  const ooxml = await invoke("hygiene_scrub", { name: "doc.docx", bytesB64: UI.toB64(new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0, 0])) });
  assert.equal(ooxml.kind, "ooxml");
  assert.equal(ooxml.real, false, "no backend → cannot really scrub OOXML, must not claim it did");
  assert.ok(!ooxml.cleanedB64, "a simulated report must not hand back a 'cleaned' file");
  assert.match(ooxml.note, /simulated report/);

  const pdf = await invoke("hygiene_scrub", { name: "doc.pdf", bytesB64: UI.toB64(UI.utf8("%PDF-1.7\n...")) });
  assert.equal(pdf.kind, "pdf");
  assert.equal(pdf.real, false);
  assert.match(pdf.note, /simulated report/);
});

test("hygiene: fails closed on an unsupported file type — never passes it through as 'cleaned'", async () => {
  await assert.rejects(
    invoke("hygiene_scrub", { name: "mystery.bin", bytesB64: UI.toB64(new Uint8Array([0x00, 0x01, 0x02, 0x03])) }),
    /unsupported file type/,
  );
});

// ════════════════════════ KEYS — real ES256, no key leak ══════════════════
test("keys: real ES256 create/sign/verify roundtrip; private key never leaves the engine", async () => {
  localStorage.removeItem("postern.preview.keys");

  await assert.rejects(invoke("keys_create", { rpId: "  " }), /relying party id required/);

  const cred = await invoke("keys_create", { rpId: "GitHub.com" });
  assert.equal(cred.rpId, "github.com", "rpId is normalised to lowercase");
  assert.ok(!("priv" in cred), "keys_create must never return the private key");

  const list = await invoke("keys_list");
  assert.equal(list.length, 1);
  assert.ok(!("priv" in list[0]), "keys_list must never leak the private key");

  const a = await invoke("keys_sign", { credentialId: cred.credentialId, challenge: "chal-1" });
  assert.equal(a.verifiedLocally, true, "the signature verifies against its own public key");
  assert.equal(a.signCount, 1);

  const b = await invoke("keys_sign", { credentialId: cred.credentialId, challenge: "chal-2" });
  assert.equal(b.signCount, 2, "signCount advances — the clone/replay signal must keep moving");
  assert.notEqual(a.signature, b.signature, "a fresh challenge yields a fresh signature");

  await assert.rejects(invoke("keys_sign", { credentialId: "deadbeef", challenge: "x" }), /credential not found/);

  await invoke("keys_remove", { credentialId: cred.credentialId });
  assert.equal((await invoke("keys_list")).length, 0);
});

// ═════════════ PHONE-AS-SIGNER — fail-closed human gate + revocation ═══════
test("pair/login/grants: refused SAS persists nothing; frameless login mints nothing; revoke denies", async () => {
  // begin → respond → REFUSE the SAS: nothing may be persisted (fail-closed).
  await invoke("pair_begin", { nickname: "phone-A" });
  await invoke("pair_respond", { pairingInitHex: UI.randHex(1600) });
  await assert.rejects(invoke("pair_confirm", { userConfirmed: false }), /NOT confirmed/);
  assert.equal((await invoke("pair_list")).pairings.length, 0, "a refused SAS pins no device");

  // begin → respond → CONFIRM: exactly one paired device.
  await invoke("pair_begin", { nickname: "phone-B" });
  await invoke("pair_respond", { pairingInitHex: UI.randHex(1600) });
  const paired = await invoke("pair_confirm", { userConfirmed: true });
  const { pairings } = await invoke("pair_list");
  assert.equal(pairings.length, 1);
  assert.equal(pairings[0].revoked, false);

  // login needs a live paired device.
  await assert.rejects(
    invoke("login_request", { org: "acme", user: "alice", sessionId: 999999 }),
    /no live paired device/,
  );
  const req = await invoke("login_request", { org: "acme", user: "alice", sessionId: paired.id });
  assert.match(req.domain, /consiglio:wallet-login:v1/, "domain-separated login transcript");

  // fail-closed: no approval frame from the phone → NOTHING is minted.
  await assert.rejects(invoke("login_complete", { id: req.id }), /no approval frame/);
  assert.equal((await invoke("grants_list")).grants.length, 0, "a frameless completion mints no grant");

  // an approval frame → a scoped, active grant.
  const g = await invoke("login_complete", { id: req.id, approvalFrameHex: UI.randHex(64), minutes: 10 });
  assert.equal(g.scope, "wallet-login:acme");
  let { grants } = await invoke("grants_list");
  assert.equal(grants.length, 1);
  assert.equal(grants[0].allow, true, "a fresh grant is active");

  // revoke → treated as never given (deny, with an honest reason).
  await invoke("grant_revoke", { id: g.grantId });
  ({ grants } = await invoke("grants_list"));
  assert.equal(grants[0].allow, false, "a revoked grant must not allow");
  assert.match(grants[0].reason, /revoked/);
});

// ════════════════════ SEAL — capped at UNVERIFIED in preview ═══════════════
test("seal: self-audit is honestly capped at UNVERIFIED with no backend", async () => {
  const r = await invoke("seal_self_audit");
  assert.equal(r.verdict, "unverified", "preview may NEVER report a device as genuine");
  assert.ok(r.items.every((i) => i.status === "unknown"), "every posture item is unknown without the backend");
});

test("seal: peer-verify structural verdicts are real, but the PQ signature is never claimed verified", async () => {
  const expected = { os_roothash: "aabbccdd", challenge: "nonce-fresh" };

  const malformed = await invoke("seal_verify_report", { report: {}, expected });
  assert.equal(malformed.verdict, "Malformed", "a report missing required fields is Malformed");

  const mismatch = await invoke("seal_verify_report", {
    report: { os_roothash: "ffffffff", nonce: "nonce-fresh", signature: "sig" }, expected,
  });
  assert.equal(mismatch.verdict, "RoothashMismatch");

  const stale = await invoke("seal_verify_report", {
    report: { os_roothash: "aabbccdd", nonce: "nonce-OLD", signature: "sig" }, expected,
  });
  assert.equal(stale.verdict, "StaleNonce", "a replayed/stale nonce is caught");

  const genuine = await invoke("seal_verify_report", {
    report: { os_roothash: "aabbccdd", nonce: "nonce-fresh", signature: "sig" }, expected,
  });
  assert.ok(genuine.verdict.startsWith("Genuine"), "matching roothash + fresh nonce is structurally genuine");
  assert.equal(genuine.preview, true, "the result is flagged preview");
  const sigCheck = genuine.checks.find((c) => /signature/i.test(c.name));
  assert.equal(sigCheck.ok, null, "the Falcon‖ML-DSA signature must never read as verified in preview");
});

// ════════════════════════ WALLET — mnemonic validation ════════════════════
test("wallet: rejects a short mnemonic; addresses are deterministic and prefix-honest", async () => {
  await assert.rejects(
    invoke("wallet_from_mnemonic", { phrase: "only three words", testnet: true }),
    /at least 12 words/,
  );

  const gen = await invoke("wallet_generate", { testnet: true });
  assert.equal(gen.mnemonic.trim().split(/\s+/).length, 12, "a generated wallet has a 12-word seed");
  assert.match(gen.address, /^tbloch1q/, "testnet addresses carry the tbloch1 prefix");

  const restored = await invoke("wallet_from_mnemonic", { phrase: gen.mnemonic, testnet: true });
  assert.equal(restored.address, gen.address, "restore from the seed is deterministic");

  const mainnet = await invoke("wallet_from_mnemonic", { phrase: gen.mnemonic, testnet: false });
  assert.match(mainnet.address, /^bloch1q/, "mainnet flag changes the prefix");
  assert.notEqual(mainnet.address, gen.address);
});
