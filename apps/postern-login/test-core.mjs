// CHIAVE core tests — run with: node test-core.mjs   (Node ≥ 18)
// Extracts the DOM-free <script id="pid-core"> and <script id="pid-seam">
// blocks from index.html and exercises:
//   · the login verifier's ceremony discipline — nonce single-use, expiry
//     against the verifier's own clock, origin binding, canonical bytes;
//   · the KDF-downgrade clamp and mnemonic round-trip;
//   · the postern-sdk SEAM (PSEAM) real-vs-fallback dispatch — the REAL
//     Argon2id/AEAD path when a host installs globalThis.PosternSDK, the
//     honest labeled PBKDF2 stand-in when absent, and fail-closed when a
//     real-core blob is opened in a plain tab.
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { webcrypto, createHash } from "node:crypto";

if (!globalThis.crypto) globalThis.crypto = webcrypto;

const html = readFileSync(new URL("./index.html", import.meta.url), "utf8");
const m = html.match(/<script id="pid-core">([\s\S]*?)<\/script>/);
assert.ok(m, "pid-core script block found");
(0, eval)(m[1]);
const PID = globalThis.PID;
assert.ok(PID && typeof PID.createVerifier === "function", "PID core loaded");

// The seam block routes the at-rest seal onto the real SDK core when present
// (item 0 wiring). It references PID as a global, exactly as it does in-page.
const seamMatch = html.match(/<script id="pid-seam">([\s\S]*?)<\/script>/);
assert.ok(seamMatch, "pid-seam script block found");
(0, eval)(seamMatch[1]);
const PSEAM = globalThis.PSEAM;
assert.ok(PSEAM && typeof PSEAM.sealAtRest === "function" && typeof PSEAM.openAtRest === "function",
  "PSEAM seam loaded");

/* ============================================================
   MOCK PosternSDK — a TEST DOUBLE for Dev1's frozen contract
   (crates/postern-sdk/wasm/postern-sdk.js). It is NOT real crypto:
   a synchronous, reversible, context-authenticated transform that
   stands in for the wasm Argon2id(64 MiB,t=3) + XChaCha20-Poly1305
   core, purely to exercise PSEAM's dispatch / round-trip / labels.
   The REAL Argon2id proof lives in the postern-sdk wasm crate
   (compile-gated, Dev1) and is NOT reproduced here — this double
   only proves Chiave routes onto the contract correctly and stays
   honest when it is absent.

   Contract assumed (frozen by Dev1, per wasm/README.md + postern-sdk.js):
     PosternSDK.__postern === true
     PosternSDK.kdf.available : boolean
     PosternSDK.kdf.label     : string
     PosternSDK.kdf.generateSalt()                    -> Uint8Array
     PosternSDK.kdf.deriveKey(passBytes, saltBytes)   -> VaultKey handle
     PosternSDK.kdf.seal(key, ctxBytes, ptBytes)      -> Uint8Array (blob)
     PosternSDK.kdf.open(key, ctxBytes, blobBytes)    -> Uint8Array (plaintext)
     VaultKey handle: .aeadSeal / .aeadOpen / .free
     PosternSDK.pq.available : boolean (false in the wasm build)
     PosternSDK.pq.reason    : string
   ============================================================ */
// F3-flake fix (carried from the sibling test-core.mjs/vault.test.mjs files):
// the mock previously derived its keystream/tag with FNV-1a (a 32-bit
// non-cryptographic hash meant for hash-table dispersion, not
// collision/preimage resistance) and truncated the AEAD tag to 4 bytes —
// measured ~11% false-accept on a WRONG passphrase in the "wrong passphrase
// rejected" parity assertion (flaky, not just theoretically weak). Fixed by
// (a) SHA-256 (real avalanche/diffusion; still just a synchronous test
// double, not a claim this IS the wasm core's Argon2id/XChaCha20-Poly1305)
// and (b) widening the tag from 4 to 16 bytes (~2^-128 accidental collision,
// not ~1-in-9).
function sha256(bytes) {
  return new Uint8Array(createHash("sha256").update(bytes).digest());
}
function mockDerive(passBytes, saltBytes) {
  return sha256(PID.concat(saltBytes, new Uint8Array([0x1f]), passBytes));
}
function mockStream(keyBytes, ctxBytes, nonce, len) {
  // SHA-256(key‖ctx‖nonce‖counter) blocks, concatenated and truncated to len
  // — a simple, deterministic, synchronous stand-in for a real XChaCha20
  // keystream (not itself claimed to be that primitive).
  const out = new Uint8Array(len);
  let o = 0, counter = 0;
  while (o < len) {
    const block = sha256(PID.concat(keyBytes, ctxBytes, nonce, new Uint8Array([counter & 0xff, (counter >>> 8) & 0xff])));
    const take = Math.min(block.length, len - o);
    out.set(block.subarray(0, take), o);
    o += take; counter++;
  }
  return out;
}
function mockTag(keyBytes, ctxBytes, nonce, ct) {
  return sha256(PID.concat(keyBytes, ctxBytes, new Uint8Array([0xa5]), ct, nonce)).subarray(0, 16);
}
class MockVaultKey {
  constructor(bytes) { this.k = bytes; this.freed = false; }
  aeadSeal(ctx, pt) {
    const nonce = PID.rand(8);
    const ks = mockStream(this.k, ctx, nonce, pt.length);
    const ct = new Uint8Array(pt.length);
    for (let i = 0; i < pt.length; i++) ct[i] = pt[i] ^ ks[i];
    const tag = mockTag(this.k, ctx, nonce, ct);
    return PID.concat(nonce, tag, ct);
  }
  aeadOpen(ctx, blob) {
    const nonce = blob.slice(0, 8), tag = blob.slice(8, 24), ct = blob.slice(24);
    const expect = mockTag(this.k, ctx, nonce, ct);
    for (let i = 0; i < 16; i++) if (tag[i] !== expect[i]) throw new Error("mock aead: tag mismatch (wrong key/context) — all-or-nothing");
    const ks = mockStream(this.k, ctx, nonce, ct.length);
    const pt = new Uint8Array(ct.length);
    for (let i = 0; i < ct.length; i++) pt[i] = ct[i] ^ ks[i];
    return pt;
  }
  free() { this.freed = true; }
}
function installMockSDK() {
  globalThis.PosternSDK = {
    __postern: true, version: "test-double", backend: "mock",
    label: "postern-sdk (mock test double)",
    kdf: {
      available: true,
      label: "Argon2id (m=65536 KiB, t=3, p=1)",
      generateSalt: () => PID.rand(16),
      deriveKey: (pass, salt) => new MockVaultKey(mockDerive(pass, salt)),
      keyFromBytes: (b) => new MockVaultKey(b),
      seal: (k, ctx, pt) => k.aeadSeal(ctx, pt),
      open: (k, ctx, blob) => k.aeadOpen(ctx, blob),
    },
    pq: { available: false, reason: "bloch-crypto links PQClean C; no wasm32 target" },
  };
}
function uninstallSDK() { delete globalThis.PosternSDK; }
uninstallSDK(); // default posture: plain browser tab, no host shell

let passed = 0;
const t = (name, fn) => Promise.resolve().then(fn).then(() => { passed++; console.log("  ok — " + name); });

const kp = await PID.genLoginKeypair();
const signer = await PID.importSigner(kp.alg, kp.priv);
const enrolled = { alg: kp.alg, pub: kp.pub };
const signCh = (ch) => PID.sign(kp.alg, signer, PID.challengeBytes(ch));

let clock = 0; // injected verifier clock
const v = PID.createVerifier("https://chiave.example", { now: () => clock, ttlMs: 120000 });

await t("happy path: fresh, origin-bound challenge verifies against the enrolled key", async () => {
  const ch = v.issue();
  assert.equal(ch.origin, "https://chiave.example");
  const verdict = await v.verify(enrolled, ch, await signCh(ch));
  assert.equal(verdict.ok, true, verdict.reason);
});
await t("nonce is single-use: the same {challenge, signature} pair never verifies twice", async () => {
  const ch = v.issue();
  const sig = await signCh(ch);
  assert.equal((await v.verify(enrolled, ch, sig)).ok, true);
  assert.equal((await v.verify(enrolled, ch, sig)).ok, false); // replay refused
});
await t("nonce is consumed even by a FAILED attempt (no retry oracle)", async () => {
  const ch = v.issue();
  assert.equal((await v.verify(enrolled, ch, "AAAA")).ok, false);        // bad signature
  assert.equal((await v.verify(enrolled, ch, await signCh(ch))).ok, false); // nonce already burned
});
await t("expiry: a challenge older than the TTL is refused (verifier's clock, not the echoed one)", async () => {
  const ch = v.issue();
  const sig = await signCh(ch);
  clock += 120001;
  const verdict = await v.verify(enrolled, ch, sig);
  assert.equal(verdict.ok, false);
  assert.match(verdict.reason, /expired/);
});
await t("origin binding: a challenge re-pointed at another origin is refused even with a valid signature", async () => {
  const ch = v.issue();
  const tampered = { ...ch, origin: "https://evil.example" };
  const verdict = await v.verify(enrolled, tampered, await signCh(tampered));
  assert.equal(verdict.ok, false);
  assert.match(verdict.reason, /origin/);
});
await t("a challenge minted by a different verifier (phishing proxy) is unknown here", async () => {
  const phish = PID.createVerifier("https://chiave.example", { now: () => clock });
  const ch = phish.issue(); // same origin string, but not OUR nonce book
  assert.equal((await v.verify(enrolled, ch, await signCh(ch))).ok, false);
});
await t("a signature from the wrong key is refused", async () => {
  const other = await PID.genLoginKeypair();
  const ch = v.issue();
  const sig = await PID.sign(other.alg, await PID.importSigner(other.alg, other.priv), PID.challengeBytes(ch));
  assert.equal((await v.verify(enrolled, ch, sig)).ok, false);
});
await t("canonical bytes: an RP-reconstructed challenge (different key order) is byte-identical", () => {
  const ch = v.issue();
  const reordered = { origin: ch.origin, issued: ch.issued, nonce: ch.nonce, v: ch.v };
  assert.equal(Buffer.compare(Buffer.from(PID.challengeBytes(ch)), Buffer.from(PID.challengeBytes(reordered))), 0);
});

/* ---- KDF-downgrade clamp ---- */
await t("kdfIter clamps a downgraded/garbage count to the floor and caps DoS values", () => {
  assert.equal(PID.kdfIter(1), PID.KDF_ITER);
  assert.equal(PID.kdfIter(0), PID.KDF_ITER);
  assert.equal(PID.kdfIter(undefined), PID.KDF_ITER);
  assert.equal(PID.kdfIter(PID.KDF_ITER + 5), PID.KDF_ITER + 5);
  assert.equal(PID.kdfIter(1e12), PID.KDF_ITER * 10);
});

/* ---- mnemonic round-trip ---- */
await t("mnemonic generates, parses, and detects a swapped word", async () => {
  const phrase = await PID.mnemonicNew();
  assert.ok((await PID.mnemonicParse(phrase)).phrase);
  const words = phrase.split(" ");
  [words[0], words[1]] = [words[1], words[0]];
  if (words.join(" ") !== phrase) {
    const res = await PID.mnemonicParse(words.join(" "));
    assert.ok(res.err, "checksum catches the swap");
  }
});

/* ============================================================
   postern-sdk SEAM — real Argon2id path (SDK present), honest
   fallback + label (SDK absent), and fail-closed on a real blob
   opened in a plain tab. AAD used by the wallet seal in-page.
   ============================================================ */
const AAD = "postern.login.v1";
const PAYLOAD = { seed: "00112233445566778899aabbccddeeff", alg: "Ed25519", priv: "cHJpdg==", pub: "cHVi" };

await t("SEAM absent by default: status() honestly reports the PBKDF2 stand-in and never says REAL", () => {
  uninstallSDK();
  const st = PSEAM.status();
  assert.equal(st.seam, false);
  assert.equal(st.kdf, false);
  assert.equal(PSEAM.kdfReal(), false);
  assert.match(st.kdfLabel, /PBKDF2-SHA-256/);
  assert.match(st.kdfLabel, /stand-in/i);
  assert.ok(!/REAL/.test(st.kdfLabel), "the fallback KDF label must NEVER be presented as REAL");
});

await t("SEAM fallback: seals under the labeled PBKDF2/AES-GCM stand-in and round-trips", async () => {
  uninstallSDK();
  const sealed = await PSEAM.sealAtRest("correct horse battery", PAYLOAD, AAD);
  assert.equal(sealed.kdf.algo, PSEAM.KDF_STANDIN);         // "PBKDF2-SHA-256"
  assert.equal(sealed.kdf.iter, PID.KDF_ITER);
  assert.equal(sealed.cipher.algo, "AES-256-GCM");
  const blob = { kdf: sealed.kdf, cipher: sealed.cipher };
  const opened = await PSEAM.openAtRest("correct horse battery", blob, AAD);
  assert.deepEqual(opened, PAYLOAD);
  await assert.rejects(PSEAM.openAtRest("wrong passphrase", blob, AAD)); // all-or-nothing, GCM tag fails
});

await t("SEAM fallback preserves the KDF-downgrade clamp through open() (stored iter=1 → floored)", async () => {
  uninstallSDK();
  const sealed = await PSEAM.sealAtRest("pw-clamp", PAYLOAD, AAD);
  const tampered = { kdf: { ...sealed.kdf, iter: 1 }, cipher: sealed.cipher }; // attacker rewrites iter down
  const opened = await PSEAM.openAtRest("pw-clamp", tampered, AAD);            // clamp restores KDF_ITER
  assert.deepEqual(opened, PAYLOAD);
});

let realBlob = null;
await t("SEAM present: routes to the REAL Argon2id/XChaCha20 core and flips the label to REAL", async () => {
  installMockSDK();
  try {
    const st = PSEAM.status();
    assert.equal(st.seam, true);
    assert.equal(st.kdf, true);
    assert.equal(PSEAM.kdfReal(), true);
    assert.match(st.kdfLabel, /REAL, via postern-sdk/);
    assert.match(st.kdfLabel, /Argon2id/);
    // Honesty: PQ signing is NOT in the wasm build — never claimed real even here.
    assert.equal(st.pq, false);
    assert.match(st.pqLabel, /classical stand-in/);

    const sealed = await PSEAM.sealAtRest("host-shell-pass", PAYLOAD, AAD);
    assert.equal(sealed.kdf.algo, PSEAM.KDF_REAL);            // "Argon2id-postern-sdk"
    assert.equal(sealed.cipher.algo, "XChaCha20-Poly1305");
    assert.ok(sealed.kdf.salt && sealed.cipher.blob, "sealed blob carries salt + ciphertext");
    realBlob = { kdf: sealed.kdf, cipher: sealed.cipher };
    const opened = await PSEAM.openAtRest("host-shell-pass", realBlob, AAD);
    assert.deepEqual(opened, PAYLOAD);
    await assert.rejects(PSEAM.openAtRest("wrong-host-pass", realBlob, AAD)); // real core: all-or-nothing
  } finally {
    uninstallSDK();
  }
});

await t("SEAM fail-closed: a real-core blob CANNOT open in a plain tab — no silent downgrade, honest error", async () => {
  assert.ok(realBlob && realBlob.kdf.algo === PSEAM.KDF_REAL, "have a real-core blob from the SDK-present run");
  uninstallSDK(); // back to a plain browser tab
  await assert.rejects(
    PSEAM.openAtRest("host-shell-pass", realBlob, AAD),
    /postern-sdk|shell/,
    "must refuse — never fall back to PBKDF2 to 'open' bytes sealed by the real core",
  );
});

await t("SEAM dispatch is on the stored kdf.algo, not current seam state (stand-in blob opens even with SDK present)", async () => {
  uninstallSDK();
  const sealed = await PSEAM.sealAtRest("mixed-state", PAYLOAD, AAD); // sealed as PBKDF2 stand-in
  const blob = { kdf: sealed.kdf, cipher: sealed.cipher };
  installMockSDK();
  try {
    const opened = await PSEAM.openAtRest("mixed-state", blob, AAD);  // opens via the tagged PBKDF2 branch
    assert.deepEqual(opened, PAYLOAD);
  } finally {
    uninstallSDK();
  }
});

console.log(`\nchiave core: ${passed} checks passed`);
