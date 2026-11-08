// SARTO core tests — run with: node test-core.mjs   (Node ≥ 18)
// Extracts the DOM-free <script id="srt-core"> block from index.html and
// exercises it. The cases below pin the honesty invariant: every limit the
// policy panel DISPLAYS is a limit checkSite ENFORCES — including overnight
// time windows — plus the KDF-downgrade clamp and the signed-policy floor.
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";

if (!globalThis.crypto) globalThis.crypto = webcrypto;

const html = readFileSync(new URL("./index.html", import.meta.url), "utf8");
const m = html.match(/<script id="srt-core">([\s\S]*?)<\/script>/);
assert.ok(m, "srt-core script block found");
(0, eval)(m[1]);
const SRT = globalThis.SRT;
assert.ok(SRT && typeof SRT.checkSite === "function", "SRT core loaded");

let passed = 0;
const t = (name, fn) => Promise.resolve().then(fn).then(() => { passed++; console.log("  ok — " + name); });

/* local-time dates; 2026-07-04 Sat, 07-05 Sun, 07-06 Mon, 07-07 Tue */
const at = (day, h, min) => new Date(2026, 6, day, h, min);
const SAT = 4, SUN = 5, MON = 6, TUE = 7;
const pol = (windows) => ({ limits: SRT.normalizeLimits({ time_windows: windows }) });
const bedtime = pol([{ label: "Bedtime", days: [1], start: "21:00", end: "06:00", blocks: ["video"] }]); // Monday nights

await t("overnight window blocks after start on a listed day (Mon 22:00)", () =>
  assert.equal(SRT.checkSite(bedtime, "youtube.com", at(MON, 22, 0)).allowed, false));
await t("overnight window blocks past midnight into the next morning (Tue 05:30)", () =>
  assert.equal(SRT.checkSite(bedtime, "youtube.com", at(TUE, 5, 30)).allowed, false));
await t("overnight end is exclusive (Tue 06:00 allowed)", () =>
  assert.equal(SRT.checkSite(bedtime, "youtube.com", at(TUE, 6, 0)).allowed, true));
await t("pre-midnight day attribution: Mon 05:30 allowed (Sunday not listed)", () =>
  assert.equal(SRT.checkSite(bedtime, "youtube.com", at(MON, 5, 30)).allowed, true));
await t("daytime on a listed day allowed (Mon 12:00)", () =>
  assert.equal(SRT.checkSite(bedtime, "youtube.com", at(MON, 12, 0)).allowed, true));
await t("evening of an unlisted day allowed (Tue 22:00)", () =>
  assert.equal(SRT.checkSite(bedtime, "youtube.com", at(TUE, 22, 0)).allowed, true));

const school = pol([{ label: "School", days: [1, 2, 3, 4, 5], start: "08:30", end: "15:00", blocks: ["social"] }]);
await t("same-day window still blocks inside (Mon 10:00)", () =>
  assert.equal(SRT.checkSite(school, "instagram.com", at(MON, 10, 0)).allowed, false));
await t("same-day window: outside hours allowed (Mon 16:00)", () =>
  assert.equal(SRT.checkSite(school, "instagram.com", at(MON, 16, 0)).allowed, true));
await t("same-day window: unlisted day allowed (Sat 10:00)", () =>
  assert.equal(SRT.checkSite(school, "instagram.com", at(SAT, 10, 0)).allowed, true));

await t("shown = enforced: zero-length window (start === end) is dropped, never displayed-but-dead", () => {
  const L = SRT.normalizeLimits({ time_windows: [{ label: "x", days: [1], start: "09:00", end: "09:00", blocks: ["video"] }] });
  assert.equal(L.time_windows.length, 0);
});
await t("shown = enforced: overnight window renders in plain language AND blocks", () => {
  const lines = SRT.policyPlainLanguage({ limits: bedtime.limits });
  assert.ok(lines.some(l => l.includes("21:00–06:00") && l.includes("overnight")), "panel names the overnight span");
  assert.equal(SRT.checkSite(bedtime, "twitch.tv", at(TUE, 1, 0)).allowed, false, "and the check enforces it");
});
await t("precedence: explicit allow beats a window-blocked category", () => {
  const p = { limits: SRT.normalizeLimits({
    site_allow: ["youtube.com"],
    time_windows: [{ label: "Bedtime", days: [1], start: "21:00", end: "06:00", blocks: ["video"] }],
  }) };
  assert.equal(SRT.checkSite(p, "youtube.com", at(MON, 22, 0)).allowed, true);
  assert.equal(SRT.checkSite(p, "twitch.tv", at(MON, 22, 0)).allowed, false);
});

/* ---- KDF-downgrade clamp ---- */
await t("kdfIter clamps a downgraded/garbage count to the floor and caps DoS values", () => {
  assert.equal(SRT.kdfIter(1), SRT.KDF_ITER);
  assert.equal(SRT.kdfIter(0), SRT.KDF_ITER);
  assert.equal(SRT.kdfIter(undefined), SRT.KDF_ITER);
  assert.equal(SRT.kdfIter("nope"), SRT.KDF_ITER);
  assert.equal(SRT.kdfIter(SRT.KDF_ITER + 5), SRT.KDF_ITER + 5);
  assert.equal(SRT.kdfIter(1e12), SRT.KDF_ITER * 10);
});
await t("openBlob ignores a tampered-down kdf.iter (derivation never runs weak)", async () => {
  const blob = await SRT.sealBlob("correct horse battery", { hello: "world" }, "test.aad", {});
  const tampered = JSON.parse(JSON.stringify(blob));
  tampered.kdf.iter = 1; // attacker-writable field
  assert.deepEqual(await SRT.openBlob("correct horse battery", tampered, "test.aad"), { hello: "world" });
  await assert.rejects(SRT.openBlob("wrong passphrase", blob, "test.aad"));
});

/* ---- signed policy: verify, tamper-evidence, transparency floor ---- */
await t("policy signs, verifies against the pin, and any tamper breaks the signature", async () => {
  const kp = await SRT.genKeypair();
  const fpr = await SRT.fingerprint(kp.pub);
  const admin = { label: "Guardian", alg: kp.alg, pub: kp.pub, fpr };
  const payload = SRT.buildPolicy({
    role: "parental", admin, device_label: "Kid's tablet",
    limits: { time_windows: [{ label: "Bedtime", days: [0, 1, 2, 3, 4, 5, 6], start: "21:00", end: "06:30", blocks: ["video", "games"] }] },
  });
  const signed = await SRT.signPolicy(await SRT.importSigner(kp.alg, kp.priv), payload);
  const pin = { alg: kp.alg, pub: kp.pub, fpr };
  assert.equal((await SRT.verifyPolicy(signed, pin)).ok, true);
  const forged = JSON.parse(JSON.stringify(signed));
  forged.payload.limits.time_windows[0].end = "23:59";
  assert.equal((await SRT.verifyPolicy(forged, pin)).ok, false);
  // the transparency floor is refused even with a "valid-looking" object
  const covert = JSON.parse(JSON.stringify(signed));
  covert.payload.transparency.monitoring = "full";
  assert.equal((await SRT.verifyPolicy(covert, pin)).ok, false);
});

console.log(`\nsarto core: ${passed} checks passed`);
