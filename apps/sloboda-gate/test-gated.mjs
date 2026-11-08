"use strict";
/* ============================================================================
   test-gated.mjs — offline tests for sloboda-gated (the consent WRITER)

   Dependency-free node test. Runs on the macOS host / any Linux — NO container,
   NO Waydroid, NO network. Proves the writer's honesty rails in code:
     • atomic write (temp+fsync+rename), exact perms, no partial/residue;
     • malformed / foreign-schema / version-mismatch canonical → full-deny;
     • projection is a pure serialization of the shipped containerAllowed()/
       activeBridges() decisions (matrix);
     • consent refuse/accept + kill transition + re-startability with the image
       sentinel intact (non-destructive kill);
     • the writer never invents state; read-only commands never mutate canonical;
     • a launcher click while blocked is refused by the wrapper (consent-coupling).

   UNTESTED on-device: proves control flow + projection math only; nothing here
   booted a container. NON-ATTESTABLE tier; UNAUDITED; personal-free.
   ============================================================================ */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import S from "./gate-store.mjs";
import G from "./sloboda-gated.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const GATED = path.join(HERE, "sloboda-gated.mjs");
const WRAPPER = path.resolve(HERE, "../sloboda/bin/sloboda");
const MOCK = path.resolve(HERE, "../sloboda/test/mock-waydroid");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; } else { fail++; console.error("FAIL:", name); } };

/* fresh isolated scratch dir per assertion group */
function scratch() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "paw-gated-"));
}
function env(dir, extra = {}) {
  return {
    ...process.env,
    POSTERN_GATE_STATE: path.join(dir, "canon", "state.json"),
    POSTERN_BRIDGE_STATE: path.join(dir, "run", "sloboda-bridge.state"),
    ...extra,
  };
}
function runGated(args, e) {
  return spawnSync(process.execPath, [GATED, ...args], { env: e, encoding: "utf8" });
}
function readProj(e) { return fs.readFileSync(e.POSTERN_BRIDGE_STATE, "utf8"); }
function readCanon(e) { return fs.readFileSync(e.POSTERN_GATE_STATE, "utf8"); }
function modeOf(p) { return fs.statSync(p).mode & 0o777; }
const line1 = (t) => t.split("\n")[0];
const hasLine = (t, l) => t.split("\n").includes(l);

/* ── 1. Atomic write: exact content, exact mode, no partial/residue ────────── */
{
  const dir = scratch();
  const target = path.join(dir, "sub", "state.json");
  G.atomicWrite(target, "AAAA\n", { mode: 0o600, dirMode: 0o700 });
  ok("atomic: content written whole", fs.readFileSync(target, "utf8") === "AAAA\n");
  ok("atomic: target mode is 0600", modeOf(target) === 0o600);
  ok("atomic: dir mode is 0700", modeOf(path.join(dir, "sub")) === 0o700);
  // Overwrite: rename-swap keeps the file complete (never truncated in place).
  G.atomicWrite(target, "BBBBBB\n", { mode: 0o600, dirMode: 0o700 });
  ok("atomic: overwrite is whole (rename-swap)", fs.readFileSync(target, "utf8") === "BBBBBB\n");
  const residue = fs.readdirSync(path.join(dir, "sub")).filter((f) => f.includes(".tmp"));
  ok("atomic: no .tmp residue left behind", residue.length === 0);
}

/* ── 2. Permissions of both files + their dirs via the real writer ─────────── */
{
  const dir = scratch();
  const e = env(dir);
  ok("perms: accept exits 0", runGated(["accept"], e).status === 0);
  ok("perms: canonical is 0600", modeOf(e.POSTERN_GATE_STATE) === 0o600);
  ok("perms: projection is 0644", modeOf(e.POSTERN_BRIDGE_STATE) === 0o644);
  ok("perms: canonical dir is 0700", modeOf(path.dirname(e.POSTERN_GATE_STATE)) === 0o700);
  ok("perms: projection dir is 0755", modeOf(path.dirname(e.POSTERN_BRIDGE_STATE)) === 0o755);
}

/* ── 3. Malformed / foreign / version-mismatch canonical → full-deny ───────── */
{
  const cases = {
    "malformed json": "{ not json",
    "empty file": "",
    "hostile accepted w/ foreign schema": JSON.stringify({ schema: "evil", version: 1, consent: { accepted: true } }),
    "right schema wrong version": JSON.stringify({ schema: S.SCHEMA_ID, version: 999, consent: { accepted: true } }),
    "accepted but no schema": JSON.stringify({ consent: { accepted: true } }),
  };
  for (const [label, text] of Object.entries(cases)) {
    const dir = scratch();
    const e = env(dir);
    fs.mkdirSync(path.dirname(e.POSTERN_GATE_STATE), { recursive: true });
    fs.writeFileSync(e.POSTERN_GATE_STATE, text);
    const st = G.loadCanonical(e);
    ok(`malformed→deny (${label}): consent denied`, st.consent.accepted === false);
    runGated(["project"], e);
    ok(`malformed→deny (${label}): projection disabled+blocked`,
      line1(readProj(e)) === "disabled" && hasLine(readProj(e), "container=blocked"));
  }
}

/* ── 4. Projection matrix — pure serialization of the shipped decisions ────── */
{
  const cases = [
    { name: "fresh deny", st: {}, line1: "disabled", allowed: false, caps: [] },
    { name: "consent, no bridge", st: { consent: { accepted: true } }, line1: "disabled", allowed: true, caps: [] },
    { name: "consent + clipboard", st: { consent: { accepted: true }, bridges: { clipboard: true } }, line1: "enabled", allowed: true, caps: ["clipboard"] },
    { name: "consent + two bridges", st: { consent: { accepted: true }, bridges: { clipboard: true, mic: true } }, line1: "enabled", allowed: true, caps: ["clipboard", "mic"] },
    { name: "bridge on but no consent", st: { bridges: { clipboard: true } }, line1: "disabled", allowed: false, caps: [] },
    { name: "kill overrides consent+bridge", st: { consent: { accepted: true }, bridges: { clipboard: true }, killSwitch: { engaged: true } }, line1: "disabled", allowed: false, caps: [] },
  ];
  for (const c of cases) {
    const proj = G.project(c.st);
    ok(`matrix (${c.name}): line1`, line1(proj) === c.line1);
    ok(`matrix (${c.name}): container marker`,
      hasLine(proj, `container=${c.allowed ? "allowed" : "blocked"}`));
    ok(`matrix (${c.name}): caps exactly ${JSON.stringify(c.caps)}`,
      JSON.stringify(c.caps.filter((k) => hasLine(proj, `${k}=on`))) === JSON.stringify(c.caps) &&
      S.BRIDGE_KEYS.filter((k) => hasLine(proj, `${k}=on`)).length === c.caps.length);
    const killLine = hasLine(proj, "kill=engaged");
    ok(`matrix (${c.name}): kill marker iff engaged`,
      killLine === (S.normalize(c.st).killSwitch.engaged === true));
  }
  // Byte-equality with the module's own project() (single source of truth).
  ok("matrix: no bridge extras when line1 disabled",
    !G.project({ consent: { accepted: true }, bridges: { mic: true }, killSwitch: { engaged: true } }).includes("mic=on"));
}

/* ── 5. Consent refuse → accept → withdraw (projection + canonical) ────────── */
{
  const dir = scratch();
  const e = env(dir);
  runGated(["project"], e); // fresh (no canonical) → default deny
  ok("consent: fresh projection is disabled/blocked",
    line1(readProj(e)) === "disabled" && hasLine(readProj(e), "container=blocked"));

  runGated(["accept", "--scope", "persistent"], e);
  const canon = JSON.parse(readCanon(e));
  ok("consent: accept persists accepted=true", canon.consent.accepted === true);
  ok("consent: accept records scope", canon.consent.scope === "persistent");
  ok("consent: accept records acceptedAtIso", typeof canon.consent.acceptedAtIso === "string");
  ok("consent: tier stays pinned non-attestable", canon.tier === "non-attestable");
  ok("consent: egress.torOnly stays pinned", canon.egress.torOnly === true);
  ok("consent: accepted → container=allowed", hasLine(readProj(e), "container=allowed"));
  ok("consent: accepted w/ no bridge → line1 still disabled (run≠share)", line1(readProj(e)) === "disabled");

  runGated(["bridge", "clipboard", "on"], e);
  ok("consent: clipboard on → line1 enabled", line1(readProj(e)) === "enabled");
  ok("consent: clipboard on → clipboard=on extra", hasLine(readProj(e), "clipboard=on"));
  ok("consent: bridge did not bundle others",
    S.BRIDGE_KEYS.filter((k) => hasLine(readProj(e), `${k}=on`)).length === 1);

  runGated(["withdraw"], e);
  ok("consent: withdraw → container=blocked", hasLine(readProj(e), "container=blocked"));
  ok("consent: withdraw → canonical accepted=false", JSON.parse(readCanon(e)).consent.accepted === false);
}

/* ── 6. Unknown bridge is rejected (no silent grant) ───────────────────────── */
{
  const dir = scratch();
  const e = env(dir);
  runGated(["accept"], e);
  const r = runGated(["bridge", "gps", "on"], e);
  ok("bridge: unknown cap rejected (exit 1)", r.status === 1);
  ok("bridge: unknown cap not projected", !hasLine(readProj(e), "gps=on"));
}

/* ── 7. Kill transition + actuator hand-off + image sentinel intact ────────── */
{
  const dir = scratch();
  // Stub actuator: records that `sloboda kill` was invoked, touches
  // NOTHING that resembles the provisioned image.
  const marker = path.join(dir, "kill.marker");
  const stub = path.join(dir, "sloboda");
  fs.writeFileSync(stub, `#!/bin/sh\nprintf 'kill-ran %s\\n' "$*" >> "${marker}"\n`, { mode: 0o755 });
  fs.chmodSync(stub, 0o755);
  // Provisioned-image sentinel that a non-destructive kill must leave untouched.
  const img = path.join(dir, "image", "IMAGE");
  fs.mkdirSync(path.dirname(img), { recursive: true });
  fs.writeFileSync(img, "PROVISIONED VANILLA\n");
  const imgBefore = fs.readFileSync(img, "utf8");

  const e = env(dir, { SLOBODA_BIN: stub });
  runGated(["accept"], e);
  runGated(["bridge", "clipboard", "on"], e);
  ok("kill: pre-kill projection enabled", line1(readProj(e)) === "enabled");

  const r = runGated(["kill", "on"], e);
  ok("kill: exit code propagates from actuator (0)", r.status === 0);
  ok("kill: canonical killSwitch.engaged=true", JSON.parse(readCanon(e)).killSwitch.engaged === true);
  ok("kill: canonical engagedAtIso recorded", typeof JSON.parse(readCanon(e)).killSwitch.engagedAtIso === "string");
  ok("kill: projection line1 disabled", line1(readProj(e)) === "disabled");
  ok("kill: projection container=blocked", hasLine(readProj(e), "container=blocked"));
  ok("kill: projection carries kill=engaged", hasLine(readProj(e), "kill=engaged"));
  ok("kill: actuator (sloboda kill) was invoked", fs.existsSync(marker) && fs.readFileSync(marker, "utf8").includes("kill-ran kill"));
  ok("kill: image sentinel UNTOUCHED (non-destructive)", fs.readFileSync(img, "utf8") === imgBefore);
  ok("kill: bridge grant preserved in canonical (not wiped)", JSON.parse(readCanon(e)).bridges.clipboard === true);

  // 8. Re-startable: disengage → projection allowed again, image still intact.
  runGated(["kill", "off"], e);
  ok("restart: kill off → canonical engaged=false", JSON.parse(readCanon(e)).killSwitch.engaged === false);
  ok("restart: kill off → container=allowed again", hasLine(readProj(e), "container=allowed"));
  ok("restart: kill off → line1 enabled again (bridge preserved)", line1(readProj(e)) === "enabled");
  ok("restart: no kill=engaged line after disengage", !hasLine(readProj(e), "kill=engaged"));
  ok("restart: image sentinel STILL intact", fs.readFileSync(img, "utf8") === imgBefore);
}

/* ── 9. Read-only commands never mutate canonical ──────────────────────────── */
{
  const dir = scratch();
  const e = env(dir);
  runGated(["accept"], e);
  runGated(["bridge", "files", "on"], e);
  const before = readCanon(e);
  runGated(["status"], e);
  runGated(["project"], e);
  ok("read-only: status+project leave canonical byte-identical", readCanon(e) === before);
}

/* ── 10. Launcher consent-coupling: a click while blocked is REFUSED ───────── */
{
  const dir = scratch();
  const e = env(dir);
  // Fresh (no consent) → projection blocked.
  runGated(["project"], e);
  ok("launcher: precondition projection blocked", hasLine(readProj(e), "container=blocked"));
  // Simulate the .desktop Exec: `sloboda app <pkg>` with mock on PATH.
  const mockdir = path.join(dir, "mockbin");
  fs.mkdirSync(mockdir, { recursive: true });
  fs.copyFileSync(MOCK, path.join(mockdir, "waydroid"));
  fs.chmodSync(path.join(mockdir, "waydroid"), 0o755);
  const wrapEnv = {
    ...process.env,
    PATH: `${mockdir}:${process.env.PATH}`,
    PAW_DRYRUN: "0",
    PAW_MOCK_STATE: path.join(dir, "mock.state"),
    PAW_BRIDGE_STATE: e.POSTERN_BRIDGE_STATE, // wrapper reads the projection we wrote
  };
  const blocked = spawnSync("sh", [WRAPPER, "app", "com.aurora.store"], { env: wrapEnv, encoding: "utf8" });
  ok("launcher: blocked → wrapper refuses (non-zero exit)", blocked.status !== 0);
  ok("launcher: blocked → refusal message is honest", /REFUSED/.test(blocked.stderr));
  ok("launcher: blocked → mock session never started",
    !fs.existsSync(wrapEnv.PAW_MOCK_STATE) || fs.readFileSync(wrapEnv.PAW_MOCK_STATE, "utf8").trim() !== "RUNNING");

  // Now accept → same click is permitted through the gate.
  runGated(["accept"], e);
  const allowed = spawnSync("sh", [WRAPPER, "app", "com.aurora.store"], { env: wrapEnv, encoding: "utf8" });
  ok("launcher: after accept → wrapper permits the click", allowed.status === 0);
}

/* ── 11. discriminatorOk() — the guard predicate, pinned directly ──────────── */
{
  const good = { schema: S.SCHEMA_ID, version: S.SCHEMA_VERSION };
  ok("guard: canonical schema+version accepted", G.discriminatorOk(good) === true);
  ok("guard: schema+version+pinned tier accepted",
    G.discriminatorOk({ ...good, tier: S.TIER }) === true);
  const rejects = {
    "null": null,
    "array": [good],
    "foreign schema": { schema: "postern.porog-gate.state", version: 1 },
    "missing schema": { version: 1 },
    "schema wrong type": { schema: 123, version: 1 },
    "unknown version": { schema: S.SCHEMA_ID, version: 999 },
    "version as string": { schema: S.SCHEMA_ID, version: "1" },
    "relabelled tier is refused (attested)": { schema: S.SCHEMA_ID, version: 1, tier: "attested" }, // never trusted
    "relabelled tier (empty)": { schema: S.SCHEMA_ID, version: 1, tier: "" },
  };
  for (const [label, raw] of Object.entries(rejects)) {
    ok(`guard: rejects ${label}`, G.discriminatorOk(raw) === false);
  }
  // A relabelled-tier file must full-deny through loadCanonical, not just the predicate.
  {
    const dir = scratch();
    const e = env(dir);
    fs.mkdirSync(path.dirname(e.POSTERN_GATE_STATE), { recursive: true });
    // A file that relabels the tier is never trusted — refused wholesale below.
    fs.writeFileSync(e.POSTERN_GATE_STATE, JSON.stringify({
      schema: S.SCHEMA_ID, version: 1, tier: "attested", consent: { accepted: true }, // refused
    }));
    ok("guard: relabelled-tier canonical → consent denied", G.loadCanonical(e).consent.accepted === false);
  }
}

/* ── 12. Egress projection — Tor-only, fail-closed (egress=tor|held|blocked) ── */
{
  const cases = [
    { name: "fresh (no consent)", st: {}, egress: "blocked" },
    { name: "consent, tor down", st: { consent: { accepted: true } }, egress: "held" },
    { name: "consent, tor up", st: { consent: { accepted: true }, egress: { torBootstrapped: true } }, egress: "tor" },
    { name: "consent+bridge, tor up", st: { consent: { accepted: true }, bridges: { clipboard: true }, egress: { torBootstrapped: true } }, egress: "tor" },
    { name: "tor up but no consent → blocked", st: { egress: { torBootstrapped: true } }, egress: "blocked" },
    { name: "kill engaged → blocked even w/ tor up", st: { consent: { accepted: true }, egress: { torBootstrapped: true }, killSwitch: { engaged: true } }, egress: "blocked" },
  ];
  for (const c of cases) {
    ok(`egress (${c.name}): egressPosture`, G.egressPosture(c.st) === c.egress);
    ok(`egress (${c.name}): projected as egress=${c.egress}`, hasLine(G.project(c.st), `egress=${c.egress}`));
  }
  // The egress line is never mistaken for a bridge cap (no =on), so paw_bridge_caps ignores it.
  ok("egress: line value is never '=on' (won't collide with cap reader)",
    !G.project({ consent: { accepted: true }, egress: { torBootstrapped: true } }).includes("egress=on"));
}

/* ── 13. `tor up|down` command drives egress.torBootstrapped + projection ───── */
{
  const dir = scratch();
  const e = env(dir);
  runGated(["accept"], e);
  ok("tor: before signal → egress=held", hasLine(readProj(e), "egress=held"));
  ok("tor: canonical torBootstrapped starts false", JSON.parse(readCanon(e)).egress.torBootstrapped === false);

  ok("tor: 'tor up' exits 0", runGated(["tor", "up"], e).status === 0);
  ok("tor: up → canonical torBootstrapped=true", JSON.parse(readCanon(e)).egress.torBootstrapped === true);
  ok("tor: up → egress=tor projected", hasLine(readProj(e), "egress=tor"));
  ok("tor: torOnly stays pinned true", JSON.parse(readCanon(e)).egress.torOnly === true);

  ok("tor: 'tor down' exits 0", runGated(["tor", "down"], e).status === 0);
  ok("tor: down → egress held again (fail-closed)", hasLine(readProj(e), "egress=held"));
  const bad = runGated(["tor", "sideways"], e);
  ok("tor: bad verb rejected (exit 2)", bad.status === 2);
}

/* ── 14. `boot`: re-derive projection + session re-ask (persistent survives) ── */
{
  // session scope → boot clears consent (re-ask)
  const dir = scratch();
  const e = env(dir);
  runGated(["accept", "--scope", "session"], e);
  runGated(["bridge", "clipboard", "on"], e);
  runGated(["tor", "up"], e);
  ok("boot: pre-boot session consent accepted", JSON.parse(readCanon(e)).consent.accepted === true);
  // Simulate reboot: projection on /run is gone.
  fs.rmSync(e.POSTERN_BRIDGE_STATE);
  ok("boot: 'boot' exits 0", runGated(["boot"], e).status === 0);
  ok("boot: projection re-derived after wipe", fs.existsSync(e.POSTERN_BRIDGE_STATE));
  ok("boot: session consent cleared (re-ask)", JSON.parse(readCanon(e)).consent.accepted === false);
  ok("boot: session boot → container=blocked", hasLine(readProj(e), "container=blocked"));
  ok("boot: torBootstrapped cleared on boot (Tor down until re-signalled)", JSON.parse(readCanon(e)).egress.torBootstrapped === false);
  ok("boot: bridge grant preserved in canonical (not wiped, just masked)", JSON.parse(readCanon(e)).bridges.clipboard === true);

  // persistent scope → boot KEEPS consent, still re-derives projection.
  const dir2 = scratch();
  const e2 = env(dir2);
  runGated(["accept", "--scope", "persistent"], e2);
  runGated(["bridge", "files", "on"], e2);
  fs.rmSync(e2.POSTERN_BRIDGE_STATE);
  runGated(["boot"], e2);
  ok("boot: persistent consent survives boot", JSON.parse(readCanon(e2)).consent.accepted === true);
  ok("boot: persistent boot → container=allowed", hasLine(readProj(e2), "container=allowed"));
  ok("boot: persistent boot → line1 enabled again (bridge preserved)", line1(readProj(e2)) === "enabled");
}

/* ── 15. atomicWrite failure leaves NO residue and NO partial target ────────── */
{
  const dir = scratch();
  const target = path.join(dir, "sub", "state.json");
  G.atomicWrite(target, "GOOD\n", { mode: 0o600, dirMode: 0o700 });
  // Force a failure mid-write: content whose write throws (a bad fd is hard to
  // stage, so use an un-stringifiable via a getter that throws on toString).
  let threw = false;
  const hostile = { toString() { throw new Error("boom"); } };
  try { G.atomicWrite(target, hostile, { mode: 0o600, dirMode: 0o700 }); }
  catch { threw = true; }
  ok("atomic-fail: a failed write throws (not silent)", threw === true);
  ok("atomic-fail: prior target content intact after failure", fs.readFileSync(target, "utf8") === "GOOD\n");
  const residue = fs.readdirSync(path.join(dir, "sub")).filter((f) => f.includes(".tmp"));
  ok("atomic-fail: no .tmp residue after a failed write", residue.length === 0);
}

/* ── 16. systemd-unit emission — text only, correct boot ordering ───────────── */
{
  const dir = scratch();
  const e = env(dir);
  const r = runGated(["systemd-unit"], e);
  ok("systemd: exits 0", r.status === 0);
  ok("systemd: ExecStart runs the boot re-derive", /ExecStart=.*\bboot\b/.test(r.stdout));
  ok("systemd: ordered BEFORE the container/session reads projection", /Before=.*waydroid/.test(r.stdout));
  ok("systemd: Type=oneshot", /Type=oneshot/.test(r.stdout));
  ok("systemd: honesty label present (non-attestable/UNAUDITED)", /non-attestable|UNAUDITED/.test(r.stdout));
  ok("systemd: emitting the unit writes NO state file", !fs.existsSync(e.POSTERN_GATE_STATE));
  const r2 = runGated(["systemd-unit"], { ...e, SLOBODA_GATED_BIN: "/usr/lib/postern/sloboda-gated" });
  ok("systemd: SLOBODA_GATED_BIN pins the ExecStart path", /ExecStart=\/usr\/lib\/postern\/sloboda-gated boot/.test(r2.stdout));
}

/* ── 17. Canonical output conforms to the published JSON Schema ─────────────────
   The writer serializes canonical state via gate-store; this locks that output
   to gate-state.schema.json so the on-disk canonical contract cannot silently
   drift (an extra key, a missing required field, a relabelled const). Tiny
   draft-07 subset validator — no deps: const / enum / type / required /
   additionalProperties / nested properties, which is everything this schema uses. */
{
  const schema = JSON.parse(fs.readFileSync(path.join(HERE, "gate-state.schema.json"), "utf8"));
  const typeOk = (v, t) => {
    if (Array.isArray(t)) return t.some((x) => typeOk(v, x));
    if (t === "object") return v !== null && typeof v === "object" && !Array.isArray(v);
    if (t === "array") return Array.isArray(v);
    if (t === "null") return v === null;
    if (t === "boolean") return typeof v === "boolean";
    if (t === "string") return typeof v === "string";
    if (t === "number" || t === "integer") return typeof v === "number";
    return true;
  };
  function validate(node, sch, at, errs) {
    if ("const" in sch && JSON.stringify(node) !== JSON.stringify(sch.const)) errs.push(`${at}: const`);
    if (sch.enum && !sch.enum.some((x) => JSON.stringify(x) === JSON.stringify(node))) errs.push(`${at}: enum`);
    if (sch.type && !typeOk(node, sch.type)) errs.push(`${at}: type`);
    if (typeOk(node, "object") && (sch.type === "object" || sch.properties)) {
      for (const r of sch.required || []) if (!(r in node)) errs.push(`${at}.${r}: required missing`);
      if (sch.additionalProperties === false) {
        for (const k of Object.keys(node)) if (!(sch.properties && k in sch.properties)) errs.push(`${at}.${k}: unexpected key`);
      }
      for (const [k, sub] of Object.entries(sch.properties || {})) if (k in node) validate(node[k], sub, `${at}.${k}`, errs);
    }
    return errs;
  }
  const check = (label, obj) => {
    const errs = validate(obj, schema, label, []);
    ok(`schema-conformance (${label}): valid`, errs.length === 0);
    if (errs.length) console.error("   ", errs.join("; "));
  };
  // Every state the writer can persist must validate against the published schema.
  check("default", JSON.parse(S.serialize(S.defaultState())));
  check("accepted+persistent", JSON.parse(S.serialize(G.applyAccept(S.defaultState(), "persistent"))));
  check("all bridges on", JSON.parse(S.serialize(
    S.BRIDGE_KEYS.reduce((st, k) => G.applyBridge(st, k, true), G.applyAccept(S.defaultState(), "session")))));
  check("kill engaged", JSON.parse(S.serialize(G.applyKill(S.defaultState(), true))));
  // And what the daemon actually wrote to disk conforms too (not just the helper).
  const dir = scratch();
  const e = env(dir);
  runGated(["accept"], e);
  runGated(["bridge", "camera", "on"], e);
  check("on-disk canonical", JSON.parse(readCanon(e)));
}

/* ── 18. Projection format locks the exact lines S1's read-only wrapper greps ───
   paw-lib.sh matches ^container=allowed$, ^kill=engaged$, line-1 == "enabled",
   and extracts caps via ^([a-z][a-z]*)=on$. If the writer's projection drifts
   from these exact anchors the wrapper silently reads OFF (fail-safe, but the
   user's choice is lost). Lock every emitted line to the wrapper's own patterns.
   The Tor-only egress line (egress=tor|held|blocked, added in the Wave-1 egress
   projection, §12) is a KNOWN informational line: it deliberately never ends in
   `=on`, so the cap reader ignores it, but it is a legitimate projection line. */
{
  const CAP_RE = /^[a-z][a-z]*=on$/;                 // paw-lib sed: s/^\([a-z][a-z]*\)=on$/\1/p
  const KNOWN = /^(enabled|disabled|container=(allowed|blocked)|kill=engaged|egress=(tor|held|blocked))$/;
  const states = [
    {}, { consent: { accepted: true } },
    { consent: { accepted: true }, bridges: { clipboard: true } },
    { consent: { accepted: true }, bridges: { clipboard: true, files: true, mic: true, camera: true, location: true } },
    { consent: { accepted: true }, bridges: { clipboard: true }, killSwitch: { engaged: true } },
  ];
  for (const st of states) {
    const proj = G.project(st);
    ok("projection: ends with exactly one trailing newline", proj.endsWith("\n") && !proj.endsWith("\n\n"));
    const lines = proj.replace(/\n$/, "").split("\n");
    ok("projection: line 1 is exactly enabled|disabled", /^(enabled|disabled)$/.test(lines[0]));
    ok("projection: every line matches a wrapper grep anchor",
      lines.every((l, i) => (i === 0) || KNOWN.test(l) || CAP_RE.test(l)));
    ok("projection: no leading/trailing space on any line", lines.every((l) => l === l.trim()));
    ok("projection: exactly one container= marker (wrapper relies on it)",
      lines.filter((l) => l.startsWith("container=")).length === 1);
  }
  // Cross-check: the caps the wrapper's sed would extract == activeBridges() exactly.
  const st = { consent: { accepted: true }, bridges: { files: true, location: true } };
  const projCaps = G.project(st).split("\n").filter((l) => CAP_RE.test(l)).map((l) => l.replace(/=on$/, ""));
  ok("projection: caps the wrapper extracts == activeBridges()",
    JSON.stringify(projCaps) === JSON.stringify(S.activeBridges(st)));
}

/* ── 19. Bridge off round-trip + accept default scope + accept idempotence ─────── */
{
  const dir = scratch();
  const e = env(dir);
  runGated(["accept"], e);
  ok("scope: accept with no --scope defaults to the safer session",
    JSON.parse(readCanon(e)).consent.scope === "session");
  runGated(["bridge", "mic", "on"], e);
  ok("bridge-off: mic on → mic=on projected", hasLine(readProj(e), "mic=on"));
  runGated(["bridge", "mic", "off"], e);
  ok("bridge-off: mic off → mic=on gone from projection", !hasLine(readProj(e), "mic=on"));
  ok("bridge-off: mic off → canonical mic=false", JSON.parse(readCanon(e)).bridges.mic === false);
  ok("bridge-off: turning one off left no other cap on",
    S.BRIDGE_KEYS.filter((k) => hasLine(readProj(e), `${k}=on`)).length === 0);
  // A second accept is idempotent — stays accepted, never throws / regresses.
  ok("idempotent: second accept exits 0", runGated(["accept"], e).status === 0);
  ok("idempotent: still accepted after re-accept", JSON.parse(readCanon(e)).consent.accepted === true);
}

console.log(`gated: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
