"use strict";
/* ============================================================================
   sloboda-gated — the consent-gate DAEMON / WRITER (Waydroid tier)

   NON-ATTESTABLE escape-hatch tier — "Postern for postmarketOS — community
   edition". NOT "Porog" (the stock-Android managed-profile container) and NEVER
   "Postern OS". Reference / prototype only. UNAUDITED — certifies nothing.
   UNTESTED on-device: nothing here has booted a container.

   THIS IS THE MISSING MIDDLE. Two halves already shipped and did not meet:
     • the wrapper (paw-lib.sh) READS a flat line-file projection and treats
       anything but a literal "enabled" line-1 as OFF (fail-safe);
     • gate-store.mjs MODELS a rich deny-by-default posture but only persisted to
       browser localStorage.
   This daemon owns the on-device write side: it applies operator intents as
   PURE transforms over gate-store.mjs's normalize() trust boundary, atomically
   writes the canonical JSON, and compiles a PURE PROJECTION of it to the minimal
   line-file the wrapper reads. It adds NO new decision logic — the projection is
   a serialization of the shipped, node-tested containerAllowed()/activeBridges()
   helpers.

   HONESTY RAILS (enforced in code, not just prose):
     • never opens a bridge on its own — every grant is an explicit operator
       intent recorded into the canonical state;
     • never lowers `tier`, never clears `egress.torOnly` (both pinned by
       gate-store.normalize());
     • no network, no telemetry — the files never leave the device;
     • fail-safe: a crash mid-write leaves either the old file or nothing, and
       "nothing" reads as OFF at the wrapper. Skew is over-restrictive, never
       over-permissive.
   ============================================================================ */

import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";
import S from "./gate-store.mjs";

/* ---- paths (all env-overridable; the tests point them at a scratch dir) ----
   CANON_PATH_DEFAULT and gate-store.mjs's STATE_PATH agree on the shared
   contract dir `/var/lib/postern/sloboda-gate/` — one dir, one contract
   (field names AND spelling). The NixOS wiring (os/sloboda-compat.nix
   consentGate) pre-creates it 0700 to match CANON_DIR_MODE below. */
export const CANON_PATH_DEFAULT = "/var/lib/postern/sloboda-gate/state.json";
export const PROJECTION_PATH_DEFAULT = "/run/postern/consent/sloboda-bridge.state";
export const SLOBODA_BIN_DEFAULT = "sloboda";

export function canonPath(env = process.env) {
  return env.POSTERN_GATE_STATE || CANON_PATH_DEFAULT;
}
export function projectionPath(env = process.env) {
  // The wrapper reads PAW_BRIDGE_STATE; honour it so a single override aligns
  // both sides. POSTERN_BRIDGE_STATE takes precedence for the daemon's own view.
  return env.POSTERN_BRIDGE_STATE || env.PAW_BRIDGE_STATE || PROJECTION_PATH_DEFAULT;
}
export function androidBin(env = process.env) {
  return env.SLOBODA_BIN || SLOBODA_BIN_DEFAULT;
}

const CANON_MODE = 0o600;
const CANON_DIR_MODE = 0o700;
const PROJECTION_MODE = 0o644;
const PROJECTION_DIR_MODE = 0o755;

const nowIso = () => new Date().toISOString();

/* ---- atomic write: temp-in-same-dir → fsync → chmod → rename ----------------
   rename() is atomic within a filesystem, so a reader never observes a partial
   file. We chmod the temp before the rename so the target appears at its final
   mode in one step. A best-effort directory fsync flushes the rename itself.

   Robustness rails:
     • the temp name is unique per call (pid + monotonic counter + random) so two
       writes to the same target from one process can never clobber each other's
       temp, and a stale temp from a crashed prior run is never reused;
     • O_EXCL ("wx") means we never adopt a pre-existing temp we didn't create;
     • on ANY failure (write/fsync/chmod/rename) the temp is unlinked before the
       error propagates, so a failed write leaves NO residue and NO partial target
       — the reader sees either the prior file or nothing, and nothing reads OFF. */
let _tmpSeq = 0;
export function atomicWrite(target, content, { mode, dirMode }) {
  const dir = path.dirname(target);
  fs.mkdirSync(dir, { recursive: true, mode: dirMode });
  // Force the dir mode even if it pre-existed with a looser one (best-effort).
  try { fs.chmodSync(dir, dirMode); } catch { /* not our dir; leave it */ }

  const uniq = `${process.pid}.${++_tmpSeq}.${Math.random().toString(36).slice(2, 10)}`;
  const tmp = path.join(dir, `.${path.basename(target)}.${uniq}.tmp`);
  try {
    const fd = fs.openSync(tmp, "wx", mode); // wx = O_EXCL: fail if it somehow exists
    try {
      fs.writeSync(fd, content);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.chmodSync(tmp, mode); // openSync mode is masked by umask; pin it exactly
    fs.renameSync(tmp, target);
  } catch (e) {
    try { fs.unlinkSync(tmp); } catch { /* nothing to clean up */ }
    throw e;
  }
  try {
    const dfd = fs.openSync(dir, "r");
    try { fs.fsyncSync(dfd); } catch { /* dir fsync unsupported on some FS */ }
    finally { fs.closeSync(dfd); }
  } catch { /* best-effort */ }
}

/* ---- discriminator + version guard (contract rail #1, shared with the spine) --
   The single predicate that decides whether an on-disk blob is even OUR file.
   Kept as a pure, exported function so the tests pin it directly and so Dev D can
   hold gate-store.parse() / the consent-spine loadState() to the SAME semantics.

   Refuse (→ false → full-deny) unless ALL hold, each checked STRICTLY (no coercion):
     • the blob is a non-null, non-array object;
     • `schema` is a string EXACTLY equal to S.SCHEMA_ID (a foreign product, a
       typo, or a number/bool masquerading as schema all fail);
     • `version` is a number EXACTLY equal to S.SCHEMA_VERSION (the string "1"
       fails the `!==` — fail-safe: an unknown/future version is refused, never
       optimistically accepted).
   Defence-in-depth note on `tier`: we do NOT trust an input `tier` even when the
   discriminator matches — gate-store.normalize() re-pins it to TIER regardless —
   but if a blob that otherwise looks canonical carries a *relabelled* tier
   ("attested"…) we still refuse it here, because a correctly-versioned file
   should never disagree on the pinned rail; a mismatch means it was tampered
   with or hand-edited, and fail-safe is to distrust it wholesale. */
export function discriminatorOk(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return false;
  if (typeof raw.schema !== "string" || raw.schema !== S.SCHEMA_ID) return false;
  if (typeof raw.version !== "number" || raw.version !== S.SCHEMA_VERSION) return false;
  // tier, if present, must be the pinned value; absent is fine (normalize pins it).
  if (raw.tier !== undefined && raw.tier !== S.TIER) return false;
  return true;
}

/* ---- load canonical (the trust boundary) ------------------------------------
   Absent / unreadable / malformed / foreign-schema / version-mismatch / relabelled
   / hostile → full-deny defaultState(). Never throws.

   The shipped gate-store.parse() normalizes but does NOT reject a foreign
   schema/version — it silently keeps well-formed fields. So the WRITER guards the
   discriminator here BEFORE trusting the blob (discriminatorOk above): a file that
   is not provably ours is treated as absent → full-deny. This is a guard, not new
   consent logic; the meaning of the fields still lives in gate-store's
   normalize()/containerAllowed(). */
export function loadCanonical(env = process.env) {
  let text;
  try { text = fs.readFileSync(canonPath(env), "utf8"); }
  catch { return S.defaultState(); }
  let raw;
  try { raw = JSON.parse(text); } catch { return S.defaultState(); }
  if (!discriminatorOk(raw)) return S.defaultState(); // foreign/version/relabel → refuse
  return S.normalize(raw);
}

/* ---- egress posture: a PURE projection of gate-store.egressAllowed() ---------
   The Tor-only egress rail (design §2.2 / CONTRACT Waydroid tier-rail) is
   fail-closed: the container may reach the network ONLY while it is allowed to
   run AND egress is pinned Tor-only AND postern-tor reports a live circuit
   (egress.torBootstrapped). This is INDEPENDENT of the data bridges — a consented
   container with zero bridges still talks to the network, and it must do so over
   Tor or not at all. So egress is projected on its own additive line:
     egress=blocked   container not allowed to run at all (consent/kill) → no net.
     egress=held      container allowed, but Tor is NOT yet bootstrapped → traffic
                      is HELD (fail-closed) until the tor-glue signals `tor up`.
     egress=tor       container allowed AND Tor live → egress may flow, Tor-only.
   Three-value (not a bare on/off) so the wrapper/tor-glue can tell "waiting for
   Tor" (held, retry) apart from "not permitted" (blocked, refuse). The value is
   never `on`, so it is NOT mistaken for a `<cap>=on` bridge line by the reader. */
export function egressPosture(state) {
  const s = S.normalize(state);
  if (!S.containerAllowed(s)) return "blocked";
  return S.egressAllowed(s) ? "tor" : "held";
}

/* ---- projection: a PURE function of the canonical state ---------------------
   Line 1 is the BRIDGE posture and keeps the shipped wrapper's `== "enabled"`
   contract byte-for-byte: "enabled" iff the container is allowed AND ≥1 bridge
   is open. The additive KEY lines an old wrapper ignores safely:
     container=allowed|blocked   the CONTAINER-ENTRY posture (consent + kill),
                                 independent of whether any bridge is open — so a
                                 consented user with NO bridges can still enter
                                 (design §2.3.4: "accept is permission to run the
                                 container, not permission to share").
     egress=tor|held|blocked     the Tor-only network-egress posture (fail-closed).
     kill=engaged                present only while the kill-switch is engaged.
     <cap>=on                    one per active bridge (only when line 1 enabled).
   No new decisions: containerAllowed()/activeBridges()/egressAllowed() are the
   shipped, node-tested helpers — the projection serializes them, never invents. */
export function project(state) {
  const s = S.normalize(state);
  const allowed = S.containerAllowed(s);
  const active = S.activeBridges(s); // [] when !allowed
  const line1 = allowed && active.length > 0 ? "enabled" : "disabled";
  const lines = [
    line1,
    `container=${allowed ? "allowed" : "blocked"}`,
    `egress=${egressPosture(s)}`,
  ];
  if (s.killSwitch.engaged) lines.push("kill=engaged");
  if (line1 === "enabled") for (const k of active) lines.push(`${k}=on`);
  return lines.join("\n") + "\n";
}

/* ---- write both files: canonical first, projection derived LAST -------------
   Projection-last means the worst two-file skew (crash between the two writes)
   leaves a fresh/older projection → the wrapper reads more-restrictive, never
   more-permissive. */
export function persist(state, env = process.env) {
  const canonical = S.serialize(state); // normalizes + pins tier/egress
  atomicWrite(canonPath(env), canonical, { mode: CANON_MODE, dirMode: CANON_DIR_MODE });
  const proj = project(state);
  atomicWrite(projectionPath(env), proj, { mode: PROJECTION_MODE, dirMode: PROJECTION_DIR_MODE });
  return { canonical, projection: proj };
}

/* ---- operator-intent transforms (record intent; NO decision logic) ---------
   Each returns a new state object; gate-store.normalize()/containerAllowed()
   remain the sole authority on what those fields MEAN. */
export function applyAccept(state, scope, iso = nowIso()) {
  const s = S.normalize(state);
  s.consent.accepted = true;
  s.consent.scope = S.CONSENT_SCOPES.includes(scope) ? scope : "session";
  s.consent.acceptedAtIso = iso;
  return s;
}
export function applyWithdraw(state) {
  const s = S.normalize(state);
  s.consent.accepted = false;
  s.consent.acceptedAtIso = null;
  return s;
}
export function applyBridge(state, cap, on) {
  const s = S.normalize(state);
  if (!S.BRIDGE_KEYS.includes(cap)) {
    throw new Error(`unknown bridge '${cap}' (expected: ${S.BRIDGE_KEYS.join("|")})`);
  }
  s.bridges[cap] = on === true;
  return s;
}
export function applyKill(state, engaged, iso = nowIso()) {
  const s = S.normalize(state);
  s.killSwitch.engaged = engaged === true;
  s.killSwitch.engagedAtIso = engaged === true ? iso : null;
  return s;
}
/* The tor-glue's live "is a circuit up?" signal — the ONLY egress input any
   external actor writes. It flips egress.torBootstrapped ONLY; torOnly stays
   pinned true by normalize(), so this can never widen egress to clearnet. `up`
   opens Tor egress (subject to container-allowed); anything else HOLDS it
   (fail-closed) — a half-open or dropped circuit is treated as no Tor. */
export function applyEgress(state, bootstrapped) {
  const s = S.normalize(state);
  s.egress.torBootstrapped = bootstrapped === true;
  return s;
}
/* Boot re-projection + session re-ask (design §5.2 #2). The projection lives on
   /run tmpfs and is GONE after a reboot, so it must be re-derived from canonical
   on boot before any wrapper reads it. Additionally, `scope:"session"` consent is
   meant to last only the session it was granted in: on boot we clear it so the
   user is re-asked, while `scope:"persistent"` survives. torBootstrapped is also
   cleared — Tor is definitionally down at boot until the glue re-signals `up`
   (fail-closed). A pure transform; the caller persists + re-projects. */
export function applyBoot(state) {
  const s = S.normalize(state);
  if (s.consent.scope === "session") {
    s.consent.accepted = false;
    s.consent.acceptedAtIso = null;
  }
  s.egress.torBootstrapped = false; // Tor is down until the glue re-signals up
  return s;
}

/* ---- kill-switch runtime actuator hand-off ----------------------------------
   The gate owns intent + state; the WRAPPER owns runtime teardown. After the
   canonical/projection are persisted (projection already "disabled"/blocked so
   the wrapper refuses re-entry), we exec `sloboda kill`. Env is
   inherited so the test harness's PAW_DRYRUN / mock / PATH flow through. */
export function execWrapperKill(env = process.env) {
  const bin = androidBin(env);
  const r = spawnSync(bin, ["kill"], { stdio: "inherit", env });
  if (r.error) {
    process.stderr.write(`sloboda-gated: WARN: could not exec '${bin} kill': ${r.error.message}\n`);
    process.stderr.write("sloboda-gated: state is persisted + projected 'disabled'; run the teardown manually.\n");
    return 127;
  }
  return typeof r.status === "number" ? r.status : 0;
}

/* ---- systemd ordering unit (emitted as TEXT; install is Dev C's os/ + VM) ----
   The projection lives on /run tmpfs and evaporates on reboot, so SOMETHING must
   run `sloboda-gated boot` early — before the Waydroid container or any wrapper
   entry path reads the projection — to re-derive it and apply the session re-ask.
   This emits that oneshot unit so the ordering contract is explicit and reviewable
   on HOST; the daemon itself never installs or talks to systemd. Actually PROVING
   the ordering (no race: projection present before first wrapper read) is
   VM-BLOCKED — matrix #13 / design §5.2 #8 — and stays UNTESTED until Dev C's
   binder VM boots it. `%h`-free system unit; the install path parameterizes ExecStart. */
export function systemdUnit(execPath = "sloboda-gated") {
  return `# sloboda-gate-boot.service — re-derive the consent projection on boot.
# NON-ATTESTABLE tier; UNAUDITED. Ordering is VM-UNTESTED (design §5.2 #8).
# Install: Dev C's os/sloboda-compat.nix (systemd.services), NOT this daemon.
[Unit]
Description=Sloboda consent-gate: re-derive /run projection on boot (non-attestable)
DefaultDependencies=no
After=local-fs.target
# The projection MUST exist before anything can enter the container:
Before=waydroid-container.service graphical-session.target

[Service]
Type=oneshot
RemainAfterExit=yes
# Re-derives the projection from persistent canonical + applies the session re-ask.
ExecStart=${execPath} boot

[Install]
# Order this ahead of every consumer of the projection.
RequiredBy=waydroid-container.service
WantedBy=multi-user.target
`;
}

function log(msg) { process.stderr.write(`sloboda-gated: ${msg}\n`); }

function usage() {
  process.stdout.write(`sloboda-gated — consent-gate writer (NON-ATTESTABLE tier, UNAUDITED)

USAGE:
  sloboda-gated <command>

COMMANDS:
  accept [--scope session|persistent]   Record informed consent (default session).
  withdraw                              Revoke consent (container refuses next entry).
  bridge <cap> on|off                   Toggle one host<->Android bridge.
                                        cap in ${S.BRIDGE_KEYS.join(", ")}
  tor up|down                           Record the tor-glue's live circuit signal
                                        (egress.torBootstrapped). 'down' HOLDS
                                        egress fail-closed; egress stays Tor-only.
  kill on                               Engage kill-switch: persist + project
                                        'disabled', then exec 'sloboda kill'.
  kill off                              Disengage kill-switch (re-startable).
  boot                                  Re-derive the projection from canonical +
                                        apply the session re-ask (run once on boot).
  project                               Re-derive the projection from canonical
                                        (no state change).
  systemd-unit                          Print the boot-ordering systemd unit (text
                                        only; install is the NixOS module's job).
  status                                Print the current posture (no side effects).

Every mutation atomically writes the canonical JSON and re-derives the projection.
The daemon does NO network I/O. Bridges are DENY-by-default; nothing bundles.
Canonical: ${canonPath()}
Projection: ${projectionPath()}
`);
}

function cmdStatus(env) {
  const s = loadCanonical(env);
  const allowed = S.containerAllowed(s);
  const active = S.activeBridges(s);
  process.stdout.write(`tier:         ${s.tier}\n`);
  process.stdout.write(`consent:      ${s.consent.accepted ? `accepted (scope=${s.consent.scope})` : "NOT accepted"}\n`);
  process.stdout.write(`killSwitch:   ${s.killSwitch.engaged ? "ENGAGED" : "clear"}\n`);
  process.stdout.write(`container:    ${allowed ? "allowed" : "BLOCKED"}\n`);
  process.stdout.write(`bridges:      ${active.length ? active.join(", ") : "(none)"}\n`);
  process.stdout.write(`egress:       Tor-only (pinned) → ${egressPosture(s)}${s.egress.torBootstrapped ? " (circuit up)" : " (HELD until Tor up)"}\n`);
  process.stdout.write(`projection:   ${JSON.stringify(project(s).split("\n")[0])} @ ${projectionPath(env)}\n`);
}

export function main(argv = process.argv.slice(2), env = process.env) {
  const cmd = argv[0] || "help";
  try {
    switch (cmd) {
      case "accept": {
        let scope = "session";
        const i = argv.indexOf("--scope");
        if (i >= 0 && argv[i + 1]) scope = argv[i + 1];
        const s = applyAccept(loadCanonical(env), scope);
        persist(s, env);
        log(`consent accepted (scope=${s.consent.scope}). Bridges stay OFF until each is toggled.`);
        return 0;
      }
      case "withdraw": {
        persist(applyWithdraw(loadCanonical(env)), env);
        log("consent withdrawn. The container will refuse entry until re-accepted.");
        return 0;
      }
      case "bridge": {
        const cap = argv[1];
        const verb = argv[2];
        if (verb !== "on" && verb !== "off") { log("usage: bridge <cap> on|off"); return 2; }
        const s = applyBridge(loadCanonical(env), cap, verb === "on");
        persist(s, env);
        log(`bridge ${cap} ${verb}. (one lever at a time; nothing bundles)`);
        return 0;
      }
      case "tor": {
        const verb = argv[1];
        if (verb !== "up" && verb !== "down") { log("usage: tor up|down"); return 2; }
        const s = applyEgress(loadCanonical(env), verb === "up");
        persist(s, env);
        log(`tor ${verb}: egress.torBootstrapped=${verb === "up"} → projection egress=${egressPosture(s)} (Tor-only, fail-closed).`);
        return 0;
      }
      case "kill": {
        const verb = argv[1];
        if (verb !== "on" && verb !== "off") { log("usage: kill on|off"); return 2; }
        const engaged = verb === "on";
        const s = applyKill(loadCanonical(env), engaged);
        persist(s, env); // projection is now 'disabled'/blocked BEFORE teardown
        if (engaged) {
          log("kill-switch ENGAGED: state persisted, projection 'disabled'. Tearing down runtime…");
          return execWrapperKill(env); // hand off to the wrapper's actuator
        }
        log("kill-switch disengaged. Container may start again once consent is present.");
        return 0;
      }
      case "boot": {
        // Re-derive the /run projection after a reboot + apply the session re-ask.
        const s = applyBoot(loadCanonical(env));
        persist(s, env);
        log(`boot: projection re-derived (${project(s).split("\n")[0]}); ` +
            `${s.consent.accepted ? "persistent consent kept" : "session consent cleared — re-ask"}.`);
        return 0;
      }
      case "project": {
        const s = loadCanonical(env);
        atomicWrite(projectionPath(env), project(s), { mode: PROJECTION_MODE, dirMode: PROJECTION_DIR_MODE });
        log(`projection re-derived: ${project(s).split("\n")[0]}`);
        return 0;
      }
      case "systemd-unit": {
        // Text only — the daemon never touches systemd; install is Dev C's os/.
        // SLOBODA_GATED_BIN lets the packager pin an absolute ExecStart path.
        process.stdout.write(systemdUnit(env.SLOBODA_GATED_BIN || "sloboda-gated"));
        return 0;
      }
      case "status":
        cmdStatus(env);
        return 0;
      case "help": case "-h": case "--help":
        usage();
        return 0;
      default:
        log(`unknown command: ${cmd}`);
        usage();
        return 2;
    }
  } catch (e) {
    log(`ERROR: ${e && e.message ? e.message : e}`);
    return 1;
  }
}

const invokedDirectly =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedDirectly) {
  process.exit(main());
}

export default {
  canonPath, projectionPath, androidBin, atomicWrite, discriminatorOk, loadCanonical,
  egressPosture, project, persist, applyAccept, applyWithdraw, applyBridge, applyKill,
  applyEgress, applyBoot, execWrapperKill, systemdUnit, main,
  CANON_PATH_DEFAULT, PROJECTION_PATH_DEFAULT, SLOBODA_BIN_DEFAULT,
};
