"use strict";
/* ============================================================================
   os/test-sloboda-gate-boot-unit.mjs — byte-parity pin for the gate boot unit

   The NixOS wiring (os/sloboda-compat.nix, postern.slobodaCompat.consentGate)
   installs sloboda-gate-boot.service from the checked-in template
   os/sloboda-gate-boot.service.in, substituting ONLY the `@sloboda-gated@`
   ExecStart placeholder with the packaged binary's store path. The CONTRACT
   for that unit's text is what apps/sloboda-gate/sloboda-gated.mjs
   systemdUnit() emits (the node-tested writer owns the ordering semantics:
   Before=waydroid-container.service, `<bin> boot`, RemainAfterExit).

   This test pins the template BYTE-FOR-BYTE to systemdUnit("@sloboda-gated@"),
   so the nix-installed unit can never silently drift from the writer's
   contract. If systemdUnit() changes, regenerate the template:

     SLOBODA_GATED_BIN='@sloboda-gated@' \
       node apps/sloboda-gate/sloboda-gated.mjs systemd-unit \
       > os/sloboda-gate-boot.service.in

   HONESTY: byte-parity here proves TEXT equality only. That the unit actually
   orders the projection ahead of the first wrapper read (no boot race), and
   that waydroid-container.service honours the Before/RequiredBy edges, is
   VM-BLOCKED and stays UNTESTED until the sloboda-vm boots (matrix #13).
   Non-attestable tier; UNAUDITED.

   Run: node os/test-sloboda-gate-boot-unit.mjs
   ============================================================================ */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { systemdUnit } from "../apps/sloboda-gate/sloboda-gated.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const templatePath = path.join(here, "sloboda-gate-boot.service.in");

let pass = 0;
let fail = 0;
function ok(cond, msg) {
  if (cond) { pass++; }
  else { fail++; process.stderr.write(`FAIL: ${msg}\n`); }
}

const template = fs.readFileSync(templatePath, "utf8");
const emitted = systemdUnit("@sloboda-gated@");

// 1. The whole point: byte-for-byte parity with the writer's emitted contract.
ok(template === emitted,
  `template != systemdUnit("@sloboda-gated@") — regenerate os/sloboda-gate-boot.service.in (see header)`);

// 2. Belt-and-suspenders pins on the load-bearing ordering lines, so a failure
//    names WHICH part of the contract broke instead of only "bytes differ".
ok(template.includes("Before=waydroid-container.service"),
  "missing Before=waydroid-container.service (projection must exist before container entry)");
ok(template.includes("ExecStart=@sloboda-gated@ boot"),
  "missing ExecStart '@sloboda-gated@ boot' (the boot re-projection + session re-ask)");
ok(template.includes("RemainAfterExit=yes"),
  "missing RemainAfterExit=yes (oneshot must stay 'active' for the ordering edges)");
ok(template.includes("Type=oneshot"), "missing Type=oneshot");
ok(template.includes("RequiredBy=waydroid-container.service"),
  "missing RequiredBy=waydroid-container.service (container must not start without the gate)");

// 3. The nix substitution seam: exactly one placeholder occurrence, in ExecStart.
const holes = template.split("@sloboda-gated@").length - 1;
ok(holes === 1, `expected exactly one @sloboda-gated@ placeholder, found ${holes}`);

process.stdout.write(`sloboda-gate-boot-unit parity: ${pass} passed, ${fail} failed\n`);
process.exit(fail === 0 ? 0 : 1);
