<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Sloboda — Wave-1 execution plan (make it FUNCTIONAL)

**PMO deliverable · non-attestable Waydroid escape-hatch tier (formerly
"postern-android", now Sloboda). Branch: `roadmap/wave1-base`.**

> ## HONESTY HEADER — read before trusting anything below
>
> Sloboda is the **NON-ATTESTABLE escape-hatch tier** — "Postern for postmarketOS
> — community edition". It is **NOT Porog** (the stock-Android managed-profile
> product) and **NEVER "Postern OS"**. It drives **Waydroid**: a full AOSP/Google
> userland in LXC on the host kernel.
>
> - **Never covered by the Postern Seal.** `os_roothash` says nothing about the
>   mutable Android image (pulled from upstream at `waydroid init`).
> - **Entering Android = data leaves the sealed base.**
> - **Play Integrity STRONG fails by design** — disclosed, never spoofed.
> - **Default-SAFE**: the wrapper only *reads* a consent toggle; anything but a
>   literal `enabled` line-1 is OFF. **VANILLA** (Google-free) is the only default;
>   no GMS is redistributed.
> - **UNTESTED**: nothing here has ever booted an Android container. Wave-1 makes
>   the scaffold *real and provable one honest tier at a time* — it does not claim
>   the boot has happened. This tier is in `NONATTEST_PATHS`
>   (`scripts/check-trust-labels.sh`); every surface must keep that green.

---

## 0. Where Wave-0 left us (the foundation these 5 devs build on)

Wave-0 already shipped more than a stub. Verified by inspection:

| Component | File(s) | State after Wave-0 |
|---|---|---|
| Reader wrapper | `apps/sloboda/bin/sloboda`, `bin/paw-lib.sh` | Full command surface + the **refuse-gate** (`paw_container_allowed` / `paw_require_container_allowed`), per-cap read, kill actuator (`cmd_kill`). Read-only over the projection. |
| Writer daemon | `apps/sloboda-gate/sloboda-gated.mjs` + `sloboda-gated` shim | Atomic canonical+projection writer; `accept/withdraw/bridge/kill/project/status`; **discriminator guard** in `loadCanonical()`; kill hand-off execs `sloboda kill`. |
| State model | `apps/sloboda-gate/gate-store.mjs` | Deny-by-default `normalize()`; pinned `tier`/`egress.torOnly`; `containerAllowed`/`activeBridges`/`egressAllowed`. |
| Shared contract | `apps/consent-contract/` (`consent-spine.mjs`, schema, `CONTRACT.md`) | One spine across sloboda/noporis/porog; 117-assertion proof. `gate-store.mjs` is byte-compatible but does **not** yet import the spine. |
| NixOS wiring | `os/sloboda-compat.nix` | Binder kernel (`ANDROID_BINDER_IPC`/`BINDERFS` forced `=y`), `virtualisation.waydroid.enable`, Weston/Phosh option, seal-exclusion assertion. Structurally outside the attested closure. **Never evaluated** (no Nix on the macOS host). |
| Offline harness | `apps/sloboda/test/dry-run.sh`, `test/mock-waydroid` | Two-mode harness (dry-run trace + mock exec) covering refuse-gate, consent accept, kill-switch end-to-end, launcher gen/prune, read-only proofs. Node daemon unit test in `apps/sloboda-gate/test-gated.mjs`. |

**So Wave-1 is not greenfield — it is HARDENING + REAL-LIFECYCLE WIRING + the VM
boot path + test scaffolding toward first boot.** The mock "boots nothing"; the
job now is to make each real `waydroid` call succeed in a binder-capable VM and to
close the honesty-labelled gaps.

Two carried-over follow-ups Wave-1 must fold in:
1. **Rename residue** — human wordmark `Postern Android` / `POSTERN·ANDROID` and env
   `POSTERN_ANDROID_BIN` still linger post-rename to Sloboda (see §5).
2. **Contract reconciliation** — `sloboda-gated.mjs` flags (Dev 0.1 note) that the
   canonical dir spelling / discriminator guard should be pinned against the shared
   spine.

---

## 1. Build order & tier model

Three run-locations (from `bridge-build-test-infra.md`):

- **HOST** — the macOS `bloch-mac` runner today. Runs `shellcheck`, `node`, the
  mock `dry-run.sh`, honesty gates. **Proves control-flow only; boots nothing.**
- **VM** — incoming Linux + Nix VM, x86_64, **binder-capable kernel**. Proves the
  Waydroid control path to `Session: RUNNING` under software GL. The single
  highest-leverage tier — flips UNTESTED → "booted once (VM)".
- **device** — real aarch64 phone with hardware GL (Lima/Panfrost). The only place
  the GPU path and the device-real halves close. Manual, never CI-green.

**Every dev WRITES their code now on HOST regardless of tier.** The tier label says
where the code can be *proven*, not where it is *written*. Honest rule: a test that
has not run on its tier is `UNTESTED`, never `passing`.

Recommended landing order (parallel where independent):

```
Foundation (Wave-0, done) ─┬─ Dev A  daemon hardening        ] parallel, HOST-provable
                           ├─ Dev B  wrapper refuse/kill/launcher ] parallel, HOST-provable
                           ├─ Dev D  model+UI+contract+naming  ] parallel, HOST-provable
                           └─ Dev E  harness (mock+dry-run)    ] parallel, HOST-provable
                                        │
   Dev C  os/sloboda-compat + VM host  │  (writes now; VM-blocked to prove)
                                        ▼
                          Dev E  VM boot-to-RUNNING smoke  (VM-blocked; needs C's VM + real waydroid)
                                        ▼
                          Device rung (out of Wave-1 CI; manual runbook)
```

Dev D's **naming sweep is serialized to the tail** (§5) — the one deliberate
cross-owner touch. Everything else is genuinely parallel.

---

## 2. The A7 verification matrix — 13 items, tiered

This anchors the test plan. Legend: **HOST** = mock/control-flow provable now;
**VM** = binder kernel + real Waydroid (x86_64, software GL); **device** = aarch64
hardware GL only. "VM*" = VM proves the mechanism, a device-specific detail remains.

| # | Unknown | Tier to PROVE | Owner(s) | Proving artifact |
|---|---|---|---|---|
| 1 | Kernel binder/binderfs | **VM** (mechanism) · device (that the *phone* kernel has it) | C (nix) / E (smoke) | `zgrep ANDROID_BINDER /proc/config.gz`; `/dev/binderfs` mounts |
| 2 | `init` pulls image per type | **VM** (x86 VANILLA) · device (aarch64 image, FOSS 404s) | C / E | `waydroid init -s VANILLA` lands image; curl image index |
| 3 | microG post-init | **VM** (arch-independent) | E | community `waydroid_script`, no boot-loop |
| 4 | `session start` → `Session: RUNNING` + string contract | **VM** | E (smoke) / B (parser) | `sloboda start` returns 0; real `waydroid status` matches `*Session*RUNNING*` |
| 5 | Wayland compositor displays | **VM** (Weston) · device (Phosh/touch) | C / E | `sloboda ui`; Android surface renders |
| 6 | `app list` parser format | **VM** | B (parser) / E | real `waydroid app list` matches `Name:`/`packageName:` |
| 7 | `app launch <pkg>` foregrounds | **VM** (software GL) | B / E | single-app path works |
| 8 | Aurora install + account-free delivery | **VM*** · device (arm-native apps) | E | Aurora delivers anonymously |
| 9 | Host `.desktop` launchers + re-enter | **VM*** (gen/perms/click) · device (Phosh grid) | B / E | files in `PAW_DESKTOP_DIR`; `update-desktop-database` refresh; click round-trip |
| 10 | Kill-switch non-destructive + re-startable | **VM** | A / B / E | `sloboda kill` → down + image intact; re-`start` RUNNING, no re-init |
| 11 | **GPU path (Lima/Panfrost vs SwiftShader)** | **device ONLY** | C (device rung) | active GL backend on Mali panel. **VM proves only software fallback.** |
| 12 | Play Integrity reality | **VM** (STRONG fails) · device (which apps refuse) | E | checker app: STRONG fails; record BASIC/DEVICE |
| 13 | Consent-gate integration | **VM** (filesystem, arch-independent) | A / B / E | daemon writes projection; wrapper read-only check matches path + `enabled` line-1 |

**Tally: ~10-11 VM-provable, item 11 is hard device-only, and the device-real
*halves* of 1/2/5/8/9/12 sit on top of a VM-proven mechanism.** Everything the mock
covers today is HOST; the leap Wave-1 sets up is HOST → VM.

---

## 3. Integration & test strategy

**T0 / HOST (green now, extend in Wave-1):**
- `shellcheck -x -s sh apps/sloboda/bin/* apps/sloboda/test/*`
- `node apps/sloboda-gate/test-gated.mjs`, `node apps/sloboda-gate/test-store.mjs`,
  `node apps/consent-contract/test-spine.mjs`
- `sh apps/sloboda/test/dry-run.sh` (mock, boots nothing) — the two-mode harness
- `bash scripts/check-trust-labels.sh` (BLOCKING: no attestation-word bleed) +
  `scripts/ci-honesty-products.sh` (naming: never "Postern OS")

**T1 / VM (new; blocked until the binder VM exists):**
- `scripts/vm/waydroid-boot-smoke.sh` (Dev E, new): binder present → `weston
  --backend=headless` → `waydroid init -s VANILLA` → `sloboda start` reaches
  `Session: RUNNING` → run `dry-run.sh` MODE 2 **against real waydroid**
  (`PAW_DRYRUN=0`, mock off PATH) → `app list`/`launch`/launchers/kill-switch.
  Proves matrix items 1,4,5,6,7,9,10,13 (+3,8,12 VM halves).
- Boot target = Dev C's non-attested VM host (`os/sloboda-vm.nix`) importing
  `os/sloboda-compat.nix`; `nix flake check` + QEMU boot.

**T2 / device (out of Wave-1 CI — manual, logged):** item 11 (hardware GL), the
device-kernel half of 1, aarch64 image (2), Phosh/touch (5,9), arm-native apps (8),
exact refusals (12). Lands in a signed device log, never a pipeline exit code.

**CI honesty rules (from A10):** tier is a job-name prefix (`t0:`/`t1:`); a `t0`
pass never implies `t1`/`t2`; absent tiers surface as `UNTESTED-until-hardware`,
not green.

---

## 4. The 5-dev partition (strict non-overlapping ownership)

See the structured task list returned to the PMO. Ownership summary (each file has
exactly one Wave-1 owner):

| Dev | Workstream | Exclusive files/dirs |
|---|---|---|
| **A** | Consent-gate **daemon** hardening + real-lifecycle wiring | `apps/sloboda-gate/sloboda-gated.mjs`, `apps/sloboda-gate/sloboda-gated`, `apps/sloboda-gate/test-gated.mjs` |
| **B** | Wrapper **refuse-gate + kill-switch + launcher** (reader, shell) | `apps/sloboda/bin/sloboda`, `bin/paw-lib.sh`, `bin/sloboda-installwatch`, `config/sloboda.conf.sample` |
| **C** | `sloboda-compat.nix` **bring-up + VM boot path** (A7 matrix) | `os/sloboda-compat.nix`, `os/sloboda-vm.nix` (new), the `sloboda-vm` `nixosConfigurations` entry in `flake.nix` |
| **D** | State **model + UI + shared-contract adherence + naming sweep** | `apps/sloboda-gate/gate-store.mjs`, `gate-state.schema.json`, `state.example.json`, `test-store.mjs`, `apps/sloboda-gate/index.html`, `apps/sloboda/ui/index.html`, `apps/sloboda/share/applications/sloboda.desktop`, `apps/sloboda/README.md`, `apps/consent-contract/*` |
| **E** | **Test harness** (mock + dry-run) + VM boot-to-RUNNING scaffolding | `apps/sloboda/test/dry-run.sh`, `apps/sloboda/test/mock-waydroid`, `scripts/vm/waydroid-boot-smoke.sh` (new) |

**Import boundaries (no file overlap):**
- A's daemon *consumes* D's `gate-store.mjs` API read-only (writer over model).
- B's wrapper *reads* the projection file A writes (reader over writer); B never
  writes consent state.
- E's harness *drives* A's daemon + B's wrapper as black boxes; owns the mock they
  run against.
- C's VM host *imports* the module C owns; provides the runtime E's VM smoke needs.

**Coordination points (semantics, not shared files):**
- **A ↔ D** on the discriminator/version guard: A hardens `loadCanonical()` in the
  daemon; D aligns `gate-store.mjs` + the spine to reject foreign schema. Agree the
  guard contract; edit separate files.
- **A ↔ B ↔ E** on the projection line-format (`container=allowed|blocked`,
  `kill=engaged`, `<cap>=on`): the wire contract between writer, reader, and the
  tests. Frozen early; changes ripple to all three tests.
- **C ↔ E** on the VM smoke: C guarantees binder + Weston + `waydroid` on PATH; E
  writes the smoke script that asserts `Session: RUNNING`.
- **D naming sweep (§5)** is the ONE deliberate cross-owner edit — serialized last.
- **flake.nix** is foundation-shared, but C is the only Wave-1 Sloboda dev touching
  it (one additive `nixosConfigurations.sloboda-vm` hunk). Coordinate with the OS
  owner; keep the entry OUT of the attested list.

---

## 5. Naming cleanup (Dev D, serialized final sweep)

Post-rename residue of `Postern Android` / `POSTERN·ANDROID` and env
`POSTERN_ANDROID_BIN`. Dev D owns the naming DECISION + the sweep. Affected surfaces
(from a repo scan):

- **D-owned (cosmetic, do inline):** `apps/sloboda/README.md`,
  `share/applications/sloboda.desktop` (Name/Categories `X-Postern-Android`),
  `apps/sloboda/ui/index.html` (title, wordmark), `apps/sloboda-gate/index.html`
  (title, wordmark, About copy pt-BR/en), `gate-store.mjs` header,
  `gate-state.schema.json` title.
- **Cross-owner (serialize AFTER A/B/E freeze):** header banners in
  `apps/sloboda/bin/sloboda`, `bin/paw-lib.sh`, `bin/sloboda-installwatch`,
  `config/sloboda.conf.sample` (B), `apps/sloboda/test/dry-run.sh` (E),
  `apps/sloboda-gate/sloboda-gated.mjs` + `test-gated.mjs` (A) — comment wordmarks
  only. Plus the functional env token **`POSTERN_ANDROID_BIN`** in
  `sloboda-gated.mjs`, `test-gated.mjs` (A) and `dry-run.sh` (E).

**Env-token decision:** rename `POSTERN_ANDROID_BIN` → `SLOBODA_BIN` (keeping
`POSTERN_ANDROID_BIN` as a fallback alias for one release is optional). This is a
private test/actuator contract, so the rename is low-risk BUT spans A+E files —
hence it runs in D's serialized sweep, after A and E have landed their functional
Wave-1 changes, with those owners rebasing over the cosmetic hunk.

**Also update** `scripts/ci-honesty-products.sh` guidance strings that still call
the tier "Postern Android" (coordinate with the honesty-gate owner; those refer to
the tier name, may be intentional — confirm before editing).

Honesty guardrail for D on every surface: `scripts/check-trust-labels.sh` stays
green; no attestation word without an adjacent negation; never "Postern OS"; keep
"UNTESTED", "STRONG fails", "non-attestable", "VANILLA default", "built on
Waydroid" (nominative) intact.

---

## 6. Top risks (Wave-1)

1. **Binder kernel on NixOS is fragile** — `ANDROID_BINDER_IPC`/`BINDERFS` are not
   default; the VM's first Waydroid boot may fail on kernel config and need a
   rebuild. Dev C's crux; budget for it.
2. **VM is x86_64, product is aarch64** — VM proves control-flow only; GPU (11),
   aarch64 image (2), Play-Integrity refusals (12) stay device-only. Guard against
   reading a green `t1:` as "works on the phone".
3. **Two-file skew** — canonical vs projection; mitigated by projection-derived-last
   + fail-safe reader (absent → OFF). Over-restrictive is the worst case.
4. **Projection wire-contract drift** — if A changes the projection format without
   B/E, the refuse-gate or tests silently mis-read. Freeze the format in §4 early.
5. **Contract fork** — `gate-store.mjs` staying flat-bool while the spine widens to
   `{open,scope}` forks the shared validator. D's v2 widening is a `normalize()`
   change, reader-invisible; align before shipping.
6. **Naming sweep merge conflicts** — the cross-owner cosmetic edits; mitigated by
   serializing D's sweep to the tail after A/B/E freeze.
7. **Honest-label discipline** — nothing here may acquire attestation-grade
   language; STRONG failing is a disclosed property, not a defect.

---

*Design / planning only. Nothing here is built, booted, attested, or audited.
Non-attestable tier — not Sealed. The coin is worthless; personal use is free; not
legal advice. Never "Postern OS".*
