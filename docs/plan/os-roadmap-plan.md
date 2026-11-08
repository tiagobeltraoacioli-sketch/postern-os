<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# OS / PLATFORM / IMAGES — Wave-1 execution plan (make it PROVABLE)

**Track-lead:** OS/Platform/Images (fable5). Branch: `roadmap/wave1-base`.
Repo: `bloch-protocol`. Source gaps: `docs/gap/os-platform-gaps.md` (A1) +
`docs/gap/POSTERN-GAP-BACKLOG.md` (items #1–#4, #11, #16, #17, #19).

> ## BLOCKED-ON-TOOLING HEADER — read before trusting anything below
>
> **THIS ENTIRE TRACK IS BLOCKED ON A LINUX + NIX (+ flakes) + QEMU BOX FOR
> PROOF.** The dev host is macOS with **NO Nix, NO QEMU, NO KVM, NO TPM2**.
> Therefore **NOTHING in this track builds, boots, or attests on-host.** Every
> task below is **WRITE + static-validate on the mac**, and **prove on the VM /
> hardware** later. No dev on this track may claim a `nix build`, a QEMU boot, a
> measured-boot PCR, or a filled cargo hash was produced on the macOS host — any
> such claim is false and fails the honesty discipline the site is graded on.
>
> **Proof tiers (from A1):**
> - **HOST** — anything runnable on the mac: `shellcheck`, `nix`-free static
>   lint, `nixpkgs-fmt`/`statix` **only if** they can run without evaluating (they
>   cannot fully — treat as VM). Essentially the only HOST proof here is
>   shell/script static-check + doc review.
> - **VM** — Linux + Nix + flakes + `qemu-system`. Gated *only* by "no Nix here."
> - **HW** — real measured-boot / TPM2 / SEV-SNP / phone. Cannot be faked in a VM.
>
> **What "done on the mac" means for every task:** the code/script/wiring is
> written, statically consistent, `shellcheck`-clean where shell, and carries the
> exact VM/HW command that will prove it — plus a self-labelled honesty note.
> **"Written, not built" is the ceiling on this host, by design, for all 5.**

---

## Shared-file coordination — the ONE hard rule

`flake.nix` is the single shared file every image/output touches. **It has
exactly ONE owner: Dev O2.** No other dev edits `flake.nix`. O1/O3/O5 needing a
new flake output (`.#seal-gate`, an x86 boot app, an attested-roothash
check/app) **request the exact attribute snippet from O2**, who integrates it.
This keeps ownership strictly non-overlapping.

Second coordination point: `os/seal-gate.nix` is consumed by `os/cloud.nix`
(line ~90: `pkgs.callPackage ./seal-gate.nix { }`). **`os/cloud.nix` is OUT OF
SCOPE for this partition** (it belongs to the Cloud/Chiostro track). Therefore
**Dev O1 MUST keep `seal-gate.nix`'s call interface `{ lib, rustPlatform }`
stable** so the existing `cloud.nix` callPackage keeps evaluating. O1 may add
outputs/hashes inside the derivation but may not change the function signature.

Third: `os/boot-harness/check-boot-log.sh` + `success-markers.txt` are the
**shared boot grader**, owned by **Dev O4** (aarch64). Dev O3 (x86_64) consumes
them **read-only** from its own new directory; any grader change O3 needs is
requested from O4. No dual-write.

**Out of scope for this 5-dev partition (owned elsewhere / already planned):**
`os/cloud.nix`, `os/sloboda-compat.nix` (see `docs/plan/sloboda-wave1-plan.md`),
`pmos-overlay/`, `os/desktop.nix`/`browser.nix` (desktop-ISO build shares O2's
flake wiring but the profiles themselves are not edited here).

---

## The 5-dev partition (STRICT non-overlapping ownership)

### Dev O1 — Seal-gate reproducible build: wire it + fill-hashes tooling

- **Scope:** Make `.#seal-gate` a real, buildable output. Today `seal-gate.nix`
  has **5 `lib.fakeHash` `cargoLock.outputHashes` sentinels** (fail-closed by
  design) and is **NOT wired into `flake.nix`** — it is only reachable via
  `cloud.nix`'s `callPackage`. Write the packaging so a Nix host can build it,
  and ship a script that fills the 5 hashes **on a Nix host** (fail-closed until
  then). Address the documented dual-git-rev `Cargo.lock` dedupe caveat in the
  script.
- **Files/dirs OWNED (write):**
  - `os/seal-gate.nix` (may edit derivation body; **must NOT change the
    `{ lib, rustPlatform }` signature** — cloud.nix depends on it)
  - `os/seal-gate/` (NEW dir): `fill-outputhashes.sh` (VM-gated hash-filler that
    parses the `nix build` fail-closed output and rewrites the 5 sentinels),
    `README.md` (the exact VM procedure + the dual-rev dedupe workaround)
- **Requests to O2 (flake owner):** add the `packages.<sys>.seal-gate =
  callPackage ./seal-gate.nix { };` output attribute. O1 provides the snippet;
  O2 integrates.
- **Proof + tier:**
  - HOST: `shellcheck os/seal-gate/fill-outputhashes.sh`; visually confirm the 5
    sentinel keys match `Cargo.lock` git-sourced crate `name-version`s.
  - **VM-gated:** `nix build .#seal-gate` → fails printing 5 real `sha256-…`;
    run `fill-outputhashes.sh`; rebuild → produces `postern-seal-gate` +
    `postern-seal-verify` bins. **This is the only real proof and CANNOT run on
    the mac.**
- **Deps:** O2 must have merged the `.#seal-gate` attr before the VM build works.
  Independent of O3/O4/O5.

---

### Dev O2 — Flake integration hub + `flake.lock` + `nix flake check` reproducibility

- **Scope:** **SOLE OWNER of `flake.nix`.** No `flake.lock` exists → the flake is
  "written, not built," and reproducibility (item #19) is unproven because nobody
  can pin inputs. Write the lock-generation process + inputs pinning so
  `nix flake check` is reproducible on the VM, and integrate the output-attr
  requests from O1/O3/O5. Own the CI wrapper that runs the lock + check.
- **Files/dirs OWNED (write):**
  - `flake.nix` (SOLE owner — integrates `.#seal-gate` from O1, x86 boot app from
    O3, attested-roothash check/app from O5)
  - `flake.lock` (NEW — generated on the VM; committed from there, never fabricated
    on the mac)
  - `scripts/flake-lock.sh` + `scripts/flake-check.sh` (NEW — the VM procedure:
    `nix flake lock` to freeze `nixpkgs` 24.05 + `mobile-nixos` revs, then
    `nix flake check`), and `docs/plan/FLAKE-REPRO.md` (the two-builder
    bit-for-bit reproduction procedure, item #19)
- **Proof + tier:**
  - HOST: `shellcheck scripts/flake-*.sh`; static read-through that every output
    attr resolves to an existing module/file path.
  - **VM-gated:** `nix flake lock` produces a committed `flake.lock`;
    `nix flake check` passes; a **second VM builder** rebuilds `.#iso` to a
    matching store hash (item #19). **CANNOT run on the mac.**
- **Deps:** the integration hub — O1/O3/O5 depend on O2's flake edits landing.
  O2 should merge the attr stubs early so the others can VM-test independently.

---

### Dev O3 — x86_64 QEMU boot harness (the OVERCLAIM fix)

- **Scope:** The site says the node + desktop ISOs are **"boot-validated on QEMU
  x86_64,"** but **no x86 boot harness and no committed boot evidence exist** —
  A1's one genuine site-vs-repo overclaim (item #17). Write an x86_64 boot
  harness mirroring the aarch64 one so the claim becomes **reproducible on the
  VM**, and consume the shared grader read-only.
- **Files/dirs OWNED (write):**
  - `os/boot-harness-x86/` (NEW dir — deliberately separate from O4's
    `os/boot-harness/` to keep ownership clean): `boot-qemu-x86_64.sh` (builds
    `.#iso`/`.#desktop-iso`, boots under `qemu-system-x86_64` TCG, captures
    serial, writes an `.evidence` sidecar), `success-markers-x86.txt` (x86 ISO
    boot ladder: bootloader → kernel → stage-1 → systemd → getty/installer),
    `README.md`
  - **Consumes read-only:** `os/boot-harness/check-boot-log.sh` (O4's grader) via
    a relative path — no write.
- **Requests to O2 (flake owner):** add `apps.x86_64-linux.boot-qemu-x86` that
  wraps `boot-qemu-x86_64.sh`. O3 provides snippet; O2 integrates.
- **Proof + tier:**
  - HOST: `shellcheck os/boot-harness-x86/boot-qemu-x86_64.sh`; confirm the
    marker file parses under O4's `check-boot-log.sh` format.
  - **VM-gated:** `nix run .#boot-qemu-x86` boots the ISO under
    `qemu-system-x86_64`, grades PASS, commits the boot log as the **first real
    x86 boot evidence** — which turns the site claim from overclaim to backed.
    **CANNOT run on the mac.**
- **Deps:** needs O4's `check-boot-log.sh` grader contract (stable — already
  exists) and O2's `apps.x86_64-linux.boot-qemu-x86` attr. Otherwise independent.

---

### Dev O4 — aarch64 QEMU boot harness runnable + mobile first-boot path

- **Scope:** `os/boot-harness/` is a **well-built marker ladder that has NEVER
  been run** (item #16). Make it runnable end-to-end on the VM and own the mobile
  image's first-boot path (the getty/MOTD marker the grader keys on). Owns the
  **shared grader** consumed by O3.
- **Files/dirs OWNED (write):**
  - `os/boot-harness/` (ALL existing files: `boot-qemu-aarch64.sh`,
    `check-boot-log.sh`, `success-markers.txt`, `README.md`) — including the
    shared grader O3 reads
  - `os/mobile.nix` (the first-boot / login banner path that produces the
    `◆ Postern OS Mobile` + `login:` markers; wire the interactive
    `bloch-wallet --help` DoD #2 follow-up as a CI-expect note)
- **Coordination:** `check-boot-log.sh` + `success-markers.txt` are jointly
  referenced by O3; O4 is the **sole writer**. O4 must not break the grader's
  CLI/format contract without telling O3.
- **Proof + tier:**
  - HOST: `shellcheck` the two harness scripts; run `check-boot-log.sh` against a
    **hand-written fixture log** to prove the grader logic (the grader itself is
    pure shell — its *logic* is HOST-checkable even though a real boot is not).
  - **VM-gated:** `nix run .#boot-qemu` (attr already in flake) builds
    `.#mobile-image`, boots `qemu-system-aarch64`, grades PASS → first real
    aarch64 software-boot evidence. **QEMU ≠ hardware; PinePhone boot is HW-gated
    and out of this wave.**
- **Deps:** `.#mobile-image` must evaluate (O2's flake + `mobile-nixos` pin).
  Grader is a dependency FOR O3, not ON anyone.

---

### Dev O5 — Attested / measured-boot roothash pipeline

- **Scope:** `os/attested.nix` builds a dm-verity erofs root + UKI, but
  **`os_roothash` is a design-reference placeholder, not a verified value**
  (item #4), and the measured-boot chain has never been exercised. Write the
  pipeline that **produces** a real roothash from the built image and **verifies**
  it binds through `roothash=` → `attestation::read_os_roothash` → the reported
  `Expected.os_roothash`. TPM2 PCR measurement is HW-gated.
- **Files/dirs OWNED (write):**
  - `os/attested.nix` (the profile — may add repart/verity wiring, must keep
    `.#attested-image` evaluating)
  - `os/attested/` (NEW dir): `extract-roothash.sh` (VM: build `.#attested-image`,
    read the dm-verity roothash systemd-repart emits, record it), `verify-boot-
    binding.sh` (verify the running node's `getattestation` reports that exact
    roothash), `README.md` (the VM build → HW/TPM2 PCR-measure procedure +
    honesty note that the placeholder stays a placeholder until a VM run fills it)
- **Requests to O2 (flake owner):** optionally add `apps.x86_64-linux.attested-
  roothash` wrapping `extract-roothash.sh`, and/or a `checks` entry. O5 provides
  snippet; O2 integrates.
- **Proof + tier:**
  - HOST: `shellcheck` the two scripts; static read that `attested.nix` still
    references a real `system.build.image` path and that the roothash variable
    name matches `attestation::read_os_roothash`'s cmdline key.
  - **VM-gated:** `nix build .#attested-image` → extract the real roothash →
    boot under QEMU → confirm `getattestation` reports it (software chain).
  - **HW-gated (TPM2):** PCR measurement of the UKI + roothash→PCR binding on a
    real measured-boot machine — **cannot be faked in a VM.**
- **Deps:** O2's `.#attested-image` must evaluate. Independent of O1/O3/O4.

---

## Ownership matrix (no cell shared)

| Path | Owner | Others' access |
|---|---|---|
| `flake.nix` | **O2** | request-only (O1, O3, O5) |
| `flake.lock`, `scripts/flake-*.sh`, `docs/plan/FLAKE-REPRO.md` | **O2** | — |
| `os/seal-gate.nix`, `os/seal-gate/` | **O1** | interface frozen for `cloud.nix` |
| `os/boot-harness-x86/` | **O3** | — |
| `os/boot-harness/` (incl. shared grader) | **O4** | O3 reads grader read-only |
| `os/mobile.nix` | **O4** | imported by `flake.nix` (O2, read) |
| `os/attested.nix`, `os/attested/` | **O5** | — |
| `os/cloud.nix`, `os/sloboda-compat.nix`, `pmos-overlay/` | **out of scope** | — |

## Dependency order

1. **O2 first** merges flake attr stubs (`.#seal-gate`, `apps…boot-qemu-x86`,
   attested app) → unblocks O1/O3/O5 VM testing.
2. **O4** grader contract is stable today → unblocks O3 immediately.
3. O1, O3, O4, O5 then proceed in parallel; all real proof waits on the VM box.

## The standing blocker (repeat)

Every "VM-gated" and "HW-gated" line above is **unprovable on the current macOS
host**. This track produces *write-complete, statically-validated, honestly-
labelled* artifacts on the mac and **cannot advance a single item past "written,
not built" until a Linux + Nix + QEMU box (and, for O5's PCR step, TPM2 hardware)
is available.** Schedule the VM box as the track's critical path.
