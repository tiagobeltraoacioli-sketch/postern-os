<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# FLAKE-REPRO — flake.lock pinning + two-builder bit-for-bit reproduction

**Owner:** Dev O2 (flake integration hub). **Scope of this doc:** the `flake.lock`
pinning approach, the `scripts/flake-lock.sh` / `scripts/flake-check.sh`
procedure, and the two-builder reproduction runbook for backlog **item #19**.

> ## STATUS — SCAFFOLD / UNAUDITED / WRITTEN, NOT EVALUATED
> Everything in this doc was **authored on a non-Nix macOS host**. No `nix flake
> lock`, no `nix flake check`, and no two-builder hash match has been run here —
> **they cannot be.** Reproducibility is the claim to **EARN on a Nix host**, not
> to assert. The static validation that *was* done on the mac is listed in §5;
> every other step is **VM-gated** and carries its exact command below.
>   - built ≠ booted · QEMU ≠ hardware · reproducible-by-design ≠ **reproduced**.

---

## 1. Why the committed `flake.lock` is an empty seed

`flake.lock` in this repo is intentionally the **empty seed**:

```json
{ "nodes": { "root": {} }, "root": "root", "version": 7 }
```

It freezes **zero** input revisions and fabricates **zero** `narHash` values.
Reasoning (this is the honest position, matching `os/seal-gate.nix`'s
`lib.fakeHash` fail-closed idiom):

- A real lock records, per input, an **exact commit rev + a cryptographic
  `narHash`**. Those hashes can only be computed by Nix fetching the source. On a
  non-Nix host they cannot be produced.
- A hand-written lock with **plausible-looking** hashes would be a lie — and,
  unlike a Nix expression, **JSON carries no comment** to disclaim it. So we do
  not write one.
- The empty seed is **fail-closed for reproducibility**: with nothing pinned, the
  flake re-resolves the moving branch refs (`nixpkgs` `nixos-24.05`,
  `mobile-nixos` HEAD) on every evaluation → **not reproducible until frozen**.

**The pinning therefore happens on the VM**, via `scripts/flake-lock.sh`, and the
**filled** lock is committed *from that VM*.

## 2. Inputs being pinned

| Input | Ref in `flake.nix` | Frozen to (by `flake-lock.sh`) | Notes |
|---|---|---|---|
| `nixpkgs` | `github:NixOS/nixpkgs/nixos-24.05` | exact rev of the 24.05 branch at freeze time | Align with whatever `nixpkgs` the pinned `mobile-nixos` rev expects. |
| `mobile-nixos` | `github:nix-community/mobile-nixos` (`flake = false`) | exact rev at freeze time | Its eval API drifts across revs — re-verify `.#mobile-image`'s output selector after any bump (see `os/MOBILE.md`). |

Optional exact-rev pins (extra determinism) are passed as env vars:

```sh
NIXPKGS_REV=<sha> MOBILE_NIXOS_REV=<sha> scripts/flake-lock.sh
```

Unset → freeze whatever the branch points at now; Nix still records an exact rev.

## 3. The freeze + check procedure (VM-gated)

On a **Linux + Nix (flakes) + QEMU** host:

```sh
# 1. Freeze inputs → writes the FILLED flake.lock (real revs + narHashes).
scripts/flake-lock.sh

# 2. Commit the filled lock FROM THIS VM (never from the mac).
git add flake.lock && git commit -m "flake.lock: freeze nixpkgs 24.05 + mobile-nixos"

# 3. Check the flake against the frozen lock (fail-closed if still the seed).
scripts/flake-check.sh          # host system
scripts/flake-check.sh --all    # every system (--all-systems)
```

`flake-check.sh` refuses to run on the empty seed and passes
`--no-update-lock-file`, so an **unpinned check can never pose as a reproducible
one**, and a stale lock errors instead of being silently re-locked.

## 4. Two-builder bit-for-bit reproduction (item #19)

Freezing the lock is **step 1 only**. The actual reproducibility *proof* is two
independent builders producing the **same store path** from the **same committed
lock**:

```sh
# Builder A (has already committed the frozen flake.lock from §3):
nix build .#iso --print-out-paths            # e.g. /nix/store/<hashA>-...-iso
# record hashA and:  nix path-info --json ./result | tee builderA.iso.json

# Builder B (fresh Nix host, SAME commit incl. the committed flake.lock):
git checkout <same-commit>
nix build .#iso --print-out-paths            # /nix/store/<hashB>-...-iso
nix path-info --json ./result | tee builderB.iso.json
```

**PASS** iff `hashA == hashB` (the store path is content-addressed by the full
input closure). Repeat for `.#desktop-iso`, `.#mobile-image` (aarch64 builder),
`.#attested-image`, `.#cloud-image`.

- A store-path match is the strongest *build* reproducibility signal Nix gives.
- It is **still not a boot**: run the QEMU harness apps (§4.1) for boot evidence
  and the hardware runbooks for the HW-gated claims. built ≠ booted.
- Record both `path-info` JSONs as committed evidence; do **not** claim item #19
  closed on a single-builder run.
- **Runnable tooling for the above:** `os/repro/repro-verify-iso.sh` (`build`
  + `compare` modes — writes the manifest, does the PASS/FAIL_SETUP/
  FAIL_DIVERGENCE diff, prints a diffoscope-style next step on divergence)
  and `os/repro/repro-verify-iso-builder-userdata.sh` (self-terminating EC2
  user-data for an independent second builder). `os/repro/README.md` also
  states the honest interpretation explicitly: a PASS proves `binary ==
  source` for the pinned closure, nothing about whether that source is safe
  — same distinction `docs/store-fdroid/02-reproducible-builds.md` §4 draws
  for the app-store verifier. STAGED, NOT RUN, same as everything else in
  this document.

### 4.1 Boot / attestation proofs live in other outputs (not this check)

`nix flake check` builds packages; it boots nothing. The real per-tier proofs:

| Claim | Output attr | Owner | Tier |
|---|---|---|---|
| aarch64 mobile software boot | `nix run .#boot-qemu` | O4 | VM (HW: PinePhone) |
| x86_64 ISO software boot | `nix run .#boot-qemu-x86` | O3 (script) / O2 (attr) | VM (HW pending) |
| dm-verity roothash extraction | `nix run .#attested-roothash` | O5 (script) / O2 (attr) | VM (HW: TPM2 PCR) |
| seal gate build | `nix build .#seal-gate` | O1/CS-5 (nix) / O2 (attr) | VM (HW: SEV-SNP) |

## 5. Static validation actually done on the mac (HOST tier)

- `shellcheck scripts/flake-lock.sh scripts/flake-check.sh` → clean.
- `flake.nix` brace/bracket/paren balance → `{}` 46/46, `[]` 10/10, `()` 55/55.
- `flake.lock` → valid JSON, canonical empty seed (no fabricated hashes).
- Read-through: every output attr resolves to an existing module/file path, or —
  for the O3/O5 harness scripts not yet landed — is guarded by
  `builtins.pathExists` so the flake still **evaluates** and the app fail-closes
  at run time. `.#seal-gate` points at the existing `os/seal-gate.nix`.

**Not done here (cannot be):** `nix flake lock`, `nix flake check`, any
`nix build`, any QEMU boot, any two-builder hash match. Those are §3–§4, VM-only.

## 6. Output attributes O2 integrated (for O1 / O3 / O5 / Cloud)

| Attr | Requester | Wraps | Guard |
|---|---|---|---|
| `packages.<sys>.seal-gate` | O1 / CS-5 | `os/seal-gate.nix` (`callPackage`) | file exists; fail-closed on 5 `fakeHash` until filled on VM |
| `apps.x86_64-linux.boot-qemu-x86` | O3 | `os/boot-harness-x86/boot-qemu-x86_64.sh` | `pathExists` — stub exits 2 until O3 lands the script |
| `apps.x86_64-linux.attested-roothash` | O5 | `os/attested/extract-roothash.sh` | `pathExists` — stub exits 2 until O5 lands the script |
| `checks.<sys>.flake-eval-smoke` | O2 | cheap eval smoke (`runCommand`) | always buildable |

`cloud-image` (Cloud Dev 5's guest image) already exists as
`packages.x86_64-linux.cloud-image`; no new cloud attr was requested beyond
`.#seal-gate`, which serves both O1 and CS-5. Any further cloud output is a
one-line additive hunk handed to O2 (the sole `flake.nix` owner).

## 7. Dependency / sequencing notes

- O2 merges these attr **stubs first** → unblocks O1/O3/O5 VM testing (per the
  roadmap dependency order). The `pathExists` guards mean a missing O3 file does
  **not** break `nix flake check` eval for O1/O5, and vice-versa.
- A **fully green** `nix flake check` additionally requires: (a) O1/CS-5 to fill
  the 5 seal-gate hashes, and (b) a frozen (non-seed) `flake.lock`. Both are
  documented, intentional gates — not defects in the flake wiring.
