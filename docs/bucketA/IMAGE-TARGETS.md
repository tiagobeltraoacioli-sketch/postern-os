<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Bucket A — the OTHER Postern OS image targets (prep, not a build)

> **STATUS: PREP ONLY. Nothing in this document has been built.** This is a
> read-through of `flake.nix` + `os/*.nix` done on a non-Nix macOS host, to
> stage the remaining `nixosConfigurations`/`packages` output attrs so a Nix
> build instance can attempt all of them in one run alongside `.#iso`. No
> `nix build` of any of these attrs has happened here or is claimed here.
> `built ≠ booted`, and for several of these, **not yet even built**.

> **⚠ FOD-HASH PATH SUPERSEDED — point at the protocol-repo flake instead.**
> The 5 `lib.fakeHash` / `cargoLock.outputHashes` sentinels and the
> fill-and-parse loop this document leans on (esp. §3 for `.#cloud-image` /
> `.#seal-gate`) are the **dead path**. The OS build now sources the `bloch`
> node from the **protocol repo's own flake**
> (`gitlab.com/blochsispow-group/BlochSISPoW-project`), which has **zero
> git-sourced crates and no FOD-hash step** — so the `outputHashes` discussion
> below no longer applies to the live build path. See
> [`PACKAGE-FOD-HASHES.md`](PACKAGE-FOD-HASHES.md) (the supersession header) and
> dossier item 7 ([`../design/RESUME-DOSSIER-2026-07-16.md`](../design/RESUME-DOSSIER-2026-07-16.md)).
> **This pivot is a recorded decision, NOT yet implemented in the tree:**
> `os/package.nix` / `os/seal-gate.nix` still carry the old FOD block,
> `flake.lock` is still the empty seed, and **no OS image (`.#iso`,
> `.#desktop-iso`, `.#attested-image`, `.#cloud-image`, `.#mobile-image`) has
> ever been built.** The FOD detail below is retained for history until the
> pivot lands in the tree.

## 1. The five image-producing attrs

All confirmed present in `flake.nix` (read 2026-07-13). Table first, detail
below.

| Attr | `flake.nix` line(s) | Backing config | Arch | Produces |
|---|---|---|---|---|
| `.#iso` | 132–133, `nixosConfigurations.postern-node-iso` (255–259) | `os/configuration.nix` on `installation-cd-minimal.nix` | `x86_64-linux` | node appliance live/installer ISO (mines on boot) |
| `.#desktop-iso` | 138–139, `postern-desktop-iso` (266–270) | `os/desktop.nix` (imports `os/browser.nix`) on the same installer CD | `x86_64-linux` | hardened GNOME live/installer ISO |
| `.#attested-image` | 145–146, `postern-attested` (276–281) | `os/attested.nix` over `os/configuration.nix` + `nixos/modules/image/repart.nix` | `x86_64-linux` | dm-verity/UKI `systemd-repart` disk image |
| `.#cloud-image` | 126–127, `postern-cloud` (242–250) | `os/cloud.nix` (imports `os/attested.nix`) + `repart.nix` | `x86_64-linux` | Chiostro confidential-VM guest disk image (SEV-SNP/TDX) |
| `.#mobile-image` | 117–121, `mobilePinephone` (73–84) | `os/mobile.nix` over Mobile-NixOS `pine64-pinephone` device eval | **`aarch64-linux` only** | flashable phone image / boot.img |

Bonus attr that `.#cloud-image` transitively depends on (see §3):

| Attr | Backing | Arch | Produces |
|---|---|---|---|
| `.#seal-gate` | `os/seal-gate.nix` (`callPackage`) | linux (built here as `x86_64-linux`, same as cloud) | `postern-seal-gate` + `postern-seal-verify` bins |

## 2. Per-target detail

### `.#desktop-iso` — hardened desktop, x86_64

```sh
nix build .#desktop-iso        # -> ./result/iso/*.iso
```

- Config: `os/desktop.nix` → GNOME/GDM (Wayland), LUKS/TPM2 machinery, Tor
  client, `os/browser.nix` (hardened Firefox via `programs.firefox`, stock
  nixpkgs — no custom derivation, no extra FOD hash).
- Same `x86_64-linux` system, same `installation-cd-minimal.nix` installer
  base, same `blochPkg` module arg as `.#iso`. **No new fixed-output hashes
  beyond what `os/package.nix` already needs** (see §3) — the extra cost here
  is closure size (full GNOME desktop + Firefox), not new inputs.
- Builds on the **same x86 instance** that builds `.#iso`.

### `.#attested-image` — immutable + measured, x86_64

```sh
nix build .#attested-image     # -> a systemd-repart disk image (not an .iso)
```

- Config: `os/attested.nix` (dm-verity erofs root + UKI + TPM2 measured
  boot) layered over `os/configuration.nix`, plus
  `${nixpkgs}/nixos/modules/image/repart.nix` — that module ships inside the
  pinned `nixpkgs` input itself, so it is **not a separate flake input**;
  `systemd-repart`/`erofs` tooling comes from the Nix build sandbox, not the
  host, so nothing needs pre-installing on the builder beyond Nix itself.
- **No new fixed-output/git hashes beyond `os/package.nix`'s 5** (see §3).
- Output is a raw disk image, not an ISO — the upload/publish step needs a
  different filename convention (`.raw`/`.img`, not `.iso`); `os/publish-iso.sh`
  as written only understands the three ISO/img names already in its
  `KNOWN_NAMES` list (`os/publish-iso.sh:111`) — publishing a new
  `attested-image` artifact needs `--allow-new-name` and a follow-up
  allowlist edit in `functions/dl/[[path]].js` (the script prints this itself).
- `os_roothash` is a **placeholder** (`null`) until this build actually runs —
  see `os/attested.nix`, `os/attested/README.md`. This attr producing a real
  roothash is itself the point of running it; nothing here fabricates one.
- Builds on the **same x86 instance** as `.#iso`.

### `.#cloud-image` — Chiostro confidential-VM guest, x86_64

```sh
nix build .#cloud-image        # -> a systemd-repart disk image
```

- Config: `os/cloud.nix` (imports `os/attested.nix`) + `repart.nix`. Adds a
  `persist` partition, SEV-SNP/TDX guest kernel modules, WireGuard, and —
  **load-bearing for the build, not just the runtime** — a systemd unit
  (`systemd.services.postern-seal-gate`, `os/cloud.nix:81-129`) whose
  `ExecStart` references `pkgs.callPackage ./seal-gate.nix { }`
  (`os/cloud.nix:91`). Because that unit is part of
  `config.system.build.toplevel`, **building `.#cloud-image` also builds
  `os/seal-gate.nix`** — this is the one target with a real extra input
  beyond everything `.#iso`/`.#attested-image` need. See §3.
- Same `x86_64-linux` system as `.#iso`/`.#attested-image`/`.#desktop-iso`.
  Builds on the **same x86 instance**.
- Same roothash-placeholder caveat as `.#attested-image` (it layers on top
  of it).

### `.#mobile-image` — Postern OS Mobile (PinePhone), aarch64 ONLY

```sh
nix build .#mobile-image       # -> device-specific flashable image / boot.img
```

- Config: `os/mobile.nix` layered on the Mobile-NixOS `pine64-pinephone`
  device eval (`evalMobile`, `flake.nix:73-84`), which supplies kernel/DTB/
  firmware/stage-1 for that phone.
- **`aarch64-linux` only** — gated by
  `nixpkgs.lib.optionalAttrs (system == "aarch64-linux")` (`flake.nix:117`).
  It does **not** appear in the `x86_64-linux` attrset at all, unlike the
  other four. The flake's own comment (`flake.nix:50-51`) is explicit: "it is
  cross-built or built natively on an aarch64 Linux host — never on the
  macOS workstation."
- `blochPkg` for this target is `blochPkgFor "aarch64-linux"` (`flake.nix:80`)
  — i.e. `os/package.nix` compiled natively for aarch64, a **separate first
  build** from the x86_64 one `.#iso` already forced, even though it shares
  the same 5 `outputHashes` sentinels (§3) — those are content hashes of the
  *fetched git source*, not of the compiled output, so they are
  architecture-independent and do not need re-discovering per arch.
- `mobile-nixos` is consumed as `flake = false` (a plain source import, not a
  flake), and the repo's `flake.lock` is currently the **empty seed**
  (`docs/plan/FLAKE-REPRO.md` §1) — so until `scripts/flake-lock.sh` freezes a
  `mobile-nixos` rev, every evaluation re-resolves its moving HEAD. The
  flake's own header warns Mobile-NixOS's eval API "differs across
  revisions" and the `.outputs.default` selector in `evalMobile` may need
  adjusting on whatever rev gets pinned (`flake.nix:67-72`). This is a real
  risk that `.#iso`/desktop/attested/cloud do not carry (they only depend on
  the far more stable `nixpkgs` input).
- **Cannot build on the x86 instance as-is.** Two real options, in order of
  what the repo already has in place:
  1. **Native aarch64 build** — reuse the aarch64 (Graviton) build host
     already used for the pmOS/mobile-signing pipeline (per prior session
     notes: it already does aarch64 Nix/Rust builds and has the datacenter
     uplink for large-artifact uploads). This is the path of least surprise —
     no emulation, no new host config.
  2. **Cross/emulated build from the x86 instance** — register
     `aarch64-linux` binfmt emulation (`boot.binfmt.emulatedSystems =
     [ "aarch64-linux" ]` on NixOS, or `qemu-user-static` + manual
     `binfmt_misc` registration on Ubuntu) and pass `--system aarch64-linux`
     to `nix build`. This works with plain Nix but is **much slower** for a
     Rust/rocksdb/openssl compile under QEMU-user emulation than native
     aarch64 silicon, and is untested in this repo. Not recommended as the
     first attempt.
- `nix run .#boot-qemu` (`flake.nix:170-179`, aarch64-only app) is the
  existing QEMU-aarch64 first-boot harness for this image, already wired.

## 3. Extra inputs beyond `.#iso`, summarized

`.#iso` itself is not free of fixed-output-hash gates — `os/package.nix` (the
`bloch` node package every target threads in as `blochPkg`) pins 5 git-sourced
crates via `cargoLock.outputHashes`, and as committed in this working tree
**all 5 are still the fail-closed `lib.fakeHash` sentinel**
(`os/package.nix:34-39`). Whatever Nix host is currently building `.#iso`
successfully must already carry a **locally patched, unfilled-here** copy
with the real hashes — those real values are the required starting point for
this doc's own image-target attempts, since every target below also consumes
`blochPkgFor <system>`.

Given that baseline is already satisfied (however that host got there), the
attr-specific deltas are:

| Attr | Extra FOD/git hashes | Extra flake inputs | Extra host tooling |
|---|---|---|---|
| `.#desktop-iso` | none | none (stock `nixpkgs` GNOME/Firefox modules) | none |
| `.#attested-image` | none | none (`repart.nix` ships inside the pinned `nixpkgs`) | none beyond Nix itself (systemd-repart/erofs run inside the sandbox) |
| `.#cloud-image` | **yes** — `os/seal-gate.nix`'s OWN 5 `outputHashes` entries (`bloch-0.1.0-genesis`, `bloch-crypto-0.1.0-genesis`, `bloch-sis-pow-0.1.0`, `coherence-core-0.1.0`, `pqcrypto-internals-0.2.11`), still all `lib.fakeHash` as committed (`os/seal-gate.nix:75-81`) — a **separate `outputHashes` map from `os/package.nix`'s**, even though it pins the identical 5 crates at the identical rev. First `nix build .#cloud-image` (or `.#seal-gate` directly) is designed to FAIL here and print the 5 real `sha256-…` values. Run `./os/seal-gate/fill-outputhashes.sh` on the Nix host to fill them (see `os/seal-gate/README.md`) — **or**, since the crates/rev are identical to `os/package.nix`'s already-filled set, try pasting those same 5 values into `os/seal-gate.nix` first and only fall back to the filler script if that guess doesn't verify (same source ⇒ same NAR hash is the expectation, not a certainty worth skipping the check). | none new | none new |
| `.#mobile-image` | none new (same 5 sentinels as `.#iso`, arch-independent, but this is the **first aarch64 compile** of `os/package.nix` — expect real wall-clock build time even after hashes are filled) | `mobile-nixos` (already an input, but **unpinned** — `flake.lock` empty seed) + risk that `evalMobile`'s `.outputs.default` selector drifts on whatever rev resolves | **aarch64 host** (native or emulated — see §2) |

## 4. Same-instance vs different-arch summary

**Builds on the same `x86_64-linux` instance already building `.#iso`, no
new host needed:**
- `.#desktop-iso`
- `.#attested-image`
- `.#cloud-image` (once `os/seal-gate.nix`'s 5 hashes are filled — see §3)
- `.#seal-gate` (prerequisite for `.#cloud-image`; build it first/alongside)

**Needs a different (aarch64) host — cannot run on the x86 instance as-is:**
- `.#mobile-image` — reuse the existing aarch64 (Graviton) build host if one
  is already provisioned for this project; native aarch64 is strongly
  preferred over binfmt emulation on the x86 box (see §2).

## 5. User-data snippet — build all viable x86 targets + stage for upload

No "build" user-data script currently exists in this repo — only the
**boot-verification** ones (`os/boot-harness-x86/boot-verify-metal-userdata.sh`,
staged/not-run, and its target is booting a pre-built ISO under KVM, not
building one). The snippet below is written to be **appended to whichever
script/step on the x86 build instance currently runs `nix build .#iso`**,
right after that step, reusing the same repo checkout and Nix install. It is
**staged, not run** — same honesty status as the rest of this file.

The full, shellcheck-clean version is saved standalone at
`os/build-all-image-targets-userdata-snippet.sh` (append it after the
existing `nix build .#iso` step in the build instance's user-data — it
assumes the same shell session: Nix already installed, repo already checked
out at `$FLAKE_DIR`). Its shape, condensed:

```sh
# ── Append after the existing `nix build .#iso` step ─────────────────────────
# Builds every OTHER x86_64 image target and stages each result to the same
# build-artifact S3 bucket os/publish-iso.sh already knows how to pull from
# (SRC_BUCKET default in that script: postern-os-build-1783966602). Does NOT
# publish to R2 / the downloads page — that stays the separate, explicit
# os/publish-iso.sh step, which enforces the boot-status honesty gate this
# build step has no way to answer.

BUILD_S3_BUCKET="${BUILD_S3_BUCKET:-postern-os-build-1783966602}"
BUILD_S3_PREFIX="${BUILD_S3_PREFIX:-builds/$(date -u +%Y-%m-%d)}"
FLAKE_DIR="${FLAKE_DIR:-/opt/postern}"   # same checkout the .#iso step used

stage_result() {   # $1=attr $2=result glob $3=dest filename
  attr="$1"; glob="$2"; dest_name="$3"
  if nix build ".#${attr}" --print-out-paths \
      > "$BUILD_LOG_DIR/${attr}.outpath" 2> "$BUILD_LOG_DIR/${attr}.log"; then
    src=""
    for cand in ${glob}; do [ -e "$cand" ] && { src="$cand"; break; }; done
    [ -n "$src" ] && aws s3 cp "$src" \
      "s3://${BUILD_S3_BUCKET}/${BUILD_S3_PREFIX}/${dest_name}"
  else
    echo "WARN: .#${attr} build FAILED (see $BUILD_LOG_DIR/${attr}.log — a" >&2
    echo "      .#cloud-image/.#seal-gate failure is EXPECTED until the 5" >&2
    echo "      fakeHash sentinels are filled, see §3)" >&2
  fi
}

cd "$FLAKE_DIR"
stage_result "desktop-iso"    "./result/iso/*.iso"            "postern-os-desktop-x86_64.iso"
stage_result "attested-image" "./result/*.raw ./result/*.img" "postern-os-attested-x86_64.raw"
stage_result "seal-gate"      "./result/bin/postern-seal-gate" "postern-seal-gate-x86_64"
stage_result "cloud-image"    "./result/*.raw ./result/*.img" "postern-cloud-x86_64.raw"

# .#mobile-image is aarch64-only — deliberately NOT attempted here. Run on a
# separate aarch64 host (see the tail of the standalone script for the
# equivalent nix build + aws s3 cp invocation).
```

## 6. What this doc does NOT claim

- No target in §1 has been built, booted, or hash-verified from this session.
- `.#cloud-image` is **expected to fail on first attempt** until
  `os/seal-gate.nix`'s 5 `lib.fakeHash` sentinels are filled on a Nix host —
  that is by design (same fail-closed idiom as `os/package.nix`), not a defect
  in this prep.
- `.#mobile-image`'s exact output attribute path (`mobilePinephone.outputs.default`)
  is unverified against whatever `mobile-nixos` revision ends up pinned —
  `flake.nix` itself flags this as something to re-check once the lock is
  frozen (`docs/plan/FLAKE-REPRO.md`).
- The user-data snippet in §5 is staged text, not a script that has ever run
  against a real instance.
