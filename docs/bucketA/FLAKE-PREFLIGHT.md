<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Flake pre-flight audit — remaining first-build gotchas

> **Method:** static read of `flake.nix`, every `os/*.nix`, `scripts/flake-check.sh`,
> `scripts/flake-lock.sh`, plus the Cargo workspace graph they build
> (`Cargo.toml`, `Cargo.lock`, `desktop/src-tauri/Cargo.toml`,
> `crates/postern-telephony/*`). No Nix on this host — nothing here was
> evaluated or built. Where a real S3 build log
> (`/private/tmp/.../scratchpad/logs/build.log`, an actual `nix build .#bloch`
> run captured pre-box, referenced by `docs/bucketA/PACKAGE-FOD-HASHES.md`)
> gives ground truth, that is called out explicitly and is **not** a claim
> made on this workstation.
>
> Two issues are already known and out of scope for re-litigation here:
> curl-bootstrap (fixed), and the 5 `lib.fakeHash` sentinels in
> `os/package.nix` (real value found in the build log, documented in
> `docs/bucketA/PACKAGE-FOD-HASHES.md`, not yet applied to the tree).

> **⚠ FOD-HASH PATH SUPERSEDED — point at the protocol-repo flake instead.**
> Issue #1 and the `os/package.nix` / `os/seal-gate.nix` FOD-hash discussion
> below assume the old path of filling the 5 `lib.fakeHash` sentinels. That
> path is **dead**: the OS build now sources the `bloch` node from the
> **protocol repo's own flake**
> (`gitlab.com/blochsispow-group/BlochSISPoW-project`), which has **zero
> git-sourced crates and no `cargoLock.outputHashes`/FOD-hash step** — so the
> sentinel-fill gotchas no longer apply to the live build path. See
> [`PACKAGE-FOD-HASHES.md`](PACKAGE-FOD-HASHES.md) (supersession header) and
> dossier item 7 ([`../design/RESUME-DOSSIER-2026-07-16.md`](../design/RESUME-DOSSIER-2026-07-16.md)).
> **This pivot is a recorded decision, NOT yet implemented in the tree** —
> `os/package.nix` / `os/seal-gate.nix` still carry the FOD block, `flake.lock`
> is still the empty seed, and **no OS image has ever been built.** The
> non-FOD findings below (ESP contents, `stateVersion`, `displayManager.gdm`,
> the clean checks) still stand; the FOD-specific ones are retained for history.

## Ranked list

### 1. [HIGH — confirmable statically, partially confirmed by a real build log] `os/package.nix` never scopes the cargo build to the `bloch` binary — the very next `nix build .#bloch` after the FOD hashes are filled is likely to fail again, on a different error

**File:** `os/package.nix:14-53` (the `rustPlatform.buildRustPackage` block).

**What's wrong:** `os/package.nix` sets `src = lib.cleanSource ../.;` (the
whole repo) and `cargoLock.lockFile = ../Cargo.lock;` (the whole root
workspace's lock) but declares **no** `buildAndTestSubdir` and **no**
`cargoBuildFlags`/`-p` selecting a package. Compare:
- `os/seal-gate.nix:84-86` — scopes with `buildAndTestSubdir = "crates/postern-seal-companion"; cargoBuildFlags = [ "--bins" ];`
- `crates/postern-telephony/package.nix:24` — scopes with `buildAndTestSubdir = "postern-telephony";`

`os/package.nix` has neither. Per Cargo semantics, a bare `cargo build` in a
**virtual workspace** (no root package — this repo's `Cargo.toml` is exactly
that) with no `default-members` set (there isn't one — checked) behaves as if
`--workspace` was passed: it builds **every** member in `Cargo.toml`'s
`members = [...]` list (`crates/postern-core`, `crates/postern-trail`, …,
`mobile/core`, **`desktop/src-tauri`** — 20 members total).

Meanwhile the actual `bloch` binary (`meta.mainProgram = "bloch"`, and what
`os/bloch-node.nix:67` execs as `"${cfg.package}/bin/bloch"`) is **not** a
member of this workspace at all — it is consumed only as an external git
dependency (`desktop/src-tauri/Cargo.toml:20` pulls `bloch = { git =
"https://gitlab.com/blochsispow-group/BlochSISPoW-project.git", rev =
"dd8df3526…" }`). Confirmed directly in `Cargo.lock:1026-1028`: `[[package]]
name = "bloch" … source = "git+https://gitlab.com/blochsispow-group/…"` — a
git source, not a `source = null` (path/workspace-member) entry. A
repo-wide search for `[[bin]]` blocks producing exactly `bloch`,
`bloch-wallet`, or `bloch-cli` (`grep -rn 'name = "bloch"' --include=Cargo.toml`)
returns **zero** hits anywhere in this repo — those binaries, if they exist at
all under those names, live only inside the external BlochSISPoW-project repo.

Cargo does **not** build binary targets of a non-workspace-member dependency
just because it's in the dependency graph — `-p <spec>`/`--package` is
restricted to workspace members (a long-standing, frequently-hit Cargo
limitation). So even a perfectly successful build of this derivation as
currently written would **never produce `$out/bin/bloch`** — the one file
every consumer (`os/bloch-node.nix`, `environment.systemPackages` in
`os/configuration.nix`/`os/desktop.nix`/`os/cloud.nix`/`os/mobile.nix`) needs.

**Compounding, more urgent problem:** because `cargo build` defaults to the
whole workspace, it also tries to compile `desktop/src-tauri` — a Tauri v2
desktop GUI app whose dependency tree (`tauri`, `tauri-build`, and on Linux
transitively `gtk`, `gtk-sys`, `webkit2gtk`, `webkit2gtk-sys`,
`javascriptcore-rs(-sys)`, `soup3(-sys)`) needs `gtk+-3.0`,
`webkit2gtk-4.1`/`4.0`, `javascriptcoregtk`, `libsoup-3.0` as **system**
libraries via `pkg-config`. `os/package.nix`'s `buildInputs = [ openssl
rocksdb ];` / `nativeBuildInputs = [ pkg-config clang ];` provide none of
these.

**Ground truth from the real build log** (the S3 log referenced by
`docs/bucketA/PACKAGE-FOD-HASHES.md`, a local copy of which is at
`/private/tmp/claude-501/-Users-tiagoacioli/e1b1043b-49c1-436d-8c39-f54a0d28ad8a/scratchpad/logs/build.log`):
that log **confirms** `gtk-sys-0.18.2`, `webkit2gtk-sys-2.0.2`,
`javascriptcore-rs(-sys)-1.1.x`, `soup3(-sys)-0.5.0`, `tauri-2.11.5`,
`tauri-build-2.6.3`, `tauri-runtime-wry-2.11.4` etc. are all fetched/vendored
as part of the `.#bloch` derivation's dependency closure (grep
`gtk\|webkit\|tauri` in that log — dozens of hits). That is real evidence
this repo's `Cargo.lock`-wide vendor step does pull in the whole GTK/WebKit
stack for `.#bloch`, exactly as this static read predicts. **What the log does
NOT yet show:** the actual `cargo build` compile phase — the captured run
aborts earlier, at the FOD hash-mismatch stage (`error: hash mismatch in
fixed-output derivation '…BlochSISPoW-project-dd8df35.drv'`, line 10552), so
whether the pkg-config failure for gtk3/webkit2gtk actually fires is
**box-gated**: it needs a real `nix build .#bloch` run *after* the 5 FOD
hashes are filled to observe the `cargo build` phase for real.

**Fix (needs an owner decision, not just a hash paste):**
- Scope the build the same way `os/seal-gate.nix` does — but `bloch` can't be
  targeted the same way (`buildAndTestSubdir`/`-p` only work for workspace
  members, and `bloch` isn't one). The real fix is likely one of:
  (a) vendor/patch `bloch` in as an actual local workspace member (a `[patch]`
  pointing `bloch` at a path, or adding it to `members`), so
  `buildAndTestSubdir`/`cargoBuildFlags = [ "-p" "bloch" ]` can target it, or
  (b) point `os/package.nix`'s `src`/`cargoLock` at a *separate* checkout of
  the BlochSISPoW-project repo itself (fetched with its own hash) instead of
  `lib.cleanSource ../.`, since that is where the `bloch` binary's own
  `Cargo.toml`/`[[bin]]` actually lives (unverified from this repo — that
  repo's manifest was never read here).
- Either way, `desktop/src-tauri` should never be part of `.#bloch`'s build
  graph — that's the wallet-desktop GUI app's own build story, not the
  headless node's.
- This is a design question for whoever owns `os/package.nix` (per the file's
  own O1/CS-5 attribution), not something to guess at from a non-Nix host.

---

### 2. [MEDIUM — box-gated] `os/attested.nix`'s ESP partition may build with no bootloader content, producing a disk image that doesn't boot

**File:** `os/attested.nix:115-124` (the `"esp"` partition: `contents = { };`
— empty).

The comment on line 117 says "UKI(s) placed by systemd-boot / the bootloader
install," but `boot.loader.systemd-boot.enable = true` (line 76) is a
*host-install-time* mechanism (`bootctl install` writes into a live `/boot`),
not something that automatically populates a `systemd-repart` image's ESP
partition contents at **image-build time**. Populating an ESP inside a
`image.repart` partition normally needs an explicit
`partitions."esp".contents."/EFI/…".source = "${pkgs...}/...";` entry (or
nixpkgs's newer UKI-in-repart integration, if the pinned 24.05 revision has
it — module surface, per the file's own header, "drifts across nixpkgs
releases"). If the pinned `nixpkgs` revision's `repart.nix` doesn't
auto-populate ESP from `boot.loader.systemd-boot`, `nix build
.#attested-image` may well **succeed** (Nix has no way to assert "this ESP
is bootable" at build time) while producing an image with an empty/non-boot
ESP — a boot-time failure that looks like a build success. **This needs a
real Nix eval of the pinned `nixpkgs`'s `nixos/modules/image/repart.nix` to
confirm** — cannot be checked from this host.

**Fix:** on the Nix host, after a first `nix build .#attested-image`, inspect
the built image's ESP partition contents before assuming it boots; if empty,
wire an explicit UKI/`systemd-bootx64.efi` `contents` entry.

---

### 3. [LOW — confirmable statically, likely harmless] `system.stateVersion` is set ahead of the pinned nixpkgs channel

**Files:** `os/configuration.nix:35`, `os/desktop.nix:87`, `os/cloud.nix:324`
all set `system.stateVersion = lib.mkDefault "25.05";` while `flake.nix:34`
pins `nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";`. `os/sloboda-vm.nix:104`
correctly uses `"24.05"`.

`stateVersion` doesn't have to equal the nixpkgs release exactly, but setting
it to a **later** release than the nixpkgs you're actually building against
is backwards from its intended use (it exists so option defaults can gate on
`lib.versionAtLeast config.system.stateVersion "X.YZ"` for **already-installed**
systems). It is unlikely to hard-fail an eval, but it is worth aligning to
`"24.05"` for honesty/consistency with the pinned channel, and because a
handful of modules do read this value to pick defaults that may reference
25.05-era behavior not actually present in the pinned 24.05 nixpkgs.

**Fix:** change the three `"25.05"` defaults to `"24.05"` to match the pinned
channel (or bump the pin — but the header's `nixos-24.05` pin is called out
deliberately elsewhere in the repo, so aligning `stateVersion` down is the
smaller, safer change).

---

### 4. [LOW — box-gated] `services.displayManager.gdm` may be the wrong option path on `nixos-24.05`

**File:** `os/desktop.nix:22` — `services.displayManager.gdm = { enable = true; wayland = true; };`

NixOS's display-manager module surface has been mid-refactor across recent
releases (moving `services.xserver.displayManager.<dm>` toward
`services.displayManager.<dm>`); whether the new `services.displayManager.gdm`
namespace is the correct/complete path on `nixos-24.05` specifically (vs.
needing `services.xserver.displayManager.gdm.enable`) is genuinely uncertain
from a static read and **needs a real `nix eval`/`nixos-option` against the
pinned revision to confirm** — exactly the class of "module option paths
drift across nixpkgs releases" risk `flake.nix:94-97` already calls out
generically for the installer/repart/verity surface. If wrong, `nix build
.#desktop-iso` fails at eval time with an "option does not exist" error
(cheap and obvious to fix once seen — flagging pre-emptively so it isn't a
surprise on the first `.#desktop-iso` attempt specifically).

---

### 5. [Checked, clean] No other `fakeHash`/empty-hash sentinels

Repo-wide grep for `fakeHash|fakeSha256|lib\.fake` across every `*.nix` file
found **only** the two already-known blocks: `os/package.nix:34-38` (5 keys,
real hash found, not yet applied — `docs/bucketA/PACKAGE-FOD-HASHES.md`) and
`os/seal-gate.nix:76-80` (5 keys, same crates/rev, documented in
`flake.nix:148-157` as an intentional cross-dev gate, plausible-but-unverified
per `docs/bucketA/PACKAGE-FOD-HASHES.md`'s own note that only a `.#bloch`
build was captured, not `.#seal-gate`). No `builtins.fetch*`, `fetchurl`,
`fetchFromGitHub`, `fetchgit`, or `fetchTarball` calls appear anywhere in any
`*.nix` file in this repo — the only network-fetching Nix mechanism in play
is the `cargoLock.outputHashes` FODs already covered above, so there is no
independent "third" fetch-hash gotcha hiding elsewhere.

---

### 6. [Checked, clean] No floating/unpinned inputs beyond the documented two

`flake.nix` declares exactly two inputs: `nixpkgs` (branch ref
`nixos-24.05`) and `mobile-nixos` (`flake = false`, no rev pin — floating
HEAD). Both are already covered by the documented empty-seed
`flake.lock`/`scripts/flake-lock.sh` mechanism (confirmed: `flake.lock` on
disk is genuinely the empty seed — `{"nodes":{"root":{}},"root":"root","version":7}`,
no fabricated `narHash`, matches the header's description exactly). No other
`.url` / floating git ref appears in any `os/*.nix` or `scripts/flake-*.sh`
file. The `Cargo.lock` git dependency (the actual second floating-ref risk,
the historical "dual-git-rev" bug) is confirmed **fixed**: all 5 affected
crates (`bloch`, `bloch-crypto`, `bloch-sis-pow`, `coherence-core`,
`pqcrypto-internals`) now share the single `rev =
dd8df3526518ba792057708a6aa0efd5a91d8e40` source string in `Cargo.lock`
(grep-verified, 5/5 identical, zero remaining `branch=main` refs) — matches
what `os/seal-gate.nix:37-74`'s comment claims.

---

### 7. [Checked, clean] All `import`-ed / `readFile`-d files referenced by `flake.nix` and `os/*.nix` exist on disk

Verified present: `os/boot-harness/boot-qemu-aarch64.sh` (read via
`builtins.readFile` in `flake.nix:177` with **no** `pathExists` guard — this
one would hard-fail eval if missing, unlike the guarded x86 apps — but it
exists), `os/attested/extract-roothash.sh`, `os/boot-harness-x86/boot-qemu-x86_64.sh`
(both `pathExists`-guarded in `flake.nix:193-231`, so a missing file
fails closed at run time, not at eval time — confirmed both exist anyway),
`os/seal-gate/fill-outputhashes.sh`, `crates/postern-telephony/package.nix`
(imported by `os/telephony.nix:26`), `os/browser.nix` (imported by
`os/desktop.nix:16`), `os/attested.nix` (imported by `os/cloud.nix:33`),
`os/telephony.nix` (imported by `os/mobile.nix:11`), `os/sloboda-compat.nix`
(imported by `os/sloboda-vm.nix:39`). No missing-file eval trap found.

---

### 8. [Checked, clean] No `assert`/`throw` that fires unfilled

Repo-wide grep for `assert |throw |lib.mkAssert` across `*.nix` found no bare
`assert`/`throw` statements. The only real NixOS `assertions = [...]` blocks
are `os/attested.nix:90-98` (fires only if `bloch.attested.osRoothash` is a
non-null, malformed value — default is `null`, so it does not fire on a
fresh eval) and `os/sloboda-compat.nix:130-156` (fires only if the
NON-ATTESTABLE Waydroid tier and the sealed read-only root are both enabled
in the same config — structurally impossible given how the modules are
wired into `flake.nix`'s `nixosConfigurations`, since `sloboda-compat.nix`
is imported only by `sloboda-vm.nix`, which never imports `attested.nix`).
Neither fires on any of the `nix build`/`nix flake check` targets as wired.

---

### 9. [Checked, clean] `system` attribute consistency

Every `nixosSystem`/`import nixpkgs { system = …; }` call in `flake.nix` uses
a hardcoded `system` matching its intended target (`x86_64-linux` for the ISO/
cloud/attested configs, `aarch64-linux` for the mobile image), consistent
with the surrounding "never cross-compiled, native build only" comments. No
mismatch found (e.g., no case of building an `aarch64-linux` output attribute
set with an `x86_64-linux` `pkgs`, or vice versa).

---

### 10. [Checked, clean] No import-from-derivation (IFD) traps in this repo's own Nix code

No `import (pkgs.runCommand …)`, `import (builtins.fetchurl …)`, or similar
IFD pattern appears anywhere in `flake.nix`/`os/*.nix`. `evalMobile`'s `import
"${mobile-nixos}/lib/eval-with-configuration.nix"` is a plain source-tree
import (mobile-nixos is `flake = false`, a plain source input), not IFD. Any
IFD inside `mobile-nixos`'s own eval machinery is out of this repo's control
and out of scope for a static read — box-gated to a real build.

## Summary: confirmable-statically vs. box-gated

| # | Risk | Confirmable statically | Needs real Nix eval/build |
|---|---|---|---|
| 1 | `os/package.nix` build-scoping (no `bloch` bin produced; likely pulls GTK/WebKit) | Yes — workspace member list, `Cargo.lock` source field, missing `buildAndTestSubdir` | Whether `cargo build` hard-fails on pkg-config (needs the FOD hashes filled first, then a real build) |
| 2 | Empty ESP contents in `os/attested.nix` | No — depends on pinned `nixpkgs` `repart.nix` internals | Yes |
| 3 | `stateVersion` "25.05" vs pinned "24.05" | Yes | No (unlikely to matter, but worth aligning) |
| 4 | `services.displayManager.gdm` option path on 24.05 | No | Yes |
| 5 | No other fakeHash sentinels | Yes | — |
| 6 | No other floating inputs | Yes | — |
| 7 | No missing imported/readFile'd files | Yes | — |
| 8 | No unfilled assert/throw | Yes | — |
| 9 | No system mismatches | Yes | — |
| 10 | No IFD traps in this repo's code | Yes | mobile-nixos's own internals — box-gated |
