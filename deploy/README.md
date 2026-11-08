<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# `deploy/` — Fly.io microVM definitions

> **STATUS: NOT LAUNCHED — SCAFFOLD.** Every `.fly.toml` in this directory
> is an authored-but-never-deployed definition. No `fly apps create`, `fly
> volumes create`, or `fly deploy`/`fly machine run` has been executed
> against any of these app names from this repo. This is Fly-gated: it needs
> an authenticated `fly` CLI, a Fly org/account with quota for the requested
> `[[vm]]` size, and a human decision to spend that quota. Nothing here
> claims a running machine exists.

## `postern-os-build.fly.toml`

The **second, independent builder** ("builder-B") for the Postern OS L1
image two-builder bit-for-bit reproducibility proof — the OS-tier
counterpart of `postern-apk-build.fly.toml` (the Alpine/postmarketOS apk
host), described in `docs/plan/FLAKE-REPRO.md` §4 and implemented by
`os/repro/repro-verify-iso.sh` + `os/repro/README.md`. The orchestrator that
drives both sides is `scripts/repro-two-builder.sh`, which defaults
`--fly-app` to `postern-os-build` and `--remote-path-b` to
`/root/bloch-protocol`.

### Why a second builder, and why Fly

A reproducibility proof needs two builders that share **nothing but the
pinned git commit and the frozen `flake.lock`** — not the same disk, not the
same kernel, not the same cloud account as builder-A. `os/repro/README.md`
also stages an EC2 path (`repro-verify-iso-builder-userdata.sh`, self-
provisioning, self-terminating). This Fly Firecracker microVM is an
alternative/complementary builder-B: cheaper to keep idling between runs
(the apk-build host already uses this pattern), reachable over `fly ssh
console` instead of SSM/SSH-key management, and — unlike the EC2 metal-boot
path — needs no `/dev/kvm`, since building `.#iso` is compiling/linking, not
booting the result.

### How the host is provisioned (staged, not run)

1. `fly apps create postern-os-build` (or let `fly launch` create it from
   this TOML) in the same org as `postern-apk-build`.
2. `fly volumes create osnix --region gru --size <N>` — sized for the Nix
   store. Unmeasured here (no build has run); start at 60-100 GiB and watch
   `nix store gc` pressure once real ISO builds happen. Mounted at `/nix` per
   the `[mounts]` block, matching the `destination = "/root"` volume
   pattern `postern-apk-build.fly.toml` uses for its abuild state, adapted
   to what actually needs to survive restarts here: the Nix store, not the
   git checkout.
3. `fly deploy --config deploy/postern-os-build.fly.toml` (or `fly machine
   run` directly from the image) to bring up the idling machine — the
   `tail -f /dev/null` process, matching the apk-build host, so the machine
   stays up between builds instead of `fly deploy` treating it as a
   request/response service.
4. On first boot, `git clone` the repo into `/root/bloch-protocol` (the
   `scripts/repro-two-builder.sh --remote-path-b` default) — this lives
   outside the `/nix` volume, so it is re-cloned per machine recreate; only
   `/nix` is persistent. That is deliberate: the repo checkout is cheap and
   must always match `<LOCK_COMMIT>` exactly (step 5), so there is no
   correctness value in persisting a stale clone across restarts.
5. **Every run**, before building: `git fetch && git checkout
   <LOCK_COMMIT>` — the EXACT same commit builder-A checked out, not
   "whatever HEAD is now" and not "each side re-running `scripts/flake-
   lock.sh` independently." `os/repro/repro-verify-iso.sh`'s header explains
   why the latter would make the comparison meaningless: `nixpkgs.url` and
   `mobile-nixos` are floating refs, so two independent locks taken at
   different moments can freeze to different upstream revisions.
   `scripts/repro-two-builder.sh` already encodes this checkout as part of
   the remote command it runs via `fly ssh console -a postern-os-build -C
   '<cmd>'` — see `build_remote_cmd()` in that script.

### The OCI/store-digest diff flow

This host does not compare anything itself — comparison is centralized in
`os/repro/repro-verify-iso.sh compare` (called once, locally, by
`scripts/repro-two-builder.sh`, never on either builder). The flow:

1. Builder-A and builder-B each run `os/repro/repro-verify-iso.sh build
   --attr <iso|desktop-iso|mobile-image|attested-image|cloud-image> --role
   <builder-a|builder-b> --commit <LOCK_COMMIT> --out <manifest>.json`,
   producing a JSON manifest: commit, `flake.lock` sha256, the resulting Nix
   **store path**, and its **narHash** (Nix's content-addressed digest of
   the build output — the OCI-equivalent "digest" for a Nix derivation
   output; there is no separate OCI image push/pull in this flow, the
   store path + narHash pair is the thing that gets diffed).
2. `scripts/repro-two-builder.sh` fetches both manifests locally (builder-B's
   over `fly ssh console -a postern-os-build -C '<cmd>'`, per
   `REMOTE_PATH_B`) and runs `repro-verify-iso.sh compare --a <A>.json --b
   <B>.json`.
3. Three outcomes, never silently collapsed into each other:
   - **MATCH** (exit 0): identical store path AND identical narHash — same
     commit, same lock, on two independent hosts.
   - **MISMATCH / FAIL_DIVERGENCE** (exit 9): same commit and lock, DIFFERENT
     output. Next step is `nix store diff-closures` for a cheap
     closure-level pass, then `nix run nixpkgs#diffoscope -- <A> <B>` for a
     byte-level report — classify each difference as known-benign
     nondeterminism (embedded timestamp, unrewritten self-reference,
     locale-dependent ordering) or unexplained (escalate; do not sign, do
     not publish).
   - **BLOCKED / FAIL_SETUP** (exit 8, or the orchestrator's own preflight
     exit 10): not a valid comparison at all — different commit, different
     lock fingerprint, a dirty worktree on either side, or (in this
     scaffold's actual case) the machine and volume don't exist yet.

### Honest caveats

- **STATUS: NOT LAUNCHED.** This directory defines the machine; it has never
  run. No `nix build` has ever executed on a `postern-os-build` Fly host
  because no such host has been created.
- **Fly-gated.** Bringing this up needs an authenticated `fly` CLI, a Fly
  org with capacity for a 4-cpu/8gb shared VM plus a multi-tens-of-GiB
  volume, and a human decision to spend that quota/cost. None of that was
  available or exercised while writing this scaffold.
- **Reproducible-by-design != reproduced.** Everything above describes a
  procedure engineered to *be capable of* proving `binary == source` for
  the pinned flake input closure. It is not itself a reproducibility claim.
  `os/repro/README.md`'s "Honest interpretation" section states this
  precisely and it applies unchanged here: a future MATCH verdict would
  prove `binary == source` at `<LOCK_COMMIT>` on two independent hosts —
  nothing about whether that source is safe, correct, non-malicious,
  whether the resulting image **boots** (`built != booted`), or how it
  behaves on real hardware (`QEMU != hardware`). Those are separate proofs
  (`os/boot-harness-x86/`, `os/ATTESTATION.md`) that this scaffold does not
  substitute for.
- **PERMISSIVE-license base only — no GPL/AGPL.** The `[build] image` in
  `postern-os-build.fly.toml` is currently `nixos/nix:latest`. Nix itself
  (the package manager binary/daemon shipped in that image) is licensed
  LGPL-2.1 — a weak copyleft, explicitly **not** GPL or AGPL, so it does not
  trip this repo's hard "no GPL/AGPL" rule (the same rule that makes
  matrix-rust-sdk/vodozemac — both Apache-2.0 — acceptable and Element
  — AGPL — never acceptable). LGPL is not the same as MIT/BSD/Apache
  permissive licensing either, and no full audit of every package layered
  into `nixos/nix:latest` (base OS + anything else the image bundles) has
  been done from this authoring host. Before any real `fly deploy` against
  this file: (a) run a license scan across the full image layers, (b) if
  anything GPL/AGPL turns up, switch `image` to a minimal Debian-slim or
  Alpine base plus the Determinate Nix installer (the same installer
  `os/repro/repro-verify-iso-builder-userdata.sh` already uses for the EC2
  path — `curl -fsSL https://install.determinate.systems/nix | sh -s --
  install --no-confirm`), and re-scan.
- **Sizing is a guess.** `cpus = 4`, `memory = "8gb"` in the `[[vm]]` block
  is a starting estimate based on "Nix ISO builds are heavier than apk
  builds," not a measurement — no build has run on this host to calibrate
  against. Expect to revise after the first real attempt.
