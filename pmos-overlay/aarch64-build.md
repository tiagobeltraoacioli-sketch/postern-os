# Building & publishing a "Postern for postmarketOS" aarch64 image

Operator runbook to assemble an **installable disk image** (`.img`) of
*Postern for postmarketOS — community edition* for one aarch64 device by
**installing the already-published, signed `postern` package** from the live R2
apk repo (it does **not** rebuild the apks), then publish the image to
Cloudflare R2 with a minisign-signed `SHA256SUMS`.

> **Read `HONESTY.md` first.** This is **"Postern for postmarketOS", never
> "Postern OS".** The pipeline is *repeatable-ish* and *publisher-authenticated*
> — it is **NOT reproducible and NOT attested**. The wallet uses a **software**
> keystore (never hardware-backed on pmOS). The coin is worthless. Skip to
> [What this proves / does not prove](#what-this-proves--does-not-prove) before
> you put anything on a download page.

**Status honesty (UNRUN / UNBOOTED).** The **apks are LIVE** — built, signed and
published on R2 (`PUBLISHED.md`). But **no image has been built or booted**: no
build host is available here (this workstation is macOS, not Linux; the former
AWS aarch64 host's key was revoked). Everything below is a **turnkey but UNRUN**
recipe. `build/build.sh` and `build/build-manifest.sample.json` ship
`status: UNBUILT`, and `publish-to-r2.sh` refuses that.

---

## 0. Host requirements — the Mac cannot do this

pmbootstrap builds inside Linux **chroots** and creates images with loop
devices; it needs a real Linux kernel, `binfmt_misc`, and root-capable mounts.
**macOS (this workstation) cannot run any of the build steps** — `build.sh
preflight` detects `uname -s != Linux` and stops. You need one of:

| Host | Works? | Notes |
|---|---|---|
| **Linux aarch64** (native arm64 server, arm64 CI runner) | ✅ best | native speed; no emulation; matches the published apks' arch |
| **Linux x86_64 cross host** with `binfmt_misc` + qemu-user | ✅ works | pmbootstrap crossdirect for any native build; the postern apks are prebuilt so little native work remains |
| Fly.io x86_64 Firecracker microVM (Alpine) | ✅ | the `setup-aarch64.sh` target; `binfmt_misc` present, no nested KVM |
| macOS (Intel or Apple Silicon) | ❌ | no Linux kernel/chroots/loop devices. Build stops at preflight |

Because we **install prebuilt apks** rather than compile them, the heavy Rust
build is already done upstream; the host mainly runs pmbootstrap's image
assembly. Sizing: 4–8 GB RAM, 15–25 GB free disk (chroots + the image itself).
Put pmbootstrap's work dir on a real volume, not a small rootfs.

The deep evaluation of *why* no KVM is needed, the crossdirect vs. full-qemu
tradeoff, and the binfmt `F`-flag detail live in the comments of
**`setup-aarch64.sh`**.

---

## 1. One-time: install pmbootstrap

On the Linux build host:

```sh
./setup-aarch64.sh preflight       # kernel + binfmt_misc + arch checks
apk add pmbootstrap                # (or: pip install pmbootstrap==<pin>)
```

You do **not** need to run `pmbootstrap init` by hand — `build/build.sh init`
runs it **non-interactively** (accepts defaults, then pins channel/device/ui via
`pmbootstrap config`). If you prefer, `setup-aarch64.sh pmbootstrap` still does
the interactive init and creates the unprivileged `build` user + doas; `build.sh`
reuses whatever config it finds.

---

## 2. Build the image (`build/build.sh`)

`build/build.sh` is the ordered recipe. It **installs the published `postern`
meta from the live R2 repo** — it never rebuilds the apks — and pins what it
can into `build-manifest.json`:

```sh
# choose the target device (aarch64 pmOS codename) and go:
DEVICE=pine64-pinephone \
PMBOOTSTRAP_VERSION=3.9.0 \
PMAPORTS_COMMIT=<pin-a-real-pmaports-sha> \
  ./build/build.sh all
```

Default device is **`pine64-pinephone`**. Documented alternatives (any aarch64
pmOS codename with a mainline/community port + Phosh): `oneplus-enchilada`,
`fairphone-fp4`, `xiaomi-scorpio`, `pine64-pinetab2`.

`all` runs, in order:

| Step | What it does | Pin captured |
|---|---|---|
| `preflight` | Linux + pmbootstrap + `wget`/`curl` + DEVICE checks | — |
| `init` | non-interactive `pmbootstrap init`; pin **channel** (= pmOS release, not edge), **device**, **ui**; enforce `PMBOOTSTRAP_VERSION` / checkout `PMAPORTS_COMMIT` if set | **pmbootstrap version + channel**, **pmaports git commit** |
| `repo` | `wget` the **`builder-6a52d247`** key into pmbootstrap's cross-chroot key dir (`$work/config_apk_keys/`, copied into every chroot incl. the rootfs); sanity-check it is a PEM key; record the LIVE R2 repo URL | **signing-key sha256** |
| `image` | phase 1: `pmbootstrap install` builds the **Phosh** base **rootfs chroot** (its own unprivileged image-assembly tail — the `/dev/install` u-boot embed — cannot run on this host, so that known post-rootfs failure is tolerated and the rootfs is then hard-asserted present); phase 2: copy the trusted key into the rootfs + `pmbootstrap chroot --rootfs -- apk add --repository <R2> postern` **passed inline** (pmbootstrap 3.10 regenerates `/etc/apk/repositories`, so the repo is NOT appended to that file — it is handed to `apk add --repository`), pulling the published meta → wallet+apps, phosh/tor resolved on-device, then each of the three postern pkgs is hard-asserted in the rootfs apk db; phase 3: **privileged manual disk-image assembly** (`_assemble_image`, `sudo`) reproducing pmbootstrap's `pine64-pinephone` layout — MBR/msdos, 256 MiB *bootable* ext2 `pmOS_boot` + ext4 `pmOS_root`, the **same fstab UUIDs** the rootfs already references, and the `u-boot-sunxi-with-spl-528.bin` blob `dd`'d in at the **8 KiB** pre-partition offset | device/UI/fs |
| `export` | sha256 the `.img` → `<img>.sha256` sidecar | image sha256 |
| `manifest` | snapshot the **exact installed package set** from the rootfs apk db (the "apk world" pin), read back the **resolved postern/-wallet/-apps versions** actually installed from R2, write `build-manifest.json` (`status: BUILT`) | **apk_world_sha256** + resolved published-package versions |

Individual steps also run standalone (`./build/build.sh init`, `… repo`,
`… image`, etc.).

**Output** (under `build/out/`):

```
build/out/postern-pmos-pine64-pinephone-v26.06-v0.1.img
build/out/postern-pmos-pine64-pinephone-v26.06-v0.1.img.sha256
build/out/build-manifest.json          # status: BUILT, boot_tested: UNBOOTED
build/out/installed-packages.txt       # the apk-world pin, sha256'd into the manifest
```

### Why "install, don't rebuild"

The three apks are already **built, signed, and published** for aarch64
(`PUBLISHED.md`): `postern-0.1.0-r0` (meta), `postern-wallet-0.1.0_alpha1-r0`,
`postern-apps-0.1.0_alpha1-r0`, indexed and abuild-signed under
`https://pub-dca67fd26bfb4a6b98115e596095ecd3.r2.dev/pmos/postern`. The image
recipe **trusts the publisher key and installs the published bits**, so the
image ships the *same* signed artifacts users get from `apk add postern` — no
divergent second build. The key is an **alpha build key** (`builder-6a52d247`),
not a stable release key; treat the signature as "this build, this key".

### The three-phase image (and its host-only risk)

pmbootstrap regenerates `/etc/apk/repositories` during `install` **and** its own
final image-assembly step runs the `/dev/install` u-boot embed as an
unprivileged user, which cannot open the loop device on this build host
(`Command failed (exit code 1)`). The recipe therefore does **not** rely on
pmbootstrap to emit the `.img`. Instead it (1) runs `pmbootstrap install` only to
build the **rootfs chroot** (tolerating the known unprivileged image-assembly
failure that follows, then asserting the rootfs is present), (2) trusts the
publisher key inside the rootfs and installs the published meta with
`pmbootstrap chroot --rootfs -- apk add --repository <R2> postern` — the repo is
passed **inline** to `apk add` (not appended to `/etc/apk/repositories`, which
3.10 regenerates across chroot calls), which pulls `postern-wallet` +
`postern-apps` (phosh/tor resolve on-device), and (3) assembles the disk image
**ourselves, with `sudo`** (`_assemble_image`), reproducing byte-equivalent —
**not** byte-identical — the layout pmbootstrap would have emitted for this
device (MBR, ext2 `pmOS_boot` + ext4 `pmOS_root` with the rootfs's own fstab
UUIDs, u-boot at the 8 KiB offset). The **#1 thing a real host must confirm** is
that this privileged manual assembly boots the device exactly as a pmbootstrap
image would — see §"needs a host" below.

### What "pinned" means here (and what it doesn't)

We pin: pmbootstrap version + channel, pmaports commit, the resolved apk world
(every installed package = version), the signing-key sha256, and the resolved
versions of the published Postern packages. Re-running with the same pins gives
a **functionally equivalent** image. It does **not** give a **bit-identical**
one — Alpine/pmOS aren't reproducible. This is *repeatable-ish*, not attestation.

---

## 3. Smoke-test on hardware (manual, sets `boot_tested`)

`build.sh` writes `boot_tested: UNBOOTED`. Flash the `.img` to the device,
boot it, confirm Phosh comes up, Tor/Arti starts, and the wallet launches,
**then** hand-edit the manifest to `boot_tested: BOOTED:<device>@<YYYY-MM-DD>`.
Never flip this without a real boot — the label is meant to be evidence-backed.

Publishing an `UNBOOTED` image is allowed (the publisher warns), but the
download page **must** say so, with the same zero-count honesty as the device
matrix (`HONESTY.md`).

---

## 4. Publish to R2 (`publish-to-r2.sh` — owned by another dev)

The publisher enforces the honesty rails: it refuses any manifest missing the
honest-status labels, refuses anything whose `status` isn't `BUILT`, refuses if
the on-disk image doesn't match the manifest sha256, and refuses if the minisign
secret key doesn't correspond to the published public key.

```sh
# dry run first — no creds, no network; validates + builds & signs SHA256SUMS locally:
./publish-to-r2.sh -i build/out/postern-pmos-*-v0.1.img \
    -m build/out/build-manifest.json -s ~/.minisign/postern.key -n

# real publish (creds from the CI secret store):
export AWS_ACCESS_KEY_ID=…  AWS_SECRET_ACCESS_KEY=…
export R2_ACCOUNT_ID=…      R2_BUCKET=postern-downloads
export MINISIGN_PASSWORD=…  # optional; else minisign prompts
./publish-to-r2.sh -i build/out/postern-pmos-*-v0.1.img \
    -m build/out/build-manifest.json -s ~/.minisign/postern.key
```

User-facing verify (goes on the download page with the disclosure below):

```sh
wget https://pub-dca67fd26bfb4a6b98115e596095ecd3.r2.dev/os/v0.1/<image>.img
wget https://pub-dca67fd26bfb4a6b98115e596095ecd3.r2.dev/os/v0.1/SHA256SUMS
wget https://pub-dca67fd26bfb4a6b98115e596095ecd3.r2.dev/os/v0.1/SHA256SUMS.minisig
minisign -Vm SHA256SUMS -P RWTSe98wfKKHuVRDnywuQmH/cMyP/HNuD/hFFLQeKdQeAHENliqJpmKs
sha256sum -c SHA256SUMS --ignore-missing     # expect: <image>.img: OK
```

---

## What this proves / does not prove

**Proves:**

- **Publisher authenticity + transit integrity.** The minisign signature over
  `SHA256SUMS`, verified with the published public key
  `RWTSe98wfKKHuVRDnywuQmH/cMyP/HNuD/hFFLQeKdQeAHENliqJpmKs`, proves the image
  was published by whoever holds the Postern secret key and wasn't altered on
  the way to you.
- **The image carries the same signed apks as the repo.** Because the recipe
  installs `postern` from the live repo (verified against the
  `builder-6a52d247` key), the wallet/apps bytes in the image are the same
  published artifacts a user would `apk add` — not a divergent rebuild.
- **Repeatability-ish.** The manifest pins pmbootstrap, the pmaports commit, the
  full apk world, the signing-key hash, and the resolved published-package
  versions. A third party with the same pins builds a **functionally
  equivalent** image and can diff the installed-package set.

**Does NOT prove:**

- **Not reproducible.** postmarketOS/Alpine are **not bit-for-bit
  reproducible** (upstream abandoned their reproducible-repo attempt for exactly
  this reason). Nobody — including us — can rebuild this and get an identical
  file. You get a functionally-equivalent image, not the same bytes.
- **Not attested.** There is no Nix closure, no verity seal, no measured boot,
  no hardware root of trust. The signature says *who published it*, not *what it
  was built from*. This repo attests **nothing** about the rest of your system.
- **Alpha build key, not a release anchor.** `builder-6a52d247` is an alpha
  build key. A stable release signing key + a documented rotation is a
  prerequisite before recommending this repo broadly (`PUBLISHED.md`).
- **No hardware-backed keys.** The wallet keystore is **software**. No TEE /
  StrongBox / Keystore guarantees on pmOS; the bootloader is unlocked on
  essentially every pmOS device. Never describe wallet keys here as
  hardware-backed.
- **No security / financial / legal claim.** The associated coin is worthless;
  none of this is a security guarantee or financial/legal advice.

If reproducible, attestable builds are the requirement, that is **Postern OS**
(Mobile NixOS images) — a different product, a shorter device list. This image
is **Postern for postmarketOS — community edition**, and must never be labeled
otherwise.

---

## Validation performed (without a build host)

The pipeline was validated **without running it** (no Linux/pmOS host available
— macOS workstation, revoked AWS host):

- `bash -n` **and** `sh -n` on `build/build.sh` — both clean.
- `shellcheck` on `build/build.sh` — **clean, no findings** (exit 0).
- A **live-repo reachability check** against R2 (this is real, and passed):
  - signing key `pmos/keys/builder-6a52d247.rsa.pub` → HTTP 200, PEM public key
  - `pmos/postern/aarch64/APKINDEX.tar.gz` → HTTP 200
  - `pmos/postern/aarch64/postern-0.1.0-r0.apk` → HTTP 200
  So `build.sh`'s `KEY_URL`/`REPO_URL` reference the **live** repo + key correctly.
- A **manifest JSON trace**: rendered `manifest()`'s `printf` block with sample
  values and validated with `python3 -m json.tool` — valid JSON, all
  publisher-required keys present (`status`, `boot_tested`, `not_product`,
  `attestation`, `reproducible=false`, `attestable=false`, `image.sha256`), and
  parseable by `publish-to-r2.sh`'s dotted-key reader.
- `build/build-manifest.sample.json` re-validated: valid JSON, `status: UNBUILT`
  (so the publisher must refuse it), new install-from-repo schema fields present.
- **Published-apk source-integrity check (2026-07-12, real, passed).** The two
  source tarballs the wallet/apps APKBUILDs pin were fetched from R2 and their
  sha512 recomputed — **both match the `sha512sums=` recorded in the APKBUILDs
  bit-for-bit**:
  - `BlochSISPoW-project-v0.1.0-alpha1.tar.gz` → `2ba8aa4b…e7bac8` (postern-wallet)
  - `bloch-sis-project-v0.1.0-alpha1.tar.gz`   → `86e1534c…a77bf` (postern-apps)

  So the published apks' source anchors are intact and verifiable from this host
  (see `build/verify-apks.sh`, which automates this). This proves *source
  provenance of the inputs*, NOT a reproduced build (Alpine is not bit-for-bit
  reproducible — `../HONESTY.md`).
- **Published-apk payload inspection (2026-07-12, real, passed).** The three
  live apks were downloaded and their `.PKGINFO` + file lists read; each matches
  its APKBUILD: `postern` (meta) depends `postern-wallet postern-apps tor
  postmarketos-ui-phosh`; `postern-wallet` ships `usr/bin/postern-wallet`
  (aarch64, musl-linked) and `postern-apps` (noarch) ships exactly the seven
  apps + `.desktop` launchers + `first-run.md` from the recipe's `_apps` list.
- **WalletCore (B3) native evidence (2026-07-12, real, passed).** `cargo test`
  in `../mobile/core` is green — 6/6, including the golden byte-identity anchor
  (`golden_byte_identity_asserts_equal_to_dev_a_canonical_tuple`) that
  assert-equals Dev-A's canonical address tuple, plus tx-signing,
  diversified-address rotation, and hybrid-signature verification. This proves
  the wallet *engine* on this host; on-device (in a booted image) is the
  separate `DEVICE-VALIDATION.md` gate, still UNRUN.

## Needs a real host + a device boot (cannot be checked here)

1. `pmbootstrap init` (non-interactive), `install` (rootfs only — its
   unprivileged image-assembly tail is expected to fail here and is tolerated),
   and `chroot --rootfs` actually run, and the rootfs chroot lands at
   `$work/chroot_rootfs_<device>/` with a populated `lib/apk/db/installed`. The
   `.img` itself is written by our own `_assemble_image` to
   `build/out/postern-pmos-<device>-<release>-<version>.img` (recorded in
   `build/out/.image.path`) — NOT taken from a pmbootstrap output path.
2. The signing key placed in `$work/config_apk_keys/` really propagates into the
   **rootfs** chroot so apk trusts the R2 repo's signature there.
3. `pmbootstrap chroot --rootfs -- apk add postern` resolves `postern` from the
   appended R2 repo line (repo survives the chroot session), pulls
   `postern-wallet` + `postern-apps`, and resolves `postmarketos-ui-phosh` + `tor`
   from the pmOS/Alpine repos for the pinned channel/ABI.
4. **The privileged `_assemble_image` produces a bootable image** — that our
   own `sudo` disk assembly (sfdisk MBR + mkfs.ext2/ext4 with the rootfs's fstab
   UUIDs + rsync of the rootfs + `dd` u-boot at 8 KiB) reproduces a layout the
   device actually boots, matching what pmbootstrap's own (unprivileged, here
   un-runnable) assembly would have emitted. This replaces the old "re-run
   pmbootstrap install to re-image" risk; the loop-device + partscan +
   `losetup` path is the part that only a real Linux host can exercise.
5. The rootfs apk-db path (`chroot_rootfs_<device>/lib/apk/db/installed`) exists
   and the world pin + resolved postern versions populate.
6. The overlay services (`../overlay/`) actually start under OpenRC and the
   nftables ruleset loads — see `../overlay/README.md` (a separate device
   checklist; the current published `postern` meta does not yet ship those
   files).
7. The image **boots** on the chosen device (the `boot_tested` flip).
8. minisign signing with the real secret key verifies against the published
   public key (the publisher self-check refuses a mismatch, but the *positive*
   path needs the real key + R2 creds).
