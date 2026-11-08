# HONESTY — read before shipping or naming anything in this directory

**This overlay is NOT reproducible and NOT attestable.**

**It must always be labeled "Postern for postmarketOS" — never "Postern OS".**
Only the Nix-built, verity-sealed Mobile NixOS images are ever called
"Postern OS" or described as attestable. One landing page that lets the
attestable claim bleed onto this overlay poisons the core promise
(mobile-base-expansion-strategy.md, Option B failure mode).

## Why, precisely

- **Alpine/postmarketOS packages are not bit-for-bit reproducible** as a
  distro property. postmarketOS's own reproducible-binary-repo attempt was
  abandoned ("didn't have real benefit since Alpine wasn't reproducible
  itself"). Pinning `Cargo.lock`, apk indices, and pmbootstrap versions makes
  builds *repeatable-ish*, not attestable.
- **There is no Nix closure here.** An APKBUILD produces an artifact you must
  trust the build host for. We sign the apk repo (see README.md), which
  proves *who published it* — it does not prove *what it was built from*.
- **No hardware-backed keys.** The wallet on pmOS uses a software keystore.
  No Android Keystore, no StrongBox, TEE access varies per device. Never
  describe wallet keys on this platform as hardware-backed.
- **The bootloader is unlocked on essentially every pmOS device**, so even a
  hypothetical verity setup would be tamper-evidence without a hardware
  anchor — not device attestation.

## Required labeling (exact strings)

- Product name: **Postern for postmarketOS — community edition**
- Mandatory disclaimer wherever it is offered for install:
  > Postern software on postmarketOS. No reproducibility or attestation
  > guarantee. The attestable images are "Postern OS" (Mobile NixOS) only.
- Per the support policy (mobile-support-policy.md): claims are stamped,
  evidence-backed, and never inflated. As of 2026-07-10 **nothing in this
  directory has ever been built or installed on any device** — every package
  here is a scaffold with TODOs. Do not publish a repo from it until a real
  `abuild` has run and the artifacts have been smoke-tested on hardware, and
  say so on the page with the same zero-count honesty the device matrix uses.

## Store-catalog signing ≠ apk builds (2026-07-13)

The Postern Store's catalog **index** (`apps/postern-store/catalog.json`) is now
signed with a detached **Ed25519** signature (`catalog.json.sig`) and verified
in-page — see `apps/postern-store/SIGNING.md`. That signature proves only that
the **list** came from Postern's curator key. It is **not** an apk signature and
says nothing about any binary in this overlay. As of this date **no apk in this
directory has been built** — the pmOS/Alpine apk build (`abuild` /
`pmbootstrap`) requires a Linux aarch64 host and cannot run on the macOS dev
host used here (`build/build.sh` refuses non-Linux; `abuild`/`apk`/`qemu` are
absent). Accordingly every hosted entry in `catalog.json` still carries
`checksum: null` and `signing.state: "unpublished"`. The apk build + repo signing
(System A RSA, `keys/postern-keygen.sh` + `publish-apk-repo.sh`) and the R2
publish (`publish-to-r2.sh`) remain host-/infra-gated and unrun.
