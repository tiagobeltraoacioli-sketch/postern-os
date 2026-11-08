# Postern for postmarketOS — apk overlay (scaffold)

Packages the Postern app suite, wallet, and Tor integration as ordinary
postmarketOS/Alpine packages, installable with `apk add postern` on any
pmOS v26.06 device. This is recommendation **C** ("overlay, not fork") from
`mobile-base-expansion-strategy.md`. **Read `HONESTY.md` first** — this is
not "Postern OS" and carries no reproducibility/attestation guarantee.

**Status: scaffold. Nothing here has been built yet.** Every `# TODO` marks
a step that needs a real Alpine/pmOS build host or a real release artifact.

## Layout

```
pmos-overlay/
├── postern/            meta package (apps + wallet + tor + default UI flavor)
├── postern-wallet/     native Rust wallet (crates/postern-vault et al.)
├── postern-apps/       web app suite (apps/*) as static assets, noarch
├── flavor/             concrete flavor: packages.list, phosh defaults, wallet
│                       launcher, first-run wiring, postern-flavor/ package, RUNBOOK.md
├── overlay/            rootfs overlay (OpenRC services, firewall, Tor/Arti, MOTD)
├── keys/               postern-keygen.sh — key generation / rotation helper
├── publish-apk-repo.sh publish the SIGNED apk repo to R2 (System A; DISTRIBUTION.md)
├── publish-to-r2.sh    publish the whole-disk .img to R2 (System B; FLASH.md)
├── build/              build.sh (image assembly) + r2_upload.py + manifest
├── KEYS.md             signing keys: alpha→stable path, rotation, ≥2 publish sites
├── REPO-HARDENING.md   review: checksums, pinned tags, index signing
├── DISTRIBUTION.md     bucket layout, publish pipeline, user install snippet
├── HONESTY.md          mandatory labeling & non-attestation statement
└── README.md           this file
```

## Building

### With pmbootstrap (recommended for pmOS targets)

pmbootstrap builds packages out of a pmaports checkout, so the overlay
directories must be visible inside it:

```sh
pmbootstrap init                       # once; pick channel matching v26.06
# TODO(verify): the supported way to add out-of-tree packages is to fork
# pmaports and drop these dirs into it (pmbootstrap scans the checkout's
# package dirs). Symlinking into the checkout also works in practice.
# Verify current guidance in the pmbootstrap docs before relying on it.
cp -r postern postern-wallet postern-apps ~/.local/var/pmbootstrap/cache_git/pmaports/temp/

pmbootstrap checksum postern-wallet    # populates sha512sums= in the APKBUILD
pmbootstrap build --arch aarch64 postern-wallet
pmbootstrap build --arch aarch64 postern-apps postern
pmbootstrap sideload postern           # install onto a connected device over SSH/WiFi
```

(`pmbootstrap build <pkg>`, `--arch`, `pmbootstrap checksum`, and
`pmbootstrap sideload` are per the pmbootstrap documentation,
docs.postmarketos.org/pmbootstrap.)

### With plain abuild (Alpine chroot / CI)

On an Alpine host or container with `alpine-sdk` installed:

```sh
abuild-keygen -a -i -n     # generate signing keypair; -a appends
                           # PACKAGER_PRIVKEY= to ~/.abuild/abuild.conf,
                           # -i installs the pubkey into /etc/apk/keys,
                           # -n is non-interactive
cd postern-wallet
abuild checksum            # fills in sha512sums=
abuild -r                  # build in a clean chroot; output lands in
                           # ~/packages/<repo>/<arch>/*.apk with a signed
                           # APKINDEX.tar.gz generated automatically
```

`# TODO(build-host)`: none of the above has been executed for these
packages; expect the first run to surface real errors (crate/binary names,
source URLs, dep names).

## Repository signing

Every `.apk` and the repository index are signed with the RSA key from
`abuild-keygen`. When assembling/refreshing a repo directory by hand:

```sh
cd repo/v26.06/postern/aarch64
apk index -o APKINDEX.tar.gz *.apk
abuild-sign -k ~/.abuild/<keyname>.rsa APKINDEX.tar.gz
```

`abuild-sign` embeds the signature as `.SIGN.RSA.<keyname>.rsa.pub` inside
the index tarball; `apk` on the client verifies it against the same-named
file in `/etc/apk/keys/` — **the public key's filename must match the key
name used at signing time** (verified against abuild-sign source: apk looks
up `/etc/apk/keys/KEY` by the pubkey's basename).

Key handling: the private key never leaves the signing host/CI secret
store; back it up offline. Losing it means re-keying every installed client.
The full key policy — the path from the **alpha build key** to a **stable
long-lived release key**, rotation (ship-new-key-first), and publishing every
public key in **≥2 places** with fingerprints — is in `KEYS.md`; generate and
rotate keys with `keys/postern-keygen.sh` (no private key is committed here).

## Hosting & installing (Cloudflare R2) — see `DISTRIBUTION.md`

An apk repository is just static files over HTTPS; we host it in a public
Cloudflare R2 bucket behind a custom domain and publish with
`./publish-apk-repo.sh` (via `build/r2_upload.py` against R2's S3 endpoint;
credentials from env vars only; fail-safe ordering: key first, then apks, then
the signed `APKINDEX.tar.gz`, then the `meta/<branch>.json` pointer last —
with index-signing, write-once-key, and immutable-apk guards enforced; see
`REPO-HARDENING.md`). The whole-disk `.img` is a separate channel published by
`./publish-to-r2.sh` (`FLASH.md`).

Layout is one branch dir per pmOS release with per-arch subdirs
(`v26.06/aarch64/`, `v26.06/x86_64/`, `edge/…`), the public key at the
stable URL `keys/<keyname>.rsa.pub`, and the end-user install is the
tagged-repo form — key into `/etc/apk/keys/`, then
`echo "@postern https://<domain>/v26.06" >> /etc/apk/repositories`, then
`apk add postern@postern`; never `--allow-untrusted`. Full layout, env
vars, install snippet, and the mandatory disclosure copy: `DISTRIBUTION.md`.
The install page MUST carry the disclaimer from `HONESTY.md`.

## Sources used for the conventions in this scaffold

- APKBUILD(5) man page — gitlab.alpinelinux.org/alpine/abuild (APKBUILD.5.scd):
  required variables, `arch` values incl. `noarch`, SPDX `license`,
  meta-package `package() { mkdir -p "$pkgdir" }`, `builddir` override,
  `options="!check"` semantics, install scripts.
- abuild-keygen / abuild-sign sources — same repo: key generation flags and
  index signature mechanics (`.SIGN.RSA.<keyname>`, `/etc/apk/keys/KEY`).
- pmbootstrap docs — docs.postmarketos.org/pmbootstrap (build, --arch,
  checksum, sideload).
- Alpine `<branch>/<repo>/<arch>` repo layout + `apk index`/`abuild-sign`
  flow — community write-ups of custom apk repositories (Alpine wiki was
  bot-blocked at research time; layout cross-checked against dl-cdn
  structure and abuild-sign source).
