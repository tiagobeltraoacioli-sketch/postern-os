# PUBLISHED — what actually exists, honestly

Updated 2026-07-11. This supersedes the "zero-count" line in `HONESTY.md` for the
one package now built — and ONLY that one.

## What IS published (real, verifiable)

Three packages are **built, signed, and published** for **aarch64**, in one
signed Alpine apk repository on the public R2 bucket (one signing key for all):

- Repo base:  `https://pub-dca67fd26bfb4a6b98115e596095ecd3.r2.dev/pmos/postern`
- Packages:   `postern-wallet-0.1.0_alpha1-r0.apk` (the real light wallet CLI),
              `postern-apps-0.1.0_alpha1-r0.apk` (the web-app bundle),
              `postern-0.1.0-r0.apk` (meta — pulls the two + declares the pmOS
              runtime deps postmarketos-ui-phosh + tor, resolved on-device)
- Index:      `pmos/postern/aarch64/APKINDEX.tar.gz` (abuild-signed)
- Signing key:`pmos/keys/builder-6a52d247.rsa.pub`

Built natively on an aarch64 host (no qemu/cross) in an Alpine container with
`abuild`, from source tarballs anchored to the `v0.1.0-alpha1` prerelease tags of
BlochSISPoW-project (the wallet) and bloch-sis-project (the apps), mirrored to R2
with pinned sha512s because both repos are private. `bloch-crypto` wallet CLI,
Falcon-1024 ‖ ML-DSA-65, software keystore.

### Add it on a pmOS / Alpine aarch64 device
```sh
wget -O /etc/apk/keys/builder-6a52d247.rsa.pub \
  https://pub-dca67fd26bfb4a6b98115e596095ecd3.r2.dev/pmos/keys/builder-6a52d247.rsa.pub
echo "https://pub-dca67fd26bfb4a6b98115e596095ecd3.r2.dev/pmos/postern" \
  >> /etc/apk/repositories
apk update
apk add postern-wallet          # just the wallet CLI, or:
apk add postern                 # the meta (wallet + apps + phosh + tor) — on a real pmOS
```

## What is NOT published / NOT done (do not round up)

- **Packages, not an OS.** `postern-wallet` is a real light CLI; `postern-apps`
  is the web-app bundle; `postern` is a meta that only makes sense on a booted
  pmOS (its phosh/tor deps resolve there). The **flavor / bootable image is NOT
  built** — three apks and an index, not an operating system.
- **Signed with an alpha BUILD key** (`builder-6a52d247`), not a stable, published
  Postern release key. Treat the signature as "this build, this key" — not a
  long-lived trust anchor. A real release key + a documented rotation is a
  prerequisite before recommending this repo broadly.
- **Never booted / run on a device.** "Built + signed + installs via apk" is not
  "runs correctly on your phone." No on-hardware validation has happened.
- **Non-attestable tier.** Alpine/musl, not Nix — signed ≠ reproducible ≠
  attested. Only the Nix images are "Postern OS" (see `HONESTY.md`).
- **UNAUDITED.** Mainnet-beta; the coin is worthless by design.

## Next to earn each claim
1. ~~Build `postern-apps` + the `postern` meta.~~ **Done** — all three published.
2. Build the flavor **image** with pmbootstrap on the aarch64 host.
3. Adopt a stable release signing key; re-sign; publish the key in ≥2 places.
   The path, rotation policy, and tooling are in `KEYS.md` +
   `keys/postern-keygen.sh` (still TODO to execute; no stable key generated yet).
4. Flash + **boot on a real device** → then, and only then, an honest ✅.
