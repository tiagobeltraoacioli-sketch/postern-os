# FLASH — verify, flash, and boot "Postern for postmarketOS"

The honest end-user runbook for the disk image published by `publish-to-r2.sh`.
Do the **verify** step first. Everything below is written to be turnkey, but as of
this writing **none of it has been run** — no image has been built, flashed, or
booted (see `HONESTY.md`, `PUBLISHED.md`). Treat every command as UNRUN until you
run it yourself.

> **Read this once, up front — the tier you are on:**
> - This is **Postern for postmarketOS — community edition**. It is **NOT
>   "Postern OS"**. "Postern OS" is reserved for the reproducible, verity-sealed
>   Mobile NixOS images and is the only thing ever called attestable or
>   Seal-covered.
> - **Non-attestable tier.** Alpine/postmarketOS is not bit-for-bit
>   reproducible. The signature below proves **who** published the image and
>   that it arrived unmodified — it does **not** prove **what it was built
>   from**. Signed ≠ reproducible ≠ attested.
> - **Signed with an alpha BUILD key** (`builder-*` for apks; the image
>   checksums are signed with the minisign key below), not a stable long-lived
>   Postern release key. Trust it as "this build, this key" — not a durable
>   trust anchor.
> - **UNBOOTED until you boot it.** No on-hardware validation has happened. The
>   build manifest ships `boot_tested: UNBOOTED`. "Installs" is not "works."
> - **UNAUDITED.** No third-party security audit.
> - **Software keystore only.** The wallet's keys live in software on this
>   platform — no TEE/StrongBox. Fine for daily use; not for keys you cannot
>   afford to lose.
> - **The Postern coin is worthless by design** and no value is claimed for it.
>   Personal use is free. Nothing here is legal or financial advice.

---

## 0. What you download

Everything lives under one R2 prefix on the public host:

```
https://pub-dca67fd26bfb4a6b98115e596095ecd3.r2.dev/os/v0.1/
  postern-pmos-<device>-<pmos-release>-<image-version>.img   # the raw disk image
  <image>.build-manifest.json                                # operator record (honest labels)
  SHA256SUMS                                                  # checksums for every image at this prefix
  SHA256SUMS.minisig                                         # minisign signature over SHA256SUMS
```

The default device image is:

```
postern-pmos-pine64-pinephone-v26.06-v0.1.img      # PinePhone (pine64-pinephone)
```

The alternate device image shipped alongside it is:

```
postern-pmos-oneplus-enchilada-v26.06-v0.1.img     # OnePlus 6 (oneplus-enchilada)
```

The exact filename is fixed by the builder (`build/build.sh`):
`postern-pmos-<device>-<pmos_release>-<image_version>.img`. Substitute your
device's filename below wherever you see `<image>.img`.

The minisign public key that signs `SHA256SUMS` (verify against exactly this):

```
RWTSe98wfKKHuVRDnywuQmH/cMyP/HNuD/hFFLQeKdQeAHENliqJpmKs
```

---

## 1. Download

Do this on the computer you will flash from (a Linux/macOS host), not the phone.

```sh
BASE=https://pub-dca67fd26bfb4a6b98115e596095ecd3.r2.dev/os/v0.1
IMG=postern-pmos-pine64-pinephone-v26.06-v0.1.img   # or the oneplus-enchilada image

wget "$BASE/$IMG"
wget "$BASE/SHA256SUMS"
wget "$BASE/SHA256SUMS.minisig"
```

---

## 2. Verify FIRST — signature, then checksum

**Never flash an image you have not verified.** Verify in this order: the
signature authenticates `SHA256SUMS`; `SHA256SUMS` then authenticates the image.

### 2a. Verify the signature over SHA256SUMS

Install minisign if needed (`apk add minisign`, `brew install minisign`,
`apt install minisign`), then:

```sh
minisign -Vm SHA256SUMS -P RWTSe98wfKKHuVRDnywuQmH/cMyP/HNuD/hFFLQeKdQeAHENliqJpmKs
```

Expect:

```
Signature and comment signature verified
Trusted comment: Postern for postmarketOS -- os/v0.1 -- signed <timestamp>
```

If this does **not** print "verified", stop. Do not use the files.

### 2b. Verify the image checksum

`SHA256SUMS` lists every image at the prefix, so check only the one you
downloaded.

GNU coreutils (most Linux, and on the phone with `apk add coreutils`):

```sh
sha256sum -c SHA256SUMS --ignore-missing        # expect: <image>.img: OK
```

macOS:

```sh
shasum -a 256 -c SHA256SUMS --ignore-missing    # expect: <image>.img: OK
```

BusyBox-only environment (no `--ignore-missing`) — check the single line:

```sh
grep "  $IMG\$" SHA256SUMS | sha256sum -c -      # expect: <image>.img: OK
```

Only proceed once you see `OK` for your image.

> What this proves, exactly: the image was published by the holder of the
> Postern image-signing key and is byte-identical to what they signed. It does
> **not** prove the binary matches any source, and it is **not** attestation.
> Never pass `--allow-untrusted` to apk on the running system to sidestep a
> failed check.

---

## 3. Flash the image to the device

The `.img` is a complete, single-file (`--no-split`) raw disk image: partition
table, boot, and root in one file. You write the whole file to the target block
device. **Writing to the wrong device destroys its data — confirm the device
node before you run `dd`.**

### 3a. PinePhone — `pine64-pinephone` (default, easiest)

The PinePhone boots from microSD without unlocking anything.

1. Insert a microSD (8 GB+) into your computer. Find its device node:
   - Linux: `lsblk` → e.g. `/dev/sdX` or `/dev/mmcblkX` (the whole disk, not a
     partition).
   - macOS: `diskutil list` → e.g. `/dev/diskN`; then `diskutil unmountDisk /dev/diskN`.
2. Write the image (double-check the target, then):
   ```sh
   # Linux
   sudo dd if="$IMG" of=/dev/sdX bs=4M conv=fsync status=progress
   # macOS (rdisk is faster; use the raw node)
   sudo dd if="$IMG" of=/dev/rdiskN bs=4m
   sync
   ```
3. Eject, insert the microSD into the powered-off PinePhone, and power on. It
   boots straight from the card.
4. To run from internal eMMC instead: boot the SD image first, or boot a
   Jumpdrive/USB-storage image, expose the eMMC as a block device, and `dd` the
   same `.img` onto the eMMC device node. Booting from SD is the honest,
   low-risk default; do the eMMC copy only once you have confirmed it boots.

### 3b. OnePlus 6 — `oneplus-enchilada` (alternate, fastboot device)

This device flashes over `fastboot` and requires an **unlocked bootloader**
(unlocking wipes the device). Two honest routes:

- **Simplest, if you can build:** use pmbootstrap end-to-end so the flasher
  handles partitioning:
  ```sh
  pmbootstrap flasher flash_rootfs     # writes the rootfs to the userdata partition
  pmbootstrap flasher flash_kernel     # writes boot
  ```
  (This is the canonical postmarketOS path; it needs the pmbootstrap workdir
  that produced the image, not just the standalone `.img`.)
- **From the standalone `.img`:** boot a temporary environment and copy the
  image onto the internal storage:
  ```sh
  fastboot boot <a-boot.img>           # boot a temporary pmOS/recovery kernel (do not permanently flash it)
  # then, from that temporary system, with the phone's storage visible as /dev/sdX:
  sudo dd if="$IMG" of=/dev/sdX bs=4M conv=fsync status=progress
  ```
  Get the device codename, unlock, and partition specifics from the
  postmarketOS wiki page for `oneplus-enchilada` before flashing — the
  partition layout is device-specific and getting it wrong can brick the phone.

> For **any other pmOS device**: substitute its image filename and follow that
> device's postmarketOS wiki flashing page. The verify step (section 2) is
> identical for every device.

---

## 4. Boot and first run

1. Power on. First boot is slow (filesystem resize, first-time setup); give it a
   few minutes before assuming it hung.
2. You land in **Phosh** (the default shell). If you set full-disk encryption at
   install time, you unlock at boot.
3. The **first thing you see is the honesty note**: the login MOTD and the
   "About this tier" screen state, verbatim, that this is the non-attestable
   tier, software keystore, no covert telemetry, coin worthless, not advice.
   That is by design, not a footnote.
4. **Privacy is on by default and inspectable:** a default-deny firewall
   (`/etc/nftables.d/postern.nft`) and Tor via Arti with an on-device SOCKS
   proxy on `127.0.0.1:9150` (`/etc/postern/arti.toml`). Every knob is a
   readable file under `/etc/postern`.
5. The wallet leads the app grid. Its keys are in software — back up your
   recovery material off-device.

---

## 5. Honest caveats (do not round up)

- **Not "Postern OS".** This is Postern software on postmarketOS. Only the
  Nix/Mobile NixOS images are "Postern OS" or attestable or Seal-covered.
- **Non-attestable tier.** Signed and publisher-authenticated only — not
  reproducible, not attested. The signature proves who and unmodified-in-transit,
  nothing about the build's provenance.
- **Alpha build key.** The signing key is an alpha build key, not a stable
  published release key with documented rotation. Adopting a release key is a
  prerequisite before this is recommended broadly.
- **UNBOOTED until you boot it.** The manifest ships `boot_tested: UNBOOTED`.
  Nothing here has been validated on hardware by the publisher. Everything that
  "works" is pending your boot.
- **UNAUDITED.** No third-party security audit. Mainnet-beta.
- **Software keystore.** No hardware-backed keys on this platform.
- **The coin is worthless by design.** No monetary value is claimed; personal
  use is free; nothing here is legal or financial advice.

If you hit a problem, the honest baseline is: verified download + correct `dd`
to the right device + a patient first boot. Beyond that, this is alpha software
on a community tier — report what you see, and treat "it booted" as new
information, because for the publisher it still is.
