<!--
SPDX-License-Identifier: MIT OR Apache-2.0
Postern for postmarketOS — community edition — on-device validation runbook (B5).
Status: UNRUN / UNBOOTED. This is a plan + evidence format, not a boot record.
NEVER "Postern OS". Non-attestable, software keystore, coin worthless, UNAUDITED.
-->

# On-device validation — the 3 published apks (B5)

**Product:** *Postern for postmarketOS — community edition* — **never "Postern OS".**
**Scope (master-plan B5):** install + run the three already-signed aarch64 apks
(`postern`, `postern-wallet`, `postern-apps`) on a real pmOS device, then flip
the build-manifest `boot_tested: UNBOOTED` → `BOOTED:<device>@<YYYY-MM-DD>`
**only** with attached evidence. Ties to **B3** (WalletCore on-device — see
`../mobile/core/ON-DEVICE.md`), which shares the same "runs on the phone" gate.

> **Honesty first (`HONESTY.md`, `PUBLISHED.md`).** "Built + signed + installs
> via apk" is **not** "runs correctly on your phone." As of today **no image has
> booted and no apk has run on any device** — zero-count. This file is the
> runbook and the evidence contract; it does not claim a result.

---

## 0. Current status — what is proven WITHOUT a device (2026-07-12)

The dev host is macOS (no Linux kernel / loop devices / aarch64 device), so the
on-device steps below are **UNRUN**. What *has* been verified off-device today
(reproduce with `build/verify-apks.sh`):

| Check | Result |
|---|---|
| Live repo reachable (key, APKINDEX, 3 apks) | ✅ HTTP 200 all five |
| Source-integrity: each APKBUILD `source=` tarball sha512 vs recorded | ✅ exact match (wallet `2ba8aa4b…`, apps `86e1534c…`) |
| Published-apk payload vs APKBUILD | ✅ meta deps, `usr/bin/postern-wallet`, 7 apps + launchers + first-run.md |
| WalletCore engine (`mobile/core`) native `cargo test` | ✅ 6/6 incl. golden byte-identity |

None of the above is a device boot or an on-device run — those stay **UNRUN**
until the steps in §2–§4 execute on hardware.

---

## 1. Preconditions — you need one of these targets

B5 needs the apks *running on a device*. Two honest paths:

1. **Flashed community image (needs B4 first).** Dev-4 / `aarch64-build.md` +
   `build/build.sh all` produce `postern-pmos-<device>-…-v0.1.img`; flash per
   `FLASH.md` and boot. The apks are already inside the image (installed from the
   live repo at build time). This is the full-stack path and the one whose boot
   flips the manifest.
2. **`apk add` onto an existing pmOS device (validates the apks alone).** On any
   pmOS/Alpine aarch64 phone already running Phosh, add the repo + key
   (`PUBLISHED.md` snippet) and `apk add postern`. This validates the **three
   apks** without waiting on the Postern image build — the narrowest true B5
   signal. Record it as "apks validated on <device> via apk (not the Postern
   image)", never rounded up to "the image booted".

Either way the device is a **listed Mobile-NixOS/pmOS handset** (default
`pine64-pinephone`; alternatives per `build.sh`). **Never an Android device** —
these apks target pmOS, not Android.

---

## 2. Install + smoke-test steps (capture everything)

Start serial/console capture BEFORE powering on (`FLASH.md §serial`), then:

```sh
# 2.a  Confirm the three packages are present + came from the signed repo.
apk info -e postern postern-wallet postern-apps      # all three: installed
apk verify /var/cache/apk/postern-wallet-*.apk       # signature verifies (builder-6a52d247)
apk policy postern-wallet                            # repo == the R2 base, key trusted

# 2.b  postern-wallet — the real work: run the CLI on-device.
postern-wallet --help                                # DoD: prints usage (binary runs on aarch64/musl)
postern-wallet new --testnet                         # generates a wallet + mnemonic (software keystore)
postern-wallet address --testnet                     # prints a bloch1t… address
#   Cross-check B3: the address for a KNOWN seed must equal mobile/core's golden
#   tuple (see ../mobile/core/ON-DEVICE.md) — same bloch-crypto rev, same bytes.

# 2.c  postern-apps — launchers land in the Phosh grid and open.
ls /usr/share/applications/postern-*.desktop         # 7 launchers present
#   Tap each in Phosh (or `gtk-launch postern-sotto`); it must open the app's
#   index.html in the system browser (xdg-open). Photograph one open app.

# 2.d  postern (meta) pulled its deps and Tor is enabled.
rc-status | grep -i tor                              # tor service enabled (post-install)
systemctl is-system-running 2>/dev/null || rc-status # OpenRC: no crashed services
```

## 3. Success markers (the shared grep list)

The QEMU CI gate (dev-1) and this hardware sign-off must agree on what "runs"
means. On-device, the run is validated when the captured log / session shows,
with **no** `Kernel panic`, no OpenRC service in `crashed`, and no apk signature
error:

- `postern-wallet --help` prints usage; `postern-wallet address` prints `bloch1…`
- all three apks report installed (`apk info -e`) and signature-verified
- the 7 `postern-*.desktop` launchers exist and at least one app opens (photo)
- `tor` service is enabled and started

## 4. Evidence format (shared with dev-1 / dev-4 boot evidence)

One evidence bundle per validated device, stored beside the manifest:

```
build/out/evidence/<device>-<YYYY-MM-DD>/
  console.log            # full serial/console capture (boot → the §2 commands)
  console.log.sha256     # sha256 of the log
  display.jpg            # photo: Phosh grid + one Postern app open on the screen
  session.txt            # the exact commands run + their output (§2)
  image.sha256           # sha256 of the .img flashed (from build/out/*.img.sha256), OR
  apk-provenance.txt     # if path-2: `apk policy` + `apk verify` output proving the signed repo
```

Then, and only then, hand-flip the manifest (same discipline as
`aarch64-build.md §3`):

```json
"boot_tested": "BOOTED:pine64-pinephone@2026-07-12"
```

Never flip `boot_tested` without `console.log` + `display.jpg` attached. An
`UNBOOTED` image may still be published (the publisher warns), but the download
page must say so with the zero-count honesty of the device matrix.

---

## 5. What a green B5 proves — and what it does not

**Proves:** the published, signed apks **install and run** on *that one* device —
the wallet CLI executes on aarch64/musl, the apps open, Tor starts. Combined with
the off-device source-integrity check (§0), the running bytes trace to the
recorded source.

**Does NOT prove:**
- **Not reproduced / not attested.** Alpine is not bit-for-bit reproducible; the
  apk signature says *who published*, not *what it was built from* (`HONESTY.md`).
- **One unit ≠ the device.** A run on one PinePhone 1.2 is not a run on 1.0/1.1,
  the PineTab2, or any other handset. The matrix stays zero-count per device
  until each is actually validated.
- **Software keystore, non-attestable.** No TEE/StrongBox on pmOS; wallet keys
  are software. Bootloader unlocked. Never described as hardware-backed.
- **Alpha build key.** `builder-6a52d247` is "this build, this key", not a
  long-lived release anchor (`KEYS.md`).
- **No security/financial claim.** UNAUDITED, mainnet-beta, coin worthless.
