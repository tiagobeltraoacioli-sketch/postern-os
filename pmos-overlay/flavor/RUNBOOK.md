# Flavor runbook — build & flash "Postern for postmarketOS" (community edition)

Step-by-step for a human to turn this flavor definition into a bootable image on
a real device. **This whole runbook requires pmbootstrap on an aarch64 (or
Linux x86_64 cross) host — none of it has been run here** (authoring host is
macOS; no Linux/pmOS build host or device is available). Treat every command as
**UNRUN** until you run it, and the result as **UNBUILT/UNBOOTED** until you see
it build and boot.

> **Read `../HONESTY.md` first.** This is *Postern for postmarketOS — community
> edition*: the **lower-trust, non-attestable tier**, always this name, **never
> "Postern OS"**, not covered by the Postern Seal. Packages are **signed** (who
> published) not **reproducible** (what they were built from), and signed with an
> **alpha build key**, not a stable release key (`../KEYS.md`). The wallet uses a
> **software** keystore. The coin is worthless; none of this is advice.

---

## 0. What this flavor is (recap, so the build is concrete)

The flavor = **package selection + rootfs overlay + first-run**, defined by:

| Piece | File | Ships via |
|---|---|---|
| Default package set | `packages.list` | the `postern` meta + `postern-flavor` |
| UI shell | Phosh (`README.md` §1) | `postmarketos-ui-phosh` (meta dep) |
| Wallet-first app grid | `phosh/20_postern-flavor.gschema.override` | `postern-flavor` |
| Wallet launcher (CLI, terminal) | `apps/postern-wallet.desktop` | `postern-flavor` |
| One-time first-run notice | `first-run/postern-first-run.{sh,desktop}` | `postern-flavor` |
| Services / firewall / Tor(Arti) / MOTD / branding | `../overlay/*` | `postern-flavor` |
| Long-form honesty text | `../overlay/usr/share/postern/first-run/about-tier.txt` | `postern-flavor` |
| Short first-run note | `first-run.md` | `postern-apps` |

`postern-flavor/` (this directory) is the package that owns the overlay + these
UI defaults. It is a **scaffold — UNBUILT**; see its APKBUILD header.

---

## 1. Host + prerequisites (hardware/host-gated)

Same host requirements as the image build — see `../aarch64-build.md` §0 (a Mac
**cannot** do this; you need a Linux aarch64 or x86_64+binfmt host). One-time
setup: `../setup-aarch64.sh` (installs pmbootstrap, doas, the `build` user).

You also need, on that host:

- the published `postern` apks reachable on R2 (they are LIVE — `../PUBLISHED.md`);
- the signing pubkey `builder-6a52d247.rsa.pub` (fetched automatically by
  `../build/build.sh repo`);
- for the **flavor package itself**, either (a) a published `postern-flavor` apk
  in the repo, or (b) the pmaports build of `postern-flavor` from this overlay
  (see §3). As of now `postern-flavor` is **not built or published** — step 3 is
  where you build it.

---

## 2. Build the base image (install the published meta)

`../build/build.sh` builds an image by **installing the published `postern`
meta** from the live R2 repo (it does not rebuild the apks). Full detail:
`../aarch64-build.md` §2.

```sh
DEVICE=pine64-pinephone \
PMBOOTSTRAP_VERSION=<pin> PMAPORTS_COMMIT=<real-pmaports-sha> \
  ../build/build.sh all
# output: ../build/out/postern-pmos-<device>-<release>-<ver>.img (+ .sha256, manifest)
```

This yields a Phosh phone with the wallet + apps + Tor. It does **not** yet carry
the `postern-flavor` overlay (services, firewall, wallet-first grid, first-run) —
that package is not in the published repo yet. Add it in §3.

---

## 3. Build + include the `postern-flavor` package (host-gated)

`postern-flavor` is `noarch` (static config/text). Build it with pmbootstrap or
plain abuild, then install it into the rootfs before re-imaging.

```sh
# a) make the package visible to pmbootstrap (fork pmaports / drop the dir in;
#    verify current guidance in the pmbootstrap docs -- see ../README.md):
cp -r postern-flavor <pmaports-checkout>/temp/

# b) fill checksums + build (noarch -> build once, index into every arch dir):
pmbootstrap checksum postern-flavor
pmbootstrap build postern-flavor            # requires a REAL source tag first (APKBUILD BLOCKER)

# c) install it into the built rootfs chroot (like build.sh phase 2 does for the
#    meta), from your local packages repo or the R2 repo once published:
pmbootstrap chroot --rootfs -- apk add postern-flavor
```

> **Honest blocker:** `postern-flavor`'s `source=` is a scaffold that does **not
> resolve** until a real release tag carrying `pmos-overlay/` exists (same
> blocker as `postern-apps`/`postern-wallet`). Until then this step cannot
> complete — do not claim a flavor-carrying image was built.

Publishing `postern-flavor` to the apk repo (so users just `apk add
postern-flavor`) uses the signed-repo publisher `../publish-apk-repo.sh`
(index-signing + write-once + immutability enforced; `../REPO-HARDENING.md`).

---

## 4. Re-image, export, manifest

Re-run the image assembly so the flavor lands in the `.img`, then export +
manifest (`../build/build.sh image export manifest`). The manifest ships
`status: BUILT`, `boot_tested: UNBOOTED`. See `../aarch64-build.md` §2.

---

## 5. Flash + boot (hardware-gated) — sets `boot_tested`

Flashing and verification are in `../FLASH.md` (verify the minisign signature
first, then `dd`). After a real boot, confirm on-device (the checklist in
`../overlay/README.md`):

- Phosh comes up; the **wallet-first app grid** shows (schema override applied).
- The **first-run notice** appears once, then never nags again.
- `rc-service postern-firewall start` loads the nftables ruleset (`nft -c`
  passes on the device's version).
- `rc-service postern-tor start` brings up Arti's SOCKS listener on
  `127.0.0.1:9150`.
- The MOTD + about screen render the honest tier label verbatim.

Only after a real boot, hand-edit the manifest
`boot_tested: BOOTED:<device>@<YYYY-MM-DD>` — never flip it without a boot.

---

## What this runbook does / does not claim

- **Does:** define the flavor concretely and give a turnkey, honestly-labeled
  path from published apks → a flavor image → a flashed device.
- **Does NOT:** claim any of it was run. No build host, no device: everything is
  **UNRUN / UNBUILT / UNBOOTED** here. Signed ≠ reproducible ≠ attested; alpha
  key, not a stable release key; community edition, **never "Postern OS"**.
