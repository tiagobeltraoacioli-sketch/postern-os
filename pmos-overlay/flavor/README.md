# Flavor spec — Postern for postmarketOS (community edition)

What `apk add postern` delivers as a coherent product: a **wallet-first,
node-capable, privacy-by-default** phone experience on postmarketOS. This is a
**flavor** (a package selection + rootfs overlay + first-run experience), not
an image and not a distribution — we ship packages, never "Postern OS"
(`../HONESTY.md`).

> **Tier, stated once and everywhere the user looks:** this is the
> **lower-trust, non-attestable** tier. Always "Postern for postmarketOS",
> never "Postern OS". **Not covered by the Postern Seal** — the Seal and the
> attestable images are Postern OS (Mobile NixOS) only. Packages are *signed*
> (who published) not *reproducible* (what it was built from).

**How the flavor is assembled (install, don't rebuild).** The three Postern
packages are already **built, signed, and LIVE** in the R2 apk repo
(`../PUBLISHED.md`): `postern` (meta), `postern-wallet`, `postern-apps`. The
image recipe (`../build/build.sh`) does **not** rebuild them — it trusts the
publisher key `builder-6a52d247` and `apk add postern` straight from
`https://pub-dca67fd26bfb4a6b98115e596095ecd3.r2.dev/pmos/postern`, letting the
meta pull the wallet + apps and resolve `postmarketos-ui-phosh` + `tor` on the
pmOS/Alpine side. Signed with an **alpha build key**, not a stable release key.

**UNBOOTED / UNBUILT-image:** the apks exist, but no bootable **image** built
from them has been produced or booted on a device — no build host is available
(the Mac is not Linux; the AWS host is gone). The `../overlay/` rootfs files are
static-checked only. See `../overlay/README.md` for the validation status and
the device-only checklist.

**Concrete flavor artifacts (this directory).** The spec below is now backed by
real, static-checked files:

| Artifact | File | Owns |
|---|---|---|
| Default package set | `packages.list` | the flavor "world" |
| Wallet-first phosh grid | `phosh/20_postern-flavor.gschema.override` | `sm.puri.phosh favorites` default |
| Wallet launcher (CLI, terminal) | `apps/postern-wallet.desktop` | the wallet grid entry |
| One-time first-run notice | `first-run/postern-first-run.{sh,desktop}` | show-once honesty pointer |
| The flavor **package** | `postern-flavor/APKBUILD` (+ post-install/upgrade) | installs `../overlay/` + the above |
| Build+flash runbook | `RUNBOOK.md` | host/hardware-gated, honestly UNRUN |

All UNBOOTED: none has been loaded by a real phosh/OpenRC/nft on a device.

## 1. Default UI shell: Phosh

Keeping the scaffold's pick, now with the reasoning nailed down (no flavor-UX
advisor doc exists yet — this remains provisional until one supersedes it):

- **Maturity on community-tier devices.** Phosh is among the most widely
  tested pmOS UIs, which matters because this non-attestable tier targets the
  broad mainline/community device list rather than a short sealed list.
- **One visual language across both tiers.** Phosh is GTK/GNOME-based, matching
  the Postern OS desktop pick (GNOME), so a user moving between the community
  tier and the attestable tier sees one Postern.
- **A real lockscreen story.** A wallet-carrying phone needs a credible
  on-device lock; Phosh has one. (Still a software keystore — never claim
  hardware-backed keys, `../HONESTY.md`.)

Packaging: the `postern` meta package depends on `postmarketos-ui-phosh`. Users
already on Plasma Mobile / Sxmo get Phosh pulled in alongside — the open
question of softening this hard-dep to a recommendation lives in
`../postern/APKBUILD` (owned by other devs; flagged, not changed here).

## 2. The centerpiece: wallet + node + privacy

| Component | Role | Ships via | Honesty note |
|---|---|---|---|
| **Postern wallet** | the centerpiece — offline, post-quantum (Falcon-1024 + ML-DSA-65) | `postern-wallet` (this overlay) | **software keystore only**; no TEE/StrongBox on this platform |
| **Postern node** | optional node daemon, Tor-routed, unprivileged | *not built by the current wallet-only APKBUILD* — overlay ships the OpenRC wiring (`../overlay/etc/init.d/postern-node`) ready for a node package | flagged in the service file; fails fast if the binary is absent |
| **Privacy: Tor via Arti** | in-process Tor (Rust); on-device SOCKS proxy on `127.0.0.1:9150` for the app suite | `../overlay/etc/init.d/postern-tor` + `arti.toml` | transparent config under `/etc/postern`; no covert routing |
| **Privacy: firewall** | default-deny inbound (nftables) | `../overlay/etc/init.d/postern-firewall` + `../overlay/etc/nftables.d/postern.nft` | endpoint posture, not a router |
| **Postern apps** | store / login / onboard / sotto / tolmach / vedetta web suite | `postern-apps` (this overlay) | offline, self-contained HTML; no external fetches |

**On "in-process Tor via Arti" vs the scaffold's `tor` dep.** The product's
privacy stack is Arti — the Rust Tor implementation — embedded in the node
in-process, with a standalone `arti proxy` service exposing the same Tor path
to the web-app suite on loopback. The current `postern` meta package still
lists the C `tor` daemon in `depends`; that APKBUILD is owned by other devs, so
this flavor **documents the Arti direction and ships the Arti overlay** and
flags the dep for them to reconcile — it does not edit the package.

### Package set

| Package | Why | Status |
|---|---|---|
| `postern` | meta: pulls wallet + apps + phosh + tor | **LIVE** in the R2 repo (`postern-0.1.0-r0`); installed by `build.sh`, not rebuilt |
| `postern-wallet` | the wallet centerpiece (software keystore) | **LIVE** in the R2 repo (`postern-wallet-0.1.0_alpha1-r0`) |
| `postern-apps` | web app suite + first-run note | **LIVE** in the R2 repo (`postern-apps-0.1.0_alpha1-r0`) |
| `arti` | in-process/on-device Tor (Rust) — the privacy layer | Alpine community repo (verify pkg name/version for the v26.06 ABI on device) |
| `nftables` | provides `/sbin/nft` for the default firewall | Alpine main |
| `postmarketos-ui-phosh` | default shell (see §1) | pmaports |
| `postern-flavor` | owns the `../overlay/` rootfs files (services, firewall, MOTD, branding) **plus** the flavor UI defaults (wallet-first phosh grid, wallet launcher, first-run notice) as a package | **scaffolded here** — `postern-flavor/APKBUILD` (+ post-install/upgrade), `noarch`, **UNBUILT** (source tag blocker, like the other packages); `depends="postern nftables"` |
| FDE unlock (`unl0kr`/`osk-sdl`) | only if the user chose FDE at pmbootstrap install — not controlled by a package | pmaports — verify current v26.06 component name on device |

## 3. First-boot experience

1. **MOTD at first login** (`../overlay/etc/motd`) states the tier verbatim:
   lower-trust, non-attestable, not Seal-covered, software keystore, no covert
   telemetry, coin worthless, personal free, not advice.
2. **"About this tier" screen** (`../overlay/usr/share/postern/first-run/about-tier.txt`)
   is the long-form version, reachable from the app suite / about entry. Same
   honesty rails, expanded. This is what §3 of the task calls the honest label
   the user actually *sees* at first run.
3. **Wallet-first landing.** The app grid leads with the wallet
   (`phosh/20_postern-flavor.gschema.override` sets `sm.puri.phosh favorites`,
   wallet first; the wallet launcher is `apps/postern-wallet.desktop`, a terminal
   entry for the CLI). The node and privacy toggles are visible and transparent,
   never hidden. The first-run note is raised as a **one-time** pointer
   (`first-run/postern-first-run.{sh,desktop}`, XDG autostart, shows once then
   stamps a marker) — a pointer, never a nag (`first-run.md`).
4. **Privacy is on by default and inspectable.** Firewall up, Tor (Arti) up,
   node (if installed) refuses non-Tor egress. Every knob is a readable file
   under `/etc/postern`.

The honesty rails are not a footnote here — they are the first two things the
user reads (`first-run.md`, `../overlay/etc/motd`), by design.

## 4. What only a device can confirm

See the checklist in `../overlay/README.md`. In short: services actually start
under OpenRC, Arti binds `127.0.0.1:9150` and accepts the config, the nftables
ruleset loads (`nft -c` passes on the device's version), the dedicated
`postern` user is created cleanly, and the MOTD/about screen render under
Phosh. None of that is claimed as working until a real boot proves it.
