# Sloboda — Waydroid gateway wrapper

> ## About the name
>
> **Sloboda** (Slavic) is the *settlement outside the fortress walls* — historically
> the foreigners'/outsiders' quarter, the district that grew up beyond the ramparts
> where those who did not belong to the sealed keep lived and traded. That is exactly
> this tier: the **non-attestable** quarter where **data leaves the sealed base**.
> It joins the suite's toponymy: **Postern** = the fortress's own postern gate,
> **Porog** = the threshold, **NoporIS** = the crossing, and **Sloboda** = the
> settlement beyond the wall.
>
> **Sloboda** — proposed product name, pending formal trademark clearance; built on
> Waydroid.

> ## ⚠ HONESTY HEADER — read before trusting anything in this directory
>
> This is the **NON-ATTESTABLE escape-hatch tier** of Postern. It manages a
> **Waydroid** container: a full Google/AOSP Android userland running in LXC on
> the host kernel.
>
> - **Entering Android = data leaves the sealed base.** The container is a large,
>   opaque trust surface sitting next to your post-quantum wallet. Keep secrets
>   **out** of Android apps.
> - **Play Integrity STRONG will fail.** Banking apps, Google Wallet/Pay, and DRM
>   video (Widevine L1) detect the environment and **refuse to run**. This is by
>   design — an uncertified container with no hardware TEE keymaster and (on most
>   devices) an unlocked bootloader **cannot** reach STRONG. Not a bug we can fix.
> - **NOT covered by the Postern Seal.** The Android image is mutable state pulled
>   at `waydroid init`, so `os_roothash` says nothing about what runs inside
>   Waydroid. Do not treat an Android app here as attested.
> - **UNTESTED.** There is no Waydroid in the build sandbox. **Nothing here has
>   ever booted an Android container.** Every `waydroid …` call is a scaffold,
>   validated only by `shellcheck` + a mock trace. Every on-device claim is an
>   unknown until proven on real aarch64 hardware.
> - **Default-safe.** This wrapper **never opens a privacy bridge.** It only
>   *reads* a toggle state file owned by the consent-gate component and treats
>   anything but a literal `enabled` as **off**.
> - **The coin is worthless. Personal use is free. This is not legal advice.**
>
> **microG-vs-GApps is a config input** (default: the private, Google-free
> `VANILLA` base). It is **never hardcoded to Google**.

This component is the gateway wrapper only. The NixOS wiring
(`os/sloboda-compat.nix`) is owned by another developer and is **not** edited
here.

---

## Which product is this? — naming & disambiguation (read this)

There are **two different Android products** in Postern, on **two different
hosts**. Do not conflate them:

| | **This directory (`apps/sloboda`)** | **Porog** *(different product)* |
|---|---|---|
| What | **Postern for postmarketOS — community edition.** A POSIX-sh wrapper around a **Waydroid** container (full AOSP/Google userland in **LXC on a GNU/Linux host**). | The **separate** stock-Android **managed-profile container** (Porog — **not this tier**): a self-enrolled work profile with StrongBox key-attestation. |
| Host | A GNU/Linux host Postern controls (postmarketOS / desktop). | **Stock Android the user already owns** — no OS replacement, no root. |
| Tier | **NON-ATTESTABLE escape hatch.** Play Integrity STRONG fails; not covered by the Postern Seal. | **Key-attested device** (attests the *phone*, not the workspace). |
| Code here? | **Yes** — this is that wrapper. | **No** — Porog's app lives in the Kotlin/DPC tree, owned by other devs. |

- **"Porog"** (Slavic for the *threshold / soleira* — the door between two
  worlds, per the Izbushka tale) is the **PROPOSED** name for the stock-Android
  container, **pending formal trademark clearance**. "Postern" stays the suite
  brand; "Porog" is that app. This Waydroid wrapper **is not Porog** — it is the
  community-edition tier.
- **Neither product is ever "Postern OS."** Postern OS is a separate,
  measured-boot OS story. The community edition is *"Postern for postmarketOS —
  community edition,"* full stop.
- The one honest qualifier, everywhere: **"key-attested device, not a measured-boot workspace"** —
  and it applies to **Porog**, not to this non-attestable Waydroid tier, which is neither.

*(Design/reference-prototype only. UNAUDITED. No security claim.)*

---

## What this is

A small POSIX-shell CLI (no heavy runtime) plus a dependency-free web control
surface, mirroring the style of the other `apps/` UIs. It manages the Waydroid
container lifecycle and surfaces app download/launch:

- **Container lifecycle** — start the session/container on demand, wait for
  readiness, stop cleanly, and a **kill-switch** that stops everything and clears
  session runtime state.
- **Enter Android** — the full desktop (`waydroid show-full-ui`) *and* a
  single-app path (`waydroid app launch <pkg>`).
- **App-store-first** — land the user on the store (Aurora by default) and a
  **host launcher hook**: an install-watch that writes `.desktop` entries which
  call back through the wrapper's `app` subcommand.

## Files

| Path | What |
|---|---|
| `bin/sloboda` | Main POSIX-sh CLI (dispatcher for all commands). |
| `bin/paw-lib.sh` | Shared library: config load, waydroid choke-point, status/wait-ready, read-only bridge check. Sourced, never executed. |
| `bin/sloboda-installwatch` | Thin service entrypoint → `sloboda install-watch`. |
| `config/sloboda.conf.sample` | Operator config (sourced KEY=VALUE sh). Copy to `~/.config/sloboda/` or `/etc/sloboda/`. |
| `share/applications/sloboda.desktop` | Host launcher for the gateway itself. |
| `share/systemd/user/sloboda-installwatch.service` | Ready-to-install **user** unit for the launcher-sync watcher (user scope, no root). |
| `ui/index.html` | Dependency-free control surface: composes the exact commands; makes **no** network calls. |
| `test/mock-waydroid` | Test double for the `waydroid` CLI. Boots nothing. |
| `test/dry-run.sh` | Offline validation harness (trace mode + mock exec mode). |

## Commands

```
sloboda init          # provision image (waydroid init -s <TYPE>)
sloboda start         # start session/container, wait-for-ready
sloboda status        # session state + honest posture
sloboda stop          # clean shutdown
sloboda kill          # KILL-SWITCH: stop all + clear session state
sloboda show          # enter full Android UI (waydroid show-full-ui)
sloboda app <pkg>     # single-app launch
sloboda store         # app-store-first landing (Aurora default)
sloboda launchers     # write host .desktop icons for installed apps
sloboda install-watch # keep launchers in sync (PAW_WATCH_ONCE=1 for one pass)
sloboda doctor        # readiness check WITHOUT touching Waydroid
sloboda config        # print effective config
```

All commands honour `PAW_DRYRUN=1` (trace, don't exec). `PAW_WAYDROID` overrides
the binary name so the mock can stand in on `PATH`.

## Configuration

Copy `config/sloboda.conf.sample` and set the keys you want. Defaults are
the private, default-safe posture:

| Key | Default | Meaning |
|---|---|---|
| `PAW_SYSTEM_TYPE` | `VANILLA` | `VANILLA` (no Google/microG) · `FOSS` (microG image, flaky) · `GAPPS` (Google, less private). |
| `PAW_MICROG` | `0` | After a VANILLA init, note the separate community microG step. |
| `PAW_STORE_PKG` | `com.aurora.store` | App-store-first landing package. |
| `PAW_READY_TIMEOUT` | `90` | Seconds to wait for `Session: RUNNING`. |
| `PAW_DESKTOP_DIR` | `$XDG_DATA_HOME/applications` | Where host `.desktop` launchers are written. |
| `PAW_BRIDGE_STATE` | `/run/postern/consent/sloboda-bridge.state` | Consent-gate toggle. **Read-only.** Bridge is enabled only if line 1 is exactly `enabled`. |

## Running the install-watch as a service

The wrapper does not own service management, but ships a ready-to-install **user**
unit at `share/systemd/user/sloboda-installwatch.service` (user scope on purpose:
it writes the per-user launcher dir with **no root**). Install and enable it with:

The shipped unit looks like:

```ini
[Unit]
Description=Sloboda — host launcher sync (non-attestable tier)
[Service]
ExecStart=%h/.local/bin/sloboda-installwatch
Restart=on-failure
[Install]
WantedBy=default.target
```

```
install -Dm644 share/systemd/user/sloboda-installwatch.service \
    ~/.config/systemd/user/sloboda-installwatch.service
systemctl --user enable --now sloboda-installwatch
```

Adjust `ExecStart=` to the installed path of the `sloboda-installwatch`
entrypoint. It is a harmless no-op while the container is down (`waydroid app
list` empty → nothing written).

### Launcher write-perm: per-user vs system-wide

- **Per-user (default):** `PAW_DESKTOP_DIR=~/.local/share/applications` — user-
  writable, the safe default, needs no privilege. After writing or pruning
  launchers the wrapper best-effort runs `update-desktop-database` (guarded by
  `command -v`) so the shell app grid re-indexes without a session restart.
- **System-wide (`/usr/share/applications`):** needs root/packager; point
  `PAW_DESKTOP_DIR` there only from the packaged/rooted context (the NixOS
  module's job — not this wrapper's). The wrapper `mkdir -p`s and fails honestly
  (`cannot create $PAW_DESKTOP_DIR`) if it lacks write permission.

---

## Validation (what was actually run here)

Run from this directory:

```
shellcheck -x -s sh bin/sloboda bin/paw-lib.sh \
  bin/sloboda-installwatch test/mock-waydroid test/dry-run.sh \
  config/sloboda.conf.sample     # → exit 0, clean
sh -n <each shell file>                  # → OK
node --check <inline UI script>          # → JS SYNTAX OK
sh test/dry-run.sh                       # → passed: 25  failed: 0
```

The harness runs two modes: **(1)** `PAW_DRYRUN=1` trace with no `waydroid` on
`PATH` (shows the exact commands that *would* run), and **(2)** `PAW_DRYRUN=0`
against `test/mock-waydroid` on `PATH` — exercising status parsing,
wait-for-ready, `.desktop` generation and pruning, the best-effort
`update-desktop-database` refresh (against a faked tool on `PATH`), the
read-only bridge/consent check, refuse-to-start, stop and the end-to-end
kill-switch (driven through the S2 `sloboda-gated` writer). Neither mode boots
Android.

## Only confirmable on a real Waydroid device (UNTESTED here)

The mock proves the wrapper's control flow. It proves **nothing** about the items
below, each of which needs real aarch64 hardware with a binder-capable kernel and
a Wayland session:

1. **Kernel binder support** — `CONFIG_ANDROID_BINDER_IPC` / `_BINDERFS` present;
   `binder_linux` module loads; `/dev/binderfs` mounts. Stock PinePhone /
   Mobile-NixOS kernels typically lack these.
2. **`waydroid init` actually pulls an image** for each `PAW_SYSTEM_TYPE`, and
   whether the `FOSS` (microG) channel has images at all (upstream often 404s).
3. **microG post-init path** (`waydroid_script`) succeeds and the services behave.
4. **`waydroid session start` reaches `Session: RUNNING`** and the container comes
   up under the `waydroid-container` service (root/systemd) — the exact strings
   `waydroid status` prints on the target build.
5. **A Wayland compositor is active** so `show-full-ui` and `app launch` actually
   display (container can "run" with nothing on screen otherwise).
6. **`waydroid app list` output format** matches the `Name:` / `packageName:`
   parser on the installed Waydroid version.
7. **`waydroid app launch <pkg>`** foregrounds the app; single-app vs full-UI
   behaviour.
8. **Aurora Store** installs and launches, and its account-free delivery still
   works (shared-account rate limits shift over releases).
9. **Host `.desktop` launchers** appear in the shell's app grid and successfully
   re-enter the container when clicked; the `update-desktop-database` refresh
   makes new/pruned icons show up without a session restart;
   `/usr/share/applications` write perms.
10. **Kill-switch** — `waydroid container stop` / `systemctl stop
    waydroid-container` privileges, and that clearing the session runtime dir
    leaves the provisioned image intact and re-startable.
11. **GPU path** — hardware GL (Lima/Panfrost) vs SwiftShader fallback on the
    device panel.
12. **Play Integrity reality** — confirm STRONG fails and which specific apps
    refuse (banking / Wallet / DRM), so the honest label matches observed
    behaviour.
13. **Consent-gate integration** — that the real bridge state file path and
    format match what the consent-gate component writes.
