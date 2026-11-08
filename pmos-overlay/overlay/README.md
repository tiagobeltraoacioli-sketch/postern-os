# overlay/ — rootfs overlay for the Postern flavor

Rootfs files for **Postern for postmarketOS — community edition**: OpenRC
services, firewall, in-process Tor (Arti) wiring, honest tier labeling, and
branding hooks. Paths under this directory mirror where they install on the
device (`overlay/etc/motd` → `/etc/motd`, etc.).

> **Read `../HONESTY.md` first.** This is the **lower-trust, non-attestable
> tier**. Always "Postern for postmarketOS", never "Postern OS". **Not covered
> by the Postern Seal.**

## UNBOOTED — status honesty

**Nothing here has been booted, started, or loaded on a device.** Authoring
was on macOS; there is no `nft`, no `openrc`, no `arti` here. Everything below
is validated only as far as static checks allow (`sh -n`, TOML parse). Every
"works" claim waits for a real pmOS boot — see the checklist at the bottom.

## What installs where

| Overlay path | Installs to | Purpose |
|---|---|---|
| `etc/init.d/postern-tor` | `/etc/init.d/` | Arti (Rust Tor) SOCKS proxy, loopback only |
| `etc/init.d/postern-node` | `/etc/init.d/` | Postern node daemon, unprivileged, Tor-routed |
| `etc/init.d/postern-firewall` | `/etc/init.d/` | loads the nftables default-deny ruleset |
| `etc/conf.d/postern-tor` | `/etc/conf.d/` | tunables for the Arti service |
| `etc/conf.d/postern-node` | `/etc/conf.d/` | tunables for the node service |
| `etc/postern/arti.toml` | `/etc/postern/` | Arti config (SOCKS 9150, 0700 state/cache) |
| `etc/postern/node.toml` | `/etc/postern/` | node config (require Tor proxy, software keystore) |
| `etc/postern/branding.conf` | `/etc/postern/` | branding hooks + verbatim tier label |
| `etc/nftables.d/postern.nft` | `/etc/nftables.d/` | default-deny inbound firewall ruleset |
| `etc/motd` | `/etc/motd` | login MOTD carrying the honest tier label |
| `usr/share/postern/first-run/about-tier.txt` | same path | "about this tier" first-run screen text |
| `usr/share/postern/branding/NOTICE` | same path | branding-asset placeholder + honesty rule |
| `usr/libexec/postern/postern-common.sh` | same path | shared helper: dedicated user + 0700 dirs |

These files are meant to be shipped by the (other devs') `postern` /
`postern-apps` packages, or a future `postern-flavor` package. This directory
does not touch any APKBUILD.

## Design in one paragraph

Least privilege: node, wallet, and Arti all run as the dedicated system user
`postern` (created idempotently in each service's `start_pre` via
`postern-common.sh`), with state under `/var/lib/postern` at `0700`. Privacy:
Arti provides Tor on `127.0.0.1:9150`; the node is configured to require that
proxy (`require_proxy = true`) and never fall back to a direct connection
silently. Firewall: default-deny inbound (nftables `inet postern` table),
loopback and established replies only. Honesty: the tier label is visible at
every login (MOTD) and in the about screen, verbatim, and no APKBUILD or
`os-release` is altered to imply "Postern OS".

## Validate without booting

```sh
# POSIX-sh syntax of every init script and the shared helper:
for f in overlay/etc/init.d/* overlay/usr/libexec/postern/postern-common.sh; do
  sh -n "$f" && echo "ok: $f"
done

# TOML parse (needs python3):
python3 - <<'PY'
import tomllib
for p in ("overlay/etc/postern/arti.toml", "overlay/etc/postern/node.toml"):
    tomllib.load(open(p, "rb")); print("ok:", p)
PY

# On a device only (nft is not on the authoring host):
nft -c -f /etc/nftables.d/postern.nft   # dry-run check the ruleset
```

## Only confirmable on a real pmOS device boot

- `rc-service postern-firewall start` actually loads the ruleset and `nft -c`
  passes against the device's nftables version.
- `rc-service postern-tor start` launches `arti proxy`, Arti accepts
  `arti.toml`, and a SOCKS listener really comes up on `127.0.0.1:9150`.
- `arti`'s `storage.permissions` accepts the `0700` service-owned dirs (Arti
  is strict about dir perms; may need tuning per its version).
- `command_user="postern:postern"` + `supervise-daemon` background the daemon
  correctly (Arti stays foreground as required).
- The dedicated `postern` user is created cleanly by busybox
  `adduser`/`addgroup` with these flags on the actual image.
- MOTD renders at TTY/SSH login and the about screen is reachable in Phosh.
- The node service is a real service (its binary is **not** built by the
  current wallet-only APKBUILD — see `etc/init.d/postern-node`).
