# postern-status

Read-only report of the privacy baseline that can be observed on the running
system. It contacts nothing, changes nothing and installs no background service.

```sh
postern-status          # table for a terminal
postern-status --json   # the same observations as `postern-status/v1` JSON
sudo postern-status     # also reads /etc/shadow for the password-login check
```

| Check | Observation |
| --- | --- |
| Release | `/etc/postern/release.json` |
| Inbound firewall | `firewall.service` is active |
| Network listeners | listening TCP sockets in `/proc/net/tcp` and `/proc/net/tcp6` |
| Remote login and discovery | SSH, Avahi, GeoClue, Tor daemon and GNOME remote desktop units |
| AppArmor | module enabled and listed as an active security module |
| CPU mitigations | no opt-out on the kernel command line; kernel-reported vulnerabilities |
| Core dumps | `kernel.core_pattern` discards dumps; `fs.suid_dumpable` is 0 |
| Kernel exposure limits | `kptr_restrict`, `dmesg_restrict`, `ptrace_scope`, unprivileged BPF |
| Swap | only compressed memory (zram), never a storage device |
| Temporary storage | `/tmp` is a tmpfs |
| System journal | volatile only |
| Password login | every account password locked (needs root) |

States are `ok`, `warn`, `fail` and `unknown`. A check that cannot read its
source reports `unknown`; it never reports `ok` by default. The exit status is
1 when any check fails and 0 otherwise.

## Limits

The report covers the listed local settings at the moment it runs. It does not
inspect firewall rules, UDP listeners, application telemetry, traffic, hardware
or firmware, and it is neither an audit nor an anonymity guarantee. An active
firewall unit is not proof that a specific port is filtered; the booted privacy
test in `os/tests/privacy.nix` exercises real inbound traffic.

## Tests

```sh
python3 -m unittest discover -s tools/postern-status/tests -v
```
