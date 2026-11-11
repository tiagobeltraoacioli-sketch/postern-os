#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Report the observable Postern privacy baseline of the running system.

Read-only and offline: it reads kernel and systemd state, changes nothing and
contacts nothing. A passing report describes only the listed observations; it
is not an audit and does not establish anonymity.
"""
import argparse
import configparser
import json
import os
from pathlib import Path
import subprocess
import sys

OK, WARN, FAIL, UNKNOWN = "ok", "warn", "fail", "unknown"
FORMAT = "postern-status/v1"
QUIET_UNITS = (
    "sshd.service", "sshd.socket", "avahi-daemon.service", "avahi-daemon.socket",
    "geoclue.service", "tor.service", "gnome-remote-desktop.service",
)
UNSAFE_PARAMETERS = frozenset((
    "mitigations=off", "nopti", "pti=off", "nospectre_v1", "nospectre_v2",
    "spectre_v2=off", "spec_store_bypass_disable=off", "l1tf=off", "mds=off",
    "tsx_async_abort=off", "srbds=off", "retbleed=off",
    "spec_rstack_overflow=off", "gather_data_sampling=off",
    "reg_file_data_sampling=off", "spectre_bhi=off",
))
SYSCTL_MINIMUMS = (
    ("kernel/kptr_restrict", 2), ("kernel/dmesg_restrict", 1),
    ("kernel/yama/ptrace_scope", 1), ("kernel/unprivileged_bpf_disabled", 1),
)
HARDENING_PARAMETERS = (
    "slab_nomerge", "init_on_alloc=1", "init_on_free=1", "page_alloc.shuffle=1",
    "randomize_kstack_offset=on", "vsyscall=none",
)
# (sysctl, comparison, value): "min" means at least, "max" means at most.
HARDENING_SYSCTLS = (
    # Only settings an ordinary user can read: the report must give the same
    # answer in the desktop application as with sudo. (net.core.bpf_jit_harden
    # is root-only; the booted test in os/tests/privacy.nix checks it.)
    ("kernel/kexec_load_disabled", "min", 1), ("kernel/perf_event_paranoid", "min", 2),
    ("dev/tty/ldisc_autoload", "max", 0),
    ("vm/unprivileged_userfaultfd", "max", 0), ("fs/protected_fifos", "min", 2),
    ("fs/protected_regular", "min", 2), ("kernel/sysrq", "max", 0),
)
NETWORK_MANAGER_CONFIG = "/etc/NetworkManager/NetworkManager.conf"
NETWORK_IDENTITY = (
    ("wifi.cloned-mac-address", ("random",), "Wi-Fi hardware address is not randomized"),
    ("ethernet.cloned-mac-address", ("random",), "wired hardware address is not randomized"),
    ("ipv4.dhcp-send-hostname-v2", ("0",), "the host name is sent in DHCPv4 requests"),
    ("ipv6.dhcp-send-hostname-v2", ("0",), "the host name is sent in DHCPv6 requests"),
)


def systemctl_state(unit):
    """Return systemd's ActiveState word, or None when it cannot be queried."""
    try:
        done = subprocess.run(["systemctl", "is-active", unit], capture_output=True,
                              text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout.strip() or None


class Probe:
    """File and unit access rooted at a directory, so tests can use a fixture."""

    def __init__(self, root="/", unit_state=systemctl_state):
        self.root = Path(root)
        self.unit_state = unit_state

    def path(self, name):
        return self.root / name.lstrip("/")

    def text(self, name):
        try:
            return self.path(name).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

    def word(self, name):
        value = self.text(name)
        return None if value is None else value.strip()


def result(key, title, state, detail):
    return {"id": key, "title": title, "state": state, "detail": detail}


def check_release(probe):
    title = "Release"
    raw = probe.text("/etc/postern/release.json")
    if raw is None:
        return result("release", title, UNKNOWN, "not a Postern OS image (no /etc/postern/release.json)")
    try:
        record = json.loads(raw)
        detail = f"{record['name']} {record['version']} ({record.get('type', 'unspecified')})"
    except (ValueError, KeyError, TypeError):
        return result("release", title, FAIL, "release.json is unreadable")
    return result("release", title, OK, detail)


def listeners(probe):
    """Listening TCP sockets as (address, port); None if /proc is unavailable."""
    found = set()
    seen = False
    for name, width in (("/proc/net/tcp", 8), ("/proc/net/tcp6", 32)):
        raw = probe.text(name)
        if raw is None:
            continue
        seen = True
        for line in raw.splitlines()[1:]:
            fields = line.split()
            if len(fields) < 4 or fields[3] != "0A":
                continue
            address, _, port = fields[1].rpartition(":")
            if len(address) != width:
                continue
            try:
                found.add((address.upper(), int(port, 16)))
            except ValueError:
                continue
    return sorted(found) if seen else None


def is_loopback(address):
    if len(address) == 8:
        # /proc prints the IPv4 address as a host-endian 32-bit word.
        return address.endswith("7F")
    return address in ("0" * 24 + "01000000", "0" * 16 + "FFFF0000" + "0100007F")


def check_listeners(probe):
    title = "Network listeners"
    sockets = listeners(probe)
    if sockets is None:
        return result("listeners", title, UNKNOWN, "/proc/net/tcp is unavailable")
    exposed = sorted({port for address, port in sockets if not is_loopback(address)})
    if 22 in exposed:
        return result("listeners", title, FAIL, "a service listens on TCP port 22")
    if exposed:
        ports = ", ".join(str(port) for port in exposed)
        return result("listeners", title, WARN,
                      f"non-loopback TCP listeners on port(s) {ports}; the firewall decides reachability")
    return result("listeners", title, OK, "no non-loopback TCP listener")


def check_firewall(probe):
    title = "Inbound firewall"
    state = probe.unit_state("firewall.service")
    if state is None:
        return result("firewall", title, UNKNOWN, "systemd state is unavailable")
    if state == "active":
        return result("firewall", title, OK, "firewall.service is active")
    return result("firewall", title, FAIL, f"firewall.service is {state}")


def check_quiet_units(probe):
    title = "Remote login and discovery"
    states = {unit: probe.unit_state(unit) for unit in QUIET_UNITS}
    if all(state is None for state in states.values()):
        return result("services", title, UNKNOWN, "systemd state is unavailable")
    running = sorted(unit for unit, state in states.items() if state in ("active", "activating", "reloading"))
    if running:
        return result("services", title, FAIL, "active: " + ", ".join(running))
    return result("services", title, OK, "SSH, Avahi, GeoClue, Tor daemon and remote desktop are not running")


def check_apparmor(probe):
    title = "AppArmor"
    enabled = probe.word("/sys/module/apparmor/parameters/enabled")
    modules = (probe.word("/sys/kernel/security/lsm") or "").split(",")
    if enabled is None:
        return result("apparmor", title, FAIL, "the AppArmor module is not loaded")
    if enabled != "Y" or "apparmor" not in modules:
        return result("apparmor", title, FAIL, "AppArmor is not an active security module")
    return result("apparmor", title, OK,
                  "enabled; confinement applies only to applications with a loaded profile")


def check_mitigations(probe):
    title = "CPU mitigations"
    cmdline = probe.word("/proc/cmdline")
    if cmdline is None:
        return result("mitigations", title, UNKNOWN, "/proc/cmdline is unavailable")
    disabled = sorted(UNSAFE_PARAMETERS.intersection(cmdline.split()))
    if disabled:
        return result("mitigations", title, FAIL, "kernel started with " + " ".join(disabled))
    vulnerable = []
    directory = probe.path("/sys/devices/system/cpu/vulnerabilities")
    try:
        entries = sorted(directory.iterdir())
    except OSError:
        entries = []
    for entry in entries:
        try:
            if entry.read_text(encoding="utf-8", errors="replace").startswith("Vulnerable"):
                vulnerable.append(entry.name)
        except OSError:
            continue
    if vulnerable:
        return result("mitigations", title, WARN,
                      "kernel reports no mitigation for: " + ", ".join(vulnerable))
    return result("mitigations", title, OK, "no mitigation opt-out on the kernel command line")


def check_core_dumps(probe):
    title = "Core dumps"
    pattern = probe.word("/proc/sys/kernel/core_pattern")
    dumpable = probe.word("/proc/sys/fs/suid_dumpable")
    if pattern is None or dumpable is None:
        return result("core-dumps", title, UNKNOWN, "kernel settings are unavailable")
    if not (pattern.startswith("|") and pattern.split()[0].endswith("/false")):
        return result("core-dumps", title, FAIL, f"core_pattern is {pattern!r}")
    if dumpable != "0":
        return result("core-dumps", title, FAIL, f"fs.suid_dumpable is {dumpable}")
    return result("core-dumps", title, OK, "discarded by the kernel; setuid programs are not dumpable")


def check_sysctls(probe):
    title = "Kernel exposure limits"
    low = []
    missing = []
    for name, minimum in SYSCTL_MINIMUMS:
        value = probe.word("/proc/sys/" + name)
        label = name.replace("/", ".")
        try:
            if value is None:
                missing.append(label)
            elif int(value) < minimum:
                low.append(f"{label}={value}")
        except ValueError:
            low.append(f"{label}={value}")
    if low:
        return result("sysctl", title, FAIL, "below baseline: " + ", ".join(low))
    if missing:
        return result("sysctl", title, UNKNOWN, "unavailable: " + ", ".join(missing))
    return result("sysctl", title, OK, "kernel pointers, dmesg, ptrace and unprivileged BPF are restricted")


def check_hardening(probe):
    """Extra kernel hardening. Its absence is a warning: the baseline above
    still holds, but memory-safety bugs are easier to exploit without it."""
    title = "Kernel hardening"
    cmdline = probe.word("/proc/cmdline")
    if cmdline is None:
        return result("hardening", title, UNKNOWN, "/proc/cmdline is unavailable")
    words = cmdline.split()
    absent = [parameter for parameter in HARDENING_PARAMETERS if parameter not in words]
    unread = []
    for name, comparison, wanted in HARDENING_SYSCTLS:
        value = probe.word("/proc/sys/" + name)
        label = name.replace("/", ".")
        try:
            number = None if value is None else int(value)
        except ValueError:
            number = None
        if number is None:
            unread.append(label)
        elif (comparison == "min" and number < wanted) or (comparison == "max" and number > wanted):
            absent.append(f"{label}={number}")
    if absent:
        return result("hardening", title, WARN, "not applied: " + ", ".join(absent))
    if unread:
        return result("hardening", title, UNKNOWN, "unavailable: " + ", ".join(unread))
    return result("hardening", title, OK,
                  "freed memory is wiped, allocator and stack hardening are on, kexec and SysRq are off")


def check_network_identity(probe):
    """What NetworkManager is configured to reveal to a local network. It reads
    the configuration file; it does not observe packets or other managers."""
    title = "Network identity"
    raw = probe.text(NETWORK_MANAGER_CONFIG)
    if raw is None:
        return result("network-identity", title, UNKNOWN,
                      "NetworkManager is not configured on this system")
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    try:
        parser.read_string(raw)
    except configparser.Error:
        return result("network-identity", title, UNKNOWN, "NetworkManager.conf is unreadable")
    exposed = [message for key, accepted, message in NETWORK_IDENTITY
               if parser.get("connection", key, fallback="").strip().lower() not in accepted]
    if exposed:
        return result("network-identity", title, WARN, "; ".join(exposed))
    return result("network-identity", title, OK,
                  "random hardware addresses; the host name is not sent in DHCP requests")


def check_swap(probe):
    title = "Swap"
    raw = probe.text("/proc/swaps")
    if raw is None:
        return result("swap", title, UNKNOWN, "/proc/swaps is unavailable")
    devices = [line.split()[0] for line in raw.splitlines()[1:] if line.split()]
    on_disk = [device for device in devices
               if not (device.startswith("/dev/zram") and device[9:].isdigit())]
    if on_disk:
        return result("swap", title, FAIL, "swap on storage: " + ", ".join(on_disk))
    if devices:
        return result("swap", title, OK, "compressed memory only (" + ", ".join(devices) + ")")
    return result("swap", title, OK, "no swap device")


def check_tmp(probe):
    title = "Temporary storage"
    raw = probe.text("/proc/mounts")
    if raw is None:
        return result("tmp", title, UNKNOWN, "/proc/mounts is unavailable")
    kind = None
    for line in raw.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[1] == "/tmp":
            kind = fields[2]
    if kind == "tmpfs":
        return result("tmp", title, OK, "/tmp is memory-backed and cleared at shutdown")
    return result("tmp", title, FAIL, "/tmp is not a tmpfs" if kind is None else f"/tmp is {kind}")


def check_journal(probe):
    title = "System journal"
    directory = probe.path("/var/log/journal")
    try:
        persistent = any(entry.is_file() for entry in directory.rglob("*"))
    except OSError:
        persistent = False
    if persistent:
        return result("journal", title, FAIL, "journal files are stored under /var/log/journal")
    if not probe.path("/run/log/journal").is_dir():
        return result("journal", title, UNKNOWN, "no volatile journal directory found")
    return result("journal", title, OK, "kept in memory only")


def check_accounts(probe):
    title = "Password login"
    raw = probe.text("/etc/shadow")
    if raw is None:
        return result("accounts", title, UNKNOWN, "needs root to read /etc/shadow (run with sudo)")
    usable = []
    for line in raw.splitlines():
        fields = line.split(":")
        if len(fields) < 2:
            continue
        if fields[1] and not fields[1].startswith(("!", "*")):
            usable.append(fields[0])
    if usable:
        return result("accounts", title, WARN, "accounts with a password: " + ", ".join(sorted(usable)))
    return result("accounts", title, OK, "every account password is locked; access is the local console")


CHECKS = (
    check_release, check_firewall, check_listeners, check_quiet_units,
    check_apparmor, check_mitigations, check_core_dumps, check_sysctls,
    check_hardening, check_network_identity,
    check_swap, check_tmp, check_journal, check_accounts,
)


def collect(probe):
    checks = [check(probe) for check in CHECKS]
    counts = {state: sum(1 for item in checks if item["state"] == state)
              for state in (OK, WARN, FAIL, UNKNOWN)}
    return {"format": FORMAT, "checks": checks, "summary": counts,
            "scope": "Observed local settings only; not an audit and not an anonymity guarantee."}


def render(report, color):
    marks = {OK: ("OK", "32"), WARN: ("WARN", "33"), FAIL: ("FAIL", "31"), UNKNOWN: ("?", "36")}
    width = max(len(item["title"]) for item in report["checks"])
    lines = ["Postern privacy baseline", ""]
    for item in report["checks"]:
        word, code = marks[item["state"]]
        tag = f"[{word:^4}]"
        if color:
            tag = f"\x1b[{code}m{tag}\x1b[0m"
        lines.append(f"{tag} {item['title']:<{width}}  {item['detail']}")
    summary = report["summary"]
    lines += ["", f"{summary[OK]} ok, {summary[WARN]} warning(s), {summary[FAIL]} failed, "
                  f"{summary[UNKNOWN]} not determined", report["scope"],
              "Details: /etc/postern/privacy.txt"]
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    parser.add_argument("--root", default="/", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    report = collect(Probe(args.root))
    if args.json:
        json.dump(report, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
        sys.stdout.write(render(report, color))
    return 1 if report["summary"][FAIL] else 0


if __name__ == "__main__":
    raise SystemExit(main())
