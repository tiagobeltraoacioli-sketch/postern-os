# SPDX-License-Identifier: MIT OR Apache-2.0
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import postern_status as status  # noqa: E402

TCP_HEADER = "  sl  local_address rem_address   st tx_queue rx_queue\n"
BASELINE = {
    "etc/postern/release.json": json.dumps(
        {"name": "Postern OS", "version": "0.3.1-dev", "type": "live-development"}),
    "etc/shadow": "root:!:1::::::\nnixos:!:1::::::\nnobody:*:1::::::\n",
    "proc/net/tcp": TCP_HEADER + "   0: 0100007F:0277 00000000:0000 0A 00000000:00000000\n",
    "proc/net/tcp6": TCP_HEADER,
    "proc/cmdline": "BOOT_IMAGE=/boot/bzImage mitigations=auto console=tty0\n",
    "proc/sys/kernel/core_pattern": "|/nix/store/abc-coreutils/bin/false\n",
    "proc/sys/fs/suid_dumpable": "0\n",
    "proc/sys/kernel/kptr_restrict": "2\n",
    "proc/sys/kernel/dmesg_restrict": "1\n",
    "proc/sys/kernel/yama/ptrace_scope": "1\n",
    "proc/sys/kernel/unprivileged_bpf_disabled": "2\n",
    "proc/swaps": "Filename\tType\tSize\tUsed\tPriority\n/dev/zram0 partition 1024 0 5\n",
    "proc/mounts": "tmpfs /tmp tmpfs rw,nosuid,nodev 0 0\n",
    "sys/module/apparmor/parameters/enabled": "Y\n",
    "sys/kernel/security/lsm": "capability,landlock,yama,apparmor\n",
    "sys/devices/system/cpu/vulnerabilities/meltdown": "Mitigation: PTI\n",
    "run/log/journal/.keep": "",
}


def units(**overrides):
    def state(unit):
        if unit in overrides:
            return overrides[unit]
        return "active" if unit == "firewall.service" else "inactive"
    return state


class StatusTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for name, content in BASELINE.items():
            self.write(name, content)

    def write(self, name, content):
        target = self.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)

    def report(self, **overrides):
        return status.collect(status.Probe(self.root, units(**overrides)))

    def state(self, key, **overrides):
        checks = {item["id"]: item for item in self.report(**overrides)["checks"]}
        return checks[key]["state"]

    def test_baseline_is_entirely_ok(self):
        report = self.report()
        self.assertEqual(report["summary"],
                         {"ok": len(status.CHECKS), "warn": 0, "fail": 0, "unknown": 0})
        self.assertEqual(report["format"], "postern-status/v1")

    def test_ssh_listener_fails(self):
        self.write("proc/net/tcp", TCP_HEADER
                   + "   0: 00000000:0016 00000000:0000 0A 00000000:00000000\n")
        self.assertEqual(self.state("listeners"), "fail")

    def test_other_exposed_listener_warns_and_connections_are_ignored(self):
        self.write("proc/net/tcp", TCP_HEADER
                   + "   0: 00000000:1F90 00000000:0000 0A 00000000:00000000\n"
                   + "   1: 0A00020F:0016 0A000202:D431 01 00000000:00000000\n")
        report = self.report()
        item = [entry for entry in report["checks"] if entry["id"] == "listeners"][0]
        self.assertEqual(item["state"], "warn")
        self.assertIn("8080", item["detail"])
        self.assertNotIn("22", item["detail"])

    def test_ipv6_loopback_listener_is_local(self):
        self.write("proc/net/tcp6", TCP_HEADER
                   + "   0: 00000000000000000000000001000000:0277 "
                   + "00000000000000000000000000000000:0000 0A 00000000:00000000\n")
        self.assertEqual(self.state("listeners"), "ok")

    def test_ipv6_wildcard_ssh_listener_fails(self):
        self.write("proc/net/tcp6", TCP_HEADER
                   + "   0: 00000000000000000000000000000000:0016 "
                   + "00000000000000000000000000000000:0000 0A 00000000:00000000\n")
        self.assertEqual(self.state("listeners"), "fail")

    def test_inactive_firewall_fails(self):
        self.assertEqual(self.state("firewall", **{"firewall.service": "inactive"}), "fail")

    def test_running_ssh_unit_fails(self):
        self.assertEqual(self.state("services", **{"sshd.service": "active"}), "fail")

    def test_systemd_unavailable_is_unknown_not_ok(self):
        report = status.collect(status.Probe(self.root, lambda unit: None))
        checks = {item["id"]: item["state"] for item in report["checks"]}
        self.assertEqual(checks["firewall"], "unknown")
        self.assertEqual(checks["services"], "unknown")

    def test_apparmor_missing_from_lsm_fails(self):
        self.write("sys/kernel/security/lsm", "capability,yama\n")
        self.assertEqual(self.state("apparmor"), "fail")

    def test_mitigation_opt_out_fails_and_vulnerable_cpu_warns(self):
        self.write("sys/devices/system/cpu/vulnerabilities/mds", "Vulnerable; SMT disabled\n")
        self.assertEqual(self.state("mitigations"), "warn")
        self.write("proc/cmdline", "console=tty0 mitigations=off\n")
        self.assertEqual(self.state("mitigations"), "fail")

    def test_plain_core_pattern_fails(self):
        self.write("proc/sys/kernel/core_pattern", "core\n")
        self.assertEqual(self.state("core-dumps"), "fail")

    def test_low_sysctl_fails(self):
        self.write("proc/sys/kernel/kptr_restrict", "0\n")
        self.assertEqual(self.state("sysctl"), "fail")

    def test_disk_swap_fails_and_no_swap_is_ok(self):
        self.write("proc/swaps", "Filename Type Size Used Priority\n/dev/sda2 partition 1 0 -2\n")
        self.assertEqual(self.state("swap"), "fail")
        self.write("proc/swaps", "Filename Type Size Used Priority\n")
        self.assertEqual(self.state("swap"), "ok")

    def test_disk_tmp_fails(self):
        self.write("proc/mounts", "/dev/sda1 /tmp ext4 rw 0 0\n")
        self.assertEqual(self.state("tmp"), "fail")

    def test_persistent_journal_fails(self):
        self.write("var/log/journal/machine/system.journal", "x")
        self.assertEqual(self.state("journal"), "fail")

    def test_password_account_warns_and_unreadable_shadow_is_unknown(self):
        self.write("etc/shadow", "root:!:1::::::\nalice:$y$j9T$abc:1::::::\n")
        self.assertEqual(self.state("accounts"), "warn")
        (self.root / "etc/shadow").unlink()
        self.assertEqual(self.state("accounts"), "unknown")

    def test_missing_release_is_unknown(self):
        (self.root / "etc/postern/release.json").unlink()
        self.assertEqual(self.state("release"), "unknown")

    def test_exit_code_and_json_output(self):
        original = status.systemctl_state
        status.systemctl_state = units()
        self.addCleanup(setattr, status, "systemctl_state", original)
        # Probe binds the default at definition time; patch the class default too.
        defaults = status.Probe.__init__.__defaults__
        status.Probe.__init__.__defaults__ = ("/", status.systemctl_state)
        self.addCleanup(setattr, status.Probe.__init__, "__defaults__", defaults)
        output = io.StringIO()
        with redirect_stdout(output):
            code = status.main(["--json", "--root", str(self.root)])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["summary"]["fail"], 0)
        self.write("proc/sys/kernel/core_pattern", "core\n")
        output = io.StringIO()
        with redirect_stdout(output):
            code = status.main(["--root", str(self.root)])
        self.assertEqual(code, 1)
        self.assertIn("[FAIL] Core dumps", output.getvalue())


if __name__ == "__main__":
    unittest.main()
