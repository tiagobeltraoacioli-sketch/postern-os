# SPDX-License-Identifier: MIT OR Apache-2.0
# A real boot test, including traffic from a separate network namespace.
{ pkgs, parallelData ? null, posternStatus, posternVault }:
pkgs.testers.runNixOSTest {
  name = "postern-privacy";
  requiredFeatures.kvm = false;
  # Use the serial test backdoor; the tested system must have no SSH daemon.
  sshBackdoor.enable = false;

  nodes.machine = { ... }: {
    imports = [ ../profiles/privacy.nix ../profiles/hardening.nix ];
    virtualisation = {
      cores = 2;
      memorySize = 2048;
      qemu.forceAccel = false;
    };
    system.stateVersion = "26.05";
    environment.systemPackages = [ pkgs.curl pkgs.iproute2 pkgs.python3 posternStatus posternVault ];
    users.users.alice = {
      isNormalUser = true;
      shell = pkgs.bashInteractive;
    };

    # Generate and exercise NetworkManager's privacy settings without taking
    # over the test driver's interface or the synthetic ingress-test link.
    networking.networkmanager = {
      enable = true;
      unmanaged = [ "interface-name:eth*" "interface-name:privacy-*" ];
    };
    networking.useDHCP = false;

    # Intentionally listen on a closed port, to test actual filtering instead
    # of mistaking an absent service for an effective firewall.
    systemd.services.privacy-test-http = {
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        ExecStart = "${pkgs.python3}/bin/python -m http.server 8080 --bind 0.0.0.0 --directory /etc/postern";
        DynamicUser = true;
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
      };
    };
  };

  testScript = ''
    import shlex

    start_all()
    machine.wait_for_unit("multi-user.target", timeout=600)
    machine.wait_for_unit("firewall.service")
    machine.wait_for_unit("apparmor.service")
    machine.wait_for_unit("NetworkManager.service")
    machine.wait_for_unit("privacy-test-http.service")
    machine.wait_until_succeeds("curl --noproxy '*' -fsS http://127.0.0.1:8080/privacy.txt")

    with subtest("no remote login or discovery services"):
        for unit in ["sshd.service", "sshd.socket", "avahi-daemon.service", "avahi-daemon.socket", "geoclue.service", "tor.service"]:
            machine.fail(f"systemctl is-active --quiet {unit}")
        for port in [22, 5353, 5355]:
            assert machine.succeed(f"ss -H -lntu 'sport = :{port}'").strip() == ""
        machine.succeed("test -r /etc/postern/privacy.txt")
        machine.succeed("NetworkManager --print-config > /run/nm-effective.conf")
        machine.succeed("${pkgs.python3}/bin/python -c " + shlex.quote(
            "import configparser; c=configparser.ConfigParser(interpolation=None); "
            "c.read('/run/nm-effective.conf'); "
            "assert not c.getboolean('connectivity','enabled'); "
            "assert c.get('connectivity','uri') == str(); "
            "assert c.getint('connection','connection.llmnr') == 0; "
            "assert c.getint('connection','connection.mdns') == 0; "
            "assert c.get('connection','wifi.cloned-mac-address') == 'random'; "
            "assert c.get('connection','ethernet.cloned-mac-address') == 'random'; "
            "assert c.getint('connection','ipv4.dhcp-send-hostname-v2') == 0; "
            "assert c.getint('connection','ipv6.dhcp-send-hostname-v2') == 0"
        ))

    with subtest("status report agrees with the booted system"):
        import json
        report = json.loads(machine.succeed("postern-status --json"))
        states = {item["id"]: item["state"] for item in report["checks"]}
        assert report["summary"]["fail"] == 0, report
        for check in ["firewall", "services", "apparmor", "core-dumps", "sysctl", "hardening",
                      "network-identity", "tmp", "journal"]:
            assert states[check] == "ok", (check, report)
        # The deliberately exposed test listener is reported, not hidden.
        assert states["listeners"] == "warn", report
        # A stopped firewall must turn the report into a failure.
        machine.succeed("systemctl stop firewall.service")
        try:
            machine.fail("postern-status")
        finally:
            machine.succeed("systemctl start firewall.service")
        machine.succeed("postern-status")

    with subtest("inbound firewall blocks a listening service"):
        machine.succeed("ip netns add privacy-peer")
        machine.succeed("ip link add privacy-host type veth peer name privacy-peer")
        machine.succeed("ip link set privacy-peer netns privacy-peer")
        machine.succeed("ip address add 192.0.2.1/24 dev privacy-host")
        machine.succeed("ip link set privacy-host up")
        machine.succeed("ip netns exec privacy-peer ip address add 192.0.2.2/24 dev privacy-peer")
        machine.succeed("ip netns exec privacy-peer ip link set privacy-peer up")
        machine.succeed("ip netns exec privacy-peer ip link set lo up")
        probe = "ip netns exec privacy-peer curl --noproxy '*' -fsS --connect-timeout 3 --max-time 5 http://192.0.2.1:8080/privacy.txt"
        machine.fail(probe)
        # A positive control proves the same route and listener actually work.
        machine.succeed("systemctl stop firewall.service")
        try:
            machine.succeed(probe)
        finally:
            machine.succeed("systemctl start firewall.service")
        machine.fail(probe)
        machine.succeed("ip netns del privacy-peer")

    with subtest("kernel hardening is in effect"):
        cmdline = machine.succeed("cat /proc/cmdline").split()
        for parameter in ["init_on_alloc=1", "init_on_free=1", "slab_nomerge", "page_alloc.shuffle=1",
                          "randomize_kstack_offset=on", "vsyscall=none", "debugfs=off"]:
            assert parameter in cmdline, (parameter, cmdline)
        for name, wanted in [("kernel.kexec_load_disabled", "1"), ("kernel.sysrq", "0"),
                             ("net.core.bpf_jit_harden", "2"), ("dev.tty.ldisc_autoload", "0"),
                             ("vm.unprivileged_userfaultfd", "0"), ("fs.protected_fifos", "2"),
                             ("fs.protected_regular", "2"),
                             ("net.ipv4.conf.all.accept_redirects", "0"),
                             ("net.ipv4.conf.all.accept_source_route", "0")]:
            assert machine.succeed(f"sysctl -n {name}").strip() == wanted, name
        assert int(machine.succeed("sysctl -n kernel.perf_event_paranoid").strip()) >= 2
        # An unused protocol module can be neither autoloaded nor loaded by hand.
        machine.fail("modprobe sctp")
        machine.fail("grep -qw sctp /proc/modules")
        machine.fail("mountpoint -q /sys/kernel/debug && test -n \"$(ls -A /sys/kernel/debug)\"")

    with subtest("encrypted vault keeps its contents unreadable while closed"):
        secret = "printf 'correct horse battery\\n'"
        machine.succeed(f"{secret} | postern-vault create /root/notes.vault 64M")
        assert machine.succeed("stat -c %a /root/notes.vault").strip() == "600"
        machine.fail(f"{secret} | postern-vault create /root/notes.vault 64M")
        machine.succeed(f"{secret} | postern-vault open /root/notes.vault")
        options = machine.succeed("findmnt -n -o OPTIONS /run/postern-vault/notes").strip().split(",")
        assert "nosuid" in options and "nodev" in options, options
        machine.succeed("echo postern-secret-marker > /run/postern-vault/notes/note.txt")
        assert "notes" in machine.succeed("postern-vault list")
        machine.succeed("postern-vault close notes")
        machine.fail("test -e /run/postern-vault/notes/note.txt")
        machine.fail("test -e /dev/mapper/postern-vault-notes")
        machine.fail("grep -a -q postern-secret-marker /root/notes.vault")
        machine.fail("printf 'a wrong passphrase\\n' | postern-vault open /root/notes.vault")
        machine.fail("test -e /dev/mapper/postern-vault-notes")
        machine.succeed(f"{secret} | postern-vault open /root/notes.vault --read-only")
        machine.succeed("grep -q postern-secret-marker /run/postern-vault/notes/note.txt")
        machine.fail("touch /run/postern-vault/notes/new-file")
        machine.succeed("postern-vault close --all")
        assert "No vault is open" in machine.succeed("postern-vault list")
        # A key file instead of a passphrase.
        machine.succeed("head -c 64 /dev/urandom > /root/vault.key")
        machine.succeed("postern-vault create /root/keyed.vault 48M --key-file /root/vault.key")
        machine.succeed("postern-vault open /root/keyed.vault --key-file /root/vault.key")
        machine.succeed("postern-vault close /root/keyed.vault")
        machine.fail("postern-vault create /root/tiny.vault 8M --key-file /root/vault.key")
        machine.fail("test -e /root/tiny.vault")

    with subtest("private file permissions and no core files"):
        machine.succeed("su - alice -c 'touch private-file; mkdir private-dir'")
        assert machine.succeed("stat -c %a /home/alice/private-file").strip() == "600"
        assert machine.succeed("stat -c %a /home/alice/private-dir").strip() == "700"
        assert machine.succeed("su - alice -c 'ulimit -H -c'").strip() == "0"
        assert machine.succeed("sysctl -n fs.suid_dumpable").strip() == "0"
        assert machine.succeed("sysctl -n kernel.core_pattern").strip() == "|${pkgs.coreutils}/bin/false"
        # Crash outside a PAM session after explicitly raising the core limit:
        # the kernel sink must still prevent local core-file persistence.
        crash = "import os,resource; os.chdir('/tmp'); resource.setrlimit(resource.RLIMIT_CORE, (resource.RLIM_INFINITY, resource.RLIM_INFINITY)); os.abort()"
        crash_status, crash_output = machine.execute("${pkgs.python3}/bin/python -c " + shlex.quote(crash))
        assert crash_status == 134, (crash_status, crash_output)
        machine.succeed("test -z \"$(find /tmp -maxdepth 1 -name 'core*' -print -quit)\"")
        machine.succeed("test ! -d /var/lib/systemd/coredump || test -z \"$(find /var/lib/systemd/coredump -type f -print -quit)\"")

    with subtest("kernel mitigations and temporary storage"):
        assert machine.succeed("cat /sys/module/apparmor/parameters/enabled").strip() == "Y"
        assert "apparmor" in machine.succeed("cat /sys/kernel/security/lsm").strip().split(",")
        assert "mitigations=auto" in machine.succeed("cat /proc/cmdline").split()
        assert "mitigations=off" not in machine.succeed("cat /proc/cmdline").split()
        assert machine.succeed("sysctl -n kernel.kptr_restrict").strip() == "2"
        assert machine.succeed("sysctl -n kernel.dmesg_restrict").strip() == "1"
        assert machine.succeed("findmnt -n -o FSTYPE /tmp").strip() == "tmpfs"
        assert machine.succeed("stat -c %a /tmp").strip() == "1777"
        tmp_options = machine.succeed("findmnt -n -o OPTIONS /tmp").strip().split(",")
        assert "nosuid" in tmp_options and "nodev" in tmp_options
        machine.succeed("test -d /run/log/journal")
        machine.succeed("test ! -d /var/log/journal || test -z \"$(find /var/log/journal -type f -print -quit)\"")
        boot_id_before = machine.succeed("cat /proc/sys/kernel/random/boot_id").strip()
        assert boot_id_before
        machine.succeed("touch /tmp/postern-expiry-probe")
        # The pinned driver's start() defaults to allow_reboot=False, so
        # reboot() makes QEMU exit rather than reconnecting to a new guest.
        # shutdown() includes wait_for_shutdown(), resetting the driver state;
        # start() then reconnects new sockets while preserving the VM disk.
        machine.shutdown()
        machine.start()
        machine.wait_for_unit("multi-user.target", timeout=600)
        machine.wait_for_unit("firewall.service")
        boot_id_after = machine.succeed("cat /proc/sys/kernel/random/boot_id").strip()
        assert boot_id_after and boot_id_after != boot_id_before
        machine.succeed("test -f /home/alice/private-file")
        machine.succeed("test ! -e /tmp/postern-expiry-probe")
        machine.fail("systemctl is-active --quiet sshd.service")
  '';
}
