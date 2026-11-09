# SPDX-License-Identifier: MIT OR Apache-2.0
# A real boot test, including traffic from a separate network namespace.
{ pkgs, parallelData ? null }:
pkgs.testers.runNixOSTest {
  name = "postern-privacy";
  requiredFeatures.kvm = false;
  # Use the serial test backdoor; the tested system must have no SSH daemon.
  sshBackdoor.enable = false;

  nodes.machine = { ... }: {
    imports = [ ../profiles/privacy.nix ];
    virtualisation = {
      cores = 2;
      memorySize = 2048;
      qemu.forceAccel = false;
    };
    system.stateVersion = "26.05";
    environment.systemPackages = [ pkgs.curl pkgs.iproute2 pkgs.python3 ];
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
            "assert c.getint('connection','connection.mdns') == 0"
        ))

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
        machine.succeed("touch /tmp/postern-expiry-probe")
        machine.reboot()
        machine.wait_for_unit("multi-user.target", timeout=600)
        machine.wait_for_unit("firewall.service")
        machine.succeed("test ! -e /tmp/postern-expiry-probe")
        machine.fail("systemctl is-active --quiet sshd.service")
  '';
}
