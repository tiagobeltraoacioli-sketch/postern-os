# SPDX-License-Identifier: MIT OR Apache-2.0
# Importable NixOS 26.05 baseline. Local-console accounts belong to the image.
{ config, lib, pkgs, ... }:
let
  unsafeKernelParameters = [
    "mitigations=off"
    "nopti"
    "pti=off"
    "nospectre_v1"
    "nospectre_v2"
    "spectre_v2=off"
    "spec_store_bypass_disable=off"
    "l1tf=off"
    "mds=off"
    "tsx_async_abort=off"
    "srbds=off"
    "retbleed=off"
    "spec_rstack_overflow=off"
    "gather_data_sampling=off"
    "reg_file_data_sampling=off"
    "spectre_bhi=off"
  ];
in
{
  # Stateful inbound filtering; ordinary outbound traffic remains possible.
  # A deliberate service profile can declare its own listening ports.
  networking.firewall = {
    enable = lib.mkForce true;
    allowedTCPPorts = lib.mkDefault [ ];
    allowedUDPPorts = lib.mkDefault [ ];
    allowedTCPPortRanges = lib.mkDefault [ ];
    allowedUDPPortRanges = lib.mkDefault [ ];
    logRefusedConnections = false;
  };
  services.openssh = {
    enable = lib.mkForce false;
    openFirewall = lib.mkForce false;
  };
  services.avahi = {
    enable = lib.mkForce false;
    openFirewall = lib.mkForce false;
    nssmdns4 = lib.mkForce false;
    nssmdns6 = lib.mkForce false;
  };
  services.geoclue2.enable = lib.mkForce false;
  services.dleyna.enable = lib.mkForce false;
  services.gnome.gnome-online-accounts.enable = lib.mkForce false;
  services.gnome.gnome-initial-setup.enable = lib.mkForce false;
  services.gnome.gnome-remote-desktop.enable = lib.mkForce false;
  services.gnome.gnome-user-share.enable = lib.mkForce false;
  services.gnome.rygel.enable = lib.mkForce false;

  # Do not introduce a public DNS provider or a background Tor daemon here.
  # These settings also apply when a desktop enables NetworkManager/resolved.
  networking.networkmanager = {
    wifi.scanRandMacAddress = true;
    settings.connectivity = {
      enabled = false;
      uri = "";
    };
    connectionConfig = {
      "connection.llmnr" = 0;
      "connection.mdns" = 0;
    };
  };
  services.resolved.settings.Resolve = {
    LLMNR = "no";
    MulticastDNS = "no";
  };
  services.tor.enable = lib.mkDefault false;
  programs.firefox.policies = {
    DisableTelemetry = true;
    DisableFirefoxStudies = true;
  };

  # Disabling systemd-coredump alone restores the kernel's local "core" file
  # behavior. Discard the stream too, including processes outside PAM/systemd.
  systemd.coredump.enable = lib.mkForce false;
  boot.kernel.sysctl = {
    "kernel.core_pattern" = lib.mkForce "|${pkgs.coreutils}/bin/false";
    "fs.suid_dumpable" = 0;
    "kernel.kptr_restrict" = 2;
    "kernel.dmesg_restrict" = 1;
    "kernel.yama.ptrace_scope" = 1;
    "kernel.unprivileged_bpf_disabled" = 1;
  };
  systemd.settings.Manager.DefaultLimitCORE = "0";
  # Enable the LSM and policy loader. Individual applications are confined
  # only where an appropriate enforcing profile is present and attached.
  security.apparmor.enable = true;
  security.pam.loginLimits = [
    { domain = "*"; type = "hard"; item = "core"; value = "0"; }
    { domain = "root"; type = "hard"; item = "core"; value = "0"; }
  ];
  security.pam.enableUMask = true;
  security.loginDefs.settings.UMASK = "077";
  environment.loginShellInit = lib.mkAfter ''
    umask 077
  '';

  # Keep useful diagnostics in RAM, bounded in size. Application-specific logs
  # and user files are not covered by this journal policy.
  services.journald = {
    storage = "volatile";
    extraConfig = ''
      RuntimeMaxUse=64M
      MaxRetentionSec=1day
    '';
  };
  boot.tmp = {
    cleanOnBoot = true;
    useTmpfs = lib.mkDefault true;
    tmpfsSize = lib.mkDefault "25%";
  };
  systemd.tmpfiles.rules = [ "d /var/tmp 1777 root root 1d" ];

  # Keep CPU vulnerability mitigations on. This guard covers known opt-outs,
  # not an assertion that every CPU/kernel vulnerability is mitigated.
  boot.kernelParams = [ "mitigations=auto" ];
  assertions = [
    {
      assertion = !lib.any (p: builtins.elem p unsafeKernelParameters) config.boot.kernelParams;
      message = "Postern privacy profile refuses kernel parameters that disable CPU mitigations.";
    }
  ];

  environment.etc."postern/privacy.txt".text = ''
    Postern privacy baseline

    No network login: SSH is disabled. The firewall filters unsolicited inbound
    connections; explicitly enabled applications may declare listening ports.
    Automatic mDNS/LLMNR/UPnP discovery, GNOME sharing/remote desktop, GeoClue
    location, GNOME online accounts, NetworkManager connectivity probes and
    Firefox telemetry/studies are off.
    This is not a claim that every installed application is free of telemetry.

    Tor Browser is optional and protects only traffic inside that browser.
    This profile does not anonymize the whole system, force traffic through Tor,
    or conceal normal DHCP, DNS, time synchronization and update requests.

    Core dumps are discarded. The system journal is volatile and bounded.
    /tmp is a size-limited tmpfs by default; /var/tmp expires after one day.
    Neither removes user documents, application logs, caches or remote records.
    tmpfs can be swapped: an installed system needs encrypted storage/swap for
    protection at rest. A live image alone does not configure disk encryption.
    AppArmor is enabled; application confinement depends on loaded profiles.
    It does not automatically confine every application.
    Local console autologin grants access to whoever controls the machine.
  '';
}
