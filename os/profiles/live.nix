{ lib, pkgs, modulesPath, ... }:
{
  imports = [ (modulesPath + "/installer/cd-dvd/installation-cd-minimal.nix") ];
  networking.hostName = lib.mkForce "postern-live";
  time.timeZone = "UTC";
  system.stateVersion = "26.05";

  # Live media is ephemeral, with a local console only. No fixed login secret.
  services.openssh.enable = lib.mkForce false;
  users.users.root.initialHashedPassword = lib.mkForce "!";
  users.users.nixos.initialHashedPassword = lib.mkForce "!";
  services.getty.autologinUser = lib.mkForce "nixos";
  services.getty.helpLine = lib.mkForce ''
    Postern OS development live image — local console only.
    Use postern-data for offline parallel processing.
    Local sudo is available. Network login is disabled.
  '';
  boot.kernelParams = [ "console=tty0" "console=ttyS0,115200n8" ];
  boot.initrd.systemd.enable = lib.mkForce false;
  boot.zfs.forceImportRoot = false;
  isoImage.squashfsCompression = "zstd -Xcompression-level 6";

  environment.etc."postern/release.json".text = builtins.toJSON {
    name = "Postern OS";
    version = "0.2.0-dev";
    type = "live-development";
    blockchainEnabled = false;
    persistentDiskEncryption = "not configured by a live image";
  };
  users.motd = lib.mkForce ''
    Postern OS 0.2.0-dev
    Offline data processing; no validator or mining service starts automatically.
    Live-session storage is temporary. Encrypt disks explicitly before installation.
    This system does not promise anonymity against every network or hardware threat.
  '';
}
