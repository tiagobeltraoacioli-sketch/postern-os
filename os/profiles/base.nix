# SPDX-License-Identifier: MIT OR Apache-2.0
# Identity, console and account policy shared by every Postern image type.
{ config, lib, pkgs, ... }:
{
  options.postern = {
    imageType = lib.mkOption {
      type = lib.types.enum [ "live-development" "vm-development" ];
      description = "Recorded in /etc/postern/release.json; never implies a release.";
    };
    profileName = lib.mkOption {
      type = lib.types.enum [ "compute" "desktop" "mobile" ];
      description = "Software profile, used in image file names.";
    };
  };

  config = {
    time.timeZone = "UTC";
    system.stateVersion = "26.05";

    # Local console only, and no fixed login secret in a published image.
    services.openssh.enable = lib.mkForce false;
    users.users.root.initialHashedPassword = lib.mkForce "!";
    users.users.nixos.initialHashedPassword = lib.mkForce "!";
    services.getty.autologinUser = lib.mkForce "nixos";
    services.getty.helpLine = lib.mkForce ''
      Postern OS development image — local console only.
      postern-status reports the privacy baseline; postern-data processes files offline.
      Local sudo is available. Network login is disabled.
    '';
    boot.kernelParams = [
      "console=tty0" "console=ttyS0,115200n8"
      "systemd.gpt_auto=0" "rd.systemd.gpt_auto=0"
    ];
    boot.zfs.forceImportRoot = false;

    environment.etc."postern/release.json".text = builtins.toJSON {
      name = "Postern OS";
      version = "0.3.1-dev";
      type = config.postern.imageType;
      blockchainEnabled = false;
      persistentDiskEncryption =
        if config.postern.imageType == "live-development"
        then "not configured by a live image"
        else "not configured; the virtual disk is unencrypted";
    };
    users.motd = lib.mkForce ''
      Postern OS 0.3.1-dev
      Offline data processing; no validator or mining service starts automatically.
      Run postern-status to see the privacy baseline observed on this system.
      This system does not promise anonymity against every network or hardware threat.
    '';
  };
}
