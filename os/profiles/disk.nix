# SPDX-License-Identifier: MIT OR Apache-2.0
# Persistent virtual-machine disk for development. Unlike the live medium it
# keeps data across restarts, on an UNENCRYPTED virtual disk, with the same
# password-locked local autologin. Do not copy it to a physical machine or use
# it for private data; an installed system needs encrypted storage and a real
# account, which this image does not configure.
{ lib, pkgs, modulesPath, ... }:
{
  imports = [
    (modulesPath + "/profiles/qemu-guest.nix")
    ./base.nix
  ];
  postern.imageType = "vm-development";
  networking.hostName = lib.mkForce "postern-vm";

  fileSystems."/" = {
    device = "/dev/disk/by-label/nixos";
    fsType = "ext4";
    autoResize = true;
  };
  fileSystems."/boot" = {
    device = "/dev/disk/by-label/ESP";
    fsType = "vfat";
    options = [ "umask=0077" ];
  };
  boot.growPartition = true;
  boot.loader.timeout = 3;
  # One image boots under both SeaBIOS and UEFI firmware.
  boot.loader.grub = {
    device = "/dev/vda";
    efiSupport = true;
    efiInstallAsRemovable = true;
  };

  users.users.nixos = {
    isNormalUser = true;
    extraGroups = [ "wheel" ];
  };
  security.sudo.wheelNeedsPassword = false;
  documentation.nixos.enable = false;
}
