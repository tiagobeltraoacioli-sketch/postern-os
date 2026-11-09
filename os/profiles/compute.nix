{ lib, ... }:
{
  services.xserver.enable = lib.mkForce false;
  services.displayManager.enable = lib.mkForce false;
  image.fileName = lib.mkForce "postern-os-compute-0.2.0-dev-x86_64.iso";
}
