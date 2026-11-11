# SPDX-License-Identifier: MIT OR Apache-2.0
# Phone interface (Phosh) on the same x86_64 base and privacy baseline, for a
# virtual machine with a portrait display or an x86 tablet. It is the mobile
# user interface of Postern OS, not a handset image: no phone hardware port,
# modem, telephony or battery management is configured or tested here.
{ lib, pkgs, ... }:
let
  # The live account has a locked password, so a lock screen could never be
  # opened. Start unlocked, like the desktop live session; an installed phone
  # must set a PIN and keep the lock.
  phoshUnlocked = pkgs.phosh.overrideAttrs (old: {
    # After fixup: the build installs the systemd user unit under lib/ and
    # only then moves it to share/. The session starts the shell from that
    # unit; the desktop file is patched too so both entry points agree.
    postFixup = (old.postFixup or "") + ''
      for unit in $out/share/systemd/user/mobi.phosh.Shell.service \
                  $out/share/applications/mobi.phosh.Shell.desktop; do
        sed -i -E 's|^(Exec(Start)?=.*/libexec/phosh)$|\1 --unlocked|' "$unit"
        grep -q -- '/libexec/phosh --unlocked$' "$unit"
      done
    '';
  });
in
{
  imports = [ ./graphical.nix ];
  boot.kernelParams = [ "vt.global_cursor_default=0" ];

  services.xserver.desktopManager.phosh = {
    enable = true;
    package = phoshUnlocked;
    user = "nixos";
    group = "users";
    # Two device pixels per point on the 720x1280 virtual display.
    phocConfig.outputs."Virtual-1".scale = 2;
  };
  # The phone shell owns the display. A text login on the first virtual
  # terminal and its blinking cursor were drawn over the interface, so the
  # mobile image keeps its diagnostic login on the serial console only.
  systemd.services."getty@tty1".enable = false;
  systemd.services."autovt@tty1".enable = false;
  # In a virtual machine the compositor's OpenGL path runs on a software
  # rasterizer and left stale black squares on screen (seen in 0.3.1-dev and
  # reproduced in QEMU); its pixman renderer draws the same picture correctly.
  # Real hardware keeps the GPU renderer.
  systemd.services.postern-phone-renderer = {
    description = "Select the phone shell renderer for a virtual machine";
    wantedBy = [ "phosh.service" ];
    before = [ "phosh.service" ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      RuntimeDirectory = "postern";
      RuntimeDirectoryPreserve = true;
    };
    script = ''
      if ${pkgs.systemd}/bin/systemd-detect-virt --vm --quiet; then
        echo WLR_RENDERER=pixman > /run/postern/phosh.env
      else
        : > /run/postern/phosh.env
      fi
    '';
  };
  systemd.services.phosh.serviceConfig.EnvironmentFile = "-/run/postern/phosh.env";
  services.gnome.gnome-keyring.enable = true;
  services.gvfs.enable = true;
  services.upower.enable = true;

  environment.systemPackages = with pkgs; [
    gnome-console nautilus gnome-control-center gnome-calculator gnome-clocks
    gnome-text-editor gnome-calendar gnome-contacts gnome-weather loupe papers
    decibels
    # KeePass-format password manager with a phone layout.
    gnome-secrets
    phosh-mobile-settings squeekboard
  ];

  programs.dconf.profiles.user.databases = [{
    settings = {
      "sm/puri/phosh" = {
        favorites = [
          "firefox.desktop" "org.gnome.Console.desktop" "org.postern.Status.desktop"
          "org.gnome.Nautilus.desktop"
        ];
        # The grid and search list applications with a phone layout. Firefox
        # and Files work on a narrow screen without declaring one. Listing
        # every installed entry instead put terminal programs first in search
        # ("console" opened btop).
        force-adaptive = [ "firefox.desktop" "org.gnome.Nautilus.desktop" ];
      };
      "org/gnome/desktop/screensaver".lock-enabled = false;
      "org/gnome/desktop/lockdown".disable-lock-screen = true;
      "org/gnome/desktop/session".idle-delay = lib.gvariant.mkUint32 0;
      "org/gnome/desktop/interface" = {
        monospace-font-name = "JetBrains Mono 10";
        show-battery-percentage = false;
      };
    };
  }];

  postern.profileName = "mobile";
}
