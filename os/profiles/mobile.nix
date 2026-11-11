# SPDX-License-Identifier: MIT OR Apache-2.0
# Phone interface (Phosh) on the same x86_64 base and privacy baseline, for a
# virtual machine with a portrait display or an x86 tablet. It is the mobile
# user interface of Postern OS, not a handset image: no phone hardware port,
# modem, telephony or battery management is configured or tested here.
{ lib, pkgs, ... }:
let
  statusApp = pkgs.callPackage ../../nix/postern-status-gui.nix { };
  wallpaper = pkgs.runCommand "postern-wallpaper.png" { nativeBuildInputs = [ pkgs.librsvg ]; } ''
    rsvg-convert --width 2560 --height 1440 ${../assets/wallpaper.svg} --output $out
  '';
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
  imports = [ ./firefox.nix ];

  fonts.fontconfig.enable = true;
  fonts.enableDefaultPackages = true;
  fonts.packages = with pkgs; [ inter jetbrains-mono dejavu_fonts ];
  fonts.fontconfig.defaultFonts = {
    sansSerif = [ "Inter" "DejaVu Sans" ];
    monospace = [ "JetBrains Mono" "DejaVu Sans Mono" ];
  };
  xdg.icons.enable = true;
  xdg.mime.enable = true;
  xdg.sounds.enable = true;
  boot.consoleLogLevel = 3;
  boot.kernelParams = [ "quiet" "vt.global_cursor_default=0" ];

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
  programs.dconf.enable = true;
  services.gnome.gnome-keyring.enable = true;
  services.gnome.gnome-online-accounts.enable = lib.mkForce false;
  services.gnome.gnome-remote-desktop.enable = lib.mkForce false;
  services.gvfs.enable = true;
  services.upower.enable = true;

  networking.networkmanager.enable = true;
  networking.networkmanager.wifi.macAddress = "random";
  networking.networkmanager.connectionConfig."ipv6.ip6-privacy" = 2;
  networking.networkmanager.settings.connectivity.enabled = false;
  networking.wireless.enable = lib.mkForce false;
  services.printing.enable = lib.mkForce false;
  hardware.bluetooth.powerOnBoot = lib.mkDefault false;

  environment.systemPackages = with pkgs; [
    statusApp gnome-console nautilus gnome-control-center gnome-calculator
    gnome-clocks gnome-text-editor adwaita-icon-theme squeekboard
  ];

  programs.dconf.profiles.user.databases = [{
    settings = {
      "sm/puri/phosh" = {
        favorites = [
          "firefox.desktop" "org.gnome.Console.desktop" "org.postern.Status.desktop"
          "org.gnome.Nautilus.desktop"
        ];
      };
      "org/gnome/desktop/background" = {
        picture-uri = "file://${wallpaper}";
        picture-uri-dark = "file://${wallpaper}";
        picture-options = "zoom";
        primary-color = "#0b1026";
      };
      "org/gnome/desktop/screensaver" = {
        lock-enabled = false;
        picture-uri = "file://${wallpaper}";
        picture-options = "zoom";
      };
      "org/gnome/desktop/lockdown".disable-lock-screen = true;
      "org/gnome/desktop/session".idle-delay = lib.gvariant.mkUint32 0;
      "org/gnome/desktop/interface" = {
        color-scheme = "prefer-dark";
        accent-color = "blue";
        font-name = "Inter 11";
        document-font-name = "Inter 11";
        monospace-font-name = "JetBrains Mono 10";
        show-battery-percentage = true;
      };
      "org/gnome/desktop/media-handling" = {
        automount = false;
        automount-open = false;
        autorun-never = true;
      };
      "org/gnome/desktop/privacy" = {
        remember-recent-files = false;
        remove-old-temp-files = true;
        remove-old-trash-files = true;
        old-files-age = lib.gvariant.mkUint32 1;
        report-technical-problems = false;
        send-software-usage-stats = false;
      };
      "org/gnome/system/location".enabled = false;
    };
  }];

  postern.profileName = "mobile";
}
