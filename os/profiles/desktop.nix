{ lib, pkgs, ... }:
{
  services.xserver.enable = true;
  services.displayManager.gdm = {
    enable = true;
  };
  services.desktopManager.gnome.enable = true;
  services.displayManager.autoLogin = {
    enable = true;
    user = "nixos";
  };
  services.gnome.gnome-online-accounts.enable = lib.mkForce false;
  services.gnome.gnome-initial-setup.enable = lib.mkForce false;
  environment.gnome.excludePackages = with pkgs; [ gnome-tour epiphany geary ];
  networking.networkmanager.enable = true;
  networking.networkmanager.wifi.macAddress = "random";
  networking.networkmanager.connectionConfig."ipv6.ip6-privacy" = 2;
  networking.networkmanager.settings.connectivity.enabled = false;
  networking.wireless.enable = lib.mkForce false;
  services.printing.enable = lib.mkForce false;
  services.gnome.gnome-remote-desktop.enable = lib.mkForce false;
  hardware.bluetooth.powerOnBoot = lib.mkDefault false;
  # The password-locked live account cannot unlock a GNOME screen lock.
  # Installed systems must configure a password and retain normal screen locks.
  services.desktopManager.gnome.extraGSettingsOverrides = ''
    [org.gnome.desktop.screensaver]
    lock-enabled=false
    [org.gnome.desktop.lockdown]
    disable-lock-screen=true
    [org.gnome.desktop.media-handling]
    automount=false
    automount-open=false
    autorun-never=true
  '';

  environment.systemPackages = with pkgs; [ gnome-terminal keepassxc ];
  programs.firefox = {
    enable = true;
    policies = {
      DisableTelemetry = true;
      DisableFirefoxStudies = true;
      DisablePocket = true;
      DisableFormHistory = true;
      DontCheckDefaultBrowser = true;
      OfferToSaveLogins = false;
      PasswordManagerEnabled = false;
      EnableTrackingProtection = {
        Value = true;
        Locked = true;
        Cryptomining = true;
        Fingerprinting = true;
      };
      FirefoxHome = {
        Search = true;
        TopSites = false;
        SponsoredTopSites = false;
        Highlights = false;
        Pocket = false;
        SponsoredPocket = false;
        Snippets = false;
      };
    };
    preferencesStatus = "locked";
    preferences = {
      "toolkit.telemetry.enabled" = false;
      "toolkit.telemetry.unified" = false;
      "datareporting.healthreport.uploadEnabled" = false;
      "datareporting.policy.dataSubmissionEnabled" = false;
      "browser.search.suggest.enabled" = false;
      "browser.urlbar.suggest.searches" = false;
      "network.prefetch-next" = false;
      "network.dns.disablePrefetch" = true;
      "network.predictor.enabled" = false;
      "network.http.speculative-parallel-limit" = 0;
      "privacy.resistFingerprinting" = true;
      "privacy.trackingprotection.enabled" = true;
      "browser.contentblocking.category" = "strict";
      "dom.security.https_only_mode" = true;
      "media.peerconnection.enabled" = false;
      "geo.enabled" = false;
    };
  };
  image.fileName = lib.mkForce "postern-os-desktop-0.2.0-dev-x86_64.iso";
}
