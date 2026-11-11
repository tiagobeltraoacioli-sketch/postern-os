# SPDX-License-Identifier: MIT OR Apache-2.0
# Firefox defaults shared by the graphical profiles.
{ ... }:
{
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
      # Start on a quiet page: no onboarding, import prompt or promotions.
      OverrideFirstRunPage = "";
      OverridePostUpdatePage = "";
      NoDefaultBookmarks = true;
      DisplayBookmarksToolbar = "never";
      UserMessaging = {
        SkipOnboarding = true;
        ExtensionRecommendations = false;
        FeatureRecommendations = false;
        MoreFromMozilla = false;
        UrlbarInterventions = false;
      };
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
      "browser.aboutwelcome.enabled" = false;
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
}
