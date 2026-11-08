# Postern Browser — a HARDENED DISTRIBUTION of Firefox ESR (Gecko).
# Class of Mullvad Browser / LibreWolf. NOT Chromium, NOT a from-scratch engine,
# NOT a source code-fork. A Postern Labs product.
#
# This file is BOTH:
#   1. a standalone Nix package derivation (`.package`) that wraps `firefox-esr`
#      with baked-in enterprise policies (./policies.json) + locked about:config
#      prefs (./user.js, owned by Lot B), producing a self-contained
#      `postern-browser` binary for desktop Linux; and
#   2. a thin NixOS module (`.nixosModule`) so Postern OS installs THIS package
#      instead of stock `pkgs.firefox`.
#
# Grown from the seed os/browser.nix (a `programs.firefox` profile on stock
# Firefox). The seed only ships policies+prefs on Mozilla's own binary, so it
# carries NO trademark obligation. This file redistributes a differently-named
# binary, so honesty and trademark rules attach — see the BRANDING note below.
#
# ── HONESTY (every claim here is literally true) ────────────────────────────────
#   * Postern Browser is HARDENED, NOT anonymous. resistFingerprinting REDUCES,
#     it does NOT eliminate, fingerprinting. Tor Browser is the uniformity gold
#     standard; this is not Tor and does not route traffic through Tor.
#   * Built on Firefox ESR under MPL-2.0 (per-file copyleft, non-viral).
#   * uBlock Origin is GPL-3.0, shipped as a SEPARATE add-on (aggregation, not
#     linked into Gecko) — installed via the ExtensionSettings policy, never
#     compiled into the binary.
#   * UNAUDITED. Built != audited. Never "secure/private browsing" as an absolute.
#
# ── BRANDING (ship-blocker; do NOT overclaim) ───────────────────────────────────
#   `wrapFirefox` performs EXTERNAL de-branding only: the .desktop entry, window
#   class, launcher name and icon become "Postern Browser". It does NOT rewrite
#   the internal "Firefox"/"Mozilla" strings and logos inside the binary
#   (about: pages, About dialog, MOZ_APP_DISPLAYNAME). Mozilla's trademark policy
#   forbids redistributing a modified build under the Firefox name/logo, so a
#   FULL source-level branding strip (the LibreWolf/Mullvad `--with-branding`
#   unofficial target) is REQUIRED before any public/signed release. That strip
#   is Lot C's job. Until it lands, builds from this file are DEV-ONLY and MUST
#   NOT be published. This file does not claim to satisfy the trademark strip.
#
# ── PINNED INPUTS (rebuild-verify; see VERIFY.md §0) ────────────────────────────
# For anyone to build-from-source and get the SAME toolchain, the nixpkgs input
# must be PINNED to an exact rev + narHash, not floated on the ambient channel.
# The pin values below are filled at pin time (TODO(pin)) — the SAME honesty
# convention this repo uses for the mozilla-esr commit and the uBlock xpi hash
# (see build.md §0/§2, extensions.md). Until the sha256 is filled, the default
# FALLS BACK to the channel <nixpkgs> and prints a loud trace: a channel build is
# NOT rebuild-verifiable. Pass your own `pkgs` to override entirely.
#
# HONEST CEILING (see build.md §7): pinning inputs makes the build REPEATABLE and
# the source REACHABLE. It does NOT make it bit-for-bit REPRODUCED, and a matching
# hash is not an audit. Do not claim "reproducible"/"reproduced" from a pin alone.
{ pkgs ? import
    (let
      # TODO(pin): set to the exact nixpkgs commit + its tarball sha256.
      nixpkgsPin = { rev = "TODO(pin)"; sha256 = "TODO(pin)"; };
    in
      if nixpkgsPin.sha256 != "TODO(pin)" then
        builtins.fetchTarball {
          url = "https://github.com/NixOS/nixpkgs/archive/${nixpkgsPin.rev}.tar.gz";
          inherit (nixpkgsPin) sha256;
        }
      else
        builtins.trace
          "postern-browser: nixpkgs input is NOT pinned (TODO(pin)); building against the ambient channel <nixpkgs>. This build is NOT rebuild-verifiable until the pin is filled — see VERIFY.md §0."
          <nixpkgs>)
    { }
, lib ? pkgs.lib
  # DoH decision (see §4.4 of the hardening spec). Default: pin Mullvad's
  # no-logging resolver (a named, vetted resolver — never silent Cloudflare).
  # Postern OS can pass dohProviderURL = null to defer to the OS/Tor resolver.
, dohProviderURL ? "https://dns.mullvad.net/dns-query"
}:

let
  # policies.json is the single source of truth for enterprise policy. Nix reads
  # it so the derivation and the on-disk policy artifact can never drift.
  policiesFile = ./policies.json;
  policySet = (builtins.fromJSON (builtins.readFile policiesFile)).policies;

  # If Postern OS opts to defer DNS to the OS/Tor resolver (dohProviderURL=null),
  # disable in-browser DoH rather than silently falling back to Mozilla's default.
  policies =
    if dohProviderURL == null then
      policySet // { DNSOverHTTPS = { Enabled = false; Locked = true; }; }
    else
      policySet // {
        DNSOverHTTPS = (policySet.DNSOverHTTPS or { }) // {
          Enabled = true;
          Locked = true;
          ProviderURL = dohProviderURL;
        };
      };

  # Locked about:config spine. Lot B owns ./user.js (the arkenfox-class prefs:
  # RFP + letterboxing, dFPI cookieBehavior=5, https_only + pbm, WebRTC leak
  # off, network.trr.mode matching the DoH decision above, telemetry kill).
  # We CONSUME it as an extra prefs file if present; we do not create it.
  # The DoH/TRR prefs in user.js MUST agree with policies.json's DNSOverHTTPS.
  userJs = ./user.js;
  haveUserJs = builtins.pathExists userJs;

  # Wrap the UNWRAPPED Firefox ESR. `firefox-esr-unwrapped` is the raw browser;
  # `wrapFirefox` injects policies, prefs and the (external) branding overrides.
  wrapFirefox = pkgs.wrapFirefox or (throw
    "pkgs.wrapFirefox not found; this file targets nixpkgs' firefox wrapper");
  esrUnwrapped = pkgs.firefox-esr-unwrapped or pkgs.firefox-esr.unwrapped;

  postern-browser = wrapFirefox esrUnwrapped {
    # External de-brand (launcher/desktop/wmclass). NOT the trademark strip — see
    # the BRANDING note at the top. A full strip is Lot C (source rebuild).
    pname = "postern-browser";
    desktopName = "Postern Browser";
    # `built on Gecko/Firefox ESR` kept as a truthful descriptor of the base.
    nameSuffix = "";
    wmClass = "postern-browser";
    # icon = ./branding/postern.png;  # Lot C provides real branding assets.

    # Enterprise policies -> policies.json inside the wrapped tree + managed reg.
    extraPolicies = policies;

    # Locked prefs. Lot B's user.js is applied as an autoconfig prefs file so the
    # spine is a build-time DEFAULT, not just a per-profile pref.
    extraPrefsFiles = lib.optional haveUserJs userJs;

    # Belt-and-suspenders defaults in case ./user.js is not yet present at build
    # time (kickoff/integration ordering). These agree with policies.json.
    extraPrefs = ''
      // Never weaken signature enforcement.
      lockPref("xpinstall.signatures.required", true);
      // No Mozilla account / Sync (matches DisableFirefoxAccounts policy).
      lockPref("identity.fxaccounts.enabled", false);
    '';

    # No proprietary/DRM codecs pulled in by default (EME off; fingerprint + non-free).
    extraNativeMessagingHosts = [ ];
  };

  # ── NixOS module ───────────────────────────────────────────────────────────
  # Installs THIS package system-wide and marks it the default browser, replacing
  # the seed's `programs.firefox`-on-stock-Firefox approach.
  nixosModule = { config, lib, pkgs, ... }:
    let cfg = config.programs.postern-browser;
    in {
      options.programs.postern-browser = {
        enable = lib.mkEnableOption "Postern Browser (hardened Firefox ESR distribution)";
        dohProviderURL = lib.mkOption {
          type = lib.types.nullOr lib.types.str;
          default = "https://dns.mullvad.net/dns-query";
          description = ''
            DNS-over-HTTPS resolver to pin. Set to null on Postern OS to disable
            in-browser DoH and defer to the OS/Tor encrypted resolver. Never left
            to Mozilla's silent Cloudflare default.
          '';
        };
      };
      config = lib.mkIf cfg.enable {
        environment.systemPackages = [
          (import ./postern-browser.nix {
            inherit pkgs;
            inherit (cfg) dohProviderURL;
          }).package
        ];
      };
    };

in {
  package = postern-browser;
  inherit policies nixosModule;
  # Default attr so `nix-build postern-browser.nix` yields the browser.
  default = postern-browser;
}
