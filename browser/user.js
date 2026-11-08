// ============================================================================
// Postern Browser — user.js (about:config hardening spine)
//
// Postern Browser is a HARDENED DISTRIBUTION of Firefox ESR (Gecko), in the
// class of Mullvad Browser / LibreWolf. It is NOT Chromium, NOT a from-scratch
// engine, and NOT a code-fork. This file is the about:config hardening spine:
// telemetry off, anti-fingerprinting (resistFingerprinting + letterboxing),
// HTTPS-only, dynamic first-party isolation, WebRTC IP-leak protection.
//
// HONEST LIMITS (these are literally true; read them):
//   - HARDENED, NOT ANONYMOUS. resistFingerprinting REDUCES, it does NOT
//     eliminate, fingerprinting. Tor Browser is the uniformity gold standard;
//     this is not that. Your ISP/VPN endpoint still sees which IPs you reach.
//   - NOT Tor. Standalone Postern Browser does NOT route traffic through Tor
//     and does not bundle Tor. (Postern OS ships a separate Tor client; the
//     browser does not force it.)
//   - UNAUDITED. Built from public source is NOT the same as independently
//     security-audited. This config is not a sandbox-escape defense.
//   - RFP BREAKS THINGS on purpose: timezone reports UTC, some canvas/media/
//     WebGL sites change or break, DRM/EME is off. This is the intended trade.
//     Do NOT "fix" breakage by disabling RFP — that de-hardens the browser.
//
// SCOPE OF THIS FILE: user.js sets pref VALUES at profile startup. It does not
// by itself LOCK them against user change. True locking in the distribution is
// enforced by the build-time autoconfig (mozilla.cfg / lockPref) and the
// enterprise policies.json (owned by other lots). Keep this file and
// policies.json in agreement on DNS/TRR and the tracking category.
//
// Grounded in the Postern OS seed profile (os/browser.nix) plus the privacy
// counselor's hardening spec. Each pref below is commented WHAT + WHY.
// ============================================================================


// ─── 1. Anti-fingerprinting: resistFingerprinting (RFP) + letterboxing ──────
// WHAT: RFP makes the browser present a uniform, spoofed surface — timezone
// forced to UTC, locale hints normalized, canvas/audio/screen/font readouts
// spoofed, user-agent managed by RFP.
// WHY: naive fingerprinting scripts get a common value instead of your real
// one. REDUCES linkability across sites; does NOT make you anonymous.
user_pref("privacy.resistFingerprinting", true);              // seed: present

// WHAT: letterboxing pads the content viewport to quantized (stepped) sizes so
// the reported window/inner size is one of a few common buckets, not a pixel-
// exact value. Renders as visible margins around the page.
// WHY: window/viewport dimensions are a strong fingerprint; RFP alone does NOT
// add letterboxing. This closes viewport-size fingerprinting. (Seed gap #1.)
user_pref("privacy.resistFingerprinting.letterboxing", true); // ADD vs seed

// WHAT: newer granular Fingerprinting Protection, kept alongside RFP.
// WHY: complements RFP with targeted per-API protections; harmless with RFP on.
user_pref("privacy.fingerprintingProtection", true);          // ADD vs seed

// WHAT: leave WebGL ENABLED (RFP spoofs its readouts).
// WHY: disabling WebGL breaks many sites for marginal gain since RFP already
// normalizes it. Flip to true only if you accept heavy breakage (strict mode).
user_pref("webgl.disable", false);                            // ADD vs seed

// WHAT: no Widevine/EME DRM by default.
// WHY: EME pulls a proprietary CDM and adds a fingerprintable capability.
// TRADE-OFF: Netflix/Spotify-class DRM streaming will not play. Documented.
user_pref("media.eme.enabled", false);                        // ADD vs seed
user_pref("media.gmp-widevinecdm.enabled", false);            // ADD vs seed

// NOTE: do NOT set general.useragent.override. RFP manages the UA; a manual
// override makes you MORE unique, not less. Intentionally omitted.


// ─── 2. Tracking protection & storage isolation (dFPI) ──────────────────────
// WHAT: strict Enhanced Tracking Protection category.
// WHY: blocks known trackers, cryptominers, fingerprinters by default.
user_pref("browser.contentblocking.category", "strict");      // seed: present
user_pref("privacy.trackingprotection.enabled", true);        // seed: present
user_pref("privacy.trackingprotection.socialtracking.enabled", true); // seed

// WHAT: cookieBehavior 5 = dynamic First-Party Isolation (Total Cookie
// Protection) — each site's cookies/storage confined to a per-site jar.
// WHY: kills third-party cross-site cookie tracking while keeping logins
// working within a site.
user_pref("network.cookie.cookieBehavior", 5);                // seed: present

// WHAT: partition network state (cache, connections, DNS, etc.) by first party.
// WHY: closes cross-site tracking via shared cache/connection reuse that
// cookie isolation alone does not cover. (Seed gap #5.)
user_pref("privacy.partition.network_state", true);           // ADD vs seed

// WHAT: leave legacy first-party isolation OFF.
// WHY: dFPI (cookieBehavior 5) supersedes legacy FPI. Stacking both is
// redundant and causes extra breakage. Do NOT enable both.
user_pref("privacy.firstparty.isolate", false);               // explicit vs seed


// ─── 3. Transport: HTTPS-only ───────────────────────────────────────────────
// WHAT: refuse plaintext HTTP; upgrade or warn.
// WHY: removes passive-observer plaintext page loads.
user_pref("dom.security.https_only_mode", true);              // seed: present

// WHAT: enforce HTTPS-only in private windows too.
// WHY: seed enforced it only in normal windows. (Seed gap #6.)
user_pref("dom.security.https_only_mode_pbm", true);          // ADD vs seed


// ─── 4. DNS-over-HTTPS (DoH) / TRR — OWNED BY policies.json, NOT HERE ────────
// SINGLE SOURCE OF TRUTH: the DoH decision lives in policies.json's
// `DNSOverHTTPS` block, which the Nix build parameterizes via `dohProviderURL`.
// This file DELIBERATELY DOES NOT set `network.trr.*`. Reason: user.js is a
// static file, but the DoH posture differs per build variant (desktop Linux
// pins a named resolver; Postern OS passes dohProviderURL=null to defer to the
// OS/Tor resolver). Setting trr prefs here too would DRIFT out of sync with the
// policy on one of those variants — exactly the inconsistency this audit fixes.
// The enterprise DNSOverHTTPS policy sets and locks network.trr.mode/uri itself.
//
// SHIPPED DEFAULT (desktop Linux): DoH ON, resolver = Mullvad
// (https://dns.mullvad.net/dns-query — named, no-logging; NEVER a silent
// Cloudflare default), Fallback = false (strict, mode-3 equivalent).
// HONEST TRADE: with Fallback off there is NO silent leak to system/ISP DNS,
// but if the resolver is unreachable, name resolution HARD-FAILS (that is the
// hardened choice — a leak-free failure, not a quiet plaintext fallback).
// Postern OS variant (dohProviderURL=null): DoH OFF, DNS deferred to the OS/Tor
// encrypted resolver. On plain desktop Linux a null would mean SYSTEM DNS
// (possibly plaintext) — which is why the desktop default pins Mullvad instead.
// VERIFY.md §B/§E is the check that policy, prefs, and the wire all agree.


// ─── 5. WebRTC IP-leak prevention (keep WebRTC usable) ──────────────────────
// WHAT: only surface the default route address in ICE candidates.
// WHY: stops enumeration of every local interface address.
user_pref("media.peerconnection.ice.default_address_only", true); // seed

// WHAT: never expose raw host (LAN) candidates via STUN.
// WHY: prevents a page from learning your private/LAN IP.
user_pref("media.peerconnection.ice.no_host", true);          // seed: present

// WHAT: force candidates through the proxy only when a proxy is configured.
// WHY: prevents WebRTC from bypassing a set proxy and leaking the real IP.
user_pref("media.peerconnection.ice.proxy_only_if_behind_proxy", true); // ADD

// NOTE: WebRTC is kept ENABLED (calls work) but leak-safe. Only fully disable
// (media.peerconnection.enabled=false) as a threat-model toggle, not default.


// ─── 6. Prefetch / speculative-connection leaks ─────────────────────────────
// WHAT: stop link/DNS prefetch, the network predictor, speculative sockets.
// WHY: these open connections to hosts you did not click, leaking intent and
// contacting third parties before you choose to.
user_pref("network.prefetch-next", false);                    // seed: present
user_pref("network.dns.disablePrefetch", true);               // seed: present
user_pref("network.predictor.enabled", false);                // seed: present
user_pref("network.http.speculative-parallel-limit", 0);      // seed: present

// WHAT: no speculative connection when hovering/typing in the address bar.
// WHY: otherwise the browser dials a guessed host before you hit enter. (Seed gap #9.)
user_pref("browser.urlbar.speculativeConnect.enabled", false); // ADD vs seed


// ─── 7. Beacons / pings / geolocation / Web Speech ──────────────────────────
// WHAT: disable the beacon API, hyperlink auditing pings, and geolocation.
// WHY: beacon/pings exfiltrate navigation data; geo reveals physical location.
user_pref("beacon.enabled", false);                           // seed: present
user_pref("browser.send_pings", false);                       // seed: present
user_pref("geo.enabled", false);                              // seed: present

// WHAT: disable Web Speech *recognition* (speech-to-text).
// WHY / CAVEAT (honest): the Web Speech recognition API can stream captured
// MICROPHONE AUDIO to a remote, third-party recognition service — historically
// a Google endpoint, not infrastructure Postern controls. That is a no-phone-
// home and a privacy leak, so recognition is OFF by default. Speech SYNTHESIS
// (text-to-speech) is left as-is: it runs on the local OS voices and does not
// exfiltrate audio, so disabling it would only cost accessibility for no gain.
user_pref("media.webspeech.recognition.enable", false);       // ADD: no remote STT


// ─── 8. Telemetry / experiments / phone-home kill (belt-and-suspenders) ─────
// WHAT + WHY: sever every Mozilla data/experiment/crash/connectivity channel so
// the browser does not contact infrastructure you do not control. Policies
// enforce the org-level versions; these are the profile-level belt-and-braces.
user_pref("toolkit.telemetry.enabled", false);                // seed: present
user_pref("toolkit.telemetry.unified", false);                // seed: present
user_pref("toolkit.telemetry.server", "data:,");              // ADD: dead endpoint
user_pref("toolkit.telemetry.archive.enabled", false);        // ADD: no local archive
user_pref("datareporting.healthreport.uploadEnabled", false); // seed: present
user_pref("datareporting.policy.dataSubmissionEnabled", false); // seed: present
user_pref("app.shield.optoutstudies.enabled", false);         // seed: present
user_pref("app.normandy.enabled", false);                     // ADD: Shield/Normandy off
user_pref("app.normandy.api_url", "");                        // ADD: no experiment fetch
user_pref("breakpad.reportURL", "");                          // ADD: no crash endpoint
user_pref("browser.tabs.crashReporting.sendReport", false);   // ADD: no crash send
user_pref("browser.crashReports.unsubmittedCheck.autoSubmit2", false); // ADD
user_pref("browser.newtabpage.activity-stream.feeds.telemetry", false); // seed
user_pref("browser.newtabpage.activity-stream.telemetry", false);       // seed
user_pref("browser.ping-centre.telemetry", false);            // ADD: ping-centre off
user_pref("network.connectivity-service.enabled", false);     // ADD: no Mozilla check
// WHAT: no Mozilla captive-portal probe. WHY: it phones a Mozilla canonical URL.
// TRADE-OFF: captive-portal (hotel/airport wifi) login detection is weaker;
// documented. Weigh per target; kept off for a clean no-phone-home cold start.
user_pref("captivedetect.canonicalURL", "");                  // ADD
user_pref("network.captive-portal-service.enabled", false);   // ADD


// ─── 9. Search / urlbar keystroke leakage ───────────────────────────────────
// WHAT: no search suggestions or urlbar search suggestions.
// WHY: otherwise every keystroke in the bar is sent to the search engine.
user_pref("browser.search.suggest.enabled", false);           // seed: present
user_pref("browser.urlbar.suggest.searches", false);          // seed: present

// WHAT: disable Firefox Suggest / quicksuggest and trending suggestions.
// WHY: these are additional Mozilla-partner network features in the address bar.
user_pref("browser.urlbar.quicksuggest.enabled", false);      // ADD vs seed
user_pref("browser.urlbar.trending.featureGate", false);      // ADD vs seed


// ─── 10. Mozilla account / Sync — disabled ──────────────────────────────────
// WHAT: hide and disable Firefox Accounts (FxA) and Sync.
// WHY: the plan forbids any Mozilla account/sync. (Seed gap #3.) Also enforced
// by policies.json DisableFirefoxAccounts.
user_pref("identity.fxaccounts.enabled", false);              // ADD vs seed


// ─── 11. Extension signature enforcement ────────────────────────────────────
// WHAT: require valid signatures on installed extensions; never disable.
// WHY: prevents silent injection of unsigned/tampered add-ons. See extensions.md.
user_pref("xpinstall.signatures.required", true);             // ADD vs seed
user_pref("extensions.htmlaboutaddons.recommendations.enabled", false); // no AMO recs
user_pref("extensions.getAddons.showPane", false);            // no AMO discovery pane


// ─── 12. Session / disk hygiene (SHOULD — sane defaults, not forced modes) ──
// WHAT: do not force permanent private browsing; keep local history usable.
// WHY: RFP + dFPI already handle the tracking leaks; forcing PBM hurts usability.
// A "clear on shutdown" strict mode is offered by the distribution, not defaulted.
user_pref("browser.privatebrowsing.autostart", false);        // default off (a mode)
user_pref("places.history.enabled", true);                    // history stays usable

// WHAT: do not offer to remember logins (use a real password manager).
// WHY: matches the seed/policy posture; the built-in store is not a vault.
user_pref("signon.rememberSignons", false);                   // matches seed policy

// ============================================================================
// End of user.js. Reminder on every surface: HARDENED, NOT ANONYMOUS;
// UNAUDITED; NOT Tor. RFP reduces — it does not eliminate — fingerprinting.
// ============================================================================
