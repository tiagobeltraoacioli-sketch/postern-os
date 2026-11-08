# Postern Browser — Storyboard / Shot List

**Total runtime:** ~86 s (01:26.5). Institutional spot.
**Format:** 16:9, 1080p or 4K. Screen captures at native resolution, no zoom
that fakes UI. **Capture on a real built Postern Browser** so every pref, policy,
and result on screen is genuine (per `VERIFY.md`) — do not mock the UI.
**Grade:** cool, low-contrast, restrained. One accent color for callouts.
**Subtitles:** English, from `postern-browser.srt`.

Legend: **SFX/notes** in italics. Timecodes are start–end.

---

### Scene 1 — Title / open
- **TC:** 00:00.000 – 00:04.000 (4.0s)
- **Visual:** Black. The Postern Browser wordmark fades up centered. No Firefox
  logo, no globe — just the wordmark and tagline.
- **On-screen text:** **POSTERN BROWSER** / *a hardened distribution of Firefox ESR (Gecko)*
- **VO:** "This is Postern Browser. A hardened distribution of Firefox ESR."
- *Note: hold 0.5s of silence before VO for the wordmark to land.*

### Scene 2 — The engine, honestly
- **TC:** 00:04.000 – 00:08.500 (4.5s)
- **Visual:** Clean desktop capture of the browser opening to a blank/neutral
  start page. Chrome reads "Postern Browser" in the title bar and task switcher.
- **On-screen text:** (none — let the real title bar speak)
- **VO:** "The same Gecko engine millions already run — rebuilt around privacy."

### Scene 3 — What it is / is not
- **TC:** 00:08.500 – 00:13.500 (5.0s)
- **Visual:** `about:` page or About dialog showing the "built on Mozilla
  Firefox ESR (Gecko) … Not affiliated with or endorsed by Mozilla" attribution
  line. Cut in three quick negative supers.
- **On-screen text:** `Not Chromium · Not a new engine · Not a code-fork`
- **VO:** "Not a new engine. Not Chromium. Firefox ESR, with the Mozilla branding stripped."

### Scene 4 — Telemetry off
- **TC:** 00:13.500 – 00:19.000 (5.5s)
- **Visual:** `about:telemetry` showing "Telemetry is disabled," then a fast wipe
  to `about:studies` showing no studies. Optional: a terminal strip of a
  cold-start packet capture with zero Mozilla telemetry hosts (VERIFY §C).
- **On-screen text:** `No telemetry · No Pocket · No crash pings`
- **VO:** "Telemetry is gone. No studies, no Pocket, no crash pings, no phone-home to Mozilla."

### Scene 5 — Enforced two ways
- **TC:** 00:19.000 – 00:23.500 (4.5s)
- **Visual:** Split screen: left, `user.js` telemetry block scrolling; right,
  `about:policies` Active tab showing `DisableTelemetry`, `DisableFirefoxStudies`,
  `DisablePocket`.
- **On-screen text:** `Enforced by user.js + enterprise policy`
- **VO:** "Disabled at both the config and the enterprise-policy level."

### Scene 6 — Fingerprint spine
- **TC:** 00:23.500 – 00:28.500 (5.0s)
- **Visual:** `about:config` filtered to `resistFingerprinting`, showing
  `privacy.resistFingerprinting = true` and
  `privacy.resistFingerprinting.letterboxing = true`, both **locked** (edit
  control greyed). Then resize the window to show it snap to letterboxed steps.
- **On-screen text:** `resistFingerprinting + letterboxing`
- **VO:** "resistFingerprinting and letterboxing present one uniform surface."

### Scene 7 — Spoofed readouts
- **TC:** 00:28.500 – 00:34.000 (5.5s)
- **Visual:** A leak/fingerprint test page (e.g. browserleaks JS panel) showing
  timezone = UTC and language = en-US; canvas/audio hash shown as uniform.
- **On-screen text:** *timezone → UTC · locale → en-US · canvas/audio spoofed*
- **VO:** "Timezone reads as UTC. Locale as en-US. Canvas and audio, spoofed."

### Scene 8 — The first limit (said plainly)
- **TC:** 00:34.000 – 00:38.500 (4.5s)
- **Visual:** Cover Your Tracks / EFF result reading "you have *some*
  protection" — deliberately NOT an "anonymous" claim. Text overlays it.
- **On-screen text:** **REDUCES — DOES NOT ELIMINATE**
- **VO:** "This reduces your fingerprint. It does not erase it."
- *Note: no music lift here. Plain.*

### Scene 9 — Core defenses stack
- **TC:** 00:38.500 – 00:44.500 (6.0s)
- **Visual:** Fast, legible montage: ETP shield on `strict`; `about:config`
  `network.cookie.cookieBehavior = 5`; an HTTPS-only interstitial appearing on an
  `http://` URL — repeated once in a private window.
- **On-screen text:** `Strict ETP · dFPI (cookieBehavior 5) · HTTPS-only`
- **VO:** "Strict tracking protection. Dynamic first-party isolation. HTTPS-only, even in private windows."

### Scene 10 — WebRTC + uBlock
- **TC:** 00:44.500 – 00:49.500 (5.0s)
- **Visual:** browserleaks/ipleak WebRTC panel showing **no** local/host IP
  candidate. Cut to `about:addons` with uBlock Origin installed and enabled.
- **On-screen text:** `WebRTC IP-leak protection · uBlock Origin bundled`
- **VO:** "WebRTC that won't leak your local IP. And uBlock Origin, shipped in the box."

### Scene 11 — Breakage is the trade
- **TC:** 00:49.500 – 00:55.500 (6.0s)
- **Visual:** A DRM stream showing a playback-unavailable notice; a page framed
  by letterbox padding. Presented matter-of-fact, not as a flaw.
- **On-screen text:** `DRM/EME off · letterboxing on — intentional`
- **VO:** "Some things break on purpose. That's the trade, not a bug — DRM is off, and sites may letterbox."

### Scene 12 — Per-site, not by de-hardening
- **TC:** 00:55.500 – 01:00.000 (4.5s)
- **Visual:** A per-site permissions/exceptions panel being used for one site,
  while the global RFP pref stays locked on in the background.
- **On-screen text:** `Fix per site — never disable the spine`
- **VO:** "We fix compatibility per site, never by weakening the defense."

### Scene 13 — Honest-label card, part 1
- **TC:** 01:00.000 – 01:05.500 (5.5s)
- **Visual:** Full-frame typographic card on flat background — the honesty
  banner. No imagery competing with it.
- **On-screen text:** **"Makes you harder to track."** (line 1 of the card)
- **VO:** "Here's the honest part. Postern Browser makes you harder to track."

### Scene 14 — Honest-label card, part 2
- **TC:** 01:05.500 – 01:11.000 (5.5s)
- **Visual:** Same card, next two lines reveal. Verbatim honesty banner.
- **On-screen text:** **"Not anonymous. Not independently audited."**
- **VO:** "It does not make you anonymous. And it has not been independently audited."

### Scene 15 — Point to Tor
- **TC:** 01:11.000 – 01:16.000 (5.0s)
- **Visual:** Plain caption card. No Tor logo (no implied endorsement) — just the
  words.
- **On-screen text:** `For anonymity: Tor Browser`
- **VO:** "For strong anonymity, use the Tor Browser — the uniformity gold standard."

### Scene 16 — Sign-off line
- **TC:** 01:16.000 – 01:21.500 (5.5s)
- **Visual:** Return to the browser, calm. Four short supers snap in on the beats.
- **On-screen text:** `Built from public source · Hardened, not anonymous · UNAUDITED · Not Tor`
- **VO:** "Built from public source. Hardened, not anonymous. Unaudited. Not Tor."

### Scene 17 — Logo card / close
- **TC:** 01:21.500 – 01:26.500 (5.0s)
- **Visual:** Postern Browser wordmark. Fine-print legal line at the bottom.
- **On-screen text:** **POSTERN BROWSER** / *A Postern Labs product · Public beta*
- **Fine print:** *Built on Firefox ESR under MPL-2.0. Firefox branding stripped.
  uBlock Origin ships as a separate GPL-3.0 add-on. Not affiliated with, endorsed
  by, or sponsored by Mozilla or the Tor Project.*
- **VO:** "Postern Browser. A Postern Labs product. Public beta."

---

## Capture checklist (so every frame is true)
- Record on a genuine built Postern Browser profile; prefs shown must be
  **locked** (VERIFY §A), not editable profile defaults.
- Fingerprint/leak-test frames must show real results — expected outcome is
  "some / partial protection," never a screen implying anonymity (VERIFY §F).
- Branding audit before export: zero surviving Firefox/Mozilla marks or logos in
  any captured frame outside license/attribution text (VERIFY §J).
- Do not show a DoH resolver claim the standalone build doesn't make; if you show
  DNS at all, show the documented, named posture — never imply silent encrypted
  DNS (user.js §4 / policies.json).
