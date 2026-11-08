# Postern Browser — Institutional Spot (English narration script)

**Working title:** *Hardened, not anonymous.*
**Runtime target:** ~86 seconds
**Voice:** single narrator — calm, precise, unhurried. Anti-hype. The "sold the
honest way" voice: it states facts, names limits, and never oversells.
**Language:** English. Burned-in / sidecar English subtitles (see
`postern-browser.srt`).
**Music:** low, sparse, restrained. No dramatic swell on the honesty section —
that beat is spoken plainly, not sold.

> Every line below is literally true against `README.md`, `user.js`,
> `policies.json`, and `VERIFY.md`. Do not add claims. Do not soften the limits.

---

## Narration (voiceover)

**VO 1 — open**
This is Postern Browser. A hardened distribution of Firefox ESR.

**VO 2**
The same Gecko engine millions already run — rebuilt around privacy.

**VO 3**
Not a new engine. Not Chromium. Firefox ESR, with the Mozilla branding stripped.

**VO 4 — telemetry**
Telemetry is gone. No studies, no Pocket, no crash pings, no phone-home to Mozilla.

**VO 5**
Disabled at both the config and the enterprise-policy level.

**VO 6 — fingerprinting**
resistFingerprinting and letterboxing present one uniform surface.

**VO 7**
Timezone reads as UTC. Locale as en-US. Canvas and audio, spoofed.

**VO 8 — the first limit, said plainly**
This reduces your fingerprint. It does not erase it.

**VO 9 — the defenses**
Strict tracking protection. Dynamic first-party isolation. HTTPS-only, even in private windows.

**VO 10**
WebRTC that won't leak your local IP. And uBlock Origin, shipped in the box.

**VO 11 — the honest trade**
Some things break on purpose. That's the trade, not a bug — DRM is off, and sites may letterbox.

**VO 12**
We fix compatibility per site, never by weakening the defense.

**VO 13 — the honest part**
Here's the honest part. Postern Browser makes you harder to track.

**VO 14**
It does not make you anonymous. And it has not been independently audited.

**VO 15**
For strong anonymity, use the Tor Browser — the uniformity gold standard.

**VO 16 — sign-off line**
Built from public source. Hardened, not anonymous. Unaudited. Not Tor.

**VO 17 — logo card**
Postern Browser. A Postern Labs product. Public beta.

---

## On-screen text / lower-thirds

| Cue | On-screen text | Placement |
|---|---|---|
| Open | **POSTERN BROWSER** / *a hardened distribution of Firefox ESR (Gecko)* | Centered title card |
| VO 3 | `Not Chromium · Not a new engine · Not a code-fork` | Lower third |
| VO 4–5 | `No telemetry · No Pocket · No crash pings` | Lower third |
| VO 5 | `Enforced by user.js + enterprise policy` | Small caption |
| VO 6–7 | `resistFingerprinting + letterboxing` / *timezone → UTC · locale → en-US* | Lower third |
| VO 8 | **REDUCES — DOES NOT ELIMINATE** | Bold caption, no music swell |
| VO 9 | `Strict ETP · dFPI (cookieBehavior 5) · HTTPS-only` | Lower third |
| VO 10 | `WebRTC IP-leak protection · uBlock Origin bundled` | Lower third |
| VO 11 | `DRM/EME off · letterboxing on — intentional` | Lower third |
| VO 13–14 | **"Makes you harder to track. Not anonymous. Not audited."** | Full-frame honest-label card |
| VO 15 | `For anonymity: Tor Browser` | Caption |
| VO 16 | `Hardened, not anonymous · UNAUDITED · Not Tor` | Lower third |
| Close | **POSTERN BROWSER** / *A Postern Labs product · Public beta* / `Built on Firefox ESR (MPL-2.0). Not affiliated with, endorsed by, or sponsored by Mozilla or the Tor Project.` | Logo card + fine-print legal line |

---

## Required legal / disclaimer supers (must appear on screen)

- On the honest-label card (VO 13–14), verbatim from the product's honesty
  banner:
  > Postern Browser makes you harder to track. It does **not** make you
  > anonymous, and it has **not** been independently audited.
- On the closing card, small but legible:
  > Built on Firefox ESR under MPL-2.0. Firefox branding stripped. uBlock Origin
  > ships as a separate GPL-3.0 add-on. Not affiliated with, endorsed by, or
  > sponsored by Mozilla or the Tor Project.

---

## Do-not-say list (kept out of this script on purpose)

"anonymous / untraceable / cannot be tracked", "secure browsing", "private
browsing" as a guarantee, "audited / attested / reproducible", "our engine / new
engine", any Firefox/Mozilla logo or surviving trademark, any implied Mozilla or
Tor endorsement, and any coin/token claim whatsoever.
