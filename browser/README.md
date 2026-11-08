# Postern Browser

`hardened, not anonymous · built on Firefox ESR · unaudited public beta`

**A hardened distribution of Firefox ESR (Gecko).** In the class of LibreWolf and
Mullvad Browser: the same engine, rebuilt with telemetry removed,
anti-fingerprinting on by default, encrypted transport forced, and Mozilla
branding stripped. A Postern Labs product.

> **Not affiliated with, endorsed by, or sponsored by Mozilla.** "Firefox ESR"
> and "Gecko" are used here only to describe *what this is built from*.

**Status: UNAUDITED PUBLIC BETA.** Built from public source; **not** independently
security-audited, **not** reproducible-verified, **not** anonymity software, and
**not** Tor. Expect breakage (see below) — it is the anti-fingerprinting trade,
not a bug. You can rebuild it from source and check the hashes yourself:
[`VERIFY.md`](VERIFY.md) §0 + [`verify-build.sh`](verify-build.sh).

---

## What it is

Postern Browser takes **Firefox ESR** — the same Gecko engine millions already
run — and ships it with the hardening spine that Postern OS uses internally
(`os/browser.nix`), promoted from an in-OS profile into a standalone, signed,
branding-stripped build for **Postern OS and desktop Linux**.

It is **not** Chromium. It is **not** a new or from-scratch browser engine. It is
**not** a code-fork of Firefox — it is a *distribution* of Firefox ESR with a
patch queue and baked-in config, published from public source.

## What it does (v1)

- **No telemetry.** Mozilla telemetry, Studies, Normandy/Shield, Pocket, crash
  reporting, connectivity checks, and captive-portal probes are disabled at both
  the build/pref and enterprise-policy level. *Caveat (honest):* "no telemetry"
  is a **configuration** claim you confirm by watching the wire on a cold start
  (`VERIFY.md` §C/§G) — it is not a cryptographic attestation that nothing is
  ever sent. Turning captive-portal detection off is a documented trade: hotel/
  airport wifi login pages are harder to catch.
- **Reduces fingerprinting** via `resistFingerprinting` **+ letterboxing** — a
  uniform, spoofed surface (timezone → UTC, locale → en-US, spoofed
  canvas/audio, quantized viewport). *Reduces, does not eliminate.*
- **Strict tracking protection** — Enhanced Tracking Protection on `strict`,
  social-tracking blocked, cryptominer + fingerprinter blocking locked on.
- **Dynamic first-party isolation (dFPI / Total Cookie Protection)** —
  `cookieBehavior = 5`, plus network-state partitioning.
- **HTTPS-only**, including in private windows.
- **WebRTC IP-leak protection** — ICE restricted so STUN cannot expose your
  LAN/host IP; WebRTC stays usable for calls.
- **Encrypted DNS (DoH)** to an **explicitly named** resolver — the desktop
  default is **Mullvad** (`dns.mullvad.net`, no-logging), **fail-closed** (no
  silent fallback to system/ISP DNS; if the resolver is unreachable, resolution
  hard-fails rather than leaking). Postern OS defers instead to the OS/Tor
  resolver (`dohProviderURL=null`). Never a silent Cloudflare default. The DoH
  decision lives in **one** place (`policies.json`); `user.js` does not set
  `trr.*`, so pref, policy, and wire cannot drift.
- **No remote speech-to-text.** Web Speech *recognition* is off — it can stream
  microphone audio to a third-party service. Local text-to-speech is untouched.
- **Ships uBlock Origin** as a separate add-on (`normal_installed`,
  version-pinned in release builds; dev builds track AMO). No other extension is
  user-installable (default `blocked`).
- **No Mozilla account or Sync.** Firefox Accounts is disabled and hidden.

## What it is NOT — read this

- **Not anonymity software.** Your ISP or VPN endpoint still sees which IPs you
  connect to. Anti-fingerprinting **reduces**, it does **not eliminate**,
  tracking — a user on a residential IP with a unique network fingerprint is
  still linkable across sessions by IP and timing. For strong anonymity use the
  **Tor Browser**, the uniformity gold standard. Postern Browser does **not**
  route your traffic through Tor.
- **Not Tor, and Tor is not bundled.** The Postern OS *profile* pairs with the
  OS Tor client; this **standalone** build makes a **direct connection** and
  ships **no** Tor. Do not read any Tor implication into it.
- **Not protection against a logged-in identity.** Sign into an account and you
  are that account. Storage isolation does nothing about voluntary
  identification.
- **Not malware- or exploit-proof.** ESR gets security patches, but a hardened
  config is not a sandbox-escape defense.
- **Not audited.** *Built from public source* is **not** the same as
  *independently security-audited*. This build is **UNAUDITED**.

**Honesty banner (verbatim, on first-run and in About):**
> Postern Browser makes you harder to track. It does **not** make you anonymous,
> and it has **not** been independently audited.

## Expect some breakage — it is intentional

Anti-fingerprinting has visible costs, and they are the trade, not bugs:
- Your timezone reads as **UTC** to sites.
- The window may **letterbox** (padding/quantized size) to hide your real
  viewport.
- Some canvas / WebGL / media sites misbehave; **DRM/EME is off by default**.

Solve compatibility **per-site**, not by disabling `resistFingerprinting` — RFP
is the fingerprinting spine. A build that ships with RFP off to "improve
compatibility" is not Postern Browser.

---

## Allowed / forbidden claims (binding — see `LABELS.md`)

**You MAY say:**
- "Postern Browser — a **hardened distribution** of Firefox ESR (Gecko)."
- "**Reduces** fingerprinting surface via resistFingerprinting + letterboxing."
- "No telemetry, strict tracking protection, HTTPS-only, dynamic first-party
  isolation, WebRTC IP-leak protection, ships uBlock Origin."
- "No Mozilla account or Sync."
- "Built on Firefox ESR under MPL-2.0; uBlock Origin ships as a separate
  GPL-3.0 add-on (aggregation)."
- "Built, not audited — **UNAUDITED**."

**You MUST NOT say:**
- "Anonymous" / "untraceable" / "cannot be tracked" — RFP reduces, never
  eliminates; **Tor Browser** is the uniformity gold standard, not this.
- "Secure browsing" / "private browsing" as an absolute guarantee.
- "Audited" / "secure" / any attestation or reproducibility guarantee — a build
  signature proves *who published*, not *what it was built from*.
- Any surviving "Firefox" / "Mozilla" trademark or logo (legal + honesty).
- Any implied endorsement by Mozilla or the Tor Project.
- "A new browser engine" / "our engine" — it is Gecko.
- Any coin/token value claim. The coin is worthless and stays out of the
  browser entirely.

---

## Licensing

- **Firefox ESR core: MPL-2.0.** Weak, per-**file** copyleft. Every mozilla-esr
  file we modify stays source-available under MPL, headers intact. We publish
  the **full patched source tree** (mozilla-esr + Postern patch queue) at a
  stable URL, reachable from the About surface (`SOURCES.txt`). We do **not**
  claim "all MPL" — the tree also contains Apache-2.0 / BSD / other components;
  see `THIRD-PARTY.md` (reproduced from `about:license`).
- **uBlock Origin: GPL-3.0**, shipped as a **separate WebExtension add-on**
  (mere aggregation, not linked into the binary), version-pinned with its
  GPL-3.0 text and upstream source reference bundled. NoScript, if offered, is
  the same (GPL, opt-in, off by default).
- **No AGPL / SSPL / BUSL / non-commercial / no-license code** anywhere in the
  core or the bundled add-ons. A CI license gate enforces this.

## Build, sign, verify

- Build + branding-strip + sign pipeline: **`build.md`**. The `nixpkgs` input is
  pinned in `postern-browser.nix` (`nixpkgsPin`); fill the pin before a
  rebuild-verifiable build (until then it falls back to the channel with a loud
  trace).
- Positioning + honesty rationale: **`HONESTY.md`** and **`LABELS.md`**.
- **Build-from-source + verify the artifact** (pin inputs, `nix-build`, hash vs
  `SHA256SUMS`, minisign signature, manifest honesty fields): **`VERIFY.md` §0**
  and **`verify-build.sh`**.
- Post-build behavioral checklist (fingerprint, DNS/WebRTC leak, telemetry-off,
  HTTPS-only, branding audit): **`VERIFY.md` §A–§L**.

Distribution artifacts are minisign-signed (the same key infrastructure as the
rest of this repo; a signature proves the publisher, not the contents) and, on
Postern OS, verifiable with **Seal**.

---

*Postern Labs is not affiliated with, endorsed by, or sponsored by Mozilla or
the Tor Project. Hardened, not anonymous. Unaudited. Not Tor.*
