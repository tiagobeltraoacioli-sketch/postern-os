# Postern Browser v1 — Verification Checklist

**Run this before calling any build "hardened", and before signing/publishing.**
This is a **behavioral** checklist: you launch the built browser and *observe*
what it does. "It compiled" is not on this list. **Built ≠ verified ≠ audited** —
passing this checklist means the hardening is *present and working*, not that the
browser is *secure* or *anonymous*.

Ground truth for the expected values: Lot B's `user.js` + Lot A's
`policies.json` + Counselor 1's hardening spec (`os/browser.nix` §4/§7). If an
observed value disagrees with those, the build is wrong — fix the build, do not
edit this checklist to match.

Record each result as **PASS / FAIL / N-A** with the observed value in a run log
attached to the release manifest. Any FAIL is a ship-blocker.

---

## 0. Build from source, then verify the artifact

Everything below (§A–§L) inspects a *running* browser. This section is the step
before that: **rebuild the artifact from public source and check the bits.** It
is what lets someone who does not trust our published binary reproduce the build
inputs and compare hashes for themselves.

### 0.1 Pin, then build

1. Get this tree at the exact release commit (the `postern_patch_queue_commit`
   in `build-manifest.json`).
2. **Fill the pins.** A build is only rebuild-verifiable when its inputs are
   pinned. Confirm none are left as `TODO(pin)`:
   - `postern-browser.nix` — the `nixpkgsPin` `rev` + `sha256` (the nixpkgs
     input). While these read `TODO(pin)`, the build falls back to the ambient
     channel and prints a loud trace: that build is **not** rebuild-verifiable.
   - `build.md` §2 — `mozilla_esr_commit` + `postern_patch_queue_commit`.
   - `extensions.md` / `policies.json` — the uBlock Origin pinned version + xpi
     sha256 (a release must pin the exact `.xpi`, never `latest.xpi`).
3. Build the package (dev wrap build — see the BRANDING note in
   `postern-browser.nix`; a *published* artifact additionally needs Lot C's
   source-level brand strip, `build.md` §3):
   ```
   nix-build postern-browser.nix -A package
   ```

### 0.2 Verify the published artifact

`verify-build.sh` automates this; run it or do it by hand:

1. **Hash** every downloaded artifact and compare to the published
   `SHA256SUMS`:
   ```
   sha256sum -c SHA256SUMS
   ```
2. **Verify the signature** of `SHA256SUMS` against the **published** minisign
   public key (not one shipped inside the download):
   ```
   minisign -Vm SHA256SUMS -P <published-minisign-pubkey>
   ```
3. **Check the manifest honesty fields** — `build-manifest.json` must carry
   `reproducible=false`, `attestable=false`, `audited=false`, `status=BUILT`,
   and its artifact sha256 must equal the on-disk artifact (this is the same
   guard the R2 publisher enforces, `build.md` §5).

### 0.3 Reproducibility caveat — read this, do not overclaim

- Pinning the nixpkgs input + the ESR commit + the uBlock xpi hash makes the
  build **repeatable-by-design** and the **source reachable**. It does **not**
  make it **bit-for-bit reproduced**. Firefox builds are not trivially
  reproducible; Postern Browser v1 does not claim they are
  (`build.md` §7; manifest `reproducible=false`).
- A matching sha256 between **your** rebuild and ours is meaningful, but it is
  **not** an independent reproduction until an independent party publishes a
  matching rebuild — and it is never an **audit**. A signature (§0.2 step 2)
  proves **who published**, not **what was built** or that it is safe.
- Passing §0 means *the inputs are pinned and the published bits match the
  published hashes+signature* — **not** "reproducible", "attested", "secure", or
  "anonymous". Keep the labels honest: **hardened, not anonymous; not Tor;
  UNAUDITED.**

---

## A. Locked prefs — `about:config` spot-check

Open `about:config` and confirm each is set **and locked** (the pencil/edit
control is disabled; value came from autoconfig, not the profile):

| Pref | Expected |
|---|---|
| `privacy.resistFingerprinting` | `true` |
| `privacy.resistFingerprinting.letterboxing` | `true` |
| `privacy.fingerprintingProtection` | `true` |
| `network.cookie.cookieBehavior` | `5` (dFPI) |
| `privacy.partition.network_state` | `true` |
| `privacy.firstparty.isolate` | `false` (dFPI supersedes; must NOT be stacked) |
| `browser.contentblocking.category` | `strict` |
| `dom.security.https_only_mode` | `true` |
| `dom.security.https_only_mode_pbm` | `true` |
| `media.peerconnection.ice.no_host` | `true` |
| `media.peerconnection.ice.default_address_only` | `true` |
| `media.eme.enabled` | `false` (DRM off — expect breakage) |
| `identity.fxaccounts.enabled` | `false` |
| `media.webspeech.recognition.enable` | `false` (no remote speech-to-text) |
| `network.trr.mode` | **set by the DNSOverHTTPS policy, not user.js** — `3` (DoH on, strict/no-fallback) on the desktop default; `5` (off) on the Postern OS `dohProviderURL=null` variant |
| `network.trr.uri` | the **named** resolver `https://dns.mullvad.net/dns-query` when DoH on; empty when off |

**PASS** = all present and locked. A pref that is present but *editable* is a
FAIL — it means it landed as a profile default, not a build-time lock.

> **DoH is policy-owned, by design.** `user.js` deliberately does **not** set
> `network.trr.*`; the enterprise `DNSOverHTTPS` policy (§B) is the single source
> of truth and sets/locks the trr prefs itself. This is what keeps the pref, the
> policy, and the wire (§E) from drifting across the two build variants. If you
> find `network.trr.mode` set from `user.js` *and* from policy, that is the old
> drift bug — FAIL.

## B. Policy set — `about:policies`

Open `about:policies` → **Active** tab. Confirm the enterprise policy set from
Lot A is live:
- `DisableTelemetry`, `DisableFirefoxStudies`, `DisablePocket`,
  `DisableFormHistory` — present.
- `DisableFirefoxAccounts` = true (no FxA / Sync).
- `EnableTrackingProtection` = {Value true, **Locked**, Cryptomining,
  Fingerprinting}.
- `DNSOverHTTPS` — on the desktop default: **Enabled = true**, **Provider =
  `https://dns.mullvad.net/dns-query`**, **Locked = true**, **Fallback = false**
  (fail-closed: no silent leak to system/ISP DNS). On the Postern OS
  `dohProviderURL=null` variant: **Enabled = false, Locked = true** (DNS deferred
  to the OS/Tor resolver). The Provider/mode here must match §A `network.trr`
  exactly — the DoH decision is consistent across policy, pref, and wire (§E).
- `OverrideFirstRunPage` and `OverridePostUpdatePage` — empty (no Mozilla
  first-run / "what's new" phone-home).
- `DisableAppUpdate` **or** `AppUpdateURL` — matches the frozen update posture
  (`build.md` §6); if an update URL is set it is **Postern's**, never Mozilla's.
- `ExtensionSettings` — uBlock Origin `normal_installed`.

## C. No outbound to Mozilla infra — cold-start capture

Capture network on a **cold first launch** (new profile), before touching the
UI. Use `mitmproxy`, Wireshark, or `sudo tcpdump -n 'port 443 or port 80'`.

**Expect ZERO connections to:** `*.telemetry.mozilla.org`,
`*.mozilla.com`/`*.mozilla.org` telemetry/Normandy/Shield/Pocket endpoints,
`crash-stats` / `crash-reports*`, `location.services.mozilla.com`,
`*.services.mozilla.com` (FxA/Sync), `detectportal.firefox.com` /
`*/canonical.html` (captive-portal probe), the connectivity-check endpoint, and
`aus*.mozilla.org` (AUS update) unless the frozen posture is a *Mozilla*-hosted
update (it must not be).

Any DoH/DNS traffic must go **only** to the named resolver from §A (or, if DoH
is off, to the OS resolver — never plaintext to a Mozilla host). **Any hit to a
Mozilla telemetry/experiment/crash/location/connectivity endpoint is a FAIL.**

## D. WebRTC IP-leak test

Visit `https://browserleaks.com/webrtc` and `https://ipleak.net` (WebRTC
section):
- **No local/host IP** (no `192.168.*` / `10.*` / `*.local` / mDNS host
  candidate) is exposed.
- Public IP exposure via WebRTC should be no worse than the direct connection
  itself (remember: v1 is a **direct connection**, not Tor — the public IP is
  *expected* to be your real one; only the **local/host** leak must be absent).

## E. DNS leak test

Visit `https://dnsleaktest.com` (extended test) or
`https://browserleaks.com/dns`:
- Resolver shown is the **named, pinned** DoH resolver from §A
  (`dns.mullvad.net`) — **or**, if the build is the DoH-off variant, the OS/Tor
  resolver. **Never** the ISP's plaintext system DNS while the browser claims
  DoH-on.
- The shipped default is **`Fallback = false` (mode 3, fail-closed)**: there is
  **no** silent fallback to system DNS, so a DoH outage HARD-FAILS resolution
  rather than leaking — confirm no plaintext system-DNS queries appear during a
  forced-resolver-down test. If a build ever ships `Fallback = true` / mode 2
  instead, a fallback to system DNS is *possible* and **must** be disclosed in
  the run log and docs (Counselor 1 §4.4), never hidden — but that is **not** the
  v1 default.

## F. Fingerprint check (expect "reduced", not "invisible")

Visit `https://coveryourtracks.eff.org` and `https://browserleaks.com`
(JavaScript / Canvas / Fonts panels):
- Timezone reports **UTC**.
- Canvas / audio readings are **spoofed/uniform** (RFP), not device-unique.
- Viewport is **letterboxed** (quantized; resize the window and watch it snap to
  stepped sizes with padding).
- Language reports **en-US**.

**Expected result is "you have some protection / partially protects you",
NOT "your browser has a unique fingerprint = you are anonymous."** A result that
says "randomized/unique every load" is *fine*; a claim of anonymity is **not** —
RFP reduces, it does not eliminate. This step PASSES when the spoofing is
*present*; it does not and cannot prove anonymity.

## G. Telemetry-off proof — `about:telemetry`

- `about:telemetry` shows recording/upload **disabled** ("Telemetry is disabled"
  or no pings queued).
- `about:studies` shows Studies + Shield **off**, no active/past studies.
- Combined with the §C capture, this is the belt-and-suspenders proof (pref +
  policy + no wire traffic).

## H. HTTPS-only enforcement

- Navigate to a plain `http://` URL (e.g. `http://neverssl.com`): the browser
  shows the **HTTPS-only "Secure Connection Not Available" interstitial**, not a
  silent plaintext load.
- Repeat in a **private window** — the interstitial must also appear
  (`https_only_mode_pbm`).

## I. Extension posture

- `about:addons` shows **uBlock Origin installed and enabled**, and its
  **version matches** the pinned version + sha256 in the build manifest
  (`build.md` §2). Install mode is **`normal_installed`** (installed + enabled by
  default; the user *may* disable it — this is the documented posture, not
  `force_installed`).
- The default `"*"` rule is `installation_mode: blocked`, so **no other
  extension can be user-installed** — confirm an arbitrary AMO install is
  refused, while uBlock is present.
- `xpinstall.signatures.required` = `true` (signature enforcement never
  disabled).
- No bundled add-on makes an outbound connection you do not control; none is
  AGPL.

## J. Branding audit (trademark ship-blocker)

Zero surviving Mozilla marks outside license/attribution text:
- **UI:** window title, task-switcher name, menus, `.desktop` name all read
  **"Postern Browser"** — no "Firefox".
- **About dialog / `about:` pages:** no Firefox logo/wordmark; the About text
  carries the required line *"a hardened distribution built on Mozilla Firefox
  ESR (Gecko) … Not affiliated with or endorsed by Mozilla."*
- **`about:rights` / `about:logo`:** no Firefox logo bitmaps.
- **Updater strings** (if an updater ships): "Postern Browser", not "Firefox".
- Static scan (from `build.md` §3.5) returns **zero** `Firefox`/`Mozilla` hits
  outside `about:license` / `THIRD-PARTY` / `SOURCES` / `LICENSE` / the
  "built on" attribution.

Any surviving Firefox trademark/logo in binary, installer, icons, `about:`
pages, or `.desktop` is a **hard FAIL** — do not sign or publish.

## K. Source + license reachability (MPL/GPL obligations)

- `SOURCES.txt` (or an About link) points to the **full patched source tree** at
  a live, reachable URL; the linked commit matches the build manifest's
  `mozilla_esr_commit` + `postern_patch_queue_commit`.
- `THIRD-PARTY.md` / `about:license` lists uBlock Origin as **GPL-3.0**, bundled
  as a separate add-on (aggregation), with its source reference + pinned
  version.
- License scan shows **no AGPL / SSPL / BUSL / non-commercial / no-license**
  component.

## L. Signature + manifest (publish gate)

- `SHA256SUMS` covers every artifact; `SHA256SUMS.minisig` verifies against the
  **published** minisign public key.
- `build-manifest.json` carries the honest-status fields — `reproducible=false`,
  `attestable=false`, `audited=false`, `status=BUILT` — and the artifact sha256
  matches. The R2 publisher must **refuse** a manifest missing these
  (`build.md` §5).
- On Postern OS: **Seal** verifies the download.

---

## Sign-off

A build is "verified for v1" only when **§0 and A–L all PASS** (or a documented,
justified N-A), the run log is attached to the release manifest, and every
surface still reads **hardened, not anonymous; unaudited; not Tor.**

Verified is still **not audited.** Nothing in this checklist substitutes for an
independent security audit, and no result here may be described as one.
