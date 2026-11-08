# Postern Browser v1 — Branding-Strip + Build + Sign Pipeline

**Lot C deliverable (packaging owner).** This document is the reproducible-ish
build recipe for **Postern Browser** — a hardened *distribution* of Firefox ESR
(Gecko), in the LibreWolf / Mullvad Browser class. It is **not** a from-scratch
engine, **not** Chromium, and **not** a code-fork. v1 rebuilds the mozilla-esr
tree with baked-in hardening config and a full Mozilla-brand strip, then signs
and publishes the artifact.

Ground truth for the *config* payload: `os/browser.nix` (the in-OS hardened
profile). Ground truth for the *hardening spine*: Lot B's `user.js` +
`autoconfig`. Ground truth for the *policies*: Lot A's `policies.json`. This
file only owns the **branding strip, the build invocation, and the signing /
publish pipeline** — it does not define prefs or policies.

> **Read before building anything:** `HONESTY.md` (Lot C), `LABELS.md` (Lot C),
> and the repo-root honesty culture in `pmos-overlay/HONESTY.md`. A build
> signature proves *who published*, never *what it was built from*. "Built" ≠
> "reproducible" ≠ "audited". Do not let any artifact imply otherwise.

---

## 0. Decisions that must be frozen at kickoff (blockers for this pipeline)

This pipeline cannot produce a publishable artifact until these are pinned. They
are listed as inputs here; the *decision* is a shared kickoff item, not Lot C's
to make alone.

| Input | Needed for | Status |
|---|---|---|
| **Exact ESR base** (mozilla-esr commit hash + ESR line, e.g. `140.x`) | source manifest, reproducibility notes | PIN AT KICKOFF |
| **Product name string** (`"Postern Browser"`) | branding strip | locked by plan |
| **App ID** (`MOZ_APP_ID`, own value, never Mozilla's) | update/telemetry non-impersonation | PIN AT KICKOFF |
| **Update posture** (`DisableAppUpdate` + OS channel **vs** own signed updater) | sign pipeline shape | PIN AT KICKOFF (see §6) |
| **DoH resolver** (pinned resolver **vs** off) | must match Lot A/B; not a Lot C decision | PIN AT KICKOFF |
| **Signing key** (minisign, same infra as `pmos-overlay/publish-to-r2.sh`) | §5 | PIN AT KICKOFF |

Until the ESR commit hash and app ID are pinned, this document builds a
**scaffold**, not a release. Say so on any page, exactly as the repo's other
distribution channels do.

---

## 1. Build strategy (v1 = source rebuild of the unbranded target)

Two options were on the table (PMO open decision #3):

- **(A) Wrap `nixpkgs` `firefox-esr`** (`wrapFirefox` + `extraPolicies` +
  `extraPrefsFiles`) — fast, but you inherit **stock Firefox branding** in the
  binary. The wrap can add policies/prefs and even swap the `.desktop` name, but
  the compiled-in `MOZ_APP_DISPLAYNAME`, the about-dialog art, `about:rights`,
  and the Firefox logo bitmaps **survive**. That is a trademark ship-blocker
  (Counselor 2, T1). A wrap is acceptable only for an *internal, unpublished*
  smoke-test build, never for a released artifact.

- **(B) Source rebuild from the unofficial branding target** — heavier, but it
  is the only path that yields a clean brand strip and a true redistributable
  *distribution*. This is what LibreWolf and Mullvad Browser do.

**v1 decision: build (B) for anything published; (A) is dev-only.** The rest of
this document is (B).

The build is driven from Nix for repeatability of the *toolchain and inputs*
(matching the repo's Nix posture), but the honest claim ceiling is
"repeatable-ish", not "reproducible" — see §7.

---

## 2. Source acquisition + manifest (MPL obligation)

MPL-2.0 is per-**file** copyleft: every mozilla-esr file we modify must be
source-available under MPL, and MPL headers must never be stripped (Counselor 2,
L1). We do not surgically release touched files — we **publish the whole patched
tree**, LibreWolf-style. It is cheaper and it makes "built from public source"
*true and reachable* (L2).

1. Fetch the exact ESR tag/commit pinned at kickoff:
   ```
   hg clone https://hg.mozilla.org/releases/mozilla-esr<NN> \
     && hg update FIREFOX_ESR_<NN>_<X>_RELEASE     # or the git mirror + commit hash
   ```
2. Record a **machine-readable source manifest** next to the artifact:
   ```json
   {
     "product": "Postern Browser",
     "built_on": "Mozilla Firefox ESR",
     "esr_line": "<NN>",
     "mozilla_esr_commit": "<40-hex>",
     "postern_patch_queue_commit": "<hash>",
     "ublock_origin_version": "<x.y.z>",
     "ublock_origin_xpi_sha256": "<hash>",
     "reproducible": false,
     "attestable": false,
     "audited": false
   }
   ```
   This mirrors the `build-manifest.json` honesty fields the repo's R2 publisher
   already enforces (`reproducible=false`, `attestable=false`), so the same
   guard rails apply.
3. Publish the full patched tree (mozilla-esr + Postern patch queue) at a stable
   URL and link it from `about:` and `SOURCES.txt` in the package (L2, L4).
4. Reproduce the tree's own license inventory (`about:license`) — **do not
   assert "all MPL"**; parts are Apache-2.0 / BSD / other (L3). Run a license
   scan and ship the result as `THIRD-PARTY.md`.

---

## 3. Branding strip (trademark-mandatory — ship-blocker)

**MPL grants no trademark rights (MPL §2.3).** You may copy and modify the code;
you may **not** ship it as "Firefox" or carry the Firefox/Mozilla logos
(Counselor 2, §2). Start from Mozilla's own **unofficial** branding target — do
not hand-strip the official one.

### 3.1 Build-config switches
```
ac_add_options --with-branding=browser/branding/unofficial   # or Postern branding dir
ac_add_options --disable-official-branding
export MOZ_OFFICIAL_BRANDING=          # unset / off
export MOZ_APP_DISPLAYNAME="Postern Browser"
export MOZ_APP_BASENAME="PosternBrowser"
export MOZ_APP_VENDOR="Postern Labs"
export MOZ_APP_ID="{<own-uuid-pinned-at-kickoff>}"   # NEVER a Mozilla app ID
```

### 3.2 Assets to replace (Postern art supplied by branding/)
- `browser/branding/**` — app icon, about-dialog logo, installer art,
  `default*.png`, `.ico` / `.icns`. **Delete** the Firefox logo bitmaps; do not
  merely overlay.
- `.desktop` name, window titles, task-switcher name → **"Postern Browser"**.
- `about:` pages that render Mozilla marks: About dialog, `about:rights`,
  `about:logo`. Substitute the Postern posture text (see §3.3).
- Every "Firefox" / "Mozilla" wordmark in menus, first-run, error pages, and
  **updater strings**.

### 3.3 Mandatory attribution + disclaimer (honesty + nominative use)
Put this in the About dialog (`about:` page) and `README.md`. "Firefox ESR /
Gecko" is used only as a **descriptor of what it is built from** — legal
nominative use, never as the product name/logo (Counselor 2, T2/T3):
> **Postern Browser** — a hardened distribution built on **Mozilla Firefox ESR**
> (Gecko engine). A Postern Labs product. **Not affiliated with, endorsed by, or
> sponsored by Mozilla.**

### 3.4 Non-impersonation of Mozilla infra (T4)
- Own `MOZ_APP_ID`, own update URL (or `DisableAppUpdate`), own/blank telemetry
  and crash endpoints. Never point at or reuse Mozilla's update, telemetry,
  AMO-signing, connectivity-check, or crash-report endpoints. (These are also
  enforced as prefs/policies in Lot A/B — this pipeline must not *re-enable* any
  of them via branding defaults.)

### 3.5 Branding-audit gate (must pass before §5 signing)
```
# zero hits required in the built tree (outside license/attribution text):
grep -RIl --exclude-dir=.git -e 'Firefox' -e 'Mozilla' <dist-root>/ \
  | grep -vE '(about:license|THIRD-PARTY|SOURCES|LICENSE|built on)'
```
Any surviving Firefox wordmark/logo in the **binary, installer, icons, `about:`
pages, or `.desktop`** is a hard fail. See `VERIFY.md` §Branding.

---

## 4. Config bake-in (consumes Lot A + Lot B outputs)

This pipeline does not *author* prefs or policies; it *installs* them into the
distribution tree so they are build-time defaults + locked, not a user profile
(Counselor 1, §4/§5):

- **Locked prefs** → `autoconfig`: ship `defaults/pref/autoconfig.js`
  (`general.config.filename = "postern.cfg"`,
  `general.config.obscure_value = 0`) + `postern.cfg` (a `mozilla.cfg`
  autoconfig file that `lockPref(...)`s Lot B's `user.js` spine, including
  `privacy.resistFingerprinting.letterboxing = true`).
- **Enterprise policies** → `distribution/policies.json` = Lot A's
  `policies.json` verbatim (DoH resolver already pinned per the shared
  decision).
- **Bundled add-on** → Lot B's pinned uBlock Origin `.xpi` (exact version +
  sha256), installed via `ExtensionSettings` as a **separate GPL-3.0 add-on**
  (aggregation, flagged in `THIRD-PARTY.md`), never linked into the binary
  (Counselor 2, G1/G2). NoScript, if shipped, same treatment, off by default.
- **License gate (CI):** SBOM + allowlist scan; **fail on any AGPL / SSPL /
  BUSL / non-commercial / no-license** dependency in core or add-ons (Counselor
  2, A1).

---

## 5. Signing + publish (reuse the repo's minisign + R2 pipeline)

Signing proves **who published**, not what was built. Use the exact model the
repo already uses in `pmos-overlay/publish-to-r2.sh`: a minisign-signed
`SHA256SUMS`, artifacts uploaded so the **signature is written last** (the
authenticating "flip"), and honest-status labels enforced in the manifest.

1. Build the artifact (§1–4) → `postern-browser-<ver>-linux-x86_64.tar.zst`
   (and/or the OS-native package).
2. Compute `SHA256SUMS` over all artifacts for the release prefix.
3. Sign with minisign:
   ```
   minisign -Sm SHA256SUMS -x SHA256SUMS.minisig     # secret key from env/agent, never in repo
   ```
   Publish the **public** key alongside docs so recipients can verify; on
   Postern OS this pairs with **Seal** download-verification
   (`crates/postern-seal-companion`).
4. Publish to R2 in fail-safe order (clients verify sig → SHA256SUMS →
   artifact, so the sig is last):
   ```
   1. postern-browser-<ver>-<arch>.tar.zst        # immutable, long cache
   2. postern-browser-<ver>.build-manifest.json    # §2 manifest (operator record)
   3. SHA256SUMS                                    # short cache
   4. SHA256SUMS.minisig                            # the flip — LAST
   ```
   Bucket / host / prefix follow the repo layout (`postern-downloads`, the
   `pub-…r2.dev` host), under a `browser/<ver>/` prefix.
5. **Hard guards (copy the publisher's honesty enforcement):** refuse to upload
   unless the manifest carries `reproducible=false`, `attestable=false`,
   `audited=false` and a `status` of `BUILT`; refuse if the on-disk artifact
   sha256 ≠ manifest; refuse if the minisign secret key ≠ the published public
   key. A scaffold manifest must be rejected, not published.

`sign.sh` (the executable Lot C ships) is a thin wrapper over this order,
delegating multipart upload to the existing `build/r2_upload.py` used by the
image publisher.

---

## 6. Update channel (kickoff decision #2)

Two honest options; pick one at kickoff, wire it here:

- **(A) `DisableAppUpdate = true` + OS/package channel.** Cleanest for Postern
  OS: no in-app updater, updates ride the signed OS repo (Seal-verified). On
  desktop Linux, ship via the signed R2 channel + distro package; the browser
  never phones an update server.
- **(B) Own signed updater.** Point `AppUpdateURL` at a Postern-controlled,
  minisign/keypair-verified endpoint. More moving parts and a bigger key-custody
  surface; only take it if in-app auto-update is a hard product requirement.

Either way: **never** point the updater at Mozilla infra (T4), and whichever is
chosen must match Lot A's `DisableAppUpdate` / `AppUpdateURL` policy exactly.

---

## 7. Reproducibility notes (honest ceiling)

- The Nix-driven build pins the **toolchain and inputs**, and §2 pins the
  mozilla-esr commit + patch-queue commit + uBlock version/hash. That makes the
  build **repeatable-ish**, and it makes the source **reachable** — it does
  **not** make it **bit-for-bit reproducible** or **attestable**. Firefox builds
  are not trivially reproducible; do not claim they are.
- The manifest therefore carries `reproducible=false` and `attestable=false`,
  and the publisher refuses any manifest that omits them — the same enforcement
  point the rest of the repo uses (`pmos-overlay/HONESTY.md`,
  `publish-to-r2.sh`).
- Mullvad Browser sets the reproducible-build bar; matching it is a **later**
  goal, not a v1 claim. If/when we get there, it is proven with a public
  rebuild-and-compare (cf. the repo's `repro-compare.sh` posture), not asserted.
- **A signature is not an audit.** "Built from public source" ≠ "independently
  security-audited." Every surface says **UNAUDITED**.

---

## 8. Pipeline summary (one screen)

```
pin ESR commit + app id + update posture + DoH resolver + signing key   (kickoff)
      │
fetch mozilla-esr@<commit>  →  apply Postern patch queue  →  write source manifest
      │
build --with-branding=unofficial, MOZ_APP_DISPLAYNAME="Postern Browser", own MOZ_APP_ID
      │
strip Mozilla marks (icons, about:, .desktop, updater strings)  →  branding-audit gate (§3.5)
      │
bake config: autoconfig(postern.cfg=Lot B) + policies.json(Lot A) + uBlock .xpi(pinned)
      │
CI license gate (no AGPL/SSPL/BUSL/no-license)   →   THIRD-PARTY.md + SOURCES.txt
      │
run VERIFY.md behavioral checklist  ← "built" is NOT "verified"
      │
SHA256SUMS  →  minisign -S  →  R2 publish (sig written LAST)  →  Seal-verifiable
```

**Bottom line:** rebuild the unbranded ESR target, strip every Mozilla mark,
bake in Lot A/B's hardening, ship uBlock as a separate flagged GPL add-on, sign
with the repo's minisign key, and label it **hardened, unaudited, not
anonymous** everywhere.
