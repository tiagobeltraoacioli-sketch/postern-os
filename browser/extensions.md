# Postern Browser — Bundled Extension Spec (v1)

Bundled add-ons for **Postern Browser**, a hardened distribution of Firefox ESR
(Gecko). This spec is grounded in the Postern OS seed profile
(`os/browser.nix`, which installs uBlock Origin via `ExtensionSettings`) and the
compliance/trademark counselor spec.

## Governing principle: aggregation, never linking

Every bundled add-on ships as a **separate WebExtension `.xpi`** that the browser
loads at runtime through the stable extension API. A WebExtension is a **separate
program**, not a derivative work of the browser binary. This is **mere
aggregation** (GPL-3.0 §5), so a **GPL-3.0** add-on can ride alongside the
**MPL-2.0** browser core without either license contaminating the other.

**Red lines (from the compliance counselor):**
- Never statically compile, inline, or link an add-on's source into the browser
  binary. Keep the aggregation boundary clean — no shared linkage, no
  recompilation into the Gecko tree.
- Never ship a GPL add-on without its **GPL-3.0 license text + a reachable
  corresponding-source reference** (upstream URL + the exact pinned version).
- **Zero AGPL-3.0 / SSPL / BUSL / non-commercial / no-license** code in the core
  or in any bundled add-on. GPL-2.0/3.0 is allowed by aggregation only.
- If you **patch** an add-on and redistribute the modified `.xpi`, you inherit
  GPL source obligations **for that add-on** — publish the modified source under
  GPL-3.0. v1 ships add-ons **unmodified** to avoid this.

## Reproducibility: pin exact XPIs + hashes

The seed uses an AMO `.../latest.xpi` URL. That is acceptable for an in-OS
profile, but a **signed, reproducible standalone distribution must pin the exact
`.xpi` version and its hash** so the shipped bits match the disclosed source. Do
**not** hot-pull `latest` in a release build.

For each add-on, the build records: extension ID, pinned version, download URL
for that exact version, and a SHA-256 of the `.xpi`. (Concrete versions/hashes
are filled in by the build/sign lot at pin time; leave them as `TODO(pin)`
placeholders here rather than inventing values.)

---

## 1. uBlock Origin — REQUIRED, installed + enabled

| Field | Value |
|---|---|
| Extension ID | `uBlock0@raymondhill.net` |
| Author | Raymond Hill (gorhill) |
| License | **GPL-3.0** |
| Role in v1 | **Required.** Content/ad/tracker blocking. |
| Install mode | `normal_installed` (installed and enabled by default) |
| Source (upstream) | https://github.com/gorhill/uBlock |
| Pinned version | `TODO(pin)` — exact version string |
| Pinned XPI URL | `TODO(pin)` — versioned `.xpi`, not `latest.xpi` |
| SHA-256 | `TODO(pin)` |

**Why bundled:** ad/tracker network blocking is core to the hardening posture and
is the one add-on the seed already ships. Default filter lists are used as-is.

**Filter-list hygiene:** do **not** add custom filter lists that phone home to
infrastructure Postern does not control. Stock uBlock default lists only.

**Licensing:** GPL-3.0, shipped as a **separate `.xpi`** — aggregation, not
linked. The distribution must include uBlock's GPL-3.0 text and a
corresponding-source reference (upstream + pinned version) in `THIRD-PARTY.md` /
`about:license`, flagged as:

> uBlock Origin (© Raymond Hill), **GPL-3.0**, bundled as a separate add-on
> (aggregation). Source: `<upstream>` @ `<pinned version>`.

Policy install entry (promoted from the seed, with a **pinned** URL):

```json
"uBlock0@raymondhill.net": {
  "installation_mode": "normal_installed",
  "install_url": "https://<pinned-versioned-xpi-url>"
}
```

---

## 2. NoScript — OPTIONAL, OFF by default

| Field | Value |
|---|---|
| Extension ID | `{73a6fe31-595d-460b-a920-fcc0f8843232}` |
| Author | Giorgio Maone |
| License | **GPL-3.0** (not AGPL — safe by aggregation, same as uBlock) |
| Role in v1 | **Optional.** Per-site JavaScript / active-content control. |
| Install mode | Available to install, **not force-installed, not enabled globally** |
| Source (upstream) | https://github.com/hackademix/noscript |
| Pinned version | `TODO(pin)` |
| Pinned XPI URL | `TODO(pin)` — versioned `.xpi` |
| SHA-256 | `TODO(pin)` |

**Why off by default:** forcing NoScript globally breaks the modern web and
raises breakage/support cost, hurting adoption. uBlock's advanced/medium mode
already covers much of the same ground. NoScript is offered as **opt-in** for
users who want per-site JS control.

**If bundled:** use `installation_mode = "normal_installed"` **without** forcing
enable-on-all-sites — the user opts into blocking. Same GPL-3.0 aggregation
treatment as uBlock: separate `.xpi`, license text + pinned source in
`THIRD-PARTY.md`, version + hash pinned.

> **Open founder decision (#4):** ship NoScript in v1 at all, or uBlock-only?
> Default recommendation is uBlock-only for v1 to minimize breakage; this entry
> documents the correct treatment **if** it is included.

---

## Do NOT bundle

- Any add-on that makes an **outbound connection to infrastructure Postern does
  not control** (defeats the no-phone-home posture).
- Any **AGPL-3.0 / SSPL / BUSL / non-commercial / no-license** add-on (license
  red line — network-triggered copyleft is toxic to the browser and to Postern's
  service lines).
- A **modified** third-party `.xpi` without publishing its modified source under
  the add-on's license.

## Related prefs (see `user.js`)

- `xpinstall.signatures.required = true` — signed extensions only; never disable.
- `extensions.htmlaboutaddons.recommendations.enabled = false` and
  `extensions.getAddons.showPane = false` — no AMO recommendation/discovery
  network features.

## Honest labels for the extension surface

- Allowed: "ships **uBlock Origin**", "bundled as a separate GPL-3.0 add-on
  (aggregation)", "NoScript available, off by default".
- Forbidden: implying the add-ons make you "anonymous" or "untraceable", or that
  bundling them equals an audit. Hardened, not anonymous; unaudited; not Tor.
