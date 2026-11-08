# REPO-HARDENING — review of the APKBUILDs + the publish pipeline

**Read `HONESTY.md`, `PUBLISHED.md`, and `KEYS.md` first.** This is *Postern for
postmarketOS — community edition*, never "Postern OS". Nothing here is
reproducible or attested; signatures prove **who published** and **unmodified in
transit**, nothing more. The coin is worthless and none of this is a
security/financial/legal claim.

This document is the hardening review of the three deliverables item 3 names —
**checksums, pinned source tags, index signing** — across the APKBUILDs and the
publish pipeline. Where a fix is safe and additive it is **applied and noted**;
where it touches an APKBUILD or `publish-to-r2.sh` (owned by other devs and
repeatedly flagged "not changed here" throughout this overlay), it is a
**recommendation for the owners**, not a silent edit.

---

## 1. Checksums

### Findings (current state)

| Package | `source=` | `sha512sums=` | Verdict |
|---|---|---|---|
| `postern-wallet` | R2-mirrored `BlochSISPoW-project-v0.1.0-alpha1.tar.gz` | pinned (real sha512) | **hardened** — a fixed sha512 over a fixed tarball is a strong content anchor |
| `postern-apps` | R2-mirrored `bloch-sis-project-v0.1.0-alpha1.tar.gz` | pinned (real sha512) | **hardened** — same |
| `postern` (meta) | empty (`source=""`) | empty (correct) | **correct** — meta packages have no source; `abuild checksum` regenerates only for install scripts |

`abuild` **fails the build** if a downloaded source's sha512 does not match
`sha512sums=`, so the pin is enforced at build time, not merely advisory. The
wallet/apps tarballs are already served from R2 with those exact hashes.

### Residual risk + recommendation (for the APKBUILD owners)

- **Mirror-of-record, not upstream-of-record.** Both sources point at the R2
  mirror because the upstream GitLab repos are private. That is a pragmatic
  necessity, but it means the sha512 anchors the *mirror copy*, not a
  publicly-fetchable upstream tag. When the upstream tags become fetchable, the
  APKBUILD comments already carry the "expected final form" pointing at
  `…/-/archive/v$pkgver/…`; switch to it and re-run `abuild checksum` so the pin
  anchors the canonical upstream archive.
- **`postern.post-install` is checksummed too.** `abuild checksum` on the meta
  regenerates `sha512sums` to cover the install script; run it before publish so
  a tampered post-install cannot slip through.

---

## 2. Pinned source tags

### Findings

- `postern-wallet` and `postern-apps` are anchored to the **`v0.1.0-alpha1`
  prerelease tag** of their upstreams (encoded in the tarball name + `builddir`),
  and the wallet additionally pins the Rust build to the upstream `Cargo.lock`
  via `cargo fetch --locked` + `cargo build --frozen` (no floating crate
  resolution). This is a solid, reproducible-*ish* pin at the source level.
- The pmOS **image** build pins further: `build/build.sh` records the
  pmbootstrap version, the **pmaports git commit**, the full resolved apk-world,
  the signing-key sha256, and the resolved published-package versions into
  `build-manifest.json`. Re-running with the same pins yields a *functionally
  equivalent* image — **not** a bit-identical one (Alpine/pmOS is not
  reproducible; this is the honest ceiling).

### Recommendation

- **`alpha1` is a prerelease pin, by design.** Do not present it as a release
  anchor. Adopting a real `v$pkgver` release tag (and the stable signing key,
  `KEYS.md`) is the documented prerequisite before recommending the repo broadly
  (`PUBLISHED.md`).
- **Pin the toolchain channel** in CI (the Alpine `rust`/`cargo` version) so the
  wallet's musl link (`-z stack-size=0x100000`, the Falcon stack fix) is built
  against a known toolchain; record it alongside the manifest pins.

---

## 3. Index signing

This is where the pipeline had a real **gap**, now closed.

### Finding: the documented apk publisher did not exist

`DISTRIBUTION.md` describes an apk-repo publisher invoked as
`publish-to-r2.sh -b <branch> -r <repo-tree> -k <pubkey>`, with fail-safe
ordering keyed on the **signed `APKINDEX.tar.gz`** as the client-visible flip.
But the actual `publish-to-r2.sh` in this directory is the **image** publisher
(`-i/-m/-s`, System B). No script implemented the apk-repo (System A) flow the
document specifies — so index-signing hardening lived only on paper.

### Fix: `publish-apk-repo.sh` (added here)

A dedicated apk-repo publisher that enforces the index-signing rules
concretely:

- **Signature-presence + name-match.** For every arch, the `APKINDEX.tar.gz`
  must contain a `.SIGN.RSA.<name>` member whose `<name>` equals the `-k`
  pubkey's basename. `apk` resolves the signature by that exact filename against
  `/etc/apk/keys/<name>`, so a name mismatch means clients can never verify —
  the script refuses to publish it.
- **Write-once key.** `keys/<name>` is uploaded once; if a *different* object
  already exists under that name the publish aborts (rotation = a new filename,
  never an overwrite — `KEYS.md` §5).
- **Immutable apks.** An existing remote `*.apk` of a different size aborts the
  publish (bump `pkgrel`, never republish changed bytes under the same
  `pkgver-pkgrel`).
- **Checksum audit sidecar.** A `SHA256SUMS.txt` is written next to each arch's
  index for out-of-band mirror auditing (not a substitute for the apk
  signature — an aid).
- **Fail-safe order.** key → apks (invisible to clients) → **signed
  `APKINDEX.tar.gz`** (the flip) → `meta/<branch>.json` pointer (dead last).
- **Dry-run** (`-n`): full validation, checksums, and the plan, with **no
  credentials and no network**.

**Honest limit of the signature check.** `publish-apk-repo.sh` verifies the
signature **member exists and is named for the right key**; full cryptographic
verification of the RSA signature over the index is what `apk` itself performs
on-device with the pubkey installed. The script does not re-implement apk's
verifier — it guarantees the index is *signed by the expected key name* and
publishes in an order where an unsigned/mis-signed index can never become the
client-visible flip.

---

## 4. `publish-to-r2.sh` (image publisher) — already hardened; no change

For completeness, the image publisher (owned by another dev; not changed here)
already enforces: honest-status label guards (product name, `not_product`,
`reproducible=false`, `attestable=false`), a `status=BUILT` gate (refuses
scaffold/sample manifests), on-disk-vs-manifest sha256 match, a minisign
self-check against the published pubkey (refuses a wrong secret key), and
fail-safe ordering with the signature written last. No hardening deficiency
found; the one recommendation is to move `DEFAULT_PUBKEY` to the **stable**
minisign key at cutover (`KEYS.md` §3).

---

## 5. Summary of what changed vs. what is recommended

**Applied in this pass (new files, no owned file edited):**

- `publish-apk-repo.sh` — the missing signed-apk-repo publisher with
  index-signing / write-once / immutability / checksum-sidecar / fail-safe
  ordering enforcement.
- `KEYS.md` + `keys/postern-keygen.sh` — the stable-key + rotation plan and
  tooling (see `KEYS.md`).
- `DISTRIBUTION.md` updated to reference `publish-apk-repo.sh` (the real tool)
  instead of the non-existent `publish-to-r2.sh -b/-r/-k` invocation.

**Recommended for the APKBUILD / publish-to-r2.sh owners (not silently edited):**

- Switch `postern-wallet` / `postern-apps` `source=` to the canonical upstream
  `v$pkgver` archive once the tags are publicly fetchable; re-run
  `abuild checksum`.
- Adopt the **stable** apk signing key (`packages@posternlabs.com-<8hex>`) and
  the **stable** minisign image key, publish both in ≥2 places with fingerprints,
  and update the caveats in `PUBLISHED.md` (`KEYS.md` §3/§6).
- Pin the Alpine `rust`/`cargo` toolchain version in CI and record it with the
  manifest pins.

None of this changes the honest ceiling: **built ≠ booted**, signed ≠
reproducible ≠ attested, community edition is **never "Postern OS"**.
