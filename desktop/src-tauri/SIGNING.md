<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Postern Desktop — packaging & signing scaffold

This is the map of how Postern Desktop goes from source to a *signed-flow-tested*
bundle, and — honestly — everything that still stands between that and a real
signed public release.

> **Nothing here produces a production release.** The crates are unaudited, the
> testnet is zero-security by design, and every key this scaffold generates is a
> throwaway stamped `dev-sample` / `DO-NOT-SHIP`. Building and even
> "signing" locally with these keys tests the *mechanics*; it is not an
> attestation and must never be shipped to a user as one.

---

## 1. The pieces (all in `desktop/src-tauri/`)

| File | Role |
|------|------|
| `tauri.conf.json` | Bundle config: product metadata, the explicit `bundle.targets` array (deb/rpm/appimage/app/dmg/msi/nsis), permissive license, `createUpdaterArtifacts: false`, and `macOS.signingIdentity: null` (unsigned-by-design; signing is opt-in via env — see §4). |
| `build.rs` | Tauri's build hook (`tauri_build::build()`) — generates the bundle/capability glue at compile time. |
| `package-signed.sh` | Host-gated driver: `--check` validates config with no build/keys; `--build` runs `cargo tauri build` for the current host, computes `SHA256SUMS`, then **reuses** the two repo pipelines below. |
| `gen-dev-signing-keys.sh` | **The signing scaffold.** Mints clearly-marked placeholder keys (`dev-sample.*`) so `package-signed.sh --build` can be exercised end-to-end without any production key. |
| `tests/bundle_config.rs` | Regression tripwire over the config + scripts (updater-off, license permissive, `signingIdentity` null, targets cover all three OSes, scaffold keeps its honesty markers). |

Reused (owned elsewhere, **not** modified by this package):

- `packaging/build-signed-bundle.sh` — dev-key TUF metadata + fail-closed verify.
- `scripts/sign-release.sh` — minisign (Ed25519) + hybrid Falcon-1024/ML-DSA-87
  signatures over the shared `SHA256SUMS` convention.

---

## 2. Validate the config (no build, no keys)

```bash
cd desktop/src-tauri
./package-signed.sh --check          # config parses, updater off, targets explicit, pipelines present
./gen-dev-signing-keys.sh --check    # confirms minisign + postern-release are available
cargo test -p bloch-desktop --test bundle_config   # the regression tripwires
```

## 3. Exercise the full signing flow with placeholder keys

```bash
cd desktop/src-tauri

# 1. mint dev-sample / DO-NOT-SHIP keys (Ed25519 + PQ hybrid) + placeholders
./gen-dev-signing-keys.sh --gen
#   -> ./dev-keys-DO-NOT-SHIP/dev-sample.minisign.{key,pub}
#      ./dev-keys-DO-NOT-SHIP/dev-sample.{falcon,mldsa}.*
#      ./dev-keys-DO-NOT-SHIP/notarize.env.sample   (fake notarization env)

# 2. host-gated build + dev-key signing (current host's targets only)
POSTERN_PACKAGING_E2E=1 ./package-signed.sh --build \
    -s ./dev-keys-DO-NOT-SHIP/dev-sample.minisign.key \
    -k ./dev-keys-DO-NOT-SHIP/dev-sample
```

Both pipelines will **loudly warn** that `dev-sample` keys are for flow-testing
only — that warning is the safety feature. The `dev-keys-DO-NOT-SHIP/` directory
is `.gitignore`d so key material never lands in the tree.

`cargo tauri build` only emits the **current host's** formats (deb/rpm/appimage
on Linux, app/dmg on macOS, msi/nsis on Windows). There is no single-host path to
all seven; each OS builds on its own runner. See `BUILD.md §7`.

---

## 4. macOS notarization & Windows Authenticode (env, placeholder-documented)

`tauri.conf.json` keeps `macOS.signingIdentity: null`, so real signing is **opt-in
via environment variables** that `cargo tauri build` reads — never hard-coded in
the committed config (and `tests/bundle_config.rs` fails if `signingIdentity`
silently flips off `null`). `gen-dev-signing-keys.sh --gen` writes a
`notarize.env.sample` with the full set as **fake placeholders**:

- **macOS signing** — `APPLE_SIGNING_IDENTITY` (Developer ID Application) *or*
  `APPLE_CERTIFICATE` + `APPLE_CERTIFICATE_PASSWORD` (base64 `.p12`), plus
  `APPLE_TEAM_ID`.
- **macOS notarization** — either `APPLE_ID` + `APPLE_PASSWORD` (app-specific) +
  `APPLE_TEAM_ID`, or the App Store Connect API key trio `APPLE_API_ISSUER` +
  `APPLE_API_KEY` + `APPLE_API_KEY_PATH`.
- **Windows Authenticode** — set `bundle.windows.certificateThumbprint`
  (+ `digestAlgorithm`, `timestampUrl`) in a release override, or a `signCommand`
  for a cloud HSM (Azure Trusted Signing / SignPath / DigiCert KeyLocker).

---

## 5. What a REAL signed release still needs (the gate)

This scaffold advances the mechanics up to — and stops at — every gate that
depends on credentials, hardware, or an audit we do not have:

1. **Production signing keys.** Real, operator-held, hardware-protected minisign +
   PQ keys (not `dev-sample`), with a published-key trust root so downstream users
   can verify. — *gate: key custody / HSM.*
2. **Apple Developer ID + notarization.** An enrolled Developer ID Application
   certificate and a notarization credential; without it macOS Gatekeeper warns on
   first launch. — *gate: paid Apple Developer account.*
3. **Windows Authenticode certificate.** An EV/OV code-signing cert (or cloud
   signing service); without it SmartScreen warns. — *gate: cert issuance.*
4. **Linux `.deb`/`.rpm` signing.** Detached GPG signatures / signed repo metadata
   (`dpkg-sig`, `rpm --addsign`) with a published repo key. — *gate: repo + key.*
5. **Per-OS build runners.** Linux/macOS/Windows CI runners, since Tauri does not
   cross-bundle. — *gate: CI infrastructure.*
6. **An update/distribution channel.** `createUpdaterArtifacts` stays `false` until
   a real TUF-backed channel exists to serve them. — *gate: hosted channel.*
7. **A security audit.** None of the above makes an unaudited prototype secure; a
   valid signature only proves the bytes came unmodified from the key holder.
   — *gate: external audit.*

Until all seven are met, treat every artifact from this scaffold as
**dev-only, source-pinned, unsigned-for-production**.
