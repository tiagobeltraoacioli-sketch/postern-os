<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Building Postern Desktop from source

**There are no prebuilt binaries.** Postern Desktop is distributed as source
only. You build it yourself from this repository, so the artifact you run is one
you (or your packager) compiled and can pin. This document is the reproducible,
platform-by-platform path to a working build.

> A pin, not an audit. Building from source does not make this app "secure" or
> "attested" — it means the bytes you run came from source you can read and
> hash, not from an opaque download. The crates here are **unaudited** and the
> testnet is zero-security by design.

---

## 1. What you are building

- **`bloch-desktop`** — the Tauri app in `desktop/src-tauri` (Rust backend +
  the dependency-free web UI in `desktop/src`). It is a *companion*: it starts,
  stops, and monitors a separate `bloch` **node** process — it does not contain
  or embed the node. It also holds a **wallet** (generate / restore a BIP39
  mnemonic, diversified receive addresses, balance, send) with **real native
  crypto** — the `postern-vault` Argon2id + XChaCha20-Poly1305 keystore and
  ML-DSA-65 signing via the same `WalletCore`/`bloch` cores the mobile wallet
  uses — and can **import a `bloch-cli` `wallet.json`** (both the simple
  `EncryptedKeystore` from `bloch-cli newwallet` and the HD wallet from
  `newseed`). Import reuses the `bloch` crate's own keystore readers, so a
  successful import means the recovered address is byte-identical to what the
  CLI wrote (the round-trip is enforced inside the crate); a simple imported
  keystore is also spendable (same `getutxos → build → broadcast` flow
  `bloch-cli send` uses). Zero-value pre-mainnet testnet, unaudited.
- The `bloch` node binary is a **separate** build from the ownerless
  [Bloch-SIS-PoW protocol repo](https://gitlab.com/blochsispow-group/BlochSISPoW-project).
  You point the app at it at runtime (see §6). Nothing is bundled as a sidecar
  today; the app never downloads a binary.

The desktop crate is a member of this repository's virtual workspace, but it
builds standalone with `-p bloch-desktop`.

---

## 2. Toolchain (all platforms)

- **Rust** — stable, edition 2021. Install via <https://rustup.rs>. This crate
  is developed against Rust 1.94; any recent stable ≥ 1.77 should work.
- **Tauri CLI v2**:

  ```bash
  cargo install tauri-cli --version '^2' --locked
  ```

  `cargo tauri --version` should print `2.x`.

Network access is required for the **first** build only: several dependencies
(the `bloch` node crates, Arti/Tor) are fetched as git dependencies pinned in
the workspace `Cargo.lock`. After the first fetch you can build `--offline`.

---

## 3. Platform prerequisites

### Linux (Debian / Ubuntu)

Tauri needs the WebKitGTK stack and a few system libs at build time:

```bash
sudo apt update
sudo apt install -y \
  build-essential curl wget file pkg-config \
  libwebkit2gtk-4.1-dev \
  libssl-dev libgtk-3-dev \
  libayatana-appindicator3-dev librsvg2-dev
```

- **Fedora**: `webkit2gtk4.1-devel gtk3-devel libappindicator-gtk3-devel librsvg2-devel openssl-devel` plus `@development-tools`.
- **Arch**: `webkit2gtk-4.1 gtk3 libappindicator-gtk3 librsvg openssl base-devel`.

### macOS

- **Xcode Command Line Tools**: `xcode-select --install`.
- No WebKitGTK needed — Tauri uses the system **WKWebView**. This is the one
  platform where the crate builds with no extra GUI system packages.

### Windows

- **Microsoft C++ Build Tools** (MSVC toolchain) — install via Visual Studio
  Build Tools with the "Desktop development with C++" workload.
- **WebView2 runtime** — preinstalled on Windows 11 / recent Windows 10; the
  Tauri bundler can also embed it. See the Tauri v2 prerequisites page.

---

## 4. Build

From the repository root (or `cd desktop/src-tauri`):

```bash
# type-check only (fast; what CI and this repo's dev loop run)
cargo check -p bloch-desktop

# run the unit + config-hardening regression tests
cargo test -p bloch-desktop

# hot-reload dev run
cd desktop/src-tauri && cargo tauri dev

# release build + OS bundle (.deb/.AppImage/.dmg/.msi as applicable)
cd desktop/src-tauri && cargo tauri build
```

The bundle lands under `desktop/src-tauri/target/release/bundle/`.
`bundle.targets` is an **explicit reviewed array** in `tauri.conf.json`
(`deb`, `rpm`, `appimage`, `app`, `dmg`, `msi`, `nsis`), but Tauri does not
cross-bundle: `cargo tauri build` only emits the subset of that array valid for
**the OS you run this command on** — `.deb`/`.rpm`/`.AppImage` on Linux,
`.app`/`.dmg` on macOS, `.msi`/NSIS `.exe` on Windows, each built on its own
machine/CI runner. To build only a further subset (e.g. skip the slow
`.rpm`/`.AppImage` pass while iterating on macOS), pass `--bundles`:

```bash
# macOS (this repo's ground-truth host): .app + .dmg
cargo tauri build --bundles app dmg

# Linux (on a Linux host with the §3 WebKitGTK deps): .deb + .rpm + .AppImage
cargo tauri build --bundles deb rpm appimage

# Windows (on a Windows host with the §3 MSVC + WebView2): .msi + NSIS .exe
cargo tauri build --bundles msi nsis
```

Each command must run **on the matching OS** — there is no single-host path to
all seven formats (see §7). CI wires exactly this, one job per OS (§8).

See §7 for the reproducibility and signing caveats that apply to every
bundle format, and `src-tauri/SIGNING.md` for the packaging/signing scaffold
(placeholder-key flow + what a real signed release still needs).

### Icons

`cargo tauri build` requires the icon set in `desktop/src-tauri/icons/` (already
checked in). To regenerate from a source logo:

```bash
cd desktop/src-tauri && cargo tauri icon path/to/logo.png
```

`cargo tauri dev` runs without a complete icon set.

---

## 5. Baking a node-integrity pin into the build (optional, recommended)

The app can refuse to start any `bloch` node binary whose SHA-256 does not match
a pin you choose (fail-closed). You can supply the pin at **runtime** or bake it
into the build so it ships with the app:

```bash
# 1. hash the node binary you trust
export POSTERN_NODE_SHA256=$(sha256sum /path/to/bloch | cut -d' ' -f1)   # Linux
# macOS: shasum -a 256 /path/to/bloch | cut -d' ' -f1

# 2a. runtime pin (checked when the app starts the node)
cargo tauri dev

# 2b. …or bake it into the release so the shipped app enforces it
POSTERN_NODE_SHA256="$POSTERN_NODE_SHA256" cargo tauri build
```

- **Match** → the node starts and a `✓ integrity: … matches the configured pin`
  line is logged.
- **Mismatch / unreadable / malformed pin** → **fail-closed**: the node is not
  started and the error surfaces in the UI.
- **No pin** → the node still starts, but a `⚠ integrity: no POSTERN_NODE_SHA256
  pin configured …` line is logged so nothing implies the binary was verified.

**Honesty / known limits.** This is a plain **software** SHA-256 over the file
bytes — tamper-evident against a digest *you* trust, **not** a signature, **not**
hardware attestation, **not** a TEE check. An on-disk `<binary>.sha256` sidecar
is deliberately *not* consulted (whoever can swap the binary can swap that file
too). There is also a residual **TOCTOU** window: the file is hashed and then
spawned by path, so a local attacker who rewrites the file in between could still
run a swapped binary — closing that fully needs an exec-by-fd primitive the Rust
std spawn API does not expose. See `verify_node_integrity` in
`src-tauri/src/main.rs`.

---

## 6. Running against a node

### Connectivity model — works on download, sovereign stays opt-in

A freshly-installed wallet must work immediately, so the **default is a remote
public node** (thin-client): the wallet reads balances and broadcasts signed
transactions against `https://posternlabs.com/rpc` — a same-origin Cloudflare
Pages Function proxy that forwards to the **canonical** Bloch node — with **no
local node required**. Three modes, selectable in the **Node → Connection** card:

| Mode | Endpoint | Trust |
|------|----------|-------|
| **Public node (quick)** — default | `https://posternlabs.com/rpc` | remote: you trust the canonical node (via the proxy) for balance display + broadcast |
| **Your own node (sovereign)** | `http://127.0.0.1:<rpcPort>` | local: you run the node |
| **Custom endpoint** | a `http(s)://host[:port]` you enter | remote: **requires an explicit confirmation checkbox** |

The webview-supplied RPC URL is validated against a **fail-closed allowlist**
(`validate_rpc_url` in `src-tauri/src/main.rs`): only the official public HTTPS
RPC, a loopback http node, or a **user-confirmed** custom endpoint pass —
everything else is rejected (SSRF pinning), so these commands can never be
turned into a generic HTTP client against arbitrary hosts.

**Key/RPC boundary (enforced + tested).** Private keys, mnemonics, and passwords
**never** touch any RPC — signing is 100% local (native / `postern-vault` /
`bloch` `TxBuilder`). Only reads (`getbalance`/`getnetworkinfo`/…) and an
**already-locally-signed** `sendrawtransaction` reach the node. A remote node
sees addresses and signed bytes, never a secret. This is proven by the
`keystore_send_never_leaks_secrets_over_rpc` test (`walletjson.rs`), which stands
up an in-process mock node and asserts the only calls are `getutxos` +
`sendrawtransaction` and that neither request body contains the password or the
private key.

The node is **not bundled** in the installer (keeps it small + per-OS packaging
clean). Sovereign users download/build the `bloch` node separately.

### Pointing at a local node

The app launches whatever `bloch` binary you point the **Binário** field at
(default: `bloch` on `$PATH`; or an absolute path to `target/release/bloch`). The
backend resolves that input to a vetted absolute path — it pins the file **name**
to `bloch` (`bloch.exe` on Windows), canonicalizes symlinks/`..`, requires a real
regular file, and (on Unix) an execute bit — before it will spawn anything. This
closes the "run any program/path" hole; the SHA-256 pin (§5) is what attests
*which* `bloch` it is.

---

## 7. Reproducibility notes

- Dependency versions are pinned by the workspace `Cargo.lock`; commit it and
  build with `--locked` for byte-stable *dependency resolution*. That pin does
  **not** extend to the bundle artifacts themselves — see below.
- `cargo tauri build` embeds build-time environment (including
  `POSTERN_NODE_SHA256` if set) — record what you set so a rebuild is
  reproducible.
- This repository does not ship, sign, or notarize release artifacts. Any
  packaging, signing, or notarization is the downstream packager's
  responsibility and is out of scope here.

### Honest limits (bundling), verified 2026-07-14 on macOS (Darwin 23.6.0, Tauri CLI 2.10.1)

- **`bundle.targets` is per-host, not cross-platform.** The explicit targets
  array (`deb`/`rpm`/`appimage`/`app`/`dmg`/`msi`/`nsis`) does not make Tauri
  cross-compile or cross-bundle: `cargo tauri build` only emits the entries
  valid *for the OS it is currently running on*. Running it on macOS produces
  `.app`/`.dmg` only; it will never emit `.deb`/`.AppImage`/`.rpm` (Linux) or
  `.msi`/NSIS `.exe` (Windows) from this machine. Each OS's artifacts must be
  built on that OS's own runner (or a matching CI image) — there is no
  single-host path to all seven formats.
- **The bundlers are not byte-reproducible**, even with `--locked` and an
  otherwise identical source tree. The `.deb`, `.AppImage`, and `.dmg`
  bundlers embed filesystem mtimes (tar/zip entry timestamps, and for `.dmg`
  the HFS+/APFS image creation time) that vary run-to-run. `--locked` pins the
  *dependency graph*, not the archive bytes — two builds from the identical
  commit will not hash-match unless the bundler is explicitly wrapped with a
  timestamp-normalizing/reproducible-build harness (not done in this repo).
  Treat "built from this source" as the reproducibility guarantee, not
  "bit-identical artifact."
- **macOS and Windows outputs are unsigned by this config.**
  `bundle.macOS.signingIdentity` is explicitly `null` (ad-hoc/unsigned `.app`
  and `.dmg`; Gatekeeper will warn on first launch) and no Windows
  Authenticode config is set either. Signing is **opt-in via environment
  variables** documented (with placeholder values) in `src-tauri/SIGNING.md`
  §4; a real signed/notarized release still needs the credentials and gates
  listed in `SIGNING.md` §5.
- **Linux and Windows bundle production is BLOCKED from a macOS host.** macOS
  produces only the `.app`/`.dmg` bundle (`cargo tauri build --bundles app
  dmg`); the `.deb`/`.AppImage`/`.rpm` and `.msi`/NSIS targets are
  config-correct (parsed and accepted by `tauri.conf.json` schema validation)
  but must be built on their own OS. That wiring now exists in
  `.gitlab-ci.yml` — see §8.

---

## 8. CI packaging (Windows / Linux / macOS installers)

`cargo tauri build` cannot cross-bundle (§7), so `.gitlab-ci.yml` has **one
`deploy`-stage job per OS**, each producing that OS's installers as pipeline
**artifacts**. None publish — nothing is uploaded to the public
`postern-downloads` R2 bucket or any live site; that promotion is a separate,
human-gated step (the site's `downloads.html` desktop table stays behind a
"pending publish" flag until a maintainer fills it in).

| Job | Runner tag | Bundles | State |
|-----|-----------|---------|-------|
| `desktop:bundle-macos` | `bloch-mac` (exists) | `app dmg` | **runnable today** |
| `desktop:bundle-linux` | `bloch-desktop-linux` (not provisioned) | `deb rpm appimage` | UNTESTED-until-runner |
| `desktop:bundle-windows` | `bloch-desktop-windows` (not provisioned) | `msi nsis` | UNTESTED-until-runner |

All three are `when: manual` (packaging an installer is an intentional act).
The Linux and Windows jobs are additionally `allow_failure: true` because their
runners are not registered yet — they surface honestly as untested rather than
faking a green build. Each job also writes a `SHA256SUMS` list beside its
installers.

**How a maintainer triggers a build:**

1. Push the branch. In the GitLab UI open **CI/CD → Pipelines** for that commit.
2. Click **▶** on `desktop:bundle-macos`. When it finishes, the `.dmg`/`.app` +
   `SHA256SUMS` are in the job's **artifacts** (download from the job page).
3. To build the Linux/Windows installers, first **register a runner** on a Linux
   / Windows host with the §3 prerequisites and the matching tag
   (`bloch-desktop-linux` / `bloch-desktop-windows`), then click **▶** on the
   corresponding job. Until such a runner exists, those jobs cannot run — this
   is the honest gap, not a hidden failure.

**Runner setup, per OS** (a GitLab shell/generic runner with the toolchain from
§2 + the OS prerequisites from §3, plus `cargo install tauri-cli --version '^2'`
— the job installs it if absent). The job needs the private-protocol dep token
`BLOCH_DEP_TOKEN` (see `.gitlab-ci.yml`'s `before_script`) exactly like the
other Rust jobs.

**Publishing (human-gated, out of scope here):** once installers are verified,
a maintainer uploads them + `SHA256SUMS` (and, ideally, a detached signature —
`SIGNING.md`) to the download host and flips the `downloads.html` desktop rows
from "pending publish" to real links. This document deliberately stops at
"built as CI artifacts"; it does not upload or announce anything.
