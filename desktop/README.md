# Postern Desktop — full node companion (Tauri)

A Postern Labs product: a Linux (and cross-platform) desktop app that runs and
monitors a Bloch-SIS node, with a built-in wallet and miner view. (The protocol
is ownerless — anyone may build their own companion apps on it.) Rust backend (`src-tauri`) + a
dependency-free web UI (`src`). Reuses the same `WalletCore` as the mobile
wallet, so addresses/signatures are byte-identical to the node.

## Status (read this first)

- **A pin, not an audit.** The integrity pin and the hardened CSP / capability
  allowlist raise the bar; they are *not* a security review. Nothing here is
  attested, sandboxed, or secure by these measures alone.
- **Unaudited.** This app and the crates behind it (vault, panic, Tor, wallet)
  have **not** been audited. Do not trust it with value.
- **Build from source — no prebuilt binaries.** There are no signed downloads
  and no bundled node sidecar. You compile the app yourself; see
  **[BUILD.md](BUILD.md)** for the reproducible, per-platform path.
- **Testnet is zero-security by design.** Don't attach value.
- The coin is **not** a security.

## What it does

- **Nó** — start/stop the `bloch` node process (data-dir, RPC port, mine
  toggle), see PID + a live RPC dashboard (height / peers / mempool).
- **Wallet** — generate a new wallet (mnemonic shown once) or restore from a
  seed; shows the `bloch1…` address + balance, and **sends** transparent txs
  (reuses the node wallet's getutxos → build → sign → sendrawtransaction flow).
- **Miner** — Module-SIS PoW status (mining is enabled by the *Minerar* toggle
  when starting the node — the reward goes to the node's address).
- **Logs** — the node's stdout/stderr streamed live.

## Prerequisites (Linux)

Tauri needs the WebKitGTK stack at build time:

```bash
# Debian/Ubuntu
sudo apt install libwebkit2gtk-4.1-dev build-essential libssl-dev \
     libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev
cargo install tauri-cli --version '^2'
```

(Fedora/Arch have equivalent `webkit2gtk4.1`/`webkit2gtk` packages.)

## Build & run

Full, per-platform (Linux / macOS / Windows) build-from-source instructions are
in **[BUILD.md](BUILD.md)**. The short version:

```bash
cargo check -p bloch-desktop         # type-check (fast)
cargo test  -p bloch-desktop         # unit + config-hardening regression tests
cd desktop/src-tauri
cargo tauri icon path/to/logo.png    # once — generates the required icons/
cargo tauri dev                      # hot-reload dev run
cargo tauri build                    # release bundle (.deb/.AppImage/.dmg/.msi)
```

The app launches whatever `bloch` binary you point the **Binário** field at
(default: `bloch` on `PATH`; or an absolute path to `target/release/bloch`).

## Node binary integrity pin (optional, fail-closed)

`node_start` first resolves the binary to a vetted absolute path (name +
location + existence + exec-bit check — never an arbitrary program). On top of
that you can pin the binary's **SHA-256** so a swapped/corrupt `bloch` is
refused before it is spawned:

```bash
# runtime pin (checked when the app starts the node)
export POSTERN_NODE_SHA256=$(sha256sum /path/to/bloch | cut -d' ' -f1)
cargo tauri dev
# …or bake it into the build so it ships with the app:
POSTERN_NODE_SHA256=<64-hex> cargo tauri build
```

Behavior:

- **Pin set + match** → a `✓ integrity: … matches the configured pin` log line,
  then the node starts.
- **Pin set + mismatch / unreadable / malformed pin** → **fail-closed**: the
  node is *not* started and the error surfaces in the UI (Start toast + log).
- **No pin** → the node still starts, but a `⚠ integrity: no POSTERN_NODE_SHA256
  pin configured …` line is logged so nothing implies the binary was verified.

**Honesty:** this is a plain **software** SHA-256 over the file bytes. It makes
the node binary **tamper-evident** against a digest *you* trust (the pin lives
in the environment or the build, not in the binary's own directory) — it is
**not** a signature, **not** hardware attestation, and **not** a
secure-hardware/TEE check. An on-disk `<binary>.sha256` sidecar is deliberately
*not* consulted: whoever can replace the binary could replace that file too.

## Vault: OS-keychain unlock (opt-in `vault-keychain` feature — OFF by default)

Built with `cargo build -p bloch-desktop --features vault-keychain`, the Vault
pane gains an **opt-in** passphrase-less unlock: while the vault is unlocked
you can *Enable keychain unlock* (the vault key is enrolled in the OS login
keychain — macOS Keychain / freedesktop Secret Service on Linux), after which
the locked pane offers *Unlock with OS keychain*; *Forget keychain key*
removes it again (idempotent). Nothing is ever enrolled implicitly.

**Honesty (ships verbatim in every `vault_status` answer and in the pane):**
keychain unlock is a **SOFTWARE convenience, not hardware protection** — the
vault key is stored in the OS login keychain and is **released to any process
running as this user**. Not a TEE until real hardware (no StrongBox / Secure
Enclave / SEV key-wrap exists here) — **UNAUDITED**, like everything in this
repo. Enabling it trades the passphrase gate for login-session convenience;
that is a weakening you opt into, never a security upgrade.

Fail-closed behavior: built **without** the feature, the three
`vault_keychain_*` commands return a clean `not built with keychain support`
error (never a silent no-op) and the pane shows no keychain controls; with the
feature but no reachable OS keychain, the status reports `available: false`;
no enrolled key, or a stale key that no longer opens the vault file, is an
error — never a silently-empty vault. Tests drive the cores against
postern-vault's RAM-only `InMemoryKeyStore` (no OS keychain in CI):
`cargo test -p bloch-desktop --features vault-keychain`.

## Content-Security-Policy (least-privilege, and why each relaxation stays)

The window CSP (`tauri.conf.json → app.security.csp`) is default-deny
(`default-src 'self'`) with every unused fetch sink pinned to `'none'`
(`font-src`, `media-src`, `worker-src`, `child-src`, `frame-src`,
`manifest-src`, `object-src`) and `base-uri`/`frame-ancestors`/`form-action`
locked down. The relaxations that remain, and why:

- **`style-src 'self' 'unsafe-inline'`** — the hand-written UI sets `style=""`
  attributes via `innerHTML` and static inline styles (~50 of them). A hash-only
  style policy would be brittle in this no-build-step app. Residual risk is
  CSS-injection, low here: the only inputs are same-origin and rendered through
  escaping. Scripts are **not** relaxed (`script-src 'self'`, no `unsafe-inline`).
- **`connect-src 'self' ipc: http://ipc.localhost`** — `ipc:` and
  `http://ipc.localhost` are Tauri v2's IPC transport (required for
  `invoke`/events). Node JSON-RPC and RPC-over-Tor run in the **Rust** backend
  (`ureq` / Arti), so the web layer needs no `http(s)` origin beyond `'self'`.
- **`img-src 'self'`** — icons/SVG are inline or same-origin; the previous
  `data:` allowance was unused and has been dropped.

The IPC command surface is separately narrowed by
`capabilities/default.json` (a default-deny allowlist granting only
`core:event:allow-listen`/`allow-unlisten`; the app's own `#[tauri::command]`s
are not ACL-gated in Tauri v2). CSP is defense-in-depth — it is not "security"
on its own, and none of this has been audited.

## Notes / honesty

- **Builds from source on macOS and Linux** — `cargo check -p bloch-desktop`
  and `cargo test -p bloch-desktop` pass with the toolchain in
  [BUILD.md](BUILD.md) (macOS uses the system WKWebView; Linux needs the
  WebKitGTK packages above). No prebuilt binaries are shipped.
- **Icons required for `cargo tauri build`** — run `cargo tauri icon` once to
  populate `src-tauri/icons/` (dev can run without a full icon set).
- The RPC dashboard uses `getblockcount` for height and best-effort `getinfo`
  for peers/mempool — fields the node doesn't expose simply show `—`.
- Testnet is zero-security by design; don't attach value.
