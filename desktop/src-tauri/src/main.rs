// SPDX-License-Identifier: MIT OR Apache-2.0
//! Postern Desktop — full node companion (Tauri backend). A Postern Labs product.
//!
//! Manages the `bloch` node process (start/stop, streamed logs), talks to its
//! JSON-RPC, and does local wallet ops (reusing the same WalletCore as the
//! mobile wallet). The web UI (../src) calls these #[tauri::command]s.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// Hygiene — the real postern-hygiene scrub core behind `hygiene_scrub`
// (replaces the JS preview engine's simulated OOXML/PDF reports). Like
// terem, the module is also re-exported from src/lib.rs so integration
// tests can drive its pure scrub functions — the same deliberate,
// disclosed dual-compile (see Cargo.toml's [lib] comment).
// Courier — the postern-courier hybrid PQ payload seal behind `courier_*`
// (courier.rs). Crypto seal only: the onion transport stays behind the
// crate's DropSender/DropFetcher trait seam (feature OFF here — no Tor, no
// network); mock-transport tested only, no live-anonymity claim. Also
// re-exported from src/lib.rs for tests/courier_core.rs (disclosed
// dual-compile, see Cargo.toml's [lib] comment).
mod courier;
// Backup — the Encrypted Backup pane's backend (backup.rs). Wires the real
// bloch-data (data/postern-data) SCAFFOLD: local file seal (real Postern AEAD,
// Argon2id key) → PBM0/PBP0 codecs → a real (UNSIGNED) DATA0 anchor whose
// manifest_root is a real SHAKE-256, re-verified on restore → content-addressed
// DirBackend store in a user-chosen folder. The Filecoin LiveBackend is a
// todo!() stub this NEVER calls (the pane's "Back up to Filecoin" is a disabled
// preview). Unaudited, like everything here. In-module #[cfg(test)] round-trip.
mod backup;
mod hygiene;
// Quarantine — the real postern-quarantine inbound-document safety core behind
// `quarantine_rebuild` (quarantine.rs); the MIRROR of hygiene (hygiene protects
// what you SEND, quarantine what you RECEIVE). Images → clean PNG (pixel
// round-trip), PDFs → flat metadata-free PDF (pure-Rust `hayro` render, feature
// render-hayro). HONESTY: the render runs IN-PROCESS with NO OS-level
// containment. Also re-exported from src/lib.rs so tests/quarantine.rs can
// drive its pure `rebuild`/`rebuild_b64` functions — the same disclosed
// dual-compile as hygiene/terem (see Cargo.toml's [lib] comment).
mod quarantine;
// Keys — the postern-keys ES256 passkey core behind `keys_*` (keys.rs).
// SOFTWARE authenticator, credentials in RAM only (zeroize-on-drop), not a
// TEE until real hardware. Also re-exported from src/lib.rs for
// tests/keys_core.rs (same disclosed dual-compile).
mod keys;
mod pairing;
mod sha256;
// Terem — the QEMU/QMP guest-runtime POC. The module compiles on every
// platform; its QMP control plane is unix-socket-only in practice (see
// terem.rs's module doc + `qmp_send_recv`'s `#[cfg(not(unix))]` stub, which
// returns an honest runtime error instead of failing the build on Windows).
mod terem;
// Vault + Panic — the postern-vault/postern-panic backend (vault.rs), also
// re-exported from src/lib.rs so tests/vault_core.rs can drive its pure
// encode/decode, status-JSON, and TOTP core without a live Tauri app —
// the same disclosed dual-compile as hygiene/terem.
mod vault;
// Walletjson — import a `bloch-cli` wallet.json (simple `EncryptedKeystore`
// v2 or HD `HdWalletFile`) and spend from an imported simple keystore
// (walletjson.rs). REAL interop: it reuses the `bloch` crate's own keystore
// readers, so the address round-trip is byte-identical to `bloch-cli` and is
// enforced inside the crate. Bin-only (not re-exported in lib.rs) — its pure
// helpers are unit-tested in-module; see walletjson.rs.
mod walletjson;
// Vestnik — the desktop CUSTODY layer for the Matrix client's sealed session
// (vestnik.rs): the courier recipient secret lives as a reserved vault entry
// and the sealed SavedSession blob is stored/loaded/opened as opaque bytes.
// The matrix client itself runs only in a `vestnik-matrix` build (see
// vestnik_client.rs below), only on user action. Also re-exported from
// src/lib.rs for tests/vestnik_custody.rs (same disclosed dual-compile).
mod vestnik;
// Vestnik client — the matrix client behind the opt-in `vestnik-matrix`
// cargo feature (OFF by default; matrix-sdk is a heavy tree — the exact
// `vault-keychain` pattern). The eight vestnik_matrix_status/vestnik_login/
// …/vestnik_logout commands are ALWAYS registered: built without the feature
// they return a clean "not built with matrix support" error (never a silent
// no-op) and vestnik_matrix_status reports { built: false, … } so the pane
// gates on real capability. A homeserver is contacted ONLY when the user
// acts (login/sync/send) — never in CI, never at app startup. Also
// re-exported from src/lib.rs for tests/vestnik_client.rs and
// tests/vestnik_client_stub.rs (same disclosed dual-compile).
mod vestnik_client;

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;

use bloch_mobile::WalletCore;
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager, State};

/// The managed node child process (at most one).
#[derive(Default)]
struct NodeProc(Mutex<Option<Child>>);

/// Expected file name of the node executable. `node_start` pins the spawned
/// program's *name* to this so it can't be turned into an arbitrary-exec
/// primitive: the caller may choose *where* the node lives, but not run some
/// other program in its place.
#[cfg(windows)]
const NODE_BIN_NAME: &str = "bloch.exe";
#[cfg(not(windows))]
const NODE_BIN_NAME: &str = "bloch";

/// Minimal `$PATH` lookup for a bare command name (avoids a `which` dep).
/// Returns the first `$PATH` entry that holds a regular file `name`.
fn which_on_path(name: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    std::env::split_paths(&paths)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

/// Resolve the caller-supplied `binary` to a vetted absolute path to the node
/// executable, or reject it. This constrains the raw spawn in `node_start`:
///   * a bare command name is accepted only if it is exactly [`NODE_BIN_NAME`]
///     and is then resolved against `$PATH` (never the CWD);
///   * a path is canonicalized (symlinks / `..` collapsed) and must point at an
///     existing regular file whose file name is [`NODE_BIN_NAME`];
///   * on Unix the file must have an execute bit set.
///
/// This is a name + location + existence check, not a signature/hash check: it
/// closes the "run any binary/path" hole but does not attest that the resolved
/// `bloch` is authentic. See the README/roadmap for the sidecar follow-up.
fn resolve_node_binary(binary: &str) -> Result<PathBuf, String> {
    let binary = binary.trim();
    if binary.is_empty() {
        return Err("node binary path is empty".into());
    }

    let candidate = if binary.chars().any(std::path::is_separator) {
        // An explicit path (relative or absolute).
        PathBuf::from(binary)
    } else {
        // A bare name: only the node binary name is allowed, resolved via $PATH
        // so `node_start` can't be asked to run e.g. `sh` off the PATH.
        if binary != NODE_BIN_NAME {
            return Err(format!(
                "refusing to run '{binary}': a bare command name must be '{NODE_BIN_NAME}'"
            ));
        }
        which_on_path(binary).ok_or_else(|| format!("'{binary}' not found on PATH"))?
    };

    // Collapse symlinks/`..` and confirm the target exists. canonicalize() errors
    // on a missing path, which also rejects typo'd or injected paths up front.
    let real = candidate
        .canonicalize()
        .map_err(|e| format!("cannot resolve node binary '{}': {e}", candidate.display()))?;

    // Pin the file name: wherever it lives, the program must be the node.
    if real.file_name().and_then(|n| n.to_str()) != Some(NODE_BIN_NAME) {
        return Err(format!(
            "refusing to run '{}': expected an executable named '{NODE_BIN_NAME}'",
            real.display()
        ));
    }

    let meta =
        std::fs::metadata(&real).map_err(|e| format!("cannot stat '{}': {e}", real.display()))?;
    if !meta.is_file() {
        return Err(format!("node binary '{}' is not a regular file", real.display()));
    }

    // On Unix, require an execute bit so we reject non-executable look-alikes.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o111 == 0 {
            return Err(format!("node binary '{}' is not executable", real.display()));
        }
    }

    Ok(real)
}

/// The canonical mainnet bootstrap peer (node3). A freshly-started local node
/// has no peer memory, so without at least one bootstrap peer it never learns
/// the tip and stays stuck at genesis — the exact "connection refused / stuck at
/// 0" symptom. `node_start` defaults the UI's Peer field to this, but the value
/// still flows through [`validate_peer_multiaddr`] like any other (no bypass).
/// The default itself is supplied by the UI (src/ui.js `CANONICAL_PEER`); this
/// const is the backend's documented copy + the fixture the tests validate, so
/// it is not referenced by the spawn path in non-test builds.
#[allow(dead_code)]
pub(crate) const CANONICAL_PEER_MULTIADDR: &str = "/ip4/45.32.154.137/tcp/16110";

/// Validate a webview-supplied libp2p bootstrap peer as a strict
/// `/ip4/<IPv4>/tcp/<port>` multiaddr, or reject it. This is the ONLY shape the
/// desktop passes to `bloch --peer`, so the field can't smuggle another
/// transport, a hostname (DNS), or extra path segments. The value is also passed
/// as its own argv entry (no shell), so this is format-hardening, not an
/// injection gate — but a well-formed peer is what actually lets the node sync.
///
///   * exactly four non-empty segments: `ip4` / `<addr>` / `tcp` / `<port>`;
///   * `<addr>` must parse as an IPv4 address (four dotted octets);
///   * `<port>` must parse as 1..=65535.
///
/// Pure + unit-tested; see the tests at the bottom of this file.
fn validate_peer_multiaddr(peer: &str) -> Result<String, String> {
    let p = peer.trim();
    if p.is_empty() {
        return Err("peer multiaddr is empty".into());
    }
    // A multiaddr starts with '/', so splitting yields a leading empty segment.
    let parts: Vec<&str> = p.split('/').collect();
    // ["", "ip4", "<addr>", "tcp", "<port>"]
    if parts.len() != 5 || !parts[0].is_empty() {
        return Err(format!(
            "invalid peer '{p}': expected exactly /ip4/<addr>/tcp/<port>"
        ));
    }
    if parts[1] != "ip4" || parts[3] != "tcp" {
        return Err(format!(
            "invalid peer '{p}': only /ip4/<addr>/tcp/<port> multiaddrs are accepted \
             (no dns/dns4/quic/other transports)"
        ));
    }
    parts[2]
        .parse::<std::net::Ipv4Addr>()
        .map_err(|_| format!("invalid peer '{p}': '{}' is not an IPv4 address", parts[2]))?;
    match parts[4].parse::<u16>() {
        Ok(0) | Err(_) => {
            return Err(format!("invalid peer '{p}': '{}' is not a port 1-65535", parts[4]))
        }
        Ok(_) => {}
    }
    Ok(p.to_string())
}

/// Normalize a raw SHA-256 pin string: trim, strip an optional (case-insensitive)
/// `sha256:` prefix, trim again, lowercase. Returns `None` for an empty result so
/// callers treat a blank pin as "no pin" rather than a malformed one.
///
/// This is deliberately pure (no env/IO) so it is unit-testable without touching
/// process-global state. It does NOT validate that the result is 64 hex chars —
/// that check lives in [`pin_is_valid_hex`] so a set-but-garbage pin fails closed
/// with a distinct, actionable error rather than being silently discarded.
fn normalize_pin(raw: &str) -> Option<String> {
    let v = raw.trim();
    // Case-insensitive `sha256:` prefix strip without allocating for the compare.
    let v = match v.get(..7) {
        Some(p) if p.eq_ignore_ascii_case("sha256:") => &v[7..],
        _ => v,
    };
    let v = v.trim().to_ascii_lowercase();
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

/// A normalized pin is well-formed iff it is exactly 64 lowercase hex digits
/// (a SHA-256 digest). Pure and testable; see [`normalize_pin`].
fn pin_is_valid_hex(pin: &str) -> bool {
    pin.len() == 64 && pin.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The pinned SHA-256 the node binary must match, if one is configured. Source,
/// in precedence order:
///   1. the `POSTERN_NODE_SHA256` environment variable at runtime;
///   2. the same variable baked in at *build* time (`option_env!`).
///
/// Either way the pin's trust is the operator's/packager's responsibility — it
/// lives in the environment or the build, not in the (attacker-controllable)
/// directory the binary sits in, so an on-disk `.sha256` sidecar is deliberately
/// NOT consulted (that would be verifying the tamperer against themselves).
///
/// Returns the normalized (lowercase, `sha256:`/whitespace-stripped) 64-hex
/// string, or `None` when no pin is set (integrity gate disabled).
fn node_integrity_pin() -> Option<String> {
    let raw = std::env::var("POSTERN_NODE_SHA256")
        .ok()
        .or_else(|| option_env!("POSTERN_NODE_SHA256").map(str::to_owned))?;
    normalize_pin(&raw)
}

/// Verify the resolved node binary against the configured SHA-256 pin, if any,
/// BEFORE it is spawned. Fail-closed: when a pin is set and the file's digest
/// does not match (or cannot be read), the node is not started.
///
/// HONESTY: this is a plain software hash over the file bytes. It makes the
/// binary *tamper-evident* against a known digest — it is NOT a signature, NOT
/// hardware attestation, and NOT a secure-hardware/TEE check. When no pin is
/// configured the binary is only name/location-checked, and the UI is told so
/// rather than being left to assume the binary was verified.
///
/// KNOWN LIMIT (TOCTOU): we hash the file at `bin` and then `node_start` spawns
/// the same path. A local attacker who can rewrite that file *between* the hash
/// and the exec could still run a swapped binary — closing that fully needs an
/// exec-by-file-descriptor primitive (e.g. `fexecve`) the std spawn API does not
/// expose. The pin is a defense against a binary swapped *before* launch and
/// against corruption, not a live-attacker guarantee. This is a pin, not an audit.
fn verify_node_integrity(app: &AppHandle, bin: &Path) -> Result<(), String> {
    let Some(pin) = node_integrity_pin() else {
        let _ = app.emit(
            "node-log",
            "⚠ integrity: no POSTERN_NODE_SHA256 pin configured — the node binary is \
             name/location-checked but NOT verified against a known hash (software check only)."
                .to_string(),
        );
        return Ok(());
    };
    if !pin_is_valid_hex(&pin) {
        return Err(format!(
            "refusing to start: POSTERN_NODE_SHA256 pin is not a 64-hex SHA-256 ({} chars) — \
             fix the pin or unset it",
            pin.len()
        ));
    }
    let file = std::fs::File::open(bin)
        .map_err(|e| format!("integrity: cannot open node binary '{}': {e}", bin.display()))?;
    let got = sha256::hex_digest_reader(BufReader::new(file))
        .map_err(|e| format!("integrity: cannot hash node binary '{}': {e}", bin.display()))?;
    if got != pin {
        return Err(format!(
            "refusing to start: node binary SHA-256 does not match the configured \
             POSTERN_NODE_SHA256 pin — the binary may be corrupt or tampered.\n  expected {pin}\n  got      {got}"
        ));
    }
    let _ = app.emit(
        "node-log",
        "✓ integrity: node binary SHA-256 matches the configured pin (software \
         integrity check — tamper-evident, not hardware attestation)."
            .to_string(),
    );
    Ok(())
}

/// Start the node process. Streams stdout+stderr to the UI via `node-log`
/// events. Returns the child PID.
#[tauri::command]
fn node_start(
    app: AppHandle,
    state: State<NodeProc>,
    binary: String,
    data_dir: String,
    rpc_port: u16,
    peer: String,
    testnet: bool,
    mine: bool,
) -> Result<u32, String> {
    let mut guard = state.0.lock().unwrap();
    if guard.is_some() {
        return Err("node already running".into());
    }
    // Validate the bootstrap peer BEFORE spawning. A fresh node with no known
    // peers never syncs; the desktop always sends the canonical mainnet peer by
    // default. An empty field means "no bootstrap peer" (isolated node — it will
    // NOT sync), which we allow but do not silently turn into a lie: the UI's
    // default is the canonical peer. A non-empty value must be a strict
    // /ip4/<addr>/tcp/<port> multiaddr (no injection, no other transports).
    let peer_arg = {
        let p = peer.trim();
        if p.is_empty() { None } else { Some(validate_peer_multiaddr(p)?) }
    };
    // Validate/pin the binary before spawning: only a vetted `bloch` executable,
    // never an arbitrary path/program. The args below are fixed by us and passed
    // as separate argv entries (no shell), so `data_dir`/`peer` can't inject flags.
    let bin = resolve_node_binary(&binary)?;
    // Integrity gate: if a SHA-256 pin is configured, the binary must match it
    // before we spawn (fail-closed). Errors here propagate to the UI toast.
    verify_node_integrity(&app, &bin)?;
    let mut cmd = Command::new(&bin);
    cmd.arg("--data-dir").arg(&data_dir)
        .arg("--rpc-port").arg(rpc_port.to_string());
    // Bootstrap peer so the node actually connects + syncs the canonical chain.
    if let Some(ref pa) = peer_arg {
        cmd.arg("--peer").arg(pa);
    }
    // Network selection. The canonical chain is MAINNET, so we pass NOTHING by
    // default (the node defaults to mainnet); `--testnet` is only added when the
    // UI's network toggle is explicitly on, keeping the spawned network exactly
    // what the UI shows. NOTE: mainnet coins here are still pre-mainnet-beta and
    // UNAUDITED — "mainnet" is the chain id, not a value claim.
    if testnet {
        cmd.arg("--testnet");
    }
    if mine {
        cmd.arg("--mine");
    }
    let _ = app.emit(
        "node-log",
        format!(
            "▶ launching {} — network={}, rpc-port={}, peer={}, mine={}",
            bin.display(),
            if testnet { "testnet" } else { "mainnet" },
            rpc_port,
            peer_arg.as_deref().unwrap_or("(none — node will NOT sync)"),
            mine,
        ),
    );
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = cmd.spawn().map_err(|e| format!("spawn {}: {e}", bin.display()))?;
    let pid = child.id();

    for stream in [child.stdout.take().map(Stream::Out), child.stderr.take().map(Stream::Err)]
        .into_iter()
        .flatten()
    {
        let app = app.clone();
        std::thread::spawn(move || match stream {
            Stream::Out(s) => pump(&app, s),
            Stream::Err(s) => pump(&app, s),
        });
    }

    *guard = Some(child);
    let _ = app.emit("node-log", format!("▶ node started (pid {pid})"));
    Ok(pid)
}

enum Stream {
    Out(std::process::ChildStdout),
    Err(std::process::ChildStderr),
}

fn pump<R: std::io::Read>(app: &AppHandle, reader: R) {
    let buf = BufReader::new(reader);
    for line in buf.lines().map_while(Result::ok) {
        let _ = app.emit("node-log", line);
    }
}

/// Stop the node process.
#[tauri::command]
fn node_stop(app: AppHandle, state: State<NodeProc>) -> Result<(), String> {
    let mut guard = state.0.lock().unwrap();
    match guard.take() {
        Some(mut child) => {
            child.kill().map_err(|e| e.to_string())?;
            let _ = child.wait();
            let _ = app.emit("node-log", "■ node stopped".to_string());
            Ok(())
        }
        None => Err("node not running".into()),
    }
}

/// Current process status. Reaps the child if it exited on its own.
#[tauri::command]
fn node_status(state: State<NodeProc>) -> Value {
    let mut guard = state.0.lock().unwrap();
    let (running, pid) = match guard.as_mut() {
        Some(child) => match child.try_wait() {
            Ok(Some(_)) => {
                *guard = None;
                (false, None)
            }
            Ok(None) => (true, Some(child.id())),
            Err(_) => (false, None),
        },
        None => (false, None),
    };
    json!({ "running": running, "pid": pid })
}

// ─────────────────────────────────────────────────────────────────────────
// SSRF pinning — `rpc`/`wallet_send` URLs and the `rpc_tor` endpoint arrive
// from the webview. Without validation those commands are a generic HTTP
// client the page content can point at LAN/intranet/cloud-metadata hosts
// (SSRF). The validators below pin `rpc`/`wallet_send` to loopback and
// `rpc_tor` to `.onion` hosts, fail-closed. Pure functions, unit-tested at
// the bottom of this file.
// ─────────────────────────────────────────────────────────────────────────

/// Split an authority `host[:port]` into host and optional port string.
/// IPv6 must be bracketed (`[::1][:port]`); an unbracketed multi-colon
/// authority is rejected rather than guessed at.
fn split_host_port(authority: &str) -> Result<(&str, Option<&str>), String> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .ok_or_else(|| "malformed IPv6 authority (missing ']')".to_string())?;
        if after.is_empty() {
            Ok((host, None))
        } else if let Some(p) = after.strip_prefix(':') {
            Ok((host, Some(p)))
        } else {
            Err("malformed authority after ']'".into())
        }
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        if host.contains(':') {
            return Err("unbracketed IPv6 host — write it as [::1]".into());
        }
        Ok((host, Some(port)))
    } else {
        Ok((authority, None))
    }
}

/// `true` iff `host` names this machine's loopback interface, by the strict
/// allowlist the desktop UI actually uses: `127.0.0.1`, `::1`, `localhost`.
/// Deliberately NOT the whole 127.0.0.0/8 block and NOT DNS-resolved —
/// exact-match only, so nothing that *resolves* to loopback (or doesn't)
/// can confuse the check.
fn host_is_loopback(host: &str) -> bool {
    host == "127.0.0.1" || host == "::1" || host.eq_ignore_ascii_case("localhost")
}

/// Parse a port string as 1–65535 (0 rejected).
fn parse_port(p: &str) -> Result<u16, String> {
    match p.parse::<u16>() {
        Ok(0) | Err(_) => Err(format!("invalid port '{p}' (need 1-65535)")),
        Ok(n) => Ok(n),
    }
}

/// The ONE official public node RPC endpoint the desktop wallet trusts by
/// default (host + scheme). A freshly-installed wallet works as a thin client
/// against this over HTTPS with no local node. HONESTY: using it means trusting
/// this node for balance display + broadcast — see the UI trust label. It never
/// receives keys/mnemonics/passwords (those never leave the device); only reads
/// and already-locally-signed `sendrawtransaction` bytes reach it.
pub(crate) const OFFICIAL_PUBLIC_RPC_HOST: &str = "posternlabs.com";

/// Validate a webview-supplied node RPC URL against an explicit, fail-closed
/// ALLOWLIST — NOT an open field. Exactly three shapes pass:
///   1. the official public RPC: `https://` + host [`OFFICIAL_PUBLIC_RPC_HOST`];
///   2. the local node: `http://` + a loopback host (127.0.0.1 / ::1 / localhost);
///   3. a user-added CUSTOM endpoint — only when `allow_custom` is true, which
///      the frontend sets solely after the user has explicitly confirmed that
///      endpoint. Even then it must be a well-formed `http(s)://host[:port]`
///      with no userinfo and a sane port.
/// Everything else is rejected, so `rpc`/`wallet_send`/`wallet_keystore_send`
/// can never be turned into a generic SSRF client against arbitrary
/// LAN/intranet/metadata hosts. (Onion nodes still go through `rpc_tor`.)
pub(crate) fn validate_rpc_url(url: &str, allow_custom: bool) -> Result<(), String> {
    let trimmed = url.trim();
    let (scheme, rest) = if let Some(r) = trimmed.strip_prefix("https://") {
        ("https", r)
    } else if let Some(r) = trimmed.strip_prefix("http://") {
        ("http", r)
    } else {
        return Err(format!("rpc url '{trimmed}' must start with http:// or https://"));
    };
    let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    if authority.is_empty() {
        return Err(format!("rpc url '{trimmed}' has no host"));
    }
    if authority.contains('@') {
        return Err(format!(
            "rpc url '{trimmed}' contains userinfo ('@') — rejected (URL-authority confusion)"
        ));
    }
    let (host, port) = split_host_port(authority).map_err(|e| format!("rpc url '{trimmed}': {e}"))?;
    if let Some(p) = port {
        parse_port(p).map_err(|e| format!("rpc url '{trimmed}': {e}"))?;
    }

    // 1. Official public RPC — HTTPS + the exact pinned host.
    if scheme == "https" && host.eq_ignore_ascii_case(OFFICIAL_PUBLIC_RPC_HOST) {
        return Ok(());
    }
    // 2. Local node — plain HTTP on the loopback allowlist.
    if scheme == "http" && host_is_loopback(host) {
        return Ok(());
    }
    // 3. User-confirmed custom endpoint (well-formed http(s), already checked).
    if allow_custom {
        return Ok(());
    }
    Err(format!(
        "rpc url '{trimmed}' is not on the allowlist: allowed are the official public HTTPS RPC \
         (https://{OFFICIAL_PUBLIC_RPC_HOST}), a loopback http node (127.0.0.1 / [::1] / localhost), \
         or a user-CONFIRMED custom endpoint. Refusing an unconfirmed non-allowlisted host \
         (SSRF pinning). For an onion node use rpc_tor."
    ))
}

/// Parse + validate a webview-supplied Tor endpoint into `(host, port, path)`.
/// Pinning rule: ONLY a `.onion` host is accepted (an optional `http://` or
/// `https://` prefix is stripped; port defaults to 80; path defaults to `/`).
/// Userinfo, port 0, and any non-onion host are rejected — the local node has
/// the loopback-pinned `rpc` command, and arbitrary clearnet hosts would turn
/// `rpc_tor` into a general-purpose proxy the webview can aim anywhere.
fn parse_onion_endpoint(endpoint: &str) -> Result<(String, u16, String), String> {
    let e = endpoint.trim();
    let e = e.strip_prefix("http://").or_else(|| e.strip_prefix("https://")).unwrap_or(e);
    let (hostport, path) = match e.find('/') {
        Some(i) => (&e[..i], &e[i..]),
        None => (e, "/"),
    };
    if hostport.contains('@') {
        return Err("endpoint contains userinfo ('@') — rejected (URL-authority confusion)".into());
    }
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h, parse_port(p)?),
        None => (hostport, 80u16),
    };
    let lower = host.to_ascii_lowercase();
    match lower.strip_suffix(".onion") {
        Some(label) if !label.is_empty() => Ok((lower, port, path.to_string())),
        _ => Err(format!(
            "rpc_tor only accepts a .onion endpoint (got host '{host}'). For the local node use \
             `rpc` (loopback-pinned); arbitrary clearnet hosts are rejected so this command can't \
             be used as a generic proxy."
        )),
    }
}

/// Generic JSON-RPC call to a node. Allowlist-pinned: `url` must pass
/// [`validate_rpc_url`] — the official public HTTPS RPC, a loopback http node,
/// or a user-confirmed custom endpoint (`allow_custom`), never an arbitrary
/// host (SSRF pinning; onion nodes go through `rpc_tor`). HONESTY: this carries
/// only reads (getbalance/getnetworkinfo/…) or an already-locally-signed
/// `sendrawtransaction` — never a key, mnemonic, or password.
#[tauri::command]
fn rpc(url: String, method: String, params: Value, allow_custom: Option<bool>) -> Result<Value, String> {
    validate_rpc_url(&url, allow_custom.unwrap_or(false))?;
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    let resp = ureq::post(&url)
        .timeout(std::time::Duration::from_secs(10))
        .send_json(body)
        .map_err(|e| format!("rpc {method}: {e}"))?;
    resp.into_json::<Value>().map_err(|e| e.to_string())
}

/// The in-process Tor client (Arti), bootstrapped lazily on the first Tor-RPC.
#[derive(Default)]
struct TorState(tokio::sync::Mutex<Option<postern_tor::PosternTor>>);

/// JSON-RPC to an onion node **over Tor** (`<addr>.onion:port[/path]`). The
/// node never learns this machine's IP. Bootstraps Tor on the first call
/// (seconds), then reuses circuits. Onion-pinned: `endpoint` must pass
/// [`parse_onion_endpoint`] — only `.onion` hosts, routed via the in-process
/// Tor client, are accepted; loopback goes through `rpc` and everything else
/// is rejected (SSRF pinning — this is not a general-purpose proxy).
#[tauri::command]
async fn rpc_tor(
    state: State<'_, TorState>,
    endpoint: String,
    method: String,
    params: Value,
) -> Result<Value, String> {
    let (host, port, path) = parse_onion_endpoint(&endpoint)?;
    // Lazily bootstrap, then clone the cheap handle out so the lock is released
    // during the (slow) RPC and concurrent Tor calls aren't serialized.
    let tor = {
        let mut guard = state.0.lock().await;
        if guard.is_none() {
            *guard = Some(postern_tor::PosternTor::bootstrap().await.map_err(|e| e.to_string())?);
        }
        guard.as_ref().unwrap().clone()
    };
    tor.json_rpc(&host, port, &path, &method, params).await.map_err(|e| e.to_string())
}

/// Create a new wallet; returns the mnemonic (show once) + address + pubkey.
#[tauri::command]
fn wallet_generate(testnet: bool) -> Result<Value, String> {
    let (w, mnemonic) = WalletCore::generate(testnet)?;
    Ok(json!({ "mnemonic": mnemonic, "address": w.address(), "pubkey": w.public_key_hex() }))
}

/// Restore a wallet from a mnemonic; returns address + pubkey.
#[tauri::command]
fn wallet_from_mnemonic(phrase: String, testnet: bool) -> Result<Value, String> {
    let w = WalletCore::from_mnemonic(&phrase, testnet)?;
    Ok(json!({ "address": w.address(), "pubkey": w.public_key_hex() }))
}

/// A diversified (unlinkable) receiving address for `index` — rotate one per
/// receive, never reuse (privacy P4). Index 0 is the base address.
#[tauri::command]
fn wallet_address_at(mnemonic: String, testnet: bool, index: u32) -> Result<String, String> {
    WalletCore::from_mnemonic(&mnemonic, testnet)?.address_at(index)
}

/// Send a transparent transaction: reuses the node wallet's full flow
/// (getutxos → build_tx → sign → sendrawtransaction). Returns the txid hex.
/// Allowlist-pinned like `rpc`: `rpc_url` must pass [`validate_rpc_url`].
///
/// KEY BOUNDARY (enforced by construction): the `mnemonic` is used to build and
/// SIGN the transaction LOCALLY inside `WalletClient::send`; it NEVER crosses
/// the RPC. Only `getutxos(address)` and `sendrawtransaction(signed_hex)` reach
/// the node, so a remote/public node sees addresses + already-signed bytes,
/// never a secret.
#[tauri::command]
async fn wallet_send(
    rpc_url: String,
    mnemonic: String,
    testnet: bool,
    to: String,
    amount: u64,
    fee: String,
    allow_custom: Option<bool>,
) -> Result<String, String> {
    use bloch::address::{Address, Network};
    use bloch::wallet::client::{FeePreference, WalletClient};
    use bloch::wallet::{SeedPhrase, Wallet};

    validate_rpc_url(&rpc_url, allow_custom.unwrap_or(false))?;
    let seed = SeedPhrase::parse(&mnemonic).map_err(|e| e.to_string())?;
    let network = if testnet { Network::Testnet } else { Network::Mainnet };
    let wallet = Wallet::from_seed(&seed, network).map_err(|e| e.to_string())?;
    let to_addr = Address::parse(&to).map_err(|e| format!("endereço inválido: {e}"))?;
    let pref = match fee.as_str() {
        "next" => FeePreference::NextBlock,
        "slow" => FeePreference::Slow,
        _ => FeePreference::Medium,
    };
    let client = WalletClient::new(rpc_url);
    let txid = client
        .send(&wallet, &to_addr, amount, pref)
        .await
        .map_err(|e| e.to_string())?;
    Ok(hex::encode(txid))
}

fn main() {
    tauri::Builder::default()
        .manage(NodeProc::default())
        .manage(TorState::default())
        .manage(vault::VaultState::default())
        .manage(pairing::PairState::default())
        .manage(terem::TeremState::default())
        .manage(keys::KeysState::default())
        .manage(vestnik_client::VestnikClientState::default())
        .invoke_handler(tauri::generate_handler![
            // ─────────────────────────────────────────────────────────────
            // Advanced / testnet (zero value)
            //
            // Node control + wallet — the full-node companion surface. HONESTY:
            // this drives a PRE-MAINNET testnet whose coins have ZERO value;
            // the node, wallet and RPC paths are UNAUDITED, and this is not
            // the primary product surface of the desktop app (the Postern
            // modules above/below are). Grouping/labelling only — the
            // commands themselves are unchanged.
            // ─────────────────────────────────────────────────────────────
            node_start,
            node_stop,
            node_status,
            rpc,
            rpc_tor,
            wallet_generate,
            wallet_from_mnemonic,
            wallet_address_at,
            wallet_send,
            // Import a bloch-cli wallet.json (walletjson.rs). REAL interop with
            // the protocol's own CLI keystore: simple `EncryptedKeystore` v2 and
            // HD `HdWalletFile`, read with the `bloch` crate's own decoders so
            // the address round-trip is byte-identical and crate-enforced.
            // wallet_keystore_send spends from an imported simple keystore via
            // the same getutxos→build→broadcast flow `bloch-cli send` uses
            // (loopback-pinned like `rpc`/`wallet_send`).
            walletjson::wallet_import_keystore,
            walletjson::wallet_import_hd,
            walletjson::wallet_keystore_send,
            // ───────────────── end Advanced / testnet (zero value) ────────
            // Vault + Panic — postern-vault/postern-panic backend (vault.rs).
            // vault_status carries the mandatory "not a TEE until real
            // hardware" honesty field; vault_totp_code derives an RFC 6238
            // code from a base32 seed stored as a vault entry (fail closed:
            // locked/missing/malformed → error, never a fake code).
            vault::vault_status,
            vault::vault_create,
            vault::vault_unlock,
            vault::vault_lock,
            vault::vault_list,
            vault::vault_get,
            vault::vault_put,
            vault::vault_remove,
            vault::vault_discard,
            vault::vault_totp_code,
            // Keychain unlock (opt-in `vault-keychain` cargo feature). HONESTY:
            // a SOFTWARE convenience, not hardware protection — the vault key
            // sits in the OS login keychain and is released to any process
            // running as this user; not a TEE until real hardware. The three
            // commands are registered unconditionally: built without the
            // feature they return a clean "not built with keychain support"
            // error, never a silent no-op.
            vault::vault_keychain_enable,
            vault::vault_unlock_keychain,
            vault::vault_keychain_forget,
            vault::panic,
            // Hygiene — metadata scrub-by-default, real postern-hygiene core
            // (hygiene.rs). Fails closed on unsupported formats; never
            // returns a simulated `real: true` result. NOTE (frontend lane):
            // the pane flips off the preview engine once api.js adds
            // "hygiene_scrub" to its REAL set — the contract already matches
            // hygiene.js exactly.
            hygiene::hygiene_scrub,
            // Quarantine — inbound-document safety, the real postern-quarantine
            // core (quarantine.rs). The MIRROR of hygiene: hygiene protects what
            // you SEND, quarantine what you RECEIVE. Images are rebuilt from
            // pixels to a clean PNG; PDFs are rendered (pure-Rust `hayro`,
            // feature render-hayro) and rebuilt into a flat, metadata-free PDF.
            // Fails closed on office/unknown magic; never returns a simulated
            // `real: true` result. HONESTY (carried in every note): the render
            // runs IN-PROCESS with NO OS-level containment (no out-of-process
            // sandbox, no Landlock/seccomp around the renderer, no wall-clock
            // timeout); the image path's Landlock confinement is Linux-only and
            // best-effort. The pane flips off preview once api.js adds
            // "quarantine_rebuild" to its REAL set.
            quarantine::quarantine_rebuild,
            // Phone-as-signer — desktop requester side (v1: wallet-login).
            pairing::pair_begin,
            pairing::pair_respond,
            pairing::pair_confirm,
            pairing::pair_cancel,
            pairing::pair_list,
            pairing::pair_unpair,
            pairing::login_request,
            pairing::login_complete,
            pairing::login_reject,
            pairing::grants_list,
            pairing::grant_revoke,
            // Terem — QEMU/QMP guest-runtime POC (terem.rs). `terem_qmp` is an
            // ALLOWLISTED passthrough, not raw QMP — see terem.rs's module doc.
            terem::terem_create,
            terem::terem_start,
            terem::terem_qmp,
            terem::terem_status,
            terem::terem_stop,
            terem::terem_destroy,
            // Courier — postern-courier hybrid PQ seal (courier.rs). HONESTY:
            // UNAUDITED reference prototype; crypto seal only in this build —
            // the onion transport stays behind the crate's trait seam
            // (mock-transport tested only, NO live-anonymity claim; no Tor
            // process, no network); recipient keys must be authenticated
            // out-of-band (compare fingerprints). Every response carries the
            // courier::HONESTY text.
            courier::courier_generate_recipient,
            courier::courier_seal,
            courier::courier_open,
            // Keys — postern-keys ES256 passkey core (keys.rs). HONESTY:
            // UNAUDITED reference prototype; SOFTWARE authenticator — private
            // keys in app RAM only (zeroize-on-drop, lost on restart), not a
            // hardware key, not a TEE until real hardware; classical P-256 by
            // WebAuthn-ecosystem necessity; no CTAP2/browser integration yet.
            // Every response carries the keys::HONESTY text.
            keys::keys_create,
            keys::keys_list,
            keys::keys_sign,
            keys::keys_remove,
            // Vestnik — desktop custody of the Matrix sealed session
            // (vestnik.rs). HONESTY: the matrix client runs only in a
            // vestnik-matrix build, only on user action (never in CI, never
            // at startup); these custody commands themselves contact no
            // homeserver. The courier recipient secret is a vault entry
            // (requires an UNLOCKED vault, fails closed when locked; the
            // vault is a software seal, not a TEE until real hardware) and
            // sealed-at-rest covers the SavedSession blob ONLY. Every
            // response carries the vestnik::HONESTY text.
            vestnik::vestnik_recipient_init,
            vestnik::vestnik_session_store,
            vestnik::vestnik_session_load,
            vestnik::vestnik_session_open,
            // Vestnik matrix client (opt-in `vestnik-matrix` cargo feature,
            // vestnik_client.rs). ALWAYS registered — built without the
            // feature they return a clean "not built with matrix support"
            // error (never a silent no-op) and vestnik_matrix_status reports
            // { built: false, … } so the pane gates on real capability, the
            // vault-keychain available:false pattern. HONESTY (carried on
            // every response, vestnik_client::HONESTY): a homeserver is
            // contacted ONLY when the user acts (login/sync/send — never in
            // CI, never at app startup); the homeserver sees the social
            // graph (no Tor wiring); Megolm/Olm is classical, not
            // post-quantum; sealed-at-rest covers the SavedSession blob
            // ONLY; the SDK's sqlite store passphrase is SDK-layer only;
            // UNAUDITED. The NotInternalE2ee send refusal is surfaced
            // verbatim — no silent downgrade.
            vestnik_client::vestnik_matrix_status,
            vestnik_client::vestnik_login,
            vestnik_client::vestnik_session_seal,
            vestnik_client::vestnik_restore,
            vestnik_client::vestnik_sync_once,
            vestnik_client::vestnik_rooms,
            vestnik_client::vestnik_send,
            vestnik_client::vestnik_logout,
            // Encrypted Backup — the LOCAL Postern → Filecoin user-backup path,
            // wired to the real bloch-data (data/postern-data) SCAFFOLD.
            // backup_seal encrypts a file with the real Postern AEAD
            // (XChaCha20-Poly1305 v2, key-committing) under an Argon2id key
            // (passphrase/key never leave the device), builds the PBM0/PBP0
            // codecs and a real DATA0 anchor whose manifest_root is a real
            // SHAKE-256 (post-quantum hash). backup_store writes it
            // content-addressed to a user-chosen folder via a real DirBackend.
            // backup_restore RE-VERIFIES the SHAKE-256 anchor + blob integrity
            // then decrypts (fail-closed). backup_filecoin_upload POSTs the
            // already-SEALED ciphertext to Lighthouse over REAL HTTPS (the
            // desktop's ureq + rustls client — NOT bloch-data::LiveBackend,
            // whose hand-rolled HTTP has no in-crate TLS and stays a todo!()
            // stub); backup_filecoin_retrieve fetches it back from the gateway
            // for a byte-identity verify. HONESTY: bloch-data is UNAUDITED
            // scaffold; the anchor is UNSIGNED (no ML-DSA/Falcon — out-of-scope
            // postern-backup-net); ONLY Postern-sealed CIPHERTEXT is uploaded
            // (the provider is trusted for availability, not confidentiality)
            // and the user supplies their OWN Lighthouse token, passed per-call,
            // never logged or persisted; every response carries the
            // backup::HONESTY / backup::FILECOIN_HONESTY text.
            backup::backup_default_dir,
            backup::backup_seal,
            backup::backup_store,
            backup::backup_restore,
            // Filecoin (Lighthouse): backup_filecoin_s3_upload is the PRIMARY
            // path — a signed PUT to the S3-compatible endpoint (minimal in-tree
            // SigV4, ureq+rustls) that returns the real IPFS/Filecoin CID from
            // object metadata; the user supplies their OWN S3 creds per-call
            // (never logged/persisted/baked-in). backup_filecoin_upload (IPFS
            // bearer add) is kept as a labeled fallback — it TIMES OUT on some
            // networks, which is why S3 is now the default.
            backup::backup_filecoin_s3_upload,
            backup::backup_filecoin_upload,
            backup::backup_filecoin_retrieve,
        ])
        // Best-effort: kill the node (and any running Terem guest) if the
        // window closes.
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::Destroyed = event {
                if let Some(state) = window.app_handle().try_state::<NodeProc>() {
                    if let Some(mut child) = state.0.lock().unwrap().take() {
                        let _ = child.kill();
                    }
                }
                if let Some(state) = window.app_handle().try_state::<terem::TeremState>() {
                    state.kill_if_running();
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running Postern Desktop");
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── pin normalization ──────────────────────────────────────────────────

    #[test]
    fn normalize_pin_strips_prefix_and_lowercases() {
        let want = "aa".repeat(32); // 64 hex chars
        let upper = "AA".repeat(32);
        assert_eq!(normalize_pin(&upper).as_deref(), Some(want.as_str()));
        assert_eq!(normalize_pin(&format!("sha256:{upper}")).as_deref(), Some(want.as_str()));
        // Prefix strip is case-insensitive, and surrounding whitespace is trimmed.
        assert_eq!(normalize_pin(&format!("  ShA256:{upper}  ")).as_deref(), Some(want.as_str()));
    }

    #[test]
    fn normalize_pin_treats_blank_as_no_pin() {
        assert_eq!(normalize_pin(""), None);
        assert_eq!(normalize_pin("    "), None);
        assert_eq!(normalize_pin("sha256:"), None);
        assert_eq!(normalize_pin("  SHA256:   "), None);
    }

    // ── pin validity (fail-closed on a set-but-garbage pin) ────────────────

    #[test]
    fn pin_is_valid_hex_accepts_only_64_hex() {
        assert!(pin_is_valid_hex(&"a".repeat(64)));
        assert!(pin_is_valid_hex(&"0123456789abcdef".repeat(4)));
        assert!(!pin_is_valid_hex(&"a".repeat(63)), "too short");
        assert!(!pin_is_valid_hex(&"a".repeat(65)), "too long");
        assert!(!pin_is_valid_hex(&"g".repeat(64)), "non-hex digit");
        assert!(!pin_is_valid_hex(""), "empty");
    }

    // ── binary resolution (name + location + existence + exec-bit) ─────────

    /// Unique scratch dir under the OS temp dir for a single test.
    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "bloch-desktop-test-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[cfg(unix)]
    fn write_exec(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, b"#!/bin/sh\ntrue\n").unwrap();
        let mut perm = std::fs::metadata(path).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(path, perm).unwrap();
    }

    #[test]
    fn resolve_rejects_empty() {
        assert!(resolve_node_binary("   ").is_err());
        assert!(resolve_node_binary("").is_err());
    }

    #[test]
    fn resolve_rejects_bare_non_node_name() {
        // A bare command name is only ever accepted if it is exactly the node's
        // name — never an arbitrary program off $PATH.
        let err = resolve_node_binary("sh").unwrap_err();
        assert!(err.contains("bare command name"), "unexpected error: {err}");
    }

    #[cfg(unix)]
    #[test]
    fn resolve_accepts_real_node_path() {
        let dir = scratch("ok");
        let bin = dir.join(NODE_BIN_NAME);
        write_exec(&bin);
        let resolved = resolve_node_binary(bin.to_str().unwrap()).expect("should resolve");
        assert_eq!(resolved.file_name().and_then(|n| n.to_str()), Some(NODE_BIN_NAME));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn resolve_rejects_wrong_file_name() {
        // A path pointing at a look-alike (wrong name) is refused even if it is a
        // real, executable file.
        let dir = scratch("wrongname");
        let bin = dir.join("blochx");
        write_exec(&bin);
        assert!(resolve_node_binary(bin.to_str().unwrap()).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn resolve_rejects_non_executable() {
        // Correct name but no execute bit → rejected (not an executable).
        let dir = scratch("noexec");
        let bin = dir.join(NODE_BIN_NAME);
        std::fs::write(&bin, b"not executable").unwrap();
        let err = resolve_node_binary(bin.to_str().unwrap()).unwrap_err();
        assert!(err.contains("not executable"), "unexpected error: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_rejects_missing_path() {
        // canonicalize() fails on a non-existent path → rejected up front.
        let missing = std::env::temp_dir().join("bloch-desktop-does-not-exist").join(NODE_BIN_NAME);
        assert!(resolve_node_binary(missing.to_str().unwrap()).is_err());
    }

    // ── peer multiaddr validation (bootstrap peer for --peer) ──────────────

    #[test]
    fn peer_accepts_canonical_and_wellformed_ip4_tcp() {
        // The canonical mainnet peer round-trips unchanged.
        assert_eq!(
            validate_peer_multiaddr(CANONICAL_PEER_MULTIADDR).unwrap(),
            CANONICAL_PEER_MULTIADDR
        );
        for ok in [
            "/ip4/45.32.154.137/tcp/16110",
            "/ip4/127.0.0.1/tcp/1",
            "/ip4/10.0.0.5/tcp/65535",
            "  /ip4/8.8.8.8/tcp/16110  ", // trimmed
        ] {
            assert!(validate_peer_multiaddr(ok).is_ok(), "should accept {ok}");
        }
    }

    #[test]
    fn peer_rejects_bad_shapes_transports_and_ports() {
        for bad in [
            "",                                    // empty
            "   ",                                 // blank
            "45.32.154.137:16110",                 // not a multiaddr
            "/ip4/45.32.154.137",                  // missing /tcp/<port>
            "/ip4/45.32.154.137/tcp",              // missing port
            "/ip4/45.32.154.137/tcp/16110/p2p/Qm", // extra segments
            "/dns4/example.com/tcp/16110",         // hostname/DNS transport
            "/ip6/::1/tcp/16110",                  // ipv6 not accepted here
            "/ip4/999.1.1.1/tcp/16110",            // not an IPv4 address
            "/ip4/45.32.154.137/udp/16110",        // wrong transport
            "/ip4/45.32.154.137/tcp/0",            // port 0
            "/ip4/45.32.154.137/tcp/99999",        // port > 65535
            "/ip4/45.32.154.137/tcp/16110x",       // trailing garbage
        ] {
            assert!(validate_peer_multiaddr(bad).is_err(), "must reject {bad:?}");
        }
    }

    // ── SSRF pinning: rpc / wallet_send allowlist validator ────────────────
    // The allowlist has exactly three members: the official public HTTPS RPC,
    // a loopback http node, and a user-CONFIRMED custom endpoint (allow_custom).
    // Everything else fails closed, so these commands can never be a generic
    // SSRF client against arbitrary LAN/intranet/metadata hosts.

    #[test]
    fn rpc_url_accepts_official_public_and_loopback_without_confirmation() {
        for ok in [
            // Official public RPC — HTTPS + the exact pinned host.
            "https://posternlabs.com",
            "https://posternlabs.com/",
            "https://POSTERNLABS.com/rpc",
            "  https://posternlabs.com  ",
            // Local node — plain http loopback.
            "http://127.0.0.1:8645",
            "http://127.0.0.1:8645/",
            "http://localhost:8645",
            "http://LOCALHOST:8645/rpc",
            "http://[::1]:8645",
            "http://127.0.0.1",
        ] {
            assert!(validate_rpc_url(ok, false).is_ok(), "should accept {ok} without confirmation");
        }
    }

    #[test]
    fn rpc_url_rejects_arbitrary_hosts_without_confirmation() {
        for bad in [
            "https://evil.com",
            "http://example.com:8645",
            "http://10.0.0.5:8645",           // LAN host
            "http://169.254.169.254/latest",  // cloud metadata endpoint
            "http://192.168.1.1:80",
            "http://localhost.evil.com:8645", // suffix trick
            "http://127.0.0.1.evil.com:8645",
            "http://127.0.0.2:8645",          // loopback /8 but not on the strict allowlist
            "http://[fe80::1]:8645",
            "http://posternlabs.com",     // official host but NOT https — rejected
            "https://posternlabs.com.evil.com", // suffix trick on the official host
        ] {
            assert!(validate_rpc_url(bad, false).is_err(), "must reject {bad} without confirmation");
        }
    }

    #[test]
    fn rpc_url_allows_arbitrary_host_only_with_explicit_confirmation() {
        // A user-confirmed custom endpoint (allow_custom = true) is accepted…
        for ok in ["https://my-own-node.example.org:8645", "http://10.0.0.5:8645/rpc"] {
            assert!(validate_rpc_url(ok, true).is_ok(), "confirmed custom {ok} should pass");
            assert!(validate_rpc_url(ok, false).is_err(), "same {ok} must fail WITHOUT confirmation");
        }
        // …but even confirmation cannot bless a malformed URL / userinfo trick.
        for bad in [
            "http://user:pass@10.0.0.5:8645",
            "ftp://10.0.0.5:8645",
            "10.0.0.5:8645",     // no scheme
            "http://10.0.0.5:0", // port 0
        ] {
            assert!(validate_rpc_url(bad, true).is_err(), "confirmation must not bless malformed {bad}");
        }
    }

    #[test]
    fn rpc_url_rejects_userinfo_authority_trick() {
        for bad in [
            "http://127.0.0.1@evil.com:8645",
            "http://user:pass@127.0.0.1:8645",
            "https://posternlabs.com@evil.com/",
        ] {
            let err = validate_rpc_url(bad, false).unwrap_err();
            assert!(err.contains("userinfo"), "unexpected error for {bad}: {err}");
        }
    }

    #[test]
    fn rpc_url_rejects_bad_scheme_and_ports() {
        for bad in [
            "ftp://127.0.0.1:8645",
            "file:///etc/passwd",
            "127.0.0.1:8645", // no scheme
            "",
            "http://",
            "http://127.0.0.1:0",     // port 0
            "http://127.0.0.1:99999", // > 65535
            "http://127.0.0.1:80x",   // trailing garbage
        ] {
            assert!(validate_rpc_url(bad, false).is_err(), "must reject {bad:?}");
            assert!(validate_rpc_url(bad, true).is_err(), "must reject {bad:?} even if confirmed");
        }
    }

    // ── SSRF pinning: rpc_tor onion-only endpoint parser ───────────────────

    #[test]
    fn onion_endpoint_accepts_onion_shapes() {
        let (h, p, path) = parse_onion_endpoint("abcdefgh.onion:8645").unwrap();
        assert_eq!((h.as_str(), p, path.as_str()), ("abcdefgh.onion", 8645, "/"));

        let (h, p, path) = parse_onion_endpoint("http://AbCdEf.ONION:8645/rpc").unwrap();
        assert_eq!((h.as_str(), p, path.as_str()), ("abcdef.onion", 8645, "/rpc"));

        // default port 80, default path "/"
        let (h, p, path) = parse_onion_endpoint("xyz.onion").unwrap();
        assert_eq!((h.as_str(), p, path.as_str()), ("xyz.onion", 80, "/"));
    }

    #[test]
    fn onion_endpoint_rejects_non_onion_hosts() {
        for bad in [
            "example.com:8645",
            "http://10.0.0.5:8645",
            "127.0.0.1:8645",           // loopback belongs to `rpc`, not rpc_tor
            "169.254.169.254:80",
            ".onion:80",                // empty label
            "onion:80",                 // not a .onion suffix
            "evil.onion.example.com:80" // .onion must be the FINAL suffix
        ] {
            assert!(parse_onion_endpoint(bad).is_err(), "must reject {bad}");
        }
    }

    #[test]
    fn onion_endpoint_rejects_userinfo_and_bad_ports() {
        assert!(parse_onion_endpoint("user@abc.onion:80").unwrap_err().contains("userinfo"));
        assert!(parse_onion_endpoint("abc.onion:0").is_err());
        assert!(parse_onion_endpoint("abc.onion:99999").is_err());
        assert!(parse_onion_endpoint("abc.onion:80x").is_err());
    }

    // ── authority splitting (shared by the loopback validator) ─────────────

    #[test]
    fn split_host_port_handles_bracketed_ipv6() {
        assert_eq!(split_host_port("[::1]:8645").unwrap(), ("::1", Some("8645")));
        assert_eq!(split_host_port("[::1]").unwrap(), ("::1", None));
        assert_eq!(split_host_port("127.0.0.1:1").unwrap(), ("127.0.0.1", Some("1")));
        assert_eq!(split_host_port("localhost").unwrap(), ("localhost", None));
        assert!(split_host_port("[::1").is_err(), "unclosed bracket");
        assert!(split_host_port("[::1]8645").is_err(), "junk after bracket");
        assert!(split_host_port("::1:8645").is_err(), "unbracketed IPv6");
    }
}
