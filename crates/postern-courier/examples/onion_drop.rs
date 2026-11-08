//! `onion_drop` — the human-runnable live onion-drop CLI for postern-courier,
//! wiring the EXISTING pieces together end-to-end: hybrid seal ([`seal`]) →
//! sender signature ([`sign_sealed`]) → ephemeral onion publish
//! ([`transport::Sender`]) → [`transport::fetch_signed_verified`] (verify
//! FIRST, replay guard, then open). Verified-receive is the ONLY receive path
//! this example offers — there is deliberately no "just fetch and open" mode.
//!
//! HONEST LIMITS (restated from the crate docs; the binary prints them
//! verbatim on every startup — see [`HONEST_LIMITS`]; never soften them):
//! UNAUDITED reference-prototype end to end — hybrid seal, sender-auth leg,
//! replay guard, onion transport. The onion address crypto is classical Tor:
//! the PQ hybrid protects the payload, not circuit metadata. Payload size and
//! timing remain observable (length-revealing AEAD, no padding). A successful
//! round-trip proves the plumbing works — it is NOT an anonymity claim, NOT a
//! security claim. Authenticate the recipient key and the sender verifying
//! key out-of-band or an active MITM reads/forges everything.
//!
//! # Runbook: the live round-trip (two terminals, real Tor, minutes)
//!
//! This is a documented MANUAL step, not a CI gate — exactly like the
//! double-gated tests in `tests/live_tor_drop.rs` (which stay `#[ignore]` +
//! `POSTERN_LIVE_TOR=1`; this example is the human-driven sibling, not a
//! replacement). A fresh onion-service descriptor takes **minutes** to reach
//! the HSDirs, so budget for that.
//!
//! ```text
//! # Terminal B (recipient) — generate the recipient keypair first:
//! cargo run -p postern-courier --features onion-transport --example onion_drop -- \
//!     keygen
//! #   → writes courier_recipient.pub / courier_recipient.key (hex) to the
//! #     current directory and prints the public key + its fingerprint.
//! #   Hand the PUBLIC key hex to the sender over a channel you both already
//! #   trust, and compare the fingerprint readings aloud.
//!
//! # Terminal A (sender) — seal, sign, publish, serve once:
//! cargo run -p postern-courier --features onion-transport --example onion_drop -- \
//!     send ./the-file -
//! #   (paste the recipient public key hex on stdin; or pass it as the arg)
//! #   → prints the ephemeral .onion address AND the sender verifying key hex
//! #     (+ fingerprint). Hand BOTH to the recipient out-of-band, then leave
//! #     the process running — it serves the drop to the first peer and exits.
//!
//! # Terminal B (recipient) — fetch, verify FIRST, replay-guard, open:
//! cargo run -p postern-courier --features onion-transport --example onion_drop -- \
//!     recv <the .onion address> -
//! #   (paste the sender verifying key hex on stdin; or pass it as the arg)
//! #   → retries the fetch while the descriptor propagates, then writes the
//! #     plaintext to courier_drop.out (refusing to overwrite).
//! ```
//!
//! Both sides bootstrap their own in-process Arti client (no system Tor
//! daemon needed). The sender's accept and the recipient's connect are each
//! bounded by the library's 120 s drop timeout, so both sides RETRY a bounded
//! number of times instead of failing the hand-timed rendezvous on the first
//! timeout. Re-publishing under the same nickname SHOULD keep the same
//! `.onion` address — that is documented arti keystore behavior (the key
//! lives in arti's on-disk keystore, which is also an honest custody limit:
//! a file, not a hardware token), NOT something verified live here yet — so
//! the sender CHECKS the address on every re-publish and, if it ever
//! differs, prints the new address loudly instead of silently serving where
//! nobody is listening.

use std::io::{BufRead, Write as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use postern_courier::replay::ReplayGuard;
use postern_courier::sender_auth::{generate_sender_identity, sender_fingerprint, sign_sealed};
use postern_courier::transport::{
    ensure_rustls_crypto_provider, fetch_signed_verified, PosternTor, Sender, MAX_DROP_BYTES,
};
use postern_courier::{key_fingerprint, seal, Recipient, PUBLIC_KEY_LEN, SECRET_KEY_LEN};

/// The crate's honest-limits text, printed VERBATIM on every startup (a
/// shipping requirement, not decoration). Do not soften, reorder, or hide it.
const HONEST_LIMITS: &str = "UNAUDITED reference-prototype end to end — hybrid seal, sender-auth leg, replay guard, onion transport. The onion address crypto is classical Tor: the PQ hybrid protects the payload, not circuit metadata. Payload size and timing remain observable (length-revealing AEAD, no padding). A successful round-trip proves the plumbing works — it is NOT an anonymity claim, NOT a security claim. Authenticate the recipient key and the sender verifying key out-of-band or an active MITM reads/forges everything.";

/// Recipient public-key file written by `keygen`, read by `recv`. Hex.
const RECIPIENT_PUB_FILE: &str = "courier_recipient.pub";
/// Recipient secret-key file written by `keygen`, read by `recv`. Hex.
/// Honest custody limit: a plain file on disk (0600 on Unix), NOT a hardware
/// token and NOT wrapped by any vault.
const RECIPIENT_KEY_FILE: &str = "courier_recipient.key";
/// Default output path `recv` writes the opened plaintext to.
const DEFAULT_OUT_FILE: &str = "courier_drop.out";

/// How many times the sender re-publishes + re-serves after a (120 s) accept
/// timeout, and the recipient re-tries the fetch while the descriptor
/// propagates. 10 × 120 s ≈ a generous 20-minute human rendezvous window.
const MAX_ATTEMPTS: u32 = 10;
/// Pause between recipient fetch attempts (descriptor propagation takes
/// minutes; hammering the HSDirs helps nobody).
const FETCH_RETRY_PAUSE: Duration = Duration::from_secs(20);

/// The parsed command line. Parsing is pure (no I/O, no Tor) so it is unit
/// tested offline below, per the crate's "the plumbing is testable without a
/// circuit" convention.
#[derive(Debug, PartialEq, Eq)]
enum Cmd {
    /// `keygen [key-dir]` — generate + write the recipient keypair.
    Keygen { dir: PathBuf },
    /// `send <file> [recipient-pub-hex|-]` — seal, sign, publish, serve once.
    /// `None` / `-` means: read the recipient public key hex from stdin.
    Send { file: PathBuf, recipient_hex: Option<String> },
    /// `recv <onion> [sender-vk-hex|-] [out-file] [key-dir]` — fetch, verify
    /// FIRST, replay-guard, open, write plaintext. `None` / `-` means: read
    /// the sender verifying key hex from stdin.
    Recv { onion: String, sender_vk_hex: Option<String>, out: PathBuf, key_dir: PathBuf },
}

const USAGE: &str = "usage:
  onion_drop keygen [key-dir]
  onion_drop send <file> [recipient-pub-hex|-]
  onion_drop recv <onion-address> [sender-vk-hex|-] [out-file] [key-dir]

'-' (or omitting the hex argument) reads the key hex from stdin.
Run each side per the runbook in this example's module docs.";

/// Parse `args` (WITHOUT argv[0]). Pure — see [`Cmd`].
fn parse_args(args: &[String]) -> Result<Cmd, String> {
    let mut it = args.iter();
    match it.next().map(String::as_str) {
        Some("keygen") => {
            let dir = PathBuf::from(it.next().cloned().unwrap_or_else(|| ".".into()));
            if it.next().is_some() {
                return Err(format!("keygen takes at most one argument\n{USAGE}"));
            }
            Ok(Cmd::Keygen { dir })
        }
        Some("send") => {
            let file = PathBuf::from(it.next().ok_or_else(|| format!("send needs a file\n{USAGE}"))?);
            let recipient_hex = hex_arg(it.next());
            if it.next().is_some() {
                return Err(format!("send takes at most two arguments\n{USAGE}"));
            }
            Ok(Cmd::Send { file, recipient_hex })
        }
        Some("recv") => {
            let onion = it
                .next()
                .ok_or_else(|| format!("recv needs an onion address\n{USAGE}"))?
                .clone();
            validate_onion_address(&onion)?;
            let sender_vk_hex = hex_arg(it.next());
            let out = PathBuf::from(it.next().cloned().unwrap_or_else(|| DEFAULT_OUT_FILE.into()));
            let key_dir = PathBuf::from(it.next().cloned().unwrap_or_else(|| ".".into()));
            if it.next().is_some() {
                return Err(format!("recv takes at most four arguments\n{USAGE}"));
            }
            Ok(Cmd::Recv { onion, sender_vk_hex, out, key_dir })
        }
        Some(other) => Err(format!("unknown command {other:?}\n{USAGE}")),
        None => Err(USAGE.to_string()),
    }
}

/// An optional key-hex positional: `-` (the "read stdin" convention) and
/// absence both mean "read from stdin".
fn hex_arg(arg: Option<&String>) -> Option<String> {
    match arg.map(String::as_str) {
        None | Some("-") => None,
        Some(s) => Some(s.to_string()),
    }
}

/// Cheap shape check so an obviously-wrong address fails at parse time
/// instead of after a Tor bootstrap: v3 onion addresses are 56 base32 chars
/// followed by ".onion". This is NOT authentication of the address — that
/// stays out-of-band, like the keys.
fn validate_onion_address(addr: &str) -> Result<(), String> {
    let stem = addr
        .strip_suffix(".onion")
        .ok_or_else(|| format!("{addr:?} does not end in .onion"))?;
    if stem.len() != 56 || !stem.chars().all(|c| c.is_ascii_lowercase() || ('2'..='7').contains(&c))
    {
        return Err(format!("{addr:?} is not a v3 onion address (56 base32 chars + .onion)"));
    }
    Ok(())
}

// --- hex helpers (pure; unit tested offline) ---------------------------------
// The crate has no hex dependency and the keys cross terminals as text, so the
// example carries its own minimal, tested codec instead of adding a dep.

/// Lowercase hex encoding.
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Strict hex decoding: even length, `[0-9a-fA-F]` only. Surrounding ASCII
/// whitespace is trimmed (keys arrive by paste); interior whitespace is an
/// error — a truncated paste must fail loudly, never decode to a short key.
fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err(format!("hex has odd length {} (truncated paste?)", s.len()));
    }
    let nibble = |c: u8| -> Result<u8, String> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(format!("invalid hex character {:?}", c as char)),
        }
    };
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    for pair in b.chunks_exact(2) {
        out.push(nibble(pair[0])? << 4 | nibble(pair[1])?);
    }
    Ok(out)
}

/// Take a key as hex from `arg` if present, otherwise prompt and read one
/// line from stdin, then decode and enforce `expected_len`.
fn read_key_hex(arg: Option<String>, prompt: &str, expected_len: usize) -> Result<Vec<u8>, String> {
    let hex = match arg {
        Some(h) => h,
        None => {
            eprint!("{prompt}: ");
            std::io::stderr().flush().ok();
            let mut line = String::new();
            std::io::stdin()
                .lock()
                .read_line(&mut line)
                .map_err(|e| format!("reading stdin: {e}"))?;
            line
        }
    };
    let key = hex_decode(&hex)?;
    if key.len() != expected_len {
        return Err(format!("key is {} bytes, expected {expected_len}", key.len()));
    }
    Ok(key)
}

// --- subcommands --------------------------------------------------------------

/// `keygen`: generate the recipient hybrid keypair and write it to `dir`.
fn run_keygen(dir: &Path) -> Result<(), String> {
    let pub_path = dir.join(RECIPIENT_PUB_FILE);
    let key_path = dir.join(RECIPIENT_KEY_FILE);
    if pub_path.exists() || key_path.exists() {
        return Err(format!(
            "refusing to overwrite existing {} / {} — move them first",
            pub_path.display(),
            key_path.display()
        ));
    }

    let rcpt: Recipient = postern_courier::generate_recipient();
    // BOTH files are created with `create_new` — the exists() check above is
    // only for the friendlier combined message; the authoritative
    // refuse-to-overwrite is the atomic create (no check-then-write race).
    // Public first: if the SECRET create then fails, remove the public half
    // (best-effort) so no stray half-keypair is left behind — and a stray
    // public key would be the harmless half anyway.
    write_new_file(&pub_path, &hex_encode(&rcpt.public), false)?;
    if let Err(e) = write_new_file(&key_path, &hex_encode(&rcpt.secret), true) {
        let _ = std::fs::remove_file(&pub_path);
        return Err(e);
    }

    println!("{}", hex_encode(&rcpt.public));
    eprintln!();
    eprintln!("recipient public key written to {} (hex above)", pub_path.display());
    eprintln!("recipient SECRET key written to {} — a plain file, NOT a hardware token; guard it", key_path.display());
    eprintln!("recipient key fingerprint: {}", key_fingerprint(&rcpt.public));
    eprintln!("Hand the PUBLIC key hex to the sender over a channel you both already trust,");
    eprintln!("and compare the fingerprint readings aloud — the seal cannot detect a substituted key.");
    Ok(())
}

/// Write `contents` to `path`, refusing to overwrite via `create_new` (an
/// atomic create — never a check-then-write race). `secret` additionally
/// sets mode 0600 on Unix.
fn write_new_file(path: &Path, contents: &str, secret: bool) -> Result<(), String> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        if secret {
            opts.mode(0o600);
        }
    }
    #[cfg(not(unix))]
    let _ = secret;
    let mut f = opts
        .open(path)
        .map_err(|e| format!("creating {}: {e}", path.display()))?;
    f.write_all(contents.as_bytes())
        .map_err(|e| format!("writing {}: {e}", path.display()))
}

/// `send`: seal to the recipient key, sign with a fresh per-drop sender
/// identity, publish the ephemeral onion, print the handover values, serve once.
async fn run_send(file: &Path, recipient_hex: Option<String>) -> Result<(), String> {
    let recipient_public = read_key_hex(
        recipient_hex,
        "paste the recipient public key hex (from their `keygen`)",
        PUBLIC_KEY_LEN,
    )?;
    eprintln!("recipient key fingerprint: {}", key_fingerprint(&recipient_public));
    eprintln!("(compare that reading with the recipient out-of-band BEFORE trusting this drop)");

    let plaintext =
        std::fs::read(file).map_err(|e| format!("reading {}: {e}", file.display()))?;

    // Fresh per-drop sender identity: ephemeral by design in this example —
    // the verifying key travels out-of-band with the onion address. (A real
    // product persists and re-authenticates a long-lived sender identity.)
    let sender_id = generate_sender_identity();
    let sealed = seal(&recipient_public, &plaintext).map_err(|e| format!("seal: {e}"))?;
    let signed = sign_sealed(&sender_id, &recipient_public, &sealed);
    let wire_len = signed.to_bytes().len();
    if wire_len > MAX_DROP_BYTES {
        return Err(format!(
            "signed drop is {wire_len} bytes; the transport cap is {MAX_DROP_BYTES}"
        ));
    }

    eprintln!("bootstrapping Tor (in-process Arti; seconds on a good link)…");
    // rustls needs a process-level crypto provider before the first TLS
    // handshake (see the helper's docs — backend selection only).
    ensure_rustls_crypto_provider();
    let tor = PosternTor::bootstrap().await.map_err(|e| format!("tor bootstrap: {e}"))?;

    // One nickname per run → one onion address per run, stable across the
    // retry loop below (the key is scoped by nickname in arti's keystore).
    // HsNickname charset is [a-z0-9_].
    let nickname = format!(
        "courier_drop_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    );

    // "Same nickname ⇒ same address on re-publish" is documented arti keystore
    // behavior that has NOT been verified live by this project — so never
    // trust it silently: remember the address the recipient was handed and
    // CHECK it on every re-publish.
    let mut handed_over_address: Option<String> = None;
    for attempt in 1..=MAX_ATTEMPTS {
        // A re-publish under the same nickname can fail transiently while
        // arti is still tearing the PREVIOUS attempt's service down
        // (observed live 2026-07-16: attempt 3's publish failed after two
        // accept timeouts and killed the whole 20-minute rendezvous window).
        // Publish failure is therefore retryable like everything else in
        // this loop — pause, then spend the attempt; only the last attempt's
        // failure is fatal.
        let sender = match Sender::publish(&tor, &nickname).await {
            Ok(sender) => sender,
            Err(e) if attempt < MAX_ATTEMPTS => {
                eprintln!(
                    "attempt {attempt}/{MAX_ATTEMPTS}: publish failed ({e}); the previous \
                     service may still be tearing down — pausing and retrying…"
                );
                tokio::time::sleep(FETCH_RETRY_PAUSE).await;
                continue;
            }
            Err(e) => return Err(format!("onion publish: {e}")),
        };
        match &handed_over_address {
            None => {
                handed_over_address = Some(sender.onion_address().to_string());
                // The handover block — machine-copyable values on stdout.
                println!("{}", sender.onion_address());
                println!("{}", hex_encode(&sender_id.public));
                eprintln!();
                eprintln!("onion address (line 1 above) + sender verifying key hex (line 2 above)");
                eprintln!("sender key fingerprint: {}", sender_fingerprint(&sender_id.public));
                eprintln!("Hand BOTH to the recipient over the same trusted out-of-band channel,");
                eprintln!("and compare the sender fingerprint readings aloud.");
                eprintln!();
                eprintln!(
                    "serving one signed drop ({wire_len} bytes on the wire — the size IS observable); \
                     a fresh descriptor takes minutes to propagate…"
                );
            }
            Some(prev) if prev != sender.onion_address() => {
                // The documented behavior did not hold — say so loudly and
                // put the NEW address on stdout instead of silently serving
                // at an address nobody was handed.
                println!("{}", sender.onion_address());
                eprintln!(
                    "WARNING: re-publish under the same nickname returned a DIFFERENT onion \
                     address — the documented arti keystore persistence did not hold here. \
                     The old address is dead; hand the recipient the NEW address (line above)."
                );
                handed_over_address = Some(sender.onion_address().to_string());
            }
            Some(_) => {}
        }
        match sender.deliver_once_signed(&signed).await {
            Ok(()) => {
                eprintln!("drop served; exiting. (Plumbing worked — that is all a success proves.)");
                return Ok(());
            }
            Err(e) if attempt < MAX_ATTEMPTS => {
                // Almost always the 120 s accept timeout while the human on
                // the other side is still pasting keys. The address is
                // re-checked (not assumed) on the next publish above.
                eprintln!("attempt {attempt}/{MAX_ATTEMPTS}: no peer yet ({e}); re-publishing and re-serving…");
            }
            Err(e) => return Err(format!("giving up after {MAX_ATTEMPTS} attempts: {e}")),
        }
    }
    unreachable!("loop returns or errors on the last attempt");
}

/// `recv` retry policy, pure so it is unit tested offline: ONLY the coarse
/// [`postern_courier::CourierError::Transport`] (connect refused / timed out /
/// wire framing rejected — the expected shape of "the descriptor has not
/// propagated yet") is retryable. Every other error means a frame actually
/// ARRIVED and failed — parse, signature, replay, or decrypt — and the sender
/// is single-shot, so a retry could only re-fetch the same bad bytes; those
/// are final on the first occurrence.
fn recv_error_is_final(err: &postern_courier::CourierError) -> bool {
    !matches!(err, postern_courier::CourierError::Transport)
}

/// `recv`: fetch the signed drop from the onion address and run the FULL
/// verified-receive pipeline — [`postern_courier::sender_auth::verify_sealed`]
/// FIRST, then the [`ReplayGuard`], then open — via [`fetch_signed_verified`].
async fn run_recv(
    onion: &str,
    sender_vk_hex: Option<String>,
    out: &Path,
    key_dir: &Path,
) -> Result<(), String> {
    let sender_verifying_key = read_key_hex(
        sender_vk_hex,
        "paste the sender verifying key hex (from their `send`)",
        postern_courier::sender_auth::SENDER_VERIFYING_KEY_LEN,
    )?;
    eprintln!("sender key fingerprint: {}", sender_fingerprint(&sender_verifying_key));
    eprintln!("(compare that reading with the sender out-of-band BEFORE trusting this drop)");

    let pub_path = key_dir.join(RECIPIENT_PUB_FILE);
    let key_path = key_dir.join(RECIPIENT_KEY_FILE);
    let read_hex_file = |p: &Path, expected: usize| -> Result<Vec<u8>, String> {
        let hex = std::fs::read_to_string(p)
            .map_err(|e| format!("reading {} (run `keygen` first?): {e}", p.display()))?;
        let key = hex_decode(&hex)?;
        if key.len() != expected {
            return Err(format!("{}: {} bytes, expected {expected}", p.display(), key.len()));
        }
        Ok(key)
    };
    let recipient_public = read_hex_file(&pub_path, PUBLIC_KEY_LEN)?;
    let recipient_secret = read_hex_file(&key_path, SECRET_KEY_LEN)?;

    // Refuse to overwrite BEFORE spending minutes on Tor.
    if out.exists() {
        return Err(format!("refusing to overwrite {} — move it first", out.display()));
    }

    eprintln!("bootstrapping Tor (in-process Arti; seconds on a good link)…");
    // rustls needs a process-level crypto provider before the first TLS
    // handshake (see the helper's docs — backend selection only).
    ensure_rustls_crypto_provider();
    let tor = PosternTor::bootstrap().await.map_err(|e| format!("tor bootstrap: {e}"))?;

    // Single-shot drop, but the descriptor may not have propagated yet, so
    // retry the fetch a bounded number of times. The guard is plumbing-honest
    // here: one process, one fetch — its window-bounded, in-process,
    // lost-on-restart protection is demonstrated, not meaningfully exercised.
    let mut guard = ReplayGuard::with_default_window();
    let mut last_err = None;
    for attempt in 1..=MAX_ATTEMPTS {
        eprintln!("fetch attempt {attempt}/{MAX_ATTEMPTS} from {onion}…");
        match fetch_signed_verified(
            &tor,
            onion,
            &sender_verifying_key,
            &recipient_public,
            &recipient_secret,
            &mut guard,
        )
        .await
        {
            Ok(plaintext) => {
                let mut opts = std::fs::OpenOptions::new();
                opts.write(true).create_new(true);
                let mut f = opts
                    .open(out)
                    .map_err(|e| format!("creating {}: {e}", out.display()))?;
                f.write_all(&plaintext)
                    .map_err(|e| format!("writing {}: {e}", out.display()))?;
                eprintln!(
                    "verified drop opened: {} bytes written to {}",
                    plaintext.len(),
                    out.display()
                );
                eprintln!("(Signature verified FIRST, replay guard passed, then decrypted.");
                eprintln!(" Plumbing worked — that is all a success proves.)");
                return Ok(());
            }
            // A verification/replay/decrypt failure is FINAL — the bytes
            // arrived and failed the pipeline; retrying would re-fetch the
            // same forgery (and the guard has burned the nonce anyway).
            Err(e @ postern_courier::CourierError::SenderSignature)
            | Err(e @ postern_courier::CourierError::SenderKey)
            | Err(e @ postern_courier::CourierError::ReplayStale)
            | Err(e @ postern_courier::CourierError::ReplayFutureDated)
            | Err(e @ postern_courier::CourierError::ReplayNonceReused)
            | Err(e @ postern_courier::CourierError::Open) => {
                return Err(format!("drop REJECTED by the verified-receive pipeline: {e}"));
            }
            // Only a coarse transport failure (connect refused / timed out /
            // bad framing on the wire) is worth retrying while the descriptor
            // propagates.
            Err(e) if !recv_error_is_final(&e) => {
                eprintln!("  not yet ({e}); descriptor propagation takes minutes");
                last_err = Some(e);
                if attempt < MAX_ATTEMPTS {
                    tokio::time::sleep(FETCH_RETRY_PAUSE).await;
                }
            }
            // Everything else means a frame ARRIVED and did not parse as a
            // signed drop (bad version, malformed key/ciphertext fields, …).
            // The sender is single-shot: a retry could only re-download the
            // same garbage — fail loudly instead of burning ~3 minutes of
            // retries a hostile server controls.
            Err(e) => {
                return Err(format!(
                    "malformed drop frame — bytes arrived but did not parse as a signed drop \
                     ({e}); not retrying (a retry would re-fetch the same bytes)"
                ));
            }
        }
    }
    Err(format!(
        "giving up after {MAX_ATTEMPTS} attempts: {}",
        last_err.map(|e| e.to_string()).unwrap_or_else(|| "no attempt ran".into())
    ))
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> std::process::ExitCode {
    // The honest-limits text prints on EVERY startup, before anything else —
    // a shipping requirement of the crate, not decoration.
    eprintln!("postern-courier onion_drop — HONEST LIMITS:");
    eprintln!("{HONEST_LIMITS}");
    eprintln!();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = match parse_args(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let result = match cmd {
        Cmd::Keygen { dir } => run_keygen(&dir),
        Cmd::Send { file, recipient_hex } => run_send(&file, recipient_hex).await,
        Cmd::Recv { onion, sender_vk_hex, out, key_dir } => {
            run_recv(&onion, sender_vk_hex, &out, &key_dir).await
        }
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

// --- offline unit tests (no Tor, no network) ----------------------------------
// Run with the example's test target:
// `cargo test -p postern-courier --features onion-transport --example onion_drop`
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let bytes: Vec<u8> = (0..=255u8).collect();
        let hex = hex_encode(&bytes);
        assert_eq!(hex.len(), 512);
        assert_eq!(hex_decode(&hex).unwrap(), bytes);
        // Uppercase and surrounding whitespace are accepted on decode.
        assert_eq!(hex_decode(&format!("  {}\n", hex.to_uppercase())).unwrap(), bytes);
    }

    #[test]
    fn hex_decode_rejects_bad_input() {
        assert!(hex_decode("abc").is_err()); // odd length (truncated paste)
        assert!(hex_decode("zz").is_err()); // not hex
        assert!(hex_decode("aa bb").is_err()); // interior whitespace
        assert_eq!(hex_decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn parse_keygen() {
        assert_eq!(
            parse_args(&["keygen".into()]).unwrap(),
            Cmd::Keygen { dir: PathBuf::from(".") }
        );
        assert_eq!(
            parse_args(&["keygen".into(), "/tmp/k".into()]).unwrap(),
            Cmd::Keygen { dir: PathBuf::from("/tmp/k") }
        );
        assert!(parse_args(&["keygen".into(), "a".into(), "b".into()]).is_err());
    }

    #[test]
    fn parse_send() {
        assert_eq!(
            parse_args(&["send".into(), "f.bin".into()]).unwrap(),
            Cmd::Send { file: PathBuf::from("f.bin"), recipient_hex: None }
        );
        // `-` is the explicit read-stdin spelling.
        assert_eq!(
            parse_args(&["send".into(), "f.bin".into(), "-".into()]).unwrap(),
            Cmd::Send { file: PathBuf::from("f.bin"), recipient_hex: None }
        );
        assert_eq!(
            parse_args(&["send".into(), "f.bin".into(), "ab12".into()]).unwrap(),
            Cmd::Send { file: PathBuf::from("f.bin"), recipient_hex: Some("ab12".into()) }
        );
        assert!(parse_args(&["send".into()]).is_err());
        assert!(parse_args(&["send".into(), "f".into(), "h".into(), "x".into()]).is_err());
    }

    #[test]
    fn parse_recv() {
        let onion = format!("{}.onion", "a".repeat(56));
        assert_eq!(
            parse_args(&["recv".into(), onion.clone()]).unwrap(),
            Cmd::Recv {
                onion: onion.clone(),
                sender_vk_hex: None,
                out: PathBuf::from(DEFAULT_OUT_FILE),
                key_dir: PathBuf::from("."),
            }
        );
        assert_eq!(
            parse_args(&[
                "recv".into(),
                onion.clone(),
                "ab".into(),
                "out.bin".into(),
                "/keys".into()
            ])
            .unwrap(),
            Cmd::Recv {
                onion,
                sender_vk_hex: Some("ab".into()),
                out: PathBuf::from("out.bin"),
                key_dir: PathBuf::from("/keys"),
            }
        );
        assert!(parse_args(&["recv".into()]).is_err());
    }

    #[test]
    fn parse_rejects_unknown_and_empty() {
        assert!(parse_args(&[]).is_err());
        assert!(parse_args(&["frobnicate".into()]).is_err());
    }

    #[test]
    fn onion_address_shape_check() {
        assert!(validate_onion_address(&format!("{}.onion", "a".repeat(56))).is_ok());
        // base32 digits 2-7 are fine.
        assert!(validate_onion_address(&format!("{}234567.onion", "b".repeat(50))).is_ok());
        assert!(validate_onion_address("example.com").is_err());
        assert!(validate_onion_address(&format!("{}.onion", "a".repeat(55))).is_err()); // short
        assert!(validate_onion_address(&format!("{}.onion", "A".repeat(56))).is_err()); // upper
        assert!(validate_onion_address(&format!("{}1.onion", "a".repeat(55))).is_err()); // '1' not base32
    }

    /// Fresh per-test scratch dir under the system temp dir (no tempfile dep).
    fn fresh_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("onion_drop_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir); // clean slate across re-runs
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn recv_retry_policy_only_transport_is_retryable() {
        use postern_courier::CourierError as E;
        // The one transient shape: descriptor not propagated / connect failed.
        assert!(!recv_error_is_final(&E::Transport));
        // EVERYTHING else means bytes arrived and failed the pipeline —
        // parse, key, signature, replay, decrypt — and the sender is
        // single-shot, so a retry can only re-fetch the same bad bytes.
        for final_err in [
            E::PublicKey,
            E::SecretKey,
            E::KemCiphertext,
            E::SharedSecret,
            E::Version,
            E::Seal,
            E::Open,
            E::ReplayStale,
            E::ReplayFutureDated,
            E::ReplayNonceReused,
            E::SenderKey,
            E::SenderSignature,
        ] {
            assert!(recv_error_is_final(&final_err), "{final_err:?} must be final");
        }
    }

    #[test]
    fn write_new_file_refuses_overwrite_atomically() {
        let dir = fresh_dir("write_new");
        let p = dir.join("f");
        write_new_file(&p, "first", false).unwrap();
        // Second create MUST fail (create_new) and MUST NOT clobber.
        let err = write_new_file(&p, "second", false).unwrap_err();
        assert!(err.contains("creating"), "{err}");
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "first");
        // The secret spelling is 0600 on Unix.
        let s = dir.join("s");
        write_new_file(&s, "top", true).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&s).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "secret file must be 0600");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn keygen_writes_hex_keypair_then_refuses_second_run() {
        let dir = fresh_dir("keygen");
        run_keygen(&dir).unwrap();
        let pub_hex = std::fs::read_to_string(dir.join(RECIPIENT_PUB_FILE)).unwrap();
        let key_hex = std::fs::read_to_string(dir.join(RECIPIENT_KEY_FILE)).unwrap();
        assert_eq!(hex_decode(&pub_hex).unwrap().len(), PUBLIC_KEY_LEN);
        assert_eq!(hex_decode(&key_hex).unwrap().len(), SECRET_KEY_LEN);
        // A second run refuses and clobbers neither file.
        let err = run_keygen(&dir).unwrap_err();
        assert!(err.contains("refusing to overwrite"), "{err}");
        assert_eq!(std::fs::read_to_string(dir.join(RECIPIENT_PUB_FILE)).unwrap(), pub_hex);
        assert_eq!(std::fs::read_to_string(dir.join(RECIPIENT_KEY_FILE)).unwrap(), key_hex);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn keygen_refuses_when_only_one_half_exists_and_preserves_it() {
        // Covers the state the exists() pre-check alone would miss if it ever
        // regressed to checking a single file — and documents that a leftover
        // half is preserved, never clobbered (the create_new writes are the
        // authoritative guard).
        let dir = fresh_dir("keygen_half");
        std::fs::write(dir.join(RECIPIENT_PUB_FILE), "sentinel").unwrap();
        // Must refuse (today via the friendly pre-check; the create_new write
        // refuses too if that check ever regresses) and must preserve the file.
        run_keygen(&dir).unwrap_err();
        assert_eq!(
            std::fs::read_to_string(dir.join(RECIPIENT_PUB_FILE)).unwrap(),
            "sentinel"
        );
        assert!(!dir.join(RECIPIENT_KEY_FILE).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn honest_limits_text_is_verbatim_and_uncensored() {
        // The shipping requirement: the exact honest-limits sentences, present
        // and unsoftened. Guard the load-bearing claims verbatim.
        for must_contain in [
            "UNAUDITED reference-prototype end to end",
            "classical Tor",
            "protects the payload, not circuit metadata",
            "NOT an anonymity claim, NOT a security claim",
            "out-of-band or an active MITM reads/forges everything",
        ] {
            assert!(
                HONEST_LIMITS.contains(must_contain),
                "honest-limits text lost: {must_contain:?}"
            );
        }
    }
}
