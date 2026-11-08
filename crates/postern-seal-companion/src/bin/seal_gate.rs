//! postern-seal-gate — the guest-side attestation endpoint of a Postern Cloud
//! confidential VM (POSTERN-CLOUD.md §4.1; wired in by os/cloud.nix).
//!
//! The ONLY pre-attestation listener on the guest. Per connection:
//! 1. read the client's challenge (`PSG1` ‖ nonce);
//! 2. request a SEV-SNP report from `/dev/sev-guest` with
//!    `report_data = SHA-256(nonce ‖ WG_guest_pub) ‖ 0…` (channel binding);
//! 3. reply with `PSE1` ‖ report ‖ VCEK ‖ WG_guest_pub.
//!
//! It holds NO secrets (the report, certs, and pubkey are public values) and
//! never trusts its peer: fixed-size challenge, one response, connection
//! closed. Verification is entirely the client's job (postern-seal-verify).
//!
//! The guest-side report fetch is NOT reimplemented here: the `/dev/sev-guest`
//! ioctl path lives once in the library
//! ([`postern_seal_companion::snp::request_bound_evidence`], with
//! [`postern_seal_companion::snp::sev_guest_device_present`] as its startup
//! probe). This binary is a thin transport shell over that one tested,
//! fail-closed codepath — there is no second inline copy of the ioctls to drift.
//!
//! HONEST STATUS: compiles everywhere; the report path requires Linux with the
//! sev-guest driver in a real SEV-SNP VM and has NOT been exercised on hardware
//! — this repo has no confidential VM to run it in. Where `/dev/sev-guest` is
//! absent (any non-Linux host, or a Linux host that is not an SEV-SNP guest) the
//! gate fails closed at startup with a named message and serves nothing. VCEK
//! delivery uses the extended report's cert table (hypervisor-provisioned);
//! where the host does not provision certs (e.g. some clouds), fetch the VCEK
//! from AMD KDS at provision time and pass `--vcek <path>`.
//!
//! Usage:
//!   postern-seal-gate --wg-pubkey /persist/postern/wg0.pub \
//!                     [--listen 0.0.0.0:16510] [--vcek /persist/postern/vcek.der]

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut listen = "0.0.0.0:16510".to_string();
    let mut wg_pubkey_path: Option<String> = None;
    let mut vcek_path: Option<String> = None;
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--listen" => listen = it.next().unwrap_or_else(|| usage("--listen needs a value")),
            "--wg-pubkey" => wg_pubkey_path = Some(it.next().unwrap_or_else(|| usage("--wg-pubkey needs a value"))),
            "--vcek" => vcek_path = Some(it.next().unwrap_or_else(|| usage("--vcek needs a value"))),
            other => usage(&format!("unknown argument: {other}")),
        }
    }
    let Some(wg_pubkey_path) = wg_pubkey_path else { usage("--wg-pubkey is required") };
    run(&listen, &wg_pubkey_path, vcek_path.as_deref());
}

fn usage(err: &str) -> ! {
    eprintln!("postern-seal-gate: {err}");
    eprintln!("usage: postern-seal-gate --wg-pubkey <path> [--listen addr:port] [--vcek <der path>]");
    std::process::exit(2);
}

fn run(listen: &str, wg_pubkey_path: &str, vcek_path: Option<&str>) {
    use postern_seal_companion::gate::{decode_challenge, CHALLENGE_LEN};
    use postern_seal_companion::snp::{request_bound_evidence, sev_guest_device_present};
    use std::io::{Read, Write};

    // Fail closed at startup: a gate must produce hardware evidence or nothing.
    // `sev_guest_device_present()` is the library's platform probe — always
    // false off Linux, and false on a Linux host that is not an SEV-SNP guest.
    // Checking it here yields ONE honest "not a confidential VM" line at startup
    // instead of one fabricated-looking failure per connection, and is the named
    // fail-closed exit this binary takes on a non-TEE host (e.g. a dev macOS or
    // a plain Linux box). It never fabricates or serves evidence it cannot back.
    if !sev_guest_device_present() {
        eprintln!(
            "postern-seal-gate: /dev/sev-guest is not present — this host is not an SEV-SNP \
             confidential VM (on non-Linux it cannot exist at all). SEV-SNP reports are the \
             only thing this gate serves, so there is nothing it can honestly produce here. \
             Refusing to listen (fail closed)."
        );
        std::process::exit(1);
    }

    // The WireGuard public key this guest generated on first boot — the key
    // the channel binding endorses. 32 raw bytes, or 44 base64 chars (the
    // `wg pubkey` output format).
    let wg_pub = read_wg_pubkey(wg_pubkey_path);

    // Static VCEK, if provisioned out of band (AMD KDS fetch at deploy time).
    let static_vcek: Option<Vec<u8>> = vcek_path.map(|p| {
        std::fs::read(p).unwrap_or_else(|e| {
            eprintln!("postern-seal-gate: cannot read VCEK {p}: {e}");
            std::process::exit(1);
        })
    });

    let listener = std::net::TcpListener::bind(listen).unwrap_or_else(|e| {
        eprintln!("postern-seal-gate: cannot bind {listen}: {e}");
        std::process::exit(1);
    });
    eprintln!("postern-seal-gate: listening on {listen} (evidence endpoint; nothing secret served)");

    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(5)));

        // Exactly one fixed-size challenge.
        let mut challenge = [0u8; CHALLENGE_LEN];
        if stream.read_exact(&mut challenge).is_err() {
            continue;
        }
        let nonce = match decode_challenge(&challenge) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("postern-seal-gate: bad challenge: {e}");
                continue;
            }
        };

        // ONE guest-side codepath: the library binds `report_data` from the
        // nonce + pubkey, drives the /dev/sev-guest ioctls, and pulls the VCEK
        // (cert table, or `static_vcek` override). No VCEK ⇒ fail-closed
        // ReportError::NoVcek — we log and close, never emit unverifiable bytes.
        match request_bound_evidence(&nonce, &wg_pub, Some(0), static_vcek.as_deref()) {
            Ok(evidence) => {
                let _ = stream.write_all(&evidence.encode());
            }
            Err(e) => {
                // Do not reply with anything unverifiable — just log and close.
                eprintln!("postern-seal-gate: report request failed: {e}");
            }
        }
    }
}

fn read_wg_pubkey(path: &str) -> Vec<u8> {
    let raw = std::fs::read(path).unwrap_or_else(|e| {
        eprintln!("postern-seal-gate: cannot read WG pubkey {path}: {e}");
        std::process::exit(1);
    });
    if raw.len() == 32 {
        return raw;
    }
    // `wg pubkey` emits base64; a WireGuard key is exactly 32 bytes.
    let text: String = String::from_utf8_lossy(&raw).trim().to_string();
    match b64_decode(&text) {
        Some(k) if k.len() == 32 => k,
        _ => {
            eprintln!("postern-seal-gate: {path} is neither 32 raw bytes nor a base64 WireGuard public key");
            std::process::exit(1);
        }
    }
}

/// Minimal standard-alphabet base64 decode (no dependency for one key file).
fn b64_decode(s: &str) -> Option<Vec<u8>> {
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let val = |c: u8| ALPHA.iter().position(|&a| a == c);
    let s = s.trim_end_matches('=');
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u8;
    for &c in s.as_bytes() {
        acc = (acc << 6) | val(c)? as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}
