//! postern-seal-verify — the client side of the Seal-gate handshake
//! (POSTERN-CLOUD.md §4.1 step 1–3): send a fresh nonce, receive evidence,
//! verify the SEV-SNP report up the VCEK → ASK → ARK chain to the pinned AMD
//! root, check measurement / HOSTDATA / channel binding / TCB, and print the
//! verdict. Exit 0 ⇔ Genuine; anything else is a loud, named refusal.
//!
//! This is the tool the runbook (docs/specs/POSTERN-CLOUD-CONFIDENTIAL.md)
//! drives against a real confidential VM. On Genuine it prints the guest
//! public key the evidence endorsed — the ONLY key it is sound to open the
//! WireGuard tunnel to.
//!
//! End-to-end revocation: pass `--crl <der>` with the AMD-KDS CRL for this
//! product line (fetched out of band from
//! `https://kdsintf.amd.com/vcek/v1/<Milan|Genoa|Turin>/crl`). With it the
//! verdict runs the full chain PLUS the CRL gate — the VCEK must chain to the
//! pinned AMD root AND not be revoked, and the CRL itself must be ASK-signed and
//! fresh (`nextUpdate` not elapsed). Revocation is fail-closed by default:
//! without `--crl` the verdict is REJECTED (no CRL to check against) unless
//! the operator passes the loud `--insecure-skip-revocation` opt-out.
//!
//! Usage:
//!   postern-seal-verify --gate <host:port> --generation milan|genoa|turin \
//!       --measurement <96 hex> [--host-data <64 hex>] \
//!       [--min-tcb bl,tee,snp,ucode] [--vmpl 0] \
//!       [--crl <der path> | --insecure-skip-revocation]

use postern_seal_companion::gate::{
    encode_challenge, GateEvidence, MAX_CERT_LEN, MAX_PUBKEY_LEN, MAX_REPORT_LEN,
};
use postern_seal_companion::snp::{
    verify_gate_evidence, AmdGeneration, KdsCrl, MinTcb, RevocationPolicy, SnpExpected, SnpVerdict,
};
use std::io::{Read, Write};

/// Wire-format overhead on top of the three field payloads: the 4-byte
/// `PSE1` magic plus one little-endian `u32` length prefix per field
/// (`gate.rs`'s `GateEvidence::encode`/`decode`: magic + 3 x (len || bytes)).
const EVIDENCE_HEADER_OVERHEAD: u64 = 4 + 3 * 4;

/// Hard ceiling on how many bytes the transport will ever hand to
/// `GateEvidence::decode`. This is the actual DoS fix: `gate.rs`'s per-field
/// caps only run on bytes already sitting in memory, so an unbounded
/// `read_to_end` ahead of `decode` lets a malicious/MITM gate stream
/// unbounded data and OOM the verifier before decode ever gets a chance to
/// reject it. The cap below is exactly the size of the largest legitimate
/// evidence message (every field at its hard cap) plus the header.
const MAX_EVIDENCE_WIRE_LEN: u64 =
    (MAX_REPORT_LEN + MAX_CERT_LEN + MAX_PUBKEY_LEN) as u64 + EVIDENCE_HEADER_OVERHEAD;

/// Read the gate's evidence response with the transport-level cap above,
/// applied BEFORE `GateEvidence::decode` runs its own per-field caps. Reads
/// `cap + 1` bytes at most: reading strictly more than `cap` bytes proves
/// the peer put more than the largest possible legitimate message on the
/// wire, so it is rejected here — the caller must never fall through to
/// `decode` on that path.
fn read_capped(mut r: impl Read, cap: u64) -> std::io::Result<Vec<u8>> {
    let mut response = Vec::new();
    r.by_ref().take(cap + 1).read_to_end(&mut response)?;
    if response.len() as u64 > cap {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "evidence stream exceeded {cap} bytes (transport-level cap; decode never reached)"
            ),
        ));
    }
    Ok(response)
}

fn main() {
    let mut gate = None;
    let mut generation = None;
    let mut measurement = None;
    let mut host_data = None;
    let mut min_tcb = None;
    let mut vmpl = Some(0u32);
    let mut crl_path: Option<String> = None;
    let mut insecure_skip_revocation = false;

    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        let mut val = || it.next().unwrap_or_else(|| usage("missing value"));
        match a.as_str() {
            "--gate" => gate = Some(val()),
            "--generation" => {
                generation = Some(match val().as_str() {
                    "milan" => AmdGeneration::Milan,
                    "genoa" => AmdGeneration::Genoa,
                    "turin" => AmdGeneration::Turin,
                    g => usage(&format!("unknown generation {g}")),
                })
            }
            "--measurement" => measurement = Some(parse_hex::<48>(&val(), "--measurement")),
            "--host-data" => host_data = Some(parse_hex::<32>(&val(), "--host-data")),
            "--min-tcb" => {
                let v = val();
                let parts: Vec<u8> = v.split(',').map(|p| p.parse().unwrap_or_else(|_| usage("--min-tcb wants bl,tee,snp,ucode"))).collect();
                if parts.len() != 4 {
                    usage("--min-tcb wants exactly 4 components: bl,tee,snp,ucode");
                }
                min_tcb = Some(MinTcb { bootloader: parts[0], tee: parts[1], snp: parts[2], microcode: parts[3] });
            }
            "--vmpl" => vmpl = Some(val().parse().unwrap_or_else(|_| usage("--vmpl wants an integer"))),
            "--no-vmpl-check" => vmpl = None,
            "--crl" => crl_path = Some(val()),
            "--insecure-skip-revocation" => insecure_skip_revocation = true,
            other => usage(&format!("unknown argument: {other}")),
        }
    }
    let gate = gate.unwrap_or_else(|| usage("--gate is required"));
    let generation = generation.unwrap_or_else(|| usage("--generation is required"));
    let measurement = measurement.unwrap_or_else(|| usage("--measurement is required (pin the release manifest's M — a verifier without it proves nothing)"));

    // One verifier wall-clock for this whole run: the AMD-KDS CRL `nextUpdate`
    // freshness check AND the ARK/ASK/VCEK certificate `notBefore`/`notAfter`
    // check (snp.rs) both judge against it — a single "now", not two that
    // could disagree.
    let now = now_unix();

    // The AMD-KDS CRL, if supplied: read the DER off disk now (the crate does no
    // network I/O — fetching the CRL out of band is the operator's job). The
    // freshness instant is the verifier's own clock; snp.rs refuses a CRL whose
    // `nextUpdate` has elapsed, so a stale CRL cannot mask a fresh revocation.
    let crl: Option<KdsCrl> = crl_path.as_deref().map(|p| {
        let crl_der = std::fs::read(p).unwrap_or_else(|e| {
            eprintln!("cannot read CRL {p}: {e}");
            std::process::exit(1);
        });
        KdsCrl { crl_der, now_unix: now }
    });

    // Fresh, single-use nonce. /dev/urandom keeps this dependency-free; the
    // nonce is a public freshness value, not key material.
    let nonce = fresh_nonce();

    // §4.1 step 1–2: challenge → evidence.
    let mut stream = std::net::TcpStream::connect(&gate).unwrap_or_else(|e| {
        eprintln!("cannot reach gate {gate}: {e}");
        std::process::exit(1);
    });
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10))).ok();
    stream.write_all(&encode_challenge(&nonce)).unwrap_or_else(|e| {
        eprintln!("challenge send failed: {e}");
        std::process::exit(1);
    });
    let response = read_capped(&mut stream, MAX_EVIDENCE_WIRE_LEN).unwrap_or_else(|e| {
        eprintln!("VERDICT: rejected — evidence read: {e}");
        std::process::exit(1);
    });
    let evidence = GateEvidence::decode(&response).unwrap_or_else(|e| {
        eprintln!("VERDICT: rejected — evidence decode: {e}");
        std::process::exit(1);
    });

    // §4.1 step 3: full verification. report_data is recomputed from OUR nonce
    // and the presented pubkey by verify_gate_evidence itself — never taken
    // from the wire.
    let expected = SnpExpected {
        generation,
        measurement,
        host_data,
        report_data: [0u8; 64], // overwritten by verify_gate_evidence
        min_reported_tcb: min_tcb,
        vmpl,
    };
    // Revocation policy: `--crl` enforces against that CRL; otherwise fail
    // closed with `RequireButMissing` unless the operator explicitly opts out
    // with the loud `--insecure-skip-revocation` flag. The decision itself is
    // the pure `revocation_choice` function below (unit-tested), so "omitting
    // --crl never silently skips" is a running assertion, not just a comment —
    // see docs/bucketB/PARTITION.md's "audit RevocationPolicy default-safety".
    let policy = match revocation_choice(crl.is_some(), insecure_skip_revocation) {
        RevocationChoice::Enforce => {
            RevocationPolicy::Enforce(crl.as_ref().expect("Enforce only chosen when crl.is_some()"))
        }
        RevocationChoice::SkipDangerously => RevocationPolicy::SkipRevocationCheckDangerously,
        RevocationChoice::RequireButMissing => RevocationPolicy::RequireButMissing,
    };
    let verdict = verify_gate_evidence(&evidence, &nonce, expected, &policy, now);
    match verdict {
        SnpVerdict::Genuine => {
            let b64 = b64_encode(&evidence.guest_pubkey);
            if crl.is_some() {
                println!("VERDICT: Genuine — report chains to the pinned AMD root; measurement, binding and policy all match; VCEK is not revoked by the (fresh, ASK-signed) AMD-KDS CRL.");
            } else {
                println!("VERDICT: Genuine — report chains to the pinned AMD root; measurement, binding and policy all match; revocation check explicitly skipped (--insecure-skip-revocation).");
                eprintln!("note: no --crl supplied — a since-revoked VCEK would NOT be caught; pass the AMD-KDS CRL for a revocation-enforced verdict.");
            }
            println!("guest WireGuard public key (the ONLY sound tunnel peer): {b64}");
        }
        SnpVerdict::Rejected(reason) => {
            println!("VERDICT: REJECTED — {reason}");
            println!("Do NOT connect. This is a hard stop (POSTERN-CLOUD.md §4.1).");
            std::process::exit(1);
        }
    }
}

fn usage(err: &str) -> ! {
    eprintln!("postern-seal-verify: {err}");
    eprintln!(
        "usage: postern-seal-verify --gate <host:port> --generation milan|genoa|turin \\\n\
         \x20      --measurement <96 hex> [--host-data <64 hex>] [--min-tcb bl,tee,snp,ucode] [--vmpl N | --no-vmpl-check] [--crl <der path> | --insecure-skip-revocation]"
    );
    std::process::exit(2);
}

/// Verifier's current time, seconds since the Unix epoch — used for BOTH the
/// CRL `nextUpdate` freshness check AND the ARK/ASK/VCEK certificate
/// `notBefore`/`notAfter` window check (`snp.rs`). A verifier clock behind
/// the CRL's issuance / the VCEK's own validity start is the only honest
/// input here; the crate does the elapsed-vs-fresh and window comparisons.
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_else(|e| {
            eprintln!("system clock is before the Unix epoch ({e}); cannot judge CRL/certificate freshness");
            std::process::exit(1);
        })
}

fn parse_hex<const N: usize>(s: &str, flag: &str) -> [u8; N] {
    let s = s.trim();
    if s.len() != 2 * N || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        usage(&format!("{flag} wants exactly {} hex chars", 2 * N));
    }
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

fn fresh_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    let mut f = std::fs::File::open("/dev/urandom").unwrap_or_else(|e| {
        eprintln!("cannot open /dev/urandom for the challenge nonce: {e}");
        std::process::exit(1);
    });
    f.read_exact(&mut nonce).expect("urandom read");
    nonce
}

fn b64_encode(data: &[u8]) -> String {
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = u32::from_be_bytes([0, b[0], b[1], b[2]]);
        out.push(ALPHA[(n >> 18 & 63) as usize] as char);
        out.push(ALPHA[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 { ALPHA[(n >> 6 & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPHA[(n & 63) as usize] as char } else { '=' });
    }
    out
}

/// Which [`RevocationPolicy`] shape the CLI flags select — extracted as a pure
/// function (no `KdsCrl` borrow) purely so this decision is unit-testable.
/// `main` still builds the actual `RevocationPolicy::Enforce(&crl)` (which
/// needs the borrow); this only decides WHICH of the three shapes applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RevocationChoice {
    /// `--crl` was supplied: enforce against it (regardless of the skip flag —
    /// a caller who passes both gets enforcement, the stronger choice).
    Enforce,
    /// No `--crl`, and the loud opt-out was passed: skip, knowingly.
    SkipDangerously,
    /// No `--crl` and no opt-out: fail closed. This is the safe default a
    /// caller reaches by doing nothing special — the whole point of
    /// `RevocationPolicy` requiring an explicit choice in `snp.rs`.
    RequireButMissing,
}

fn revocation_choice(has_crl: bool, insecure_skip_revocation: bool) -> RevocationChoice {
    match (has_crl, insecure_skip_revocation) {
        (true, _) => RevocationChoice::Enforce,
        (false, true) => RevocationChoice::SkipDangerously,
        (false, false) => RevocationChoice::RequireButMissing,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The actual DoS this branch fixes: an oversized/flooding gate must be
    // rejected by the transport-level cap alone, never by allocating enough
    // memory to reach `GateEvidence::decode`. A tiny cap keeps the test fast
    // and independent of the real ~25 KiB limit.
    #[test]
    fn oversized_evidence_stream_is_rejected_before_decode() {
        let oversized = vec![0u8; 101];
        let err = read_capped(std::io::Cursor::new(oversized), 100).unwrap_err();
        assert!(
            err.to_string().contains("exceeded 100 bytes"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn evidence_stream_exactly_at_cap_is_accepted_by_the_transport_layer() {
        // At-cap is not decode's problem to solve twice — the transport
        // layer must let exactly-at-cap traffic through to decode, which
        // enforces the real per-field caps.
        let exact = vec![0u8; 100];
        let out = read_capped(std::io::Cursor::new(exact), 100).expect("at-cap must be accepted");
        assert_eq!(out.len(), 100);
    }

    #[test]
    fn real_wire_cap_matches_gate_rs_field_caps_plus_header() {
        // Pin MAX_EVIDENCE_WIRE_LEN to gate.rs's own caps so the two never
        // drift apart silently.
        assert_eq!(
            MAX_EVIDENCE_WIRE_LEN,
            (MAX_REPORT_LEN + MAX_CERT_LEN + MAX_PUBKEY_LEN) as u64 + EVIDENCE_HEADER_OVERHEAD
        );
    }

    // The core "audit RevocationPolicy default-safety" guarantee
    // (docs/bucketB/PARTITION.md): omitting --crl must NEVER silently resolve
    // to SkipRevocationCheckDangerously — it must fail closed instead, and the
    // only way to reach the skip is the loudly-named flag.
    #[test]
    fn no_crl_and_no_opt_out_fails_closed_never_skips_silently() {
        assert_eq!(revocation_choice(false, false), RevocationChoice::RequireButMissing);
    }

    #[test]
    fn skip_dangerously_requires_the_explicit_opt_out_flag() {
        assert_eq!(revocation_choice(false, true), RevocationChoice::SkipDangerously);
    }

    #[test]
    fn crl_present_always_enforces_regardless_of_the_skip_flag() {
        // A supplied --crl always wins: the loud opt-out only matters when
        // there is no CRL to enforce against in the first place.
        assert_eq!(revocation_choice(true, false), RevocationChoice::Enforce);
        assert_eq!(revocation_choice(true, true), RevocationChoice::Enforce);
    }
}
