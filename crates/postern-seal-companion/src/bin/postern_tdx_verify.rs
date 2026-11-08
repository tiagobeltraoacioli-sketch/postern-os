//! postern-tdx-verify — the Intel **TDX** DCAP verifier CLI (SNP-parity tool).
//! The client-side deliverable that finally *drives* the (already real,
//! `x509-parser`/ring + `p256`-backed) `crate::tdx` DCAP verifier from a binary:
//! feed it a DCAP **v4** TD quote (DER/raw bytes on disk), the expected genuine
//! measurements to pin (`MRTD`, optional `MRCONFIGID` / `RTMR[0..4]`), the
//! 64-byte channel binding (`report_data`, supplied raw OR recomputed from a
//! nonce + guest public key), and — optionally — the Intel PCS/DCAP CRL
//! collateral fetched out of band. It prints a single, loud, NAMED verdict.
//!
//! Exit 0 ⇔ `VERDICT: Genuine`. Anything else — a malformed quote, a chain that
//! does not terminate at the pinned Intel SGX Root CA, an expired/revoked cert,
//! a stale CRL, a QE-binding / signature failure, a bound-field mismatch, or the
//! fail-closed no-collateral refusal — prints `VERDICT: REJECTED — <reason>` and
//! exits nonzero. This mirrors, field for field, `postern-seal-verify` (SNP).
//!
//! ## Fail-closed on missing revocation collateral (SNP parity)
//!
//! Exactly like the SEV-SNP verifier's `--crl` discipline: with NO CRL
//! collateral supplied (`--root-ca-crl` / `--pck-crl`) and no loud opt-out, the
//! verdict is REJECTED **before the verifier is ever called** — there is nothing
//! to check revocation against, so we refuse rather than silently skip. An
//! operator who knowingly accepts that gap must pass the loudly-named
//! `--insecure-skip-revocation`; a supplied CRL always enforces. The decision is
//! the pure, unit-tested [`crl_choice`] (mirrors `seal_verify.rs`'s
//! `revocation_choice`), so "omitting the CRL never silently skips" is a running
//! assertion, not a comment.
//!
//! ## What a Genuine here would prove — and why it CANNOT be reached on this host
//!
//! **This tool has never printed, and on this host CANNOT print, `Genuine`.**
//! `crate::tdx` pins Intel's genuine, published SGX Root CA as the anchor, and
//! [`verify_td_quote_with_collateral`] only returns `Genuine` when a quote's
//! embedded PCK chain terminates at *that exact* root AND every bound field
//! matches. No genuine Intel-rooted TD quote from TDX silicon we control exists
//! here, so every quote fed in either fails to parse, fails to anchor
//! (`RootNotAnchored`), or fails a field/signature check — always a fail-closed
//! REJECTED, never Genuine. Reaching Genuine is **hardware-gated** (needs a real
//! Intel TDX quote + matching PCS/DCAP collateral). **Reference-prototype /
//! UNAUDITED** — the underlying verifier's real crypto has only ever run against
//! SYNTHETIC vectors (`tests/tdx_collateral.rs`), never a chain minted by real
//! TDX hardware. See `crate::tdx` module docs.
//!
//! Usage:
//!   postern-tdx-verify \
//!       --quote <td_quote.bin> \
//!       --mrtd <96 hex> \
//!       [--mrconfigid <96 hex>] \
//!       [--rtmr0 <96 hex> --rtmr1 <96 hex> --rtmr2 <96 hex> --rtmr3 <96 hex>] \
//!       ( --report-data <128 hex> | --nonce <64 hex> --guest-pubkey <hex> ) \
//!       [--root-ca-crl <der> ] [--pck-crl <der>] \
//!       [--tcb-svn-floor <32 hex>] [--now <unix-seconds>] \
//!       [--insecure-skip-revocation]
//!
//! `--report-data` pins the 64-byte channel binding directly; alternatively pass
//! `--nonce`/`--guest-pubkey` to recompute it as `binding::report_data(nonce,
//! pubkey)` — the same layout SNP uses. All four `--rtmrN` must be given together
//! or not at all. The PCK chain itself travels INSIDE the quote — only the CRLs,
//! the anti-rollback TCB floor, and the freshness clock live on the command line.

use postern_seal_companion::binding;
use postern_seal_companion::tdx::{verify_td_quote_with_collateral, TdxCollateral, TdxExpected};
use postern_seal_companion::Verdict;

fn main() {
    let cfg = parse_args(std::env::args().skip(1).collect());

    // The quote is mandatory — a verifier with no quote proves nothing.
    let quote_path = cfg
        .quote_path
        .as_deref()
        .unwrap_or_else(|| usage("--quote <td_quote.bin> is required"));
    let quote = read_bytes(quote_path, "TD quote");

    // MRTD is the load-bearing measurement pin (the SNP `--measurement`
    // analogue): a verifier without it cannot say WHICH TD it expected.
    let mrtd = cfg
        .mrtd
        .unwrap_or_else(|| usage("--mrtd <96 hex> is required (pin the audited TD build measurement)"));

    // All four RTMRs together, or none — a partial set would silently waive the
    // registers the operator forgot, which is the wrong (unsafe) default.
    let rtmr = resolve_rtmr(&cfg.rtmr).unwrap_or_else(|e| usage(e));

    // The 64-byte channel binding: pinned raw OR recomputed from nonce+pubkey.
    let report_data = resolve_report_data(cfg.report_data, cfg.nonce, cfg.guest_pubkey.as_deref())
        .unwrap_or_else(|e| usage(e));

    let expected = TdxExpected {
        mrtd,
        mr_config_id: cfg.mr_config_id,
        rtmr,
        report_data,
    };

    // One verifier wall-clock for this run: CRL `nextUpdate` freshness AND the
    // PCK leaf/intermediate/root `notBefore`/`notAfter` windows both judge
    // against it (crate::tdx) — a single "now", never two that could disagree.
    let now = cfg.now_unix.unwrap_or_else(now_unix);

    // Revocation collateral, SNP-parity fail-closed: with no CRL and no loud
    // opt-out we REJECT here, before the verifier is called — never a silent
    // skip. The decision is the pure crl_choice below (unit-tested).
    let has_crl = cfg.root_ca_crl_path.is_some() || cfg.pck_crl_path.is_some();
    let collateral = match crl_choice(has_crl, cfg.insecure_skip_revocation) {
        CrlChoice::RequireButMissing => {
            println!(
                "VERDICT: REJECTED — no Intel PCS/DCAP CRL collateral supplied \
                 (--root-ca-crl / --pck-crl); refusing to skip revocation silently. \
                 Fetch the CRLs out of band, or pass --insecure-skip-revocation to \
                 knowingly accept that a since-revoked PCK would NOT be caught."
            );
            println!("Do NOT trust this quote. This is a hard stop (fail-closed).");
            std::process::exit(1);
        }
        CrlChoice::SkipDangerously => {
            eprintln!(
                "note: --insecure-skip-revocation set — no CRL enforced; a since-revoked \
                 PCK/intermediate would NOT be caught. Supply --root-ca-crl/--pck-crl for a \
                 revocation-enforced verdict."
            );
            TdxCollateral {
                root_ca_crl_der: None,
                pck_crl_der: None,
                now_unix: now,
                tcb_svn_floor: cfg.tcb_svn_floor,
                json: None,
            }
        }
        CrlChoice::Enforce => TdxCollateral {
            root_ca_crl_der: cfg
                .root_ca_crl_path
                .as_deref()
                .map(|p| read_bytes(p, "Intel SGX Root CA CRL")),
            pck_crl_der: cfg
                .pck_crl_path
                .as_deref()
                .map(|p| read_bytes(p, "Intel PCK CA CRL")),
            now_unix: now,
            tcb_svn_floor: cfg.tcb_svn_floor,
            json: None,
        },
    };

    // Call the real DCAP verifier. On this host it can only ever fail closed
    // (the pinned Intel root cannot be anchored by any quote we possess), never
    // Genuine — that path is hardware-gated. See the module docs above.
    match verify_td_quote_with_collateral(&quote, &expected, &collateral) {
        Verdict::Genuine => {
            // Unreachable on this host, but wired so the shape is complete and a
            // real Intel-rooted quote on TDX hardware would surface correctly.
            println!(
                "VERDICT: Genuine — TD quote chains to the pinned Intel SGX Root CA; \
                 QE binding, QE-report and quote signatures verify; CRLs fresh and not \
                 revoked; MRTD/MRCONFIGID/RTMR and the channel binding all match."
            );
        }
        Verdict::Mismatch(reason) => {
            println!("VERDICT: REJECTED — {reason}");
            println!("Do NOT trust this quote. This is a hard stop (fail-closed).");
            std::process::exit(1);
        }
        Verdict::Unverified(reason) => {
            println!("VERDICT: REJECTED — {reason}");
            eprintln!(
                "note: on this host TDX never reaches Genuine — the pinned Intel SGX Root CA \
                 cannot be anchored by any quote available here (hardware-gated; UNAUDITED)."
            );
            println!("Do NOT trust this quote. This is a hard stop (fail-closed).");
            std::process::exit(1);
        }
    }
}

/// Parsed CLI configuration (post-flag-parse, pre-file-read). A plain struct so
/// [`parse_args`] is a pure string→config transform the arg-parse tests can
/// drive without touching the filesystem — same shape as `seal_verify_mobile.rs`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TdxArgs {
    quote_path: Option<String>,
    mrtd: Option<[u8; 48]>,
    mr_config_id: Option<[u8; 48]>,
    /// `RTMR[0..4]`, each independently optional at parse time; the all-or-none
    /// invariant is enforced later by [`resolve_rtmr`].
    rtmr: [Option<[u8; 48]>; 4],
    report_data: Option<[u8; 64]>,
    nonce: Option<[u8; 32]>,
    guest_pubkey: Option<Vec<u8>>,
    root_ca_crl_path: Option<String>,
    pck_crl_path: Option<String>,
    tcb_svn_floor: Option<[u8; 16]>,
    now_unix: Option<i64>,
    insecure_skip_revocation: bool,
}

impl Default for TdxArgs {
    fn default() -> Self {
        TdxArgs {
            quote_path: None,
            mrtd: None,
            mr_config_id: None,
            rtmr: [None, None, None, None],
            report_data: None,
            nonce: None,
            guest_pubkey: None,
            root_ca_crl_path: None,
            pck_crl_path: None,
            tcb_svn_floor: None,
            now_unix: None,
            // Fail-safe default: revocation is NOT skipped unless the operator
            // asks by name. A silent omission fails closed (see crl_choice).
            insecure_skip_revocation: false,
        }
    }
}

/// Pure flag parser: `Vec<String>` args → [`TdxArgs`]. No filesystem access
/// (paths are collected, not read), so the default/parse invariants are
/// unit-testable, mirroring `seal_verify_mobile.rs`'s pure `parse_args`.
fn parse_args(args: Vec<String>) -> TdxArgs {
    let mut out = TdxArgs::default();
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        let mut val = || it.next().unwrap_or_else(|| usage("missing value"));
        match a.as_str() {
            "--quote" => out.quote_path = Some(val()),
            "--mrtd" => out.mrtd = Some(parse_hex_arr::<48>(&val(), "--mrtd")),
            "--mrconfigid" => out.mr_config_id = Some(parse_hex_arr::<48>(&val(), "--mrconfigid")),
            "--rtmr0" => out.rtmr[0] = Some(parse_hex_arr::<48>(&val(), "--rtmr0")),
            "--rtmr1" => out.rtmr[1] = Some(parse_hex_arr::<48>(&val(), "--rtmr1")),
            "--rtmr2" => out.rtmr[2] = Some(parse_hex_arr::<48>(&val(), "--rtmr2")),
            "--rtmr3" => out.rtmr[3] = Some(parse_hex_arr::<48>(&val(), "--rtmr3")),
            "--report-data" => out.report_data = Some(parse_hex_arr::<64>(&val(), "--report-data")),
            "--nonce" => out.nonce = Some(parse_hex_arr::<32>(&val(), "--nonce")),
            "--guest-pubkey" => out.guest_pubkey = Some(parse_hex_vec(&val(), "--guest-pubkey")),
            "--root-ca-crl" => out.root_ca_crl_path = Some(val()),
            "--pck-crl" => out.pck_crl_path = Some(val()),
            "--tcb-svn-floor" => {
                out.tcb_svn_floor = Some(parse_hex_arr::<16>(&val(), "--tcb-svn-floor"))
            }
            "--now" => {
                out.now_unix =
                    Some(val().parse().unwrap_or_else(|_| usage("--now wants unix seconds")))
            }
            "--insecure-skip-revocation" => out.insecure_skip_revocation = true,
            "-h" | "--help" => usage("help"),
            other => usage(&format!("unknown argument: {other}")),
        }
    }
    out
}

/// Collapse the four independently-optional `--rtmrN` flags into the library's
/// `Option<[[u8;48];4]>`: all four present → `Some([...])`; none present →
/// `None` (registers waived, documented); a PARTIAL set is an error — silently
/// waiving the RTMRs the operator forgot is the wrong, unsafe default.
fn resolve_rtmr(rtmr: &[Option<[u8; 48]>; 4]) -> Result<Option<[[u8; 48]; 4]>, &'static str> {
    let set = rtmr.iter().filter(|r| r.is_some()).count();
    match set {
        0 => Ok(None),
        4 => Ok(Some([
            rtmr[0].unwrap(),
            rtmr[1].unwrap(),
            rtmr[2].unwrap(),
            rtmr[3].unwrap(),
        ])),
        _ => Err("--rtmr0..--rtmr3 must be given all together or not at all (a partial set would silently waive the missing registers)"),
    }
}

/// Resolve the 64-byte channel binding from EXACTLY ONE source: the raw
/// `--report-data`, or `binding::report_data(nonce, guest_pubkey)` recomputed
/// from `--nonce` + `--guest-pubkey`. Supplying both, or neither, is an error —
/// an ambiguous or absent binding must never be guessed.
fn resolve_report_data(
    report_data: Option<[u8; 64]>,
    nonce: Option<[u8; 32]>,
    guest_pubkey: Option<&[u8]>,
) -> Result<[u8; 64], &'static str> {
    let have_binding_inputs = nonce.is_some() || guest_pubkey.is_some();
    match (report_data, have_binding_inputs) {
        (Some(_), true) => Err(
            "supply EITHER --report-data OR --nonce/--guest-pubkey, not both (ambiguous channel binding)",
        ),
        (Some(rd), false) => Ok(rd),
        (None, true) => match (nonce, guest_pubkey) {
            (Some(n), Some(pk)) => Ok(binding::report_data(&n, pk)),
            _ => Err("--nonce and --guest-pubkey must BOTH be supplied to recompute the channel binding"),
        },
        (None, false) => Err(
            "the 64-byte channel binding is required: pass --report-data <128 hex> OR --nonce <64 hex> --guest-pubkey <hex>",
        ),
    }
}

/// Which revocation-collateral posture the CLI flags select — the pure decision,
/// extracted (no `TdxCollateral` build) so it is unit-testable. Mirrors
/// `seal_verify.rs`'s `revocation_choice` exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CrlChoice {
    /// A CRL was supplied: enforce against it (regardless of the skip flag — a
    /// caller who passes both gets enforcement, the stronger choice).
    Enforce,
    /// No CRL, and the loud opt-out was passed: skip revocation, knowingly.
    SkipDangerously,
    /// No CRL and no opt-out: fail closed. The safe default reached by doing
    /// nothing special — omitting the CRL must NEVER silently skip revocation.
    RequireButMissing,
}

fn crl_choice(has_crl: bool, insecure_skip_revocation: bool) -> CrlChoice {
    match (has_crl, insecure_skip_revocation) {
        (true, _) => CrlChoice::Enforce,
        (false, true) => CrlChoice::SkipDangerously,
        (false, false) => CrlChoice::RequireButMissing,
    }
}

/// Verifier's current time, seconds since the Unix epoch — used for BOTH the CRL
/// `nextUpdate` freshness check AND the PCK cert `notBefore`/`notAfter` window
/// check (`crate::tdx`). A clock before the Unix epoch cannot judge either.
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_else(|e| {
            eprintln!("system clock is before the Unix epoch ({e}); cannot judge CRL/certificate freshness");
            std::process::exit(1);
        })
}

fn read_bytes(path: &str, what: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| {
        eprintln!("cannot read {what} {path}: {e}");
        std::process::exit(1);
    })
}

fn parse_hex_vec(s: &str, flag: &str) -> Vec<u8> {
    let s = s.trim();
    if s.is_empty() || s.len() % 2 != 0 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        usage(&format!("{flag} wants an even-length hex string"));
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn parse_hex_arr<const N: usize>(s: &str, flag: &str) -> [u8; N] {
    let s = s.trim();
    if s.len() != 2 * N || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        usage(&format!("{flag} wants exactly {} hex chars ({N} bytes)", 2 * N));
    }
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

fn usage(err: &str) -> ! {
    eprintln!("postern-tdx-verify: {err}");
    eprintln!(
        "usage: postern-tdx-verify \\\n\
         \x20  --quote <td_quote.bin> \\\n\
         \x20  --mrtd <96 hex> [--mrconfigid <96 hex>] \\\n\
         \x20  [--rtmr0 <96 hex> --rtmr1 <96 hex> --rtmr2 <96 hex> --rtmr3 <96 hex>] \\\n\
         \x20  ( --report-data <128 hex> | --nonce <64 hex> --guest-pubkey <hex> ) \\\n\
         \x20  [--root-ca-crl <der>] [--pck-crl <der>] \\\n\
         \x20  [--tcb-svn-floor <32 hex>] [--now <unix-seconds>] [--insecure-skip-revocation]\n\
         \n\
         With NO --root-ca-crl/--pck-crl (and no --insecure-skip-revocation) the verdict is\n\
         REJECTED (fail-closed): revocation is never silently skipped. This host can NEVER\n\
         reach Genuine — the pinned Intel SGX Root CA is unanchorable here (hardware-gated)."
    );
    std::process::exit(2);
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── the core fail-closed default (mirrors seal_verify.rs's revocation_choice
    //    and seal_verify_mobile.rs's no-anchor default-safety tests) ────────────

    // "No collateral ⇒ nothing to check revocation against ⇒ fail closed."
    // Omitting the CRL must NEVER silently resolve to SkipDangerously; the only
    // way to reach a skip is the loudly-named opt-out flag.
    #[test]
    fn no_crl_and_no_opt_out_fails_closed_never_skips_silently() {
        assert_eq!(crl_choice(false, false), CrlChoice::RequireButMissing);
    }

    #[test]
    fn skip_revocation_requires_the_explicit_opt_out_flag() {
        assert_eq!(crl_choice(false, true), CrlChoice::SkipDangerously);
    }

    #[test]
    fn crl_present_always_enforces_regardless_of_the_skip_flag() {
        // A supplied CRL always wins: the loud opt-out only matters when there is
        // no CRL to enforce against in the first place.
        assert_eq!(crl_choice(true, false), CrlChoice::Enforce);
        assert_eq!(crl_choice(true, true), CrlChoice::Enforce);
    }

    // The parse layer must default to the fail-closed posture: no CRL paths and
    // revocation NOT skipped, so main() reaches RequireButMissing.
    #[test]
    fn parse_defaults_to_fail_closed_no_crl_no_skip() {
        let cfg = parse_args(vec!["--quote".into(), "q.bin".into()]);
        assert!(cfg.root_ca_crl_path.is_none());
        assert!(cfg.pck_crl_path.is_none());
        assert!(!cfg.insecure_skip_revocation);
        // End-to-end: the parsed defaults drive the fail-closed choice.
        let has_crl = cfg.root_ca_crl_path.is_some() || cfg.pck_crl_path.is_some();
        assert_eq!(
            crl_choice(has_crl, cfg.insecure_skip_revocation),
            CrlChoice::RequireButMissing
        );
    }

    // Fail-closed at the LIBRARY boundary too, not just the flag layer: even with
    // an (empty, all-waived) collateral, the DCAP verifier must never mint
    // Genuine on bytes that are not a real Intel-rooted quote — here a malformed
    // quote fails closed to Unverified.
    #[test]
    fn dcap_verifier_fails_closed_on_a_non_anchorable_quote() {
        let expected = TdxExpected {
            mrtd: [0x11; 48],
            mr_config_id: None,
            rtmr: None,
            report_data: [0x22; 64],
        };
        let collateral = TdxCollateral {
            root_ca_crl_der: None,
            pck_crl_der: None,
            now_unix: 1_700_000_000,
            tcb_svn_floor: None,
            json: None,
        };
        // Empty bytes are not a well-formed v4 TD quote — fail closed, never Genuine.
        let v = verify_td_quote_with_collateral(&[], &expected, &collateral);
        assert!(
            matches!(v, Verdict::Unverified(_)),
            "a non-anchorable quote must fail closed with Verdict::Unverified, got {v:?}"
        );
        assert_ne!(v, Verdict::Genuine, "TDX must never reach Genuine on this host");
    }

    // ── report_data (channel binding) resolution ──────────────────────────────

    #[test]
    fn report_data_raw_is_used_verbatim() {
        let rd = [0xAB; 64];
        assert_eq!(resolve_report_data(Some(rd), None, None).unwrap(), rd);
    }

    #[test]
    fn report_data_from_nonce_and_pubkey_matches_the_shared_binding_layout() {
        let nonce = [7u8; 32];
        let pubkey = [9u8; 32];
        let got = resolve_report_data(None, Some(nonce), Some(&pubkey)).unwrap();
        assert_eq!(got, binding::report_data(&nonce, &pubkey));
    }

    #[test]
    fn report_data_both_sources_is_ambiguous_and_neither_is_missing() {
        assert!(resolve_report_data(Some([0; 64]), Some([1; 32]), Some(&[2u8; 32])).is_err());
        assert!(resolve_report_data(None, None, None).is_err());
        // Half the binding inputs is also an error — never guess the other half.
        assert!(resolve_report_data(None, Some([1; 32]), None).is_err());
        assert!(resolve_report_data(None, None, Some(&[2u8; 32])).is_err());
    }

    // ── RTMR all-or-none invariant ────────────────────────────────────────────

    #[test]
    fn rtmr_none_present_waives_and_all_four_bind() {
        assert_eq!(resolve_rtmr(&[None, None, None, None]).unwrap(), None);
        let full = [
            Some([0xA0; 48]),
            Some([0xA1; 48]),
            Some([0xA2; 48]),
            Some([0xA3; 48]),
        ];
        assert_eq!(
            resolve_rtmr(&full).unwrap(),
            Some([[0xA0; 48], [0xA1; 48], [0xA2; 48], [0xA3; 48]])
        );
    }

    #[test]
    fn rtmr_partial_set_is_rejected_not_silently_waived() {
        let partial = [Some([0xA0; 48]), None, Some([0xA2; 48]), None];
        assert!(resolve_rtmr(&partial).is_err());
    }

    // ── flag parsing ──────────────────────────────────────────────────────────

    #[test]
    fn hex_flags_parse_at_the_right_widths_and_order() {
        let cfg = parse_args(vec![
            "--quote".into(),
            "td.bin".into(),
            "--mrtd".into(),
            "11".repeat(48),
            "--mrconfigid".into(),
            "22".repeat(48),
            "--report-data".into(),
            "33".repeat(64),
            "--tcb-svn-floor".into(),
            "44".repeat(16),
            "--now".into(),
            "1700000000".into(),
        ]);
        assert_eq!(cfg.quote_path.as_deref(), Some("td.bin"));
        assert_eq!(cfg.mrtd, Some([0x11; 48]));
        assert_eq!(cfg.mr_config_id, Some([0x22; 48]));
        assert_eq!(cfg.report_data, Some([0x33; 64]));
        assert_eq!(cfg.tcb_svn_floor, Some([0x44; 16]));
        assert_eq!(cfg.now_unix, Some(1_700_000_000));
    }

    #[test]
    fn crl_paths_and_skip_flag_parse() {
        let cfg = parse_args(vec![
            "--root-ca-crl".into(),
            "root.crl".into(),
            "--pck-crl".into(),
            "pck.crl".into(),
            "--insecure-skip-revocation".into(),
        ]);
        assert_eq!(cfg.root_ca_crl_path.as_deref(), Some("root.crl"));
        assert_eq!(cfg.pck_crl_path.as_deref(), Some("pck.crl"));
        assert!(cfg.insecure_skip_revocation);
    }

    #[test]
    fn nonce_and_guest_pubkey_parse_for_the_binding_path() {
        let cfg = parse_args(vec![
            "--nonce".into(),
            "aa".repeat(32),
            "--guest-pubkey".into(),
            "abcdef".into(),
        ]);
        assert_eq!(cfg.nonce, Some([0xAA; 32]));
        assert_eq!(cfg.guest_pubkey, Some(vec![0xAB, 0xCD, 0xEF]));
    }
}
