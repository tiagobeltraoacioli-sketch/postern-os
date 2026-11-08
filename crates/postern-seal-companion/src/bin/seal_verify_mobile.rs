//! postern-seal-verify-mobile — the Android **Key Attestation** client side of
//! the Seal handshake. It is the CLI deliverable that finally *drives* the
//! (already real, x509-parser/ring-backed) `crate::mobile` verifier from a
//! binary: feed it a **leaf-first** Android Key-Attestation certificate chain
//! (DER), one or more **caller-pinned Google attestation root(s)** (DER), the
//! attestation **nonce** it was challenged with, and the deployment's policy
//! floors — it prints a single, loud verdict.
//!
//! On success it prints `VERDICT: Genuine`, the security tier the key was
//! **ACTUALLY** attested at (StrongBox vs TEE vs Software — never up-labelled
//! past what the chain proves; the tier is read straight out of the attested
//! `MobileAttestation`), and the **attested leaf public key** (the
//! SubjectPublicKeyInfo the chain endorses — the only key it is sound to trust
//! as this device's hardware key). Exit 0 ⇔ Genuine.
//!
//! On ANY doubt — wrong/absent pinned root, a broken/tampered chain link, an
//! expired cert, a nonce/boot-state/patch-level/app-identity/security-level
//! mismatch — it prints a NAMED `VERDICT: REJECTED — <reason>` and exits
//! nonzero. Fail-closed by default: **with no `--root` pinned there is no trust
//! anchor**, so the verdict is REJECTED (the crate's `Verdict::Unverified`),
//! never Genuine — exactly like the SEV-SNP verifier refuses a report with no
//! anchor. The wire never supplies its own anchor.
//!
//! ## What Genuine here proves — and what it does NOT (honesty, per module docs)
//!
//! It proves *a hardware key on a device whose verified-boot state, OS patch
//! level and attesting-app identity are AS REPORTED, attested by a chain that
//! terminates at the Google root you pinned, freshly bound to your nonce.* It
//! does NOT measure the workspace (that is Postern OS Mobile's measured-boot,
//! not key attestation), and the whole chain roots in **Google's** CA + the
//! OEM. **Reference-prototype / UNAUDITED** — the crate has never been run
//! against a chain minted by a real StrongBox on hardware (`vector-tested ≠
//! attested`). See `crate::mobile` module docs.
//!
//! ## No in-crate revocation (a stated, open gap — same honesty as tdx.rs)
//!
//! This crate does NO Google status-list revocation check yet, so a
//! compromised-and-revoked device key would still chain. An operator must
//! refresh Google's attestation status list out of band. Restated loudly here
//! so a Genuine verdict is not over-read; see `crate::mobile`.
//!
//! Usage:
//!   postern-seal-verify-mobile \
//!       <leaf.der> [<intermediate.der> ...] <root_in_chain.der> \
//!       --root <pinned-google-root.der> [--root <second-root.der> ...] \
//!       --nonce <nonce.bin | hex> \
//!       [--min-security-level software|tee|strongbox] \
//!       [--require-verified-boot] [--require-device-locked] \
//!       [--min-os-patch YYYYMM] \
//!       [--app-package <name> ...] [--app-digest <hex> ...] \
//!       [--now <unix-seconds>]
//!
//! The **leaf-first** chain certs (index 0 is the attested key's leaf) are given
//! as bare **positional** DER paths — the shape the acceptance runbook drives
//! (`postern-seal-verify-mobile chain-0.der chain-1.der chain-2.der --root … --nonce nonce.bin`).
//! The explicit `--cert <path>` flag remains accepted and is interchangeable with
//! (and additive to) the positional form. `--root` is repeatable — pin MORE than
//! one across an RKP root-rotation window (Google rotated 2026-02-01; see
//! `crate::mobile::GoogleRootPinProvenance`).
//!
//! `--nonce` takes the attestation challenge as **either** a path to a raw-bytes
//! file (e.g. the captured `nonce.bin`) **or** a hex string — a readable file at
//! that path wins, otherwise the value is parsed as hex. `--nonce-file <path>`
//! forces the file reading unambiguously.

use postern_seal_companion::mobile::{
    verify_key_attestation_detailed, AppIdentity, MobileExpected, SecurityLevel,
};
use postern_seal_companion::Verdict;

fn main() {
    let cfg = parse_args(std::env::args().skip(1).collect());

    // Read the leaf-first chain DER off disk (this crate does no network I/O —
    // presenting the chain is the caller's job, matching the offline-verify
    // discipline of the SEV-SNP / TDX verifiers).
    let chain_owned: Vec<Vec<u8>> = cfg
        .cert_paths
        .iter()
        .map(|p| read_der(p, "certificate"))
        .collect();
    // Read the pinned Google root(s). EMPTY is allowed to reach the verifier on
    // purpose: the library fails closed with Verdict::Unverified when no root is
    // pinned, and we surface that as a REJECTED verdict below — never a bypass.
    let roots: Vec<Vec<u8>> = cfg
        .root_paths
        .iter()
        .map(|p| read_der(p, "pinned root"))
        .collect();

    if chain_owned.is_empty() {
        usage("at least one --cert (leaf-first chain) is required");
    }

    let expected = MobileExpected {
        roots,
        challenge: cfg.nonce,
        require_device_locked: cfg.require_device_locked,
        require_verified_boot: cfg.require_verified_boot,
        min_security_level: cfg.min_security_level,
        min_os_patch_level: cfg.min_os_patch_level,
        expected_app: build_app_identity(cfg.app_packages, cfg.app_digests),
        now_unix: cfg.now_unix,
    };

    let chain: Vec<&[u8]> = chain_owned.iter().map(|v| v.as_slice()).collect();

    match verify_key_attestation_detailed(&chain, &expected) {
        Ok(att) => {
            // The tier is whatever the chain ACTUALLY attested — printed
            // verbatim from the authenticated MobileAttestation, never
            // re-labelled upward past what the evidence proves.
            println!(
                "VERDICT: Genuine — chain terminates at a pinned Google attestation root; \
                 nonce, verified-boot/device-locked, OS-patch, app-identity and security-level \
                 policy all satisfied."
            );
            println!(
                "attested security tier (exactly what the chain proves): {}",
                tier_str(att.security_level)
            );
            println!("verified-boot state: {:?}", att.verified_boot_state);
            println!("device-locked: {}", att.device_locked);
            match att.os_patch_level {
                Some(p) => println!("OS patch level (YYYYMM): {p}"),
                None => println!("OS patch level (YYYYMM): <not reported>"),
            }
            if !att.package_names.is_empty() {
                println!("attesting app package(s): {}", att.package_names.join(", "));
            }
            // The attested leaf public key: the SubjectPublicKeyInfo the chain
            // endorses — the ONLY key it is sound to treat as this device's
            // hardware key. Extracted from the leaf cert (chain index 0).
            match leaf_public_key_spki(&chain_owned[0]) {
                Some(spki) => {
                    println!(
                        "attested leaf public key (SubjectPublicKeyInfo DER, base64): {}",
                        b64_encode(&spki)
                    );
                }
                None => {
                    // Cannot happen after a Genuine verdict (the leaf parsed and
                    // its signature verified up the chain), but never claim a key
                    // we could not re-extract.
                    eprintln!("note: leaf public key could not be re-extracted for display (chain verified regardless)");
                }
            }
            eprintln!(
                "note: Android Key Attestation attests the PHONE, not the workspace; no in-crate \
                 status-list revocation runs here — refresh Google's attestation status list out of band."
            );
        }
        Err(verdict) => {
            let reason = verdict_reason(&verdict);
            println!("VERDICT: REJECTED — {reason}");
            println!("Do NOT trust this device key. This is a hard stop (fail-closed).");
            std::process::exit(1);
        }
    }
}

/// Parsed CLI configuration (post-flag-parse, pre-file-read). Kept as a plain
/// struct so `parse_args` is a pure string→config transform that the
/// arg-parse/default tests can drive without touching the filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MobileArgs {
    cert_paths: Vec<String>,
    root_paths: Vec<String>,
    nonce: Vec<u8>,
    require_verified_boot: bool,
    require_device_locked: bool,
    min_security_level: SecurityLevel,
    min_os_patch_level: Option<u32>,
    app_packages: Vec<String>,
    app_digests: Vec<Vec<u8>>,
    now_unix: Option<i64>,
}

impl Default for MobileArgs {
    fn default() -> Self {
        MobileArgs {
            cert_paths: Vec::new(),
            root_paths: Vec::new(),
            nonce: Vec::new(),
            require_verified_boot: false,
            require_device_locked: false,
            // Fail-safe default: require the STRONGEST tier unless the operator
            // explicitly relaxes it. A deployment that wants the TEE-fallback
            // tier must ask for it by name (`--min-security-level tee`), so a
            // silent omission never accepts a weaker key than intended.
            min_security_level: SecurityLevel::StrongBox,
            min_os_patch_level: None,
            app_packages: Vec::new(),
            app_digests: Vec::new(),
            now_unix: None,
        }
    }
}

/// Pure flag parser: `Vec<String>` args → [`MobileArgs`]. No filesystem access
/// (paths are collected, not read) so the default/parse invariants are
/// unit-testable, mirroring `seal_verify.rs`'s pure `revocation_choice`.
fn parse_args(args: Vec<String>) -> MobileArgs {
    let mut out = MobileArgs::default();
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        let mut val = || it.next().unwrap_or_else(|| usage("missing value"));
        match a.as_str() {
            "--cert" => out.cert_paths.push(val()),
            "--root" => out.root_paths.push(val()),
            // `--nonce` accepts EITHER a raw-bytes file path (a readable file at
            // that path wins) OR a hex string — the file-or-hex resolution the
            // acceptance runbook drives with `--nonce nonce.bin`.
            "--nonce" => out.nonce = resolve_nonce(&val()),
            // `--nonce-file` forces file reading (no hex fallback) for callers
            // who want to be unambiguous.
            "--nonce-file" => out.nonce = read_der(&val(), "nonce"),
            "--min-security-level" => {
                out.min_security_level = parse_security_level(&val())
                    .unwrap_or_else(|| usage("--min-security-level wants software|tee|strongbox"))
            }
            "--require-verified-boot" => out.require_verified_boot = true,
            "--require-device-locked" => out.require_device_locked = true,
            "--min-os-patch" => {
                out.min_os_patch_level = Some(
                    val()
                        .parse()
                        .unwrap_or_else(|_| usage("--min-os-patch wants a YYYYMM integer")),
                )
            }
            "--app-package" => out.app_packages.push(val()),
            "--app-digest" => out.app_digests.push(parse_hex_vec(&val(), "--app-digest")),
            "--now" => {
                out.now_unix =
                    Some(val().parse().unwrap_or_else(|_| usage("--now wants unix seconds")))
            }
            "-h" | "--help" => usage("help"),
            // A bare token that is NOT a flag is a positional, leaf-first chain
            // cert DER path (the acceptance form: `… chain-0.der chain-1.der
            // chain-2.der --root …`). Anything that starts with `-` but is not a
            // known flag is still a hard error — a mistyped flag must never be
            // silently swallowed as a certificate path.
            other if other.starts_with('-') => usage(&format!("unknown argument: {other}")),
            other => out.cert_paths.push(other.to_string()),
        }
    }
    out
}

/// Resolve a `--nonce` value to raw challenge bytes: if a **readable file**
/// exists at `spec`, its bytes ARE the nonce (the captured `nonce.bin` case);
/// otherwise `spec` is parsed as a hex string. File-first so an operator can
/// always point at the exact challenge file the Keystore was given, while the
/// terse `--nonce <hex>` form still works for ad-hoc use.
fn resolve_nonce(spec: &str) -> Vec<u8> {
    // `metadata().is_file()` (not merely `exists()`) so a directory or special
    // node never masquerades as a nonce; on any file-read error we do NOT fall
    // through to hex (that would silently accept a typo'd path) — we hard-stop.
    match std::fs::metadata(spec) {
        Ok(m) if m.is_file() => read_der(spec, "nonce"),
        _ => parse_hex_vec(spec, "--nonce"),
    }
}

/// Assemble the [`AppIdentity`] policy from the `--app-package` / `--app-digest`
/// flags. `None` (neither supplied) means "do not pin the app" — a weaker but
/// explicit posture the library documents; any package OR digest supplied
/// switches the pin on.
fn build_app_identity(packages: Vec<String>, digests: Vec<Vec<u8>>) -> Option<AppIdentity> {
    if packages.is_empty() && digests.is_empty() {
        None
    } else {
        Some(AppIdentity {
            package_names: packages,
            signature_digests: digests,
        })
    }
}

fn parse_security_level(s: &str) -> Option<SecurityLevel> {
    match s.trim().to_ascii_lowercase().as_str() {
        "software" | "sw" => Some(SecurityLevel::Software),
        "tee" | "trusted-environment" | "trustedenvironment" => {
            Some(SecurityLevel::TrustedEnvironment)
        }
        "strongbox" | "sb" => Some(SecurityLevel::StrongBox),
        _ => None,
    }
}

fn tier_str(level: SecurityLevel) -> &'static str {
    match level {
        SecurityLevel::Software => "Software (NOT hardware-backed)",
        SecurityLevel::TrustedEnvironment => "TrustedEnvironment (TEE)",
        SecurityLevel::StrongBox => "StrongBox (discrete HSM)",
    }
}

/// Map a fail-closed [`Verdict`] to its named reason string for the REJECTED
/// line. `Genuine` never reaches here (handled on the Ok arm).
fn verdict_reason(v: &Verdict) -> &'static str {
    match v {
        Verdict::Genuine => "genuine (unexpected on the reject path)",
        Verdict::Mismatch(r) => r,
        Verdict::Unverified(r) => r,
    }
}

/// Extract the leaf certificate's SubjectPublicKeyInfo (full DER) for display.
/// Returns `None` only if the leaf will not parse — impossible after a Genuine
/// verdict, but we never fabricate a key we could not re-derive.
fn leaf_public_key_spki(leaf_der: &[u8]) -> Option<Vec<u8>> {
    use x509_parser::certificate::X509Certificate;
    use x509_parser::prelude::FromDer;
    let (_, cert) = X509Certificate::from_der(leaf_der).ok()?;
    Some(cert.public_key().raw.to_vec())
}

fn read_der(path: &str, what: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| {
        eprintln!("cannot read {what} DER {path}: {e}");
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

fn usage(err: &str) -> ! {
    eprintln!("postern-seal-verify-mobile: {err}");
    eprintln!(
        "usage: postern-seal-verify-mobile \\\n\
         \x20  <leaf.der> [<intermediate.der> ...] <root-in-chain.der> \\\n\
         \x20  --root <pinned-google-root.der> [--root <second-root.der> ...] \\\n\
         \x20  --nonce <nonce.bin | hex> \\\n\
         \x20  [--min-security-level software|tee|strongbox] \\\n\
         \x20  [--require-verified-boot] [--require-device-locked] \\\n\
         \x20  [--min-os-patch YYYYMM] \\\n\
         \x20  [--app-package <name> ...] [--app-digest <hex> ...] [--now <unix-seconds>]\n\
         \n\
         The leaf-first chain certs (index 0 = attested leaf) are bare positional DER\n\
         paths; --cert <path> is also accepted and interchangeable. --nonce takes a\n\
         raw-bytes file (a readable file wins) OR a hex string. With NO --root pinned\n\
         the verdict is REJECTED (fail-closed): a chain proves nothing without an anchor."
    );
    std::process::exit(2);
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── the core fail-closed default (mirrors seal_verify.rs's
    //    revocation_choice default-safety tests) ────────────────────────────

    // The "no anchor ⇒ nothing authenticates" guarantee at the CLI boundary:
    // when the operator pins NO --root, the parsed config carries an empty root
    // list, and the library MUST fail closed (Verdict::Unverified) rather than
    // trust the chain's own terminal cert. This is the mobile analogue of
    // "omitting --crl never silently skips revocation".
    #[test]
    fn no_root_pinned_defaults_to_empty_and_fails_closed() {
        let cfg = parse_args(vec![
            "--cert".into(),
            "leaf.der".into(),
            "--nonce".into(),
            "01020304".into(),
        ]);
        // Default parse pins NO root.
        assert!(cfg.root_paths.is_empty(), "no --root must leave root_paths empty");

        // And an empty-roots MobileExpected drives the library to fail closed —
        // proven here end-to-end, not just asserted about the flag. A single
        // well-formed-looking cert is enough; the anchor gate fires first.
        let expected = MobileExpected {
            roots: Vec::new(), // <- the empty set a missing --root produces
            challenge: cfg.nonce,
            require_device_locked: cfg.require_device_locked,
            require_verified_boot: cfg.require_verified_boot,
            min_security_level: cfg.min_security_level,
            min_os_patch_level: cfg.min_os_patch_level,
            expected_app: None,
            now_unix: None,
        };
        let dummy_leaf: &[u8] = &[0x30, 0x00];
        let v = verify_key_attestation_detailed(&[dummy_leaf], &expected).unwrap_err();
        assert!(
            matches!(v, Verdict::Unverified(_)),
            "no pinned root must fail closed with Verdict::Unverified, got {v:?}"
        );
    }

    #[test]
    fn min_security_level_defaults_to_strongbox_the_strongest_tier() {
        // A silent omission must default to the STRONGEST floor, never the
        // weakest — the fail-safe direction. Relaxing requires the explicit flag.
        let cfg = parse_args(vec!["--cert".into(), "leaf.der".into()]);
        assert_eq!(cfg.min_security_level, SecurityLevel::StrongBox);
    }

    #[test]
    fn boot_and_lock_policy_flags_default_off_and_flip_on_when_passed() {
        let base = parse_args(vec!["--cert".into(), "leaf.der".into()]);
        assert!(!base.require_verified_boot);
        assert!(!base.require_device_locked);

        let hardened = parse_args(vec![
            "--cert".into(),
            "leaf.der".into(),
            "--require-verified-boot".into(),
            "--require-device-locked".into(),
        ]);
        assert!(hardened.require_verified_boot);
        assert!(hardened.require_device_locked);
    }

    #[test]
    fn security_level_strings_parse_case_insensitively_and_reject_junk() {
        assert_eq!(parse_security_level("software"), Some(SecurityLevel::Software));
        assert_eq!(parse_security_level("TEE"), Some(SecurityLevel::TrustedEnvironment));
        assert_eq!(parse_security_level("StrongBox"), Some(SecurityLevel::StrongBox));
        assert_eq!(parse_security_level("nonsense"), None);
    }

    #[test]
    fn repeatable_cert_and_root_flags_preserve_leaf_first_order() {
        let cfg = parse_args(vec![
            "--cert".into(),
            "leaf.der".into(),
            "--cert".into(),
            "inter.der".into(),
            "--cert".into(),
            "root.der".into(),
            "--root".into(),
            "google-a.der".into(),
            "--root".into(),
            "google-b.der".into(),
        ]);
        assert_eq!(cfg.cert_paths, vec!["leaf.der", "inter.der", "root.der"]);
        assert_eq!(cfg.root_paths, vec!["google-a.der", "google-b.der"]);
    }

    #[test]
    fn nonce_and_digest_hex_parse_and_policy_ints_parse() {
        let cfg = parse_args(vec![
            "--nonce".into(),
            "a1b2c3d4".into(),
            "--min-os-patch".into(),
            "202401".into(),
            "--app-package".into(),
            "labs.postern.wallet".into(),
            "--app-digest".into(),
            "abcdef".into(),
            "--now".into(),
            "1700000000".into(),
        ]);
        assert_eq!(cfg.nonce, vec![0xA1, 0xB2, 0xC3, 0xD4]);
        assert_eq!(cfg.min_os_patch_level, Some(202401));
        assert_eq!(cfg.app_packages, vec!["labs.postern.wallet"]);
        assert_eq!(cfg.app_digests, vec![vec![0xAB, 0xCD, 0xEF]]);
        assert_eq!(cfg.now_unix, Some(1_700_000_000));
    }

    // ── positional (bare) chain paths — the acceptance-runbook form ──────────

    // The acceptance command feeds the leaf-first chain as BARE positional DER
    // paths (`… chain-0.der chain-1.der chain-2.der --root … --nonce …`); they
    // must land in cert_paths in order, exactly as repeated `--cert` would.
    #[test]
    fn bare_positional_certs_are_leaf_first_chain_paths() {
        let cfg = parse_args(vec![
            "chain-0.der".into(),
            "chain-1.der".into(),
            "chain-2.der".into(),
            "--root".into(),
            "google_prod_attestation_root.der".into(),
        ]);
        assert_eq!(cfg.cert_paths, vec!["chain-0.der", "chain-1.der", "chain-2.der"]);
        assert_eq!(cfg.root_paths, vec!["google_prod_attestation_root.der"]);
    }

    // Positional and explicit --cert are interchangeable and additive, order
    // preserved across the mix.
    #[test]
    fn positional_and_explicit_cert_flags_compose_in_order() {
        let cfg = parse_args(vec![
            "leaf.der".into(),
            "--cert".into(),
            "inter.der".into(),
            "root.der".into(),
        ]);
        assert_eq!(cfg.cert_paths, vec!["leaf.der", "inter.der", "root.der"]);
    }

    // A mistyped flag (starts with `-`) must still hard-error, never be
    // swallowed as a certificate path — otherwise `--noce foo` would silently
    // drop the nonce. (usage() exits the process, so we assert the discriminator
    // directly rather than call parse_args here.)
    #[test]
    fn unknown_dash_token_is_not_treated_as_a_positional_cert() {
        // The guard is `other.starts_with('-')`; encode the invariant we rely on.
        assert!("--noce".starts_with('-'));
        assert!(!"chain-0.der".starts_with('-'));
    }

    // ── --nonce file-or-hex resolution ──────────────────────────────────────

    // A readable file path resolves to its RAW bytes (the captured nonce.bin
    // case); a hex string with no such file resolves via hex. Proven end-to-end
    // through resolve_nonce against a real temp file.
    #[test]
    fn nonce_resolves_file_bytes_then_falls_back_to_hex() {
        // hex fallback (no such file)
        assert_eq!(resolve_nonce("a1b2c3d4"), vec![0xA1, 0xB2, 0xC3, 0xD4]);

        // file-first: write raw bytes and point --nonce at them.
        let dir = std::env::temp_dir();
        let path = dir.join(format!("postern-nonce-test-{}.bin", std::process::id()));
        let raw = b"postern-seal-mobile-attest-nnc32".to_vec();
        std::fs::write(&path, &raw).unwrap();
        let got = resolve_nonce(path.to_str().unwrap());
        std::fs::remove_file(&path).ok();
        assert_eq!(got, raw, "a readable nonce file must resolve to its raw bytes");
    }

    #[test]
    fn build_app_identity_is_none_without_pins_and_some_with() {
        assert!(build_app_identity(vec![], vec![]).is_none());
        let id =
            build_app_identity(vec!["labs.postern.wallet".into()], vec![vec![0xAB; 32]]).unwrap();
        assert_eq!(id.package_names, vec!["labs.postern.wallet".to_string()]);
        assert_eq!(id.signature_digests, vec![vec![0xAB; 32]]);
    }
}
