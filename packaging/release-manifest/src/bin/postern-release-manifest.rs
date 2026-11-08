// SPDX-License-Identifier: MIT OR Apache-2.0

//! `postern-release-manifest` — CLI for the signed release-manifest step of
//! `packaging/build-signed-bundle.sh`.
//!
//! Std-only argument parsing (`std::env::args`) — no clap, no new dependency,
//! matching this repo's other single-purpose CLIs (`postern-tuf`,
//! `postern-release`).
//!
//! ```text
//! postern-release-manifest build  <bundle-dir> <manifest-path>
//! postern-release-manifest keygen <key-prefix>
//! postern-release-manifest sign   <manifest-path> <key-prefix> [sig-path]
//! postern-release-manifest verify <bundle-dir> <manifest-path> <pub-prefix> [sig-path]
//! ```
//!
//! All cryptography is `postern_release::sign` (crates/postern-release),
//! reused unmodified: hybrid Falcon-1024 + ML-DSA-87, AND-of-both, over the
//! exact manifest file bytes. `<key-prefix>` uses that crate's CLI file
//! convention — `<prefix>.falcon.pub`, `<prefix>.falcon.sec`,
//! `<prefix>.mldsa.pub`, `<prefix>.mldsa.seed` — so keys made by either tool
//! interoperate. `verify` additionally re-stats and re-hashes the bundle dir
//! against the manifest and FAILS CLOSED on any discrepancy; on success it
//! prints one `sha256sum`-format line per artifact to stdout (stderr carries
//! everything else) so the shell pipeline can cross-check against SHA256SUMS.
//!
//! HONESTY: dev keys only, UNAUDITED, LOCAL metadata only — see the library
//! docs and the note embedded in every manifest.

use std::env;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

use postern_release::sign::{self, HybridSignature, KeyPair, PublicKeyBundle};
use postern_release_manifest as manifest;

fn usage() -> &'static str {
    "usage:\n\
     \x20 postern-release-manifest build  <bundle-dir> <manifest-path>\n\
     \x20 postern-release-manifest keygen <key-prefix>\n\
     \x20 postern-release-manifest sign   <manifest-path> <key-prefix> [sig-path]\n\
     \x20 postern-release-manifest verify <bundle-dir> <manifest-path> <pub-prefix> [sig-path]\n\
     \x20 postern-release-manifest merge-sums <local-sums> <remote-sums> <pub-prefix> <out-path> [remote-sig]\n\n\
     [sig-path] defaults to <manifest-path>.pqsig. A <key-prefix> of\n\
     \"dev-keys-DO-NOT-SHIP/dev\" names dev.falcon.{pub,sec} and\n\
     dev.mldsa.{pub,seed} (same file convention as the postern-release CLI).\n\n\
     merge-sums VERIFIES the remote SHA256SUMS' detached hybrid signature\n\
     ([remote-sig], default <remote-sums>.pqsig) against <pub-prefix> BEFORE\n\
     merging — a missing or invalid signature is a hard error (FAIL CLOSED:\n\
     re-signing unverified remote bytes would launder a tampered bucket\n\
     object under a fresh signature). Local entries win name collisions.\n\
     Verifying the remote signature is NOT rollback protection by itself.\n\n\
     DEV KEYS ONLY / UNAUDITED / LOCAL ONLY: the hybrid Falcon-1024+ML-DSA-87\n\
     signature (both legs must verify) COMPLEMENTS, does not replace, the\n\
     repo's minisign signature, and proves origin+integrity of the manifest\n\
     only — not attestation, not reproducibility, not an audit."
}

fn write_file(path: &str, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create '{}': {e}", parent.display()))?;
        }
    }
    fs::write(path, bytes).map_err(|e| format!("cannot write '{path}': {e}"))
}

fn read_file(path: &str) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|e| format!("cannot read '{path}': {e}"))
}

fn cmd_build(bundle_dir: &str, manifest_path: &str) -> Result<(), String> {
    let m = manifest::build_manifest(Path::new(bundle_dir))
        .map_err(|e| format!("building manifest over '{bundle_dir}': {e}"))?;
    let bytes = manifest::to_json_bytes(&m).map_err(|e| e.to_string())?;
    write_file(manifest_path, &bytes)?;
    eprintln!(
        "wrote {manifest_path} ({} artifact(s), {} bytes, schema v{})",
        m.artifacts.len(),
        bytes.len(),
        m.schema_version
    );
    Ok(())
}

fn cmd_keygen(prefix: &str) -> Result<(), String> {
    let kp = KeyPair::generate();
    let pubkey = kp.public_key();
    write_file(&format!("{prefix}.falcon.pub"), &pubkey.falcon_public)?;
    write_file(&format!("{prefix}.falcon.sec"), &kp.falcon_secret_bytes())?;
    write_file(&format!("{prefix}.mldsa.pub"), &pubkey.ml_dsa_public)?;
    write_file(&format!("{prefix}.mldsa.seed"), &kp.ml_dsa_seed_bytes())?;
    eprintln!("wrote {prefix}.falcon.{{pub,sec}} and {prefix}.mldsa.{{pub,seed}}");
    eprintln!(
        "WARNING: DEV key material for the local bundle pipeline only. It must\n\
         never leave this machine and must never sign anything a user receives."
    );
    Ok(())
}

fn load_key_pair(prefix: &str) -> Result<KeyPair, String> {
    let falcon_public = read_file(&format!("{prefix}.falcon.pub"))?;
    let falcon_secret = read_file(&format!("{prefix}.falcon.sec"))?;
    let seed_bytes = read_file(&format!("{prefix}.mldsa.seed"))?;
    let seed: [u8; 32] = seed_bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("'{prefix}.mldsa.seed' must be exactly 32 bytes"))?;
    KeyPair::from_parts(falcon_public, falcon_secret, seed)
        .map_err(|e| format!("loading key pair from '{prefix}.*': {e}"))
}

fn load_public_keys(prefix: &str) -> Result<PublicKeyBundle, String> {
    Ok(PublicKeyBundle {
        falcon_public: read_file(&format!("{prefix}.falcon.pub"))?,
        ml_dsa_public: read_file(&format!("{prefix}.mldsa.pub"))?,
    })
}

fn cmd_sign(manifest_path: &str, key_prefix: &str, sig_path: Option<&str>) -> Result<(), String> {
    let sig_path = sig_path
        .map(str::to_string)
        .unwrap_or_else(|| format!("{manifest_path}.pqsig"));

    // Sign the EXACT bytes on disk — no re-serialization between build and
    // sign, so what verifies later is what the operator inspected.
    let manifest_bytes = read_file(manifest_path)?;
    // Parse first so we never sign something that is not a valid v1 manifest.
    manifest::from_json_bytes(&manifest_bytes)
        .map_err(|e| format!("refusing to sign '{manifest_path}': {e}"))?;

    let key_pair = load_key_pair(key_prefix)?;
    let signature = sign::sign_manifest(&manifest_bytes, &key_pair)
        .map_err(|e| format!("signing manifest: {e}"))?;
    write_file(&sig_path, &signature.to_bytes())?;
    eprintln!(
        "wrote {sig_path} (falcon-1024 {} bytes, ML-DSA-87 {} bytes)",
        signature.falcon.len(),
        signature.ml_dsa.len()
    );
    eprintln!(
        "This is a DEV, UNAUDITED hybrid PQ signature — it complements (does\n\
         not replace) the repo's existing minisign(Ed25519) convention."
    );
    Ok(())
}

fn cmd_verify(
    bundle_dir: &str,
    manifest_path: &str,
    pub_prefix: &str,
    sig_path: Option<&str>,
) -> Result<(), String> {
    let sig_path = sig_path
        .map(str::to_string)
        .unwrap_or_else(|| format!("{manifest_path}.pqsig"));

    // 1. Hybrid signature over the exact manifest bytes (AND-of-both:
    //    postern_release rejects the pair if either leg fails).
    let manifest_bytes = read_file(manifest_path)?;
    let signature = HybridSignature::from_bytes(&read_file(&sig_path)?)
        .map_err(|e| format!("reading signature '{sig_path}': {e}"))?;
    let public_keys = load_public_keys(pub_prefix)?;
    sign::verify_manifest(&manifest_bytes, &signature, &public_keys)
        .map_err(|e| format!("HYBRID VERIFY FAILED (fail closed): {e}"))?;
    eprintln!("signature OK: falcon-1024 AND ML-DSA-87 both verify over {manifest_path}");

    // 2. Parse (fail closed on schema drift) and re-check the bundle dir:
    //    re-stat sizes + re-hash SHA-256s; any mismatch, missing artifact,
    //    or unlisted file is a hard error, never a warning.
    let m = manifest::from_json_bytes(&manifest_bytes)
        .map_err(|e| format!("parsing '{manifest_path}': {e}"))?;
    manifest::check_against_dir(&m, Path::new(bundle_dir))
        .map_err(|e| format!("BUNDLE RE-CHECK FAILED (fail closed): {e}"))?;
    eprintln!(
        "bundle re-check OK: {} artifact(s) in '{bundle_dir}' match the manifest byte-for-byte",
        m.artifacts.len()
    );

    // stdout carries ONLY sha256sum-format lines, for the shell cross-check
    // against SHA256SUMS in build-signed-bundle.sh.
    for a in &m.artifacts {
        println!("{}  {}", a.sha256, a.name);
    }
    eprintln!(
        "REMINDER: origin+integrity of the manifest only — not attestation, not\n\
         reproducibility, not an audit. Dev keys; also verify minisign."
    );
    Ok(())
}

fn cmd_merge_sums(
    local_path: &str,
    remote_path: &str,
    pub_prefix: &str,
    out_path: &str,
    remote_sig_path: Option<&str>,
) -> Result<(), String> {
    let remote_sig_path = remote_sig_path
        .map(str::to_string)
        .unwrap_or_else(|| format!("{remote_path}.pqsig"));

    let local = read_file(local_path)?;
    let local = std::str::from_utf8(&local)
        .map_err(|_| format!("'{local_path}' is not valid UTF-8 (fail closed)"))?;
    let remote = read_file(remote_path)?;
    // FAIL CLOSED on a missing signature file: an unsigned remote SUMS is
    // never merged (see the library docs — re-signing unverified remote
    // bytes launders tampering).
    let remote_sig = read_file(&remote_sig_path).map_err(|e| {
        format!(
            "remote SHA256SUMS signature is REQUIRED and could not be read (fail closed; \
             refusing to merge an unverified remote SUMS): {e}"
        )
    })?;
    let public_keys = load_public_keys(pub_prefix)?;

    let merged = manifest::merge_signed_sha256sums(
        local,
        Some(&remote),
        Some(&remote_sig),
        &public_keys,
    )
    .map_err(|e| format!("MERGE REFUSED (fail closed): {e}"))?;
    eprintln!("remote signature OK: falcon-1024 AND ML-DSA-87 both verify over {remote_path}");
    write_file(out_path, merged.as_bytes())?;
    eprintln!(
        "wrote {out_path} ({} line(s); local '{local_path}' entries won any name collision)",
        merged.lines().count()
    );
    eprintln!(
        "REMINDER: re-sign {out_path} (hybrid + minisign) before publishing; verifying the\n\
         remote signature is origin+integrity only — not attestation and not, by itself,\n\
         rollback protection. Dev keys; UNAUDITED."
    );
    Ok(())
}

fn run(args: &[String]) -> Result<(), String> {
    let arg = |i: usize| args.get(i).map(String::as_str);
    match arg(0) {
        Some("build") => match (arg(1), arg(2), arg(3)) {
            (Some(dir), Some(out), None) => cmd_build(dir, out),
            _ => Err(format!("build takes exactly <bundle-dir> <manifest-path>\n\n{}", usage())),
        },
        Some("keygen") => match (arg(1), arg(2)) {
            (Some(prefix), None) => cmd_keygen(prefix),
            _ => Err(format!("keygen takes exactly <key-prefix>\n\n{}", usage())),
        },
        Some("sign") => match (arg(1), arg(2), arg(4)) {
            (Some(m), Some(k), None) => cmd_sign(m, k, arg(3)),
            _ => Err(format!("sign takes <manifest-path> <key-prefix> [sig-path]\n\n{}", usage())),
        },
        Some("verify") => match (arg(1), arg(2), arg(3), arg(5)) {
            (Some(d), Some(m), Some(p), None) => cmd_verify(d, m, p, arg(4)),
            _ => Err(format!(
                "verify takes <bundle-dir> <manifest-path> <pub-prefix> [sig-path]\n\n{}",
                usage()
            )),
        },
        Some("merge-sums") => match (arg(1), arg(2), arg(3), arg(4), arg(6)) {
            (Some(l), Some(r), Some(p), Some(o), None) => cmd_merge_sums(l, r, p, o, arg(5)),
            _ => Err(format!(
                "merge-sums takes <local-sums> <remote-sums> <pub-prefix> <out-path> [remote-sig]\n\n{}",
                usage()
            )),
        },
        Some(other) => Err(format!("unknown subcommand '{other}'\n\n{}", usage())),
        None => Err(usage().to_string()),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("error: {msg}");
            ExitCode::FAILURE
        }
    }
}
