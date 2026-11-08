//! `postern-release` — build a `SHA256SUMS` manifest and a detached HYBRID
//! Falcon-1024 + ML-DSA-87 signature over it.
//!
//! Std-only argument parsing (`std::env::args`) — no clap, no new dependency,
//! matching this repo's other single-purpose CLIs (see `postern-hygiene`).
//!
//! ```text
//! postern-release keygen  --out <prefix>
//! postern-release sign    --artifacts <dir> --key <prefix> [--out <sigfile>]
//! postern-release verify  --artifacts <dir> --pub <prefix> [--sig <sigfile>]
//! ```
//!
//! `<prefix>` names four files: `<prefix>.falcon.pub`, `<prefix>.falcon.sec`,
//! `<prefix>.mldsa.pub`, `<prefix>.mldsa.seed`. `keygen` writes all four;
//! `sign` reads the `.sec`/`.seed` pair; `verify` reads only the `.pub` pair
//! (never needs the secret material).
//!
//! **`keygen` output is DEV/SAMPLE-grade key material for exercising this
//! tool's own sign/verify flow.** It is written to whatever path the caller
//! gives `--out`; this CLI never writes a key into the repository tree on its
//! own, and any key an operator DOES commit under a `dev-sample` name (as the
//! repo already does for its minisign key) must never sign a real release.
//! See the `postern_release` crate docs for the full HONESTY section (this
//! signature is origin+integrity only — not attestation, not
//! reproducibility, not audit — and complements, not replaces, the existing
//! minisign signature).

use std::env;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

use postern_release::sign::{HybridSignature, KeyPair, PublicKeyBundle};
use postern_release::{manifest, sign};

fn usage() -> &'static str {
    "usage:\n\
     \x20 postern-release keygen  --out <key-prefix>\n\
     \x20 postern-release sign    --artifacts <dir> --key <key-prefix> [--out <sigfile>]\n\
     \x20 postern-release verify  --artifacts <dir> --pub <key-prefix> [--sig <sigfile>]\n\n\
     A <key-prefix> of \"keys/dev-sample\" names:\n\
     \x20 keys/dev-sample.falcon.pub  keys/dev-sample.falcon.sec\n\
     \x20 keys/dev-sample.mldsa.pub   keys/dev-sample.mldsa.seed\n\n\
     'sign' defaults --out to <artifacts>/SHA256SUMS.pqsig; 'verify' defaults\n\
     --sig the same way. This is a SECOND, post-quantum signature that\n\
     COMPLEMENTS (does not replace) the repo's existing minisign signature.\n\
     Both legs (Falcon-1024 AND ML-DSA-87) must verify; UNAUDITED — see the\n\
     postern_release crate docs."
}

/// Parse `--flag value` pairs out of `args`. Unknown/missing flags are the
/// caller's problem to report with a clear message, not this parser's.
fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

fn write_key_file(path: &str, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| format!("cannot create '{parent:?}': {e}"))?;
        }
    }
    fs::write(path, bytes).map_err(|e| format!("cannot write '{path}': {e}"))
}

fn read_key_file(path: &str) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|e| format!("cannot read '{path}': {e}"))
}

fn cmd_keygen(args: &[String]) -> Result<(), String> {
    let prefix = flag(args, "--out").ok_or("keygen requires --out <key-prefix>")?;

    let kp = KeyPair::generate();
    let pubkey = kp.public_key();

    write_key_file(&format!("{prefix}.falcon.pub"), &pubkey.falcon_public)?;
    write_key_file(&format!("{prefix}.falcon.sec"), &kp.falcon_secret_bytes())?;
    write_key_file(&format!("{prefix}.mldsa.pub"), &pubkey.ml_dsa_public)?;
    write_key_file(&format!("{prefix}.mldsa.seed"), &kp.ml_dsa_seed_bytes())?;

    eprintln!("wrote {prefix}.falcon.{{pub,sec}} and {prefix}.mldsa.{{pub,seed}}");
    eprintln!(
        "WARNING: DEV/SAMPLE-grade key material. Never sign a real release with a\n\
         key produced this way unless YOU, the operator, generated and are holding\n\
         it specifically for that purpose — this crate never generates a\n\
         production key into the repository tree."
    );
    Ok(())
}

fn load_key_pair(prefix: &str) -> Result<KeyPair, String> {
    let falcon_public = read_key_file(&format!("{prefix}.falcon.pub"))?;
    let falcon_secret = read_key_file(&format!("{prefix}.falcon.sec"))?;
    let seed_bytes = read_key_file(&format!("{prefix}.mldsa.seed"))?;
    let seed: [u8; 32] = seed_bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("'{prefix}.mldsa.seed' must be exactly 32 bytes"))?;

    KeyPair::from_parts(falcon_public, falcon_secret, seed)
        .map_err(|e| format!("loading key pair from '{prefix}.*': {e}"))
}

fn load_public_keys(prefix: &str) -> Result<PublicKeyBundle, String> {
    Ok(PublicKeyBundle {
        falcon_public: read_key_file(&format!("{prefix}.falcon.pub"))?,
        ml_dsa_public: read_key_file(&format!("{prefix}.mldsa.pub"))?,
    })
}

fn cmd_sign(args: &[String]) -> Result<(), String> {
    let artifacts = flag(args, "--artifacts").ok_or("sign requires --artifacts <dir>")?;
    let key_prefix = flag(args, "--key").ok_or("sign requires --key <key-prefix>")?;
    let out = flag(args, "--out")
        .map(str::to_string)
        .unwrap_or_else(|| format!("{artifacts}/{}.pqsig", manifest::MANIFEST_NAME));

    let manifest_bytes = manifest::write_manifest(Path::new(artifacts))
        .map_err(|e| format!("building manifest over '{artifacts}': {e}"))?;
    eprintln!(
        "wrote {artifacts}/{} ({} bytes)",
        manifest::MANIFEST_NAME,
        manifest_bytes.len()
    );

    let key_pair = load_key_pair(key_prefix)?;
    let signature = sign::sign_manifest(&manifest_bytes, &key_pair)
        .map_err(|e| format!("signing manifest: {e}"))?;

    fs::write(&out, signature.to_bytes()).map_err(|e| format!("cannot write '{out}': {e}"))?;
    eprintln!("wrote {out} (falcon-1024 {} bytes, ML-DSA-87 {} bytes)", signature.falcon.len(), signature.ml_dsa.len());
    eprintln!(
        "This is a SECOND, PQ, UNAUDITED signature — it complements (does not\n\
         replace) the repo's existing minisign(Ed25519) signature. Ship both."
    );
    Ok(())
}

fn cmd_verify(args: &[String]) -> Result<(), String> {
    let artifacts = flag(args, "--artifacts").ok_or("verify requires --artifacts <dir>")?;
    let pub_prefix = flag(args, "--pub").ok_or("verify requires --pub <key-prefix>")?;
    let sig_path = flag(args, "--sig")
        .map(str::to_string)
        .unwrap_or_else(|| format!("{artifacts}/{}.pqsig", manifest::MANIFEST_NAME));

    let manifest_bytes = manifest::build_manifest(Path::new(artifacts))
        .map_err(|e| format!("rebuilding manifest over '{artifacts}': {e}"))?;

    let sig_bytes = read_key_file(&sig_path)?;
    let signature = HybridSignature::from_bytes(&sig_bytes)
        .map_err(|e| format!("reading signature '{sig_path}': {e}"))?;

    let public_keys = load_public_keys(pub_prefix)?;

    sign::verify_manifest(&manifest_bytes, &signature, &public_keys)
        .map_err(|e| format!("HYBRID VERIFY FAILED: {e}"))?;

    println!("OK: falcon-1024 AND ML-DSA-87 both verify over {artifacts}/{}", manifest::MANIFEST_NAME);
    println!(
        "This proves origin+integrity of the manifest ONLY — not attestation,\n\
         not reproducibility, not an audit. Also verify the minisign signature."
    );
    Ok(())
}

fn run(args: &[String]) -> Result<(), String> {
    let Some(cmd) = args.first() else {
        return Err(usage().to_string());
    };
    let rest = &args[1..];
    match cmd.as_str() {
        "keygen" => cmd_keygen(rest),
        "sign" => cmd_sign(rest),
        "verify" => cmd_verify(rest),
        other => Err(format!("unknown subcommand '{other}'\n\n{}", usage())),
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
