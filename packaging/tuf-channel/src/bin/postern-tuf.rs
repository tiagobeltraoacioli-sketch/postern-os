// SPDX-License-Identifier: MIT OR Apache-2.0
//
// postern-tuf — DEV/TESTING-ONLY CLI for the local Postern TUF update-channel
// scaffold. Dev keys only (dev-keys-DO-NOT-SHIP), UNAUDITED, no live update
// endpoint exists; all metadata is LOCAL. See src/lib.rs for the rails.

use std::path::Path;
use std::process::ExitCode;

const USAGE: &str = "\
postern-tuf — DEV-ONLY local TUF update-channel scaffold (UNAUDITED; no live endpoint)

USAGE:
  postern-tuf init <repo-dir>
      Create a new local dev TUF repository: generate ed25519 dev keys into
      <repo-dir>/dev-keys-DO-NOT-SHIP/ and write signed root/targets/snapshot/
      timestamp metadata with sane dev expiries.

  postern-tuf add-target <repo-dir> <file>
      Hash + length <file> into targets metadata, copy it into targets/, and
      re-sign targets/snapshot/timestamp (versions bumped).

  postern-tuf verify <repo-dir> <target-name>
      Load the repository through tough's fail-closed client (expired or
      tampered metadata is a hard error), fetch the target, print its SHA-256.

  postern-tuf rotate-root <repo-dir>
      Rotate the root role key: generate a fresh ed25519 DEV key, build root
      vN+1 (other role keys unchanged) and dual-sign it with BOTH the old and
      the new root key (TUF spec 5.3.4), write N+1.root.json, retire the old
      key file to a .retired name. Not atomic, but crash-recoverable: a
      rotation interrupted mid-key-swap is detected (via the staged key file)
      and finished by the next run. LOCAL exercise of the rotation rule with
      throwaway dev keys — NOT a key ceremony, NOT a custody plan.

  postern-tuf refresh <repo-dir>
      Re-sign snapshot + timestamp with bumped versions and fresh dev
      expiries (targets metadata preserved byte-for-byte) — the
      anti-staleness operation a real channel runs on a schedule. No
      scheduler or endpoint exists here, and refresh cannot rescue a repo
      whose metadata ALREADY expired (fail closed) — that lapse is what
      `recover` is for.

  postern-tuf recover <repo-dir>
      Recover a repo whose snapshot/timestamp LAPSED. Fail closed: the root
      chain must still be within its own expiry (an expired root is a hard
      error — full re-init only), targets.json must re-verify against the
      trusted root's targets key, and every file under targets/ must re-hash
      to its recorded hash+length BEFORE fresh bumped snapshot/timestamp are
      re-signed. A repo that still verifies is refused (use refresh). LOCAL
      exercise of the recovery rule with throwaway dev keys — NOT an
      operated channel.
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: failed to start async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    let result = match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["init", repo_dir] => rt.block_on(cmd_init(Path::new(repo_dir))),
        ["add-target", repo_dir, file] => {
            rt.block_on(cmd_add_target(Path::new(repo_dir), Path::new(file)))
        }
        ["verify", repo_dir, target_name] => {
            rt.block_on(cmd_verify(Path::new(repo_dir), target_name))
        }
        ["rotate-root", repo_dir] => rt.block_on(cmd_rotate_root(Path::new(repo_dir))),
        ["refresh", repo_dir] => rt.block_on(cmd_refresh(Path::new(repo_dir))),
        ["recover", repo_dir] => rt.block_on(cmd_recover(Path::new(repo_dir))),
        _ => {
            eprint!("{USAGE}");
            return ExitCode::FAILURE;
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn cmd_init(repo_dir: &Path) -> anyhow::Result<()> {
    let paths = postern_tuf::init_repo(repo_dir).await?;
    println!(
        "initialized local DEV TUF repository at {}",
        paths.repo_dir.display()
    );
    println!("  metadata: {}", paths.metadata_dir.display());
    println!("  targets:  {}", paths.targets_dir.display());
    println!(
        "  keys:     {}  (DEV/TESTING-ONLY — never ship these)",
        paths.keys_dir.display()
    );
    println!("NOTE: channel is UNAUDITED and no live update endpoint exists.");
    Ok(())
}

async fn cmd_add_target(repo_dir: &Path, file: &Path) -> anyhow::Result<()> {
    let name = postern_tuf::add_target(repo_dir, file).await?;
    println!("added target '{name}' and re-signed targets/snapshot/timestamp (dev keys)");
    Ok(())
}

async fn cmd_verify(repo_dir: &Path, target_name: &str) -> anyhow::Result<()> {
    let outdir = tempfile_dir()?;
    let sha256 = postern_tuf::verify_target(repo_dir, target_name, &outdir).await?;
    println!("{sha256}  {target_name}");
    println!("OK: target verified through the full TUF client path (dev keys, local metadata)");
    std::fs::remove_dir_all(&outdir).ok();
    Ok(())
}

async fn cmd_rotate_root(repo_dir: &Path) -> anyhow::Result<()> {
    let rotation = postern_tuf::rotate_root(repo_dir).await?;
    println!(
        "rotated root to v{}: {}",
        rotation.new_version,
        rotation.new_root_json.display()
    );
    println!(
        "  dual-signed (old + new root key) per TUF spec 5.3.4; old dev key retired to {}",
        rotation.retired_key.display()
    );
    println!(
        "NOTE: DEV KEYS ONLY, UNAUDITED, LOCAL metadata — this is a local exercise of the"
    );
    println!(
        "rotation rule, NOT a key ceremony and NOT a custody plan; nothing signed here ships."
    );
    Ok(())
}

async fn cmd_refresh(repo_dir: &Path) -> anyhow::Result<()> {
    let (snapshot_version, timestamp_version) = postern_tuf::refresh(repo_dir).await?;
    println!(
        "refreshed: snapshot v{snapshot_version}, timestamp v{timestamp_version} (fresh dev expiries; targets unchanged)"
    );
    println!("NOTE: LOCAL metadata, dev keys only, UNAUDITED — no live update endpoint exists.");
    Ok(())
}

async fn cmd_recover(repo_dir: &Path) -> anyhow::Result<()> {
    let recovery = postern_tuf::recover(repo_dir).await?;
    println!(
        "recovered lapsed repo under root v{}: snapshot v{}, timestamp v{} re-signed (fresh dev expiries)",
        recovery.root_version, recovery.snapshot_version, recovery.timestamp_version
    );
    println!(
        "  targets.json signature re-verified against the trusted root; {} artifact(s) re-hashed",
        recovery.targets_checked
    );
    println!(
        "HONESTY: DEV KEYS ONLY, LOCAL repository, UNAUDITED — this exercised the designed"
    );
    println!(
        "lapse-recovery RULE; it is NOT an operated channel. No live update endpoint exists,"
    );
    println!(
        "and desktop keeps createUpdaterArtifacts=false until real keys + endpoint + audit exist."
    );
    Ok(())
}

/// Minimal unique temp dir (std-only; avoids pulling tempfile into the bin).
fn tempfile_dir() -> anyhow::Result<std::path::PathBuf> {
    let dir = std::env::temp_dir().join(format!(
        "postern-tuf-verify-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}
