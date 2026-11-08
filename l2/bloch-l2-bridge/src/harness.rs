// SPDX-License-Identifier: MIT OR Apache-2.0
//! Deploy HARNESS CONFIG — types + validation ONLY. **Not a live deploy.**
//!
//! Describes what a testnet genesis/deploy of the §5 bridge surface WOULD
//! contain: the WBLCH predeploy (WETH9-style wrapper, `contracts/wblch/
//! WBLCH.sol`, fixed OP-convention address `0x42..0006`, solc `^0.8.24`)
//! and the UNCHANGED Uniswap-v2 factory/router artifacts (that byte-for-
//! byte-unchanged deployability is the whole point of the EVM L2).
//!
//! What this module actually does:
//! * (de)serializes `deploy/testnet.json`;
//! * validates it: chain id, address syntax, the pinned WBLCH address,
//!   that the referenced Solidity source EXISTS on disk and that its
//!   keccak256 matches the hash pinned in the config (so the config and
//!   the source cannot drift silently).
//!
//! What it deliberately does NOT do (see [`crate::stubs`]): compile
//! Solidity, talk to any chain, deploy anything, or hold keys.
//!
//! SCAFFOLD, UNAUDITED. Chain id 700771 is a PLACEHOLDER pending
//! ethereum-lists/chains registration; the Uniswap artifact hashes are
//! labelled placeholders until real artifacts are vendored.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::hex;
use crate::merkle::keccak256;

/// The fixed WBLCH predeploy address (§5, OP-Stack address convention).
pub const WBLCH_PREDEPLOY_ADDRESS: &str = "0x4200000000000000000000000000000000000006";
/// Proposed testnet chain id — PLACEHOLDER pending registration (§1).
pub const TESTNET_CHAIN_ID: u64 = 700_771;
/// solc pragma the WBLCH source pins.
pub const WBLCH_SOLC_PRAGMA: &str = "^0.8.24";

/// Top-level deploy harness config (`deploy/testnet.json`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeployConfig {
    /// Human label, e.g. "bloch-l2-testnet".
    pub network: String,
    /// EVM chain id (700771 testnet placeholder).
    pub chain_id: u64,
    /// solc version pragma the predeploy sources pin.
    pub solc_version: String,
    /// Predeploys placed in the genesis alloc (not deployed by tx).
    pub predeploys: Vec<Predeploy>,
    /// Unchanged third-party artifacts deployed by ordinary txs.
    pub uniswap_v2: UniswapV2Artifacts,
    /// Carried honesty banner; validated non-empty.
    pub honesty: String,
}

/// One genesis predeploy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Predeploy {
    pub name: String,
    /// 0x-prefixed 20-byte EVM address.
    pub address: String,
    /// Path to the Solidity source, relative to this crate's root.
    pub source_path: String,
    /// keccak256 of the exact source bytes, 0x-prefixed — pins the file.
    pub source_keccak256: String,
    /// Exact compiler + settings the pinned bytecode hash was built with.
    pub compiler: CompilerConfig,
    /// keccak256 of the DEPLOYED (runtime) bytecode solc emits for this
    /// source under `compiler`, 0x-prefixed. A REAL hash (not a
    /// placeholder): recomputed by the harness test, which fails if the
    /// source — or the pinned compiler — drifts.
    pub deployed_bytecode_keccak256: String,
    #[serde(default)]
    pub notes: Option<String>,
}

/// Exact solc invocation the pinned deployed-bytecode hash is reproducible
/// under. EVM bytecode is only byte-for-byte stable for a FIXED compiler
/// version + settings, so all of these are pinned alongside the hash.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompilerConfig {
    /// Exact solc version, e.g. "0.8.24" (must satisfy the source pragma).
    pub solc_version_exact: String,
    /// solc optimizer `enabled`.
    pub optimizer_enabled: bool,
    /// solc optimizer `runs`.
    pub optimizer_runs: u32,
    /// Target EVM version, e.g. "shanghai" (0.8.24's default).
    pub evm_version: String,
    /// solc `metadata.bytecodeHash`. "none" strips the trailing CBOR
    /// metadata hash so the bytecode is a pure function of source +
    /// compiler + settings (no embedded IPFS/swarm digest to drift).
    pub metadata_bytecode_hash: String,
}

/// The unchanged Uniswap-v2 pair of artifacts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UniswapV2Artifacts {
    pub factory: ExternalArtifact,
    pub router02: ExternalArtifact,
}

/// An artifact deployed byte-for-byte from Ethereum mainnet builds.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExternalArtifact {
    pub name: String,
    /// Provenance note ("unchanged Uniswap v2 mainnet artifact").
    pub origin: String,
    /// The Ethereum-mainnet deployment this artifact is taken from
    /// (documentation; nothing is fetched).
    pub ethereum_mainnet_address: String,
    /// keccak256 of the creation bytecode — PLACEHOLDER (all-zero) until
    /// the real artifact is vendored; `placeholder: true` says so.
    pub artifact_keccak256: String,
    /// Honesty flag: true while `artifact_keccak256` is not a real hash.
    pub placeholder: bool,
}

/// A validated view of the config, with parsed addresses and the
/// on-disk source hash re-computed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedDeploy {
    pub chain_id: u64,
    /// (name, parsed address, absolute source path, keccak256 of source)
    pub predeploys: Vec<ValidatedPredeploy>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedPredeploy {
    pub name: String,
    pub address: [u8; 20],
    pub source_path: PathBuf,
    pub source_keccak256: [u8; 32],
}

/// Typed harness errors.
#[derive(Debug)]
pub enum HarnessError {
    Io(std::io::Error),
    Json(serde_json::Error),
    BadAddress {
        field: String,
        reason: String,
    },
    ChainIdMismatch {
        expected: u64,
        actual: u64,
    },
    WblchAddressMismatch {
        actual: String,
    },
    WblchMissing,
    SolcMismatch {
        expected: String,
        actual: String,
    },
    SourceMissing {
        path: PathBuf,
    },
    SourceHashMismatch {
        path: PathBuf,
        expected: String,
        actual: String,
    },
    EmptyHonestyBanner,
    UnlabelledPlaceholder {
        artifact: String,
    },
    /// solc is not on `PATH` and `$SOLC` is unset (compile step skipped).
    SolcNotFound,
    /// solc could not be executed or its output parsed.
    SolcInvocation(String),
    /// solc reported a hard compile error.
    SolcCompile(String),
    /// The available solc is not the exact pinned version, so the pinned
    /// bytecode hash is not reproducible with it.
    SolcVersionMismatch {
        expected: String,
        actual: String,
    },
    /// The compiled deployed-bytecode hash differs from the pinned value.
    DeployedBytecodeMismatch {
        expected: String,
        actual: String,
    },
}

impl core::fmt::Display for HarnessError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HarnessError::Io(e) => write!(f, "io: {e}"),
            HarnessError::Json(e) => write!(f, "json: {e}"),
            HarnessError::BadAddress { field, reason } => {
                write!(f, "bad address in {field}: {reason}")
            }
            HarnessError::ChainIdMismatch { expected, actual } => {
                write!(f, "chain id mismatch: expected {expected}, got {actual}")
            }
            HarnessError::WblchAddressMismatch { actual } => write!(
                f,
                "WBLCH predeploy must sit at {WBLCH_PREDEPLOY_ADDRESS}, got {actual}"
            ),
            HarnessError::WblchMissing => write!(f, "config has no WBLCH predeploy"),
            HarnessError::SolcMismatch { expected, actual } => {
                write!(f, "solc pragma mismatch: expected {expected}, got {actual}")
            }
            HarnessError::SourceMissing { path } => {
                write!(f, "referenced source missing: {}", path.display())
            }
            HarnessError::SourceHashMismatch {
                path,
                expected,
                actual,
            } => write!(
                f,
                "source hash mismatch for {}: config pins {expected}, file is {actual}",
                path.display()
            ),
            HarnessError::EmptyHonestyBanner => {
                write!(f, "honesty banner must be present and non-empty")
            }
            HarnessError::UnlabelledPlaceholder { artifact } => write!(
                f,
                "artifact {artifact} has an all-zero hash but placeholder=false"
            ),
            HarnessError::SolcNotFound => write!(
                f,
                "solc not found (set $SOLC or put solc on PATH) — compile step skipped"
            ),
            HarnessError::SolcInvocation(e) => write!(f, "solc invocation failed: {e}"),
            HarnessError::SolcCompile(e) => write!(f, "solc compile error: {e}"),
            HarnessError::SolcVersionMismatch { expected, actual } => write!(
                f,
                "solc version mismatch: pinned {expected}, found {actual} (bytecode not reproducible)"
            ),
            HarnessError::DeployedBytecodeMismatch { expected, actual } => write!(
                f,
                "deployed-bytecode hash mismatch: config pins {expected}, compiled {actual} \
                 (update deploy/testnet.json if WBLCH.sol legitimately changed)"
            ),
        }
    }
}

impl std::error::Error for HarnessError {}

impl From<std::io::Error> for HarnessError {
    fn from(e: std::io::Error) -> Self {
        HarnessError::Io(e)
    }
}

impl From<serde_json::Error> for HarnessError {
    fn from(e: serde_json::Error) -> Self {
        HarnessError::Json(e)
    }
}

/// Parse a 0x-prefixed 20-byte EVM address.
pub fn parse_address(s: &str) -> Result<[u8; 20], String> {
    if !s.starts_with("0x") {
        return Err("missing 0x prefix".to_string());
    }
    hex::decode_array::<20>(s).map_err(|e| e.to_string())
}

/// Load `deploy/testnet.json` (or any harness config) from disk.
pub fn load_config(path: &Path) -> Result<DeployConfig, HarnessError> {
    let bytes = std::fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Path of the in-repo testnet config, resolved from this crate's root.
pub fn default_config_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("deploy/testnet.json")
}

/// Validate a config against `base_dir` (the crate root for the in-repo
/// config): chain id, address syntax, WBLCH pinning, source existence,
/// and source-hash stability. Returns the parsed view.
pub fn validate(config: &DeployConfig, base_dir: &Path) -> Result<ValidatedDeploy, HarnessError> {
    if config.chain_id != TESTNET_CHAIN_ID {
        return Err(HarnessError::ChainIdMismatch {
            expected: TESTNET_CHAIN_ID,
            actual: config.chain_id,
        });
    }
    if config.solc_version != WBLCH_SOLC_PRAGMA {
        return Err(HarnessError::SolcMismatch {
            expected: WBLCH_SOLC_PRAGMA.to_string(),
            actual: config.solc_version.clone(),
        });
    }
    if config.honesty.trim().is_empty() {
        return Err(HarnessError::EmptyHonestyBanner);
    }

    let mut validated = Vec::new();
    let mut saw_wblch = false;
    for p in &config.predeploys {
        let address = parse_address(&p.address).map_err(|reason| HarnessError::BadAddress {
            field: format!("predeploys[{}].address", p.name),
            reason,
        })?;
        if p.name == "WBLCH" {
            saw_wblch = true;
            if !p.address.eq_ignore_ascii_case(WBLCH_PREDEPLOY_ADDRESS) {
                return Err(HarnessError::WblchAddressMismatch {
                    actual: p.address.clone(),
                });
            }
        }
        let source_path = base_dir.join(&p.source_path);
        if !source_path.is_file() {
            return Err(HarnessError::SourceMissing { path: source_path });
        }
        let bytes = std::fs::read(&source_path)?;
        let actual = keccak256(&bytes);
        let expected =
            hex::decode_array::<32>(&p.source_keccak256).map_err(|e| HarnessError::BadAddress {
                field: format!("predeploys[{}].source_keccak256", p.name),
                reason: e.to_string(),
            })?;
        if actual != expected {
            return Err(HarnessError::SourceHashMismatch {
                path: source_path,
                expected: p.source_keccak256.clone(),
                actual: hex::encode_prefixed(&actual),
            });
        }
        // The pinned deployed-bytecode hash must be a well-formed, NON-zero
        // 32-byte value: it is a real compiled hash, never a placeholder.
        let dep_hash = hex::decode_array::<32>(&p.deployed_bytecode_keccak256).map_err(|e| {
            HarnessError::BadAddress {
                field: format!("predeploys[{}].deployed_bytecode_keccak256", p.name),
                reason: e.to_string(),
            }
        })?;
        if dep_hash == [0u8; 32] {
            return Err(HarnessError::UnlabelledPlaceholder {
                artifact: format!("predeploys[{}].deployed_bytecode_keccak256", p.name),
            });
        }
        // Compiler pin must be self-consistent and satisfy the source pragma.
        if p.compiler.optimizer_enabled && p.compiler.optimizer_runs == 0 {
            return Err(HarnessError::BadAddress {
                field: format!("predeploys[{}].compiler.optimizer_runs", p.name),
                reason: "optimizer enabled but runs == 0".to_string(),
            });
        }
        if !pragma_satisfies(&config.solc_version, &p.compiler.solc_version_exact) {
            return Err(HarnessError::SolcMismatch {
                expected: config.solc_version.clone(),
                actual: p.compiler.solc_version_exact.clone(),
            });
        }
        validated.push(ValidatedPredeploy {
            name: p.name.clone(),
            address,
            source_path,
            source_keccak256: actual,
        });
    }
    if !saw_wblch {
        return Err(HarnessError::WblchMissing);
    }

    // External artifacts: address syntax + honest placeholder labelling.
    for artifact in [&config.uniswap_v2.factory, &config.uniswap_v2.router02] {
        parse_address(&artifact.ethereum_mainnet_address).map_err(|reason| {
            HarnessError::BadAddress {
                field: format!("uniswap_v2.{}.ethereum_mainnet_address", artifact.name),
                reason,
            }
        })?;
        let hash = hex::decode_array::<32>(&artifact.artifact_keccak256).map_err(|e| {
            HarnessError::BadAddress {
                field: format!("uniswap_v2.{}.artifact_keccak256", artifact.name),
                reason: e.to_string(),
            }
        })?;
        let is_zero = hash == [0u8; 32];
        if is_zero && !artifact.placeholder {
            return Err(HarnessError::UnlabelledPlaceholder {
                artifact: artifact.name.clone(),
            });
        }
    }

    Ok(ValidatedDeploy {
        chain_id: config.chain_id,
        predeploys: validated,
    })
}

/// Does the exact version `X.Y.Z` satisfy a solc caret pragma `^A.B.C`?
///
/// Implements Solidity's caret semantics for the `0.y` line: `^0.8.24`
/// means `>=0.8.24 <0.9.0` (the minor is the "major" for 0.x). A bare
/// `A.B.C` (no `^`) requires an exact match. This is intentionally minimal
/// — it only needs to gate the one pragma this crate pins.
pub fn pragma_satisfies(pragma: &str, exact: &str) -> bool {
    fn triple(s: &str) -> Option<(u64, u64, u64)> {
        let mut it = s.trim().split('.');
        let a = it.next()?.parse().ok()?;
        let b = it.next()?.parse().ok()?;
        let c = it.next()?.parse().ok()?;
        if it.next().is_some() {
            return None;
        }
        Some((a, b, c))
    }
    let ev = match triple(exact) {
        Some(v) => v,
        None => return false,
    };
    if let Some(rest) = pragma.trim().strip_prefix('^') {
        let pv = match triple(rest) {
            Some(v) => v,
            None => return false,
        };
        if pv.0 != ev.0 {
            return false; // different major
        }
        if pv.0 == 0 {
            // ^0.B.C == >=0.B.C <0.(B+1).0
            ev.1 == pv.1 && ev.2 >= pv.2
        } else {
            // ^A.B.C == >=A.B.C <(A+1).0.0
            ev.1 > pv.1 || (ev.1 == pv.1 && ev.2 >= pv.2)
        }
    } else {
        triple(pragma) == Some(ev)
    }
}

/// Locate a solc binary: `$SOLC` (a path) if set and present, else the
/// first `solc` found on `PATH`. `None` if neither exists.
pub fn find_solc() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("SOLC") {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return Some(pb);
        }
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join("solc"))
        .find(|c| c.is_file())
}

/// The `X.Y.Z` version the given solc reports (parsed from `--version`).
pub fn solc_version(solc: &Path) -> Result<String, HarnessError> {
    let out = std::process::Command::new(solc)
        .arg("--version")
        .output()
        .map_err(|e| HarnessError::SolcInvocation(e.to_string()))?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if let Some(rest) = line.trim().strip_prefix("Version:") {
            // e.g. "0.8.24+commit.e11b9ed9.Darwin.appleclang"
            let v = rest.trim();
            let ver = v.split('+').next().unwrap_or(v).trim();
            return Ok(ver.to_string());
        }
    }
    Err(HarnessError::SolcInvocation(
        "could not parse `solc --version` output".to_string(),
    ))
}

/// Compile `source_path` (containing a contract named `contract_name`) with
/// the EXACT pinned `cfg`, via solc `--standard-json`, and return the
/// DEPLOYED (runtime) bytecode. Deterministic: same source + same `cfg` +
/// same solc version ⇒ identical bytes. Does NOT deploy anything — it only
/// invokes the compiler and reads its stdout.
pub fn compile_deployed_bytecode(
    solc: &Path,
    contract_name: &str,
    source_path: &Path,
    cfg: &CompilerConfig,
) -> Result<Vec<u8>, HarnessError> {
    let source = std::fs::read_to_string(source_path)?;
    let file_key = source_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("Contract.sol")
        .to_string();

    let input = serde_json::json!({
        "language": "Solidity",
        "sources": { file_key.clone(): { "content": source } },
        "settings": {
            "optimizer": { "enabled": cfg.optimizer_enabled, "runs": cfg.optimizer_runs },
            "evmVersion": cfg.evm_version,
            "metadata": { "bytecodeHash": cfg.metadata_bytecode_hash },
            "outputSelection": { "*": { "*": ["evm.deployedBytecode.object"] } }
        }
    });

    use std::io::Write;
    let mut child = std::process::Command::new(solc)
        .arg("--standard-json")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| HarnessError::SolcInvocation(e.to_string()))?;
    child
        .stdin
        .take()
        .ok_or_else(|| HarnessError::SolcInvocation("no stdin handle".to_string()))?
        .write_all(input.to_string().as_bytes())?;
    let out = child
        .wait_with_output()
        .map_err(|e| HarnessError::SolcInvocation(e.to_string()))?;

    let res: serde_json::Value = serde_json::from_slice(&out.stdout)
        .map_err(|e| HarnessError::SolcInvocation(format!("bad solc JSON output: {e}")))?;

    if let Some(errs) = res.get("errors").and_then(|e| e.as_array()) {
        let hard: Vec<String> = errs
            .iter()
            .filter(|e| e.get("severity").and_then(|s| s.as_str()) == Some("error"))
            .map(|e| {
                e.get("formattedMessage")
                    .or_else(|| e.get("message"))
                    .and_then(|m| m.as_str())
                    .unwrap_or("(unknown error)")
                    .to_string()
            })
            .collect();
        if !hard.is_empty() {
            return Err(HarnessError::SolcCompile(hard.join("\n")));
        }
    }

    let obj = res
        .get("contracts")
        .and_then(|c| c.get(&file_key))
        .and_then(|f| f.get(contract_name))
        .and_then(|c| c.get("evm"))
        .and_then(|e| e.get("deployedBytecode"))
        .and_then(|b| b.get("object"))
        .and_then(|o| o.as_str())
        .ok_or_else(|| {
            HarnessError::SolcCompile(format!(
                "deployedBytecode.object missing for {contract_name} in {file_key}"
            ))
        })?;

    hex::decode(obj).map_err(|e| HarnessError::SolcCompile(format!("bad bytecode hex: {e}")))
}

/// Compile the given predeploy's source with `solc` and assert the
/// keccak256 of its deployed bytecode equals the pinned
/// `deployed_bytecode_keccak256`. Enforces the exact pinned solc version
/// first (bytecode is only reproducible under it). This is the check the
/// harness test runs; it fails if the source — or the compiler pin — drifts.
pub fn verify_deployed_bytecode(
    solc: &Path,
    predeploy: &Predeploy,
    base_dir: &Path,
) -> Result<[u8; 32], HarnessError> {
    let found = solc_version(solc)?;
    if found != predeploy.compiler.solc_version_exact {
        return Err(HarnessError::SolcVersionMismatch {
            expected: predeploy.compiler.solc_version_exact.clone(),
            actual: found,
        });
    }
    let source_path = base_dir.join(&predeploy.source_path);
    let bytecode =
        compile_deployed_bytecode(solc, &predeploy.name, &source_path, &predeploy.compiler)?;
    let actual = keccak256(&bytecode);
    let expected =
        hex::decode_array::<32>(&predeploy.deployed_bytecode_keccak256).map_err(|e| {
            HarnessError::BadAddress {
                field: format!("predeploys[{}].deployed_bytecode_keccak256", predeploy.name),
                reason: e.to_string(),
            }
        })?;
    if actual != expected {
        return Err(HarnessError::DeployedBytecodeMismatch {
            expected: hex::encode_prefixed(&expected),
            actual: hex::encode_prefixed(&actual),
        });
    }
    Ok(actual)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pragma_caret_semantics() {
        assert!(pragma_satisfies("^0.8.24", "0.8.24"));
        assert!(pragma_satisfies("^0.8.24", "0.8.30"));
        assert!(!pragma_satisfies("^0.8.24", "0.8.23")); // below floor
        assert!(!pragma_satisfies("^0.8.24", "0.9.0")); // crosses minor
        assert!(!pragma_satisfies("^0.8.24", "0.7.24")); // below minor
        assert!(pragma_satisfies("0.8.24", "0.8.24")); // exact pin
        assert!(!pragma_satisfies("0.8.24", "0.8.25"));
    }

    #[test]
    fn parse_address_accepts_wblch_predeploy() {
        let a = parse_address(WBLCH_PREDEPLOY_ADDRESS).unwrap();
        assert_eq!(a[0], 0x42);
        assert_eq!(a[19], 0x06);
        assert_eq!(&a[1..19], &[0u8; 18]);
    }

    #[test]
    fn parse_address_rejects_bad_input() {
        assert!(parse_address("4200000000000000000000000000000000000006").is_err()); // no 0x
        assert!(parse_address("0x42").is_err()); // short
        assert!(parse_address("0xzz00000000000000000000000000000000000006").is_err());
    }
}
