//! The **Threshold Test** — fail-closed validation of an Izbushka manifest.
//!
//! Before any run, Yagabona tests the manifest at the threshold. [`validate`]
//! either returns a [`Grant`] (the door turns; execution may proceed strictly
//! inside the granted capabilities) or a [`Refusal`] carrying a reason. On a
//! refusal, **nothing executes** — no silent retry, no partial run.
//!
//! The rules enforced:
//!
//! 1. All capabilities are declared up front (guaranteed structurally by the
//!    manifest parser — the `[capabilities]` table and its `network` field are
//!    mandatory).
//! 2. Every `read_paths` / `write_paths` entry canonicalizes to a location
//!    **inside** `workspace_root`. A `..` component or a symlink that escapes
//!    the workspace (detected *after* canonicalization) is refused.
//! 3. `network` is `None`, or exactly `api.anthropic.com`.
//! 4. `expires` is present, parseable (RFC 3339), and **in the future**.
//! 5. No inline secret/token/credential appears in the manifest (heuristic).
//! 6. Capabilities do not *obviously* exceed the task description (heuristic).

use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

use postern_policy::{Expiry, ExpiryError};
use time::OffsetDateTime;

use crate::manifest::{Manifest, Network};

/// A capability grant: the manifest passed the Threshold Test. The paths here
/// are **canonicalized and confined** to `workspace_root`; downstream code
/// (the [`crate::fsboundary::ScopedFs`]) enforces them at open time.
#[derive(Debug, Clone)]
pub struct Grant {
    pub manifest: Manifest,
    /// Canonical workspace root; all granted paths live under it.
    pub workspace_root: PathBuf,
    /// Canonicalized, in-workspace readable roots.
    pub read_paths: Vec<PathBuf>,
    /// Canonicalized, in-workspace writable roots.
    pub write_paths: Vec<PathBuf>,
    pub network: Network,
    /// Parsed expiry instant.
    pub expires: OffsetDateTime,
}

/// Why the threshold refused. Every variant is a *reason*; a [`Refusal`]
/// carries exactly one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RefusalReason {
    #[error("workspace root does not exist or is not accessible: {0}")]
    WorkspaceUnavailable(String),

    #[error("path {declared:?} contains a `..` traversal component")]
    PathTraversal { declared: String },

    #[error("path {declared:?} could not be resolved: {io}")]
    PathUnresolvable { declared: String, io: String },

    #[error("path {declared:?} resolves to {resolved:?}, which escapes the workspace {workspace:?}")]
    PathEscapesWorkspace {
        declared: String,
        resolved: String,
        workspace: String,
    },

    #[error("network destination {got:?} is not permitted (only \"none\" or \"api.anthropic.com\")")]
    NetworkNotPermitted { got: String },

    #[error("expiry {value:?} is not a valid RFC 3339 instant: {detail}")]
    ExpiryUnparseable { value: String, detail: String },

    #[error("grant is expired: expires {expires:?} is not after now {now:?}")]
    ExpiryInPast { expires: String, now: String },

    #[error("possible inline secret in field `{field}`: {hint}")]
    InlineSecret { field: String, hint: String },

    #[error("capabilities exceed the description: {detail}")]
    CapabilityExceedsDescription { detail: String },
}

/// A refusal of the Threshold Test. Carries the [`RefusalReason`]. Its presence
/// means nothing ran.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("Yagabona refuses at the threshold: {reason}")]
pub struct Refusal {
    pub reason: RefusalReason,
}

impl Refusal {
    fn of(reason: RefusalReason) -> Refusal {
        Refusal { reason }
    }
    /// The reason for this refusal.
    pub fn reason(&self) -> &RefusalReason {
        &self.reason
    }
}

/// Run the Threshold Test against the current wall-clock time.
///
/// See [`validate_at`] for the deterministic, time-injected variant.
pub fn validate(manifest: &Manifest, workspace_root: &Path) -> Result<Grant, Refusal> {
    validate_at(manifest, workspace_root, OffsetDateTime::now_utc())
}

/// Run the Threshold Test as if "now" were `now` — deterministic for tests.
pub fn validate_at(
    manifest: &Manifest,
    workspace_root: &Path,
    now: OffsetDateTime,
) -> Result<Grant, Refusal> {
    // (0) The workspace root itself must exist so we have a canonical anchor.
    let ws = workspace_root
        .canonicalize()
        .map_err(|e| Refusal::of(RefusalReason::WorkspaceUnavailable(e.to_string())))?;

    // (5) Heuristic secret scan across every string field, before anything else.
    scan_for_secrets(manifest)?;

    // (2) Confine every declared path to the workspace.
    let read_paths = confine_all(&manifest.capabilities.read_paths, &ws)?;
    let write_paths = confine_all(&manifest.capabilities.write_paths, &ws)?;

    // (3) Network: the enum already excludes every other literal at parse time;
    // re-affirm defensively.
    let network = manifest.capabilities.network;
    match network {
        Network::None | Network::Anthropic => {}
    }

    // (4) Expiry present, parseable (RFC 3339), and strictly in the future.
    // The check itself lives in the shared consent kernel (`postern_policy`);
    // here we only translate its typed error into the Threshold's own
    // `RefusalReason`, so the public refusal surface is unchanged.
    let expiry = Expiry::checked(&manifest.task.expires, now).map_err(expiry_refusal)?;

    // (6) Capabilities must not obviously exceed the stated description.
    check_capabilities_match_description(manifest)?;

    Ok(Grant {
        manifest: manifest.clone(),
        workspace_root: ws,
        read_paths,
        write_paths,
        network,
        expires: expiry.instant(),
    })
}

/// Translate the shared consent kernel's [`ExpiryError`] into the Threshold's
/// own [`RefusalReason`], so the public refusal surface is unchanged: a missing
/// or malformed expiry becomes [`RefusalReason::ExpiryUnparseable`], a past one
/// [`RefusalReason::ExpiryInPast`].
fn expiry_refusal(err: ExpiryError) -> Refusal {
    Refusal::of(match err {
        ExpiryError::Missing => RefusalReason::ExpiryUnparseable {
            value: String::new(),
            detail: "expiry is required but was missing or empty".to_string(),
        },
        ExpiryError::Unparseable { value, detail } => {
            RefusalReason::ExpiryUnparseable { value, detail }
        }
        ExpiryError::InPast { expires, now } => RefusalReason::ExpiryInPast { expires, now },
    })
}

fn confine_all(declared: &[String], ws: &Path) -> Result<Vec<PathBuf>, Refusal> {
    declared.iter().map(|d| confine_one(d, ws)).collect()
}

/// Resolve one declared path and prove it lands inside `ws`.
fn confine_one(declared: &str, ws: &Path) -> Result<PathBuf, Refusal> {
    let raw = Path::new(declared);

    // Reject `..` lexically. Canonicalization resolves it away for the existing
    // prefix, but a `..` in the not-yet-created tail can only be caught here.
    if raw.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(Refusal::of(RefusalReason::PathTraversal {
            declared: declared.to_string(),
        }));
    }

    // Relative paths are interpreted against the workspace root; absolute paths
    // are taken as-is (they must still resolve inside the workspace).
    let joined = if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        ws.join(raw)
    };

    let resolved = resolve_partial(&joined).map_err(|e| {
        Refusal::of(RefusalReason::PathUnresolvable {
            declared: declared.to_string(),
            io: e.to_string(),
        })
    })?;

    // The load-bearing check: after resolving symlinks on the existing prefix,
    // the target must still be under the canonical workspace root.
    if !resolved.starts_with(ws) {
        return Err(Refusal::of(RefusalReason::PathEscapesWorkspace {
            declared: declared.to_string(),
            resolved: resolved.display().to_string(),
            workspace: ws.display().to_string(),
        }));
    }

    Ok(resolved)
}

/// Canonicalize as far as the path exists, then re-append the non-existent tail.
///
/// A writable target (e.g. an index directory to be created) need not exist
/// yet, but its existing ancestor is canonicalized so a symlinked prefix that
/// escapes the workspace is still caught. Assumes an absolute input (callers
/// join relative paths onto the workspace first).
fn resolve_partial(path: &Path) -> std::io::Result<PathBuf> {
    let mut tail: Vec<&OsStr> = Vec::new();
    let mut cur: &Path = path;
    loop {
        if cur.exists() {
            let mut base = cur.canonicalize()?;
            for name in tail.iter().rev() {
                base.push(name);
            }
            return Ok(base);
        }
        match (cur.parent(), cur.file_name()) {
            (Some(parent), Some(name)) => {
                tail.push(name);
                cur = parent;
            }
            // No existing ancestor: let canonicalize surface the real IO error.
            _ => return path.canonicalize(),
        }
    }
}

/// Heuristic scan for inline secrets/tokens/credentials in any string field.
///
/// This is a best-effort tripwire, not a proof of absence — it catches the
/// obvious cases (embedded API keys, PEM blocks, `password = ...`) so a
/// careless manifest is refused rather than silently trusted.
fn scan_for_secrets(m: &Manifest) -> Result<(), Refusal> {
    let read_joined = m.capabilities.read_paths.join(" ");
    let write_joined = m.capabilities.write_paths.join(" ");
    // EVERY manifest string field is scanned — the tripwire has no window.
    // (`ritual.granted_at` was once missing from this list: a credential
    // pasted there sailed past the scan because nothing else ever parses
    // that field. Keep this list in lockstep with `crate::manifest`.)
    let fields: [(&str, &str); 9] = [
        ("task.name", m.task.name.as_str()),
        ("task.description", m.task.description.as_str()),
        ("task.schedule", m.task.schedule.as_str()),
        ("ritual.granted_by", m.ritual.granted_by.as_str()),
        ("ritual.granted_at", m.ritual.granted_at.as_str()),
        ("ritual.formula", m.ritual.formula.as_str()),
        ("capabilities.read_paths", read_joined.as_str()),
        ("capabilities.write_paths", write_joined.as_str()),
        ("task.expires", m.task.expires.as_str()),
    ];
    for (field, value) in fields {
        if let Some(hint) = looks_like_secret(value) {
            return Err(Refusal::of(RefusalReason::InlineSecret {
                field: field.to_string(),
                hint: hint.to_string(),
            }));
        }
    }
    Ok(())
}

/// Return a hint if `s` looks like it embeds a credential.
fn looks_like_secret(s: &str) -> Option<&'static str> {
    let lower = s.to_ascii_lowercase();

    // Named-credential keywords.
    const KEYWORDS: &[&str] = &[
        "password",
        "passwd",
        "secret",
        "api_key",
        "apikey",
        "api-key",
        "access_key",
        "private_key",
        "client_secret",
        "bearer ",
        "authorization:",
    ];
    for kw in KEYWORDS {
        if lower.contains(kw) {
            return Some("credential-like keyword");
        }
    }

    // Common key prefixes (Anthropic/OpenAI `sk-`, GitHub `ghp_`, AWS `AKIA`).
    for token in s.split(|c: char| c.is_whitespace() || c == '"' || c == ',') {
        if token.len() >= 20 && (token.starts_with("sk-") || token.starts_with("ghp_")) {
            return Some("secret-key-shaped token");
        }
        if token.starts_with("AKIA") && token.len() >= 20 {
            return Some("AWS-access-key-shaped token");
        }
        // A long, uninterrupted hex run reads like a raw key/hash, not a path.
        if token.len() >= 40 && token.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some("long hex blob");
        }
    }

    if s.contains("-----BEGIN") {
        return Some("PEM-encoded key block");
    }

    None
}

/// Heuristic: refuse capabilities that plainly exceed what the description says
/// the task does. Conservative on purpose — it only fires when a broad
/// capability (writing files, reaching the network) has *no* supporting hint in
/// the description at all.
fn check_capabilities_match_description(m: &Manifest) -> Result<(), Refusal> {
    let desc = m.task.description.to_ascii_lowercase();

    const WRITE_HINTS: &[&str] = &[
        "index", "write", "save", "store", "update", "cache", "db", "database", "generate",
        "create", "build", "sync", "record", "log", "output", "backup", "export", "render",
    ];
    if !m.capabilities.write_paths.is_empty()
        && !WRITE_HINTS.iter().any(|w| desc.contains(w))
    {
        return Err(Refusal::of(RefusalReason::CapabilityExceedsDescription {
            detail: "write_paths declared, but the description does not describe writing anything"
                .to_string(),
        }));
    }

    const NET_HINTS: &[&str] = &[
        "anthropic", "api", "network", "cloud", "online", "sync", "upload", "download", "fetch",
        "remote", "model", "llm", "claude", "summar", "classif", "embed",
    ];
    if m.capabilities.network == Network::Anthropic
        && !NET_HINTS.iter().any(|w| desc.contains(w))
    {
        return Err(Refusal::of(RefusalReason::CapabilityExceedsDescription {
            detail: "network access to api.anthropic.com declared, but the description gives no \
                     reason to reach the network"
                .to_string(),
        }));
    }

    Ok(())
}
