//! The Izbushka task manifest — model + parse.
//!
//! The manifest is the *ritual formula*: the only door into Yagabona. It is a
//! small, strict TOML document. Anything the parser does not recognize is
//! rejected (`deny_unknown_fields`) — an overreaching manifest should never be
//! able to smuggle an undeclared field past the threshold.
//!
//! ```toml
//! [task]
//! name        = "nightly-notes-index"
//! description = "Index ~/Notes into a local search db every night"
//! schedule    = "daily 02:30"
//! expires     = "2026-12-31T23:59:59Z"
//!
//! [capabilities]
//! read_paths  = ["~/Notes"]
//! write_paths = ["~/.local/share/izbushka/index"]
//! network     = "none"           # or "api.anthropic.com" — nothing else exists
//!
//! [ritual]
//! granted_by  = "tiago"
//! granted_at  = "2026-07-11T14:02:00-03:00"
//! formula     = "izbushka-turn-your-face-to-me"
//! ```

use serde::Deserialize;

/// A parsed Izbushka manifest. Parsing proves the *shape* is well-formed; it
/// does **not** prove the request is safe — that is the job of
/// [`crate::threshold::validate`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub task: Task,
    pub capabilities: Capabilities,
    pub ritual: Ritual,
}

/// `[task]` — what runs, when, and until when.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Task {
    pub name: String,
    pub description: String,
    /// Schedule string, e.g. `"daily 02:30"`. Parsed by
    /// [`crate::scheduler::Schedule`].
    pub schedule: String,
    /// RFC 3339 expiry instant, e.g. `"2026-12-31T23:59:59Z"`. Every grant
    /// carries an expiry; the threshold rejects a missing or past one.
    pub expires: String,
}

/// `[capabilities]` — the declared reach of the task. Everything the task may
/// touch must be named here, up front.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    #[serde(default)]
    pub read_paths: Vec<String>,
    #[serde(default)]
    pub write_paths: Vec<String>,
    pub network: Network,
}

/// The only two network states that exist. Any other literal is rejected at
/// parse time — Sotto's network guarantee is that the sole permissible
/// destination is `api.anthropic.com`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// No network access at all.
    None,
    /// Exactly `api.anthropic.com`, nothing else.
    Anthropic,
}

impl Network {
    /// The wire/destination string this state authorizes.
    pub fn destination(&self) -> &'static str {
        match self {
            Network::None => "none",
            Network::Anthropic => "api.anthropic.com",
        }
    }
}

impl<'de> Deserialize<'de> for Network {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "none" => Ok(Network::None),
            "api.anthropic.com" => Ok(Network::Anthropic),
            other => Err(serde::de::Error::custom(format!(
                "network must be \"none\" or \"api.anthropic.com\", got {other:?}"
            ))),
        }
    }
}

/// `[ritual]` — the explicit consent record. Who granted the capability, when,
/// and the folkloric formula string that marks the door as opened willingly.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ritual {
    pub granted_by: String,
    pub granted_at: String,
    pub formula: String,
}

/// Errors from parsing an Izbushka manifest.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("invalid Izbushka manifest: {0}")]
    Toml(#[from] toml::de::Error),
}

impl Manifest {
    /// Parse an Izbushka manifest from TOML text.
    pub fn parse(text: &str) -> Result<Manifest, ManifestError> {
        Ok(toml::from_str(text)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
        [task]
        name        = "nightly-notes-index"
        description = "Index Notes into a local search db every night"
        schedule    = "daily 02:30"
        expires     = "2026-12-31T23:59:59Z"

        [capabilities]
        read_paths  = ["notes"]
        write_paths = ["index"]
        network     = "none"

        [ritual]
        granted_by  = "tiago"
        granted_at  = "2026-07-11T14:02:00-03:00"
        formula     = "izbushka-turn-your-face-to-me"
    "#;

    #[test]
    fn parses_a_valid_manifest() {
        let m = Manifest::parse(VALID).expect("valid manifest parses");
        assert_eq!(m.task.name, "nightly-notes-index");
        assert_eq!(m.capabilities.network, Network::None);
        assert_eq!(m.capabilities.read_paths, vec!["notes".to_string()]);
        assert_eq!(m.ritual.granted_by, "tiago");
    }

    #[test]
    fn rejects_unknown_network_literal() {
        let bad = VALID.replace(r#"network     = "none""#, r#"network     = "evil.example.com""#);
        let err = Manifest::parse(&bad).unwrap_err();
        assert!(err.to_string().contains("api.anthropic.com"), "got: {err}");
    }

    #[test]
    fn accepts_anthropic_literal() {
        let ok = VALID.replace(r#"network     = "none""#, r#"network     = "api.anthropic.com""#);
        let m = Manifest::parse(&ok).unwrap();
        assert_eq!(m.capabilities.network, Network::Anthropic);
    }

    #[test]
    fn rejects_unknown_field() {
        let bad = VALID.replace(
            r#"formula     = "izbushka-turn-your-face-to-me""#,
            "formula     = \"x\"\n        backdoor = true",
        );
        assert!(Manifest::parse(&bad).is_err());
    }

    #[test]
    fn rejects_missing_expiry_field() {
        let bad = VALID.replace(r#"expires     = "2026-12-31T23:59:59Z""#, "");
        assert!(Manifest::parse(&bad).is_err());
    }
}
