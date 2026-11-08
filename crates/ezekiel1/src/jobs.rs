//! Scheduled-job manifests — **Ezekiel declares, Yagabona runs**.
//!
//! Ezekiel does not schedule or execute anything itself. Instead it *emits*
//! Izbushka task manifests — the exact strict TOML schema that
//! `yagabona::manifest::Manifest` parses (`[task]` / `[capabilities]` /
//! `[ritual]`, `network = "none"`, every grant carrying an `expires`). Yagabona
//! then runs them under its own Threshold Test, on the owner's machine, with
//! zero telemetry.
//!
//! Two jobs are emitted:
//!
//! - **expiry sweep** — periodically re-reads the policy and flags grants whose
//!   `expires` has passed, so nothing lingers past its lease.
//! - **wall audit** — periodically re-verifies the Chinese-wall access history
//!   and the [rims-full-of-eyes trail](crate::trail) hash chain.
//!
//! Both are strictly local (`network = "none"`): they read the policy and write
//! the trail, nothing more.

use serde::Serialize;

/// Inputs shared by the emitted manifests: where the policy and trail live, who
/// authorized the schedule, and when the schedule itself expires.
#[derive(Debug, Clone)]
pub struct JobConfig {
    /// Path (relative to Yagabona's workspace root) of the policy document.
    pub policy_path: String,
    /// Path (relative to the workspace root) of the audit trail JSONL.
    pub trail_path: String,
    /// Who granted the scheduled job (an owner id).
    pub granted_by: String,
    /// RFC 3339 instant the grant was made.
    pub granted_at: String,
    /// RFC 3339 instant the scheduled grant itself expires.
    pub expires: String,
}

/// A serializable mirror of the Yagabona Izbushka manifest schema. Kept local
/// (Ezekiel does not depend on the yagabona crate) but field-for-field
/// identical, so `yagabona::manifest::Manifest::parse` accepts the output.
#[derive(Debug, Clone, Serialize)]
struct Manifest {
    task: Task,
    capabilities: Capabilities,
    ritual: Ritual,
}

#[derive(Debug, Clone, Serialize)]
struct Task {
    name: String,
    description: String,
    schedule: String,
    expires: String,
}

#[derive(Debug, Clone, Serialize)]
struct Capabilities {
    read_paths: Vec<String>,
    write_paths: Vec<String>,
    /// Always `"none"`: sweeps and audits are strictly local.
    network: String,
}

#[derive(Debug, Clone, Serialize)]
struct Ritual {
    granted_by: String,
    granted_at: String,
    formula: String,
}

/// Emit the **expiry-sweep** Izbushka manifest (TOML). Runs daily; reads the
/// policy, writes findings into the trail.
pub fn expiry_sweep_manifest(cfg: &JobConfig) -> String {
    let m = Manifest {
        task: Task {
            name: "ezekiel1-expiry-sweep".into(),
            description: "Sweep the Ezekiel policy for grants whose expiry has passed and record \
                          each lapse in the audit trail."
                .into(),
            schedule: "daily 03:00".into(),
            expires: cfg.expires.clone(),
        },
        capabilities: Capabilities {
            read_paths: vec![cfg.policy_path.clone()],
            write_paths: vec![cfg.trail_path.clone()],
            network: "none".into(),
        },
        ritual: Ritual {
            granted_by: cfg.granted_by.clone(),
            granted_at: cfg.granted_at.clone(),
            formula: "izbushka-turn-your-face-to-me".into(),
        },
    };
    toml::to_string(&m).expect("manifest serializes")
}

/// Emit the **wall-audit** Izbushka manifest (TOML). Runs hourly; reads the
/// policy, re-verifies the trail's hash chain and Brewer-Nash history, and
/// records the audit result in the trail.
pub fn wall_audit_manifest(cfg: &JobConfig) -> String {
    let m = Manifest {
        task: Task {
            name: "ezekiel1-wall-audit".into(),
            description: "Audit the Ezekiel Chinese-wall access history and verify the audit \
                          trail hash chain; record the audit outcome in the trail."
                .into(),
            schedule: "hourly".into(),
            expires: cfg.expires.clone(),
        },
        capabilities: Capabilities {
            read_paths: vec![cfg.policy_path.clone()],
            write_paths: vec![cfg.trail_path.clone()],
            network: "none".into(),
        },
        ritual: Ritual {
            granted_by: cfg.granted_by.clone(),
            granted_at: cfg.granted_at.clone(),
            formula: "izbushka-turn-your-face-to-me".into(),
        },
    };
    toml::to_string(&m).expect("manifest serializes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    // A strict mirror of the Yagabona manifest schema, to prove the emitted
    // TOML parses under `deny_unknown_fields` exactly as Yagabona would parse it.
    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct YagaManifest {
        task: YagaTask,
        capabilities: YagaCaps,
        ritual: YagaRitual,
    }
    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct YagaTask {
        name: String,
        description: String,
        schedule: String,
        expires: String,
    }
    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct YagaCaps {
        #[serde(default)]
        read_paths: Vec<String>,
        #[serde(default)]
        write_paths: Vec<String>,
        network: String,
    }
    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct YagaRitual {
        granted_by: String,
        granted_at: String,
        formula: String,
    }

    fn cfg() -> JobConfig {
        JobConfig {
            policy_path: "policy/ezekiel.toml".into(),
            trail_path: "trail/ezekiel.jsonl".into(),
            granted_by: "tiago".into(),
            granted_at: "2026-07-11T14:02:00-03:00".into(),
            expires: "2027-01-01T00:00:00Z".into(),
        }
    }

    #[test]
    fn emitted_manifests_match_yagabona_schema() {
        for toml_text in [
            expiry_sweep_manifest(&cfg()),
            wall_audit_manifest(&cfg()),
        ] {
            let m: YagaManifest =
                toml::from_str(&toml_text).expect("emitted manifest parses under Yagabona schema");
            assert_eq!(m.capabilities.network, "none");
            assert!(!m.task.expires.is_empty());
            assert_eq!(m.ritual.formula, "izbushka-turn-your-face-to-me");
            let _ = (&m.task.name, &m.task.description, &m.task.schedule);
            let _ = (&m.capabilities.read_paths, &m.capabilities.write_paths);
            let _ = &m.ritual.granted_by;
            let _ = &m.ritual.granted_at;
        }
    }
}
