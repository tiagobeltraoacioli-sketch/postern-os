//! The **spirit in the wheels** — per-access, fail-closed evaluation.
//!
//! > "…the spirit of the living creature was in the wheels." — Ezekiel 1:20
//!
//! Every access is judged **on its own**, against the policy, at the moment it
//! is requested. There is **no cross-firmament cache**: one tenant's decision
//! never speeds up or leaks into another's. The default is **deny** — where the
//! policy is silent, the answer is no ([`Decision::Deny`]).
//!
//! The [`Engine`] owns the validated policy, the built lattice, the Brewer-Nash
//! access history, and the [rims-full-of-eyes trail](crate::trail). On
//! construction it validates the policy (fail-closed: an inadmissible policy
//! yields no engine) and writes a genesis entry recording the policy's hash.
//! Every subsequent [`Engine::evaluate`] appends its outcome to the trail.
//!
//! An access is allowed only when **all** hold; any gap is a denial:
//!
//! 1. the subject exists and occupies a layer in the requested context;
//! 2. the resource exists;
//! 3. subject and resource are in the **same firmament** (business);
//! 4. no Chinese wall stands (business, Brewer-Nash);
//! 5. the lattice permits it — no-read-up / no-write-down (business), or
//!    non-inverted `parent -> child` control (personal);
//! 6. an **unexpired grant** authorizes the subject for the resource and action.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use postern_policy::Expiry;
use serde::Deserialize;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// The one fail-closed decision type, from the shared consent kernel. Ezekiel 1
/// previously defined its own byte-identical `Decision` (`Allow` / `Deny {
/// reason }`, default deny); it now consumes [`postern_policy::Decision`] so it
/// and yagabona can never drift into two different "silence = deny" rules.
/// Re-exported here (and via the crate root) so existing `ezekiel1::Decision`
/// and `crate::eval::Decision` paths keep resolving.
pub use postern_policy::Decision;

use crate::lattice::Lattice;
use crate::policy::{Edition, Policy, PolicyError};
use crate::trail::{ChainError, Record, Trail};
use crate::{firmament, walls};

/// What an access (or a grant) is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    /// Read the resource. Governed by *no read up*.
    Read,
    /// Write the resource. Governed by *no write down*.
    Write,
    /// A grant scope covering both read and write. Not a request action.
    ReadWrite,
}

impl Default for Action {
    fn default() -> Self {
        Action::Read
    }
}

impl Action {
    fn as_str(self) -> &'static str {
        match self {
            Action::Read => "read",
            Action::Write => "write",
            Action::ReadWrite => "read-write",
        }
    }
    /// Does a grant for `self` cover a request for `requested`?
    fn covers(self, requested: Action) -> bool {
        match (self, requested) {
            (Action::ReadWrite, Action::Read | Action::Write) => true,
            (g, r) => g == r,
        }
    }
}

/// Errors constructing or driving an [`Engine`].
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("policy is inadmissible: {0}")]
    Policy(#[from] PolicyError),
    #[error("audit trail error: {0}")]
    Trail(#[from] ChainError),
    #[error(
        "refusing to lower {requested:?}: a lower must name exactly ONE declared wall — a blank \
         or wildcard scope would be an unscoped, global disable of every Chinese wall (fail closed)"
    )]
    UnscopedWallLower { requested: String },
    #[error(
        "refusing to lower unknown wall {wall:?}: it names no wall declared in this policy, so \
         nothing would actually be lowered — recording it as a deliberate owner act would \
         overstate the audit trail (fail closed)"
    )]
    UnknownWall { wall: String },
    #[error(
        "refusing to lower wall {wall:?} without a non-empty owner and reason: lowering is a \
         deliberate, attributable owner act, never an anonymous or unexplained one (fail closed)"
    )]
    UnattributedWallLower { wall: String },
}

/// The governance engine: a validated policy plus its live evaluation state.
#[derive(Debug)]
pub struct Engine {
    policy: Policy,
    lattice: Lattice,
    /// Brewer-Nash history: subject -> datasets it has accessed.
    history: BTreeMap<String, BTreeSet<String>>,
    /// Walls the owner has explicitly lowered at runtime (by name).
    lowered_walls: BTreeSet<String>,
    /// The rims-full-of-eyes audit trail. `Some` for a file-backed engine
    /// ([`Engine::new`]); `None` for an ephemeral, filesystem-free engine
    /// ([`Engine::new_ephemeral`]) used where there is no writable filesystem
    /// (the WASM/browser build). The **decision** is identical either way — the
    /// trail only *records* outcomes, it never changes them.
    trail: Option<Trail>,
}

impl Engine {
    /// Build an engine over `policy`, writing its trail to `trail_path`.
    /// Fails closed: an inadmissible policy yields **no** engine. On success a
    /// genesis entry recording the policy hash anchors the trail.
    pub fn new(policy: Policy, trail_path: impl AsRef<Path>) -> Result<Engine, EngineError> {
        let lattice = policy.validate()?;
        let mut trail = Trail::open(trail_path)?;
        trail.append(Record {
            ts: now_rfc3339(OffsetDateTime::now_utc()),
            actor: "engine".into(),
            event: "policy-loaded".into(),
            subject: "-".into(),
            resource: "-".into(),
            decision: "n/a".into(),
            reason: format!("genesis; policy hash {}", policy_hash(&policy)),
        })?;
        Ok(Engine {
            policy,
            lattice,
            history: BTreeMap::new(),
            lowered_walls: BTreeSet::new(),
            trail: Some(trail),
        })
    }

    /// Build a trail-less engine over `policy` — same validation, same
    /// fail-closed decision pipeline, but **no** file-backed audit trail. This
    /// exists for targets with no writable filesystem (the WASM/browser build):
    /// there, [`Trail::open`] cannot create a file, so the engine records no
    /// trail. Every [`Engine::evaluate`]/[`Engine::evaluate_at`] returns the
    /// *identical* [`Decision`] it would with a trail — this is exactly the
    /// property the WASM↔native parity harness proves.
    ///
    /// Fails closed: an inadmissible policy still yields **no** engine.
    pub fn new_ephemeral(policy: Policy) -> Result<Engine, EngineError> {
        let lattice = policy.validate()?;
        Ok(Engine {
            policy,
            lattice,
            history: BTreeMap::new(),
            lowered_walls: BTreeSet::new(),
            trail: None,
        })
    }

    /// The validated policy.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Evaluate an access against wall-clock now. See [`Engine::evaluate_at`].
    pub fn evaluate(
        &mut self,
        subject: &str,
        resource: &str,
        context: &str,
        action: Action,
    ) -> Result<Decision, EngineError> {
        self.evaluate_at(subject, resource, context, action, OffsetDateTime::now_utc())
    }

    /// Evaluate an access as if "now" were `now` — deterministic for tests.
    /// Records the outcome to the trail either way and, on an allow, records the
    /// touched dataset into the Brewer-Nash history.
    pub fn evaluate_at(
        &mut self,
        subject: &str,
        resource: &str,
        context: &str,
        action: Action,
        now: OffsetDateTime,
    ) -> Result<Decision, EngineError> {
        let (decision, touched_dataset) = self.decide(subject, resource, context, action, now);

        let (dstr, reason) = match &decision {
            Decision::Allow => ("allow", "-".to_string()),
            Decision::Deny { reason } => ("deny", reason.clone()),
        };
        if let Some(trail) = &mut self.trail {
            trail.append(Record {
                ts: now_rfc3339(now),
                actor: subject.to_string(),
                event: if decision.is_allow() { "allow" } else { "deny" }.into(),
                subject: subject.to_string(),
                resource: resource.to_string(),
                decision: dstr.into(),
                reason,
            })?;
        }

        // Record the dataset touch only after a successful allow (so a denied
        // access never poisons the history).
        if decision.is_allow() {
            if let Some(ds) = touched_dataset {
                self.history.entry(subject.to_string()).or_default().insert(ds);
            }
        }

        Ok(decision)
    }

    /// Lower a live Chinese wall. This is the only way past a wall, and it is a
    /// deliberate owner act: it requires a non-empty `reason` and is recorded to
    /// the trail. It never appears in a policy (a config `bypass` is refused).
    ///
    /// Fail-closed scoping (no global disable):
    ///
    /// - `wall` must name exactly **one** wall declared in this policy. A
    ///   blank or wildcard (`""`, `"*"`) "scope" is refused — it would be an
    ///   unscoped, tenant-less collapse of every wall at once, which is never
    ///   a single deliberate act ([`EngineError::UnscopedWallLower`]).
    /// - A name that matches no declared wall is refused rather than silently
    ///   accepted: nothing would actually be lowered, and recording a
    ///   `wall-lowered` trail entry for it would overstate the audit
    ///   ([`EngineError::UnknownWall`]).
    /// - `owner` and `reason` must be non-blank — lowering is attributable
    ///   and explained, or it does not happen
    ///   ([`EngineError::UnattributedWallLower`]).
    ///
    /// Nothing is inserted and nothing is written to the trail unless every
    /// check passes.
    pub fn lower_wall(
        &mut self,
        wall: &str,
        owner: &str,
        reason: &str,
    ) -> Result<(), EngineError> {
        let wall = wall.trim();
        if wall.is_empty() || wall == "*" {
            return Err(EngineError::UnscopedWallLower { requested: wall.to_string() });
        }
        if !self.policy.walls.iter().any(|w| w.name == wall) {
            return Err(EngineError::UnknownWall { wall: wall.to_string() });
        }
        if owner.trim().is_empty() || reason.trim().is_empty() {
            return Err(EngineError::UnattributedWallLower { wall: wall.to_string() });
        }
        self.lowered_walls.insert(wall.to_string());
        if let Some(trail) = &mut self.trail {
            trail.append(Record {
                ts: now_rfc3339(OffsetDateTime::now_utc()),
                actor: owner.to_string(),
                event: "wall-lowered".into(),
                subject: "-".into(),
                resource: wall.to_string(),
                decision: "n/a".into(),
                reason: reason.to_string(),
            })?;
        }
        Ok(())
    }

    /// The core decision. Returns the [`Decision`] plus, on an allow, the
    /// dataset that was touched (to fold into Brewer-Nash history).
    fn decide(
        &self,
        subject: &str,
        resource: &str,
        context: &str,
        action: Action,
        now: OffsetDateTime,
    ) -> (Decision, Option<String>) {
        let deny = |reason: String| (Decision::Deny { reason }, None);

        // (1) Subject exists and occupies a layer in this context.
        let subj = match self.policy.subjects.iter().find(|s| s.name == subject) {
            Some(s) => s,
            None => return deny(format!("unknown subject {subject:?} (policy is silent)")),
        };
        let subj_layer = match subj.layer_for(context) {
            Some(l) => l,
            None => {
                return deny(format!(
                    "subject {subject:?} has no layer in context {context:?} (policy is silent)"
                ))
            }
        };

        // (2) Resource exists.
        let res = match self.policy.resources.iter().find(|r| r.id == resource) {
            Some(r) => r,
            None => return deny(format!("unknown resource {resource:?} (policy is silent)")),
        };

        // (3) Firmament: same tenant (business). Personal has no tenants.
        if self.policy.edition == Edition::Business
            && !firmament::same_firmament(subj.tenant.as_deref(), res.tenant.as_deref())
        {
            return deny(format!(
                "firmament isolation: subject {:?} (tenant {:?}) may not reach resource {:?} (tenant {:?})",
                subject,
                subj.tenant.as_deref().unwrap_or("-"),
                resource,
                res.tenant.as_deref().unwrap_or("-"),
            ));
        }

        // (4) Chinese walls (business, Brewer-Nash), unless lowered.
        if self.policy.edition == Edition::Business {
            if let Some(ds) = &res.dataset {
                let active: Vec<walls::Wall> = self
                    .policy
                    .walls
                    .iter()
                    .filter(|w| !self.lowered_walls.contains(&w.name))
                    .cloned()
                    .collect();
                let empty = BTreeSet::new();
                let hist = self.history.get(subject).unwrap_or(&empty);
                if let Decision::Deny { reason } = walls::may_access(&active, hist, ds) {
                    return deny(reason);
                }
            }
        }

        // (5) Lattice. Both lookups are proven to resolve by policy validation
        // (`Policy::validate_subjects` for the subject's layer,
        // `Policy::validate_resource_layers` for the resource's), but this is
        // the single per-access decision point, so it does not trust that
        // invariant blindly: an unresolved layer denies outright rather than
        // defaulting to a level. A default here would fail OPEN — the old
        // `unwrap_or(u32::MAX)` handed an unresolvable subject the *highest*
        // clearance (always satisfies no-read-up), and `unwrap_or(0)` handed
        // an unresolvable resource the *lowest* classification (same effect:
        // any subject clears no-read-up against it). Neither default is safe;
        // deny is.
        let subj_level = match self.lattice.level(subj_layer) {
            Some(l) => l,
            None => {
                return deny(format!(
                    "subject {subject:?} layer {subj_layer:?} does not resolve in the lattice (fail-closed)"
                ))
            }
        };
        let res_level = match self.lattice.level(&res.layer) {
            Some(l) => l,
            None => {
                return deny(format!(
                    "resource {resource:?} layer {:?} does not resolve in the lattice (fail-closed)",
                    res.layer
                ))
            }
        };
        match self.policy.edition {
            Edition::Business => {
                let ok = match action {
                    Action::Read => Lattice::may_read(subj_level, res_level),
                    Action::Write => Lattice::may_write(subj_level, res_level),
                    Action::ReadWrite => {
                        Lattice::may_read(subj_level, res_level)
                            && Lattice::may_write(subj_level, res_level)
                    }
                };
                if !ok {
                    return deny(format!(
                        "lattice: {} at level {subj_level} may not {} resource at level {res_level}",
                        subject,
                        action.as_str(),
                    ));
                }
            }
            Edition::Personal => {
                // Control flows parent -> child: the resource's layer must not
                // be a strict ancestor of the subject's layer (no reaching up).
                if self.lattice.is_strict_ancestor(&res.layer, subj_layer) {
                    return deny(format!(
                        "inverted control: subject {subject:?} in layer {subj_layer:?} may not reach up to resource {resource:?} in layer {:?}",
                        res.layer,
                    ));
                }
            }
        }

        // (6) An unexpired grant must authorize this subject/resource/action.
        let granted = self.policy.grants.iter().any(|g| {
            g.subject == subject
                && g.resource == resource
                && g.action.covers(action)
                && grant_live(&g.expires, now)
        });
        if !granted {
            return deny(format!(
                "no unexpired grant authorizes {subject:?} to {} {resource:?} (fail-closed)",
                action.as_str()
            ));
        }

        (Decision::Allow, res.dataset.clone())
    }
}

/// Is this grant still live (present, RFC-3339, strictly after `now`)? The
/// check itself is the shared consent kernel's [`Expiry`]; fail-closed
/// semantics are preserved — a missing or unparseable expiry is treated as
/// expired (`false`), never as a live grant.
fn grant_live(expires: &str, now: OffsetDateTime) -> bool {
    Expiry::parse(expires).is_ok_and(|e| !e.is_expired(now))
}

fn now_rfc3339(now: OffsetDateTime) -> String {
    now.format(&Rfc3339).unwrap_or_else(|_| now.to_string())
}

/// A SHAKE-256 digest of the policy's canonical TOML, for the genesis entry.
fn policy_hash(policy: &Policy) -> String {
    let toml = toml_of(policy);
    let mut hasher = Shake256::default();
    hasher.update(toml.as_bytes());
    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; 32];
    reader.read(&mut out);
    let mut s = String::with_capacity(64);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for b in out {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Best-effort canonicalization of the policy for hashing. Uses serde_json's
/// stable value ordering rather than TOML round-tripping (Policy is Deserialize
/// only), which is sufficient for a content fingerprint.
fn toml_of(policy: &Policy) -> String {
    // We derive a stable fingerprint from the debug form; it is deterministic
    // for a given in-memory policy and only used to anchor the genesis entry.
    format!("{policy:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Assignment, Layer, Resource, Subject};

    // A minimal, already-validated two-layer lattice: root(3) -> inner(2).
    fn lattice() -> Lattice {
        Lattice::build(&[
            Layer { name: "root".into(), parent: None, level: 3 },
            Layer { name: "inner".into(), parent: Some("root".into()), level: 2 },
        ])
        .unwrap()
    }

    fn engine_with(policy: Policy) -> Engine {
        let lattice = lattice();
        Engine {
            policy,
            lattice,
            history: BTreeMap::new(),
            lowered_walls: BTreeSet::new(),
            trail: None,
        }
    }

    // Defense-in-depth: even if a resource somehow reaches `decide()` naming a
    // layer absent from the lattice (the case `Policy::validate_resource_layers`
    // now refuses at the gate — this test proves the evaluator does not ALSO
    // need that gate to fail closed). Before this fix, the lattice lookup
    // defaulted an unresolvable resource to level 0 (`unwrap_or(0)`), which
    // Bell-LaPadula's `subject_level >= resource_level` satisfies for *every*
    // subject — a silent, unconditional read-allow. It must deny instead.
    #[test]
    fn unresolved_resource_layer_denies_rather_than_defaulting_to_level_zero() {
        let policy = Policy {
            edition: Edition::Business,
            tenants: vec![],
            layers: vec![
                Layer { name: "root".into(), parent: None, level: 3 },
                Layer { name: "inner".into(), parent: Some("root".into()), level: 2 },
            ],
            subjects: vec![Subject {
                name: "alice".into(),
                tenant: None,
                role: None,
                assignments: vec![Assignment { context: "default".into(), layer: "inner".into() }],
            }],
            resources: vec![Resource {
                id: "typo/resource".into(),
                layer: "no-such-layer".into(), // never declared — a policy typo
                tenant: None,
                dataset: None,
            }],
            walls: vec![],
            grants: vec![],
        };
        let engine = engine_with(policy);
        let (decision, touched) =
            engine.decide("alice", "typo/resource", "default", Action::Read, OffsetDateTime::now_utc());
        assert!(
            matches!(decision, Decision::Deny { .. }),
            "an unresolvable resource layer must deny, not default to level 0, got {decision:?}"
        );
        assert!(touched.is_none());
    }

    // Regression (wall-lowering scope): `lower_wall` used to accept ANY string
    // — blank, "*", or a name matching no declared wall — inserting it and
    // recording a deliberate-sounding "wall-lowered" trail entry while either
    // (a) silently doing nothing (audit overstate) or (b) standing by as an
    // unscoped global-disable convention. It must fail closed instead.
    #[test]
    fn lower_wall_refuses_blank_wildcard_unknown_and_unattributed() {
        let policy = Policy {
            edition: Edition::Business,
            tenants: vec![],
            layers: vec![
                Layer { name: "root".into(), parent: None, level: 3 },
                Layer { name: "inner".into(), parent: Some("root".into()), level: 2 },
            ],
            subjects: vec![],
            resources: vec![],
            walls: vec![crate::walls::Wall {
                name: "banking-coi".into(),
                classes: vec![crate::walls::ConflictClass {
                    name: "banks".into(),
                    members: vec!["bank-a".into(), "bank-b".into()],
                }],
                bypass: false,
            }],
            grants: vec![],
        };
        let mut engine = engine_with(policy);

        // Unscoped (global) lowers are refused.
        assert!(matches!(
            engine.lower_wall("", "owner", "reason"),
            Err(EngineError::UnscopedWallLower { .. })
        ));
        assert!(matches!(
            engine.lower_wall("*", "owner", "reason"),
            Err(EngineError::UnscopedWallLower { .. })
        ));
        // A wall that is not declared in the policy is refused, not recorded.
        assert!(matches!(
            engine.lower_wall("no-such-wall", "owner", "reason"),
            Err(EngineError::UnknownWall { .. })
        ));
        // Anonymous or unexplained lowering is refused (the doc always said
        // a non-empty reason is required; now it is enforced).
        assert!(matches!(
            engine.lower_wall("banking-coi", "", "reason"),
            Err(EngineError::UnattributedWallLower { .. })
        ));
        assert!(matches!(
            engine.lower_wall("banking-coi", "owner", "   "),
            Err(EngineError::UnattributedWallLower { .. })
        ));
        // Every refusal above must have lowered NOTHING.
        assert!(engine.lowered_walls.is_empty(), "refused lowers must not touch state");

        // A properly scoped, attributed, explained lower still works.
        engine
            .lower_wall("banking-coi", "owner-tiago", "audit engagement: dual review approved")
            .unwrap();
        assert!(engine.lowered_walls.contains("banking-coi"));
    }

    // Same defense-in-depth, the write side: an unresolvable SUBJECT layer must
    // not default to `u32::MAX` (the old fallback), which would satisfy
    // Bell-LaPadula's read check unconditionally and starve only writes rather
    // than failing closed outright.
    #[test]
    fn unresolved_subject_layer_denies_rather_than_defaulting_to_max() {
        let policy = Policy {
            edition: Edition::Business,
            tenants: vec![],
            layers: vec![
                Layer { name: "root".into(), parent: None, level: 3 },
                Layer { name: "inner".into(), parent: Some("root".into()), level: 2 },
            ],
            subjects: vec![Subject {
                name: "mallory".into(),
                tenant: None,
                role: None,
                assignments: vec![Assignment { context: "default".into(), layer: "ghost-layer".into() }],
            }],
            resources: vec![Resource {
                id: "acme/ledger".into(),
                layer: "inner".into(),
                tenant: None,
                dataset: None,
            }],
            walls: vec![],
            grants: vec![],
        };
        let engine = engine_with(policy);
        let (decision, _) =
            engine.decide("mallory", "acme/ledger", "default", Action::Read, OffsetDateTime::now_utc());
        assert!(
            matches!(decision, Decision::Deny { .. }),
            "an unresolvable subject layer must deny, not default to u32::MAX, got {decision:?}"
        );
    }
}
