//! The policy model — the governance document, and its strict TOML parse.
//!
//! A policy is a small, strict TOML document. Every table uses
//! `#[serde(deny_unknown_fields)]`: anything the parser does not recognize is
//! rejected, so an overreaching policy can never smuggle an undeclared construct
//! past the gate.
//!
//! The pieces:
//!
//! - **`edition`** — [`Edition::Personal`] or [`Edition::Business`]. Checked
//!   *first* by the [edition gate](crate::edition); each edition forbids the
//!   other's constructs, fail-closed.
//! - **`[[layers]]`** — the *wheels within wheels*. Each layer names its
//!   `parent` (except the root) and a `level`. A child may never *widen* itself
//!   past its parent (see [`crate::lattice`]).
//! - **`[[subjects]]`** — each subject maps to **exactly one layer per
//!   context** (a duplicated context is rejected).
//! - **`[[resources]]`** — classified into a layer, optionally into a `tenant`
//!   (its firmament) and a `dataset` (its Chinese-wall conflict member).
//! - **`[[walls]]`** — Brewer-Nash Chinese walls (business only). A wall has
//!   **no bypass**: a `bypass = true` is rejected at validation.
//! - **`[[grants]]`** — each grant **must** carry an `expires`; a missing
//!   `expires` fails to parse.
//! - **`[[tenants]]`** — firmaments (business only).
//!
//! ```toml
//! edition = "business"
//!
//! [[tenants]]
//! name = "acme"
//!
//! [[layers]]
//! name  = "root"
//! level = 3
//!
//! [[layers]]
//! name   = "internal"
//! parent = "root"
//! level  = 2
//!
//! [[subjects]]
//! name   = "alice"
//! tenant = "acme"
//! role   = "finance-analyst"
//! assignments = [{ context = "default", layer = "internal" }]
//!
//! [[resources]]
//! id      = "acme/ledger"
//! layer   = "internal"
//! tenant  = "acme"
//! dataset = "bank-a"
//!
//! [[grants]]
//! subject = "alice"
//! resource = "acme/ledger"
//! action  = "read"
//! expires = "2027-01-01T00:00:00Z"
//! ```

use serde::Deserialize;

use crate::eval::Action;
use crate::lattice::Lattice;
use crate::{edition, firmament, walls};

/// Which edition a policy is written for. The [edition gate](crate::edition)
/// checks this **first** and refuses any out-of-edition construct, fail-closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Edition {
    /// Parental control only: a single household, `parent -> child` levels, no
    /// Chinese walls, no tenants, no corporate roles, no spying (inverted
    /// control is refused).
    Personal,
    /// The full lattice: multi-level no-read-up/no-write-down, Brewer-Nash
    /// Chinese walls, and firmament-grade tenant isolation.
    Business,
}

/// A parsed governance policy. Parsing proves the *shape*; [`Policy::validate`]
/// proves it is admissible for its edition and internally consistent.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub edition: Edition,
    #[serde(default)]
    pub tenants: Vec<Tenant>,
    pub layers: Vec<Layer>,
    #[serde(default)]
    pub subjects: Vec<Subject>,
    #[serde(default)]
    pub resources: Vec<Resource>,
    #[serde(default)]
    pub walls: Vec<walls::Wall>,
    #[serde(default)]
    pub grants: Vec<Grant>,
}

/// A firmament: an isolation domain. No resource id/index, and no derived
/// signal, crosses between tenants (see [`crate::firmament`]).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tenant {
    pub name: String,
}

/// One *wheel*: a nested access layer. The root names no `parent`; every other
/// layer names exactly one. `level` is the sensitivity/clearance tier (higher =
/// more privileged / more sensitive).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Layer {
    pub name: String,
    #[serde(default)]
    pub parent: Option<String>,
    pub level: u32,
}

/// A governed principal. It maps to **exactly one layer per context**; a
/// duplicated context is rejected by [`Policy::validate`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Subject {
    pub name: String,
    /// The subject's firmament (business). `None` in personal.
    #[serde(default)]
    pub tenant: Option<String>,
    /// A corporate role (business). Refused outright in personal.
    #[serde(default)]
    pub role: Option<String>,
    pub assignments: Vec<Assignment>,
}

/// A single `context -> layer` mapping for a subject.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assignment {
    pub context: String,
    pub layer: String,
}

impl Subject {
    /// The layer this subject occupies in `context`, if any.
    pub fn layer_for(&self, context: &str) -> Option<&str> {
        self.assignments
            .iter()
            .find(|a| a.context == context)
            .map(|a| a.layer.as_str())
    }
}

/// A governed object, classified into a `layer`, and optionally into a `tenant`
/// (its firmament) and a `dataset` (its Chinese-wall conflict member).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    pub id: String,
    pub layer: String,
    #[serde(default)]
    pub tenant: Option<String>,
    #[serde(default)]
    pub dataset: Option<String>,
}

/// An explicit, expiring authorization. **Every** grant carries an `expires`;
/// a missing one fails to parse (see [`Policy::parse`]).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub subject: String,
    pub resource: String,
    /// What the grant authorizes. Defaults to [`Action::Read`].
    #[serde(default)]
    pub action: Action,
    /// RFC 3339 expiry instant. **Required** — the field's absence is a parse
    /// error, which is exactly the fail-closed "no grant without expiry" rule.
    pub expires: String,
}

/// Errors from parsing or validating a policy. Every variant is a *reason a
/// policy is refused*; the engine never proceeds on one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("invalid policy TOML: {0}")]
    Toml(String),

    // --- edition gate ---
    #[error("edition {edition:?} forbids this construct: {construct}")]
    OutOfEdition { edition: Edition, construct: String },

    // --- lattice (wheels within wheels) ---
    #[error("layer {layer:?} names an unknown parent {parent:?}")]
    UnknownLayerParent { layer: String, parent: String },
    #[error("layer parent chain forms a cycle at {layer:?}")]
    LayerCycle { layer: String },
    #[error("child layer {child:?} (level {child_level}) widens beyond its parent {parent:?} (level {parent_level}): no layer widens itself")]
    ChildWidensParent {
        child: String,
        child_level: u32,
        parent: String,
        parent_level: u32,
    },

    // --- subjects ---
    #[error("subject {subject:?} maps to more than one layer in context {context:?}")]
    SubjectMultipleLayers { subject: String, context: String },
    #[error("{referent} {name:?} references unknown layer {layer:?}")]
    UnknownLayerRef {
        referent: String,
        name: String,
        layer: String,
    },

    // --- walls ---
    #[error("Chinese wall {wall:?} declares a bypass: a wall has no bypass")]
    WallHasBypass { wall: String },
    #[error("Chinese wall {wall:?} conflict class {class:?} is empty")]
    EmptyConflictClass { wall: String, class: String },

    // --- firmament ---
    #[error("firmament breach: resource id {resource:?} is shared across tenants {tenant_a:?} and {tenant_b:?}")]
    FirmamentBreach {
        resource: String,
        tenant_a: String,
        tenant_b: String,
    },
    #[error("duplicate resource id {resource:?}")]
    DuplicateResource { resource: String },
    #[error("{referent} {name:?} references unknown tenant {tenant:?}")]
    UnknownTenantRef {
        referent: String,
        name: String,
        tenant: String,
    },

    // --- grants ---
    #[error("grant references unknown subject {subject:?}")]
    UnknownGrantSubject { subject: String },
    #[error("grant references unknown resource {resource:?}")]
    UnknownGrantResource { resource: String },
    #[error("grant expiry {value:?} is not a valid RFC 3339 instant: {detail}")]
    GrantExpiryUnparseable { value: String, detail: String },
    #[error("inverted control: subject {subject:?} in layer {subject_layer:?} is granted {resource:?} classified above it in layer {resource_layer:?} — personal control must flow parent -> child")]
    InvertedControl {
        subject: String,
        subject_layer: String,
        resource: String,
        resource_layer: String,
    },
}

impl Policy {
    /// Parse a policy from TOML text. Structural rules are enforced here:
    /// unknown fields are rejected, and a grant missing its `expires` fails to
    /// parse. It does **not** yet prove the policy is admissible — call
    /// [`Policy::validate`].
    pub fn parse(text: &str) -> Result<Policy, PolicyError> {
        toml::from_str(text).map_err(|e| PolicyError::Toml(e.to_string()))
    }

    /// Validate the policy, fail-closed. The [edition gate](crate::edition) runs
    /// **first**; then the lattice (no widening), the walls (no bypass), the
    /// subjects (one layer per context, layer resolves), the resources (layer
    /// resolves), the firmament (no shared resource), and the grants
    /// (references resolve; personal control is not inverted).
    ///
    /// Returns the built [`Lattice`] on success so callers need not rebuild it.
    pub fn validate(&self) -> Result<Lattice, PolicyError> {
        // (1) Edition gate FIRST — refuse any out-of-edition construct.
        edition::enforce(self)?;

        // (2) The lattice: parents resolve, no cycles, no child widens itself.
        let lattice = Lattice::build(&self.layers)?;
        lattice.validate_no_widening(&self.layers)?;

        // (3) Walls: no bypass, no empty conflict class.
        walls::validate(&self.walls)?;

        // (4) Subjects: exactly one layer per context; layers exist.
        self.validate_subjects(&lattice)?;

        // (4b) Resources: every resource's classifying layer must exist. Left
        // unchecked, a typo'd/unknown `layer` would sail through validation and
        // reach the evaluator, whose lattice lookup would otherwise have to
        // guess a level for it — silently fail-OPEN territory. `eval::decide`
        // now also refuses defensively if this is ever bypassed, but the
        // policy itself must never be allowed to admit the typo in the first
        // place (fail-closed at the gate, not just at the point of use).
        self.validate_resource_layers(&lattice)?;

        // (5) Firmament: no resource id/index shared across tenants.
        firmament::validate(self)?;

        // (6) Grants: references resolve; expiry parses; personal control is
        //     parent -> child (not inverted).
        self.validate_grants(&lattice)?;

        Ok(lattice)
    }

    fn validate_subjects(&self, lattice: &Lattice) -> Result<(), PolicyError> {
        for s in &self.subjects {
            let mut seen: Vec<&str> = Vec::new();
            for a in &s.assignments {
                if seen.contains(&a.context.as_str()) {
                    return Err(PolicyError::SubjectMultipleLayers {
                        subject: s.name.clone(),
                        context: a.context.clone(),
                    });
                }
                seen.push(&a.context);
                if lattice.level(&a.layer).is_none() {
                    return Err(PolicyError::UnknownLayerRef {
                        referent: "subject".into(),
                        name: s.name.clone(),
                        layer: a.layer.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Every resource's classifying `layer` must resolve in the lattice. This
    /// mirrors [`Policy::validate_subjects`]'s check on subject assignments —
    /// a resource is just as capable of naming a stale/typo'd layer, and the
    /// consequence of admitting one is worse: the evaluator's Bell-LaPadula
    /// comparison needs *some* level for the resource, and a silently missing
    /// one must never be allowed to reach that point.
    fn validate_resource_layers(&self, lattice: &Lattice) -> Result<(), PolicyError> {
        for r in &self.resources {
            if lattice.level(&r.layer).is_none() {
                return Err(PolicyError::UnknownLayerRef {
                    referent: "resource".into(),
                    name: r.id.clone(),
                    layer: r.layer.clone(),
                });
            }
        }
        Ok(())
    }

    fn validate_grants(&self, lattice: &Lattice) -> Result<(), PolicyError> {
        use time::format_description::well_known::Rfc3339;
        use time::OffsetDateTime;

        for g in &self.grants {
            let subject = self
                .subjects
                .iter()
                .find(|s| s.name == g.subject)
                .ok_or_else(|| PolicyError::UnknownGrantSubject {
                    subject: g.subject.clone(),
                })?;
            let resource = self
                .resources
                .iter()
                .find(|r| r.id == g.resource)
                .ok_or_else(|| PolicyError::UnknownGrantResource {
                    resource: g.resource.clone(),
                })?;

            OffsetDateTime::parse(&g.expires, &Rfc3339).map_err(|e| {
                PolicyError::GrantExpiryUnparseable {
                    value: g.expires.clone(),
                    detail: e.to_string(),
                }
            })?;

            // Personal: control must flow parent -> child. If the subject sits
            // *below* the resource's layer in the wheel tree, the grant would
            // let a child reach up to a parent — inverted control / spying.
            if self.edition == Edition::Personal {
                // Use the subject's layer in whatever context it is assigned;
                // personal subjects carry a single context in practice, so we
                // check every assignment.
                for a in &subject.assignments {
                    if lattice.is_strict_ancestor(&resource.layer, &a.layer) {
                        return Err(PolicyError::InvertedControl {
                            subject: subject.name.clone(),
                            subject_layer: a.layer.clone(),
                            resource: resource.id.clone(),
                            resource_layer: resource.layer.clone(),
                        });
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"
edition = "business"

[[tenants]]
name = "acme"

[[layers]]
name  = "root"
level = 3

[[layers]]
name   = "internal"
parent = "root"
level  = 2

[[subjects]]
name   = "alice"
tenant = "acme"
assignments = [{ context = "default", layer = "root" }]

[[resources]]
id      = "acme/ledger"
layer   = "internal"
tenant  = "acme"

[[grants]]
subject  = "alice"
resource = "acme/ledger"
action   = "read"
expires  = "2027-01-01T00:00:00Z"
"#;

    #[test]
    fn valid_policy_still_validates() {
        let p = Policy::parse(BASE).expect("parses");
        assert!(p.validate().is_ok());
    }

    // A resource naming a layer that was never declared (a policy typo) must
    // be REFUSED at validation, not silently admitted. Before this fix,
    // nothing checked `Resource.layer` against the lattice at all — only
    // subject assignments were checked — so this policy validated
    // successfully and the typo'd resource reached the evaluator, where the
    // lattice lookup used to default the unresolvable layer to level 0
    // (`Lattice::level(..).unwrap_or(0)`), which Bell-LaPadula's
    // `subject_level >= resource_level` satisfies unconditionally: any
    // subject, any clearance, could read it (fail-OPEN by omission).
    #[test]
    fn reject_resource_with_unknown_layer() {
        let bad = BASE.replace(
            "id      = \"acme/ledger\"\nlayer   = \"internal\"",
            "id      = \"acme/ledger\"\nlayer   = \"no-such-layer\"",
        );
        let policy = Policy::parse(&bad).expect("parses (shape is still valid TOML)");
        let err = policy.validate().unwrap_err();
        assert!(
            matches!(
                err,
                PolicyError::UnknownLayerRef { ref referent, .. } if referent == "resource"
            ),
            "expected UnknownLayerRef{{referent: \"resource\", ..}}, got {err:?}"
        );
    }
}
