//! Chinese walls — the **Brewer-Nash** model (business edition).
//!
//! A wall groups *competing* datasets into conflict-of-interest (COI) classes.
//! Once a subject has touched one member of a class, every **competing** member
//! of that class is denied to them **permanently** — the wall records history
//! and never forgets. A wall has **no bypass**: a `bypass = true` in the policy
//! is refused at validation ([`validate`]). Lowering a live wall is a separate,
//! deliberate act — an explicit owner action with a recorded reason
//! (`Engine::lower_wall`), never a silent config flag.
//!
//! The decision is pure given the access history:
//! [`may_access`] takes what a subject has already touched plus the target
//! dataset and returns [`Decision::Allow`] or [`Decision::Deny`].

use std::collections::BTreeSet;

use serde::Deserialize;

use crate::eval::Decision;
use crate::policy::PolicyError;

/// A Chinese wall: one or more conflict-of-interest classes. `bypass` exists in
/// the schema only so a policy that *asks* for a bypass can be explicitly
/// refused — the honest failure mode, rather than silently ignoring the field.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Wall {
    pub name: String,
    pub classes: Vec<ConflictClass>,
    /// A wall has no bypass. This field is rejected when `true` by [`validate`].
    #[serde(default)]
    pub bypass: bool,
}

/// A conflict-of-interest class: the set of mutually-competing datasets. Access
/// to one poisons access to the others for that subject.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConflictClass {
    pub name: String,
    /// The competing dataset members (as referenced by `Resource::dataset`).
    pub members: Vec<String>,
}

/// Validate every wall: none may declare a bypass, and no class may be empty.
pub fn validate(walls: &[Wall]) -> Result<(), PolicyError> {
    for w in walls {
        if w.bypass {
            return Err(PolicyError::WallHasBypass {
                wall: w.name.clone(),
            });
        }
        for c in &w.classes {
            if c.members.is_empty() {
                return Err(PolicyError::EmptyConflictClass {
                    wall: w.name.clone(),
                    class: c.name.clone(),
                });
            }
        }
    }
    Ok(())
}

/// The Brewer-Nash decision for accessing `dataset`, given the datasets the
/// subject has `already_accessed`. Denied iff the target shares a conflict
/// class with something already touched but is not that same dataset.
pub fn may_access(walls: &[Wall], already_accessed: &BTreeSet<String>, dataset: &str) -> Decision {
    for w in walls {
        for c in &w.classes {
            if !c.members.iter().any(|m| m == dataset) {
                continue; // target not in this class
            }
            // Target is in this class. If the subject already touched a
            // *different* member of the same class, the wall stands.
            for member in &c.members {
                if member != dataset && already_accessed.contains(member) {
                    return Decision::Deny {
                        reason: format!(
                            "Chinese wall {:?} class {:?}: already accessed competing dataset {:?}, so {:?} is denied",
                            w.name, c.name, member, dataset
                        ),
                    };
                }
            }
        }
    }
    Decision::Allow
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wall() -> Wall {
        Wall {
            name: "banking".into(),
            classes: vec![ConflictClass {
                name: "banks".into(),
                members: vec!["bank-a".into(), "bank-b".into()],
            }],
            bypass: false,
        }
    }

    #[test]
    fn validate_rejects_bypass() {
        let mut w = wall();
        w.bypass = true;
        let err = validate(&[w]).unwrap_err();
        assert!(matches!(err, PolicyError::WallHasBypass { .. }));
    }

    #[test]
    fn brewer_nash_denies_competitor_after_first_touch() {
        let walls = vec![wall()];
        let mut history = BTreeSet::new();

        // First touch of bank-a: allowed.
        assert_eq!(may_access(&walls, &history, "bank-a"), Decision::Allow);
        history.insert("bank-a".to_string());

        // bank-a again: still allowed (same dataset, not a competitor).
        assert_eq!(may_access(&walls, &history, "bank-a"), Decision::Allow);

        // bank-b now competes with an already-touched member: denied.
        assert!(matches!(
            may_access(&walls, &history, "bank-b"),
            Decision::Deny { .. }
        ));
    }
}
