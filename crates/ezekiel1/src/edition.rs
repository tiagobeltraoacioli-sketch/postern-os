//! The **edition gate** — checked first, fails closed.
//!
//! Before any structural validation, Ezekiel confirms the policy uses only the
//! constructs its declared edition permits. This is a hard boundary between two
//! products that happen to share an engine:
//!
//! - [`Edition::Personal`] — *parental control only*. It refuses every
//!   corporate/multi-tenant construct: no tenants (no multi-tenant, no
//!   cross-household firmaments), no Chinese walls, no corporate roles, no
//!   tenant-classified resources. Control flows `parent -> child`; inverted
//!   control (a child reaching up to a parent) is refused later, in
//!   [`crate::policy::Policy::validate_grants`]. There is no spying.
//! - [`Edition::Business`] — enables the full lattice, Chinese walls, and
//!   tenants. It refuses nothing here; its stricter rules (no-read-up/
//!   no-write-down, Brewer-Nash, firmament isolation) are enforced downstream.
//!
//! A policy that names an out-of-edition construct is refused with
//! [`PolicyError::OutOfEdition`] — never quietly downgraded.

use crate::policy::{Edition, Policy, PolicyError};

/// Enforce the edition boundary. Runs **first** in [`Policy::validate`].
pub fn enforce(policy: &Policy) -> Result<(), PolicyError> {
    match policy.edition {
        Edition::Business => Ok(()), // the full construct set is permitted.
        Edition::Personal => enforce_personal(policy),
    }
}

fn enforce_personal(policy: &Policy) -> Result<(), PolicyError> {
    let refuse = |construct: &str| PolicyError::OutOfEdition {
        edition: Edition::Personal,
        construct: construct.to_string(),
    };

    // No multi-tenant / cross-household firmaments.
    if !policy.tenants.is_empty() {
        return Err(refuse(
            "tenants (multi-tenant / cross-household is a business construct)",
        ));
    }
    // No Chinese walls.
    if !policy.walls.is_empty() {
        return Err(refuse("Chinese walls (a business construct)"));
    }
    // No corporate roles.
    if let Some(s) = policy.subjects.iter().find(|s| s.role.is_some()) {
        return Err(refuse(&format!(
            "corporate role on subject {:?} (a business construct)",
            s.name
        )));
    }
    // No subject bound to a firmament.
    if let Some(s) = policy.subjects.iter().find(|s| s.tenant.is_some()) {
        return Err(refuse(&format!(
            "tenant on subject {:?} (a business construct)",
            s.name
        )));
    }
    // No resource classified into a firmament.
    if let Some(r) = policy.resources.iter().find(|r| r.tenant.is_some()) {
        return Err(refuse(&format!(
            "tenant on resource {:?} (a business construct)",
            r.id
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Layer, Subject};

    fn base(edition: Edition) -> Policy {
        Policy {
            edition,
            tenants: vec![],
            layers: vec![Layer {
                name: "root".into(),
                parent: None,
                level: 1,
            }],
            subjects: vec![],
            resources: vec![],
            walls: vec![],
            grants: vec![],
        }
    }

    #[test]
    fn personal_refuses_corporate_role() {
        let mut p = base(Edition::Personal);
        p.subjects.push(Subject {
            name: "kid".into(),
            tenant: None,
            role: Some("finance-analyst".into()),
            assignments: vec![],
        });
        assert!(matches!(
            enforce(&p),
            Err(PolicyError::OutOfEdition { .. })
        ));
    }

    #[test]
    fn business_permits_everything_here() {
        let p = base(Edition::Business);
        assert!(enforce(&p).is_ok());
    }
}
