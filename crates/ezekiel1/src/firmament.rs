//! The **firmament** — tenant isolation.
//!
//! > "…the likeness of the firmament… stretched forth over their heads above."
//! > — Ezekiel 1:22
//!
//! A firmament separates tenants so completely that **no resource id or index,
//! and no derived signal, crosses it**. This module enforces the structural
//! half of that promise: within one policy, a resource id/index is never shared
//! between two tenants ([`validate`]), and it exposes the runtime check the
//! evaluator uses — a subject may only reach a resource in its **own**
//! firmament ([`same_firmament`]).
//!
//! # Honest status — real vs. aspirational
//!
//! What is **real** here: Ezekiel enforces firmament separation **by
//! construction** inside a single process. Distinct tenants share no resource
//! id, the evaluator refuses any cross-firmament access, and — because each
//! access is evaluated on its own with no cross-firmament cache (see
//! [`crate::eval`]) — no derived signal (a timing, a cached decision, a counter)
//! is threaded between tenants through this engine.
//!
//! What is **aspirational**: this is **not** an OS/kernel or hardware boundary.
//! Two tenants evaluated by the same process still share an address space, an
//! allocator, and a CPU. A memory-safety break, a side channel, or a bug
//! outside this module could still bridge firmaments. True firmament-grade
//! isolation (separate processes/VMs/hosts per tenant, on the customer's own
//! infrastructure — there is no Postern server) is the deployment's job, not
//! this crate's. Ezekiel makes the separation *policy-correct*; it does not make
//! it *physically inescapable*. (This mirrors Yagabona's "userland boundary, not
//! an OS sandbox" honesty.)

use std::collections::BTreeMap;

use postern_policy::EnforcementMode;

use crate::policy::{Policy, PolicyError};

/// How firmament isolation is honestly enforced **today**:
/// [`EnforcementMode::ByConstruction`] — a userland, in-process check, **not**
/// an OS/kernel or hardware boundary. This is the shared consent-kernel type,
/// so the caveat is one word across the workspace (identical to yagabona's
/// `ScopedFs`) rather than prose that could drift into "isolated" or
/// "sandboxed". See [`EnforcementMode::honest_label`] for the exact wording and
/// the module docs above for the full real-vs-aspirational note.
pub const ENFORCEMENT: EnforcementMode = EnforcementMode::ByConstruction;

/// How firmament isolation is enforced — see [`ENFORCEMENT`]. Exposed so UIs
/// and logs read the honest caveat from the shared type, never a hand-written
/// sentence.
pub fn enforcement_mode() -> EnforcementMode {
    ENFORCEMENT
}

/// Structural firmament check: no resource id/index is shared across tenants,
/// and every resource id is unique. Referenced tenants must be declared.
pub fn validate(policy: &Policy) -> Result<(), PolicyError> {
    // Referenced tenants (on subjects and resources) must be declared.
    let declared: Vec<&str> = policy.tenants.iter().map(|t| t.name.as_str()).collect();
    for s in &policy.subjects {
        if let Some(t) = &s.tenant {
            if !declared.contains(&t.as_str()) {
                return Err(PolicyError::UnknownTenantRef {
                    referent: "subject".into(),
                    name: s.name.clone(),
                    tenant: t.clone(),
                });
            }
        }
    }
    for r in &policy.resources {
        if let Some(t) = &r.tenant {
            if !declared.contains(&t.as_str()) {
                return Err(PolicyError::UnknownTenantRef {
                    referent: "resource".into(),
                    name: r.id.clone(),
                    tenant: t.clone(),
                });
            }
        }
    }

    // No resource id shared. If two entries share an id but differ in tenant,
    // that is a firmament breach specifically; otherwise a plain duplicate.
    let mut seen: BTreeMap<&str, Option<&str>> = BTreeMap::new();
    for r in &policy.resources {
        if let Some(prev_tenant) = seen.get(r.id.as_str()) {
            let a = prev_tenant.unwrap_or("-");
            let b = r.tenant.as_deref().unwrap_or("-");
            if a != b {
                return Err(PolicyError::FirmamentBreach {
                    resource: r.id.clone(),
                    tenant_a: a.to_string(),
                    tenant_b: b.to_string(),
                });
            }
            return Err(PolicyError::DuplicateResource {
                resource: r.id.clone(),
            });
        }
        seen.insert(r.id.as_str(), r.tenant.as_deref());
    }
    Ok(())
}

/// Runtime firmament check: a subject in `subject_tenant` may reach a resource
/// in `resource_tenant` only when they are the **same** firmament. Two `None`s
/// are the single implicit firmament of a personal household; a mismatch (or a
/// resource in a firmament the subject is not in) is refused.
pub fn same_firmament(subject_tenant: Option<&str>, resource_tenant: Option<&str>) -> bool {
    subject_tenant == resource_tenant
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Edition, Layer, Resource, Tenant};

    fn policy_with(resources: Vec<Resource>, tenants: Vec<Tenant>) -> Policy {
        Policy {
            edition: Edition::Business,
            tenants,
            layers: vec![Layer {
                name: "root".into(),
                parent: None,
                level: 1,
            }],
            subjects: vec![],
            resources,
            walls: vec![],
            grants: vec![],
        }
    }

    #[test]
    fn shared_resource_across_tenants_is_a_breach() {
        let p = policy_with(
            vec![
                Resource {
                    id: "shared/index".into(),
                    layer: "root".into(),
                    tenant: Some("acme".into()),
                    dataset: None,
                },
                Resource {
                    id: "shared/index".into(),
                    layer: "root".into(),
                    tenant: Some("globex".into()),
                    dataset: None,
                },
            ],
            vec![Tenant { name: "acme".into() }, Tenant { name: "globex".into() }],
        );
        assert!(matches!(
            validate(&p),
            Err(PolicyError::FirmamentBreach { .. })
        ));
    }

    #[test]
    fn same_firmament_gate() {
        assert!(same_firmament(Some("acme"), Some("acme")));
        assert!(!same_firmament(Some("acme"), Some("globex")));
        assert!(same_firmament(None, None));
        assert!(!same_firmament(Some("acme"), None));
    }
}
