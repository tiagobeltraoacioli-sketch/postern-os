//! Minimal org model — user, org, role, and the RBAC gate.
//!
//! This mirrors the Consiglio reference console (`apps/postern-enterprise`,
//! its `ROLES` / `SOD` / `rbacCheck`): the same five machine-profile roles and
//! the same "role entitled to a volume family + clearance ≥ required" check,
//! reduced to the subset needed to demo "wallet logs in → role gate applies".
//!
//! Reference prototype / UNAUDITED — demonstrates controls that ENABLE
//! compliance; it is NOT compliance and not a hardened IAM. The store is
//! in-memory (durable via the [`crate::persist`] snapshot/restore seam) and this
//! module's gate is role+clearance (RBAC+ABAC). The Brewer–Nash information
//! barrier declared here (`Role::sod_conflicts`) is **no longer merely declared**:
//! it is wired into the runtime dual-control gate in [`crate::control`], where a
//! privileged change requires two *separated* admins to sign off (see
//! [`Role::sod_separated_from`]) — and, since the conflict-of-interest fields
//! landed on [`Volume`], it is also enforced **dynamically on data access**:
//! `AuthServer::authorize` binds a user to the first dataset they are granted
//! in a [`Volume::coi_class`] and fail-closed denies competing datasets in the
//! same class thereafter. [`rbac_check`] itself stays the pure, stateless
//! RBAC+ABAC helper — the stateful wall lives server-side in
//! `crate::server::AuthServer::authorize`, a userland enforcement point, not a
//! kernel boundary.

use serde::{Deserialize, Serialize};

/// Opaque org identifier (e.g. `"acme"`).
pub type OrgId = String;
/// Opaque user identifier within an org (e.g. `"alice"`).
pub type UserId = String;

/// The five Consiglio machine-profile roles (RBAC == machine profile).
///
/// Kept byte-identical (ids) to the console's `ROLES` catalog so an enrollment
/// minted here means the same thing there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    Engineer,
    FinanceAnalyst,
    Counsel,
    ItAdmin,
    ComplianceOfficer,
}

impl Role {
    /// Stable id string — matches the console's `ROLES[].id`.
    pub fn id(&self) -> &'static str {
        match self {
            Role::Engineer => "engineer",
            Role::FinanceAnalyst => "finance-analyst",
            Role::Counsel => "counsel",
            Role::ItAdmin => "it-admin",
            Role::ComplianceOfficer => "compliance-officer",
        }
    }

    /// Volume families this role is entitled to (the RBAC entitlement).
    /// Empty for the two administrative roles (they manage, they don't read
    /// business volumes) — exactly as in the console.
    pub fn volumes(&self) -> &'static [&'static str] {
        match self {
            Role::Engineer => &["engineering"],
            Role::FinanceAnalyst => &["finance"],
            Role::Counsel => &["client-matter"],
            Role::ItAdmin => &[],
            Role::ComplianceOfficer => &[],
        }
    }

    /// Separation-of-duty: roles that MUST NOT be held by the same user.
    /// Mirrors the console `SOD = [["it-admin","compliance-officer"]]`.
    /// NOW ENFORCED at runtime by the dual-control gate ([`crate::control`]).
    pub fn sod_conflicts(&self) -> &'static [Role] {
        match self {
            Role::ItAdmin => &[Role::ComplianceOfficer],
            Role::ComplianceOfficer => &[Role::ItAdmin],
            _ => &[],
        }
    }

    /// The two administrative roles that may PROPOSE/APPROVE privileged changes
    /// (enroll/offboard). Business roles administer nothing; they read volumes.
    /// Mirrors the console: `it-admin` and `compliance-officer` are the controls.
    pub fn is_admin(&self) -> bool {
        matches!(self, Role::ItAdmin | Role::ComplianceOfficer)
    }

    /// True iff `self` and `other` are a Brewer–Nash *separated* pair — i.e. each
    /// is on the other's SoD conflict list. Dual-control REQUIRES the two
    /// controllers (proposer + approver) to be such a separated pair, so a
    /// privileged change always needs sign-off from *both* sides of the wall
    /// (one IT-admin AND one compliance-officer) — two colluding IT-admins can
    /// never bypass compliance oversight, and vice-versa.
    pub fn sod_separated_from(&self, other: Role) -> bool {
        self.sod_conflicts().contains(&other)
    }
}

/// A volume (resource) the login might gate access to. `family` is the RBAC
/// entitlement key (e.g. `"engineering"`); `clearance` is the ABAC floor.
///
/// The two optional conflict-of-interest fields drive the **dynamic
/// Brewer–Nash wall** in `AuthServer::authorize`: volumes carrying the same
/// `coi_class` (e.g. `"audit-clients"`) belong to competing datasets, and the
/// first dataset a user is *granted* in that class binds them — a later
/// request for a DIFFERENT dataset in the SAME class is denied. Both fields
/// default to `None` (backward-compatible: no class, no wall) and old
/// serialized volumes deserialize unchanged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Volume {
    pub id: String,
    pub family: String,
    pub clearance: u8,
    /// Brewer–Nash conflict-of-interest class this volume's data belongs to
    /// (e.g. `"audit-clients"`). `None` (the default) means the volume is
    /// outside every wall.
    #[serde(default)]
    pub coi_class: Option<String>,
    /// Which dataset within `coi_class` this volume carries (e.g. the client
    /// the files belong to). `None` falls back to the volume `id` — see
    /// [`Volume::dataset_id`]. Meaningless without a `coi_class`.
    #[serde(default)]
    pub dataset: Option<String>,
}

impl Volume {
    /// A plain volume with no conflict-of-interest class (the pre-wall shape).
    pub fn new(id: impl Into<String>, family: impl Into<String>, clearance: u8) -> Self {
        Self {
            id: id.into(),
            family: family.into(),
            clearance,
            coi_class: None,
            dataset: None,
        }
    }

    /// Tag this volume with a Brewer–Nash conflict-of-interest class and the
    /// dataset it carries within that class. Chainable.
    pub fn with_coi(mut self, class: impl Into<String>, dataset: impl Into<String>) -> Self {
        self.coi_class = Some(class.into());
        self.dataset = Some(dataset.into());
        self
    }

    /// The dataset identity the wall tracks: the explicit `dataset` if set,
    /// otherwise the volume `id` (several volumes may share one dataset).
    pub fn dataset_id(&self) -> &str {
        self.dataset.as_deref().unwrap_or(&self.id)
    }
}

/// An enrolled member: identity + role + clearance. The binding of this user to
/// a wallet public key lives in [`crate::enroll`], not here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub org_id: OrgId,
    pub user_id: UserId,
    pub role: Role,
    /// ABAC clearance level (0 = lowest). Compared against a volume's floor.
    pub clearance: u8,
}

/// An org (the "council" — *consiglio*). Just a name in the MVP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Org {
    pub org_id: OrgId,
    pub name: String,
}

/// Outcome of the RBAC + ABAC gate. `ok == false` carries a human reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessDecision {
    pub ok: bool,
    pub why: Option<String>,
}

impl AccessDecision {
    pub(crate) fn deny(why: impl Into<String>) -> Self {
        Self { ok: false, why: Some(why.into()) }
    }
    pub(crate) fn allow() -> Self {
        Self { ok: true, why: None }
    }
}

/// The role gate, pure and total — the same shape as the console's `rbacCheck`:
///   1. role must be entitled to the volume's `family`;
///   2. the user's `clearance` must be ≥ the volume's floor.
///
/// A denied login role therefore can't read a volume it isn't entitled to,
/// which is the whole point of "wallet logs in, role gate applies".
///
/// This helper is deliberately STATELESS: it does not see the per-user
/// dataset-access history, so it cannot apply the dynamic Brewer–Nash wall.
/// The enforced gate — session revalidation, live-enrollment role read, AND
/// the wall — is `AuthServer::authorize`; use this only over data you know is
/// current (it is the caller-applied form the honesty table warns about).
pub fn rbac_check(user: &User, vol: &Volume) -> AccessDecision {
    if !user.role.volumes().contains(&vol.family.as_str()) {
        return AccessDecision::deny(format!(
            "role '{}' not entitled to '{}' volumes",
            user.role.id(),
            vol.family
        ));
    }
    if user.clearance < vol.clearance {
        return AccessDecision::deny(format!(
            "clearance {} < required {}",
            user.clearance, vol.clearance
        ));
    }
    AccessDecision::allow()
}
