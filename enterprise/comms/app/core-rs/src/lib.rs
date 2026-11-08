// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
//! Bloch — org internal messenger, thin Rust core. **Business/Enterprise edition
//! only.** Pre-release and **UNAUDITED**.
//!
//! This crate is a small, honest model of an org messenger's conversations that
//! **binds to the Postern Messenger E2EE tier wall**
//! ([`postern_messenger::SecurityTier`]) — it references that crate by path and
//! does **not** fork it, does **not** reimplement crypto, and does **not** enable
//! its heavy `matrix` feature. End-to-end encryption of message bodies is owned
//! entirely by `postern-messenger` (Matrix + vodozemac/Megolm). Here we only
//! model channels/DMs, org-scoped membership, and the fail-closed license gate.
//!
//! The JS/ESM core in `../src/*.mjs` is the app's primary implementation (it
//! plugs into `enterprise/features/{license-hook,sub-access}.mjs`); this Rust
//! core exists to demonstrate the same rails against the crate's own types.

use std::collections::BTreeSet;

use postern_messenger::{disclosure, SecurityTier};

/// The license tiers under which this ENTERPRISE-ONLY app is permitted to run.
/// Mirrors the JS license bridge: corporate-master or the free business tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenseTier {
    /// Verified corporate master token — unlimited seats.
    CorporateMaster,
    /// Free business freemium (up to 3 desktops, 2 years).
    BusinessFreemium,
    /// Anything else: unverified, expired, or absent. Fails closed.
    Unlicensed,
}

impl LicenseTier {
    /// The one rail that never bends: the app runs only on an enterprise tier.
    pub const fn comms_allowed(self) -> bool {
        matches!(self, LicenseTier::CorporateMaster | LicenseTier::BusinessFreemium)
    }
}

/// Refusal reasons — the app never fabricates a "licensed" state.
#[derive(Debug, thiserror::Error)]
pub enum CommsError {
    #[error("Bloch is Business/Enterprise-edition only and refuses to run: license tier {0:?} is not permitted")]
    Refused(LicenseTier),
    #[error("\"{0}\" is not in the org roster (an active sub-access grant) — invite them first")]
    NotAMember(String),
    #[error("Bloch is an internal messenger: it does not carry {0:?} conversations (those belong to the Messenger Bridges tab, disclosed, never here)")]
    NotInternal(SecurityTier),
}

/// A conversation: an org channel or a DM. Every Bloch conversation is
/// [`SecurityTier::InternalE2ee`] — bridged/external is out of scope here and is
/// rejected at construction (no silent downgrade, honoring the crate's wall).
#[derive(Debug, Clone)]
pub struct Conversation {
    pub id: u64,
    pub kind: ConvKind,
    pub name: String,
    pub members: BTreeSet<String>,
    tier: SecurityTier,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConvKind {
    Channel,
    Dm,
}

impl Conversation {
    /// The tier badge the UI must show, sourced from the messenger crate.
    pub fn tier_badge(&self) -> &'static str {
        self.tier.badge()
    }
    /// Whether a persistent disclaimer is mandatory (never, for internal E2EE).
    pub fn requires_persistent_disclaimer(&self) -> bool {
        self.tier.requires_persistent_disclaimer()
    }
}

/// The org messenger. FAIL-CLOSED: [`Org::new`] refuses unless the license tier
/// permits enterprise features. Membership is an org-scoped roster (in the real
/// app it is derived from the enterprise sub-access grants).
pub struct Org {
    pub name: String,
    pub tier: LicenseTier,
    roster: BTreeSet<String>,
    convs: Vec<Conversation>,
    seq: u64,
}

impl Org {
    /// Build the org, or refuse. `roster` is the set of org members (labels of
    /// active sub-access grants).
    pub fn new(
        name: impl Into<String>,
        tier: LicenseTier,
        roster: impl IntoIterator<Item = String>,
    ) -> Result<Self, CommsError> {
        if !tier.comms_allowed() {
            return Err(CommsError::Refused(tier));
        }
        Ok(Self {
            name: name.into(),
            tier,
            roster: roster.into_iter().collect(),
            convs: Vec::new(),
            seq: 0,
        })
    }

    pub fn is_member(&self, label: &str) -> bool {
        self.roster.contains(label)
    }

    fn require_member(&self, label: &str) -> Result<(), CommsError> {
        if self.is_member(label) {
            Ok(())
        } else {
            Err(CommsError::NotAMember(label.to_string()))
        }
    }

    /// Create an internal E2EE channel. Every member must be on the roster.
    pub fn create_channel(
        &mut self,
        name: impl Into<String>,
        members: impl IntoIterator<Item = String>,
    ) -> Result<u64, CommsError> {
        let mut set = BTreeSet::new();
        for m in members {
            self.require_member(&m)?;
            set.insert(m);
        }
        self.seq += 1;
        let id = self.seq;
        self.convs.push(Conversation {
            id,
            kind: ConvKind::Channel,
            name: name.into(),
            members: set,
            // Bloch is internal-only. The tier is fixed at the internal wall.
            tier: SecurityTier::InternalE2ee,
        });
        Ok(id)
    }

    /// Open a DM between two roster members (order-independent).
    pub fn open_dm(&mut self, a: &str, b: &str) -> Result<u64, CommsError> {
        self.require_member(a)?;
        self.require_member(b)?;
        let members: BTreeSet<String> = [a.to_string(), b.to_string()].into_iter().collect();
        if let Some(c) = self
            .convs
            .iter()
            .find(|c| c.kind == ConvKind::Dm && c.members == members)
        {
            return Ok(c.id);
        }
        self.seq += 1;
        let id = self.seq;
        let name = format!("{a} ↔ {b}");
        self.convs.push(Conversation {
            id,
            kind: ConvKind::Dm,
            name,
            members,
            tier: SecurityTier::InternalE2ee,
        });
        Ok(id)
    }

    pub fn conversations(&self) -> &[Conversation] {
        &self.convs
    }
}

/// The honest E2EE disclosure the transparency banner surfaces. Message bodies
/// are Megolm-E2EE; metadata is org-visible. Bridged copy is sourced VERBATIM
/// from the messenger crate so no layer softens the wording.
pub fn internal_e2ee_note() -> &'static str {
    "Message bodies in Bloch channels and DMs are end-to-end encrypted (Megolm via \
     vodozemac). Metadata — that a conversation exists, its members, and timestamps — \
     is visible to the org's homeserver. Megolm is classical, not post-quantum."
}

/// The exact bridged-tab banner from the messenger crate — re-exposed so callers
/// never have to re-type (and thus never accidentally weaken) it.
pub fn bridged_banner() -> &'static str {
    disclosure::BRIDGE_TAB_BANNER
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enterprise_only_fails_closed() {
        let err = Org::new("Acme", LicenseTier::Unlicensed, []);
        assert!(matches!(err, Err(CommsError::Refused(LicenseTier::Unlicensed))));
        assert!(Org::new("Acme", LicenseTier::CorporateMaster, []).is_ok());
        assert!(Org::new("Acme", LicenseTier::BusinessFreemium, []).is_ok());
    }

    #[test]
    fn membership_is_org_scoped() {
        let mut org = Org::new(
            "Acme",
            LicenseTier::CorporateMaster,
            ["Ana".into(), "Bruno".into()],
        )
        .unwrap();
        assert!(org.create_channel("eng", ["Ana".into()]).is_ok());
        assert!(matches!(
            org.create_channel("x", ["Ghost".into()]),
            Err(CommsError::NotAMember(_))
        ));
        let d1 = org.open_dm("Ana", "Bruno").unwrap();
        let d2 = org.open_dm("Bruno", "Ana").unwrap();
        assert_eq!(d1, d2, "DM is order-independent / reused");
    }

    #[test]
    fn conversations_carry_the_internal_e2ee_tier() {
        let mut org = Org::new("Acme", LicenseTier::CorporateMaster, ["Ana".into()]).unwrap();
        let id = org.create_channel("general", ["Ana".into()]).unwrap();
        let c = org.conversations().iter().find(|c| c.id == id).unwrap();
        assert_eq!(c.tier_badge(), SecurityTier::InternalE2ee.badge());
        assert!(!c.requires_persistent_disclaimer());
        assert!(bridged_banner().contains("does not operate this bridge"));
    }
}
