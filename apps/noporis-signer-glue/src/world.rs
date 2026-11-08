// SPDX-License-Identifier: MIT OR Apache-2.0
//! # `World` — the two personas one phone stands between
//!
//! The signer core has **no notion of a persona, world, or profile**: a
//! signature is bound to *a session*, *a named peer*, and *the exact bytes*
//! (`postern-signer-protocol`). A "world" here is therefore **not** a new signer
//! concept — it is simply *which pairing a request arrived on*, given a human
//! name. This module is the display/policy vocabulary for that fact; it holds no
//! key material and takes no part in signing.
//!
//! Two worlds, deliberately opposite trust postures:
//!
//! - [`World::Porog`] — the **guarded door** into the hardened side. Key-attested
//!   device (StrongBox/TEE where present), **not** measured-boot workspace;
//!   Tor-only. A real `Verdict::Genuine` is *possible* here (the app may surface
//!   one from `seal::verify_report`), so [`World::may_show_attestation`] is true.
//! - [`World::Noporis`] — the **guarded bridge**'s second persona: the
//!   Google-Play / business side. **`tier = non-attestable`, always, by
//!   construction.** No Seal, no padlock, and it phones home to Google. It is the
//!   **less-private side**, and every surface says so.
//!
//! ## World-badging with NO new wire data
//!
//! The rendered `Wysiwys` already carries a `peer_device` field, and the phone
//! learns that name at pairing — **never** from the request bytes. So the world
//! badge needs no new wire field: we fold it into the `peer_device` string at
//! construction, from *which pairing (world) the signer was built for*. A
//! compromised desktop cannot narrate a lie (there is no human-text field on the
//! wire) and now also cannot **mislabel its world** — the badge is derived, not
//! requester-controlled. See [`World::badge`] and [`World::peer_device`].

/// Which of the two worlds a pairing belongs to. `Copy`; carries no secret.
///
/// A `World` is *derived from which pairing a frame arrived on*, and must never
/// be taken from anything the requester controls.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum World {
    /// The guarded **door** — the hardened, Tor-only side. Key-attested device,
    /// not a measured-boot workspace.
    Porog,
    /// The guarded **bridge**'s second persona — the Google-Play / business side.
    /// **Non-attestable by construction; the less-private side.**
    Noporis,
}

impl World {
    /// The short human label ("Porog", "NoporIS").
    pub fn name(self) -> &'static str {
        match self {
            World::Porog => "Porog",
            World::Noporis => "NoporIS",
        }
    }

    /// The **world badge** shown on every surface, including the signer prompt.
    /// A fact, not decoration: the NoporIS badge always carries "less private".
    ///
    /// This string is the prefix of the world-badged [`peer_device`](World::peer_device),
    /// so a surface can assert a prompt's `peer_device` starts with the badge of
    /// the lane it is drawn on and refuse a mismatch.
    pub fn badge(self) -> &'static str {
        match self {
            World::Porog => "Porog · hardened",
            World::Noporis => "NoporIS · Google-Play side — less private",
        }
    }

    /// The world-badged `peer_device` string handed to `PhoneApprover::new`.
    /// It reuses the EXISTING WYSIWYS `peer_device` field (no new wire data): the
    /// world badge is derived from the pairing this signer was built for, then the
    /// human peer nickname is appended.
    ///
    /// e.g. `"NoporIS · Google-Play side — less private · Tiago's Chromebook"`.
    pub fn peer_device(self, peer_nickname: &str) -> String {
        format!("{} · {}", self.badge(), peer_nickname)
    }

    /// True only for the world where a genuine attestation *can exist* (Porog).
    /// The NoporIS side is `non-attestable` by construction — showing a padlock
    /// there would be the exact theater we reject, so this is **false** for it.
    pub fn may_show_attestation(self) -> bool {
        matches!(self, World::Porog)
    }

    /// True for the world that is **less private by construction** (NoporIS): it
    /// phones home to Google and is never sealed/attested.
    pub fn is_less_private(self) -> bool {
        matches!(self, World::Noporis)
    }

    /// True only for the world that owns the bridge kill-switch (NoporIS). The
    /// door (Porog) has no bridge to cut.
    pub fn has_bridge_kill_switch(self) -> bool {
        matches!(self, World::Noporis)
    }

    /// The one honest, one-line disclosure for this world. Shown plainly on the
    /// surface — not only in a doc — so the trust posture is never implied by a
    /// lock icon that means nothing.
    pub fn disclosure(self) -> &'static str {
        match self {
            World::Porog => {
                "Hardened side. Key-attested device (StrongBox/TEE where present), \
                 NOT measured-boot workspace; Tor-only. Attests the phone, not the \
                 workspace. A rooted/compromised host defeats the separation."
            }
            World::Noporis => {
                "Less-private side by construction. This persona phones home to \
                 Google; the tier is non-attestable — no Seal, no padlock. The \
                 bridge conveniences and separates; it does NOT make you private."
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn badge_carries_the_less_private_fact_for_noporis_only() {
        assert!(World::Noporis.badge().contains("less private"));
        assert!(!World::Porog.badge().contains("less private"));
        assert!(World::Noporis.is_less_private());
        assert!(!World::Porog.is_less_private());
    }

    #[test]
    fn peer_device_is_badge_prefixed_and_names_the_peer() {
        let pd = World::Noporis.peer_device("Tiago's Chromebook");
        assert!(pd.starts_with(World::Noporis.badge()));
        assert!(pd.contains("Tiago's Chromebook"));
        // The two worlds produce DIFFERENT peer_device strings for the same
        // nickname — the structural anchor for grant/world isolation.
        assert_ne!(
            World::Noporis.peer_device("Same Laptop"),
            World::Porog.peer_device("Same Laptop"),
        );
    }

    #[test]
    fn only_porog_may_show_attestation_and_only_noporis_has_a_kill_switch() {
        assert!(World::Porog.may_show_attestation());
        assert!(!World::Noporis.may_show_attestation());
        assert!(World::Noporis.has_bridge_kill_switch());
        assert!(!World::Porog.has_bridge_kill_switch());
    }

    #[test]
    fn disclosures_are_honest_and_never_claim_measured_boot() {
        assert!(World::Porog.disclosure().contains("NOT measured-boot"));
        assert!(World::Noporis.disclosure().contains("non-attestable"));
        assert!(World::Noporis.disclosure().contains("Google"));
    }
}
