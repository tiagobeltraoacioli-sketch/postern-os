// SPDX-License-Identifier: MIT OR Apache-2.0
//! # `noporis-signer-glue` — the guarded bridge, made honest in code
//!
//! **Status: reference-prototype. UNAUDITED — certifies nothing about security.**
//!
//! ## The one load-bearing structural fact
//!
//! The signer core has **no notion of a persona, world, or profile.** A signature
//! is bound to *a session*, *a named peer*, and *the exact bytes*
//! (`postern-signer-protocol`). There is no "cross-world approval" primitive, and
//! inventing one would contradict the invariants the scaffolds enforce. So the
//! honest model is **ONE phone holding TWO INDEPENDENT pairings** — one per world
//! — **never one signer that spans the bridge.**
//!
//! This crate implements exactly that model as **glue**. It composes existing
//! crates without editing any of their internals:
//!
//! - [`postern_signer_protocol`] — `PhoneApprover`, byte-derived WYSIWYS, the
//!   time-boxed/revocable `ApprovalGrant`, and the fail-closed `ReplayGuard`
//!   session binding.
//! - [`postern_pairing`] — the pairing ceremony and the sealed `PairedTerminals`
//!   collection (monotonic per-record revoke, panic-revoke-all).
//! - [`postern_policy`] — the one shared consent kernel (fail-closed `Decision`,
//!   the honest `EnforcementMode` label).
//! - `postern-mobile-signer` — the REAL WalletCore-backed signer, behind the
//!   `wallet-core` feature (OFF by default; it pulls heavyweight PQ crypto).
//!
//! ## What it adds (a lane, never a shortcut)
//!
//! | Concern | Type | Honest behaviour |
//! |---|---|---|
//! | Two independent pairings | [`WorldPairings`] | two separate sealed stores, one per world; unpairing one can't touch the other |
//! | Two independent signers | [`WorldSigner`] / [`TwoWorldSigner`] | one approver + session + badged peer per world; no shared approver |
//! | Fail-closed session binding | [`TwoWorldSigner::receive_on`] | a request for world A on world B → `WrongSession`; a Google-Play grant never auto-approves Porog |
//! | World-badging, no new wire data | [`World::peer_device`] | the badge rides the EXISTING WYSIWYS `peer_device`, derived from the pairing, never the request |
//! | Revoke a grant (soft) | [`WorldSigner::revoke_grant`] | per-world, per-scope; collapses to "never given" |
//! | Unpair a world (hard) | [`WorldPairings::unpair`] | drops that world's `PairingRecord`; the other is untouched |
//! | Kill the bridge | [`TwoWorldSigner::engage_bridge_kill`] | NoporIS-only; cuts the lane, **never destroys sealed wallet state** or a pairing |
//!
//! ## Honesty rails (carried in code, not only prose)
//!
//! - **SCAFFOLD / UNAUDITED.** Default builds sign with `ScaffoldSigner`, a
//!   deterministic SHA3 stand-in — **NOT real cryptography**. The real signer
//!   (`wallet-core` feature) is still **not a hardware wallet**: the PQ key is in
//!   RAM at sign time.
//! - **Userland, not a kernel boundary.** Grant enforcement and the kill-switch
//!   are `EnforcementMode::ByConstruction` — in-process checks. A rooted/malware
//!   host reads keys from RAM and can forge the approval UI; nothing here fixes
//!   that. See [`RAILS`].
//! - **The Google side does not make you private** — that persona phones home to
//!   Google. Its `tier` is `non-attestable` **by construction**; it shows no Seal
//!   and no padlock it hasn't earned.
//! - **This is an app on stock Android — NEVER "Postern OS".** The measured-boot,
//!   self-sovereign path is Postern OS Mobile; NoporIS and Porog are not it.
//! - **Licensing.** Respect Google's and Android's licenses: this crate bundles no
//!   Google-proprietary code and consumes only the AOSP managed-profile / gate
//!   patterns via the crates above. **BLCH is not a security**, is not involved in
//!   licensing, and buys no software; personal use is free.
//! - **Marks.** "NoporIS/Nopor" is a **coined, proposed** name pending formal
//!   trademark clearance (a bare "NOPOR" filing is on record); the authentic myth
//!   is the *crossing between two worlds*, not the word "Nopor". The guardian is
//!   **Yagabona**, never the registered "Baba Yaga".

#![forbid(unsafe_code)]

pub mod killswitch;
pub mod pairings;
pub mod signer;
pub mod world;

pub use killswitch::{BridgeKillSwitch, ConsentRevoker, BRIDGE_ENFORCEMENT, BRIDGE_KILL_REVOKE_REASON};
pub use pairings::WorldPairings;
pub use signer::{GlueError, TwoWorldSigner, WorldSigner};
pub use world::World;

// Re-export the composed crates so a downstream Dev/app layer can reach the
// frozen types without adding separate dependency lines (mirroring how
// `postern-mobile-signer` re-exports its two dependencies).
pub use postern_pairing as pairing;
pub use postern_policy as policy;
pub use postern_signer_protocol as protocol;

/// The one design rule to write on the tin, verbatim: the signer is one keyring
/// the human carries between two doors; it is presented at one door at a time,
/// each presentation named and consented. **There is no master approval that
/// opens both.**
pub const DESIGN_RULE: &str = "One keyring, two doors; presented at one door at a time, each \
    presentation named and consented. No master approval opens both.";

/// The honesty rails this crate refuses to round up on, as one string a surface
/// can print. Kept next to the code so it can't drift from what the code does.
pub const RAILS: &str = "reference-prototype / UNAUDITED. ScaffoldSigner is NOT real \
    cryptography. Not a hardware wallet — the PQ key is in RAM at sign time. Grant \
    enforcement and the bridge kill-switch are userland, in-process checks \
    (ByConstruction), not an OS/kernel boundary; a rooted host defeats them. The \
    NoporIS/Google-Play side is non-attestable by construction and phones home to \
    Google — it does not make you private. An app on stock Android, NEVER 'Postern OS'.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn design_rule_and_rails_state_the_no_master_approval_invariant() {
        assert!(DESIGN_RULE.contains("No master approval"));
        assert!(RAILS.contains("UNAUDITED"));
        assert!(RAILS.contains("NOT real cryptography"));
        assert!(RAILS.contains("not an OS/kernel boundary"));
        assert!(RAILS.contains("non-attestable"));
        assert!(RAILS.contains("NEVER 'Postern OS'"));
    }

    #[test]
    fn the_two_worlds_are_the_door_and_the_bridge() {
        // Porog is the door (attestable-capable, no kill-switch); NoporIS is the
        // bridge (less-private, non-attestable, owns the kill-switch).
        assert!(World::Porog.may_show_attestation());
        assert!(!World::Porog.has_bridge_kill_switch());
        assert!(World::Noporis.is_less_private());
        assert!(World::Noporis.has_bridge_kill_switch());
        assert!(!World::Noporis.may_show_attestation());
    }
}
