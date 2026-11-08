// SPDX-License-Identifier: MIT OR Apache-2.0
//! # terem-gate -- the Terem (desktop guest sandbox) DATA-CROSSING consent tier
//!
//! ## SCAFFOLD / reference-prototype -- UNAUDITED. Certifies nothing.
//!
//! Terem is the OS Portal v2 desktop guest sandbox: Windows/Ubuntu/RHEL run
//! inside a KVM/QEMU VM or an `nspawn` container, or a single Wine/Proton app
//! runs inside a `WINEPREFIX`, on the Postern OS Desktop host
//! (`docs/os-portal-v2/01-architecture.md`). Per `docs/os-portal-v2/
//! 02-security-consent-privacy.md` SS3 and `docs/os-portal-v2/
//! B-sandbox-consent.md` SS2, every guest<->host crossing is closed by
//! default and stays closed until an explicit, disclosed, individually-
//! revocable consent opens it. This crate is that consent tier's REAL,
//! host-testable implementation of the five bridges: **clipboard,
//! sharedFolder, network, usb, audio**.
//!
//! ## What it reuses (not reinvented)
//!
//! `apps/noporis-bridge-glue/src/consent_record.rs`'s signed, time-boxed
//! `ConsentRecord` model, unchanged in shape: signature -> instance binding
//! -> direction -> capability -> time-box, with the same four revocation
//! paths (explicit revoke, capability-lane close, kill-switch, expiry). The
//! host+guest here are co-resident on one machine (no second physical
//! device), so NoporIS's pairing/transport layer is dropped -- every other
//! rail is kept, per `B-sandbox-consent.md` SS2.1's own note on this exact
//! simplification.
//!
//! ## What is new here (the two red-team fixes this crate embeds)
//!
//! - **(a) `sharedFolder.hostPath` disjointness** (`crate::paths`): a
//!   `SharedFolder` grant cannot be minted at all if its `hostPath` overlaps
//!   -- in either direction -- Terem's own consent-state dir, audit-trail
//!   dir, or `WINEPREFIX`. There is no code path that produces a
//!   `ConsentRecord` for an overlapping path; the only mint entry point
//!   (`ConsentAuthority::mint_shared_folder`) runs the check first and
//!   returns no record on failure.
//! - **(b) USB identity is spoofable, and this crate says so in the type
//!   itself** (`crate::capability::USB_IDENTITY_SPOOFABLE_CAVEAT`): a USB
//!   grant binds vendor:product ID + serial, never "all USB" -- but that
//!   identity is firmware-reported, not hardware-fused, and a BadUSB-class
//!   device can present any identity it likes. `Capability::Usb.caveat()`
//!   surfaces this in the exact same place a consent UI would render the
//!   grant, not just in a doc comment.
//!
//! ## The load-bearing claim: only the host mints, the guest only asks
//!
//! [`ConsentAuthority`] is the sole way to produce a [`ConsentRecord`], and
//! only the host process ever constructs one. The guest can build a
//! [`ConsentRequest`] -- an *ask* -- but that type carries no signature and
//! has no method to add one. A compromised guest that forges its own
//! keypair and mints its own "yes" produces a record that fails
//! [`ConsentLedger::admit`] at the signature check, before it can ever
//! authorize anything (see the `consent_record` module's
//! `a_guest_holding_a_foreign_key_cannot_self_authorize` test). **The guest
//! never authorizes itself.**
//!
//! ## Honesty rails (carry these wherever this crate is described)
//!
//! - **Reference-prototype, UNAUDITED.** Nothing here is built on hardware,
//!   deployed, or reviewed beyond this scaffold.
//! - **The Terem guest is the non-attestable tier, by construction, forever**
//!   (`02-security-consent-privacy.md` SS6) -- this crate's consent decisions
//!   say nothing about, and never claim, anything about what the guest OS
//!   itself is running.
//! - **Fail-closed throughout.** An empty ledger authorizes nothing. A
//!   malformed/foreign/tampered record is refused, never defaulted open. A
//!   `sharedFolder.hostPath` that cannot be proven disjoint is refused, never
//!   minted "with a warning."
//! - **A rooted/compromised host defeats every boundary here** -- this crate
//!   protects the host from a hostile guest; it cannot protect a guest (or
//!   the operator) from an already-compromised host, the same honest ceiling
//!   every other Postern bridge product states.
//! - **`widen.gpuPassthrough` is deliberately out of scope for this crate**
//!   (`B-sandbox-consent.md` SS2.4/SS3.0): GPU passthrough widens the
//!   boundary itself rather than crossing data across it, so it does not fit
//!   -- and is not modeled by -- this crate's `Capability` enum at all.
//! - **The coin (BLCH) is not a security and buys no software.**

#![forbid(unsafe_code)]

pub mod audit;
pub mod capability;
pub mod consent_record;
pub mod error;
pub mod paths;
pub mod world;

pub use audit::{AuditTrail, GateEvent, GateRecord};
pub use capability::{Capability, UsbDeviceId, USB_IDENTITY_SPOOFABLE_CAVEAT};
pub use consent_record::{
    Authorized, ConsentAuthority, ConsentLedger, ConsentRecord, ConsentRequest, ConsentScope,
    CrossingTarget, Direction, GuestInstanceId,
};
pub use error::TeremGateError;
pub use paths::TeremPaths;
pub use world::World;

#[cfg(test)]
mod tests {
    //! End-to-end proofs, one per bridge, threading `ConsentAuthority ->
    //! ConsentLedger -> authorize()` exactly the way a real Terem host
    //! daemon would before performing the underlying QEMU/virtiofs/PipeWire
    //! action (`02-security-consent-privacy.md` SS3.1's mechanism table).
    //! These are the "HOST-testable" proofs the bridges are (1) default-
    //! closed, (2) per-direction, and (3) revocable -- run with `cargo test`
    //! on any developer machine, no VM/QEMU required, because the crossing
    //! decision is entirely userland/in-process (the honest label every
    //! sibling crate in this fleet carries).

    use std::path::Path;

    use super::*;

    const NOW: i64 = 1_752_000_000;
    const WIN11: GuestInstanceId = [0xA1; 16];

    fn guarded_paths() -> TeremPaths {
        TeremPaths::new(
            "/var/lib/postern/terem-gate/state",
            "/var/lib/postern/terem-gate/audit",
        )
        .with_wineprefix("/home/operator/.wine-terem")
    }

    /// One bridge, fully wired: mint -> admit -> authorize -> commit, then
    /// revoke and prove the lane is dead. Exercised once per capability
    /// below with the capability-appropriate mint call.
    #[test]
    fn every_bridge_starts_closed_opens_one_direction_and_is_revocable() {
        // clipboard
        {
            let mut host = ConsentAuthority::generate();
            let mut ledger = ConsentLedger::new(host.host_pub());
            assert_eq!(
                ledger
                    .authorize(&WIN11, Capability::Clipboard, World::Host, World::Guest, NOW, None)
                    .unwrap_err(),
                TeremGateError::NoRecord,
                "clipboard must start closed"
            );
            let rec = host
                .mint(WIN11, Capability::Clipboard, Direction::host_to_guest(), ConsentScope::Session, NOW, NOW + 300, "win11")
                .unwrap();
            ledger.admit(rec).unwrap();
            assert!(ledger.authorize(&WIN11, Capability::Clipboard, World::Host, World::Guest, NOW, None).is_ok());
            assert_eq!(
                ledger.authorize(&WIN11, Capability::Clipboard, World::Guest, World::Host, NOW, None).unwrap_err(),
                TeremGateError::WrongDirection,
                "the reverse direction was never granted"
            );
            ledger.revoke_capability(Capability::Clipboard);
            assert_eq!(
                ledger.authorize(&WIN11, Capability::Clipboard, World::Host, World::Guest, NOW, None).unwrap_err(),
                TeremGateError::CapabilityClosed
            );
        }
        // sharedFolder (also exercises red-team fix (a) end to end)
        {
            let mut host = ConsentAuthority::generate();
            let mut ledger = ConsentLedger::new(host.host_pub());
            assert_eq!(
                ledger
                    .authorize(&WIN11, Capability::SharedFolder, World::Host, World::Guest, NOW, None)
                    .unwrap_err(),
                TeremGateError::NoRecord,
                "sharedFolder must start closed"
            );
            // A grant over Terem's own state dir is never mintable.
            let unsafe_grant = host.mint_shared_folder(
                WIN11, Direction::host_to_guest(), ConsentScope::Session, NOW, NOW + 300, "win11",
                Path::new("/var/lib/postern/terem-gate/state"), &guarded_paths(),
            );
            assert!(matches!(unsafe_grant, Err(TeremGateError::SharedFolderPathOverlap { .. })));
            // A disjoint path mints and authorizes normally.
            let rec = host.mint_shared_folder(
                WIN11, Direction::host_to_guest(), ConsentScope::Session, NOW, NOW + 300, "win11",
                Path::new("/home/operator/Documents/shared-with-win11"), &guarded_paths(),
            ).unwrap();
            ledger.admit(rec).unwrap();
            let target = Some(CrossingTarget::SharedFolder(Path::new("/home/operator/Documents/shared-with-win11")));
            assert!(ledger.authorize(&WIN11, Capability::SharedFolder, World::Host, World::Guest, NOW, target).is_ok());
            assert_eq!(
                ledger.authorize(&WIN11, Capability::SharedFolder, World::Guest, World::Host, NOW, target).unwrap_err(),
                TeremGateError::WrongDirection,
                "write-back direction was never granted"
            );
            let revoked = ledger.revoke_all("operator closed the session");
            assert_eq!(revoked, 1);
            assert_eq!(
                ledger.authorize(&WIN11, Capability::SharedFolder, World::Host, World::Guest, NOW, target).unwrap_err(),
                TeremGateError::Revoked
            );
        }
        // network
        {
            let mut host = ConsentAuthority::generate();
            let mut ledger = ConsentLedger::new(host.host_pub());
            assert_eq!(
                ledger.authorize(&WIN11, Capability::Network, World::Guest, World::Host, NOW, None).unwrap_err(),
                TeremGateError::NoRecord,
                "bridged-LAN escalation must start closed"
            );
            let rec = host.mint(WIN11, Capability::Network, Direction::guest_to_host(), ConsentScope::Session, NOW, NOW + 300, "win11").unwrap();
            let id = rec.id;
            ledger.admit(rec).unwrap();
            assert!(ledger.authorize(&WIN11, Capability::Network, World::Guest, World::Host, NOW, None).is_ok());
            ledger.revoke(id);
            assert_eq!(
                ledger.authorize(&WIN11, Capability::Network, World::Guest, World::Host, NOW, None).unwrap_err(),
                TeremGateError::Revoked
            );
        }
        // usb (also exercises the BadUSB caveat labeling)
        {
            let mut host = ConsentAuthority::generate();
            let mut ledger = ConsentLedger::new(host.host_pub());
            assert_eq!(
                ledger.authorize(&WIN11, Capability::Usb, World::Host, World::Guest, NOW, None).unwrap_err(),
                TeremGateError::NoRecord,
                "usb passthrough must start closed"
            );
            let device = UsbDeviceId::new(0x0781, 0x5583, "4C531001234567891234");
            assert!(Capability::Usb.caveat().unwrap().contains("spoofable"));
            let rec = host
                .mint_usb(WIN11, Direction::host_to_guest(), ConsentScope::Session, NOW, NOW + 300, "win11", device.clone())
                .unwrap();
            ledger.admit(rec).unwrap();
            let target = Some(CrossingTarget::Usb(&device));
            assert!(ledger.authorize(&WIN11, Capability::Usb, World::Host, World::Guest, NOW, target).is_ok());
            // A different device (even same vendor:product, different
            // serial) does not match the pinned grant.
            let other = UsbDeviceId::new(0x0781, 0x5583, "DIFFERENT-SERIAL");
            let other_target = Some(CrossingTarget::Usb(&other));
            assert_eq!(
                ledger.authorize(&WIN11, Capability::Usb, World::Host, World::Guest, NOW, other_target).unwrap_err(),
                TeremGateError::UsbDeviceMismatch
            );
            ledger.engage_kill_switch();
            assert_eq!(
                ledger.authorize(&WIN11, Capability::Usb, World::Host, World::Guest, NOW, target).unwrap_err(),
                TeremGateError::KillSwitchEngaged
            );
        }
        // audio
        {
            let mut host = ConsentAuthority::generate();
            let mut ledger = ConsentLedger::new(host.host_pub());
            assert_eq!(
                ledger.authorize(&WIN11, Capability::Audio, World::Guest, World::Host, NOW, None).unwrap_err(),
                TeremGateError::NoRecord,
                "microphone capture must start closed"
            );
            // Playback (host->guest) granted; capture (guest->host, the mic)
            // deliberately never granted in this test -- proves the two
            // audio directions are independent, matching the design docs'
            // "mic capture is the highest-consequence direction" framing.
            let rec = host.mint(WIN11, Capability::Audio, Direction::host_to_guest(), ConsentScope::Session, NOW, NOW + 300, "win11").unwrap();
            let id = rec.id;
            ledger.admit(rec).unwrap();
            assert!(ledger.authorize(&WIN11, Capability::Audio, World::Host, World::Guest, NOW, None).is_ok());
            assert_eq!(
                ledger.authorize(&WIN11, Capability::Audio, World::Guest, World::Host, NOW, None).unwrap_err(),
                TeremGateError::WrongDirection,
                "mic capture (guest->host) must stay closed even though playback is open"
            );
            ledger.revoke(id);
            assert_eq!(
                ledger.authorize(&WIN11, Capability::Audio, World::Host, World::Guest, NOW, None).unwrap_err(),
                TeremGateError::Revoked
            );
        }
    }

    #[test]
    fn expiry_closes_every_bridge_without_any_explicit_revoke() {
        for cap in Capability::ALL {
            let mut host = ConsentAuthority::generate();
            let mut ledger = ConsentLedger::new(host.host_pub());
            let rec = match cap {
                Capability::SharedFolder => host
                    .mint_shared_folder(
                        WIN11, Direction::host_to_guest(), ConsentScope::Session, NOW, NOW + 10, "g",
                        Path::new("/home/operator/Shared"), &guarded_paths(),
                    )
                    .unwrap(),
                Capability::Usb => host
                    .mint_usb(
                        WIN11, Direction::host_to_guest(), ConsentScope::Session, NOW, NOW + 10, "g",
                        UsbDeviceId::new(0x1111, 0x2222, "S1"),
                    )
                    .unwrap(),
                _ => host
                    .mint(WIN11, cap, Direction::host_to_guest(), ConsentScope::Session, NOW, NOW + 10, "g")
                    .unwrap(),
            };
            ledger.admit(rec).unwrap();
            assert_eq!(
                ledger.authorize(&WIN11, cap, World::Host, World::Guest, NOW + 10, None).unwrap_err(),
                TeremGateError::Expired,
                "{cap:?} did not fail-closed on expiry"
            );
        }
    }
}
