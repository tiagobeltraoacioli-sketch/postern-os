// SPDX-License-Identifier: MIT OR Apache-2.0
//! The two sides a `terem-gate` crossing connects.
//!
//! Mirrors `apps/noporis-bridge-glue/src/persona.rs`'s `Persona` one-for-one,
//! renamed for Terem's shape: not "clean vs. Google-Play" but **"host desktop
//! vs. guest OS/VM/container"**. Per `docs/os-portal-v2/B-sandbox-consent.md`
//! SS2.1's mapping table: `Persona::Clean` -> the host (mints); `Persona::
//! GooglePlay` -> the guest (asks only). Same load-bearing property carried
//! over verbatim: **the world label is derived from which side actually holds
//! the signing key, never from a field the requester controls.** A compromised
//! guest cannot mislabel itself as the host.

use serde::{Deserialize, Serialize};

/// Which side of the Terem boundary a crossing endpoint is. Exactly two: the
/// host desktop process (the only holder of the `ConsentAuthority` signing
/// key, SS2.5) and the guest (a KVM/QEMU VM, an `nspawn` container, or an App
/// Mode `WINEPREFIX` process) -- the non-attestable tier, always
/// (`02-security-consent-privacy.md` SS6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum World {
    /// The Postern OS Desktop host process -- the sandbox-gate daemon that
    /// alone holds the `ConsentAuthority` signing key. **The only side that
    /// mints.**
    Host,
    /// The guest OS/VM/container Terem runs (Windows, Ubuntu, RHEL, or
    /// anything else the operator boots) -- non-attestable, by construction,
    /// forever. **Can only ask** (`ConsentRequest`, never a `ConsentRecord`).
    Guest,
}

impl World {
    /// A plain-language label for the crossing prompt / audit trail.
    pub fn label(self) -> &'static str {
        match self {
            World::Host => "host desktop",
            World::Guest => "guest (non-attestable)",
        }
    }

    /// True for the guest side -- the non-attestable, ask-only side. Not
    /// covered by any host-side seal; surfaced wherever the world appears, a
    /// fact, not decoration (mirrors `Persona::is_less_private`).
    pub fn is_non_attestable(self) -> bool {
        matches!(self, World::Guest)
    }
}
