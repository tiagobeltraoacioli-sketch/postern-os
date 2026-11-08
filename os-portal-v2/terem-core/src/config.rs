// SPDX-License-Identifier: MIT OR Apache-2.0
//
// DESIGN PREVIEW — written ≠ built ≠ booted. UNAUDITED. THIS MODULE SPAWNS
// NOTHING: it is configuration data only; toggling a flag here runs nothing
// by itself. These flags now gate the crate's one real spawn path
// (`crate::spawn`), which is OFF under the defaults below. Product name
// "Terem" is proposed only, pending trademark clearance.

//! Terem's license-safe feature configuration.
//!
//! Encodes `docs/os-portal-v2/LICENSE-DECISION.md` §2 as types: **every
//! GPL-adjacent feature defaults OFF and is opt-in only**, so Postern's
//! default, published, attested build stays literally permissive-only
//! ("zero GPL/LGPL/AGPL code in the shipped stack") with no asterisk.

use serde::{Deserialize, Serialize};

/// Feature toggles for a Terem installation, with license-safe defaults.
///
/// # License posture (LICENSE-DECISION.md §1–2)
///
/// QEMU (GPL-2.0) and Wine (LGPL-2.1) are **external, operator-supplied,
/// opt-in processes — never linked, never bundled, never vendored** into
/// any Postern binary or the default attested image. When `full_vm_qemu` is
/// `true`, the only thing the runtime layer does is resolve an
/// operator-installed binary by pinned name ([`crate::resolve`]), plan its
/// argv ([`crate::launch`]), and — via the crate's one spawn path,
/// [`crate::spawn::spawn_plan`] — drive it over its own documented CLI/QMP
/// boundary as a plain external child process. Both the plan step and the
/// spawn step independently refuse when the flag is `false`.
///
/// `Default` is the license decision in code: both flags `false`.
/// A `TeremConfig::default()` describes Postern's default build truthfully:
/// 100% permissively licensed, no GPL/LGPL software involved or required.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TeremConfig {
    /// Opt-in: full-VM guests via an operator-supplied QEMU (GPL-2.0).
    ///
    /// **Default `false`** (LICENSE-DECISION.md §1 table: QEMU is "not
    /// bundled by Postern, default build stays clean, opt-in only").
    /// Enabling this never adds GPL code to a Postern artifact — it only
    /// permits resolving, planning, and (via [`crate::spawn::spawn_plan`])
    /// spawning the operator's own `qemu-system-x86_64` as an external
    /// process.
    pub full_vm_qemu: bool,

    /// Opt-in: Windows-app compatibility via an operator-supplied Wine
    /// (LGPL-2.1), with vanilla Wine + DXVK + VKD3D-Proton as the shape —
    /// Valve's Proton build is not shipped at all (LICENSE-DECISION.md §3).
    ///
    /// **Default `false`** — same opt-in, never-bundled, never-linked
    /// treatment as [`Self::full_vm_qemu`].
    pub wine_proton: bool,
}

// Deliberately explicit rather than `#[derive(Default)]`: the two `false`s
// below ARE the LICENSE-DECISION.md §2 decision, and must stay visible and
// greppable here rather than implied by bool's default.
#[allow(clippy::derivable_impls)]
impl Default for TeremConfig {
    fn default() -> Self {
        // The LICENSE-DECISION.md §2 decision, as code: every GPL-adjacent
        // feature is OFF unless the operator explicitly opts in.
        Self {
            full_vm_qemu: false,
            wine_proton: false,
        }
    }
}

impl TeremConfig {
    /// `true` iff no GPL-adjacent feature is enabled — i.e. this config
    /// describes the default, permissive-only posture.
    pub fn is_license_safe_default(&self) -> bool {
        !self.full_vm_qemu && !self.wine_proton
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The load-bearing assertion of this module: every GPL-adjacent
    /// feature defaults OFF. If a new GPL-adjacent flag is ever added to
    /// `TeremConfig`, extend this test — a default-ON GPL feature would
    /// falsify the repo's "permissive-only shipped stack" claim.
    #[test]
    fn gpl_adjacent_features_default_off() {
        let cfg = TeremConfig::default();
        assert!(!cfg.full_vm_qemu, "QEMU (GPL-2.0) must be opt-in, never default-on");
        assert!(!cfg.wine_proton, "Wine (LGPL-2.1) must be opt-in, never default-on");
        assert!(cfg.is_license_safe_default());
    }

    /// An empty JSON object deserializes to the same license-safe defaults —
    /// a missing/blank config file can never silently opt a machine in.
    #[test]
    fn empty_json_yields_license_safe_defaults() {
        let cfg: TeremConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(cfg, TeremConfig::default());
        assert!(cfg.is_license_safe_default());
    }

    /// Opt-in round-trips faithfully: an operator who DID flip a toggle gets
    /// that choice preserved (and visibly not the default) — mirrors the
    /// "honestly different, measurable image" point of LICENSE-DECISION.md §2.
    #[test]
    fn opt_in_round_trips() {
        let cfg = TeremConfig {
            full_vm_qemu: true,
            wine_proton: false,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: TeremConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cfg);
        assert!(!back.is_license_safe_default());
    }

    /// Unknown fields are rejected, not silently dropped — a typo'd opt-in
    /// key fails loudly instead of appearing to work.
    #[test]
    fn unknown_fields_rejected() {
        assert!(serde_json::from_str::<TeremConfig>(r#"{"full_vm_qemuu": true}"#).is_err());
    }
}
